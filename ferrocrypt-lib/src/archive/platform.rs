//! Capability-based extraction primitives.
//!
//! Every operation inside the user's `output_dir` is anchored to a
//! `cap_std::fs::Dir` handle, traversed component by component via
//! `cap_fs_ext::DirExt::open_dir_nofollow`, and (on Windows) post-
//! checked against `FILE_ATTRIBUTE_REPARSE_POINT` so junctions and
//! mount points are rejected alongside std-recognised symlinks. File
//! creation goes through `OpenOptions::create_new(true)` with
//! `OpenOptionsFollowExt::follow(FollowSymlinks::No)`. Permissions are
//! always set on an open handle, never via a re-resolved path.
//!
//! Universal across Linux / macOS / Windows. The same code path runs
//! on every target so the threat model stays uniform — the invariant
//!
//! > Any symlink, or on Windows any NTFS reparse point including
//! > junctions, in an extraction path is an extraction error
//!
//! is enforced by [`finalize_dir_open`] for every directory open and
//! by `OpenOptions::create_new` + `follow(FollowSymlinks::No)` for
//! every file create.
//!
//! Internally cap-std and cap-fs-ext layer on `rustix` (Linux/macOS)
//! and `windows-sys` (Windows). ferrocrypt itself contains no
//! `unsafe`; all direct syscall surface is in audited Bytecode
//! Alliance crates.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Component, Path};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsSyncExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, Metadata, OpenOptions};

use crate::CryptoError;
use crate::error::{sanitize_for_display, sanitize_path_for_display};

/// Default mode passed to `mkdir` when creating a fresh extraction
/// directory (rwx------). Applied atomically at create time on Unix via
/// `cap_std::fs::DirBuilderExt::mode`, so the directory is never briefly
/// world-traversable under a permissive process umask. The manifest-stored
/// directory mode is applied later via a handle-based chmod so a
/// restrictive parent (e.g. 0o500) declared higher up in the archive
/// doesn't block creation of its children. The temporary mode is
/// owner-private on purpose: root directory chmods are deferred until
/// after the `.incomplete` → final rename for macOS compatibility, so
/// the working tree must not expose plaintext or wider group/other
/// access while it is still staged. Unix-only — Windows ignores the
/// mode arg.
#[cfg(unix)]
const DIR_CREATE_MODE: u32 = 0o700;

/// Initial mode for newly-created regular-file extraction outputs
/// (rw-------). Restrictive on purpose:
///
/// - **Descendant files** (inside a directory root) are chmod'd to the
///   manifest-stored mode after the content write. They sit inside the
///   0o700 staged root, so the wider final mode is never visible to
///   other local users while the file holds plaintext.
/// - **Single-file roots** stay at 0o600 throughout staging AND across
///   the `.incomplete` → final rename. The manifest-stored mode is
///   applied via a handle-based chmod AFTER the rename completes (see
///   `decode::apply_root_file_mode`), so the file is never briefly
///   visible to other local users at a wider mode. There is no
///   protective parent directory in this case, hence the post-rename
///   deferral.
///
/// Effective on Unix only; Windows ignores the mode argument to
/// `create_file_at`.
pub(crate) const INITIAL_FILE_CREATE_MODE: u32 = 0o600;

/// Whether this target has a safe no-clobber directory-promotion
/// backend for committing a directory-root extraction (`FORMAT.md`
/// §9.11 step 15): Linux and macOS via the handle-relative
/// `rename_at_no_clobber`, Windows via the path-based `rename_no_clobber`.
/// No other target has one, so both the archive writer and the extractor
/// refuse a directory root there — keeping "wrote it" symmetric with
/// "can read it back." Single source of truth for the supported set so
/// the two sides cannot drift. A `cfg!` value (not a `#[cfg]` gate) so
/// every caller type-checks on every target.
pub(crate) const DIRECTORY_PROMOTION_SUPPORTED: bool = cfg!(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows"
));

/// `FILE_ATTRIBUTE_REPARSE_POINT` from `WinNT.h`. Stable Win32 ABI
/// bit set on EVERY reparse point regardless of tag — symlinks,
/// junctions, mount points, and any future tag. Single source of
/// truth for the value so encode-side and decode-side reparse-point
/// checks can't drift. Hardcoded so the crate doesn't pull
/// `windows-sys` for a single constant.
#[cfg(windows)]
pub(super) const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

/// Diagnostic label prefix for symlink rejections on the decode side
/// (extraction). Single source of truth for the wording so a future
/// rename catches all call sites. See [`classify_open_failure`].
const SYMLINK_IN_EXTRACTION_PATH: &str = "Symlink in extraction path";

/// Diagnostic for a directory on a walked path that is no longer there.
/// Both walks expect every component to exist, so its absence reports a
/// tree another process changed while the run was using it.
const DIRECTORY_MISSING_IN_EXTRACTION: &str = "Directory in extraction path went missing";

const DIRECTORY_MISSING_IN_ARCHIVE_SOURCE: &str = "Directory in archive source went missing";

/// Which side of the archive a path walk belongs to. One value carries
/// every diagnostic label for that side, so a walk that rejects says
/// whether it was reading the caller's source tree or writing the
/// extracted one, whatever the reason.
#[derive(Clone, Copy)]
pub(crate) enum WalkSide {
    /// Reading the source tree an encrypt was pointed at.
    ArchiveSource,
    /// Writing the tree a decrypt is extracting.
    Extraction,
}

impl WalkSide {
    fn symlink_label(self) -> &'static str {
        match self {
            Self::ArchiveSource => SYMLINK_IN_ARCHIVE_SOURCE,
            Self::Extraction => SYMLINK_IN_EXTRACTION_PATH,
        }
    }

    fn missing_directory_label(self) -> &'static str {
        match self {
            Self::ArchiveSource => DIRECTORY_MISSING_IN_ARCHIVE_SOURCE,
            Self::Extraction => DIRECTORY_MISSING_IN_EXTRACTION,
        }
    }
}

/// Diagnostic label prefix for symlink rejections on the encode side
/// (source-tree walk). Same shape as [`SYMLINK_IN_EXTRACTION_PATH`]
/// but role-specific so the caller can tell at a glance whether the
/// rejection came from archiving or extracting.
pub(super) const SYMLINK_IN_ARCHIVE_SOURCE: &str = "Symlink in archive source";

/// Opens the user-supplied output directory as the trusted anchor.
/// `output_dir` is chosen by the caller (CLI args / GUI picker); the
/// caller's choice IS the trust boundary, so no NOFOLLOW or reparse
/// check is applied to it. Every operation inside is rooted here.
pub(crate) fn open_anchor(path: &Path) -> Result<Dir, CryptoError> {
    Dir::open_ambient_dir(path, ambient_authority()).map_err(CryptoError::Io)
}

/// Identity of a filesystem object, read from an open handle so a later
/// step can tell whether a name still denotes the object this run
/// created. Rename does not change it, so it survives promotion.
///
/// The pair is the device and inode number on Unix, and the volume
/// serial number and file index on Windows; both are read through
/// [`crate::fs::atomic::file_identity`], which states what the
/// comparison can and cannot distinguish. A filesystem that reports no
/// distinct identifiers makes every comparison hold, so the steps that
/// compare keep the no-follow opens and the reparse-point checks as
/// their guard.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct ObjectId {
    dev: u64,
    ino: u64,
}

/// Reads the identity out of metadata already taken. `metadata` must
/// come from an open handle or a cap-std stat, as
/// [`crate::fs::atomic::file_identity`] requires.
pub(crate) fn metadata_object_id(metadata: &Metadata) -> ObjectId {
    let (dev, ino) = crate::fs::atomic::file_identity(metadata);
    ObjectId { dev, ino }
}

/// Reads the identity of the directory `dir` refers to.
pub(crate) fn dir_object_id(dir: &Dir) -> Result<ObjectId, CryptoError> {
    let metadata = dir.dir_metadata().map_err(CryptoError::Io)?;
    Ok(metadata_object_id(&metadata))
}

/// Reads the identity of the file `file` refers to.
pub(crate) fn file_object_id(file: &File) -> Result<ObjectId, CryptoError> {
    let metadata = file.metadata().map_err(CryptoError::Io)?;
    Ok(metadata_object_id(&metadata))
}

/// What a comparison of two objects' owners established. Each platform
/// constructs only the variants it can report.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum OwnerComparison {
    /// Both objects report the same owner.
    #[cfg_attr(not(unix), allow(dead_code))]
    Same,
    /// The objects report different owners.
    #[cfg_attr(not(unix), allow(dead_code))]
    Different,
    /// The metadata a handle yields on this platform carries no owner.
    #[cfg_attr(unix, allow(dead_code))]
    Unavailable,
}

/// Compares the owners of `dir` and `file`, both created by this run.
///
/// Two objects one run creates through the same filesystem agree on
/// every filesystem — they carry the run's own identity where ownership
/// is recorded, and the mount's fixed or remapped identity elsewhere —
/// while a directory another user planted carries that user's identity
/// wherever ownership is recorded. The comparison therefore never
/// refuses the run's own objects, and detects a planted directory on
/// any filesystem that can show one.
#[cfg(unix)]
pub(crate) fn compare_owners(dir: &Dir, file: &File) -> Result<OwnerComparison, CryptoError> {
    use cap_std::fs::MetadataExt;

    let dir_owner = dir.dir_metadata().map_err(CryptoError::Io)?.uid();
    let file_owner = file.metadata().map_err(CryptoError::Io)?.uid();
    Ok(if dir_owner == file_owner {
        OwnerComparison::Same
    } else {
        OwnerComparison::Different
    })
}

/// Windows metadata carries no owner without a security-descriptor
/// query, so the comparison is unavailable there.
#[cfg(not(unix))]
pub(crate) fn compare_owners(_dir: &Dir, _file: &File) -> Result<OwnerComparison, CryptoError> {
    Ok(OwnerComparison::Unavailable)
}

/// Handle-relative no-clobber rename used to promote a staged
/// `{root}.incomplete` to its final `{root}` name (FORMAT.md §9.11
/// step 15) without re-resolving the ambient `output_dir` path.
///
/// Both endpoints resolve through `dir` — the extraction-directory
/// handle `open_anchor` returned — via
/// `renameat(dir, from, dir, to, RENAME_NOREPLACE)`. A rename or
/// replacement of the `output_dir` path between staging and this commit
/// therefore cannot redirect the promotion to a different directory: it
/// lands in the exact directory the contents were written to, and the
/// kernel still refuses an existing `to` atomically
/// (`io::ErrorKind::AlreadyExists`). A best-effort directory `fsync`
/// follows so the rename is durable, mirroring the parent-directory
/// sync the path-based `fs::atomic` helpers perform.
///
/// Linux and macOS only. `RENAME_NOREPLACE` maps to `renameat2` on
/// Linux and `renameatx_np(RENAME_EXCL)` on macOS, both through
/// `rustix`. Filesystems that cannot perform a flagged rename at all
/// (macOS exFAT among them; see
/// [`crate::fs::atomic::no_replace_rename_unsupported`]) fall back to
/// [`rename_at_no_clobber_via_claim`], which keeps both the no-clobber
/// guarantee and the handle-relative anchoring. `root_is_file` selects
/// the fallback's claim strategy; the flagged rename itself promotes
/// files and directories alike. Windows keeps the path-based promotion
/// in `fs::atomic`, because a handle-relative no-replace rename there
/// needs an `unsafe` Win32 call the crate forbids; see `SECURITY.md`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn rename_at_no_clobber(
    dir: &Dir,
    from: &OsStr,
    to: &OsStr,
    root_is_file: bool,
) -> io::Result<PromotionOutcome> {
    use std::os::fd::AsFd;

    use rustix::fs::{RenameFlags, renameat_with};

    if let Err(e) = renameat_with(dir.as_fd(), from, dir.as_fd(), to, RenameFlags::NOREPLACE) {
        let error = io::Error::from(e);
        if !crate::fs::atomic::no_replace_rename_unsupported(&error) {
            return Err(error);
        }
        return rename_at_no_clobber_via_claim(dir, from, to, root_is_file);
    }
    // Best-effort durability: flush the directory so the rename survives
    // a crash, mirroring the parent-directory sync the path-based
    // `fs::atomic` helpers perform.
    sync_dir_handle(dir);
    Ok(PromotionOutcome::Clean)
}

/// Result of a successful step-15 promotion.
///
/// Every route that commits a file root leaves the caller the same
/// post-condition: confirm through the retained file handle that the
/// committed inode carries exactly one link. The staged plaintext is
/// created under a name any local writer with access to the output
/// directory can link to, and that link survives the promotion, so the
/// count is read whatever route committed the final name.
///
/// A file-root fallback first links the complete staged file at its final
/// name, then removes the staged name, which makes the count necessary for
/// a second reason: a concurrent writer can move the staged link and make
/// the unlink return `NotFound`, or replace it so the unlink removes the
/// wrong file. The path-based file promotion used off Linux and macOS can
/// commit by hard link the same way — `tempfile`'s own fallback, whose
/// unlink result it does not report — so it is marked through
/// [`Self::for_tempfile_file_promotion`].
///
/// If the staged-name unlink fails, the final name must not be withdrawn by
/// name: a concurrent writer can replace that entry while the failed unlink
/// is blocked, and a later bare-name removal would delete the replacement.
/// The caller therefore completes the post-promotion checks and reports
/// either condition without running failure cleanup against the committed
/// inode.
#[derive(Debug)]
pub(crate) enum PromotionOutcome {
    /// The final name was committed by one-step rename or by a claim route,
    /// neither of which creates a second link to the committed inode.
    Clean,
    /// A file was committed over a route that links it to its final name:
    /// the crate's own fallback after a staged-name removal that reported
    /// success or `NotFound`, or `tempfile`'s internal fallback, which does
    /// not report its removal result at all. It records which route ran
    /// rather than selecting a check — the caller requires a link count of
    /// one for [`Self::Clean`] just the same — because that removal is the
    /// second reason the count cannot be skipped.
    #[cfg(unix)]
    LinkedFile,
    /// The final name is committed, but the staging name could not be
    /// removed. Both names may still denote the same complete file.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    StagedLinkRetained(io::Error),
}

impl PromotionOutcome {
    /// The outcome of a file root committed through
    /// `fs::atomic::promote_single_file_no_clobber`. Windows moves the file
    /// in one step and never links. On every other Unix target `tempfile`
    /// may commit — or, off its `renameat_with` platforms, always commits —
    /// by hard link with a discarded unlink, so the caller must prove the
    /// cleanup through the retained-inode link count.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn for_tempfile_file_promotion() -> Self {
        #[cfg(unix)]
        {
            Self::LinkedFile
        }
        #[cfg(not(unix))]
        {
            Self::Clean
        }
    }

    /// Returns the staged-name unlink failure, where the commit completed with
    /// a second link still present.
    pub(crate) fn into_staged_link_error(self) -> Option<io::Error> {
        match self {
            Self::Clean => None,
            #[cfg(unix)]
            Self::LinkedFile => None,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::StagedLinkRetained(error) => Some(error),
        }
    }
}

/// Fallback for filesystems where the kernel refuses the no-replace
/// rename flag outright. A file root on a filesystem with hard links is
/// moved by [`link_no_clobber`], which needs no placeholder at all;
/// every other case — no hard links or another pre-commit link failure —
/// claims the name and renames over its own claim:
///
/// 1. atomically claim the final name through `dir` — `create_new` for
///    a file root, owner-only `mkdir` for a directory root — refusing
///    any pre-existing entry with `AlreadyExists`, the same error the
///    flagged rename reports;
/// 2. plain handle-relative rename of the staged entry over the claim.
///    Renaming onto the placeholder replaces it in a single step (an
///    empty directory target is replaced under POSIX rename rules), so
///    content appears at the final name whole, never partially.
///
/// Both steps resolve through `dir`, preserving the redirect-proofing
/// of the flagged path. Only the entry created in step 1 can be
/// replaced, so the no-clobber guarantee against pre-existing entries
/// is unconditional. The owner-only claim modes
/// ([`INITIAL_FILE_CREATE_MODE`] file / [`DIR_CREATE_MODE`] directory)
/// keep other local users from writing into the claimed name where
/// the filesystem enforces modes; on a permissionless filesystem
/// (exFAT) a concurrent local write into a directory claim makes
/// step 2 fail closed with a non-empty-target error instead.
///
/// Between the two steps the claim is an ordinary entry, so a local
/// writer with access to the destination directory can remove it and
/// leave one of their own, which step 2 then replaces. That window is
/// why the link move above is preferred wherever the filesystem
/// supports links; `SECURITY.md` states what remains for the cases that
/// cannot use it.
///
/// If step 2 fails, the claim is removed best-effort and the staged
/// entry stays in place for the caller's retain-on-error handling.
/// Process interruption between the steps leaves an empty placeholder
/// at the final name next to the staged `.incomplete` entry.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rename_at_no_clobber_via_claim(
    dir: &Dir,
    from: &OsStr,
    to: &OsStr,
    root_is_file: bool,
) -> io::Result<PromotionOutcome> {
    if root_is_file {
        match link_no_clobber(dir, from, to) {
            Ok(outcome) => return Ok(outcome),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(e),
            Err(_) => {}
        }
        create_file_at(dir, to, INITIAL_FILE_CREATE_MODE)?;
    } else {
        create_dir_initial_mode(dir, to)?;
    }
    match dir.rename(from, dir, to) {
        Ok(()) => {
            sync_dir_handle(dir);
            Ok(PromotionOutcome::Clean)
        }
        Err(e) => {
            if root_is_file {
                let _ = dir.remove_file(to);
            } else {
                let _ = dir.remove_dir(to);
            }
            Err(e)
        }
    }
}

/// Moves a staged file root to its final name by linking it there and
/// unlinking the staged name, both handle-relative through `dir`.
///
/// `link` refuses an existing target atomically, so this reaches the
/// final name without ever creating a placeholder another process could
/// replace — the no-clobber guarantee holds against a concurrent local
/// writer, not only against entries that predate the commit. Both names
/// denote the finished content in between, so an interruption leaves
/// the complete output at the final name rather than an empty entry.
///
/// Only for file roots: directories cannot be linked. Filesystems
/// without hard links (exFAT and FAT among them) reject the call, and
/// the caller falls back to claiming the name. A staged name whose
/// unlink fails is reported as [`PromotionOutcome::StagedLinkRetained`]. A
/// successful or missing-name result is [`PromotionOutcome::LinkedFile`], so
/// the caller verifies through the retained inode that no moved link survived.
/// The final name is deliberately not withdrawn after that delayed failure:
/// a concurrent writer may already have replaced it, and no portable
/// unlink-if-identity-matches primitive is available.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn link_no_clobber(dir: &Dir, from: &OsStr, to: &OsStr) -> io::Result<PromotionOutcome> {
    link_no_clobber_with_remove(dir, from, to, |dir, from| dir.remove_file(from))
}

/// Testable implementation of [`link_no_clobber`]. `remove_staged` is the
/// single operation that can fail only after the final link exists; injecting
/// it lets the tests pin the post-commit policy without depending on a
/// filesystem that can refuse one unlink on demand.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn link_no_clobber_with_remove(
    dir: &Dir,
    from: &OsStr,
    to: &OsStr,
    remove_staged: impl FnOnce(&Dir, &OsStr) -> io::Result<()>,
) -> io::Result<PromotionOutcome> {
    dir.hard_link(from, dir, to)?;
    let outcome = match remove_staged(dir, from) {
        Ok(()) => PromotionOutcome::LinkedFile,
        // Missing is not proof that the link was destroyed: a concurrent
        // writer may have renamed it. The retained-handle link-count check in
        // `decode` distinguishes removal from a move without trusting names.
        Err(error) if error.kind() == io::ErrorKind::NotFound => PromotionOutcome::LinkedFile,
        // Do not remove `to` after an error here. The unlink may have blocked,
        // giving a concurrent writer time to replace the final entry; there is
        // no portable unlink-if-identity-matches primitive.
        Err(error) => PromotionOutcome::StagedLinkRetained(error),
    };
    sync_dir_handle(dir);
    Ok(outcome)
}

/// Best-effort `fsync` of the directory `dir` refers to. This flushes
/// the directory entries — the links to its child files and
/// subdirectories — to stable storage.
///
/// The extractor uses this before promoting a directory root, so a
/// crash after the `.incomplete` → final rename cannot leave the final
/// output present while nested entries are missing on filesystems where
/// file `fsync` does not imply directory durability. The promotion path
/// also uses it after a handle-relative rename to make the rename
/// durable.
///
/// cap-std may hold `dir` as an `O_PATH` handle on Linux, where
/// `fsync` fails with `EBADF`. The helper therefore opens `.` relative
/// to `dir` and syncs that fresh read-only handle. This avoids ambient
/// path resolution and works whether or not `dir` itself is `O_PATH`.
/// Failures are ignored because this durability hint must not turn a
/// completed operation into an error.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn sync_dir_handle(dir: &Dir) {
    if let Ok(sync_fd) = open_dir_sync_fd(dir) {
        let _ = crate::fs::atomic::fsync_uninterrupted(&sync_fd);
    }
}

/// No-op on targets without this `openat`/`fsync` directory-sync path.
///
/// On Windows this is a real gap, not an equivalence: `FlushFileBuffers`
/// requires a write handle, and the extraction `Dir` handles are opened
/// read-only. A capability-relative reopen of `.` with write access
/// could close the gap, but is not implemented or verified on Windows.
/// Staged descendant directories are therefore not flushed there. The
/// path-based
/// `fs::atomic::sync_parent_dir` still flushes the output directory
/// entry after promotion, and NTFS journals metadata, so the exposure is
/// a crash between extraction and promotion. `FORMAT.md` §9.11 states
/// the directory sync as SHOULD, so this stays within the specification.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn sync_dir_handle(_dir: &Dir) {}

/// Opens `.` relative to a capability directory for a subsequent sync.
///
/// cap-std may represent a directory with an `O_PATH` handle on Linux,
/// which cannot itself be passed to `fsync`. Reopening `.` supplies a
/// syncable read handle without resolving an ambient path. The open is
/// retried on `EINTR` so callers do not silently lose or spuriously fail
/// a durability barrier when a signal arrives.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_dir_sync_fd(dir: &Dir) -> io::Result<rustix::fd::OwnedFd> {
    use std::os::fd::AsFd;

    use rustix::fs::{Mode, OFlags, openat};

    rustix::io::retry_on_intr(|| {
        openat(
            dir.as_fd(),
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
    })
    .map_err(io::Error::from)
}

/// Completes the extraction-side durability sequence before a staged
/// directory is promoted.
///
/// Every staged regular file has already received plain `fsync(2)`, and
/// every staged directory has had the same best-effort sync attempted.
/// On macOS, plain `fsync` can leave those writes only in the drive's
/// volatile cache, so one `F_FULLFSYNC` on the completed staged root asks
/// the drive to commit all buffered data to persistent storage. This is
/// one full-device barrier per directory decrypt, rather than one per
/// extracted file.
///
/// Filesystems that do not support `F_FULLFSYNC` fall back to plain
/// `fsync`, matching the strongest behavior available before the batched
/// barrier. Genuine open or sync failures are returned so extraction
/// stops before promotion. Other targets need no extra barrier: Linux
/// `fsync` already has the semantics its `sync_all` path used, while
/// Windows keeps `FlushFileBuffers` on every extracted file.
#[cfg(target_os = "macos")]
pub(crate) fn sync_extraction_barrier(dir: &Dir) -> io::Result<()> {
    let sync_fd = match open_dir_sync_fd(dir) {
        Ok(sync_fd) => sync_fd,
        Err(e) if crate::fs::atomic::dir_sync_unsupported(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    match rustix::io::retry_on_intr(|| rustix::fs::fcntl_fullfsync(&sync_fd)) {
        Ok(()) => Ok(()),
        Err(e) => {
            let e = io::Error::from(e);
            if !crate::fs::atomic::dir_sync_unsupported(&e) {
                return Err(e);
            }
            match crate::fs::atomic::fsync_uninterrupted(&sync_fd) {
                Ok(()) => Ok(()),
                Err(e) if crate::fs::atomic::dir_sync_unsupported(&e) => Ok(()),
                Err(e) => Err(e),
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn sync_extraction_barrier(_dir: &Dir) -> io::Result<()> {
    Ok(())
}

/// Windows-only post-condition for a successful directory open.
/// cap-fs-ext's `open_dir_nofollow` uses
/// `FILE_FLAG_OPEN_REPARSE_POINT` and then rejects entries whose
/// `is_symlink()` is true — but `is_symlink()` returns `false` for
/// NTFS junctions / mount points (`IO_REPARSE_TAG_MOUNT_POINT`).
/// Without this post-check, an attacker who plants a junction inside
/// `.incomplete/` (or inside the writer's source tree) would redirect
/// the operation through it.
///
/// `FILE_ATTRIBUTE_REPARSE_POINT` (0x400, defined in `WinNT.h`) is
/// set on EVERY reparse point regardless of tag, so the bitmask check
/// rejects symlinks, junctions, mount points, and any future tag
/// uniformly.
#[cfg(windows)]
fn reject_reparse_point(dir: &Dir, name: &OsStr, label: &str) -> Result<(), CryptoError> {
    use cap_std::fs::MetadataExt;
    let meta = dir.dir_metadata().map_err(CryptoError::Io)?;
    reject_reparse_attributes(meta.file_attributes(), name, label)
}

/// Single source of truth for the "is this entry a reparse point?"
/// check shared by [`reject_reparse_point`] (directory handles) and
/// [`finalize_file_open`] (regular-file handles). Takes the already-
/// extracted `file_attributes` word so the helper stays type-agnostic
/// — `cap_std::fs::Dir` and `cap_std::fs::File` expose attributes
/// through different methods (`dir_metadata` vs `metadata`). `label`
/// is the caller's side ([`SYMLINK_IN_EXTRACTION_PATH`] or
/// [`SYMLINK_IN_ARCHIVE_SOURCE`]).
#[cfg(windows)]
fn reject_reparse_attributes(
    file_attributes: u32,
    name: &OsStr,
    label: &str,
) -> Result<(), CryptoError> {
    if file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(CryptoError::InvalidInput(format!(
            "{label}: {}",
            sanitize_for_display(&name.to_string_lossy())
        )));
    }
    Ok(())
}

/// Post-open finalize step. On Windows runs the reparse-point bitmask
/// check with the caller's diagnostic label; on Unix is a no-op
/// (cap-fs-ext's `open_dir_nofollow` plus the kernel's symlink
/// semantics already give the equivalent invariant — there's no
/// separate "reparse point" concept).
fn finalize_dir_open(dir: Dir, _name: &OsStr, _label: &str) -> Result<Dir, CryptoError> {
    #[cfg(windows)]
    reject_reparse_point(&dir, _name, _label)?;
    Ok(dir)
}

/// Maps an `open_dir_nofollow` failure to a typed error. When the
/// backing entry is in fact a symlink we surface a labelled symlink
/// diagnostic (`"<label>: <diagnostic>"`); otherwise the underlying
/// `io::Error` is propagated unchanged. The post-mortem
/// `symlink_metadata` probe is a diagnostic hint only — under TOCTOU
/// it might race the original failure — but it never affects the
/// rejection (the open already failed) and matches the rustix-era
/// taxonomy whenever it observes the same state.
///
/// `label` lets encode-side ("Symlink in archive source") and
/// decode-side ("Symlink in extraction path") share one helper while
/// still emitting the role-specific diagnostic. `diagnostic` is the
/// path string the caller wants surfaced (typically the leaf name
/// for decode-side path walks, or the full archive-relative path
/// for encode-side `walk_directory` so the operator sees which
/// manifest entry is implicated, not just the failing leaf).
pub(super) fn classify_open_failure(
    parent: &Dir,
    name: &OsStr,
    e: io::Error,
    label: &str,
    diagnostic: &str,
) -> CryptoError {
    if let Ok(meta) = parent.symlink_metadata(name) {
        if meta.file_type().is_symlink() {
            return CryptoError::InvalidInput(format!(
                "{label}: {}",
                sanitize_for_display(diagnostic)
            ));
        }
    }
    CryptoError::Io(e)
}

/// Opens an existing directory `name` under `parent` with no-follow
/// plus the Windows reparse-point post-check. The single open step
/// shared by the per-component walks ([`walk_to_parent`],
/// [`open_dir_at_rel`]) and the writer's source-root open. A symlink
/// at `name` fails with the labelled diagnostic; on Windows a
/// junction or mount point fails via [`finalize_dir_open`].
pub(crate) fn open_child_dir_nofollow(
    parent: &Dir,
    name: &OsStr,
    label: &str,
) -> Result<Dir, CryptoError> {
    let dir = parent.open_dir_nofollow(name).map_err(|e| {
        classify_open_failure(
            parent,
            name,
            e,
            label,
            &Path::new(name).display().to_string(),
        )
    })?;
    finalize_dir_open(dir, name, label)
}

/// Creates a fresh directory `name` under `parent` and opens it with
/// no-follow. Fails with `AlreadyExists` if anything — including a
/// symlink, on Windows including a junction — already exists at that
/// name.
pub(crate) fn mkdir_strict(parent: &Dir, name: &OsStr) -> Result<Dir, CryptoError> {
    create_dir_with_default_mode(parent, name)
}

/// Second handle to the staged root directory `dir`, created as `name`
/// under `parent`, for the extractor to hold across promotion: the
/// checks after promotion compare the final name with the object this
/// run created (`FORMAT.md` §9.11 steps 16 and 17), and on Unix the
/// failure cleanup removes the staged tree through it.
///
/// On Unix it duplicates `dir`. On Windows a duplicate would keep the
/// sharing mode of a cap-std directory handle, which excludes delete
/// sharing and so makes the promotion rename fail while it is open. The
/// entry is therefore opened again by name with the default sharing
/// mode — read, write, and delete — requesting no access, as a
/// metadata query does, with backup semantics and without following a
/// symlink or reparse point, and wrapped as a `Dir` for the identity
/// read; the rename proceeds with that handle open, and the identity it
/// reads afterwards is the promoted directory's. Because that open
/// resolves `name`, the caller must confirm the returned handle denotes
/// `dir` before recording it, and must not walk from it.
pub(crate) fn retain_staged_dir(parent: &Dir, name: &OsStr, dir: &Dir) -> io::Result<Dir> {
    #[cfg(unix)]
    {
        let _ = (parent, name);
        dir.try_clone()
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;

        let _ = dir;
        let mut options = OpenOptions::new();
        options
            .access_mode(0)
            .custom_flags(crate::fs::atomic::FILE_FLAG_BACKUP_SEMANTICS);
        options.follow(FollowSymlinks::No);
        let file = parent.open_with(name, &options)?;
        Ok(Dir::from_std_file(file.into_std()))
    }
}

/// Internal: creates `name` with the initial owner-private directory
/// mode applied atomically (Unix: `mkdir(0o700)` via cap-std's
/// `DirBuilderExt::mode`, so a permissive process umask cannot leave
/// the directory briefly world-traversable; Windows: ignored), then
/// re-opens it with no-follow + the Windows reparse-point post-check.
/// Keeps the "create with a safe temporary mode, apply manifest-stored
/// mode later" behavior without ever chmod-ing through a re-resolved
/// path.
fn create_dir_with_default_mode(parent: &Dir, name: &OsStr) -> Result<Dir, CryptoError> {
    create_dir_initial_mode(parent, name).map_err(CryptoError::Io)?;

    let dir = parent.open_dir_nofollow(name).map_err(|e| {
        classify_open_failure(
            parent,
            name,
            e,
            SYMLINK_IN_EXTRACTION_PATH,
            &Path::new(name).display().to_string(),
        )
    })?;
    finalize_dir_open(dir, name, SYMLINK_IN_EXTRACTION_PATH)
}

/// Atomic mkdir-with-mode on Unix; plain mkdir on non-Unix targets.
/// Pinning the mode at create time (rather than mkdir + chmod) closes
/// the umask race where a permissive `0o022` umask would briefly leave
/// a fresh `.incomplete` directory at `0o755`.
#[cfg(unix)]
fn create_dir_initial_mode(parent: &Dir, name: &OsStr) -> io::Result<()> {
    use cap_std::fs::{DirBuilder, DirBuilderExt};
    let mut builder = DirBuilder::new();
    builder.mode(DIR_CREATE_MODE);
    parent.create_dir_with(name, &builder)
}

#[cfg(not(unix))]
fn create_dir_initial_mode(parent: &Dir, name: &OsStr) -> io::Result<()> {
    parent.create_dir(name)
}

/// Internal helper: applies a Unix mode to the directory `dir` refers to.
///
/// **Why this is not `dir.try_clone().into_std_file().set_permissions(...)`.**
/// cap-std opens directories with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW`
/// plus, on Linux, `O_PATH` (cap-primitives' `compute_oflags` adds
/// `O_PATH` whenever `dir_required` is set without write or readdir
/// access — which is every directory we open). `fchmod(2)` on an
/// `O_PATH` fd returns `EBADF` on Linux, so calling
/// `std_file.set_permissions(...)` against the underlying fd from
/// `Dir::into_std_file()` always fails on Linux dir handles even
/// though the same code runs cleanly on macOS (which has no
/// `O_PATH`).
///
/// `Dir::set_permissions(".", perm)` routes through cap-primitives'
/// `set_permissions_impl`, which on Linux uses the `/proc/self/fd/N`
/// magic-link `chmodat` trick (precisely the workaround for
/// `O_PATH`-vs-`fchmod`) and on macOS / other Unix opens the path
/// with `read(true)` and fchmods the regular fd. Same code path on
/// every Unix target, no `unsafe`, and the path resolution stays
/// rooted in `dir`'s capability so it can never escape the sandbox.
#[cfg(unix)]
fn chmod_dir_via_self_path(dir: &Dir, mode: u32) -> Result<(), CryptoError> {
    use cap_std::fs::PermissionsExt;
    let perm = cap_std::fs::Permissions::from_mode(mode & super::PERMISSION_BITS_MASK);
    dir.set_permissions(".", perm).map_err(CryptoError::Io)
}

/// Walks `rel` under `root` opening existing directories only, and
/// returns a fresh handle to the final component's parent together
/// with the final component's name. Every intermediate open goes
/// through no-follow + reparse-check, so a substituted symlink or
/// junction anywhere along the path fails closed with `label`.
///
/// It creates nothing. On the extraction side every directory the
/// validated manifest declares already exists, so a missing one means
/// another process changed the staged tree, and creating it again
/// would carry on into a tree that no longer holds what was written
/// into it. On the source side the tree is the caller's own input.
///
/// `side` names which tree is being walked, so every rejection says
/// whether it came from archiving or extracting — both the symlink
/// diagnostic and the one for a directory that has gone.
///
/// `rel` must have at least one component; an empty path is treated
/// as an internal invariant violation.
pub(crate) fn walk_to_parent(
    root: &Dir,
    rel: &Path,
    side: WalkSide,
) -> Result<(Dir, OsString), CryptoError> {
    let mut components: Vec<Component<'_>> = rel.components().collect();
    let last = components.pop().ok_or(crate::error::internal_invariant!(
        "archive entry resolved to empty path"
    ))?;
    let final_name = normal_component(last, rel)?.to_os_string();

    let mut cur = root.try_clone().map_err(CryptoError::Io)?;
    for component in components {
        let name = normal_component(component, rel)?;
        cur = open_child_dir_nofollow(&cur, name, side.symlink_label())
            .map_err(|e| missing_walk_component(e, side, name))?;
    }
    Ok((cur, final_name))
}

/// Replaces the bare not-found error a walk raises for a directory that
/// has gone with one that names the path and says what its absence
/// means. Both sides of the walk expect every component to be there —
/// extraction created them, the source tree is the caller's own — so a
/// component that is missing says another process changed the tree
/// under the run, which a transparent "No such file or directory" does
/// not convey. Every other failure keeps its own classification.
fn missing_walk_component(error: CryptoError, side: WalkSide, name: &OsStr) -> CryptoError {
    match &error {
        CryptoError::Io(io_error) if io_error.kind() == io::ErrorKind::NotFound => {
            CryptoError::InvalidInput(format!(
                "{}: {}",
                side.missing_directory_label(),
                sanitize_for_display(&name.to_string_lossy())
            ))
        }
        _ => error,
    }
}

/// Walks `rel` under `root` opening existing dirs only — never
/// creates anything. Used at chmod time so deferred directory
/// permissions can be applied against a fresh handle instead of a
/// re-resolved path. Every component goes through no-follow +
/// reparse-check.
///
/// **Empty-`rel` behavior.** When `rel` has no components,
/// `rel.components()` yields nothing and the for-loop is a no-op,
/// so the function returns a fresh clone of `root` itself. The
/// in-`extract_entries` deferred dir-permissions loop only invokes
/// this helper for non-empty `rel` (root-level chmods are deferred
/// past rename and applied separately by `unarchive`); the
/// empty-`rel` branch is preserved both for adversarial robustness
/// and so the helper remains usable from future call sites that
/// want a uniform parent-or-self handle.
pub(crate) fn open_dir_at_rel(root: &Dir, rel: &Path) -> Result<Dir, CryptoError> {
    let mut cur = root.try_clone().map_err(CryptoError::Io)?;
    for component in rel.components() {
        let name = normal_component(component, rel)?;
        cur = open_child_dir_nofollow(&cur, name, SYMLINK_IN_EXTRACTION_PATH)
            .map_err(|e| missing_walk_component(e, WalkSide::Extraction, name))?;
    }
    Ok(cur)
}

/// Opens an existing regular file beneath `parent` without following
/// symlinks, then validates the opened handle through
/// [`finalize_file_open`]. This is the file equivalent of
/// [`open_dir_at_rel`] and is used for the final permission update after
/// promotion.
///
/// On Unix the open is non-blocking, so a FIFO at the name cannot wait for a
/// writer. The subsequent type check rejects FIFOs and other non-regular
/// objects. On Windows the reparse-point check also applies.
pub(crate) fn open_file_nofollow(parent: &Dir, name: &OsStr) -> Result<File, CryptoError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = parent.open_with(name, &options).map_err(|e| {
        classify_open_failure(
            parent,
            name,
            e,
            SYMLINK_IN_EXTRACTION_PATH,
            &Path::new(name).display().to_string(),
        )
    })?;
    finalize_file_open(file, name)
}

/// Validates an opened file handle. The handle must refer to a regular file;
/// FIFOs, devices, sockets, and directories are rejected. On Windows the
/// reparse-point check runs first because a no-follow open may return a handle
/// to the reparse point itself. Unix rejects symlinks during the open.
fn finalize_file_open(file: File, name: &OsStr) -> Result<File, CryptoError> {
    let metadata = file.metadata().map_err(CryptoError::Io)?;
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt;
        reject_reparse_attributes(metadata.file_attributes(), name, SYMLINK_IN_EXTRACTION_PATH)?;
    }
    if !metadata.file_type().is_file() {
        return Err(CryptoError::InvalidInput(format!(
            "Extraction path is no longer a regular file: {}",
            sanitize_for_display(&name.to_string_lossy())
        )));
    }
    Ok(file)
}

fn normal_component<'a>(component: Component<'a>, full: &Path) -> Result<&'a OsStr, CryptoError> {
    match component {
        Component::Normal(s) => Ok(s),
        _ => Err(CryptoError::InvalidInput(format!(
            "Invalid component in archive entry: {}",
            sanitize_path_for_display(full)
        ))),
    }
}

/// Atomically creates a new regular file under `parent`. Any pre-
/// existing entry — including a symlink whose target exists, a
/// dangling symlink, or (on Windows) a reparse point — causes
/// `AlreadyExists`. The initial permission word is restrictive
/// (`0o600` on Unix, default on Windows); callers apply the
/// manifest-stored mode via [`chmod_file_handle`] after writing so
/// plaintext is never briefly visible to unintended users.
///
/// `OpenOptionsFollowExt::follow(FollowSymlinks::No)` is set
/// alongside `create_new(true)` for defense in depth — both prevent
/// the open from following a pre-placed symlink at the leaf, on
/// platforms where the underlying open semantics differ.
pub(crate) fn create_file_at(
    parent: &Dir,
    name: &OsStr,
    #[cfg_attr(not(unix), allow(unused_variables))] create_mode: u32,
) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    options.follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_fs_ext::OpenOptionsExt;
        options.mode(create_mode & super::PERMISSION_BITS_MASK);
    }
    parent.open_with(name, &options)
}

/// Applies the standard per-file flush used while extracting a directory.
/// On Linux and macOS this is plain `fsync(2)`; on Windows and other
/// targets it is `sync_all`.
///
/// On macOS, plain `fsync` sends the file's contents and permission bits
/// to the drive but does not force its volatile cache to persistent
/// storage. Directory extraction therefore MUST call
/// [`sync_extraction_barrier`] after all per-file and per-directory
/// flushes and before promotion. That final call pays for one
/// `F_FULLFSYNC` per operation rather than one per file. `fdatasync`
/// cannot replace this helper because it does not promise to flush the
/// permission bits applied immediately before it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn sync_file_standard(file: &File) -> io::Result<()> {
    crate::fs::atomic::fsync_uninterrupted(file)
}

/// On targets without the `rustix` `fsync` path, `sync_all` is the only
/// flush available; on Windows that is `FlushFileBuffers`.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn sync_file_standard(file: &File) -> io::Result<()> {
    file.sync_all()
}

/// Strongest available flush for a single-file extraction.
///
/// A single-file root has no per-entry scaling cost, so it keeps the
/// original `sync_all` behavior: macOS `F_FULLFSYNC`, Linux `fsync`, and
/// Windows `FlushFileBuffers`. Filesystems that reject the macOS full
/// flush fall back to plain `fsync`, matching the encrypted-output and
/// key-file durability policy.
pub(crate) fn sync_single_file_durable(file: &File) -> io::Result<()> {
    match file.sync_all() {
        Ok(()) => Ok(()),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Err(e) if crate::fs::atomic::errno_not_supported(&e) => {
            crate::fs::atomic::fsync_uninterrupted(file)
        }
        Err(e) => Err(e),
    }
}

/// Sets the rwx permission bits on an already-open file handle.
/// Special bits (setuid/setgid/sticky) are stripped — extraction never
/// honors a manifest-stored special bit, so callers can pass the raw header
/// mode without pre-masking. Handle-based, so a substituted symlink
/// after the open cannot redirect the chmod. Unix-only; on Windows
/// the operation is a no-op (manifest-stored Unix modes don't apply).
#[cfg(unix)]
pub(crate) fn chmod_file_handle(file: &File, mode: u32) -> Result<(), CryptoError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode & super::PERMISSION_BITS_MASK);
    file.set_permissions(cap_std::fs::Permissions::from_std(perms))
        .map_err(CryptoError::Io)
}

#[cfg(not(unix))]
pub(crate) fn chmod_file_handle(_file: &File, _mode: u32) -> Result<(), CryptoError> {
    Ok(())
}

/// Sets the rwx permission bits on an already-open directory handle.
/// Routes through `Dir::set_permissions(".", perm)` so the chmod
/// stays rooted in the capability `dir` already grants — see
/// [`chmod_dir_via_self_path`] for why we cannot just `fchmod` the
/// underlying fd on Linux. Unix-only; no-op on Windows.
///
/// Consumes the `Dir` because every caller (writer-side initial mode,
/// decrypt-side deferred dir-permissions loop) uses the handle once
/// and immediately drops it; making the consumption explicit prevents
/// callers from accidentally reusing the handle after a chmod that
/// might have made the directory unreadable to the holder.
#[cfg(unix)]
pub(crate) fn chmod_dir_handle(dir: Dir, mode: u32) -> Result<(), CryptoError> {
    chmod_dir_via_self_path(&dir, mode)
}

#[cfg(not(unix))]
pub(crate) fn chmod_dir_handle(_dir: Dir, _mode: u32) -> Result<(), CryptoError> {
    Ok(())
}

/// Gives the owner back read, write, and search permission on a
/// directory the run created, named relative to its parent handle, so
/// failure cleanup can remove the run's own entries whatever mode the
/// extraction applied. The directory goes back to [`DIR_CREATE_MODE`],
/// the mode it was created with.
///
/// The change is made by name from the parent rather than through a
/// handle of the directory's own, because a directory left without read
/// permission cannot be opened for reading at all. The call needs search
/// permission on `parent` — which cleanup restores first, parents before
/// children — and ownership of the directory, nothing on the directory
/// itself.
///
/// cap-std opens the name with `O_PATH`, which no mode refuses, and
/// applies the mode through `/proc/self/fd`. A name that resolves to a
/// symlink is followed only within `parent`'s own sandbox, so nothing
/// outside the staged tree can receive the mode.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn restore_owner_access(parent: &Dir, name: &OsStr) -> io::Result<()> {
    use cap_std::fs::PermissionsExt;
    parent.set_permissions(name, cap_std::fs::Permissions::from_mode(DIR_CREATE_MODE))
}

/// macOS arm of [`restore_owner_access`]. cap-std's route opens the name
/// for reading before it changes the mode, which a directory without
/// read permission refuses, so the mode is set with `fchmodat` instead,
/// which opens nothing. `SYMLINK_NOFOLLOW` keeps a symlink at the name
/// from redirecting the change: macOS then changes the link itself,
/// which still touches nothing outside the staged tree.
#[cfg(target_os = "macos")]
pub(crate) fn restore_owner_access(parent: &Dir, name: &OsStr) -> io::Result<()> {
    use std::os::fd::AsFd;

    use rustix::fs::{AtFlags, Mode, RawMode, chmodat};

    chmodat(
        parent.as_fd(),
        name,
        Mode::from_bits_truncate(DIR_CREATE_MODE as RawMode),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)
}

/// [`chmod_dir_handle`] with the new mode covered by a flush, used for
/// staged descendant directories during extraction.
///
/// The handle used for the flush is opened before the chmod, while the
/// directory still has the permissive staging mode: a stored mode without read
/// permission (`0o311`, for example) would make a later open fail. The
/// flush then runs after the chmod and covers the new mode as well as
/// the directory entries, so a staged directory is as durable as a
/// staged file, whose mode is also applied before its flush. Permission
/// is checked when a handle is opened, not when it is used, so the
/// restrictive mode does not affect the flush.
///
/// A failed flush is ignored, as in [`sync_dir_handle`]: a durability
/// hint must not turn a completed extraction into an error. A failed
/// chmod is returned.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn chmod_dir_handle_durable(dir: Dir, mode: u32) -> Result<(), CryptoError> {
    let sync_fd = open_dir_sync_fd(&dir).ok();
    chmod_dir_handle(dir, mode)?;
    if let Some(sync_fd) = sync_fd {
        let _ = crate::fs::atomic::fsync_uninterrupted(&sync_fd);
    }
    Ok(())
}

/// On targets where [`sync_dir_handle`] does nothing there is no flush to
/// place after the chmod, so this is a plain [`chmod_dir_handle`].
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn chmod_dir_handle_durable(dir: Dir, mode: u32) -> Result<(), CryptoError> {
    chmod_dir_handle(dir, mode)
}

/// Test helper that creates an NTFS junction (mount point) through
/// `mklink /J`, which needs no privilege on a standard Windows account.
/// Junctions are reparse points that `is_symlink()` does not report, so
/// they are the case the explicit `FILE_ATTRIBUTE_REPARSE_POINT` checks
/// exist for; the helper is shared by the archive writer, reader, and
/// primitive tests. Returns the failure so a caller can skip where the
/// command is unavailable.
#[cfg(all(test, windows))]
pub(crate) fn try_make_junction(target: &Path, junction: &Path) -> io::Result<()> {
    // `output` captures what `mklink` prints, keeping test output clean.
    let output = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(junction)
        .arg(target)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "mklink /J failed with exit code {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    //! Adversarial scenarios for the hardened extractor primitives.
    //! Unix tests create POSIX symlinks; Windows tests below create
    //! Windows symlinks and NTFS junctions under `cfg(windows)`.
    use super::*;

    use std::ffi::OsStr;
    use std::fs;
    use std::path::Path;

    // ── cross-sandbox scenarios (every backend must reject) ─────────

    #[cfg(unix)]
    #[test]
    fn open_dir_at_rel_rejects_symlink_to_outside() {
        use std::os::unix::fs as unix_fs;
        let tmp = tempfile::TempDir::new().unwrap();
        unix_fs::symlink("/tmp", tmp.path().join("evil")).unwrap();

        let parent = open_anchor(tmp.path()).unwrap();
        let err = open_dir_at_rel(&parent, Path::new("evil")).unwrap_err();
        assert!(
            err.to_string().contains("Symlink in extraction path"),
            "expected symlink-path diagnostic, got: {err}"
        );
    }

    // ── in-sandbox symlink scenarios ────────

    /// `open_child_dir_nofollow` is also the open step the writer uses
    /// for its source root. A symlink at the name must reject with the
    /// caller-supplied encode-side label rather than being followed.
    #[cfg(unix)]
    #[test]
    fn open_child_dir_nofollow_rejects_symlink_with_archive_label() {
        use std::os::unix::fs as unix_fs;
        let tmp = tempfile::TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("real")).unwrap();
        unix_fs::symlink("real", tmp.path().join("link")).unwrap();

        let parent = open_anchor(tmp.path()).unwrap();
        let err = open_child_dir_nofollow(&parent, OsStr::new("link"), SYMLINK_IN_ARCHIVE_SOURCE)
            .unwrap_err();
        assert!(
            err.to_string().contains("Symlink in archive source"),
            "expected encode-side symlink diagnostic, got: {err}"
        );
    }

    /// Opening an ordinary file returns a usable regular-file handle on every
    /// platform. The Unix non-blocking flag must not affect this path.
    #[test]
    fn open_file_nofollow_opens_regular_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(tmp.path().join("plain.txt"), b"content").unwrap();

        let parent = open_anchor(tmp.path()).unwrap();
        let file = open_file_nofollow(&parent, OsStr::new("plain.txt")).unwrap();
        assert!(file.metadata().unwrap().is_file());
    }

    /// The staged-file flush must work on the handles extraction uses, so
    /// a target whose `fsync` rejects one fails here rather than part-way
    /// through a real extraction.
    #[test]
    fn extraction_syncs_succeed_on_created_entries() {
        use std::io::Write;

        let tmp = tempfile::TempDir::new().unwrap();
        let parent = open_anchor(tmp.path()).unwrap();

        let mut single =
            create_file_at(&parent, OsStr::new("single"), INITIAL_FILE_CREATE_MODE).unwrap();
        single.write_all(b"content").unwrap();
        sync_single_file_durable(&single).unwrap();

        let root = mkdir_strict(&parent, OsStr::new("root")).unwrap();
        let mut child =
            create_file_at(&root, OsStr::new("child"), INITIAL_FILE_CREATE_MODE).unwrap();
        child.write_all(b"content").unwrap();
        sync_file_standard(&child).unwrap();
        sync_dir_handle(&root);
        sync_extraction_barrier(&root).unwrap();
    }

    /// A FIFO must be rejected as non-regular without waiting for a writer.
    /// Completion of the test also verifies that the Unix open is non-blocking.
    #[cfg(unix)]
    #[test]
    fn open_file_nofollow_rejects_fifo_without_blocking() {
        let tmp = tempfile::TempDir::new().unwrap();
        crate::fs::paths::make_fifo(&tmp.path().join("swapped"));

        let parent = open_anchor(tmp.path()).unwrap();
        let err = open_file_nofollow(&parent, OsStr::new("swapped")).unwrap_err();
        assert!(
            err.to_string()
                .contains("Extraction path is no longer a regular file"),
            "expected regular-file rejection, got: {err}"
        );
    }

    /// A directory must be rejected because the helper promises a regular
    /// file. Unix reaches the post-open type check; Windows may reject the
    /// open itself, so the test verifies only that the operation fails.
    #[test]
    fn open_file_nofollow_rejects_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("subdir")).unwrap();

        let parent = open_anchor(tmp.path()).unwrap();
        assert!(open_file_nofollow(&parent, OsStr::new("subdir")).is_err());
    }

    /// In-sandbox relative symlink: hardened helper must reject.
    /// Plain `Dir::open_dir` would FOLLOW this (capability-confined
    /// but not no-follow); the hardened backend uses
    /// `cap_fs_ext::open_dir_nofollow` to refuse symlinks regardless
    /// of where the target resolves.
    #[cfg(unix)]
    #[test]
    fn open_dir_at_rel_rejects_in_sandbox_symlink() {
        use std::os::unix::fs as unix_fs;
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir_all(root.join("real")).unwrap();
        unix_fs::symlink("real", root.join("link")).unwrap();

        let parent = open_anchor(&root).unwrap();
        let err = open_dir_at_rel(&parent, Path::new("link")).unwrap_err();
        assert!(err.to_string().contains("Symlink in extraction path"));
    }

    /// Walk through an in-sandbox symlink. Every intermediate component
    /// goes through `open_dir_nofollow`, so the walker rejects before
    /// any write reaches the symlink target.
    #[cfg(unix)]
    #[test]
    fn walk_to_parent_rejects_in_sandbox_intermediate_symlink() {
        use std::os::unix::fs as unix_fs;
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir_all(root.join("real")).unwrap();
        unix_fs::symlink("real", root.join("link")).unwrap();

        let parent = open_anchor(&root).unwrap();
        let err =
            walk_to_parent(&parent, Path::new("link/file.txt"), WalkSide::Extraction).unwrap_err();
        assert!(err.to_string().contains("Symlink in extraction path"));
        assert!(!root.join("real/file.txt").exists());
    }

    /// Cross-sandbox intermediate symlink (target outside `root`).
    /// `cap-std`'s capability boundary catches this directly; we
    /// still get the typed diagnostic via the post-mortem.
    #[cfg(unix)]
    #[test]
    fn walk_to_parent_rejects_outside_intermediate_symlink() {
        use std::os::unix::fs as unix_fs;
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("root");
        let a = root.join("a");
        fs::create_dir_all(&a).unwrap();
        let victim = tmp.path().join("victim_dir");
        fs::create_dir_all(&victim).unwrap();
        unix_fs::symlink(&victim, a.join("b")).unwrap();

        let parent = open_anchor(&root).unwrap();
        let err =
            walk_to_parent(&parent, Path::new("a/b/file.txt"), WalkSide::Extraction).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("symlink") || err.to_string().contains("path")
        );
        assert!(victim.read_dir().unwrap().next().is_none());
    }

    /// Pre-existing symlink at the file's leaf name fails closed with
    /// `AlreadyExists`. The file's target is not opened or written.
    #[cfg(unix)]
    #[test]
    fn create_file_at_rejects_existing_symlink() {
        use std::os::unix::fs as unix_fs;
        let tmp = tempfile::TempDir::new().unwrap();
        let victim = tmp.path().join("victim.txt");
        fs::write(&victim, "original").unwrap();
        unix_fs::symlink(&victim, tmp.path().join("link.txt")).unwrap();

        let parent = open_anchor(tmp.path()).unwrap();
        let err =
            create_file_at(&parent, OsStr::new("link.txt"), INITIAL_FILE_CREATE_MODE).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&victim).unwrap(), "original");
    }

    /// Dangling symlink at the file's leaf name. Same `AlreadyExists`
    /// rejection — the symlink itself IS the existing entry, even if
    /// its target doesn't exist.
    #[cfg(unix)]
    #[test]
    fn create_file_at_rejects_dangling_symlink() {
        use std::os::unix::fs as unix_fs;
        let tmp = tempfile::TempDir::new().unwrap();
        unix_fs::symlink(
            tmp.path().join("does_not_exist"),
            tmp.path().join("link.txt"),
        )
        .unwrap();

        let parent = open_anchor(tmp.path()).unwrap();
        let err =
            create_file_at(&parent, OsStr::new("link.txt"), INITIAL_FILE_CREATE_MODE).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(!tmp.path().join("does_not_exist").exists());
    }

    /// Relative-symlink escape (`inside/escape -> ../outside`). The
    /// capability boundary stops this even before our post-checks run.
    #[cfg(unix)]
    #[test]
    fn open_dir_at_rel_rejects_relative_escape_symlink() {
        use std::os::unix::fs as unix_fs;
        let tmp = tempfile::TempDir::new().unwrap();
        let inside = tmp.path().join("inside");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&inside).unwrap();
        fs::create_dir_all(&outside).unwrap();
        unix_fs::symlink("../outside", inside.join("escape")).unwrap();

        let parent = open_anchor(&inside).unwrap();
        let result = open_dir_at_rel(&parent, Path::new("escape"));
        assert!(result.is_err());
        assert!(outside.read_dir().unwrap().next().is_none());
    }

    /// A missing intermediate directory fails the walk and is not
    /// created. Extraction pre-creates every directory the validated
    /// manifest declares, so a gap means another process changed the
    /// staged tree; re-creating it would carry the run on into a tree
    /// that no longer holds what was written into it.
    #[test]
    fn walk_to_parent_refuses_a_missing_intermediate_and_creates_nothing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir_all(&root).unwrap();

        let parent = open_anchor(&root).unwrap();
        let result = walk_to_parent(&parent, Path::new("missing/file.txt"), WalkSide::Extraction);
        let err = result.expect_err("a missing intermediate must fail the walk");
        assert!(
            err.to_string().contains(DIRECTORY_MISSING_IN_EXTRACTION),
            "the walk must say the directory went missing, got: {err}"
        );
        assert!(
            !root.join("missing").exists(),
            "the walk must not create the missing directory"
        );
    }

    /// `..` traversal: cap-std refuses it at the syscall boundary
    /// (defense-in-depth — upstream `validate_archive_path_components`
    /// already filters these before they reach the platform layer).
    #[cfg(unix)]
    #[test]
    fn walk_to_parent_rejects_dot_dot_traversal() {
        let tmp = tempfile::TempDir::new().unwrap();
        let inside = tmp.path().join("inside");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&inside).unwrap();
        fs::create_dir_all(&outside).unwrap();

        let parent = open_anchor(&inside).unwrap();
        let result = walk_to_parent(&parent, Path::new("../outside/x.txt"), WalkSide::Extraction);
        assert!(result.is_err());
    }

    // ── deferred chmod scenarios ────────────────────────────────────

    /// Deferred chmod where an attacker has
    /// substituted the freshly-extracted directory with a symlink
    /// between extraction and chmod. The handle-based chmod path
    /// catches this because it re-opens via `open_dir_nofollow`
    /// (which refuses symlinks) before applying the mode to the
    /// resulting `Dir` handle.
    #[cfg(unix)]
    #[test]
    fn deferred_chmod_does_not_follow_substituted_symlink() {
        use std::os::unix::fs as unix_fs;
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir_all(root.join("real")).unwrap();
        fs::set_permissions(root.join("real"), fs::Permissions::from_mode(0o755)).unwrap();
        unix_fs::symlink("real", root.join("extracted")).unwrap();

        let parent = open_anchor(&root).unwrap();
        // open_dir_at_rel then a handle-based chmod is the chmod-time recipe.
        let dir_result = open_dir_at_rel(&parent, Path::new("extracted"));
        assert!(
            dir_result.is_err(),
            "open_dir_at_rel must reject the substituted symlink"
        );

        let real_mode = fs::metadata(root.join("real"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            real_mode, 0o755,
            "real's mode must remain unchanged after rejected re-open"
        );
    }

    /// `chmod_file_handle` applies the mode on the just-created file
    /// handle; never via a path that could resolve through a symlink.
    #[cfg(unix)]
    #[test]
    fn chmod_file_handle_applies_mode_on_handle() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let parent = open_anchor(tmp.path()).unwrap();
        let f = create_file_at(&parent, OsStr::new("plain.bin"), INITIAL_FILE_CREATE_MODE).unwrap();
        chmod_file_handle(&f, 0o640).unwrap();
        drop(f);

        let mode = fs::metadata(tmp.path().join("plain.bin"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640);
    }

    /// `chmod_dir_handle` applies the mode on the directory's open
    /// handle. Special bits in `mode` are stripped via
    /// `PERMISSION_BITS_MASK = 0o777` — extraction never honors
    /// setuid/setgid/sticky.
    #[cfg(unix)]
    #[test]
    fn chmod_dir_handle_strips_special_bits() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let parent = open_anchor(tmp.path()).unwrap();
        let dir = mkdir_strict(&parent, OsStr::new("d")).unwrap();

        chmod_dir_handle(dir, 0o4755).unwrap(); // setuid + 755

        let mode = fs::metadata(tmp.path().join("d"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o755, "setuid bit must be stripped");
    }

    /// `chmod_dir_handle_durable` applies a mode without read permission
    /// and still reports success: the handle it flushes is opened before
    /// the mode is applied, so a directory that can no longer be opened
    /// is not a problem.
    #[cfg(unix)]
    #[test]
    fn chmod_dir_handle_durable_applies_unreadable_mode() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let parent = open_anchor(tmp.path()).unwrap();
        let dir = mkdir_strict(&parent, OsStr::new("d")).unwrap();

        chmod_dir_handle_durable(dir, 0o311).unwrap(); // search-only, no read

        let path = tmp.path().join("d");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o311, "expected mode 0o311, got 0o{mode:o}");

        // Restore read permission so tempdir cleanup can list the
        // directory.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    // ── non-symlink helpers ─────────────────────────────────────────

    /// `mkdir_strict` mirrors the rustix-era behavior: succeed on
    /// fresh names, fail with `AlreadyExists` on any pre-existing
    /// entry.
    #[test]
    fn mkdir_strict_creates_then_rejects_repeat() {
        let tmp = tempfile::TempDir::new().unwrap();
        let parent = open_anchor(tmp.path()).unwrap();

        let _d = mkdir_strict(&parent, OsStr::new("fresh")).unwrap();
        assert!(tmp.path().is_dir());
        assert!(tmp.path().join("fresh").is_dir());

        let err = mkdir_strict(&parent, OsStr::new("fresh")).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("exist"),
            "expected AlreadyExists-style rejection, got: {err}"
        );
    }

    /// A directory and a file this process creates report the same
    /// owner, which is what the staged-root comparison relies on. A
    /// mismatch needs a directory owned by another user and cannot be
    /// produced without privileges; `decode.rs` substitutes the answer
    /// to cover that branch.
    #[cfg(unix)]
    #[test]
    fn objects_this_process_creates_report_the_same_owner() {
        let tmp = tempfile::TempDir::new().unwrap();
        let parent = open_anchor(tmp.path()).unwrap();

        let dir = mkdir_strict(&parent, OsStr::new("d")).unwrap();
        let file = create_file_at(&dir, OsStr::new("f"), INITIAL_FILE_CREATE_MODE).unwrap();

        assert_eq!(compare_owners(&dir, &file).unwrap(), OwnerComparison::Same);
    }

    /// Fresh extraction directories start owner-private so root-level
    /// permission restoration can be deferred until after promotion
    /// without exposing staged plaintext to group/other users.
    #[cfg(unix)]
    #[test]
    fn mkdir_strict_initial_mode_is_owner_private() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let parent = open_anchor(tmp.path()).unwrap();

        let _d = mkdir_strict(&parent, OsStr::new("private")).unwrap();

        let mode = fs::metadata(tmp.path().join("private"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "expected initial mode 0o700, got 0o{mode:o}");
    }

    /// `open_dir_at_rel` with empty `rel` returns a fresh clone of
    /// `root_dir`. The deferred-dir-permissions loop relies on this
    /// to fold the root-directory case into the same call site as
    /// descendant directories — if the helper ever changes to error
    /// or panic on empty paths, root-level dir permissions stop
    /// applying.
    #[test]
    fn open_dir_at_rel_with_empty_rel_returns_root_clone() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir_all(&root).unwrap();

        let root_dir = open_anchor(&root).unwrap();
        let cloned = open_dir_at_rel(&root_dir, Path::new("")).unwrap();

        // The cloned handle points at the same directory: a file
        // created under it must appear at the root's path.
        let _f = create_file_at(&cloned, OsStr::new("via_clone.txt"), 0o600).unwrap();
        assert!(root.join("via_clone.txt").exists());
    }

    // ── handle-relative promotion (FORMAT.md §9.11 step 15) ─────────

    /// `rename_at_no_clobber` resolves both endpoints through the open
    /// `dir` handle, so a swap of the ambient `output_dir` path after the
    /// anchor is opened but before promotion cannot redirect the rename.
    /// Pins review-3's promotion-race fix: the staged content is promoted
    /// in the directory the handle actually refers to, and a decoy
    /// `.incomplete` planted in the swapped-in replacement directory is
    /// never promoted.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn rename_at_no_clobber_anchors_to_handle_across_path_swap() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("root.incomplete"), b"real").unwrap();

        // Open the anchor, THEN swap the path: move the real directory
        // aside (the handle follows the inode) and drop a decoy in its
        // place with an attacker-controlled staged file.
        let handle = open_anchor(&out).unwrap();
        let moved = tmp.path().join("out.moved");
        fs::rename(&out, &moved).unwrap();
        fs::create_dir(&out).unwrap();
        fs::write(out.join("root.incomplete"), b"attacker").unwrap();

        rename_at_no_clobber(
            &handle,
            OsStr::new("root.incomplete"),
            OsStr::new("root"),
            true,
        )
        .unwrap();

        // Promotion landed in the handle's directory (now `moved`), not
        // the swapped-in decoy.
        assert_eq!(fs::read(moved.join("root")).unwrap(), b"real");
        assert!(!moved.join("root.incomplete").exists());
        // The decoy's planted `.incomplete` was never promoted.
        assert!(!out.join("root").exists());
        assert_eq!(fs::read(out.join("root.incomplete")).unwrap(), b"attacker");
    }

    /// `rename_at_no_clobber` keeps no-clobber semantics: an existing
    /// final name is refused atomically with `AlreadyExists`, and both
    /// the staged source and the existing target are left untouched.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn rename_at_no_clobber_refuses_existing_target() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("root.incomplete"), b"new").unwrap();
        fs::write(out.join("root"), b"existing").unwrap();

        let handle = open_anchor(&out).unwrap();
        let err = rename_at_no_clobber(
            &handle,
            OsStr::new("root.incomplete"),
            OsStr::new("root"),
            true,
        )
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(out.join("root")).unwrap(), b"existing");
        assert_eq!(fs::read(out.join("root.incomplete")).unwrap(), b"new");
    }

    // ── claim-then-rename fallback (filesystems without RENAME_EXCL) ─
    //
    // The fallback cannot be triggered through `rename_at_no_clobber`
    // on the filesystems that host `cargo test` (they support the
    // flagged rename), so these tests exercise
    // `rename_at_no_clobber_via_claim` directly. The fs-matrix exFAT
    // lane exercises the full errno-driven dispatch end to end.

    /// File-root fallback promotes the staged file when the final name
    /// is free, and the placeholder claim never survives as a separate
    /// entry.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn via_claim_promotes_file_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(tmp.path().join("root.incomplete"), b"payload").unwrap();

        let handle = open_anchor(tmp.path()).unwrap();
        rename_at_no_clobber_via_claim(
            &handle,
            OsStr::new("root.incomplete"),
            OsStr::new("root"),
            true,
        )
        .unwrap();

        assert_eq!(fs::read(tmp.path().join("root")).unwrap(), b"payload");
        assert!(!tmp.path().join("root.incomplete").exists());
    }

    /// The link move commits the staged file under the final name and
    /// clears the staged name, and refuses an occupied final name
    /// atomically — leaving both that entry and the staged file alone.
    /// Nothing is ever created at the final name that is not the
    /// finished content, so no entry a concurrent writer plants can be
    /// replaced.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn link_no_clobber_commits_without_a_placeholder() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(tmp.path().join("root.incomplete"), b"payload").unwrap();
        fs::write(tmp.path().join("taken"), b"existing").unwrap();
        let handle = open_anchor(tmp.path()).unwrap();

        let outcome =
            link_no_clobber(&handle, OsStr::new("root.incomplete"), OsStr::new("root")).unwrap();
        assert!(
            matches!(outcome, PromotionOutcome::LinkedFile),
            "a link commit must report the route it took"
        );
        assert_eq!(fs::read(tmp.path().join("root")).unwrap(), b"payload");
        assert!(!tmp.path().join("root.incomplete").exists());

        fs::write(tmp.path().join("root.incomplete"), b"payload").unwrap();
        let err = link_no_clobber(&handle, OsStr::new("root.incomplete"), OsStr::new("taken"))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(tmp.path().join("taken")).unwrap(), b"existing");
        assert!(tmp.path().join("root.incomplete").exists());
    }

    /// A staged-name unlink failure is a post-commit outcome, not a reason to
    /// withdraw the final name. The caller reports the retained second link
    /// after ratifying the committed identity. Driven through the injectable
    /// unlink seam because no local filesystem refuses one unlink on demand.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_failed_staged_unlink_keeps_both_complete_links_and_reports() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(tmp.path().join("root.incomplete"), b"payload").unwrap();
        let handle = open_anchor(tmp.path()).unwrap();

        let outcome = link_no_clobber_with_remove(
            &handle,
            OsStr::new("root.incomplete"),
            OsStr::new("root"),
            |_, _| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unlink refused",
                ))
            },
        )
        .unwrap();

        let error = outcome
            .into_staged_link_error()
            .expect("the staged unlink failure must be reported");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            tmp.path().join("root").exists(),
            "the complete final link must not be withdrawn"
        );
        assert_eq!(fs::read(tmp.path().join("root")).unwrap(), b"payload");
        assert_eq!(
            fs::read(tmp.path().join("root.incomplete")).unwrap(),
            b"payload"
        );
    }

    /// `NotFound` from the staged-name unlink is not evidence that the link was
    /// destroyed: a concurrent writer may have renamed it. The outcome must
    /// preserve the hard-link marker so `decode` checks the retained inode.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_renamed_staged_link_keeps_the_link_count_check_after_not_found() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(tmp.path().join("root.incomplete"), b"payload").unwrap();
        let handle = open_anchor(tmp.path()).unwrap();

        let outcome = link_no_clobber_with_remove(
            &handle,
            OsStr::new("root.incomplete"),
            OsStr::new("root"),
            |dir, from| {
                dir.rename(from, dir, "moved-staging-link")?;
                dir.remove_file(from)
            },
        )
        .unwrap();

        assert!(matches!(outcome, PromotionOutcome::LinkedFile));
        assert!(outcome.into_staged_link_error().is_none());
        assert_eq!(fs::read(tmp.path().join("root")).unwrap(), b"payload");
        assert_eq!(
            fs::read(tmp.path().join("moved-staging-link")).unwrap(),
            b"payload"
        );
        assert!(!tmp.path().join("root.incomplete").exists());
    }

    /// The failed staged unlink may have blocked long enough for a concurrent
    /// writer to replace the final entry. The failure path must not remove
    /// that replacement by bare name; it preserves both the writer's entry
    /// and this run's complete staged link.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_failed_staged_unlink_never_removes_a_replaced_final_entry() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(tmp.path().join("root.incomplete"), b"payload").unwrap();
        let handle = open_anchor(tmp.path()).unwrap();

        let outcome = link_no_clobber_with_remove(
            &handle,
            OsStr::new("root.incomplete"),
            OsStr::new("root"),
            |dir, _| {
                dir.remove_file("root")?;
                let mut options = cap_std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                let mut replacement = dir.open_with("root", &options)?;
                use std::io::Write as _;
                replacement.write_all(b"replacement")?;
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "delayed staged unlink refused",
                ))
            },
        )
        .unwrap();

        assert!(outcome.into_staged_link_error().is_some());
        assert_eq!(fs::read(tmp.path().join("root")).unwrap(), b"replacement");
        assert_eq!(
            fs::read(tmp.path().join("root.incomplete")).unwrap(),
            b"payload"
        );
    }

    /// Directory-root fallback promotes the staged tree over the
    /// claimed empty directory, contents intact.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn via_claim_promotes_directory_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let staged = tmp.path().join("root.incomplete");
        fs::create_dir(&staged).unwrap();
        fs::write(staged.join("inner.txt"), b"alpha").unwrap();

        let handle = open_anchor(tmp.path()).unwrap();
        rename_at_no_clobber_via_claim(
            &handle,
            OsStr::new("root.incomplete"),
            OsStr::new("root"),
            false,
        )
        .unwrap();

        assert_eq!(
            fs::read(tmp.path().join("root").join("inner.txt")).unwrap(),
            b"alpha"
        );
        assert!(!staged.exists());
    }

    /// The claim step refuses a pre-existing entry of either kind with
    /// `AlreadyExists`, leaving the existing entry and the staged
    /// source untouched — the same contract as the flagged rename.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn via_claim_refuses_existing_target() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(tmp.path().join("staged-file"), b"new").unwrap();
        fs::create_dir(tmp.path().join("staged-dir")).unwrap();
        fs::write(tmp.path().join("taken-file"), b"existing").unwrap();
        fs::create_dir(tmp.path().join("taken-dir")).unwrap();

        let handle = open_anchor(tmp.path()).unwrap();
        // Every kind combination must refuse: the claim is create_new /
        // mkdir, both of which fail on ANY existing entry.
        for (from, to, is_file) in [
            ("staged-file", "taken-file", true),
            ("staged-file", "taken-dir", true),
            ("staged-dir", "taken-file", false),
            ("staged-dir", "taken-dir", false),
        ] {
            let err =
                rename_at_no_clobber_via_claim(&handle, OsStr::new(from), OsStr::new(to), is_file)
                    .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{from} -> {to}");
        }
        assert_eq!(
            fs::read(tmp.path().join("taken-file")).unwrap(),
            b"existing"
        );
        assert_eq!(fs::read(tmp.path().join("staged-file")).unwrap(), b"new");
        assert!(tmp.path().join("staged-dir").is_dir());
    }

    /// A failed rename step removes the placeholder claim and leaves
    /// the staged entry in place, so retain-on-error semantics and
    /// retry-ability hold. Forced by staging nothing: the claim
    /// succeeds, then the rename fails with `NotFound`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn via_claim_removes_claim_when_rename_fails() {
        let tmp = tempfile::TempDir::new().unwrap();
        let handle = open_anchor(tmp.path()).unwrap();

        for is_file in [true, false] {
            let err = rename_at_no_clobber_via_claim(
                &handle,
                OsStr::new("missing.incomplete"),
                OsStr::new("root"),
                is_file,
            )
            .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::NotFound);
            assert!(
                !tmp.path().join("root").exists(),
                "claim must not survive a failed promotion (is_file={is_file})"
            );
        }
    }

    /// The fallback resolves the claim and the rename through the open
    /// handle, so a swap of the ambient path cannot redirect the
    /// promotion — the same anchoring contract as the flagged rename.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn via_claim_anchors_to_handle_across_path_swap() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("root.incomplete"), b"real").unwrap();

        let handle = open_anchor(&out).unwrap();
        let moved = tmp.path().join("out.moved");
        fs::rename(&out, &moved).unwrap();
        fs::create_dir(&out).unwrap();
        fs::write(out.join("root.incomplete"), b"attacker").unwrap();

        rename_at_no_clobber_via_claim(
            &handle,
            OsStr::new("root.incomplete"),
            OsStr::new("root"),
            true,
        )
        .unwrap();

        assert_eq!(fs::read(moved.join("root")).unwrap(), b"real");
        assert!(!moved.join("root.incomplete").exists());
        assert!(!out.join("root").exists());
        assert_eq!(fs::read(out.join("root.incomplete")).unwrap(), b"attacker");
    }

    // ── Windows reparse-point / symlink rejection ───────────────────
    //
    // **Strict-mode CI flag.** Windows symlink creation requires
    // `SeCreateSymbolicLinkPrivilege` (Developer Mode or admin). On
    // local dev boxes without that privilege, the symlink_dir tests
    // silently skip — convenient for `cargo test` from an unprivileged
    // shell, but DANGEROUS for CI where a green run might mean "no
    // assertions executed". Set
    // `FERROCRYPT_REQUIRE_WINDOWS_SYMLINK_TESTS=1` in the Windows CI
    // environment to fail closed on a missing privilege rather than
    // skipping. The repo's `.github/workflows/rust.yml` sets this on
    // the windows-latest matrix entry.
    //
    // The junction (`mklink /J`) tests do NOT require elevated
    // privileges and run unconditionally on Windows CI.

    /// Skip-or-fail-closed helper. In strict mode (CI) a missing
    /// privilege panics; otherwise it returns `None` and the test
    /// returns early.
    #[cfg(windows)]
    fn require_or_skip<T>(label: &str, result: io::Result<T>) -> Option<T> {
        match result {
            Ok(t) => Some(t),
            Err(e) => {
                if std::env::var_os("FERROCRYPT_REQUIRE_WINDOWS_SYMLINK_TESTS").is_some() {
                    panic!("{label} required by CI but failed: {e}");
                }
                eprintln!(
                    "{label} unavailable ({e}); skipping. \
                     Set FERROCRYPT_REQUIRE_WINDOWS_SYMLINK_TESTS=1 in CI to fail closed."
                );
                None
            }
        }
    }

    /// Windows symlink-dir at the leaf of an `open_dir_at_rel` call.
    /// Hardened helper must reject — same invariant as Unix.
    #[cfg(windows)]
    #[test]
    fn open_dir_at_rel_rejects_windows_symlink_dir() {
        use std::os::windows::fs as win_fs;
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("target_dir");
        fs::create_dir_all(&target).unwrap();
        if require_or_skip(
            "symlink_dir",
            win_fs::symlink_dir(&target, tmp.path().join("link")),
        )
        .is_none()
        {
            return;
        }

        let parent = open_anchor(tmp.path()).unwrap();
        let _err = open_dir_at_rel(&parent, Path::new("link")).unwrap_err();
    }

    /// Windows symlink-dir mid-path. Hardened walk must reject before
    /// any write reaches the target.
    #[cfg(windows)]
    #[test]
    fn walk_through_windows_symlink_dir_rejects() {
        use std::os::windows::fs as win_fs;
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir_all(root.join("real")).unwrap();
        if require_or_skip(
            "symlink_dir",
            win_fs::symlink_dir("real", root.join("link")),
        )
        .is_none()
        {
            return;
        }

        let parent = open_anchor(&root).unwrap();
        let result = walk_to_parent(&parent, Path::new("link/file.txt"), WalkSide::Extraction);
        assert!(
            result.is_err(),
            "hardened walk MUST reject Windows symlink-dir in path"
        );
        assert!(
            !root.join("real/file.txt").exists(),
            "real subdir must remain empty"
        );
    }

    /// Windows symlink-file at file leaf. cap-std `create_new` + the
    /// explicit `FollowSymlinks::No` flag should reject as
    /// `AlreadyExists`.
    #[cfg(windows)]
    #[test]
    fn create_file_at_rejects_windows_symlink_file() {
        use std::os::windows::fs as win_fs;
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("target.txt");
        fs::write(&target, "original").unwrap();
        if require_or_skip(
            "symlink_file",
            win_fs::symlink_file(&target, tmp.path().join("link.txt")),
        )
        .is_none()
        {
            return;
        }

        let parent = open_anchor(tmp.path()).unwrap();
        let err =
            create_file_at(&parent, OsStr::new("link.txt"), INITIAL_FILE_CREATE_MODE).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
    }

    /// NTFS junction at a directory
    /// name. Junctions are reparse points whose `is_symlink()` is
    /// FALSE, so cap-fs-ext's `open_dir_nofollow` does NOT reject them
    /// on its own — the explicit `FILE_ATTRIBUTE_REPARSE_POINT`
    /// post-check in [`finalize_dir_open`] is what catches this.
    /// `mklink /J` does not require elevated privileges, so this
    /// runs on any standard Windows account in CI.
    #[cfg(windows)]
    #[test]
    fn open_dir_at_rel_rejects_windows_junction() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("target");
        fs::create_dir_all(&target).unwrap();
        let junction = tmp.path().join("junction");

        if require_or_skip("mklink /J", try_make_junction(&target, &junction)).is_none() {
            return;
        }

        let parent = open_anchor(tmp.path()).unwrap();
        let err = open_dir_at_rel(&parent, Path::new("junction")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Symlink in extraction path"),
            "junction must be rejected with the symlink-path diagnostic, got: {msg}"
        );
    }

    /// Walk-through-junction: an attacker who plants a junction
    /// mid-path under `.incomplete/` redirects per-entry walk writes
    /// through the junction target. The reparse-point post-check on
    /// every `open_dir_nofollow` step rejects this.
    #[cfg(windows)]
    #[test]
    fn walk_through_windows_junction_rejects() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir_all(root.join("real")).unwrap();
        let junction = root.join("link");

        if require_or_skip(
            "mklink /J",
            try_make_junction(&root.join("real"), &junction),
        )
        .is_none()
        {
            return;
        }

        let parent = open_anchor(&root).unwrap();
        let result = walk_to_parent(&parent, Path::new("link/file.txt"), WalkSide::Extraction);
        assert!(
            result.is_err(),
            "hardened walk MUST reject NTFS junction in path"
        );
        assert!(
            !root.join("real/file.txt").exists(),
            "real subdir must remain empty after junction-walk rejection"
        );
    }
}
