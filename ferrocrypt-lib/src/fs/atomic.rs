//! Atomic output finalization helpers.
//!
//! This module centralizes the path-based "write under a temp name,
//! promote to the final name only on success" pattern used throughout
//! the crate for encrypted-file output, generated key files, and the
//! Windows / other-target decrypt-promotion fallback.
//!
//! Linux and macOS archive decrypt promotion is deliberately not owned
//! here: `archive::platform::rename_at_no_clobber` performs that commit
//! handle-relative to the extraction directory, so a mid-run path swap
//! cannot redirect it.
//!
//! Four primitives are provided:
//!
//! - [`finalize_file`] — promote a [`tempfile::NamedTempFile`] through a
//!   caller-retained output-directory anchor. Used by key generation on every
//!   target and by encrypted output on Linux/macOS.
//! - `finalize_file_path_based` — keep encrypted output's existing
//!   path-based commit on the other targets, without adding a directory-open
//!   requirement their primary backend cannot use.
//! - [`promote_single_file_no_clobber`] — promote a staged single-file
//!   `.incomplete` path to its final name with atomic no-clobber semantics
//!   on every supported platform, Windows included. Used by archive
//!   extraction only on Windows / other non-Linux/macOS targets; Linux and
//!   macOS use `archive::platform::rename_at_no_clobber` instead.
//! - [`rename_no_clobber`] — path-based rename of a staged `.incomplete`
//!   entry (directory or regular file) to its final name with no-clobber
//!   semantics. Used by archive extraction for directory roots only on
//!   Windows / other non-Linux/macOS targets; Linux and macOS decrypt
//!   promotion is handle-relative in `archive::platform`.
//!
//! Two durability helpers support these operations. [`sync_file_durable`]
//! flushes staged encrypted output and key files before promotion; archive
//! extraction has its own flush. [`sync_dir_durable`] flushes
//! directory entries and reports failures; it is key generation's required
//! barrier on Windows and the other targets, while Linux and macOS use
//! [`OutputDir::flush_durable`] so the barrier follows the handle the key
//! files were committed through. [`sync_parent_dir`] remains best-effort for
//! outputs whose loss can be recovered.
//!
//! [`OutputDir`] retains a handle to the directory an operation publishes
//! into. Cleanup after a failed commit goes through that handle, so it
//! removes the entry the operation created rather than whatever its path
//! happens to name once the operation is already under way.
//!
//! **Zero in-repo unsafe.** On Linux and macOS the file cases issue
//! `rustix::renameat_with(..., RenameFlags::NOREPLACE)` themselves
//! through [`crate::fs::commit`], relative to one retained
//! [`OutputDir`]; Windows and the other Unix targets delegate to
//! `tempfile`, which is atomic-no-replace on Windows (`MoveFileExW`
//! without the replace flag). Where the filesystem cannot perform a
//! no-replace rename, the Unix fallback is [`crate::fs::commit`]'s
//! handle-relative link, claim, and rename operations, anchored to that
//! same handle. The directory rename case in [`rename_no_clobber`]
//! delegates to `rustix` directly on Linux and macOS, and on Windows uses
//! `symlink_metadata()` + `std::fs::rename`, which keeps the crate
//! zero-unsafe but offers a narrower best-effort no-clobber guarantee
//! for directory promotion on that target.

use std::io;
use std::path::Path;

use tempfile::NamedTempFile;

use crate::CryptoError;
use crate::error::sanitize_path_for_display;
#[cfg(unix)]
use crate::fs::commit::{CommitFailure, CommitKind, CommitRoute};
use crate::fs::paths::already_exists_error;

/// A file whose commit completed, keeping the committed handle alive. It
/// is used, on every platform, to confirm immediately before returning
/// that the reported path still denotes this object and that the commit
/// left exactly one name for the committed file — `tempfile`'s own
/// persist can fall back on Unix to a hard link whose staged-name unlink
/// result it discards, and a link a local writer creates against the
/// staged temporary before the commit survives it anywhere — and by a
/// key-generation rollback to confirm that the entry it removes is still
/// this file. On Windows the rollback deletes the file through this
/// handle, which relies on `tempfile` opening a named temporary with the
/// default sharing mode; that mode admits the delete-access reopen, unlike
/// the exclusive mode of its unnamed temporaries.
#[derive(Debug)]
pub(crate) struct FinalizedFile {
    file: std::fs::File,
}

impl FinalizedFile {
    fn new(file: std::fs::File) -> Self {
        Self { file }
    }

    /// Confirms that `path`, the value a writer is about to report, still
    /// denotes this committed file. A final-entry replacement, or a
    /// directory swap where the platform permits one while the handle is
    /// open, can otherwise make the returned path lead to
    /// attacker-controlled bytes. A path that no longer exists counts as
    /// changed too: the commit created an entry there, so its absence
    /// means the name no longer denotes the output — the same rule the
    /// decrypt side applies.
    pub(crate) fn confirm_reported_path(&self, path: &Path) -> Result<(), CryptoError> {
        let committed = cap_std::fs::Metadata::from_file(&self.file).map_err(CryptoError::Io)?;
        let reported = match reported_entry_metadata(path) {
            Ok(reported) => reported,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(reported_output_changed(path));
            }
            Err(e) => return Err(CryptoError::Io(e)),
        };
        if !reported.is_file() || identities_differ(&reported, &committed) {
            return Err(reported_output_changed(path));
        }
        Ok(())
    }

    /// Requires the commit to have left exactly one name for the committed
    /// file before success is reported. Reading through the retained
    /// handle makes this independent of concurrent renames or replacements of
    /// either directory entry.
    fn confirm_single_link(&self, path: &Path) -> Result<(), CryptoError> {
        use cap_fs_ext::MetadataExt;

        let link_count = cap_std::fs::Metadata::from_file(&self.file)
            .map_err(CryptoError::Io)?
            .nlink();
        if link_count != 1 {
            return Err(committed_link_count_error(
                &sanitize_path_for_display(path),
                link_count,
            ));
        }
        Ok(())
    }
}

/// Identity of a filesystem object: the device and inode number on Unix,
/// the volume serial number and the 64-bit file index on Windows.
/// Comparing the object behind a retained handle with the entry under a
/// name catches a final-name replacement, and a parent-directory swap
/// where the platform permits one, before an operation reports that
/// path. The decrypt side reads the same pair through
/// `archive::platform::ObjectId`.
///
/// `None` where the inode number or file index is zero: a filesystem
/// that assigns none reports zero for every object, so the value says
/// nothing about which object was read. Every comparison in this crate
/// treats that as evidence it does not have — it skips the comparison
/// where skipping only forgoes a check, and reports an action it cannot
/// confirm where acting would mean removing an entry — never as a
/// match (`THREAT_MODEL.md` §7.4).
///
/// Every comparison in this crate is between objects that both exist
/// when it runs — a retained handle, or a link just made, keeps the
/// recorded one alive — because a filesystem may reuse an identifier once
/// its object is gone, and two live objects on one volume never share
/// one. What remains is documented in `SECURITY.md`: ReFS reports a
/// 64-bit truncation of a wider identifier, and a filesystem that
/// assigns one non-zero identifier to every object — some network
/// redirectors — makes every comparison hold, so these checks detect
/// nothing there rather than fail.
///
/// `metadata` must come from an open handle —
/// [`cap_std::fs::Metadata::from_file`], or a cap-std stat, which opens
/// the entry itself — or, on Unix, from a `std` stat converted with
/// `from_just_metadata`. cap-std fills the Windows fields only from an
/// open handle, and its accessors panic where they are absent; the crate
/// never reads an identity out of a directory listing.
pub(crate) fn file_identity(metadata: &cap_std::fs::Metadata) -> Option<FileIdentity> {
    use cap_fs_ext::MetadataExt;

    identity_pair(metadata.dev(), metadata.ino())
}

/// The pair [`file_identity`] reads: device and inode number on Unix,
/// volume serial number and file index on Windows.
pub(crate) type FileIdentity = (u64, u64);

/// The rule behind [`file_identity`]: a zero inode number or file index
/// is no identity.
fn identity_pair(dev: u64, ino: u64) -> Option<FileIdentity> {
    (ino != 0).then_some((dev, ino))
}

/// Whether two metadata values are shown to describe different objects
/// by their [`file_identity`]. Where either carries none the objects
/// cannot be told apart, and this answers `false`, so a check that only
/// refuses on a difference is skipped; a caller that would act on a
/// match reads the identities itself.
pub(crate) fn identities_differ(a: &cap_std::fs::Metadata, b: &cap_std::fs::Metadata) -> bool {
    match (file_identity(a), file_identity(b)) {
        (Some(a), Some(b)) => a != b,
        _ => false,
    }
}

/// Metadata of the entry at `path` without following a final symlink,
/// carrying its identity. Unix reads it with `lstat`, which needs only
/// search permission on the parent.
#[cfg(unix)]
fn reported_entry_metadata(path: &Path) -> io::Result<cap_std::fs::Metadata> {
    std::fs::symlink_metadata(path).map(cap_std::fs::Metadata::from_just_metadata)
}

/// Windows counterpart of the Unix `lstat`: the entry is opened without
/// following a symlink or reparse point, requesting no access — the open
/// `std` performs for `symlink_metadata`, which needs only traversal of
/// the parent — and its identity is read from that handle, because a
/// `std` metadata value carries none on stable Rust. A symlink or
/// junction at the path is the reparse point itself, which the caller's
/// regular-file test rejects.
#[cfg(windows)]
fn reported_entry_metadata(path: &Path) -> io::Result<cap_std::fs::Metadata> {
    use std::os::windows::fs::OpenOptionsExt;

    let entry = std::fs::OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    cap_std::fs::Metadata::from_file(&entry)
}

/// `CreateFileW` flag without which a directory cannot be opened.
#[cfg(windows)]
pub(crate) const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// `CreateFileW` flag that opens a symlink or other reparse point itself
/// instead of following it.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

fn reported_output_changed(path: &Path) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "Output is complete but its reported path changed: {}",
        sanitize_path_for_display(path)
    ))
}

/// Post-commit failure for a committed file with a link count other than
/// one. The retained handle, rather than either mutable name, supplies the
/// count. The message reports the count alone, because the operation cannot
/// tell a name its own hard-link fallback left from one a local writer made
/// against the staged file before the commit. `display_name` must already be
/// safe to render. Shared with archive extraction so the writer and the
/// reader report this condition in the same words.
pub(crate) fn committed_link_count_error(display_name: &str, link_count: u64) -> CryptoError {
    CryptoError::Io(io::Error::other(format!(
        "Output {display_name} is complete, but has {link_count} filesystem names (expected 1)",
    )))
}

/// What an identity-checked removal did with a file this operation wrote,
/// either an already committed key file or its still-staged sibling. Only
/// [`Self::Removed`] needs no report: every other outcome means that file may
/// still exist, and the returned error says so since nothing else reaches the
/// caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RollbackOutcome {
    /// The retained file was removed, and its name was the only one it had.
    Removed,
    /// The retained file's name was removed, but the file had `link_count`
    /// names at that moment, so it survives under the others.
    RemovedButLinked { link_count: u64 },
    /// The entry under the name is no longer the retained file and was left
    /// in place; the retained file survives under whatever name it was moved
    /// to, if any.
    Replaced,
    /// Nothing was removed: the name is gone, an identity could not be
    /// read, or the removal itself failed.
    Unconfirmed,
}

impl RollbackOutcome {
    /// The clause appended to the operation's error, or `None` when the
    /// rollback removed the file completely.
    fn report(self, path: &Path) -> Option<String> {
        let shown = final_component_for_display(path);
        Some(match self {
            Self::Removed => return None,
            Self::RemovedButLinked { link_count } => format!(
                "the removed {shown} had {link_count} filesystem names, so a copy may remain under another name"
            ),
            Self::Replaced => format!(
                "{shown} was replaced during the operation and left in place, and the file this run wrote may remain under another name"
            ),
            Self::Unconfirmed => format!("the removal of {shown} could not be confirmed"),
        })
    }
}

/// The final component of `path`, escaped and bounded for a message.
/// Both failure reports in this module name a file that way: the caller
/// chose the directory and knows it already.
fn final_component_for_display(path: &Path) -> String {
    let name = path.file_name().unwrap_or(path.as_os_str());
    crate::error::sanitize_for_display(&name.to_string_lossy())
}

/// Appends a removal's report to the error the operation is already
/// returning, through [`crate::error::append_report`]; a removal that
/// took the file away completely returns `error` unchanged. Serves the
/// rollback of a committed key file and the removal of its still-staged
/// sibling alike: in either case the fact that matters is whether a
/// file this run wrote may remain.
pub(crate) fn with_rollback_report(
    error: CryptoError,
    outcome: RollbackOutcome,
    path: &Path,
) -> CryptoError {
    match outcome.report(path) {
        Some(report) => crate::error::append_report(error, &report),
        None => error,
    }
}

/// Failure from [`finalize_file`], retaining whether the file reached a final
/// name before the error. Key generation needs that distinction: if
/// `public.key` committed and only a post-commit verification failed, rolling
/// back `private.key` would leave an unsafe public-only pair.
#[derive(Debug)]
pub(crate) struct FinalizeFileError {
    error: CryptoError,
    committed: bool,
}

impl FinalizeFileError {
    fn before_commit(error: CryptoError) -> Self {
        Self {
            error,
            committed: false,
        }
    }

    fn after_commit(error: CryptoError) -> Self {
        Self {
            error,
            committed: true,
        }
    }

    #[cfg(test)]
    pub(crate) fn after_commit_for_test(error: CryptoError) -> Self {
        Self::after_commit(error)
    }

    /// Whether a final name was created before this error.
    pub(crate) fn committed(&self) -> bool {
        self.committed
    }

    /// Returns the caller-visible error.
    pub(crate) fn into_crypto_error(self) -> CryptoError {
        self.error
    }
}

/// Best-effort parent-directory sync used after a successful file persist or
/// directory rename. This slightly improves durability after the final path
/// becomes visible.
///
/// Routes through [`sync_dir_durable`] and drops its result. Sharing that
/// helper keeps the open hardened: the parent is opened as a directory, so a
/// path replaced by a FIFO or a device node between publication and this call
/// is refused rather than opened. Opening such an object for reading would
/// otherwise wait for a writer, and there is no error for a best-effort
/// helper to swallow while the open itself is still blocked.
///
/// Failures are intentionally ignored here:
/// - not every filesystem supports syncing directories cleanly
/// - finalization has already succeeded by the time this runs
/// - returning an error after the final path is visible would be more
///   confusing to callers than helpful
///
/// Callers that require directory-flush failures to be reported call
/// [`sync_dir_durable`] directly.
#[cfg(any(unix, windows))]
fn sync_parent_dir(path: &Path) {
    let _ = sync_dir_durable(crate::fs::paths::parent_or_cwd(path));
}

#[cfg(not(any(unix, windows)))]
fn sync_parent_dir(_path: &Path) {}

/// Promotes a `NamedTempFile` to its final path with no-clobber semantics.
/// Linux and macOS resolve the commit through the destination-directory
/// anchor the caller retained before staging. Other targets retain their
/// path-based primary persist; key generation still supplies its readable
/// anchor for rollback, durability, and the other-Unix compatibility
/// fallback. An occupied final path rejects with the same typed
/// `InvalidInput("<label> already exists: …")` message the pre-write
/// occupancy check emits, so a path that becomes occupied between the
/// preflight and this rename reports the same error class. Other
/// failures surface as [`CryptoError::Io`]. A failure before publication
/// removes the temp file best-effort. A failure after publication is marked
/// by [`FinalizeFileError::committed`]; the final entry is kept because a
/// bare-name rollback could delete a concurrent replacement.
///
/// On Linux and macOS the anchor is a parameter rather than something opened
/// here because its lifetime is the guarantee: a handle opened at the commit
/// would denote whatever occupies the output path by then, and a local writer
/// who moves the staged entry into a directory of their own and installs it at
/// that path would have the commit land there. Held from before staging, the
/// handle stays bound to the directory the operation began in, and a staged
/// entry moved out of it is refused.
///
/// The promotion is a single atomic no-replace rename wherever the
/// filesystem supports one: handle-relative through the anchor on Linux
/// and macOS ([`finalize_file_at`]), by ambient path through `tempfile`
/// elsewhere. Where the filesystem supports no such rename (see
/// [`no_replace_rename_unsupported`]), the Unix fallback commits by
/// linking or, on a filesystem without hard links, by claiming the name
/// and renaming over the claim ([`crate::fs::commit`]). Every route keeps
/// the no-clobber guarantee against entries that predate the commit.
///
/// Callers are expected to have already flushed and synced the temp file
/// before calling this function. Every anchored route requires the temp file
/// to be an entry of the anchored directory; [`OutputDir::confirm_staged`]
/// establishes that at staging time and the route confirms it again here.
pub(crate) fn finalize_file(
    tmp: NamedTempFile,
    final_path: &Path,
    label: &str,
    anchor: &OutputDir,
) -> Result<FinalizedFile, FinalizeFileError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        finalize_file_at(tmp, final_path, label, anchor)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        finalize_by_persist(tmp, final_path, label, Some(anchor))
    }
}

/// Path-based encrypted-output commit for targets whose production backend
/// deliberately remains path-based. Unlike [`finalize_file`], this route does
/// not make the caller open and retain a directory handle that the primary
/// commit cannot use. That preserves the pre-existing output-directory access
/// requirements on Windows and on the other non-Linux/macOS targets.
///
/// A Unix filesystem that rejects `tempfile`'s one-step no-replace persist
/// still reaches the shared link-or-claim compatibility fallback. Only that
/// exceptional route opens the readable directory anchor it needs, matching
/// the behaviour before writer commits became handle-relative on Linux and
/// macOS.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn finalize_file_path_based(
    tmp: NamedTempFile,
    final_path: &Path,
    label: &str,
) -> Result<FinalizedFile, FinalizeFileError> {
    finalize_by_persist(tmp, final_path, label, None)
}

/// `tempfile`'s one-step no-replace persist, the primary route off Linux
/// and macOS. `anchor` is the directory handle the caller retains, where
/// it holds one: the Unix compatibility fallback commits through it, and
/// opens a readable handle of its own where the caller holds none.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn finalize_by_persist(
    tmp: NamedTempFile,
    final_path: &Path,
    label: &str,
    anchor: Option<&OutputDir>,
) -> Result<FinalizedFile, FinalizeFileError> {
    match tmp.persist_noclobber(final_path) {
        Ok(file) => finalized_from_persist(file, final_path),
        Err(e) => finalize_persist_failure(e, final_path, label, anchor),
    }
}

/// The Linux and macOS commit: a no-replace rename resolved through
/// `anchor` ([`crate::fs::commit::rename_no_replace_at`]), falling back
/// to the link-or-claim commit where the filesystem cannot perform one.
///
/// Both endpoints resolve through the retained handle, so a rename or
/// replacement of the output path between staging and the commit cannot
/// redirect it — the same anchoring archive extraction has committed
/// through since it gained one. The staged temporary is confirmed to be
/// the entry under its name in that directory before any step runs, so
/// a temporary moved out of the anchored directory can never commit a
/// same-named entry of some other directory's in its place.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn finalize_file_at(
    tmp: NamedTempFile,
    final_path: &Path,
    label: &str,
    anchor: &OutputDir,
) -> Result<FinalizedFile, FinalizeFileError> {
    use crate::fs::commit::{FlaggedRename, commit_by_link_or_claim, rename_no_replace_at};

    finalize_file_commit(
        tmp,
        final_path,
        label,
        anchor,
        |anchor, staged, final_name| match rename_no_replace_at(anchor, staged, final_name) {
            Ok(FlaggedRename::Committed) => Ok(CommitRoute::Renamed),
            Ok(FlaggedRename::Unsupported) => {
                commit_by_link_or_claim(anchor, staged, final_name, CommitKind::File)
            }
            Err(error) => Err(CommitFailure::plain(error)),
        },
    )
}

/// Completes a successful one-step persist: parent flush, retained
/// committed handle, and the reported-path and single-link confirmations.
///
/// Windows and the other Unix targets only: Linux and macOS commit
/// through [`finalize_file_at`] instead.
/// The link count is required even on this arm because `tempfile` retries
/// a rejected no-replace rename on Unix through a hard link of its own and
/// discards the unlink of the staged name, so its `Ok` alone does not
/// prove the staged name is gone; and on every platform a link a local
/// writer created against the staged temporary before the commit
/// survives it.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn finalized_from_persist(
    file: std::fs::File,
    final_path: &Path,
) -> Result<FinalizedFile, FinalizeFileError> {
    sync_parent_dir(final_path);
    let finalized = FinalizedFile::new(file);
    finalized
        .confirm_reported_path(final_path)
        .map_err(FinalizeFileError::after_commit)?;
    finalized
        .confirm_single_link(final_path)
        .map_err(FinalizeFileError::after_commit)?;
    Ok(finalized)
}

/// Failure arm of [`finalize_by_persist`] on the Unix targets outside
/// Linux and macOS. A filesystem that cannot perform the flagged rename
/// reaches the shared link-or-claim fallback — through `anchor` where the
/// caller holds one, otherwise through a readable handle opened for it —
/// and every other failure is mapped and returned.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn finalize_persist_failure(
    e: tempfile::PersistError,
    final_path: &Path,
    label: &str,
    anchor: Option<&OutputDir>,
) -> Result<FinalizedFile, FinalizeFileError> {
    if no_replace_rename_unsupported(&e.error) {
        return match anchor {
            Some(anchor) => finalize_file_via_link_or_claim_in(e.file, final_path, label, anchor),
            None => finalize_file_via_link_or_claim(e.file, final_path, label),
        };
    }
    Err(FinalizeFileError::before_commit(map_persist_error(
        e.error, final_path, label,
    )))
}

/// No compatibility fallback exists off Unix, so the anchor has no route
/// to serve. In particular, Windows keeps `tempfile`'s path-based atomic
/// no-replace move without first opening the output directory for read
/// access.
#[cfg(not(unix))]
fn finalize_persist_failure(
    e: tempfile::PersistError,
    final_path: &Path,
    label: &str,
    _anchor: Option<&OutputDir>,
) -> Result<FinalizedFile, FinalizeFileError> {
    Err(FinalizeFileError::before_commit(map_persist_error(
        e.error, final_path, label,
    )))
}

/// Maps a failed promotion to the caller-visible error: an occupied
/// final path becomes the typed already-exists message, everything
/// else passes through as [`CryptoError::Io`].
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn map_persist_error(error: io::Error, final_path: &Path, label: &str) -> CryptoError {
    if error.kind() == io::ErrorKind::AlreadyExists {
        already_exists_error(label, final_path)
    } else {
        CryptoError::Io(error)
    }
}

/// Whether an operation failed because the kernel or filesystem does
/// not support it at all, as opposed to an ordinary failure of a
/// supported operation.
///
/// The raw errno values are matched, not just [`io::ErrorKind`],
/// because the std mapping does not cover them on every platform —
/// macOS `ENOTSUP` (45), the error its exFAT and smbfs drivers return
/// for unsupported operations, surfaces as an uncategorized kind.
/// `ENOTSUP` and `EOPNOTSUPP` share a value on Linux but differ on
/// macOS; both are listed and the duplicate arm collapses where equal.
/// [`io::ErrorKind::Unsupported`] covers `ENOSYS` (kernels without the
/// syscall) and synthesized non-OS errors of that kind.
#[cfg(unix)]
pub(crate) fn errno_not_supported(e: &io::Error) -> bool {
    if e.kind() == io::ErrorKind::Unsupported {
        return true;
    }
    matches!(
        e.raw_os_error(),
        Some(code) if code == libc::ENOTSUP || code == libc::EOPNOTSUPP
    )
}

/// Whether a failed no-replace rename means the kernel or filesystem
/// cannot perform one at all, as opposed to an ordinary failure of a
/// supported rename.
///
/// Beyond [`errno_not_supported`] (macOS `renameatx_np(RENAME_EXCL)`
/// on filesystems without the operation — exFAT and smbfs among them —
/// and `hard_link`-based emulation on filesystems without hard links),
/// raw `EINVAL` is included: Linux `renameat2` reports an unsupported
/// `RENAME_NOREPLACE` flag on some filesystems (network and FUSE
/// mounts) as an invalid-flag error. A genuine invalid-argument
/// failure that slips through simply fails again inside the fallback,
/// so the wide trigger cannot weaken the no-clobber guarantee.
///
/// The `EINVAL` arm is load-bearing for every caller that issues the
/// flagged rename itself: [`crate::fs::commit::rename_no_replace_at`],
/// which both the encrypted-output commit and the archive promotion go
/// through on Linux and macOS. Only where `tempfile` performs the
/// rename — Windows and the other Unix targets — is that arm
/// unreachable, because `tempfile` retries `EINVAL` itself through its
/// hard-link emulation.
#[cfg(unix)]
pub(crate) fn no_replace_rename_unsupported(e: &io::Error) -> bool {
    errno_not_supported(e) || e.raw_os_error() == Some(libc::EINVAL)
}

/// Flushes `fd` with `fsync(2)`, retrying on `EINTR`.
///
/// Single source of truth for EINTR handling on the flush paths that
/// call `fsync` directly ([`sync_file_durable`] and [`sync_dir_durable`]
/// here, `archive::platform::sync_file_standard`,
/// `sync_extraction_barrier`, and `sync_dir_handle`). `File::sync_all`
/// retries internally, but `rustix`
/// reports a signal-interrupted call as `EINTR`. Without the retry, a
/// signal arriving during the flush would fail the operation, or leave
/// it silently unflushed where the caller discards the error.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn fsync_uninterrupted<Fd: std::os::fd::AsFd>(fd: Fd) -> io::Result<()> {
    rustix::io::retry_on_intr(|| rustix::fs::fsync(&fd)).map_err(io::Error::from)
}

/// Flushes `file` to stable storage with the strongest primitive the
/// filesystem supports. `File::sync_all` is the primary (on macOS it
/// issues `F_FULLFSYNC`); a filesystem that reports the full flush as
/// unsupported — macOS smbfs among them — falls back to plain
/// `fsync(2)`, which such filesystems do honor. Genuine sync failures
/// surface unchanged; only the capability gap downgrades.
///
/// Directory extraction deliberately does not use this helper per file:
/// it applies `archive::platform::sync_file_standard` to each staged
/// file, then pays for one operation-level full barrier through
/// `sync_extraction_barrier`. Single-file extraction keeps the strongest
/// flush through `archive::platform::sync_single_file_durable`.
pub(crate) fn sync_file_durable(file: &std::fs::File) -> io::Result<()> {
    match file.sync_all() {
        Ok(()) => Ok(()),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Err(e) if errno_not_supported(&e) => fsync_uninterrupted(file),
        Err(e) => Err(e),
    }
}

/// Flushes the directory entries in `dir` to stable storage and reports
/// failures. Flushing a file makes its contents durable, but not the directory
/// entry that names it. A rename or removal is durable only after the
/// directory is flushed.
///
/// Unlike [`sync_parent_dir`], this function returns genuine open or flush
/// failures so callers can stop when durability is required. If the filesystem
/// does not support directory flushing, [`dir_sync_unsupported`] treats that
/// condition as success because no stronger operation is available. In that
/// case, protection from power loss depends on the filesystem; key generation
/// still retains its private-first protection against process interruption.
#[cfg(unix)]
pub(crate) fn sync_dir_durable(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    // `O_DIRECTORY` ensures that `dir` is a directory. A regular file
    // therefore returns `NotADirectory` instead of being flushed, and a
    // substituted FIFO or device node is refused rather than opened.
    // `O_NONBLOCK` keeps that refusal immediate on a platform that
    // checks the directory requirement only after opening the object.
    let handle = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK)
        .open(dir)
    {
        Ok(handle) => handle,
        Err(e) if dir_sync_unsupported(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    flush_dir_handle(&handle)
}

/// Flushes an already-open directory handle. Matches
/// [`sync_file_durable`]: try `sync_all` first, then plain `fsync`
/// where supported, and treat a filesystem that provides no directory
/// flushing as success — no stronger operation exists there. Directory
/// flushing has a wider set of unsupported errors than file flushing.
#[cfg(unix)]
fn flush_dir_handle(handle: &std::fs::File) -> io::Result<()> {
    match handle.sync_all() {
        Ok(()) => Ok(()),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Err(e) if dir_sync_unsupported(&e) => match fsync_uninterrupted(handle) {
            Ok(()) => Ok(()),
            Err(again) if dir_sync_unsupported(&again) => Ok(()),
            Err(again) => Err(again),
        },
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Err(e) if dir_sync_unsupported(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Windows implementation of [`sync_dir_durable`]. Opening a directory
/// requires the backup-semantics flag, and `FlushFileBuffers` requires write
/// access. The metadata check rejects a non-directory path, matching the Unix
/// `O_DIRECTORY` behavior.
#[cfg(windows)]
pub(crate) fn sync_dir_durable(dir: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    let handle = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
    {
        Ok(handle) => handle,
        Err(e) if dir_sync_unsupported(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    if !handle.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "Path to flush is not a directory",
        ));
    }
    match handle.sync_all() {
        Ok(()) => Ok(()),
        Err(e) if dir_sync_unsupported(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Returns whether a directory open or flush failed because the filesystem
/// does not provide directory flushing, rather than because a supported
/// operation failed or was denied.
///
/// - [`errno_not_supported`] covers unsupported-operation errors.
/// - `EINVAL` and `EBADF` are returned by some network and FUSE filesystems
///   when directory `fsync` is unavailable.
///
/// Permission denial (`EACCES`) is deliberately excluded. A write-only
/// directory refuses the read handle that directory flushing needs, but that
/// is a denied barrier, not a missing capability: key generation must fail
/// rather than report success without making its directory entries durable.
#[cfg(unix)]
pub(crate) fn dir_sync_unsupported(e: &io::Error) -> bool {
    errno_not_supported(e)
        || matches!(
            e.raw_os_error(),
            Some(code) if code == libc::EINVAL || code == libc::EBADF
        )
}

/// Windows equivalent of the Unix classification.
/// `ERROR_INVALID_FUNCTION`, `ERROR_NOT_SUPPORTED`, and
/// `ERROR_INVALID_PARAMETER` indicate that the volume or network provider
/// cannot flush directory entries.
///
/// Access denial is deliberately excluded, matching the Unix treatment of
/// `EACCES`. A directory that cannot be opened with the write access
/// `FlushFileBuffers` needs is a denied barrier, not a missing capability, so
/// key generation must fail rather than report success without making its
/// directory entries durable.
#[cfg(windows)]
fn dir_sync_unsupported(e: &io::Error) -> bool {
    const ERROR_INVALID_FUNCTION: i32 = 1;
    const ERROR_NOT_SUPPORTED: i32 = 50;
    const ERROR_INVALID_PARAMETER: i32 = 87;

    e.kind() == io::ErrorKind::Unsupported
        || matches!(
            e.raw_os_error(),
            Some(ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED | ERROR_INVALID_PARAMETER)
        )
}

/// A retained handle to the directory an operation publishes into.
///
/// An operation that commits more than one entry, or that has to undo a
/// commit it already made, performs those later steps once its own first
/// write is already visible on disk. Resolving them through the ambient
/// output path again lets a rename, or a symlink substituted at that
/// path, send a removal into a different directory, where it can unlink
/// a file the operation never created. Removals therefore stay inside this
/// handle's directory. On Unix the final identity check and unlink remain two
/// operations, with the substitution instant documented in `SECURITY.md`; on
/// Windows deletion is bound to the retained file handle itself.
///
/// The handle does not make the chosen directory trustworthy. The
/// caller's choice of output directory IS the trust boundary, and a path
/// already substituted before the handle is opened simply anchors the
/// whole operation there. What the handle removes is the mismatch
/// between the directory an operation wrote to and the directory it
/// later cleans up in.
///
/// `cap_std::fs::Dir` is the same capability primitive the archive
/// extractor anchors to. On Linux and macOS its removals are
/// handle-relative. On Windows, cap-std resolves the handle to the
/// directory's current path for every name-based operation; the
/// anchored directory itself cannot be renamed or removed while this
/// handle is open, because cap-std opens directories without delete
/// sharing, so that path denotes it. The rollback's removal there does
/// not go by name at all: it deletes through the retained committed
/// handle, so it can only ever delete the file that handle refers to.
pub(crate) struct OutputDir {
    dir: cap_std::fs::Dir,
}

impl OutputDir {
    /// Opens `path` as the anchor for the operation's own cleanup, and
    /// for anything else it has to read there. Needs a readable output
    /// directory; `SECURITY.md` records that requirement.
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let dir = cap_std::fs::Dir::open_ambient_dir(path, cap_std::ambient_authority())?;
        Ok(Self { dir })
    }

    /// Opens `path` as the anchor for a commit alone, preferring the
    /// narrowest access a commit needs
    /// ([`crate::fs::commit::open_commit_anchor`]). An output directory
    /// that grants write and search but not read therefore still
    /// receives encrypted output on Linux and macOS, and a filesystem
    /// that refuses the narrow open still commits through an ordinary
    /// directory handle. Production encrypted output calls this only on
    /// those two targets; its other-target backend remains path-based.
    ///
    /// Not for key generation, which reopens its anchor for a required
    /// durability barrier and so keeps the readable requirement of
    /// [`Self::open`].
    #[cfg(any(test, target_os = "linux", target_os = "macos"))]
    pub(crate) fn open_for_commit(path: &Path) -> io::Result<Self> {
        Ok(Self {
            dir: crate::fs::commit::open_commit_anchor(path)?,
        })
    }

    /// Requires `tmp` to be the entry under its own name in this
    /// directory, before a caller writes any content into it.
    ///
    /// A commit resolves the staged name through this handle, so the
    /// staged file must be an entry of the anchored directory. Checking
    /// it at staging time rather than only at the commit means a
    /// destination replaced in the window between opening this handle
    /// and creating the temporary is refused before the operation pays
    /// for the whole write. Off Unix the commit does not resolve
    /// through the handle, so there is nothing to confirm.
    #[cfg(unix)]
    pub(crate) fn confirm_staged(&self, tmp: &NamedTempFile) -> Result<(), CryptoError> {
        let Some(name) = tmp.path().file_name() else {
            return Err(CryptoError::Io(no_final_component_error()));
        };
        require_staged_temp_in_output_dir(tmp, self, name)
    }

    #[cfg(not(unix))]
    pub(crate) fn confirm_staged(&self, _tmp: &NamedTempFile) -> Result<(), CryptoError> {
        Ok(())
    }

    /// Removes a still-staged key-file temporary only while the entry under
    /// its random name in this anchored directory is still the file whose
    /// handle the caller retained. The `NamedTempFile` destructor is disarmed
    /// first: after the output directory has been renamed, its recorded
    /// ambient path can lead to a replacement directory and must not drive
    /// cleanup there.
    ///
    /// The returned outcome must be reported unless it is [`RollbackOutcome::Removed`].
    /// On Unix, removal is by name inside this anchor after the identity
    /// comparison; on Windows it is through the retained file handle, matching
    /// committed-key rollback.
    #[must_use = "the outcome says whether the staged file is gone; report it"]
    pub(crate) fn remove_staged_if_retained(&self, tmp: NamedTempFile) -> RollbackOutcome {
        let Some(name) = tmp.path().file_name().map(|name| name.to_os_string()) else {
            let _ = tmp.into_temp_path().keep();
            return RollbackOutcome::Unconfirmed;
        };
        let (retained, temp_path) = tmp.into_parts();
        let _ = temp_path.keep();
        self.remove_if_retained(&name, retained)
    }

    /// Removes the entry named by `path`'s final component, resolved
    /// inside the anchored directory, but only while that entry is still
    /// the committed file `finalized` retains, compared by identity
    /// without following symlinks. A rollback runs once its commit is
    /// already visible, so an entry replaced in that window must be left
    /// in place rather than deleted; the committed file then survives
    /// under whatever name it was moved to. An entry or handle whose
    /// identity cannot be read is left in place on the same terms: an
    /// unconfirmed entry is not this operation's to remove. The returned
    /// [`RollbackOutcome`] says whether the file is gone, so the caller
    /// can report a rollback that left the file, or another name for it,
    /// behind. The link count is read through the retained handle before
    /// the removal; a name added after that read is not counted. The
    /// identity, and what it cannot distinguish, is [`file_identity`]'s.
    ///
    /// The committed handle is consumed and closed here, so the removal
    /// is complete when this returns. What the removal acts on is
    /// [`remove_retained`]'s: on Unix the name, unlinked inside the
    /// anchored directory; on Windows the retained handle itself.
    #[must_use = "the outcome says whether the committed file is gone; report it"]
    pub(crate) fn remove_published_if_retained(
        &self,
        path: &Path,
        finalized: FinalizedFile,
    ) -> RollbackOutcome {
        let Some(name) = path.file_name() else {
            return RollbackOutcome::Unconfirmed;
        };
        self.remove_if_retained(name, finalized.file)
    }

    /// The identity-checked removal behind
    /// [`Self::remove_published_if_retained`]: an entry of the anchored
    /// directory whose creator still holds a handle to it, which here
    /// is a committed key file.
    fn remove_if_retained(
        &self,
        name: &std::ffi::OsStr,
        retained: std::fs::File,
    ) -> RollbackOutcome {
        self.remove_if_retained_with(name, retained, || {})
    }

    /// Testable [`Self::remove_if_retained`]: `between` runs after the
    /// identity check and before the removal, where a local writer's
    /// replacement would land.
    fn remove_if_retained_with(
        &self,
        name: &std::ffi::OsStr,
        retained: std::fs::File,
        between: impl FnOnce(),
    ) -> RollbackOutcome {
        use cap_fs_ext::MetadataExt;

        let Ok(committed) = cap_std::fs::Metadata::from_file(&retained) else {
            return RollbackOutcome::Unconfirmed;
        };
        let Ok(entry) = self.dir.symlink_metadata(name) else {
            return RollbackOutcome::Unconfirmed;
        };
        if !entry.is_file() {
            return RollbackOutcome::Replaced;
        }
        // Removing needs a match, and an identity that carries no
        // information cannot supply one.
        match (file_identity(&entry), file_identity(&committed)) {
            (Some(entry_id), Some(committed_id)) if entry_id == committed_id => {}
            (Some(_), Some(_)) => return RollbackOutcome::Replaced,
            _ => return RollbackOutcome::Unconfirmed,
        }
        between();
        if remove_retained(&self.dir, name, retained).is_err() {
            return RollbackOutcome::Unconfirmed;
        }
        match committed.nlink() {
            1 => RollbackOutcome::Removed,
            link_count => RollbackOutcome::RemovedButLinked { link_count },
        }
    }

    /// Flushes the anchored directory's entries, resolving through the
    /// held handle, so the barrier covers the directory the entries
    /// were committed to even if the ambient path was renamed since.
    /// The flush itself keeps the unsupported-filesystem tolerance of
    /// [`sync_dir_durable`]; genuine open and flush failures are
    /// reported so a caller that requires durability can stop.
    ///
    /// cap-std may hold the directory as an `O_PATH` handle on Linux,
    /// which cannot be flushed, so `.` is reopened through the handle —
    /// the same technique as `archive::platform`'s directory sync. The
    /// reopen needs read permission, exactly what the path-based flush
    /// needs, so restrictive directories refuse both the same way. A
    /// failed reopen tolerates only a genuine unsupported-operation
    /// result: this is an ordinary directory open with plain flags, so
    /// `EINVAL` or `EBADF` here reports a broken call or anchor, not the
    /// missing flush capability [`dir_sync_unsupported`] describes, and
    /// a required barrier must not report success over either.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn flush_durable(&self) -> io::Result<()> {
        use std::os::fd::AsFd;

        use rustix::fs::{Mode, OFlags, openat};

        let fd = match rustix::io::retry_on_intr(|| {
            openat(
                self.dir.as_fd(),
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
        }) {
            Ok(fd) => fd,
            Err(e) => {
                let e = io::Error::from(e);
                return if errno_not_supported(&e) {
                    Ok(())
                } else {
                    Err(e)
                };
            }
        };
        flush_dir_handle(&std::fs::File::from(fd))
    }
}

/// Removes the object `retained` refers to, once its identity has been
/// confirmed under `name` in `dir`, and closes the handle. Unix has no
/// removal by descriptor, so the name is unlinked inside the anchored
/// directory; an entry replaced in the instant between the check and the
/// unlink is what that removal then reaches, a bound `SECURITY.md`
/// states.
#[cfg(unix)]
fn remove_retained(
    dir: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    retained: std::fs::File,
) -> io::Result<()> {
    let result = dir.remove_file(name);
    drop(retained);
    result
}

/// Windows removes through the handle itself: the file is reopened from
/// `retained` — a relative open of the same object, no path involved —
/// with the delete-on-close flag, and the deletion takes effect when the
/// last handle closes, which happens here. An entry replaced in the
/// instant between the identity check and this call therefore survives:
/// the removal can only ever delete the file the handle refers to. The
/// reopen relies on `tempfile` opening its named temporaries with the
/// default sharing mode, which permits a delete-access open of the same
/// file, and requires the original handle to have been opened for
/// writing, as every committed file here was.
#[cfg(windows)]
fn remove_retained(
    _dir: &cap_std::fs::Dir,
    _name: &std::ffi::OsStr,
    retained: std::fs::File,
) -> io::Result<()> {
    use cap_fs_ext::Reopen;
    use cap_std::fs::OpenOptionsExt;

    let mut options = cap_std::fs::OpenOptions::new();
    options
        .access_mode(DELETE | FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_DELETE_ON_CLOSE);
    let marked_for_deletion = retained.reopen(&options)?;
    drop(marked_for_deletion);
    drop(retained);
    Ok(())
}

/// Access right to delete an object, from `WinNT.h`.
#[cfg(windows)]
const DELETE: u32 = 0x0001_0000;

/// Access right to read an object's attributes, from `WinNT.h`.
#[cfg(windows)]
const FILE_READ_ATTRIBUTES: u32 = 0x0080;

/// `CreateFileW` flag that deletes the file when its last handle closes.
#[cfg(windows)]
const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;

/// Error for a path with no final component: there is no name to link,
/// claim, or rename to, so the commit rejects rather than falling back
/// to some other entry.
#[cfg(unix)]
fn no_final_component_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Output path has no final component",
    )
}

/// Commits `tmp` to `final_path` where `tempfile` could not perform an
/// atomic no-replace rename, keeping the no-clobber guarantee against
/// entries that predate the commit.
///
/// The whole fallback commit is anchored. Linux/macOS encryption and key
/// generation receive the [`OutputDir`] their caller opened before staging;
/// path-based encryption on the other Unix targets opens one here only after
/// the primary persist proves unsupported. The link, claim, rename, and every
/// removal then resolve through that handle. The staged temp file must be an
/// entry of the same directory, and the route refuses to start until the entry
/// under its name is confirmed by identity to be the staged file itself.
/// Linux/macOS encryption's anchor requires search but not permission to list
/// the directory; key generation and the ordinary-handle fallback on other
/// Unix targets retain the readable-directory requirement documented in
/// `SECURITY.md`.
///
/// Which route reaches the final name is
/// [`crate::fs::commit::commit_by_link_or_claim`]'s, the same commit
/// archive extraction reaches on these filesystems: a link where the
/// filesystem has hard links, a claim over which the staged entry is
/// renamed where it has none. `tempfile` does not retry the
/// unsupported-operation error that leads here: its own link fallback
/// answers only a no-replace flag reported as unknown or invalid, and
/// discards that fallback's unlink result — which is why the persist
/// arm requires the single-link confirmation as well.
///
/// What is finished here is the route's post-condition. If the
/// staged-name unlink fails after a link commit, the operation reports a
/// post-commit error and preserves both complete links; it never removes
/// the final name after a potentially delayed failure. A successful or
/// missing-name unlink is accepted only when the retained committed
/// handle reports one link, which catches a concurrent move of the
/// staged link and a successful unlink of a planted replacement.
/// The wrapper below is production code only for path-based encryption on the
/// other Unix targets; Linux/macOS tests also use it to exercise a fallback
/// their ordinary filesystem may not select.
#[cfg(all(unix, any(test, not(any(target_os = "linux", target_os = "macos")))))]
fn finalize_file_via_link_or_claim(
    tmp: NamedTempFile,
    final_path: &Path,
    label: &str,
) -> Result<FinalizedFile, FinalizeFileError> {
    let output_dir = OutputDir::open(crate::fs::paths::parent_or_cwd(final_path))
        .map_err(CryptoError::Io)
        .map_err(FinalizeFileError::before_commit)?;
    finalize_file_via_link_or_claim_in(tmp, final_path, label, &output_dir)
}

/// [`finalize_file_via_link_or_claim`] against an already-open anchor.
// Reached in production only on the Unix targets without a
// handle-relative commit; elsewhere the tests drive it to exercise
// the route a filesystem with a working no-replace rename never takes.
#[cfg_attr(any(target_os = "linux", target_os = "macos"), allow(dead_code))]
#[cfg(unix)]
fn finalize_file_via_link_or_claim_in(
    tmp: NamedTempFile,
    final_path: &Path,
    label: &str,
    output_dir: &OutputDir,
) -> Result<FinalizedFile, FinalizeFileError> {
    finalize_file_commit(
        tmp,
        final_path,
        label,
        output_dir,
        |anchor, staged, final_name| {
            crate::fs::commit::commit_by_link_or_claim(anchor, staged, final_name, CommitKind::File)
        },
    )
}

/// The part of a fallback commit that does not depend on which route
/// reached the final name: confirm the staged temporary against the
/// anchor, run `commit`, and finish the route it reports.
///
/// `commit` is a parameter so a test can drive the claim route directly
/// on a filesystem whose hard links would always win the link-first
/// entry point above.
#[cfg(unix)]
fn finalize_file_commit(
    tmp: NamedTempFile,
    final_path: &Path,
    label: &str,
    output_dir: &OutputDir,
    commit: impl FnOnce(
        &cap_std::fs::Dir,
        &std::ffi::OsStr,
        &std::ffi::OsStr,
    ) -> Result<CommitRoute, CommitFailure>,
) -> Result<FinalizedFile, FinalizeFileError> {
    // Owned, because the arms below consume `tmp` while the staged
    // name is still needed.
    let Some(tmp_name) = tmp.path().file_name().map(|name| name.to_os_string()) else {
        // With no staged name to verify against the anchor, retain the
        // existing best-effort destructor behaviour. It attempts the recorded
        // ambient path, which may no longer lead to the original directory.
        return Err(FinalizeFileError::before_commit(CryptoError::Io(
            no_final_component_error(),
        )));
    };
    // Verified before any removal resolves through the anchor, so a
    // same-named entry there is never unlinked in place of a temp that
    // was staged somewhere else.
    if let Err(error) = require_staged_temp_in_output_dir(&tmp, output_dir, &tmp_name) {
        // `tmp` drops here and its destructor attempts cleanup through the
        // recorded ambient path. This is the pre-existing staging policy; a
        // parent rename can make that path differ from the anchored directory.
        return Err(FinalizeFileError::before_commit(error));
    }
    let Some(final_name) = final_path.file_name() else {
        let _ = remove_staged_temp(tmp, output_dir);
        return Err(FinalizeFileError::before_commit(CryptoError::Io(
            no_final_component_error(),
        )));
    };
    match commit(&output_dir.dir, &tmp_name, final_name) {
        Ok(CommitRoute::Linked) => finish_link_commit(tmp, output_dir, final_path, &tmp_name),
        Ok(CommitRoute::Renamed) => finish_renamed_commit(tmp, output_dir, final_path),
        Err(failure) => {
            let _ = remove_staged_temp(tmp, output_dir);
            let error = if failure.error.kind() == io::ErrorKind::AlreadyExists {
                already_exists_error(label, final_path)
            } else {
                CryptoError::Io(failure.error)
            };
            // A final name the commit claimed is left in place and may
            // still be occupied, where it blocks the next attempt, so it
            // is reported. No content from this run's staged file reached
            // that name: the commit failed before it could be moved there.
            Err(FinalizeFileError::before_commit(if failure.claim_left {
                crate::error::append_report(error, &claim_left_report(final_path))
            } else {
                error
            }))
        }
    }
}

/// Finishes a commit a rename reached — the flagged no-replace rename,
/// or the claim route's rename over its own placeholder. Either moved
/// the staged file's inode to the final name, so the handle held since
/// staging is the committed one and needs no reopen.
#[cfg(unix)]
fn finish_renamed_commit(
    tmp: NamedTempFile,
    output_dir: &OutputDir,
    final_path: &Path,
) -> Result<FinalizedFile, FinalizeFileError> {
    // The rename moved the staged entry away, so disarm the destructor:
    // its unlink could only ever reach an entry another process creates
    // at the freed temp name afterwards. Not [`remove_staged_temp`], for
    // the same reason.
    let (file, temp_path) = tmp.into_parts();
    let _ = temp_path.keep();
    sync_committed_parent(output_dir, final_path);

    let finalized = FinalizedFile::new(file);
    finalized
        .confirm_reported_path(final_path)
        .map_err(FinalizeFileError::after_commit)?;
    finalized
        .confirm_single_link(final_path)
        .map_err(FinalizeFileError::after_commit)?;
    Ok(finalized)
}

/// Requires the entry under the staged name in the anchored destination
/// directory to be the staged file itself, before any fallback commit step
/// runs. Both routes resolve the staged name through the anchor, so the
/// commit must be refused when that entry is missing or is another
/// object — whether a caller staged the temporary in some other
/// directory, or a local writer deleted or replaced the staged entry
/// while the operation ran. The entry is read without following
/// symlinks, so a link planted under the staged name cannot satisfy the
/// comparison either.
#[cfg(unix)]
fn require_staged_temp_in_output_dir(
    tmp: &NamedTempFile,
    output_dir: &OutputDir,
    tmp_name: &std::ffi::OsStr,
) -> Result<(), CryptoError> {
    let staged = cap_std::fs::Metadata::from_file(tmp.as_file()).map_err(CryptoError::Io)?;
    let entry = match output_dir.dir.symlink_metadata(tmp_name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(staged_temp_not_in_output_dir(tmp_name));
        }
        Err(error) => return Err(CryptoError::Io(error)),
    };
    if !entry.is_file() || identities_differ(&entry, &staged) {
        return Err(staged_temp_not_in_output_dir(tmp_name));
    }
    Ok(())
}

/// Rejection from [`require_staged_temp_in_output_dir`]: the entry under
/// the staged name is missing or is not the staged file. A local writer
/// deleting or replacing the staged entry reaches this in ordinary
/// operation on the filesystems that use the fallback route, so the
/// error reports a filesystem condition rather than a library bug.
#[cfg(unix)]
fn staged_temp_not_in_output_dir(staged_name: &std::ffi::OsStr) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "Staged temporary file {} is not the entry under its name in the destination directory",
        sanitize_path_for_display(Path::new(staged_name)),
    ))
}

/// Finishes a link commit after the final link exists. The unlink is
/// injectable one level down so tests can exercise the post-commit failure
/// policy without a filesystem that selectively refuses it.
#[cfg(unix)]
fn finish_link_commit(
    tmp: NamedTempFile,
    output_dir: &OutputDir,
    final_path: &Path,
    tmp_name: &std::ffi::OsStr,
) -> Result<FinalizedFile, FinalizeFileError> {
    finish_link_commit_with_remove(tmp, output_dir, final_path, tmp_name, |dir, name| {
        dir.remove_file(name)
    })
}

#[cfg(unix)]
fn finish_link_commit_with_remove(
    tmp: NamedTempFile,
    output_dir: &OutputDir,
    final_path: &Path,
    tmp_name: &std::ffi::OsStr,
    remove_staged: impl FnOnce(&cap_std::fs::Dir, &std::ffi::OsStr) -> io::Result<()>,
) -> Result<FinalizedFile, FinalizeFileError> {
    let (committed_identity, staged_unlink) =
        unlink_staged_temp_with_remove(tmp, output_dir, tmp_name, remove_staged);
    sync_committed_parent(output_dir, final_path);

    let committed_identity = committed_identity.map_err(FinalizeFileError::after_commit)?;
    let Some(final_name) = final_path.file_name() else {
        return Err(FinalizeFileError::after_commit(CryptoError::Io(
            no_final_component_error(),
        )));
    };
    let finalized = reopen_committed_file(output_dir, final_name, committed_identity, final_path)
        .map_err(FinalizeFileError::after_commit)?;
    finalized
        .confirm_reported_path(final_path)
        .map_err(FinalizeFileError::after_commit)?;
    if let Err(error) = staged_unlink {
        return Err(FinalizeFileError::after_commit(staged_temp_link_retained(
            final_path, tmp_name, error,
        )));
    }
    finalized
        .confirm_single_link(final_path)
        .map_err(FinalizeFileError::after_commit)?;
    Ok(finalized)
}

/// The clause appended when the claim route left the name it claimed in
/// place. No content from this run's staged file reached that name, because
/// the commit failed before it could be moved there, but a further attempt may
/// find the name occupied. The wording does not say whose the entry is or
/// whether it contains anything: the claim ran with its entry already visible,
/// and a failed commit removes nothing from the final name.
///
/// The decrypt side reports the same condition in its own words
/// (`archive::decode::claim_left_report`): the two share the commit and
/// the flag that raises this, not the sentence. That side names the
/// whole working path, because a failed decrypt is where the caller goes
/// looking for what was left behind.
#[cfg(unix)]
fn claim_left_report(final_path: &Path) -> String {
    format!(
        "{} may still be occupied by an entry this run did not remove",
        final_component_for_display(final_path)
    )
}

/// Disarms the destructor's ambient-path removal, records the open file's
/// identity, closes that handle, and unlinks the staged name through the
/// anchor. Closing first preserves compatibility with filesystems that refuse
/// to unlink a name while the client still has the file open. The final link
/// is reopened and checked against the recorded identity afterwards; its
/// retained handle then supplies the authoritative link-count post-condition.
#[cfg(unix)]
fn unlink_staged_temp(
    tmp: NamedTempFile,
    output_dir: &OutputDir,
    name: &std::ffi::OsStr,
) -> (Result<Option<FileIdentity>, CryptoError>, io::Result<()>) {
    unlink_staged_temp_with_remove(tmp, output_dir, name, |dir, name| dir.remove_file(name))
}

#[cfg(unix)]
fn unlink_staged_temp_with_remove(
    tmp: NamedTempFile,
    output_dir: &OutputDir,
    name: &std::ffi::OsStr,
    remove_staged: impl FnOnce(&cap_std::fs::Dir, &std::ffi::OsStr) -> io::Result<()>,
) -> (Result<Option<FileIdentity>, CryptoError>, io::Result<()>) {
    let (file, temp_path) = tmp.into_parts();
    let identity = cap_std::fs::Metadata::from_file(&file)
        .map(|metadata| file_identity(&metadata))
        .map_err(CryptoError::Io);
    drop(file);
    let _ = temp_path.keep();
    let result = match remove_staged(&output_dir.dir, name) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    };
    (identity, result)
}

/// Best-effort pre-commit cleanup through the retained directory anchor.
#[cfg(unix)]
fn remove_staged_temp(tmp: NamedTempFile, output_dir: &OutputDir) -> io::Result<()> {
    let Some(name) = tmp.path().file_name().map(|name| name.to_os_string()) else {
        let _ = tmp.into_temp_path().keep();
        return Err(no_final_component_error());
    };
    let (_, result) = unlink_staged_temp(tmp, output_dir, &name);
    result
}

/// Reopens a linked commit through the same directory anchor and requires it
/// to be the regular file whose identity was recorded before the staged name
/// was removed. This supplies the retained handle without keeping the staged
/// handle open across an unlink on restrictive network filesystems. Where
/// either identity is absent the comparison is skipped; the link-count and
/// reported-path checks that follow still run.
#[cfg(unix)]
fn reopen_committed_file(
    output_dir: &OutputDir,
    final_name: &std::ffi::OsStr,
    expected: Option<FileIdentity>,
    final_path: &Path,
) -> Result<FinalizedFile, CryptoError> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, OpenOptionsSyncExt};

    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = output_dir
        .dir
        .open_with(final_name, &options)
        .map_err(CryptoError::Io)?
        .into_std();
    let metadata = cap_std::fs::Metadata::from_file(&file).map_err(CryptoError::Io)?;
    if !metadata.is_file() {
        return Err(reported_output_changed(final_path));
    }
    if matches!(
        (file_identity(&metadata), expected),
        (Some(found), Some(expected)) if found != expected
    ) {
        return Err(reported_output_changed(final_path));
    }
    Ok(FinalizedFile::new(file))
}

/// Best-effort durability barrier for a fallback commit. Linux and macOS
/// flush the exact directory handle the commit used; other Unix targets keep
/// the existing path-based fallback because no handle-relative implementation
/// is available there.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sync_committed_parent(output_dir: &OutputDir, _final_path: &Path) {
    let _ = output_dir.flush_durable();
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn sync_committed_parent(_output_dir: &OutputDir, final_path: &Path) {
    sync_parent_dir(final_path);
}

/// Reports a post-commit staged-name unlink failure without withdrawing the
/// final name. Both entries may still be hard links to the same complete file.
#[cfg(unix)]
fn staged_temp_link_retained(
    final_path: &Path,
    staged_name: &std::ffi::OsStr,
    source: io::Error,
) -> CryptoError {
    CryptoError::Io(io::Error::new(
        source.kind(),
        format!(
            "Output {} is complete, but temporary name {} could not be removed: {source}",
            sanitize_path_for_display(final_path),
            sanitize_path_for_display(Path::new(staged_name)),
        ),
    ))
}

/// Promotes a staged single-file path `from` to the final name `to`
/// with atomic no-clobber semantics on every supported platform.
/// Fails with [`io::ErrorKind::AlreadyExists`] if `to` is already taken.
///
/// The underlying primitive is `tempfile::TempPath::persist_noclobber`,
/// which dispatches to:
///
/// - **Windows:** `MoveFileExW(from, to, 0)` — the kernel performs the
///   test-and-set in one call, closing the check-then-rename race that
///   [`rename_no_clobber`] still has on this target for the directory
///   case.
/// - **Linux / macOS / iOS / Android:**
///   `rustix::renameat_with(..., RenameFlags::NOREPLACE)`, falling back
///   to `hard_link` + `unlink` if the kernel or filesystem rejects the
///   flag (very old Linux, some FUSE / NFS). The fallback preserves
///   no-clobber (`hard_link` itself refuses an existing target); only
///   atomicity is briefly relaxed.
/// - **Other Unix targets:** `hard_link` + `unlink` unconditionally.
///
/// The link fallback discards its unlink result, so success alone does
/// not prove the staged name is gone. Archive extraction accounts for
/// that by reporting the link outcome (`platform::PromotionOutcome`)
/// and requiring one link through its retained staged handle.
///
/// Intended for **single-file** promotions only. Directory promotion on
/// Windows still goes through [`rename_no_clobber`] because no
/// equivalent safe atomic primitive is available there for directories.
///
/// On failure, `from` is left in place so the
/// `IncompleteOutputPolicy::RetainOnError` contract — "keep the staged
/// `.incomplete` on disk after a failed decrypt" — continues to hold
/// when promotion itself is what failed.
///
/// Archive promotion calls this on Windows and other non-Linux/macOS
/// targets; on Linux and macOS the archive layer promotes
/// handle-relative via `archive::platform::rename_at_no_clobber`, so the
/// production caller here is `cfg`'d away and the dead-code check fires
/// in a non-test build on those targets. The `allow` keeps the helper
/// (and its cross-platform tests) compiled everywhere.
#[cfg_attr(any(target_os = "linux", target_os = "macos"), allow(dead_code))]
pub(crate) fn promote_single_file_no_clobber(from: &Path, to: &Path) -> io::Result<()> {
    let temp_path = tempfile::TempPath::try_from_path(from)?;
    match temp_path.persist_noclobber(to) {
        Ok(()) => {
            sync_parent_dir(to);
            Ok(())
        }
        Err(e) => {
            // Recover the staging file: disable cleanup on the
            // returned TempPath so its destructor does not `remove_file`
            // it when this match arm ends. RetainOnError relies on
            // `from` still being on disk after a refused promotion.
            let mut recovered = e.path;
            recovered.disable_cleanup(true);
            Err(e.error)
        }
    }
}

/// Renames `from` to `to`, refusing if `to` already exists. Works for
/// files and directories.
///
/// - **Linux / macOS:** atomic —
///   `rustix::renameat_with(..., RenameFlags::NOREPLACE)`.
/// - **Windows:** best-effort. `symlink_metadata()` + `std::fs::rename`.
///   A small race window exists between the two: a process that
///   creates `to` in that window has its file silently overwritten by
///   ours. Plaintext is never redirected (Windows renames replace the
///   directory entry, not the link target), so the failure mode is
///   integrity, not confidentiality. Closing this fully needs Win32
///   FFI, which the zero-`unsafe` invariant rules out. See
///   `SECURITY.md`.
/// - **Other targets:** unsupported.
///
/// Single-file promotions should prefer [`promote_single_file_no_clobber`],
/// which is atomic no-clobber on Windows too.
///
/// Build-time-unused on Linux and macOS for the same reason as
/// [`promote_single_file_no_clobber`]: archive promotion there is
/// handle-relative. The `allow` keeps it (and its tests) compiled on
/// every platform.
#[cfg_attr(any(target_os = "linux", target_os = "macos"), allow(dead_code))]
pub(crate) fn rename_no_clobber(from: &Path, to: &Path) -> io::Result<()> {
    rename_no_clobber_impl(from, to)?;
    sync_parent_dir(to);
    Ok(())
}

// Reached only through `rename_no_clobber`, which is itself build-time-
// unused on Linux/macOS (archive promotion is handle-relative there).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)]
fn rename_no_clobber_impl(from: &Path, to: &Path) -> io::Result<()> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE).map_err(io::Error::from)
}

#[cfg(target_os = "windows")]
fn rename_no_clobber_impl(from: &Path, to: &Path) -> io::Result<()> {
    // `symlink_metadata` does not follow links, so a dangling symlink
    // at `to` reports `Ok(_)` and rejects here instead of falling
    // through `Path::try_exists()` (which follows the link to a
    // missing target and returns `Ok(false)`). Closes the gap that
    // `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)` would otherwise
    // exploit by replacing the dangling link with the staged file.
    match std::fs::symlink_metadata(to) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Target already exists",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::rename(from, to)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn rename_no_clobber_impl(_from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Atomic rename is not supported on this target",
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;

    use super::*;

    /// An occupied final path rejects with the same typed message the
    /// pre-write occupancy check emits, so a conflict that appears in
    /// the window between the preflight and this rename reports the
    /// same error class. The destination stays untouched and the temp
    /// file is removed.
    #[test]
    fn finalize_file_refuses_to_overwrite() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");
        fs::write(&final_path, "existing").unwrap();

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"new").unwrap();
        let tmp_path = tmp.path().to_path_buf();

        let error = commit_to(tmp, &final_path, "Output")
            .expect_err("an occupied output must fail before commit");
        assert!(!error.committed());
        match error.into_crypto_error() {
            CryptoError::InvalidInput(msg) => {
                assert!(msg.starts_with("Output already exists: "), "got: {msg}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "existing");
        assert!(!tmp_path.exists(), "temp file must be removed on failure");
    }

    #[test]
    fn finalize_file_succeeds_when_target_missing() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"payload").unwrap();

        commit_to(tmp, &final_path, "Output").unwrap();
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "payload");
    }

    /// The ordinary one-step persist also retains the committed handle. If
    /// the parent directory is replaced before the caller reports its path,
    /// the final check rejects that path while leaving both the real output
    /// and the replacement untouched. Unix only: NTFS refuses to rename a
    /// directory while a handle is open anywhere beneath it, so the retained
    /// handle itself rules this swap out there.
    #[cfg(unix)]
    #[test]
    fn finalized_file_rejects_a_reported_path_after_parent_replacement() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let out = tmp_dir.path().join("out");
        fs::create_dir(&out).unwrap();
        let final_path = out.join("out.txt");

        let mut tmp = tempfile::Builder::new().tempfile_in(&out).unwrap();
        tmp.write_all(b"payload").unwrap();
        let finalized = commit_to(tmp, &final_path, "Output").unwrap();

        let moved = tmp_dir.path().join("out.moved");
        fs::rename(&out, &moved).unwrap();
        fs::create_dir(&out).unwrap();
        fs::write(&final_path, b"replacement").unwrap();

        let err = finalized
            .confirm_reported_path(&final_path)
            .expect_err("the returned path no longer denotes the committed file");
        assert!(
            matches!(
                err,
                CryptoError::InvalidInput(message)
                    if message.contains("reported path changed")
            ),
            "the path mismatch must be explicit"
        );
        assert_eq!(fs::read(moved.join("out.txt")).unwrap(), b"payload");
        assert_eq!(fs::read(&final_path).unwrap(), b"replacement");
    }

    /// A replacement of the final entry itself — the committed file moved
    /// aside and another file planted under its name, which a local writer
    /// can do on every platform while the handle is retained — is rejected
    /// the same way, and both files are left where they are.
    #[test]
    fn finalized_file_rejects_a_reported_path_after_entry_replacement() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"payload").unwrap();
        let finalized = commit_to(tmp, &final_path, "Output").unwrap();

        let moved = tmp_dir.path().join("out.moved");
        fs::rename(&final_path, &moved).unwrap();
        fs::write(&final_path, b"replacement").unwrap();

        let err = finalized
            .confirm_reported_path(&final_path)
            .expect_err("the returned path no longer denotes the committed file");
        assert!(
            matches!(
                err,
                CryptoError::InvalidInput(message)
                    if message.contains("reported path changed")
            ),
            "the entry mismatch must be explicit"
        );
        assert_eq!(fs::read(&moved).unwrap(), b"payload");
        assert_eq!(fs::read(&final_path).unwrap(), b"replacement");
    }

    /// Creates a file symlink `link` → `target`. Windows needs a privilege
    /// the local account may lack; that failure is returned so the caller
    /// can skip, unless `FERROCRYPT_REQUIRE_WINDOWS_SYMLINK_TESTS` demands
    /// the assertion, as the extraction tests do.
    fn plant_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(windows)]
        {
            let result = std::os::windows::fs::symlink_file(target, link);
            if let Err(e) = &result {
                if std::env::var_os("FERROCRYPT_REQUIRE_WINDOWS_SYMLINK_TESTS").is_some() {
                    panic!("symlink creation required by CI but failed: {e}");
                }
            }
            result
        }
    }

    /// A symlink planted at the reported name, pointing at the committed
    /// file moved aside, must be rejected: the entry is read without
    /// following it, so a name the writer can retarget later is never
    /// confirmed even while it currently leads to the right bytes.
    #[test]
    fn finalized_file_rejects_a_symlink_planted_at_the_reported_path() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"payload").unwrap();
        let finalized = commit_to(tmp, &final_path, "Output").unwrap();

        let moved = tmp_dir.path().join("out.moved");
        fs::rename(&final_path, &moved).unwrap();
        if let Err(e) = plant_file_symlink(&moved, &final_path) {
            eprintln!("symlink creation unavailable ({e}); skipping");
            return;
        }

        let err = finalized
            .confirm_reported_path(&final_path)
            .expect_err("a symlink at the reported name is not the committed entry");
        assert!(
            matches!(
                err,
                CryptoError::InvalidInput(message)
                    if message.contains("reported path changed")
            ),
            "the planted symlink must report as a path mismatch"
        );
        assert_eq!(fs::read(&moved).unwrap(), b"payload");
    }

    /// A final name that is gone — here moved away — counts as changed,
    /// exactly like one that holds another object: the commit created an
    /// entry there.
    #[test]
    fn finalized_file_rejects_a_reported_path_that_no_longer_exists() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"payload").unwrap();
        let finalized = commit_to(tmp, &final_path, "Output").unwrap();

        fs::rename(&final_path, tmp_dir.path().join("out.moved")).unwrap();

        let err = finalized
            .confirm_reported_path(&final_path)
            .expect_err("a missing final name no longer denotes the output");
        assert!(
            matches!(
                err,
                CryptoError::InvalidInput(message)
                    if message.contains("reported path changed")
            ),
            "the missing name must report as a path mismatch"
        );
    }

    /// `tempfile` can persist through a hard link of its own on Unix and
    /// discard the staged-name unlink result, and a local writer can link
    /// the staged temporary before the commit anywhere, so the persist arm
    /// must not report success while a second complete link to the
    /// committed file exists. Runs on Windows too: NTFS has hard links, and
    /// the check is load-bearing there.
    ///
    /// Only where the persist arm is the commit. Linux and macOS commit
    /// through the handle-relative rename instead, and the end-to-end
    /// test below pins the same rule for it.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn persist_arm_rejects_a_second_link_to_the_committed_file() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");
        fs::write(&final_path, "payload").unwrap();
        let leftover = tmp_dir.path().join(".tmpleftover.incomplete");
        fs::hard_link(&final_path, &leftover).unwrap();

        let file = fs::File::open(&final_path).unwrap();
        let error = finalized_from_persist(file, &final_path)
            .expect_err("a surviving second link must fail after commit");
        assert!(error.committed());
        let message = error.into_crypto_error().to_string();
        assert!(message.contains("has 2 filesystem names"), "got: {message}");
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "payload");
        assert_eq!(fs::read_to_string(&leftover).unwrap(), "payload");
    }

    /// An output directory that grants write and search but not read
    /// still receives encrypted output on Linux and macOS: the commit
    /// resolves through an anchor opened for path resolution alone. Key
    /// generation is deliberately not covered — it opens a readable
    /// anchor for a durability barrier it must be able to report on.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn finalize_file_commits_into_a_write_and_search_only_directory() {
        let out = crate::fs::commit::SearchOnlyDir::new();
        let final_path = out.path().join("out.txt");

        let mut tmp = tempfile::Builder::new().tempfile_in(out.path()).unwrap();
        tmp.write_all(b"payload").unwrap();
        out.close_reading();

        let finalized = commit_to(tmp, &final_path, "Output")
            .map_err(FinalizeFileError::into_crypto_error)
            .expect("a write-and-search-only directory must still receive the output");
        finalized.confirm_reported_path(&final_path).unwrap();
        assert_eq!(fs::read(&final_path).unwrap(), b"payload");
    }

    /// The no-clobber refusal is unchanged there: an entry that predates
    /// the commit is still never replaced, and reports the typed
    /// already-exists error rather than a bare permission failure.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn finalize_file_still_refuses_an_occupied_name_in_a_search_only_directory() {
        let out = crate::fs::commit::SearchOnlyDir::new();
        let final_path = out.path().join("out.txt");
        fs::write(&final_path, "existing").unwrap();

        let mut tmp = tempfile::Builder::new().tempfile_in(out.path()).unwrap();
        tmp.write_all(b"payload").unwrap();
        out.close_reading();

        let error = commit_to(tmp, &final_path, "Output")
            .expect_err("an occupied final name must refuse the commit");
        assert!(!error.committed());
        match error.into_crypto_error() {
            CryptoError::InvalidInput(message) => {
                assert!(
                    message.starts_with("Output already exists: "),
                    "got: {message}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "existing");
    }

    /// The anchor is held from before staging, so a local writer who
    /// moves the output directory aside and installs another at that
    /// path does not redirect the commit: the output lands in the
    /// directory the write began in, their directory is untouched, and
    /// the caller is told the reported path no longer names the output.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_directory_swapped_in_after_staging_receives_nothing() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let chosen = tmp_dir.path().join("out");
        let substituted = tmp_dir.path().join("theirs");
        fs::create_dir(&chosen).unwrap();
        fs::create_dir(&substituted).unwrap();

        let anchor = OutputDir::open_for_commit(&chosen).unwrap();
        let mut tmp = tempfile::Builder::new().tempfile_in(&chosen).unwrap();
        anchor.confirm_staged(&tmp).unwrap();
        tmp.write_all(b"payload").unwrap();

        fs::rename(&chosen, tmp_dir.path().join("out.moved")).unwrap();
        fs::rename(&substituted, &chosen).unwrap();

        let error = finalize_file(tmp, &chosen.join("out.txt"), "Output", &anchor)
            .expect_err("the reported path no longer names the output");
        assert!(
            error.committed(),
            "the output is committed; only the reported path is wrong"
        );
        assert!(
            !chosen.join("out.txt").exists(),
            "nothing may reach the substituted directory"
        );
        assert_eq!(
            fs::read(tmp_dir.path().join("out.moved").join("out.txt")).unwrap(),
            b"payload",
            "the output belongs in the directory the write began in"
        );
    }

    /// The same swap, with the staged file moved into the replacement
    /// first. Opening the anchor at the commit would find the staged
    /// inode there and commit into the replacement; an anchor held from
    /// before staging refuses, because the staged file is no longer an
    /// entry of the directory the write began in.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_staged_file_moved_into_a_swapped_in_directory_refuses_the_commit() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let chosen = tmp_dir.path().join("out");
        let replacement = tmp_dir.path().join("replacement");
        fs::create_dir(&chosen).unwrap();
        fs::create_dir(&replacement).unwrap();

        let anchor = OutputDir::open_for_commit(&chosen).unwrap();
        let mut tmp = tempfile::Builder::new().tempfile_in(&chosen).unwrap();
        anchor.confirm_staged(&tmp).unwrap();
        tmp.write_all(b"payload").unwrap();
        let staged_name = tmp.path().file_name().unwrap().to_os_string();

        // The local writer moves the staged file into a directory of
        // their own, then installs that directory at the chosen path.
        fs::rename(chosen.join(&staged_name), replacement.join(&staged_name)).unwrap();
        fs::rename(&chosen, tmp_dir.path().join("out.moved")).unwrap();
        fs::rename(&replacement, &chosen).unwrap();

        let error = finalize_file(tmp, &chosen.join("out.txt"), "Output", &anchor)
            .expect_err("a staged file outside the anchor must refuse the commit");
        assert!(!error.committed(), "nothing may be committed");
        assert!(
            !chosen.join("out.txt").exists(),
            "the replacement directory must receive nothing"
        );
        assert!(
            !tmp_dir.path().join("out.moved").join("out.txt").exists(),
            "the original directory must receive nothing either"
        );
    }

    /// The same guarantee end to end through `finalize_file`: a hard link
    /// a local writer created against the staged temporary before the
    /// commit survives the one-step persist as a second name for the
    /// committed file, so the commit fails after the final name exists and
    /// keeps both complete names.
    #[test]
    fn finalize_file_rejects_a_link_planted_against_the_staged_temporary() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"payload").unwrap();
        let planted = tmp_dir.path().join("planted.txt");
        fs::hard_link(tmp.path(), &planted).unwrap();

        let error = commit_to(tmp, &final_path, "Output")
            .expect_err("a second link to the committed file must fail after commit");
        assert!(error.committed());
        let message = error.into_crypto_error().to_string();
        assert!(message.contains("has 2 filesystem names"), "got: {message}");
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "payload");
        assert_eq!(fs::read_to_string(&planted).unwrap(), "payload");
    }

    /// The fallback trigger fires only for "the filesystem cannot do a
    /// no-replace rename" errors, never for ordinary failures such as
    /// an occupied target.
    #[cfg(unix)]
    #[test]
    fn no_replace_rename_unsupported_matches_capability_errors_only() {
        // Raw ENOTSUP is the exact shape the macOS exFAT driver
        // produces; it must match even though std leaves its kind
        // uncategorized on macOS.
        assert!(no_replace_rename_unsupported(
            &io::Error::from_raw_os_error(libc::ENOTSUP)
        ));
        assert!(no_replace_rename_unsupported(
            &io::Error::from_raw_os_error(libc::EOPNOTSUPP)
        ));
        assert!(no_replace_rename_unsupported(
            &io::Error::from_raw_os_error(libc::EINVAL)
        ));
        assert!(no_replace_rename_unsupported(&io::Error::new(
            io::ErrorKind::Unsupported,
            "flag not supported",
        )));
        assert!(!no_replace_rename_unsupported(
            &io::Error::from_raw_os_error(libc::EEXIST)
        ));
        assert!(!no_replace_rename_unsupported(&io::Error::new(
            io::ErrorKind::NotFound,
            "missing",
        )));
    }

    /// `EINVAL` means "flag not supported" only for the flagged rename;
    /// the shared not-supported predicate must not treat it as a
    /// capability gap (a plain `fsync` that fails with `EINVAL` is a
    /// real error, not a missing feature).
    #[cfg(unix)]
    #[test]
    fn errno_not_supported_excludes_einval() {
        assert!(errno_not_supported(&io::Error::from_raw_os_error(
            libc::ENOTSUP
        )));
        assert!(!errno_not_supported(&io::Error::from_raw_os_error(
            libc::EINVAL
        )));
    }

    /// On a filesystem with full sync support a writable regular file
    /// can be durably synced.
    #[test]
    fn sync_file_durable_succeeds_on_regular_file() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let path = tmp_dir.path().join("synced.txt");
        fs::write(&path, b"bytes").unwrap();
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        sync_file_durable(&file).unwrap();
    }

    /// Flushing an ordinary directory succeeds when the filesystem supports
    /// directory synchronization, including after a new entry is created.
    #[test]
    fn sync_dir_durable_succeeds_on_regular_directory() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        fs::write(tmp_dir.path().join("entry.txt"), b"bytes").unwrap();
        sync_dir_durable(tmp_dir.path()).unwrap();
    }

    /// A missing directory is a real failure, not an unsupported operation.
    /// The caller must be told that the target directory has disappeared.
    #[test]
    fn sync_dir_durable_reports_missing_directory() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let gone = tmp_dir.path().join("vanished");
        let err =
            sync_dir_durable(&gone).expect_err("missing directory must fail the directory flush");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    /// A regular file at the supplied path is an error. The function must not
    /// treat it as the directory whose entries should be flushed.
    #[test]
    fn sync_dir_durable_rejects_regular_file() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let file_path = tmp_dir.path().join("not-a-directory");
        fs::write(&file_path, b"bytes").unwrap();
        let err =
            sync_dir_durable(&file_path).expect_err("regular file must fail the directory flush");
        assert_eq!(err.kind(), io::ErrorKind::NotADirectory);
    }

    /// A directory with no read permission (write-and-execute only) fails the
    /// required flush instead of being treated as unsupported: the read handle
    /// that directory `fsync` needs is denied, and key generation must fail
    /// rather than skip the barrier. Reproduces the audited `0o333` case.
    /// Unix-only. A privileged process bypasses the read check, so the test
    /// probes whether the denial actually took effect and asserts only then;
    /// the classifier test pins the errno decision everywhere.
    #[cfg(unix)]
    #[test]
    fn sync_dir_durable_reports_permission_denied_directory() {
        use std::os::unix::fs::PermissionsExt;

        let tmp_dir = tempfile::TempDir::new().unwrap();
        let locked = tmp_dir.path().join("writeonly");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o333)).unwrap();

        // Only assert when the read open is genuinely denied. A privileged
        // user (such as root) bypasses the check, and the barrier then
        // legitimately succeeds.
        let read_denied = fs::File::open(&locked).is_err();
        let result = sync_dir_durable(&locked);
        // Restore read permission so `TempDir` cleanup can remove the directory.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();

        if read_denied {
            let err = result.expect_err("a read-denied directory must fail the required flush");
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        }
    }

    /// Only errors that mean directory flushing is unavailable are treated as
    /// unsupported. Device I/O errors, path errors, and permission denial
    /// (`EACCES`) must remain genuine failures so the required key-generation
    /// barrier is never silently skipped.
    #[cfg(unix)]
    #[test]
    fn dir_sync_unsupported_classifies_unix_errnos() {
        for unavailable in [libc::ENOTSUP, libc::EINVAL, libc::EBADF] {
            assert!(
                dir_sync_unsupported(&io::Error::from_raw_os_error(unavailable)),
                "errno {unavailable} must classify as directory-flush unsupported"
            );
        }
        assert!(dir_sync_unsupported(&io::Error::new(
            io::ErrorKind::Unsupported,
            "synthesized unsupported"
        )));
        for genuine in [
            libc::EIO,
            libc::ENOENT,
            libc::ENOTDIR,
            libc::ENOSPC,
            libc::EACCES,
        ] {
            assert!(
                !dir_sync_unsupported(&io::Error::from_raw_os_error(genuine)),
                "errno {genuine} must propagate as a genuine failure"
            );
        }
    }

    /// Windows counterpart to the Unix error-classification test.
    #[cfg(windows)]
    #[test]
    fn dir_sync_unsupported_classifies_windows_errors() {
        // ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED, ERROR_INVALID_PARAMETER.
        for unavailable in [1, 50, 87] {
            assert!(
                dir_sync_unsupported(&io::Error::from_raw_os_error(unavailable)),
                "code {unavailable} must classify as directory-flush unsupported"
            );
        }
        // ERROR_FILE_NOT_FOUND, ERROR_IO_DEVICE, and ERROR_ACCESS_DENIED (5)
        // stay genuine: permission denial must fail the required barrier.
        for genuine in [2, 1117, 5] {
            assert!(
                !dir_sync_unsupported(&io::Error::from_raw_os_error(genuine)),
                "code {genuine} must propagate as a genuine failure"
            );
        }
    }

    /// Runs `f` on a worker thread and returns its result, failing the
    /// test if it has not finished within five seconds. A helper that
    /// opens a substituted FIFO without the directory flag waits for a
    /// writer that never arrives, which would hang the whole suite
    /// instead of reporting a failure.
    #[cfg(unix)]
    fn within_timeout<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(value) => value,
            Err(_) => panic!("{what} blocked instead of refusing a non-directory path"),
        }
    }

    /// A required directory flush must refuse a FIFO immediately. The
    /// open would otherwise wait for a writer, turning a durability
    /// barrier into an indefinite stall.
    #[cfg(unix)]
    #[test]
    fn sync_dir_durable_rejects_fifo_without_blocking() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let fifo = tmp_dir.path().join("pipe");
        crate::fs::paths::make_fifo(&fifo);

        let err = within_timeout("sync_dir_durable", move || sync_dir_durable(&fifo))
            .expect_err("a FIFO must fail the directory flush");
        assert_eq!(err.kind(), io::ErrorKind::NotADirectory);
    }

    /// The best-effort barrier re-resolves the parent path after the
    /// final name is already visible, so a local writer can substitute a
    /// FIFO for it in between. Opening that FIFO for reading would block
    /// until a writer appears, and there is no error to swallow while
    /// the open itself is stuck. The helper must return regardless.
    #[cfg(unix)]
    #[test]
    fn sync_parent_dir_does_not_block_on_a_fifo_parent() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let fifo = tmp_dir.path().join("parent");
        crate::fs::paths::make_fifo(&fifo);
        let child = fifo.join("committed.txt");

        within_timeout("sync_parent_dir", move || sync_parent_dir(&child));
    }

    /// Cleanup after a failed commit must resolve inside the directory
    /// the handle was opened on. Renaming that directory aside and
    /// leaving a symlink to an unrelated one in its place — what a local
    /// writer with access to the parent can do — must not redirect the
    /// removal onto the same-named file there.
    #[cfg(unix)]
    #[test]
    fn output_dir_removal_stays_in_the_anchored_directory() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let anchored = tmp_dir.path().join("out");
        let substituted = tmp_dir.path().join("elsewhere");
        fs::create_dir(&anchored).unwrap();
        fs::create_dir(&substituted).unwrap();
        fs::write(substituted.join("key"), "unrelated").unwrap();

        let handle = OutputDir::open(&anchored).unwrap();
        let ours = crate::fs::commit::create_file_at(
            &handle.dir,
            std::ffi::OsStr::new("key"),
            crate::fs::commit::STAGED_FILE_MODE,
        )
        .unwrap()
        .into_std();
        fs::rename(&anchored, tmp_dir.path().join("out.moved")).unwrap();
        std::os::unix::fs::symlink(&substituted, &anchored).unwrap();

        assert_eq!(
            handle.remove_if_retained(std::ffi::OsStr::new("key"), ours),
            RollbackOutcome::Removed
        );

        assert_eq!(
            fs::read_to_string(substituted.join("key")).unwrap(),
            "unrelated",
            "a substituted directory's file must not be removed"
        );
        assert!(
            !tmp_dir.path().join("out.moved").join("key").exists(),
            "the anchored directory's own entry must still be removed"
        );
    }

    /// Commits `b"committed"` under `name` in `dir` through `anchor` and
    /// returns the final path with the retained committed handle.
    fn commit_through_anchor(
        dir: &Path,
        anchor: &OutputDir,
        name: &str,
    ) -> (std::path::PathBuf, FinalizedFile) {
        let mut tmp = tempfile::Builder::new().tempfile_in(dir).unwrap();
        tmp.write_all(b"committed").unwrap();
        let path = dir.join(name);
        let finalized = finalize_file(tmp, &path, "Key file", anchor)
            .expect("the commit must succeed on a fresh name");
        (path, finalized)
    }

    /// The rollback tells its caller what it left behind: a file removed
    /// with its only name needs no report, a file with a second name
    /// survives under it, an entry that is no longer the committed file is
    /// left in place, and a name that is already gone cannot be confirmed.
    /// The rollback consumes the committed handle, so the on-disk state is
    /// final when it returns on every platform. The second-name case runs
    /// on Windows too, where NTFS has hard links and the report is
    /// load-bearing.
    #[test]
    fn rollback_reports_a_removed_linked_replaced_or_missing_file() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let dir = tmp_dir.path();
        let anchor = OutputDir::open(dir).unwrap();

        let (removed, finalized) = commit_through_anchor(dir, &anchor, "removed");
        assert_eq!(
            anchor.remove_published_if_retained(&removed, finalized),
            RollbackOutcome::Removed
        );
        assert!(!removed.exists(), "a file with one name must be gone");

        let (linked, finalized) = commit_through_anchor(dir, &anchor, "linked");
        let other_name = dir.join("linked.other");
        fs::hard_link(&linked, &other_name).unwrap();
        assert_eq!(
            anchor.remove_published_if_retained(&linked, finalized),
            RollbackOutcome::RemovedButLinked { link_count: 2 }
        );
        assert!(!linked.exists(), "the committed name must still be removed");
        assert_eq!(
            fs::read(&other_name).unwrap(),
            b"committed",
            "the other name is not this operation's to remove"
        );

        let (replaced, finalized) = commit_through_anchor(dir, &anchor, "replaced");
        let moved = dir.join("replaced.moved");
        fs::rename(&replaced, &moved).unwrap();
        fs::write(&replaced, b"planted").unwrap();
        assert_eq!(
            anchor.remove_published_if_retained(&replaced, finalized),
            RollbackOutcome::Replaced
        );
        assert_eq!(fs::read(&replaced).unwrap(), b"planted");
        assert_eq!(fs::read(&moved).unwrap(), b"committed");

        let (missing, finalized) = commit_through_anchor(dir, &anchor, "missing");
        fs::remove_file(&missing).unwrap();
        assert_eq!(
            anchor.remove_published_if_retained(&missing, finalized),
            RollbackOutcome::Unconfirmed
        );
    }

    /// The identity check and the removal are two steps, and a local
    /// writer can replace the entry between them. On Windows the removal
    /// acts on the retained handle, so the replacement survives and the
    /// committed file is the one removed — wherever it was moved to. Unix
    /// unlinks by name and cannot make this promise; `SECURITY.md` records
    /// that bound.
    #[cfg(windows)]
    #[test]
    fn rollback_removal_acts_on_the_committed_file_not_on_the_name() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let dir = tmp_dir.path();
        let anchor = OutputDir::open(dir).unwrap();
        let (path, finalized) = commit_through_anchor(dir, &anchor, "private.key");
        let moved = dir.join("private.moved");

        let outcome =
            anchor.remove_if_retained_with(path.file_name().unwrap(), finalized.file, || {
                fs::rename(&path, &moved).unwrap();
                fs::write(&path, b"planted").unwrap();
            });

        assert_eq!(outcome, RollbackOutcome::Removed);
        assert_eq!(
            fs::read(&path).unwrap(),
            b"planted",
            "an entry planted after the identity check must survive"
        );
        assert!(
            !moved.exists(),
            "the committed file must be removed under whatever name it holds"
        );
    }

    /// Only a complete removal leaves the operation's error unchanged.
    /// Every other outcome appends its report, and the error keeps its
    /// class so callers matching on it see what they saw before.
    #[test]
    fn rollback_report_is_appended_without_changing_the_error_class() {
        let path = Path::new("out/private.key");
        let io_error = || CryptoError::Io(io::Error::new(io::ErrorKind::TimedOut, "flush failed"));

        let unchanged = with_rollback_report(io_error(), RollbackOutcome::Removed, path);
        assert_eq!(unchanged.to_string(), "flush failed");

        let linked = with_rollback_report(
            io_error(),
            RollbackOutcome::RemovedButLinked { link_count: 2 },
            path,
        );
        assert_eq!(
            linked.to_string(),
            "flush failed; the removed private.key had 2 filesystem names, so a copy may remain under another name"
        );
        match linked {
            CryptoError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
            other => panic!("the I/O class must be kept, got {other:?}"),
        }

        let replaced = with_rollback_report(
            CryptoError::InvalidInput("Key file already exists: out/public.key".into()),
            RollbackOutcome::Replaced,
            path,
        );
        assert_eq!(
            replaced.to_string(),
            "Key file already exists: out/public.key; private.key was replaced during the operation and left in place, and the file this run wrote may remain under another name"
        );
        assert!(matches!(replaced, CryptoError::InvalidInput(_)));

        let unconfirmed = with_rollback_report(io_error(), RollbackOutcome::Unconfirmed, path);
        assert_eq!(
            unconfirmed.to_string(),
            "flush failed; the removal of private.key could not be confirmed"
        );
    }

    /// The durability barrier must flush the directory the handle was
    /// opened on, not whatever its path names later. After the
    /// directory is renamed aside, the handle-relative flush still
    /// succeeds against the moved directory, while the path-based
    /// flush of the old path has nothing left to open.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn output_dir_flush_durable_follows_the_handle_after_a_path_swap() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let anchored = tmp_dir.path().join("out");
        fs::create_dir(&anchored).unwrap();
        let handle = OutputDir::open(&anchored).unwrap();

        fs::rename(&anchored, tmp_dir.path().join("out.moved")).unwrap();

        handle
            .flush_durable()
            .expect("the flush must follow the handle, not the path");
        assert!(
            sync_dir_durable(&anchored).is_err(),
            "the old path no longer names a directory to flush"
        );
    }

    // Neither fallback can be reached through `finalize_file` on the
    // filesystems that host `cargo test` (they support the atomic
    // no-replace rename), so both are exercised directly. The fs-matrix
    // exFAT lane covers the errno-driven dispatch end to end.

    /// A zero inode number or file index is what a filesystem without
    /// identifiers reports for every object, so it is read as no
    /// identity rather than as one every object shares.
    #[test]
    fn a_zero_inode_is_no_identity() {
        assert_eq!(identity_pair(7, 0), None);
        assert_eq!(identity_pair(0, 0), None);
        assert_eq!(identity_pair(7, 1), Some((7, 1)));
        assert_eq!(identity_pair(0, 1), Some((0, 1)));
    }

    /// The link route commits the staged content under the final name
    /// and leaves no staged name behind. It is the route taken wherever
    /// the filesystem has hard links, which is the case for the
    /// filesystems hosting `cargo test`.
    ///
    /// The committed file must be the staged file itself, not a copy of
    /// it: callers pin the staged mode for a `.fcr` file and for
    /// `private.key`, so a commit that reproduced the content under
    /// fresh permissions would widen both.
    #[cfg(unix)]
    #[test]
    fn finalize_via_link_commits_and_drops_the_staged_name() {
        use std::os::unix::fs::PermissionsExt;

        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");

        let mut tmp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o600))
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"payload").unwrap();
        let tmp_path = tmp.path().to_path_buf();

        finalize_file_via_link_or_claim(tmp, &final_path, "Output").unwrap();
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "payload");
        assert!(
            !tmp_path.exists(),
            "staged name must not survive the commit"
        );
        assert_eq!(
            fs::metadata(&final_path).unwrap().permissions().mode() & 0o777,
            0o600,
            "the staged file's mode must survive the commit"
        );
    }

    /// A temp file staged outside the destination directory violates the
    /// [`finalize_file`] contract. The fallback must refuse it by identity
    /// before creating anything at the final name, rather than let the
    /// mismatch surface later as placeholder churn and an orphaned staged
    /// file. The same rejection covers a staged entry deleted or replaced
    /// by a local writer, so it reports as a filesystem condition, not an
    /// internal error. The refused temp is removed by its own destructor
    /// at the path it was actually created.
    #[cfg(unix)]
    #[test]
    fn fallback_refuses_a_temp_staged_outside_the_destination_directory() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let elsewhere = tmp_dir.path().join("elsewhere");
        let out = tmp_dir.path().join("out");
        fs::create_dir(&elsewhere).unwrap();
        fs::create_dir(&out).unwrap();
        let final_path = out.join("out.txt");

        let mut tmp = tempfile::Builder::new().tempfile_in(&elsewhere).unwrap();
        tmp.write_all(b"payload").unwrap();
        let tmp_path = tmp.path().to_path_buf();

        let error = finalize_file_via_link_or_claim(tmp, &final_path, "Output")
            .expect_err("a temp staged elsewhere must be refused");
        assert!(!error.committed());
        assert!(
            matches!(
                error.into_crypto_error(),
                CryptoError::InvalidInput(message)
                    if message.contains("is not the entry under its name")
            ),
            "the refusal must name the staged-entry mismatch"
        );
        assert_eq!(
            fs::read_dir(&out).unwrap().count(),
            0,
            "the refusal must precede any entry at the final name"
        );
        assert!(
            !tmp_path.exists(),
            "the refused temp is cleaned up at its own path"
        );
    }

    /// The staged-entry verification precedes every removal on the fallback
    /// route. With the temp staged elsewhere and a final path with no last
    /// component, the refusal must be the identity one, and a same-named
    /// entry in the anchored directory must survive.
    #[cfg(unix)]
    #[test]
    fn fallback_verifies_the_staged_temp_before_any_removal() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let elsewhere = tmp_dir.path().join("elsewhere");
        let out = tmp_dir.path().join("out");
        fs::create_dir(&elsewhere).unwrap();
        fs::create_dir(&out).unwrap();

        let mut tmp = tempfile::Builder::new().tempfile_in(&elsewhere).unwrap();
        tmp.write_all(b"payload").unwrap();
        let tmp_path = tmp.path().to_path_buf();
        let planted = out.join(tmp_path.file_name().unwrap());
        fs::write(&planted, b"unrelated").unwrap();

        let error = finalize_file_via_link_or_claim_in(
            tmp,
            Path::new("/"),
            "Output",
            &OutputDir::open(&out).unwrap(),
        )
        .expect_err("an unverified staged temp must be refused");
        assert!(!error.committed());
        assert!(
            matches!(
                error.into_crypto_error(),
                CryptoError::InvalidInput(message)
                    if message.contains("is not the entry under its name")
            ),
            "the identity refusal must come before the missing-name error"
        );
        assert_eq!(
            fs::read(&planted).unwrap(),
            b"unrelated",
            "the same-named entry in the anchor must survive"
        );
        assert!(!tmp_path.exists(), "the temp is removed at its own path");
    }

    /// A final path with no last component still refuses, and the staged
    /// temp — verified as the anchored entry by then — is removed through
    /// the anchor.
    #[cfg(unix)]
    #[test]
    fn fallback_removes_a_verified_temp_when_the_final_path_has_no_name() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"payload").unwrap();
        let tmp_path = tmp.path().to_path_buf();

        let error = finalize_file_via_link_or_claim_in(
            tmp,
            Path::new("/"),
            "Output",
            &OutputDir::open(tmp_dir.path()).unwrap(),
        )
        .expect_err("a final path with no last component must be refused");
        assert!(!error.committed());
        match error.into_crypto_error() {
            CryptoError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidInput),
            other => panic!("expected an I/O error, got {other:?}"),
        }
        assert!(!tmp_path.exists(), "the staged temp must be removed");
    }

    /// Once the final hard link exists, a staged-name unlink failure must not
    /// be swallowed. It is a post-commit error, and both complete links are
    /// preserved so no bare-name rollback can delete a concurrent replacement.
    #[cfg(unix)]
    #[test]
    fn finalize_via_link_reports_a_retained_staging_link() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"payload").unwrap();
        let tmp_name = tmp.path().file_name().unwrap().to_os_string();
        let output_dir = OutputDir::open(tmp_dir.path()).unwrap();
        output_dir
            .dir
            .hard_link(&tmp_name, &output_dir.dir, final_path.file_name().unwrap())
            .unwrap();

        let error =
            finish_link_commit_with_remove(tmp, &output_dir, &final_path, &tmp_name, |_, _| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected staged unlink failure",
                ))
            })
            .expect_err("a retained temporary name must not report success");

        assert!(error.committed());
        let rendered = error.into_crypto_error().to_string();
        assert!(
            rendered.contains("temporary name") && rendered.contains("could not be removed"),
            "the retained link must be explicit, got: {rendered}"
        );
        assert_eq!(fs::read(&final_path).unwrap(), b"payload");
        assert_eq!(fs::read(tmp_dir.path().join(tmp_name)).unwrap(), b"payload");
    }

    /// A concurrent directory writer can rename the staged link after the
    /// final link exists. The attempted unlink then reports `NotFound`, which
    /// is harmless only when the committed inode actually has one link left.
    #[cfg(unix)]
    #[test]
    fn finalize_via_link_rejects_a_renamed_staging_link_after_not_found() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");
        let hidden_name = std::ffi::OsString::from("moved-staging-link");

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"payload").unwrap();
        let tmp_name = tmp.path().file_name().unwrap().to_os_string();
        let output_dir = OutputDir::open(tmp_dir.path()).unwrap();
        output_dir
            .dir
            .hard_link(&tmp_name, &output_dir.dir, final_path.file_name().unwrap())
            .unwrap();

        let error = finish_link_commit_with_remove(
            tmp,
            &output_dir,
            &final_path,
            &tmp_name,
            |dir, name| {
                dir.rename(name, dir, &hidden_name)?;
                dir.remove_file(name)
            },
        )
        .expect_err("a renamed second link must not report success");

        assert!(error.committed());
        let rendered = error.into_crypto_error().to_string();
        assert!(
            rendered.contains("has 2 filesystem names"),
            "the retained inode link must be explicit, got: {rendered}"
        );
        assert_eq!(fs::read(&final_path).unwrap(), b"payload");
        assert_eq!(
            fs::read(tmp_dir.path().join(hidden_name)).unwrap(),
            b"payload"
        );
        assert!(!tmp_dir.path().join(tmp_name).exists());
    }

    /// Renaming the staged link aside and planting a replacement at its old
    /// name can make the unlink itself succeed. The inode link count must still
    /// expose the retained original rather than trusting that return value.
    #[cfg(unix)]
    #[test]
    fn finalize_via_link_rejects_a_hidden_link_when_replacement_unlink_succeeds() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");
        let hidden_name = std::ffi::OsString::from("moved-staging-link");

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"payload").unwrap();
        let tmp_name = tmp.path().file_name().unwrap().to_os_string();
        let output_dir = OutputDir::open(tmp_dir.path()).unwrap();
        output_dir
            .dir
            .hard_link(&tmp_name, &output_dir.dir, final_path.file_name().unwrap())
            .unwrap();

        let error = finish_link_commit_with_remove(
            tmp,
            &output_dir,
            &final_path,
            &tmp_name,
            |dir, name| {
                dir.rename(name, dir, &hidden_name)?;
                let mut options = cap_std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                let mut replacement = dir.open_with(name, &options)?;
                replacement.write_all(b"replacement")?;
                drop(replacement);
                dir.remove_file(name)
            },
        )
        .expect_err("a hidden second link must not report success");

        assert!(error.committed());
        let rendered = error.into_crypto_error().to_string();
        assert!(
            rendered.contains("has 2 filesystem names"),
            "the retained inode link must be explicit, got: {rendered}"
        );
        assert_eq!(fs::read(&final_path).unwrap(), b"payload");
        assert_eq!(
            fs::read(tmp_dir.path().join(hidden_name)).unwrap(),
            b"payload"
        );
        assert!(!tmp_dir.path().join(tmp_name).exists());
    }

    /// The link route refuses an occupied final path with the same typed
    /// message as the atomic path, without creating a placeholder first.
    #[cfg(unix)]
    #[test]
    fn finalize_via_link_refuses_to_overwrite() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");
        fs::write(&final_path, "existing").unwrap();

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"new").unwrap();
        let tmp_path = tmp.path().to_path_buf();

        let error = finalize_file_via_link_or_claim(tmp, &final_path, "Output")
            .expect_err("an occupied output must fail before commit");
        assert!(!error.committed());
        match error.into_crypto_error() {
            CryptoError::InvalidInput(msg) => {
                assert!(msg.starts_with("Output already exists: "), "got: {msg}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "existing");
        assert!(!tmp_path.exists(), "temp file must be removed on failure");
    }

    /// A dangling symlink at the final path counts as occupied for the
    /// link route as well: `link` does not follow the target name, so it
    /// refuses rather than committing through the link.
    #[cfg(unix)]
    #[test]
    fn finalize_via_link_refuses_dangling_symlink_at_target() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");
        std::os::unix::fs::symlink(tmp_dir.path().join("nowhere"), &final_path).unwrap();

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"new").unwrap();

        let error = finalize_file_via_link_or_claim(tmp, &final_path, "Output")
            .expect_err("a dangling final symlink must fail before commit");
        assert!(!error.committed());
        match error.into_crypto_error() {
            CryptoError::InvalidInput(msg) => {
                assert!(msg.starts_with("Output already exists: "), "got: {msg}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        let meta = fs::symlink_metadata(&final_path).unwrap();
        assert!(meta.file_type().is_symlink(), "symlink must be left as-is");
        assert!(
            !tmp_dir.path().join("nowhere").exists(),
            "the link target must not have been created"
        );
    }

    /// Commits `tmp` the way a caller does: through an anchor opened on
    /// the destination directory. Tests that exercise the anchor's own
    /// lifetime open and hold their own.
    fn commit_to(
        tmp: NamedTempFile,
        final_path: &Path,
        label: &str,
    ) -> Result<FinalizedFile, FinalizeFileError> {
        let anchor = OutputDir::open_for_commit(crate::fs::paths::parent_or_cwd(final_path))
            .expect("the destination directory must open as a commit anchor");
        finalize_file(tmp, final_path, label, &anchor)
    }

    /// Drives the claim route the way `finalize_file_via_link_or_claim_in`
    /// does, skipping the link the entry point would take first: a
    /// filesystem with hard links never reaches the claim through it.
    #[cfg(unix)]
    fn claim_commit(
        tmp: NamedTempFile,
        final_path: &Path,
        label: &str,
        output_dir: &OutputDir,
    ) -> Result<FinalizedFile, FinalizeFileError> {
        claim_commit_with(tmp, final_path, label, output_dir, |_| {})
    }

    /// [`claim_commit`] with the window between the claim and the rename
    /// over it, where a local writer's replacement would land.
    #[cfg(unix)]
    fn claim_commit_with(
        tmp: NamedTempFile,
        final_path: &Path,
        label: &str,
        output_dir: &OutputDir,
        after_claim: impl FnOnce(&cap_std::fs::Dir),
    ) -> Result<FinalizedFile, FinalizeFileError> {
        finalize_file_commit(
            tmp,
            final_path,
            label,
            output_dir,
            |anchor, staged, final_name| {
                crate::fs::commit::commit_by_claim_with(
                    anchor,
                    staged,
                    final_name,
                    CommitKind::File,
                    after_claim,
                )
            },
        )
    }

    /// Claim fallback commits the temp file when the final name is
    /// free; no placeholder survives.
    #[cfg(unix)]
    #[test]
    fn finalize_via_claim_succeeds_when_target_missing() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"payload").unwrap();
        let tmp_path = tmp.path().to_path_buf();

        claim_commit(
            tmp,
            &final_path,
            "Output",
            &OutputDir::open(tmp_dir.path()).unwrap(),
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "payload");
        assert!(!tmp_path.exists());
    }

    /// A hard link planted against the staged temp file survives the claim
    /// commit as a second name for the committed inode, so the route must
    /// report it after commit instead of succeeding.
    #[cfg(unix)]
    #[test]
    fn finalize_via_claim_rejects_a_second_link_to_the_committed_file() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"payload").unwrap();
        let planted = tmp_dir.path().join("planted.txt");
        fs::hard_link(tmp.path(), &planted).unwrap();

        let error = claim_commit(
            tmp,
            &final_path,
            "Output",
            &OutputDir::open(tmp_dir.path()).unwrap(),
        )
        .expect_err("a second link to the committed inode must fail after commit");
        assert!(error.committed());
        let message = error.into_crypto_error().to_string();
        assert!(message.contains("has 2 filesystem names"), "got: {message}");
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "payload");
        assert_eq!(fs::read_to_string(&planted).unwrap(), "payload");
    }

    /// Claim fallback refuses an occupied final path with the same
    /// typed message as the atomic path, leaves the existing content
    /// untouched, and removes the temp file.
    #[cfg(unix)]
    #[test]
    fn finalize_via_claim_refuses_to_overwrite() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");
        fs::write(&final_path, "existing").unwrap();

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"new").unwrap();
        let tmp_path = tmp.path().to_path_buf();

        let error = claim_commit(
            tmp,
            &final_path,
            "Output",
            &OutputDir::open(tmp_dir.path()).unwrap(),
        )
        .expect_err("an occupied output must fail before commit");
        assert!(!error.committed());
        match error.into_crypto_error() {
            CryptoError::InvalidInput(msg) => {
                assert!(msg.starts_with("Output already exists: "), "got: {msg}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "existing");
        assert!(!tmp_path.exists(), "temp file must be removed on failure");
    }

    /// A dangling symlink at the final path counts as occupied for the
    /// claim (`create_new` refuses to follow or replace it), matching
    /// the no-clobber contract of the atomic path.
    #[cfg(unix)]
    #[test]
    fn finalize_via_claim_refuses_dangling_symlink_at_target() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");
        std::os::unix::fs::symlink(tmp_dir.path().join("nowhere"), &final_path).unwrap();

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"new").unwrap();

        let error = claim_commit(
            tmp,
            &final_path,
            "Output",
            &OutputDir::open(tmp_dir.path()).unwrap(),
        )
        .expect_err("a dangling final symlink must fail before commit");
        assert!(!error.committed());
        match error.into_crypto_error() {
            CryptoError::InvalidInput(msg) => {
                assert!(msg.starts_with("Output already exists: "), "got: {msg}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        let meta = fs::symlink_metadata(&final_path).unwrap();
        assert!(meta.file_type().is_symlink(), "symlink must be left as-is");
    }

    /// A failed rename step leaves the placeholder at the final name and
    /// reports it, because the empty file then holds that name against a
    /// further attempt. Forced by removing the staged file once the
    /// claim exists, which leaves the rename nothing to move.
    #[cfg(unix)]
    #[test]
    fn finalize_via_claim_leaves_the_claim_and_reports_it_when_the_rename_fails() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");

        let tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        let tmp_name = tmp.path().file_name().unwrap().to_os_string();
        let output_dir = OutputDir::open(tmp_dir.path()).unwrap();

        let err = claim_commit_with(tmp, &final_path, "Output", &output_dir, |dir| {
            dir.remove_file(&tmp_name).unwrap();
        })
        .expect_err("a rename with no staged file must fail the commit");
        assert!(!err.committed());
        let message = match err.into_crypto_error() {
            CryptoError::Io(e) => e.to_string(),
            other => panic!("expected an I/O failure, got {other:?}"),
        };
        assert!(
            message.contains("out.txt") && message.contains("may still be occupied"),
            "the name left occupied must be reported, got: {message}"
        );
        let left = fs::metadata(&final_path).expect("the placeholder stays at the final name");
        assert!(left.is_file() && left.len() == 0, "{left:?}");
    }

    /// A local writer can remove the placeholder and plant an entry of
    /// its own before the rename. When the rename then fails — the staged
    /// file is removed in the same window — that planted entry must be
    /// left where it is: a failed commit removes nothing from the final
    /// name.
    #[cfg(unix)]
    #[test]
    fn finalize_via_claim_leaves_a_replaced_claim_in_place() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");
        let final_name = final_path.file_name().unwrap();

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"payload").unwrap();
        let tmp_name = tmp.path().file_name().unwrap().to_os_string();
        let output_dir = OutputDir::open(tmp_dir.path()).unwrap();

        let err = claim_commit_with(tmp, &final_path, "Output", &output_dir, |dir| {
            dir.remove_file(final_name).unwrap();
            dir.write(final_name, b"planted").unwrap();
            dir.remove_file(&tmp_name).unwrap();
        })
        .expect_err("a rename with no staged file must fail the commit");
        assert!(!err.committed());
        assert_eq!(
            fs::read(&final_path).unwrap(),
            b"planted",
            "an entry planted in place of the placeholder must survive"
        );
    }

    /// An anchor threaded in by the caller is the directory the fallback
    /// commits in. Swap the output path after that anchor is opened and mint
    /// a same-named victim at the old path: the commit must land in the
    /// anchored (moved) directory, the victim must survive, and the final
    /// identity check must report a post-commit path-change error. Pins what
    /// the caller-threaded `anchor` argument guarantees for this fallback:
    /// the directory that receives the commit is also the one key-generation
    /// rollback acts on. Linux and macOS use the anchor for their directory
    /// barrier as well.
    #[cfg(unix)]
    #[test]
    fn anchored_fallback_commits_in_the_threaded_anchor_across_a_path_swap() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let orig = tmp_dir.path().join("orig");
        fs::create_dir(&orig).unwrap();
        let final_path = orig.join("out.txt");

        let mut tmp = tempfile::Builder::new().tempfile_in(&orig).unwrap();
        tmp.write_all(b"payload").unwrap();
        let anchor = OutputDir::open(&orig).unwrap();

        let moved = tmp_dir.path().join("moved");
        fs::rename(&orig, &moved).unwrap();
        fs::create_dir(&orig).unwrap();
        fs::write(&final_path, "victim").unwrap();

        let error = finalize_file_via_link_or_claim_in(tmp, &final_path, "Output", &anchor)
            .expect_err("the ambient path no longer names the committed file");
        assert!(error.committed());
        assert!(
            matches!(
                error.into_crypto_error(),
                CryptoError::InvalidInput(message)
                    if message.contains("reported path changed")
            ),
            "the path mismatch must be reported explicitly"
        );
        assert_eq!(
            fs::read_to_string(moved.join("out.txt")).unwrap(),
            "payload",
            "the commit must land in the anchored directory"
        );
        assert_eq!(
            fs::read_to_string(&final_path).unwrap(),
            "victim",
            "the entry at the old path must survive"
        );
    }

    /// The claim route commits through its retained anchor, but must not report
    /// the old ambient path after that directory is swapped. The real output
    /// lands in the moved directory, the substituted victim survives, and the
    /// final identity check reports a post-commit path-change error.
    #[cfg(unix)]
    #[test]
    fn finalize_via_claim_rejects_the_reported_path_after_a_directory_swap() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let orig = tmp_dir.path().join("orig");
        fs::create_dir(&orig).unwrap();
        let final_path = orig.join("out.txt");

        let mut tmp = tempfile::Builder::new().tempfile_in(&orig).unwrap();
        tmp.write_all(b"payload").unwrap();
        let tmp_name = tmp.path().file_name().unwrap().to_os_string();
        let output_dir = OutputDir::open(&orig).unwrap();

        // Swap: move the anchored directory aside and mint a
        // replacement holding a same-named victim.
        let moved = tmp_dir.path().join("moved");
        fs::rename(&orig, &moved).unwrap();
        fs::create_dir(&orig).unwrap();
        fs::write(&final_path, "victim").unwrap();

        let error = claim_commit(tmp, &final_path, "Output", &output_dir)
            .expect_err("the ambient path no longer names the committed file");
        assert!(error.committed());
        assert!(
            matches!(
                error.into_crypto_error(),
                CryptoError::InvalidInput(message)
                    if message.contains("reported path changed")
            ),
            "the path mismatch must be reported explicitly"
        );

        assert_eq!(
            fs::read_to_string(moved.join("out.txt")).unwrap(),
            "payload",
            "the commit must land in the anchored directory"
        );
        assert_eq!(
            fs::read_to_string(&final_path).unwrap(),
            "victim",
            "the entry at the swapped-in path must survive the commit"
        );
        assert!(
            !moved.join(&tmp_name).exists(),
            "the staged entry must not survive the commit"
        );
    }

    #[test]
    fn rename_no_clobber_refuses_to_overwrite_dir() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let from = tmp_dir.path().join("src");
        let to = tmp_dir.path().join("dst");
        fs::create_dir(&from).unwrap();
        fs::write(from.join("inner.txt"), "new").unwrap();
        fs::create_dir(&to).unwrap();
        fs::write(to.join("existing.txt"), "existing").unwrap();

        let err = rename_no_clobber(&from, &to).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(from.exists(), "source should not have been moved");
        assert!(
            to.join("existing.txt").exists(),
            "destination should be untouched"
        );
    }

    #[test]
    fn rename_no_clobber_succeeds_when_target_missing_dir() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let from = tmp_dir.path().join("src");
        let to = tmp_dir.path().join("dst");
        fs::create_dir(&from).unwrap();
        fs::write(from.join("payload.txt"), "hello").unwrap();

        rename_no_clobber(&from, &to).unwrap();

        assert!(!from.exists(), "source should have been moved");
        assert!(to.is_dir(), "destination should exist as a directory");
        assert_eq!(fs::read_to_string(to.join("payload.txt")).unwrap(), "hello",);
    }

    #[test]
    fn rename_no_clobber_handles_regular_file() {
        // The helper supports both directory entries and regular files;
        // prove the file case works with both the success path and the
        // refuse-to-overwrite path even though archive single-file
        // promotion prefers `promote_single_file_no_clobber` on the
        // targets that still route through this module.
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let from = tmp_dir.path().join("staged.txt");
        let to = tmp_dir.path().join("final.txt");
        fs::write(&from, "payload").unwrap();

        rename_no_clobber(&from, &to).unwrap();
        assert!(!from.exists());
        assert_eq!(fs::read_to_string(&to).unwrap(), "payload");

        // Re-stage and confirm the no-clobber branch also fires on files.
        fs::write(&from, "second").unwrap();
        let err = rename_no_clobber(&from, &to).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&to).unwrap(), "payload");
        assert_eq!(fs::read_to_string(&from).unwrap(), "second");
    }

    #[test]
    fn promote_single_file_succeeds_when_target_missing() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let from = tmp_dir.path().join("staged.txt");
        let to = tmp_dir.path().join("final.txt");
        fs::write(&from, "payload").unwrap();

        promote_single_file_no_clobber(&from, &to).unwrap();
        assert!(!from.exists(), "Source should have been moved");
        assert_eq!(fs::read_to_string(&to).unwrap(), "payload");
    }

    #[test]
    fn promote_single_file_refuses_existing_target() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let from = tmp_dir.path().join("staged.txt");
        let to = tmp_dir.path().join("final.txt");
        fs::write(&from, "new").unwrap();
        fs::write(&to, "existing").unwrap();

        let err = promote_single_file_no_clobber(&from, &to).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&to).unwrap(), "existing");
    }

    /// Pins the RetainOnError contract at the helper level: when the
    /// kernel refuses promotion (final name already taken), the staging
    /// file `from` must remain on disk. Regression-protects the
    /// `disable_cleanup` step inside `promote_single_file_no_clobber`
    /// against an inadvertent revert that would let `TempPath`'s
    /// destructor `remove_file(from)` after the failure path returns.
    #[test]
    fn promote_single_file_leaves_source_in_place_after_refusal() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let from = tmp_dir.path().join("staged.txt");
        let to = tmp_dir.path().join("final.txt");
        fs::write(&from, "new").unwrap();
        fs::write(&to, "existing").unwrap();

        let _ = promote_single_file_no_clobber(&from, &to).unwrap_err();
        assert!(
            from.exists(),
            "RetainOnError contract: source must remain after refused promotion"
        );
        assert_eq!(fs::read_to_string(&from).unwrap(), "new");
    }

    /// `sync_parent_dir` is a best-effort durability hint — it must
    /// swallow every failure so a callsite (`finalize_file`,
    /// `rename_no_clobber`) returning success is not retroactively
    /// flipped to an error after the final path is already visible.
    /// Pin the swallow with a missing parent: opening the parent dirfd
    /// fails, but the helper still returns `()` so finalization stays
    /// successful.
    #[test]
    fn sync_parent_dir_swallows_missing_parent() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let phantom_parent = tmp_dir.path().join("does-not-exist");
        let phantom_child = phantom_parent.join("child.txt");
        // No `unwrap` — `sync_parent_dir` returns `()` even though
        // `parent_or_cwd(phantom_child) = phantom_parent` is missing.
        sync_parent_dir(&phantom_child);
    }
}
