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

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};

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
/// `rustix`. Windows keeps the path-based promotion in `fs::atomic`,
/// because a handle-relative no-replace rename there needs an `unsafe`
/// Win32 call the crate forbids; see `SECURITY.md`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn rename_at_no_clobber(dir: &Dir, from: &OsStr, to: &OsStr) -> io::Result<()> {
    use std::os::fd::AsFd;

    use rustix::fs::{RenameFlags, renameat_with};

    renameat_with(dir.as_fd(), from, dir.as_fd(), to, RenameFlags::NOREPLACE)
        .map_err(io::Error::from)?;
    // Best-effort durability: flush the directory so the rename survives
    // a crash, mirroring the parent-directory sync the path-based
    // `fs::atomic` helpers perform.
    sync_dir_handle(dir);
    Ok(())
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
    use std::os::fd::AsFd;

    use rustix::fs::{Mode, OFlags, fsync, openat};

    if let Ok(sync_fd) = openat(
        dir.as_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        let _ = fsync(&sync_fd);
    }
}

/// No-op on targets without this `openat`/`fsync` directory-sync path.
/// Windows promotion uses the path-based `fs::atomic` helpers instead.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn sync_dir_handle(_dir: &Dir) {}

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
/// shared by the per-component walks ([`walk_to_parent_readonly`],
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

/// Ensures `name` exists as a directory under `parent`, returning a
/// fresh handle to it. Opens with no-follow first; on `NotFound`
/// creates and re-opens. A symlink at that name aborts with the typed
/// "Symlink in extraction path" diagnostic; on Windows, a junction at
/// the name fails the same way via [`finalize_dir_open`].
pub(crate) fn ensure_dir(parent: &Dir, name: &OsStr) -> Result<Dir, CryptoError> {
    match parent.open_dir_nofollow(name) {
        Ok(dir) => finalize_dir_open(dir, name, SYMLINK_IN_EXTRACTION_PATH),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Create, re-open via no-follow as a TOCTOU race detector,
            // and apply the initial permissive mode by handle. If
            // anything substituted the freshly-created entry with a
            // symlink/reparse point, the helper fails closed.
            create_dir_with_default_mode(parent, name)
        }
        Err(e) => Err(classify_open_failure(
            parent,
            name,
            e,
            SYMLINK_IN_EXTRACTION_PATH,
            &Path::new(name).display().to_string(),
        )),
    }
}

/// Creates a fresh directory `name` under `parent` and opens it with
/// no-follow. Fails with `AlreadyExists` if anything — including a
/// symlink, on Windows including a junction — already exists at that
/// name.
pub(crate) fn mkdir_strict(parent: &Dir, name: &OsStr) -> Result<Dir, CryptoError> {
    create_dir_with_default_mode(parent, name)
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
    create_dir_initial_mode(parent, name)?;

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
fn create_dir_initial_mode(parent: &Dir, name: &OsStr) -> Result<(), CryptoError> {
    use cap_std::fs::{DirBuilder, DirBuilderExt};
    let mut builder = DirBuilder::new();
    builder.mode(DIR_CREATE_MODE);
    parent
        .create_dir_with(name, &builder)
        .map_err(CryptoError::Io)
}

#[cfg(not(unix))]
fn create_dir_initial_mode(parent: &Dir, name: &OsStr) -> Result<(), CryptoError> {
    parent.create_dir(name).map_err(CryptoError::Io)
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

/// Walks `rel` under `root`, creating intermediate directories as
/// needed. Returns a fresh handle to the final component's parent and
/// the final component's name. Every intermediate open goes through
/// no-follow + reparse-check, so a substituted symlink or junction
/// anywhere along the path fails closed with the typed "Symlink in
/// extraction path" diagnostic.
pub(crate) fn walk_to_parent(root: &Dir, rel: &Path) -> Result<(Dir, OsString), CryptoError> {
    let mut components: Vec<Component<'_>> = rel.components().collect();
    let last = components.pop().ok_or(CryptoError::InternalInvariant(
        "archive entry resolved to empty path",
    ))?;
    let final_name = normal_component(last, rel)?.to_os_string();

    let mut cur = root.try_clone().map_err(CryptoError::Io)?;
    for component in components {
        let name = normal_component(component, rel)?;
        cur = ensure_dir(&cur, name)?;
    }
    Ok((cur, final_name))
}

/// Walks `rel` under `root` opening existing dirs only — returns the
/// final component's parent handle and the final component's name.
/// Read-only counterpart to [`walk_to_parent`] (which creates
/// intermediate dirs); used by the encode-side per-entry content
/// reopen so the writer's source walk gets the same per-component
/// no-follow + reparse-check guarantee the reader has.
///
/// `rel` MUST have at least one component; an empty path is treated
/// as an internal invariant violation, mirroring [`walk_to_parent`].
pub(crate) fn walk_to_parent_readonly(
    root: &Dir,
    rel: &Path,
) -> Result<(Dir, OsString), CryptoError> {
    let mut components: Vec<Component<'_>> = rel.components().collect();
    let last = components.pop().ok_or(CryptoError::InternalInvariant(
        "archive entry resolved to empty path",
    ))?;
    let final_name = normal_component(last, rel)?.to_os_string();

    let mut cur = root.try_clone().map_err(CryptoError::Io)?;
    for component in components {
        let name = normal_component(component, rel)?;
        cur = open_child_dir_nofollow(&cur, name, SYMLINK_IN_ARCHIVE_SOURCE)?;
    }
    Ok((cur, final_name))
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
        cur = open_child_dir_nofollow(&cur, name, SYMLINK_IN_EXTRACTION_PATH)?;
    }
    Ok(cur)
}

/// Opens an existing regular file under `parent` with no-follow + the
/// Windows reparse-point post-check. File-side parallel of
/// [`open_dir_at_rel`]; used by the post-rename root-file chmod
/// (`decode::apply_root_file_mode`) so the chmod runs against a
/// freshly-opened handle rather than through a re-resolved path. A
/// symlink at that name aborts with the typed "Symlink in extraction
/// path" diagnostic; on Windows, a reparse point at the name fails the
/// same way via the post-check.
pub(crate) fn open_file_nofollow(parent: &Dir, name: &OsStr) -> Result<File, CryptoError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
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

/// Post-open finalize for a regular-file handle. On Windows, rejects
/// reparse points (cap-fs-ext's `FollowSymlinks::No` translates to
/// `FILE_FLAG_OPEN_REPARSE_POINT`, which would otherwise let an
/// attacker-substituted symlink at the path open as a regular-file
/// handle and have its bits flipped). No-op on Unix where the kernel's
/// `O_NOFOLLOW` semantics already give the equivalent invariant.
#[cfg(windows)]
fn finalize_file_open(file: File, name: &OsStr) -> Result<File, CryptoError> {
    use cap_std::fs::MetadataExt;
    let meta = file.metadata().map_err(CryptoError::Io)?;
    reject_reparse_attributes(meta.file_attributes(), name, SYMLINK_IN_EXTRACTION_PATH)?;
    Ok(file)
}

#[cfg(not(windows))]
fn finalize_file_open(file: File, _name: &OsStr) -> Result<File, CryptoError> {
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
    fn ensure_dir_rejects_symlink_to_outside() {
        use std::os::unix::fs as unix_fs;
        let tmp = tempfile::TempDir::new().unwrap();
        unix_fs::symlink("/tmp", tmp.path().join("evil")).unwrap();

        let parent = open_anchor(tmp.path()).unwrap();
        let err = ensure_dir(&parent, OsStr::new("evil")).unwrap_err();
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

    /// In-sandbox relative symlink: hardened helper must reject.
    /// Plain `Dir::open_dir` would FOLLOW this (capability-confined
    /// but not no-follow); the hardened backend uses
    /// `cap_fs_ext::open_dir_nofollow` to refuse symlinks regardless
    /// of where the target resolves.
    #[cfg(unix)]
    #[test]
    fn ensure_dir_rejects_in_sandbox_symlink() {
        use std::os::unix::fs as unix_fs;
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir_all(root.join("real")).unwrap();
        unix_fs::symlink("real", root.join("link")).unwrap();

        let parent = open_anchor(&root).unwrap();
        let err = ensure_dir(&parent, OsStr::new("link")).unwrap_err();
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
        let err = walk_to_parent(&parent, Path::new("link/file.txt")).unwrap_err();
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
        let err = walk_to_parent(&parent, Path::new("a/b/file.txt")).unwrap_err();
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
    fn ensure_dir_rejects_relative_escape_symlink() {
        use std::os::unix::fs as unix_fs;
        let tmp = tempfile::TempDir::new().unwrap();
        let inside = tmp.path().join("inside");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&inside).unwrap();
        fs::create_dir_all(&outside).unwrap();
        unix_fs::symlink("../outside", inside.join("escape")).unwrap();

        let parent = open_anchor(&inside).unwrap();
        let result = ensure_dir(&parent, OsStr::new("escape"));
        assert!(result.is_err());
        assert!(outside.read_dir().unwrap().next().is_none());
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
        let result = walk_to_parent(&parent, Path::new("../outside/x.txt"));
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
        // open_dir_at_rel + chmod_dir_handle is the chmod-time recipe.
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

        rename_at_no_clobber(&handle, OsStr::new("root.incomplete"), OsStr::new("root")).unwrap();

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
        let err = rename_at_no_clobber(&handle, OsStr::new("root.incomplete"), OsStr::new("root"))
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(out.join("root")).unwrap(), b"existing");
        assert_eq!(fs::read(out.join("root.incomplete")).unwrap(), b"new");
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

    /// Creates an NTFS junction (mount point) via `mklink /J`. Junctions
    /// are reparse points but `is_symlink()` returns FALSE for them, so
    /// only the explicit `FILE_ATTRIBUTE_REPARSE_POINT` post-check
    /// catches them. `mklink /J` does NOT require elevated privileges,
    /// so this works on standard Windows accounts.
    #[cfg(windows)]
    fn try_make_junction(target: &Path, junction: &Path) -> io::Result<()> {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(junction)
            .arg(target)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "mklink /J failed with exit code {status}"
            )))
        }
    }

    /// Windows symlink-dir at the leaf of an `ensure_dir` call. Hardened
    /// helper must reject — same invariant as Unix.
    #[cfg(windows)]
    #[test]
    fn ensure_dir_rejects_windows_symlink_dir() {
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
        let _err = ensure_dir(&parent, OsStr::new("link")).unwrap_err();
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
        let result = walk_to_parent(&parent, Path::new("link/file.txt"));
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
    fn ensure_dir_rejects_windows_junction() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("target");
        fs::create_dir_all(&target).unwrap();
        let junction = tmp.path().join("junction");

        if require_or_skip("mklink /J", try_make_junction(&target, &junction)).is_none() {
            return;
        }

        let parent = open_anchor(tmp.path()).unwrap();
        let err = ensure_dir(&parent, OsStr::new("junction")).unwrap_err();
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
        let result = walk_to_parent(&parent, Path::new("link/file.txt"));
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
