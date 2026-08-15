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
//! Three primitives are provided:
//!
//! - [`finalize_file`] — promote a [`tempfile::NamedTempFile`] to its final
//!   path with atomic no-clobber semantics. Used by encryption output and
//!   key generation.
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
//! directory entries and reports failures; key generation calls it after each
//! key-file commit. [`sync_parent_dir`] remains best-effort for outputs whose
//! loss can be recovered.
//!
//! [`OutputDir`] retains a handle to the directory an operation publishes
//! into. Cleanup after a failed commit goes through that handle, so it
//! removes the entry the operation created rather than whatever its path
//! happens to name once the operation is already under way.
//!
//! **Zero in-repo unsafe.** The file cases delegate to `tempfile`,
//! which is atomic-no-replace on Windows (`MoveFileExW`
//! without the replace flag) and uses
//! `rustix::renameat_with(..., RenameFlags::NOREPLACE)` on Linux and
//! macOS; where the filesystem supports neither, the Unix fallback uses
//! `cap-std` handle-relative link, claim, and rename operations,
//! anchored to one retained [`OutputDir`]. The directory rename case in
//! [`rename_no_clobber`] delegates
//! to `rustix` directly on Linux and macOS, and on Windows uses
//! `symlink_metadata()` + `std::fs::rename`, which keeps the crate
//! zero-unsafe but offers a narrower best-effort no-clobber guarantee
//! for directory promotion on that target.

use std::io;
use std::path::Path;

use tempfile::NamedTempFile;

use crate::CryptoError;
#[cfg(unix)]
use crate::error::sanitize_path_for_display;
use crate::fs::paths::already_exists_error;

/// A file whose commit completed. Unix keeps the committed handle alive so a
/// caller can confirm immediately before returning that its reported path
/// still denotes the same object. The hard-link fallback also uses that handle
/// to prove its temporary-link cleanup left exactly one name for the committed
/// inode. Other targets expose no stable identity through `std`, so retaining
/// the handle there would only obstruct rollback on Windows.
#[derive(Debug)]
pub(crate) struct FinalizedFile {
    #[cfg(unix)]
    file: std::fs::File,
}

impl FinalizedFile {
    fn new(file: std::fs::File) -> Self {
        #[cfg(unix)]
        {
            Self { file }
        }
        #[cfg(not(unix))]
        {
            drop(file);
            Self {}
        }
    }

    /// Confirms that `path`, the value a writer is about to report, still
    /// denotes this committed file. A directory swap after the commit can
    /// otherwise make the returned path lead to attacker-controlled bytes.
    pub(crate) fn confirm_reported_path(&self, path: &Path) -> Result<(), CryptoError> {
        #[cfg(unix)]
        {
            let committed = self.file.metadata().map_err(CryptoError::Io)?;
            let reported = std::fs::symlink_metadata(path).map_err(CryptoError::Io)?;
            if !reported.file_type().is_file()
                || file_identity(&committed) != file_identity(&reported)
            {
                return Err(reported_output_changed(path));
            }
        }
        #[cfg(not(unix))]
        let _ = path;
        Ok(())
    }

    /// Requires the hard-link commit route to have removed every additional
    /// link it created before success is reported. Reading through the retained
    /// handle makes this independent of concurrent renames or replacements of
    /// either directory entry.
    #[cfg(unix)]
    fn confirm_single_link(&self, path: &Path) -> Result<(), CryptoError> {
        use std::os::unix::fs::MetadataExt;

        let link_count = self.file.metadata().map_err(CryptoError::Io)?.nlink();
        if link_count != 1 {
            return Err(unexpected_committed_link_count(path, link_count));
        }
        Ok(())
    }
}

/// Stable Unix identity for a committed file. Comparing the object behind the
/// retained handle with the final path catches both a final-name replacement
/// and a parent-directory swap before a writer reports that path.
#[cfg(unix)]
fn file_identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;

    (metadata.dev(), metadata.ino())
}

#[cfg(unix)]
fn reported_output_changed(path: &Path) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "Output is complete but its reported path changed: {}",
        sanitize_path_for_display(path)
    ))
}

/// Post-commit failure for a hard-link fallback whose staged-name removal
/// returned success (or `NotFound`) while another link to the committed inode
/// still exists. The retained handle, rather than either mutable name, supplies
/// the count.
#[cfg(unix)]
fn unexpected_committed_link_count(path: &Path, link_count: u64) -> CryptoError {
    CryptoError::Io(io::Error::other(format!(
        "Output {} is complete, but temporary-link cleanup left {link_count} filesystem links (expected 1)",
        sanitize_path_for_display(path),
    )))
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

/// Promotes a `NamedTempFile` to its final path with no-clobber
/// semantics. An occupied final path rejects with the same typed
/// `InvalidInput("<label> already exists: …")` message the pre-write
/// occupancy check emits, so a path that becomes occupied between the
/// preflight and this rename reports the same error class. Other
/// failures surface as [`CryptoError::Io`]. A failure before publication
/// removes the temp file best-effort. A failure after publication is marked
/// by [`FinalizeFileError::committed`]; the final entry is kept because a
/// bare-name rollback could delete a concurrent replacement.
///
/// The promotion is a single atomic no-replace rename wherever the
/// filesystem supports one. Where it does not (see
/// [`no_replace_rename_unsupported`]), the Unix fallback
/// [`finalize_file_via_link_or_claim`] commits by linking or, on a
/// filesystem without hard links, by claiming the name and renaming
/// over the claim. Both keep the no-clobber guarantee against entries
/// that predate the commit.
///
/// Callers are expected to have already flushed and synced the temp file
/// before calling this function. The temp file must be created inside
/// the destination directory (`tempfile::Builder::tempfile_in`): that
/// keeps it on the final path's filesystem, and the Unix fallback
/// routes commit handle-relative inside that directory, refusing by
/// identity — [`CryptoError::InternalInvariant`] — a temp file staged
/// anywhere else.
pub(crate) fn finalize_file(
    tmp: NamedTempFile,
    final_path: &Path,
    label: &str,
) -> Result<FinalizedFile, FinalizeFileError> {
    match tmp.persist_noclobber(final_path) {
        Ok(file) => {
            sync_parent_dir(final_path);
            let finalized = FinalizedFile::new(file);
            finalized
                .confirm_reported_path(final_path)
                .map_err(FinalizeFileError::after_commit)?;
            Ok(finalized)
        }
        Err(e) => finalize_persist_failure(e, final_path, label),
    }
}

/// Failure arm of [`finalize_file`]. On Unix, a filesystem that cannot
/// perform an atomic no-replace rename retries through
/// [`finalize_file_via_link_or_claim`]; every other failure maps to the
/// caller-visible error taxonomy. Dropping the `PersistError` removes
/// the temp file on the non-retry paths.
#[cfg(unix)]
fn finalize_persist_failure(
    e: tempfile::PersistError,
    final_path: &Path,
    label: &str,
) -> Result<FinalizedFile, FinalizeFileError> {
    if no_replace_rename_unsupported(&e.error) {
        return finalize_file_via_link_or_claim(e.file, final_path, label);
    }
    Err(FinalizeFileError::before_commit(map_persist_error(
        e.error, final_path, label,
    )))
}

#[cfg(not(unix))]
fn finalize_persist_failure(
    e: tempfile::PersistError,
    final_path: &Path,
    label: &str,
) -> Result<FinalizedFile, FinalizeFileError> {
    Err(FinalizeFileError::before_commit(map_persist_error(
        e.error, final_path, label,
    )))
}

/// Maps a failed promotion to the caller-visible error: an occupied
/// final path becomes the typed already-exists message, everything
/// else passes through as [`CryptoError::Io`].
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
/// The two callers reach different arms. [`finalize_file`] sits behind
/// `tempfile`, which already retries `EINVAL` itself through its
/// hard-link emulation, so only the unsupported-operation arm is
/// reachable there. `archive::platform::rename_at_no_clobber` calls
/// `renameat_with` directly, and the `EINVAL` arm is load-bearing only
/// for it.
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

    // `CreateFileW` flag without which a directory cannot be opened.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

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
/// a file the operation never created. Removals go through this handle
/// instead, which stays bound to the directory the entries were
/// committed to.
///
/// The handle does not make the chosen directory trustworthy. The
/// caller's choice of output directory IS the trust boundary, and a path
/// already substituted before the handle is opened simply anchors the
/// whole operation there. What the handle removes is the mismatch
/// between the directory an operation wrote to and the directory it
/// later cleans up in.
///
/// `cap_std::fs::Dir` is the same capability primitive the archive
/// extractor anchors to, and behaves uniformly on Linux, macOS, and
/// Windows.
pub(crate) struct OutputDir {
    dir: cap_std::fs::Dir,
}

impl OutputDir {
    /// Opens `path` as the anchor for the operation's own cleanup.
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let dir = cap_std::fs::Dir::open_ambient_dir(path, cap_std::ambient_authority())?;
        Ok(Self { dir })
    }

    /// Removes the entry named by `path`'s final component, resolved
    /// inside the anchored directory rather than through `path` itself.
    /// Callers pass the full path of an entry they committed directly
    /// into this directory; a deeper path is not walked, and one with no
    /// final component names no entry and removes nothing.
    ///
    /// Best-effort by design: this undoes a commit made on a path that
    /// is already returning an error, so a failure here has no better
    /// error to report than the one being returned.
    pub(crate) fn remove_published(&self, path: &Path) {
        if let Some(name) = path.file_name() {
            let _ = self.dir.remove_file(name);
        }
    }

    /// Flushes the anchored directory's entries, resolving through the
    /// held handle, so the barrier covers the directory the entries
    /// were committed to even if the ambient path was renamed since.
    /// Same unsupported-filesystem tolerance as [`sync_dir_durable`];
    /// genuine open and flush failures are reported so a caller that
    /// requires durability can stop.
    ///
    /// cap-std may hold the directory as an `O_PATH` handle on Linux,
    /// which cannot be flushed, so `.` is reopened through the handle —
    /// the same technique as `archive::platform`'s directory sync. The
    /// reopen needs read permission, exactly what the path-based flush
    /// needs, so restrictive directories refuse both the same way.
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
                return if dir_sync_unsupported(&e) {
                    Ok(())
                } else {
                    Err(e)
                };
            }
        };
        flush_dir_handle(&std::fs::File::from(fd))
    }
}

/// Mode bits for the zero-byte placeholder that claims the final name
/// in [`finalize_file_via_claim`]. Owner-only, matching the mode
/// `tempfile` gives the staged temp file; the placeholder is replaced
/// by the staged file's rename, so this mode governs only the claim
/// window.
#[cfg(unix)]
const FINAL_NAME_CLAIM_MODE: u32 = 0o600;

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
/// The whole commit is anchored: the destination directory is opened
/// once as an [`OutputDir`], and the link, the claim fallback, and
/// every removal resolve through that handle, so a rename or
/// replacement of the output path mid-commit cannot redirect any step
/// into another directory. The staged temp file is an entry of that
/// same directory (see [`finalize_file`]), and the route refuses to
/// start until the entry under the staged name in the anchored
/// directory is confirmed by identity to be the staged file itself.
/// Opening the anchor needs a readable output directory; `SECURITY.md`
/// records that requirement.
///
/// A filesystem with hard links reaches the final name by linking the
/// staged file there and dropping the staged name. `hard_link` refuses
/// an existing target atomically, so no placeholder is created that
/// another process could replace, and both names denote the finished
/// content in between. `tempfile` does not try this for the error that
/// leads here: it links only when the kernel reports the no-replace
/// flag as unknown, not when the filesystem rejects the operation. A
/// filesystem with links but without a no-replace rename — SMB among
/// them — is therefore committed here without a claim window.
///
/// Only a filesystem without hard links (exFAT and FAT among them)
/// falls through to [`finalize_file_via_claim`]. Any other link failure
/// falls through too: the claim path attempts the same commit and
/// reports the failure itself, so the wide trigger cannot weaken the
/// guarantee. If the staged-name unlink fails after a link commit, the
/// operation reports a post-commit error and preserves both complete links;
/// it never removes the final name after a potentially delayed failure. A
/// successful or missing-name unlink is accepted only when the retained
/// committed handle reports one link, which catches a concurrent move of the
/// staged link and a successful unlink of a planted replacement.
#[cfg(unix)]
fn finalize_file_via_link_or_claim(
    tmp: NamedTempFile,
    final_path: &Path,
    label: &str,
) -> Result<FinalizedFile, FinalizeFileError> {
    let output_dir = OutputDir::open(crate::fs::paths::parent_or_cwd(final_path))
        .map_err(CryptoError::Io)
        .map_err(FinalizeFileError::before_commit)?;
    let Some(final_name) = final_path.file_name() else {
        let _ = remove_staged_temp(tmp, &output_dir);
        return Err(FinalizeFileError::before_commit(CryptoError::Io(
            no_final_component_error(),
        )));
    };
    // Owned, because the arms below consume `tmp` while the staged
    // name is still needed.
    let Some(tmp_name) = tmp.path().file_name().map(|name| name.to_os_string()) else {
        let _ = remove_staged_temp(tmp, &output_dir);
        return Err(FinalizeFileError::before_commit(CryptoError::Io(
            no_final_component_error(),
        )));
    };
    if let Err(error) = require_staged_temp_in_output_dir(&tmp, &output_dir, &tmp_name) {
        // `tmp` drops here, so its own destructor removes the staged
        // file at the path the caller actually created it.
        return Err(FinalizeFileError::before_commit(error));
    }
    match output_dir
        .dir
        .hard_link(&tmp_name, &output_dir.dir, final_name)
    {
        Ok(()) => finish_link_commit(tmp, &output_dir, final_path, &tmp_name),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let _ = remove_staged_temp(tmp, &output_dir);
            Err(FinalizeFileError::before_commit(already_exists_error(
                label, final_path,
            )))
        }
        Err(_) => finalize_file_via_claim(tmp, final_path, label, &output_dir),
    }
}

/// Requires the entry under the staged name in the anchored destination
/// directory to be the staged file itself, before any fallback commit step
/// runs. Both routes resolve the staged name through the anchor, so a
/// temporary staged in any other directory must be refused here — as a
/// contract violation, not left to surface later as placeholder churn and
/// an orphaned staged file on the filesystems that reach this route. The
/// entry is read without following symlinks, so a link planted under the
/// staged name cannot satisfy the comparison either.
#[cfg(unix)]
fn require_staged_temp_in_output_dir(
    tmp: &NamedTempFile,
    output_dir: &OutputDir,
    tmp_name: &std::ffi::OsStr,
) -> Result<(), CryptoError> {
    use cap_std::fs::MetadataExt;

    let staged = tmp.as_file().metadata().map_err(CryptoError::Io)?;
    let entry = match output_dir.dir.symlink_metadata(tmp_name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(staged_temp_outside_output_dir());
        }
        Err(error) => return Err(CryptoError::Io(error)),
    };
    if !entry.is_file() || (entry.dev(), entry.ino()) != file_identity(&staged) {
        return Err(staged_temp_outside_output_dir());
    }
    Ok(())
}

/// Contract violation from [`require_staged_temp_in_output_dir`]: the
/// staged temporary file is not an entry of the destination directory.
#[cfg(unix)]
fn staged_temp_outside_output_dir() -> CryptoError {
    CryptoError::InternalInvariant(
        "the staged temporary file is not an entry of the destination directory",
    )
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

/// Commits `tmp` to `final_path` on a filesystem with neither an atomic
/// no-replace rename nor hard links, in two steps:
///
/// 1. claim the final name by creating it — an atomic test-and-create
///    on every filesystem, refusing any pre-existing entry including a
///    dangling symlink;
/// 2. rename the staged temp file over the placeholder just created.
///    The plain rename replaces the placeholder in one step, so no
///    reader ever observes partial content at the final name.
///
/// A pre-existing final path rejects in step 1 with the same typed
/// message as the atomic path, so the no-clobber guarantee against
/// entries that predate the commit is unconditional. Between the two
/// steps the claim is an ordinary entry, so a local writer with access
/// to the destination directory can remove it and leave one of their
/// own, which step 2 then replaces. That window is why
/// [`finalize_file_via_link_or_claim`] links wherever the filesystem
/// supports it; `SECURITY.md` states what remains.
///
/// The claim, the step-2 rename, and every removal resolve through the
/// caller's [`OutputDir`] handle — both names are entries of the
/// anchored directory (see [`finalize_file`]) — so a directory renamed
/// or replaced mid-commit can neither redirect the commit nor send the
/// cleanup onto an unrelated file, and the rename can replace only the
/// placeholder step 1 created. Process interruption between the two
/// steps leaves an empty placeholder at the final name next to the
/// temp file. On step-2 failure the placeholder and the temp entry are
/// removed through the same handle, matching the [`finalize_file`]
/// contract.
#[cfg(unix)]
fn finalize_file_via_claim(
    tmp: NamedTempFile,
    final_path: &Path,
    label: &str,
    output_dir: &OutputDir,
) -> Result<FinalizedFile, FinalizeFileError> {
    match claim_final_name(output_dir, final_path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let _ = remove_staged_temp(tmp, output_dir);
            return Err(FinalizeFileError::before_commit(already_exists_error(
                label, final_path,
            )));
        }
        Err(e) => {
            let _ = remove_staged_temp(tmp, output_dir);
            return Err(FinalizeFileError::before_commit(CryptoError::Io(e)));
        }
    }
    // `claim_final_name` already rejected a path with no final
    // component, so these arms are backstops.
    let Some(final_name) = final_path.file_name() else {
        output_dir.remove_published(final_path);
        let _ = remove_staged_temp(tmp, output_dir);
        return Err(FinalizeFileError::before_commit(CryptoError::Io(
            no_final_component_error(),
        )));
    };
    let Some(tmp_name) = tmp.path().file_name().map(|name| name.to_os_string()) else {
        output_dir.remove_published(final_path);
        let _ = remove_staged_temp(tmp, output_dir);
        return Err(FinalizeFileError::before_commit(CryptoError::Io(
            no_final_component_error(),
        )));
    };
    match output_dir
        .dir
        .rename(&tmp_name, &output_dir.dir, final_name)
    {
        Ok(()) => {
            // The rename moved the staged entry away. Disarm the
            // destructor so it cannot remove an entry another process
            // creates at the freed temp name afterwards. Not
            // [`remove_staged_temp`]: with the entry gone, its unlink
            // could only ever hit such a newcomer.
            let (file, temp_path) = tmp.into_parts();
            let _ = temp_path.keep();
            sync_committed_parent(output_dir, final_path);

            let finalized = FinalizedFile::new(file);
            finalized
                .confirm_reported_path(final_path)
                .map_err(FinalizeFileError::after_commit)?;
            Ok(finalized)
        }
        Err(e) => {
            output_dir.remove_published(final_path);
            let _ = remove_staged_temp(tmp, output_dir);
            Err(FinalizeFileError::before_commit(CryptoError::Io(e)))
        }
    }
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
) -> (Result<(u64, u64), CryptoError>, io::Result<()>) {
    unlink_staged_temp_with_remove(tmp, output_dir, name, |dir, name| dir.remove_file(name))
}

#[cfg(unix)]
fn unlink_staged_temp_with_remove(
    tmp: NamedTempFile,
    output_dir: &OutputDir,
    name: &std::ffi::OsStr,
    remove_staged: impl FnOnce(&cap_std::fs::Dir, &std::ffi::OsStr) -> io::Result<()>,
) -> (Result<(u64, u64), CryptoError>, io::Result<()>) {
    let (file, temp_path) = tmp.into_parts();
    let identity = file
        .metadata()
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
/// handle open across an unlink on restrictive network filesystems.
#[cfg(unix)]
fn reopen_committed_file(
    output_dir: &OutputDir,
    final_name: &std::ffi::OsStr,
    expected: (u64, u64),
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
    let metadata = file.metadata().map_err(CryptoError::Io)?;
    if !metadata.file_type().is_file() || file_identity(&metadata) != expected {
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

/// Creates the zero-byte placeholder that claims the final name,
/// through the anchored directory handle so the entry
/// [`finalize_file_via_claim`] may later remove is the one it created
/// here. `create_new` refuses any pre-existing entry; the no-follow flag
/// is defense in depth for platforms whose open semantics differ, so a
/// symlink raced into place cannot redirect the create either way.
///
/// A final path with no last component names nothing to claim and
/// rejects rather than falling back to some other entry.
#[cfg(unix)]
fn claim_final_name(output_dir: &OutputDir, final_path: &Path) -> io::Result<()> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsExt, OpenOptionsFollowExt};

    let Some(name) = final_path.file_name() else {
        return Err(no_final_component_error());
    };
    let mut options = cap_std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    options.follow(FollowSymlinks::No);
    options.mode(FINAL_NAME_CLAIM_MODE);
    output_dir.dir.open_with(name, &options).map(|_| ())
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

        let error = finalize_file(tmp, &final_path, "Output")
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

        finalize_file(tmp, &final_path, "Output").unwrap();
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "payload");
    }

    /// The ordinary one-step persist also retains the committed handle. If
    /// the parent directory is replaced before the caller reports its path,
    /// the final check rejects that path while leaving both the real output
    /// and the replacement untouched.
    #[cfg(unix)]
    #[test]
    fn finalized_file_rejects_a_reported_path_after_parent_replacement() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let out = tmp_dir.path().join("out");
        fs::create_dir(&out).unwrap();
        let final_path = out.join("out.txt");

        let mut tmp = tempfile::Builder::new().tempfile_in(&out).unwrap();
        tmp.write_all(b"payload").unwrap();
        let finalized = finalize_file(tmp, &final_path, "Output").unwrap();

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
        fs::write(anchored.join("key"), "ours").unwrap();
        fs::write(substituted.join("key"), "unrelated").unwrap();

        let handle = OutputDir::open(&anchored).unwrap();
        fs::rename(&anchored, tmp_dir.path().join("out.moved")).unwrap();
        std::os::unix::fs::symlink(&substituted, &anchored).unwrap();

        handle.remove_published(&anchored.join("key"));

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
    /// file. The refused temp is removed by its own destructor at the path
    /// it was actually created.
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
                CryptoError::InternalInvariant(message)
                    if message.contains("not an entry of the destination directory")
            ),
            "the contract violation must be explicit"
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
            rendered.contains("temporary-link cleanup left 2 filesystem links"),
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
            rendered.contains("temporary-link cleanup left 2 filesystem links"),
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

        finalize_file_via_claim(
            tmp,
            &final_path,
            "Output",
            &OutputDir::open(tmp_dir.path()).unwrap(),
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "payload");
        assert!(!tmp_path.exists());
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

        let error = finalize_file_via_claim(
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

        let error = finalize_file_via_claim(
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

    /// A failed rename step removes the placeholder, so a retry is not
    /// blocked by an empty file at the final name. Forced by removing
    /// the staged file, which leaves the rename nothing to move.
    #[cfg(unix)]
    #[test]
    fn finalize_via_claim_removes_the_claim_when_the_rename_fails() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");

        let tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        fs::remove_file(tmp.path()).unwrap();

        let err = finalize_file_via_claim(
            tmp,
            &final_path,
            "Output",
            &OutputDir::open(tmp_dir.path()).unwrap(),
        )
        .expect_err("a rename with no staged file must fail the commit");
        assert!(!err.committed());
        assert!(
            matches!(err.into_crypto_error(), CryptoError::Io(_)),
            "expected an I/O failure"
        );
        assert!(
            !final_path.exists(),
            "the placeholder must not survive a failed rename"
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

        let error = finalize_file_via_claim(tmp, &final_path, "Output", &output_dir)
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
