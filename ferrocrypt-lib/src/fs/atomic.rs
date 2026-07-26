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
//! flushes staged file contents before promotion. [`sync_dir_durable`] flushes
//! directory entries and reports failures; key generation calls it after each
//! key-file commit. [`sync_parent_dir`] remains best-effort for outputs whose
//! loss can be recovered.
//!
//! **Zero in-repo unsafe.** The file cases delegate entirely to
//! `tempfile`, which is atomic-no-replace on Windows (`MoveFileExW`
//! without the replace flag) and uses
//! `rustix::renameat_with(..., RenameFlags::NOREPLACE)` on Linux and
//! macOS. The directory rename case in [`rename_no_clobber`] delegates
//! to `rustix` directly on Linux and macOS, and on Windows uses
//! `symlink_metadata()` + `std::fs::rename`, which keeps the crate
//! zero-unsafe but offers a narrower best-effort no-clobber guarantee
//! for directory promotion on that target.

use std::io;
use std::path::Path;

use tempfile::NamedTempFile;

use crate::CryptoError;
use crate::fs::paths::already_exists_error;

/// Best-effort parent-directory sync used after a successful file persist or
/// directory rename. This slightly improves durability on Unix-like systems
/// after the final path becomes visible.
///
/// Failures are intentionally ignored here:
/// - not every filesystem supports syncing directories cleanly
/// - finalization has already succeeded by the time this runs
/// - returning an error after the final path is visible would be more
///   confusing to callers than helpful
///
/// Callers that require directory-flush failures to be reported use
/// [`sync_dir_durable`] instead.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) {
    if let Ok(dir) = std::fs::File::open(crate::fs::paths::parent_or_cwd(path)) {
        let _ = dir.sync_all();
    }
}

/// Windows arm of [`sync_parent_dir`]. Routes through
/// [`sync_dir_durable`], which opens the directory with backup
/// semantics and write access because `FlushFileBuffers` requires it.
/// The result is dropped for the same reasons the Unix arm ignores its
/// own: finalization has already succeeded by the time this runs.
#[cfg(windows)]
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
/// failures surface as [`CryptoError::Io`]. The temp file is removed
/// on every failure path.
///
/// The promotion is a single atomic no-replace rename wherever the
/// filesystem supports one. Where it does not (see
/// [`no_replace_rename_unsupported`]), the Unix fallback
/// [`finalize_file_via_claim`] commits in two steps while keeping the
/// no-clobber guarantee unconditional.
///
/// Callers are expected to have already flushed and synced the temp file
/// before calling this function. The temp file and the final path must
/// live on the same filesystem (this is why the temp file should be
/// created inside the destination directory via
/// `tempfile::Builder::tempfile_in`).
pub(crate) fn finalize_file(
    tmp: NamedTempFile,
    final_path: &Path,
    label: &str,
) -> Result<(), CryptoError> {
    match tmp.persist_noclobber(final_path) {
        Ok(_) => {
            sync_parent_dir(final_path);
            Ok(())
        }
        Err(e) => finalize_persist_failure(e, final_path, label),
    }
}

/// Failure arm of [`finalize_file`]. On Unix, a filesystem that cannot
/// perform an atomic no-replace rename retries through
/// [`finalize_file_via_claim`]; every other failure maps to the
/// caller-visible error taxonomy. Dropping the `PersistError` removes
/// the temp file on the non-retry paths.
#[cfg(unix)]
fn finalize_persist_failure(
    e: tempfile::PersistError,
    final_path: &Path,
    label: &str,
) -> Result<(), CryptoError> {
    if no_replace_rename_unsupported(&e.error) {
        return finalize_file_via_claim(e.file, final_path, label);
    }
    Err(map_persist_error(e.error, final_path, label))
}

#[cfg(not(unix))]
fn finalize_persist_failure(
    e: tempfile::PersistError,
    final_path: &Path,
    label: &str,
) -> Result<(), CryptoError> {
    Err(map_persist_error(e.error, final_path, label))
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

/// Flushes `file` to stable storage with the strongest primitive the
/// filesystem supports. `File::sync_all` is the primary (on macOS it
/// issues `F_FULLFSYNC`); a filesystem that reports the full flush as
/// unsupported — macOS smbfs among them — falls back to plain
/// `fsync(2)`, which such filesystems do honor. Genuine sync failures
/// surface unchanged; only the capability gap downgrades.
///
/// The extraction-side twin for capability-anchored handles is
/// `archive::platform::sync_file_durable`; keep their fallback
/// condition in step.
pub(crate) fn sync_file_durable(file: &std::fs::File) -> io::Result<()> {
    match file.sync_all() {
        Ok(()) => Ok(()),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Err(e) if errno_not_supported(&e) => rustix::fs::fsync(file).map_err(io::Error::from),
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
    // therefore returns `NotADirectory` instead of being flushed.
    let handle = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(dir)
    {
        Ok(handle) => handle,
        Err(e) if dir_sync_unsupported(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    // Match `sync_file_durable`: try `sync_all` first, then plain
    // `fsync` where supported. Directory flushing has a wider set of
    // unsupported errors than file flushing.
    match handle.sync_all() {
        Ok(()) => Ok(()),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Err(e) if dir_sync_unsupported(&e) => match rustix::fs::fsync(&handle) {
            Ok(()) => Ok(()),
            Err(again) => {
                let again = io::Error::from(again);
                if dir_sync_unsupported(&again) {
                    Ok(())
                } else {
                    Err(again)
                }
            }
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
fn dir_sync_unsupported(e: &io::Error) -> bool {
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

/// Mode bits for the zero-byte placeholder that claims the final name
/// in [`finalize_file_via_claim`]. Owner-only, matching the mode
/// `tempfile` gives the staged temp file; the placeholder is replaced
/// by the staged file's rename, so this mode governs only the claim
/// window.
#[cfg(unix)]
const FINAL_NAME_CLAIM_MODE: u32 = 0o600;

/// Commits `tmp` to `final_path` on filesystems without an atomic
/// no-replace rename, keeping the no-clobber guarantee unconditional:
///
/// 1. claim the final name with `create_new(true)` — an atomic
///    test-and-create on every filesystem, refusing any pre-existing
///    entry including a dangling symlink;
/// 2. rename the staged temp file over the placeholder just created.
///    The plain rename replaces the placeholder in one step, so no
///    reader ever observes partial content at the final name.
///
/// Only the entry step 1 itself created is ever replaced; a
/// pre-existing final path rejects in step 1 with the same typed
/// message as the atomic path. Process interruption between the two
/// steps leaves an empty placeholder at the final name next to the
/// temp file. On step-2 failure the placeholder is removed best-effort
/// and the temp file is removed by its destructor, matching the
/// [`finalize_file`] contract.
#[cfg(unix)]
fn finalize_file_via_claim(
    tmp: NamedTempFile,
    final_path: &Path,
    label: &str,
) -> Result<(), CryptoError> {
    use std::os::unix::fs::OpenOptionsExt;

    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FINAL_NAME_CLAIM_MODE)
        .open(final_path)
    {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(already_exists_error(label, final_path));
        }
        Err(e) => return Err(CryptoError::Io(e)),
    }
    match tmp.persist(final_path) {
        Ok(_) => {
            sync_parent_dir(final_path);
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(final_path);
            Err(CryptoError::Io(e.error))
        }
    }
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

        match finalize_file(tmp, &final_path, "Output") {
            Err(CryptoError::InvalidInput(msg)) => {
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

    // The claim path cannot be reached through `finalize_file` on the
    // filesystems that host `cargo test` (they support the atomic
    // no-replace rename), so it is exercised directly. The fs-matrix
    // exFAT lane covers the errno-driven dispatch end to end.

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

        finalize_file_via_claim(tmp, &final_path, "Output").unwrap();
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

        match finalize_file_via_claim(tmp, &final_path, "Output") {
            Err(CryptoError::InvalidInput(msg)) => {
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

        match finalize_file_via_claim(tmp, &final_path, "Output") {
            Err(CryptoError::InvalidInput(msg)) => {
                assert!(msg.starts_with("Output already exists: "), "got: {msg}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        let meta = fs::symlink_metadata(&final_path).unwrap();
        assert!(meta.file_type().is_symlink(), "symlink must be left as-is");
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
