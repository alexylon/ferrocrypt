//! Atomic output finalization helpers.
//!
//! This module centralizes the "write under a temp name, promote to the
//! final name only on success" pattern used throughout the crate for
//! encrypted-file output, key files, and decrypted directory extraction.
//!
//! Two primitives are provided:
//!
//! - [`finalize_file`] — promote a [`tempfile::NamedTempFile`] to its final
//!   path with atomic no-clobber semantics. Used by encryption output and
//!   key generation.
//! - [`rename_no_clobber`] — rename a staged `.incomplete` entry (directory
//!   or regular file) to its final name with no-clobber semantics. Used by
//!   archive extraction for both directory roots and single-file roots.
//!
//! **Zero in-repo unsafe.** The file case delegates entirely to
//! `tempfile`; the Linux and macOS rename case delegates to `rustix`'s safe
//! `renameat_with` wrapper; the Windows rename case uses `try_exists()` +
//! `std::fs::rename`, which keeps the crate zero-unsafe but offers a
//! somewhat narrower best-effort no-clobber guarantee on that target.

use std::io;
use std::path::Path;

use tempfile::NamedTempFile;

/// Best-effort parent-directory sync used after a successful file persist or
/// directory rename. This slightly improves durability on Unix-like systems
/// after the final path becomes visible.
///
/// Failures are intentionally ignored here:
/// - not every filesystem supports syncing directories cleanly
/// - finalization has already succeeded by the time this runs
/// - returning an error after the final path is visible would be more
///   confusing to callers than helpful
#[cfg(unix)]
fn sync_parent_dir(path: &Path) {
    if let Ok(dir) = std::fs::File::open(crate::fs::paths::parent_or_cwd(path)) {
        let _ = dir.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) {}

/// Promotes a `NamedTempFile` to its final path with atomic no-clobber
/// semantics. Fails with [`io::ErrorKind::AlreadyExists`] if the final
/// path already exists.
///
/// Callers are expected to have already flushed and synced the temp file
/// before calling this function. The temp file and the final path must
/// live on the same filesystem (this is why the temp file should be
/// created inside the destination directory via
/// `tempfile::Builder::tempfile_in`).
pub(crate) fn finalize_file(tmp: NamedTempFile, final_path: &Path) -> io::Result<()> {
    tmp.persist_noclobber(final_path).map_err(|e| e.error)?;
    sync_parent_dir(final_path);
    Ok(())
}

/// No-clobber rename of a filesystem entry. Works for both regular files
/// and directories — the underlying primitives (`renameat_with` on Linux
/// and macOS, `rename` on Windows) treat them uniformly. Fails with
/// [`io::ErrorKind::AlreadyExists`] if `to` already exists.
///
/// Platform strategy (ferrocrypt targets Linux / macOS / Windows desktops):
///
/// - Linux / macOS: `rustix::fs::renameat_with` with `RenameFlags::NOREPLACE`
///   — strict atomic no-clobber via a safe Rust wrapper.
/// - Windows: best-effort via `try_exists()` pre-check + `std::fs::rename`.
///   This keeps ferrocrypt zero-unsafe, but it leaves a small TOCTOU window.
/// - Other targets: unsupported in this helper rather than silently applying
///   desktop-target assumptions to platforms ferrocrypt does not currently aim
///   to support here.
pub(crate) fn rename_no_clobber(from: &Path, to: &Path) -> io::Result<()> {
    rename_no_clobber_impl(from, to)?;
    sync_parent_dir(to);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rename_no_clobber_impl(from: &Path, to: &Path) -> io::Result<()> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE).map_err(io::Error::from)
}

#[cfg(target_os = "windows")]
fn rename_no_clobber_impl(from: &Path, to: &Path) -> io::Result<()> {
    if to.try_exists()? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Target already exists",
        ));
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

    #[test]
    fn finalize_file_refuses_to_overwrite() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");
        fs::write(&final_path, "existing").unwrap();

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"new").unwrap();

        let err = finalize_file(tmp, &final_path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "existing");
    }

    #[test]
    fn finalize_file_succeeds_when_target_missing() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let final_path = tmp_dir.path().join("out.txt");

        let mut tmp = tempfile::Builder::new()
            .tempfile_in(tmp_dir.path())
            .unwrap();
        tmp.write_all(b"payload").unwrap();

        finalize_file(tmp, &final_path).unwrap();
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "payload");
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
        // The helper is used for both directory roots and single-file
        // roots during archive extraction; prove the file case works
        // with both the success path and the refuse-to-overwrite path.
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
}
