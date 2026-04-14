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
//! - [`rename_dir_no_clobber`] — rename a staged `.incomplete` directory
//!   to its final name with no-clobber semantics. Used by archive
//!   extraction.
//!
//! **Zero in-repo unsafe.** The file case delegates entirely to
//! `tempfile`; the Linux and macOS directory case delegates to `rustix`'s
//! safe `renameat_with` wrapper; the Windows directory case uses
//! `try_exists()` + `std::fs::rename`, which keeps the crate zero-unsafe
//! but offers a somewhat narrower best-effort no-clobber guarantee for
//! directory finalization.

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
fn sync_parent_dir(path: &Path) {
    // Suppress the "unused" warning on non-Unix targets where the body
    // below is entirely cfg-gated out.
    let _ = path;

    #[cfg(unix)]
    {
        use std::fs::File;

        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

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
    tmp.persist_noclobber(final_path)
        .map_err(|e| e.error)
        .map(|_| {
            sync_parent_dir(final_path);
        })
}

/// No-clobber rename for a directory. Fails with
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
pub(crate) fn rename_dir_no_clobber(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use rustix::fs::{CWD, RenameFlags, renameat_with};
        renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE)
            .map_err(io::Error::from)
            .map(|_| {
                sync_parent_dir(to);
            })
    }

    #[cfg(target_os = "windows")]
    {
        if to.try_exists()? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "target exists",
            ));
        }
        std::fs::rename(from, to)?;
        sync_parent_dir(to);
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = from;
        let _ = to;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "directory finalization is not supported on this target",
        ))
    }
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
    fn rename_dir_no_clobber_refuses_to_overwrite() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let from = tmp_dir.path().join("src");
        let to = tmp_dir.path().join("dst");
        fs::create_dir(&from).unwrap();
        fs::write(from.join("inner.txt"), "new").unwrap();
        fs::create_dir(&to).unwrap();
        fs::write(to.join("existing.txt"), "existing").unwrap();

        let err = rename_dir_no_clobber(&from, &to).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(from.exists(), "source should not have been moved");
        assert!(
            to.join("existing.txt").exists(),
            "destination should be untouched"
        );
    }

    #[test]
    fn rename_dir_no_clobber_succeeds_when_target_missing() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let from = tmp_dir.path().join("src");
        let to = tmp_dir.path().join("dst");
        fs::create_dir(&from).unwrap();
        fs::write(from.join("payload.txt"), "hello").unwrap();

        rename_dir_no_clobber(&from, &to).unwrap();

        assert!(!from.exists(), "source should have been moved");
        assert!(to.is_dir(), "destination should exist as a directory");
        assert_eq!(fs::read_to_string(to.join("payload.txt")).unwrap(), "hello",);
    }
}
