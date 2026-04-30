//! General path helpers — encrypted filename derivation, base-name
//! extraction, parent-directory resolution, and user-path I/O error
//! mapping.
//!
//! Centralises the small filesystem-level helpers that don't belong
//! to a single crypto or container module so the relevant logic lives
//! in one place per the single-source-of-truth table
//! (`notes/STRUCTURE_PROPOSAL.md` §6.1).

use std::ffi::OsStr;
use std::io;
use std::path::Path;

use crate::CryptoError;

/// Suffix appended to atomic-write working names so plaintext (or any
/// not-yet-finalised output) is never visible under the final name.
/// Used by `container::write_encrypted_file` for the streaming
/// `.fcr` tempfile and by `archive::decode::unarchive` for the per-root
/// rename-into-place pattern.
pub(crate) const INCOMPLETE_SUFFIX: &str = ".incomplete";

pub fn file_stem(filename: &Path) -> Result<&OsStr, CryptoError> {
    filename
        .file_stem()
        .ok_or_else(|| CryptoError::InvalidInput("Cannot get file stem".to_string()))
}

/// Returns the base name for building the default encrypted output filename.
/// For regular files, returns the file stem (without extension).
/// For directories, returns the full directory name (preserving dots like `photos.v1`).
///
/// Uses `symlink_metadata` (lstat) rather than `Path::is_dir` so a
/// symlink that races into place between the upstream
/// `validate_encrypt_input` symlink check and this lookup cannot be
/// followed to a directory and silently change the chosen output
/// name. The downstream `open_no_follow` would still abort the
/// archive step, but defending here keeps the directory-vs-file
/// classification honest. Falls back to the file branch when
/// `symlink_metadata` fails (e.g. NotFound after a race), letting
/// the subsequent `file_stem` surface the real error.
pub fn encryption_base_name(path: impl AsRef<Path>) -> Result<String, CryptoError> {
    let path = path.as_ref();
    let is_real_dir = std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_dir())
        .unwrap_or(false);
    if is_real_dir {
        Ok(path
            .file_name()
            .ok_or_else(|| CryptoError::InvalidInput("Cannot get directory name".to_string()))?
            .to_string_lossy()
            .into_owned())
    } else {
        Ok(file_stem(path)?.to_string_lossy().into_owned())
    }
}

/// Returns the parent directory of `path`, or `Path::new(".")` when the
/// parent is empty or absent. Centralises the "directory in which to
/// create the staging tempfile / open a dirfd for `sync_all`" lookup
/// shared by `fs::atomic` and `container`.
pub(crate) fn parent_or_cwd(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Converts an [`io::Error`] from a user-provided path read into a
/// typed [`CryptoError`]. `NotFound` maps to [`CryptoError::InputPath`]
/// so "file does not exist" gives the same pretty message here as it
/// does from the upfront `validate_input_path` check. Everything else
/// falls through to [`CryptoError::Io`].
pub(crate) fn map_user_path_io_error(e: io::Error) -> CryptoError {
    if e.kind() == io::ErrorKind::NotFound {
        CryptoError::InputPath
    } else {
        CryptoError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_base_name_file() {
        let stem = encryption_base_name("path/to/file.txt").unwrap();
        assert_eq!(stem, "file");
    }

    #[test]
    fn test_encryption_base_name_no_extension() {
        let stem = encryption_base_name("path/to/file").unwrap();
        assert_eq!(stem, "file");
    }

    #[test]
    fn test_encryption_base_name_dotted_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dotted_dir = tmp.path().join("photos.v1");
        std::fs::create_dir(&dotted_dir).unwrap();
        let name = encryption_base_name(&dotted_dir).unwrap();
        assert_eq!(name, "photos.v1");
    }

    #[test]
    fn parent_or_cwd_returns_parent_when_present() {
        assert_eq!(parent_or_cwd(Path::new("dir/file.txt")), Path::new("dir"));
        assert_eq!(parent_or_cwd(Path::new("/abs/file.txt")), Path::new("/abs"));
    }

    #[test]
    fn parent_or_cwd_falls_back_to_cwd() {
        // `Path::parent` returns `Some("")` for a bare filename and `None` for
        // the empty path; both must collapse to ".".
        assert_eq!(parent_or_cwd(Path::new("file.txt")), Path::new("."));
        assert_eq!(parent_or_cwd(Path::new("")), Path::new("."));
    }
}
