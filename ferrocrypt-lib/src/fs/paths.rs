//! General path helpers — encrypted filename derivation, base-name
//! extraction, parent-directory resolution, and user-path I/O error
//! mapping.
//!
//! Centralises small filesystem-level helpers that do not belong to a single
//! crypto or container module.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;

use crate::CryptoError;

/// Suffix appended to atomic-write working names so plaintext (or any
/// not-yet-finalised output) is never visible under the final name.
/// Used by `container::write_encrypted_file` for the streaming
/// `.fcr` tempfile and by `archive::decode::unarchive` for the per-root
/// rename-into-place pattern. `pub` (in a private module) so
/// `fuzz_exports` can re-export it for the full-pipeline fuzz oracle.
pub const INCOMPLETE_SUFFIX: &str = ".incomplete";

/// Opens `path` read-only for header probing, decryption, or key-file
/// reading, refusing FIFOs, sockets, and device nodes.
///
/// On Unix the open itself uses `O_NONBLOCK`, so an attacker-placed
/// FIFO cannot block the process inside `open(2)` (without that flag,
/// opening a FIFO read-only blocks until a writer appears). The file
/// type is then checked on the open handle, leaving no window between
/// check and use; `O_NONBLOCK` has no effect on regular-file reads.
/// Directories pass through deliberately — each caller keeps its
/// established directory handling (probe short-circuits them, decrypt
/// surfaces the platform's directory-read error).
///
/// `map_open_error` translates an `open` failure so each caller keeps
/// its established mapping ([`map_user_path_io_error`] for key files,
/// `CryptoError::Io` for probe / decrypt).
pub(crate) fn open_input_file(
    path: &Path,
    map_open_error: impl FnOnce(io::Error) -> CryptoError,
) -> Result<File, CryptoError> {
    let mut options = File::options();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(map_open_error)?;
    let file_type = file.metadata().map_err(CryptoError::Io)?.file_type();
    if !file_type.is_file() && !file_type.is_dir() {
        return Err(CryptoError::InvalidInput(format!(
            "Unsupported file type: {}",
            path.display()
        )));
    }
    Ok(file)
}

/// Reads `path` into memory, refusing files whose byte length exceeds
/// `cap`. Bounds the allocation at `cap + 1` bytes so a caller pointed
/// at a multi-gigabyte file rejects in-flight rather than after the
/// kernel page-faults the whole thing in. The `over_cap_error` closure
/// supplies the typed rejection so each caller can route the failure
/// to the right diagnostic class (`MalformedPublicKey` / `MalformedPrivateKey`).
/// Opens via [`open_input_file`], so FIFOs, sockets, and device nodes
/// are refused without blocking.
pub(crate) fn read_file_capped(
    path: &Path,
    cap: usize,
    over_cap_error: impl FnOnce() -> CryptoError,
) -> Result<Vec<u8>, CryptoError> {
    let mut file = open_input_file(path, map_user_path_io_error)?;
    let mut buf = Vec::with_capacity(cap.saturating_add(1).min(64 * 1024));
    let read = file
        .by_ref()
        .take(cap as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(CryptoError::Io)?;
    if read > cap {
        return Err(over_cap_error());
    }
    Ok(buf)
}

pub(crate) fn file_stem(filename: &Path) -> Result<&OsStr, CryptoError> {
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
/// classification honest. `NotFound` falls through to the file branch
/// (race against deletion); other I/O errors propagate so a
/// `PermissionDenied` is not silently misclassified as "not a
/// directory" and downgraded into a confusing later failure.
pub(crate) fn encryption_base_name(path: impl AsRef<Path>) -> Result<String, CryptoError> {
    let path = path.as_ref();
    let is_real_dir = match std::fs::symlink_metadata(path) {
        Ok(m) => m.file_type().is_dir(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => return Err(CryptoError::Io(e)),
    };
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

/// Returns `true` if anything occupies `path`, including a dangling
/// symlink. Uses `symlink_metadata` (lstat) so a symlink whose target
/// is missing is reported as occupied — `Path::exists()` would follow
/// the link and return `false`, letting an output preflight pass even
/// though the final no-clobber rename would later refuse to overwrite
/// the dangling link. Used by the encrypt / keygen output-precheck
/// sites so a stale symlink rejects in milliseconds instead of after
/// Argon2id / file-key wrapping.
pub(crate) fn path_occupied(path: &Path) -> Result<bool, CryptoError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(CryptoError::Io(e)),
    }
}

/// Returns `Err(InvalidInput)` if `path` is occupied (real file, real
/// directory, or dangling symlink). `label` is used as the message
/// prefix so callers can tailor the wording (`"Output"`, `"Key file"`).
pub(crate) fn reject_occupied(path: &Path, label: &str) -> Result<(), CryptoError> {
    if path_occupied(path)? {
        return Err(CryptoError::InvalidInput(format!(
            "{label} already exists: {}",
            path.display()
        )));
    }
    Ok(())
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

    /// Filesystem-root inputs are unreachable in production (no caller
    /// stages a tempfile at `/`), but the fallback semantic ("parent of
    /// `/` is the current working directory") would silently mis-route
    /// such a stage. Pinning the existing behaviour with a test so a
    /// future caller that tries this hits a clear contract rather than
    /// a surprise.
    #[cfg(unix)]
    #[test]
    fn parent_or_cwd_root_path_falls_back_to_cwd() {
        assert_eq!(parent_or_cwd(Path::new("/")), Path::new("."));
    }

    /// FIFO-input regressions. Unix-only — Windows has no FIFO file
    /// type in the filesystem namespace. Before the `open_input_file`
    /// guard, pointing any read path at a FIFO hung the process inside
    /// `open(2)` until a writer appeared.
    #[cfg(unix)]
    mod special_file_inputs {
        use super::*;

        /// Creates a FIFO via the POSIX `mkfifo` utility. A subprocess
        /// keeps the crate free of an `unsafe` `libc::mkfifo` call
        /// (`rustix` exposes no FIFO creation on Apple targets).
        fn make_fifo(path: &Path) {
            let status = std::process::Command::new("mkfifo")
                .arg(path)
                .status()
                .expect("spawn mkfifo");
            assert!(status.success(), "mkfifo failed for {}", path.display());
        }

        #[test]
        fn open_input_file_rejects_fifo_without_blocking() {
            let tmp = tempfile::TempDir::new().unwrap();
            let fifo = tmp.path().join("pipe.fcr");
            make_fifo(&fifo);
            match open_input_file(&fifo, CryptoError::Io) {
                Err(CryptoError::InvalidInput(msg)) => {
                    assert!(msg.contains("Unsupported file type"), "got: {msg}");
                }
                other => panic!("expected InvalidInput, got {other:?}"),
            }
        }

        #[test]
        fn read_file_capped_rejects_fifo() {
            let tmp = tempfile::TempDir::new().unwrap();
            let fifo = tmp.path().join("private.key");
            make_fifo(&fifo);
            match read_file_capped(&fifo, 1024, || {
                CryptoError::InvalidInput("over cap".to_string())
            }) {
                Err(CryptoError::InvalidInput(msg)) => {
                    assert!(msg.contains("Unsupported file type"), "got: {msg}");
                }
                other => panic!("expected InvalidInput, got {other:?}"),
            }
        }

        #[test]
        fn open_input_file_accepts_regular_file() {
            let tmp = tempfile::TempDir::new().unwrap();
            let file = tmp.path().join("regular");
            std::fs::write(&file, b"bytes").unwrap();
            open_input_file(&file, CryptoError::Io).expect("regular file must open");
        }
    }

    #[test]
    fn path_occupied_returns_false_for_missing_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let absent = tmp.path().join("does-not-exist");
        assert!(!path_occupied(&absent).unwrap());
    }

    #[test]
    fn path_occupied_returns_true_for_real_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file = tmp.path().join("real");
        std::fs::write(&file, b"x").unwrap();
        assert!(path_occupied(&file).unwrap());
    }

    /// A dangling symlink (target missing) must be reported as occupied
    /// so encrypt / keygen output prechecks reject it before any
    /// expensive KDF / wrapping work runs. `Path::exists()` follows the
    /// link and would return `false`, masking the conflict until the
    /// atomic no-clobber rename. Unix-only because Windows symlink
    /// creation requires elevated privileges and the platform-level
    /// hardening tests already cover that surface.
    #[cfg(unix)]
    #[test]
    fn path_occupied_returns_true_for_dangling_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::TempDir::new().unwrap();
        let link = tmp.path().join("dangling");
        symlink(tmp.path().join("absent-target"), &link).unwrap();
        assert!(!link.exists(), "sanity: target really is missing");
        assert!(path_occupied(&link).unwrap());
    }
}
