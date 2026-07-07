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
use crate::error::{sanitize_for_display, sanitize_path_for_display};

/// Suffix appended to atomic-write working names so plaintext (or any
/// not-yet-finalised output) is never visible under the final name.
/// Used by `container::write_encrypted_file` for the streaming
/// `.fcr` tempfile and by `archive::decode::unarchive` for the per-root
/// rename-into-place pattern. `pub` (in a private module) so
/// `fuzz_exports` can re-export it for the full-pipeline fuzz oracle.
pub const INCOMPLETE_SUFFIX: &str = ".incomplete";

/// Conflict-message label for the encrypted-file or extracted output
/// artefact ("Output already exists: …"). The occupancy pre-check
/// ([`reject_occupied`]) and the no-clobber commit
/// (`fs::atomic::finalize_file`) for the same operation must pass the
/// same label so their two messages read identically; a shared
/// constant makes that structural rather than a per-site literal.
pub(crate) const OUTPUT_LABEL: &str = "Output";

/// Conflict-message label for a generated key file ("Key file already
/// exists: …"). Paired between the keygen pre-check and its no-clobber
/// commit the same way as [`OUTPUT_LABEL`].
pub(crate) const KEY_FILE_LABEL: &str = "Key file";

/// Builds the "Input name is not valid UTF-8: `<path>`" rejection.
/// FCA paths are UTF-8 (`FORMAT.md` §9.6), so a non-UTF-8 input name
/// can never encrypt. Shared by the default-output-name path
/// ([`encryption_base_name`]) and the archive writer's root-name check
/// so both surfaces of the same rejection read identically.
pub(crate) fn input_name_not_utf8_error(path: &Path) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "Input name is not valid UTF-8: {}",
        sanitize_path_for_display(path)
    ))
}

/// Builds the "Unsupported file type: `<path>`" rejection for an input
/// that is neither a regular file nor a directory (a FIFO, socket, or
/// device node). Shared by [`open_input_file`] and the archive
/// writer's input-root checks.
pub(crate) fn unsupported_file_type_error(path: &Path) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "Unsupported file type: {}",
        sanitize_path_for_display(path)
    ))
}

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
        return Err(unsupported_file_type_error(path));
    }
    Ok(file)
}

/// Reads `path` into memory, refusing files whose byte length exceeds
/// `cap`. Bounds the allocation at `cap + 1` bytes so a caller pointed
/// at a multi-gigabyte file rejects before the kernel pages the whole file
/// into memory. The `over_cap_error` closure supplies the typed rejection so
/// each caller can route the failure to the right diagnostic class
/// (`MalformedPublicKey` / `MalformedPrivateKey`).
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
        .take((cap as u64).saturating_add(1))
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
/// Returns [`CryptoError::InvalidInput`] when the name is not valid
/// UTF-8: FCA paths are UTF-8 (`FORMAT.md` §9.6), so such an input can
/// never encrypt anyway, and a lossy replacement could silently
/// collapse two distinct on-disk names into the same output name.
///
/// Uses `symlink_metadata` (lstat) rather than `Path::is_dir` so a
/// symlink that races into place between the earlier
/// `validate_encrypt_input` symlink check and this lookup cannot be
/// followed to a directory and silently change the chosen output
/// name. The later `open_no_follow` would still abort the archive step,
/// but defending here keeps the directory-vs-file classification honest.
/// `NotFound` falls through to the file branch (race against deletion);
/// other I/O errors propagate so `PermissionDenied` is not misreported as
/// "not a directory" and downgraded into a confusing later failure.
pub(crate) fn encryption_base_name(path: impl AsRef<Path>) -> Result<String, CryptoError> {
    let path = path.as_ref();
    let is_real_dir = match std::fs::symlink_metadata(path) {
        Ok(m) => m.file_type().is_dir(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => return Err(CryptoError::Io(e)),
    };
    let name = if is_real_dir {
        path.file_name()
            .ok_or_else(|| CryptoError::InvalidInput("Cannot get directory name".to_string()))?
    } else {
        file_stem(path)?
    };
    name.to_str()
        .map(str::to_owned)
        .ok_or_else(|| input_name_not_utf8_error(path))
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

/// Builds the "`<label>` already exists: `<path>`" rejection. Shared by
/// [`reject_occupied`] (pre-write occupancy check),
/// `fs::atomic::finalize_file` (no-clobber rename refusal), and the
/// archive extractor's occupied-output rejection, so every surface of
/// the same conflict renders identically.
///
/// The parent directory is the caller's trust boundary: shown raw and
/// never truncated, so the operator can always locate the conflict.
/// The final component can be attacker-influenced (an input-derived
/// file stem, an archive-chosen root name), so it is escaped and
/// length-bounded.
pub(crate) fn already_exists_error(label: &str, path: &Path) -> CryptoError {
    let full = path.display().to_string();
    let rendered = match path.file_name().map(|n| n.to_string_lossy()) {
        // The rendered path ends with the rendered file name by
        // construction; keep the directory prefix (with its original
        // separator) raw and escape only the name.
        Some(name) if name.len() < full.len() && full.ends_with(name.as_ref()) => {
            format!(
                "{}{}",
                &full[..full.len() - name.len()],
                sanitize_for_display(&name)
            )
        }
        // No directory prefix to keep (bare file name, filesystem
        // root, or a `..` tail): sanitize the whole path.
        _ => sanitize_for_display(&full),
    };
    CryptoError::InvalidInput(format!("{label} already exists: {rendered}"))
}

/// Returns `Err(InvalidInput)` if `path` is occupied (real file, real
/// directory, or dangling symlink). `label` is the artefact name in the
/// message prefix; callers pass [`OUTPUT_LABEL`] or [`KEY_FILE_LABEL`]
/// and must reuse the same value at the paired
/// `fs::atomic::finalize_file` commit so both messages match.
pub(crate) fn reject_occupied(path: &Path, label: &str) -> Result<(), CryptoError> {
    if path_occupied(path)? {
        return Err(already_exists_error(label, path));
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

    /// A non-UTF-8 input name rejects with a typed error instead of
    /// lossy-replacing the invalid bytes: two distinct on-disk names
    /// could otherwise collapse to the same computed output name, and
    /// the FCA layer would refuse the name later anyway. Unix-only —
    /// Windows file names are always valid Unicode at this API level.
    #[cfg(unix)]
    #[test]
    fn encryption_base_name_rejects_non_utf8_name() {
        use std::os::unix::ffi::OsStrExt;
        let name = OsStr::from_bytes(b"bad\xFFname.txt");
        match encryption_base_name(Path::new(name)) {
            Err(CryptoError::InvalidInput(msg)) => {
                assert!(
                    msg.starts_with("Input name is not valid UTF-8: "),
                    "got: {msg}"
                );
            }
            other => panic!("expected InvalidInput for non-UTF-8 name, got {other:?}"),
        }
    }

    /// Fallback arm of the conflict-message renderer: a path with no
    /// directory prefix (a bare file name, as `save_as` can supply)
    /// sanitizes the whole path, so malicious bytes in a bare name are
    /// escaped the same way as in a name under a directory.
    #[test]
    fn already_exists_error_escapes_bare_hostile_name() {
        match already_exists_error("Output", Path::new("evil\u{1b}.fcr")) {
            CryptoError::InvalidInput(msg) => {
                assert_eq!(msg, "Output already exists: evil\\u{1b}.fcr");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    /// Fast arm with a multibyte directory prefix: the split between
    /// "keep raw" and "escape" lands on a UTF-8 boundary (the byte
    /// slice must not panic), the non-ASCII directory name stays raw so
    /// the operator can read it, and the malicious leaf is escaped.
    #[test]
    fn already_exists_error_keeps_multibyte_dir_raw_escapes_name() {
        match already_exists_error("Key file", Path::new("Données/evil\u{202e}.key")) {
            CryptoError::InvalidInput(msg) => {
                assert_eq!(msg, "Key file already exists: Données/evil\\u{202e}.key");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    /// A malicious file name at an occupied output path renders escaped:
    /// the rejection message must never carry raw control bytes to a
    /// terminal. The parent directory stays raw so the operator can
    /// locate the conflict; the file name has its own display budget,
    /// so the escaped form appears in full regardless of how long the
    /// directory prefix is. Unix-only — Windows refuses control bytes
    /// in file names at creation time.
    #[cfg(unix)]
    #[test]
    fn reject_occupied_escapes_hostile_file_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        let hostile = tmp.path().join("evil\u{1b}]0;pwned\u{7}.txt");
        std::fs::write(&hostile, b"x").unwrap();
        match reject_occupied(&hostile, "Output") {
            Err(CryptoError::InvalidInput(msg)) => {
                assert!(msg.starts_with("Output already exists: "), "got: {msg}");
                assert!(
                    msg.contains("evil\\u{1b}]0;pwned\\u{7}.txt"),
                    "escaped file name must appear in full: {msg}"
                );
                assert!(
                    !msg.chars().any(char::is_control),
                    "raw control character leaked: {msg:?}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
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

        /// The unsupported-file-type rejection escapes a malicious input
        /// name; the message must never carry raw control bytes.
        #[test]
        fn open_input_file_escapes_hostile_fifo_name() {
            let tmp = tempfile::TempDir::new().unwrap();
            let fifo = tmp.path().join("pipe\u{1b}[2K.fcr");
            make_fifo(&fifo);
            match open_input_file(&fifo, CryptoError::Io) {
                Err(CryptoError::InvalidInput(msg)) => {
                    assert!(msg.starts_with("Unsupported file type: "), "got: {msg}");
                    assert!(
                        !msg.chars().any(char::is_control),
                        "raw control character leaked: {msg:?}"
                    );
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
