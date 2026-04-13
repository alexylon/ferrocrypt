use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use crate::CryptoError;

/// Default file mode for non-Unix platforms (rw-r--r--).
#[cfg(not(unix))]
const DEFAULT_FILE_MODE: u32 = 0o644;

/// Mask that keeps only owner/group/other rwx bits, stripping
/// setuid, setgid, and sticky bits from tar-stored permissions.
#[cfg(unix)]
const PERMISSION_BITS_MASK: u32 = 0o777;

/// Rejects paths that could escape the output directory (path traversal).
pub(crate) fn validate_archive_path(path: &Path) -> Result<(), CryptoError> {
    for component in path.components() {
        match component {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(CryptoError::InvalidInput(format!(
                    "Unsafe path in archive: {}",
                    path.display()
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Archives a file or directory into a TAR stream written to `writer`.
/// Returns a tuple of the file stem (base name without extension for files,
/// directory name for directories) and the writer, so the caller can finalize it.
///
/// For directories, uses a manual recursive walk instead of `append_dir_all`
/// to give per-entry control: symlinks and special entries (sockets, FIFOs,
/// devices) are rejected with a clear error. Hardlinks are archived as regular
/// file contents without preserving link identity.
pub fn archive<W: Write>(
    input_path: impl AsRef<Path>,
    writer: W,
) -> Result<(String, W), CryptoError> {
    let input_path = input_path.as_ref();
    if input_path.is_symlink() {
        return Err(CryptoError::InvalidInput(format!(
            "Input is a symlink: {}",
            input_path.display()
        )));
    }
    if !input_path.is_file() && !input_path.is_dir() {
        return Err(CryptoError::InvalidInput(format!(
            "Unsupported file type: {}",
            input_path.display()
        )));
    }
    let mut builder = tar::Builder::new(writer);

    let stem = if input_path.is_file() {
        let file_name = input_path
            .file_name()
            .ok_or_else(|| CryptoError::InvalidInput("Cannot get file name".to_string()))?;

        append_file(&mut builder, input_path, Path::new(file_name))?;

        crate::common::file_stem(input_path)?
            .to_string_lossy()
            .into_owned()
    } else {
        let dir_name = input_path
            .file_name()
            .ok_or_else(|| CryptoError::InvalidInput("Cannot get directory name".to_string()))?;

        let archive_root = PathBuf::from(dir_name);
        archive_directory(&mut builder, input_path, &archive_root)?;
        dir_name.to_string_lossy().into_owned()
    };

    let writer = builder.into_inner()?;
    Ok((stem, writer))
}

fn append_file<W: Write>(
    builder: &mut tar::Builder<W>,
    src_path: &Path,
    archive_path: &Path,
) -> Result<(), CryptoError> {
    let mut file = open_no_follow(src_path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(CryptoError::InvalidInput(format!(
            "Path is no longer a regular file: {}",
            src_path.display()
        )));
    }
    let mut header = tar::Header::new_gnu();
    header.set_size(metadata.len());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        header.set_mode(metadata.permissions().mode() & PERMISSION_BITS_MASK);
    }
    #[cfg(not(unix))]
    header.set_mode(DEFAULT_FILE_MODE);
    header.set_cksum();
    builder.append_data(&mut header, archive_path, &mut file)?;
    Ok(())
}

fn append_dir_entry<W: Write>(
    builder: &mut tar::Builder<W>,
    src_path: &Path,
    archive_path: &Path,
) -> Result<(), CryptoError> {
    let metadata = fs::metadata(src_path)?;
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        header.set_mode(metadata.permissions().mode() & PERMISSION_BITS_MASK);
    }
    #[cfg(not(unix))]
    header.set_mode(0o755);
    header.set_cksum();
    builder.append_data(&mut header, archive_path, &mut io::empty())?;
    Ok(())
}

/// Opens a file refusing to follow symlinks.
/// On Unix, uses `O_NOFOLLOW` so the open itself is atomic.
/// On other platforms, falls back to a symlink_metadata check before opening.
#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File, CryptoError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                CryptoError::InvalidInput(format!("Path is a symlink: {}", path.display()))
            } else {
                CryptoError::Io(e)
            }
        })
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<File, CryptoError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(CryptoError::InvalidInput(format!(
            "Path is not a regular file: {}",
            path.display()
        )));
    }
    Ok(File::open(path)?)
}

/// Recursively archives a directory. Uses `entry.file_type()` (lstat-based)
/// to classify entries without following symlinks.
fn archive_directory<W: Write>(
    builder: &mut tar::Builder<W>,
    dir_path: &Path,
    archive_prefix: &Path,
) -> Result<(), CryptoError> {
    append_dir_entry(builder, dir_path, archive_prefix)?;

    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let src_path = entry.path();
        let ft = entry.file_type()?;
        let entry_archive_path = archive_prefix.join(entry.file_name());

        if ft.is_symlink() {
            return Err(CryptoError::InvalidInput(format!(
                "Directory contains a symlink: {}",
                src_path.display()
            )));
        } else if ft.is_dir() {
            archive_directory(builder, &src_path, &entry_archive_path)?;
        } else if ft.is_file() {
            append_file(builder, &src_path, &entry_archive_path)?;
        } else {
            return Err(CryptoError::InvalidInput(format!(
                "Unsupported file type in directory: {}",
                src_path.display()
            )));
        }
    }
    Ok(())
}

/// Extracts a TAR archive from `reader` into the specified directory.
///
/// All output is written under an `.incomplete` working name so that
/// plaintext never appears under the final name during streaming
/// decryption. On success, the working name is atomically renamed to the
/// final name. On failure, the `.incomplete` output stays on disk for
/// the user to inspect or delete.
pub fn unarchive<R: Read>(reader: R, output_dir: &Path) -> Result<PathBuf, CryptoError> {
    let mut archive = tar::Archive::new(reader);
    let mut first_entry_root: Option<PathBuf> = None;
    let mut checked_roots: Vec<OsString> = Vec::new();

    let extract_result = extract_entries(
        &mut archive,
        output_dir,
        &mut first_entry_root,
        &mut checked_roots,
    );

    extract_result?;

    // Rename each root from .incomplete working name to final name.
    for root_name in &checked_roots {
        let mut incomplete_name = root_name.clone();
        incomplete_name.push(".incomplete");
        let working_path = output_dir.join(&incomplete_name);
        let final_path = output_dir.join(root_name);
        if let Err(e) = rename_no_clobber(&working_path, &final_path) {
            return Err(CryptoError::InternalError(format!(
                "Cannot rename to final output: {e}"
            )));
        }
    }

    first_entry_root.ok_or_else(|| CryptoError::InvalidInput("Empty archive".to_string()))
}

/// Atomically renames `from` to `to`, failing if `to` already exists.
#[cfg(target_os = "linux")]
pub(crate) fn rename_no_clobber(from: &Path, to: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let from_c = CString::new(from.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("path contains null byte"))?;
    let to_c = CString::new(to.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("path contains null byte"))?;
    // SAFETY: CString pointers are valid, null-terminated, and live for the call.
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from_c.as_ptr(),
            libc::AT_FDCWD,
            to_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn rename_no_clobber(from: &Path, to: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let from_c = CString::new(from.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("path contains null byte"))?;
    let to_c = CString::new(to.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("path contains null byte"))?;
    // SAFETY: CString pointers are valid, null-terminated, and live for the call.
    #[allow(unsafe_code)]
    let ret = unsafe { libc::renamex_np(from_c.as_ptr(), to_c.as_ptr(), libc::RENAME_EXCL) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn rename_no_clobber(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    // Windows path encoding constants.
    const BACK: u16 = b'\\' as u16;
    const QUESTION: u16 = b'?' as u16;
    const DOT: u16 = b'.' as u16;
    // Paths whose wide-encoded length (including null terminator) exceeds
    // this threshold are converted to the \\?\ verbatim form so they can
    // bypass the MAX_PATH limit on Windows APIs.
    const MAX_PATH: usize = 260;

    // Encode a path as a null-terminated UTF-16 wide string, rejecting
    // embedded NUL code units (which are invalid in Windows paths anyway).
    fn to_wide(p: &Path) -> io::Result<Vec<u16>> {
        let mut out: Vec<u16> = Vec::with_capacity(p.as_os_str().len() + 1);
        for u in p.as_os_str().encode_wide() {
            if u == 0 {
                return Err(io::Error::other("path contains null code unit"));
            }
            out.push(u);
        }
        out.push(0);
        Ok(out)
    }

    // True when the wide path is already in the Win32 file namespace
    // (`\\?\...`) or the device namespace (`\\.\...`), in which case it
    // must be passed through untouched.
    fn is_verbatim(w: &[u16]) -> bool {
        w.len() >= 4
            && w[0] == BACK
            && w[1] == BACK
            && (w[2] == QUESTION || w[2] == DOT)
            && w[3] == BACK
    }

    // Canonicalize a path via GetFullPathNameW. Required before verbatim
    // prefixing because verbatim paths do not undergo `.` / `..` / redundant
    // separator normalization — the literal string is handed to the kernel.
    fn full_path(input: &[u16]) -> io::Result<Vec<u16>> {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetFullPathNameW(
                lp_file_name: *const u16,
                n_buffer_length: u32,
                lp_buffer: *mut u16,
                lp_file_part: *mut *mut u16,
            ) -> u32;
        }

        // Probe for the required buffer size (return value includes the
        // terminating null). SAFETY: `input` is a valid null-terminated
        // UTF-16 buffer; passing (length = 0, buffer = null) for the output
        // is a documented Win32 pattern.
        #[allow(unsafe_code)]
        let required = unsafe {
            GetFullPathNameW(
                input.as_ptr(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if required == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut buf: Vec<u16> = vec![0u16; required as usize];
        // SAFETY: `input` and `buf` are valid for the duration of the call;
        // `buf` has capacity for exactly `required` wide chars, matching
        // what the probe demanded.
        #[allow(unsafe_code)]
        let written = unsafe {
            GetFullPathNameW(
                input.as_ptr(),
                required,
                buf.as_mut_ptr(),
                std::ptr::null_mut(),
            )
        };
        if written == 0 {
            return Err(io::Error::last_os_error());
        }
        // `written` excludes the null terminator. If it equals or exceeds
        // `required` the canonical form grew between the two calls — fail
        // instead of silently truncating.
        if written >= required {
            return Err(io::Error::other("path grew during canonicalization"));
        }
        buf.truncate(written as usize + 1);
        Ok(buf)
    }

    // Prepend the appropriate verbatim prefix to a canonical absolute path.
    // GetFullPathNameW returns either drive-letter form (`C:\...`) or UNC
    // form (`\\server\share\...`); map them to `\\?\C:\...` and
    // `\\?\UNC\server\share\...` respectively.
    fn to_verbatim(canonical: Vec<u16>) -> Vec<u16> {
        debug_assert_eq!(canonical.last(), Some(&0));
        let body_len = canonical.len() - 1;
        let body = &canonical[..body_len];

        let is_unc = body_len >= 2 && body[0] == BACK && body[1] == BACK;

        if is_unc {
            const PREFIX: [u16; 8] = [
                BACK,
                BACK,
                QUESTION,
                BACK,
                b'U' as u16,
                b'N' as u16,
                b'C' as u16,
                BACK,
            ];
            let mut out = Vec::with_capacity(PREFIX.len() + body_len - 2 + 1);
            out.extend_from_slice(&PREFIX);
            out.extend_from_slice(&body[2..]);
            out.push(0);
            out
        } else {
            const PREFIX: [u16; 4] = [BACK, BACK, QUESTION, BACK];
            let mut out = Vec::with_capacity(PREFIX.len() + body_len + 1);
            out.extend_from_slice(&PREFIX);
            out.extend_from_slice(body);
            out.push(0);
            out
        }
    }

    // Convert any path into a form MoveFileExW can always handle. Short
    // and already-verbatim paths pass through unchanged; long paths are
    // canonicalized and prefixed so they bypass the MAX_PATH limit.
    fn prepare(p: &Path) -> io::Result<Vec<u16>> {
        let wide = to_wide(p)?;
        if is_verbatim(&wide) || wide.len() <= MAX_PATH {
            return Ok(wide);
        }
        let canonical = full_path(&wide)?;
        // Defensive: GetFullPathNameW is not documented to introduce a
        // verbatim prefix on its own, but if it ever did we must not
        // double-prefix it here.
        if is_verbatim(&canonical) {
            return Ok(canonical);
        }
        Ok(to_verbatim(canonical))
    }

    // MoveFileExW with dwFlags = 0 fails with ERROR_ALREADY_EXISTS if `to`
    // exists. Rust's `std::fs::rename` on Windows sets the replace-if-exists
    // flag and would silently clobber the destination, which is why this
    // arm uses a direct FFI call instead of `std::fs::rename`.
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(
            lp_existing_file_name: *const u16,
            lp_new_file_name: *const u16,
            dw_flags: u32,
        ) -> i32;
    }

    let from_w = prepare(from)?;
    let to_w = prepare(to)?;

    // SAFETY: both pointers reference valid, null-terminated UTF-16 buffers
    // that live for the duration of the call. `dw_flags = 0` is a well-
    // defined value (no replace, no cross-volume copy, no delay).
    #[allow(unsafe_code)]
    let ret = unsafe { MoveFileExW(from_w.as_ptr(), to_w.as_ptr(), 0) };
    if ret != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn rename_no_clobber(from: &Path, to: &Path) -> io::Result<()> {
    // Fallback: check + rename (TOCTOU possible, best effort).
    if to.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "target exists",
        ));
    }
    fs::rename(from, to)
}

fn extract_entries<R: Read>(
    archive: &mut tar::Archive<R>,
    output_dir: &Path,
    first_entry_root: &mut Option<PathBuf>,
    checked_roots: &mut Vec<OsString>,
) -> Result<(), CryptoError> {
    // Directory permissions are applied after all entries are extracted,
    // deepest first, so that a restrictive parent mode (e.g. 0o500) does
    // not block creation of child entries.
    let mut dir_permissions: Vec<(PathBuf, u32)> = Vec::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let path = entry.path()?.to_path_buf();
        validate_archive_path(&path)?;

        let first_component = path
            .components()
            .next()
            .ok_or_else(|| CryptoError::InvalidInput("Empty archive entry".to_string()))?;
        let root_name = first_component.as_os_str().to_os_string();

        if !checked_roots.contains(&root_name) {
            let final_path = output_dir.join(&root_name);
            if final_path.exists() {
                return Err(CryptoError::InvalidInput(format!(
                    "Output already exists: {}",
                    final_path.display()
                )));
            }
            let mut incomplete_name = root_name.clone();
            incomplete_name.push(".incomplete");
            let incomplete_path = output_dir.join(&incomplete_name);
            if incomplete_path.exists() {
                return Err(CryptoError::InvalidInput(format!(
                    "Previous .incomplete exists: {}",
                    incomplete_path.display()
                )));
            }
            if first_entry_root.is_none() {
                *first_entry_root = Some(final_path);
            }
            checked_roots.push(root_name.clone());
        }

        // Rewrite the entry path: replace the root component with {root}.incomplete
        let working_path = incomplete_entry_path(output_dir, &root_name, &path);
        let entry_type = entry.header().entry_type();

        if entry_type.is_dir() {
            fs::create_dir_all(&working_path)?;
            if let Ok(mode) = entry.header().mode() {
                dir_permissions.push((working_path, mode));
            }
        } else if entry_type.is_file() {
            if let Some(parent) = working_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }
            let mut outfile = File::create(&working_path)?;
            io::copy(&mut entry, &mut outfile)?;
            drop(outfile);
            restore_permissions(entry.header(), &working_path)?;
        } else {
            return Err(CryptoError::InvalidInput(format!(
                "Unsupported archive entry type {:?} for path: {}",
                entry_type,
                path.display()
            )));
        }
    }

    // Apply directory permissions deepest-first so that restricting a parent
    // does not prevent setting permissions on its children.
    dir_permissions.sort_by(|a, b| b.0.components().count().cmp(&a.0.components().count()));
    for (path, mode) in &dir_permissions {
        restore_permissions_from_mode(*mode, path)?;
    }

    Ok(())
}

/// Rewrites a TAR entry path so the root component has an `.incomplete` suffix.
///
/// - Single file `hello.txt` → `output_dir/hello.txt.incomplete`
/// - Directory entry `mydir/sub/file.txt` → `output_dir/mydir.incomplete/sub/file.txt`
fn incomplete_entry_path(output_dir: &Path, root_name: &OsStr, entry_path: &Path) -> PathBuf {
    let mut incomplete_root = root_name.to_os_string();
    incomplete_root.push(".incomplete");
    match entry_path.strip_prefix(root_name) {
        Ok(rest) if rest.as_os_str().is_empty() => output_dir.join(&incomplete_root),
        Ok(rest) => output_dir.join(&incomplete_root).join(rest),
        Err(_) => output_dir.join(&incomplete_root),
    }
}

/// Restores file permissions from the TAR header.
/// On Unix, applies the stored mode with setuid/setgid/sticky bits stripped.
/// On other platforms this is a no-op.
#[cfg(unix)]
fn restore_permissions(header: &tar::Header, path: &Path) -> Result<(), CryptoError> {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(mode) = header.mode() {
        // Strip setuid, setgid, and sticky bits for safety.
        let safe_mode = mode & PERMISSION_BITS_MASK;
        fs::set_permissions(path, std::fs::Permissions::from_mode(safe_mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn restore_permissions(_header: &tar::Header, _path: &Path) -> Result<(), CryptoError> {
    Ok(())
}

/// Applies a stored mode to a path, stripping dangerous bits.
/// Used for deferred directory permission restoration.
#[cfg(unix)]
fn restore_permissions_from_mode(mode: u32, path: &Path) -> Result<(), CryptoError> {
    use std::os::unix::fs::PermissionsExt;
    let safe_mode = mode & PERMISSION_BITS_MASK;
    fs::set_permissions(path, std::fs::Permissions::from_mode(safe_mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn restore_permissions_from_mode(_mode: u32, _path: &Path) -> Result<(), CryptoError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;

    use crate::archiver::{archive, rename_no_clobber, unarchive};

    #[test]
    fn archive_and_unarchive_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("hello.txt");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(&input_file, "file content here").unwrap();

        let mut buf = Vec::new();
        let (stem, _) = archive(&input_file, &mut buf).unwrap();
        assert_eq!(stem, "hello");

        let output = unarchive(Cursor::new(buf), &extract_dir).unwrap();
        assert!(output.exists());

        let restored = fs::read_to_string(extract_dir.join("hello.txt")).unwrap();
        assert_eq!(restored, "file content here");
    }

    #[test]
    fn archive_and_unarchive_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_dir = tmp.path().join("mydir");
        let sub_dir = input_dir.join("sub");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&sub_dir).unwrap();
        fs::create_dir_all(&extract_dir).unwrap();

        fs::write(input_dir.join("a.txt"), "file a").unwrap();
        fs::write(sub_dir.join("b.txt"), "file b").unwrap();

        let mut buf = Vec::new();
        let (stem, _) = archive(&input_dir, &mut buf).unwrap();
        assert_eq!(stem, "mydir");

        let output = unarchive(Cursor::new(buf), &extract_dir).unwrap();
        assert!(output.exists());

        let restored_a = fs::read_to_string(extract_dir.join("mydir/a.txt")).unwrap();
        assert_eq!(restored_a, "file a");
        let restored_b = fs::read_to_string(extract_dir.join("mydir/sub/b.txt")).unwrap();
        assert_eq!(restored_b, "file b");
    }

    #[cfg(unix)]
    #[test]
    fn archive_rejects_directory_with_symlink() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_dir = tmp.path().join("mydir");
        fs::create_dir_all(&input_dir).unwrap();
        fs::write(input_dir.join("real.txt"), "content").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", input_dir.join("link.txt")).unwrap();

        let mut buf = Vec::new();
        let err = archive(&input_dir, &mut buf).unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "expected symlink error, got: {err}"
        );
    }

    #[test]
    fn archive_empty_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("empty.txt");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(&input_file, "").unwrap();

        let mut buf = Vec::new();
        let (stem, _) = archive(&input_file, &mut buf).unwrap();
        assert_eq!(stem, "empty");

        unarchive(Cursor::new(buf), &extract_dir).unwrap();
        let restored = fs::read_to_string(extract_dir.join("empty.txt")).unwrap();
        assert_eq!(restored, "");
    }

    #[test]
    fn validate_rejects_path_traversal() {
        use crate::archiver::validate_archive_path;
        use std::path::Path;

        assert!(validate_archive_path(Path::new("safe.txt")).is_ok());
        assert!(validate_archive_path(Path::new("dir/file.txt")).is_ok());
        assert!(validate_archive_path(Path::new("../escape.txt")).is_err());
        assert!(validate_archive_path(Path::new("dir/../../escape.txt")).is_err());
        assert!(validate_archive_path(Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn unarchive_rejects_second_root_that_conflicts() {
        // Craft a TAR with two top-level roots: "innocent/" and "victim.txt".
        // Pre-create "victim.txt" in the extract dir to prove the second root
        // is checked and the extraction is refused.
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(extract_dir.join("victim.txt"), "original").unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);

            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "innocent/", &[] as &[u8])
                .unwrap();

            let data = b"malicious payload";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "victim.txt", &data[..])
                .unwrap();

            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
        assert!(
            err.to_string().contains("Output already exists"),
            "expected conflict error, got: {err}"
        );

        // Verify the original file was NOT overwritten
        let content = fs::read_to_string(extract_dir.join("victim.txt")).unwrap();
        assert_eq!(content, "original");
    }

    #[test]
    fn unarchive_rejects_symlink_entry() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);

            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_link(&mut header, "link.txt", "target.txt")
                .unwrap();

            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
        assert!(
            err.to_string().contains("Unsupported archive entry type"),
            "expected unsupported entry error, got: {err}"
        );
    }

    #[test]
    fn archive_binary_content() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("data.bin");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let binary_data: Vec<u8> = (0..=255).collect();
        fs::write(&input_file, &binary_data).unwrap();

        let mut buf = Vec::new();
        let (_, _) = archive(&input_file, &mut buf).unwrap();

        unarchive(Cursor::new(buf), &extract_dir).unwrap();

        let restored = fs::read(extract_dir.join("data.bin")).unwrap();
        assert_eq!(restored, binary_data);
    }

    #[cfg(unix)]
    #[test]
    fn archive_preserves_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("script.sh");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(&input_file, "#!/bin/sh\necho hi").unwrap();
        fs::set_permissions(&input_file, fs::Permissions::from_mode(0o755)).unwrap();

        let mut buf = Vec::new();
        let (_, _) = archive(&input_file, &mut buf).unwrap();

        unarchive(Cursor::new(buf), &extract_dir).unwrap();

        let restored = extract_dir.join("script.sh");
        let mode = fs::metadata(&restored).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "expected 0o755, got 0o{mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn archive_preserves_directory_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let input_dir = tmp.path().join("mydir");
        let sub_dir = input_dir.join("restricted");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&sub_dir).unwrap();
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(sub_dir.join("secret.txt"), "data").unwrap();
        fs::set_permissions(&sub_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let mut buf = Vec::new();
        let (_, _) = archive(&input_dir, &mut buf).unwrap();

        unarchive(Cursor::new(buf), &extract_dir).unwrap();

        let restored_sub = extract_dir.join("mydir/restricted");
        let mode = fs::metadata(&restored_sub).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected 0o700, got 0o{mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn archive_restrictive_dir_does_not_block_children() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let input_dir = tmp.path().join("mydir");
        let sub_dir = input_dir.join("readonly");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&sub_dir).unwrap();
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(sub_dir.join("inner.txt"), "hello").unwrap();
        // r-x------ : no write permission
        fs::set_permissions(&sub_dir, fs::Permissions::from_mode(0o500)).unwrap();

        let mut buf = Vec::new();
        let (_, _) = archive(&input_dir, &mut buf).unwrap();

        // Must not fail with "Permission denied" when extracting inner.txt
        unarchive(Cursor::new(buf), &extract_dir).unwrap();

        let restored_file = extract_dir.join("mydir/readonly/inner.txt");
        assert_eq!(fs::read_to_string(&restored_file).unwrap(), "hello");

        let dir_mode = fs::metadata(extract_dir.join("mydir/readonly"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o500, "expected 0o500, got 0o{dir_mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn archive_strips_special_bits_on_extract() {
        use std::os::unix::fs::PermissionsExt;

        let cases: &[(u32, &str)] = &[
            (0o4755, "setuid"),
            (0o2755, "setgid"),
            (0o1755, "sticky"),
            (0o6755, "setuid+setgid"),
            (0o7777, "all special + all rwx"),
        ];

        for &(input_mode, label) in cases {
            let tmp = tempfile::TempDir::new().unwrap();
            let extract_dir = tmp.path().join("extracted");
            fs::create_dir_all(&extract_dir).unwrap();

            let data = b"payload";
            let mut buf = Vec::new();
            {
                let mut builder = tar::Builder::new(&mut buf);
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(input_mode);
                header.set_cksum();
                builder
                    .append_data(&mut header, "file.sh", &data[..])
                    .unwrap();
                builder.finish().unwrap();
            }

            unarchive(Cursor::new(buf), &extract_dir).unwrap();

            let restored = extract_dir.join("file.sh");
            let mode = fs::metadata(&restored).unwrap().permissions().mode() & 0o7777;
            let expected = input_mode & 0o777;
            assert_eq!(
                mode, expected,
                "{label}: expected 0o{expected:o}, got 0o{mode:o}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn archive_strips_special_bits_on_directory_extract() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);

            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o4755); // setuid on directory
            header.set_cksum();
            builder
                .append_data(&mut header, "stickydir/", &[] as &[u8])
                .unwrap();

            let data = b"child";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "stickydir/child.txt", &data[..])
                .unwrap();

            builder.finish().unwrap();
        }

        unarchive(Cursor::new(buf), &extract_dir).unwrap();

        let dir_mode = fs::metadata(extract_dir.join("stickydir"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            dir_mode, 0o755,
            "directory setuid should be stripped: expected 0o755, got 0o{dir_mode:o}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn archive_strips_special_bits_on_archive_side() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("script.sh");
        fs::write(&input_file, "#!/bin/sh").unwrap();
        fs::set_permissions(&input_file, fs::Permissions::from_mode(0o4755)).unwrap();

        let mut buf = Vec::new();
        let (_, _) = archive(&input_file, &mut buf).unwrap();

        // Read the mode stored in the tar header directly.
        let mut tar_archive = tar::Archive::new(Cursor::new(buf));
        let entry = tar_archive.entries().unwrap().next().unwrap().unwrap();
        let stored_mode = entry.header().mode().unwrap();
        assert_eq!(
            stored_mode & 0o7000,
            0,
            "special bits should not be stored in archive: mode 0o{stored_mode:o}"
        );
        assert_eq!(
            stored_mode & 0o777,
            0o755,
            "rwx bits should be preserved: mode 0o{stored_mode:o}"
        );
    }

    #[test]
    fn rename_no_clobber_refuses_to_overwrite() {
        let tmp = tempfile::TempDir::new().unwrap();
        let from = tmp.path().join("src.txt");
        let to = tmp.path().join("dst.txt");
        fs::write(&from, "new").unwrap();
        fs::write(&to, "existing").unwrap();

        let err = rename_no_clobber(&from, &to).unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::AlreadyExists,
            "expected AlreadyExists, got: {err:?}"
        );
        // Destination must be untouched and source must still exist.
        assert_eq!(fs::read_to_string(&to).unwrap(), "existing");
        assert!(from.exists(), "source should not have been moved");
    }

    #[test]
    fn rename_no_clobber_succeeds_when_target_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let from = tmp.path().join("src.txt");
        let to = tmp.path().join("dst.txt");
        fs::write(&from, "payload").unwrap();

        rename_no_clobber(&from, &to).unwrap();

        assert!(!from.exists(), "source should have been moved");
        assert_eq!(fs::read_to_string(&to).unwrap(), "payload");
    }
}
