//! Encrypt-side TAR construction: validates the input, walks the
//! source tree (rejecting symlinks and unsupported file types), and
//! emits canonical POSIX ustar headers verbatim — no GNU long-name or
//! PAX extension records.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use crate::CryptoError;
use crate::fs::paths::file_stem;

use super::limits::{ArchiveLimits, enforce_per_entry_caps, enforce_total_bytes_cap};
use super::path::{UstarEntryKind, ustar};

/// Default file mode for non-Unix platforms (rw-r--r--).
#[cfg(not(unix))]
const DEFAULT_FILE_MODE: u32 = 0o644;

/// Default directory mode for non-Unix platforms (rwxr-xr-x).
#[cfg(not(unix))]
const DEFAULT_DIR_MODE: u32 = 0o755;

/// Reads the rwx-only Unix permission word from `metadata`, stripping
/// setuid/setgid/sticky. Used by the encrypt-side header builders to
/// fold the `cfg(unix)`-gated `PermissionsExt` import into one place.
#[cfg(unix)]
fn metadata_perm_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & super::PERMISSION_BITS_MASK
}

/// Mode to store in a TAR header for a regular file. On Unix the rwx
/// bits of the source file (special bits stripped); on non-Unix targets
/// a fixed default since Unix permission semantics don't apply. Folds
/// the per-platform `cfg` dance out of `append_file`.
fn archive_file_mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        metadata_perm_mode(metadata)
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        DEFAULT_FILE_MODE
    }
}

/// Mode to store in a TAR header for a directory. Reads `src_path`
/// metadata fresh on Unix; on non-Unix returns the fixed default
/// without touching the filesystem (Windows has no rwx perms to read,
/// and skipping the syscall avoids a fresh failure mode where a
/// concurrent removal between `read_dir` and `append_dir_entry` would
/// otherwise abort the archive).
fn archive_dir_mode(src_path: &Path) -> Result<u32, CryptoError> {
    #[cfg(unix)]
    {
        Ok(metadata_perm_mode(&fs::metadata(src_path)?))
    }
    #[cfg(not(unix))]
    {
        let _ = src_path;
        Ok(DEFAULT_DIR_MODE)
    }
}

/// Running totals threaded through the recursive archive walk so the
/// encrypt-side preflight (`archive` → `archive_directory` →
/// `append_file` / `append_dir_entry`) can enforce [`ArchiveLimits`]
/// across the entire tree, not just per-call.
#[derive(Debug, Default)]
struct ArchiveCounters {
    entry_count: u32,
    total_bytes: u64,
}

/// Archives a file or directory into a TAR stream written to `writer`.
/// Returns a tuple of the file stem (base name without extension for files,
/// directory name for directories) and the writer, so the caller can finalize it.
///
/// For directories, uses a manual recursive walk instead of `append_dir_all`
/// to give per-entry control: symlinks and special entries (sockets, FIFOs,
/// devices) are rejected with a clear error. Hardlinks are archived as regular
/// file contents without preserving link identity.
pub(crate) fn archive<W: Write>(
    input_path: impl AsRef<Path>,
    writer: W,
    limits: ArchiveLimits,
) -> Result<(String, W), CryptoError> {
    let input_path = input_path.as_ref();
    validate_encrypt_input(input_path)?;
    let mut builder = tar::Builder::new(writer);
    let mut counters = ArchiveCounters::default();

    let stem = if input_path.is_file() {
        let file_name = input_path
            .file_name()
            .ok_or_else(|| CryptoError::InvalidInput("Cannot get file name".to_string()))?;

        append_file(
            &mut builder,
            input_path,
            Path::new(file_name),
            &mut counters,
            &limits,
        )?;

        file_stem(input_path)?.to_string_lossy().into_owned()
    } else {
        let dir_name = input_path
            .file_name()
            .ok_or_else(|| CryptoError::InvalidInput("Cannot get directory name".to_string()))?;

        let archive_root = PathBuf::from(dir_name);
        archive_directory(
            &mut builder,
            input_path,
            &archive_root,
            &mut counters,
            &limits,
        )?;
        dir_name.to_string_lossy().into_owned()
    };

    let writer = builder.into_inner()?;
    Ok((stem, writer))
}

/// Rejects inputs the archiver will not accept: symlinks (live or dangling)
/// and anything that isn't a regular file or directory. Defined here because
/// these are the archiver's per-entry rules; `lib.rs` also calls this at the
/// top of every encrypt entry point so that the rejection fires before any
/// Argon2id or cipher work runs (up to a gigabyte of RAM and several seconds
/// of CPU on default settings), not only at archive time. The archive-time
/// call remains as defense-in-depth against TOCTOU and direct callers.
///
/// The `is_symlink` check runs before the existence check so that dangling
/// symlinks fail with a clear "Input is a symlink" message instead of a
/// generic `InputPath` not-found.
pub(crate) fn validate_encrypt_input(input_path: &Path) -> Result<(), CryptoError> {
    if input_path.is_symlink() {
        return Err(CryptoError::InvalidInput(format!(
            "Input is a symlink: {}",
            input_path.display()
        )));
    }
    if !input_path.exists() {
        return Err(CryptoError::InputPath);
    }
    if !input_path.is_file() && !input_path.is_dir() {
        return Err(CryptoError::InvalidInput(format!(
            "Unsupported file type: {}",
            input_path.display()
        )));
    }
    Ok(())
}

/// Translates a relative `archive_path` (any platform) into the
/// canonical UTF-8 `/`-separated form required by the v1 archive
/// subset and rejects inputs that cannot be represented in raw POSIX
/// ustar (`name(100) || prefix(155)`). Directory paths get a single
/// trailing `/`; file paths must not end with one.
///
/// `Builder::append_data` would silently fall back to a GNU long-name
/// extension record for paths above the ustar limit; v1 forbids those,
/// so the rejection has to happen here, before any header bytes are
/// emitted.
fn ustar_archive_path_string(
    archive_path: &Path,
    kind: UstarEntryKind,
) -> Result<String, CryptoError> {
    let mut joined = String::new();
    let mut iter = archive_path.components().peekable();
    while let Some(component) = iter.next() {
        let part = match component {
            Component::Normal(s) => s.to_str().ok_or_else(|| {
                CryptoError::InvalidInput(format!(
                    "Archive path is not valid UTF-8: {}",
                    archive_path.display()
                ))
            })?,
            _ => {
                return Err(CryptoError::InvalidInput(format!(
                    "Archive path has forbidden component: {}",
                    archive_path.display()
                )));
            }
        };
        // Symmetric with the reader's `validate_ustar_entry` raw-byte
        // checks: a Unix filename containing `\` or NUL is technically
        // legal at the kernel level but produces an archive that v1
        // readers MUST reject (`FORMAT.md` §9). Rejecting here keeps
        // the writer round-trip-safe rather than emitting bytes our
        // own reader will refuse to decrypt.
        if part.contains('\\') || part.contains('\0') {
            return Err(CryptoError::InvalidInput(format!(
                "Archive path component contains forbidden byte (`\\` or NUL): {}",
                archive_path.display()
            )));
        }
        joined.push_str(part);
        if iter.peek().is_some() {
            joined.push('/');
        }
    }
    if joined.is_empty() {
        return Err(CryptoError::InvalidInput(
            "Empty archive entry path".to_string(),
        ));
    }
    if matches!(kind, UstarEntryKind::Directory) {
        joined.push('/');
    }
    if joined.len() > ustar::PATH_REPRESENTABLE_MAX {
        return Err(CryptoError::InvalidInput(format!(
            "Archive path cannot be represented in POSIX ustar: {}",
            archive_path.display()
        )));
    }
    Ok(joined)
}

/// Builds a v1-conforming ustar header for one archive entry. Pulled
/// out so `append_file` and `append_dir_entry` share the
/// path-normalization → `new_ustar` → `set_path` → `set_entry_type` →
/// `set_mode` → `set_cksum` sequence and the same error-message
/// translation for paths that don't fit the ustar `name + prefix`
/// split. `Header::set_path` would otherwise let `Builder::append_data`
/// silently fall back to a GNU long-name extension; we use
/// `Builder::append` at the call sites so this header is written
/// verbatim, with no auto-extension path.
fn build_ustar_header(
    archive_path: &Path,
    kind: UstarEntryKind,
    size: u64,
    mode: u32,
) -> Result<tar::Header, CryptoError> {
    let path_str = ustar_archive_path_string(archive_path, kind)?;
    let mut header = tar::Header::new_ustar();
    header.set_path(&path_str).map_err(|_| {
        CryptoError::InvalidInput(format!(
            "Archive path cannot be represented in POSIX ustar: {}",
            archive_path.display()
        ))
    })?;
    header.set_entry_type(match kind {
        UstarEntryKind::File => tar::EntryType::Regular,
        UstarEntryKind::Directory => tar::EntryType::Directory,
    });
    header.set_size(size);
    header.set_mode(mode);
    header.set_cksum();
    Ok(header)
}

fn append_file<W: Write>(
    builder: &mut tar::Builder<W>,
    src_path: &Path,
    archive_path: &Path,
    counters: &mut ArchiveCounters,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    counters.entry_count = counters.entry_count.saturating_add(1);
    enforce_per_entry_caps(counters.entry_count, archive_path, limits)?;

    let mut file = open_no_follow(src_path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(CryptoError::InvalidInput(format!(
            "Input is no longer a regular file: {}",
            src_path.display()
        )));
    }

    enforce_total_bytes_cap(metadata.len(), &mut counters.total_bytes, limits)?;

    let mode = archive_file_mode(&metadata);
    let header = build_ustar_header(archive_path, UstarEntryKind::File, metadata.len(), mode)?;
    builder.append(&header, &mut file)?;
    Ok(())
}

fn append_dir_entry<W: Write>(
    builder: &mut tar::Builder<W>,
    src_path: &Path,
    archive_path: &Path,
    counters: &mut ArchiveCounters,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    counters.entry_count = counters.entry_count.saturating_add(1);
    enforce_per_entry_caps(counters.entry_count, archive_path, limits)?;

    let mode = archive_dir_mode(src_path)?;
    let header = build_ustar_header(archive_path, UstarEntryKind::Directory, 0, mode)?;
    builder.append(&header, io::empty())?;
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
                CryptoError::InvalidInput(format!("Input is a symlink: {}", path.display()))
            } else {
                CryptoError::Io(e)
            }
        })
}

/// Best-effort no-follow open for Windows / non-Unix targets.
///
/// **Hardening note (Windows / non-Unix):** unlike the Unix branch
/// above, this implementation has a TOCTOU window between
/// `symlink_metadata` and `File::open`: a local attacker who can
/// rename the input path between the two syscalls can swap a regular
/// file for a symlink and have the open follow it. Closing the gap
/// requires `NtCreateFile` with `OBJECT_ATTRIBUTES` (or equivalent
/// winapi work), which the crate does not currently take on because
/// of its zero-`unsafe` stance. The pre-archive
/// [`validate_encrypt_input`] still rejects symlinks at the *outermost*
/// input path, and the per-entry recursive walker re-applies symlink
/// rejection — so an attacker's window is the syscall gap on each
/// open, not the entire archive run.
#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<File, CryptoError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(CryptoError::InvalidInput(format!(
            "Input is no longer a regular file: {}",
            path.display()
        )));
    }
    Ok(File::open(path)?)
}

/// Recursively archives a directory. Uses `entry.file_type()` (lstat-based)
/// to classify entries without following symlinks. Per-entry resource
/// caps from `limits` are enforced inside `append_file` /
/// `append_dir_entry` before each TAR header is emitted.
fn archive_directory<W: Write>(
    builder: &mut tar::Builder<W>,
    dir_path: &Path,
    archive_prefix: &Path,
    counters: &mut ArchiveCounters,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    append_dir_entry(builder, dir_path, archive_prefix, counters, limits)?;

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
            archive_directory(builder, &src_path, &entry_archive_path, counters, limits)?;
        } else if ft.is_file() {
            append_file(builder, &src_path, &entry_archive_path, counters, limits)?;
        } else {
            return Err(CryptoError::InvalidInput(format!(
                "Unsupported file type in directory: {}",
                src_path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::limits::ArchiveLimits;
    use super::super::path::UstarEntryKind;
    use super::super::path::ustar;
    use super::super::{archive, unarchive};
    use super::ustar_archive_path_string;

    use std::fs;
    use std::io::Cursor;
    use std::path::PathBuf;

    #[test]
    fn archive_and_unarchive_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("hello.txt");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(&input_file, "file content here").unwrap();

        let mut buf = Vec::new();
        let (stem, _) = archive(&input_file, &mut buf, ArchiveLimits::default()).unwrap();
        assert_eq!(stem, "hello");

        let output = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap();
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
        let (stem, _) = archive(&input_dir, &mut buf, ArchiveLimits::default()).unwrap();
        assert_eq!(stem, "mydir");

        let output = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap();
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
        let err = archive(&input_dir, &mut buf, ArchiveLimits::default()).unwrap_err();
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
        let (stem, _) = archive(&input_file, &mut buf, ArchiveLimits::default()).unwrap();
        assert_eq!(stem, "empty");

        unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap();
        let restored = fs::read_to_string(extract_dir.join("empty.txt")).unwrap();
        assert_eq!(restored, "");
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
        let (_, _) = archive(&input_file, &mut buf, ArchiveLimits::default()).unwrap();

        unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap();

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
        let (_, _) = archive(&input_file, &mut buf, ArchiveLimits::default()).unwrap();

        unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap();

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
        let (_, _) = archive(&input_dir, &mut buf, ArchiveLimits::default()).unwrap();

        unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap();

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
        let (_, _) = archive(&input_dir, &mut buf, ArchiveLimits::default()).unwrap();

        // Must not fail with "Permission denied" when extracting inner.txt
        unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap();

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
    fn archive_strips_special_bits_on_archive_side() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("script.sh");
        fs::write(&input_file, "#!/bin/sh").unwrap();
        fs::set_permissions(&input_file, fs::Permissions::from_mode(0o4755)).unwrap();

        let mut buf = Vec::new();
        let (_, _) = archive(&input_file, &mut buf, ArchiveLimits::default()).unwrap();

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

    /// `FORMAT.md` §9 requires every emitted header to use the POSIX
    /// ustar magic (`"ustar\0" + "00"` at offsets 257..265) and forbids
    /// GNU magic. Pin the writer's per-entry magic + version bytes so a
    /// future regression that switches back to `new_gnu()` (or to a
    /// helper that auto-promotes overlong paths to a long-name
    /// extension) fails this test loudly.
    #[test]
    fn archive_emits_posix_ustar_headers() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input = tmp.path().join("hello.txt");
        fs::write(&input, "hello").unwrap();

        let mut buf = Vec::new();
        let (_, _) = archive(&input, &mut buf, ArchiveLimits::default()).unwrap();

        let mut ar = tar::Archive::new(Cursor::new(buf));
        let mut entries = ar.entries().unwrap();
        let entry = entries.next().expect("one entry").unwrap();
        let raw = entry.header().as_bytes();

        assert_eq!(&raw[257..263], b"ustar\0", "expected POSIX ustar magic");
        assert_eq!(&raw[263..265], b"00", "expected ustar version 00");
        assert_eq!(raw[156], b'0', "expected typeflag '0' for regular file");
    }

    /// `FORMAT.md` §9 forbids GNU long-name records and the writer
    /// must reject overlong paths up-front rather than silently
    /// promoting them to an extension. The exact ustar limit is
    /// `name(100) + '/' + prefix(155)`; any path over that surfaces
    /// as a typed `InvalidInput` rejection.
    ///
    /// We drive the writer-side ustar path normalizer directly rather
    /// than going through `archive()` because some host filesystems
    /// (notably macOS APFS) reject single components ≥255 chars
    /// before our code sees them; the helper is the canonical
    /// rejection point used by both `append_file` and
    /// `append_dir_entry`.
    #[test]
    fn archive_rejects_path_that_cannot_fit_ustar() {
        let too_long: String = "a".repeat(ustar::PATH_REPRESENTABLE_MAX + 4);
        let path = PathBuf::from(too_long);
        let err = ustar_archive_path_string(&path, UstarEntryKind::File).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("POSIX ustar"),
            "expected POSIX ustar rejection, got: {msg}"
        );
    }

    /// Writer-side symmetry with the reader's `\` / NUL rejection
    /// (`FORMAT.md` §9). Unix kernels permit `\` in filenames, so a
    /// naive walker could emit an archive whose paths the reader
    /// would refuse to decrypt. Gated to `#[cfg(unix)]` because on
    /// Windows the `Path` API treats `\` as a separator, so a single
    /// `Normal` component can never contain a literal `\` byte and
    /// the bug doesn't apply.
    #[cfg(unix)]
    #[test]
    fn archive_rejects_backslash_in_path_component() {
        let weird = PathBuf::from("weird\\file.txt");
        let err = ustar_archive_path_string(&weird, UstarEntryKind::File).unwrap_err();
        assert!(
            err.to_string().contains("forbidden byte"),
            "expected backslash rejection, got: {err}"
        );
    }

    /// Encrypt-side preflight: a directory whose entry count would
    /// exceed `ArchiveLimits::max_entry_count` must be rejected by
    /// `archive` BEFORE TAR bytes are emitted, so the writer never
    /// produces an archive that the default-config decrypt would
    /// refuse. Mirrors the decrypt-side `entry-count cap` test.
    #[test]
    fn archive_rejects_input_above_entry_count_cap() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_dir = tmp.path().join("myroot");
        fs::create_dir_all(&input_dir).unwrap();
        // 1 directory entry (the root) + 5 files = 6 entries.
        for i in 0..5 {
            fs::write(input_dir.join(format!("file_{i}")), b"x").unwrap();
        }

        let limits = ArchiveLimits {
            max_entry_count: 3,
            ..ArchiveLimits::default()
        };
        let mut buf = Vec::new();
        let err = archive(&input_dir, &mut buf, limits).unwrap_err();
        assert!(
            err.to_string().contains("entry-count cap"),
            "expected entry-count cap rejection, got: {err}"
        );
    }

    /// Encrypt-side preflight: an input file whose size exceeds
    /// `ArchiveLimits::max_total_plaintext_bytes` must be rejected by
    /// `archive` BEFORE the TAR header for the entry is emitted.
    #[test]
    fn archive_rejects_input_above_total_bytes_cap() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("big.bin");
        fs::write(&input_file, vec![0u8; 1000]).unwrap();

        let limits = ArchiveLimits {
            max_total_plaintext_bytes: 100,
            ..ArchiveLimits::default()
        };
        let mut buf = Vec::new();
        let err = archive(&input_file, &mut buf, limits).unwrap_err();
        assert!(
            err.to_string().contains("total-bytes cap"),
            "expected total-bytes cap rejection, got: {err}"
        );
    }

    /// Encrypt-side preflight: a directory whose entry path depth
    /// exceeds `ArchiveLimits::max_path_depth` must be rejected by
    /// `archive` before the deep entry's TAR header is emitted.
    #[test]
    fn archive_rejects_input_above_path_depth_cap() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Root-relative depth 7: myroot/a/b/c/d/e/file.txt.
        let input_dir = tmp.path().join("myroot");
        let deep_parent = input_dir.join("a/b/c/d/e");
        fs::create_dir_all(&deep_parent).unwrap();
        fs::write(deep_parent.join("file.txt"), b"x").unwrap();

        let limits = ArchiveLimits {
            max_path_depth: 4,
            ..ArchiveLimits::default()
        };
        let mut buf = Vec::new();
        let err = archive(&input_dir, &mut buf, limits).unwrap_err();
        assert!(
            err.to_string().contains("path depth cap"),
            "expected path depth cap rejection, got: {err}"
        );
    }
}
