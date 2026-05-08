//! FCA archive writer: source-tree traversal (metadata pass) and
//! content-streaming pass.
//!
//! See `notes/archive_format/ARCHIVE_FORMAT.md` §10 (entry ordering),
//! §11 (limits), §12 (internal API), §13 (module layout),
//! §14.13 (writer entry-point skeleton), §15 (writer requirements),
//! §17 (platform requirements), §19.6 (writer-side rejection list).
//!
//! The writer is two-pass:
//!
//! 1. **Metadata pass** — recursively walks the source tree via
//!    `std::fs::read_dir`, building a [`Manifest`] of [`ArchiveEntry`]s
//!    with FCA-canonical paths, modes, sizes, and source paths.
//!    Symlinks, FIFOs, sockets, devices, and Windows reparse points are
//!    rejected inline. Entry-count, total-bytes, depth, path-byte, and
//!    manifest-size caps are applied progressively, and every path is
//!    routed through [`validate_fca_path`] so the writer never emits
//!    a path its own reader would refuse.
//!
//! 2. **Content pass** — for each file entry in canonical manifest
//!    order, reopens the source file with `O_NOFOLLOW` (Unix) or
//!    `symlink_metadata` + `File::open` (non-Unix), refreshes metadata
//!    from the open handle, requires the source is still a regular
//!    file with `len() == manifest size`, and streams exactly the
//!    declared size via [`copy_exact_n`].
//!
//! Between the two passes the source tree may change. Spec §15.5
//! defines the response: shrink / type change / inaccessible →
//! encryption MUST fail; growth before the fresh metadata check →
//! reject; growth during the copy after the fresh metadata check →
//! the writer copies exactly the declared size, keeping the archive
//! self-consistent.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::CryptoError;
use crate::fs::paths::file_stem;

#[cfg(unix)]
use super::format::PERMISSION_BITS_MASK;
use super::format::{copy_exact_n, serialize_manifest, write_fca_header};
use super::limits::{
    ArchiveLimits, enforce_per_entry_caps, enforce_total_bytes_cap, entry_count_cap_error,
    manifest_len_cap_error,
};
use super::model::{ArchiveEntry, ArchiveEntryKind, Manifest};
use super::path::{canonical_path_order, validate_fca_path};
use super::tree::validate_manifest_tree;

/// Default file mode for non-Unix platforms (rw-r--r--). FCA stores a
/// Unix-style permission word; on Windows there is no rwx semantic to
/// read so a fixed default is used and round-trip extraction applies
/// it as a no-op (Windows chmod is a no-op in the platform backend).
#[cfg(not(unix))]
const DEFAULT_FILE_MODE: u32 = 0o644;

/// Default directory mode for non-Unix platforms (rwxr-xr-x).
#[cfg(not(unix))]
const DEFAULT_DIR_MODE: u32 = 0o755;

/// Reads the rwx-only Unix permission word from `metadata`, stripping
/// setuid/setgid/sticky. Folds the `cfg(unix)`-gated `PermissionsExt`
/// import into one place.
#[cfg(unix)]
fn metadata_perm_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & PERMISSION_BITS_MASK
}

/// Mode to store for a regular file: Unix returns the rwx bits of
/// the source file (special bits stripped via `metadata_perm_mode`);
/// non-Unix targets have no rwx semantic and return the fixed default.
#[cfg(unix)]
fn archive_file_mode(metadata: &fs::Metadata) -> u32 {
    metadata_perm_mode(metadata)
}
#[cfg(not(unix))]
fn archive_file_mode(_metadata: &fs::Metadata) -> u32 {
    DEFAULT_FILE_MODE
}

/// Mode to store for a directory. Unix reads `src_path` metadata
/// fresh; non-Unix returns the fixed default without touching the
/// filesystem (no rwx semantic to read, and skipping the syscall
/// avoids a stray failure mode where a concurrent removal between
/// `read_dir` and `archive_dir_mode` would otherwise abort the
/// archive).
#[cfg(unix)]
fn archive_dir_mode(src_path: &Path) -> Result<u32, CryptoError> {
    Ok(metadata_perm_mode(&fs::metadata(src_path)?))
}
#[cfg(not(unix))]
fn archive_dir_mode(_src_path: &Path) -> Result<u32, CryptoError> {
    Ok(DEFAULT_DIR_MODE)
}

/// Windows-only rejection for any NTFS reparse point in the archive
/// source tree. `file_type().is_symlink()` is not enough on Windows:
/// junctions and mount points are reparse points but may not classify
/// as symlinks. FCA v1 stores no reparse-point semantics, so writer
/// input rejects them before they can redirect traversal or content
/// reads.
#[cfg(windows)]
fn reject_windows_reparse_point(
    metadata: &fs::Metadata,
    label: &str,
    path: &Path,
) -> Result<(), CryptoError> {
    use std::os::windows::fs::MetadataExt;

    // From WinNT.h. Stable Win32 ABI bit for all reparse-point tags
    // including symlinks, junctions, mount points, and future tags.
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(CryptoError::InvalidInput(format!(
            "{label} is a Windows reparse point: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_windows_reparse_point(
    _metadata: &fs::Metadata,
    _label: &str,
    _path: &Path,
) -> Result<(), CryptoError> {
    Ok(())
}

/// Opens a regular file for reading without following symlinks. On
/// Unix uses `O_NOFOLLOW` so the open itself is atomic; on Windows uses
/// `FILE_FLAG_OPEN_REPARSE_POINT` plus a metadata post-check so a racing
/// symlink/junction replacement is rejected instead of followed. Other
/// non-Unix targets fall back to a `symlink_metadata` pre-check followed
/// by `File::open`.
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
                input_is_symlink_error(path)
            } else {
                CryptoError::Io(e)
            }
        })
}

#[cfg(windows)]
fn open_no_follow(path: &Path) -> Result<File, CryptoError> {
    use std::os::windows::fs::OpenOptionsExt;

    // From WinBase.h. Opening with this flag prevents Windows from
    // transparently following a reparse point if one is substituted
    // between the pre-check and the open.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let metadata = fs::symlink_metadata(path)?;
    reject_windows_reparse_point(&metadata, "Input", path)?;
    require_regular_file(&metadata, "Input", path)?;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let opened_metadata = file.metadata().map_err(CryptoError::Io)?;
    reject_windows_reparse_point(&opened_metadata, "Input", path)?;
    require_regular_file(&opened_metadata, "Input", path)?;
    Ok(file)
}

#[cfg(all(not(unix), not(windows)))]
fn open_no_follow(path: &Path) -> Result<File, CryptoError> {
    let metadata = fs::symlink_metadata(path)?;
    require_regular_file(&metadata, "Input", path)?;
    Ok(File::open(path)?)
}

/// Defense-in-depth at every open / re-open boundary: rejects a
/// non-regular file (symlink, FIFO, device) with a labelled
/// `CryptoError::InvalidInput`. The `label` is the role of `path`
/// in the failing context — `"Input"` at the outermost open,
/// `"Source"` at the per-entry content-stream re-open.
fn require_regular_file(
    metadata: &fs::Metadata,
    label: &str,
    path: &Path,
) -> Result<(), CryptoError> {
    if !metadata.file_type().is_file() {
        return Err(CryptoError::InvalidInput(format!(
            "{label} is no longer a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

/// Rejects inputs the archiver will not accept: symlinks (live or
/// dangling) and anything that isn't a regular file or directory.
/// Called at the top of every encrypt entry point in `api.rs` so the
/// rejection fires before any KDF / cipher work runs (up to a gigabyte
/// of RAM and several seconds of CPU on default Argon2id), not only at
/// archive time. The archive-time call below remains as defense-in-
/// depth against TOCTOU and direct callers.
///
/// The `symlink_metadata` call runs before classification so dangling symlinks
/// can still be identified from the link itself. Windows reparse points are
/// rejected before the generic symlink branch so junctions, mount points, and
/// Windows symlinks report the explicit reparse-point diagnostic.
pub(crate) fn validate_encrypt_input(input_path: &Path) -> Result<(), CryptoError> {
    let metadata = match fs::symlink_metadata(input_path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(CryptoError::InputPath),
        Err(e) => return Err(CryptoError::Io(e)),
    };
    reject_windows_reparse_point(&metadata, "Input", input_path)?;

    if metadata.file_type().is_symlink() {
        return Err(input_is_symlink_error(input_path));
    }

    let file_type = metadata.file_type();
    if !file_type.is_file() && !file_type.is_dir() {
        return Err(CryptoError::InvalidInput(format!(
            "Unsupported file type: {}",
            input_path.display()
        )));
    }
    Ok(())
}

/// Running totals threaded through the recursive metadata-pass walk
/// so caps can fire across the entire tree, not just per-call.
#[derive(Debug, Default)]
struct ArchiveCounters {
    entry_count: u32,
    total_bytes: u64,
}

/// Single source of truth for the writer's [`ArchiveEntry`]
/// construction during the metadata pass. Every `entry_ext` is empty
/// because v1 native writers emit no per-entry TLV bytes (FORMAT.md
/// §9.13). Used by both branches of [`build_manifest`] and both
/// branches of [`walk_directory`] so the field set stays consistent
/// across all four call sites.
fn writer_entry(
    kind: ArchiveEntryKind,
    path_utf8: String,
    mode: u32,
    size: u64,
    source_path: PathBuf,
) -> ArchiveEntry {
    ArchiveEntry {
        kind,
        path_utf8,
        mode,
        size,
        source_path: Some(source_path),
        entry_ext: Vec::new(),
    }
}

/// Shared per-entry recording: increments the entry count, applies
/// every cap [`enforce_per_entry_caps`] covers, optionally sums into
/// the total-bytes cap (for file entries), and runs
/// [`validate_fca_path`]. Used by both branches of the metadata-pass
/// walk so the file-entry and directory-entry call sites have one
/// canonical sequence of checks.
fn record_entry(
    counters: &mut ArchiveCounters,
    fca_path_utf8: &str,
    file_size: Option<u64>,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    counters.entry_count = counters
        .entry_count
        .checked_add(1)
        .ok_or_else(|| CryptoError::InvalidInput("Archive entry-count overflow".to_string()))?;
    enforce_per_entry_caps(counters.entry_count, fca_path_utf8, limits)?;
    if let Some(size) = file_size {
        enforce_total_bytes_cap(size, &mut counters.total_bytes, limits)?;
    }
    validate_fca_path(fca_path_utf8, *limits)?;
    Ok(())
}

/// Single source of truth for the "Input is a symlink: <path>"
/// rejection. Used by `validate_encrypt_input`, `build_manifest`'s
/// input-root symlink check, and the Unix `open_no_follow`
/// `ELOOP` arm.
fn input_is_symlink_error(path: &Path) -> CryptoError {
    CryptoError::InvalidInput(format!("Input is a symlink: {}", path.display()))
}

/// Builds a fully validated [`Manifest`] from the source tree under
/// `input_path`. Single-file inputs produce a one-entry manifest with
/// `root_is_file = true`; directory inputs produce a multi-entry
/// manifest with `root_is_file = false`.
fn build_manifest(input_path: &Path, limits: &ArchiveLimits) -> Result<Manifest, CryptoError> {
    let metadata = fs::symlink_metadata(input_path)?;
    reject_windows_reparse_point(&metadata, "Input", input_path)?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(input_is_symlink_error(input_path));
    }

    let name = input_path
        .file_name()
        .ok_or_else(|| CryptoError::InvalidInput("Cannot get input file name".to_string()))?;
    let name_str = name
        .to_str()
        .ok_or_else(|| {
            CryptoError::InvalidInput(format!(
                "Input name is not valid UTF-8: {}",
                input_path.display()
            ))
        })?
        .to_string();

    // Path grammar applies to the root regardless of kind; validate
    // once before the file/dir dispatch.
    validate_fca_path(&name_str, *limits)?;

    if file_type.is_file() {
        let mode = archive_file_mode(&metadata);
        let size = metadata.len();

        let mut total_bytes = 0u64;
        enforce_total_bytes_cap(size, &mut total_bytes, limits)?;

        let entry = writer_entry(
            ArchiveEntryKind::File,
            name_str.clone(),
            mode,
            size,
            input_path.to_path_buf(),
        );

        Ok(Manifest {
            entries: vec![entry],
            total_file_bytes: size,
            root_name: OsString::from(&name_str),
            root_is_file: true,
        })
    } else if file_type.is_dir() {
        let root_mode = archive_dir_mode(input_path)?;

        let mut entries = vec![writer_entry(
            ArchiveEntryKind::Directory,
            name_str.clone(),
            root_mode,
            0,
            input_path.to_path_buf(),
        )];
        let mut counters = ArchiveCounters {
            entry_count: 1,
            total_bytes: 0,
        };

        walk_directory(input_path, &name_str, &mut entries, &mut counters, limits)?;

        sort_entries_canonically(&mut entries);

        Ok(Manifest {
            entries,
            total_file_bytes: counters.total_bytes,
            root_name: OsString::from(&name_str),
            root_is_file: false,
        })
    } else {
        Err(CryptoError::InvalidInput(format!(
            "Unsupported file type: {}",
            input_path.display()
        )))
    }
}

/// Recursively walks `src_dir`, appending entries to `entries` with
/// FCA paths rooted at `fca_prefix`. Symlinks, devices, FIFOs, sockets,
/// reparse points (via the file-type classification) are rejected.
fn walk_directory(
    src_dir: &Path,
    fca_prefix: &str,
    entries: &mut Vec<ArchiveEntry>,
    counters: &mut ArchiveCounters,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    let src_dir_metadata = fs::symlink_metadata(src_dir)?;
    reject_windows_reparse_point(&src_dir_metadata, "Source directory", src_dir)?;
    if src_dir_metadata.file_type().is_symlink() {
        return Err(CryptoError::InvalidInput(format!(
            "Symlink in archive source: {}",
            src_dir.display()
        )));
    }

    for read_dir_entry in fs::read_dir(src_dir)? {
        let dir_entry = read_dir_entry?;
        let full_path = dir_entry.path();
        let metadata = fs::symlink_metadata(&full_path)?;
        reject_windows_reparse_point(&metadata, "Source entry", &full_path)?;
        let file_type = metadata.file_type();

        if file_type.is_symlink() {
            return Err(CryptoError::InvalidInput(format!(
                "Symlink in archive source: {}",
                full_path.display()
            )));
        }

        let name = dir_entry.file_name();
        let name_str = name.to_str().ok_or_else(|| {
            CryptoError::InvalidInput(format!(
                "Source filename is not valid UTF-8: {}",
                dir_entry.path().display()
            ))
        })?;

        let fca_path_utf8 = format!("{fca_prefix}/{name_str}");

        if file_type.is_file() {
            let mode = archive_file_mode(&metadata);
            let size = metadata.len();

            record_entry(counters, &fca_path_utf8, Some(size), limits)?;

            entries.push(writer_entry(
                ArchiveEntryKind::File,
                fca_path_utf8.clone(),
                mode,
                size,
                full_path,
            ));
        } else if file_type.is_dir() {
            let mode = archive_dir_mode(&full_path)?;

            record_entry(counters, &fca_path_utf8, None, limits)?;

            entries.push(writer_entry(
                ArchiveEntryKind::Directory,
                fca_path_utf8.clone(),
                mode,
                0,
                full_path.clone(),
            ));

            walk_directory(&full_path, &fca_path_utf8, entries, counters, limits)?;
        } else {
            return Err(CryptoError::InvalidInput(format!(
                "Unsupported file type in archive: {}",
                full_path.display()
            )));
        }
    }
    Ok(())
}

/// Sorts entries by `(component_count, path_utf8_bytes)` per spec §10.
/// The root directory sorts first by construction (smallest component
/// count plus shortest path among any entry sharing the root).
fn sort_entries_canonically(entries: &mut [ArchiveEntry]) {
    entries.sort_by(|a, b| canonical_path_order(&a.path_utf8, &b.path_utf8));
}

/// Streams one file entry's contents into `writer`. Reopens the source
/// no-follow, refreshes metadata from the open handle, requires the
/// source is still a regular file with `len() == entry.size`, then
/// copies exactly `entry.size` bytes.
///
/// Spec §15.5: on shrink, type change, or pre-copy growth — fail. On
/// growth during the copy after the fresh metadata check — copy
/// exactly the declared size, keeping the archive self-consistent.
fn stream_source_file<W: Write>(entry: &ArchiveEntry, writer: &mut W) -> Result<(), CryptoError> {
    let source = entry
        .source_path
        .as_ref()
        .ok_or(CryptoError::InternalInvariant(
            "Manifest entry missing source_path during content streaming",
        ))?;

    let mut file = open_no_follow(source)?;
    let metadata = file.metadata().map_err(CryptoError::Io)?;
    reject_windows_reparse_point(&metadata, "Source", source)?;
    require_regular_file(&metadata, "Source", source)?;
    if metadata.len() != entry.size {
        return Err(CryptoError::InvalidInput(format!(
            "Source file size changed during archive ({} → {}): {}",
            entry.size,
            metadata.len(),
            source.display(),
        )));
    }

    copy_exact_n(&mut file, writer, entry.size)
}

/// Archives a file or directory into the FCA wire format. Returns the
/// output stem (file stem for file inputs, directory name for
/// directory inputs) plus the writer for the caller to finalize.
///
/// Matches the existing internal API per spec §12.
pub(crate) fn archive<W: Write>(
    input_path: impl AsRef<Path>,
    mut writer: W,
    limits: ArchiveLimits,
) -> Result<(String, W), CryptoError> {
    let input_path = input_path.as_ref();
    let limits = limits.validate()?;

    // Defense-in-depth: api.rs runs validate_encrypt_input up-front, but
    // direct callers and any TOCTOU shift between that check and now
    // get re-validated here.
    validate_encrypt_input(input_path)?;

    // Pass 1: metadata-only manifest.
    let manifest = build_manifest(input_path, &limits)?;

    // Defense-in-depth: a bug in walk_directory would surface here
    // rather than producing a malformed archive.
    let _ = validate_manifest_tree(&manifest.entries, manifest.total_file_bytes, limits)?;

    let manifest_bytes = serialize_manifest(&manifest, limits)?;
    let entry_count = u32::try_from(manifest.entries.len())
        .map_err(|_| entry_count_cap_error(u32::MAX, limits.max_entry_count))?;
    let manifest_len = u32::try_from(manifest_bytes.len()).map_err(|_| {
        manifest_len_cap_error(manifest_bytes.len() as u64, limits.max_manifest_bytes)
    })?;

    // FCA v1 writers always emit `archive_ext_len = 0`; the archive-
    // level TLV region exists in the wire layout but defines no v1
    // tags, so writers MUST NOT emit any bytes there.
    writer = write_fca_header(
        writer,
        entry_count,
        0,
        manifest_len,
        manifest.total_file_bytes,
    )?;
    writer.write_all(&manifest_bytes).map_err(CryptoError::Io)?;

    // Pass 2: stream file contents in canonical manifest order.
    for entry in &manifest.entries {
        if entry.kind == ArchiveEntryKind::File {
            stream_source_file(entry, &mut writer)?;
        }
    }

    let stem = output_stem(input_path)?;
    Ok((stem, writer))
}

/// Returns the output stem used to name the encrypted output file.
/// For file inputs, the file stem (no extension); for directory
/// inputs, the full directory name (preserving any dots).
fn output_stem(input_path: &Path) -> Result<String, CryptoError> {
    if input_path.is_dir() {
        let name = input_path
            .file_name()
            .ok_or_else(|| CryptoError::InvalidInput("Cannot get directory name".to_string()))?;
        Ok(name.to_string_lossy().into_owned())
    } else {
        Ok(file_stem(input_path)?.to_string_lossy().into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::super::IncompleteOutputPolicy;
    use super::super::decode::unarchive;
    use super::super::model::make_entry;
    use super::*;
    use std::io::Cursor;
    #[cfg(windows)]
    use std::path::Path;
    use std::path::PathBuf;

    /// End-to-end round-trip: archive → unarchive on the same tempdir
    /// (different output dir so the source isn't overwritten).
    fn round_trip(src_root: &Path, out_root: &Path) -> PathBuf {
        let mut buf = Vec::new();
        let _ = archive(src_root, &mut buf, ArchiveLimits::default()).unwrap();
        unarchive(
            Cursor::new(buf),
            out_root,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
        )
        .unwrap()
    }

    // -- Positive round-trip tests -----------------------------------------

    #[test]
    fn round_trip_single_file() {
        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let src_file = src.path().join("hello.txt");
        fs::write(&src_file, b"Hello, world!").unwrap();

        let final_path = round_trip(&src_file, out.path());
        assert_eq!(final_path, out.path().join("hello.txt"));
        assert_eq!(fs::read(&final_path).unwrap(), b"Hello, world!");
    }

    #[test]
    fn round_trip_empty_file() {
        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let src_file = src.path().join("empty.bin");
        fs::write(&src_file, b"").unwrap();

        let final_path = round_trip(&src_file, out.path());
        assert_eq!(fs::read(&final_path).unwrap(), b"");
    }

    #[test]
    fn round_trip_directory_tree() {
        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("photos");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("index.txt"), b"hello").unwrap();
        fs::write(dir.join("cover.jpg"), b"jpegjpe").unwrap();
        fs::create_dir(dir.join("raw")).unwrap();
        fs::write(dir.join("raw").join("a.dng"), b"raw_data").unwrap();

        let final_path = round_trip(&dir, out.path());
        assert!(final_path.is_dir());
        assert_eq!(fs::read(final_path.join("index.txt")).unwrap(), b"hello");
        assert_eq!(fs::read(final_path.join("cover.jpg")).unwrap(), b"jpegjpe");
        assert_eq!(
            fs::read(final_path.join("raw").join("a.dng")).unwrap(),
            b"raw_data",
        );
    }

    #[test]
    fn round_trip_empty_directory() {
        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("emptydir");
        fs::create_dir(&dir).unwrap();

        let final_path = round_trip(&dir, out.path());
        assert!(final_path.is_dir());
        assert_eq!(fs::read_dir(&final_path).unwrap().count(), 0);
    }

    /// Manifest determinism end-to-end: two encrypts of the same tree
    /// produce byte-identical archive bytes. Pinned because the
    /// metadata-pass walk uses `fs::read_dir` which has filesystem-
    /// dependent order — without `sort_entries_canonically` this would
    /// fail.
    #[test]
    fn archive_output_is_deterministic() {
        let src = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("d");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("z.txt"), b"zzz").unwrap();
        fs::write(dir.join("a.txt"), b"aaa").unwrap();
        fs::write(dir.join("m.txt"), b"mmm").unwrap();

        let mut buf1 = Vec::new();
        let _ = archive(&dir, &mut buf1, ArchiveLimits::default()).unwrap();
        let mut buf2 = Vec::new();
        let _ = archive(&dir, &mut buf2, ArchiveLimits::default()).unwrap();

        assert_eq!(buf1, buf2);
    }

    /// The output stem returned by `archive` follows the existing
    /// internal API per spec §12: file stem for files, dir name for
    /// directories.
    #[test]
    fn returns_correct_output_stem() {
        let src = tempfile::TempDir::new().unwrap();
        let mut buf = Vec::new();

        let file = src.path().join("hello.txt");
        fs::write(&file, b"x").unwrap();
        let (stem, _) = archive(&file, &mut buf, ArchiveLimits::default()).unwrap();
        assert_eq!(stem, "hello");

        buf.clear();
        let dotfile = src.path().join("photos.v1");
        fs::create_dir(&dotfile).unwrap();
        let (stem, _) = archive(&dotfile, &mut buf, ArchiveLimits::default()).unwrap();
        assert_eq!(stem, "photos.v1");
    }

    // -- Writer-side rejections (§19.6) ------------------------------------

    #[cfg(unix)]
    #[test]
    fn rejects_root_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("real.txt");
        fs::write(&target, b"data").unwrap();
        let link = tmp.path().join("link.txt");
        symlink(&target, &link).unwrap();

        let mut buf = Vec::new();
        let err = archive(&link, &mut buf, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("Input is a symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_dangling_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::TempDir::new().unwrap();
        let link = tmp.path().join("dangling");
        symlink(tmp.path().join("absent-target"), &link).unwrap();

        let mut buf = Vec::new();
        let err = archive(&link, &mut buf, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_inside_directory_tree() {
        use std::os::unix::fs::symlink;

        let src = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("d");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("real.txt"), b"data").unwrap();
        symlink("real.txt", dir.join("link.txt")).unwrap();

        let mut buf = Vec::new();
        let err = archive(&dir, &mut buf, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("Symlink in archive source"));
    }

    #[cfg(windows)]
    fn try_make_junction(target: &Path, junction: &Path) -> std::io::Result<()> {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(junction)
            .arg(target)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "mklink /J failed with exit code {status}"
            )))
        }
    }

    #[cfg(windows)]
    #[test]
    fn rejects_root_windows_junction() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("target");
        fs::create_dir_all(&target).unwrap();
        let junction = tmp.path().join("junction");
        try_make_junction(&target, &junction).unwrap();

        let mut buf = Vec::new();
        let err = archive(&junction, &mut buf, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("Windows reparse point"));
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_junction_inside_directory_tree() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("d");
        fs::create_dir(&dir).unwrap();
        let target = tmp.path().join("target");
        fs::create_dir_all(&target).unwrap();
        let junction = dir.join("junction");
        try_make_junction(&target, &junction).unwrap();

        let mut buf = Vec::new();
        let err = archive(&dir, &mut buf, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("Windows reparse point"));
    }

    #[test]
    fn rejects_missing_input() {
        let tmp = tempfile::TempDir::new().unwrap();
        let absent = tmp.path().join("does-not-exist");
        let mut buf = Vec::new();
        let err = archive(&absent, &mut buf, ArchiveLimits::default()).unwrap_err();
        assert!(matches!(err, CryptoError::InputPath));
    }

    /// Per-entry caps fire during the metadata pass — catch-cap before
    /// any header bytes are emitted.
    #[test]
    fn rejects_tree_above_entry_count_cap() {
        let src = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("d");
        fs::create_dir(&dir).unwrap();
        for i in 0..5 {
            fs::write(dir.join(format!("f{i}.txt")), b"x").unwrap();
        }

        let limits = ArchiveLimits::default().with_max_entry_count(3);
        let mut buf = Vec::new();
        let err = archive(&dir, &mut buf, limits).unwrap_err();
        assert!(format!("{err}").contains("entry-count cap exceeded"));
        // No header bytes should have been emitted.
        assert!(buf.is_empty(), "writer must not emit bytes when caps fail");
    }

    #[test]
    fn rejects_tree_above_total_bytes_cap() {
        let src = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("d");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("big.bin"), vec![0u8; 1000]).unwrap();

        let limits = ArchiveLimits::default().with_max_total_plaintext_bytes(100);
        let mut buf = Vec::new();
        let err = archive(&dir, &mut buf, limits).unwrap_err();
        assert!(format!("{err}").contains("total-bytes cap exceeded"));
    }

    /// Spec §8.2: a Windows-reserved device name in the source tree
    /// MUST reject during the metadata pass — otherwise the writer
    /// would emit a path its own reader rejects.
    #[cfg(unix)]
    #[test]
    fn rejects_windows_reserved_device_name_in_source() {
        let src = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("d");
        fs::create_dir(&dir).unwrap();
        // "CON" is fine on Unix as a filename, but FCA rejects it.
        fs::write(dir.join("CON"), b"x").unwrap();

        let mut buf = Vec::new();
        let err = archive(&dir, &mut buf, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("Windows-reserved device"));
    }

    // -- §19.1 positive round-trips (extra coverage) -----------------------

    /// Bytes 0x00..=0xFF cycled to 1 KiB. Pins that the writer does
    /// not assume printable / text content and the reader does not
    /// silently transform any byte.
    #[test]
    fn round_trip_binary_file() {
        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let content: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        let src_file = src.path().join("binary.bin");
        fs::write(&src_file, &content).unwrap();

        let final_path = round_trip(&src_file, out.path());
        assert_eq!(fs::read(&final_path).unwrap(), content);
    }

    /// Empty subdirectories nested 3 levels deep round-trip to disk
    /// with the same shape. Pins that directory pre-creation in the
    /// reader's Pass 1 walks all the way down even when no file
    /// content is emitted.
    #[test]
    fn round_trip_nested_empty_directories() {
        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("root");
        fs::create_dir(&dir).unwrap();
        fs::create_dir(dir.join("a")).unwrap();
        fs::create_dir(dir.join("a").join("b")).unwrap();
        fs::create_dir(dir.join("a").join("b").join("c")).unwrap();

        let final_path = round_trip(&dir, out.path());
        assert!(final_path.is_dir());
        assert!(final_path.join("a").is_dir());
        assert!(final_path.join("a").join("b").is_dir());
        assert!(final_path.join("a").join("b").join("c").is_dir());
    }

    // -- §19.1 / §19.7 Unix mode preservation ------------------------------

    /// Source file mode round-trips through the archive intact (rwx
    /// bits only — special bits stripped per §15.4). Pins
    /// `archive_file_mode` on the writer side and
    /// `chmod_file_handle` post-copy on the reader side.
    #[cfg(unix)]
    #[test]
    fn round_trip_preserves_file_mode() {
        use std::os::unix::fs::PermissionsExt;

        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let src_file = src.path().join("hello.txt");
        fs::write(&src_file, b"x").unwrap();
        fs::set_permissions(&src_file, fs::Permissions::from_mode(0o600)).unwrap();

        let final_path = round_trip(&src_file, out.path());
        let mode = fs::metadata(&final_path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600, "file mode lost in round trip");
    }

    /// Source directory mode round-trips intact via the writer's
    /// `archive_dir_mode` and the reader's post-rename root-chmod
    /// (spec §16.3). Validates "root chmod after rename" indirectly:
    /// if the reader applied root mode pre-rename and the mode lacked
    /// search permission, the rename itself would fail on macOS.
    #[cfg(unix)]
    #[test]
    fn round_trip_preserves_directory_mode() {
        use std::os::unix::fs::PermissionsExt;

        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("root");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

        let final_path = round_trip(&dir, out.path());
        let mode = fs::metadata(&final_path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o700, "directory mode lost in round trip");
    }

    /// Spec §15.4: writers MUST NOT store setuid, setgid, or sticky
    /// bits. Pin the strip on the WRITER side: a source file with
    /// 0o4644 (setuid + rw-r--r--) extracts as 0o644.
    #[cfg(unix)]
    #[test]
    fn round_trip_strips_setuid_bit_from_source() {
        use std::os::unix::fs::PermissionsExt;

        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let src_file = src.path().join("hello.txt");
        fs::write(&src_file, b"x").unwrap();
        fs::set_permissions(&src_file, fs::Permissions::from_mode(0o4644)).unwrap();

        let final_path = round_trip(&src_file, out.path());
        let mode = fs::metadata(&final_path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o644, "setuid bit must be stripped, got 0o{mode:o}",);
    }

    // -- Source mutation between passes (§15.5) ----------------------------

    /// Spec §15.5: a source file shrinking between metadata pass and
    /// content pass MUST fail. We can't shrink a real file mid-archive
    /// race-free, so this test exercises the size-check directly via
    /// `stream_source_file` with a pre-built `ArchiveEntry` whose
    /// recorded size doesn't match the file on disk.
    #[test]
    fn stream_source_file_rejects_size_mismatch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("real.txt");
        fs::write(&path, b"actual content").unwrap();

        // 9999 ≠ actual file size → exercises the size-mismatch arm.
        let mut entry = make_entry("real.txt", ArchiveEntryKind::File, 9999, 0o644);
        entry.source_path = Some(path);

        let mut buf = Vec::new();
        let err = stream_source_file(&entry, &mut buf).unwrap_err();
        assert!(format!("{err}").contains("size changed"));
    }
}
