//! FCA archive writer: source-tree traversal (metadata pass) and
//! content-streaming pass.
//!
//! See `ferrocrypt-lib/FORMAT.md` §9.8 (canonical entry ordering),
//! §9.10 (writer obligations), §9.12 (resource caps), §9.13 (platform
//! metadata and preservation).
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
//! Between the two passes the source tree may change. FORMAT.md §9.10
//! defines the response: shrink / type change / inaccessible →
//! encryption MUST fail; growth before the fresh metadata check →
//! reject; growth during the copy after the fresh metadata check →
//! the writer copies exactly the declared size, keeping the archive
//! self-consistent.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};

use crate::CryptoError;
use crate::fs::paths::file_stem;

use super::format::PERMISSION_BITS_MASK;
use super::format::{copy_exact_n, serialize_manifest, write_fca_header};
use super::limits::{
    ArchiveLimits, enforce_entry_count_cap, enforce_manifest_len_cap, enforce_per_entry_caps,
    enforce_total_bytes_cap, entry_count_cap_error, manifest_len_cap_error,
};
use super::model::{ArchiveEntry, ArchiveEntryKind, Manifest};
use super::path::{canonical_path_order, validate_fca_path};
use super::platform;
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
/// import into one place. Used by the single-file root path which
/// retains its `std::fs`-based open via `O_NOFOLLOW` on the leaf.
#[cfg(unix)]
fn metadata_perm_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & PERMISSION_BITS_MASK
}

/// Cap-std parallel of [`metadata_perm_mode`]. Used by the directory
/// metadata-pass walker which threads `cap_std::Dir` handles instead
/// of absolute paths (FORMAT.md §9.10 writer obligation, parity with
/// the reader's hardened extraction backend).
#[cfg(unix)]
fn cap_metadata_perm_mode(metadata: &cap_std::fs::Metadata) -> u32 {
    use cap_std::fs::PermissionsExt;
    metadata.permissions().mode() & PERMISSION_BITS_MASK
}

/// Mode to store for a single-file root: Unix returns the rwx bits
/// of the source file (special bits stripped via [`metadata_perm_mode`]);
/// non-Unix targets have no rwx semantic and return the fixed default.
#[cfg(unix)]
fn archive_file_mode(metadata: &fs::Metadata) -> u32 {
    metadata_perm_mode(metadata)
}
#[cfg(not(unix))]
fn archive_file_mode(_metadata: &fs::Metadata) -> u32 {
    DEFAULT_FILE_MODE
}

/// Mode to store for a regular file discovered during the cap-std
/// metadata-pass walk. Unix reads the rwx bits from the cap-std
/// metadata captured atomically with the no-follow `read_dir` entry;
/// non-Unix targets return the fixed default.
#[cfg(unix)]
fn archive_file_mode_cap(metadata: &cap_std::fs::Metadata) -> u32 {
    cap_metadata_perm_mode(metadata)
}
#[cfg(not(unix))]
fn archive_file_mode_cap(_metadata: &cap_std::fs::Metadata) -> u32 {
    DEFAULT_FILE_MODE
}

/// Mode to store for a directory discovered during the cap-std walk.
/// Takes pre-fetched cap-std metadata so the caller can reuse a
/// single `dir_metadata()` syscall across reparse-point check, cycle
/// detection, and mode read. Unix returns rwx bits; non-Unix returns
/// the fixed default.
#[cfg(unix)]
fn archive_dir_mode_cap(metadata: &cap_std::fs::Metadata) -> u32 {
    cap_metadata_perm_mode(metadata)
}
#[cfg(not(unix))]
fn archive_dir_mode_cap(_metadata: &cap_std::fs::Metadata) -> u32 {
    DEFAULT_DIR_MODE
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

/// Cap-std parallel of [`reject_windows_reparse_point`] for the
/// metadata-pass walk. Operates on a `cap_std::fs::Metadata` (lstat
/// semantics on Unix, directly produced from the open `Dir` or
/// `read_dir` `DirEntry` on every platform), so junctions and mount
/// points discovered mid-walk are caught alongside std-recognised
/// symlinks.
#[cfg(windows)]
fn reject_windows_reparse_point_cap(
    metadata: &cap_std::fs::Metadata,
    label: &str,
    name: &OsStr,
) -> Result<(), CryptoError> {
    use cap_std::fs::MetadataExt;
    if metadata.file_attributes() & platform::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(CryptoError::InvalidInput(format!(
            "{label} is a Windows reparse point: {}",
            Path::new(name).display()
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_windows_reparse_point_cap(
    _metadata: &cap_std::fs::Metadata,
    _label: &str,
    _name: &OsStr,
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
/// so caps can fire across the entire tree, not just per-call. The
/// `seen_inodes` set on Unix detects directory hardlinks (HFS+ and
/// some network filesystems permit them) so the writer rejects a
/// pathological cycle instead of silently archiving the same content
/// under multiple paths until one of the entry-count / total-bytes
/// caps fires.
#[derive(Debug, Default)]
struct ArchiveCounters {
    entry_count: u32,
    total_bytes: u64,
    /// `(dev, ino)` of every directory visited so far. Unix-only
    /// because Windows does not expose stable directory inodes.
    #[cfg(unix)]
    seen_dirs: std::collections::HashSet<(u64, u64)>,
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

/// Single source of truth for the "Symlink in archive source"
/// diagnostic emitted when `walk_directory` encounters a symlink at
/// a leaf entry (the file-type check arm). The dir-branch's
/// `open_dir_nofollow` failure routes through
/// [`platform::classify_open_failure`] with the same label and the
/// same `{fca_prefix}/{name}` diagnostic shape; both arms surface
/// byte-identical messages.
///
/// `fca_prefix` is the parent directory's archive path (e.g.
/// `"root/d"`). `name` is the offending leaf as raw `OsStr` so a
/// non-UTF-8 filename still produces a useful diagnostic via
/// `Path::display`'s replacement-character semantics.
fn symlink_in_archive_source_error(fca_prefix: &str, name: &OsStr) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "{}: {fca_prefix}/{}",
        platform::SYMLINK_IN_ARCHIVE_SOURCE,
        Path::new(name).display()
    ))
}

/// Single source of truth for the "Source file size changed during
/// archive (X → Y): path" diagnostic. Emitted by both
/// [`stream_single_file_root`] (single-file inputs, std-fs metadata)
/// and [`stream_directory_descendant`] (directory descendants,
/// cap-std metadata). Stable wording so downstream callers parsing
/// the message see the same shape regardless of input kind.
fn size_changed_error(
    expected: u64,
    observed: u64,
    display: std::path::Display<'_>,
) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "Source file size changed during archive ({expected} → {observed}): {display}"
    ))
}

/// Builds a fully validated [`Manifest`] from the source tree under
/// `input_path`. Single-file inputs produce a one-entry manifest with
/// `root_is_file = true`; directory inputs produce a multi-entry
/// manifest with `root_is_file = false`.
fn build_manifest(
    input_path: &Path,
    limits: &ArchiveLimits,
) -> Result<(Manifest, Option<Dir>), CryptoError> {
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
        // Single-file root: keeps the `std::fs` + `O_NOFOLLOW`-on-leaf
        // path. A single-component input has no intermediate-directory
        // TOCTOU surface to protect, so threading a cap-std capability
        // here would be ceremony without value.
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

        let manifest = Manifest {
            entries: vec![entry],
            total_file_bytes: size,
            root_name: OsString::from(&name_str),
            root_is_file: true,
            root_mode: mode,
        };
        Ok((manifest, None))
    } else if file_type.is_dir() {
        // Directory root: open the source tree through `cap_std::Dir`
        // so every subsequent metadata read, file open, and directory
        // descent is anchored to a capability handle. Intermediate
        // directories cannot be replaced with symlinks between the
        // metadata pass and the content pass — `walk_to_parent_readonly`
        // re-walks each component via `open_dir_nofollow`. Closes the
        // FORMAT.md §9.10 same-size-substitution surface that the
        // old absolute-path open path explicitly documented.
        let source_root = platform::open_anchor(input_path)?;

        // One `dir_metadata` syscall amortised across the reparse-point
        // check (Windows), the mode read, and the cycle-detection
        // seed (Unix). `dir_metadata` reads through the open `Dir`
        // capability, so the result is atomic with the `open_anchor`
        // — no race window between the path's stat and the capability
        // we just acquired.
        let source_root_meta = source_root.dir_metadata().map_err(CryptoError::Io)?;

        // Defense-in-depth on Windows: `Dir::open_ambient_dir` does
        // not refuse reparse points by default. The user-supplied path
        // might resolve through a junction or mount point; reject here
        // so the writer never archives content reached through one.
        // Unix `open_anchor` uses `O_DIRECTORY | O_NOFOLLOW` so a
        // symlink at the root path fails the open itself.
        reject_windows_reparse_point_cap(&source_root_meta, "Input", name)?;

        let root_mode = archive_dir_mode_cap(&source_root_meta);

        let mut entries = vec![writer_entry(
            ArchiveEntryKind::Directory,
            name_str.clone(),
            root_mode,
            0,
            // Empty rel-path identifies the source root itself. The
            // root entry has no content to stream so this field is
            // never read; populated for shape consistency.
            PathBuf::new(),
        )];
        let mut counters = ArchiveCounters {
            entry_count: 1,
            total_bytes: 0,
            #[cfg(unix)]
            seen_dirs: std::collections::HashSet::new(),
        };

        // Seed cycle detection with the source root's own (dev, ino)
        // so a hardlinked subdirectory pointing back to it is rejected.
        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt;
            counters
                .seen_dirs
                .insert((source_root_meta.dev(), source_root_meta.ino()));
        }

        walk_directory(
            &source_root,
            &name_str,
            Path::new(""),
            &mut entries,
            &mut counters,
            limits,
        )?;

        sort_entries_canonically(&mut entries);

        let manifest = Manifest {
            entries,
            total_file_bytes: counters.total_bytes,
            root_name: OsString::from(&name_str),
            root_is_file: false,
            root_mode,
        };
        Ok((manifest, Some(source_root)))
    } else {
        Err(CryptoError::InvalidInput(format!(
            "Unsupported file type: {}",
            input_path.display()
        )))
    }
}

/// Recursively walks `parent_dir` via `cap_std::Dir::read_dir`,
/// appending entries to `entries` with FCA paths rooted at
/// `fca_prefix` and rel-paths rooted at `rel_prefix` (relative to
/// the source root). Symlinks, devices, FIFOs, sockets, and
/// reparse points are rejected via the lstat-semantics
/// `DirEntry::metadata` plus a Windows reparse-point bit check.
///
/// The capability handle is the writer-side parity of
/// `archive/decode.rs` + `archive/platform.rs::walk_to_parent`:
/// every directory descent is a `cap_fs_ext::open_dir_nofollow`,
/// every file open routes through the parent capability, no
/// intermediate component is resolved through an absolute path
/// that an attacker could substitute.
fn walk_directory(
    parent_dir: &Dir,
    fca_prefix: &str,
    rel_prefix: &Path,
    entries: &mut Vec<ArchiveEntry>,
    counters: &mut ArchiveCounters,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    // `parent_dir` was opened via `open_anchor` (root) or
    // `open_dir_nofollow` (descendant), both of which reject symlinks
    // at open time, so the directory itself is already known good.
    // The cycle-detection seed/insert happens at the call site that
    // OPENED the dir so an empty directory still consumes the
    // dev/ino slot.

    for read_dir_entry in parent_dir.entries().map_err(CryptoError::Io)? {
        let dir_entry = read_dir_entry.map_err(CryptoError::Io)?;
        let metadata = dir_entry.metadata().map_err(CryptoError::Io)?;
        let file_type = metadata.file_type();
        let name_os = dir_entry.file_name();

        // Reject symlinks via the lstat-semantics file_type. The
        // diagnostic includes the FCA-relative path (parent prefix +
        // leaf) so the operator sees which manifest entry is
        // implicated, not just the failing leaf component.
        if file_type.is_symlink() {
            return Err(symlink_in_archive_source_error(fca_prefix, &name_os));
        }
        // Reject Windows reparse points that don't classify as
        // symlinks (junctions, mount points). No-op on Unix.
        reject_windows_reparse_point_cap(&metadata, "Source entry", &name_os)?;

        let name_str = name_os.to_str().ok_or_else(|| {
            CryptoError::InvalidInput(format!(
                "Source filename is not valid UTF-8: {fca_prefix}/{}",
                Path::new(&name_os).display()
            ))
        })?;

        // Defense-in-depth against custom filesystems that smuggle
        // path separators inside a single `file_name()` entry. POSIX
        // and NTFS forbid these bytes natively, but a FUSE / network
        // mount with permissive semantics could let one slip through
        // and silently mint a multi-component FCA path from what was
        // meant to be a single source filename.
        if name_str.bytes().any(|b| b == b'/' || b == b'\\') {
            return Err(CryptoError::InvalidInput(format!(
                "Source filename contains path separator: {fca_prefix}/{name_str}"
            )));
        }

        let fca_path_utf8 = format!("{fca_prefix}/{name_str}");
        let mut child_rel = rel_prefix.to_path_buf();
        child_rel.push(&name_os);

        if file_type.is_file() {
            let mode = archive_file_mode_cap(&metadata);
            let size = metadata.len();

            record_entry(counters, &fca_path_utf8, Some(size), limits)?;

            entries.push(writer_entry(
                ArchiveEntryKind::File,
                fca_path_utf8,
                mode,
                size,
                child_rel,
            ));
        } else if file_type.is_dir() {
            // Open the child directory through `open_dir_nofollow` —
            // identical primitive to the reader's per-component walk.
            // A symlink substituted here between `read_dir` and now
            // fails closed via the shared `classify_open_failure`
            // helper, with the encode-side label and the FCA path as
            // diagnostic context (matches the leaf-arm symlink message).
            let child_dir = parent_dir.open_dir_nofollow(&name_os).map_err(|e| {
                platform::classify_open_failure(
                    parent_dir,
                    &name_os,
                    e,
                    platform::SYMLINK_IN_ARCHIVE_SOURCE,
                    &fca_path_utf8,
                )
            })?;

            // One `dir_metadata` call amortised across the
            // Windows reparse-point post-check, the Unix
            // (dev, ino) cycle-detection seed, and the mode read.
            // Atomic with the `open_dir_nofollow` above — no race
            // window between the open and the metadata read.
            let child_meta = child_dir.dir_metadata().map_err(CryptoError::Io)?;

            // Windows reparse-point post-check on the opened handle:
            // catches a junction or mount point that wasn't classified
            // as a symlink by `read_dir`.
            reject_windows_reparse_point_cap(&child_meta, "Source directory", &name_os)?;

            // Cycle detection on Unix using (dev, ino).
            #[cfg(unix)]
            {
                use cap_std::fs::MetadataExt;
                let key = (child_meta.dev(), child_meta.ino());
                if !counters.seen_dirs.insert(key) {
                    return Err(CryptoError::InvalidInput(format!(
                        "Directory cycle in archive source: {fca_path_utf8}"
                    )));
                }
            }

            let mode = archive_dir_mode_cap(&child_meta);

            record_entry(counters, &fca_path_utf8, None, limits)?;

            entries.push(writer_entry(
                ArchiveEntryKind::Directory,
                fca_path_utf8.clone(),
                mode,
                0,
                child_rel.clone(),
            ));

            walk_directory(
                &child_dir,
                &fca_path_utf8,
                &child_rel,
                entries,
                counters,
                limits,
            )?;
        } else {
            return Err(CryptoError::InvalidInput(format!(
                "Unsupported file type in archive: {fca_path_utf8}"
            )));
        }
    }
    Ok(())
}

/// Sorts entries by `(component_count, path_utf8_bytes)` per
/// FORMAT.md §9.8. The root directory sorts first by construction
/// (smallest component count plus shortest path among any entry
/// sharing the root).
fn sort_entries_canonically(entries: &mut [ArchiveEntry]) {
    entries.sort_by(|a, b| canonical_path_order(&a.path_utf8, &b.path_utf8));
}

/// Streams one file entry's contents into `writer`. Dispatches based
/// on whether `source_root` was captured (directory input) or not
/// (single-file input).
///
/// FORMAT.md §9.10: on shrink, type change, or pre-copy growth — fail.
/// On growth during the copy after the fresh metadata check — copy
/// exactly the declared size, keeping the archive self-consistent.
fn stream_source_file<W: Write>(
    entry: &ArchiveEntry,
    source_root: Option<&Dir>,
    writer: &mut W,
) -> Result<(), CryptoError> {
    let source = entry
        .source_path
        .as_ref()
        .ok_or(CryptoError::InternalInvariant(
            "Manifest entry missing source_path during content streaming",
        ))?;

    match source_root {
        None => stream_single_file_root(entry, source, writer),
        Some(root) => stream_directory_descendant(root, entry, source, writer),
    }
}

/// Single-file root content stream: opens the absolute source path
/// with leaf-only `O_NOFOLLOW` on Unix or `FILE_FLAG_OPEN_REPARSE_POINT`
/// plus a post-check on Windows. A single-component input has no
/// intermediate-directory TOCTOU surface to protect.
fn stream_single_file_root<W: Write>(
    entry: &ArchiveEntry,
    source: &Path,
    writer: &mut W,
) -> Result<(), CryptoError> {
    let mut file = open_no_follow(source)?;
    let metadata = file.metadata().map_err(CryptoError::Io)?;
    reject_windows_reparse_point(&metadata, "Source", source)?;
    require_regular_file(&metadata, "Source", source)?;
    if metadata.len() != entry.size {
        return Err(size_changed_error(
            entry.size,
            metadata.len(),
            source.display(),
        ));
    }

    copy_exact_n(&mut file, writer, entry.size)
}

/// Directory-descendant content stream: walks `rel` under `source_root`
/// component-by-component through `cap_fs_ext::open_dir_nofollow`, then
/// opens the leaf via the parent capability with `FollowSymlinks::No`.
/// Closes the FORMAT.md §9.10 same-size-substitution surface that the
/// path-based open could not — every intermediate directory is
/// re-anchored to a capability handle, so a replacement between the
/// metadata pass and the content pass fails the per-component open.
fn stream_directory_descendant<W: Write>(
    source_root: &Dir,
    entry: &ArchiveEntry,
    rel: &Path,
    writer: &mut W,
) -> Result<(), CryptoError> {
    let (parent, file_name) = platform::walk_to_parent_readonly(source_root, rel)?;

    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(&file_name, &options)
        .map_err(CryptoError::Io)?;

    let metadata = file.metadata().map_err(CryptoError::Io)?;
    reject_windows_reparse_point_cap(&metadata, "Source", &file_name)?;
    if !metadata.is_file() {
        return Err(CryptoError::InvalidInput(format!(
            "Source is no longer a regular file: {}",
            Path::new(&file_name).display()
        )));
    }
    if metadata.len() != entry.size {
        return Err(size_changed_error(
            entry.size,
            metadata.len(),
            Path::new(&file_name).display(),
        ));
    }

    copy_exact_n(&mut file, writer, entry.size)
}

/// Archives a file or directory into the FCA wire format. Returns the
/// output stem (file stem for file inputs, directory name for
/// directory inputs) plus the writer for the caller to finalize.
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

    // Pass 1: metadata-only manifest. For directory inputs the
    // returned `Dir` capability handle is held across both passes
    // so the content pass can re-anchor each per-entry open without
    // resolving the source path through the kernel a second time.
    let (manifest, source_root) = build_manifest(input_path, &limits)?;

    // Defense-in-depth: a bug in walk_directory would surface here
    // rather than producing a malformed archive.
    let _ = validate_manifest_tree(&manifest.entries, manifest.total_file_bytes, limits)?;

    let manifest_bytes = serialize_manifest(&manifest, limits)?;
    // The wire-format `entry_count` and `manifest_len` are u32. Convert
    // first (so a usize > u32::MAX surfaces immediately as a cap-style
    // error), then run the cap helpers as the single source of truth
    // for the cap rule itself. Caps were already enforced earlier in
    // the pipeline (`build_manifest` and `checked_manifest_len`); the
    // re-checks here keep encode.rs from inlining its own `> cap`
    // comparison.
    let entry_count = u32::try_from(manifest.entries.len())
        .map_err(|_| entry_count_cap_error(u32::MAX, limits.max_entry_count))?;
    enforce_entry_count_cap(entry_count, &limits)?;
    let manifest_len = u32::try_from(manifest_bytes.len()).map_err(|_| {
        manifest_len_cap_error(manifest_bytes.len() as u64, limits.max_manifest_bytes)
    })?;
    enforce_manifest_len_cap(u64::from(manifest_len), &limits)?;

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
    // `source_root` is `Some` for directory inputs (cap-std anchored
    // re-open per entry) and `None` for single-file inputs (leaf-only
    // `O_NOFOLLOW` open suffices — no intermediate directory surface).
    for entry in &manifest.entries {
        if entry.kind == ArchiveEntryKind::File {
            stream_source_file(entry, source_root.as_ref(), &mut writer)?;
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
    /// internal API: file stem for files, dir name for directories.
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

    // -- Writer-side rejections --------------------------------------------

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

    // -- Positive round-trips (extra coverage) -----------------------------

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

    // -- Unix mode preservation --------------------------------------------

    /// Source file mode round-trips through the archive intact (rwx
    /// bits only — special bits stripped per FORMAT.md §9.10). Pins
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
    /// (FORMAT.md §9.11 step 16). Validates "root chmod after rename"
    /// indirectly: if the reader applied root mode pre-rename and the
    /// mode lacked search permission, the rename itself would fail on
    /// macOS.
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

    /// FORMAT.md §9.10: writers MUST NOT store setuid, setgid, or
    /// sticky bits. Pin the strip on the WRITER side: a source file
    /// with 0o4644 (setuid + rw-r--r--) extracts as 0o644.
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

    // -- Source mutation between passes ------------------------------------

    // -- Mode round-trips (Batch 2.2) --------------------------------------

    // Mode 0o000 admissibility is tested on the decode side
    // (`archive::decode::tests::extract_applies_mode_0o000_to_output_file`)
    // because a source file with mode 0o000 cannot be read by its
    // owner on a non-root account, so the encode side cannot
    // round-trip it. Decode-side coverage exercises `chmod_file_handle`
    // with the value directly, which is the actual property we care
    // about (extraction faithfully applies the manifest-stored mode).

    /// File mode 0o400 (read-only owner) round-trips intact.
    #[cfg(unix)]
    #[test]
    fn round_trip_file_mode_0o400() {
        use std::os::unix::fs::PermissionsExt;

        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let src_file = src.path().join("hello.txt");
        fs::write(&src_file, b"x").unwrap();
        fs::set_permissions(&src_file, fs::Permissions::from_mode(0o400)).unwrap();

        let final_path = round_trip(&src_file, out.path());
        let mode = fs::metadata(&final_path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o400);

        fs::set_permissions(&final_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&src_file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// File mode 0o755 (executable) round-trips intact.
    #[cfg(unix)]
    #[test]
    fn round_trip_file_mode_0o755() {
        use std::os::unix::fs::PermissionsExt;

        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let src_file = src.path().join("hello.txt");
        fs::write(&src_file, b"x").unwrap();
        fs::set_permissions(&src_file, fs::Permissions::from_mode(0o755)).unwrap();

        let final_path = round_trip(&src_file, out.path());
        let mode = fs::metadata(&final_path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o755);
    }

    /// File mode 0o777 (all permissions) round-trips intact. Upper
    /// boundary of FCA's permission word (special bits stripped).
    #[cfg(unix)]
    #[test]
    fn round_trip_file_mode_0o777() {
        use std::os::unix::fs::PermissionsExt;

        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let src_file = src.path().join("hello.txt");
        fs::write(&src_file, b"x").unwrap();
        fs::set_permissions(&src_file, fs::Permissions::from_mode(0o777)).unwrap();

        let final_path = round_trip(&src_file, out.path());
        let mode = fs::metadata(&final_path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o777);
    }

    /// Directory mode 0o500 round-trips. Restrictive enough that
    /// the apply-modes pass MUST run after children are created.
    #[cfg(unix)]
    #[test]
    fn round_trip_directory_mode_0o500() {
        use std::os::unix::fs::PermissionsExt;

        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("locked");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("file"), b"x").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();

        let final_path = round_trip(&dir, out.path());
        let mode = fs::metadata(&final_path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o500);

        fs::set_permissions(&final_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    }

    // -- Tree shape and stress (Batch 2.6) --------------------------------

    /// Very wide directory: 1000 files in one directory round-trip.
    /// Confirms the manifest sort, dedup, and per-entry caps all
    /// scale to a fan-out near the typical workspace.
    #[test]
    fn round_trip_very_wide_directory() {
        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("wide");
        fs::create_dir(&dir).unwrap();
        for i in 0..1000 {
            fs::write(dir.join(format!("f{i:04}.bin")), b"x").unwrap();
        }

        let final_path = round_trip(&dir, out.path());
        assert!(final_path.is_dir());
        assert_eq!(fs::read_dir(&final_path).unwrap().count(), 1000);
    }

    /// Path depth at the FCA cap round-trips end-to-end — not just
    /// the validator. Pins that the writer's path construction, the
    /// reader's `walk_to_parent`, and the per-entry path-bytes cap
    /// all admit the cap value. Tied to `ArchiveLimits::max_path_depth`
    /// so a future cap change does not silently leave the test off-by-N.
    #[test]
    fn round_trip_depth_at_cap() {
        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        // Components: root + (cap - 2) intermediate dirs + leaf = cap.
        let cap = ArchiveLimits::default().max_path_depth as usize;
        assert!(
            cap >= 2,
            "round_trip_depth_at_cap requires max_path_depth >= 2 (got {cap})"
        );
        let intermediate_dirs = cap - 2;

        let root = src.path().join("root");
        let mut p = root.clone();
        for _ in 0..intermediate_dirs {
            p = p.join("a");
        }
        fs::create_dir_all(&p).unwrap();
        let leaf = p.join("leaf.txt");
        fs::write(&leaf, b"deep").unwrap();

        let final_path = round_trip(&root, out.path());
        let mut q = final_path.clone();
        for _ in 0..intermediate_dirs {
            q = q.join("a");
        }
        assert_eq!(fs::read(q.join("leaf.txt")).unwrap(), b"deep");
    }

    /// Many empty directories (1000) round-trip. Pins that
    /// directory-only stress doesn't trip the entry-count cap and
    /// that Pass 1 (pre-create dirs) handles a wide sibling fan-out.
    #[test]
    fn round_trip_many_empty_directories() {
        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let root = src.path().join("dirs");
        fs::create_dir(&root).unwrap();
        for i in 0..1000 {
            fs::create_dir(root.join(format!("d{i:04}"))).unwrap();
        }

        let final_path = round_trip(&root, out.path());
        assert_eq!(fs::read_dir(&final_path).unwrap().count(), 1000);
    }

    /// Many zero-byte files (1000) round-trip. Pins that the
    /// content pass is well-defined for size-0 entries — every read
    /// would have remaining=0 immediately, so the loop body never
    /// runs but the entry still consumes a manifest slot.
    #[test]
    fn round_trip_many_zero_byte_files() {
        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let root = src.path().join("zeros");
        fs::create_dir(&root).unwrap();
        for i in 0..1000 {
            fs::write(root.join(format!("f{i:04}.empty")), b"").unwrap();
        }

        let final_path = round_trip(&root, out.path());
        assert_eq!(fs::read_dir(&final_path).unwrap().count(), 1000);
    }

    // -- Hardlinks (Batch 2.8) --------------------------------------------

    /// Two hardlinks to the same regular file in the source tree are
    /// stored as INDEPENDENT entries (each with its own size and
    /// content), per FORMAT.md design. FCA has no hardlink entry kind;
    /// the writer sees two `read_dir` entries pointing at the same
    /// inode and emits two file entries.
    ///
    /// Pin this designed behavior so a future "deduplicate by inode"
    /// optimization that would change the wire output is caught at
    /// test time.
    #[cfg(unix)]
    #[test]
    fn round_trip_hardlinked_files_stored_as_independent() {
        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("d");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("original.txt"), b"shared content").unwrap();
        fs::hard_link(dir.join("original.txt"), dir.join("link.txt")).unwrap();

        let final_path = round_trip(&dir, out.path());
        // Both files extracted with the same content.
        assert_eq!(
            fs::read(final_path.join("original.txt")).unwrap(),
            b"shared content"
        );
        assert_eq!(
            fs::read(final_path.join("link.txt")).unwrap(),
            b"shared content"
        );

        // On the OUTPUT side they are NOT hardlinked (FCA stores them
        // as independent files). Pin this by checking that modifying
        // one doesn't affect the other — confirms distinct inodes.
        fs::write(final_path.join("original.txt"), b"modified").unwrap();
        assert_eq!(
            fs::read(final_path.join("link.txt")).unwrap(),
            b"shared content"
        );
    }

    // -- Source-tree edge cases (Batch 2.12) ------------------------------

    /// Symlink-to-directory at the input root rejects with the same
    /// diagnostic as symlink-to-file. Complements the existing
    /// `rejects_root_symlink` (file target) and `rejects_dangling_symlink`
    /// (no target).
    #[cfg(unix)]
    #[test]
    fn rejects_root_symlink_to_directory() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("real_dir");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("inside.txt"), b"data").unwrap();
        let link = tmp.path().join("link_dir");
        symlink(&target, &link).unwrap();

        let mut buf = Vec::new();
        let err = archive(&link, &mut buf, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("Input is a symlink"));
    }

    /// Source filename with non-UTF-8 bytes (built via raw `OsString`
    /// from invalid UTF-8 byte sequence) rejects with the typed
    /// "not valid UTF-8" diagnostic. Covers the §16 "Non-UTF-8 host
    /// filenames on Unix" case.
    ///
    /// **Linux-only.** macOS APFS and Windows NTFS reject non-UTF-8
    /// filenames at the filesystem syscall layer (APFS returns
    /// `EILSEQ` on `creat`), so this test cannot construct the input
    /// state on those targets. Linux ext4 / btrfs / xfs accept
    /// arbitrary bytes for names and exercise the FCA rejection.
    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_non_utf8_source_filename() {
        use std::os::unix::ffi::OsStrExt;

        let src = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("d");
        fs::create_dir(&dir).unwrap();

        // 0xFF is not a valid UTF-8 start byte; build an OsString
        // directly from the raw bytes.
        let invalid_name = std::ffi::OsString::from(OsStr::from_bytes(b"bad\xFF"));
        let bad_path = dir.join(&invalid_name);
        fs::write(&bad_path, b"data").unwrap();

        let mut buf = Vec::new();
        let err = archive(&dir, &mut buf, ArchiveLimits::default()).unwrap_err();
        assert!(
            format!("{err}").contains("not valid UTF-8"),
            "expected UTF-8 rejection, got: {err}",
        );
    }

    /// FORMAT.md §9.10: a source file shrinking between metadata pass
    /// and content pass MUST fail. We can't shrink a real file mid-archive
    /// race-free, so this test exercises the size-check directly via
    /// `stream_source_file` with a pre-built `ArchiveEntry` whose
    /// recorded size doesn't match the file on disk. Single-file root
    /// path (`source_root = None`).
    #[test]
    fn stream_source_file_rejects_size_mismatch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("real.txt");
        fs::write(&path, b"actual content").unwrap();

        // 9999 ≠ actual file size → exercises the size-mismatch arm.
        let mut entry = make_entry("real.txt", ArchiveEntryKind::File, 9999, 0o644);
        entry.source_path = Some(path);

        let mut buf = Vec::new();
        let err = stream_source_file(&entry, None, &mut buf).unwrap_err();
        assert!(format!("{err}").contains("size changed"));
    }

    /// Cap-std parity test: an attacker who replaces an intermediate
    /// directory with a symlink between the metadata pass and the
    /// content pass MUST be rejected. Drives `stream_source_file` with
    /// `source_root = Some(...)` so the cap-std walker is exercised.
    /// Pre-builds a manifest entry with `rel = "a/b/file.txt"`,
    /// then replaces `a/b` with a symlink and asserts the per-entry
    /// reopen fails closed.
    ///
    /// Pre-refactor this attack would have succeeded via the absolute-
    /// path open: even with `O_NOFOLLOW` on the leaf, the kernel
    /// resolved the intermediate `a/b` through the substituted symlink.
    /// The cap-std walk (`platform::walk_to_parent_readonly`) re-opens
    /// each component via `open_dir_nofollow`, so the substitution is
    /// caught here.
    #[cfg(unix)]
    #[test]
    fn stream_source_file_rejects_intermediate_symlink_substitution() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::TempDir::new().unwrap();
        let src_root = tmp.path().join("source");
        fs::create_dir_all(src_root.join("a").join("b")).unwrap();
        fs::write(src_root.join("a").join("b").join("file.txt"), b"trusted").unwrap();

        // Open the source root capability BEFORE the swap so the
        // capability is the same one a real archive() invocation
        // would hold across the metadata and content passes.
        let source_root = platform::open_anchor(&src_root).unwrap();

        // Build the entry pointing at the original (good) location.
        let mut entry = make_entry("source/a/b/file.txt", ArchiveEntryKind::File, 7, 0o644);
        entry.source_path = Some(PathBuf::from("a/b/file.txt"));

        // Now swap: replace `a/b` (a real dir) with a symlink to a
        // sibling holding attacker-controlled content of the same
        // size. The size-check guard (which tar-rs and the legacy
        // FCA writer both relied on) cannot catch a same-size swap.
        let attacker = tmp.path().join("attacker");
        fs::create_dir(&attacker).unwrap();
        fs::write(attacker.join("file.txt"), b"hostile").unwrap();

        fs::remove_dir_all(src_root.join("a").join("b")).unwrap();
        symlink(&attacker, src_root.join("a").join("b")).unwrap();

        let mut buf = Vec::new();
        let err = stream_source_file(&entry, Some(&source_root), &mut buf).unwrap_err();
        // Encode-side symlink rejection from `walk_to_parent_readonly`
        // routes through `platform::classify_open_failure` with the
        // `SYMLINK_IN_ARCHIVE_SOURCE` label.
        assert!(
            format!("{err}").contains(platform::SYMLINK_IN_ARCHIVE_SOURCE),
            "expected `{}` rejection, got: {err}",
            platform::SYMLINK_IN_ARCHIVE_SOURCE,
        );
    }
}
