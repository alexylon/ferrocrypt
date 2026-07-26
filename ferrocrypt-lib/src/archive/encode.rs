//! FCA archive writer: source-tree traversal (metadata pass) and
//! content-streaming pass.
//!
//! See `ferrocrypt-lib/FORMAT.md` §9.8 (canonical entry ordering),
//! §9.10 (writer obligations), §9.12 (resource caps), §9.13 (platform
//! metadata and preservation).
//!
//! The writer is two-pass:
//!
//! 1. **Metadata pass** — opens the source root once. A single-file
//!    root is opened with a no-follow, non-blocking open and its mode
//!    and size are read from that handle. A directory root is opened
//!    directly on Unix via `open_anchor` and verified with a `(dev, ino)`
//!    re-check; on Windows it is opened through its parent directory via
//!    `open_child_dir_nofollow` with the reparse-point post-check. The
//!    directory is then walked iteratively over
//!    `cap_std::fs::Dir::entries`, driven by a heap-backed stack of
//!    pending directories with deferred child opens (live handles
//!    track the depth of the tree, not its width, and deep nesting
//!    cannot overflow the process stack). The walk builds a
//!    [`Manifest`] of [`ArchiveEntry`]s with FCA-canonical paths,
//!    modes, sizes, and source paths. Symlinks, FIFOs, sockets,
//!    devices, and Windows reparse points are rejected inline.
//!    Entry-count, total-bytes, depth, path-byte, and manifest-size
//!    caps are applied while the tree is walked, so an over-cap tree
//!    is rejected without first holding every scanned entry in
//!    memory, and every path is routed through [`validate_fca_path`]
//!    so the writer never emits a path its own reader would refuse.
//!
//! 2. **Content pass** — for each file entry in canonical manifest
//!    order, refreshes metadata from an open handle, requires the
//!    source is still a regular file with `len() == manifest size`,
//!    and streams exactly the declared size via [`copy_exact_n`]. A
//!    single-file root streams from the handle held since the
//!    metadata pass, so no component of the user-supplied path is
//!    resolved a second time. Directory descendants re-anchor through
//!    the directory capability held since the metadata pass, then
//!    take a no-follow non-blocking leaf open.
//!
//! Between the two passes the source tree may change. FORMAT.md §9.10
//! defines the response: shrink / type change / inaccessible →
//! encryption must fail; growth before the fresh metadata check →
//! reject; growth during the copy after the fresh metadata check →
//! the writer copies exactly the declared size, keeping the archive
//! self-consistent.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};

use crate::CryptoError;
use crate::error::{sanitize_for_display, sanitize_path_for_display};
#[cfg(windows)]
use crate::fs::paths::parent_or_cwd;
use crate::fs::paths::{input_name_not_utf8_error, unsupported_file_type_error};

#[cfg(unix)]
use super::format::PERMISSION_BITS_MASK;
use super::format::{checked_entry_wire_len, copy_exact_n, serialize_manifest, write_fca_header};
use super::limits::{
    ARCHIVE_MANIFEST_LEN_OVERFLOW, ArchiveLimits, enforce_entry_count_cap,
    enforce_manifest_len_cap, enforce_per_entry_caps, enforce_total_bytes_cap,
    entry_count_cap_error, manifest_len_cap_error,
};
use super::model::{ArchiveEntry, ArchiveEntryKind, Manifest};
use super::path::{canonical_path_order, validate_fca_path};
use super::platform;
use super::tree::validate_manifest_tree;

// The walker's safety nets are platform-specific: Unix has `(dev, ino)`
// directory-cycle detection, Windows has reparse-point rejection. Any
// other target would walk a cyclic source tree until a resource cap
// fires, so refuse it at build time.
#[cfg(not(any(unix, windows)))]
compile_error!("The FCA archive writer supports only Unix and Windows targets");

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
/// as symlinks. FCA stores no reparse-point semantics, so writer
/// input rejects them before they can redirect traversal or content
/// reads.
#[cfg(windows)]
fn reject_windows_reparse_point(
    metadata: &fs::Metadata,
    label: &str,
    path: &Path,
) -> Result<(), CryptoError> {
    use std::os::windows::fs::MetadataExt;

    if metadata.file_attributes() & platform::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(CryptoError::InvalidInput(format!(
            "{label} is a Windows reparse point: {}",
            sanitize_path_for_display(path)
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
            sanitize_for_display(&name.to_string_lossy())
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
/// Unix uses `O_NOFOLLOW` so the open itself is atomic, plus
/// `O_NONBLOCK` so a FIFO substituted for the source cannot block the
/// process inside `open(2)` — the caller's post-open type check
/// rejects it, and the flag has no effect on regular-file reads. On
/// Windows uses `FILE_FLAG_OPEN_REPARSE_POINT` plus a metadata
/// post-check so a racing symlink/junction replacement is rejected
/// instead of followed.
#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File, CryptoError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
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
            sanitize_path_for_display(path)
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
        return Err(unsupported_file_type_error(input_path));
    }
    // The extractor refuses a directory root on targets without a
    // promotion backend; the writer refuses the same input so it never
    // produces an archive it cannot read back (encrypt/decrypt symmetry).
    if file_type.is_dir() && !platform::DIRECTORY_PROMOTION_SUPPORTED {
        return Err(CryptoError::InvalidInput(
            "Encrypting a directory is not supported on this target".to_string(),
        ));
    }
    Ok(())
}

/// Running totals threaded through the metadata-pass walk so caps can
/// fire across the entire tree, not just per-call. The `seen_dirs`
/// set on Unix detects directory hardlinks (HFS+ and some network
/// filesystems permit them) so the writer rejects a pathological
/// cycle instead of silently archiving the same content under
/// multiple paths until one of the entry-count / total-bytes caps
/// fires.
#[derive(Debug, Default)]
struct ArchiveCounters {
    entry_count: u32,
    total_bytes: u64,
    /// Running serialized length of the manifest built so far. Checked
    /// against `max_manifest_bytes` per entry so an over-cap tree is
    /// rejected during the walk, before every scanned entry is
    /// resident in memory.
    manifest_len: u64,
    /// `(dev, ino)` of every directory visited so far. Unix-only
    /// because Windows does not expose stable directory inodes.
    /// Directories whose filesystem reports inode 0 are left out, since
    /// that value identifies nothing.
    #[cfg(unix)]
    seen_dirs: std::collections::HashSet<(u64, u64)>,
}

/// Single source of truth for the writer's [`ArchiveEntry`]
/// construction during the metadata pass. Every `entry_ext` is empty
/// because native writers emit no per-entry TLV bytes (FORMAT.md
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
/// every cap [`enforce_per_entry_caps`] covers, sums into the
/// manifest-length cap, optionally sums into the total-bytes cap (for
/// file entries), and runs [`validate_fca_path`]. Used for the
/// directory-root entry and for every entry the directory walk
/// discovers, so the whole directory tree shares one sequence of
/// checks. A single-file root records its one entry inline (it has no
/// walk); the writer-side [`serialize_manifest`] gate re-applies every
/// cap before any byte is emitted, so a per-entry rule added here that
/// a single-file root must also obey belongs in that gate too.
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

    // Writer entries carry no per-entry TLV bytes (FORMAT.md §9.13),
    // so this entry's serialized length is the fixed size plus the
    // path bytes. `serialize_manifest` re-checks the final sum through
    // the same `enforce_manifest_len_cap` before any byte is emitted.
    counters.manifest_len = checked_entry_wire_len(fca_path_utf8.len(), 0)
        .and_then(|entry_len| counters.manifest_len.checked_add(entry_len as u64))
        .ok_or(CryptoError::MalformedArchive {
            reason: ARCHIVE_MANIFEST_LEN_OVERFLOW,
        })?;
    enforce_manifest_len_cap(counters.manifest_len, limits)?;

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
    CryptoError::InvalidInput(format!(
        "Input is a symlink: {}",
        sanitize_path_for_display(path)
    ))
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
        "{}: {}",
        platform::SYMLINK_IN_ARCHIVE_SOURCE,
        sanitize_for_display(&format!("{fca_prefix}/{}", name.to_string_lossy()))
    ))
}

/// Single source of truth for the "Source file size changed during
/// archive (X → Y): path" diagnostic. Emitted by both
/// [`stream_single_file_root`] (single-file inputs, std-fs metadata)
/// and [`stream_directory_descendant`] (directory descendants,
/// cap-std metadata). Stable wording so downstream callers parsing
/// the message see the same shape regardless of input kind.
fn size_changed_error(expected: u64, observed: u64, path_text: &str) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "Source file size changed during archive ({expected} → {observed}): {path_text}"
    ))
}

/// Source access captured by the metadata pass and reused by the
/// content pass. Holding it across both passes is what makes the
/// content pass immune to path swaps: a single-file root streams from
/// the very handle its metadata came from, and directory descendants
/// re-anchor through the directory capability instead of resolving
/// the user-supplied path a second time.
enum ArchiveSource {
    /// Single-file root: the handle the metadata pass opened with
    /// no-follow.
    RootFile(File),
    /// Directory root: the capability handle every per-entry re-open
    /// walks from.
    RootDir(Dir),
}

/// Builds a fully validated [`Manifest`] from the source tree under
/// `input_path`, together with the [`ArchiveSource`] the content pass
/// streams from. Single-file inputs produce a one-entry manifest with
/// `root_is_file = true`; directory inputs produce a multi-entry
/// manifest with `root_is_file = false`.
fn build_manifest(
    input_path: &Path,
    limits: &ArchiveLimits,
) -> Result<(Manifest, ArchiveSource), CryptoError> {
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
        .ok_or_else(|| input_name_not_utf8_error(input_path))?
        .to_string();

    // Path grammar applies to the root regardless of kind; validate
    // once before the file/dir dispatch.
    validate_fca_path(&name_str, *limits)?;

    if file_type.is_file() {
        // Single-file root: open once and keep the handle for the
        // content pass, so no component of the user-supplied path is
        // resolved a second time and a leaf or ancestor swap between
        // the passes cannot substitute the source. `open_no_follow`
        // refuses a symlink leaf atomically; the type re-check below
        // catches a FIFO swapped in after the lstat above.
        let source = open_no_follow(input_path)?;
        let handle_meta = source.metadata().map_err(CryptoError::Io)?;
        require_regular_file(&handle_meta, "Input", input_path)?;

        let mode = archive_file_mode(&handle_meta);
        let size = handle_meta.len();

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
        Ok((manifest, ArchiveSource::RootFile(source)))
    } else if file_type.is_dir() {
        // Directory root. Both platforms reject an input-root symlink or
        // reparse point swapped in after the lstat above (FORMAT.md §9.10
        // MUST-reject), and anchor every later open to the returned
        // capability handle so no intermediate component can be replaced
        // between the metadata pass and the content pass. The open differs
        // by platform:
        //
        // - Unix: open the directory directly. `open_ambient_dir` follows
        //   a symlink at `input_path`, but the `(dev, ino)` re-check below
        //   rejects any swap, so opening the directory itself — rather
        //   than its parent — keeps the prior permission requirement
        //   (search on the parent, not read).
        // - Windows: there is no stable directory inode to re-check, so
        //   anchor the parent and take a no-follow open of the leaf, whose
        //   reparse-point post-check rejects a junction at `input_path`.
        #[cfg(unix)]
        let source_root = platform::open_anchor(input_path)?;
        #[cfg(windows)]
        let source_root = {
            let parent_anchor = platform::open_anchor(parent_or_cwd(input_path))?;
            platform::open_child_dir_nofollow(
                &parent_anchor,
                name,
                platform::SYMLINK_IN_ARCHIVE_SOURCE,
            )?
        };

        // One `dir_metadata` call reused for the Unix identity
        // re-check, the cycle-detection seed, and the mode read.
        let source_root_meta = source_root.dir_metadata().map_err(CryptoError::Io)?;

        // A real directory swapped in at `input_path` after the lstat
        // pre-check still opens on Unix; comparing the opened handle's
        // (dev, ino) against the pre-check rejects any such swap.
        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt as _;
            use std::os::unix::fs::MetadataExt as _;
            if (source_root_meta.dev(), source_root_meta.ino()) != (metadata.dev(), metadata.ino())
            {
                return Err(CryptoError::InvalidInput(format!(
                    "Input directory changed during archive: {}",
                    sanitize_path_for_display(input_path)
                )));
            }
        }

        let root_mode = archive_dir_mode_cap(&source_root_meta);

        let mut counters = ArchiveCounters::default();
        record_entry(&mut counters, &name_str, None, limits)?;
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

        // Seed cycle detection with the source root's own (dev, ino)
        // so a hardlinked subdirectory pointing back to it is rejected.
        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt;
            let (dev, ino) = (source_root_meta.dev(), source_root_meta.ino());
            if ino != 0 {
                counters.seen_dirs.insert((dev, ino));
            }
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
        Ok((manifest, ArchiveSource::RootDir(source_root)))
    } else {
        Err(unsupported_file_type_error(input_path))
    }
}

/// A subdirectory discovered by the metadata scan but not yet opened:
/// the parent's shared handle plus the child's own name. Opening is
/// deferred to the moment the item is popped, so simultaneously-open
/// directory handles track the active descent chain (O(depth)) rather
/// than the discovery frontier (O(sibling count)) — a directory with
/// more children than the process fd limit walks fine.
struct PendingDir {
    parent: Rc<Dir>,
    name: OsString,
    fca_path: String,
    rel_path: PathBuf,
}

/// Walks `parent_dir` iteratively via `cap_std::Dir::read_dir`,
/// appending entries to `entries` with FCA paths rooted at
/// `fca_prefix` and rel-paths rooted at `rel_prefix` (relative to
/// the source root). Symlinks, devices, FIFOs, sockets, and
/// reparse points are rejected via the lstat-semantics
/// `DirEntry::metadata` plus a Windows reparse-point bit check.
///
/// Iterative on purpose: a deeply-nested source tree under raised
/// `ArchiveLimits` (`max_path_depth` well beyond the default 64)
/// must not consume O(depth) of process stack, so the traversal
/// stack lives on the heap. Child directories are pushed by name
/// ([`PendingDir`]) and opened only when popped, so a wide directory
/// cannot exhaust the process fd limit either.
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
    // `try_clone` gives the walk its own owned `Dir` (fresh fd) so the
    // borrowed `parent_dir` is unaffected; `Rc` lets every pending
    // child share that one handle instead of holding an fd each.
    let root = Rc::new(parent_dir.try_clone().map_err(CryptoError::Io)?);
    let mut stack: Vec<PendingDir> = Vec::new();
    scan_directory(
        &root, fca_prefix, rel_prefix, &mut stack, entries, counters, limits,
    )?;
    // Release the walk's own root reference: from here on, pending
    // children alone keep each ancestor handle alive, and a handle
    // closes as soon as its last pending child has been processed.
    drop(root);

    while let Some(PendingDir {
        parent,
        name,
        fca_path,
        rel_path,
    }) = stack.pop()
    {
        // Open the child only now, through `open_dir_nofollow` — the
        // identical primitive to the reader's per-component walk. A
        // symlink substituted since the scan fails closed via the
        // shared `classify_open_failure` helper, with the encode-side
        // label and the FCA path as diagnostic context.
        let child_dir = parent.open_dir_nofollow(&name).map_err(|e| {
            platform::classify_open_failure(
                &parent,
                &name,
                e,
                platform::SYMLINK_IN_ARCHIVE_SOURCE,
                &fca_path,
            )
        })?;
        // This item's parent reference is no longer needed; dropping it
        // before the descent lets the parent handle close with the last
        // pending sibling instead of staying open through the subtree.
        drop(parent);

        // One `dir_metadata` call amortised across the Windows
        // reparse-point post-check, the Unix (dev, ino) cycle-detection
        // seed, and the mode read. Atomic with the `open_dir_nofollow`
        // above — no race window between the open and the metadata read.
        let child_meta = child_dir.dir_metadata().map_err(CryptoError::Io)?;

        // Windows reparse-point post-check on the opened handle:
        // catches a junction or mount point that wasn't classified as a
        // symlink during the scan.
        reject_windows_reparse_point_cap(&child_meta, "Source directory", &name)?;

        // Cycle detection on Unix using (dev, ino). The insert happens
        // here, where the dir is OPENED, so an empty directory still
        // consumes its dev/ino slot.
        //
        // Inode 0 means the filesystem supplies no inode number — some
        // network mounts and overlay filesystems report it for every
        // entry. Comparing those would reject the second subdirectory
        // as a cycle, so they are skipped; the entry-count, depth, and
        // total-bytes caps still bound a walk that cannot be checked
        // this way.
        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt;
            let (dev, ino) = (child_meta.dev(), child_meta.ino());
            if ino != 0 && !counters.seen_dirs.insert((dev, ino)) {
                return Err(CryptoError::InvalidInput(format!(
                    "Directory cycle in archive source: {}",
                    sanitize_for_display(&fca_path)
                )));
            }
        }

        let mode = archive_dir_mode_cap(&child_meta);

        entries.push(writer_entry(
            ArchiveEntryKind::Directory,
            fca_path.clone(),
            mode,
            0,
            rel_path.clone(),
        ));

        let child = Rc::new(child_dir);
        scan_directory(
            &child, &fca_path, &rel_path, &mut stack, entries, counters, limits,
        )?;
    }
    Ok(())
}

/// Single metadata scan over one opened directory: runs the per-name
/// rejections that need only directory-entry metadata (Windows reparse
/// pre-check, symlink rejection, UTF-8, separator smuggling), records
/// file entries, counts each subdirectory against the resource caps,
/// and pushes it onto `stack` unopened. The per-directory work that
/// needs the child's own handle — reparse post-check, cycle detection,
/// mode read, manifest entry — runs in [`walk_directory`]'s pop loop.
fn scan_directory(
    dir: &Rc<Dir>,
    fca_prefix: &str,
    rel_prefix: &Path,
    stack: &mut Vec<PendingDir>,
    entries: &mut Vec<ArchiveEntry>,
    counters: &mut ArchiveCounters,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    for read_dir_entry in dir.entries().map_err(CryptoError::Io)? {
        let dir_entry = read_dir_entry.map_err(CryptoError::Io)?;
        let metadata = dir_entry.metadata().map_err(CryptoError::Io)?;
        let file_type = metadata.file_type();
        let name_os = dir_entry.file_name();

        // On Windows, reject any reparse point (symlinks, junctions,
        // mount points) with the explicit reparse-point diagnostic
        // before the generic symlink check below. The
        // FILE_ATTRIBUTE_REPARSE_POINT bit is set on every variant —
        // including the ones cap_primitives reports as
        // `is_symlink() == true` (NTFS junctions are
        // reparse-tag-name-surrogate, so std and cap-std both flag
        // them as symlinks). Running this first means a junction
        // surfaces as "Windows reparse point" rather than the less
        // accurate "Symlink in archive source". No-op on Unix.
        reject_windows_reparse_point_cap(&metadata, "Source entry", &name_os)?;

        // Reject Unix symlinks via the lstat-semantics file_type. The
        // diagnostic includes the FCA-relative path (parent prefix +
        // leaf) so the operator sees which manifest entry is
        // implicated, not just the failing leaf component. On
        // Windows, the reparse-point check above already caught
        // anything `is_symlink()` would flag.
        if file_type.is_symlink() {
            return Err(symlink_in_archive_source_error(fca_prefix, &name_os));
        }

        let name_str = name_os.to_str().ok_or_else(|| {
            CryptoError::InvalidInput(format!(
                "Source filename is not valid UTF-8: {}",
                sanitize_for_display(&format!("{fca_prefix}/{}", name_os.to_string_lossy()))
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
                "Source filename contains path separator: {}",
                sanitize_for_display(&format!("{fca_prefix}/{name_str}"))
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
            // Counted at discovery, not at pop: the entry-count and
            // path caps must bound the pending stack itself, or one
            // directory wider than the cap would queue every child
            // before the first cap check ran.
            record_entry(counters, &fca_path_utf8, None, limits)?;

            stack.push(PendingDir {
                parent: Rc::clone(dir),
                name: name_os,
                fca_path: fca_path_utf8,
                rel_path: child_rel,
            });
        } else {
            return Err(CryptoError::InvalidInput(format!(
                "Unsupported file type in archive: {}",
                sanitize_for_display(&fca_path_utf8)
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

/// Streams one file entry's contents into `writer`. Dispatches on the
/// [`ArchiveSource`] kind captured by the metadata pass.
///
/// FORMAT.md §9.10: on shrink, type change, or pre-copy growth — fail.
/// On growth during the copy after the fresh metadata check — copy
/// exactly the declared size, keeping the archive self-consistent.
fn stream_source_file<W: Write>(
    entry: &ArchiveEntry,
    source: &ArchiveSource,
    writer: &mut W,
) -> Result<(), CryptoError> {
    let source_path = entry
        .source_path
        .as_ref()
        .ok_or(CryptoError::InternalInvariant(
            "Manifest entry missing source_path during content streaming",
        ))?;

    match source {
        ArchiveSource::RootFile(file) => stream_single_file_root(entry, file, source_path, writer),
        ArchiveSource::RootDir(root) => {
            stream_directory_descendant(root, entry, source_path, writer)
        }
    }
}

/// Single-file root content stream: reads from the handle held since
/// the metadata pass, so no path is resolved again and a leaf or
/// ancestor swap between the passes cannot substitute the source. The
/// only mutation still reachable is through the file itself (same
/// inode); the fresh length check below catches it. The type re-check
/// is defense-in-depth at this re-use boundary. `source` is the
/// original input path, used for diagnostics only.
fn stream_single_file_root<W: Write>(
    entry: &ArchiveEntry,
    file: &File,
    source: &Path,
    writer: &mut W,
) -> Result<(), CryptoError> {
    let metadata = file.metadata().map_err(CryptoError::Io)?;
    require_regular_file(&metadata, "Source", source)?;
    if metadata.len() != entry.size {
        return Err(size_changed_error(
            entry.size,
            metadata.len(),
            &sanitize_path_for_display(source),
        ));
    }

    let mut reader = file;
    copy_exact_n(&mut reader, writer, entry.size, source_shrank_error)
}

/// Error for a source file that hit EOF before its manifest-declared
/// size during the content pass: the file shrank after the fresh
/// metadata check, and FORMAT.md §9.10 requires encryption to fail.
fn source_shrank_error() -> CryptoError {
    CryptoError::InvalidInput("Source file shrank during archiving".to_string())
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
    // O_NONBLOCK so a FIFO substituted for the source file cannot
    // block the open; the type check below rejects it. No effect on
    // regular-file reads.
    #[cfg(unix)]
    {
        use cap_fs_ext::OpenOptionsSyncExt;
        options.nonblock(true);
    }
    let mut file = parent
        .open_with(&file_name, &options)
        .map_err(CryptoError::Io)?;

    let metadata = file.metadata().map_err(CryptoError::Io)?;
    reject_windows_reparse_point_cap(&metadata, "Source", &file_name)?;
    if !metadata.is_file() {
        return Err(CryptoError::InvalidInput(format!(
            "Source is no longer a regular file: {}",
            sanitize_for_display(&file_name.to_string_lossy())
        )));
    }
    if metadata.len() != entry.size {
        return Err(size_changed_error(
            entry.size,
            metadata.len(),
            &sanitize_for_display(&file_name.to_string_lossy()),
        ));
    }

    copy_exact_n(&mut file, writer, entry.size, source_shrank_error)
}

/// A validated source tree prepared for archiving. It contains the manifest,
/// its serialized form, and the retained [`ArchiveSource`] used to read file
/// contents.
///
/// [`prepare_archive`] creates this value, and [`PreparedArchive::write_to`]
/// consumes it. Separating the phases lets encryption finish source
/// validation before cipher work and output staging begin. A staging file
/// created inside the input tree therefore cannot become archive content.
/// Files created after preparation are not included.
pub(crate) struct PreparedArchive {
    manifest: Manifest,
    manifest_bytes: Vec<u8>,
    entry_count: u32,
    manifest_len: u32,
    source: ArchiveSource,
}

/// Performs the FCA metadata phase for `input_path`: input validation,
/// source-tree traversal, tree validation, manifest serialization, and all
/// writer-side limit checks. It creates no output and performs no cipher work.
///
/// The returned [`PreparedArchive`] retains the opened source file or source
/// directory handle. The later content phase therefore does not resolve the
/// user-supplied path again.
pub(crate) fn prepare_archive(
    input_path: impl AsRef<Path>,
    limits: ArchiveLimits,
) -> Result<PreparedArchive, CryptoError> {
    let input_path = input_path.as_ref();
    let limits = limits.validate()?;

    // Defense-in-depth: api.rs runs validate_encrypt_input up-front, but
    // direct callers and any TOCTOU shift between that check and now
    // get re-validated here.
    validate_encrypt_input(input_path)?;

    // Pass 1: metadata-only manifest. The returned `ArchiveSource`
    // (open file handle or directory capability) is held across both
    // passes so the content pass never resolves the source path
    // through the kernel a second time.
    let (manifest, source) = build_manifest(input_path, &limits)?;

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

    Ok(PreparedArchive {
        manifest,
        manifest_bytes,
        entry_count,
        manifest_len,
        source,
    })
}

impl PreparedArchive {
    /// Writes the prepared archive to `writer`: FCA header, serialized
    /// manifest, and file contents in canonical manifest order. File contents
    /// are read from the retained source. Returns the writer for finalization.
    pub(crate) fn write_to<W: Write>(self, mut writer: W) -> Result<W, CryptoError> {
        // FCA writers set `archive_ext_len` to zero. The field is
        // reserved for later versions, but FCA archive version 0x01
        // defines no archive-level extension tags.
        writer = write_fca_header(
            writer,
            self.entry_count,
            0,
            self.manifest_len,
            self.manifest.total_file_bytes,
        )?;
        // Preserve the embedded stream error so `From<io::Error>` can
        // convert it to the corresponding `CryptoError` variant.
        writer.write_all(&self.manifest_bytes)?;

        // Write file contents in canonical manifest order, using the
        // source file or directory handle retained during preparation.
        for entry in &self.manifest.entries {
            if entry.kind == ArchiveEntryKind::File {
                stream_source_file(entry, &self.source, &mut writer)?;
            }
        }

        Ok(writer)
    }
}

/// Archives a file or directory in one call by running [`prepare_archive`]
/// followed by [`PreparedArchive::write_to`]. Returns the writer for
/// finalization.
///
/// Production encryption calls the phases separately so preparation finishes
/// before the ciphertext staging file exists. This helper is limited to tests
/// and fuzzing code, where the caller does not create output inside the source
/// tree.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn archive<W: Write>(
    input_path: impl AsRef<Path>,
    writer: W,
    limits: ArchiveLimits,
) -> Result<W, CryptoError> {
    prepare_archive(input_path, limits)?.write_to(writer)
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

    /// Wide-tree fd regression: with eager child opens, the walk held
    /// one open descriptor per discovered sibling subdirectory, so a
    /// directory wider than the process fd limit failed to encrypt
    /// with EMFILE. Deferred opens keep live handles at O(depth); the
    /// metadata pass over 200 sibling directories must succeed under a
    /// 64-descriptor soft limit. Relies on the workspace convention of
    /// running tests with `--test-threads=1` (the limit is process-wide
    /// while the guard is active). Linux/macOS only — matches the
    /// `rustix` dev-dependency that provides the safe setrlimit.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn walk_directory_handles_wide_tree_under_low_fd_limit() {
        use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("wide");
        fs::create_dir(&root).unwrap();
        for i in 0..200 {
            fs::create_dir(root.join(format!("d{i:03}"))).unwrap();
        }

        // Restores the saved limit even if the assertion below panics,
        // so later tests in the same process run unrestricted.
        struct RestoreNofile(Rlimit);
        impl Drop for RestoreNofile {
            fn drop(&mut self) {
                let _ = rustix::process::setrlimit(rustix::process::Resource::Nofile, self.0);
            }
        }
        let saved = getrlimit(Resource::Nofile);
        let _restore = RestoreNofile(saved);
        setrlimit(
            Resource::Nofile,
            Rlimit {
                current: Some(64),
                maximum: saved.maximum,
            },
        )
        .expect("lower the NOFILE soft limit");

        let (manifest, _source) =
            build_manifest(&root, &ArchiveLimits::default()).expect("wide tree must walk");
        assert_eq!(manifest.entries.len(), 201, "root + 200 subdirectories");
    }

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

    /// Files created beneath the source root after [`prepare_archive`]
    /// returns are not included when the prepared archive is written. This
    /// covers an encryption staging file created inside the input tree.
    #[test]
    fn prepare_then_write_excludes_files_created_after_prepare() {
        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("docs");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("a.txt"), b"original").unwrap();

        let prepared = prepare_archive(&dir, ArchiveLimits::default()).unwrap();
        fs::write(dir.join("late.txt"), b"created after prepare").unwrap();

        let buf = prepared.write_to(Vec::new()).unwrap();
        let restored_root = unarchive(
            Cursor::new(buf),
            out.path(),
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
        )
        .unwrap();

        assert_eq!(fs::read(restored_root.join("a.txt")).unwrap(), b"original");
        assert!(
            !restored_root.join("late.txt").exists(),
            "file created after prepare must not be archived"
        );
        let names: Vec<_> = fs::read_dir(&restored_root)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            names.len(),
            1,
            "restored tree must hold only a.txt, got {names:?}"
        );
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

    /// On the supported platforms (Linux, macOS, Windows — the CI matrix)
    /// a directory input passes `validate_encrypt_input`, mirroring the
    /// extractor's `decode::tests::directory_root_allowed_on_supported_platform`.
    /// The rejection fires only on other targets and cannot run here, but
    /// this pins that the guard does not spuriously reject if
    /// `DIRECTORY_PROMOTION_SUPPORTED` is ever inverted.
    #[test]
    fn directory_input_allowed_on_supported_platform() {
        let src = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("d");
        fs::create_dir(&dir).unwrap();
        validate_encrypt_input(&dir)
            .expect("a directory input must be allowed on a supported platform");
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
        assert!(matches!(
            err,
            CryptoError::ArchiveEntryCountCapExceeded { .. }
        ));
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
        assert!(matches!(
            err,
            CryptoError::ArchiveTotalBytesCapExceeded { .. }
        ));
    }

    /// Spec §9.6: a source name longer than the per-component byte cap
    /// must reject during the metadata pass — without the cap, the
    /// writer would emit an archive whose `.incomplete` working name
    /// exceeds the 255-byte filesystem limit at extraction time.
    /// Unix-only: a 250-byte filename near the Windows `MAX_PATH`
    /// ceiling cannot be reliably created in a tempdir there.
    #[cfg(unix)]
    #[test]
    fn rejects_over_long_component_in_source() {
        let src = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("d");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("n".repeat(250)), b"x").unwrap();

        let mut buf = Vec::new();
        let err = archive(&dir, &mut buf, ArchiveLimits::default()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: crate::archive::path::COMPONENT_TOO_LONG,
                ..
            }
        ));
        assert!(buf.is_empty(), "writer must not emit bytes when caps fail");
    }

    /// A root name exactly at the per-component byte cap round-trips:
    /// its 255-byte `.incomplete` working name is still creatable on
    /// every supported filesystem. Unix-only for the same `MAX_PATH`
    /// reason as the rejection test above.
    #[cfg(unix)]
    #[test]
    fn round_trip_component_at_byte_cap() {
        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let name = "n".repeat(244);
        let src_file = src.path().join(&name);
        fs::write(&src_file, b"payload").unwrap();

        let final_path = round_trip(&src_file, out.path());
        assert_eq!(final_path, out.path().join(&name));
        assert_eq!(fs::read(&final_path).unwrap(), b"payload");
    }

    /// Spec §9.6: a Windows-reserved device name in the source tree
    /// must reject during the metadata pass — otherwise the writer
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
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "Windows-reserved device name",
                ..
            }
        ));
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
    /// `archive_file_mode` on the writer side and `chmod_file_handle`
    /// on the reader side. For a single-file root the reader-side
    /// chmod runs post-rename via `apply_root_file_mode` (FORMAT.md
    /// §9.11 step 16); descendant-file chmods run post-copy inside
    /// the staged 0o700 root.
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

    /// FORMAT.md §9.10: writers must not store setuid, setgid, or
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
    /// the apply-modes pass must run after children are created.
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

    /// The source-tree walker must not consume O(depth) of process
    /// stack. Builds a deep tree under raised `ArchiveLimits` and
    /// runs the writer on a 128 KiB-stack thread: a recursive walker
    /// overflows here; the iterative one succeeds.
    #[test]
    fn deep_source_tree_does_not_stack_overflow() {
        use std::thread;

        let src = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();

        // Single-byte components keep the absolute path under macOS
        // `PATH_MAX = 1024`. `fs::create_dir_all` hits that ceiling
        // before the walker does.
        let depth: usize = 400;
        let root = src.path().join("root");
        let mut p = root.clone();
        for _ in 0..depth {
            p = p.join("a");
        }
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("leaf.txt"), b"deep").unwrap();

        let limits = ArchiveLimits::default()
            .with_max_path_depth((depth + 8) as u32)
            .with_max_path_bytes(((depth * 2) + 64) as u32);
        let src_root = root;
        let out_root = out.path().to_path_buf();

        // 128 KiB stack: too small for `depth` recursive frames, so a
        // regression to recursion fails this test as a stack overflow
        // instead of passing silently. The iterative walker uses a
        // heap-backed `PendingDir` stack.
        let handle = thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                let mut buf = Vec::new();
                archive(&src_root, &mut buf, limits).expect("archive deep tree");
                unarchive(
                    Cursor::new(buf),
                    &out_root,
                    limits,
                    IncompleteOutputPolicy::DeleteOnError,
                )
                .expect("unarchive deep tree")
            })
            .expect("spawn small-stack thread");
        let final_path = handle.join().expect("small-stack worker panicked");

        let mut q = final_path;
        for _ in 0..depth {
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
    /// and content pass must fail. The single-file content pass reads
    /// from the held handle, so the mismatch is injected by recording
    /// a wrong size in the entry rather than by racing the file.
    #[test]
    fn stream_source_file_rejects_size_mismatch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("real.txt");
        fs::write(&path, b"actual content").unwrap();

        // 9999 ≠ actual file size → exercises the size-mismatch arm.
        let mut entry = make_entry("real.txt", ArchiveEntryKind::File, 9999, 0o644);
        entry.source_path = Some(path.clone());
        let source = ArchiveSource::RootFile(open_no_follow(&path).unwrap());

        let mut buf = Vec::new();
        let err = stream_source_file(&entry, &source, &mut buf).unwrap_err();
        assert!(format!("{err}").contains("size changed"));
    }

    /// Cap-std parity test: an attacker who replaces an intermediate
    /// directory with a symlink between the metadata pass and the
    /// content pass must be rejected. Drives `stream_source_file` with
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
        let source = ArchiveSource::RootDir(platform::open_anchor(&src_root).unwrap());

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
        let err = stream_source_file(&entry, &source, &mut buf).unwrap_err();
        // Encode-side symlink rejection from `walk_to_parent_readonly`
        // routes through `platform::classify_open_failure` with the
        // `SYMLINK_IN_ARCHIVE_SOURCE` label.
        assert!(
            format!("{err}").contains(platform::SYMLINK_IN_ARCHIVE_SOURCE),
            "expected `{}` rejection, got: {err}",
            platform::SYMLINK_IN_ARCHIVE_SOURCE,
        );
    }

    /// Creates a FIFO via the POSIX `mkfifo` utility. A subprocess
    /// keeps the crate free of an `unsafe` `libc::mkfifo` call
    /// (`rustix` exposes no FIFO creation on Apple targets).
    #[cfg(unix)]
    fn make_fifo(path: &Path) {
        let status = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .expect("spawn mkfifo");
        assert!(status.success(), "mkfifo failed for {}", path.display());
    }

    /// A FIFO swapped in for a single-file root between the metadata
    /// and content passes has no effect: the content pass reads from
    /// the handle held since the metadata pass, never from the path
    /// the FIFO now occupies.
    #[cfg(unix)]
    #[test]
    fn held_handle_ignores_fifo_swapped_for_file_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file = tmp.path().join("data.bin");
        fs::write(&file, b"trusted").unwrap();

        let source = ArchiveSource::RootFile(open_no_follow(&file).unwrap());
        let mut entry = make_entry("data.bin", ArchiveEntryKind::File, 7, 0o644);
        entry.source_path = Some(file.clone());

        fs::remove_file(&file).unwrap();
        make_fifo(&file);

        let mut buf = Vec::new();
        stream_source_file(&entry, &source, &mut buf).unwrap();
        assert_eq!(buf, b"trusted");
    }

    /// Single-file mirror of
    /// [`stream_source_file_rejects_intermediate_symlink_substitution`]:
    /// replacing an ancestor directory of the input path with a
    /// symlink to an attacker-controlled tree between the passes must
    /// not change what is archived. The held handle keeps the content
    /// pass on the original file, so the same-size attacker copy — a
    /// swap no size check can catch — is never read.
    #[cfg(unix)]
    #[test]
    fn held_handle_streams_original_after_ancestor_swap() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::TempDir::new().unwrap();
        let src_root = tmp.path().join("source");
        fs::create_dir_all(src_root.join("a").join("b")).unwrap();
        let input = src_root.join("a").join("b").join("file.txt");
        fs::write(&input, b"trusted").unwrap();

        // Metadata pass: open and hold the handle.
        let source = ArchiveSource::RootFile(open_no_follow(&input).unwrap());
        let mut entry = make_entry("file.txt", ArchiveEntryKind::File, 7, 0o644);
        entry.source_path = Some(input.clone());

        // Swap `a/b` for a symlink to a sibling holding a same-size
        // attacker file. A path-based re-open would resolve through
        // the symlink and pass the size check.
        let attacker = tmp.path().join("attacker");
        fs::create_dir(&attacker).unwrap();
        fs::write(attacker.join("file.txt"), b"hostile").unwrap();
        fs::remove_dir_all(src_root.join("a").join("b")).unwrap();
        symlink(&attacker, src_root.join("a").join("b")).unwrap();

        let mut buf = Vec::new();
        stream_source_file(&entry, &source, &mut buf).unwrap();
        assert_eq!(buf, b"trusted", "content must come from the held handle");
    }

    /// A FIFO as the encrypt input is rejected up front, before any
    /// archive bytes are produced. The lstat-based check never opens
    /// the FIFO, so nothing can block.
    #[cfg(unix)]
    #[test]
    fn rejects_fifo_input_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let fifo = tmp.path().join("pipe.bin");
        make_fifo(&fifo);

        let mut buf = Vec::new();
        let err = archive(&fifo, &mut buf, ArchiveLimits::default()).unwrap_err();
        assert!(
            format!("{err}").contains("Unsupported file type"),
            "expected unsupported-type rejection, got: {err}"
        );
    }

    /// The same FIFO swap aimed at a directory descendant: the
    /// capability-anchored content-pass re-open must reject it
    /// without blocking.
    #[cfg(unix)]
    #[test]
    fn stream_source_file_rejects_fifo_swapped_for_descendant() {
        let tmp = tempfile::TempDir::new().unwrap();
        let src_root = tmp.path().join("source");
        fs::create_dir_all(&src_root).unwrap();
        fs::write(src_root.join("file.txt"), b"trusted").unwrap();

        let source = ArchiveSource::RootDir(platform::open_anchor(&src_root).unwrap());

        let mut entry = make_entry("source/file.txt", ArchiveEntryKind::File, 7, 0o644);
        entry.source_path = Some(PathBuf::from("file.txt"));

        fs::remove_file(src_root.join("file.txt")).unwrap();
        make_fifo(&src_root.join("file.txt"));

        let mut buf = Vec::new();
        let err = stream_source_file(&entry, &source, &mut buf).unwrap_err();
        assert!(
            format!("{err}").contains("no longer a regular file"),
            "expected regular-file rejection, got: {err}"
        );
    }

    // -- Manifest-size cap during the walk ---------------------------------

    /// The manifest-size cap fires while the tree is walked: an entry
    /// recorded after the running serialized length crosses the cap is
    /// rejected, so writer memory is bounded near the cap instead of
    /// by the whole tree.
    #[test]
    fn record_entry_enforces_manifest_len_cap_during_walk() {
        use crate::archive::format::FCA_ENTRY_FIXED_SIZE;

        // Cap sized for exactly two single-byte-path entries.
        let one_entry = (FCA_ENTRY_FIXED_SIZE + 1) as u32;
        let limits = ArchiveLimits::default().with_max_manifest_bytes(2 * one_entry);

        let mut counters = ArchiveCounters::default();
        record_entry(&mut counters, "a", None, &limits).unwrap();
        record_entry(&mut counters, "b", None, &limits).unwrap();
        let err = record_entry(&mut counters, "c", None, &limits).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::ArchiveManifestLenCapExceeded { .. }
        ));
    }

    /// End-to-end: a tree whose manifest would exceed the cap rejects
    /// with the typed cap error and emits no archive bytes.
    #[test]
    fn rejects_tree_above_manifest_len_cap() {
        use crate::archive::format::FCA_ENTRY_FIXED_SIZE;

        let src = tempfile::TempDir::new().unwrap();
        let dir = src.path().join("d");
        fs::create_dir(&dir).unwrap();
        for i in 0..4 {
            fs::write(dir.join(format!("f{i}.txt")), b"x").unwrap();
        }

        // Room for the root entry and two children; the third child
        // crosses the cap mid-walk.
        let root_entry = FCA_ENTRY_FIXED_SIZE + "d".len();
        let child_entry = FCA_ENTRY_FIXED_SIZE + "d/f0.txt".len();
        let cap = (root_entry + 2 * child_entry) as u32;
        let limits = ArchiveLimits::default().with_max_manifest_bytes(cap);

        let mut buf = Vec::new();
        let err = archive(&dir, &mut buf, limits).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::ArchiveManifestLenCapExceeded { .. }
        ));
        assert!(buf.is_empty(), "writer must not emit bytes when caps fail");
    }
}
