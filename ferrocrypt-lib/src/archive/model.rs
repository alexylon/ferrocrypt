//! FCA model types: parsed header summary, entry kind, archive entry,
//! and full manifest.
//!
//! See `FORMAT.md` §9.

use std::ffi::OsString;
use std::path::PathBuf;

/// Parsed values from the 27-byte FCA fixed header. Resource caps have
/// already been applied; the consumer can use these counts/lengths to
/// drive bounded allocations.
#[derive(Debug, Clone, Copy)]
pub struct FcaHeader {
    /// Number of manifest entries (`FORMAT.md` §9).
    pub entry_count: u32,
    /// Byte length of the FCA archive-level TLV region (`archive_ext`)
    /// that immediately follows the fixed header. Native writers emit
    /// zero; readers parse + validate any non-zero region under
    /// the no-known-critical policy.
    pub archive_ext_len: u32,
    /// Byte length of the serialised manifest that follows `archive_ext`.
    pub manifest_len: u32,
    /// Sum of `size` across every file entry in the manifest.
    pub total_file_bytes: u64,
}

/// Archive entry classification per FCA `kind` byte: regular file or
/// directory. FCA archive version 0x01 defines no other kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveEntryKind {
    /// Regular file; `size` is the cleartext byte length.
    File,
    /// Directory; `size` must be `0`.
    Directory,
}

/// One manifest entry plus the (writer-only) source-file path used by
/// the content pass. The FCA path is always stored as `path_utf8`;
/// downstream code that needs a `Path` constructs one on demand.
#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    /// File or directory classification.
    pub kind: ArchiveEntryKind,
    /// Forward-slash-separated archive path (`FORMAT.md` §9.6 grammar).
    pub path_utf8: String,
    /// POSIX-style mode bits the reader applies to the extracted entry.
    pub mode: u32,
    /// Cleartext byte length for files; `0` for directories.
    pub size: u64,
    /// Set by the writer's metadata pass so the content pass can reopen
    /// the source file no-follow. Readers leave this `None`; the reader
    /// walks the manifest's `path_utf8` component-by-component through
    /// the hardened platform backend, never opening by absolute source
    /// path.
    pub source_path: Option<PathBuf>,
    /// Identity of the source file recorded by the writer's metadata
    /// pass, so the content pass can confirm that the file it reopens
    /// by name is the one that was recorded. The pair is the device and
    /// inode number, the same identity `fs::atomic::file_identity`
    /// reads.
    ///
    /// `None` wherever no comparison is possible: readers, directory
    /// entries, a single-file root streamed from a handle held since
    /// the metadata pass, a filesystem that reports no inode number,
    /// and every target outside Unix, where a directory listing carries
    /// no identity at all.
    pub source_id: Option<(u64, u64)>,
    /// Per-entry TLV extension bytes (`entry_ext`). Native writers emit
    /// an empty `Vec`; readers populate it with the raw bytes of the
    /// region after structural + canonicality validation. Opaque to
    /// the model — interpretation is the caller's responsibility.
    pub entry_ext: Vec<u8>,
}

/// Fully validated FCA manifest, ready to drive extraction (reader)
/// or content streaming (writer).
#[derive(Debug, Clone)]
pub struct Manifest {
    /// Manifest entries in writer-canonical order.
    pub entries: Vec<ArchiveEntry>,
    /// Sum of `size` across every file entry; matches the header's
    /// `total_file_bytes` after parse-time validation.
    pub total_file_bytes: u64,
    /// Top-level component shared by every entry's `path_utf8`.
    pub root_name: OsString,
    /// `true` when the manifest's single entry is a regular file at the
    /// root; `false` for directory roots with one or more children.
    pub root_is_file: bool,
    /// Cached `mode` of the root entry. Captured during
    /// `validate_manifest_tree` so the directory-mode apply step does
    /// not re-scan up to 250k entries on every extraction.
    pub root_mode: u32,
}

/// Test-only constructor for an [`ArchiveEntry`] without the writer's
/// source fields (the reader's view, plus most parser-side test
/// fixtures). Single source of truth for the `kind / path_utf8 /
/// mode / size / source_path: None / source_id: None / entry_ext:
/// empty` boilerplate shared by in-tree archive tests.
#[cfg(test)]
pub(crate) fn make_entry(path: &str, kind: ArchiveEntryKind, size: u64, mode: u32) -> ArchiveEntry {
    ArchiveEntry {
        kind,
        path_utf8: path.to_string(),
        mode,
        size,
        source_path: None,
        source_id: None,
        entry_ext: Vec::new(),
    }
}
