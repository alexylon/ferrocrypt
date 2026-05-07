//! FCA model types: parsed header summary, entry kind, archive entry,
//! and full manifest.
//!
//! See `notes/archive_format/ARCHIVE_FORMAT.md` §14.2.

use std::ffi::OsString;
use std::path::PathBuf;

/// Parsed values from the 23-byte FCA fixed header. Resource caps have
/// already been applied; the consumer can use these counts/lengths to
/// drive bounded allocations.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FcaHeader {
    pub entry_count: u32,
    pub manifest_len: u32,
    pub total_file_bytes: u64,
}

/// Archive entry classification per FCA `kind` byte: regular file or
/// directory. v1 has no other kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchiveEntryKind {
    File,
    Directory,
}

/// One manifest entry plus the cached `PathBuf` and (writer-only)
/// source-file path used by later passes.
#[derive(Debug, Clone)]
pub(crate) struct ArchiveEntry {
    pub kind: ArchiveEntryKind,
    pub path_utf8: String,
    pub path: PathBuf,
    pub mode: u32,
    pub size: u64,
    /// Set by the writer's metadata pass so the content pass can reopen
    /// the source file no-follow. Readers leave this `None`; the reader
    /// walks the manifest's `path` component-by-component through the
    /// hardened platform backend, never opening by absolute source path.
    pub source_path: Option<PathBuf>,
}

/// Fully validated FCA manifest, ready to drive extraction (reader)
/// or content streaming (writer).
#[derive(Debug, Clone)]
pub(crate) struct Manifest {
    pub entries: Vec<ArchiveEntry>,
    pub total_file_bytes: u64,
    pub root_name: OsString,
    pub root_is_file: bool,
}
