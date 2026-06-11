#![no_main]

//! End-to-end FCA reader fuzzer: drives `archive::unarchive` on
//! arbitrary input bytes through every stage — header parse,
//! `archive_ext` TLV validation, manifest parse, tree validation,
//! content streaming, atomic promotion — and asserts the harness
//! never panics.
//!
//! Complements the per-stage parser fuzzers (`fuzz_fca_header`,
//! `fuzz_fca_manifest`, `fuzz_archive_path`, `fuzz_tlv`) by exercising
//! the cross-stage interactions that those targets cannot reach in
//! isolation: `archive_ext` TLV bytes feeding into the manifest parse,
//! tree-validation rejecting after structural parse, content
//! streaming surfacing typed errors via `copy_exact_n`, and the
//! `.incomplete` cleanup loop on every error path.
//!
//! The target also pins the `DeleteOnError` cleanup contract as an
//! oracle. The harness induces no external I/O failures, so cleanup
//! has no legitimate reason to leave residue: on error, no
//! `.incomplete` entry may remain in the output directory; on
//! success, the returned path must exist and no `.incomplete` entry
//! other than a final output legitimately named that way may remain.
//!
//! Each iteration creates a fresh tempdir for `output_dir`. Slower
//! than parser-only targets (filesystem ops dominate) but the only
//! way to fuzz the post-parse extraction logic.

use std::ffi::OsStr;
use std::path::Path;

use ferrocrypt::ArchiveLimits;
use ferrocrypt::fuzz_exports::{INCOMPLETE_SUFFIX, unarchive_for_fuzz};
use libfuzzer_sys::fuzz_target;

/// Returns `true` if any entry directly under `dir`, except an entry
/// named `exclude`, ends with the `.incomplete` staging suffix.
/// `exclude` covers a successful extraction whose archive-chosen root
/// name itself ends with the suffix — a valid FCA name that must not
/// count as staging residue.
fn has_incomplete_residue(dir: &Path, exclude: Option<&OsStr>) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        let name = entry.file_name();
        if exclude == Some(name.as_os_str()) {
            return false;
        }
        name.to_string_lossy().ends_with(INCOMPLETE_SUFFIX)
    })
}

fuzz_target!(|data: &[u8]| {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };

    match unarchive_for_fuzz(data, dir.path(), ArchiveLimits::default()) {
        Ok(path) => {
            assert!(
                std::fs::symlink_metadata(&path).is_ok(),
                "unarchive returned Ok but the output path is missing: {path:?}"
            );
            assert!(
                !has_incomplete_residue(dir.path(), path.file_name()),
                "staged .incomplete residue left after a successful extraction"
            );
        }
        Err(_) => {
            assert!(
                !has_incomplete_residue(dir.path(), None),
                "DeleteOnError left .incomplete residue after a failed extraction"
            );
        }
    }
});
