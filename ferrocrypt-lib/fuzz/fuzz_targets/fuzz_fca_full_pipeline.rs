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
//! Each iteration creates a fresh tempdir for `output_dir`. Slower
//! than parser-only targets (filesystem ops dominate) but the only
//! way to fuzz the post-parse extraction logic.

use ferrocrypt::ArchiveLimits;
use ferrocrypt::fuzz_exports::unarchive_for_fuzz;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let _ = unarchive_for_fuzz(data, dir.path(), ArchiveLimits::default());
});
