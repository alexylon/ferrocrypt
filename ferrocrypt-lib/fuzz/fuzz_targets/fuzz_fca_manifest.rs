#![no_main]

//! Fuzzes the full FCA manifest pipeline: header parse → manifest
//! bytes read → `parse_manifest_bytes` (per-entry validation + path
//! grammar + tree-shape validation).
//!
//! Spec §20 manifest invariants — on a successful parse, the returned
//! [`Manifest`] MUST satisfy ALL of:
//!
//! - non-empty entries;
//! - `entries.len() <= limits.max_entry_count`;
//! - `total_file_bytes <= limits.max_total_plaintext_bytes`;
//! - every path is unique under exact equality;
//! - every path is unique under ASCII-case-insensitive comparison;
//! - every entry's mode fits in `0o000..=0o777`;
//! - every entry's path passes `validate_fca_path` (the same gate the
//!   parser ran during construction);
//! - every directory entry has `size == 0`.
//!
//! A regression in any of these arms surfaces here as a panic.

use std::collections::HashSet;

use ferrocrypt::ArchiveLimits;
use ferrocrypt::fuzz_exports::{
    ArchiveEntryKind, ascii_case_collision_key, parse_fca_header, parse_manifest_bytes,
    validate_fca_path,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = ArchiveLimits::default();
    let mut reader = std::io::Cursor::new(data);

    let Ok(header) = parse_fca_header(&mut reader, limits) else {
        return;
    };

    // Read exactly `manifest_len` bytes from the cursor, mirroring
    // what `unarchive_inner` does at runtime.
    let pos = reader.position() as usize;
    let manifest_len = header.manifest_len as usize;
    let bytes = reader.get_ref();
    let Some(manifest_bytes) = bytes.get(pos..).and_then(|tail| tail.get(..manifest_len)) else {
        return;
    };

    let Ok(manifest) = parse_manifest_bytes(manifest_bytes, header, limits) else {
        return;
    };

    // §20 invariants.
    assert!(!manifest.entries.is_empty());
    assert!(manifest.entries.len() <= limits.max_entry_count as usize);
    assert!(manifest.total_file_bytes <= limits.max_total_plaintext_bytes);

    let mut exact: HashSet<String> = HashSet::new();
    let mut ascii_ci: HashSet<Vec<u8>> = HashSet::new();
    for e in &manifest.entries {
        assert!(exact.insert(e.path_utf8.clone()), "exact-duplicate path");
        assert!(
            ascii_ci.insert(ascii_case_collision_key(&e.path_utf8)),
            "ASCII-case-insensitive duplicate path"
        );
        assert!(e.mode <= 0o777, "mode out of range: 0o{:o}", e.mode);
        validate_fca_path(&e.path_utf8, limits)
            .expect("path that survived the parser must pass validate_fca_path");
        if matches!(e.kind, ArchiveEntryKind::Directory) {
            assert_eq!(e.size, 0, "directory entry has non-zero size");
        }
    }
});
