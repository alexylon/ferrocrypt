#![no_main]

//! Fuzzes the full FCA manifest pipeline: header parse →
//! `archive_ext` read + TLV validation → manifest bytes read →
//! `parse_manifest_bytes` (per-entry validation including each
//! `entry_ext` TLV region + path grammar + tree-shape validation).
//!
//! Manifest invariants — on a successful parse, the returned
//! [`Manifest`] MUST satisfy ALL of:
//!
//! - non-empty entries;
//! - `entries.len() <= ArchiveLimits::ENTRY_COUNT_DEFAULT`;
//! - `total_file_bytes <= ArchiveLimits::TOTAL_PLAINTEXT_BYTES_DEFAULT`;
//! - every path is unique under exact equality;
//! - every path is unique under ASCII-case-insensitive comparison;
//! - every entry's mode fits in `0o000..=0o777`;
//! - every entry's path passes `validate_fca_path` (the same gate the
//!   parser ran during construction);
//! - every directory entry has `size == 0`;
//! - every entry's `entry_ext` byte length is
//!   `<= ArchiveLimits::ENTRY_EXT_BYTES_DEFAULT`;
//! - the sum of every entry's `entry_ext` byte length is
//!   `<= ArchiveLimits::TOTAL_ENTRY_EXT_BYTES_DEFAULT`;
//! - re-serializing through the production writer gate
//!   (`serialize_manifest`) succeeds and is byte-identical — the
//!   mechanical form of the encrypt/decrypt symmetry rule, and the
//!   only coverage the writer side gets from fuzzing.
//!
//! A regression in any of these arms surfaces here as a panic.
//!
//! The target fuzzes the default configuration, so the cap bounds are
//! the published `ArchiveLimits::*_DEFAULT` constants rather than fields
//! read back from the value handed to the parser. Change both together
//! if this target ever fuzzes a non-default configuration.

use std::collections::HashSet;

use ferrocrypt::ArchiveLimits;
use ferrocrypt::fuzz_exports::{
    ArchiveEntryKind, ascii_case_collision_key, parse_fca_header, parse_manifest_bytes,
    serialize_manifest, validate_fca_path, validate_no_known_critical,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = ArchiveLimits::default();
    let mut reader = std::io::Cursor::new(data);

    let Ok(header) = parse_fca_header(&mut reader, limits) else {
        return;
    };

    // Read exactly `archive_ext_len` bytes and validate them under
    // the same no-known-critical TLV policy production uses, then
    // read exactly `manifest_len` bytes from the cursor. Mirrors
    // `unarchive_inner` end-to-end. The cap on
    // `header.archive_ext_len` was already enforced inside
    // `parse_fca_header`, so the pointer arithmetic here cannot
    // overflow under default limits.
    let pos = reader.position() as usize;
    let bytes = reader.get_ref();
    let archive_ext_len = header.archive_ext_len as usize;
    let manifest_len = header.manifest_len as usize;
    let Some(after_archive_ext) = pos.checked_add(archive_ext_len) else {
        return;
    };
    let Some(archive_ext_bytes) = bytes.get(pos..after_archive_ext) else {
        return;
    };
    if validate_no_known_critical(
        archive_ext_bytes,
        ArchiveLimits::ARCHIVE_EXT_BYTES_DEFAULT,
        ArchiveLimits::TLV_VALUE_BYTES_DEFAULT,
    )
    .is_err()
    {
        return;
    }
    let Some(manifest_bytes) = bytes
        .get(after_archive_ext..)
        .and_then(|tail| tail.get(..manifest_len))
    else {
        return;
    };

    let Ok(manifest) = parse_manifest_bytes(manifest_bytes, header, limits) else {
        return;
    };

    // Manifest invariants.
    assert!(!manifest.entries.is_empty());
    assert!(manifest.entries.len() <= ArchiveLimits::ENTRY_COUNT_DEFAULT as usize);
    assert!(manifest.total_file_bytes <= ArchiveLimits::TOTAL_PLAINTEXT_BYTES_DEFAULT);

    let mut exact: HashSet<String> = HashSet::new();
    let mut ascii_ci: HashSet<Vec<u8>> = HashSet::new();
    let mut total_entry_ext: u64 = 0;
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
        assert!(
            e.entry_ext.len() <= ArchiveLimits::ENTRY_EXT_BYTES_DEFAULT as usize,
            "entry_ext over per-entry cap: {} bytes",
            e.entry_ext.len()
        );
        total_entry_ext = total_entry_ext
            .checked_add(e.entry_ext.len() as u64)
            .expect("total entry_ext overflow");
    }
    assert!(
        total_entry_ext <= ArchiveLimits::TOTAL_ENTRY_EXT_BYTES_DEFAULT,
        "sum of entry_ext over total cap: {total_entry_ext} bytes"
    );

    // Writer/reader symmetry oracle: a manifest the reader accepted
    // must pass the writer gate and serialize byte-identically (parse
    // preserves wire order and every field verbatim).
    let reserialized = serialize_manifest(&manifest, limits)
        .expect("manifest accepted by the reader must pass the writer gate");
    assert_eq!(
        reserialized, manifest_bytes,
        "manifest re-serialization must be byte-identical"
    );
});
