#![no_main]

//! Fuzzes `parse_fca_header` — the 27-byte fixed FCA header parser
//! (FORMAT.md §9.2).
//!
//! Spec invariant: on success, the returned [`FcaHeader`] values MUST
//! be inside the supplied [`ArchiveLimits`]. Catches a regression in
//! the resource-cap arms of the parser, including the `archive_ext_len`
//! cap added with FCA's forward-compatibility hooks.

use ferrocrypt::ArchiveLimits;
use ferrocrypt::fuzz_exports::parse_fca_header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = ArchiveLimits::default();
    let mut reader = std::io::Cursor::new(data);
    if let Ok(header) = parse_fca_header(&mut reader, limits) {
        assert!(header.entry_count >= 1);
        assert!(header.entry_count <= limits.max_entry_count);
        assert!(header.archive_ext_len <= limits.max_archive_ext_bytes);
        assert!(header.manifest_len >= 1);
        assert!(header.manifest_len <= limits.max_manifest_bytes);
        assert!(header.total_file_bytes <= limits.max_total_plaintext_bytes);
    }
});
