#![no_main]

//! Fuzzes `parse_fca_header` — the 23-byte fixed FCA header parser.
//!
//! Spec invariant (§20): on success, the returned [`FcaHeader`] values
//! MUST be inside the supplied [`ArchiveLimits`]. Catches a regression
//! in the resource-cap arms of the parser.

use ferrocrypt::ArchiveLimits;
use ferrocrypt::fuzz_exports::parse_fca_header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = ArchiveLimits::default();
    let mut reader = std::io::Cursor::new(data);
    if let Ok(header) = parse_fca_header(&mut reader, limits) {
        assert!(header.entry_count >= 1);
        assert!(header.entry_count <= limits.max_entry_count);
        assert!(header.manifest_len >= 1);
        assert!(header.manifest_len <= limits.max_manifest_bytes);
        assert!(header.total_file_bytes <= limits.max_total_plaintext_bytes);
    }
});
