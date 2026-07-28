#![no_main]

//! Fuzzes `parse_fca_header` — the 27-byte fixed FCA header parser
//! (FORMAT.md §9.2).
//!
//! Spec invariant: on success, the returned [`FcaHeader`] values MUST
//! be inside the supplied [`ArchiveLimits`]. Catches a regression in
//! the resource-cap arms of the parser, including the `archive_ext_len`
//! cap added with FCA's forward-compatibility hooks.
//!
//! The target fuzzes the default configuration, so the bounds below are
//! the published `ArchiveLimits::*_DEFAULT` constants rather than fields
//! read back from the value handed to the parser. Change both together
//! if this target ever fuzzes a non-default configuration.

use ferrocrypt::ArchiveLimits;
use ferrocrypt::fuzz_exports::parse_fca_header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = ArchiveLimits::default();
    let mut reader = std::io::Cursor::new(data);
    if let Ok(header) = parse_fca_header(&mut reader, limits) {
        assert!(header.entry_count >= 1);
        assert!(header.entry_count <= ArchiveLimits::ENTRY_COUNT_DEFAULT);
        assert!(header.archive_ext_len <= ArchiveLimits::ARCHIVE_EXT_BYTES_DEFAULT);
        assert!(header.manifest_len >= 1);
        assert!(header.manifest_len <= ArchiveLimits::MANIFEST_BYTES_DEFAULT);
        assert!(header.total_file_bytes <= ArchiveLimits::TOTAL_PLAINTEXT_BYTES_DEFAULT);
    }
});
