#![no_main]

//! Fuzzes `validate_fca_path` — the FCA archive-path grammar gate
//! shared by writer (encode-side metadata pass) and reader
//! (manifest-parse).
//!
//! The validator takes `&str`, so the harness rejects non-UTF-8 input
//! up-front. Manifest bytes that survive UTF-8 decoding by the parser
//! are exactly what reaches `validate_fca_path` in production, so this
//! is the right input shape — not raw bytes via `OsStr::from_bytes`
//! (which would test a code path that doesn't exist for FCA).

use ferrocrypt::ArchiveLimits;
use ferrocrypt::fuzz_exports::validate_fca_path;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = validate_fca_path(s, ArchiveLimits::default());
    }
});
