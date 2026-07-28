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
//!
//! On `Ok`, the target asserts every property the FORMAT.md §9.6
//! grammar promises, so a regression that starts ACCEPTING hostile
//! paths — the security-relevant failure direction for a validator —
//! crashes the fuzzer instead of passing silently.
//!
//! The target fuzzes the default configuration, so the byte and depth
//! bounds are the published `ArchiveLimits::*_DEFAULT` constants rather
//! than fields read back from the value handed to the validator. Change
//! both together if this target ever fuzzes a non-default configuration.

use ferrocrypt::ArchiveLimits;
use ferrocrypt::fuzz_exports::{FCA_COMPONENT_MAX_BYTES, validate_fca_path};
use libfuzzer_sys::fuzz_target;

/// FORMAT.md §9.6 reserved device names, restated independently of
/// the production table on purpose: an oracle that read the same
/// constant would be true by construction.
const RESERVED_DEVICE_NAMES: &[&str] = &[
    "con",
    "prn",
    "aux",
    "nul",
    "clock$",
    "conin$",
    "conout$",
    "com0",
    "com1",
    "com2",
    "com3",
    "com4",
    "com5",
    "com6",
    "com7",
    "com8",
    "com9",
    "com\u{b9}",
    "com\u{b2}",
    "com\u{b3}",
    "lpt0",
    "lpt1",
    "lpt2",
    "lpt3",
    "lpt4",
    "lpt5",
    "lpt6",
    "lpt7",
    "lpt8",
    "lpt9",
    "lpt\u{b9}",
    "lpt\u{b2}",
    "lpt\u{b3}",
];

/// Asserts the FORMAT.md §9.6 grammar promises on a path the
/// validator accepted.
fn assert_accepted_path_invariants(path: &str) {
    assert!(!path.is_empty());
    assert!(path.len() <= ArchiveLimits::PATH_BYTES_DEFAULT as usize);
    assert!(!path.starts_with('/') && !path.ends_with('/'), "{path:?}");
    assert!(!path.contains("//"), "{path:?}");
    assert!(!path.contains('\0'), "{path:?}");
    assert!(!path.contains('\\'), "{path:?}");

    let components: Vec<&str> = path.split('/').collect();
    assert!(components.len() <= ArchiveLimits::PATH_DEPTH_DEFAULT as usize);
    for component in components {
        assert!(!component.is_empty(), "{path:?}");
        assert_ne!(component, ".");
        assert_ne!(component, "..");
        assert!(component.len() <= FCA_COMPONENT_MAX_BYTES, "{component:?}");
        assert!(!component.bytes().any(|b| b <= 0x1f), "{component:?}");
        assert!(
            !component.bytes().any(|b| b"<>:\"|?*".contains(&b)),
            "{component:?}"
        );
        assert!(
            !component.ends_with(' ') && !component.ends_with('.'),
            "{component:?}"
        );

        // The spec's reserved-device check is ASCII-case-insensitive
        // only, and Windows strips trailing spaces from the stem before
        // resolving it, so the oracle folds and trims the same way.
        let stem = component
            .split_once('.')
            .map_or(component, |(stem, _)| stem)
            .trim_end_matches(' ');
        let stem_lower = stem.to_ascii_lowercase();
        assert!(
            !RESERVED_DEVICE_NAMES.contains(&stem_lower.as_str()),
            "reserved device name accepted: {component:?}"
        );
    }

    for component in std::path::Path::new(path).components() {
        assert!(
            matches!(component, std::path::Component::Normal(_)),
            "non-normal host component accepted: {path:?}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let limits = ArchiveLimits::default();
        if validate_fca_path(s, limits).is_ok() {
            assert_accepted_path_invariants(s);
        }
    }
});
