#![no_main]

//! Fuzzes the generic typed-payload recipient-string decoder via the
//! two-argument `fuzz_exports::decode_recipient_string`. Unlike
//! `fuzz_recipient_decode` (the public X25519-specialised wrapper with
//! the fixed default cap), this reaches arbitrary `type_name` values,
//! non-32-byte key material, the canonical-padding re-encode check,
//! and caller-chosen length caps up to the 20,000-character structural
//! ceiling.

use ferrocrypt::fuzz_exports::decode_recipient_string;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((cap_bytes, rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    // Cap in 0..=20_000 (the structural ceiling) so both the
    // cap-rejection arm and full-length decodes get exercised.
    let cap = usize::from(u16::from_le_bytes(*cap_bytes)) % 20_001;
    let Ok(s) = std::str::from_utf8(rest) else {
        return;
    };
    let _ = decode_recipient_string(s, cap);
});
