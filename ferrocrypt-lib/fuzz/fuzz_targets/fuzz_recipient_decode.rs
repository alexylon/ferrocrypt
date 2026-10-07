#![no_main]

//! Fuzzes `decode_x25519_recipient_string` — the Bech32 (`fcr1…`) recipient string
//! parser. Covers HRP mismatch, bad checksum, and payload length
//! validation. This public parser does not require the `unstable-fuzzing`
//! feature.

use ferrocrypt::decode_x25519_recipient_string;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = decode_x25519_recipient_string(s);
    }
});
