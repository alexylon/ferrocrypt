#![no_main]

//! Fuzzes `decode_x25519_recipient_string` — the Bech32 (`fcr1…`) recipient string
//! parser. Covers HRP mismatch, bad checksum, and payload length
//! validation. This is the only fully-public parser entry point in
//! the set and does not require the `fuzzing` feature.

use ferrocrypt::decode_x25519_recipient_string;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = decode_x25519_recipient_string(s);
    }
});
