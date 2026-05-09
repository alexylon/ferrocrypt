#![no_main]

//! Fuzzes `probe_recipient_mode` — the public entry point that reads
//! the v1 12-byte prefix and the recipient list of a candidate file
//! and classifies it as `UnauthenticatedRecipientMode::Passphrase`,
//! `UnauthenticatedRecipientMode::PublicKey`, or not a FerroCrypt file
//! at all. Written to a real temp file so the actual `File::read` path
//! is exercised end-to-end.

use std::io::Write;

use ferrocrypt::probe_recipient_mode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let tmp = match tempfile::NamedTempFile::new() {
        Ok(t) => t,
        Err(_) => return,
    };
    if tmp.as_file().write_all(data).is_err() {
        return;
    }
    let _ = probe_recipient_mode(tmp.path());
});
