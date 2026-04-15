#![no_main]

//! Fuzzes `detect_encryption_mode` — the public entry point that reads
//! the first 27 bytes of a candidate file, runs replication decode,
//! and decides whether it is a symmetric `.fcr`, a hybrid `.fcr`, or
//! not a FerroCrypt file at all. Written to a real temp file so the
//! actual `File::read` path is exercised end-to-end.

use std::io::Write;

use ferrocrypt::detect_encryption_mode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let tmp = match tempfile::NamedTempFile::new() {
        Ok(t) => t,
        Err(_) => return,
    };
    if tmp.as_file().write_all(data).is_err() {
        return;
    }
    let _ = detect_encryption_mode(tmp.path());
});
