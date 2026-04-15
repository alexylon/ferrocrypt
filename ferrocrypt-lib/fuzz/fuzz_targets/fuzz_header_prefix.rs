#![no_main]

//! Fuzzes the 27-byte triple-replicated header-prefix parser.
//!
//! First byte of input selects `TYPE_SYMMETRIC` or `TYPE_HYBRID` as the
//! expected type; the rest is fed to `read_header_from_reader` via a
//! `Cursor`. Exercises replication decode + magic byte + type check
//! without running any KDF.

use std::io::Cursor;

use ferrocrypt::fuzz_exports::{TYPE_HYBRID, TYPE_SYMMETRIC, read_header_from_reader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((selector, tail)) = data.split_first() else {
        return;
    };
    let expected_type = if selector & 1 == 0 {
        TYPE_SYMMETRIC
    } else {
        TYPE_HYBRID
    };
    let mut cursor = Cursor::new(tail);
    let _ = read_header_from_reader(&mut cursor, expected_type);
});
