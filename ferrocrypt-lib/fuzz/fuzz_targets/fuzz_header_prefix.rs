#![no_main]

//! Fuzzes the v1 `.fcr` encrypted-file header parser
//! (`read_encrypted_header`). Exercises prefix structural validation
//! (magic + version + kind + prefix_flags + header_len), `header_fixed`
//! parse, recipient-entry framing, and ext-region accounting without
//! running any KDF, recipient unwrap, or MAC verification.

use std::io::Cursor;

use ferrocrypt::fuzz_exports::{HeaderReadLimits, read_encrypted_header};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let _ = read_encrypted_header(&mut cursor, HeaderReadLimits::default());
});
