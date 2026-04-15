#![no_main]

//! Fuzzes the key-file header parser and layout validator.
//!
//! First byte of input selects whether to validate as a public-key file
//! or a private-key file (they differ in `expected_data_size` and in
//! the expected type byte). The remaining bytes are passed verbatim to
//! `parse_key_file_header` and then — on success — to
//! `validate_key_v2_layout` so the second-stage checks (algorithm,
//! data_len, flags, total size) are also exercised.

use ferrocrypt::fuzz_exports::{
    KEY_FILE_TYPE_PUBLIC, KEY_FILE_TYPE_SECRET, PUBLIC_KEY_DATA_SIZE, SECRET_KEY_DATA_SIZE,
    parse_key_file_header, validate_key_v2_layout,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let (expected_type, expected_data_size) = if selector & 1 == 0 {
        (KEY_FILE_TYPE_PUBLIC, PUBLIC_KEY_DATA_SIZE)
    } else {
        (KEY_FILE_TYPE_SECRET, SECRET_KEY_DATA_SIZE)
    };
    let Ok(header) = parse_key_file_header(rest, expected_type) else {
        return;
    };
    let _ = validate_key_v2_layout(rest, &header, expected_data_size);
});
