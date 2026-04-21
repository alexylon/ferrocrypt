#![no_main]

//! Fuzzes the key-file header parser and layout validator.
//!
//! First byte of input selects whether to validate as a public-key file
//! or a private-key file (they differ in body layout and in the
//! expected type byte). The remaining bytes are passed verbatim to
//! `parse_key_file_header` and then — on success — to either
//! `validate_key_layout` (public: exact fixed size) or
//! `validate_private_key_body_shape` (private: fixed minimum plus
//! variable `ext_bytes`, plus data_len / ext_len consistency) so the
//! second-stage checks (algorithm, data_len, flags, total size) are
//! also exercised.

use ferrocrypt::fuzz_exports::{
    KEY_FILE_TYPE_PRIVATE, KEY_FILE_TYPE_PUBLIC, PUBLIC_KEY_DATA_SIZE, parse_key_file_header,
    validate_key_layout, validate_private_key_body_shape,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    if selector & 1 == 0 {
        let Ok(header) = parse_key_file_header(rest, KEY_FILE_TYPE_PUBLIC) else {
            return;
        };
        let _ = validate_key_layout(rest, &header, PUBLIC_KEY_DATA_SIZE);
    } else {
        let Ok(header) = parse_key_file_header(rest, KEY_FILE_TYPE_PRIVATE) else {
            return;
        };
        let _ = validate_private_key_body_shape(rest, &header);
    }
});
