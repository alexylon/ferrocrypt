#![no_main]

//! Fuzzes the `private.key` header parser and shape validator.
//!
//! In v1 only `private.key` has a binary on-disk layout
//! (`public.key` is a text file carrying a Bech32 `fcr1…` string and
//! is fuzzed via `fuzz_recipient_decode`). The bytes are passed to
//! `parse_private_key_header` and — on success — to
//! `validate_private_key_shape` so the second-stage structural checks
//! (algorithm byte, total-size consistency between declared `ext_len`
//! and the on-disk body) are also exercised.

use ferrocrypt::fuzz_exports::{parse_private_key_header, validate_private_key_shape};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(header) = parse_private_key_header(data) else {
        return;
    };
    let _ = validate_private_key_shape(data, &header);
});
