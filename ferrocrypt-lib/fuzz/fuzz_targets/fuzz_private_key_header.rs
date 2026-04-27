#![no_main]

//! Fuzzes the v1 `private.key` header parser and shape validator.
//!
//! In v1 only `private.key` has a binary on-disk layout (`public.key`
//! is a text file carrying a Bech32 `fcr1…` string and is fuzzed via
//! `fuzz_recipient_decode`). The bytes are passed to
//! `validate_private_key_shape`, which itself runs
//! `PrivateKeyHeader::parse` (magic / version / kind / `key_flags` /
//! length-field structural caps) and the second-stage size-consistency
//! check between declared lengths and the actual on-disk body.

use ferrocrypt::fuzz_exports::validate_private_key_shape;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = validate_private_key_shape(data);
});
