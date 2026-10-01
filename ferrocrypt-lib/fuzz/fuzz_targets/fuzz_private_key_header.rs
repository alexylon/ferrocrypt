#![no_main]

//! Fuzzes the `private.key` header parser and shape validator.
//!
//! Only `private.key` has a binary layout; the text `public.key` has its own
//! `fuzz_public_key_file` target. This target passes arbitrary bytes to the
//! structural validator `validate_private_key_shape`: the `public.key` check,
//! the fixed header, the file length, the type name, and the X25519 lengths.

use ferrocrypt::fuzz_exports::validate_private_key_shape;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = validate_private_key_shape(data);
});
