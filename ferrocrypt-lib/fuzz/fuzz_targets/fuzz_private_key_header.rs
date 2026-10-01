#![no_main]

//! Fuzzes the `private.key` header parser and shape validator.
//!
//! Only `private.key` has a binary on-disk layout; the text-based
//! `public.key` grammar has its own `fuzz_public_key_file` target. This
//! target passes arbitrary bytes to `validate_private_key_shape`, which
//! runs `PrivateKeyHeader::parse` (magic, kind, version, `key_flags`, and
//! the structural caps of the length fields and KDF parameters), then the
//! size-consistency check between declared lengths and the actual on-disk
//! body, then the type-name and X25519 checks.

use ferrocrypt::fuzz_exports::validate_private_key_shape;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = validate_private_key_shape(data);
});
