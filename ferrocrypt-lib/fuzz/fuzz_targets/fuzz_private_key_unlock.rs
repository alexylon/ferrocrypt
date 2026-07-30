#![no_main]

//! Fuzzes the generic `private.key` load + unlock path over
//! attacker-controlled bytes.
//!
//! `fuzz_private_key_header` covers only the structural shape gate
//! (`validate_private_key_shape`). This target drives the generic unlock past
//! it — the KDF resource cap, the wrapped-secret cap, the total-length check,
//! type-name grammar, and AEAD-AAD unlock — with a fixed passphrase and a
//! tight 64 KiB Argon2id memory cap so the fuzzer cannot force a large
//! key-derivation allocation.

use ferrocrypt::fuzz_exports::open_private_key_for_fuzz;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = open_private_key_for_fuzz(data);
});
