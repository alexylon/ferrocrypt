#![no_main]

//! Fuzzes the generic `private.key` load + unlock path over
//! attacker-controlled bytes.
//!
//! `fuzz_private_key_header` exercises structural validation only. This target
//! exercises generic parsing and unlocking, including KDF policy and AEAD
//! authentication. A fixed passphrase and a 64 KiB Argon2id memory cap limit
//! the key-derivation allocation.

use ferrocrypt::fuzz_exports::open_private_key_for_fuzz;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = open_private_key_for_fuzz(data);
});
