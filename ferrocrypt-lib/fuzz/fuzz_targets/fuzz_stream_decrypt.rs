#![no_main]

//! Fuzzes the STREAM-BE32 `DecryptReader` directly. It covers chunk
//! refill, exact-chunk lookahead, truncation, authentication failure,
//! trailing-data classification, and the rule that later reads fail
//! after the first error. End-to-end decrypt targets cannot reach this
//! layer with arbitrary ciphertext because the header MAC is verified
//! first; this target tests the cipher layer directly with a fixed key
//! and nonce.
//!
//! Corpus seeds produced by `gen_seeds` include canonical ciphertexts under
//! the same fixed key and nonce, so successful decryption remains reachable,
//! plus authenticated must-reject shapes that mutation cannot synthesize.
//! The target checks two properties:
//!
//! - **Round trip.** STREAM is deterministic. Re-encrypting successfully
//!   decrypted plaintext must reproduce the input exactly. A difference
//!   means the reader accepted chunking that the writer does not produce.
//! - **Terminal failure.** After any rejected input, another read must also
//!   fail. Returning bytes or a clean end-of-file result would resume a
//!   rejected stream.

use std::io::Read as _;

use ferrocrypt::fuzz_exports::{encrypt_stream_for_fuzz, stream_decryptor_for_fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reader = stream_decryptor_for_fuzz(data);
    let mut plaintext = Vec::new();
    match reader.read_to_end(&mut plaintext) {
        Ok(_) => {
            let reencrypted = encrypt_stream_for_fuzz(&plaintext)
                .expect("plaintext that decrypted must re-encrypt");
            // Avoid `assert_eq!` because it would print both buffers,
            // each up to about 65 KB. The saved fuzzing input already
            // contains the original bytes.
            assert!(
                reencrypted == data,
                "STREAM round-trip diverged: re-encrypted {} bytes vs input {} bytes",
                reencrypted.len(),
                data.len()
            );
        }
        Err(_) => {
            let mut probe = [0u8; 64];
            if let Ok(n) = reader.read(&mut probe) {
                panic!("DecryptReader served a read of {n} bytes after a terminal error");
            }
        }
    }
});
