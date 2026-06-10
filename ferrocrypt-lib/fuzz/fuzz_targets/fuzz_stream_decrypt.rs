#![no_main]

//! Fuzzes the STREAM-BE32 `DecryptReader` state machine directly —
//! chunk refill, the exact-chunk one-byte peek, truncation vs tamper
//! vs trailing-data classification, and the zeroize-and-park error
//! path. The MAC-gated end-to-end decrypt targets can never reach
//! this layer with attacker-shaped bytes (the header MAC rejects
//! first); this target feeds the cipher layer directly under a fixed
//! key and nonce.
//!
//! Corpus seeds built by `gen_seeds` are valid ciphertexts under the
//! same fixed key/nonce, so the success branches (`decrypt_next`,
//! final-chunk handling) stay reachable. STREAM is deterministic:
//! whenever an input decrypts, re-encrypting the recovered plaintext
//! must reproduce the input byte-for-byte — any divergence means the
//! reader accepted a non-canonical chunking the writer would never
//! emit.

use ferrocrypt::fuzz_exports::{decrypt_stream_for_fuzz, encrypt_stream_for_fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(plaintext) = decrypt_stream_for_fuzz(data) {
        let reencrypted =
            encrypt_stream_for_fuzz(&plaintext).expect("plaintext that decrypted must re-encrypt");
        // Manual compare: `assert_eq!` would dump both buffers
        // (up to ~65 KB each) into the crash log; the saved artifact
        // already carries the input.
        assert!(
            reencrypted == data,
            "STREAM round-trip diverged: re-encrypted {} bytes vs input {} bytes",
            reencrypted.len(),
            data.len()
        );
    }
});
