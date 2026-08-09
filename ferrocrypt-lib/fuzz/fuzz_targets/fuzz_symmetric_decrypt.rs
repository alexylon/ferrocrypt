#![no_main]
//! End-to-end fuzz target for the passphrase decrypt pipeline. Drives
//! arbitrary bytes through `Decryptor::open` + `PassphraseDecryptor::decrypt`
//! to keep coverage on the full wire-format → MAC → AEAD path. The
//! fuzz harness ignores all errors (rejection is the expected outcome
//! for almost every input); we only care that the library never panics.

use std::fs;
use std::io::Write;

use ferrocrypt::Passphrase;
use ferrocrypt::{Decryptor, KdfLimit};
use libfuzzer_sys::fuzz_target;

/// Argon2id budget for the harness: a fuzzer-crafted but structurally
/// valid `argon2id` header may demand up to the 1 GiB default reader
/// ceiling per iteration, stalling the fuzzer. 8 MiB keeps real KDF
/// runs reachable while the cap-rejection arm stays covered.
const FUZZ_KDF_MEM_KIB: u32 = 8 * 1024;

fuzz_target!(|data: &[u8]| {
    let tmp_dir = tempfile::tempdir().unwrap();
    let input_path = tmp_dir.path().join("input.fcr");
    let output_dir = tmp_dir.path().join("output");
    fs::create_dir_all(&output_dir).unwrap();

    let mut f = fs::File::create(&input_path).unwrap();
    f.write_all(data).unwrap();
    drop(f);

    if let Ok(Decryptor::Passphrase(d)) = Decryptor::open(&input_path) {
        let passphrase = Passphrase::new("fuzz");
        let _ =
            d.kdf_limit(KdfLimit::new(FUZZ_KDF_MEM_KIB))
                .decrypt(passphrase, &output_dir, |_| {});
    }
});
