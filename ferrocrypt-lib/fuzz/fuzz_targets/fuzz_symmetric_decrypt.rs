#![no_main]
//! End-to-end fuzz target for the passphrase decrypt pipeline. Drives
//! arbitrary bytes through `Decryptor::open` + `PassphraseDecryptor::decrypt`
//! to keep coverage on the full wire-format → MAC → AEAD path. The
//! fuzz harness ignores all errors (rejection is the expected outcome
//! for almost every input); we only care that the library never panics.

use std::fs;
use std::io::Write;

use ferrocrypt::Decryptor;
use ferrocrypt::secrecy::SecretString;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let tmp_dir = tempfile::tempdir().unwrap();
    let input_path = tmp_dir.path().join("input.fcr");
    let output_dir = tmp_dir.path().join("output");
    fs::create_dir_all(&output_dir).unwrap();

    let mut f = fs::File::create(&input_path).unwrap();
    f.write_all(data).unwrap();
    drop(f);

    if let Ok(Decryptor::Passphrase(d)) = Decryptor::open(&input_path) {
        let passphrase = SecretString::from("fuzz".to_string());
        let _ = d.decrypt(passphrase, &output_dir, |_| {});
    }
});
