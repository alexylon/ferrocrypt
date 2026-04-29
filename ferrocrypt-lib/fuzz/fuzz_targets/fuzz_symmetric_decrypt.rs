#![no_main]
// `fuzz_symmetric_decrypt` exercises the deprecated decrypt entry point
// on purpose so coverage of the existing wire-format decode pipeline
// does not move under us mid-restructure. Step 10 swaps it for the new
// API.
#![allow(deprecated)]

use std::fs;
use std::io::Write;

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{SymmetricDecryptConfig, symmetric_decrypt};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let tmp_dir = tempfile::tempdir().unwrap();
    let input_path = tmp_dir.path().join("input.fcr");
    let output_dir = tmp_dir.path().join("output");
    fs::create_dir_all(&output_dir).unwrap();

    let mut f = fs::File::create(&input_path).unwrap();
    f.write_all(data).unwrap();
    drop(f);

    let passphrase = SecretString::from("fuzz".to_string());
    let config = SymmetricDecryptConfig::new(&input_path, &output_dir, passphrase);
    let _ = symmetric_decrypt(config, |_| {});
});
