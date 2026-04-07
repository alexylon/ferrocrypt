#![no_main]

use std::fs;
use std::io::Write;

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::symmetric_encryption;
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
    let _ = symmetric_encryption(&input_path, &output_dir, &passphrase, None, |_| {});
});
