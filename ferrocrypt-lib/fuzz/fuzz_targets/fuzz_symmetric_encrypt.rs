#![no_main]

use std::fs;
use std::io::Write;

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::symmetric_encrypt;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let tmp_dir = tempfile::tempdir().unwrap();
    let input_file = tmp_dir.path().join("input.bin");
    let output_dir = tmp_dir.path().join("output");
    fs::create_dir_all(&output_dir).unwrap();

    let mut f = fs::File::create(&input_file).unwrap();
    f.write_all(data).unwrap();
    drop(f);

    let passphrase = SecretString::from("fuzz".to_string());
    let _ = symmetric_encrypt(&input_file, &output_dir, &passphrase, None, |_| {});
});
