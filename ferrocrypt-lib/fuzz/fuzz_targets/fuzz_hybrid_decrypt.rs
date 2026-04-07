#![no_main]

use std::fs;
use std::io::Write;

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{generate_key_pair, hybrid_encryption};
use libfuzzer_sys::fuzz_target;

/// Generates a keypair once per process into a persistent temp directory.
fn key_dir() -> &'static std::path::Path {
    use std::sync::OnceLock;
    static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let pass = SecretString::from("fuzz_key".to_string());
        generate_key_pair(&pass, dir.path(), |_| {}).unwrap();
        dir
    })
    .path()
}

fuzz_target!(|data: &[u8]| {
    let keys = key_dir();
    let priv_key = keys.join("private.key");

    let tmp_dir = tempfile::tempdir().unwrap();
    let input_path = tmp_dir.path().join("input.fcr");
    let output_dir = tmp_dir.path().join("output");
    fs::create_dir_all(&output_dir).unwrap();

    let mut f = fs::File::create(&input_path).unwrap();
    f.write_all(data).unwrap();
    drop(f);

    let passphrase = SecretString::from("fuzz_key".to_string());
    let _ = hybrid_encryption(
        &input_path,
        &output_dir,
        &priv_key,
        &passphrase,
        None,
        |_| {},
    );
});
