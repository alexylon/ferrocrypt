#![no_main]
// `fuzz_hybrid_decrypt` exercises the deprecated decrypt entry point on
// purpose so coverage of the existing wire-format decode pipeline does
// not move under us mid-restructure. Step 10 swaps it for the new API.
#![allow(deprecated)]

use std::fs;
use std::io::Write;

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{HybridDecryptConfig, PrivateKey, generate_key_pair, hybrid_decrypt};
use libfuzzer_sys::fuzz_target;

/// Generates a keypair once per process into a persistent temp directory.
fn key_dir() -> &'static std::path::Path {
    use std::sync::OnceLock;
    static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let pass = SecretString::from("fuzz_key".to_string());
        generate_key_pair(dir.path(), pass, |_| {}).unwrap();
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
    let config = HybridDecryptConfig::new(
        &input_path,
        &output_dir,
        PrivateKey::from_key_file(&priv_key),
        passphrase,
    );
    let _ = hybrid_decrypt(config, |_| {});
});
