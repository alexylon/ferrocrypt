#![no_main]
//! End-to-end fuzz target for the recipient (X25519) decrypt pipeline.
//! Drives arbitrary bytes through `Decryptor::open` +
//! `PrivateKeyDecryptor::decrypt` so coverage stays on the full
//! wire-format → MAC → AEAD path. The harness ignores all errors —
//! rejection is the expected outcome for almost every input; we only
//! care that the library never panics.

use std::fs;
use std::io::Write;

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{Decryptor, KdfLimit, KdfParams, KeyPairGenerator, PrivateKey};
use libfuzzer_sys::fuzz_target;

/// Argon2id budget for the harness: the per-iteration `private.key`
/// unlock at the 1 GiB production default dominated fuzz wall-clock.
/// The fixture key is sealed at 8 MiB and the reader limit below
/// matches, so the unlock always succeeds and stays cheap.
const FUZZ_KDF_MEM_KIB: u32 = 8 * 1024;

/// Generates a keypair once per process into a persistent temp directory.
fn key_dir() -> &'static std::path::Path {
    use std::sync::OnceLock;
    static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let pass = SecretString::from("fuzz_key".to_string());
        KeyPairGenerator::with_passphrase(pass)
            .kdf_params(KdfParams {
                mem_cost: FUZZ_KDF_MEM_KIB,
                time_cost: 1,
                lanes: 4,
            })
            .write(dir.path(), |_| {})
            .unwrap();
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

    if let Ok(Decryptor::PrivateKey(d)) = Decryptor::open(&input_path) {
        let passphrase = SecretString::from("fuzz_key".to_string());
        let _ = d.kdf_limit(KdfLimit::new(FUZZ_KDF_MEM_KIB)).decrypt(
            PrivateKey::from_key_file(&priv_key),
            passphrase,
            &output_dir,
            |_| {},
        );
    }
});
