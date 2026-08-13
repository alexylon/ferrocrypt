#![no_main]
//! End-to-end fuzz target for the recipient (X25519) decrypt pipeline.
//! Drives arbitrary bytes through `Decryptor::open` +
//! `PrivateKeyDecryptor::decrypt` so coverage stays on the full
//! wire-format → MAC → AEAD path. The harness ignores all errors —
//! rejection is the expected outcome for almost every input; we only
//! care that the library never panics.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;

use ferrocrypt::Passphrase;
use ferrocrypt::fuzz_exports::MIN_WRITE_MEM_COST;
use ferrocrypt::{Decryptor, KdfLimit, PrivateKey};
use libfuzzer_sys::fuzz_target;

/// Passphrase sealing the committed fixture key.
const FIXTURE_PASSPHRASE: &str = "fuzz_key";

/// The committed fixture `private.key`, embedded so the harness needs
/// nothing from the filesystem it is run in.
///
/// It is a fixture rather than a key generated per process because a
/// seed can only reach the payload region if this harness holds the
/// matching private key: against a fresh key every committed input
/// decrypts to nothing and the corpus exercises only the reject path.
/// `fuzz/examples/gen_seeds.rs` mints the pair and writes the seeds to
/// its public half.
const FIXTURE_PRIVATE_KEY: &[u8] = include_bytes!("../fixtures/hybrid/private.key");

/// Argon2id budget for the harness. The fixture key is sealed at the
/// writer's memory floor with the cheapest legal time and lane counts,
/// and this limit matches, so the per-iteration unlock always succeeds
/// and stays as cheap as the format allows. At the 1 GiB production
/// default that unlock would dominate fuzz wall-clock.
fn harness_kdf_limit() -> KdfLimit {
    KdfLimit::new(MIN_WRITE_MEM_COST)
        .max_time_cost(1)
        .max_lanes(4)
        .max_work(u64::from(MIN_WRITE_MEM_COST))
}

/// Materializes the embedded fixture key once per process.
fn fixture_private_key_path() -> &'static Path {
    static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("private.key"), FIXTURE_PRIVATE_KEY).unwrap();
        dir
    })
    .path()
}

fuzz_target!(|data: &[u8]| {
    let priv_key = fixture_private_key_path().join("private.key");

    let tmp_dir = tempfile::tempdir().unwrap();
    let input_path = tmp_dir.path().join("input.fcr");
    let output_dir = tmp_dir.path().join("output");
    fs::create_dir_all(&output_dir).unwrap();

    let mut f = fs::File::create(&input_path).unwrap();
    f.write_all(data).unwrap();
    drop(f);

    if let Ok(Decryptor::PrivateKey(d)) = Decryptor::open(&input_path) {
        let passphrase = Passphrase::new(FIXTURE_PASSPHRASE);
        let _ = d.kdf_limit(harness_kdf_limit()).decrypt(
            PrivateKey::from_key_file(&priv_key, passphrase),
            &output_dir,
            |_| {},
        );
    }
});
