//! Wire-format stability fixtures.
//!
//! Decrypts checked-in `.fcr` artefacts under `tests/fixtures/encrypted/`
//! and asserts their plaintext matches the matching `tests/fixtures/source/`
//! files byte-for-byte. Failure here means the refactor has changed
//! wire-format or decrypt behaviour — investigate before merging (see the
//! "Core invariant: pure refactor" section of `notes/RESTRUCTURE_PLAN.md`).
//!
//! To regenerate the fixtures (only after a *deliberate*, reviewed format
//! change has merged) run:
//!
//! ```bash
//! cargo test --package ferrocrypt fixture_stability::regenerate \
//!     -- --ignored --test-threads=1
//! ```
//!
//! That deletes `tests/fixtures/encrypted/` and `tests/fixtures/keys/`,
//! regenerates the test key pair, and re-encrypts the source files. The
//! resulting `.fcr` and key files are then committed by the human engineer.

use std::fs;
use std::path::{Path, PathBuf};

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    HybridDecryptConfig, HybridEncryptConfig, KeyGenConfig, PrivateKey, PublicKey,
    SymmetricDecryptConfig, SymmetricEncryptConfig, generate_key_pair, hybrid_decrypt,
    hybrid_encrypt, symmetric_decrypt, symmetric_encrypt,
};

const FIXTURE_PASSPHRASE: &str = "fixture-passphrase-not-secret-do-not-reuse";
const TEST_WORKSPACE: &str = "tests/workspace_fixture_stability";

const SMALL_FILE_NAME: &str = "small_file.txt";
const SMALL_DIR_NAME: &str = "small_dir";

const PASSPHRASE_FILE_FCR: &str = "small_file.passphrase.fcr";
const PASSPHRASE_DIR_FCR: &str = "small_dir.passphrase.fcr";
const RECIPIENT_FILE_FCR: &str = "small_file.recipient.fcr";
const RECIPIENT_DIR_FCR: &str = "small_dir.recipient.fcr";

const PUBLIC_KEY_FILE: &str = "public.key";
const PRIVATE_KEY_FILE: &str = "private.key";

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn source_dir() -> PathBuf {
    fixtures_dir().join("source")
}

fn encrypted_dir() -> PathBuf {
    fixtures_dir().join("encrypted")
}

fn keys_dir() -> PathBuf {
    fixtures_dir().join("keys")
}

fn fresh_temp(name: &str) -> PathBuf {
    let dir = Path::new(TEST_WORKSPACE).join(name);
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clean fixture-stability temp");
    }
    fs::create_dir_all(&dir).expect("create fixture-stability temp");
    dir
}

fn fixture_passphrase() -> SecretString {
    SecretString::from(FIXTURE_PASSPHRASE.to_string())
}

#[ctor::dtor]
fn cleanup() {
    if Path::new(TEST_WORKSPACE).exists() {
        let _ = fs::remove_dir_all(TEST_WORKSPACE);
    }
}

fn read_files_recursive(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read_dir fixture tree") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            let ft = entry.file_type().expect("file_type");
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                let rel = path.strip_prefix(root).expect("strip_prefix").to_path_buf();
                let bytes = fs::read(&path).expect("read fixture file");
                out.push((rel, bytes));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn assert_dirs_equal(expected_root: &Path, actual_root: &Path) {
    let expected = read_files_recursive(expected_root);
    let actual = read_files_recursive(actual_root);
    let expected_paths: Vec<_> = expected.iter().map(|(p, _)| p.clone()).collect();
    let actual_paths: Vec<_> = actual.iter().map(|(p, _)| p.clone()).collect();
    assert_eq!(
        expected_paths, actual_paths,
        "fixture file set differs between expected and actual"
    );
    for ((path, expected_bytes), (_, actual_bytes)) in expected.iter().zip(actual.iter()) {
        assert_eq!(
            expected_bytes,
            actual_bytes,
            "fixture content drifted at {}",
            path.display()
        );
    }
}

#[test]
fn decrypt_passphrase_file_fixture_matches_source() {
    let out = fresh_temp("decrypt_passphrase_file");
    let cfg = SymmetricDecryptConfig::new(
        encrypted_dir().join(PASSPHRASE_FILE_FCR),
        &out,
        fixture_passphrase(),
    );
    symmetric_decrypt(cfg, |_| {}).expect("decrypt passphrase-file fixture");
    let decrypted = fs::read(out.join(SMALL_FILE_NAME)).expect("read decrypted plaintext");
    let expected = fs::read(source_dir().join(SMALL_FILE_NAME)).expect("read source plaintext");
    assert_eq!(
        decrypted, expected,
        "passphrase-file fixture plaintext drifted"
    );
}

#[test]
fn decrypt_passphrase_dir_fixture_matches_source() {
    let out = fresh_temp("decrypt_passphrase_dir");
    let cfg = SymmetricDecryptConfig::new(
        encrypted_dir().join(PASSPHRASE_DIR_FCR),
        &out,
        fixture_passphrase(),
    );
    symmetric_decrypt(cfg, |_| {}).expect("decrypt passphrase-dir fixture");
    assert_dirs_equal(
        &source_dir().join(SMALL_DIR_NAME),
        &out.join(SMALL_DIR_NAME),
    );
}

#[test]
fn decrypt_recipient_file_fixture_matches_source() {
    let out = fresh_temp("decrypt_recipient_file");
    let cfg = HybridDecryptConfig::new(
        encrypted_dir().join(RECIPIENT_FILE_FCR),
        &out,
        PrivateKey::from_key_file(keys_dir().join(PRIVATE_KEY_FILE)),
        fixture_passphrase(),
    );
    hybrid_decrypt(cfg, |_| {}).expect("decrypt recipient-file fixture");
    let decrypted = fs::read(out.join(SMALL_FILE_NAME)).expect("read decrypted plaintext");
    let expected = fs::read(source_dir().join(SMALL_FILE_NAME)).expect("read source plaintext");
    assert_eq!(
        decrypted, expected,
        "recipient-file fixture plaintext drifted"
    );
}

#[test]
fn decrypt_recipient_dir_fixture_matches_source() {
    let out = fresh_temp("decrypt_recipient_dir");
    let cfg = HybridDecryptConfig::new(
        encrypted_dir().join(RECIPIENT_DIR_FCR),
        &out,
        PrivateKey::from_key_file(keys_dir().join(PRIVATE_KEY_FILE)),
        fixture_passphrase(),
    );
    hybrid_decrypt(cfg, |_| {}).expect("decrypt recipient-dir fixture");
    assert_dirs_equal(
        &source_dir().join(SMALL_DIR_NAME),
        &out.join(SMALL_DIR_NAME),
    );
}

/// Regenerates the on-disk fixtures from the source tree.
///
/// Run only when a deliberate, reviewed format change has merged. Marked
/// `#[ignore]` so it does not run in normal `cargo test` invocations; the
/// engineer commits the resulting fixture files by hand.
#[test]
#[ignore]
fn regenerate_fixtures() {
    if encrypted_dir().exists() {
        fs::remove_dir_all(encrypted_dir()).expect("clean encrypted/");
    }
    if keys_dir().exists() {
        fs::remove_dir_all(keys_dir()).expect("clean keys/");
    }
    fs::create_dir_all(encrypted_dir()).expect("create encrypted/");
    fs::create_dir_all(keys_dir()).expect("create keys/");

    let kg_outcome = generate_key_pair(KeyGenConfig::new(keys_dir(), fixture_passphrase()), |_| {})
        .expect("generate fixture key pair");
    eprintln!(
        "fixture key pair regenerated; public fingerprint = {}",
        kg_outcome.fingerprint
    );

    symmetric_encrypt(
        SymmetricEncryptConfig::new(
            source_dir().join(SMALL_FILE_NAME),
            encrypted_dir(),
            fixture_passphrase(),
        )
        .save_as(encrypted_dir().join(PASSPHRASE_FILE_FCR)),
        |_| {},
    )
    .expect("encrypt passphrase-file fixture");

    symmetric_encrypt(
        SymmetricEncryptConfig::new(
            source_dir().join(SMALL_DIR_NAME),
            encrypted_dir(),
            fixture_passphrase(),
        )
        .save_as(encrypted_dir().join(PASSPHRASE_DIR_FCR)),
        |_| {},
    )
    .expect("encrypt passphrase-dir fixture");

    hybrid_encrypt(
        HybridEncryptConfig::new(
            source_dir().join(SMALL_FILE_NAME),
            encrypted_dir(),
            PublicKey::from_key_file(keys_dir().join(PUBLIC_KEY_FILE)),
        )
        .save_as(encrypted_dir().join(RECIPIENT_FILE_FCR)),
        |_| {},
    )
    .expect("encrypt recipient-file fixture");

    hybrid_encrypt(
        HybridEncryptConfig::new(
            source_dir().join(SMALL_DIR_NAME),
            encrypted_dir(),
            PublicKey::from_key_file(keys_dir().join(PUBLIC_KEY_FILE)),
        )
        .save_as(encrypted_dir().join(RECIPIENT_DIR_FCR)),
        |_| {},
    )
    .expect("encrypt recipient-dir fixture");
}
