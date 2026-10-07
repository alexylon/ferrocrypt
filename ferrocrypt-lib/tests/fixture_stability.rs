//! Wire-format stability fixtures.
//!
//! Decrypts checked-in `.fcr` artefacts under `tests/fixtures/encrypted/`
//! and asserts their plaintext matches the matching `tests/fixtures/source/`
//! files byte-for-byte. Failure here means a change has altered
//! wire-format or decrypt behaviour — investigate before merging.
//!
//! To regenerate the fixtures (only after a *deliberate*, reviewed format
//! change has merged) run:
//!
//! ```bash
//! cargo test --package ferrocrypt --test fixture_stability regenerate_fixtures \
//!     -- --ignored --test-threads=1
//! ```
//!
//! That deletes `tests/fixtures/encrypted/` and `tests/fixtures/keys/`,
//! regenerates the test key pair, and re-encrypts the source files. The
//! resulting `.fcr` and key files are then committed by the human engineer.

use std::fs;
use std::path::{Path, PathBuf};

use ferrocrypt::Passphrase;
use ferrocrypt::{CryptoError, Decryptor, Encryptor, PrivateKey, PublicKey};
use ferrocrypt_test_support::{
    assert_tree_matches, fast_keypair_generator, fast_passphrase_encryptor, is_os_metadata_name,
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
    // Per-process subtree, so a concurrent `cargo test` invocation of
    // this binary cannot delete files this run is using.
    let dir = ferrocrypt_test_support::per_process_workspace(TEST_WORKSPACE).join(name);
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clean fixture-stability temp");
    }
    fs::create_dir_all(&dir).expect("create fixture-stability temp");
    dir
}

fn fixture_passphrase() -> Passphrase {
    Passphrase::new(FIXTURE_PASSPHRASE)
}

#[ctor::dtor]
fn cleanup() {
    ferrocrypt_test_support::remove_per_process_workspace(TEST_WORKSPACE);
}

/// Copies the tree at `from` to `to` without the metadata an operating system
/// wrote into it ([`is_os_metadata_name`]), keeping each file's permissions.
/// An entry that is neither a file nor a directory is refused, as the archive
/// writer would refuse it.
fn copy_without_os_metadata(from: &Path, to: &Path) {
    fs::create_dir(to).expect("create fixture source copy");
    for entry in fs::read_dir(from).expect("read fixture source tree") {
        let entry = entry.expect("fixture source entry");
        if is_os_metadata_name(&entry.file_name()) {
            continue;
        }
        let target = to.join(entry.file_name());
        let file_type = entry.file_type().expect("fixture source entry type");
        if file_type.is_dir() {
            copy_without_os_metadata(&entry.path(), &target);
        } else if file_type.is_file() {
            fs::copy(entry.path(), &target).expect("copy fixture source file");
        } else {
            panic!("{}: neither a file nor a directory", entry.path().display());
        }
    }
}

fn passphrase_decrypt(fcr: PathBuf, out: &Path) -> Result<(), CryptoError> {
    match Decryptor::open(&fcr)? {
        Decryptor::Passphrase(d) => {
            d.decrypt(fixture_passphrase(), out, |_| {})?;
            Ok(())
        }
        other => panic!("expected passphrase decryptor, got {other:?}"),
    }
}

fn recipient_decrypt(fcr: PathBuf, out: &Path) -> Result<(), CryptoError> {
    match Decryptor::open(&fcr)? {
        Decryptor::PrivateKey(d) => {
            d.decrypt(
                PrivateKey::from_key_file(keys_dir().join(PRIVATE_KEY_FILE), fixture_passphrase()),
                out,
                |_| {},
            )?;
            Ok(())
        }
        other => panic!("expected private-key decryptor, got {other:?}"),
    }
}

#[test]
fn decrypt_passphrase_file_fixture_matches_source() {
    let out = fresh_temp("decrypt_passphrase_file");
    passphrase_decrypt(encrypted_dir().join(PASSPHRASE_FILE_FCR), &out)
        .expect("decrypt passphrase-file fixture");
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
    passphrase_decrypt(encrypted_dir().join(PASSPHRASE_DIR_FCR), &out)
        .expect("decrypt passphrase-dir fixture");
    assert_tree_matches(
        &source_dir().join(SMALL_DIR_NAME),
        &out.join(SMALL_DIR_NAME),
    );
}

#[test]
fn decrypt_recipient_file_fixture_matches_source() {
    let out = fresh_temp("decrypt_recipient_file");
    recipient_decrypt(encrypted_dir().join(RECIPIENT_FILE_FCR), &out)
        .expect("decrypt recipient-file fixture");
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
    recipient_decrypt(encrypted_dir().join(RECIPIENT_DIR_FCR), &out)
        .expect("decrypt recipient-dir fixture");
    assert_tree_matches(
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
    // The directory fixtures encrypt a copy of the source tree without the
    // metadata an operating system wrote into it, which is not fixture content.
    let small_dir = fresh_temp("regenerate_source").join(SMALL_DIR_NAME);
    copy_without_os_metadata(&source_dir().join(SMALL_DIR_NAME), &small_dir);

    if encrypted_dir().exists() {
        fs::remove_dir_all(encrypted_dir()).expect("clean encrypted/");
    }
    if keys_dir().exists() {
        fs::remove_dir_all(keys_dir()).expect("clean keys/");
    }
    fs::create_dir_all(encrypted_dir()).expect("create encrypted/");
    fs::create_dir_all(keys_dir()).expect("create keys/");

    // Regenerated fixtures use the workspace-internal fast Argon2id
    // parameters so committed `.fcr` and `private.key` artefacts unlock
    // in milliseconds during routine `cargo test` runs, not seconds.
    // Production strength is not the goal here — fixture stability is
    // about wire-format invariants, and the KDF cost is independent of
    // those invariants.
    let kg_outcome = fast_keypair_generator(fixture_passphrase())
        .write(keys_dir(), |_| {})
        .expect("generate fixture key pair");
    eprintln!(
        "fixture key pair regenerated; public fingerprint = {}",
        kg_outcome.fingerprint
    );

    fast_passphrase_encryptor(fixture_passphrase())
        .save_as(encrypted_dir().join(PASSPHRASE_FILE_FCR))
        .write(source_dir().join(SMALL_FILE_NAME), encrypted_dir(), |_| {})
        .expect("encrypt passphrase-file fixture");

    fast_passphrase_encryptor(fixture_passphrase())
        .save_as(encrypted_dir().join(PASSPHRASE_DIR_FCR))
        .write(&small_dir, encrypted_dir(), |_| {})
        .expect("encrypt passphrase-dir fixture");

    Encryptor::with_public_key(
        PublicKey::from_key_file(keys_dir().join(PUBLIC_KEY_FILE)).expect("read public key"),
    )
    .save_as(encrypted_dir().join(RECIPIENT_FILE_FCR))
    .write(source_dir().join(SMALL_FILE_NAME), encrypted_dir(), |_| {})
    .expect("encrypt recipient-file fixture");

    Encryptor::with_public_key(
        PublicKey::from_key_file(keys_dir().join(PUBLIC_KEY_FILE)).expect("read public key"),
    )
    .save_as(encrypted_dir().join(RECIPIENT_DIR_FCR))
    .write(&small_dir, encrypted_dir(), |_| {})
    .expect("encrypt recipient-dir fixture");
}
