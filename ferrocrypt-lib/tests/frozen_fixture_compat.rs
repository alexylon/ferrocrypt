//! Backward-compatibility checks against frozen release fixtures.
//!
//! `tests/fixtures/frozen/<version>/` holds encrypted `.fcr` artefacts, the
//! key pair that opens them, and their expected plaintext, captured from a
//! specific released version and **never regenerated**. (`regenerate_fixtures`
//! rewrites only `tests/fixtures/encrypted/` and `tests/fixtures/keys/`, not
//! `frozen/`.) This test decrypts each frozen artefact with the current reader
//! and asserts it still reproduces the original plaintext byte-for-byte.
//! This checks backward compatibility for the cases represented by the
//! fixtures; the wire corpus provides broader conformance coverage.
//!
//! To freeze a new version at release time, copy the freshly regenerated
//! `encrypted/`, `keys/`, and `source/` into `frozen/<version>/` and add its
//! directory to `FROZEN_VERSIONS` below.

use std::fs;
use std::path::{Path, PathBuf};

use ferrocrypt::Passphrase;
use ferrocrypt::{Decryptor, PrivateKey};
use ferrocrypt_test_support::assert_tree_matches;

/// Passphrase every frozen fixture uses (both the passphrase `.fcr` files and
/// the `private.key` unlock). Fixture-only; not a secret.
const FIXTURE_PASSPHRASE: &str = "fixture-passphrase-not-secret-do-not-reuse";

/// Frozen corpora to replay. Add a new entry when a release is frozen.
const FROZEN_VERSIONS: &[&str] = &["v0.3.0"];

const SMALL_FILE_NAME: &str = "small_file.txt";
const SMALL_DIR_NAME: &str = "small_dir";

fn frozen_root(version: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/frozen")
        .join(version)
}

fn passphrase() -> Passphrase {
    Passphrase::new(FIXTURE_PASSPHRASE)
}

fn passphrase_decrypt(fcr: PathBuf, out: &Path) -> PathBuf {
    match Decryptor::open(&fcr).expect("open frozen passphrase fixture") {
        Decryptor::Passphrase(d) => {
            d.decrypt(passphrase(), out, |_| {})
                .expect("decrypt frozen passphrase fixture")
                .output_path
        }
        other => panic!("expected passphrase decryptor, got {other:?}"),
    }
}

fn recipient_decrypt(fcr: PathBuf, private_key: PathBuf, out: &Path) -> PathBuf {
    match Decryptor::open(&fcr).expect("open frozen recipient fixture") {
        Decryptor::PrivateKey(d) => {
            d.decrypt(
                PrivateKey::from_key_file(private_key, passphrase()),
                out,
                |_| {},
            )
            .expect("decrypt frozen recipient fixture")
            .output_path
        }
        other => panic!("expected private-key decryptor, got {other:?}"),
    }
}

#[test]
fn frozen_fixtures_still_decrypt_with_current_reader() {
    for &version in FROZEN_VERSIONS {
        let root = frozen_root(version);
        assert!(
            root.is_dir(),
            "frozen corpus {version} is missing at {root:?}"
        );
        let encrypted = root.join("encrypted");
        let source = root.join("source");
        let private_key = root.join("keys/private.key");
        let tmp = tempfile::TempDir::new().expect("temp output dir");

        // Passphrase file.
        let out = tmp.path().join(format!("{version}_pw_file"));
        fs::create_dir_all(&out).unwrap();
        let got = passphrase_decrypt(encrypted.join("small_file.passphrase.fcr"), &out);
        assert_eq!(
            fs::read(&got).unwrap(),
            fs::read(source.join(SMALL_FILE_NAME)).unwrap(),
            "{version}: passphrase file fixture"
        );

        // Recipient file.
        let out = tmp.path().join(format!("{version}_rc_file"));
        fs::create_dir_all(&out).unwrap();
        let got = recipient_decrypt(
            encrypted.join("small_file.recipient.fcr"),
            private_key.clone(),
            &out,
        );
        assert_eq!(
            fs::read(&got).unwrap(),
            fs::read(source.join(SMALL_FILE_NAME)).unwrap(),
            "{version}: recipient file fixture"
        );

        // Passphrase directory.
        let out = tmp.path().join(format!("{version}_pw_dir"));
        fs::create_dir_all(&out).unwrap();
        let got = passphrase_decrypt(encrypted.join("small_dir.passphrase.fcr"), &out);
        assert_tree_matches(&source.join(SMALL_DIR_NAME), &got);

        // Recipient directory.
        let out = tmp.path().join(format!("{version}_rc_dir"));
        fs::create_dir_all(&out).unwrap();
        let got = recipient_decrypt(encrypted.join("small_dir.recipient.fcr"), private_key, &out);
        assert_tree_matches(&source.join(SMALL_DIR_NAME), &got);
    }
}
