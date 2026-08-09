//! Cross-version backward-read net.
//!
//! `tests/fixtures/frozen/<version>/` holds encrypted `.fcr` artefacts, the
//! key pair that opens them, and their expected plaintext, captured from a
//! specific released version and **never regenerated**. (`regenerate_fixtures`
//! rewrites only `tests/fixtures/encrypted/` and `tests/fixtures/keys/`, not
//! `frozen/`.) This test decrypts each frozen artefact with the current reader
//! and asserts it still reproduces the original plaintext byte-for-byte, so a
//! future change that stops reading bytes an older release wrote is caught
//! here — the "never strand a recipient" guarantee, mechanically enforced.
//!
//! To freeze a new version at release time, copy the freshly regenerated
//! `encrypted/`, `keys/`, and `source/` into `frozen/<version>/` and add its
//! directory to `FROZEN_VERSIONS` below.

use std::fs;
use std::path::{Path, PathBuf};

use ferrocrypt::Passphrase;
use ferrocrypt::{Decryptor, PrivateKey};

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

/// Sorted `(path-relative-to-root, bytes)` for every regular file under `root`.
fn read_files_recursive(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read frozen dir") {
            let path = entry.expect("frozen dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = path
                    .strip_prefix(root)
                    .expect("relative path")
                    .to_path_buf();
                let bytes = fs::read(&path).expect("read frozen file");
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
        "frozen fixture file set differs after decrypt"
    );
    for ((path, expected_bytes), (_, actual_bytes)) in expected.iter().zip(actual.iter()) {
        assert_eq!(
            expected_bytes, actual_bytes,
            "frozen fixture content differs after decrypt at {path:?}"
        );
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
        assert_dirs_equal(&source.join(SMALL_DIR_NAME), &got);

        // Recipient directory.
        let out = tmp.path().join(format!("{version}_rc_dir"));
        fs::create_dir_all(&out).unwrap();
        let got = recipient_decrypt(encrypted.join("small_dir.recipient.fcr"), private_key, &out);
        assert_dirs_equal(&source.join(SMALL_DIR_NAME), &got);
    }
}
