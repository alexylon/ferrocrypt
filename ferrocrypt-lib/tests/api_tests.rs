//! Public coverage for the new `Encryptor` / `Decryptor` API.
//!
//! `integration_tests.rs` exercises round-trip behavior through the
//! `symmetric_auto` / `hybrid_auto` shims (which now wrap the new API
//! internally). This file targets the new API surface directly so the
//! builder methods, `Decryptor::open` mode classification, multi-
//! recipient encrypt, and `EmptyRecipientList` rejection have explicit
//! coverage independent of the shim implementation.

use std::fs;
use std::path::{Path, PathBuf};

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    CryptoError, Decryptor, Encryptor, FormatDefect, PrivateKey, PublicKey, detect_encryption_mode,
    generate_key_pair,
};

const PASSPHRASE: &str = "api-test-passphrase";
const TEST_WORKSPACE: &str = "tests/workspace_api";

#[ctor::dtor]
fn cleanup() {
    if Path::new(TEST_WORKSPACE).exists() {
        let _ = fs::remove_dir_all(TEST_WORKSPACE);
    }
}

fn fresh_workspace(name: &str) -> PathBuf {
    let dir = Path::new(TEST_WORKSPACE).join(name);
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clean api workspace");
    }
    fs::create_dir_all(&dir).expect("create api workspace");
    dir
}

fn pass() -> SecretString {
    SecretString::from(PASSPHRASE.to_string())
}

#[test]
fn encryptor_passphrase_round_trip() {
    let work = fresh_workspace("passphrase_round_trip");
    let input = work.join("data.txt");
    fs::write(&input, b"hello passphrase api").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let outcome = Encryptor::with_passphrase(pass())
        .write(&input, &out_dir, |_| {})
        .expect("encrypt");

    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let decrypted = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::Passphrase(d) => d.decrypt(pass(), &restore, |_| {}).expect("decrypt"),
        Decryptor::Recipient(_) => panic!("expected passphrase decryptor"),
        _ => unreachable!("Decryptor is non_exhaustive; v1 has only Passphrase + Recipient"),
    };
    let restored_bytes = fs::read(decrypted.output_path).unwrap();
    assert_eq!(restored_bytes, b"hello passphrase api");
}

#[test]
fn encryptor_recipient_round_trip() {
    let work = fresh_workspace("recipient_round_trip");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let kg = generate_key_pair(&keys, pass(), |_| {}).expect("keygen");
    let input = work.join("data.txt");
    fs::write(&input, b"hello recipient api").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let outcome = Encryptor::with_recipient(PublicKey::from_key_file(&kg.public_key_path))
        .write(&input, &out_dir, |_| {})
        .expect("encrypt");

    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let decrypted = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::Recipient(d) => d
            .decrypt(
                PrivateKey::from_key_file(&kg.private_key_path),
                pass(),
                &restore,
                |_| {},
            )
            .expect("decrypt"),
        Decryptor::Passphrase(_) => panic!("expected recipient decryptor"),
        _ => unreachable!("Decryptor is non_exhaustive; v1 has only Passphrase + Recipient"),
    };
    let restored_bytes = fs::read(decrypted.output_path).unwrap();
    assert_eq!(restored_bytes, b"hello recipient api");
}

#[test]
fn encryptor_with_recipients_each_can_decrypt() {
    let work = fresh_workspace("multi_recipients");
    let keys_a = work.join("keys_a");
    let keys_b = work.join("keys_b");
    fs::create_dir_all(&keys_a).unwrap();
    fs::create_dir_all(&keys_b).unwrap();
    let kg_a = generate_key_pair(&keys_a, pass(), |_| {}).expect("keygen alice");
    let kg_b = generate_key_pair(&keys_b, pass(), |_| {}).expect("keygen bob");
    let input = work.join("data.txt");
    fs::write(&input, b"multi recipient payload").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let outcome = Encryptor::with_recipients([
        PublicKey::from_key_file(&kg_a.public_key_path),
        PublicKey::from_key_file(&kg_b.public_key_path),
    ])
    .expect("with_recipients")
    .write(&input, &out_dir, |_| {})
    .expect("encrypt");

    for (label, kg) in [("alice", &kg_a), ("bob", &kg_b)] {
        let restore = work.join(format!("restored-{label}"));
        fs::create_dir_all(&restore).unwrap();
        let decrypted = match Decryptor::open(&outcome.output_path).expect("open") {
            Decryptor::Recipient(d) => d
                .decrypt(
                    PrivateKey::from_key_file(&kg.private_key_path),
                    pass(),
                    &restore,
                    |_| {},
                )
                .expect("decrypt"),
            Decryptor::Passphrase(_) => panic!("expected recipient decryptor"),
            _ => unreachable!("Decryptor is non_exhaustive"),
        };
        let restored_bytes = fs::read(decrypted.output_path).unwrap();
        assert_eq!(
            restored_bytes, b"multi recipient payload",
            "{label} restored bytes drifted"
        );
    }
}

#[test]
fn encryptor_with_recipients_rejects_empty() {
    let err = Encryptor::with_recipients(std::iter::empty::<PublicKey>()).unwrap_err();
    assert!(
        matches!(err, CryptoError::EmptyRecipientList),
        "expected EmptyRecipientList, got {err:?}"
    );
}

#[test]
fn save_as_overrides_default_filename() {
    let work = fresh_workspace("save_as");
    let input = work.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let custom = work.join("custom-name.fcr");

    let outcome = Encryptor::with_passphrase(pass())
        .save_as(&custom)
        .write(&input, &work, |_| {})
        .expect("encrypt");

    assert_eq!(outcome.output_path, custom, "save_as path not honored");
    assert!(custom.exists(), "custom path missing on disk");
}

#[test]
fn decryptor_open_rejects_directory() {
    let work = fresh_workspace("open_dir");
    let err = Decryptor::open(&work).unwrap_err();
    match err {
        CryptoError::InvalidInput(msg) => {
            assert!(msg.contains("directory"), "unexpected message: {msg:?}");
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[test]
fn decryptor_open_rejects_non_fcr_file() {
    let work = fresh_workspace("open_bad_magic");
    let path = work.join("plain.txt");
    fs::write(&path, b"this is not a FerroCrypt file").unwrap();
    let err = Decryptor::open(&path).unwrap_err();
    match err {
        CryptoError::InvalidFormat(FormatDefect::BadMagic) => {}
        other => panic!("expected InvalidFormat(BadMagic), got {other:?}"),
    }
}

#[test]
fn decryptor_open_rejects_missing_input() {
    let err = Decryptor::open("/nonexistent/never/exists.fcr").unwrap_err();
    assert!(
        matches!(err, CryptoError::InputPath),
        "expected InputPath, got {err:?}"
    );
}

/// `Encryptor::with_passphrase("")` must reject the empty passphrase
/// at the top of `write`, before the input-existence check fires. Pins
/// the cheap-caller-input-first ordering matching the deprecated
/// `symmetric_encrypt` path so an empty passphrase against a missing
/// input still surfaces the more actionable "Passphrase must not be
/// empty" diagnostic.
#[test]
fn encryptor_passphrase_rejects_empty_before_input_check() {
    let work = fresh_workspace("empty_pass_before_input");
    let missing = work.join("does-not-exist.txt");
    let err = Encryptor::with_passphrase(SecretString::from(String::new()))
        .write(&missing, &work, |_| {})
        .unwrap_err();
    match err {
        CryptoError::InvalidInput(msg) => assert!(
            msg.contains("Passphrase"),
            "expected Passphrase rejection, got {msg:?}"
        ),
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

/// Pins the secrecy-redaction invariant on the new API. `Encryptor`
/// embeds a `SecretString` for the passphrase variant; this test fails
/// fast if `SecretString` is ever swapped for a raw `String`.
#[test]
fn encryptor_debug_does_not_leak_passphrase() {
    const SECRET: &str = "totally-secret-passphrase-9F2";
    let encryptor = Encryptor::with_passphrase(SecretString::from(SECRET.to_string()));
    let rendered = format!("{encryptor:?}");
    assert!(
        !rendered.contains(SECRET),
        "Encryptor leaked passphrase into Debug output: {rendered}"
    );
}

#[test]
fn detect_encryption_mode_round_trips_via_encryptor() {
    let work = fresh_workspace("detect_round_trip");
    let input = work.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let outcome = Encryptor::with_passphrase(pass())
        .write(&input, &work, |_| {})
        .expect("encrypt");
    assert!(
        detect_encryption_mode(&outcome.output_path)
            .unwrap()
            .is_some(),
        "encrypt output must classify as a known FerroCrypt mode"
    );
}
