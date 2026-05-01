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
    CryptoError, Decryptor, Encryptor, FormatDefect, HeaderReadLimits, PrivateKey, PublicKey,
    detect_encryption_mode, detect_encryption_mode_with_limits, generate_key_pair,
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

/// Exercises the new `archive_limits()` builder on
/// [`PassphraseDecryptor`]. The bug being guarded is that callers who
/// raise the encrypt-side cap had no way to lift the decrypt-side cap,
/// so a legitimately-encrypted archive could be un-decryptable under
/// default decrypt limits. Setting a TIGHT decrypt cap proves the
/// value is plumbed through to `unarchive`.
#[test]
fn passphrase_decryptor_archive_limits_constrains_extraction() {
    use ferrocrypt::ArchiveLimits;

    let work = fresh_workspace("passphrase_archive_limits");
    let dir = work.join("input");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("a.txt"), b"a").unwrap();
    fs::write(dir.join("b.txt"), b"b").unwrap();
    fs::write(dir.join("c.txt"), b"c").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let outcome = Encryptor::with_passphrase(pass())
        .write(&dir, &out_dir, |_| {})
        .expect("encrypt");

    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let tight = ArchiveLimits::default().with_max_entry_count(1);
    let result = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::Passphrase(d) => d.archive_limits(tight).decrypt(pass(), &restore, |_| {}),
        _ => panic!("expected passphrase decryptor"),
    };
    match result {
        Err(CryptoError::InvalidInput(msg)) => {
            assert!(
                msg.contains("entry-count cap exceeded"),
                "expected entry-count cap error, got: {msg}"
            );
        }
        other => panic!("expected InvalidInput cap error, got {other:?}"),
    }
}

/// Mirrors `passphrase_decryptor_archive_limits_constrains_extraction`
/// for [`RecipientDecryptor`]: the `archive_limits()` builder must
/// reach `unarchive` on the recipient decrypt path too.
#[test]
fn recipient_decryptor_archive_limits_constrains_extraction() {
    use ferrocrypt::ArchiveLimits;

    let work = fresh_workspace("recipient_archive_limits");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let kg = generate_key_pair(&keys, pass(), |_| {}).expect("keygen");
    let dir = work.join("input");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("a.txt"), b"a").unwrap();
    fs::write(dir.join("b.txt"), b"b").unwrap();
    fs::write(dir.join("c.txt"), b"c").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let outcome = Encryptor::with_recipient(PublicKey::from_key_file(&kg.public_key_path))
        .write(&dir, &out_dir, |_| {})
        .expect("encrypt");

    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let tight = ArchiveLimits::default().with_max_entry_count(1);
    let result = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::Recipient(d) => d.archive_limits(tight).decrypt(
            PrivateKey::from_key_file(&kg.private_key_path),
            pass(),
            &restore,
            |_| {},
        ),
        _ => panic!("expected recipient decryptor"),
    };
    match result {
        Err(CryptoError::InvalidInput(msg)) => {
            assert!(
                msg.contains("entry-count cap exceeded"),
                "expected entry-count cap error, got: {msg}"
            );
        }
        other => panic!("expected InvalidInput cap error, got {other:?}"),
    }
}

/// Round-trip with raised caps on both sides — the symmetric case
/// the new builder enables. Without `Decryptor::archive_limits`, this
/// pattern was impossible: the encrypt side could exceed defaults but
/// the decrypt side was hardcoded to `ArchiveLimits::default()`.
#[test]
fn archive_limits_raised_on_both_sides_round_trips() {
    use ferrocrypt::ArchiveLimits;

    let work = fresh_workspace("archive_limits_raised");
    let dir = work.join("input");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("a.txt"), b"alpha").unwrap();
    fs::write(dir.join("b.txt"), b"beta").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let raised = ArchiveLimits::default()
        .with_max_entry_count(8)
        .with_max_path_depth(8);
    let outcome = Encryptor::with_passphrase(pass())
        .archive_limits(raised)
        .write(&dir, &out_dir, |_| {})
        .expect("encrypt");

    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let outcome_decrypt = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::Passphrase(d) => d
            .archive_limits(raised)
            .decrypt(pass(), &restore, |_| {})
            .expect("decrypt"),
        _ => panic!("expected passphrase decryptor"),
    };
    let extracted = outcome_decrypt.output_path;
    assert!(extracted.is_dir());
    assert_eq!(fs::read(extracted.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(fs::read(extracted.join("b.txt")).unwrap(), b"beta");
}

/// Encrypts to 80 of the same recipient — above the default
/// `RECIPIENT_COUNT_LOCAL_CAP_DEFAULT` (64) but well below the
/// structural ceiling (4096). [`Decryptor::open`] with default limits
/// MUST refuse the file with [`CryptoError::RecipientCountCapExceeded`];
/// the same file MUST decrypt successfully when the caller raises the
/// cap via [`Decryptor::open_with_limits`] /
/// [`HeaderReadLimits::max_recipient_count`]. Pins the audit-flagged
/// Low 2 finding closed at the public-API level (not just the
/// internal parser).
#[test]
fn decryptor_open_with_limits_accepts_recipient_count_above_default() {
    let work = fresh_workspace("recipient_count_above_default");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let kg = generate_key_pair(&keys, pass(), |_| {}).expect("keygen");
    let input = work.join("data.txt");
    fs::write(&input, b"raised count payload").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    // 80 copies of the same recipient produce a file with 80 x25519
    // recipient entries. Each entry independently wraps the same
    // file_key, so the holder of `kg`'s private key can decrypt any
    // of them.
    const RECIPIENT_COUNT: usize = 80;
    let recipients: Vec<PublicKey> = (0..RECIPIENT_COUNT)
        .map(|_| PublicKey::from_key_file(&kg.public_key_path))
        .collect();
    let outcome = Encryptor::with_recipients(recipients)
        .expect("with_recipients")
        .write(&input, &out_dir, |_| {})
        .expect("encrypt");

    // Default open: rejected by recipient_count cap.
    match Decryptor::open(&outcome.output_path) {
        Err(CryptoError::RecipientCountCapExceeded { count, local_cap }) => {
            assert_eq!(count, RECIPIENT_COUNT as u16);
            assert!(
                local_cap < count,
                "default local_cap should be below file count"
            );
        }
        other => panic!("expected RecipientCountCapExceeded with default cap, got {other:?}"),
    }

    // Same file via open_with_limits: succeeds.
    let raised = HeaderReadLimits::default().max_recipient_count(128);
    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let decrypted = match Decryptor::open_with_limits(&outcome.output_path, raised)
        .expect("open_with_limits")
    {
        Decryptor::Recipient(d) => d
            .decrypt(
                PrivateKey::from_key_file(&kg.private_key_path),
                pass(),
                &restore,
                |_| {},
            )
            .expect("decrypt"),
        _ => panic!("expected recipient decryptor"),
    };
    assert_eq!(
        fs::read(decrypted.output_path).unwrap(),
        b"raised count payload"
    );
}

/// `detect_encryption_mode_with_limits` honors the elevated cap when
/// classifying a file the default-limited variant refuses. Companion
/// to [`decryptor_open_with_limits_accepts_recipient_count_above_default`]
/// for the detection-only path used by callers that want to classify
/// without going through `Decryptor::open`.
#[test]
fn detect_encryption_mode_with_limits_accepts_above_default() {
    use ferrocrypt::EncryptionMode;

    let work = fresh_workspace("detect_with_limits");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let kg = generate_key_pair(&keys, pass(), |_| {}).expect("keygen");
    let input = work.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let recipients: Vec<PublicKey> = (0..80)
        .map(|_| PublicKey::from_key_file(&kg.public_key_path))
        .collect();
    let outcome = Encryptor::with_recipients(recipients)
        .expect("with_recipients")
        .write(&input, &out_dir, |_| {})
        .expect("encrypt");

    // Default detect: rejected.
    match detect_encryption_mode(&outcome.output_path) {
        Err(CryptoError::RecipientCountCapExceeded { .. }) => {}
        other => panic!("expected RecipientCountCapExceeded with default detect, got {other:?}"),
    }

    // Raised detect: classifies cleanly.
    let raised = HeaderReadLimits::default().max_recipient_count(128);
    match detect_encryption_mode_with_limits(&outcome.output_path, raised) {
        Ok(Some(EncryptionMode::Recipient)) => {}
        other => panic!("expected Ok(Some(Recipient)) under raised cap, got {other:?}"),
    }
}
