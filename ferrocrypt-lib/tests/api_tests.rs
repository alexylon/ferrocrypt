//! Public coverage for the new `Encryptor` / `Decryptor` API.
//!
//! `integration_tests.rs` exercises round-trip behavior through the
//! `passphrase_auto` / `recipient_auto` shims (which now wrap the new API
//! internally). This file targets the new API surface directly so the
//! builder methods, `Decryptor::open` mode classification, multi-
//! recipient encrypt, and `EmptyRecipientList` rejection have explicit
//! coverage independent of the shim implementation.

use std::fs;
use std::path::{Path, PathBuf};

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    CryptoError, Decryptor, Encryptor, FormatDefect, HeaderReadLimits, InvalidKdfParams, KdfLimit,
    KdfParams, KeyPairGenerator, PrivateKey, PublicKey, probe_recipient_mode,
    probe_recipient_mode_with_limits,
};
use ferrocrypt_test_support::{
    TEST_FAST_KDF_MEM_COST, fast_keypair_generator, fast_passphrase_encryptor,
};

/// Test-side keygen helper that mirrors the lib's free `generate_key_pair`
/// signature but routes through the workspace-internal fast-Argon2id
/// builder so each call returns in milliseconds rather than seconds.
fn generate_key_pair(
    output_dir: impl AsRef<Path>,
    passphrase: SecretString,
    on_event: impl Fn(&ferrocrypt::ProgressEvent),
) -> Result<ferrocrypt::KeyGenOutcome, CryptoError> {
    fast_keypair_generator(passphrase).write(output_dir, on_event)
}

const PASSPHRASE: &str = "api-test-passphrase";
const TEST_WORKSPACE: &str = "tests/workspace_api";

/// A structurally valid Argon2id memory cost below the writer's 19 MiB
/// production floor, used by the floor-rejection tests. Kept separate
/// from `TEST_FAST_KDF_MEM_COST` (which sits at the floor) so the fast
/// test params and the below-floor sentinel cannot drift together.
const BELOW_FLOOR_KDF_MEM: u32 = 8 * 1024;

#[ctor::dtor]
fn cleanup() {
    ferrocrypt_test_support::remove_per_process_workspace(TEST_WORKSPACE);
}

fn fresh_workspace(name: &str) -> PathBuf {
    // Per-process subtree, so a concurrent `cargo test` invocation of
    // this binary cannot delete files this run is using.
    let dir = ferrocrypt_test_support::per_process_workspace(TEST_WORKSPACE).join(name);
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clean api workspace");
    }
    fs::create_dir_all(&dir).expect("create api workspace");
    dir
}

fn pass() -> SecretString {
    SecretString::from(PASSPHRASE.to_string())
}

/// Returns sorted, `/`-separated paths for every entry beneath `root`.
/// Output-inside-input tests use this to compare the restored tree with the
/// source tree recorded before encryption.
fn tree_names(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            out.push(rel);
            if path.is_dir() {
                walk(&path, root, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

#[test]
fn encryptor_passphrase_round_trip() {
    let work = fresh_workspace("passphrase_round_trip");
    let input = work.join("data.txt");
    fs::write(&input, b"hello passphrase api").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let outcome = fast_passphrase_encryptor(pass())
        .write(&input, &out_dir, |_| {})
        .expect("encrypt");

    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let decrypted = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::Passphrase(d) => d.decrypt(pass(), &restore, |_| {}).expect("decrypt"),
        Decryptor::PrivateKey(_) => panic!("expected passphrase decryptor"),
        _ => unreachable!("Decryptor is non_exhaustive; v1 has only Passphrase + PrivateKey"),
    };
    let restored_bytes = fs::read(decrypted.output_path).unwrap();
    assert_eq!(restored_bytes, b"hello passphrase api");
}

/// Encrypting a directory to its default destination inside that directory
/// must not include the ciphertext staging file or final `.fcr` file in the
/// restored tree. Source preparation completes before either output exists.
#[test]
fn encrypt_directory_to_output_inside_input_tree() {
    let work = fresh_workspace("output_inside_input_default");
    let input = work.join("input");
    fs::create_dir_all(&input).unwrap();
    fs::write(input.join("a.txt"), b"hello inside-output").unwrap();

    let outcome = fast_passphrase_encryptor(pass())
        .write(&input, &input, |_| {})
        .expect("encrypt with output inside the input directory");
    assert_eq!(outcome.output_path, input.join("input.fcr"));

    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let decrypted = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::Passphrase(d) => d.decrypt(pass(), &restore, |_| {}).expect("decrypt"),
        Decryptor::PrivateKey(_) => panic!("expected passphrase decryptor"),
        _ => unreachable!("Decryptor is non_exhaustive; v1 has only Passphrase + PrivateKey"),
    };

    let names = tree_names(&decrypted.output_path);
    assert_eq!(
        names,
        vec!["a.txt".to_string()],
        "restored tree must match the pre-encryption input exactly"
    );
    assert_eq!(
        fs::read(decrypted.output_path.join("a.txt")).unwrap(),
        b"hello inside-output"
    );
}

/// Verifies the same rule for an explicit `save_as` path in a nested source
/// directory. The payload spans several stream chunks so the staging file is
/// written while source file contents are still being read.
#[test]
fn encrypt_directory_to_save_as_inside_nested_subdirectory() {
    let work = fresh_workspace("output_inside_input_save_as");
    let input = work.join("input");
    let nested = input.join("sub");
    fs::create_dir_all(&nested).unwrap();
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(input.join("a.txt"), b"small").unwrap();
    fs::write(nested.join("big.bin"), &big).unwrap();

    let save_as = nested.join("out.fcr");
    let outcome = fast_passphrase_encryptor(pass())
        .save_as(&save_as)
        .write(&input, &work, |_| {})
        .expect("encrypt with save_as inside a nested input subdirectory");
    assert_eq!(outcome.output_path, save_as);

    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let decrypted = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::Passphrase(d) => d.decrypt(pass(), &restore, |_| {}).expect("decrypt"),
        Decryptor::PrivateKey(_) => panic!("expected passphrase decryptor"),
        _ => unreachable!("Decryptor is non_exhaustive; v1 has only Passphrase + PrivateKey"),
    };

    let names = tree_names(&decrypted.output_path);
    assert_eq!(
        names,
        vec![
            "a.txt".to_string(),
            "sub".to_string(),
            "sub/big.bin".to_string(),
        ],
        "restored tree must match the pre-encryption input exactly"
    );
    assert_eq!(
        fs::read(decrypted.output_path.join("sub/big.bin")).unwrap(),
        big
    );
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

    let outcome = Encryptor::with_public_key(PublicKey::from_key_file(&kg.public_key_path))
        .write(&input, &out_dir, |_| {})
        .expect("encrypt");

    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let decrypted = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::PrivateKey(d) => d
            .decrypt(
                PrivateKey::from_key_file(&kg.private_key_path),
                pass(),
                &restore,
                |_| {},
            )
            .expect("decrypt"),
        Decryptor::Passphrase(_) => panic!("expected private-key decryptor"),
        _ => unreachable!("Decryptor is non_exhaustive; v1 has only Passphrase + PrivateKey"),
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

    let outcome = Encryptor::with_public_keys([
        PublicKey::from_key_file(&kg_a.public_key_path),
        PublicKey::from_key_file(&kg_b.public_key_path),
    ])
    .expect("with_public_keys")
    .write(&input, &out_dir, |_| {})
    .expect("encrypt");

    for (label, kg) in [("alice", &kg_a), ("bob", &kg_b)] {
        let restore = work.join(format!("restored-{label}"));
        fs::create_dir_all(&restore).unwrap();
        let decrypted = match Decryptor::open(&outcome.output_path).expect("open") {
            Decryptor::PrivateKey(d) => d
                .decrypt(
                    PrivateKey::from_key_file(&kg.private_key_path),
                    pass(),
                    &restore,
                    |_| {},
                )
                .expect("decrypt"),
            Decryptor::Passphrase(_) => panic!("expected private-key decryptor"),
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
    let err = Encryptor::with_public_keys(std::iter::empty::<PublicKey>()).unwrap_err();
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

    let outcome = fast_passphrase_encryptor(pass())
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

#[test]
fn probe_recipient_mode_reports_input_path_for_missing_file() {
    let err = probe_recipient_mode("/nonexistent/never/exists.fcr").unwrap_err();
    assert!(
        matches!(err, CryptoError::InputPath),
        "expected InputPath, got {err:?}"
    );
}

/// A `.fcr` that disappears between `Decryptor::open` and `decrypt` must
/// surface the same typed `InputPath` the open itself reports for a
/// missing input, not a raw I/O error.
#[test]
fn passphrase_decrypt_reports_input_path_when_file_vanishes() {
    let work = fresh_workspace("decrypt_vanished_input");
    let input = work.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let outcome = fast_passphrase_encryptor(pass())
        .write(&input, &work, |_| {})
        .expect("encrypt");

    let decryptor = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::Passphrase(d) => d,
        other => panic!("expected passphrase decryptor, got {other:?}"),
    };
    fs::remove_file(&outcome.output_path).unwrap();

    let err = decryptor.decrypt(pass(), &work, |_| {}).unwrap_err();
    assert!(
        matches!(err, CryptoError::InputPath),
        "expected InputPath, got {err:?}"
    );
}

/// Private-key variant of the missing-input test. Opening the decryption
/// session occurs before `private.key` is unlocked, so the missing file must
/// return `InputPath` without starting Argon2id.
#[test]
fn private_key_decrypt_reports_input_path_when_file_vanishes() {
    let work = fresh_workspace("pk_decrypt_vanished_input");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let kg = generate_key_pair(&keys, pass(), |_| {}).expect("keygen");
    let input = work.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let outcome = Encryptor::with_public_key(PublicKey::from_key_file(&kg.public_key_path))
        .write(&input, &work, |_| {})
        .expect("encrypt");

    let decryptor = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::PrivateKey(d) => d,
        other => panic!("expected private-key decryptor, got {other:?}"),
    };
    fs::remove_file(&outcome.output_path).unwrap();

    let unlock_event_count = std::cell::Cell::new(0u32);
    let err = decryptor
        .decrypt(
            PrivateKey::from_key_file(&kg.private_key_path),
            pass(),
            &work,
            |evt| {
                if matches!(evt, ferrocrypt::ProgressEvent::UnlockingPrivateKey) {
                    unlock_event_count.set(unlock_event_count.get() + 1);
                }
            },
        )
        .unwrap_err();
    assert!(
        matches!(err, CryptoError::InputPath),
        "expected InputPath, got {err:?}"
    );
    assert_eq!(
        unlock_event_count.get(),
        0,
        "Argon2id unlock ran before the vanished-input rejection",
    );
}

/// Replacing the encrypted-file path after `PrivateKeyDecryptor::decrypt`
/// opens and validates it must not change the file being decrypted. The test
/// performs the replacement from the `UnlockingPrivateKey` progress callback.
/// Decryption must still restore the content from the originally opened file.
#[test]
fn private_key_decrypt_uses_the_validated_file_not_a_swapped_replacement() {
    let work = fresh_workspace("pk_decrypt_swap_after_open");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let kg = generate_key_pair(&keys, pass(), |_| {}).expect("keygen");

    let original = work.join("original.txt");
    fs::write(&original, b"original plaintext").unwrap();
    let substitute = work.join("substitute.txt");
    fs::write(&substitute, b"substitute plaintext").unwrap();

    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let original_fcr = Encryptor::with_public_key(PublicKey::from_key_file(&kg.public_key_path))
        .write(&original, &out_dir, |_| {})
        .expect("encrypt original")
        .output_path;
    let substitute_fcr = Encryptor::with_public_key(PublicKey::from_key_file(&kg.public_key_path))
        .write(&substitute, &out_dir, |_| {})
        .expect("encrypt substitute")
        .output_path;

    let decryptor = match Decryptor::open(&original_fcr).expect("open") {
        Decryptor::PrivateKey(d) => d,
        other => panic!("expected private-key decryptor, got {other:?}"),
    };

    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let swapped = std::cell::Cell::new(false);
    let outcome = decryptor
        .decrypt(
            PrivateKey::from_key_file(&kg.private_key_path),
            pass(),
            &restore,
            |evt| {
                if matches!(evt, ferrocrypt::ProgressEvent::UnlockingPrivateKey) && !swapped.get() {
                    swapped.set(true);
                    fs::rename(&substitute_fcr, &original_fcr)
                        .expect("swap the encrypted file during the unlock");
                }
            },
        )
        .expect("decrypt must succeed against the originally opened file");

    assert!(
        swapped.get(),
        "sanity: the swap really happened during the unlock"
    );
    assert_eq!(
        outcome.output_path,
        restore.join("original.txt"),
        "the restored name must come from the originally opened file"
    );
    assert_eq!(
        fs::read(&outcome.output_path).unwrap(),
        b"original plaintext",
        "the restored content must come from the originally opened file"
    );
}

/// `fast_passphrase_encryptor("")` must reject the empty passphrase
/// at the top of `write`, before the input-existence check fires. Pins
/// the cheap-caller-input-first ordering matching the deprecated
/// `symmetric_encrypt` path so an empty passphrase against a missing
/// input still surfaces the more actionable "Passphrase must not be
/// empty" diagnostic.
#[test]
fn encryptor_passphrase_rejects_empty_before_input_check() {
    let work = fresh_workspace("empty_pass_before_input");
    let missing = work.join("does-not-exist.txt");
    let err = fast_passphrase_encryptor(SecretString::from(String::new()))
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
    let encryptor = fast_passphrase_encryptor(SecretString::from(SECRET.to_string()));
    let rendered = format!("{encryptor:?}");
    assert!(
        !rendered.contains(SECRET),
        "Encryptor leaked passphrase into Debug output: {rendered}"
    );
}

#[test]
fn probe_recipient_mode_round_trips_via_encryptor() {
    let work = fresh_workspace("probe_round_trip");
    let input = work.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let outcome = fast_passphrase_encryptor(pass())
        .write(&input, &work, |_| {})
        .expect("encrypt");
    assert!(
        probe_recipient_mode(&outcome.output_path)
            .unwrap()
            .is_some(),
        "encrypt output must classify as a known FerroCrypt mode"
    );
}

/// Regression: verifies that `DecryptOutcome::recipient_mode` is populated
/// with the mode that actually authenticated the file, not the other one.
/// Without this test, swapping the two `AuthenticatedRecipientMode::*()`
/// constructors between `PassphraseDecryptor::decrypt` and
/// `PrivateKeyDecryptor::decrypt` would silently compile and pass every
/// other test — those check `output_path` but not which mode authenticated.
#[test]
fn decrypt_outcome_carries_authenticated_passphrase_mode() {
    let work = fresh_workspace("outcome_mode_passphrase");
    let input = work.join("data.txt");
    fs::write(&input, b"plaintext").unwrap();
    let encrypted = fast_passphrase_encryptor(pass())
        .write(&input, &work, |_| {})
        .expect("encrypt");

    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let outcome = match Decryptor::open(&encrypted.output_path).expect("open") {
        Decryptor::Passphrase(d) => d.decrypt(pass(), &restore, |_| {}).expect("decrypt"),
        other => panic!("expected passphrase decryptor, got {other:?}"),
    };
    assert!(
        outcome.recipient_mode.is_passphrase(),
        "passphrase decrypt must report passphrase mode, got {}",
        outcome.recipient_mode
    );
    assert!(!outcome.recipient_mode.is_public_key());
}

/// Companion regression for the recipient (X25519) decrypt path.
#[test]
fn decrypt_outcome_carries_authenticated_public_key_mode() {
    let work = fresh_workspace("outcome_mode_public_key");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let kg = generate_key_pair(&keys, pass(), |_| {}).expect("keygen");
    let input = work.join("data.txt");
    fs::write(&input, b"plaintext").unwrap();
    let encrypted = Encryptor::with_public_key(PublicKey::from_key_file(&kg.public_key_path))
        .write(&input, &work, |_| {})
        .expect("encrypt");

    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let outcome = match Decryptor::open(&encrypted.output_path).expect("open") {
        Decryptor::PrivateKey(d) => d
            .decrypt(
                PrivateKey::from_key_file(&kg.private_key_path),
                pass(),
                &restore,
                |_| {},
            )
            .expect("decrypt"),
        other => panic!("expected private-key decryptor, got {other:?}"),
    };
    assert!(
        outcome.recipient_mode.is_public_key(),
        "public-key decrypt must report public-key mode, got {}",
        outcome.recipient_mode
    );
    assert!(!outcome.recipient_mode.is_passphrase());
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

    let outcome = fast_passphrase_encryptor(pass())
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
        Err(CryptoError::ArchiveEntryCountCapExceeded { local_cap: 1, .. }) => {}
        other => panic!("expected the typed entry-count cap error, got {other:?}"),
    }
}

/// Mirrors `passphrase_decryptor_archive_limits_constrains_extraction`
/// for [`PrivateKeyDecryptor`]: the `archive_limits()` builder must
/// reach `unarchive` on the public-key decrypt path too.
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

    let outcome = Encryptor::with_public_key(PublicKey::from_key_file(&kg.public_key_path))
        .write(&dir, &out_dir, |_| {})
        .expect("encrypt");

    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let tight = ArchiveLimits::default().with_max_entry_count(1);
    let result = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::PrivateKey(d) => d.archive_limits(tight).decrypt(
            PrivateKey::from_key_file(&kg.private_key_path),
            pass(),
            &restore,
            |_| {},
        ),
        _ => panic!("expected private-key decryptor"),
    };
    match result {
        Err(CryptoError::ArchiveEntryCountCapExceeded { local_cap: 1, .. }) => {}
        other => panic!("expected the typed entry-count cap error, got {other:?}"),
    }
}

/// Encrypt-side `archive_limits` raised above the default while the
/// reader uses [`ArchiveLimits::default`]: a file containing a path
/// deeper than the reader's default `max_path_depth` (64) is rejected
/// at extract time with the typed `path too deep` message,
/// and the same file decrypts successfully when the reader raises
/// `archive_limits` to match the writer.
///
/// Pins the documented asymmetry on
/// [`PassphraseDecryptor::archive_limits`] / [`PrivateKeyDecryptor::archive_limits`]
/// ("Must match (or exceed) the limits the writer used") as
/// intentional behavior rather than implicit. `max_path_depth` is
/// used because it is the only `ArchiveLimits` axis whose default cap
/// (64) is small enough to exercise asymmetrically with a tractable
/// fixture; `max_entry_count` (250 000) and
/// `max_total_plaintext_bytes` (64 GiB) would each require an
/// impractical fixture.
#[test]
fn archive_limits_writer_raised_default_reader_rejects_path_depth() {
    use ferrocrypt::ArchiveLimits;

    let work = fresh_workspace("archive_limits_asymmetric_path_depth");
    let input = work.join("input");
    // Archive paths are emitted as `<root>/<rel>`: the input directory
    // contributes one component (`input`), each nested `a` adds one,
    // and the leaf file adds one. 64 nested directories therefore
    // produce a leaf entry with 66 components — two over the default
    // reader cap of 64, so the rejection cannot be a fence-post mistake.
    let mut deepest = input.clone();
    for _ in 0..64 {
        deepest = deepest.join("a");
    }
    fs::create_dir_all(&deepest).unwrap();
    fs::write(deepest.join("leaf.txt"), b"deep payload").unwrap();

    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    // Writer raises `max_path_depth` so the encrypt-side preflight
    // accepts the deep tree. Without this raise the writer's own
    // preflight would reject before any payload bytes were written.
    let raised = ArchiveLimits::default().with_max_path_depth(80);
    let outcome = fast_passphrase_encryptor(pass())
        .archive_limits(raised)
        .write(&input, &out_dir, |_| {})
        .expect("encrypt");

    // Default reader: rejects on extract with the typed path-depth
    // cap error from `enforce_per_entry_caps`.
    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let default_decrypt = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::Passphrase(d) => d.decrypt(pass(), &restore, |_| {}),
        _ => panic!("expected passphrase decryptor"),
    };
    match default_decrypt {
        Err(CryptoError::ArchivePathDepthCapExceeded { local_cap: 64, .. }) => {}
        other => panic!("expected default reader to reject deep file, got {other:?}"),
    }

    // Reader raises `archive_limits` to match the writer: succeeds.
    let restore2 = work.join("restored2");
    fs::create_dir_all(&restore2).unwrap();
    let raised_decrypt = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::Passphrase(d) => d
            .archive_limits(raised)
            .decrypt(pass(), &restore2, |_| {})
            .expect("raised reader must accept the file the default reader refused"),
        _ => panic!("expected passphrase decryptor"),
    };
    assert!(raised_decrypt.output_path.is_dir());
    let mut leaf = raised_decrypt.output_path.clone();
    for _ in 0..64 {
        leaf = leaf.join("a");
    }
    leaf = leaf.join("leaf.txt");
    assert_eq!(fs::read(&leaf).unwrap(), b"deep payload");
}

/// Round-trip with raised caps on both sides — the writer-and-reader-
/// aligned case the new builder enables. Without `Decryptor::archive_limits`, this
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
    let outcome = fast_passphrase_encryptor(pass())
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
    // Writer-mirrors-reader contract: the writer refuses lists above the
    // default `RECIPIENT_COUNT_LOCAL_CAP_DEFAULT` (64) unless the caller
    // raises `Encryptor::header_read_limits` explicitly. The decryptor
    // must mirror the raise via `Decryptor::open_with_limits`.
    let writer_limits = HeaderReadLimits::default().max_recipient_count(128);
    let outcome = Encryptor::with_public_keys(recipients)
        .expect("with_public_keys")
        .header_read_limits(writer_limits)
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
        Decryptor::PrivateKey(d) => d
            .decrypt(
                PrivateKey::from_key_file(&kg.private_key_path),
                pass(),
                &restore,
                |_| {},
            )
            .expect("decrypt"),
        _ => panic!("expected private-key decryptor"),
    };
    assert_eq!(
        fs::read(decrypted.output_path).unwrap(),
        b"raised count payload"
    );
}

/// `probe_recipient_mode_with_limits` honors the elevated cap when
/// classifying a file the default-limited variant refuses. Companion
/// to [`decryptor_open_with_limits_accepts_recipient_count_above_default`]
/// for the probe-only path used by callers that want to classify
/// without going through `Decryptor::open`.
#[test]
fn probe_recipient_mode_with_limits_accepts_above_default() {
    use ferrocrypt::UnauthenticatedRecipientMode;

    let work = fresh_workspace("probe_with_limits");
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
    // Writer must opt into the raised recipient-count cap; the
    // probe-only path below confirms the same opt-in is required
    // on the read side.
    let writer_limits = HeaderReadLimits::default().max_recipient_count(128);
    let outcome = Encryptor::with_public_keys(recipients)
        .expect("with_public_keys")
        .header_read_limits(writer_limits)
        .write(&input, &out_dir, |_| {})
        .expect("encrypt");

    // Default probe: rejected.
    match probe_recipient_mode(&outcome.output_path) {
        Err(CryptoError::RecipientCountCapExceeded { .. }) => {}
        other => panic!("expected RecipientCountCapExceeded with default probe, got {other:?}"),
    }

    // Raised probe: classifies cleanly.
    let raised = HeaderReadLimits::default().max_recipient_count(128);
    match probe_recipient_mode_with_limits(&outcome.output_path, raised) {
        Ok(Some(UnauthenticatedRecipientMode::PublicKey)) => {}
        other => panic!("expected Ok(Some(PublicKey)) under raised cap, got {other:?}"),
    }
}

// ─── Writer caps mirror reader defaults ────────────────────────────────────
//
// Pin the contract that a default-configured `Encryptor` /
// `KeyPairGenerator` produces files a default-configured `Decryptor`
// (or `PrivateKeyDecryptor` `private.key` unlock) can read. Going
// above default requires the caller to opt in on BOTH sides; the
// tests below pin both the rejection (no opt-in) and the acceptance
// (opt-in matches) directions.

/// Default `Encryptor::with_public_keys(N>64)` rejects at write time
/// with [`CryptoError::RecipientCountCapExceeded`] before any X25519
/// ECDH or key wrapping runs. Pins the writer-side half of the
/// recipient-count contract; the matching reader-side rejection /
/// acceptance is pinned by
/// [`decryptor_open_with_limits_accepts_recipient_count_above_default`].
#[test]
fn encryptor_with_recipients_above_default_rejects_without_opt_in() {
    let work = fresh_workspace("recipients_above_default_rejects");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let kg = generate_key_pair(&keys, pass(), |_| {}).expect("keygen");
    let input = work.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let cap = HeaderReadLimits::RECIPIENT_COUNT_DEFAULT;

    // One above the default cap — boundary rejection, not "way over".
    let recipients: Vec<PublicKey> = (0..(cap as usize + 1))
        .map(|_| PublicKey::from_key_file(&kg.public_key_path))
        .collect();
    let result = Encryptor::with_public_keys(recipients)
        .expect("with_public_keys")
        .write(&input, &out_dir, |_| {});
    match result {
        Err(CryptoError::RecipientCountCapExceeded { count, local_cap }) => {
            assert_eq!(count, cap + 1);
            assert_eq!(local_cap, cap);
        }
        other => panic!("expected RecipientCountCapExceeded, got {other:?}"),
    }

    // Boundary: a list at exactly the default cap MUST succeed under
    // default settings. Pins the cap check uses `>`, not `>=`.
    let at_cap: Vec<PublicKey> = (0..cap)
        .map(|_| PublicKey::from_key_file(&kg.public_key_path))
        .collect();
    let at_cap_out = out_dir.join("at_cap");
    fs::create_dir_all(&at_cap_out).unwrap();
    let outcome = Encryptor::with_public_keys(at_cap)
        .expect("with_public_keys at cap")
        .write(&input, &at_cap_out, |_| {})
        .expect("encrypt at exactly the default cap must succeed");
    assert!(outcome.output_path.exists());
}

/// Writer-side `HeaderReadLimits` preflight applies to passphrase files
/// too, not just public-key files. Tightening recipient_count
/// below the one canonical `argon2id` slot rejects before Argon2id runs,
/// preventing a file that the same limits would reject on decrypt.
#[test]
fn encryptor_passphrase_header_limits_reject_tight_recipient_count() {
    let work = fresh_workspace("passphrase_header_count_tight");
    let input = work.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let tight = HeaderReadLimits::default().max_recipient_count(0);
    let result = fast_passphrase_encryptor(pass())
        .header_read_limits(tight)
        .write(&input, &out_dir, |_| {});
    match result {
        Err(CryptoError::RecipientCountCapExceeded {
            count: 1,
            local_cap: 0,
        }) => {}
        other => panic!("expected RecipientCountCapExceeded(1, 0), got {other:?}"),
    }
}

/// Writer-side `HeaderReadLimits::max_recipient_body_len` is enforced
/// against native body lengths. A caller who tightens below the v1
/// `argon2id` body length gets the same typed cap error during encrypt
/// that a reader would later return.
#[test]
fn encryptor_passphrase_header_limits_reject_tight_body_len() {
    let work = fresh_workspace("passphrase_header_body_tight");
    let input = work.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let tight = HeaderReadLimits::default().max_recipient_body_len(1);
    let result = fast_passphrase_encryptor(pass())
        .header_read_limits(tight)
        .write(&input, &out_dir, |_| {});
    match result {
        Err(CryptoError::RecipientBodyCapExceeded {
            body_len,
            local_cap,
        }) => {
            assert!(body_len > local_cap);
            assert_eq!(local_cap, 1);
        }
        other => panic!("expected RecipientBodyCapExceeded, got {other:?}"),
    }
}

/// Writer-side `HeaderReadLimits::max_header_len` is enforced against
/// the exact v1 header length the writer will emit. Tightening below
/// that shape rejects before any output is written.
#[test]
fn encryptor_recipient_header_limits_reject_tight_header_len() {
    let work = fresh_workspace("recipient_header_len_tight");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let kg = generate_key_pair(&keys, pass(), |_| {}).expect("keygen");
    let input = work.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let tight = HeaderReadLimits::default().max_header_len(32);
    let result = Encryptor::with_public_key(PublicKey::from_key_file(&kg.public_key_path))
        .header_read_limits(tight)
        .write(&input, &out_dir, |_| {});
    match result {
        Err(CryptoError::HeaderLenCapExceeded {
            header_len,
            local_cap: 32,
        }) => {
            assert!(header_len > 32);
        }
        other => panic!("expected HeaderLenCapExceeded, got {other:?}"),
    }
}

/// Writer-side KDF validation now mirrors reader-side structural rules,
/// not just the local memory cap. A `time_cost` accepted by upstream
/// Argon2 but outside FerroCrypt v1's structural range rejects at write
/// time instead of producing an undecryptable `.fcr`.
#[test]
fn encryptor_kdf_params_rejects_structural_time_cost() {
    let work = fresh_workspace("kdf_structural_time_rejects");
    let input = work.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let invalid = KdfParams {
        mem_cost: TEST_FAST_KDF_MEM_COST,
        time_cost: 13,
        lanes: 4,
    };
    let result = Encryptor::with_passphrase(pass())
        .kdf_params(invalid)
        .write(&input, &out_dir, |_| {});
    match result {
        Err(CryptoError::InvalidKdfParams(InvalidKdfParams::TimeCost(13))) => {}
        other => panic!("expected InvalidKdfParams::TimeCost(13), got {other:?}"),
    }
}

/// The floored `Encryptor::kdf_params` rejects a structurally valid but
/// below-floor `mem_cost` at write time with `KdfBelowWriteFloor`, so a
/// downstream caller cannot accidentally seal a `.fcr` with weak Argon2id
/// memory. No `.fcr` is produced.
#[test]
fn encryptor_kdf_params_rejects_below_floor() {
    let work = fresh_workspace("kdf_below_floor_rejects");
    let input = work.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let weak = KdfParams {
        mem_cost: BELOW_FLOOR_KDF_MEM, // 8 MiB, below the 19 MiB floor
        time_cost: 4,
        lanes: 4,
    };
    let result =
        Encryptor::with_passphrase(pass())
            .kdf_params(weak)
            .write(&input, &out_dir, |_| {});
    match result {
        Err(CryptoError::KdfBelowWriteFloor {
            mem_cost_kib,
            floor_kib,
        }) => {
            assert_eq!(mem_cost_kib, BELOW_FLOOR_KDF_MEM);
            assert!(floor_kib > BELOW_FLOOR_KDF_MEM);
        }
        other => panic!("expected KdfBelowWriteFloor, got {other:?}"),
    }
    assert_eq!(fs::read_dir(&out_dir).unwrap().count(), 0);
}

/// `KeyPairGenerator::kdf_params` applies the same floor as the
/// passphrase path, so a below-floor `mem_cost` cannot accidentally seal
/// a weak `private.key`.
#[test]
fn keypair_generator_kdf_params_rejects_below_floor() {
    let work = fresh_workspace("keypair_kdf_below_floor_rejects");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();

    let weak = KdfParams {
        mem_cost: BELOW_FLOOR_KDF_MEM,
        time_cost: 4,
        lanes: 4,
    };
    let result = KeyPairGenerator::with_passphrase(pass())
        .kdf_params(weak)
        .write(&keys, |_| {});
    match result {
        Err(CryptoError::KdfBelowWriteFloor { mem_cost_kib, .. }) => {
            assert_eq!(mem_cost_kib, BELOW_FLOOR_KDF_MEM);
        }
        other => panic!("expected KdfBelowWriteFloor, got {other:?}"),
    }
}

/// Even with an explicitly raised writer-side `KdfLimit`, structural
/// `mem_cost` above FerroCrypt's v1 maximum must reject before Argon2id
/// runs. This prevents the resource-limit opt-in from bypassing the
/// file-format structural ceiling.
#[test]
fn encryptor_kdf_params_rejects_structural_mem_cost_even_with_raised_limit() {
    let work = fresh_workspace("kdf_structural_mem_rejects");
    let input = work.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let invalid_mem = 3 * 1024 * 1024;
    let invalid = KdfParams {
        mem_cost: invalid_mem,
        time_cost: 4,
        lanes: 4,
    };
    let result = Encryptor::with_passphrase(pass())
        .kdf_params(invalid)
        .kdf_limit(KdfLimit::new(4 * 1024 * 1024))
        .write(&input, &out_dir, |_| {});
    match result {
        Err(CryptoError::InvalidKdfParams(InvalidKdfParams::MemoryCost(n))) => {
            assert_eq!(n, invalid_mem);
        }
        other => panic!("expected InvalidKdfParams::MemoryCost, got {other:?}"),
    }
}

/// Key-pair generation uses the same writer-side KDF validator as
/// passphrase `.fcr` encryption. Invalid `lanes` rejects before a
/// `private.key` containing reader-rejected KDF params can be written.
#[test]
fn keypair_generator_kdf_params_rejects_structural_lanes() {
    let work = fresh_workspace("keypair_kdf_structural_lanes_rejects");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();

    let invalid = KdfParams {
        mem_cost: TEST_FAST_KDF_MEM_COST,
        time_cost: 1,
        lanes: 9,
    };
    let result = KeyPairGenerator::with_passphrase(pass())
        .kdf_params(invalid)
        .write(&keys, |_| {});
    match result {
        Err(CryptoError::InvalidKdfParams(InvalidKdfParams::Parallelism(9))) => {}
        other => panic!("expected InvalidKdfParams::Parallelism(9), got {other:?}"),
    }
}

/// Public API: a tightened `KdfLimit::with_max_time_cost` on `Encryptor`
/// rejects a structurally valid `kdf_params` value before Argon2id runs or any
/// `.fcr` is produced. Pins the public builder path, not only the internal
/// `KdfParams` gate.
#[test]
fn encryptor_kdf_limit_rejects_time_cost_above_tightened_cap() {
    let work = fresh_workspace("kdf_tightened_time_cost_rejects");
    let input = work.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    // `time_cost` is structurally valid (<= 12) and `mem_cost` sits at the
    // write floor, so the value reaches the resource-policy check and is
    // rejected by the tightened time-cost cap.
    let params = KdfParams {
        mem_cost: TEST_FAST_KDF_MEM_COST,
        time_cost: 8,
        lanes: 4,
    };
    let result = Encryptor::with_passphrase(pass())
        .kdf_params(params)
        .kdf_limit(KdfLimit::default().with_max_time_cost(6))
        .write(&input, &out_dir, |_| {});
    match result {
        Err(CryptoError::KdfTimeCostCapExceeded {
            time_cost,
            local_cap,
        }) => {
            assert_eq!(time_cost, 8);
            assert_eq!(local_cap, 6);
        }
        other => panic!("expected KdfTimeCostCapExceeded, got {other:?}"),
    }
    assert_eq!(
        fs::read_dir(&out_dir).unwrap().count(),
        0,
        "no .fcr should be produced when the writer rejects the params"
    );
}

/// Public API: a tightened `KdfLimit::with_max_lanes` on `KeyPairGenerator`
/// rejects a structurally valid `kdf_params` value before `private.key` is
/// written. Pins the lane-count cap through the public builder path.
#[test]
fn keypair_generator_kdf_limit_rejects_lanes_above_tightened_cap() {
    let work = fresh_workspace("keypair_kdf_tightened_lanes_rejects");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();

    let params = KdfParams {
        mem_cost: TEST_FAST_KDF_MEM_COST,
        time_cost: 4,
        lanes: 4,
    };
    let result = KeyPairGenerator::with_passphrase(pass())
        .kdf_params(params)
        .kdf_limit(KdfLimit::default().with_max_lanes(2))
        .write(&keys, |_| {});
    match result {
        Err(CryptoError::KdfLanesCapExceeded { lanes, local_cap }) => {
            assert_eq!(lanes, 4);
            assert_eq!(local_cap, 2);
        }
        other => panic!("expected KdfLanesCapExceeded, got {other:?}"),
    }
    assert_eq!(
        fs::read_dir(&keys).unwrap().count(),
        0,
        "no private.key should be produced when the generator rejects the params"
    );
}

/// Default `Encryptor::kdf_params(P)` with `P.mem_cost > KdfLimit::default()`
/// rejects at write time before Argon2id runs. The matching opt-in
/// path is pinned by [`encryptor_kdf_params_at_kdf_limit_succeeds`].
#[test]
fn encryptor_kdf_params_above_default_rejects_with_default_kdf_limit() {
    let work = fresh_workspace("kdf_above_default_rejects");
    let input = work.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    // mem_cost = default + 1 KiB — minimal overflow, still well
    // within `KdfParams::MAX_MEM_COST`, so this exercises the
    // writer-side resource cap after structural validation succeeds.
    let default_limit = KdfLimit::default();
    let oversized_params = KdfParams {
        mem_cost: default_limit.max_mem_cost_kib + 1,
        time_cost: 4,
        lanes: 4,
    };
    let result = Encryptor::with_passphrase(pass())
        .kdf_params(oversized_params)
        .write(&input, &out_dir, |_| {});
    match result {
        Err(CryptoError::KdfResourceCapExceeded {
            mem_cost_kib,
            local_cap_kib,
        }) => {
            assert_eq!(mem_cost_kib, oversized_params.mem_cost);
            assert_eq!(local_cap_kib, default_limit.max_mem_cost_kib);
        }
        other => panic!("expected KdfResourceCapExceeded, got {other:?}"),
    }
}

/// `Encryptor::kdf_params(P).kdf_limit(L)` with `P.mem_cost <= L` is
/// accepted by the writer, the resulting `.fcr` round-trips under a
/// matching reader-side `kdf_limit`, and the cap check uses `>`
/// (boundary inclusive) — `mem_cost == max_mem_cost_kib` succeeds.
///
/// The test deliberately uses `TEST_FAST_KDF_MEM_COST` (19 MiB, the
/// writer floor) so the real Argon2id run inside the assertion stays
/// fast; the same boundary semantics apply at any `mem_cost` the writer
/// might configure.
#[test]
fn encryptor_kdf_params_at_kdf_limit_succeeds() {
    let work = fresh_workspace("kdf_at_limit_succeeds");
    let input = work.join("data.txt");
    fs::write(&input, b"hello").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    // Boundary: kdf_limit at exactly fast-KDF mem_cost. Cap check
    // (`mem_cost > max_mem_cost_kib`) is `false`, so the encrypt
    // proceeds into a real (fast) Argon2id run.
    let exact = KdfLimit::new(TEST_FAST_KDF_MEM_COST);
    let outcome = fast_passphrase_encryptor(pass())
        .kdf_limit(exact)
        .write(&input, &out_dir, |_| {})
        .expect("encrypt with kdf_limit at boundary");

    // Round-trip under matching reader settings.
    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let decrypted = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::Passphrase(d) => d
            .kdf_limit(exact)
            .decrypt(pass(), &restore, |_| {})
            .expect("decrypt"),
        _ => panic!("expected passphrase decryptor"),
    };
    assert_eq!(fs::read(decrypted.output_path).unwrap(), b"hello");
}

/// Default `KeyPairGenerator::kdf_params(P)` with
/// `P.mem_cost > KdfLimit::default()` rejects at write time before
/// Argon2id runs.
#[test]
fn keypair_generator_kdf_params_above_default_rejects_with_default_kdf_limit() {
    let work = fresh_workspace("keypair_kdf_above_default_rejects");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();

    let default_limit = KdfLimit::default();
    let oversized_params = KdfParams {
        mem_cost: default_limit.max_mem_cost_kib + 1,
        time_cost: 4,
        lanes: 4,
    };
    let result = KeyPairGenerator::with_passphrase(pass())
        .kdf_params(oversized_params)
        .write(&keys, |_| {});
    match result {
        Err(CryptoError::KdfResourceCapExceeded {
            mem_cost_kib,
            local_cap_kib,
        }) => {
            assert_eq!(mem_cost_kib, oversized_params.mem_cost);
            assert_eq!(local_cap_kib, default_limit.max_mem_cost_kib);
        }
        other => panic!("expected KdfResourceCapExceeded, got {other:?}"),
    }
}

/// `KeyPairGenerator::kdf_params(P).kdf_limit(L)` with
/// `P.mem_cost <= L` produces a `private.key` whose unlock under a
/// matching `PrivateKeyDecryptor::kdf_limit(L)` succeeds.
#[test]
fn keypair_generator_kdf_params_at_kdf_limit_succeeds() {
    let work = fresh_workspace("keypair_kdf_at_limit_succeeds");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();

    let exact = KdfLimit::new(TEST_FAST_KDF_MEM_COST);
    let kg = fast_keypair_generator(pass())
        .kdf_limit(exact)
        .write(&keys, |_| {})
        .expect("keygen with kdf_limit at boundary");

    // Encrypt to that key with default Encryptor (X25519 path
    // doesn't run Argon2id), then decrypt with the matching
    // PrivateKeyDecryptor::kdf_limit so the private.key unlock
    // accepts the elevated mem_cost authenticated in the cleartext.
    let input = work.join("data.txt");
    fs::write(&input, b"x25519 round-trip via raised kdf").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let outcome = Encryptor::with_public_key(PublicKey::from_key_file(&kg.public_key_path))
        .write(&input, &out_dir, |_| {})
        .expect("encrypt");

    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let decrypted = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::PrivateKey(d) => d
            .kdf_limit(exact)
            .decrypt(
                PrivateKey::from_key_file(&kg.private_key_path),
                pass(),
                &restore,
                |_| {},
            )
            .expect("decrypt"),
        _ => panic!("expected private-key decryptor"),
    };
    assert_eq!(
        fs::read(decrypted.output_path).unwrap(),
        b"x25519 round-trip via raised kdf"
    );
}

/// A second passphrase encrypt to a path already occupied by an `.fcr`
/// file from the first run must reject *before* Argon2id fires. The
/// output-precheck inside `protocol::encrypt` runs ahead of any KDF
/// emission, so a `DerivingPassphraseWrapKey` event count of 0 on
/// the failing run proves the user did not pay for a multi-second KDF
/// just to learn the destination was occupied. Pinned as a regression
/// for BUG_REVIEW #2 — without the preflight, the failure used to
/// surface only after the KDF + recipient wrap + header build.
#[test]
fn encryptor_passphrase_rejects_existing_output_before_kdf() {
    let work = fresh_workspace("rejects_existing_output_before_kdf");
    let input = work.join("data.txt");
    fs::write(&input, b"output-conflict preflight").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    fast_passphrase_encryptor(pass())
        .write(&input, &out_dir, |_| {})
        .expect("first encrypt");

    let kdf_event_count = std::cell::Cell::new(0u32);
    let result = fast_passphrase_encryptor(pass()).write(&input, &out_dir, |evt| {
        if matches!(evt, ferrocrypt::ProgressEvent::DerivingPassphraseWrapKey) {
            kdf_event_count.set(kdf_event_count.get() + 1);
        }
    });

    match result {
        Err(CryptoError::InvalidInput(msg)) => {
            assert!(
                msg.starts_with("Output already exists:"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected InvalidInput(Output already exists), got {other:?}"),
    }
    assert_eq!(
        kdf_event_count.get(),
        0,
        "Argon2id ran before the output-conflict preflight"
    );
}

/// Companion to the test above: a dangling symlink at the encrypt
/// output path must reject up front. `Path::exists()` follows the link
/// and would return `false` (target missing), letting Argon2id run
/// before the atomic no-clobber rename finally refuses to overwrite.
/// The fix routes the precheck through `symlink_metadata`, so a
/// `DerivingPassphraseWrapKey` event count of 0 on the failing run
/// proves the user did not pay for a multi-second KDF to learn that a
/// stale symlink occupies the destination. Pinned for BUG_REVIEW #3.
#[cfg(unix)]
#[test]
fn encryptor_passphrase_rejects_dangling_symlink_at_output_before_kdf() {
    use std::os::unix::fs::symlink;

    let work = fresh_workspace("rejects_dangling_symlink_before_kdf");
    let input = work.join("data.txt");
    fs::write(&input, b"dangling-symlink preflight").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let dangling = out_dir.join("data.fcr");
    symlink(out_dir.join("absent-target"), &dangling).unwrap();
    assert!(!dangling.exists(), "sanity: target really is missing");

    let kdf_event_count = std::cell::Cell::new(0u32);
    let result = fast_passphrase_encryptor(pass()).write(&input, &out_dir, |evt| {
        if matches!(evt, ferrocrypt::ProgressEvent::DerivingPassphraseWrapKey) {
            kdf_event_count.set(kdf_event_count.get() + 1);
        }
    });

    match result {
        Err(CryptoError::InvalidInput(msg)) => {
            assert!(
                msg.starts_with("Output already exists:"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected InvalidInput(Output already exists), got {other:?}"),
    }
    assert_eq!(
        kdf_event_count.get(),
        0,
        "Argon2id ran before the dangling-symlink preflight"
    );
}

/// `PrivateKeyDecryptor::decrypt` opens and validates the input before
/// unlocking `private.key`. A malformed replacement installed between
/// `Decryptor::open` and `.decrypt` must be rejected without starting
/// Argon2id or emitting `UnlockingPrivateKey`.
#[test]
fn private_key_decrypt_revalidates_input_before_unlock() {
    let work = fresh_workspace("private_key_decrypt_revalidate");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let kg = generate_key_pair(&keys, pass(), |_| {}).expect("keygen");
    let input = work.join("data.txt");
    fs::write(&input, b"payload").unwrap();
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let outcome = Encryptor::with_public_key(PublicKey::from_key_file(&kg.public_key_path))
        .write(&input, &out_dir, |_| {})
        .expect("encrypt");

    let decryptor = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::PrivateKey(d) => d,
        other => panic!("expected private-key decryptor, got {other:?}"),
    };

    // Simulate a hostile path swap between `open` and `decrypt`:
    // replace the .fcr bytes with something that fails the magic check.
    fs::write(&outcome.output_path, b"NOT-AN-FCR-FILE").unwrap();

    let unlock_event_count = std::cell::Cell::new(0u32);
    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let err = decryptor
        .decrypt(
            PrivateKey::from_key_file(&kg.private_key_path),
            pass(),
            &restore,
            |evt| {
                if matches!(evt, ferrocrypt::ProgressEvent::UnlockingPrivateKey) {
                    unlock_event_count.set(unlock_event_count.get() + 1);
                }
            },
        )
        .expect_err("expected rejection of swapped .fcr");

    match err {
        CryptoError::InvalidFormat(FormatDefect::BadMagic) => {}
        other => panic!("expected BadMagic from the pre-unlock validation, got {other:?}"),
    }
    assert_eq!(
        unlock_event_count.get(),
        0,
        "Argon2id unlock ran before the swapped-input rejection",
    );
}

/// An input under an unreadable directory is a permission problem, not
/// a missing file: `Decryptor::open` must surface `Io(PermissionDenied)`
/// rather than collapsing the failure into `InputPath`.
#[cfg(unix)]
#[test]
fn decryptor_open_reports_permission_error_not_missing_input() {
    use std::os::unix::fs::PermissionsExt;

    let work = fresh_workspace("open_permission_error");
    let blocked_dir = work.join("blocked");
    fs::create_dir_all(&blocked_dir).unwrap();
    let input = blocked_dir.join("file.fcr");
    fs::write(&input, b"irrelevant").unwrap();

    fs::set_permissions(&blocked_dir, fs::Permissions::from_mode(0o000)).unwrap();
    // Root bypasses directory permissions; the scenario cannot be
    // produced there, so the assertion would be meaningless.
    if fs::symlink_metadata(&input).is_ok() {
        fs::set_permissions(&blocked_dir, fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }

    let result = Decryptor::open(&input);
    fs::set_permissions(&blocked_dir, fs::Permissions::from_mode(0o700)).unwrap();

    match result {
        Err(CryptoError::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "got: {e}");
        }
        other => panic!("expected Io(PermissionDenied), got {other:?}"),
    }
}
