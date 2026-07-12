/// Integration tests for ferrocrypt library
mod common;

use std::fs;
use std::path::{Path, PathBuf};

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    CryptoError, ENCRYPTED_EXTENSION, PublicKey, decode_recipient_string, probe_recipient_mode,
    validate_private_key_file,
};

use common::{generate_key_pair, passphrase_auto, recipient_auto};

const TEST_WORKSPACE: &str = "tests/workspace";

fn setup_test_dir(test_name: &str) -> PathBuf {
    // Per-process subtree, so a concurrent `cargo test` invocation of
    // this binary cannot delete files this run is using.
    let test_dir = ferrocrypt_test_support::per_process_workspace(TEST_WORKSPACE).join(test_name);
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("Failed to clean test directory");
    }
    fs::create_dir_all(&test_dir).expect("Failed to create test directory");
    test_dir
}

fn create_test_file(path: &Path, content: &str) -> PathBuf {
    fs::write(path, content).expect("Failed to write test file");
    path.to_path_buf()
}

fn create_test_directory(base: &Path) -> PathBuf {
    let test_dir = base.join("test_folder");
    fs::create_dir_all(&test_dir).expect("Failed to create test directory");

    create_test_file(&test_dir.join("file1.txt"), "Content of file 1");
    create_test_file(&test_dir.join("file2.txt"), "Content of file 2");

    let subdir = test_dir.join("subdir");
    fs::create_dir_all(&subdir).expect("Failed to create subdirectory");
    create_test_file(&subdir.join("file3.txt"), "Content of file 3");

    test_dir
}

fn cleanup_test_workspace() {
    ferrocrypt_test_support::remove_per_process_workspace(TEST_WORKSPACE);
}

#[test]
fn test_passphrase_encrypt_decrypt_single_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("passphrase_single_file");
    let input_file = test_dir.join("input.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let original_content = "This is a test file with sensitive data.";
    create_test_file(&input_file, original_content);

    let passphrase = SecretString::from("test_password_123".to_string());

    // Encrypt
    let encrypt_result =
        passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    assert!(encrypt_result.exists());
    assert!(encrypt_dir.join("input.fcr").exists());

    // Decrypt
    let decrypt_result = passphrase_auto(
        encrypt_dir.join("input.fcr"),
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    assert!(decrypt_result.exists());

    // Verify content
    let decrypted_content = fs::read_to_string(decrypt_dir.join("input.txt"))?;
    assert_eq!(original_content, decrypted_content);

    Ok(())
}

#[test]
fn test_passphrase_encrypt_decrypt_directory() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("passphrase_directory");
    let input_dir = create_test_directory(&test_dir);
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let passphrase = SecretString::from("directory_password".to_string());

    // Encrypt directory
    let encrypt_result =
        passphrase_auto(&input_dir, &encrypt_dir, &passphrase, None, None, |_| {})?;

    assert!(encrypt_result.exists());
    assert!(encrypt_dir.join("test_folder.fcr").exists());

    // Decrypt directory
    let decrypt_result = passphrase_auto(
        encrypt_dir.join("test_folder.fcr"),
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    assert!(decrypt_result.exists());

    // Verify directory structure and content
    let decrypted_dir = decrypt_dir.join("test_folder");
    assert!(decrypted_dir.exists());
    assert!(decrypted_dir.join("file1.txt").exists());
    assert!(decrypted_dir.join("file2.txt").exists());
    assert!(decrypted_dir.join("subdir/file3.txt").exists());

    let content1 = fs::read_to_string(decrypted_dir.join("file1.txt"))?;
    assert_eq!("Content of file 1", content1);

    let content3 = fs::read_to_string(decrypted_dir.join("subdir/file3.txt"))?;
    assert_eq!("Content of file 3", content3);

    Ok(())
}

/// Regression guard for directory-root durability syncs (`FORMAT.md`
/// §9.11). A stored subdirectory mode of `0o500` must not prevent
/// extraction: the reader writes children while the staged directory is
/// still `0o700`, syncs the directory, then applies the stored mode.
/// The test verifies both the extracted content and the final mode.
#[cfg(unix)]
#[test]
fn test_decrypt_directory_with_read_only_subdir() -> Result<(), CryptoError> {
    use std::os::unix::fs::PermissionsExt;

    let test_dir = setup_test_dir("dir_readonly_subdir");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // Tighten the subdirectory mode after writing its file. The source
    // keeps read and search permissions, so the archive writer can walk it.
    let source = test_dir.join("ro_folder");
    let subdir = source.join("locked");
    fs::create_dir_all(&subdir)?;
    create_test_file(&source.join("top.txt"), "top-level content");
    create_test_file(&subdir.join("inside.txt"), "nested content");
    fs::set_permissions(&subdir, fs::Permissions::from_mode(0o500))?;

    let passphrase = SecretString::from("ro-subdir-password".to_string());
    let encrypt_result = passphrase_auto(&source, &encrypt_dir, &passphrase, None, None, |_| {});
    // Restore write on the source subdirectory even if encryption
    // fails, so workspace cleanup can remove it.
    let _ = fs::set_permissions(&subdir, fs::Permissions::from_mode(0o700));
    encrypt_result?;

    passphrase_auto(
        encrypt_dir.join("ro_folder.fcr"),
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    // Restore write before assertions so a failed assertion cannot leave
    // a 0o500 directory that prevents later cleanup.
    let out = decrypt_dir.join("ro_folder");
    let out_subdir = out.join("locked");
    let top_exists = out.join("top.txt").exists();
    let inside_content = fs::read_to_string(out_subdir.join("inside.txt")).ok();
    let subdir_mode = fs::metadata(&out_subdir)
        .map(|m| m.permissions().mode() & 0o777)
        .ok();
    let _ = fs::set_permissions(&out_subdir, fs::Permissions::from_mode(0o700));

    assert!(top_exists, "top-level file must extract");
    assert_eq!(
        inside_content.as_deref(),
        Some("nested content"),
        "file under the read-only subdirectory must extract with its content"
    );
    assert_eq!(
        subdir_mode,
        Some(0o500),
        "subdirectory mode must round-trip"
    );

    Ok(())
}

#[test]
fn test_passphrase_wrong_password() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("passphrase_wrong_password");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Secret content");

    let correct_pass = SecretString::from("correct_password".to_string());
    let wrong_pass = SecretString::from("wrong_password".to_string());

    // Encrypt with correct password
    passphrase_auto(&input_file, &encrypt_dir, &correct_pass, None, None, |_| {})?;

    // Try to decrypt with wrong password - should fail
    let result = passphrase_auto(
        encrypt_dir.join("secret.fcr"),
        &decrypt_dir,
        &wrong_pass,
        None,
        None,
        |_| {},
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::RecipientUnwrapFailed { ref type_name }) if type_name == "argon2id" => {}
        other => panic!(
            "Expected RecipientUnwrapFailed {{ type_name: \"argon2id\" }}, got {:?}",
            other
        ),
    }

    Ok(())
}

/// Appending bytes to a finished `.fcr` file must fail closed at the
/// public API level. STREAM-BE32's per-chunk nonce binding rejects the
/// append as a tampered final chunk, so the user-visible variant is
/// `PayloadTampered`. The dedicated `ExtraDataAfterPayload` variant
/// covers the orthogonal "pathological reader signals EOF then yields
/// more bytes" case, which is unreachable through a path-based API
/// (`File`'s `Read` impl does not violate the trait contract that way)
/// — that branch is exercised by `streaming_aead_extra_data_after_final_chunk_rejected`
/// in `common.rs::tests` via a custom `Read` wrapper, and the
/// `From<io::Error>` mapping is locked in by
/// `stream_error_markers_map_to_typed_variants` in `error.rs::tests`.
/// Together these three tests form the regression coverage for the
/// trailing-data probe wiring; this integration test pins the
/// realistic file-with-appended-bytes shape through the public API.
#[test]
fn test_passphrase_appended_bytes_fail_closed_at_public_api() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("passphrase_appended_bytes");
    let input_file = test_dir.join("payload.bin");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // Multi-chunk plaintext so the final partial chunk is short and
    // the appended bytes land alongside it inside `decrypt_last`'s
    // input buffer (the realistic on-disk shape for an attacker
    // tacking bytes onto a finished `.fcr`).
    let big_data: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();
    fs::write(&input_file, &big_data)?;

    let passphrase = SecretString::from("appended_pass".to_string());
    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("payload.fcr");
    let mut ct = fs::read(&encrypted_path)?;
    ct.extend_from_slice(b"garbage-appended-by-attacker");
    fs::write(&encrypted_path, &ct)?;

    match passphrase_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    ) {
        Err(CryptoError::PayloadTampered) => Ok(()),
        other => panic!("expected PayloadTampered for appended bytes, got {other:?}"),
    }
}

#[test]
fn test_passphrase_payload_tamper_mid_chunk() -> Result<(), CryptoError> {
    // Flipping a byte inside a ciphertext chunk (not the header) must
    // surface as PayloadTampered, not as a generic Io error.
    let test_dir = setup_test_dir("passphrase_payload_tamper");
    let input_file = test_dir.join("payload.bin");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // Big enough to span multiple AEAD chunks so the tamper lands well
    // past the header region.
    let big_data: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();
    fs::write(&input_file, &big_data)?;

    let passphrase = SecretString::from("tamper_pass".to_string());
    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("payload.fcr");
    let mut ct = fs::read(&encrypted_path)?;
    // Flip a byte deep into the ciphertext, far past the header region.
    let flip_offset = ct.len() / 2;
    ct[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &ct)?;

    let result = passphrase_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );
    match result {
        Err(CryptoError::PayloadTampered) => {}
        other => panic!("Expected PayloadTampered, got {:?}", other),
    }

    Ok(())
}

#[test]
fn test_passphrase_decrypt_delete_on_error_removes_incomplete_after_payload_tamper()
-> Result<(), CryptoError> {
    use ferrocrypt::{Decryptor, IncompleteOutputPolicy};

    let test_dir = setup_test_dir("decrypt_delete_on_error");
    let input_file = test_dir.join("payload.bin");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // Multi-chunk plaintext so the tamper-byte at ct.len()/2 lands
    // inside a non-first STREAM chunk. Earlier chunks succeed and
    // stream their bytes into `.incomplete`; the tampered chunk fails
    // mid-extract, so cleanup has to handle a partially-populated
    // `.incomplete` working tree.
    let big_data: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();
    fs::write(&input_file, &big_data)?;

    let passphrase = SecretString::from("delete-pass".to_string());
    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("payload.fcr");
    let mut ct = fs::read(&encrypted_path)?;
    let flip_offset = ct.len() / 2;
    ct[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &ct)?;

    let Decryptor::Passphrase(decryptor) = Decryptor::open(&encrypted_path)? else {
        panic!("expected passphrase-sealed file");
    };
    let result = decryptor
        .incomplete_output_policy(IncompleteOutputPolicy::DeleteOnError)
        .decrypt(passphrase, &decrypt_dir, |_| {});
    match result {
        Err(CryptoError::PayloadTampered) => {}
        other => panic!("expected PayloadTampered, got {other:?}"),
    }

    let working_path = decrypt_dir.join("payload.bin.incomplete");
    assert!(
        fs::symlink_metadata(&working_path).is_err(),
        "DeleteOnError must remove .incomplete; still present: {}",
        working_path.display()
    );
    let final_path = decrypt_dir.join("payload.bin");
    assert!(
        fs::symlink_metadata(&final_path).is_err(),
        "final name must not exist after a failed decrypt"
    );
    Ok(())
}

#[test]
fn test_passphrase_decrypt_retain_on_error_keeps_incomplete_after_payload_tamper()
-> Result<(), CryptoError> {
    use ferrocrypt::{Decryptor, IncompleteOutputPolicy};

    let test_dir = setup_test_dir("decrypt_retain_on_error");
    let input_file = test_dir.join("payload.bin");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let big_data: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();
    fs::write(&input_file, &big_data)?;

    let passphrase = SecretString::from("retain-pass".to_string());
    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("payload.fcr");
    let mut ct = fs::read(&encrypted_path)?;
    let flip_offset = ct.len() / 2;
    ct[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &ct)?;

    let Decryptor::Passphrase(decryptor) = Decryptor::open(&encrypted_path)? else {
        panic!("expected passphrase-sealed file");
    };
    let result = decryptor
        .incomplete_output_policy(IncompleteOutputPolicy::RetainOnError)
        .decrypt(passphrase, &decrypt_dir, |_| {});
    assert!(matches!(result, Err(CryptoError::PayloadTampered)));

    let working_path = decrypt_dir.join("payload.bin.incomplete");
    let meta = fs::symlink_metadata(&working_path).expect("RetainOnError must keep .incomplete");
    assert!(
        meta.is_file(),
        "expected staged file at {}",
        working_path.display()
    );
    Ok(())
}

#[test]
fn test_passphrase_decrypt_default_policy_removes_incomplete() -> Result<(), CryptoError> {
    use ferrocrypt::Decryptor;

    // Confirms the implicit default (no `.incomplete_output_policy`
    // call) matches `IncompleteOutputPolicy::DeleteOnError`.
    let test_dir = setup_test_dir("decrypt_default_policy");
    let input_file = test_dir.join("payload.bin");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let big_data: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();
    fs::write(&input_file, &big_data)?;

    let passphrase = SecretString::from("default-pass".to_string());
    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("payload.fcr");
    let mut ct = fs::read(&encrypted_path)?;
    let flip_offset = ct.len() / 2;
    ct[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &ct)?;

    let Decryptor::Passphrase(decryptor) = Decryptor::open(&encrypted_path)? else {
        panic!("expected passphrase-sealed file");
    };
    let result = decryptor.decrypt(passphrase, &decrypt_dir, |_| {});
    assert!(matches!(result, Err(CryptoError::PayloadTampered)));

    let working_path = decrypt_dir.join("payload.bin.incomplete");
    assert!(
        fs::symlink_metadata(&working_path).is_err(),
        "default policy must match DeleteOnError; still present: {}",
        working_path.display()
    );
    Ok(())
}

#[test]
fn test_passphrase_encrypt_decrypt_multi_chunk_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("passphrase_multi_chunk");
    let input_file = test_dir.join("multi_chunk.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // The content must span several 64 KiB payload chunks so this actually
    // exercises multi-chunk streaming — multiple full `next` chunks plus a
    // partial `last` chunk (FORMAT.md §5). 210,000 bytes spans four chunks;
    // the previous 10,500-byte content fit inside a single chunk, so a
    // multi-chunk streaming regression would have passed unnoticed.
    let content = "Multi chunk content. ".repeat(10_000);
    assert!(
        content.len() > 3 * 65_536,
        "test content must span multiple 64 KiB payload chunks (got {} bytes)",
        content.len()
    );
    create_test_file(&input_file, &content);

    let passphrase = SecretString::from("multi_chunk_password".to_string());

    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    assert!(encrypt_dir.join("multi_chunk.fcr").exists());

    passphrase_auto(
        encrypt_dir.join("multi_chunk.fcr"),
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    let decrypted_content = fs::read_to_string(decrypt_dir.join("multi_chunk.txt"))?;
    assert_eq!(content, decrypted_content);

    Ok(())
}

#[test]
fn test_recipient_keygen_rejects_empty_passphrase() {
    let test_dir = setup_test_dir("keygen_empty_pass");
    let empty = SecretString::from("".to_string());

    let err = generate_key_pair(&empty, &test_dir, |_| {}).unwrap_err();
    assert!(
        err.to_string().contains("empty"),
        "expected empty-passphrase error, got: {err}"
    );
}

/// M-3 regression: `PrivateKeyDecryptor::decrypt` must reject an empty
/// passphrase at the top of the function, before `open_x25519_private_key`
/// and any KDF work runs. Pre-restructure the hybrid path was a
/// consistency gap that let an empty passphrase burn an Argon2id cycle
/// on the private-key file before failing.
#[test]
fn test_recipient_decrypt_rejects_empty_passphrase_before_kdf() {
    use ferrocrypt::{Decryptor, Encryptor, PrivateKey, ProgressEvent, PublicKey};
    use ferrocrypt_test_support::fast_keypair_generator;
    use std::cell::Cell;

    let test_dir = setup_test_dir("recipient_decrypt_empty_pass");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    // Build a real recipient `.fcr` so `Decryptor::open` returns the
    // `PrivateKey` variant. Setup events fire here, before we install
    // the observing closure.
    let setup_pass = SecretString::from("setup-pass".to_string());
    let kg = fast_keypair_generator(setup_pass)
        .write(&keys_dir, |_| {})
        .expect("generate fixture key pair");
    let input = test_dir.join("data.txt");
    fs::write(&input, b"x").unwrap();
    let encrypted_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypted_dir).unwrap();
    let outcome = Encryptor::with_public_key(PublicKey::from_key_file(&kg.public_key_path))
        .write(&input, &encrypted_dir, |_| {})
        .expect("encrypt fixture file");

    let restore_dir = test_dir.join("restored");
    fs::create_dir_all(&restore_dir).unwrap();
    let saw_kdf_event = Cell::new(false);
    let err = match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::PrivateKey(d) => d
            .decrypt(
                PrivateKey::from_key_file(&kg.private_key_path),
                SecretString::from(String::new()),
                &restore_dir,
                |ev| {
                    if matches!(
                        ev,
                        ProgressEvent::UnlockingPrivateKey
                            | ProgressEvent::DerivingPassphraseWrapKey
                    ) {
                        saw_kdf_event.set(true);
                    }
                },
            )
            .unwrap_err(),
        other => panic!("expected PrivateKey decryptor, got {other:?}"),
    };

    assert!(
        err.to_string().contains("empty"),
        "expected empty-passphrase error, got: {err}"
    );
    assert!(
        !saw_kdf_event.get(),
        "no KDF event must fire before the empty-passphrase check"
    );
}

/// M-4 regression: `Encryptor::write` must reject a symlink input with
/// a typed `InvalidInput` error *before* kicking off Argon2id. Pre-audit
/// the rejection happened inside `archive::archive`, which runs after
/// the KDF — an accidental symlink cost the user seconds and up to 1 GiB
/// of RAM. Observes the `DerivingPassphraseWrapKey` progress event to
/// prove the rejection short-circuits the KDF path.
#[cfg(unix)]
#[test]
fn test_passphrase_encrypt_rejects_symlink_before_kdf() {
    use ferrocrypt::{Encryptor, ProgressEvent};
    use std::cell::Cell;
    use std::os::unix::fs::symlink;

    let test_dir = setup_test_dir("passphrase_encrypt_symlink");
    let target = create_test_file(&test_dir.join("real.txt"), "data");
    let link = test_dir.join("link.txt");
    symlink(&target, &link).expect("failed to create symlink");

    let output_dir = test_dir.join("out");
    fs::create_dir_all(&output_dir).unwrap();
    let passphrase = SecretString::from("pass".to_string());

    let saw_kdf_event = Cell::new(false);
    let err = Encryptor::with_passphrase(passphrase)
        .write(&link, &output_dir, |ev| {
            if matches!(ev, ProgressEvent::DerivingPassphraseWrapKey) {
                saw_kdf_event.set(true);
            }
        })
        .unwrap_err();

    match err {
        CryptoError::InvalidInput(ref msg) => {
            assert!(
                msg.contains("symlink"),
                "expected symlink error, got: {msg}"
            );
        }
        other => panic!("expected InvalidInput, got: {other:?}"),
    }
    assert!(
        !saw_kdf_event.get(),
        "no KDF event must fire before the symlink check"
    );
}

/// L-2 regression: on a successful public-key decrypt, `UnlockingPrivateKey`
/// fires before the private-key Argon2id runs and `Decrypting` fires only after
/// the envelope/HMAC checks pass (just before streaming unarchive). Pre-audit
/// the path emitted `Decrypting` immediately at the top of `hybrid::decrypt_file`
/// and never emitted any KDF event, so a UI would mislabel the multi-second KDF
/// window as "decrypting". (Post-#7: the legacy single `DerivingKey` event was
/// split into `UnlockingPrivateKey` for the `private.key` Argon2id boundary
/// and `DerivingPassphraseWrapKey` for the passphrase recipient.)
#[test]
fn test_recipient_decrypt_progress_events_in_order() -> Result<(), CryptoError> {
    use ferrocrypt::ProgressEvent;
    use std::sync::Mutex;

    let test_dir = setup_test_dir("recipient_decrypt_progress");
    let keys_dir = test_dir.join("keys");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let passphrase = SecretString::from("pass".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    let input_file = test_dir.join("data.txt");
    create_test_file(&input_file, "hybrid progress order");

    let public_key_path = keys_dir.join("public.key");
    recipient_auto(
        &input_file,
        &encrypt_dir,
        &public_key_path,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    let encrypted_path = encrypt_dir.join("data.fcr");
    let events: Mutex<Vec<ProgressEvent>> = Mutex::new(Vec::new());
    recipient_auto(
        &encrypted_path,
        &decrypt_dir,
        keys_dir.join("private.key"),
        &passphrase,
        None,
        None,
        |ev| events.lock().unwrap().push(*ev),
    )?;

    let events = events.into_inner().unwrap();
    let unlocking_at = events
        .iter()
        .position(|e| matches!(e, ProgressEvent::UnlockingPrivateKey));
    let decrypting_at = events
        .iter()
        .position(|e| matches!(e, ProgressEvent::Decrypting));
    let unlocking_at = unlocking_at.expect("UnlockingPrivateKey must fire on public-key decrypt");
    let decrypting_at = decrypting_at.expect("Decrypting must fire on public-key decrypt");
    assert!(
        unlocking_at < decrypting_at,
        "UnlockingPrivateKey ({unlocking_at}) must fire before Decrypting ({decrypting_at}); events: {events:?}"
    );
    // Recipient (X25519) decrypt MUST NOT fire `DerivingPassphraseWrapKey`
    // — that event belongs to the passphrase-recipient slot loop, not
    // to the X25519 unwrap path.
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, ProgressEvent::DerivingPassphraseWrapKey)),
        "public-key decrypt must not emit DerivingPassphraseWrapKey; events: {events:?}"
    );

    Ok(())
}

/// Companion of `test_recipient_decrypt_progress_events_in_order` for
/// the passphrase mode: a successful passphrase encrypt followed by a
/// successful passphrase decrypt must emit exactly one
/// `DerivingPassphraseWrapKey` per operation (paired with `Encrypting`
/// or `Decrypting`), and zero `UnlockingPrivateKey` events at any
/// point — the passphrase path never opens a `private.key`. Pinned
/// after #7 to guarantee the work-boundary contract for the
/// passphrase recipient stays honest end to end.
#[test]
fn test_passphrase_decrypt_progress_events_in_order() -> Result<(), CryptoError> {
    use ferrocrypt::ProgressEvent;
    use std::sync::Mutex;

    let test_dir = setup_test_dir("passphrase_decrypt_progress");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let passphrase = SecretString::from("passphrase progress order".to_string());
    let input_file = test_dir.join("data.txt");
    create_test_file(&input_file, "passphrase progress order");

    let encrypt_events: Mutex<Vec<ProgressEvent>> = Mutex::new(Vec::new());
    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |ev| {
        encrypt_events.lock().unwrap().push(*ev)
    })?;

    let encrypted_path = encrypt_dir.join("data.fcr");
    let decrypt_events: Mutex<Vec<ProgressEvent>> = Mutex::new(Vec::new());
    passphrase_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |ev| decrypt_events.lock().unwrap().push(*ev),
    )?;

    let encrypt_events = encrypt_events.into_inner().unwrap();
    let decrypt_events = decrypt_events.into_inner().unwrap();

    let count =
        |evs: &[ProgressEvent], target: ProgressEvent| evs.iter().filter(|e| **e == target).count();

    assert_eq!(
        count(&encrypt_events, ProgressEvent::DerivingPassphraseWrapKey),
        1,
        "passphrase encrypt must emit exactly one DerivingPassphraseWrapKey; events: {encrypt_events:?}"
    );
    assert_eq!(
        count(&encrypt_events, ProgressEvent::UnlockingPrivateKey),
        0,
        "passphrase encrypt must not emit UnlockingPrivateKey; events: {encrypt_events:?}"
    );

    assert_eq!(
        count(&decrypt_events, ProgressEvent::DerivingPassphraseWrapKey),
        1,
        "passphrase decrypt must emit exactly one DerivingPassphraseWrapKey; events: {decrypt_events:?}"
    );
    assert_eq!(
        count(&decrypt_events, ProgressEvent::UnlockingPrivateKey),
        0,
        "passphrase decrypt must not emit UnlockingPrivateKey; events: {decrypt_events:?}"
    );

    let deriving_at = encrypt_events
        .iter()
        .position(|e| matches!(e, ProgressEvent::DerivingPassphraseWrapKey))
        .unwrap();
    let encrypting_at = encrypt_events
        .iter()
        .position(|e| matches!(e, ProgressEvent::Encrypting))
        .expect("Encrypting must fire");
    assert!(
        deriving_at < encrypting_at,
        "DerivingPassphraseWrapKey ({deriving_at}) must precede Encrypting ({encrypting_at}); events: {encrypt_events:?}"
    );

    let deriving_at = decrypt_events
        .iter()
        .position(|e| matches!(e, ProgressEvent::DerivingPassphraseWrapKey))
        .unwrap();
    let decrypting_at = decrypt_events
        .iter()
        .position(|e| matches!(e, ProgressEvent::Decrypting))
        .expect("Decrypting must fire");
    assert!(
        deriving_at < decrypting_at,
        "DerivingPassphraseWrapKey ({deriving_at}) must precede Decrypting ({decrypting_at}); events: {decrypt_events:?}"
    );

    Ok(())
}

/// Pure-X25519 encrypt MUST emit zero KDF events (no
/// `DerivingPassphraseWrapKey`, no `UnlockingPrivateKey`) — every
/// recipient is wrapped via X25519, which is sub-millisecond. Pre-#7
/// the orchestrator emitted a generic `DerivingKey` here, lying about
/// a multi-second pause that never happened.
#[test]
fn test_recipient_encrypt_emits_no_kdf_events() -> Result<(), CryptoError> {
    use ferrocrypt::ProgressEvent;
    use std::sync::Mutex;

    let test_dir = setup_test_dir("recipient_encrypt_no_kdf_events");
    let keys_dir = test_dir.join("keys");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;

    let passphrase = SecretString::from("pass".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    let input_file = test_dir.join("data.txt");
    create_test_file(&input_file, "x25519 encrypt no kdf events");

    let public_key_path = keys_dir.join("public.key");
    let events: Mutex<Vec<ProgressEvent>> = Mutex::new(Vec::new());
    recipient_auto(
        &input_file,
        &encrypt_dir,
        &public_key_path,
        &passphrase,
        None,
        None,
        |ev| events.lock().unwrap().push(*ev),
    )?;

    let events = events.into_inner().unwrap();
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, ProgressEvent::DerivingPassphraseWrapKey)),
        "X25519 encrypt must not emit DerivingPassphraseWrapKey; events: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, ProgressEvent::UnlockingPrivateKey)),
        "X25519 encrypt must not emit UnlockingPrivateKey; events: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ProgressEvent::Encrypting)),
        "X25519 encrypt must emit Encrypting; events: {events:?}"
    );

    Ok(())
}

#[cfg(unix)]
#[test]
fn test_recipient_keygen_private_key_permissions() -> Result<(), CryptoError> {
    use std::os::unix::fs::PermissionsExt;

    let test_dir = setup_test_dir("keygen_permissions");
    let passphrase = SecretString::from("pass".to_string());

    generate_key_pair(&passphrase, &test_dir, |_| {})?;

    let private_key_path = test_dir.join("private.key");
    let pub_key = test_dir.join("public.key");
    let priv_mode = fs::metadata(&private_key_path)?.permissions().mode() & 0o777;
    let pub_mode = fs::metadata(&pub_key)?.permissions().mode() & 0o777;

    assert_eq!(priv_mode, 0o600, "private key should be owner-only");
    assert_ne!(pub_mode, 0o600, "public key should not be restricted");

    Ok(())
}

#[test]
fn test_recipient_keygen_encrypt_decrypt_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("recipient_full_workflow");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let original_content = "Hybrid encryption test data";
    create_test_file(&input_file, original_content);

    let key_passphrase = SecretString::from("key_protection_password".to_string());

    // Generate key pair
    let keygen_result = generate_key_pair(&key_passphrase, &keys_dir, |_| {})?;

    assert!(keygen_result.private_key_path.exists());
    assert!(keygen_result.public_key_path.exists());
    assert_eq!(keygen_result.fingerprint.len(), 64);

    // Encrypt with public key
    let pub_key_path = keys_dir.join("public.key");
    let empty_pass = SecretString::from("".to_string());

    let encrypt_result = recipient_auto(
        &input_file,
        &encrypt_dir,
        &pub_key_path,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    assert!(encrypt_result.exists());
    assert!(encrypt_dir.join("data.fcr").exists());

    // Decrypt with private key
    let private_key_path = keys_dir.join("private.key");

    let decrypt_result = recipient_auto(
        encrypt_dir.join("data.fcr"),
        &decrypt_dir,
        &private_key_path,
        &key_passphrase,
        None,
        None,
        |_| {},
    )?;

    assert!(decrypt_result.exists());

    // Verify content
    let decrypted_content = fs::read_to_string(decrypt_dir.join("data.txt"))?;
    assert_eq!(original_content, decrypted_content);

    Ok(())
}

#[test]
fn test_recipient_encrypt_decrypt_directory() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("recipient_directory");
    let keys_dir = test_dir.join("keys");
    let input_dir = create_test_directory(&test_dir);
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let key_passphrase = SecretString::from("hybrid_dir_key_pass".to_string());

    // Generate keys
    generate_key_pair(&key_passphrase, &keys_dir, |_| {})?;

    // Encrypt directory
    let pub_key_path = keys_dir.join("public.key");
    let empty_pass = SecretString::from("".to_string());

    recipient_auto(
        &input_dir,
        &encrypt_dir,
        &pub_key_path,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    assert!(encrypt_dir.join("test_folder.fcr").exists());

    // Decrypt directory
    let private_key_path = keys_dir.join("private.key");

    recipient_auto(
        encrypt_dir.join("test_folder.fcr"),
        &decrypt_dir,
        &private_key_path,
        &key_passphrase,
        None,
        None,
        |_| {},
    )?;

    // Verify directory structure
    let decrypted_dir = decrypt_dir.join("test_folder");
    assert!(decrypted_dir.exists());
    assert!(decrypted_dir.join("file1.txt").exists());
    assert!(decrypted_dir.join("subdir/file3.txt").exists());

    Ok(())
}

#[test]
fn test_recipient_wrong_key_passphrase() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("recipient_wrong_passphrase");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Sensitive data");

    let correct_pass = SecretString::from("correct_key_pass".to_string());
    let wrong_pass = SecretString::from("wrong_key_pass".to_string());

    // Generate keys with correct passphrase
    generate_key_pair(&correct_pass, &keys_dir, |_| {})?;

    // Encrypt
    let pub_key_path = keys_dir.join("public.key");
    let empty_pass = SecretString::from("".to_string());

    recipient_auto(
        &input_file,
        &encrypt_dir,
        &pub_key_path,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    // Try to decrypt with wrong passphrase for the private key file.
    // The passphrase protects the private key file itself, so a wrong
    // passphrase fails at the key-file unlock stage.
    let private_key_path = keys_dir.join("private.key");

    let result = recipient_auto(
        encrypt_dir.join("data.fcr"),
        &decrypt_dir,
        &private_key_path,
        &wrong_pass,
        None,
        None,
        |_| {},
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::KeyFileUnlockFailed) => {}
        other => panic!("Expected KeyFileUnlockFailed, got {:?}", other),
    }

    Ok(())
}

#[test]
fn test_empty_file_encryption() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("empty_file");
    let input_file = test_dir.join("empty.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // Create empty file
    create_test_file(&input_file, "");

    let passphrase = SecretString::from("empty_test".to_string());

    // Encrypt empty file
    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // Decrypt
    passphrase_auto(
        encrypt_dir.join("empty.fcr"),
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    // Verify empty file was preserved
    let decrypted_content = fs::read_to_string(decrypt_dir.join("empty.txt"))?;
    assert_eq!("", decrypted_content);

    Ok(())
}

#[test]
fn test_unicode_content() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("unicode_content");
    let input_file = test_dir.join("unicode.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let unicode_content = "Hello 世界! Привет мир! مرحبا بالعالم! 🔐🚀";
    create_test_file(&input_file, unicode_content);

    let passphrase = SecretString::from("unicode_pass".to_string());

    // Encrypt
    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // Decrypt
    passphrase_auto(
        encrypt_dir.join("unicode.fcr"),
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    // Verify unicode content
    let decrypted_content = fs::read_to_string(decrypt_dir.join("unicode.txt"))?;
    assert_eq!(unicode_content, decrypted_content);

    Ok(())
}

#[test]
fn test_special_characters_in_filename() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("special_filenames");
    let input_file = test_dir.join("file-with_special.chars.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Content with special filename");

    let passphrase = SecretString::from("special_pass".to_string());

    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    passphrase_auto(
        encrypt_dir.join("file-with_special.chars.fcr"),
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    assert!(decrypt_dir.join("file-with_special.chars.txt").exists());

    Ok(())
}

#[test]
fn test_nonexistent_output_dir() {
    let passphrase = SecretString::from("test".to_string());

    let result = passphrase_auto(
        "Cargo.toml",
        "/nonexistent/path/output",
        &passphrase,
        None,
        None,
        |_| {},
    );

    assert!(result.is_err());
}

#[test]
fn test_decrypt_nonexistent_fcr_file() {
    let test_dir = setup_test_dir("decrypt_nonexistent");
    let missing = test_dir.join("missing.fcr");

    // Call the public API directly. The `passphrase_auto` shim short-circuits
    // on a missing path, so routing through it would test the shim, not the
    // library. `Decryptor::open` on an absent file must report the typed
    // `InputPath`, not a generic I/O error.
    let result = ferrocrypt::Decryptor::open(&missing);
    assert!(
        matches!(result, Err(CryptoError::InputPath)),
        "opening a missing .fcr must report InputPath, got {result:?}"
    );
}

#[test]
fn test_binary_file_content() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("binary_content");
    let input_file = test_dir.join("data.bin");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // Binary data with null bytes and all byte values
    let binary_content: Vec<u8> = (0..=255).cycle().take(1024).collect();
    fs::write(&input_file, &binary_content)?;

    let passphrase = SecretString::from("binary_pass".to_string());

    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    passphrase_auto(
        encrypt_dir.join("data.fcr"),
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    let decrypted = fs::read(decrypt_dir.join("data.bin"))?;
    assert_eq!(binary_content, decrypted);

    Ok(())
}

#[test]
fn test_passphrase_streaming_wrong_password() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("streaming_wrong_password");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let content = "Large mode wrong password test. ".repeat(100);
    create_test_file(&input_file, &content);

    let correct_pass = SecretString::from("correct".to_string());
    let wrong_pass = SecretString::from("wrong".to_string());

    passphrase_auto(&input_file, &encrypt_dir, &correct_pass, None, None, |_| {})?;

    // Decrypt with wrong password
    let result = passphrase_auto(
        encrypt_dir.join("data.fcr"),
        &decrypt_dir,
        &wrong_pass,
        None,
        None,
        |_| {},
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::RecipientUnwrapFailed { ref type_name }) if type_name == "argon2id" => {}
        other => panic!(
            "Expected RecipientUnwrapFailed {{ type_name: \"argon2id\" }}, got {:?}",
            other
        ),
    }

    Ok(())
}

#[test]
fn test_passphrase_encrypt_decrypt_directory_streaming() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("directory_streaming");
    let input_dir = create_test_directory(&test_dir);
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let passphrase = SecretString::from("dir_streaming_pass".to_string());

    passphrase_auto(&input_dir, &encrypt_dir, &passphrase, None, None, |_| {})?;

    assert!(encrypt_dir.join("test_folder.fcr").exists());

    passphrase_auto(
        encrypt_dir.join("test_folder.fcr"),
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    let decrypted_dir = decrypt_dir.join("test_folder");
    assert!(decrypted_dir.exists());
    assert_eq!(
        fs::read_to_string(decrypted_dir.join("file1.txt"))?,
        "Content of file 1"
    );
    assert_eq!(
        fs::read_to_string(decrypted_dir.join("subdir/file3.txt"))?,
        "Content of file 3"
    );

    Ok(())
}

#[test]
fn test_passphrase_empty_password_rejected() {
    let test_dir = setup_test_dir("empty_password");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");

    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "Protected with empty password");

    let empty_pass = SecretString::from("".to_string());

    let result = passphrase_auto(&input_file, &encrypt_dir, &empty_pass, None, None, |_| {});

    assert!(result.is_err());
    match result {
        Err(CryptoError::InvalidInput(msg)) => {
            assert!(msg.contains("empty"));
        }
        other => panic!(
            "Expected Message error about empty passphrase, got {:?}",
            other
        ),
    }
}

#[test]
fn test_recipient_wrong_key_pair() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("recipient_wrong_keypair");
    let keys_a = test_dir.join("keys_a");
    let keys_b = test_dir.join("keys_b");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_a)?;
    fs::create_dir_all(&keys_b)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Sensitive data");

    let pass_a = SecretString::from("pass_a".to_string());
    let pass_b = SecretString::from("pass_b".to_string());

    // Generate two different key pairs
    generate_key_pair(&pass_a, &keys_a, |_| {})?;
    generate_key_pair(&pass_b, &keys_b, |_| {})?;

    // Encrypt with key pair A's public key
    let pub_key_a = keys_a.join("public.key");
    let empty_pass = SecretString::from("".to_string());

    recipient_auto(
        &input_file,
        &encrypt_dir,
        &pub_key_a,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    // Decrypt with key pair B's private key. private.key unlocks fine
    // (right passphrase), but every x25519 slot AEAD-fails because
    // ECDH was performed against A's public key. This is the supported-
    // recipient wrong-key case, surfaced as `RecipientUnwrapFailed`.
    let private_key_b = keys_b.join("private.key");

    let result = recipient_auto(
        encrypt_dir.join("data.fcr"),
        &decrypt_dir,
        &private_key_b,
        &pass_b,
        None,
        None,
        |_| {},
    );

    match result {
        Err(CryptoError::RecipientUnwrapFailed { ref type_name }) if type_name == "x25519" => {}
        other => panic!("Expected RecipientUnwrapFailed(x25519), got {:?}", other),
    }

    Ok(())
}

#[test]
fn test_recipient_key_round_trip() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("recipient_key_round_trip");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let original_content = "X25519 round-trip test";
    create_test_file(&input_file, original_content);

    let key_passphrase = SecretString::from("keypass".to_string());

    generate_key_pair(&key_passphrase, &keys_dir, |_| {})?;

    // Encrypt
    let pub_key_path = keys_dir.join("public.key");
    let empty_pass = SecretString::from("".to_string());

    recipient_auto(
        &input_file,
        &encrypt_dir,
        &pub_key_path,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    assert!(encrypt_dir.join("data.fcr").exists());

    // Decrypt
    let private_key_path = keys_dir.join("private.key");

    recipient_auto(
        encrypt_dir.join("data.fcr"),
        &decrypt_dir,
        &private_key_path,
        &key_passphrase,
        None,
        None,
        |_| {},
    )?;

    let decrypted_content = fs::read_to_string(decrypt_dir.join("data.txt"))?;
    assert_eq!(original_content, decrypted_content);

    Ok(())
}

#[test]
fn test_recipient_binary_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("recipient_binary");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.bin");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let binary_content: Vec<u8> = (0..=255).cycle().take(2048).collect();
    fs::write(&input_file, &binary_content)?;

    let key_passphrase = SecretString::from("hybrid_bin_pass".to_string());
    generate_key_pair(&key_passphrase, &keys_dir, |_| {})?;

    let pub_key_path = keys_dir.join("public.key");
    let empty_pass = SecretString::from("".to_string());

    recipient_auto(
        &input_file,
        &encrypt_dir,
        &pub_key_path,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    let private_key_path = keys_dir.join("private.key");

    recipient_auto(
        encrypt_dir.join("data.fcr"),
        &decrypt_dir,
        &private_key_path,
        &key_passphrase,
        None,
        None,
        |_| {},
    )?;

    let decrypted = fs::read(decrypt_dir.join("data.bin"))?;
    assert_eq!(binary_content, decrypted);

    Ok(())
}

#[test]
fn test_nonexistent_input_path_encrypt() {
    let test_dir = setup_test_dir("nonexistent_input_encrypt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    let missing = test_dir.join("does-not-exist.txt");

    // Call the public encryptor directly (the `passphrase_auto` shim
    // short-circuits on a missing path). A missing input must be reported as
    // the typed InputPath, before any key derivation runs.
    let passphrase = SecretString::from("test".to_string());
    let result = ferrocrypt_test_support::fast_passphrase_encryptor(passphrase)
        .write(&missing, &encrypt_dir, |_| {})
        .map(|_| ());
    assert!(
        matches!(result, Err(CryptoError::InputPath)),
        "encrypting a missing input must report InputPath, got {result:?}"
    );
}

#[test]
fn test_truncated_passphrase_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("truncated_passphrase");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // Encrypt a real file, then truncate so the header prefix is intact
    // (magic bytes detected) but the rest of the header is missing.
    let input_file = test_dir.join("data.txt");
    create_test_file(&input_file, "truncation test data");
    let passphrase = SecretString::from("test".to_string());

    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("data.fcr");
    let data = fs::read(&encrypted_path)?;

    // Keep only 30 bytes: the 12-byte prefix plus part of the header,
    // enough for magic detection but not a complete header.
    let truncated = &data[..30];
    fs::write(&encrypted_path, truncated)?;

    let result = passphrase_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_truncated_recipient_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("truncated_recipient");
    let keys_dir = test_dir.join("keys");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let key_passphrase = SecretString::from("pass".to_string());
    generate_key_pair(&key_passphrase, &keys_dir, |_| {})?;

    let public_key = keys_dir.join("public.key");
    let private_key_path = keys_dir.join("private.key");

    // Encrypt a real file, then truncate so the header prefix is intact
    // (magic bytes detected) but the rest of the header is missing.
    let input_file = test_dir.join("data.txt");
    create_test_file(&input_file, "truncation test");
    let empty_pass = SecretString::from("".to_string());
    recipient_auto(
        &input_file,
        &encrypt_dir,
        &public_key,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    let encrypted_path = encrypt_dir.join("data.fcr");
    let data = fs::read(&encrypted_path)?;
    let truncated = &data[..30];
    fs::write(&encrypted_path, truncated)?;

    let result = recipient_auto(
        &encrypted_path,
        &decrypt_dir,
        &private_key_path,
        &key_passphrase,
        None,
        None,
        |_| {},
    );

    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_passphrase_header_tamper_detection() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("passphrase_tamper");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Tamper detection test");

    let passphrase = SecretString::from("tamper_pass".to_string());

    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // Flip one byte in the authenticated stream_nonce. The recipient
    // body still unwraps, but the header MAC no longer matches, so
    // decrypt must fail at the post-unwrap tamper check.
    // stream_nonce sits inside HEADER_FIXED at offset 12 (after
    // header_flags(2) + recipient_count(2) + recipient_entries_len(4)
    // + ext_len(4)); file offset = PREFIX_SIZE(12) + 12 = 24.
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const NONCE_OFFSET: usize = 12 + 12;
    data[NONCE_OFFSET] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let result = passphrase_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );

    match result {
        Err(CryptoError::HeaderTampered) => {}
        other => panic!("expected HeaderTampered, got {other:?}"),
    }

    Ok(())
}

#[test]
fn test_recipient_header_tamper_detection() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("recipient_tamper");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Hybrid tamper test");

    let key_passphrase = SecretString::from("tamper_key_pass".to_string());
    generate_key_pair(&key_passphrase, &keys_dir, |_| {})?;

    let pub_key_path = keys_dir.join("public.key");
    let empty_pass = SecretString::from("".to_string());

    recipient_auto(
        &input_file,
        &encrypt_dir,
        &pub_key_path,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    // Flip one byte in the authenticated stream_nonce. The x25519
    // recipient body can still unwrap, but the header MAC must fail
    // afterwards. stream_nonce sits inside HEADER_FIXED at offset 12;
    // file offset = PREFIX_SIZE(12) + 12 = 24. For a single-recipient
    // recipient file the post-unwrap MAC failure surfaces as
    // `HeaderMacFailedAfterUnwrap` per FORMAT.md §3.7 (the loop's
    // per-candidate variant; the loop has no further candidates).
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const NONCE_OFFSET: usize = 12 + 12;
    data[NONCE_OFFSET] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let private_key_path = keys_dir.join("private.key");

    let result = recipient_auto(
        &encrypted_path,
        &decrypt_dir,
        &private_key_path,
        &key_passphrase,
        None,
        None,
        |_| {},
    );

    // Single x25519 recipient, one flipped `stream_nonce` byte: the wrap
    // key derivation does not involve `stream_nonce`, so the slot unwraps
    // and yields the real file key, but the header MAC over the tampered
    // bytes no longer verifies. The one reachable verdict is
    // `HeaderMacFailedAfterUnwrap { type_name: "x25519" }`.
    match result {
        Err(CryptoError::HeaderMacFailedAfterUnwrap { ref type_name }) if type_name == "x25519" => {
        }
        other => panic!("expected HeaderMacFailedAfterUnwrap(x25519), got {other:?}"),
    }

    Ok(())
}

/// Any flip in the 12-byte prefix MUST be caught at structural parse
/// before any cryptographic work runs. Pins the version-byte case so
/// a future change that softens the prefix parse fails the regression.
#[test]
fn test_passphrase_prefix_byte_tamper_detected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("passphrase_prefix_byte_tamper");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Prefix tamper test");

    let passphrase = SecretString::from("prefix_tamper_pass".to_string());

    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // Flip the version byte (offset 4 in the 12-byte prefix) so the
    // file claims an unsupported version. v1 readers must reject
    // before any recipient unwrap or KDF work runs.
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    data[4] ^= 0x10;
    fs::write(&encrypted_path, &data)?;

    let result = passphrase_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );

    match result {
        Err(CryptoError::UnsupportedVersion(_)) | Err(CryptoError::InvalidFormat(_)) => {}
        other => panic!(
            "expected UnsupportedVersion or InvalidFormat for tampered version byte, got {other:?}"
        ),
    }

    Ok(())
}

#[test]
fn test_non_ferrocrypt_fcr_file_can_be_encrypted() {
    let test_dir = setup_test_dir("not_ferrocrypt");
    let fake_file = test_dir.join("photo.fcr");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    // A JPEG header renamed to .fcr — routing by magic bytes only means
    // this is treated as a normal file and can be encrypted.
    let content = b"\xFF\xD8\xFF\xE0fake jpeg data padding!!";
    fs::write(&fake_file, content).unwrap();

    let passphrase = SecretString::from("test".to_string());
    let result = passphrase_auto(&fake_file, &encrypt_dir, &passphrase, None, None, |_| {});
    assert!(
        result.is_ok(),
        "Expected encryption to succeed, got: {:?}",
        result
    );

    // Verify round-trip: decrypt the encrypted file and compare
    let encrypted_path = encrypt_dir.join("photo.fcr");
    assert!(encrypted_path.exists());

    let result = passphrase_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );
    assert!(result.is_ok());

    let decrypted = fs::read(decrypt_dir.join("photo.fcr")).unwrap();
    assert_eq!(decrypted, content);
}

#[test]
fn test_wrong_format_type_recipient_as_passphrase() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("wrong_format_type");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "format type test");
    let key_passphrase = SecretString::from("pass".to_string());
    generate_key_pair(&key_passphrase, &keys_dir, |_| {})?;

    // Encrypt as recipient (x25519)
    let pub_key_path = keys_dir.join("public.key");
    let empty_pass = SecretString::from("".to_string());

    recipient_auto(
        &input_file,
        &encrypt_dir,
        &pub_key_path,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    // Try to decrypt a recipient `.fcr` file via the passphrase path — format type mismatch
    let encrypted_path = encrypt_dir.join("data.fcr");
    let passphrase = SecretString::from("pass".to_string());
    let result = passphrase_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );

    // `passphrase_auto` classifies the file via `Decryptor::open`, which
    // routes a recipient (`x25519`) file to the `PrivateKey` variant; the
    // shim then refuses to drive it through the passphrase path and
    // returns `NoSupportedRecipient`. This pins the auto-routing shim's
    // refusal, not the library's own mode-mismatch handling — that is
    // covered directly by
    // `protocol::tests::decrypt_rejects_recipient_file_with_passphrase_credential`,
    // which asserts `DecryptorModeMismatch`.
    match result {
        Err(CryptoError::NoSupportedRecipient) => {}
        other => panic!("expected NoSupportedRecipient from the passphrase shim, got {other:?}"),
    }

    Ok(())
}

#[test]
fn test_recipient_empty_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("recipient_empty_file");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("empty.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "");
    let key_passphrase = SecretString::from("hybrid_empty".to_string());
    generate_key_pair(&key_passphrase, &keys_dir, |_| {})?;

    let pub_key = keys_dir.join("public.key");
    let empty_pass = SecretString::from("".to_string());

    recipient_auto(
        &input_file,
        &encrypt_dir,
        &pub_key,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    let private_key_path = keys_dir.join("private.key");

    recipient_auto(
        encrypt_dir.join("empty.fcr"),
        &decrypt_dir,
        &private_key_path,
        &key_passphrase,
        None,
        None,
        |_| {},
    )?;

    let decrypted = fs::read_to_string(decrypt_dir.join("empty.txt"))?;
    assert_eq!("", decrypted);

    Ok(())
}

#[test]
fn test_two_encryptions_produce_different_output() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("nonce_uniqueness");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir_a = test_dir.join("encrypted_a");
    let encrypt_dir_b = test_dir.join("encrypted_b");

    fs::create_dir_all(&encrypt_dir_a)?;
    fs::create_dir_all(&encrypt_dir_b)?;

    create_test_file(&input_file, "Same content encrypted twice");
    let passphrase = SecretString::from("same_pass".to_string());

    passphrase_auto(&input_file, &encrypt_dir_a, &passphrase, None, None, |_| {})?;

    passphrase_auto(&input_file, &encrypt_dir_b, &passphrase, None, None, |_| {})?;

    let file_a = fs::read(encrypt_dir_a.join("data.fcr"))?;
    let file_b = fs::read(encrypt_dir_b.join("data.fcr"))?;

    // Same plaintext + same password must produce different ciphertext (unique salt + nonce)
    assert_ne!(file_a, file_b);

    Ok(())
}

#[test]
fn test_passphrase_output_file_override() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("passphrase_output_file_override");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "custom output path test");
    let passphrase = SecretString::from("test_password_123".to_string());

    let custom_output = encrypt_dir.join("custom_name.fcr");
    let result = passphrase_auto(
        &input_file,
        &encrypt_dir,
        &passphrase,
        Some(custom_output.as_path()),
        None,
        |_| {},
    )?;

    assert_eq!(result, custom_output);
    assert!(custom_output.exists());
    // Default name should not exist
    assert!(!encrypt_dir.join("data.fcr").exists());

    // Decrypt the custom-named file
    let decrypt_result = passphrase_auto(
        &custom_output,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    assert!(decrypt_result.exists());
    let content = fs::read_to_string(decrypt_dir.join("data.txt"))?;
    assert_eq!("custom output path test", content);

    Ok(())
}

#[test]
fn test_recipient_output_file_override() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("recipient_output_file_override");
    let input_file = test_dir.join("data.txt");
    let key_dir = test_dir.join("keys");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&key_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "hybrid custom output test");
    let passphrase = SecretString::from("key_pass_123".to_string());

    generate_key_pair(&passphrase, &key_dir, |_| {})?;

    let pub_key = key_dir.join("public.key");
    let private_key_path = key_dir.join("private.key");
    let custom_output = encrypt_dir.join("my_vault.fcr");
    let empty = SecretString::from("".to_string());

    let result = recipient_auto(
        &input_file,
        &encrypt_dir,
        &pub_key,
        &empty,
        Some(custom_output.as_path()),
        None,
        |_| {},
    )?;

    assert_eq!(result, custom_output);
    assert!(custom_output.exists());
    assert!(!encrypt_dir.join("data.fcr").exists());

    // Decrypt the custom-named file
    let decrypt_result = recipient_auto(
        &custom_output,
        &decrypt_dir,
        &private_key_path,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    assert!(decrypt_result.exists());
    let content = fs::read_to_string(decrypt_dir.join("data.txt"))?;
    assert_eq!("hybrid custom output test", content);

    Ok(())
}

#[test]
fn test_output_file_none_uses_default_name() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("output_file_none_default");
    let input_file = test_dir.join("report.txt");
    let encrypt_dir = test_dir.join("encrypted");

    fs::create_dir_all(&encrypt_dir)?;

    create_test_file(&input_file, "default naming test");
    let passphrase = SecretString::from("test_password_123".to_string());

    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let expected = encrypt_dir.join(format!("report.{}", ENCRYPTED_EXTENSION));
    assert!(expected.exists());

    Ok(())
}

// ---------------------------------------------------------------------------
// Malformed-header tests
// ---------------------------------------------------------------------------

#[test]
fn test_passphrase_empty_file_rejected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("pass_empty_file");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // Encrypt a real file, then replace its content with just the prefix
    // (enough for magic-byte detection) but no actual header payload.
    let input_file = test_dir.join("data.txt");
    create_test_file(&input_file, "payload");
    let passphrase = SecretString::from("test".to_string());

    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("data.fcr");
    let data = fs::read(&encrypted_path)?;

    // Keep only 27 bytes: the 12-byte prefix plus part of the header —
    // enough for magic detection, but the header is incomplete.
    let prefix_only = &data[..27];
    fs::write(&encrypted_path, prefix_only)?;

    let result = passphrase_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_recipient_empty_file_rejected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("rec_empty_file");
    let keys_dir = test_dir.join("keys");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let key_pass = SecretString::from("kp".to_string());
    generate_key_pair(&key_pass, &keys_dir, |_| {})?;

    let public_key = keys_dir.join("public.key");
    let private_key_path = keys_dir.join("private.key");

    // Encrypt a real file, then truncate to prefix-only so magic-byte
    // detection routes to decrypt, which then fails on the empty payload.
    let input_file = test_dir.join("data.txt");
    create_test_file(&input_file, "payload");
    let empty_pass = SecretString::from("".to_string());
    recipient_auto(
        &input_file,
        &encrypt_dir,
        &public_key,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    let encrypted_path = encrypt_dir.join("data.fcr");
    let data = fs::read(&encrypted_path)?;
    let prefix_only = &data[..27];
    fs::write(&encrypted_path, prefix_only)?;

    let result = recipient_auto(
        &encrypted_path,
        &decrypt_dir,
        &private_key_path,
        &key_pass,
        None,
        None,
        |_| {},
    );
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_passphrase_truncated_mid_header() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("pass_truncated_mid_header");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Truncation mid-header test");
    let passphrase = SecretString::from("pass".to_string());

    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let data = fs::read(&encrypted_path)?;

    // Keep 30 bytes: the 12-byte prefix plus part of the header, so magic
    // detection succeeds but the header ends mid-field.
    let truncated = &data[..30];
    fs::write(&encrypted_path, truncated)?;

    let result = passphrase_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_passphrase_oversized_ext_len() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("pass_oversized_ext_len");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Oversized ext_len test");
    let passphrase = SecretString::from("pass".to_string());

    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // `ext_len` is the u32 at file offset 20: prefix(12) + header_flags(2)
    // + recipient_count(2) + recipient_entries_len(4). Raising it above
    // EXT_LEN_MAX (65,536) makes the structural header parse reject with
    // `ExtTooLarge` before any recipient work runs.
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const EXT_LEN_OFFSET: usize = 20;
    data[EXT_LEN_OFFSET..EXT_LEN_OFFSET + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    fs::write(&encrypted_path, &data)?;

    match passphrase_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    ) {
        Err(CryptoError::InvalidFormat(ferrocrypt::FormatDefect::ExtTooLarge { .. })) => {}
        other => panic!("expected ExtTooLarge for oversized ext_len, got {other:?}"),
    }
    Ok(())
}

#[test]
fn test_recipient_truncated_mid_header() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("rec_truncated_mid_header");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let key_pass = SecretString::from("kp".to_string());
    generate_key_pair(&key_pass, &keys_dir, |_| {})?;

    let pub_key = keys_dir.join("public.key");
    let private_key_path = keys_dir.join("private.key");
    let empty_pass = SecretString::from("".to_string());

    create_test_file(&input_file, "Hybrid truncation mid-header");

    recipient_auto(
        &input_file,
        &encrypt_dir,
        &pub_key,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let data = fs::read(&encrypted_path)?;

    // Keep 30 bytes: the 12-byte prefix plus part of the header, so magic
    // detection succeeds but the header ends mid-field.
    let truncated = &data[..30];
    fs::write(&encrypted_path, truncated)?;

    let result = recipient_auto(
        &encrypted_path,
        &decrypt_dir,
        &private_key_path,
        &key_pass,
        None,
        None,
        |_| {},
    );
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_recipient_oversized_ext_len() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("rec_oversized_ext_len");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let key_pass = SecretString::from("kp".to_string());
    generate_key_pair(&key_pass, &keys_dir, |_| {})?;

    let pub_key = keys_dir.join("public.key");
    let private_key_path = keys_dir.join("private.key");
    let empty_pass = SecretString::from("".to_string());

    create_test_file(&input_file, "Hybrid oversized ext_len");

    recipient_auto(
        &input_file,
        &encrypt_dir,
        &pub_key,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    // `ext_len` is the u32 at file offset 20: prefix(12) + header_flags(2)
    // + recipient_count(2) + recipient_entries_len(4). Raising it above
    // EXT_LEN_MAX (65,536) makes the structural header parse reject with
    // `ExtTooLarge` before any recipient work runs.
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const EXT_LEN_OFFSET: usize = 20;
    data[EXT_LEN_OFFSET..EXT_LEN_OFFSET + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    fs::write(&encrypted_path, &data)?;

    match recipient_auto(
        &encrypted_path,
        &decrypt_dir,
        &private_key_path,
        &key_pass,
        None,
        None,
        |_| {},
    ) {
        Err(CryptoError::InvalidFormat(ferrocrypt::FormatDefect::ExtTooLarge { .. })) => {}
        other => panic!("expected ExtTooLarge for oversized ext_len, got {other:?}"),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Ciphertext mutation tests
// ---------------------------------------------------------------------------

#[test]
fn test_passphrase_ciphertext_bit_flip_detected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("pass_ciphertext_flip");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "AEAD ciphertext integrity test");
    let passphrase = SecretString::from("ct_flip_pass".to_string());

    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;

    // Flip a byte well past the header, in the ciphertext body
    let flip_offset = data.len() - 10;
    data[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let result = passphrase_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );
    assert!(
        matches!(result, Err(CryptoError::PayloadTampered)),
        "a flipped ciphertext byte must surface as PayloadTampered, not a \
         generic error, got {result:?}"
    );
    Ok(())
}

#[test]
fn test_recipient_ciphertext_bit_flip_detected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("rec_ciphertext_flip");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let key_pass = SecretString::from("ct_flip_key".to_string());
    generate_key_pair(&key_pass, &keys_dir, |_| {})?;

    let pub_key = keys_dir.join("public.key");
    let private_key_path = keys_dir.join("private.key");
    let empty_pass = SecretString::from("".to_string());

    create_test_file(&input_file, "Hybrid AEAD ciphertext integrity test");

    recipient_auto(
        &input_file,
        &encrypt_dir,
        &pub_key,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;

    // Flip a byte in the ciphertext body (well past the header)
    let flip_offset = data.len() - 10;
    data[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let result = recipient_auto(
        &encrypted_path,
        &decrypt_dir,
        &private_key_path,
        &key_pass,
        None,
        None,
        |_| {},
    );
    assert!(
        matches!(result, Err(CryptoError::PayloadTampered)),
        "a flipped ciphertext byte must surface as PayloadTampered, not a \
         generic error, got {result:?}"
    );
    Ok(())
}

#[test]
fn test_passphrase_ciphertext_truncation_detected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("pass_ciphertext_trunc");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // Use enough data to span multiple 64 KiB chunks
    let content = "A".repeat(128 * 1024);
    create_test_file(&input_file, &content);
    let passphrase = SecretString::from("trunc_pass".to_string());

    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let data = fs::read(&encrypted_path)?;

    // Truncate after the first ciphertext chunk but before the final chunk
    let half = data.len() / 2;
    fs::write(&encrypted_path, &data[..half])?;

    let result = passphrase_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );
    // A mid-stream cut leaves a partial or boundary-shifted chunk; STREAM
    // cannot tell a shortened chunk from a modified one, so either
    // payload-integrity variant is correct. Pinning both still rules out the
    // regression the bare `is_err()` missed: truncation surfacing as a
    // generic `Io` error instead of a typed payload failure (FORMAT.md §5).
    assert!(
        matches!(
            result,
            Err(CryptoError::PayloadTruncated | CryptoError::PayloadTampered)
        ),
        "mid-stream truncation must surface as a typed payload failure, got {result:?}"
    );
    Ok(())
}

#[test]
fn test_passphrase_ciphertext_appended_bytes_detected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("pass_ciphertext_append");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Append detection test");
    let passphrase = SecretString::from("append_pass".to_string());

    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;

    // Append extra bytes after the ciphertext
    data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    fs::write(&encrypted_path, &data)?;

    let result = passphrase_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_public_key_fingerprint() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("fingerprint");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir)?;

    let passphrase = SecretString::from("fp_test_pass".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    let pub_key = keys_dir.join("public.key");
    let fp = PublicKey::from_key_file(&pub_key).fingerprint()?;

    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));

    // Deterministic: same key always produces the same fingerprint
    let fp2 = PublicKey::from_key_file(&pub_key).fingerprint()?;
    assert_eq!(fp, fp2);

    // Rejects private key files
    let private_key_path = keys_dir.join("private.key");
    assert!(
        PublicKey::from_key_file(&private_key_path)
            .fingerprint()
            .is_err()
    );

    Ok(())
}

#[test]
fn test_different_keys_different_fingerprints() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("fingerprint_diff");
    let keys_a = test_dir.join("keys_a");
    let keys_b = test_dir.join("keys_b");
    fs::create_dir_all(&keys_a)?;
    fs::create_dir_all(&keys_b)?;

    let passphrase = SecretString::from("fp_diff_pass".to_string());
    generate_key_pair(&passphrase, &keys_a, |_| {})?;
    generate_key_pair(&passphrase, &keys_b, |_| {})?;

    let fp_a = PublicKey::from_key_file(keys_a.join("public.key")).fingerprint()?;
    let fp_b = PublicKey::from_key_file(keys_b.join("public.key")).fingerprint()?;

    assert_ne!(fp_a, fp_b);

    Ok(())
}

/// `PublicKey::validate` succeeds on a well-formed key file, succeeds
/// unconditionally on the bytes source, and fails with a structural
/// error (not a panic) when pointed at a file that does not exist.
#[test]
fn test_public_key_validate() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("public_key_validate");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir)?;

    let passphrase = SecretString::from("vp".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    // Valid file: validate passes.
    PublicKey::from_key_file(keys_dir.join("public.key")).validate()?;

    // Raw bytes: `from_bytes` already structurally rejects degenerate
    // (e.g. all-zero) inputs at construction, so any successfully
    // constructed `PublicKey::from_bytes` value passes `validate()`.
    PublicKey::from_bytes([0xAB; 32])?.validate()?;

    // Nonexistent file: validate returns an I/O error, not a panic.
    let missing = keys_dir.join("does_not_exist.key");
    assert!(PublicKey::from_key_file(&missing).validate().is_err());

    // Pointing at a private-key file: the public-key parser rejects the
    // wrong key-file kind instead of leaking secret material.
    let private_key_path = keys_dir.join("private.key");
    assert!(
        PublicKey::from_key_file(&private_key_path)
            .validate()
            .is_err()
    );

    Ok(())
}

/// The `FromStr` impl routes through `PublicKey::from_recipient_string`,
/// so `"fcr1…".parse::<PublicKey>()` must accept a valid recipient
/// string and round-trip back through `to_recipient_string`, and must
/// reject Bech32 with the wrong HRP.
#[test]
fn test_public_key_from_str_round_trip() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("public_key_from_str");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir)?;

    let passphrase = SecretString::from("fs".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    let encoded = PublicKey::from_key_file(keys_dir.join("public.key")).to_recipient_string()?;
    let parsed: PublicKey = encoded
        .parse()
        .expect("valid recipient string must parse via FromStr");
    assert_eq!(parsed.to_recipient_string()?, encoded);

    // Wrong HRP must fail to parse.
    let wrong_hrp =
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse_unchecked("age"), &[0xCC; 32]).unwrap();
    assert!(wrong_hrp.parse::<PublicKey>().is_err());

    Ok(())
}

#[cfg(unix)]
#[test]
fn test_passphrase_encrypt_cleans_up_on_failure() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("pass_encrypt_cleanup");
    let real_file = test_dir.join("real.txt");
    let symlink_path = test_dir.join("link.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir)?;
    create_test_file(&real_file, "target content");
    std::os::unix::fs::symlink(&real_file, &symlink_path).unwrap();

    let passphrase = SecretString::from("cleanup_pass".to_string());
    let result = passphrase_auto(&symlink_path, &encrypt_dir, &passphrase, None, None, |_| {});
    assert!(result.is_err());

    let would_be_output = encrypt_dir.join(format!("link.{}", ENCRYPTED_EXTENSION));
    assert!(
        !would_be_output.exists(),
        "partial .fcr file should have been cleaned up"
    );

    Ok(())
}

#[cfg(unix)]
#[test]
fn test_recipient_encrypt_cleans_up_on_failure() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("rec_encrypt_cleanup");
    let keys_dir = test_dir.join("keys");
    let real_file = test_dir.join("real.txt");
    let symlink_path = test_dir.join("link.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    create_test_file(&real_file, "target content");
    std::os::unix::fs::symlink(&real_file, &symlink_path).unwrap();

    let key_pass = SecretString::from("cleanup_key".to_string());
    generate_key_pair(&key_pass, &keys_dir, |_| {})?;

    let result = recipient_auto(
        &symlink_path,
        &encrypt_dir,
        keys_dir.join("public.key"),
        &key_pass,
        None,
        None,
        |_| {},
    );
    assert!(result.is_err());

    let would_be_output = encrypt_dir.join(format!("link.{}", ENCRYPTED_EXTENSION));
    assert!(
        !would_be_output.exists(),
        "partial .fcr file should have been cleaned up"
    );

    Ok(())
}

#[test]
fn test_passphrase_decrypt_marks_incomplete_file() -> Result<(), CryptoError> {
    use ferrocrypt::{Decryptor, IncompleteOutputPolicy};

    let test_dir = setup_test_dir("pass_decrypt_incomplete_file");
    let input_file = test_dir.join("bigfile.bin");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // 200 KB file — spans multiple 64 KB encryption chunks
    let big_data: Vec<u8> = (0..204_800u32).map(|i| (i % 256) as u8).collect();
    fs::write(&input_file, &big_data)?;

    let passphrase = SecretString::from("incomplete_pass".to_string());
    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("bigfile.fcr");
    let mut data = fs::read(&encrypted_path)?;
    // Corrupt a byte in a late chunk (well past the first 64 KB)
    let flip_offset = data.len() - 50;
    data[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let Decryptor::Passphrase(decryptor) = Decryptor::open(&encrypted_path)? else {
        panic!("expected passphrase-sealed file");
    };
    let result = decryptor
        .incomplete_output_policy(IncompleteOutputPolicy::RetainOnError)
        .decrypt(passphrase, &decrypt_dir, |_| {});
    assert!(result.is_err());

    let incomplete_path = decrypt_dir.join("bigfile.bin.incomplete");
    assert!(
        incomplete_path.exists(),
        "RetainOnError should leave the partial output as .incomplete"
    );
    // Original name should not exist
    assert!(!decrypt_dir.join("bigfile.bin").exists());

    Ok(())
}

#[test]
fn test_passphrase_decrypt_marks_incomplete_directory() -> Result<(), CryptoError> {
    use ferrocrypt::{Decryptor, IncompleteOutputPolicy};

    let test_dir = setup_test_dir("pass_decrypt_incomplete_dir");
    let input_dir = test_dir.join("mydir");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&input_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_dir.join("small.txt"), "small file content");
    // Large file to span multiple chunks
    let big_data: Vec<u8> = (0..204_800u32).map(|i| (i % 256) as u8).collect();
    fs::write(input_dir.join("bigfile.bin"), &big_data)?;

    let passphrase = SecretString::from("incomplete_dir_pass".to_string());
    passphrase_auto(&input_dir, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("mydir.fcr");
    let mut data = fs::read(&encrypted_path)?;
    let flip_offset = data.len() - 50;
    data[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let Decryptor::Passphrase(decryptor) = Decryptor::open(&encrypted_path)? else {
        panic!("expected passphrase-sealed file");
    };
    let result = decryptor
        .incomplete_output_policy(IncompleteOutputPolicy::RetainOnError)
        .decrypt(passphrase, &decrypt_dir, |_| {});
    assert!(result.is_err());

    let incomplete_path = decrypt_dir.join("mydir.incomplete");
    assert!(
        incomplete_path.exists(),
        "RetainOnError should leave the partial directory as .incomplete"
    );
    assert!(incomplete_path.is_dir());
    assert!(!decrypt_dir.join("mydir").exists());

    Ok(())
}

#[test]
fn test_successful_decrypt_produces_final_name_not_incomplete() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("decrypt_final_name");
    let input_file = test_dir.join("payload.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;
    fs::write(&input_file, "clean decryption")?;

    let passphrase = SecretString::from("final_name_pass".to_string());
    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let output = passphrase_auto(
        encrypt_dir.join("payload.fcr"),
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    )?;
    assert!(output.exists());
    assert_eq!(output, decrypt_dir.join("payload.txt"));
    assert!(!decrypt_dir.join("payload.txt.incomplete").exists());

    Ok(())
}

#[test]
fn test_existing_incomplete_blocks_retry() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("incomplete_blocks_retry");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;
    fs::write(&input_file, "some content")?;

    let passphrase = SecretString::from("retry_pass".to_string());
    passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // Simulate leftover .incomplete from a previous failed attempt
    fs::write(decrypt_dir.join("data.txt.incomplete"), "stale partial")?;

    let result = passphrase_auto(
        encrypt_dir.join("data.fcr"),
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );
    assert!(result.is_err());
    match result {
        Err(CryptoError::InvalidInput(msg)) => {
            assert!(msg.contains("Previous .incomplete exists"), "got: {msg}");
        }
        other => panic!("expected InvalidInput about incomplete, got: {other:?}"),
    }

    // Stale .incomplete must not be overwritten
    let stale = fs::read_to_string(decrypt_dir.join("data.txt.incomplete"))?;
    assert_eq!(stale, "stale partial");

    Ok(())
}

#[test]
fn test_encrypt_produces_final_name_not_incomplete() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("encrypt_final_name");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::write(&input_file, "secret data")?;

    let passphrase = SecretString::from("enc_final".to_string());
    let output = passphrase_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    assert!(output.exists());
    assert_eq!(output, encrypt_dir.join("secret.fcr"));
    assert!(!encrypt_dir.join("secret.fcr.incomplete").exists());

    Ok(())
}

#[test]
fn test_keygen_no_partial_state_on_existing_key() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("keygen_no_partial");
    let passphrase = SecretString::from("atomic_pass".to_string());

    generate_key_pair(&passphrase, &test_dir, |_| {})?;
    let private_before = fs::read(test_dir.join("private.key"))?;
    let public_before = fs::read(test_dir.join("public.key"))?;

    let result = generate_key_pair(&passphrase, &test_dir, |_| {});
    assert!(
        result.is_err(),
        "keygen must refuse to overwrite existing keys"
    );

    // No partial state: the pre-existing keys are byte-for-byte intact and
    // no `.ferrocrypt-*` staging tempfile is left behind.
    assert_eq!(fs::read(test_dir.join("private.key"))?, private_before);
    assert_eq!(fs::read(test_dir.join("public.key"))?, public_before);
    let leftover: Vec<String> = fs::read_dir(&test_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".ferrocrypt-"))
        .collect();
    assert!(
        leftover.is_empty(),
        "no staging tempfile should remain after a failed keygen: {leftover:?}"
    );

    Ok(())
}

/// Flipping a byte in the cleartext salt region of a v1 `private.key`
/// file must cause decryption to fail. v1 binds every cleartext byte
/// before `wrapped_private_key` (header + argon2_salt + kdf_params +
/// wrap_nonce + ext_bytes) as AEAD associated data, so any header or
/// body tamper fails authentication on unlock.
#[test]
fn test_private_key_salt_tamper_rejected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("private_key_salt_tamper");
    let keys_dir = test_dir.join("keys");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let passphrase = SecretString::from("aad_salt_pass".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    let input_file = test_dir.join("data.txt");
    create_test_file(&input_file, "confidential");
    let empty = SecretString::from("".to_string());
    recipient_auto(
        &input_file,
        &encrypt_dir,
        keys_dir.join("public.key"),
        &empty,
        None,
        None,
        |_| {},
    )?;

    // The 32-byte Argon2 salt sits at offset 22 in the private.key
    // cleartext header, after magic(4), version(1), kind(1), key_flags(2),
    // and the four length fields (16). It is bound as AEAD associated data
    // and doubles as the Argon2/HKDF salt, so flipping one byte both derives
    // the wrong wrap key and fails AAD authentication — surfacing as the
    // ambiguity-preserving `KeyFileUnlockFailed`.
    let private_key_path = keys_dir.join("private.key");
    let mut key_data = fs::read(&private_key_path)?;
    const SALT_OFFSET: usize = 22;
    key_data[SALT_OFFSET] ^= 0x01;
    fs::write(&private_key_path, &key_data)?;

    match recipient_auto(
        encrypt_dir.join("data.fcr"),
        &decrypt_dir,
        &private_key_path,
        &passphrase,
        None,
        None,
        |_| {},
    ) {
        Err(CryptoError::KeyFileUnlockFailed) => {}
        other => panic!("tampered salt must fail key-file unlock, got {other:?}"),
    }

    Ok(())
}

/// Tampering the `ext_len` field of a `private.key` cleartext header
/// makes the declared length no longer match the on-disk body, so the
/// structural validator rejects it as `MalformedPrivateKey` before the
/// KDF is attempted. `ext_len` is also part of the AEAD AAD, so a tamper
/// that somehow passed the length check would still fail authentication
/// on unlock — but the cheap structural check comes first.
#[test]
fn test_private_key_ext_len_tamper_rejected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("private_key_ext_len_tamper");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir)?;

    let passphrase = SecretString::from("ext_len_pass".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    // Flipping a bit in the `ext_len` field (u32 BE at bytes 14..=17)
    // of the `private.key` cleartext header makes the declared length
    // no longer match the on-disk body — surfaces as
    // `MalformedPrivateKey`.
    let private_key_path = keys_dir.join("private.key");
    let mut key_data = fs::read(&private_key_path)?;
    key_data[14] |= 0x01;
    fs::write(&private_key_path, &key_data)?;

    match validate_private_key_file(&private_key_path) {
        Err(ferrocrypt::CryptoError::InvalidFormat(
            ferrocrypt::FormatDefect::MalformedPrivateKey,
        )) => {}
        other => panic!("expected MalformedPrivateKey, got {:?}", other),
    }

    Ok(())
}

// ─── probe_recipient_mode: fail-closed on malformed headers ──────────────

#[test]
fn test_probe_plaintext_file_returns_none() -> Result<(), CryptoError> {
    let dir = setup_test_dir("probe_plaintext");
    let path = dir.join("hello.txt");
    fs::write(&path, "just plain text")?;
    assert!(probe_recipient_mode(&path)?.is_none());
    Ok(())
}

#[test]
fn test_probe_empty_file_returns_none() -> Result<(), CryptoError> {
    let dir = setup_test_dir("probe_empty");
    let path = dir.join("empty.bin");
    fs::write(&path, b"")?;
    assert!(probe_recipient_mode(&path)?.is_none());
    Ok(())
}

/// A directory is unambiguously "not an encrypted file." Unix lets us open a
/// directory fd and only fails at `read()` with `IsADirectory`; Windows'
/// `CreateFile` rejects directories outright with `ERROR_ACCESS_DENIED`.
/// Regardless of platform, `probe_recipient_mode` must classify a directory
/// as `Ok(None)` so that auto-routing wrappers take the encrypt branch rather
/// than surfacing a permission error. Covers both populated and empty roots.
#[test]
fn test_probe_directory_returns_none() -> Result<(), CryptoError> {
    let dir = setup_test_dir("probe_directory");

    let populated = dir.join("populated");
    fs::create_dir_all(&populated)?;
    create_test_file(&populated.join("inside.txt"), "content");
    assert!(probe_recipient_mode(&populated)?.is_none());

    let empty = dir.join("empty");
    fs::create_dir_all(&empty)?;
    assert!(probe_recipient_mode(&empty)?.is_none());

    Ok(())
}

#[test]
fn test_probe_valid_passphrase_file() -> Result<(), CryptoError> {
    let dir = setup_test_dir("probe_passphrase");
    let input = dir.join("data.txt");
    fs::write(&input, "payload")?;
    let pass = SecretString::from("pw".to_string());
    let encrypted = passphrase_auto(&input, &dir, &pass, None, None, |_| {})?;
    let mode = probe_recipient_mode(&encrypted)?;
    assert_eq!(
        mode,
        Some(ferrocrypt::UnauthenticatedRecipientMode::Passphrase)
    );
    Ok(())
}

/// A short file whose first four bytes are not the `FCR\0` magic must not
/// be misclassified as an encrypted `.fcr`. The probe reads the 4-byte
/// magic at offset 0; here `0xFC` sits at bytes 3 and 11 — never as the
/// magic at offset 0 — so the probe returns `Ok(None)`.
#[test]
fn test_probe_short_file_with_two_magic_bytes_returns_none() {
    let dir = setup_test_dir("probe_two_magic_coincidence");
    let path = dir.join("coincidence.bin");
    let mut data = vec![0u8; 15];
    data[3] = 0xFC;
    data[11] = 0xFC;
    fs::write(&path, &data).unwrap();
    assert!(
        probe_recipient_mode(&path).unwrap().is_none(),
        "a file without the FCR\\0 magic cannot be classified as a `.fcr`"
    );
}

#[test]
fn test_probe_short_file_with_single_magic_byte_returns_none() {
    let dir = setup_test_dir("probe_single_magic");
    let path = dir.join("coincidence.bin");
    // A short file with a single stray `0xFC` at byte 3: the first four
    // bytes are not `FCR\0`, so the probe returns `Ok(None)`.
    let mut data = vec![0u8; 10];
    data[3] = 0xFC;
    fs::write(&path, &data).unwrap();
    let result = probe_recipient_mode(&path);
    assert!(
        result.unwrap().is_none(),
        "a stray byte must not trigger a false `.fcr` classification"
    );
}

#[test]
fn test_detect_corrupted_fcr_not_silently_encrypted() {
    let dir = setup_test_dir("detect_no_reencrypt");
    let input = dir.join("corrupted.fcr");
    // Minimal v1 prefix only: magic + version + kind 'E' (encrypted)
    // + zero prefix_flags + header_len = 0. Detection must route
    // this file to decrypt, where the missing rest-of-header fails
    // closed — rather than the helper treating it as plaintext and
    // re-encrypting it (which would produce a path collision and
    // mask the structural failure).
    let mut prefix = vec![b'F', b'C', b'R', 0, ferrocrypt::FCR_FILE_VERSION]; // magic + current wire version
    prefix.push(b'E'); // KIND_ENCRYPTED
    prefix.extend_from_slice(&0u16.to_be_bytes()); // prefix_flags = 0
    prefix.extend_from_slice(&0u32.to_be_bytes()); // header_len = 0 (truncated)
    fs::write(&input, &prefix).unwrap();
    let pass = SecretString::from("pw".to_string());
    let result = passphrase_auto(&input, &dir, &pass, None, None, |_| {});
    assert!(
        matches!(result, Err(CryptoError::InvalidFormat(_))),
        "corrupted .fcr should fail closed, got: {:?}",
        result
    );
}

// ─── Bech32 recipient tests ──────────────────────────────────────────────

#[test]
fn test_recipient_round_trip() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("recipient_roundtrip");
    let keys_dir = test_dir.join("keys");
    let passphrase = SecretString::from("rp".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    let encoded = PublicKey::from_key_file(keys_dir.join("public.key")).to_recipient_string()?;
    assert!(encoded.starts_with("fcr1"));

    let decoded = decode_recipient_string(&encoded)?;
    let re_encoded = PublicKey::from_bytes(decoded)?.to_recipient_string()?;
    assert_eq!(encoded, re_encoded);

    Ok(())
}

#[test]
fn test_recipient_malformed_bech32_rejected() {
    let result = decode_recipient_string("fcr1not-valid-bech32!!!");
    assert!(result.is_err());
}

#[test]
fn test_recipient_uppercase_rejected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("recipient_uppercase");
    let keys_dir = test_dir.join("keys");
    let passphrase = SecretString::from("uc".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    let encoded = PublicKey::from_key_file(keys_dir.join("public.key")).to_recipient_string()?;
    let uppercased = encoded.to_uppercase();
    assert!(
        decode_recipient_string(&uppercased).is_err(),
        "uppercase-only recipient strings are non-canonical and must be rejected"
    );

    Ok(())
}

#[ctor::dtor]
fn cleanup() {
    cleanup_test_workspace();
}
