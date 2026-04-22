/// Integration tests for ferrocrypt library
mod common;

use std::fs;
use std::path::{Path, PathBuf};

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    CryptoError, ENCRYPTED_EXTENSION, PublicKey, decode_recipient, detect_encryption_mode,
    validate_private_key_file,
};

use common::{generate_key_pair, hybrid_auto, symmetric_auto};

const TEST_WORKSPACE: &str = "tests/workspace";

/// Triple-replicates an 8-byte prefix for constructing test headers.
fn encode_test_prefix(prefix: &[u8; 8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(27);
    out.push(0); // padding bytes (8 is even)
    out.push(0);
    out.push(0);
    out.extend_from_slice(prefix);
    out.extend_from_slice(prefix);
    out.extend_from_slice(prefix);
    out
}

fn setup_test_dir(test_name: &str) -> PathBuf {
    let test_dir = PathBuf::from(TEST_WORKSPACE).join(test_name);
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
    if Path::new(TEST_WORKSPACE).exists() {
        let _ = fs::remove_dir_all(TEST_WORKSPACE);
    }
}

#[test]
fn test_symmetric_encrypt_decrypt_single_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("symmetric_single_file");
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
        symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    assert!(encrypt_result.exists());
    assert!(encrypt_dir.join("input.fcr").exists());

    // Decrypt
    let decrypt_result = symmetric_auto(
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
fn test_symmetric_encrypt_decrypt_directory() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("symmetric_directory");
    let input_dir = create_test_directory(&test_dir);
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let passphrase = SecretString::from("directory_password".to_string());

    // Encrypt directory
    let encrypt_result = symmetric_auto(&input_dir, &encrypt_dir, &passphrase, None, None, |_| {})?;

    assert!(encrypt_result.exists());
    assert!(encrypt_dir.join("test_folder.fcr").exists());

    // Decrypt directory
    let decrypt_result = symmetric_auto(
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

#[test]
fn test_symmetric_wrong_password() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("symmetric_wrong_password");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Secret content");

    let correct_pass = SecretString::from("correct_password".to_string());
    let wrong_pass = SecretString::from("wrong_password".to_string());

    // Encrypt with correct password
    symmetric_auto(&input_file, &encrypt_dir, &correct_pass, None, None, |_| {})?;

    // Try to decrypt with wrong password - should fail
    let result = symmetric_auto(
        encrypt_dir.join("secret.fcr"),
        &decrypt_dir,
        &wrong_pass,
        None,
        None,
        |_| {},
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::HeaderAuthenticationFailed) => {}
        other => panic!("Expected HeaderAuthenticationFailed, got {:?}", other),
    }

    Ok(())
}

#[test]
fn test_symmetric_payload_tamper_mid_chunk() -> Result<(), CryptoError> {
    // Flipping a byte inside a ciphertext chunk (not the header) must
    // surface as PayloadAuthenticationFailed, not as a generic Io error.
    let test_dir = setup_test_dir("symmetric_payload_tamper");
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
    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("payload.fcr");
    let mut ct = fs::read(&encrypted_path)?;
    // Flip a byte deep into the ciphertext, far past the header region.
    let flip_offset = ct.len() / 2;
    ct[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &ct)?;

    let result = symmetric_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );
    match result {
        Err(CryptoError::PayloadAuthenticationFailed) => {}
        other => panic!("Expected PayloadAuthenticationFailed, got {:?}", other),
    }

    Ok(())
}

#[test]
fn test_symmetric_encrypt_decrypt_multi_chunk_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("symmetric_multi_chunk");
    let input_file = test_dir.join("multi_chunk.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let content = "Multi chunk content. ".repeat(500);
    create_test_file(&input_file, &content);

    let passphrase = SecretString::from("multi_chunk_password".to_string());

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    assert!(encrypt_dir.join("multi_chunk.fcr").exists());

    symmetric_auto(
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
fn test_hybrid_keygen_rejects_empty_passphrase() {
    let test_dir = setup_test_dir("keygen_empty_pass");
    let empty = SecretString::from("".to_string());

    let err = generate_key_pair(&empty, &test_dir, |_| {}).unwrap_err();
    assert!(
        err.to_string().contains("empty"),
        "expected empty-passphrase error, got: {err}"
    );
}

/// M-3 regression: `hybrid_decrypt` must reject an empty passphrase at the
/// top of the function, before `validate_input_path` and before any KDF work
/// runs. The symmetric path already did this pre-audit; the hybrid path was
/// a consistency gap that let an empty passphrase burn an Argon2id cycle on
/// the private-key file before failing.
#[test]
fn test_hybrid_decrypt_rejects_empty_passphrase_before_kdf() {
    use ferrocrypt::{HybridDecryptConfig, PrivateKey, ProgressEvent, hybrid_decrypt};
    use std::cell::Cell;

    let test_dir = setup_test_dir("hybrid_decrypt_empty_pass");
    let empty = SecretString::from("".to_string());

    // The input and key file paths are not resolved — the passphrase check
    // must fire first, so the paths can be placeholders that do not exist.
    let config = HybridDecryptConfig::new(
        test_dir.join("nonexistent.fcr"),
        &test_dir,
        PrivateKey::from_key_file(test_dir.join("nonexistent.key")),
        empty,
    );

    let saw_deriving = Cell::new(false);
    let err = hybrid_decrypt(config, |ev| {
        if matches!(ev, ProgressEvent::DerivingKey) {
            saw_deriving.set(true);
        }
    })
    .unwrap_err();

    assert!(
        err.to_string().contains("empty"),
        "expected empty-passphrase error, got: {err}"
    );
    assert!(
        !saw_deriving.get(),
        "DerivingKey must not fire before the empty-passphrase check"
    );
}

/// M-4 regression: `symmetric_encrypt` must reject a symlink input with a
/// typed `InvalidInput` error *before* kicking off Argon2id. Pre-audit the
/// rejection happened inside `archiver::archive`, which runs after the KDF
/// — an accidental symlink cost the user seconds and up to 1 GiB of RAM.
/// Observes the `DerivingKey` progress event to prove the rejection
/// short-circuits the KDF path.
#[cfg(unix)]
#[test]
fn test_symmetric_encrypt_rejects_symlink_before_kdf() {
    use ferrocrypt::{ProgressEvent, SymmetricEncryptConfig, symmetric_encrypt};
    use std::cell::Cell;
    use std::os::unix::fs::symlink;

    let test_dir = setup_test_dir("symmetric_encrypt_symlink");
    let target = create_test_file(&test_dir.join("real.txt"), "data");
    let link = test_dir.join("link.txt");
    symlink(&target, &link).expect("failed to create symlink");

    let output_dir = test_dir.join("out");
    fs::create_dir_all(&output_dir).unwrap();
    let passphrase = SecretString::from("pass".to_string());

    let config = SymmetricEncryptConfig::new(&link, &output_dir, passphrase);
    let saw_deriving = Cell::new(false);
    let err = symmetric_encrypt(config, |ev| {
        if matches!(ev, ProgressEvent::DerivingKey) {
            saw_deriving.set(true);
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
        !saw_deriving.get(),
        "DerivingKey must not fire before the symlink check"
    );
}

/// L-2 regression: on a successful hybrid decrypt, `DerivingKey` fires before
/// the private-key Argon2id runs and `Decrypting` fires only after the
/// envelope/HMAC checks pass (just before streaming unarchive). Pre-audit the
/// path emitted `Decrypting` immediately at the top of `hybrid::decrypt_file`
/// and never emitted `DerivingKey`, so a UI would mislabel the multi-second
/// KDF window as "decrypting".
#[test]
fn test_hybrid_decrypt_progress_events_in_order() -> Result<(), CryptoError> {
    use ferrocrypt::ProgressEvent;
    use std::sync::Mutex;

    let test_dir = setup_test_dir("hybrid_decrypt_progress");
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
    hybrid_auto(
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
    hybrid_auto(
        &encrypted_path,
        &decrypt_dir,
        keys_dir.join("private.key"),
        &passphrase,
        None,
        None,
        |ev| events.lock().unwrap().push(*ev),
    )?;

    let events = events.into_inner().unwrap();
    let deriving_at = events
        .iter()
        .position(|e| matches!(e, ProgressEvent::DerivingKey));
    let decrypting_at = events
        .iter()
        .position(|e| matches!(e, ProgressEvent::Decrypting));
    let deriving_at = deriving_at.expect("DerivingKey must fire on hybrid decrypt");
    let decrypting_at = decrypting_at.expect("Decrypting must fire on hybrid decrypt");
    assert!(
        deriving_at < decrypting_at,
        "DerivingKey ({deriving_at}) must fire before Decrypting ({decrypting_at}); events: {events:?}"
    );

    Ok(())
}

#[cfg(unix)]
#[test]
fn test_hybrid_keygen_private_key_permissions() -> Result<(), CryptoError> {
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
fn test_hybrid_keygen_encrypt_decrypt_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hybrid_full_workflow");
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

    let encrypt_result = hybrid_auto(
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

    let decrypt_result = hybrid_auto(
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
fn test_hybrid_encrypt_decrypt_directory() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hybrid_directory");
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

    hybrid_auto(
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

    hybrid_auto(
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
fn test_hybrid_wrong_key_passphrase() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hybrid_wrong_passphrase");
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

    hybrid_auto(
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

    let result = hybrid_auto(
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
    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // Decrypt
    symmetric_auto(
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
    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // Decrypt
    symmetric_auto(
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

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    symmetric_auto(
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

    let result = symmetric_auto(
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
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&decrypt_dir).unwrap();

    let passphrase = SecretString::from("test".to_string());

    let result = symmetric_auto(
        "/nonexistent/missing.fcr",
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );

    assert!(result.is_err());
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

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    symmetric_auto(
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
fn test_symmetric_streaming_wrong_password() -> Result<(), CryptoError> {
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

    symmetric_auto(&input_file, &encrypt_dir, &correct_pass, None, None, |_| {})?;

    // Decrypt with wrong password
    let result = symmetric_auto(
        encrypt_dir.join("data.fcr"),
        &decrypt_dir,
        &wrong_pass,
        None,
        None,
        |_| {},
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::HeaderAuthenticationFailed) => {}
        other => panic!("Expected HeaderAuthenticationFailed, got {:?}", other),
    }

    Ok(())
}

#[test]
fn test_symmetric_encrypt_decrypt_directory_streaming() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("directory_streaming");
    let input_dir = create_test_directory(&test_dir);
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let passphrase = SecretString::from("dir_streaming_pass".to_string());

    symmetric_auto(&input_dir, &encrypt_dir, &passphrase, None, None, |_| {})?;

    assert!(encrypt_dir.join("test_folder.fcr").exists());

    symmetric_auto(
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
fn test_symmetric_empty_password_rejected() {
    let test_dir = setup_test_dir("empty_password");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");

    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "Protected with empty password");

    let empty_pass = SecretString::from("".to_string());

    let result = symmetric_auto(&input_file, &encrypt_dir, &empty_pass, None, None, |_| {});

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
fn test_hybrid_wrong_key_pair() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hybrid_wrong_keypair");
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

    hybrid_auto(
        &input_file,
        &encrypt_dir,
        &pub_key_a,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    // Try to decrypt with key pair B's private key — the passphrase is
    // correct for key pair B (so private.key unlocks fine), but the
    // ECDH envelope was sealed for recipient A, so envelope AEAD fails
    // and the decryption must surface as HeaderAuthenticationFailed.
    let private_key_b = keys_b.join("private.key");

    let result = hybrid_auto(
        encrypt_dir.join("data.fcr"),
        &decrypt_dir,
        &private_key_b,
        &pass_b,
        None,
        None,
        |_| {},
    );

    match result {
        Err(CryptoError::HeaderAuthenticationFailed) => {}
        other => panic!("Expected HeaderAuthenticationFailed, got {:?}", other),
    }

    Ok(())
}

#[test]
fn test_hybrid_key_round_trip() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hybrid_key_round_trip");
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

    hybrid_auto(
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

    hybrid_auto(
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
fn test_hybrid_binary_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hybrid_binary");
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

    hybrid_auto(
        &input_file,
        &encrypt_dir,
        &pub_key_path,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    let private_key_path = keys_dir.join("private.key");

    hybrid_auto(
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

    let passphrase = SecretString::from("test".to_string());

    let result = symmetric_auto(
        "/nonexistent/path/file.txt",
        &encrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::InputPath) => {}
        other => panic!("Expected InputPath error, got {:?}", other),
    }
}

#[test]
fn test_truncated_symmetric_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("truncated_symmetric");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // Encrypt a real file, then truncate so the header prefix is intact
    // (magic bytes detected) but the rest of the header is missing.
    let input_file = test_dir.join("data.txt");
    create_test_file(&input_file, "truncation test data");
    let passphrase = SecretString::from("test".to_string());

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("data.fcr");
    let data = fs::read(&encrypted_path)?;

    // Keep only 30 bytes: enough for the 27-byte encoded prefix but not a full header
    let truncated = &data[..30];
    fs::write(&encrypted_path, truncated)?;

    let result = symmetric_auto(
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
fn test_truncated_hybrid_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("truncated_hybrid");
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
    hybrid_auto(
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

    let result = hybrid_auto(
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
fn test_symmetric_header_tamper_detection() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("symmetric_tamper");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Tamper detection test");

    let passphrase = SecretString::from("tamper_pass".to_string());

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // Tamper with the same salt byte in all three replicated copies so majority
    // vote cannot recover the original value and the decoded salt changes.
    // Encoded salt layout: [prefix(27)] [padding(3)] [copy0(32)] [copy1(32)] [copy2(32)]
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const PREFIX: usize = 27; // HEADER_PREFIX_ENCODED_SIZE
    const SALT_LEN: usize = 32;
    const SALT_BYTE: usize = 1; // which byte within each copy to corrupt
    data[PREFIX + 3 + SALT_BYTE] ^= 0xFF;
    data[PREFIX + 3 + SALT_LEN + SALT_BYTE] ^= 0xFF;
    data[PREFIX + 3 + 2 * SALT_LEN + SALT_BYTE] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_auto(
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
fn test_hybrid_header_tamper_detection() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hybrid_tamper");
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

    hybrid_auto(
        &input_file,
        &encrypt_dir,
        &pub_key_path,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    // Tamper with the same nonce byte in all three replicated copies so majority
    // vote cannot recover the original value and the decoded nonce changes.
    // Hybrid header: [prefix(27)] [encoded_envelope(411)] [encoded_nonce(63)] [encoded_hmac(99)]
    // encoded_envelope = replication::encode(136-byte envelope) = 3 + 136*3 = 411
    // encoded_nonce layout: [padding(3)] [copy0(20)] [copy1(20)] [copy2(20)]
    // (STREAM_NONCE_SIZE=19, padded to 20)
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const PREFIX: usize = 27;
    const ENVELOPE_SIZE: usize = 136;
    const ENCODED_ENVELOPE_LEN: usize = 3 + ENVELOPE_SIZE * 3;
    const PADDED_NONCE: usize = 20; // 19 rounded up to even
    const NONCE_REGION: usize = PREFIX + ENCODED_ENVELOPE_LEN; // start of encoded_nonce
    const NONCE_BYTE: usize = 5;
    data[NONCE_REGION + 3 + NONCE_BYTE] ^= 0xFF;
    data[NONCE_REGION + 3 + PADDED_NONCE + NONCE_BYTE] ^= 0xFF;
    data[NONCE_REGION + 3 + 2 * PADDED_NONCE + NONCE_BYTE] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let private_key_path = keys_dir.join("private.key");

    let result = hybrid_auto(
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
fn test_symmetric_single_copy_corruption_recovery() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("symmetric_single_copy_recovery");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let content = "Recovery test content";
    create_test_file(&input_file, content);

    let passphrase = SecretString::from("recovery_pass".to_string());

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // Corrupt one byte in copy 0 only — majority vote with copies 1 and 2 recovers it.
    // Encoded salt layout: [prefix(27)] [padding(3)] [copy0(32)] [copy1(32)] [copy2(32)]
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const PREFIX: usize = 27;
    const SALT_BYTE: usize = 5;
    data[PREFIX + 3 + SALT_BYTE] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    symmetric_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    let decrypted = fs::read_to_string(decrypt_dir.join("secret.txt"))?;
    assert_eq!(decrypted, content);

    Ok(())
}

#[test]
fn test_symmetric_two_copy_corruption_detected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("symmetric_two_copy_corrupt");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Two copy corruption test");

    let passphrase = SecretString::from("two_copy_pass".to_string());

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // Corrupt the same byte in 2 of 3 copies — majority vote picks the corrupted value,
    // changing the decoded salt and causing HMAC or key derivation failure.
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const PREFIX: usize = 27;
    const SALT_LEN: usize = 32;
    const SALT_BYTE: usize = 5;
    data[PREFIX + 3 + SALT_BYTE] ^= 0xFF;
    data[PREFIX + 3 + SALT_LEN + SALT_BYTE] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_auto(
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
fn test_symmetric_prefix_flags_tamper_detected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("symmetric_prefix_flags_tamper");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Prefix flags tamper test");

    let passphrase = SecretString::from("prefix_flags_pass".to_string());

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // Flip a bit in the flags field (logical prefix byte 6) across 2 of 3
    // replicated copies so majority vote picks the corrupted value.
    // Encoded prefix: [pad(3)] [copy0(8)] [copy1(8)] [copy2(8)]
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const FLAGS_LOGICAL: usize = 6;
    data[3 + FLAGS_LOGICAL] ^= 0x01; // copy 0
    data[11 + FLAGS_LOGICAL] ^= 0x01; // copy 1
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_auto(
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
fn test_hybrid_single_copy_corruption_recovery() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hybrid_single_copy_recovery");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let content = "Hybrid recovery test";
    create_test_file(&input_file, content);

    let key_passphrase = SecretString::from("hybrid_recovery_pass".to_string());
    generate_key_pair(&key_passphrase, &keys_dir, |_| {})?;

    let pub_key_path = keys_dir.join("public.key");

    hybrid_auto(
        &input_file,
        &encrypt_dir,
        &pub_key_path,
        &SecretString::from("".to_string()),
        None,
        None,
        |_| {},
    )?;

    // Corrupt one byte in copy 0 of the encoded nonce — majority vote recovers it.
    // Hybrid header: [prefix(27)] [encoded_envelope(411)] [encoded_nonce(63)] ...
    // encoded_nonce: [padding(3)] [copy0(20)] [copy1(20)] [copy2(20)]
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const PREFIX: usize = 27;
    const ENVELOPE_SIZE: usize = 136;
    const ENCODED_ENVELOPE_LEN: usize = 3 + ENVELOPE_SIZE * 3;
    const NONCE_REGION: usize = PREFIX + ENCODED_ENVELOPE_LEN;
    const NONCE_BYTE: usize = 5;
    data[NONCE_REGION + 3 + NONCE_BYTE] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let private_key_path = keys_dir.join("private.key");

    hybrid_auto(
        &encrypted_path,
        &decrypt_dir,
        &private_key_path,
        &key_passphrase,
        None,
        None,
        |_| {},
    )?;

    let decrypted = fs::read_to_string(decrypt_dir.join("secret.txt"))?;
    assert_eq!(decrypted, content);

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
    let result = symmetric_auto(&fake_file, &encrypt_dir, &passphrase, None, None, |_| {});
    assert!(
        result.is_ok(),
        "Expected encryption to succeed, got: {:?}",
        result
    );

    // Verify round-trip: decrypt the encrypted file and compare
    let encrypted_path = encrypt_dir.join("photo.fcr");
    assert!(encrypted_path.exists());

    let result = symmetric_auto(
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
fn test_future_major_version_rejected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("future_version");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "version test");
    let passphrase = SecretString::from("pass".to_string());

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // Patch the major version (logical prefix byte 2) in all 3 replicated copies
    // Encoded prefix: [pad(3)] [copy0(8)] [copy1(8)] [copy2(8)]
    let encrypted_path = encrypt_dir.join("data.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const MAJOR_LOGICAL: usize = 2;
    data[3 + MAJOR_LOGICAL] = 99; // copy 0
    data[11 + MAJOR_LOGICAL] = 99; // copy 1
    data[19 + MAJOR_LOGICAL] = 99; // copy 2
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );

    assert!(result.is_err());
    match &result {
        Err(CryptoError::UnsupportedVersion(v)) => {
            let msg = v.to_string();
            assert!(msg.contains("Newer file format"), "got: {msg}");
            assert!(msg.contains("Upgrade"), "got: {msg}");
        }
        other => panic!("Expected version error, got {:?}", other),
    }

    Ok(())
}

#[test]
fn test_wrong_format_type_hybrid_as_symmetric() -> Result<(), CryptoError> {
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

    // Encrypt as hybrid
    let pub_key_path = keys_dir.join("public.key");
    let empty_pass = SecretString::from("".to_string());

    hybrid_auto(
        &input_file,
        &encrypt_dir,
        &pub_key_path,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    // Try to decrypt a hybrid .fcr file with symmetric_encryption — format type mismatch
    let encrypted_path = encrypt_dir.join("data.fcr");
    let passphrase = SecretString::from("pass".to_string());
    let result = symmetric_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );

    assert!(result.is_err());
    match &result {
        Err(CryptoError::InvalidFormat(defect)) => {
            assert!(
                defect
                    .to_string()
                    .contains("Wrong encrypted file type for this operation")
            );
        }
        other => panic!("Expected format type error, got {:?}", other),
    }

    Ok(())
}

#[test]
fn test_hybrid_empty_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hybrid_empty_file");
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

    hybrid_auto(
        &input_file,
        &encrypt_dir,
        &pub_key,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    let private_key_path = keys_dir.join("private.key");

    hybrid_auto(
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

    symmetric_auto(&input_file, &encrypt_dir_a, &passphrase, None, None, |_| {})?;

    symmetric_auto(&input_file, &encrypt_dir_b, &passphrase, None, None, |_| {})?;

    let file_a = fs::read(encrypt_dir_a.join("data.fcr"))?;
    let file_b = fs::read(encrypt_dir_b.join("data.fcr"))?;

    // Same plaintext + same password must produce different ciphertext (unique salt + nonce)
    assert_ne!(file_a, file_b);

    Ok(())
}

#[test]
fn test_symmetric_output_file_override() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("symmetric_output_file_override");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "custom output path test");
    let passphrase = SecretString::from("test_password_123".to_string());

    let custom_output = encrypt_dir.join("custom_name.fcr");
    let result = symmetric_auto(
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
    let decrypt_result = symmetric_auto(
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
fn test_hybrid_output_file_override() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hybrid_output_file_override");
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

    let result = hybrid_auto(
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
    let decrypt_result = hybrid_auto(
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

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let expected = encrypt_dir.join(format!("report.{}", ENCRYPTED_EXTENSION));
    assert!(expected.exists());

    Ok(())
}

// ---------------------------------------------------------------------------
// Malformed-header tests
// ---------------------------------------------------------------------------

#[test]
fn test_symmetric_empty_file_rejected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("sym_empty_file");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // Encrypt a real file, then replace its content with just the prefix
    // (enough for magic-byte detection) but no actual header payload.
    let input_file = test_dir.join("data.txt");
    create_test_file(&input_file, "payload");
    let passphrase = SecretString::from("test".to_string());

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("data.fcr");
    let data = fs::read(&encrypted_path)?;

    // Keep only the 27-byte encoded prefix — enough for detection, no payload
    let prefix_only = &data[..27];
    fs::write(&encrypted_path, prefix_only)?;

    let result = symmetric_auto(
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
fn test_hybrid_empty_file_rejected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hyb_empty_file");
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
    hybrid_auto(
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

    let result = hybrid_auto(
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
fn test_symmetric_truncated_mid_header() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("sym_truncated_mid_header");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Truncation mid-header test");
    let passphrase = SecretString::from("pass".to_string());

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let data = fs::read(&encrypted_path)?;

    // Truncate after the 27-byte encoded prefix (enough for magic-byte detection)
    // but before the header ends — in the middle of the salt field
    let truncated = &data[..30];
    fs::write(&encrypted_path, truncated)?;

    let result = symmetric_auto(
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
fn test_symmetric_oversized_ext_len() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("sym_oversized_ext_len");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Oversized ext_len test");
    let passphrase = SecretString::from("pass".to_string());

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // Set ext_len to 0xFFFF in all 3 replicated copies of the prefix.
    // Encoded prefix: [pad(3)] [copy0(8)] [copy1(8)] [copy2(8)]
    // ext_len lives at offsets 6..=7 inside each 8-byte copy.
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const EXT_HI: usize = 6;
    const EXT_LO: usize = 7;
    for copy_start in [3, 11, 19] {
        data[copy_start + EXT_HI] = 0xFF;
        data[copy_start + EXT_LO] = 0xFF;
    }
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_auto(
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
fn test_symmetric_all_zero_header_body() {
    let test_dir = setup_test_dir("sym_zero_header_body");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&decrypt_dir).unwrap();

    // Valid prefix magic/type/version, flags=0, ext_len=0. Body is zero-filled,
    // so HMAC verification (and every subsequent check) must fail.
    let prefix: [u8; 8] = [0xFC, 0x53, 3, 0, 0, 0, 0, 0];
    let mut data = encode_test_prefix(&prefix);
    data.extend_from_slice(&[0u8; 600]);

    let file = test_dir.join("zeroed.fcr");
    fs::write(&file, &data).unwrap();

    let passphrase = SecretString::from("test".to_string());
    let result = symmetric_auto(&file, &decrypt_dir, &passphrase, None, None, |_| {});
    assert!(result.is_err());
}

#[test]
fn test_hybrid_truncated_mid_header() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hyb_truncated_mid_header");
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

    hybrid_auto(
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

    // Truncate after the 27-byte encoded prefix (enough for magic-byte detection)
    // but before the header ends — in the middle of the envelope field
    let truncated = &data[..30];
    fs::write(&encrypted_path, truncated)?;

    let result = hybrid_auto(
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
fn test_hybrid_oversized_ext_len() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hyb_oversized_ext_len");
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

    hybrid_auto(
        &input_file,
        &encrypt_dir,
        &pub_key,
        &empty_pass,
        None,
        None,
        |_| {},
    )?;

    // Set ext_len to 0xFFFF in all 3 replicated copies of the prefix.
    // ext_len lives at offsets 6..=7 inside each 8-byte copy.
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const EXT_HI: usize = 6;
    const EXT_LO: usize = 7;
    for copy_start in [3, 11, 19] {
        data[copy_start + EXT_HI] = 0xFF;
        data[copy_start + EXT_LO] = 0xFF;
    }
    fs::write(&encrypted_path, &data)?;

    let result = hybrid_auto(
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

// ---------------------------------------------------------------------------
// Ciphertext mutation tests
// ---------------------------------------------------------------------------

#[test]
fn test_symmetric_ciphertext_bit_flip_detected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("sym_ciphertext_flip");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "AEAD ciphertext integrity test");
    let passphrase = SecretString::from("ct_flip_pass".to_string());

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;

    // Flip a byte well past the header, in the ciphertext body
    let flip_offset = data.len() - 10;
    data[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_auto(
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
fn test_hybrid_ciphertext_bit_flip_detected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hyb_ciphertext_flip");
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

    hybrid_auto(
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

    let result = hybrid_auto(
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
fn test_symmetric_ciphertext_truncation_detected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("sym_ciphertext_trunc");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // Use enough data to span multiple 64 KiB chunks
    let content = "A".repeat(128 * 1024);
    create_test_file(&input_file, &content);
    let passphrase = SecretString::from("trunc_pass".to_string());

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let data = fs::read(&encrypted_path)?;

    // Truncate after the first ciphertext chunk but before the final chunk
    let half = data.len() / 2;
    fs::write(&encrypted_path, &data[..half])?;

    let result = symmetric_auto(
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
fn test_symmetric_ciphertext_appended_bytes_detected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("sym_ciphertext_append");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Append detection test");
    let passphrase = SecretString::from("append_pass".to_string());

    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;

    // Append extra bytes after the ciphertext
    data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_auto(
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

/// `PublicKey::to_bytes` round-trips through a generated key file and
/// matches the raw 32-byte payload stored after the 8-byte key-file
/// header. Also verifies the byte-source variant simply returns what
/// was passed in.
#[test]
fn test_public_key_to_bytes_round_trip() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("pubkey_to_bytes");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir)?;

    let passphrase = SecretString::from("tb".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    let pub_path = keys_dir.join("public.key");
    let from_file = PublicKey::from_key_file(&pub_path).to_bytes()?;

    // The key file stores the 8-byte header followed by the raw key.
    let raw_file = fs::read(&pub_path)?;
    assert_eq!(&from_file, &raw_file[8..40]);

    // Round-trip: from_bytes → to_bytes is the identity.
    let echoed = PublicKey::from_bytes(from_file).to_bytes()?;
    assert_eq!(echoed, from_file);

    Ok(())
}

/// `PublicKey::validate` succeeds on a well-formed key file, succeeds
/// unconditionally on the bytes source, and fails with a structural
/// error (not a panic) when pointed at a file that does not exist.
#[test]
fn test_public_key_validate() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("pubkey_validate");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir)?;

    let passphrase = SecretString::from("vp".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    // Valid file: validate passes.
    PublicKey::from_key_file(keys_dir.join("public.key")).validate()?;

    // Raw bytes: validate is always Ok (no structural checks apply).
    PublicKey::from_bytes([0xAB; 32]).validate()?;

    // Nonexistent file: validate returns an I/O error, not a panic.
    let missing = keys_dir.join("does_not_exist.key");
    assert!(PublicKey::from_key_file(&missing).validate().is_err());

    // Pointing at a private-key file: the public-key parser rejects the
    // wrong key-file kind instead of leaking secret material.
    let private_as_public = PublicKey::from_key_file(keys_dir.join("private.key"));
    assert!(private_as_public.validate().is_err());

    Ok(())
}

/// The `FromStr` impl routes through `PublicKey::from_recipient_string`,
/// so `"fcr1…".parse::<PublicKey>()` must accept a valid recipient
/// string and round-trip back through `to_recipient_string`, and must
/// reject Bech32 with the wrong HRP.
#[test]
fn test_public_key_from_str_round_trip() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("pubkey_from_str");
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
fn test_symmetric_encrypt_cleans_up_on_failure() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("sym_encrypt_cleanup");
    let real_file = test_dir.join("real.txt");
    let symlink_path = test_dir.join("link.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir)?;
    create_test_file(&real_file, "target content");
    std::os::unix::fs::symlink(&real_file, &symlink_path).unwrap();

    let passphrase = SecretString::from("cleanup_pass".to_string());
    let result = symmetric_auto(&symlink_path, &encrypt_dir, &passphrase, None, None, |_| {});
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
fn test_hybrid_encrypt_cleans_up_on_failure() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hyb_encrypt_cleanup");
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

    let result = hybrid_auto(
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
fn test_symmetric_decrypt_marks_incomplete_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("sym_decrypt_incomplete_file");
    let input_file = test_dir.join("bigfile.bin");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // 200 KB file — spans multiple 64 KB encryption chunks
    let big_data: Vec<u8> = (0..204_800u32).map(|i| (i % 256) as u8).collect();
    fs::write(&input_file, &big_data)?;

    let passphrase = SecretString::from("incomplete_pass".to_string());
    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("bigfile.fcr");
    let mut data = fs::read(&encrypted_path)?;
    // Corrupt a byte in a late chunk (well past the first 64 KB)
    let flip_offset = data.len() - 50;
    data[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );
    assert!(result.is_err());

    let incomplete_path = decrypt_dir.join("bigfile.bin.incomplete");
    assert!(
        incomplete_path.exists(),
        "partial output should have been renamed to .incomplete"
    );
    // Original name should not exist
    assert!(!decrypt_dir.join("bigfile.bin").exists());

    Ok(())
}

#[test]
fn test_symmetric_decrypt_marks_incomplete_directory() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("sym_decrypt_incomplete_dir");
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
    symmetric_auto(&input_dir, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let encrypted_path = encrypt_dir.join("mydir.fcr");
    let mut data = fs::read(&encrypted_path)?;
    let flip_offset = data.len() - 50;
    data[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );
    assert!(result.is_err());

    let incomplete_path = decrypt_dir.join("mydir.incomplete");
    assert!(
        incomplete_path.exists(),
        "partial directory should have been renamed to .incomplete"
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
    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    let output = symmetric_auto(
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
    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // Simulate leftover .incomplete from a previous failed attempt
    fs::write(decrypt_dir.join("data.txt.incomplete"), "stale partial")?;

    let result = symmetric_auto(
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
    let output = symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    assert!(output.exists());
    assert_eq!(output, encrypt_dir.join("secret.fcr"));
    assert!(!encrypt_dir.join("secret.fcr.incomplete").exists());

    Ok(())
}

#[test]
fn test_keygen_no_partial_state_on_existing_key() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("keygen_no_partial");
    let passphrase = SecretString::from("atomic_pass".to_string());

    // First keygen succeeds
    generate_key_pair(&passphrase, &test_dir, |_| {})?;
    assert!(test_dir.join("private.key").exists());
    assert!(test_dir.join("public.key").exists());

    // Second keygen to the same dir fails — keys already exist
    let result = generate_key_pair(&passphrase, &test_dir, |_| {});
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_older_major_version_rejected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("older_version");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "version test");
    let passphrase = SecretString::from("pass".to_string());
    symmetric_auto(&input_file, &encrypt_dir, &passphrase, None, None, |_| {})?;

    // Patch the major version to an older value in all 3 replicated copies
    let encrypted_path = encrypt_dir.join("data.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const MAJOR_OFFSET: usize = 2;
    data[3 + MAJOR_OFFSET] = 1; // copy 0
    data[11 + MAJOR_OFFSET] = 1; // copy 1
    data[19 + MAJOR_OFFSET] = 1; // copy 2
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_auto(
        &encrypted_path,
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    );
    assert!(result.is_err());
    match &result {
        Err(CryptoError::UnsupportedVersion(v)) => {
            let msg = v.to_string();
            assert!(msg.contains("Older file format"), "got: {msg}");
            assert!(msg.contains("Use a previous release"), "got: {msg}");
        }
        other => panic!("Expected version error, got {:?}", other),
    }

    Ok(())
}

#[test]
fn test_older_key_version_rejected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("older_key_version");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let passphrase = SecretString::from("key_ver_pass".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    // Encrypt a file so we have something to try decrypting
    let empty = SecretString::from("".to_string());
    create_test_file(&input_file, "key version test");
    hybrid_auto(
        &input_file,
        &encrypt_dir,
        keys_dir.join("public.key"),
        &empty,
        None,
        None,
        |_| {},
    )?;

    // Patch private key version to an older value (byte offset 2)
    let private_key_path = keys_dir.join("private.key");
    let mut key_data = fs::read(&private_key_path)?;
    key_data[2] = 1; // older version
    fs::write(&private_key_path, &key_data)?;

    let result = hybrid_auto(
        encrypt_dir.join("data.fcr"),
        &decrypt_dir,
        &private_key_path,
        &passphrase,
        None,
        None,
        |_| {},
    );
    assert!(result.is_err());
    match &result {
        Err(CryptoError::UnsupportedVersion(v)) => {
            let msg = v.to_string();
            assert!(msg.contains("Older key format"), "got: {msg}");
            assert!(msg.contains("Use a previous release"), "got: {msg}");
        }
        other => panic!("Expected key version error, got {:?}", other),
    }

    Ok(())
}

/// Flipping a byte in the cleartext salt region of a v4 `private.key`
/// file must cause decryption to fail. v4 binds the cleartext
/// header/KDF-params/salt/nonce/ext_len/ext_bytes as AEAD associated
/// data; in the old v3 format the same tamper would only make the
/// derived key wrong, producing an identical AEAD failure downstream,
/// so this test documents the behavior at the public API surface.
#[test]
fn test_private_key_v4_salt_tamper_rejected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("v4_salt_tamper");
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
    hybrid_auto(
        &input_file,
        &encrypt_dir,
        keys_dir.join("public.key"),
        &empty,
        None,
        None,
        |_| {},
    )?;

    // Flip one byte inside the 32-byte Argon2 salt region. v4 body layout:
    //   [kdf(12)][salt(32)][nonce(24)][ext_len(2)][ext_bytes(0)][ciphertext+tag(48)]
    // The salt region starts at header(8) + kdf(12) = offset 20.
    let private_key_path = keys_dir.join("private.key");
    let mut key_data = fs::read(&private_key_path)?;
    let salt_offset = 8 + 12;
    key_data[salt_offset] ^= 0x01;
    fs::write(&private_key_path, &key_data)?;

    let result = hybrid_auto(
        encrypt_dir.join("data.fcr"),
        &decrypt_dir,
        &private_key_path,
        &passphrase,
        None,
        None,
        |_| {},
    );
    assert!(
        result.is_err(),
        "tampered salt must not decrypt even with the correct passphrase"
    );

    Ok(())
}

/// Setting a reserved key-file flag bit must be rejected by the
/// structural validator before the KDF is even attempted. The flags
/// field is also part of the AEAD AAD on decrypt — even if the
/// validator were bypassed, AEAD authentication would also reject the
/// tampered file — but the cheap structural check comes first.
#[test]
fn test_private_key_v4_flags_tamper_rejected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("v4_flags_tamper");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir)?;

    let passphrase = SecretString::from("flags_pass".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    // Flip a reserved flag bit in the 8-byte key-file header. Flags are
    // the big-endian u16 at bytes 6..=7.
    let private_key_path = keys_dir.join("private.key");
    let mut key_data = fs::read(&private_key_path)?;
    key_data[7] |= 0x01;
    fs::write(&private_key_path, &key_data)?;

    match validate_private_key_file(&private_key_path) {
        Err(ferrocrypt::CryptoError::InvalidFormat(
            ferrocrypt::FormatDefect::UnknownKeyFileFlags(_),
        )) => {}
        other => panic!("expected UnknownKeyFileFlags, got {:?}", other),
    }

    Ok(())
}

/// The body-size consistency check rejects a file whose declared
/// `data_len` disagrees with the parsed `ext_len`. This test corrupts
/// `data_len` without adjusting the body so the two disagree.
#[test]
fn test_private_key_v4_data_len_mismatch_rejected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("v4_data_len_mismatch");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir)?;

    let passphrase = SecretString::from("dl_pass".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    // Bump `data_len` (big-endian u16 at bytes 4..=5) by 1 — the body
    // itself stays 118 bytes so the declared size no longer matches
    // the on-disk size.
    let private_key_path = keys_dir.join("private.key");
    let mut key_data = fs::read(&private_key_path)?;
    let current = u16::from_be_bytes([key_data[4], key_data[5]]);
    let bumped = current.wrapping_add(1).to_be_bytes();
    key_data[4] = bumped[0];
    key_data[5] = bumped[1];
    fs::write(&private_key_path, &key_data)?;

    match validate_private_key_file(&private_key_path) {
        Err(ferrocrypt::CryptoError::InvalidFormat(ferrocrypt::FormatDefect::BadKeyFileSize)) => {}
        other => panic!("expected BadKeyFileSize, got {:?}", other),
    }

    Ok(())
}

#[test]
fn test_future_key_version_rejected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("future_key_version");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir)?;

    let passphrase = SecretString::from("key_ver_pass".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    // Patch private key version to a future value
    let private_key_path = keys_dir.join("private.key");
    let mut key_data = fs::read(&private_key_path)?;
    key_data[2] = 99; // future version
    fs::write(&private_key_path, &key_data)?;

    let result = validate_private_key_file(&private_key_path);
    assert!(result.is_err());
    match &result {
        Err(CryptoError::UnsupportedVersion(v)) => {
            let msg = v.to_string();
            assert!(msg.contains("Newer key format"), "got: {msg}");
            assert!(msg.contains("Upgrade"), "got: {msg}");
        }
        other => panic!("Expected key version error, got {:?}", other),
    }

    // Same for public key
    let public_key_path = keys_dir.join("public.key");
    let mut pub_data = fs::read(&public_key_path)?;
    pub_data[2] = 99;
    fs::write(&public_key_path, &pub_data)?;

    let result = PublicKey::from_key_file(&public_key_path).fingerprint();
    assert!(result.is_err());
    match &result {
        Err(CryptoError::UnsupportedVersion(v)) => {
            let msg = v.to_string();
            assert!(msg.contains("Newer key format"), "got: {msg}");
            assert!(msg.contains("Upgrade"), "got: {msg}");
        }
        other => panic!("Expected key version error, got {:?}", other),
    }

    Ok(())
}

// ─── detect_encryption_mode: fail-closed on malformed headers ────────────

#[test]
fn test_detect_plaintext_file_returns_none() -> Result<(), CryptoError> {
    let dir = setup_test_dir("detect_plaintext");
    let path = dir.join("hello.txt");
    fs::write(&path, "just plain text")?;
    assert!(detect_encryption_mode(&path)?.is_none());
    Ok(())
}

#[test]
fn test_detect_empty_file_returns_none() -> Result<(), CryptoError> {
    let dir = setup_test_dir("detect_empty");
    let path = dir.join("empty.bin");
    fs::write(&path, b"")?;
    assert!(detect_encryption_mode(&path)?.is_none());
    Ok(())
}

/// A directory is unambiguously "not an encrypted file." Unix lets us open a
/// directory fd and only fails at `read()` with `IsADirectory`; Windows'
/// `CreateFile` rejects directories outright with `ERROR_ACCESS_DENIED`.
/// Regardless of platform, `detect_encryption_mode` must classify a directory
/// as `Ok(None)` so that auto-routing wrappers take the encrypt branch rather
/// than surfacing a permission error. Covers both populated and empty roots.
#[test]
fn test_detect_directory_returns_none() -> Result<(), CryptoError> {
    let dir = setup_test_dir("detect_directory");

    let populated = dir.join("populated");
    fs::create_dir_all(&populated)?;
    create_test_file(&populated.join("inside.txt"), "content");
    assert!(detect_encryption_mode(&populated)?.is_none());

    let empty = dir.join("empty");
    fs::create_dir_all(&empty)?;
    assert!(detect_encryption_mode(&empty)?.is_none());

    Ok(())
}

#[test]
fn test_detect_valid_symmetric_file() -> Result<(), CryptoError> {
    let dir = setup_test_dir("detect_sym");
    let input = dir.join("data.txt");
    fs::write(&input, "payload")?;
    let pass = SecretString::from("pw".to_string());
    let encrypted = symmetric_auto(&input, &dir, &pass, None, None, |_| {})?;
    let mode = detect_encryption_mode(&encrypted)?;
    assert_eq!(mode, Some(ferrocrypt::EncryptionMode::Symmetric));
    Ok(())
}

#[test]
fn test_detect_truncated_fcr_file_returns_error() {
    let dir = setup_test_dir("detect_truncated");
    let path = dir.join("truncated.fcr");
    // Write a partial encoded prefix with magic byte in at least two copy positions.
    // Copy 0 starts at byte 3, copy 1 at byte 11 — both need 0xFC for majority vote.
    let mut data = vec![0u8; 15];
    data[3] = 0xFC; // magic byte in copy 0
    data[11] = 0xFC; // magic byte in copy 1
    fs::write(&path, &data).unwrap();
    let result = detect_encryption_mode(&path);
    assert!(
        result.is_err(),
        "expected error for truncated .fcr, got: {result:?}"
    );
    match &result {
        Err(CryptoError::InvalidFormat(defect)) => {
            let msg = defect.to_string();
            assert!(msg.contains("truncated"), "got: {msg}");
        }
        other => panic!("expected InvalidFormat, got: {other:?}"),
    }
}

#[test]
fn test_detect_short_file_with_single_magic_byte_returns_none() {
    let dir = setup_test_dir("detect_single_magic");
    let path = dir.join("coincidence.bin");
    // A short file with 0xFC at position 3 by coincidence — only one copy
    // position matches, so majority vote says "not ferrocrypt."
    let mut data = vec![0u8; 10];
    data[3] = 0xFC;
    fs::write(&path, &data).unwrap();
    let result = detect_encryption_mode(&path);
    assert!(
        result.unwrap().is_none(),
        "single magic byte should not trigger false positive"
    );
}

#[test]
fn test_detect_corrupted_header_returns_error() {
    let dir = setup_test_dir("detect_corrupted");
    let path = dir.join("corrupted.fcr");
    // Build a full-length encoded prefix (27 bytes) where the magic byte is
    // present in all three copy positions but the rest is garbage, so
    // replication decode produces an invalid type byte.
    let mut data = vec![0u8; 27];
    // padding bytes (positions 0-2): 0
    // Copy 0 starts at 3, copy 1 at 11, copy 2 at 19
    data[3] = 0xFC; // magic byte in copy 0
    data[11] = 0xFC; // magic byte in copy 1
    data[19] = 0xFC; // magic byte in copy 2
    // Type byte (position 1 of each copy) is 0xFF — unknown type
    data[4] = 0xFF;
    data[12] = 0xFF;
    data[20] = 0xFF;
    fs::write(&path, &data).unwrap();
    let result = detect_encryption_mode(&path);
    assert!(
        result.is_err(),
        "expected error for corrupted header, got: {result:?}"
    );
}

#[test]
fn test_detect_unknown_type_byte_returns_error() {
    let dir = setup_test_dir("detect_unknown_type");
    let path = dir.join("unknown_type.fcr");
    // Encode a valid-looking prefix with magic byte but invalid type 0x41 ('A')
    let prefix: [u8; 8] = [0xFC, 0x41, 3, 0, 0, 30, 0, 0];
    let encoded = encode_test_prefix(&prefix);
    fs::write(&path, &encoded).unwrap();
    let result = detect_encryption_mode(&path);
    assert!(
        result.is_err(),
        "expected error for unknown type, got: {result:?}"
    );
    match &result {
        Err(CryptoError::InvalidFormat(defect)) => {
            let msg = defect.to_string();
            assert!(msg.contains("0x41"), "got: {msg}");
        }
        other => panic!("expected InvalidFormat with type byte, got: {other:?}"),
    }
}

#[test]
fn test_detect_corrupted_fcr_not_silently_encrypted() {
    let dir = setup_test_dir("detect_no_reencrypt");
    let input = dir.join("corrupted.fcr");
    // A file with magic bytes but corrupted — should not be re-encrypted
    let prefix: [u8; 8] = [0xFC, 0x41, 3, 0, 0, 30, 0, 0];
    let encoded = encode_test_prefix(&prefix);
    fs::write(&input, &encoded).unwrap();
    let pass = SecretString::from("pw".to_string());
    let result = symmetric_auto(&input, &dir, &pass, None, None, |_| {});
    assert!(
        result.is_err(),
        "corrupted .fcr should not be silently re-encrypted"
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

    let decoded = decode_recipient(&encoded)?;
    let re_encoded = PublicKey::from_bytes(decoded).to_recipient_string()?;
    assert_eq!(encoded, re_encoded);

    Ok(())
}

#[test]
fn test_recipient_wrong_hrp_rejected() {
    // Valid Bech32 with wrong HRP
    let wrong =
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse_unchecked("age"), &[0xBB; 32]).unwrap();
    let result = decode_recipient(&wrong);
    assert!(result.is_err());
    match result {
        Err(CryptoError::InvalidInput(msg)) => {
            assert!(msg.contains("Not a FerroCrypt"), "got: {msg}");
        }
        other => panic!("Expected InvalidInput, got {:?}", other),
    }
}

#[test]
fn test_recipient_wrong_length_rejected() {
    // Encode 16 bytes (too short for X25519) with the right HRP
    let short =
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse_unchecked("fcr"), &[0xAA; 16]).unwrap();
    let result = decode_recipient(&short);
    assert!(result.is_err());
    match result {
        Err(CryptoError::InvalidInput(msg)) => {
            assert!(msg.contains("length"), "got: {msg}");
        }
        other => panic!("Expected InvalidInput, got {:?}", other),
    }
}

#[test]
fn test_recipient_malformed_bech32_rejected() {
    let result = decode_recipient("fcr1not-valid-bech32!!!");
    assert!(result.is_err());
}

#[test]
fn test_recipient_decodes_to_key_file_bytes() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("recipient_keybytes");
    let keys_dir = test_dir.join("keys");
    let passphrase = SecretString::from("rf".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    let pub_path = keys_dir.join("public.key");
    let recipient = PublicKey::from_key_file(&pub_path).to_recipient_string()?;
    let decoded_bytes = decode_recipient(&recipient)?;

    // Verify decoded bytes match the raw key in the file (after 8-byte header)
    let raw_file = fs::read(&pub_path)?;
    assert_eq!(&decoded_bytes, &raw_file[8..40]);

    Ok(())
}

#[test]
fn test_recipient_uppercase_accepted() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("recipient_uppercase");
    let keys_dir = test_dir.join("keys");
    let passphrase = SecretString::from("uc".to_string());
    generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    let encoded = PublicKey::from_key_file(keys_dir.join("public.key")).to_recipient_string()?;
    let uppercased = encoded.to_uppercase();
    let decoded = decode_recipient(&uppercased)?;
    let original = decode_recipient(&encoded)?;
    assert_eq!(decoded, original);

    Ok(())
}

#[ctor::dtor]
fn cleanup() {
    cleanup_test_workspace();
}
