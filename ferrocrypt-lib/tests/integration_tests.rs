/// Integration tests for ferrocrypt library
use std::fs;
use std::path::{Path, PathBuf};

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    CryptoError, ENCRYPTED_EXTENSION, generate_key_pair, hybrid_encryption, public_key_fingerprint,
    symmetric_encryption,
};

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
    let encrypt_result = symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    assert!(encrypt_result.contains("Encrypted to"));
    assert!(encrypt_dir.join("input.fcr").exists());

    // Decrypt
    let decrypt_result = symmetric_encryption(
        encrypt_dir.join("input.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    assert!(decrypt_result.contains("Decrypted to"));

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
    let encrypt_result = symmetric_encryption(
        input_dir.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    assert!(encrypt_result.contains("Encrypted to"));
    assert!(encrypt_dir.join("test_folder.fcr").exists());

    // Decrypt directory
    let decrypt_result = symmetric_encryption(
        encrypt_dir.join("test_folder.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    assert!(decrypt_result.contains("Decrypted to"));

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
    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &correct_pass,
        None,
        |_| {},
    )?;

    // Try to decrypt with wrong password - should fail
    let result = symmetric_encryption(
        encrypt_dir.join("secret.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &wrong_pass,
        None,
        |_| {},
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::CryptoOperation(msg)) => {
            assert!(msg.contains("incorrect"));
        }
        _ => panic!("Expected CryptoOperation"),
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

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    assert!(encrypt_dir.join("multi_chunk.fcr").exists());

    symmetric_encryption(
        encrypt_dir.join("multi_chunk.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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

    let err = generate_key_pair(&empty, test_dir.to_str().unwrap(), |_| {}).unwrap_err();
    assert!(
        err.to_string().contains("empty"),
        "expected empty-passphrase error, got: {err}"
    );
}

#[cfg(unix)]
#[test]
fn test_hybrid_keygen_private_key_permissions() -> Result<(), CryptoError> {
    use std::os::unix::fs::PermissionsExt;

    let test_dir = setup_test_dir("keygen_permissions");
    let passphrase = SecretString::from("pass".to_string());

    generate_key_pair(&passphrase, test_dir.to_str().unwrap(), |_| {})?;

    let secret_key = test_dir.join("private.key");
    let pub_key = test_dir.join("public.key");
    let priv_mode = fs::metadata(&secret_key)?.permissions().mode() & 0o777;
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
    let keygen_result = generate_key_pair(&key_passphrase, keys_dir.to_str().unwrap(), |_| {})?;

    assert!(keygen_result.contains("Generated key pair"));
    assert!(keys_dir.join("private.key").exists());
    assert!(keys_dir.join("public.key").exists());

    // Encrypt with public key
    let pub_key_path = keys_dir.join("public.key").to_str().unwrap().to_string();
    let empty_pass = SecretString::from("".to_string());

    let encrypt_result = hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &pub_key_path,
        &empty_pass,
        None,
        |_| {},
    )?;

    assert!(encrypt_result.contains("Encrypted to"));
    assert!(encrypt_dir.join("data.fcr").exists());

    // Decrypt with private key
    let secret_key_path = keys_dir.join("private.key").to_str().unwrap().to_string();

    let decrypt_result = hybrid_encryption(
        encrypt_dir.join("data.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &secret_key_path,
        &key_passphrase,
        None,
        |_| {},
    )?;

    assert!(decrypt_result.contains("Decrypted to"));

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
    generate_key_pair(&key_passphrase, keys_dir.to_str().unwrap(), |_| {})?;

    // Encrypt directory
    let pub_key_path = keys_dir.join("public.key").to_str().unwrap().to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_dir.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &pub_key_path,
        &empty_pass,
        None,
        |_| {},
    )?;

    assert!(encrypt_dir.join("test_folder.fcr").exists());

    // Decrypt directory
    let secret_key_path = keys_dir.join("private.key").to_str().unwrap().to_string();

    hybrid_encryption(
        encrypt_dir.join("test_folder.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &secret_key_path,
        &key_passphrase,
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
    generate_key_pair(&correct_pass, keys_dir.to_str().unwrap(), |_| {})?;

    // Encrypt
    let pub_key_path = keys_dir.join("public.key").to_str().unwrap().to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &pub_key_path,
        &empty_pass,
        None,
        |_| {},
    )?;

    // Try to decrypt with wrong passphrase
    let secret_key_path = keys_dir.join("private.key").to_str().unwrap().to_string();

    let result = hybrid_encryption(
        encrypt_dir.join("data.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &secret_key_path,
        &wrong_pass,
        None,
        |_| {},
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::CryptoOperation(msg)) => {
            assert!(msg.contains("Incorrect password") || msg.contains("wrong private key"));
        }
        _ => panic!("Expected CryptoOperation"),
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
    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    // Decrypt
    symmetric_encryption(
        encrypt_dir.join("empty.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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
    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    // Decrypt
    symmetric_encryption(
        encrypt_dir.join("unicode.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    symmetric_encryption(
        encrypt_dir
            .join("file-with_special.chars.fcr")
            .to_str()
            .unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    assert!(decrypt_dir.join("file-with_special.chars.txt").exists());

    Ok(())
}

#[test]
fn test_nonexistent_output_dir() {
    let passphrase = SecretString::from("test".to_string());

    let result = symmetric_encryption(
        "Cargo.toml",
        "/nonexistent/path/output",
        &passphrase,
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

    let result = symmetric_encryption(
        "/nonexistent/missing.fcr",
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    symmetric_encryption(
        encrypt_dir.join("data.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &correct_pass,
        None,
        |_| {},
    )?;

    // Decrypt with wrong password
    let result = symmetric_encryption(
        encrypt_dir.join("data.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &wrong_pass,
        None,
        |_| {},
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::CryptoOperation(msg)) => {
            assert!(msg.contains("incorrect"));
        }
        _ => panic!("Expected CryptoOperation"),
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

    symmetric_encryption(
        input_dir.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    assert!(encrypt_dir.join("test_folder.fcr").exists());

    symmetric_encryption(
        encrypt_dir.join("test_folder.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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

    let result = symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &empty_pass,
        None,
        |_| {},
    );

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
    generate_key_pair(&pass_a, keys_a.to_str().unwrap(), |_| {})?;
    generate_key_pair(&pass_b, keys_b.to_str().unwrap(), |_| {})?;

    // Encrypt with key pair A's public key
    let pub_key_a = keys_a.join("public.key").to_str().unwrap().to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &pub_key_a,
        &empty_pass,
        None,
        |_| {},
    )?;

    // Try to decrypt with key pair B's private key — should fail
    let secret_key_b = keys_b.join("private.key").to_str().unwrap().to_string();

    let result = hybrid_encryption(
        encrypt_dir.join("data.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &secret_key_b,
        &pass_b,
        None,
        |_| {},
    );

    assert!(result.is_err());

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

    generate_key_pair(&key_passphrase, keys_dir.to_str().unwrap(), |_| {})?;

    // Encrypt
    let pub_key_path = keys_dir.join("public.key").to_str().unwrap().to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &pub_key_path,
        &empty_pass,
        None,
        |_| {},
    )?;

    assert!(encrypt_dir.join("data.fcr").exists());

    // Decrypt
    let secret_key_path = keys_dir.join("private.key").to_str().unwrap().to_string();

    hybrid_encryption(
        encrypt_dir.join("data.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &secret_key_path,
        &key_passphrase,
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
    generate_key_pair(&key_passphrase, keys_dir.to_str().unwrap(), |_| {})?;

    let pub_key_path = keys_dir.join("public.key").to_str().unwrap().to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &pub_key_path,
        &empty_pass,
        None,
        |_| {},
    )?;

    let secret_key_path = keys_dir.join("private.key").to_str().unwrap().to_string();

    hybrid_encryption(
        encrypt_dir.join("data.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &secret_key_path,
        &key_passphrase,
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

    let result = symmetric_encryption(
        "/nonexistent/path/file.txt",
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::InputPath(_)) => {}
        other => panic!("Expected InputPath error, got {:?}", other),
    }
}

#[test]
fn test_truncated_symmetric_file() {
    let test_dir = setup_test_dir("truncated_symmetric");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&decrypt_dir).unwrap();

    // Write a tiny file that's too short to be a valid .fcr
    let truncated_file = test_dir.join("truncated.fcr");
    fs::write(&truncated_file, b"short").unwrap();

    let passphrase = SecretString::from("test".to_string());

    let result = symmetric_encryption(
        truncated_file.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    );

    assert!(result.is_err());
}

#[test]
fn test_truncated_hybrid_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("truncated_hybrid");
    let keys_dir = test_dir.join("keys");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let key_passphrase = SecretString::from("pass".to_string());
    generate_key_pair(&key_passphrase, keys_dir.to_str().unwrap(), |_| {})?;

    // Write a tiny file that's too short to be a valid .fcr
    let truncated_file = test_dir.join("truncated.fcr");
    fs::write(&truncated_file, b"short").unwrap();

    let secret_key_path = keys_dir.join("private.key").to_str().unwrap().to_string();

    let result = hybrid_encryption(
        truncated_file.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &secret_key_path,
        &key_passphrase,
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

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

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

    let result = symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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
    generate_key_pair(&key_passphrase, keys_dir.to_str().unwrap(), |_| {})?;

    let pub_key_path = keys_dir.join("public.key").to_str().unwrap().to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &pub_key_path,
        &empty_pass,
        None,
        |_| {},
    )?;

    // Tamper with the same nonce byte in all three replicated copies so majority
    // vote cannot recover the original value and the decoded nonce changes.
    // Hybrid header: [prefix(27)] [encoded_envelope(411)] [encoded_nonce(63)] [encoded_hmac(99)]
    // encoded_envelope = rep_encode(136-byte envelope) = 3 + 136*3 = 411
    // encoded_nonce layout: [padding(3)] [copy0(20)] [copy1(20)] [copy2(20)]
    // (NONCE_SIZE=19, padded to 20)
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

    let secret_key_path = keys_dir.join("private.key").to_str().unwrap().to_string();

    let result = hybrid_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &secret_key_path,
        &key_passphrase,
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

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    // Corrupt one byte in copy 0 only — majority vote with copies 1 and 2 recovers it.
    // Encoded salt layout: [prefix(27)] [padding(3)] [copy0(32)] [copy1(32)] [copy2(32)]
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const PREFIX: usize = 27;
    const SALT_BYTE: usize = 5;
    data[PREFIX + 3 + SALT_BYTE] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

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

    let result = symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    // Flip a bit in the flags field (logical prefix byte 6) across 2 of 3
    // replicated copies so majority vote picks the corrupted value.
    // Encoded prefix: [pad(3)] [copy0(8)] [copy1(8)] [copy2(8)]
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const FLAGS_LOGICAL: usize = 6;
    data[3 + FLAGS_LOGICAL] ^= 0x01; // copy 0
    data[11 + FLAGS_LOGICAL] ^= 0x01; // copy 1
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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
    generate_key_pair(&key_passphrase, keys_dir.to_str().unwrap(), |_| {})?;

    let pub_key_path = keys_dir.join("public.key").to_str().unwrap().to_string();

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &pub_key_path,
        &SecretString::from("".to_string()),
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

    let secret_key_path = keys_dir.join("private.key").to_str().unwrap().to_string();

    hybrid_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &secret_key_path,
        &key_passphrase,
        None,
        |_| {},
    )?;

    let decrypted = fs::read_to_string(decrypt_dir.join("secret.txt"))?;
    assert_eq!(decrypted, content);

    Ok(())
}

#[test]
fn test_not_a_ferrocrypt_file() {
    let test_dir = setup_test_dir("not_ferrocrypt");
    let fake_file = test_dir.join("photo.fcr");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&decrypt_dir).unwrap();

    // A JPEG header renamed to .fcr (padded to exceed the replicated prefix size)
    fs::write(&fake_file, b"\xFF\xD8\xFF\xE0fake jpeg data padding!!").unwrap();

    let passphrase = SecretString::from("test".to_string());
    let result = symmetric_encryption(
        fake_file.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::CryptoOperation(msg)) => {
            assert!(msg.contains("Not a valid FerroCrypt file"));
        }
        other => panic!("Expected 'Not a valid FerroCrypt file', got {:?}", other),
    }
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

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    // Patch the major version (logical prefix byte 2) in all 3 replicated copies
    // Encoded prefix: [pad(3)] [copy0(8)] [copy1(8)] [copy2(8)]
    let encrypted_path = encrypt_dir.join("data.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const MAJOR_LOGICAL: usize = 2;
    data[3 + MAJOR_LOGICAL] = 99; // copy 0
    data[11 + MAJOR_LOGICAL] = 99; // copy 1
    data[19 + MAJOR_LOGICAL] = 99; // copy 2
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::CryptoOperation(msg)) => {
            assert!(msg.contains("not supported"));
            assert!(msg.contains("Upgrade"));
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
    generate_key_pair(&key_passphrase, keys_dir.to_str().unwrap(), |_| {})?;

    // Encrypt as hybrid
    let pub_key_path = keys_dir.join("public.key").to_str().unwrap().to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &pub_key_path,
        &empty_pass,
        None,
        |_| {},
    )?;

    // Try to decrypt a hybrid .fcr file with symmetric_encryption — format type mismatch
    let encrypted_path = encrypt_dir.join("data.fcr");
    let passphrase = SecretString::from("pass".to_string());
    let result = symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::CryptoOperation(msg)) => {
            assert!(msg.contains("different format type"));
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
    generate_key_pair(&key_passphrase, keys_dir.to_str().unwrap(), |_| {})?;

    let pub_key = keys_dir.join("public.key").to_str().unwrap().to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &pub_key,
        &empty_pass,
        None,
        |_| {},
    )?;

    let secret_key = keys_dir.join("private.key").to_str().unwrap().to_string();

    hybrid_encryption(
        encrypt_dir.join("empty.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &secret_key,
        &key_passphrase,
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

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir_a.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir_b.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

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
    let result = symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        Some(custom_output.to_str().unwrap()),
        |_| {},
    )?;

    assert!(result.contains("custom_name.fcr"));
    assert!(custom_output.exists());
    // Default name should not exist
    assert!(!encrypt_dir.join("data.fcr").exists());

    // Decrypt the custom-named file
    let decrypt_result = symmetric_encryption(
        custom_output.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    assert!(decrypt_result.contains("Decrypted to"));
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

    generate_key_pair(&passphrase, key_dir.to_str().unwrap(), |_| {})?;

    let pub_key = key_dir.join("public.key");
    let secret_key = key_dir.join("private.key");
    let custom_output = encrypt_dir.join("my_vault.fcr");
    let empty = SecretString::from("".to_string());

    let result = hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        pub_key.to_str().unwrap(),
        &empty,
        Some(custom_output.to_str().unwrap()),
        |_| {},
    )?;

    assert!(result.contains("my_vault.fcr"));
    assert!(custom_output.exists());
    assert!(!encrypt_dir.join("data.fcr").exists());

    // Decrypt the custom-named file
    let decrypt_result = hybrid_encryption(
        custom_output.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        secret_key.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    assert!(decrypt_result.contains("Decrypted to"));
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

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    let expected = encrypt_dir.join(format!("report.{}", ENCRYPTED_EXTENSION));
    assert!(expected.exists());

    Ok(())
}

// ---------------------------------------------------------------------------
// Malformed-header tests
// ---------------------------------------------------------------------------

#[test]
fn test_symmetric_empty_file_rejected() {
    let test_dir = setup_test_dir("sym_empty_file");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&decrypt_dir).unwrap();

    let empty_file = test_dir.join("empty.fcr");
    fs::write(&empty_file, b"").unwrap();

    let passphrase = SecretString::from("test".to_string());
    let result = symmetric_encryption(
        empty_file.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    );
    assert!(result.is_err());
}

#[test]
fn test_hybrid_empty_file_rejected() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hyb_empty_file");
    let keys_dir = test_dir.join("keys");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let key_pass = SecretString::from("kp".to_string());
    generate_key_pair(&key_pass, keys_dir.to_str().unwrap(), |_| {})?;

    let secret_key = keys_dir.join("private.key");
    let empty_file = test_dir.join("empty.fcr");
    fs::write(&empty_file, b"").unwrap();

    let result = hybrid_encryption(
        empty_file.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        secret_key.to_str().unwrap(),
        &key_pass,
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

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let data = fs::read(&encrypted_path)?;

    // Truncate in the middle of the salt field (after prefix but before header ends)
    let truncated = &data[..12];
    fs::write(&encrypted_path, truncated)?;

    let result = symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    );
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_symmetric_oversized_header_len() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("sym_oversized_header_len");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    create_test_file(&input_file, "Oversized header_len test");
    let passphrase = SecretString::from("pass".to_string());

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    // Set header_len to 0xFFFF in all 3 replicated copies
    // Encoded prefix: [pad(3)] [copy0(8)] [copy1(8)] [copy2(8)]
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const HLEN_HI: usize = 4;
    const HLEN_LO: usize = 5;
    for copy_start in [3, 11, 19] {
        data[copy_start + HLEN_HI] = 0xFF;
        data[copy_start + HLEN_LO] = 0xFF;
    }
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    );
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_symmetric_header_len_too_small() {
    let test_dir = setup_test_dir("sym_header_len_too_small");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&decrypt_dir).unwrap();

    // Build a replicated prefix with header_len = 4, which is invalid
    let prefix: [u8; 8] = [0xFC, 0x53, 3, 0, 0, 4, 0, 0];
    let mut data = encode_test_prefix(&prefix);
    data.extend_from_slice(&[0u8; 64]);

    let file = test_dir.join("bad_hlen.fcr");
    fs::write(&file, &data).unwrap();

    let passphrase = SecretString::from("test".to_string());
    let result = symmetric_encryption(
        file.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    );
    assert!(result.is_err());
}

#[test]
fn test_symmetric_all_zero_header_body() {
    let test_dir = setup_test_dir("sym_zero_header_body");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&decrypt_dir).unwrap();

    // Valid prefix magic/type/version, plausible header_len, but zero-filled fields
    let header_len: u16 = 600;
    let prefix: [u8; 8] = [
        0xFC,
        0x53,
        3,
        0,
        (header_len >> 8) as u8,
        (header_len & 0xFF) as u8,
        0,
        0,
    ];
    let mut data = encode_test_prefix(&prefix);
    data.extend_from_slice(&[0u8; 600]);

    let file = test_dir.join("zeroed.fcr");
    fs::write(&file, &data).unwrap();

    let passphrase = SecretString::from("test".to_string());
    let result = symmetric_encryption(
        file.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    );
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
    generate_key_pair(&key_pass, keys_dir.to_str().unwrap(), |_| {})?;

    let pub_key = keys_dir.join("public.key");
    let secret_key = keys_dir.join("private.key");
    let empty_pass = SecretString::from("".to_string());

    create_test_file(&input_file, "Hybrid truncation mid-header");

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        pub_key.to_str().unwrap(),
        &empty_pass,
        None,
        |_| {},
    )?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let data = fs::read(&encrypted_path)?;

    // Truncate in the middle of the encrypted envelope field
    let truncated = &data[..20];
    fs::write(&encrypted_path, truncated)?;

    let result = hybrid_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        secret_key.to_str().unwrap(),
        &key_pass,
        None,
        |_| {},
    );
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_hybrid_oversized_header_len() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hyb_oversized_header_len");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let key_pass = SecretString::from("kp".to_string());
    generate_key_pair(&key_pass, keys_dir.to_str().unwrap(), |_| {})?;

    let pub_key = keys_dir.join("public.key");
    let secret_key = keys_dir.join("private.key");
    let empty_pass = SecretString::from("".to_string());

    create_test_file(&input_file, "Hybrid oversized header_len");

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        pub_key.to_str().unwrap(),
        &empty_pass,
        None,
        |_| {},
    )?;

    // Set header_len to 0xFFFF in all 3 replicated copies
    // Encoded prefix: [pad(3)] [copy0(8)] [copy1(8)] [copy2(8)]
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    const HLEN_HI: usize = 4;
    const HLEN_LO: usize = 5;
    for copy_start in [3, 11, 19] {
        data[copy_start + HLEN_HI] = 0xFF;
        data[copy_start + HLEN_LO] = 0xFF;
    }
    fs::write(&encrypted_path, &data)?;

    let result = hybrid_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        secret_key.to_str().unwrap(),
        &key_pass,
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

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;

    // Flip a byte well past the header, in the ciphertext body
    let flip_offset = data.len() - 10;
    data[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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
    generate_key_pair(&key_pass, keys_dir.to_str().unwrap(), |_| {})?;

    let pub_key = keys_dir.join("public.key");
    let secret_key = keys_dir.join("private.key");
    let empty_pass = SecretString::from("".to_string());

    create_test_file(&input_file, "Hybrid AEAD ciphertext integrity test");

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        pub_key.to_str().unwrap(),
        &empty_pass,
        None,
        |_| {},
    )?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;

    // Flip a byte in the ciphertext body (well past the header)
    let flip_offset = data.len() - 10;
    data[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let result = hybrid_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        secret_key.to_str().unwrap(),
        &key_pass,
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

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let data = fs::read(&encrypted_path)?;

    // Truncate after the first ciphertext chunk but before the final chunk
    let half = data.len() / 2;
    fs::write(&encrypted_path, &data[..half])?;

    let result = symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;

    // Append extra bytes after the ciphertext
    data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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
    generate_key_pair(&passphrase, keys_dir.to_str().unwrap(), |_| {})?;

    let pub_key = keys_dir.join("public.key");
    let fp = public_key_fingerprint(pub_key.to_str().unwrap())?;

    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));

    // Deterministic: same key always produces the same fingerprint
    let fp2 = public_key_fingerprint(pub_key.to_str().unwrap())?;
    assert_eq!(fp, fp2);

    // Rejects private key files
    let secret_key = keys_dir.join("private.key");
    assert!(public_key_fingerprint(secret_key.to_str().unwrap()).is_err());

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
    generate_key_pair(&passphrase, keys_a.to_str().unwrap(), |_| {})?;
    generate_key_pair(&passphrase, keys_b.to_str().unwrap(), |_| {})?;

    let fp_a = public_key_fingerprint(keys_a.join("public.key").to_str().unwrap())?;
    let fp_b = public_key_fingerprint(keys_b.join("public.key").to_str().unwrap())?;

    assert_ne!(fp_a, fp_b);

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
    let result = symmetric_encryption(
        symlink_path.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
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
    generate_key_pair(&key_pass, keys_dir.to_str().unwrap(), |_| {})?;

    let result = hybrid_encryption(
        symlink_path.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        keys_dir.join("public.key").to_str().unwrap(),
        &key_pass,
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
    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    let encrypted_path = encrypt_dir.join("bigfile.fcr");
    let mut data = fs::read(&encrypted_path)?;
    // Corrupt a byte in a late chunk (well past the first 64 KB)
    let flip_offset = data.len() - 50;
    data[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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
    symmetric_encryption(
        input_dir.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        None,
        |_| {},
    )?;

    let encrypted_path = encrypt_dir.join("mydir.fcr");
    let mut data = fs::read(&encrypted_path)?;
    let flip_offset = data.len() - 50;
    data[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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

#[ctor::dtor]
fn cleanup() {
    cleanup_test_workspace();
}
