/// Integration tests for ferrocrypt library
use std::fs;
use std::path::{Path, PathBuf};

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    CryptoError, generate_asymmetric_key_pair, hybrid_encryption, symmetric_encryption,
};

const TEST_WORKSPACE: &str = "tests/workspace";

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
    )?;

    assert!(encrypt_result.contains("Encrypted to"));
    assert!(encrypt_dir.join("input.fcr").exists());

    // Decrypt
    let decrypt_result = symmetric_encryption(
        encrypt_dir.join("input.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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
    )?;

    assert!(encrypt_result.contains("Encrypted to"));
    assert!(encrypt_dir.join("test_folder.fcr").exists());

    // Decrypt directory
    let decrypt_result = symmetric_encryption(
        encrypt_dir.join("test_folder.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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
    )?;

    // Try to decrypt with wrong password - should fail
    let result = symmetric_encryption(
        encrypt_dir.join("secret.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &wrong_pass,
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::EncryptionDecryptionError(msg)) => {
            assert!(msg.contains("incorrect"));
        }
        _ => panic!("Expected EncryptionDecryptionError"),
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
    )?;

    assert!(encrypt_dir.join("multi_chunk.fcr").exists());

    symmetric_encryption(
        encrypt_dir.join("multi_chunk.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
    )?;

    let decrypted_content = fs::read_to_string(decrypt_dir.join("multi_chunk.txt"))?;
    assert_eq!(content, decrypted_content);

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
    let keygen_result = generate_asymmetric_key_pair(
        2048, // Smaller key for faster tests
        &key_passphrase,
        keys_dir.to_str().unwrap(),
    )?;

    assert!(keygen_result.contains("Generated key pair"));
    assert!(keys_dir.join("rsa-2048-priv-key.pem").exists());
    assert!(keys_dir.join("rsa-2048-pub-key.pem").exists());

    // Encrypt with public key
    let mut pub_key_path = keys_dir
        .join("rsa-2048-pub-key.pem")
        .to_str()
        .unwrap()
        .to_string();
    let empty_pass = SecretString::from("".to_string());

    let encrypt_result = hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &mut pub_key_path,
        &empty_pass,
    )?;

    assert!(encrypt_result.contains("Encrypted to"));
    assert!(encrypt_dir.join("data.fcr").exists());

    // Decrypt with private key
    let mut priv_key_path = keys_dir
        .join("rsa-2048-priv-key.pem")
        .to_str()
        .unwrap()
        .to_string();

    let decrypt_result = hybrid_encryption(
        encrypt_dir.join("data.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &mut priv_key_path,
        &key_passphrase,
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
    generate_asymmetric_key_pair(2048, &key_passphrase, keys_dir.to_str().unwrap())?;

    // Encrypt directory
    let mut pub_key_path = keys_dir
        .join("rsa-2048-pub-key.pem")
        .to_str()
        .unwrap()
        .to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_dir.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &mut pub_key_path,
        &empty_pass,
    )?;

    assert!(encrypt_dir.join("test_folder.fcr").exists());

    // Decrypt directory
    let mut priv_key_path = keys_dir
        .join("rsa-2048-priv-key.pem")
        .to_str()
        .unwrap()
        .to_string();

    hybrid_encryption(
        encrypt_dir.join("test_folder.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &mut priv_key_path,
        &key_passphrase,
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
    generate_asymmetric_key_pair(2048, &correct_pass, keys_dir.to_str().unwrap())?;

    // Encrypt
    let mut pub_key_path = keys_dir
        .join("rsa-2048-pub-key.pem")
        .to_str()
        .unwrap()
        .to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &mut pub_key_path,
        &empty_pass,
    )?;

    // Try to decrypt with wrong passphrase
    let mut priv_key_path = keys_dir
        .join("rsa-2048-priv-key.pem")
        .to_str()
        .unwrap()
        .to_string();

    let result = hybrid_encryption(
        encrypt_dir.join("data.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &mut priv_key_path,
        &wrong_pass,
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::EncryptionDecryptionError(msg)) => {
            assert!(msg.contains("Incorrect password") || msg.contains("wrong private key"));
        }
        _ => panic!("Expected EncryptionDecryptionError"),
    }

    Ok(())
}

#[test]
fn test_hybrid_key_sizes() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hybrid_key_sizes");

    let passphrase = SecretString::from("test_pass".to_string());

    // Test RSA-2048
    let keys_2048 = test_dir.join("keys_2048");
    fs::create_dir_all(&keys_2048)?;
    generate_asymmetric_key_pair(2048, &passphrase, keys_2048.to_str().unwrap())?;
    assert!(keys_2048.join("rsa-2048-priv-key.pem").exists());
    assert!(keys_2048.join("rsa-2048-pub-key.pem").exists());

    // Test RSA-4096
    let keys_4096 = test_dir.join("keys_4096");
    fs::create_dir_all(&keys_4096)?;
    generate_asymmetric_key_pair(4096, &passphrase, keys_4096.to_str().unwrap())?;
    assert!(keys_4096.join("rsa-4096-priv-key.pem").exists());
    assert!(keys_4096.join("rsa-4096-pub-key.pem").exists());

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
    )?;

    // Decrypt
    symmetric_encryption(
        encrypt_dir.join("empty.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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
    )?;

    // Decrypt
    symmetric_encryption(
        encrypt_dir.join("unicode.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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
    )?;

    symmetric_encryption(
        encrypt_dir
            .join("file-with_special.chars.fcr")
            .to_str()
            .unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
    )?;

    assert!(decrypt_dir.join("file-with_special.chars.txt").exists());

    Ok(())
}

#[test]
fn test_nonexistent_output_dir() {
    let passphrase = SecretString::from("test".to_string());

    let result = symmetric_encryption("Cargo.toml", "/nonexistent/path/output", &passphrase);

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
    )?;

    symmetric_encryption(
        encrypt_dir.join("data.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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
    )?;

    // Decrypt with wrong password
    let result = symmetric_encryption(
        encrypt_dir.join("data.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &wrong_pass,
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::EncryptionDecryptionError(msg)) => {
            assert!(msg.contains("incorrect"));
        }
        _ => panic!("Expected EncryptionDecryptionError"),
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
    )?;

    assert!(encrypt_dir.join("test_folder.fcr").exists());

    symmetric_encryption(
        encrypt_dir.join("test_folder.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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
fn test_symmetric_empty_password() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("empty_password");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let content = "Protected with empty password";
    create_test_file(&input_file, content);

    let empty_pass = SecretString::from("".to_string());

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &empty_pass,
    )?;

    symmetric_encryption(
        encrypt_dir.join("secret.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &empty_pass,
    )?;

    let decrypted = fs::read_to_string(decrypt_dir.join("secret.txt"))?;
    assert_eq!(content, decrypted);

    Ok(())
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
    generate_asymmetric_key_pair(2048, &pass_a, keys_a.to_str().unwrap())?;
    generate_asymmetric_key_pair(2048, &pass_b, keys_b.to_str().unwrap())?;

    // Encrypt with key pair A's public key
    let mut pub_key_a = keys_a
        .join("rsa-2048-pub-key.pem")
        .to_str()
        .unwrap()
        .to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &mut pub_key_a,
        &empty_pass,
    )?;

    // Try to decrypt with key pair B's private key — should fail
    let mut priv_key_b = keys_b
        .join("rsa-2048-priv-key.pem")
        .to_str()
        .unwrap()
        .to_string();

    let result = hybrid_encryption(
        encrypt_dir.join("data.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &mut priv_key_b,
        &pass_b,
    );

    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_hybrid_4096_key_round_trip() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("hybrid_4096_round_trip");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let original_content = "RSA-4096 round-trip test";
    create_test_file(&input_file, original_content);

    let key_passphrase = SecretString::from("rsa4096pass".to_string());

    generate_asymmetric_key_pair(4096, &key_passphrase, keys_dir.to_str().unwrap())?;

    // Encrypt
    let mut pub_key_path = keys_dir
        .join("rsa-4096-pub-key.pem")
        .to_str()
        .unwrap()
        .to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &mut pub_key_path,
        &empty_pass,
    )?;

    assert!(encrypt_dir.join("data.fcr").exists());

    // Decrypt
    let mut priv_key_path = keys_dir
        .join("rsa-4096-priv-key.pem")
        .to_str()
        .unwrap()
        .to_string();

    hybrid_encryption(
        encrypt_dir.join("data.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &mut priv_key_path,
        &key_passphrase,
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
    generate_asymmetric_key_pair(2048, &key_passphrase, keys_dir.to_str().unwrap())?;

    let mut pub_key_path = keys_dir
        .join("rsa-2048-pub-key.pem")
        .to_str()
        .unwrap()
        .to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &mut pub_key_path,
        &empty_pass,
    )?;

    let mut priv_key_path = keys_dir
        .join("rsa-2048-priv-key.pem")
        .to_str()
        .unwrap()
        .to_string();

    hybrid_encryption(
        encrypt_dir.join("data.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &mut priv_key_path,
        &key_passphrase,
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
    generate_asymmetric_key_pair(2048, &key_passphrase, keys_dir.to_str().unwrap())?;

    // Write a tiny file that's too short to be a valid .fcr
    let truncated_file = test_dir.join("truncated.fcr");
    fs::write(&truncated_file, b"short").unwrap();

    let mut priv_key_path = keys_dir
        .join("rsa-2048-priv-key.pem")
        .to_str()
        .unwrap()
        .to_string();

    let result = hybrid_encryption(
        truncated_file.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &mut priv_key_path,
        &key_passphrase,
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
    )?;

    // Tamper with a byte in the encoded salt region (offset 10, within the header)
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    data[10] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
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
    generate_asymmetric_key_pair(2048, &key_passphrase, keys_dir.to_str().unwrap())?;

    let mut pub_key_path = keys_dir
        .join("rsa-2048-pub-key.pem")
        .to_str()
        .unwrap()
        .to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &mut pub_key_path,
        &empty_pass,
    )?;

    // Tamper with the encoded nonce region (after flags + encoded_encrypted_key)
    let encrypted_path = encrypt_dir.join("secret.fcr");
    let mut data = fs::read(&encrypted_path)?;
    // Flip a byte well into the header but before the HMAC tag
    let tamper_offset = data.len() / 3;
    data[tamper_offset] ^= 0xFF;
    fs::write(&encrypted_path, &data)?;

    let mut priv_key_path = keys_dir
        .join("rsa-2048-priv-key.pem")
        .to_str()
        .unwrap()
        .to_string();

    let result = hybrid_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &mut priv_key_path,
        &key_passphrase,
    );

    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_not_a_ferrocrypt_file() {
    let test_dir = setup_test_dir("not_ferrocrypt");
    let fake_file = test_dir.join("photo.fcr");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&decrypt_dir).unwrap();

    // A JPEG header renamed to .fcr
    fs::write(&fake_file, b"\xFF\xD8\xFF\xE0fake jpeg data").unwrap();

    let passphrase = SecretString::from("test".to_string());
    let result = symmetric_encryption(
        fake_file.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::EncryptionDecryptionError(msg)) => {
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
    )?;

    // Patch the major version byte (offset 2) to a future version
    let encrypted_path = encrypt_dir.join("data.fcr");
    let mut data = fs::read(&encrypted_path)?;
    data[2] = 99;
    fs::write(&encrypted_path, &data)?;

    let result = symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::EncryptionDecryptionError(msg)) => {
            assert!(msg.contains("not supported"));
            assert!(msg.contains("upgrade"));
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
    generate_asymmetric_key_pair(2048, &key_passphrase, keys_dir.to_str().unwrap())?;

    // Encrypt as hybrid
    let mut pub_key_path = keys_dir
        .join("rsa-2048-pub-key.pem")
        .to_str()
        .unwrap()
        .to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &mut pub_key_path,
        &empty_pass,
    )?;

    // Try to decrypt a hybrid .fcr file with symmetric_encryption — format type mismatch
    let encrypted_path = encrypt_dir.join("data.fcr");
    let passphrase = SecretString::from("pass".to_string());
    let result = symmetric_encryption(
        encrypted_path.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::EncryptionDecryptionError(msg)) => {
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
    generate_asymmetric_key_pair(2048, &key_passphrase, keys_dir.to_str().unwrap())?;

    let mut pub_key = keys_dir
        .join("rsa-2048-pub-key.pem")
        .to_str()
        .unwrap()
        .to_string();
    let empty_pass = SecretString::from("".to_string());

    hybrid_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &mut pub_key,
        &empty_pass,
    )?;

    let mut priv_key = keys_dir
        .join("rsa-2048-priv-key.pem")
        .to_str()
        .unwrap()
        .to_string();

    hybrid_encryption(
        encrypt_dir.join("empty.fcr").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &mut priv_key,
        &key_passphrase,
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
    )?;

    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir_b.to_str().unwrap(),
        &passphrase,
    )?;

    let file_a = fs::read(encrypt_dir_a.join("data.fcr"))?;
    let file_b = fs::read(encrypt_dir_b.join("data.fcr"))?;

    // Same plaintext + same password must produce different ciphertext (unique salt + nonce)
    assert_ne!(file_a, file_b);

    Ok(())
}

#[ctor::dtor]
fn cleanup() {
    cleanup_test_workspace();
}
