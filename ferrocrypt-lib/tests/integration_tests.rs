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
        false,
    )?;

    assert!(encrypt_result.contains("Encrypted to"));
    assert!(encrypt_dir.join("input.fcs").exists());

    // Decrypt
    let decrypt_result = symmetric_encryption(
        encrypt_dir.join("input.fcs").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        false,
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
        false,
    )?;

    assert!(encrypt_result.contains("Encrypted to"));
    assert!(encrypt_dir.join("test_folder.fcs").exists());

    // Decrypt directory
    let decrypt_result = symmetric_encryption(
        encrypt_dir.join("test_folder.fcs").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        false,
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
        false,
    )?;

    // Try to decrypt with wrong password - should fail
    let result = symmetric_encryption(
        encrypt_dir.join("secret.fcs").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &wrong_pass,
        false,
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
fn test_symmetric_large_file_mode() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("symmetric_large_file");
    let input_file = test_dir.join("large.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    // Create a larger file (10KB of repeated content)
    let content = "Large file content. ".repeat(500);
    create_test_file(&input_file, &content);

    let passphrase = SecretString::from("large_file_password".to_string());

    // Encrypt with large flag
    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        true, // large mode
    )?;

    assert!(encrypt_dir.join("large.fcs").exists());

    // Decrypt
    symmetric_encryption(
        encrypt_dir.join("large.fcs").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        false,
    )?;

    // Verify content
    let decrypted_content = fs::read_to_string(decrypt_dir.join("large.txt"))?;
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
    assert!(encrypt_dir.join("data.fch").exists());

    // Decrypt with private key
    let mut priv_key_path = keys_dir
        .join("rsa-2048-priv-key.pem")
        .to_str()
        .unwrap()
        .to_string();

    let decrypt_result = hybrid_encryption(
        encrypt_dir.join("data.fch").to_str().unwrap(),
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

    assert!(encrypt_dir.join("test_folder.fch").exists());

    // Decrypt directory
    let mut priv_key_path = keys_dir
        .join("rsa-2048-priv-key.pem")
        .to_str()
        .unwrap()
        .to_string();

    hybrid_encryption(
        encrypt_dir.join("test_folder.fch").to_str().unwrap(),
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
        encrypt_dir.join("data.fch").to_str().unwrap(),
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
        false,
    )?;

    // Decrypt
    symmetric_encryption(
        encrypt_dir.join("empty.fcs").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        false,
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
        false,
    )?;

    // Decrypt
    symmetric_encryption(
        encrypt_dir.join("unicode.fcs").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        false,
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
        false,
    )?;

    symmetric_encryption(
        encrypt_dir
            .join("file-with_special.chars.fcs")
            .to_str()
            .unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        false,
    )?;

    assert!(decrypt_dir.join("file-with_special.chars.txt").exists());

    Ok(())
}

#[test]
fn test_nonexistent_output_dir() {
    let passphrase = SecretString::from("test".to_string());

    let result = symmetric_encryption("Cargo.toml", "/nonexistent/path/output", &passphrase, false);

    assert!(result.is_err());
}

#[test]
fn test_decrypt_nonexistent_fcs_file() {
    let test_dir = setup_test_dir("decrypt_nonexistent");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&decrypt_dir).unwrap();

    let passphrase = SecretString::from("test".to_string());

    let result = symmetric_encryption(
        "/nonexistent/missing.fcs",
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        false,
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
        false,
    )?;

    symmetric_encryption(
        encrypt_dir.join("data.fcs").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        false,
    )?;

    let decrypted = fs::read(decrypt_dir.join("data.bin"))?;
    assert_eq!(binary_content, decrypted);

    Ok(())
}

#[test]
fn test_symmetric_large_mode_wrong_password() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("large_wrong_password");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let content = "Large mode wrong password test. ".repeat(100);
    create_test_file(&input_file, &content);

    let correct_pass = SecretString::from("correct".to_string());
    let wrong_pass = SecretString::from("wrong".to_string());

    // Encrypt in large mode
    symmetric_encryption(
        input_file.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &correct_pass,
        true,
    )?;

    // Decrypt with wrong password
    let result = symmetric_encryption(
        encrypt_dir.join("data.fcs").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &wrong_pass,
        false,
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
fn test_symmetric_large_mode_directory() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("large_directory");
    let input_dir = create_test_directory(&test_dir);
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let passphrase = SecretString::from("large_dir_pass".to_string());

    symmetric_encryption(
        input_dir.to_str().unwrap(),
        encrypt_dir.to_str().unwrap(),
        &passphrase,
        true,
    )?;

    assert!(encrypt_dir.join("test_folder.fcs").exists());

    symmetric_encryption(
        encrypt_dir.join("test_folder.fcs").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        false,
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
        false,
    )?;

    symmetric_encryption(
        encrypt_dir.join("secret.fcs").to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &empty_pass,
        false,
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
        encrypt_dir.join("data.fch").to_str().unwrap(),
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

    assert!(encrypt_dir.join("data.fch").exists());

    // Decrypt
    let mut priv_key_path = keys_dir
        .join("rsa-4096-priv-key.pem")
        .to_str()
        .unwrap()
        .to_string();

    hybrid_encryption(
        encrypt_dir.join("data.fch").to_str().unwrap(),
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
        encrypt_dir.join("data.fch").to_str().unwrap(),
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
        false,
    );

    assert!(result.is_err());
    match result {
        Err(CryptoError::InputPath(_)) => {}
        other => panic!("Expected InputPath error, got {:?}", other),
    }
}

#[test]
fn test_truncated_fcs_file() {
    let test_dir = setup_test_dir("truncated_fcs");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&decrypt_dir).unwrap();

    // Write a tiny file that's too short to be a valid .fcs
    let truncated_file = test_dir.join("truncated.fcs");
    fs::write(&truncated_file, b"short").unwrap();

    let passphrase = SecretString::from("test".to_string());

    let result = symmetric_encryption(
        truncated_file.to_str().unwrap(),
        decrypt_dir.to_str().unwrap(),
        &passphrase,
        false,
    );

    assert!(result.is_err());
}

#[test]
fn test_truncated_fch_file() -> Result<(), CryptoError> {
    let test_dir = setup_test_dir("truncated_fch");
    let keys_dir = test_dir.join("keys");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let key_passphrase = SecretString::from("pass".to_string());
    generate_asymmetric_key_pair(2048, &key_passphrase, keys_dir.to_str().unwrap())?;

    // Write a tiny file that's too short to be a valid .fch
    let truncated_file = test_dir.join("truncated.fch");
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

#[ctor::dtor]
fn cleanup() {
    cleanup_test_workspace();
}
