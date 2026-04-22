/// CLI integration tests for ferrocrypt-cli
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const TEST_WORKSPACE: &str = "tests/cli_workspace";

fn get_binary_path() -> PathBuf {
    let mut path = std::env::current_exe().expect("Failed to get current exe path");

    path.pop();
    path.pop();

    path.push("ferrocrypt");

    if cfg!(windows) {
        path.set_extension("exe");
    }

    path
}

fn setup_test_dir(test_name: &str) -> PathBuf {
    let test_dir = PathBuf::from(TEST_WORKSPACE).join(test_name);
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("Failed to clean test directory");
    }
    fs::create_dir_all(&test_dir).expect("Failed to create test directory");
    test_dir
}

fn create_test_file(path: &Path, content: &str) {
    fs::write(path, content).expect("Failed to write test file");
}

fn cleanup_test_workspace() {
    if Path::new(TEST_WORKSPACE).exists() {
        let _ = fs::remove_dir_all(TEST_WORKSPACE);
    }
}

#[test]
fn test_cli_symmetric_encrypt_decrypt_file() {
    let test_dir = setup_test_dir("cli_symmetric_file");
    let input_file = test_dir.join("test.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    let content = "CLI test content";
    create_test_file(&input_file, content);

    let binary = get_binary_path();

    // Encrypt
    let encrypt_output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "test_password")
        .output()
        .expect("Failed to execute encrypt command");

    assert!(
        encrypt_output.status.success(),
        "Encryption failed: {}",
        String::from_utf8_lossy(&encrypt_output.stderr)
    );

    assert!(encrypt_dir.join("test.fcr").exists());

    // Decrypt
    let decrypt_output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(encrypt_dir.join("test.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "test_password")
        .output()
        .expect("Failed to execute decrypt command");

    assert!(
        decrypt_output.status.success(),
        "Decryption failed: {}",
        String::from_utf8_lossy(&decrypt_output.stderr)
    );

    // Verify content
    let decrypted_content =
        fs::read_to_string(decrypt_dir.join("test.txt")).expect("Failed to read decrypted file");
    assert_eq!(content, decrypted_content);
}

#[test]
fn test_cli_symmetric_multi_chunk_file() {
    let test_dir = setup_test_dir("cli_symmetric_multi_chunk");
    let input_file = test_dir.join("multi_chunk.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    let content = "Multi chunk file content\n".repeat(1000);
    create_test_file(&input_file, &content);

    let binary = get_binary_path();

    let encrypt_output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "multi_chunk_password")
        .output()
        .expect("Failed to execute encrypt command");

    assert!(encrypt_output.status.success());
    assert!(encrypt_dir.join("multi_chunk.fcr").exists());

    let decrypt_output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(encrypt_dir.join("multi_chunk.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "multi_chunk_password")
        .output()
        .expect("Failed to execute decrypt command");

    assert!(decrypt_output.status.success());

    let decrypted_content = fs::read_to_string(decrypt_dir.join("multi_chunk.txt"))
        .expect("Failed to read decrypted file");
    assert_eq!(content, decrypted_content);
}

#[test]
fn test_cli_symmetric_wrong_password() {
    let test_dir = setup_test_dir("cli_symmetric_wrong_pass");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    create_test_file(&input_file, "Secret data");

    let binary = get_binary_path();

    // Encrypt with correct password
    let encrypt_output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "correct_password")
        .output()
        .expect("Failed to execute encrypt command");

    assert!(encrypt_output.status.success());

    // Try to decrypt with wrong password
    let decrypt_output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(encrypt_dir.join("secret.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "wrong_password")
        .output()
        .expect("Failed to execute decrypt command");

    // Should fail with the typed Display message from the library. The CLI
    // formats errors via `Display`, so a regression to `Debug` or a change
    // to the wording would break this assertion.
    assert!(!decrypt_output.status.success());
    let stderr = String::from_utf8_lossy(&decrypt_output.stderr);
    assert!(
        stderr.contains("Decryption failed: wrong passphrase or tampered file"),
        "expected typed header-auth message on stderr, got: {stderr}"
    );
    assert!(
        !stderr.contains("aead::Error"),
        "stderr must not leak internal crate error names, got: {stderr}"
    );
}

#[test]
fn test_cli_keygen() {
    let test_dir = setup_test_dir("cli_keygen");
    let keys_dir = test_dir.join("keys");

    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    // Generate key pair
    let keygen_output = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key_password")
        .output()
        .expect("Failed to execute keygen command");

    assert!(
        keygen_output.status.success(),
        "Keygen failed: {}",
        String::from_utf8_lossy(&keygen_output.stderr)
    );

    // Check that keys were generated
    assert!(keys_dir.join("private.key").exists());
    assert!(keys_dir.join("public.key").exists());

    // Verify keys have expected sizes.
    // private.key v4: 8-byte header + 118-byte fixed body (kdf 12 + salt 32
    // + nonce 24 + ext_len 2 + ciphertext+tag 48) + 0-byte ext_bytes = 126.
    // public.key  v3: 8-byte header + 32-byte raw key = 40.
    let private_key_size = fs::metadata(keys_dir.join("private.key")).unwrap().len();
    let public_key_size = fs::metadata(keys_dir.join("public.key")).unwrap().len();

    assert_eq!(private_key_size, 126);
    assert_eq!(public_key_size, 40);
}

#[test]
fn test_cli_hybrid_encrypt_decrypt_file() {
    let test_dir = setup_test_dir("cli_hybrid_file");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    let content = "Hybrid encryption test data";
    create_test_file(&input_file, content);

    let binary = get_binary_path();

    // Generate keys
    let keygen_output = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key_pass")
        .output()
        .expect("Failed to execute keygen");

    assert!(keygen_output.status.success());

    // Encrypt with public key
    let encrypt_output = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("Failed to execute encrypt");

    assert!(
        encrypt_output.status.success(),
        "Encryption failed: {}",
        String::from_utf8_lossy(&encrypt_output.stderr)
    );

    assert!(encrypt_dir.join("data.fcr").exists());

    // Decrypt with private key
    let decrypt_output = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("private.key"))
        .env("FERROCRYPT_PASSPHRASE", "key_pass")
        .output()
        .expect("Failed to execute decrypt");

    assert!(
        decrypt_output.status.success(),
        "Decryption failed: {}",
        String::from_utf8_lossy(&decrypt_output.stderr)
    );

    // Verify content
    let decrypted_content =
        fs::read_to_string(decrypt_dir.join("data.txt")).expect("Failed to read decrypted file");
    assert_eq!(content, decrypted_content);
}

#[test]
fn test_cli_symmetric_payload_tamper_message() {
    let test_dir = setup_test_dir("cli_symmetric_payload_tamper");
    let input_file = test_dir.join("payload.bin");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    let content = "payload tamper test\n".repeat(20_000);
    create_test_file(&input_file, &content);

    let binary = get_binary_path();

    let encrypt_output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "tamper_password")
        .output()
        .expect("Failed to execute encrypt command");
    assert!(
        encrypt_output.status.success(),
        "Encryption failed: {}",
        String::from_utf8_lossy(&encrypt_output.stderr)
    );

    let encrypted_path = encrypt_dir.join("payload.fcr");
    let mut ciphertext = fs::read(&encrypted_path).expect("Failed to read encrypted file");
    let flip_offset = ciphertext.len() / 2;
    ciphertext[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &ciphertext).expect("Failed to write tampered ciphertext");

    let decrypt_output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(&encrypted_path)
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "tamper_password")
        .output()
        .expect("Failed to execute decrypt command");

    assert!(!decrypt_output.status.success());
    let stderr = String::from_utf8_lossy(&decrypt_output.stderr);
    assert!(
        stderr.contains("Payload authentication failed: data tampered or corrupted"),
        "expected typed payload-auth message on stderr, got: {stderr}"
    );
    assert!(
        !stderr.contains("aead::Error"),
        "stderr must not leak internal crate error names, got: {stderr}"
    );
}

#[test]
fn test_cli_hybrid_wrong_key_passphrase() {
    let test_dir = setup_test_dir("cli_hybrid_wrong_pass");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    create_test_file(&input_file, "Secret hybrid data");

    let binary = get_binary_path();

    // Generate keys with passphrase
    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "correct_key_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    // Encrypt
    let encrypt = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("Failed to execute encrypt");
    assert!(encrypt.status.success());

    // Try to decrypt with wrong passphrase
    let decrypt_output = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("private.key"))
        .env("FERROCRYPT_PASSPHRASE", "wrong_key_pass")
        .output()
        .expect("Failed to execute decrypt");

    assert!(!decrypt_output.status.success());
    let stderr = String::from_utf8_lossy(&decrypt_output.stderr);
    assert!(
        stderr.contains("Private key unlock failed: wrong passphrase or tampered file"),
        "expected typed key-unlock message on stderr, got: {stderr}"
    );
    assert!(
        !stderr.contains("aead::Error"),
        "stderr must not leak internal crate error names, got: {stderr}"
    );
}

#[test]
fn test_cli_directory_encryption() {
    let test_dir = setup_test_dir("cli_directory");
    let input_dir = test_dir.join("input_folder");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&input_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    // Create test directory structure
    create_test_file(&input_dir.join("file1.txt"), "Content 1");
    create_test_file(&input_dir.join("file2.txt"), "Content 2");

    let subdir = input_dir.join("subdir");
    fs::create_dir_all(&subdir).unwrap();
    create_test_file(&subdir.join("file3.txt"), "Content 3");

    let binary = get_binary_path();

    // Encrypt directory
    let encrypt_output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(&input_dir)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "dir_password")
        .output()
        .expect("Failed to execute encrypt command");

    assert!(encrypt_output.status.success());
    assert!(encrypt_dir.join("input_folder.fcr").exists());

    // Decrypt directory
    let decrypt_output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(encrypt_dir.join("input_folder.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "dir_password")
        .output()
        .expect("Failed to execute decrypt command");

    assert!(decrypt_output.status.success());

    // Verify directory structure
    let decrypted_dir = decrypt_dir.join("input_folder");
    assert!(decrypted_dir.exists());
    assert!(decrypted_dir.join("file1.txt").exists());
    assert!(decrypted_dir.join("file2.txt").exists());
    assert!(decrypted_dir.join("subdir/file3.txt").exists());

    // Verify content
    let content1 = fs::read_to_string(decrypted_dir.join("file1.txt")).unwrap();
    assert_eq!("Content 1", content1);
}

#[test]
fn test_cli_symmetric_save_as() {
    let test_dir = setup_test_dir("cli_symmetric_save_as");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    let content = "Save-as test content";
    create_test_file(&input_file, content);

    let custom_output = encrypt_dir.join("my_vault.fcr");
    let binary = get_binary_path();

    let encrypt_output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-s")
        .arg(&custom_output)
        .env("FERROCRYPT_PASSPHRASE", "test_password")
        .output()
        .expect("Failed to execute encrypt command");

    assert!(
        encrypt_output.status.success(),
        "Encryption failed: {}",
        String::from_utf8_lossy(&encrypt_output.stderr)
    );

    assert!(custom_output.exists());
    assert!(!encrypt_dir.join("data.fcr").exists());

    // Decrypt the custom-named file
    let decrypt_output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(&custom_output)
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "test_password")
        .output()
        .expect("Failed to execute decrypt command");

    assert!(
        decrypt_output.status.success(),
        "Decryption failed: {}",
        String::from_utf8_lossy(&decrypt_output.stderr)
    );

    let decrypted_content =
        fs::read_to_string(decrypt_dir.join("data.txt")).expect("Failed to read decrypted file");
    assert_eq!(content, decrypted_content);
}

#[test]
fn test_cli_hybrid_save_as() {
    let test_dir = setup_test_dir("cli_hybrid_save_as");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    let content = "Hybrid save-as test";
    create_test_file(&input_file, content);

    let binary = get_binary_path();

    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let custom_output = encrypt_dir.join("backup.enc");

    let encrypt_output = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .arg("-s")
        .arg(&custom_output)
        .output()
        .expect("Failed to execute encrypt");

    assert!(
        encrypt_output.status.success(),
        "Encryption failed: {}",
        String::from_utf8_lossy(&encrypt_output.stderr)
    );

    assert!(custom_output.exists());
    assert!(!encrypt_dir.join("data.fcr").exists());

    let decrypt_output = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(&custom_output)
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("private.key"))
        .env("FERROCRYPT_PASSPHRASE", "key_pass")
        .output()
        .expect("Failed to execute decrypt");

    assert!(
        decrypt_output.status.success(),
        "Decryption failed: {}",
        String::from_utf8_lossy(&decrypt_output.stderr)
    );

    let decrypted_content =
        fs::read_to_string(decrypt_dir.join("data.txt")).expect("Failed to read decrypted file");
    assert_eq!(content, decrypted_content);
}

#[test]
fn test_cli_symmetric_without_save_as_uses_default() {
    let test_dir = setup_test_dir("cli_symmetric_no_save_as");
    let input_file = test_dir.join("report.txt");
    let encrypt_dir = test_dir.join("encrypted");

    fs::create_dir_all(&encrypt_dir).unwrap();

    create_test_file(&input_file, "default naming test");

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "test_password")
        .output()
        .expect("Failed to execute encrypt command");

    assert!(output.status.success());
    assert!(encrypt_dir.join("report.fcr").exists());
}

#[test]
fn test_cli_fingerprint() {
    let test_dir = setup_test_dir("cli_fingerprint");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "fp_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let fp_output = Command::new(&binary)
        .arg("fingerprint")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("Failed to execute fingerprint command");

    assert!(fp_output.status.success());
    let stdout = String::from_utf8_lossy(&fp_output.stdout);
    let fp_line = stdout
        .lines()
        .find(|l| l.len() == 64 && l.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(
        fp_line.is_some(),
        "expected 64-char hex fingerprint in output: {}",
        stdout
    );
}

#[test]
fn test_cli_keygen_prints_fingerprint() {
    let test_dir = setup_test_dir("cli_keygen_fp");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "keygen_fp_pass")
        .output()
        .expect("Failed to execute keygen");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Public key fingerprint:"),
        "keygen output should include fingerprint, got: {}",
        stdout
    );
}

#[test]
fn test_cli_recipient() {
    let test_dir = setup_test_dir("cli_recipient");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    // Generate keys first
    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "rcpt_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    // Get recipient string
    let output = Command::new(&binary)
        .arg("recipient")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("Failed to execute recipient");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let recipient = stdout.trim();
    assert!(
        recipient.starts_with("fcr1"),
        "recipient should start with fcr1, got: {}",
        recipient
    );
}

#[test]
fn test_cli_keygen_prints_recipient() {
    let test_dir = setup_test_dir("cli_keygen_rcpt");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "keygen_rcpt_pass")
        .output()
        .expect("Failed to execute keygen");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("fcr1"),
        "keygen output should include recipient string, got: {}",
        stdout
    );
}

#[test]
fn test_cli_hybrid_encrypt_with_recipient_string() {
    let test_dir = setup_test_dir("cli_hybrid_recipient");
    let keys_dir = test_dir.join("keys");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    let binary = get_binary_path();

    // Generate keys
    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "rcpt_enc_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    // Get recipient string
    let rcpt_output = Command::new(&binary)
        .arg("recipient")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("Failed to get recipient");
    assert!(rcpt_output.status.success());
    let recipient = String::from_utf8_lossy(&rcpt_output.stdout)
        .trim()
        .to_string();

    // Encrypt with --recipient
    let input_file = test_dir.join("secret.txt");
    create_test_file(&input_file, "recipient encryption test");

    let encrypt = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-r")
        .arg(&recipient)
        .output()
        .expect("Failed to encrypt with recipient");
    assert!(
        encrypt.status.success(),
        "Encrypt with recipient failed: {}",
        String::from_utf8_lossy(&encrypt.stderr)
    );
    assert!(encrypt_dir.join("secret.fcr").exists());

    // Decrypt with private key
    let decrypt = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(encrypt_dir.join("secret.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("private.key"))
        .env("FERROCRYPT_PASSPHRASE", "rcpt_enc_pass")
        .output()
        .expect("Failed to decrypt");
    assert!(
        decrypt.status.success(),
        "Decrypt failed: {}",
        String::from_utf8_lossy(&decrypt.stderr)
    );

    let content = fs::read_to_string(decrypt_dir.join("secret.txt")).unwrap();
    assert_eq!(content, "recipient encryption test");
}

#[test]
fn test_cli_recipient_alias_rc() {
    let test_dir = setup_test_dir("cli_recipient_alias_rc");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "alias_rc_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let output = Command::new(&binary)
        .arg("rc")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("Failed to execute rc alias");

    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .starts_with("fcr1")
    );
}

#[test]
fn test_cli_hybrid_rejects_invalid_recipient_string() {
    let test_dir = setup_test_dir("cli_hybrid_invalid_recipient");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "invalid recipient test");

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-r")
        .arg("fcr1not-valid-bech32!!!")
        .output()
        .expect("Failed to execute hybrid with invalid recipient");

    assert!(!output.status.success());
}

#[test]
fn test_cli_hybrid_rejects_key_and_recipient_together() {
    let test_dir = setup_test_dir("cli_hybrid_key_and_recipient_conflict");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "conflict test");

    let binary = get_binary_path();

    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "conflict_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let rcpt_output = Command::new(&binary)
        .arg("recipient")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("Failed to get recipient");
    assert!(rcpt_output.status.success());
    let recipient = String::from_utf8_lossy(&rcpt_output.stdout)
        .trim()
        .to_string();

    let output = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .arg("-r")
        .arg(&recipient)
        .output()
        .expect("Failed to execute conflicting hybrid command");

    assert!(!output.status.success());
}

#[test]
fn test_cli_hybrid_decrypt_rejects_recipient_flag() {
    let test_dir = setup_test_dir("cli_hybrid_decrypt_recipient_rejected");
    let keys_dir = test_dir.join("keys");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    let input_file = test_dir.join("secret.txt");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "recipient decrypt reject test");

    let binary = get_binary_path();

    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "decrypt_reject_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let encrypt = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("Failed to execute encrypt");
    assert!(encrypt.status.success());

    let rcpt_output = Command::new(&binary)
        .arg("recipient")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("Failed to get recipient");
    assert!(rcpt_output.status.success());
    let recipient = String::from_utf8_lossy(&rcpt_output.stdout)
        .trim()
        .to_string();

    // -k and -r conflict at clap level, so this should fail
    let decrypt = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(encrypt_dir.join("secret.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("private.key"))
        .arg("-r")
        .arg(&recipient)
        .env("FERROCRYPT_PASSPHRASE", "decrypt_reject_pass")
        .output()
        .expect("Failed to execute decrypt with recipient flag");

    assert!(!decrypt.status.success());
}

#[test]
fn test_cli_hybrid_encrypt_requires_key_or_recipient() {
    let test_dir = setup_test_dir("cli_hybrid_requires_key_or_recipient");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "missing key test");

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .output()
        .expect("Failed to execute hybrid without key or recipient");

    assert!(!output.status.success());
}

#[test]
fn test_cli_symmetric_decrypt_rejects_save_as() {
    let test_dir = setup_test_dir("cli_symmetric_decrypt_rejects_save_as");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "save-as reject test");

    let binary = get_binary_path();

    let encrypt = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "save_as_pass")
        .output()
        .expect("Failed to encrypt");
    assert!(encrypt.status.success());

    let decrypt = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-s")
        .arg(decrypt_dir.join("ignored.txt"))
        .env("FERROCRYPT_PASSPHRASE", "save_as_pass")
        .output()
        .expect("Failed to execute decrypt with save-as");

    assert!(!decrypt.status.success());
}

#[test]
fn test_cli_hybrid_decrypt_rejects_save_as() {
    let test_dir = setup_test_dir("cli_hybrid_decrypt_rejects_save_as");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "hybrid save-as reject test");

    let binary = get_binary_path();

    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "hybrid_save_as_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let encrypt = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("Failed to execute encrypt");
    assert!(encrypt.status.success());

    let decrypt = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("private.key"))
        .arg("-s")
        .arg(decrypt_dir.join("ignored.txt"))
        .env("FERROCRYPT_PASSPHRASE", "hybrid_save_as_pass")
        .output()
        .expect("Failed to execute decrypt with save-as");

    assert!(!decrypt.status.success());
}

#[test]
fn test_cli_hybrid_encrypt_rejects_max_kdf_memory() {
    let test_dir = setup_test_dir("cli_hybrid_encrypt_rejects_max_kdf_memory");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "hybrid kdf reject test");

    let binary = get_binary_path();

    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "hybrid_kdf_reject_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let output = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .arg("--max-kdf-memory")
        .arg("64")
        .output()
        .expect("Failed to execute hybrid encrypt with max-kdf-memory");

    assert!(!output.status.success());
}

#[test]
fn test_cli_symmetric_encrypt_rejects_max_kdf_memory() {
    let test_dir = setup_test_dir("cli_symmetric_encrypt_rejects_max_kdf_memory");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "symmetric kdf reject test");

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "sym_reject_pass")
        .arg("--max-kdf-memory")
        .arg("64")
        .output()
        .expect("Failed to execute symmetric encrypt with max-kdf-memory");

    assert!(!output.status.success());
}

#[test]
fn test_cli_rejects_empty_passphrase_env_var() {
    let test_dir = setup_test_dir("cli_empty_passphrase_env");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "empty passphrase test");

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "")
        .output()
        .expect("Failed to execute with empty passphrase");

    assert!(!output.status.success());
}

#[test]
fn test_cli_fails_without_passphrase_and_no_tty() {
    let test_dir = setup_test_dir("cli_no_passphrase_no_tty");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "no tty test");

    let binary = get_binary_path();

    // Null stdin = no terminal. On Unix rpassword would otherwise open
    // /dev/tty directly and block; on Windows it would open CONIN$ and
    // block the same way. The CLI's cross-platform `is_terminal()` guard
    // must catch this up-front and fail with a clear error rather than
    // hang or silently prompt on some hidden console.
    let output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env_remove("FERROCRYPT_PASSPHRASE")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("Failed to execute without passphrase");

    assert!(
        !output.status.success(),
        "binary should exit non-zero without a passphrase and no terminal"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("FERROCRYPT_PASSPHRASE") || stderr.contains("interactive terminal"),
        "expected non-interactive passphrase error, got: {stderr}"
    );
}

#[test]
fn test_cli_hybrid_decrypt_requires_key() {
    let test_dir = setup_test_dir("cli_hybrid_decrypt_requires_key");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "missing key on decrypt test");

    let binary = get_binary_path();

    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "dk_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let encrypt = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("Failed to encrypt");
    assert!(encrypt.status.success());

    let decrypt = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "dk_pass")
        .output()
        .expect("Failed to execute decrypt without key");

    assert!(!decrypt.status.success());
}

#[test]
fn test_cli_hybrid_nonexistent_key_file() {
    let test_dir = setup_test_dir("cli_hybrid_nonexistent_key");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "nonexistent key test");

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(test_dir.join("nonexistent.key"))
        .output()
        .expect("Failed to execute with nonexistent key");

    assert!(!output.status.success());
}

#[test]
fn test_cli_symmetric_nonexistent_input() {
    let test_dir = setup_test_dir("cli_sym_nonexistent_input");

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("symmetric")
        .arg("-i")
        .arg(test_dir.join("nonexistent.txt"))
        .arg("-o")
        .arg(&test_dir)
        .env("FERROCRYPT_PASSPHRASE", "noinput_pass")
        .output()
        .expect("Failed to execute with nonexistent input");

    assert!(!output.status.success());
}

#[test]
fn test_cli_hybrid_nonexistent_input() {
    let test_dir = setup_test_dir("cli_hyb_nonexistent_input");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "noinput_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let output = Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(test_dir.join("nonexistent.txt"))
        .arg("-o")
        .arg(&test_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("Failed to execute with nonexistent input");

    assert!(!output.status.success());
}

#[test]
fn test_cli_fingerprint_nonexistent_file() {
    let test_dir = setup_test_dir("cli_fp_nonexistent");

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("fingerprint")
        .arg(test_dir.join("nonexistent.key"))
        .output()
        .expect("Failed to execute fingerprint with nonexistent file");

    assert!(!output.status.success());
}

#[test]
fn test_cli_recipient_nonexistent_file() {
    let test_dir = setup_test_dir("cli_rcpt_nonexistent");

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("recipient")
        .arg(test_dir.join("nonexistent.key"))
        .output()
        .expect("Failed to execute recipient with nonexistent file");

    assert!(!output.status.success());
}

#[test]
fn test_cli_symmetric_alias_sym() {
    let test_dir = setup_test_dir("cli_alias_sym");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "alias test");

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("sym")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "alias_pass")
        .output()
        .expect("Failed to execute sym alias");

    assert!(output.status.success());
    assert!(encrypt_dir.join("data.fcr").exists());
}

#[test]
fn test_cli_keygen_alias_gen() {
    let test_dir = setup_test_dir("cli_alias_gen");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("gen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "alias_gen_pass")
        .output()
        .expect("Failed to execute gen alias");

    assert!(output.status.success());
    assert!(keys_dir.join("private.key").exists());
    assert!(keys_dir.join("public.key").exists());
}

#[test]
fn test_cli_fingerprint_alias_fp() {
    let test_dir = setup_test_dir("cli_alias_fp");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "alias_fp_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let output = Command::new(&binary)
        .arg("fp")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("Failed to execute fp alias");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().len() == 64,
        "expected 64-char fingerprint, got: {}",
        stdout.trim()
    );
}

// ─── Conflict detection tests ──────────────────────────────────────────────

#[test]
fn test_symmetric_encrypt_conflict_detected() {
    let test_dir = setup_test_dir("sym_encrypt_conflict");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "payload");

    let binary = get_binary_path();

    // First encrypt succeeds
    let first = Command::new(&binary)
        .arg("sym")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("first encrypt");
    assert!(first.status.success(), "first encrypt should succeed");
    assert!(encrypt_dir.join("data.fcr").exists());

    // Second encrypt hits the conflict (non-interactive → error)
    let second = Command::new(&binary)
        .arg("sym")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("second encrypt");
    assert!(
        !second.status.success(),
        "second encrypt should fail on conflict"
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("Already exists"),
        "expected conflict message, got: {stderr}"
    );
}

#[test]
fn test_symmetric_encrypt_conflict_with_save_as() {
    let test_dir = setup_test_dir("sym_save_as_conflict");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let custom_out = encrypt_dir.join("custom.fcr");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "payload");

    let binary = get_binary_path();

    // Create the target file so the conflict fires
    create_test_file(&custom_out, "placeholder");

    let output = Command::new(&binary)
        .arg("sym")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-s")
        .arg(&custom_out)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt with save_as conflict");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Already exists"),
        "expected conflict for save_as path, got: {stderr}"
    );
}

#[test]
fn test_hybrid_encrypt_conflict_detected() {
    let test_dir = setup_test_dir("hyb_encrypt_conflict");
    let input_file = test_dir.join("secret.txt");
    let keys_dir = test_dir.join("keys");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "secret data");

    let binary = get_binary_path();

    // Generate key pair
    let kg = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "keypass")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    // First encrypt
    let first = Command::new(&binary)
        .arg("hyb")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("first hybrid encrypt");
    assert!(
        first.status.success(),
        "first encrypt failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    // Second encrypt hits conflict
    let second = Command::new(&binary)
        .arg("hyb")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("second hybrid encrypt");
    assert!(
        !second.status.success(),
        "second encrypt should fail on conflict"
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("Already exists"),
        "expected conflict message, got: {stderr}"
    );
}

#[test]
fn test_keygen_conflict_both_keys() {
    let test_dir = setup_test_dir("keygen_conflict_both");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    // First keygen succeeds
    let first = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "keypass")
        .output()
        .expect("first keygen");
    assert!(first.status.success());

    // Second keygen hits conflict (non-interactive → error)
    let second = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "keypass")
        .output()
        .expect("second keygen");
    assert!(
        !second.status.success(),
        "second keygen should fail on conflict"
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("Key pair already exists"),
        "expected key pair conflict, got: {stderr}"
    );
}

#[test]
fn test_keygen_conflict_private_only() {
    let test_dir = setup_test_dir("keygen_conflict_priv");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    // Place only private.key
    create_test_file(&keys_dir.join("private.key"), "dummy");

    let binary = get_binary_path();
    let output = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "keypass")
        .output()
        .expect("keygen with private conflict");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Private key already exists"),
        "expected private key conflict, got: {stderr}"
    );
}

#[test]
fn test_keygen_conflict_public_only() {
    let test_dir = setup_test_dir("keygen_conflict_pub");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    // Place only public.key
    create_test_file(&keys_dir.join("public.key"), "dummy");

    let binary = get_binary_path();
    let output = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "keypass")
        .output()
        .expect("keygen with public conflict");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Public key already exists"),
        "expected public key conflict, got: {stderr}"
    );
}

#[test]
fn test_decrypt_does_not_trigger_cli_conflict_check() {
    let test_dir = setup_test_dir("no_cli_conflict_decrypt");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "payload");

    let binary = get_binary_path();

    // Encrypt
    let enc = Command::new(&binary)
        .arg("sym")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    // Decrypt once to populate the output dir
    let dec1 = Command::new(&binary)
        .arg("sym")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("first decrypt");
    assert!(dec1.status.success());

    // Decrypt again — the library may reject overwrite, but the CLI conflict
    // check (which uses "Already exists: ..." prefix) must NOT fire since
    // conflict checks only apply to encryption, matching desktop behavior.
    let dec2 = Command::new(&binary)
        .arg("sym")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("second decrypt");
    let stderr = String::from_utf8_lossy(&dec2.stderr);
    assert!(
        !stderr.contains("Already exists:"),
        "decrypt must not trigger CLI conflict check, got: {stderr}"
    );
}

// ─── Optional --output-path tests ──────────────────────────────────────────

#[test]
fn test_symmetric_encrypt_save_as_without_output_path() {
    let test_dir = setup_test_dir("sym_save_as_no_out");
    let input_file = test_dir.join("data.txt");
    let target = test_dir.join("result.fcr");
    create_test_file(&input_file, "payload");

    let binary = get_binary_path();

    // Encrypt with --save-as only, no -o
    let output = Command::new(&binary)
        .arg("sym")
        .arg("-i")
        .arg(&input_file)
        .arg("-s")
        .arg(&target)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt with save_as only");
    assert!(
        output.status.success(),
        "encrypt without -o should succeed when --save-as is given: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(target.exists());
}

#[test]
fn test_hybrid_encrypt_save_as_without_output_path() {
    let test_dir = setup_test_dir("hyb_save_as_no_out");
    let input_file = test_dir.join("data.txt");
    let keys_dir = test_dir.join("keys");
    let target = test_dir.join("result.fcr");
    fs::create_dir_all(&keys_dir).unwrap();
    create_test_file(&input_file, "payload");

    let binary = get_binary_path();

    let kg = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "kp")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    // Encrypt with --save-as only, no -o
    let output = Command::new(&binary)
        .arg("hyb")
        .arg("-i")
        .arg(&input_file)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .arg("-s")
        .arg(&target)
        .output()
        .expect("encrypt with save_as only");
    assert!(
        output.status.success(),
        "encrypt without -o should succeed when --save-as is given: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(target.exists());
}

#[test]
fn test_symmetric_encrypt_without_output_path_or_save_as_fails() {
    let test_dir = setup_test_dir("sym_no_out_no_save");
    let input_file = test_dir.join("data.txt");
    create_test_file(&input_file, "payload");

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("sym")
        .arg("-i")
        .arg(&input_file)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt without -o or -s");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--output-path is required"),
        "expected --output-path error, got: {stderr}"
    );
}

#[test]
fn test_symmetric_decrypt_without_output_path_fails() {
    let test_dir = setup_test_dir("sym_decrypt_no_out");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "payload");

    let binary = get_binary_path();

    // Encrypt first
    let enc = Command::new(&binary)
        .arg("sym")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    // Decrypt without -o
    let dec = Command::new(&binary)
        .arg("sym")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("decrypt without -o");
    assert!(!dec.status.success());
    let stderr = String::from_utf8_lossy(&dec.stderr);
    assert!(
        stderr.contains("--output-path is required"),
        "expected --output-path error, got: {stderr}"
    );
}

// ─── Help and version output ───────────────────────────────────────────────

#[test]
fn test_cli_help_flag_lists_subcommands() {
    let output = Command::new(get_binary_path())
        .arg("--help")
        .output()
        .expect("--help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage:"),
        "expected Usage section, got:\n{stdout}"
    );
    for sub in ["symmetric", "hybrid", "keygen", "fingerprint", "recipient"] {
        assert!(
            stdout.contains(sub),
            "missing subcommand {sub} in:\n{stdout}"
        );
    }
}

#[test]
fn test_cli_help_shows_format_primitives() {
    let output = Command::new(get_binary_path())
        .arg("--help")
        .output()
        .expect("--help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for token in ["Argon2id", "XChaCha20-Poly1305", "X25519"] {
        assert!(
            stdout.contains(token),
            "long_about should mention {token}, got:\n{stdout}"
        );
    }
}

#[test]
fn test_cli_version_flag_matches_cargo_pkg_version() {
    let output = Command::new(get_binary_path())
        .arg("--version")
        .output()
        .expect("--version");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = env!("CARGO_PKG_VERSION");
    assert!(
        stdout.contains(expected),
        "expected version {expected} in output, got:\n{stdout}"
    );
}

#[test]
fn test_cli_subcommand_help_symmetric() {
    let output = Command::new(get_binary_path())
        .args(["symmetric", "--help"])
        .output()
        .expect("sym --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for token in [
        "--input-path",
        "--output-path",
        "--save-as",
        "--max-kdf-memory",
    ] {
        assert!(stdout.contains(token), "missing {token} in:\n{stdout}");
    }
}

#[test]
fn test_cli_subcommand_help_hybrid() {
    let output = Command::new(get_binary_path())
        .args(["hybrid", "--help"])
        .output()
        .expect("hyb --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for token in [
        "--input-path",
        "--output-path",
        "--key",
        "--recipient",
        "--save-as",
        "--max-kdf-memory",
    ] {
        assert!(stdout.contains(token), "missing {token} in:\n{stdout}");
    }
}

#[test]
fn test_cli_subcommand_help_keygen() {
    let output = Command::new(get_binary_path())
        .args(["keygen", "--help"])
        .output()
        .expect("gen --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--output-path"));
}

#[test]
fn test_cli_subcommand_help_fingerprint() {
    let output = Command::new(get_binary_path())
        .args(["fingerprint", "--help"])
        .output()
        .expect("fp --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.to_lowercase().contains("public key"));
}

#[test]
fn test_cli_subcommand_help_recipient() {
    let output = Command::new(get_binary_path())
        .args(["recipient", "--help"])
        .output()
        .expect("rc --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.to_lowercase().contains("recipient"));
}

// ─── Exit codes ────────────────────────────────────────────────────────────

#[test]
fn test_cli_wrong_passphrase_returns_nonzero() {
    let test_dir = setup_test_dir("cli_exit_wrong_password");
    let input_file = test_dir.join("test.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "content");

    let binary = get_binary_path();
    let enc = Command::new(&binary)
        .args(["sym", "-i"])
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "right")
        .output()
        .expect("encrypt");
    assert_eq!(enc.status.code(), Some(0));

    let dec = Command::new(&binary)
        .args(["sym", "-i"])
        .arg(encrypt_dir.join("test.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "wrong")
        .output()
        .expect("decrypt");
    assert_ne!(dec.status.code(), Some(0));
}

#[test]
fn test_cli_unknown_flag_returns_nonzero() {
    let output = Command::new(get_binary_path())
        .args(["sym", "--not-a-real-flag"])
        .output()
        .expect("bad args");
    assert_ne!(output.status.code(), Some(0));
}

#[test]
fn test_cli_missing_required_input_returns_nonzero() {
    let output = Command::new(get_binary_path())
        .arg("sym")
        .output()
        .expect("missing args");
    assert_ne!(output.status.code(), Some(0));
}

// ─── Empty inputs ──────────────────────────────────────────────────────────

#[test]
fn test_cli_symmetric_empty_file_roundtrip() {
    let test_dir = setup_test_dir("cli_empty_file_sym");
    let input_file = test_dir.join("empty.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "");
    assert_eq!(fs::metadata(&input_file).unwrap().len(), 0);

    let binary = get_binary_path();
    let enc = Command::new(&binary)
        .args(["sym", "-i"])
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt");
    assert!(
        enc.status.success(),
        "encrypt failed: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let dec = Command::new(&binary)
        .args(["sym", "-i"])
        .arg(encrypt_dir.join("empty.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("decrypt");
    assert!(
        dec.status.success(),
        "decrypt failed: {}",
        String::from_utf8_lossy(&dec.stderr)
    );

    let decrypted = decrypt_dir.join("empty.txt");
    assert!(decrypted.exists());
    assert_eq!(fs::metadata(&decrypted).unwrap().len(), 0);
}

#[test]
fn test_cli_hybrid_empty_file_roundtrip() {
    let test_dir = setup_test_dir("cli_empty_file_hyb");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("empty.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "");

    let binary = get_binary_path();
    let kg = Command::new(&binary)
        .args(["gen", "-o"])
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let enc = Command::new(&binary)
        .args(["hyb", "-i"])
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("encrypt");
    assert!(
        enc.status.success(),
        "encrypt failed: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let dec = Command::new(&binary)
        .args(["hyb", "-i"])
        .arg(encrypt_dir.join("empty.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("private.key"))
        .env("FERROCRYPT_PASSPHRASE", "key")
        .output()
        .expect("decrypt");
    assert!(
        dec.status.success(),
        "decrypt failed: {}",
        String::from_utf8_lossy(&dec.stderr)
    );

    let decrypted = decrypt_dir.join("empty.txt");
    assert!(decrypted.exists());
    assert_eq!(fs::metadata(&decrypted).unwrap().len(), 0);
}

#[test]
fn test_cli_symmetric_empty_directory_roundtrip() {
    let test_dir = setup_test_dir("cli_empty_dir");
    let input_dir = test_dir.join("emptydir");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&input_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    assert!(input_dir.read_dir().unwrap().next().is_none());

    let binary = get_binary_path();
    let enc = Command::new(&binary)
        .args(["sym", "-i"])
        .arg(&input_dir)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt");
    assert!(
        enc.status.success(),
        "encrypt failed: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let dec = Command::new(&binary)
        .args(["sym", "-i"])
        .arg(encrypt_dir.join("emptydir.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("decrypt");
    assert!(
        dec.status.success(),
        "decrypt failed: {}",
        String::from_utf8_lossy(&dec.stderr)
    );

    let decrypted_dir = decrypt_dir.join("emptydir");
    assert!(decrypted_dir.exists() && decrypted_dir.is_dir());
    assert!(decrypted_dir.read_dir().unwrap().next().is_none());
}

// ─── Malformed key files at CLI layer ──────────────────────────────────────

#[test]
fn test_cli_hybrid_encrypt_with_malformed_public_key_fails() {
    let test_dir = setup_test_dir("cli_hybrid_malformed_public");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "content");
    fs::write(keys_dir.join("public.key"), b"not a real key file").unwrap();

    let output = Command::new(get_binary_path())
        .args(["hyb", "-i"])
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("encrypt");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("aead::Error"),
        "internal error name leaked: {stderr}"
    );
}

#[test]
fn test_cli_hybrid_decrypt_with_malformed_private_key_fails() {
    let test_dir = setup_test_dir("cli_hybrid_malformed_private");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "content");

    let binary = get_binary_path();
    let kg = Command::new(&binary)
        .args(["gen", "-o"])
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key")
        .output()
        .expect("keygen");
    assert!(kg.status.success());
    let enc = Command::new(&binary)
        .args(["hyb", "-i"])
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    fs::write(keys_dir.join("private.key"), b"not a real private key").unwrap();

    let dec = Command::new(&binary)
        .args(["hyb", "-i"])
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("private.key"))
        .env("FERROCRYPT_PASSPHRASE", "key")
        .output()
        .expect("decrypt");
    assert!(!dec.status.success());
    let stderr = String::from_utf8_lossy(&dec.stderr);
    assert!(
        !stderr.contains("aead::Error"),
        "internal error name leaked: {stderr}"
    );
}

#[test]
fn test_cli_fingerprint_on_malformed_key_fails() {
    let test_dir = setup_test_dir("cli_fp_malformed");
    let bad_key = test_dir.join("bad.key");
    fs::write(&bad_key, b"garbage").unwrap();

    let output = Command::new(get_binary_path())
        .arg("fp")
        .arg(&bad_key)
        .output()
        .expect("fp");
    assert!(!output.status.success());
}

#[test]
fn test_cli_recipient_on_malformed_key_fails() {
    let test_dir = setup_test_dir("cli_rc_malformed");
    let bad_key = test_dir.join("bad.key");
    fs::write(&bad_key, b"garbage").unwrap();

    let output = Command::new(get_binary_path())
        .arg("rc")
        .arg(&bad_key)
        .output()
        .expect("rc");
    assert!(!output.status.success());
}

#[test]
fn test_cli_fingerprint_on_private_key_fails() {
    let test_dir = setup_test_dir("cli_fp_on_private");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();
    let kg = Command::new(&binary)
        .args(["gen", "-o"])
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let output = Command::new(&binary)
        .arg("fp")
        .arg(keys_dir.join("private.key"))
        .output()
        .expect("fp");
    assert!(!output.status.success());
}

#[test]
fn test_cli_recipient_on_private_key_fails() {
    let test_dir = setup_test_dir("cli_rc_on_private");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();
    let kg = Command::new(&binary)
        .args(["gen", "-o"])
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let output = Command::new(&binary)
        .arg("rc")
        .arg(keys_dir.join("private.key"))
        .output()
        .expect("rc");
    assert!(!output.status.success());
}

#[test]
fn test_cli_hybrid_decrypt_rejects_public_key_as_private() {
    let test_dir = setup_test_dir("cli_hybrid_wrong_key_type");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "content");

    let binary = get_binary_path();
    let kg = Command::new(&binary)
        .args(["gen", "-o"])
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key")
        .output()
        .expect("keygen");
    assert!(kg.status.success());
    let enc = Command::new(&binary)
        .args(["hyb", "-i"])
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    let dec = Command::new(&binary)
        .args(["hyb", "-i"])
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .env("FERROCRYPT_PASSPHRASE", "key")
        .output()
        .expect("decrypt");
    assert!(!dec.status.success());
}

#[ctor::dtor]
fn cleanup() {
    cleanup_test_workspace();
}
