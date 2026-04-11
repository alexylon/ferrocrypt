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

    // Should fail
    assert!(!decrypt_output.status.success());
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

    // Verify keys have expected sizes (secret: 116 bytes + header, public: 32 bytes + header)
    let secret_key_size = fs::metadata(keys_dir.join("private.key")).unwrap().len();
    let pub_key_size = fs::metadata(keys_dir.join("public.key")).unwrap().len();

    assert_eq!(secret_key_size, 124);
    assert_eq!(pub_key_size, 40);
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
    Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "correct_key_pass")
        .output()
        .expect("Failed to execute keygen");

    // Encrypt
    Command::new(&binary)
        .arg("hybrid")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("Failed to execute encrypt");

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

    // Should fail
    assert!(!decrypt_output.status.success());
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

    Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key_pass")
        .output()
        .expect("Failed to execute keygen");

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

    Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "fp_pass")
        .output()
        .expect("Failed to execute keygen");

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
    // On Unix, rpassword reads from /dev/tty directly, so null stdin does
    // not simulate a non-interactive session.
    #[cfg(unix)]
    return;

    #[cfg(not(unix))]
    {
        let test_dir = setup_test_dir("cli_no_passphrase_no_tty");
        let input_file = test_dir.join("data.txt");
        let encrypt_dir = test_dir.join("encrypted");
        fs::create_dir_all(&encrypt_dir).unwrap();
        create_test_file(&input_file, "no tty test");

        let binary = get_binary_path();

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

        assert!(!output.status.success());
    }
}

#[ctor::dtor]
fn cleanup() {
    cleanup_test_workspace();
}
