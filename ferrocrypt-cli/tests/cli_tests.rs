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
fn test_cli_passphrase_encrypt_decrypt_file() {
    let test_dir = setup_test_dir("cli_passphrase_file");
    let input_file = test_dir.join("test.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    let content = "CLI test content";
    create_test_file(&input_file, content);

    let binary = get_binary_path();

    let encrypt_output = Command::new(&binary)
        .arg("encrypt")
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

    let decrypt_output = Command::new(&binary)
        .arg("decrypt")
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

    let decrypted_content =
        fs::read_to_string(decrypt_dir.join("test.txt")).expect("Failed to read decrypted file");
    assert_eq!(content, decrypted_content);
}

#[test]
fn test_cli_passphrase_multi_chunk_file() {
    let test_dir = setup_test_dir("cli_passphrase_multi_chunk");
    let input_file = test_dir.join("multi_chunk.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    let content = "Multi chunk file content\n".repeat(1000);
    create_test_file(&input_file, &content);

    let binary = get_binary_path();

    let encrypt_output = Command::new(&binary)
        .arg("encrypt")
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
        .arg("decrypt")
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
fn test_cli_passphrase_wrong_password() {
    let test_dir = setup_test_dir("cli_passphrase_wrong_pass");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    create_test_file(&input_file, "Secret data");

    let binary = get_binary_path();

    let encrypt_output = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "correct_password")
        .output()
        .expect("Failed to execute encrypt command");

    assert!(encrypt_output.status.success());

    let decrypt_output = Command::new(&binary)
        .arg("decrypt")
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
        stderr.contains("recipient `argon2id` unwrap failed"),
        "expected typed argon2id-recipient unwrap-failure message on stderr, got: {stderr}"
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

    assert!(keys_dir.join("private.key").exists());
    assert!(keys_dir.join("public.key").exists());

    // Pin the on-disk byte counts so a silent change to either layout
    // (private.key cleartext header per `FORMAT.md` §8, public.key
    // Bech32 grammar per §7) shows up as a test failure alongside the
    // spec update. private.key with `ext_len = 0`:
    // header_fixed(90) + type_name("x25519" = 6) + public(32)
    //   + ext(0) + wrapped_secret(32 + 16 tag) = 176.
    let private_key_size = fs::metadata(keys_dir.join("private.key")).unwrap().len();
    let public_key_size = fs::metadata(keys_dir.join("public.key")).unwrap().len();
    assert_eq!(private_key_size, 176, "v1 X25519 private.key size");
    assert_eq!(public_key_size, 107, "v1 X25519 public.key text size");
}

#[test]
fn test_cli_recipient_encrypt_decrypt_file() {
    let test_dir = setup_test_dir("cli_recipient_file");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    let content = "Public-key encryption test data";
    create_test_file(&input_file, content);

    let binary = get_binary_path();

    let keygen_output = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key_pass")
        .output()
        .expect("Failed to execute keygen");

    assert!(keygen_output.status.success());

    let encrypt_output = Command::new(&binary)
        .arg("encrypt")
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

    let decrypt_output = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-K")
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
fn test_cli_passphrase_payload_tamper_message() {
    let test_dir = setup_test_dir("cli_passphrase_payload_tamper");
    let input_file = test_dir.join("payload.bin");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    let content = "payload tamper test\n".repeat(20_000);
    create_test_file(&input_file, &content);

    let binary = get_binary_path();

    let encrypt_output = Command::new(&binary)
        .arg("encrypt")
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
        .arg("decrypt")
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
fn test_cli_recipient_wrong_key_passphrase() {
    let test_dir = setup_test_dir("cli_recipient_wrong_pass");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    create_test_file(&input_file, "Secret recipient data");

    let binary = get_binary_path();

    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "correct_key_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let encrypt = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("Failed to execute encrypt");
    assert!(encrypt.status.success());

    let decrypt_output = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-K")
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

    create_test_file(&input_dir.join("file1.txt"), "Content 1");
    create_test_file(&input_dir.join("file2.txt"), "Content 2");

    let subdir = input_dir.join("subdir");
    fs::create_dir_all(&subdir).unwrap();
    create_test_file(&subdir.join("file3.txt"), "Content 3");

    let binary = get_binary_path();

    let encrypt_output = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_dir)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "dir_password")
        .output()
        .expect("Failed to execute encrypt command");

    assert!(encrypt_output.status.success());
    assert!(encrypt_dir.join("input_folder.fcr").exists());

    let decrypt_output = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("input_folder.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "dir_password")
        .output()
        .expect("Failed to execute decrypt command");

    assert!(decrypt_output.status.success());

    let decrypted_dir = decrypt_dir.join("input_folder");
    assert!(decrypted_dir.exists());
    assert!(decrypted_dir.join("file1.txt").exists());
    assert!(decrypted_dir.join("file2.txt").exists());
    assert!(decrypted_dir.join("subdir/file3.txt").exists());

    let content1 = fs::read_to_string(decrypted_dir.join("file1.txt")).unwrap();
    assert_eq!("Content 1", content1);
}

#[test]
fn test_cli_passphrase_save_as() {
    let test_dir = setup_test_dir("cli_passphrase_save_as");
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
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
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

    let decrypt_output = Command::new(&binary)
        .arg("decrypt")
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
fn test_cli_recipient_save_as() {
    let test_dir = setup_test_dir("cli_recipient_save_as");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    let content = "Recipient save-as test";
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
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
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

    let decrypt_output = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(&custom_output)
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-K")
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
fn test_cli_passphrase_without_save_as_uses_default() {
    let test_dir = setup_test_dir("cli_passphrase_no_save_as");
    let input_file = test_dir.join("report.txt");
    let encrypt_dir = test_dir.join("encrypted");

    fs::create_dir_all(&encrypt_dir).unwrap();

    create_test_file(&input_file, "default naming test");

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("encrypt")
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

/// Reads the canonical `fcr1...` recipient string out of a `public.key` file
/// the way the CLI's `recipient` subcommand used to. The subcommand was
/// removed because `public.key` is already a UTF-8 single-line text file.
fn read_recipient_from_public_key(public_key: &Path) -> String {
    fs::read_to_string(public_key)
        .expect("read public.key")
        .trim()
        .to_string()
}

#[test]
fn test_cli_encrypt_with_recipient_string() {
    let test_dir = setup_test_dir("cli_encrypt_recipient_string");
    let keys_dir = test_dir.join("keys");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    let binary = get_binary_path();

    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "rcpt_enc_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let recipient = read_recipient_from_public_key(&keys_dir.join("public.key"));
    assert!(recipient.starts_with("fcr1"));

    let input_file = test_dir.join("secret.txt");
    create_test_file(&input_file, "recipient encryption test");

    let encrypt = Command::new(&binary)
        .arg("encrypt")
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

    let decrypt = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("secret.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-K")
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
fn test_cli_encrypt_rejects_invalid_recipient_string() {
    let test_dir = setup_test_dir("cli_encrypt_invalid_recipient");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "invalid recipient test");

    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-r")
        .arg("fcr1not-valid-bech32!!!")
        .output()
        .expect("Failed to execute encrypt with invalid recipient");

    assert!(!output.status.success());
}

#[test]
fn test_cli_encrypt_mixes_public_key_and_recipient() {
    // The new encrypt subcommand allows -k and -r to be combined: every
    // listed key/recipient gets its own X25519 entry in the .fcr.
    let test_dir = setup_test_dir("cli_encrypt_mixed_key_and_recipient");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "mixed mode test");

    let binary = get_binary_path();

    let keygen = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "mixed_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let recipient = read_recipient_from_public_key(&keys_dir.join("public.key"));

    let output = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .arg("-r")
        .arg(&recipient)
        .output()
        .expect("Failed to execute encrypt with mixed -k and -r");

    assert!(
        output.status.success(),
        "encrypt with -k and -r should succeed, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(encrypt_dir.join("secret.fcr").exists());

    // Either entry can decrypt the file.
    let dec = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("secret.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-K")
        .arg(keys_dir.join("private.key"))
        .env("FERROCRYPT_PASSPHRASE", "mixed_pass")
        .output()
        .expect("decrypt mixed file");
    assert!(dec.status.success());
    assert_eq!(
        fs::read_to_string(decrypt_dir.join("secret.txt")).unwrap(),
        "mixed mode test"
    );
}

#[test]
fn test_cli_encrypt_multiple_public_keys() {
    let test_dir = setup_test_dir("cli_encrypt_multi_public_key");
    let keys_a = test_dir.join("keys_a");
    let keys_b = test_dir.join("keys_b");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir_a = test_dir.join("dec_a");
    let decrypt_dir_b = test_dir.join("dec_b");
    for d in [
        &keys_a,
        &keys_b,
        &encrypt_dir,
        &decrypt_dir_a,
        &decrypt_dir_b,
    ] {
        fs::create_dir_all(d).unwrap();
    }
    create_test_file(&input_file, "two-recipient test");

    let binary = get_binary_path();

    for (dir, pass) in [(&keys_a, "pa"), (&keys_b, "pb")] {
        let kg = Command::new(&binary)
            .arg("keygen")
            .arg("-o")
            .arg(dir)
            .env("FERROCRYPT_PASSPHRASE", pass)
            .output()
            .expect("keygen");
        assert!(kg.status.success());
    }

    let enc = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_a.join("public.key"))
        .arg("-k")
        .arg(keys_b.join("public.key"))
        .output()
        .expect("encrypt");
    assert!(
        enc.status.success(),
        "encrypt with two -k flags failed: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    // Either private key decrypts the file.
    let dec_a = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("secret.fcr"))
        .arg("-o")
        .arg(&decrypt_dir_a)
        .arg("-K")
        .arg(keys_a.join("private.key"))
        .env("FERROCRYPT_PASSPHRASE", "pa")
        .output()
        .expect("decrypt A");
    assert!(dec_a.status.success());

    let dec_b = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("secret.fcr"))
        .arg("-o")
        .arg(&decrypt_dir_b)
        .arg("-K")
        .arg(keys_b.join("private.key"))
        .env("FERROCRYPT_PASSPHRASE", "pb")
        .output()
        .expect("decrypt B");
    assert!(dec_b.status.success());
}

#[test]
fn test_cli_decrypt_rejects_recipient_flag() {
    // -r is encrypt-only; clap rejects it on `decrypt` at parse time.
    let test_dir = setup_test_dir("cli_decrypt_recipient_rejected");
    let bad_input = test_dir.join("does_not_matter.fcr");
    fs::write(&bad_input, b"not a real .fcr").unwrap();

    let output = Command::new(get_binary_path())
        .arg("decrypt")
        .arg("-i")
        .arg(&bad_input)
        .arg("-o")
        .arg(&test_dir)
        .arg("-r")
        .arg("fcr1...")
        .output()
        .expect("decrypt with -r");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected") || stderr.to_lowercase().contains("argument"),
        "expected clap unrecognized-flag error, got: {stderr}"
    );
}

#[test]
fn test_cli_encrypt_passphrase_conflicts_with_recipient_flag() {
    let test_dir = setup_test_dir("cli_encrypt_p_conflicts_r");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "conflict");

    let output = Command::new(get_binary_path())
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-p")
        .arg("-r")
        .arg("fcr1deadbeef")
        .output()
        .expect("encrypt -p -r");
    assert!(!output.status.success());
}

#[test]
fn test_cli_encrypt_passphrase_conflicts_with_public_key_flag() {
    let test_dir = setup_test_dir("cli_encrypt_p_conflicts_k");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "conflict");

    let binary = get_binary_path();

    let kg = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "kp")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let output = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-p")
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("encrypt -p -k");
    assert!(!output.status.success());
}

#[test]
fn test_cli_encrypt_output_dir_conflicts_with_save_as() {
    let test_dir = setup_test_dir("cli_encrypt_o_conflicts_s");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let target = test_dir.join("custom.fcr");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "conflict");

    let output = Command::new(get_binary_path())
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-s")
        .arg(&target)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt -o -s");
    assert!(!output.status.success());
}

#[test]
fn test_cli_encrypt_explicit_passphrase_flag_succeeds() {
    let test_dir = setup_test_dir("cli_encrypt_explicit_p");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "explicit -p test");

    let binary = get_binary_path();

    let enc = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-p")
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt -p");
    assert!(
        enc.status.success(),
        "encrypt -p should produce a passphrase file: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let dec = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("secret.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("decrypt");
    assert!(dec.status.success());
}

#[test]
fn test_cli_decrypt_passphrase_file_with_private_key_fails_before_prompt() {
    let test_dir = setup_test_dir("cli_decrypt_passphrase_with_K");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "passphrase file");

    let binary = get_binary_path();

    let kg = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "kp")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let enc = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    // Even with no passphrase env var, the dispatcher must reject -K
    // before the prompt fires. stdin is null so a leaked prompt would hang.
    let dec = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-K")
        .arg(keys_dir.join("private.key"))
        .env_remove("FERROCRYPT_PASSPHRASE")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("decrypt with -K");
    assert!(!dec.status.success());
    let stderr = String::from_utf8_lossy(&dec.stderr);
    assert!(
        stderr.contains("--private-key is not applicable"),
        "expected typed rejection message, got: {stderr}"
    );
}

#[test]
fn test_cli_decrypt_recipient_file_without_private_key_fails() {
    let test_dir = setup_test_dir("cli_decrypt_recipient_without_K");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "recipient file");

    let binary = get_binary_path();

    let kg = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "kp")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let enc = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    let dec = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "kp")
        .output()
        .expect("decrypt without -K");
    assert!(!dec.status.success());
    let stderr = String::from_utf8_lossy(&dec.stderr);
    assert!(
        stderr.contains("--private-key is required"),
        "expected typed --private-key required message, got: {stderr}"
    );
}

#[test]
fn test_cli_decrypt_accepts_max_kdf_memory_passphrase_mode() {
    let test_dir = setup_test_dir("cli_decrypt_kdf_passphrase");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "kdf passphrase test");

    let binary = get_binary_path();
    let enc = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    // 2048 MiB is wide enough to admit the default 1 GiB Argon2id cost.
    let dec = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("--max-kdf-memory")
        .arg("2048")
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("decrypt with --max-kdf-memory");
    assert!(
        dec.status.success(),
        "decrypt with widened --max-kdf-memory failed: {}",
        String::from_utf8_lossy(&dec.stderr)
    );
}

#[test]
fn test_cli_decrypt_accepts_max_kdf_memory_recipient_mode() {
    let test_dir = setup_test_dir("cli_decrypt_kdf_recipient");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "kdf recipient test");

    let binary = get_binary_path();
    let kg = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "kp")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let enc = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    let dec = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-K")
        .arg(keys_dir.join("private.key"))
        .arg("--max-kdf-memory")
        .arg("2048")
        .env("FERROCRYPT_PASSPHRASE", "kp")
        .output()
        .expect("decrypt with --max-kdf-memory");
    assert!(
        dec.status.success(),
        "decrypt with widened --max-kdf-memory (recipient mode) failed: {}",
        String::from_utf8_lossy(&dec.stderr)
    );
}

#[test]
fn test_cli_encrypt_rejects_max_kdf_memory_flag() {
    // --max-kdf-memory is decrypt-only; clap rejects it on `encrypt`.
    let test_dir = setup_test_dir("cli_encrypt_rejects_max_kdf");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "kdf reject test");

    let output = Command::new(get_binary_path())
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("--max-kdf-memory")
        .arg("64")
        .env("FERROCRYPT_PASSPHRASE", "p")
        .output()
        .expect("encrypt --max-kdf-memory");
    assert!(!output.status.success());
}

#[test]
fn test_cli_decrypt_rejects_save_as_flag() {
    // -s is encrypt-only; clap rejects it on `decrypt`.
    let test_dir = setup_test_dir("cli_decrypt_rejects_s");
    let bad_input = test_dir.join("does_not_matter.fcr");
    fs::write(&bad_input, b"not a real .fcr").unwrap();

    let output = Command::new(get_binary_path())
        .arg("decrypt")
        .arg("-i")
        .arg(&bad_input)
        .arg("-o")
        .arg(&test_dir)
        .arg("-s")
        .arg(test_dir.join("ignored.txt"))
        .output()
        .expect("decrypt -s");
    assert!(!output.status.success());
}

#[test]
fn test_cli_rejects_empty_passphrase_env_var() {
    let test_dir = setup_test_dir("cli_empty_passphrase_env");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "empty passphrase test");

    let output = Command::new(get_binary_path())
        .arg("encrypt")
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

    // Null stdin = no terminal. On Unix rpassword would otherwise open
    // /dev/tty directly and block; on Windows it would open CONIN$ and
    // block the same way. The CLI's cross-platform `is_terminal()` guard
    // must catch this up-front and fail with a clear error rather than
    // hang or silently prompt on some hidden console.
    let output = Command::new(get_binary_path())
        .arg("encrypt")
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
fn test_cli_recipient_nonexistent_key_file() {
    let test_dir = setup_test_dir("cli_nonexistent_key");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "nonexistent key test");

    let output = Command::new(get_binary_path())
        .arg("encrypt")
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
fn test_cli_passphrase_nonexistent_input() {
    let test_dir = setup_test_dir("cli_passphrase_nonexistent_input");

    let output = Command::new(get_binary_path())
        .arg("encrypt")
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
fn test_cli_recipient_nonexistent_input() {
    let test_dir = setup_test_dir("cli_recipient_nonexistent_input");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    let kg = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "noinput_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(kg.status.success());

    let output = Command::new(&binary)
        .arg("encrypt")
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

    let output = Command::new(get_binary_path())
        .arg("fingerprint")
        .arg(test_dir.join("nonexistent.key"))
        .output()
        .expect("Failed to execute fingerprint with nonexistent file");

    assert!(!output.status.success());
}

#[test]
fn test_cli_encrypt_alias_enc() {
    let test_dir = setup_test_dir("cli_alias_enc");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "alias enc test");

    let output = Command::new(get_binary_path())
        .arg("enc")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "alias_pass")
        .output()
        .expect("Failed to execute enc alias");

    assert!(output.status.success());
    assert!(encrypt_dir.join("data.fcr").exists());
}

#[test]
fn test_cli_decrypt_alias_dec() {
    let test_dir = setup_test_dir("cli_alias_dec");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "alias dec test");

    let binary = get_binary_path();

    let enc = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "alias_dec_pass")
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    let output = Command::new(&binary)
        .arg("dec")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "alias_dec_pass")
        .output()
        .expect("Failed to execute dec alias");

    assert!(output.status.success());
    assert_eq!(
        fs::read_to_string(decrypt_dir.join("data.txt")).unwrap(),
        "alias dec test"
    );
}

#[test]
fn test_cli_keygen_alias_gen() {
    let test_dir = setup_test_dir("cli_alias_gen");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let output = Command::new(get_binary_path())
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
fn test_passphrase_encrypt_conflict_detected() {
    let test_dir = setup_test_dir("passphrase_encrypt_conflict");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "payload");

    let binary = get_binary_path();

    let first = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("first encrypt");
    assert!(first.status.success(), "first encrypt should succeed");
    assert!(encrypt_dir.join("data.fcr").exists());

    let second = Command::new(&binary)
        .arg("encrypt")
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
fn test_passphrase_encrypt_conflict_with_save_as() {
    let test_dir = setup_test_dir("passphrase_save_as_conflict");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let custom_out = encrypt_dir.join("custom.fcr");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "payload");

    create_test_file(&custom_out, "placeholder");

    let output = Command::new(get_binary_path())
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
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
fn test_recipient_encrypt_conflict_detected() {
    let test_dir = setup_test_dir("recipient_encrypt_conflict");
    let input_file = test_dir.join("secret.txt");
    let keys_dir = test_dir.join("keys");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "secret data");

    let binary = get_binary_path();

    let kg = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "keypass")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let first = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("first recipient encrypt");
    assert!(
        first.status.success(),
        "first encrypt failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let second = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("second recipient encrypt");
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

    let first = Command::new(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "keypass")
        .output()
        .expect("first keygen");
    assert!(first.status.success());

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

    create_test_file(&keys_dir.join("private.key"), "dummy");

    let output = Command::new(get_binary_path())
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

    create_test_file(&keys_dir.join("public.key"), "dummy");

    let output = Command::new(get_binary_path())
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

    let enc = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    let dec1 = Command::new(&binary)
        .arg("decrypt")
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
        .arg("decrypt")
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

// ─── -o / -s requirement tests ─────────────────────────────────────────────

#[test]
fn test_passphrase_encrypt_save_as_without_output_dir() {
    let test_dir = setup_test_dir("passphrase_save_as_no_out");
    let input_file = test_dir.join("data.txt");
    let target = test_dir.join("result.fcr");
    create_test_file(&input_file, "payload");

    let output = Command::new(get_binary_path())
        .arg("encrypt")
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
fn test_recipient_encrypt_save_as_without_output_dir() {
    let test_dir = setup_test_dir("recipient_save_as_no_out");
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

    let output = Command::new(&binary)
        .arg("encrypt")
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
fn test_encrypt_without_output_dir_or_save_as_fails() {
    let test_dir = setup_test_dir("encrypt_no_out_no_save");
    let input_file = test_dir.join("data.txt");
    create_test_file(&input_file, "payload");

    let output = Command::new(get_binary_path())
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt without -o or -s");
    assert!(!output.status.success());
}

#[test]
fn test_decrypt_without_output_dir_fails() {
    let test_dir = setup_test_dir("decrypt_no_out");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "payload");

    let binary = get_binary_path();

    let enc = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    let dec = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("decrypt without -o");
    assert!(!dec.status.success());
}

// ─── Double-encrypt gate ───────────────────────────────────────────────────

#[test]
fn test_encrypt_double_encrypt_no_tty_refuses() {
    let test_dir = setup_test_dir("double_encrypt_no_tty");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let encrypt_dir2 = test_dir.join("encrypted2");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&encrypt_dir2).unwrap();
    create_test_file(&input_file, "double encrypt");

    let binary = get_binary_path();

    let enc = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "p1")
        .output()
        .expect("first encrypt");
    assert!(enc.status.success());
    let first_fcr = encrypt_dir.join("data.fcr");

    // Non-interactive (null stdin) must refuse without --allow-double-encrypt.
    let again = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&first_fcr)
        .arg("-o")
        .arg(&encrypt_dir2)
        .env("FERROCRYPT_PASSPHRASE", "p2")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("second encrypt without TTY");
    assert!(!again.status.success(), "should refuse without flag/TTY");
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(
        stderr.contains("refusing to encrypt an existing FerroCrypt file"),
        "expected double-encrypt refusal, got: {stderr}"
    );
}

#[test]
fn test_encrypt_double_encrypt_with_flag_succeeds() {
    let test_dir = setup_test_dir("double_encrypt_with_flag");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let encrypt_dir2 = test_dir.join("encrypted2");
    let decrypt_outer = test_dir.join("dec_outer");
    let decrypt_inner = test_dir.join("dec_inner");
    for d in [&encrypt_dir, &encrypt_dir2, &decrypt_outer, &decrypt_inner] {
        fs::create_dir_all(d).unwrap();
    }
    create_test_file(&input_file, "onion-layer test");

    let binary = get_binary_path();

    let enc = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "p1")
        .output()
        .expect("first encrypt");
    assert!(enc.status.success());
    let first_fcr = encrypt_dir.join("data.fcr");

    let again = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&first_fcr)
        .arg("-o")
        .arg(&encrypt_dir2)
        .arg("--allow-double-encrypt")
        .env("FERROCRYPT_PASSPHRASE", "p2")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("second encrypt with flag");
    assert!(
        again.status.success(),
        "encrypt with --allow-double-encrypt should succeed: {}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("already be a FerroCrypt file"),
        "expected the warning to still fire on stderr"
    );

    // Round-trip the onion: outer pass, then inner.
    let outer_fcr = encrypt_dir2.join("data.fcr");
    let dec_outer = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(&outer_fcr)
        .arg("-o")
        .arg(&decrypt_outer)
        .env("FERROCRYPT_PASSPHRASE", "p2")
        .output()
        .expect("outer decrypt");
    assert!(dec_outer.status.success());
    // The outer decrypt restores the original .fcr name (data.fcr).
    let inner_fcr = decrypt_outer.join("data.fcr");
    assert!(inner_fcr.exists());

    let dec_inner = Command::new(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(&inner_fcr)
        .arg("-o")
        .arg(&decrypt_inner)
        .env("FERROCRYPT_PASSPHRASE", "p1")
        .output()
        .expect("inner decrypt");
    assert!(dec_inner.status.success());
    assert_eq!(
        fs::read_to_string(decrypt_inner.join("data.txt")).unwrap(),
        "onion-layer test"
    );
}

#[test]
fn test_encrypt_output_conflict_wins_over_double_encrypt_gate() {
    // When both `output exists` and `input is .fcr` are true, the conflict
    // check must fire first so the user sees `Already exists` immediately
    // rather than being asked a y/N about double-encrypting an output that
    // we'd then refuse to write anyway.
    let test_dir = setup_test_dir("encrypt_conflict_wins_over_gate");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let encrypt_dir2 = test_dir.join("encrypted2");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&encrypt_dir2).unwrap();
    create_test_file(&input_file, "ordering test");

    let binary = get_binary_path();

    let enc = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "p1")
        .output()
        .expect("first encrypt");
    assert!(enc.status.success());
    let inner_fcr = encrypt_dir.join("data.fcr");

    // Pre-create the would-be output of the second encrypt so the conflict
    // check has something to fire on.
    let target = encrypt_dir2.join("data.fcr");
    create_test_file(&target, "placeholder");

    let again = Command::new(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&inner_fcr)
        .arg("-o")
        .arg(&encrypt_dir2)
        .env("FERROCRYPT_PASSPHRASE", "p2")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("second encrypt");
    assert!(!again.status.success());
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(
        stderr.contains("Already exists"),
        "conflict check should fire first; got: {stderr}"
    );
    assert!(
        !stderr.contains("refusing to encrypt an existing FerroCrypt file"),
        "double-encrypt gate should not have fired before the conflict check; got: {stderr}"
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
    for sub in ["encrypt", "decrypt", "keygen", "fingerprint"] {
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
fn test_cli_subcommand_help_encrypt() {
    let output = Command::new(get_binary_path())
        .args(["encrypt", "--help"])
        .output()
        .expect("encrypt --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for token in [
        "--input",
        "--output-dir",
        "--save-as",
        "--passphrase",
        "--recipient",
        "--public-key",
        "--allow-double-encrypt",
    ] {
        assert!(stdout.contains(token), "missing {token} in:\n{stdout}");
    }
}

#[test]
fn test_cli_subcommand_help_decrypt() {
    let output = Command::new(get_binary_path())
        .args(["decrypt", "--help"])
        .output()
        .expect("decrypt --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for token in [
        "--input",
        "--output-dir",
        "--private-key",
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
        .expect("keygen --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--output-dir"));
}

#[test]
fn test_cli_subcommand_help_fingerprint() {
    let output = Command::new(get_binary_path())
        .args(["fingerprint", "--help"])
        .output()
        .expect("fingerprint --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.to_lowercase().contains("public key"));
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
        .args(["encrypt", "-i"])
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "right")
        .output()
        .expect("encrypt");
    assert_eq!(enc.status.code(), Some(0));

    let dec = Command::new(&binary)
        .args(["decrypt", "-i"])
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
        .args(["encrypt", "--not-a-real-flag"])
        .output()
        .expect("bad args");
    assert_ne!(output.status.code(), Some(0));
}

#[test]
fn test_cli_missing_required_input_returns_nonzero() {
    let output = Command::new(get_binary_path())
        .arg("encrypt")
        .output()
        .expect("missing args");
    assert_ne!(output.status.code(), Some(0));
}

// ─── Empty inputs ──────────────────────────────────────────────────────────

#[test]
fn test_cli_passphrase_empty_file_roundtrip() {
    let test_dir = setup_test_dir("cli_empty_file_passphrase");
    let input_file = test_dir.join("empty.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "");
    assert_eq!(fs::metadata(&input_file).unwrap().len(), 0);

    let binary = get_binary_path();
    let enc = Command::new(&binary)
        .args(["encrypt", "-i"])
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
        .args(["decrypt", "-i"])
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
fn test_cli_recipient_empty_file_roundtrip() {
    let test_dir = setup_test_dir("cli_empty_file_recipient");
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
        .args(["encrypt", "-i"])
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
        .args(["decrypt", "-i"])
        .arg(encrypt_dir.join("empty.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-K")
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
fn test_cli_passphrase_empty_directory_roundtrip() {
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
        .args(["encrypt", "-i"])
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
        .args(["decrypt", "-i"])
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
fn test_cli_encrypt_with_malformed_public_key_fails() {
    let test_dir = setup_test_dir("cli_malformed_public");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "content");
    fs::write(keys_dir.join("public.key"), b"not a real key file").unwrap();

    let output = Command::new(get_binary_path())
        .args(["encrypt", "-i"])
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
fn test_cli_decrypt_with_malformed_private_key_fails() {
    let test_dir = setup_test_dir("cli_malformed_private");
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
        .args(["encrypt", "-i"])
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
        .args(["decrypt", "-i"])
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-K")
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
fn test_cli_decrypt_rejects_public_key_as_private() {
    let test_dir = setup_test_dir("cli_wrong_key_type");
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
        .args(["encrypt", "-i"])
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    let dec = Command::new(&binary)
        .args(["decrypt", "-i"])
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-K")
        .arg(keys_dir.join("public.key"))
        .env("FERROCRYPT_PASSPHRASE", "key")
        .output()
        .expect("decrypt");
    assert!(!dec.status.success());
}

#[test]
fn test_cli_decrypt_wrong_key_type_rejects_before_prompt() {
    // `validate_private_key_file` must fire before the passphrase prompt:
    // if it didn't, this command would hang on a hidden-input prompt because
    // stdin is null and FERROCRYPT_PASSPHRASE is unset.
    let test_dir = setup_test_dir("cli_wrong_key_type_before_prompt");
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
        .env("FERROCRYPT_PASSPHRASE", "kp")
        .output()
        .expect("keygen");
    assert!(kg.status.success());
    let enc = Command::new(&binary)
        .args(["encrypt", "-i"])
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    let dec = Command::new(&binary)
        .args(["decrypt", "-i"])
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-K")
        .arg(keys_dir.join("public.key"))
        .env_remove("FERROCRYPT_PASSPHRASE")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("decrypt");
    assert!(!dec.status.success());
    let stderr = String::from_utf8_lossy(&dec.stderr);
    // Whatever the exact wording, the failure must NOT be the no-passphrase
    // prompt error — that would mean `validate_private_key_file` was bypassed.
    assert!(
        !stderr.contains("No passphrase provided"),
        "expected validate_private_key_file to reject before prompt; got: {stderr}"
    );
}

#[ctor::dtor]
fn cleanup() {
    cleanup_test_workspace();
}
