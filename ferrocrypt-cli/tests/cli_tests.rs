//! CLI integration tests for ferrocrypt-cli.
//!
//! ## Release-profile gating
//!
//! The cli binary's `test_fast_kdf_override` reads
//! `FERROCRYPT_INTERNAL_TEST_FAST_KDF=1` (set by [`cli_command`] below)
//! ONLY inside its `#[cfg(debug_assertions)]` block. In `cargo test`
//! (default debug profile) the override fires and KDF-heavy paths run
//! in milliseconds. In `cargo test --release` the cli is compiled with
//! `debug_assertions = false`, the override branch is gone, and every
//! `encrypt`-passphrase / `keygen` / `decrypt`-passphrase /
//! `decrypt`-recipient subprocess runs full-strength Argon2id (1 GiB
//! memory, time_cost 4). With cargo's default per-binary parallelism
//! that means concurrent multi-GiB allocations and, on typical dev
//! machines, swap thrash and effectively-frozen sessions.
//!
//! Tests that exercise a full Argon2id run are therefore guarded with
//! `#[cfg_attr(not(debug_assertions), ignore = "...")]`, so
//! `cargo test --release` skips them and only validates the fast paths
//! (clap parse errors, mode-check rejections, `--help` / `--version`,
//! recipient-mode encrypt which uses ECDH and never runs Argon2id,
//! malformed-input rejections that fail before KDF, etc.). Lib-side
//! test binaries continue to run full-coverage in release because they
//! thread fast Argon2id through `ferrocrypt-test-support` instead of
//! spawning a release CLI subprocess.
//!
//! Run the gated tests explicitly with
//! `cargo test --release --package ferrocrypt-cli --test cli_tests -- --ignored --test-threads=1`
//! on a machine with enough RAM to absorb sequential 1 GiB Argon2id
//! runs. Workspace-wide `cargo test ... -- --ignored` would also pull in
//! the lib's `regenerate_fixtures` opt-in helper, which is unrelated.
//!
//! A test that is not merely slow in release but *invalid* there — one
//! pinning a value the fast override defines — uses `#[cfg(debug_assertions)]`
//! instead. `ignore` is how this file marks "run me in the release lane", so
//! marking such a test with it would select it exactly where it cannot pass.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const TEST_WORKSPACE: &str = "tests/cli_workspace";
/// Mirrors `INTERNAL_TEST_FAST_KDF_ENV` in the cli binary's production
/// source. The cli's `cfg(debug_assertions)` branch reads this name and
/// only activates fast Argon2id when the value is exactly
/// [`INTERNAL_TEST_FAST_KDF_VALUE`]. Tests cannot import the const
/// directly because `ferrocrypt-cli` is a binary crate with no `[lib]`
/// target, so the name and value are mirrored here. Keep in sync with
/// `ferrocrypt-cli/src/cli.rs`.
const INTERNAL_TEST_FAST_KDF_ENV: &str = "FERROCRYPT_INTERNAL_TEST_FAST_KDF";
const INTERNAL_TEST_FAST_KDF_VALUE: &str = "1";

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

/// Builds a `Command` for the cli binary with the in-tree test-only
/// fast-Argon2id env var pre-set. The env var has effect ONLY in debug
/// builds of the cli (i.e. plain `cargo test`); under
/// `cargo test --release` the override branch is compiled out and the
/// env var is silently ignored, so tests that actually run Argon2id are
/// gated with `#[cfg_attr(not(debug_assertions), ignore = "...")]`.
/// See the file-level doc comment for the full rationale.
fn cli_command(binary: &Path) -> Command {
    let mut cmd = Command::new(binary);
    cmd.env(INTERNAL_TEST_FAST_KDF_ENV, INTERNAL_TEST_FAST_KDF_VALUE);
    cmd
}

fn setup_test_dir(test_name: &str) -> PathBuf {
    // Per-process subtree, so a concurrent `cargo test` invocation of
    // this binary (debug next to release) cannot delete files this
    // run is using.
    let test_dir = ferrocrypt_test_support::per_process_workspace(TEST_WORKSPACE).join(test_name);
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
    ferrocrypt_test_support::remove_per_process_workspace(TEST_WORKSPACE);
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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

    let encrypt_output = cli_command(&binary)
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

    let decrypt_output = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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

    let encrypt_output = cli_command(&binary)
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

    let decrypt_output = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_passphrase_wrong_password() {
    let test_dir = setup_test_dir("cli_passphrase_wrong_pass");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    create_test_file(&input_file, "Secret data");

    let binary = get_binary_path();

    let encrypt_output = cli_command(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "correct_password")
        .output()
        .expect("Failed to execute encrypt command");

    assert!(encrypt_output.status.success());

    let decrypt_output = cli_command(&binary)
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
        stderr.contains("wrong passphrase or modified file"),
        "expected the plain wrong-passphrase message on stderr, got: {stderr}"
    );
    assert!(
        !stderr.contains("aead::Error"),
        "stderr must not leak internal crate error names, got: {stderr}"
    );
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_keygen() {
    let test_dir = setup_test_dir("cli_keygen");
    let keys_dir = test_dir.join("keys");

    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    let keygen_output = cli_command(&binary)
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
    //   + ext(0) + wrapped_secret(32 + 16 tag) = 176. public.key is
    // a Bech32 fcr1… string + one trailing LF; the typed payload is
    // version(1) + type_name_len(2) + key_material_len(4) + "x25519"(6)
    // + key_material(32) + checksum(16) = 61 bytes → 98 Bech32 data
    // chars + 4-char Bech32 envelope ("fcr1") + 6-char Bech32 checksum
    // + 1 LF = 109 bytes.
    let private_key_size = fs::metadata(keys_dir.join("private.key")).unwrap().len();
    let public_key_size = fs::metadata(keys_dir.join("public.key")).unwrap().len();
    assert_eq!(private_key_size, 176, "X25519 private.key size");
    assert_eq!(public_key_size, 109, "X25519 public.key text size");
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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

    let keygen_output = cli_command(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key_pass")
        .output()
        .expect("Failed to execute keygen");

    assert!(keygen_output.status.success());

    let encrypt_output = cli_command(&binary)
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

    let decrypt_output = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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

    let encrypt_output = cli_command(&binary)
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

    let decrypt_output = cli_command(&binary)
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
        stderr.contains("Decryption failed: file data was modified or corrupted"),
        "expected typed payload-auth message on stderr, got: {stderr}"
    );
    assert!(
        !stderr.contains("aead::Error"),
        "stderr must not leak internal crate error names, got: {stderr}"
    );
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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

    let keygen = cli_command(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "correct_key_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let encrypt = cli_command(&binary)
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

    let decrypt_output = cli_command(&binary)
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
        stderr.contains("Private key unlock failed: wrong passphrase or modified key file"),
        "expected typed key-unlock message on stderr, got: {stderr}"
    );
    assert!(
        !stderr.contains("aead::Error"),
        "stderr must not leak internal crate error names, got: {stderr}"
    );
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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

    let encrypt_output = cli_command(&binary)
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

    let decrypt_output = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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

    let encrypt_output = cli_command(&binary)
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

    let decrypt_output = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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

    let keygen = cli_command(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let custom_output = encrypt_dir.join("backup.enc");

    let encrypt_output = cli_command(&binary)
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

    let decrypt_output = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_passphrase_without_save_as_uses_default() {
    let test_dir = setup_test_dir("cli_passphrase_no_save_as");
    let input_file = test_dir.join("report.txt");
    let encrypt_dir = test_dir.join("encrypted");

    fs::create_dir_all(&encrypt_dir).unwrap();

    create_test_file(&input_file, "default naming test");

    let binary = get_binary_path();

    let output = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_fingerprint() {
    let test_dir = setup_test_dir("cli_fingerprint");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    let keygen = cli_command(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "fp_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let fp_output = cli_command(&binary)
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
#[cfg(unix)]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_fingerprint_survives_closed_stdout_pipe() {
    use std::process::Stdio;

    let test_dir = setup_test_dir("cli_fingerprint_closed_pipe");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();
    let keygen = cli_command(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "fp_pass")
        .output()
        .expect("keygen");
    assert!(keygen.status.success());

    // Spawn `fingerprint` with stdout piped, then close the read end without
    // reading. The command reads the key file and computes the fingerprint
    // before it writes, so by write time the reader is gone and the write hits
    // a broken pipe. The CLI must finish cleanly instead of panicking, which
    // would surface as exit code 101 and a panic message on stderr.
    let mut child = cli_command(&binary)
        .arg("fingerprint")
        .arg(keys_dir.join("public.key"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fingerprint");
    drop(child.stdout.take());
    let output = child.wait_with_output().expect("wait fingerprint");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "broken stdout pipe must not crash fingerprint; code={:?}, stderr={stderr}",
        output.status.code()
    );
    assert!(
        !stderr.contains("panicked"),
        "fingerprint panicked on a broken pipe: {stderr}"
    );
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_keygen_prints_fingerprint() {
    let test_dir = setup_test_dir("cli_keygen_fp");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    let output = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_keygen_prints_recipient() {
    let test_dir = setup_test_dir("cli_keygen_rcpt");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    let output = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_encrypt_with_recipient_string() {
    let test_dir = setup_test_dir("cli_encrypt_recipient_string");
    let keys_dir = test_dir.join("keys");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();

    let binary = get_binary_path();

    let keygen = cli_command(&binary)
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

    let encrypt = cli_command(&binary)
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

    let decrypt = cli_command(&binary)
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

    let output = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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

    let keygen = cli_command(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "mixed_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let recipient = read_recipient_from_public_key(&keys_dir.join("public.key"));

    let output = cli_command(&binary)
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
    let dec = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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
        let kg = cli_command(&binary)
            .arg("keygen")
            .arg("-o")
            .arg(dir)
            .env("FERROCRYPT_PASSPHRASE", pass)
            .output()
            .expect("keygen");
        assert!(kg.status.success());
    }

    let enc = cli_command(&binary)
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
    let dec_a = cli_command(&binary)
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

    let dec_b = cli_command(&binary)
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

    let output = cli_command(&get_binary_path())
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

    let output = cli_command(&get_binary_path())
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
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "conflict");

    // `-p` conflicts with `-k` at clap parse time, before the key file is
    // read, so an uncreated key path is enough and no Argon2id runs.
    let output = cli_command(&get_binary_path())
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-p")
        .arg("-k")
        .arg(test_dir.join("nonexistent-public.key"))
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

    let output = cli_command(&get_binary_path())
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_encrypt_explicit_passphrase_flag_succeeds() {
    let test_dir = setup_test_dir("cli_encrypt_explicit_p");
    let input_file = test_dir.join("secret.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "explicit -p test");

    let binary = get_binary_path();

    let enc = cli_command(&binary)
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

    let dec = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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

    let kg = cli_command(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "kp")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let enc = cli_command(&binary)
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
    let dec = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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

    let kg = cli_command(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "kp")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let enc = cli_command(&binary)
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

    let dec = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_decrypt_accepts_max_kdf_memory_passphrase_mode() {
    let test_dir = setup_test_dir("cli_decrypt_kdf_passphrase");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "kdf passphrase test");

    let binary = get_binary_path();
    let enc = cli_command(&binary)
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
    let dec = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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
    let kg = cli_command(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "kp")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let enc = cli_command(&binary)
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

    let dec = cli_command(&binary)
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

/// `--max-kdf-work` reaches the decryptor and moves the accepted boundary.
///
/// Compiled only in the debug profile, rather than ignored there: it pins the
/// exact work of the fast Argon2id override (19 MiB × 1 pass), and a release
/// build seals the same file at the writer's own defaults, whose work is a
/// different number. An `ignore` would put it in the set that the release lane
/// selects with `--ignored`, which is the one place it can never pass.
#[cfg(debug_assertions)]
#[test]
fn test_cli_decrypt_max_kdf_work_bounds_the_accepted_header() {
    const FAST_KDF_WORK: u32 = ferrocrypt_test_support::TEST_FAST_KDF_MEM_COST
        * ferrocrypt_test_support::TEST_FAST_KDF_TIME_COST;

    let test_dir = setup_test_dir("cli_decrypt_kdf_work");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let refused_dir = test_dir.join("refused");
    let accepted_dir = test_dir.join("accepted");
    for dir in [&encrypt_dir, &refused_dir, &accepted_dir] {
        fs::create_dir_all(dir).unwrap();
    }
    create_test_file(&input_file, "kdf work test");

    let binary = get_binary_path();
    let enc = cli_command(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    let decrypt_with = |budget: u32, out: &Path| {
        cli_command(&binary)
            .arg("decrypt")
            .arg("-i")
            .arg(encrypt_dir.join("data.fcr"))
            .arg("-o")
            .arg(out)
            .arg("--max-kdf-work")
            .arg(budget.to_string())
            .env("FERROCRYPT_PASSPHRASE", "pass")
            .output()
            .expect("decrypt with --max-kdf-work")
    };

    // One unit below the file's own work: refused, and the message names
    // the work dimension rather than any other cap.
    let refused = decrypt_with(FAST_KDF_WORK - 1, &refused_dir);
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success(),
        "a budget below the file's work must refuse it"
    );
    assert!(
        stderr.contains("work over limit"),
        "expected the work-cap message, got: {stderr}"
    );

    // Exactly at the file's own work: accepted, so the boundary is inclusive
    // and the flag is not simply refusing everything.
    let accepted = decrypt_with(FAST_KDF_WORK, &accepted_dir);
    assert!(
        accepted.status.success(),
        "a budget equal to the file's work must accept it: {}",
        String::from_utf8_lossy(&accepted.stderr)
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

    let output = cli_command(&get_binary_path())
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_decrypt_rejects_tightened_max_kdf_lanes() {
    let test_dir = setup_test_dir("cli_decrypt_kdf_lanes_reject");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "kdf lanes reject test");

    let binary = get_binary_path();
    let enc = cli_command(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    // The file's Argon2id lane count is 4 (both the fast-KDF test override
    // and the production default use 4 lanes); a tightened cap of 2 must
    // reject it before Argon2id runs, so the decrypt fails.
    let dec = cli_command(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("--max-kdf-lanes")
        .arg("2")
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("decrypt with --max-kdf-lanes");
    assert!(
        !dec.status.success(),
        "decrypt should fail when --max-kdf-lanes is below the file's lane count"
    );
    let stderr = String::from_utf8_lossy(&dec.stderr);
    assert!(
        stderr.contains("parallelism over limit"),
        "expected a lane/parallelism-limit error, got: {stderr}"
    );
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_decrypt_rejects_tightened_max_kdf_time_cost() {
    let test_dir = setup_test_dir("cli_decrypt_kdf_time_reject");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "kdf time reject test");

    let binary = get_binary_path();
    let enc = cli_command(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    // Every valid file has time_cost >= 1, so a cap of 0 rejects any of them.
    // This confirms --max-kdf-time-cost tightens the decrypt-side limit
    // regardless of the file's exact iteration count.
    let dec = cli_command(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("--max-kdf-time-cost")
        .arg("0")
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("decrypt with --max-kdf-time-cost");
    assert!(
        !dec.status.success(),
        "decrypt should fail when --max-kdf-time-cost is below the file's time cost"
    );
    let stderr = String::from_utf8_lossy(&dec.stderr);
    assert!(
        stderr.contains("time over limit"),
        "expected a time-limit error, got: {stderr}"
    );
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_decrypt_rejects_tightened_max_kdf_memory() {
    let test_dir = setup_test_dir("cli_decrypt_kdf_memory_reject");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "kdf memory reject test");

    let binary = get_binary_path();
    let enc = cli_command(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    // The file's Argon2id memory cost is at least 19 MiB (the fast-KDF test
    // override; the production default is 1 GiB); a cap of 1 MiB is far below
    // it, so the file is rejected before Argon2id runs.
    let dec = cli_command(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("--max-kdf-memory")
        .arg("1")
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("decrypt with --max-kdf-memory");
    assert!(
        !dec.status.success(),
        "decrypt should fail when --max-kdf-memory is below the file's memory cost"
    );
    let stderr = String::from_utf8_lossy(&dec.stderr);
    assert!(
        stderr.contains("memory over limit"),
        "expected a memory-limit error, got: {stderr}"
    );
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_decrypt_rejects_tightened_max_kdf_lanes_private_key_mode() {
    let test_dir = setup_test_dir("cli_decrypt_kdf_lanes_reject_private");
    let keys_dir = test_dir.join("keys");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "kdf lanes reject private-key test");

    let binary = get_binary_path();
    let kg = cli_command(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "kp")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let enc = cli_command(&binary)
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

    // The `private.key` is sealed with 4 Argon2id lanes (both the fast-KDF
    // test override and the production default use 4). The cap applies to the
    // private-key unlock, so a tightened cap of 2 rejects it before Argon2id
    // runs and the decrypt fails.
    let dec = cli_command(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("data.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("-K")
        .arg(keys_dir.join("private.key"))
        .arg("--max-kdf-lanes")
        .arg("2")
        .env("FERROCRYPT_PASSPHRASE", "kp")
        .output()
        .expect("decrypt with --max-kdf-lanes");
    assert!(
        !dec.status.success(),
        "decrypt should fail when --max-kdf-lanes is below the private key's lane count"
    );
    let stderr = String::from_utf8_lossy(&dec.stderr);
    assert!(
        stderr.contains("parallelism over limit"),
        "expected a lane/parallelism-limit error, got: {stderr}"
    );
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_decrypt_keep_partial_retains_incomplete_on_failure() {
    let test_dir = setup_test_dir("cli_decrypt_keep_partial");
    let input_file = test_dir.join("payload.bin");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_default = test_dir.join("decrypted_default");
    let decrypt_keep = test_dir.join("decrypted_keep");
    for d in [&encrypt_dir, &decrypt_default, &decrypt_keep] {
        fs::create_dir_all(d).unwrap();
    }

    // Multi-chunk plaintext so a byte flipped at the file's midpoint lands
    // inside a non-first STREAM payload chunk: the earlier chunk decrypts and
    // streams into `.incomplete`, then the tampered chunk fails, leaving a
    // partially written staged output for the policy to act on.
    let big_data: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();
    fs::write(&input_file, &big_data).unwrap();

    let binary = get_binary_path();
    let enc = cli_command(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    let encrypted_path = encrypt_dir.join("payload.fcr");
    let mut ct = fs::read(&encrypted_path).unwrap();
    let flip_offset = ct.len() / 2;
    ct[flip_offset] ^= 0xFF;
    fs::write(&encrypted_path, &ct).unwrap();

    // Without --keep-partial the staged `.incomplete` is removed on failure.
    let dec = cli_command(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(&encrypted_path)
        .arg("-o")
        .arg(&decrypt_default)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("decrypt without --keep-partial");
    assert!(
        !dec.status.success(),
        "tampered payload must fail to decrypt"
    );
    assert!(
        !decrypt_default.join("payload.bin.incomplete").exists(),
        "default policy must remove the .incomplete staged output"
    );

    // With --keep-partial the staged `.incomplete` survives for recovery.
    let dec_keep = cli_command(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(&encrypted_path)
        .arg("-o")
        .arg(&decrypt_keep)
        .arg("--keep-partial")
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("decrypt with --keep-partial");
    assert!(
        !dec_keep.status.success(),
        "tampered payload must fail to decrypt even with --keep-partial"
    );
    assert!(
        decrypt_keep.join("payload.bin.incomplete").exists(),
        "--keep-partial must retain the .incomplete staged output"
    );
}

#[test]
fn test_cli_decrypt_rejects_save_as_flag() {
    // -s is encrypt-only; clap rejects it on `decrypt`.
    let test_dir = setup_test_dir("cli_decrypt_rejects_s");
    let bad_input = test_dir.join("does_not_matter.fcr");
    fs::write(&bad_input, b"not a real .fcr").unwrap();

    let output = cli_command(&get_binary_path())
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

    let output = cli_command(&get_binary_path())
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
    let output = cli_command(&get_binary_path())
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

    let output = cli_command(&get_binary_path())
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

    let output = cli_command(&get_binary_path())
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_recipient_nonexistent_input() {
    let test_dir = setup_test_dir("cli_recipient_nonexistent_input");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    let kg = cli_command(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "noinput_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(kg.status.success());

    let output = cli_command(&binary)
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

    let output = cli_command(&get_binary_path())
        .arg("fingerprint")
        .arg(test_dir.join("nonexistent.key"))
        .output()
        .expect("Failed to execute fingerprint with nonexistent file");

    assert!(!output.status.success());
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_encrypt_alias_enc() {
    let test_dir = setup_test_dir("cli_alias_enc");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "alias enc test");

    let output = cli_command(&get_binary_path())
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_decrypt_alias_dec() {
    let test_dir = setup_test_dir("cli_alias_dec");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "alias dec test");

    let binary = get_binary_path();

    let enc = cli_command(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "alias_dec_pass")
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    let output = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_keygen_alias_gen() {
    let test_dir = setup_test_dir("cli_alias_gen");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let output = cli_command(&get_binary_path())
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_fingerprint_alias_fp() {
    let test_dir = setup_test_dir("cli_alias_fp");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    let keygen = cli_command(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "alias_fp_pass")
        .output()
        .expect("Failed to execute keygen");
    assert!(keygen.status.success());

    let output = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_passphrase_encrypt_conflict_detected() {
    let test_dir = setup_test_dir("passphrase_encrypt_conflict");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "payload");

    let binary = get_binary_path();

    let first = cli_command(&binary)
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

    let second = cli_command(&binary)
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
#[cfg(unix)]
fn test_encrypt_conflict_detects_dangling_symlink() {
    use std::os::unix::fs::symlink;

    let test_dir = setup_test_dir("encrypt_conflict_dangling_symlink");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "payload");

    // A dangling symlink at the would-be output path: `Path::exists` follows
    // it and reports nothing there, but the entry still blocks the output.
    // The conflict check must catch it before any passphrase is requested, so
    // the run fails with the conflict message rather than the missing-passphrase
    // one (no passphrase env, no terminal).
    symlink("nonexistent-target", encrypt_dir.join("data.fcr")).unwrap();

    let out = cli_command(&get_binary_path())
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env_remove("FERROCRYPT_PASSPHRASE")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("encrypt with dangling-symlink output");
    assert!(
        !out.status.success(),
        "should fail on the dangling-symlink conflict"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Already exists"),
        "expected fail-fast conflict before the passphrase prompt, got: {stderr}"
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

    let output = cli_command(&get_binary_path())
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_recipient_encrypt_conflict_detected() {
    let test_dir = setup_test_dir("recipient_encrypt_conflict");
    let input_file = test_dir.join("secret.txt");
    let keys_dir = test_dir.join("keys");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&keys_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "secret data");

    let binary = get_binary_path();

    let kg = cli_command(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "keypass")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let first = cli_command(&binary)
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

    let second = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_keygen_conflict_both_keys() {
    let test_dir = setup_test_dir("keygen_conflict_both");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();

    let first = cli_command(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "keypass")
        .output()
        .expect("first keygen");
    assert!(first.status.success());

    let second = cli_command(&binary)
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

    let output = cli_command(&get_binary_path())
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

    let output = cli_command(&get_binary_path())
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_decrypt_does_not_trigger_cli_conflict_check() {
    let test_dir = setup_test_dir("no_cli_conflict_decrypt");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "payload");

    let binary = get_binary_path();

    let enc = cli_command(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "pass")
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    let dec1 = cli_command(&binary)
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
    let dec2 = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_passphrase_encrypt_save_as_without_output_dir() {
    let test_dir = setup_test_dir("passphrase_save_as_no_out");
    let input_file = test_dir.join("data.txt");
    let target = test_dir.join("result.fcr");
    create_test_file(&input_file, "payload");

    let output = cli_command(&get_binary_path())
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_recipient_encrypt_save_as_without_output_dir() {
    let test_dir = setup_test_dir("recipient_save_as_no_out");
    let input_file = test_dir.join("data.txt");
    let keys_dir = test_dir.join("keys");
    let target = test_dir.join("result.fcr");
    fs::create_dir_all(&keys_dir).unwrap();
    create_test_file(&input_file, "payload");

    let binary = get_binary_path();

    let kg = cli_command(&binary)
        .arg("keygen")
        .arg("-o")
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "kp")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let output = cli_command(&binary)
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

    let output = cli_command(&get_binary_path())
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

    // `decrypt` requires `-o` at clap parse time, before the input is read,
    // so an uncreated input path is enough and no Argon2id runs.
    let dec = cli_command(&get_binary_path())
        .arg("decrypt")
        .arg("-i")
        .arg(test_dir.join("nonexistent.fcr"))
        .output()
        .expect("decrypt without -o");
    assert!(!dec.status.success());
}

// ─── Double-encrypt gate ───────────────────────────────────────────────────

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_encrypt_double_encrypt_no_tty_refuses() {
    let test_dir = setup_test_dir("double_encrypt_no_tty");
    let input_file = test_dir.join("data.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let encrypt_dir2 = test_dir.join("encrypted2");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&encrypt_dir2).unwrap();
    create_test_file(&input_file, "double encrypt");

    let binary = get_binary_path();

    let enc = cli_command(&binary)
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
    let again = cli_command(&binary)
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
        stderr.contains("Refusing to encrypt an existing FerroCrypt file"),
        "expected double-encrypt refusal, got: {stderr}"
    );
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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

    let enc = cli_command(&binary)
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

    let again = cli_command(&binary)
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
    let dec_outer = cli_command(&binary)
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

    let dec_inner = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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

    let enc = cli_command(&binary)
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

    let again = cli_command(&binary)
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
        !stderr.contains("Refusing to encrypt an existing FerroCrypt file"),
        "double-encrypt gate should not have fired before the conflict check; got: {stderr}"
    );
}

// ─── Help and version output ───────────────────────────────────────────────

#[test]
fn test_cli_help_flag_lists_subcommands() {
    let output = cli_command(&get_binary_path())
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
    let output = cli_command(&get_binary_path())
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
    let output = cli_command(&get_binary_path())
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
    let output = cli_command(&get_binary_path())
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
    let output = cli_command(&get_binary_path())
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
        "--max-kdf-time-cost",
        "--max-kdf-lanes",
        "--keep-partial",
    ] {
        assert!(stdout.contains(token), "missing {token} in:\n{stdout}");
    }
}

#[test]
fn test_cli_subcommand_help_keygen() {
    let output = cli_command(&get_binary_path())
        .args(["keygen", "--help"])
        .output()
        .expect("keygen --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--output-dir"));
}

#[test]
fn test_cli_subcommand_help_fingerprint() {
    let output = cli_command(&get_binary_path())
        .args(["fingerprint", "--help"])
        .output()
        .expect("fingerprint --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.to_lowercase().contains("public key"));
}

// ─── Exit codes ────────────────────────────────────────────────────────────

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_wrong_passphrase_returns_nonzero() {
    let test_dir = setup_test_dir("cli_exit_wrong_password");
    let input_file = test_dir.join("test.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "content");

    let binary = get_binary_path();
    let enc = cli_command(&binary)
        .args(["encrypt", "-i"])
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "right")
        .output()
        .expect("encrypt");
    assert_eq!(enc.status.code(), Some(0));

    let dec = cli_command(&binary)
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
    let output = cli_command(&get_binary_path())
        .args(["encrypt", "--not-a-real-flag"])
        .output()
        .expect("bad args");
    assert_ne!(output.status.code(), Some(0));
}

#[test]
fn test_cli_missing_required_input_returns_nonzero() {
    let output = cli_command(&get_binary_path())
        .arg("encrypt")
        .output()
        .expect("missing args");
    assert_ne!(output.status.code(), Some(0));
}

// ─── Empty inputs ──────────────────────────────────────────────────────────

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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
    let enc = cli_command(&binary)
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

    let dec = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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
    let kg = cli_command(&binary)
        .args(["gen", "-o"])
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let enc = cli_command(&binary)
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

    let dec = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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
    let enc = cli_command(&binary)
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

    let dec = cli_command(&binary)
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

    let output = cli_command(&get_binary_path())
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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
    let kg = cli_command(&binary)
        .args(["gen", "-o"])
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key")
        .output()
        .expect("keygen");
    assert!(kg.status.success());
    let enc = cli_command(&binary)
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

    let dec = cli_command(&binary)
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

    let output = cli_command(&get_binary_path())
        .arg("fp")
        .arg(&bad_key)
        .output()
        .expect("fp");
    assert!(!output.status.success());
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_fingerprint_on_private_key_fails() {
    let test_dir = setup_test_dir("cli_fp_on_private");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let binary = get_binary_path();
    let kg = cli_command(&binary)
        .args(["gen", "-o"])
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key")
        .output()
        .expect("keygen");
    assert!(kg.status.success());

    let output = cli_command(&binary)
        .arg("fp")
        .arg(keys_dir.join("private.key"))
        .output()
        .expect("fp");
    assert!(!output.status.success());
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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
    let kg = cli_command(&binary)
        .args(["gen", "-o"])
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "key")
        .output()
        .expect("keygen");
    assert!(kg.status.success());
    let enc = cli_command(&binary)
        .args(["encrypt", "-i"])
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    let dec = cli_command(&binary)
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
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
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
    let kg = cli_command(&binary)
        .args(["gen", "-o"])
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "kp")
        .output()
        .expect("keygen");
    assert!(kg.status.success());
    let enc = cli_command(&binary)
        .args(["encrypt", "-i"])
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .arg("-k")
        .arg(keys_dir.join("public.key"))
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    let dec = cli_command(&binary)
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

/// Substring of the warning `test_fast_kdf_override` prints when the
/// fast-Argon2id override actually fires. Mirrors the wording in
/// `ferrocrypt-cli/src/cli.rs`; keep in sync.
const FAST_KDF_OVERRIDE_WARNING: &str = "using fast Argon2id parameters";

/// Guards the premise the release-cli lane depends on: in a release build
/// the `FERROCRYPT_INTERNAL_TEST_FAST_KDF` override must be compiled out,
/// so the lane genuinely exercises production Argon2id. `cli_command`
/// sets the env var on every invocation, so the warning appears if and
/// only if the override branch is live. A misconfigured
/// `[profile.release] debug-assertions = true` (the exact hazard
/// `cli.rs` warns about) would leave the branch live in release, the
/// warning would appear, and this test would fail — instead of the lane
/// silently passing on fast KDF while shipped binaries honour a
/// strength-reducing env var. The debug half also pins that the override
/// really does fire in debug, so the fast tests are fast for the right
/// reason.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_fast_kdf_override_state_matches_build_profile() {
    let test_dir = setup_test_dir("cli_fast_kdf_override_state");
    let input_file = test_dir.join("in.txt");
    let encrypt_dir = test_dir.join("encrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    create_test_file(&input_file, "premise-check");

    let binary = get_binary_path();
    let out = cli_command(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "b4-premise-passphrase")
        .output()
        .expect("Failed to execute encrypt command");
    assert!(
        out.status.success(),
        "Encryption failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let warned = stderr.contains(FAST_KDF_OVERRIDE_WARNING);

    if cfg!(debug_assertions) {
        assert!(
            warned,
            "debug build must apply the fast-KDF override (expected the override \
             warning on stderr, so the fast CLI tests are fast for the right \
             reason); stderr: {stderr}"
        );
    } else {
        assert!(
            !warned,
            "release build must NOT apply the fast-KDF override: the override \
             branch should be compiled out, otherwise the release-cli lane is \
             testing fast KDF, not production Argon2id. Check that \
             `[profile.release] debug-assertions` is not enabled; stderr: {stderr}"
        );
    }
}

/// Param-sensitive complement to the warning check above: proves the
/// on-disk file the release binary writes actually carries production
/// KDF strength, not just that the warning is absent. Encrypt produces a
/// passphrase `.fcr` whose Argon2id `mem_cost` is 19 MiB in a debug
/// (fast-override) build and 1 GiB in a release build. Decrypt with a
/// 128 MiB memory cap — above fast, below production — then succeeds in
/// debug and is rejected before Argon2id in release. A release build that
/// SUCCEEDS here wrote a fast-KDF file, meaning the override leaked into
/// release; a debug build that is REJECTED means the override did not
/// apply.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_encrypted_file_kdf_strength_matches_build_profile() {
    let test_dir = setup_test_dir("cli_kdf_strength_profile");
    let input_file = test_dir.join("in.txt");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_file, "kdf-strength-probe");

    let binary = get_binary_path();
    let passphrase = "b4-kdf-strength-passphrase";
    let enc = cli_command(&binary)
        .arg("encrypt")
        .arg("-i")
        .arg(&input_file)
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", passphrase)
        .output()
        .expect("Failed to execute encrypt command");
    assert!(
        enc.status.success(),
        "Encryption failed: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    // 128 MiB sits between the fast override (19 MiB) and the production
    // default (1 GiB). --max-kdf-memory is in MiB and its cap check runs
    // before Argon2id, so the release rejection costs no KDF work.
    let dec = cli_command(&binary)
        .arg("decrypt")
        .arg("-i")
        .arg(encrypt_dir.join("in.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .arg("--max-kdf-memory")
        .arg("128")
        .env("FERROCRYPT_PASSPHRASE", passphrase)
        .output()
        .expect("Failed to execute decrypt command");
    let stderr = String::from_utf8_lossy(&dec.stderr);

    if cfg!(debug_assertions) {
        assert!(
            dec.status.success(),
            "a 19 MiB fast-KDF file must decrypt under a 128 MiB cap; stderr: {stderr}"
        );
    } else {
        assert!(
            !dec.status.success(),
            "a production 1 GiB-KDF file must be rejected by a 128 MiB cap. If this \
             decrypt SUCCEEDED, the release binary wrote a fast-KDF file and the \
             release-cli lane is not testing production Argon2id."
        );
        assert!(
            stderr.contains("over limit"),
            "expected a KDF memory-cap rejection; stderr: {stderr}"
        );
    }
}

/// The no-subcommand interactive REPL had no end-to-end coverage. On piped
/// (non-TTY) stdin rustyline degrades to line reading, so `exit` drives a
/// clean shutdown. Dropping stdin also sends EOF, so the process can never
/// hang waiting for input.
#[test]
fn test_cli_repl_exit_returns_success() {
    use std::io::Write;
    let binary = get_binary_path();
    let mut child = cli_command(&binary)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn repl");
    {
        let mut stdin = child.stdin.take().expect("repl stdin");
        stdin.write_all(b"exit\n").expect("write to repl");
    }
    let out = child.wait_with_output().expect("repl output");
    assert!(
        out.status.success(),
        "REPL `exit` must return success; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A failing command inside the REPL prints an error but must NOT change the
/// process exit status — the REPL keeps running and a later `exit` leaves
/// cleanly. This pins the "command failure does not fail the process"
/// contract that no test covered.
#[test]
fn test_cli_repl_command_failure_does_not_change_exit_status() {
    use std::io::Write;
    let binary = get_binary_path();
    let mut child = cli_command(&binary)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn repl");
    {
        let mut stdin = child.stdin.take().expect("repl stdin");
        stdin
            .write_all(b"fingerprint /does/not/exist\nexit\n")
            .expect("write to repl");
    }
    let out = child.wait_with_output().expect("repl output");
    assert!(
        out.status.success(),
        "REPL must exit 0 even after a failed command; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.to_lowercase().contains("error")
            || combined.to_lowercase().contains("missing")
            || combined.to_lowercase().contains("not a"),
        "the failed REPL command must surface an error; got: {combined}"
    );
}

/// Crash safety: killing an encrypt mid-stream must never leave a partial
/// committed `.fcr`. Ported from `stress_test.sh` phase 22 to a Rust
/// integration test so it runs on all three OSes — Windows had no crash
/// coverage anywhere before this. `Child::kill()` is `SIGKILL` on Unix and
/// `TerminateProcess` on Windows, so both platforms exercise the same
/// invariant: after each kill the output name is either absent (the process
/// died before the atomic rename) or a complete file that decrypts back to
/// the original — never a truncated or blended file. Public-key mode keeps
/// Argon2id off the encrypt path so the kill lands in the streaming window,
/// not the KDF. The pass/fail result is scheduling-independent: it holds
/// regardless of where each kill happens to land.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_sigkill_during_encrypt_never_commits_partial() {
    use std::thread::sleep;
    use std::time::Duration;

    let test_dir = setup_test_dir("cli_crash_encrypt");
    let keys_dir = test_dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();
    let binary = get_binary_path();

    let kg = cli_command(&binary)
        .args(["keygen", "-o"])
        .arg(&keys_dir)
        .env("FERROCRYPT_PASSPHRASE", "crash-test-passphrase")
        .output()
        .expect("keygen");
    assert!(
        kg.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&kg.stderr)
    );
    let pub_key = keys_dir.join("public.key");
    let priv_key = keys_dir.join("private.key");

    // Large enough that encryption takes long enough to interrupt in the
    // streaming window.
    let input = test_dir.join("big.bin");
    let payload = vec![0xC7u8; 32 * 1024 * 1024];
    fs::write(&input, &payload).unwrap();

    for i in 0..10u64 {
        let out_dir = test_dir.join(format!("enc_{i}"));
        fs::create_dir_all(&out_dir).unwrap();
        let mut child = cli_command(&binary)
            .args(["encrypt", "-i"])
            .arg(&input)
            .arg("-o")
            .arg(&out_dir)
            .arg("-k")
            .arg(&pub_key)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn encrypt");

        // Vary the delay so the kill lands at different stream positions.
        sleep(Duration::from_millis(2 + i * 6));
        let _ = child.kill();
        let _ = child.wait();

        // The committed name is either absent or a complete, decryptable file.
        // A leftover temporary staging file under `out_dir` is the expected
        // artifact of an interrupted run and is not the committed name.
        let committed = out_dir.join("big.fcr");
        if committed.exists() {
            let dec_dir = test_dir.join(format!("dec_{i}"));
            fs::create_dir_all(&dec_dir).unwrap();
            let dec = cli_command(&binary)
                .args(["decrypt", "-i"])
                .arg(&committed)
                .arg("-o")
                .arg(&dec_dir)
                .arg("-K")
                .arg(&priv_key)
                .env("FERROCRYPT_PASSPHRASE", "crash-test-passphrase")
                .output()
                .expect("decrypt");
            assert!(
                dec.status.success(),
                "a committed .fcr must decrypt cleanly (iteration {i}): {}",
                String::from_utf8_lossy(&dec.stderr)
            );
            assert_eq!(
                fs::read(dec_dir.join("big.bin")).unwrap(),
                payload,
                "committed .fcr decrypted to the wrong content (iteration {i})"
            );
        }
    }
}

/// `-i .` is a natural thing to type from inside the directory being
/// encrypted, and `.` carries no name of its own, so the archive takes the
/// name of the directory it resolves to. The round trip restores that
/// directory under its real name.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_encrypt_current_directory_input() {
    let test_dir = setup_test_dir("cli_current_dir_input");
    let input_dir = test_dir.join("photos");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&input_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    create_test_file(&input_dir.join("holiday.txt"), "Sea and sun");

    // The child runs with `input_dir` as its working directory, so the
    // output paths it is given must not be relative to this process.
    let encrypt_dir = fs::canonicalize(&encrypt_dir).unwrap();
    let decrypt_dir = fs::canonicalize(&decrypt_dir).unwrap();

    let binary = get_binary_path();

    let encrypt_output = cli_command(&binary)
        .current_dir(&input_dir)
        .args(["encrypt", "-i", "."])
        .arg("-o")
        .arg(&encrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "current_dir_password")
        .output()
        .expect("Failed to execute encrypt command");

    assert!(
        encrypt_output.status.success(),
        "encrypting `.` must succeed: {}",
        String::from_utf8_lossy(&encrypt_output.stderr)
    );
    assert!(encrypt_dir.join("photos.fcr").exists());

    let decrypt_output = cli_command(&binary)
        .args(["decrypt", "-i"])
        .arg(encrypt_dir.join("photos.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .env("FERROCRYPT_PASSPHRASE", "current_dir_password")
        .output()
        .expect("Failed to execute decrypt command");

    assert!(decrypt_output.status.success());
    assert_eq!(
        fs::read_to_string(decrypt_dir.join("photos/holiday.txt")).unwrap(),
        "Sea and sun"
    );
}

/// The archive caps reach the library from both subcommands: a cap below
/// the tree's entry count refuses the work on either side, and a matching
/// pair of raised caps completes the round trip. Guards the wiring, not the
/// cap rule itself, which the library tests own.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "full Argon2id; see file-level note")]
fn test_cli_archive_entry_cap_flag() {
    let test_dir = setup_test_dir("cli_archive_entry_cap");
    let input_dir = test_dir.join("tree");
    let encrypt_dir = test_dir.join("encrypted");
    let decrypt_dir = test_dir.join("decrypted");

    fs::create_dir_all(&input_dir).unwrap();
    fs::create_dir_all(&encrypt_dir).unwrap();
    fs::create_dir_all(&decrypt_dir).unwrap();
    // Three entries: the root directory and two files.
    create_test_file(&input_dir.join("one.txt"), "1");
    create_test_file(&input_dir.join("two.txt"), "2");

    let binary = get_binary_path();

    let too_low = cli_command(&binary)
        .args(["encrypt", "-i"])
        .arg(&input_dir)
        .arg("-o")
        .arg(&encrypt_dir)
        .args(["--max-archive-entries", "2"])
        .env("FERROCRYPT_PASSPHRASE", "entry_cap_password")
        .output()
        .expect("Failed to execute encrypt command");

    assert!(!too_low.status.success());
    assert!(
        String::from_utf8_lossy(&too_low.stderr).contains("Too many archive entries"),
        "stderr: {}",
        String::from_utf8_lossy(&too_low.stderr)
    );
    assert!(!encrypt_dir.join("tree.fcr").exists());

    let raised = cli_command(&binary)
        .args(["encrypt", "-i"])
        .arg(&input_dir)
        .arg("-o")
        .arg(&encrypt_dir)
        .args(["--max-archive-entries", "3"])
        .env("FERROCRYPT_PASSPHRASE", "entry_cap_password")
        .output()
        .expect("Failed to execute encrypt command");

    assert!(
        raised.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&raised.stderr)
    );

    let decrypt_too_low = cli_command(&binary)
        .args(["decrypt", "-i"])
        .arg(encrypt_dir.join("tree.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .args(["--max-archive-entries", "2"])
        .env("FERROCRYPT_PASSPHRASE", "entry_cap_password")
        .output()
        .expect("Failed to execute decrypt command");

    assert!(!decrypt_too_low.status.success());
    assert!(
        String::from_utf8_lossy(&decrypt_too_low.stderr).contains("Too many archive entries"),
        "stderr: {}",
        String::from_utf8_lossy(&decrypt_too_low.stderr)
    );

    let decrypt_ok = cli_command(&binary)
        .args(["decrypt", "-i"])
        .arg(encrypt_dir.join("tree.fcr"))
        .arg("-o")
        .arg(&decrypt_dir)
        .args(["--max-archive-entries", "3"])
        .env("FERROCRYPT_PASSPHRASE", "entry_cap_password")
        .output()
        .expect("Failed to execute decrypt command");

    assert!(
        decrypt_ok.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&decrypt_ok.stderr)
    );
    assert_eq!(
        fs::read_to_string(decrypt_dir.join("tree/one.txt")).unwrap(),
        "1"
    );
}

#[ctor::dtor]
fn cleanup() {
    cleanup_test_workspace();
}
