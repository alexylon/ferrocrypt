//! Golden fixture tests for version compatibility.
//!
//! These tests verify that the current code can still decrypt files and read keys
//! produced by previously released format versions. The fixtures are read-only
//! artifacts committed once and never regenerated — they represent the format
//! as-shipped.
//!
//! ## Fixture discipline
//!
//! - Fixtures must never be regenerated without explicit justification.
//! - Any change to committed fixtures must be reviewed and documented in
//!   the changelog / release notes.
//! - The `generate_*_fixtures` tests are `#[ignore]` and must only be run
//!   once during initial fixture creation.

use std::fs;
use std::path::Path;

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    CryptoError, hybrid_auto, public_key_fingerprint, symmetric_auto, validate_secret_key_file,
};

const FIXTURE_DIR: &str = "tests/fixtures";
const SYM_PASSWORD: &str = "fixture-password-v3";
const KEY_PASSWORD_V4: &str = "fixture-key-v4";

// ─── v3 symmetric fixtures (still supported) ─────────────────────────────

#[test]
fn test_v3_symmetric_fixture_decrypts() -> Result<(), CryptoError> {
    let decrypt_dir = tempfile::TempDir::new().unwrap();
    let passphrase = SecretString::from(SYM_PASSWORD.to_string());
    let encrypted = Path::new(FIXTURE_DIR).join("v3/symmetric/hello.fcr");

    let result = symmetric_auto(
        &encrypted,
        decrypt_dir.path(),
        &passphrase,
        None,
        None,
        |_| {},
    )?;
    assert!(result.exists());

    let expected = fs::read_to_string(Path::new(FIXTURE_DIR).join("v3/symmetric/hello.txt"))?;
    let actual = fs::read_to_string(decrypt_dir.path().join("hello.txt"))?;
    assert_eq!(expected, actual);
    Ok(())
}

#[test]
fn test_v3_symmetric_binary_fixture_decrypts() -> Result<(), CryptoError> {
    let decrypt_dir = tempfile::TempDir::new().unwrap();
    let passphrase = SecretString::from(SYM_PASSWORD.to_string());
    let encrypted = Path::new(FIXTURE_DIR).join("v3/symmetric/data.fcr");

    symmetric_auto(
        &encrypted,
        decrypt_dir.path(),
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    let expected: Vec<u8> = (0..=255).cycle().take(1024).collect();
    let actual = fs::read(decrypt_dir.path().join("data.bin"))?;
    assert_eq!(expected, actual);
    Ok(())
}

#[test]
fn test_v3_symmetric_directory_fixture_decrypts() -> Result<(), CryptoError> {
    let decrypt_dir = tempfile::TempDir::new().unwrap();
    let passphrase = SecretString::from(SYM_PASSWORD.to_string());
    let encrypted = Path::new(FIXTURE_DIR).join("v3/symmetric/testdir.fcr");

    symmetric_auto(
        &encrypted,
        decrypt_dir.path(),
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    let a = fs::read_to_string(decrypt_dir.path().join("testdir/a.txt"))?;
    let b = fs::read_to_string(decrypt_dir.path().join("testdir/sub/b.txt"))?;
    assert_eq!(a, "file a");
    assert_eq!(b, "file b");
    Ok(())
}

// ─── v2 key file fixtures (still supported with v3 key reader) ───────────
// These live under v3/hybrid/ because that was the release directory.
// The key files themselves are key-format v2 (same byte layout as v3).

#[test]
fn test_v2_private_key_fixture_validates() -> Result<(), CryptoError> {
    let private_key = Path::new(FIXTURE_DIR).join("v3/hybrid/private.key");
    validate_secret_key_file(&private_key)
}

#[test]
fn test_v2_public_key_fingerprint_stable() -> Result<(), CryptoError> {
    let public_key = Path::new(FIXTURE_DIR).join("v3/hybrid/public.key");
    let fp = public_key_fingerprint(&public_key)?;
    assert_eq!(fp.len(), 64);

    // Regression: fingerprint must not change across releases
    let expected_fp = fs::read_to_string(Path::new(FIXTURE_DIR).join("v3/hybrid/fingerprint.txt"))?;
    assert_eq!(fp, expected_fp.trim());
    Ok(())
}

// ─── v4 hybrid fixtures ──────────────────────────────────────────────────

#[test]
fn test_v4_hybrid_fixture_decrypts() -> Result<(), CryptoError> {
    let decrypt_dir = tempfile::TempDir::new().unwrap();
    let passphrase = SecretString::from(KEY_PASSWORD_V4.to_string());
    let encrypted = Path::new(FIXTURE_DIR).join("v4/hybrid/hello.fcr");
    let private_key = Path::new(FIXTURE_DIR).join("v4/hybrid/private.key");

    let result = hybrid_auto(
        &encrypted,
        decrypt_dir.path(),
        &private_key,
        &passphrase,
        None,
        None,
        |_| {},
    )?;
    assert!(result.exists());

    let expected = fs::read_to_string(Path::new(FIXTURE_DIR).join("v4/hybrid/hello.txt"))?;
    let actual = fs::read_to_string(decrypt_dir.path().join("hello.txt"))?;
    assert_eq!(expected, actual);
    Ok(())
}

#[test]
fn test_v4_hybrid_binary_fixture_decrypts() -> Result<(), CryptoError> {
    let decrypt_dir = tempfile::TempDir::new().unwrap();
    let passphrase = SecretString::from(KEY_PASSWORD_V4.to_string());
    let encrypted = Path::new(FIXTURE_DIR).join("v4/hybrid/data.fcr");
    let private_key = Path::new(FIXTURE_DIR).join("v4/hybrid/private.key");

    hybrid_auto(
        &encrypted,
        decrypt_dir.path(),
        &private_key,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    let expected: Vec<u8> = (0..=255).cycle().take(1024).collect();
    let actual = fs::read(decrypt_dir.path().join("data.bin"))?;
    assert_eq!(expected, actual);
    Ok(())
}

#[test]
fn test_v4_hybrid_directory_fixture_decrypts() -> Result<(), CryptoError> {
    let decrypt_dir = tempfile::TempDir::new().unwrap();
    let passphrase = SecretString::from(KEY_PASSWORD_V4.to_string());
    let encrypted = Path::new(FIXTURE_DIR).join("v4/hybrid/testdir.fcr");
    let private_key = Path::new(FIXTURE_DIR).join("v4/hybrid/private.key");

    hybrid_auto(
        &encrypted,
        decrypt_dir.path(),
        &private_key,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    let a = fs::read_to_string(decrypt_dir.path().join("testdir/a.txt"))?;
    let b = fs::read_to_string(decrypt_dir.path().join("testdir/sub/b.txt"))?;
    assert_eq!(a, "file a");
    assert_eq!(b, "file b");
    Ok(())
}

#[test]
fn test_v4_public_key_fingerprint_stable() -> Result<(), CryptoError> {
    let public_key = Path::new(FIXTURE_DIR).join("v4/hybrid/public.key");
    let fp = public_key_fingerprint(&public_key)?;
    assert_eq!(fp.len(), 64);

    let expected_fp = fs::read_to_string(Path::new(FIXTURE_DIR).join("v4/hybrid/fingerprint.txt"))?;
    assert_eq!(fp, expected_fp.trim());
    Ok(())
}

// ─── Fixture generators (run once, then commit fixtures) ─────────────────

/// Generates the v3 golden fixtures. Run once with:
///   cargo test -p ferrocrypt generate_v3_fixtures -- --ignored --test-threads=1
#[test]
#[ignore]
fn generate_v3_fixtures() -> Result<(), CryptoError> {
    let base = Path::new(FIXTURE_DIR).join("v3");

    // --- Symmetric fixtures ---
    let sym_dir = base.join("symmetric");
    fs::create_dir_all(&sym_dir)?;
    let passphrase = SecretString::from(SYM_PASSWORD.to_string());

    // Text file
    let plaintext = "Hello from FerroCrypt v3 symmetric fixture.\n";
    let hello_txt = sym_dir.join("hello.txt");
    fs::write(&hello_txt, plaintext)?;
    symmetric_auto(&hello_txt, &sym_dir, &passphrase, None, None, |_| {})?;
    assert!(sym_dir.join("hello.fcr").exists());

    // Binary file
    let binary_data: Vec<u8> = (0..=255).cycle().take(1024).collect();
    let bin_file = sym_dir.join("data.bin");
    fs::write(&bin_file, &binary_data)?;
    symmetric_auto(&bin_file, &sym_dir, &passphrase, None, None, |_| {})?;
    assert!(sym_dir.join("data.fcr").exists());

    // Directory
    let dir_fixture = sym_dir.join("testdir");
    let sub_dir = dir_fixture.join("sub");
    fs::create_dir_all(&sub_dir)?;
    fs::write(dir_fixture.join("a.txt"), "file a")?;
    fs::write(sub_dir.join("b.txt"), "file b")?;
    symmetric_auto(&dir_fixture, &sym_dir, &passphrase, None, None, |_| {})?;
    assert!(sym_dir.join("testdir.fcr").exists());

    println!("v3 symmetric fixtures generated at {}", base.display());
    Ok(())
}

/// Generates the v4 hybrid golden fixtures. Run once with:
///   cargo test -p ferrocrypt generate_v4_hybrid_fixtures -- --ignored --test-threads=1
#[test]
#[ignore]
fn generate_v4_hybrid_fixtures() -> Result<(), CryptoError> {
    let base = Path::new(FIXTURE_DIR).join("v4");
    let hyb_dir = base.join("hybrid");
    fs::create_dir_all(&hyb_dir)?;

    let key_pass = SecretString::from(KEY_PASSWORD_V4.to_string());
    ferrocrypt::generate_key_pair(&key_pass, &hyb_dir, |_| {})?;
    assert!(hyb_dir.join("public.key").exists());
    assert!(hyb_dir.join("private.key").exists());

    let empty_pass = SecretString::from("".to_string());
    let plaintext = "Hello from FerroCrypt v4 hybrid fixture.\n";

    // Text file
    let hello_txt = hyb_dir.join("hello.txt");
    fs::write(&hello_txt, plaintext)?;
    hybrid_auto(
        &hello_txt,
        &hyb_dir,
        hyb_dir.join("public.key"),
        &empty_pass,
        None,
        None,
        |_| {},
    )?;
    assert!(hyb_dir.join("hello.fcr").exists());

    // Binary file
    let binary_data: Vec<u8> = (0..=255).cycle().take(1024).collect();
    let bin_file = hyb_dir.join("data.bin");
    fs::write(&bin_file, &binary_data)?;
    hybrid_auto(
        &bin_file,
        &hyb_dir,
        hyb_dir.join("public.key"),
        &empty_pass,
        None,
        None,
        |_| {},
    )?;
    assert!(hyb_dir.join("data.fcr").exists());

    // Directory
    let dir_fixture = hyb_dir.join("testdir");
    let sub_dir = dir_fixture.join("sub");
    fs::create_dir_all(&sub_dir)?;
    fs::write(dir_fixture.join("a.txt"), "file a")?;
    fs::write(sub_dir.join("b.txt"), "file b")?;
    hybrid_auto(
        &dir_fixture,
        &hyb_dir,
        hyb_dir.join("public.key"),
        &empty_pass,
        None,
        None,
        |_| {},
    )?;
    assert!(hyb_dir.join("testdir.fcr").exists());

    // Save fingerprint for regression
    let fp = public_key_fingerprint(hyb_dir.join("public.key"))?;
    fs::write(hyb_dir.join("fingerprint.txt"), &fp)?;

    println!("v4 hybrid fixtures generated at {}", base.display());
    Ok(())
}
