//! Filesystem-matrix smoke tests. Each test is `#[ignore = "fs-matrix"]`,
//! so default `cargo test` skips the whole file. The matrix CI lane (see
//! `.github/workflows/rust.yml::fs_matrix_*`) mounts a non-default
//! filesystem (case-sensitive APFS, btrfs, exFAT, …), points
//! `FERROCRYPT_FS_MATRIX_DIR` at the mount, and runs:
//!
//! ```text
//! cargo test --test archive_fs_matrix -- --ignored
//! ```
//!
//! Each test sources its tempdir from
//! [`ferrocrypt_test_support::fs_matrix_tempdir`], which honours the env
//! var when set and falls back to the system temp dir otherwise. Running
//! these tests outside a matrix lane (with the env var unset) still works
//! and just exercises the default filesystem — useful for local sanity
//! checking before shipping the YAML lane.
//!
//! These are deliberately lightweight: a single file round-trip and a
//! small directory tree round-trip. The matrix lane is meant to catch
//! filesystem-quirk regressions (case-folding, missing rwx bits,
//! short-write semantics on FAT-family filesystems) — not to re-run the
//! full suite. Substantial coverage already lives in the in-tree
//! `archive::*::tests` modules.

mod common;

use std::fs;

use ferrocrypt::CryptoError;
use ferrocrypt::secrecy::SecretString;
use ferrocrypt_test_support::fs_matrix_tempdir;

use common::passphrase_auto;

#[test]
#[ignore = "fs-matrix"]
fn fs_matrix_round_trip_single_file() -> Result<(), CryptoError> {
    let tmp = fs_matrix_tempdir().expect("create fs-matrix tempdir");
    let input_dir = tmp.path().join("input");
    let encrypt_dir = tmp.path().join("encrypted");
    let decrypt_dir = tmp.path().join("decrypted");
    fs::create_dir_all(&input_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let input = input_dir.join("payload.bin");
    let original: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    fs::write(&input, &original)?;

    let passphrase = SecretString::from("matrix-test".to_string());

    passphrase_auto(&input, &encrypt_dir, &passphrase, None, None, |_| {})?;
    let decrypted = passphrase_auto(
        encrypt_dir.join("payload.fcr"),
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    let roundtripped = fs::read(&decrypted)?;
    assert_eq!(original, roundtripped, "byte mismatch on {decrypted:?}");
    Ok(())
}

#[test]
#[ignore = "fs-matrix"]
fn fs_matrix_round_trip_directory() -> Result<(), CryptoError> {
    let tmp = fs_matrix_tempdir().expect("create fs-matrix tempdir");
    let input_dir = tmp.path().join("input").join("tree");
    let encrypt_dir = tmp.path().join("encrypted");
    let decrypt_dir = tmp.path().join("decrypted");
    fs::create_dir_all(&input_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    fs::write(input_dir.join("a.txt"), b"alpha")?;
    fs::write(input_dir.join("b.txt"), b"bravo")?;
    fs::create_dir_all(input_dir.join("nested"))?;
    fs::write(input_dir.join("nested").join("c.txt"), b"charlie")?;

    let passphrase = SecretString::from("matrix-test".to_string());

    passphrase_auto(&input_dir, &encrypt_dir, &passphrase, None, None, |_| {})?;
    let decrypted = passphrase_auto(
        encrypt_dir.join("tree.fcr"),
        &decrypt_dir,
        &passphrase,
        None,
        None,
        |_| {},
    )?;

    assert!(decrypted.is_dir(), "expected directory at {decrypted:?}");
    assert_eq!(fs::read(decrypted.join("a.txt"))?, b"alpha");
    assert_eq!(fs::read(decrypted.join("b.txt"))?, b"bravo");
    assert_eq!(
        fs::read(decrypted.join("nested").join("c.txt"))?,
        b"charlie"
    );
    Ok(())
}
