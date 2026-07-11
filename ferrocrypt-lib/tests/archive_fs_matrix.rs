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
//! These are deliberately lightweight: a single-file round-trip, a
//! small directory-tree round-trip, and key-pair generation. The matrix
//! lane is meant to catch filesystem-quirk regressions (case-folding,
//! missing rwx bits, short-write semantics on FAT-family filesystems) —
//! not to re-run the full suite. Substantial coverage already lives in
//! the in-tree `archive::*::tests` modules.

mod common;

use std::fs;

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{CryptoError, validate_private_key_file, validate_public_key_file};
use ferrocrypt_test_support::fs_matrix_tempdir;

use common::{generate_key_pair, passphrase_auto};

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

#[test]
#[ignore = "fs-matrix"]
fn fs_matrix_generate_key_pair() -> Result<(), CryptoError> {
    let tmp = fs_matrix_tempdir().expect("create fs-matrix tempdir");
    let keys_dir = tmp.path().join("keys");
    fs::create_dir_all(&keys_dir)?;

    let passphrase = SecretString::from("matrix-test".to_string());
    let outcome = generate_key_pair(&passphrase, &keys_dir, |_| {})?;

    validate_private_key_file(&outcome.private_key_path)?;
    validate_public_key_file(&outcome.public_key_path)?;

    let mut names = fs::read_dir(&keys_dir)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    assert_eq!(
        names,
        vec![
            std::ffi::OsString::from("private.key"),
            std::ffi::OsString::from("public.key"),
        ],
        "key generation must leave only the two final key files"
    );
    Ok(())
}

/// No-clobber holds on the matrix filesystem: a second decrypt into the
/// same output directory must reject because the output name is taken,
/// and the first output must survive unchanged. The rejection comes
/// from decode's occupancy preflight (the final path must not exist
/// before extraction), which runs before any promotion primitive; the
/// promotion fallback's own refusal path is covered by the
/// `via_claim_*` unit tests in `archive::platform`.
#[test]
#[ignore = "fs-matrix"]
fn fs_matrix_second_decrypt_rejects_existing_output() -> Result<(), CryptoError> {
    let tmp = fs_matrix_tempdir().expect("create fs-matrix tempdir");
    let input_dir = tmp.path().join("input");
    let encrypt_dir = tmp.path().join("encrypted");
    let decrypt_dir = tmp.path().join("decrypted");
    fs::create_dir_all(&input_dir)?;
    fs::create_dir_all(&encrypt_dir)?;
    fs::create_dir_all(&decrypt_dir)?;

    let input = input_dir.join("payload.bin");
    fs::write(&input, b"no-clobber matrix payload")?;

    let passphrase = SecretString::from("matrix-test".to_string());

    passphrase_auto(&input, &encrypt_dir, &passphrase, None, None, |_| {})?;
    let fcr = encrypt_dir.join("payload.fcr");
    let decrypted = passphrase_auto(&fcr, &decrypt_dir, &passphrase, None, None, |_| {})?;
    assert_eq!(fs::read(&decrypted)?, b"no-clobber matrix payload");

    let err = passphrase_auto(&fcr, &decrypt_dir, &passphrase, None, None, |_| {})
        .expect_err("second decrypt into an occupied output name must reject");
    let rendered = format!("{err}").to_lowercase();
    assert!(
        rendered.contains("already exists"),
        "expected an already-exists rejection, got: {err}"
    );
    assert_eq!(
        fs::read(&decrypted)?,
        b"no-clobber matrix payload",
        "first output must survive the refused second decrypt"
    );
    Ok(())
}
