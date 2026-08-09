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

    let passphrase = "matrix-test";

    passphrase_auto(&input, &encrypt_dir, passphrase, None, None, |_| {})?;
    let decrypted = passphrase_auto(
        encrypt_dir.join("payload.fcr"),
        &decrypt_dir,
        passphrase,
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

    let passphrase = "matrix-test";

    passphrase_auto(&input_dir, &encrypt_dir, passphrase, None, None, |_| {})?;
    let decrypted = passphrase_auto(
        encrypt_dir.join("tree.fcr"),
        &decrypt_dir,
        passphrase,
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

    let passphrase = "matrix-test";
    let outcome = generate_key_pair(passphrase, &keys_dir, |_| {})?;

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

    let passphrase = "matrix-test";

    passphrase_auto(&input, &encrypt_dir, passphrase, None, None, |_| {})?;
    let fcr = encrypt_dir.join("payload.fcr");
    let decrypted = passphrase_auto(&fcr, &decrypt_dir, passphrase, None, None, |_| {})?;
    assert_eq!(fs::read(&decrypted)?, b"no-clobber matrix payload");

    let err = passphrase_auto(&fcr, &decrypt_dir, passphrase, None, None, |_| {})
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

/// The case-sensitive-APFS lane exists to reach the ASCII-case collision
/// check with two files that genuinely coexist. On a case-sensitive volume,
/// `README.txt` and `readme.txt` are distinct files, so the archive layer
/// must reject the pair as an ASCII-case-insensitive collision before writing
/// any output. On a case-insensitive volume the second write lands on the same
/// file, so only one entry exists and encryption succeeds — this test probes
/// the volume and asserts whichever outcome is representable there.
#[test]
#[ignore = "fs-matrix"]
fn fs_matrix_case_collision_rejected_where_representable() -> Result<(), CryptoError> {
    let tmp = fs_matrix_tempdir().expect("create fs-matrix tempdir");

    // Probe case sensitivity: write to two case-only-different names; if the
    // uppercase content survives the lowercase write, they are distinct files.
    let probe = tmp.path().join("probe");
    fs::create_dir_all(&probe)?;
    fs::write(probe.join("CASEPROBE"), b"upper")?;
    fs::write(probe.join("caseprobe"), b"lower")?;
    let case_sensitive = fs::read(probe.join("CASEPROBE"))? == b"upper";

    let src = tmp.path().join("input").join("tree");
    fs::create_dir_all(&src)?;
    fs::write(src.join("README.txt"), b"one")?;
    fs::write(src.join("readme.txt"), b"two")?;

    let enc = tmp.path().join("enc");
    fs::create_dir_all(&enc)?;
    let passphrase = "matrix-test";
    let result = passphrase_auto(&src, &enc, passphrase, None, None, |_| {});

    if case_sensitive {
        let err = result.expect_err("case-colliding names must reject on a case-sensitive volume");
        assert!(
            matches!(err, CryptoError::InvalidArchiveTree { .. }),
            "expected InvalidArchiveTree for an ASCII-case collision, got {err:?}"
        );
    } else {
        result.expect("a single-entry tree must encrypt on a case-insensitive volume");
    }
    Ok(())
}

/// FAT-family lanes exist to prove extraction — which chmods every file — does
/// not error on a volume where the chmod is structurally a no-op. This probes
/// whether the volume preserves Unix mode bits: where it does (ext4, APFS,
/// btrfs) the round trip must restore the exact modes; where it does not
/// (exFAT, FAT32) the round trip must still succeed and preserve content.
#[cfg(unix)]
#[test]
#[ignore = "fs-matrix"]
fn fs_matrix_mode_bits_preserved_or_noop() -> Result<(), CryptoError> {
    use std::os::unix::fs::PermissionsExt;

    let tmp = fs_matrix_tempdir().expect("create fs-matrix tempdir");

    // Probe whether this volume preserves Unix permission bits.
    let mode_probe = tmp.path().join("mode_probe");
    fs::write(&mode_probe, b"x")?;
    fs::set_permissions(&mode_probe, fs::Permissions::from_mode(0o600))?;
    let preserves_modes = fs::metadata(&mode_probe)?.permissions().mode() & 0o777 == 0o600;

    let src = tmp.path().join("input").join("tree");
    fs::create_dir_all(&src)?;
    fs::write(src.join("secret.bin"), b"six-hundred")?;
    fs::set_permissions(src.join("secret.bin"), fs::Permissions::from_mode(0o600))?;
    fs::write(src.join("run.sh"), b"seven-five-five")?;
    fs::set_permissions(src.join("run.sh"), fs::Permissions::from_mode(0o755))?;

    let enc = tmp.path().join("enc");
    let dec = tmp.path().join("dec");
    fs::create_dir_all(&enc)?;
    fs::create_dir_all(&dec)?;
    let passphrase = "matrix-test";
    passphrase_auto(&src, &enc, passphrase, None, None, |_| {})?;
    let out = passphrase_auto(enc.join("tree.fcr"), &dec, passphrase, None, None, |_| {})?;

    // Content survives on every filesystem.
    assert_eq!(fs::read(out.join("secret.bin"))?, b"six-hundred");
    assert_eq!(fs::read(out.join("run.sh"))?, b"seven-five-five");

    if preserves_modes {
        assert_eq!(
            fs::metadata(out.join("secret.bin"))?.permissions().mode() & 0o777,
            0o600,
            "0o600 mode must survive the round trip on a perms-preserving volume"
        );
        assert_eq!(
            fs::metadata(out.join("run.sh"))?.permissions().mode() & 0o777,
            0o755,
            "0o755 mode must survive the round trip on a perms-preserving volume"
        );
    }
    Ok(())
}
