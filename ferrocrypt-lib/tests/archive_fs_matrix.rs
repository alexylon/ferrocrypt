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
use std::path::Path;

use ferrocrypt::{
    CryptoError, Decryptor, IncompleteOutputPolicy, Passphrase, validate_private_key_file,
    validate_public_key_file,
};
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

/// Names of the entries directly under `dir`, sorted.
///
/// The residue assertions below compare against the whole directory
/// rather than probing for the staging suffix, so they catch a leftover
/// under any name and need no copy of a name the library owns.
fn entry_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("read output directory")
        .map(|entry| {
            entry
                .expect("read directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// Total bytes held by every regular file at or under `root`, so a
/// staged tree can be shown to hold plaintext rather than merely exist.
fn bytes_under(root: &Path) -> u64 {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(_) => return 0,
    };
    if metadata.is_file() {
        return metadata.len();
    }
    if !metadata.is_dir() {
        return 0;
    }
    fs::read_dir(root)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| bytes_under(&entry.path()))
                .sum()
        })
        .unwrap_or(0)
}

/// Writes a source tree whose encrypted payload spans several 64 KiB
/// chunks, so a later truncation can leave whole files staged.
fn write_multi_chunk_tree(root: &Path) -> Result<(), CryptoError> {
    fs::create_dir_all(root)?;
    for index in 0..5 {
        let content: Vec<u8> = (0..=255u8).cycle().take(60 * 1024).collect();
        fs::write(root.join(format!("part{index}.bin")), &content)?;
    }
    Ok(())
}

/// Names the route this filesystem's single-file commits take.
///
/// `fs/atomic.rs` tries an atomic no-replace rename first and falls back
/// to linking the output to its final name and unlinking the staged one.
/// Nothing observable after a successful commit says which of those ran,
/// so both primitives are probed directly — the rename through the same
/// call the library makes. A lane's residue result then names the route
/// it exercised instead of leaving it to be guessed, which is what
/// decides whether that lane has anything to say about the link route's
/// unlink step.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn commit_route(dir: &Path) -> String {
    use rustix::fs::{CWD, RenameFlags, renameat_with};

    let source = dir.join("probe-source");
    let target = dir.join("probe-target");
    fs::write(&source, b"probe").expect("write the probe file");
    let no_replace_rename =
        renameat_with(CWD, &source, CWD, &target, RenameFlags::NOREPLACE).is_ok();
    let _ = fs::remove_file(&target);

    fs::write(&source, b"probe").expect("write the probe file");
    let hard_links = fs::hard_link(&source, &target).is_ok();
    let _ = fs::remove_file(&target);
    let _ = fs::remove_file(&source);

    match (no_replace_rename, hard_links) {
        (true, _) => "atomic no-replace rename".to_string(),
        (false, true) => "link and unlink".to_string(),
        (false, false) => "claim and rename".to_string(),
    }
}

/// Windows commits by path rather than choosing among those routes, so
/// there is nothing to probe.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn commit_route(_dir: &Path) -> String {
    "path-based move".to_string()
}

/// A successful decrypt leaves the output directory holding exactly the
/// decrypted entry, with no staging leftover under any name.
///
/// This belongs on every lane because what the commit does with the
/// staging name is the filesystem's business. Where a driver cannot
/// perform an atomic no-replace rename, a single-file output is linked
/// to its final name and the staged name unlinked; a driver that
/// refuses that unlink would leave the staged entry behind. Both root
/// kinds run, because only a file root can reach the link route.
#[test]
#[ignore = "fs-matrix"]
fn fs_matrix_success_leaves_no_staging_residue() -> Result<(), CryptoError> {
    let tmp = fs_matrix_tempdir().expect("create fs-matrix tempdir");
    let passphrase = "matrix-test";
    let probe_dir = tmp.path().join("probe");
    fs::create_dir_all(&probe_dir)?;
    let route = commit_route(&probe_dir);
    println!("fs-matrix commit route for a single-file output: {route}");

    for root_is_file in [true, false] {
        let label = if root_is_file { "file" } else { "directory" };
        let input_dir = tmp.path().join(format!("input-{label}"));
        let encrypt_dir = tmp.path().join(format!("encrypted-{label}"));
        let decrypt_dir = tmp.path().join(format!("decrypted-{label}"));
        fs::create_dir_all(&input_dir)?;
        fs::create_dir_all(&encrypt_dir)?;
        fs::create_dir_all(&decrypt_dir)?;

        // The encrypted file is named after the input's stem, while the
        // archive restores the name in full, so the two differ for a
        // file root.
        let (input, stem, expected) = if root_is_file {
            let input = input_dir.join("payload.bin");
            fs::write(&input, b"residue check payload")?;
            (input, "payload", "payload.bin")
        } else {
            let input = input_dir.join("tree");
            fs::create_dir_all(input.join("nested"))?;
            fs::write(input.join("a.txt"), b"alpha")?;
            fs::write(input.join("nested/b.txt"), b"bravo")?;
            (input, "tree", "tree")
        };

        passphrase_auto(&input, &encrypt_dir, passphrase, None, None, |_| {})?;
        let fcr = encrypt_dir.join(format!("{stem}.fcr"));
        passphrase_auto(&fcr, &decrypt_dir, passphrase, None, None, |_| {})?;

        assert_eq!(
            entry_names(&decrypt_dir),
            vec![expected.to_string()],
            "{label} root: a finished decrypt must leave only its output (commit route: {route})"
        );

        // A cleared output must accept the same file again, so nothing
        // the first run left behind can block a retry.
        fs::remove_dir_all(&decrypt_dir)?;
        fs::create_dir_all(&decrypt_dir)?;
        passphrase_auto(&fcr, &decrypt_dir, passphrase, None, None, |_| {})?;
        assert_eq!(
            entry_names(&decrypt_dir),
            vec![expected.to_string()],
            "{label} root: a second decrypt into a cleared output must succeed (commit route: {route})"
        );
    }
    Ok(())
}

/// A decrypt that fails after staging real plaintext honours the chosen
/// policy: `DeleteOnError` removes the populated staging tree,
/// `RetainOnError` keeps it.
///
/// The payload spans several 64 KiB chunks and is cut partway, so whole
/// files are already staged when the truncation is detected. Cutting on
/// the first chunk would prove only that an empty tree is removed, which
/// is the easy half.
#[test]
#[ignore = "fs-matrix"]
fn fs_matrix_failed_decrypt_honours_policy() -> Result<(), CryptoError> {
    let tmp = fs_matrix_tempdir().expect("create fs-matrix tempdir");
    let passphrase = "matrix-test";
    let input = tmp.path().join("input/tree");
    write_multi_chunk_tree(&input)?;
    let encrypt_dir = tmp.path().join("encrypted");
    fs::create_dir_all(&encrypt_dir)?;
    passphrase_auto(&input, &encrypt_dir, passphrase, None, None, |_| {})?;

    // Two of the five chunks survive, so the reader authenticates and
    // writes whole files before it reaches the cut.
    let fcr = encrypt_dir.join("tree.fcr");
    let whole = fs::read(&fcr)?;
    let truncated = tmp.path().join("truncated.fcr");
    fs::write(&truncated, &whole[..whole.len() * 2 / 5])?;

    for retain in [false, true] {
        let policy = if retain {
            IncompleteOutputPolicy::RetainOnError
        } else {
            IncompleteOutputPolicy::DeleteOnError
        };
        let decrypt_dir = tmp.path().join(format!("decrypted-{retain}"));
        fs::create_dir_all(&decrypt_dir)?;

        let Decryptor::Passphrase(decryptor) = Decryptor::open(&truncated)? else {
            panic!("a passphrase file must open as a passphrase decryptor");
        };
        let error = decryptor
            .incomplete_output_policy(policy)
            .decrypt(Passphrase::new(passphrase), &decrypt_dir, |_| {})
            .expect_err("a truncated payload must refuse");

        let names = entry_names(&decrypt_dir);
        if retain {
            assert_eq!(
                names.len(),
                1,
                "retention must keep the staged tree, got {names:?} after {error}"
            );
            let staged = decrypt_dir.join(&names[0]);
            assert!(
                bytes_under(&staged) > 0,
                "retention must keep a populated staged tree, {staged:?} holds nothing"
            );
        } else {
            assert!(
                names.is_empty(),
                "deletion must leave no staged plaintext, got {names:?} after {error} — \
                 removal is best-effort, so a failure here names a filesystem that \
                 could not remove what the run staged"
            );
        }
    }
    Ok(())
}
