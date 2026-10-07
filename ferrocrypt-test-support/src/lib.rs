//! Workspace-internal test helpers for ferrocrypt.
//!
//! This crate is **not published** (`publish = false`). It exists so that
//! the workspace's tests can construct fast Argon2id parameters without
//! forcing the public `ferrocrypt` crate to expose any feature or runtime
//! mechanism that lowers production cryptographic strength, and so that the
//! wire-corpus generator and its replays share one manifest grammar
//! ([`wire_manifest`]).
//!
//! The published `ferrocrypt` crate has no Cargo feature touching crypto
//! strength, no doc-hidden test constructors, and no runtime override
//! path. Tests in this workspace get fast Argon2id parameters by
//! depending on this internal crate as a `[dev-dependencies]` entry and
//! explicitly threading [`fast_kdf_params`] through the encrypt and
//! keygen builders' `kdf_params(...)` methods. Those parameters sit at
//! the writer's production memory floor, so they pass `validate_for_write`
//! directly.
//!
//! Production code MUST NOT call into this crate.
//!
//! ## Design context
//!
//! Earlier revisions of ferrocrypt exposed a public Cargo feature named
//! `fast-kdf` that set `KdfParams::default()` to test-speed values. Cargo
//! unifies features across the dependency graph, so a production debug
//! build could silently emit `.fcr` files with weak KDF parameters. The
//! feature was removed and replaced by this workspace-internal crate plus
//! explicit `kdf_params(...)` builder methods on `Encryptor` and
//! `KeyPairGenerator`. Those builders later gained a production memory
//! floor; this crate's fast parameters sit at that floor, so they pass
//! through the ordinary `kdf_params(...)` path.

#![forbid(unsafe_code)]

pub mod wire_manifest;

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use ferrocrypt::Passphrase;
use ferrocrypt::{Encryptor, KdfParams, KeyPairGenerator};

/// Argon2id memory cost (KiB) for workspace-internal test-fast runs.
/// Set to ferrocrypt's 19 MiB production write floor
/// (`KdfParams::MIN_WRITE_MEM_COST`), so artifacts produced through the
/// public `Encryptor::write` / `KeyPairGenerator::write` path pass
/// `validate_for_write` via the ordinary `kdf_params(...)` builder.
/// Single source of truth for the lib's `cfg(test) test_fast_default`
/// helper and this crate's own [`fast_kdf_params`] function. The cli's
/// debug-only override has its own local copy because `ferrocrypt-cli`
/// is `publish = true` and Cargo refuses to publish a crate whose
/// regular dep tree includes a `publish = false` workspace member like
/// this one. `pub` visibility here is reachable only from workspace
/// members that take this crate as a dev-dep (currently `ferrocrypt-lib`)
/// — never on crates.io, since this whole crate is unpublishable.
pub const TEST_FAST_KDF_MEM_COST: u32 = 19 * 1024;
pub const TEST_FAST_KDF_TIME_COST: u32 = 1;
pub const TEST_FAST_KDF_LANES: u32 = 4;

/// Returns Argon2id parameters tuned for fast test execution
/// (19 MiB memory, time_cost 1, parallelism 4).
///
/// Memory sits at the writer's production floor, so these parameters pass
/// `validate_for_write` through the ordinary floored `kdf_params(...)`
/// builder while keeping passphrase-based tests in the tens of
/// milliseconds — versus the seconds a 1 GiB default would cost.
///
/// # Caller obligations
///
/// **Production code MUST NOT call this function.** It exists for tests
/// only. The crate it lives in is `publish = false` and will not appear
/// in any `crates.io` artifact.
pub fn fast_kdf_params() -> KdfParams {
    KdfParams {
        mem_cost: TEST_FAST_KDF_MEM_COST,
        time_cost: TEST_FAST_KDF_TIME_COST,
        lanes: TEST_FAST_KDF_LANES,
    }
}

/// Returns an [`Encryptor`] pre-configured for passphrase encryption with
/// the test-fast Argon2id parameters from [`fast_kdf_params`]. Callers
/// chain additional builder methods (`save_as`, `archive_limits`, …) and
/// finalise with `.write(...)`.
///
/// **Production code MUST NOT call this function.**
pub fn fast_passphrase_encryptor(passphrase: Passphrase) -> Encryptor {
    Encryptor::with_passphrase(passphrase).kdf_params(fast_kdf_params())
}

/// Returns a [`KeyPairGenerator`] pre-configured with the test-fast
/// Argon2id parameters from [`fast_kdf_params`]. Callers finalise with
/// `.write(output_dir, on_event)`.
///
/// **Production code MUST NOT call this function.**
pub fn fast_keypair_generator(passphrase: Passphrase) -> KeyPairGenerator {
    KeyPairGenerator::with_passphrase(passphrase).kdf_params(fast_kdf_params())
}

/// Creates a `TempDir` rooted at the filesystem-matrix mount when
/// `FERROCRYPT_FS_MATRIX_DIR` is set to a non-empty value, falling
/// back to the system temp dir otherwise. The matrix CI lane mounts a
/// non-default filesystem (case-sensitive APFS, btrfs, exFAT, …) and
/// points this env var at the mount point, so tests opted in to the
/// matrix lane (via `#[ignore = "fs-matrix"]` plus an explicit
/// `--ignored` invocation) exercise the archive layer against the
/// target filesystem instead of the runner's default.
///
/// Tests outside the matrix lane call this with the env var unset and
/// behave identically to a plain `TempDir::new()`. An empty env var
/// is treated as unset so a stray `export FERROCRYPT_FS_MATRIX_DIR=""`
/// does not silently land tempdirs in the current working directory.
pub fn fs_matrix_tempdir() -> std::io::Result<tempfile::TempDir> {
    match std::env::var_os("FERROCRYPT_FS_MATRIX_DIR") {
        Some(root) if !root.is_empty() => tempfile::TempDir::new_in(root),
        _ => tempfile::TempDir::new(),
    }
}

/// Per-process staging area under a test binary's fixed workspace
/// root: `<root>/run-<pid>`.
///
/// Integration-test binaries stage their scratch files under a fixed
/// relative root (for example `tests/workspace`). Two concurrent
/// `cargo test` invocations of the same binary — a debug run next to a
/// release run, or two terminals — would share that root and delete
/// each other's staged files mid-test. Routing every path through this
/// helper keeps each process in its own subtree, so concurrent
/// invocations cannot interfere. Pair with
/// [`remove_per_process_workspace`] in the binary's exit hook.
pub fn per_process_workspace(root: &str) -> std::path::PathBuf {
    std::path::Path::new(root).join(format!("run-{}", std::process::id()))
}

/// Removes this process's [`per_process_workspace`] subtree, then
/// prunes the shared `root` itself if no other run is using it.
/// Both steps are best-effort: cleanup runs in an exit hook where a
/// failure must not turn a finished test run into an error, and a
/// still-populated root simply refuses the non-recursive removal —
/// exactly right while a concurrent run is active.
pub fn remove_per_process_workspace(root: &str) {
    let own = per_process_workspace(root);
    if own.exists() {
        let _ = std::fs::remove_dir_all(&own);
    }
    let _ = std::fs::remove_dir(root);
}

/// Names of the files operating systems write into a directory a user opens:
/// macOS Finder's `.DS_Store` and Windows Explorer's `Thumbs.db` and
/// `desktop.ini`. `testvectors/wire/tools/verify_manifests.py` holds the same
/// list.
const OS_METADATA_NAMES: [&str; 3] = [".DS_Store", "Thumbs.db", "desktop.ini"];

/// Whether a directory entry name is one an operating system writes on its
/// own: `.DS_Store`, `Thumbs.db`, `desktop.ini`, or an AppleDouble `._` file,
/// which macOS writes beside a file on a volume that cannot hold its extended
/// attributes.
///
/// `.gitignore` lists every such name, so no committed test tree holds one,
/// and a test that scans the working copy of a committed tree skips it.
pub fn is_os_metadata_name(name: &OsStr) -> bool {
    let name = name.as_encoded_bytes();
    name.starts_with(b"._")
        || OS_METADATA_NAMES
            .iter()
            .any(|known| name == known.as_bytes())
}

/// Asserts that the tree at `actual` holds the same directories and files,
/// with the same bytes, as the working copy of a committed tree at
/// `expected`. Metadata an operating system wrote into `expected`
/// ([`is_os_metadata_name`]) is left out; `actual` is compared whole.
///
/// # Panics
///
/// If the trees differ, or if either holds an entry that is neither a file
/// nor a directory or cannot be read.
pub fn assert_tree_matches(expected: &Path, actual: &Path) {
    let expected_entries = tree_entries(expected, is_os_metadata_name);
    let actual_entries = tree_entries(actual, |_| false);
    let expected_paths: Vec<_> = expected_entries.iter().map(|(path, _)| path).collect();
    let actual_paths: Vec<_> = actual_entries.iter().map(|(path, _)| path).collect();
    assert_eq!(
        expected_paths,
        actual_paths,
        "the entries under {} and {} differ",
        expected.display(),
        actual.display()
    );
    for ((path, expected_content), (_, actual_content)) in
        expected_entries.iter().zip(&actual_entries)
    {
        assert_eq!(
            expected_content,
            actual_content,
            "{} differs under {}",
            path.display(),
            actual.display()
        );
    }
}

/// Every entry under `root` except those `skip` names, as `(path relative to
/// root, content)` sorted by path: a file's bytes, or `None` for a directory.
fn tree_entries(root: &Path, skip: fn(&OsStr) -> bool) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read tree directory") {
            let entry = entry.expect("read tree entry");
            if skip(&entry.file_name()) {
                continue;
            }
            let path = entry.path();
            let file_type = entry.file_type().expect("read tree entry type");
            let content = if file_type.is_dir() {
                None
            } else if file_type.is_file() {
                Some(fs::read(&path).expect("read tree file"))
            } else {
                panic!("{}: neither a file nor a directory", path.display());
            };
            let relative = path.strip_prefix(root).expect("entry is under the root");
            out.push((relative.to_path_buf(), content));
            if file_type.is_dir() {
                stack.push(path);
            }
        }
    }
    out.sort();
    out
}
