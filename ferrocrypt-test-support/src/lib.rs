//! Workspace-internal test helpers for ferrocrypt.
//!
//! This crate is **not published** (`publish = false`). It exists only so
//! that the workspace's tests can construct fast Argon2id parameters
//! without forcing the public `ferrocrypt` crate to expose any feature
//! or runtime mechanism that lowers production cryptographic strength.
//!
//! The published `ferrocrypt` crate has no Cargo feature touching crypto
//! strength, no doc-hidden test constructors, and no runtime override
//! path. Callers who genuinely need to construct weak Argon2id parameters
//! (e.g. tests in this workspace) do so by depending on this internal
//! crate as a `[dev-dependencies]` entry and explicitly threading
//! [`fast_kdf_params`] through the encrypt and keygen builders.
//!
//! Production code MUST NOT call into this crate.
//!
//! ## Design context
//!
//! Earlier revisions of ferrocrypt exposed a public Cargo feature named
//! `fast-kdf` that mutated `KdfParams::default()` to test-speed values.
//! That mechanism unified across the dependency graph and was a documented
//! misuse surface (production debug builds could silently emit `.fcr` files
//! with weak KDF parameters). The audit findings F-01 and F-05 were
//! resolved by removing the feature entirely and replacing it with this
//! workspace-internal crate plus explicit `kdf_params(...)` builder
//! methods on `Encryptor` and `KeyPairGenerator`.

#![forbid(unsafe_code)]

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{Encryptor, KdfParams, KeyPairGenerator};

/// Argon2id memory cost (KiB) for workspace-internal test-fast runs.
/// Single source of truth for the lib's `cfg(test) test_fast_default`
/// helper and this crate's own [`fast_kdf_params`] function. The cli's
/// debug-only override has its own local copy because `ferrocrypt-cli`
/// is `publish = true` and Cargo refuses to publish a crate whose
/// regular dep tree includes a `publish = false` workspace member like
/// this one. `pub` visibility here is reachable only from workspace
/// members that take this crate as a dev-dep (currently `ferrocrypt-lib`)
/// — never on crates.io, since this whole crate is unpublishable.
pub const TEST_FAST_KDF_MEM_COST: u32 = 8192;
pub const TEST_FAST_KDF_TIME_COST: u32 = 1;
pub const TEST_FAST_KDF_LANES: u32 = 4;

/// Returns Argon2id parameters tuned for fast test execution
/// (8 MiB memory, time_cost 1, parallelism 4).
///
/// Structurally valid — passes `KdfParams::from_bytes` and the writer-side
/// `enforce_limit` against `KdfLimit::default()` — but well below the
/// security floor used by `KdfParams::default()` (1 GiB memory,
/// time_cost 4). Threads through `Encryptor::kdf_params(...)` and
/// `KeyPairGenerator::kdf_params(...)` to make passphrase-based tests
/// run in milliseconds instead of seconds.
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
pub fn fast_passphrase_encryptor(passphrase: SecretString) -> Encryptor {
    Encryptor::with_passphrase(passphrase).kdf_params(fast_kdf_params())
}

/// Returns a [`KeyPairGenerator`] pre-configured with the test-fast
/// Argon2id parameters from [`fast_kdf_params`]. Callers finalise with
/// `.write(output_dir, on_event)`.
///
/// **Production code MUST NOT call this function.**
pub fn fast_keypair_generator(passphrase: SecretString) -> KeyPairGenerator {
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
