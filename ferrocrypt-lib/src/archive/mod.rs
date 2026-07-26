//! FerroCrypt Archive (FCA) — native archive payload format.
//!
//! Full wire-format spec: `ferrocrypt-lib/FORMAT.md` §9.

pub(crate) mod decode;
pub(crate) mod encode;
pub(crate) mod format;
pub(crate) mod limits;
pub(crate) mod model;
pub(crate) mod path;
pub(crate) mod platform;
pub(crate) mod reasons;
pub(crate) mod tree;

pub use limits::ArchiveLimits;

pub(crate) use decode::unarchive;
#[cfg(feature = "fuzzing")]
pub(crate) use encode::archive;
pub(crate) use encode::{PreparedArchive, prepare_archive, validate_encrypt_input};
#[cfg(unix)]
pub(crate) use format::PERMISSION_BITS_MASK;

/// Policy for the `.incomplete` working tree when decrypt fails.
///
/// During decryption the archive is staged under
/// `{output_dir}/{root_name}.incomplete` and atomically renamed to
/// `{output_dir}/{root_name}` only after every authentication and
/// validation check has passed. This policy controls what happens to
/// the staged tree when a decrypt error occurs *before* that rename:
/// payload AEAD failure on a later chunk, archive structural reject
/// (manifest tree-shape failure, path-grammar reject, duplicate
/// detection), trailing-bytes reject, or a final-name collision
/// discovered at promotion time.
///
/// [`Self::DeleteOnError`] is the default. It matches the typical user
/// expectation that "decrypt failed → no plaintext on disk" and avoids
/// leaving authenticated-but-incomplete plaintext that an unaware
/// caller could pick up.
///
/// [`Self::RetainOnError`] is the opt-in for backup-recovery and
/// forensic flows where partial plaintext is more useful than no
/// plaintext.
///
/// Note: this policy only governs cleanup of the `.incomplete` working
/// tree after a normal `Err` return. Process termination (crash, SIGKILL,
/// power loss) and panic unwinding bypass cleanup entirely, so a killed
/// or panicking process can leave `.incomplete` output regardless of the
/// policy. The library does not wrap extraction in `catch_unwind`; if a
/// panic propagates out of `unarchive`, treat the working tree as if the
/// process had been killed. It may contain authenticated but incomplete
/// plaintext that the caller must inspect or remove explicitly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum IncompleteOutputPolicy {
    /// On decrypt error, best-effort remove the `.incomplete` working
    /// tree from `output_dir`. Cleanup failures (path already gone,
    /// permission denied, racing process) are swallowed so the original
    /// `CryptoError` is the value the caller sees.
    #[default]
    DeleteOnError,
    /// On decrypt error, leave the `.incomplete` working tree in
    /// `output_dir` for the caller to inspect or recover.
    ///
    /// **Truncation-prefix caveat**: FerroCrypt's payload uses
    /// XChaCha20-Poly1305 STREAM-BE32, which authenticates each 64 KiB
    /// chunk individually but does not detect truncation until the
    /// final chunk's `last_flag` arrives. An attacker who can truncate
    /// the ciphertext at a chunk boundary can therefore choose which
    /// authenticated plaintext prefix is retained. Callers who opt in
    /// to retention and act on partial output must treat the staged
    /// plaintext as a potentially attacker-chosen subset of the original,
    /// not as the full original truncated by storage failure.
    RetainOnError,
}
