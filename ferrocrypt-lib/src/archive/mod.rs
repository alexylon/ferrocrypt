//! TAR archive subset and directory/file payload semantics.
//!
//! Owns:
//!
//! - [`limits`] — [`ArchiveLimits`] and resource-cap helpers shared by
//!   the encrypt-side preflight and the decrypt-side extraction loop.
//! - [`path`] — archive path canonicalization and rejection
//!   ([`validate_archive_path_components`]), the POSIX ustar wire-format constants
//!   used by both writer and reader, and the [`UstarEntryKind`]
//!   classification.
//! - [`encode`] — encrypt-side traversal: [`validate_encrypt_input`],
//!   [`archive`], TAR header emission, the `open_no_follow` symlink
//!   guard, and the encrypt-side mode helpers.
//! - [`decode`] — decrypt-side TAR reading and output reconstruction:
//!   [`unarchive`], unified hardened `extract_entries`, TAR-subset
//!   validation, and trailing zero-block enforcement.
//! - [`platform`] — capability-based extraction primitives built on
//!   cap-std + cap-fs-ext, universal across Linux / macOS / Windows.
//!   Anchors every operation to a directory handle, refuses every
//!   symlink in the extraction path, and on Windows also rejects
//!   NTFS reparse points (junctions, mount points) via the
//!   `FILE_ATTRIBUTE_REPARSE_POINT` post-check.
//!
//! [`ArchiveLimits`]: crate::ArchiveLimits
//! [`validate_archive_path_components`]: crate::archive::validate_archive_path_components
//! [`validate_encrypt_input`]: crate::archive::validate_encrypt_input
//! [`archive`]: crate::archive::archive
//! [`unarchive`]: crate::archive::unarchive
//! [`UstarEntryKind`]: crate::archive::path::UstarEntryKind

pub(crate) mod decode;
pub(crate) mod encode;
pub(crate) mod limits;
pub(crate) mod path;

pub(crate) mod platform;

pub use limits::ArchiveLimits;

pub(crate) use decode::unarchive;
pub(crate) use encode::{archive, validate_encrypt_input};

/// Policy for the `.incomplete` working tree when decrypt fails.
///
/// During decryption the archive is staged under
/// `{output_dir}/{root_name}.incomplete` and atomically renamed to
/// `{output_dir}/{root_name}` only after every authentication and
/// validation check has passed. This policy controls what happens to
/// the staged tree when a decrypt error occurs *before* that rename:
/// payload AEAD failure on a later chunk, archive structural reject
/// (PAX/GNU extension, duplicate path, traversal), trailing zero-block
/// reject, or a final-name collision discovered at promotion time.
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
/// tree. Process termination (crash, SIGKILL, power loss) bypasses
/// cleanup entirely, so a `.incomplete` left by a killed process is
/// available for recovery regardless of the policy.
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
    /// the ciphertext at any chunk boundary can therefore choose what
    /// authenticated-prefix the recovered plaintext contains. Callers
    /// who opt in to retention and act on partial output MUST treat the
    /// staged plaintext as a potentially attacker-chosen subset of the
    /// original, not as the full original truncated by honest
    /// corruption.
    RetainOnError,
}

/// Mask that keeps only owner/group/other rwx bits, stripping
/// setuid, setgid, and sticky bits from tar-stored permissions.
/// Shared by the encrypt-side `metadata_perm_mode` reader and the
/// unified cap-std extraction platform's handle-based chmod helpers.
#[cfg(unix)]
pub(crate) const PERMISSION_BITS_MASK: u32 = 0o777;
