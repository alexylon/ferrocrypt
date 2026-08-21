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

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) mod fd_limit;

pub(crate) use decode::unarchive;
#[cfg(feature = "unstable-fuzzing")]
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
/// [`Self::DeleteOnError`] is the default. Before commit, it avoids leaving
/// authenticated-but-incomplete plaintext that an unaware caller could pick
/// up. The post-commit exceptions are described below.
///
/// Three reports can occur *after* the output became visible at the final
/// name. The staged record leaves the cleanup slot as soon as the run
/// establishes that the entry there is its own — at the root-mode step where
/// the identity confirms it, otherwise at the final-name check that follows —
/// so this policy never removes a committed output:
///
/// - The final name no longer denotes the entry the run staged. The
///   decrypt returns `Err` and FerroCrypt does not remove the committed
///   object. If another writer moved it, it remains under that writer's chosen
///   name; an entry placed at the final name is also left alone. The check runs
///   on every supported platform, and is skipped only where the filesystem
///   supplies no identity to compare.
/// - The destination directory path no longer denotes the directory used for
///   the commit. The decrypt returns `Err` and does not remove the confirmed
///   output by name. If the directory was renamed, the complete plaintext is
///   under that new name. This check runs on the same terms.
/// - A committed file root carries more than one name. The count is read
///   through the retained handle for every file root, on every supported
///   platform and whatever route committed the name: a local writer can link
///   the staged plaintext before the commit, and that link survives it. A
///   hard-link fallback can also leave its staging name behind, or have its
///   removal reach the wrong entry. The decrypt returns `Err`, preserves the
///   complete commit and any additional name, and never withdraws the final
///   name after cleanup uncertainty.
///
/// A run that cannot hold a handle to the staged root fails before
/// writing any plaintext, so a low open-file limit leaves at most an
/// empty staged entry — which the removal may not be able to take
/// away either, needing a descriptor of its own; the returned error
/// then says so. A retry reports `Incomplete output already exists`.
///
/// [`Self::RetainOnError`] is the opt-in for backup-recovery and
/// forensic flows where partial plaintext is more useful than no
/// plaintext.
///
/// The enum is `#[non_exhaustive]` so future releases can add richer
/// recovery policies. It deliberately does not implement `Copy`: such a
/// policy is configuration, and one may need to carry owned data — a
/// destination directory for retained partial output, for example.
///
/// Note: this policy only governs cleanup of the `.incomplete` working
/// tree after a normal `Err` return. Process termination (crash, SIGKILL,
/// power loss) and panic unwinding bypass cleanup entirely, so a killed
/// or panicking process can leave `.incomplete` output regardless of the
/// policy. The library does not wrap extraction in `catch_unwind`; if a
/// panic propagates out of `unarchive`, treat the working tree as if the
/// process had been killed. It may contain authenticated but incomplete
/// plaintext that the caller must inspect or remove explicitly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum IncompleteOutputPolicy {
    /// On decrypt error, remove the `.incomplete` working tree from
    /// `output_dir`. Directory permissions the run applied to its own
    /// staged tree are restored first, so a stored mode without owner
    /// write permission cannot keep the run's own entries on disk. If
    /// the removal still fails or cannot be confirmed — a permission
    /// another process changed, a storage error, a staged tree that is
    /// no longer where it was created — the returned error names the
    /// working path and says whether plaintext may remain there (a
    /// staged file is emptied through its handle before the unlink, so
    /// one that could not be unlinked holds none). The original error
    /// keeps its class where that class carries a message, and
    /// otherwise becomes [`CryptoError::Io`] with both texts. A staged
    /// directory found to have another owner before any content was
    /// written is not this run's, so it is named in the error and left
    /// in place rather than removed.
    ///
    /// [`CryptoError::Io`]: crate::CryptoError::Io
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
