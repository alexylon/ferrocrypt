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
/// Three reports can occur *after* the root-mode step has confirmed the
/// promoted identity. That confirmation ratifies the output as the
/// operation's committed result rather than staged work, so this policy never
/// removes it:
///
/// - The final name no longer denotes the entry the run staged. The
///   decrypt returns `Err` and FerroCrypt does not remove the committed
///   object. If another writer moved it, it remains under that writer's chosen
///   name; an entry placed at the final name is also left alone. This identity
///   check is Unix-only.
/// - The destination directory path no longer denotes the directory used for
///   the commit. The decrypt returns `Err` and does not remove the confirmed
///   output by name. If the directory was renamed, the complete plaintext is
///   under that new name. This check is also Unix-only.
/// - On a Unix filesystem whose no-replace rename is unavailable, a file-root
///   commit can succeed by hard link while removal of the `.incomplete` name
///   fails, or while a concurrent rename/replacement makes that removal target
///   the wrong entry. The decrypt requires the retained committed inode to have
///   exactly one link before success. Otherwise it returns `Err`, preserves the
///   complete commit and any additional link, and never withdraws the final
///   name after cleanup uncertainty.
///
/// A run that cannot hold a handle to the staged root fails before
/// writing any plaintext, so a low open-file limit leaves at most an
/// empty staged entry — which the removal may not be able to take
/// away either, needing a descriptor of its own. A retry then reports
/// `Incomplete output already exists`.
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
