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

/// Cleanup policy for staged plaintext after a returned decryption error.
///
/// Decryption stages a file or directory at
/// `{output_dir}/{root_name}.incomplete`. After payload authentication and
/// archive validation complete, it promotes that entry to
/// `{output_dir}/{root_name}` using the platform's no-clobber commit route.
/// Root permission and identity checks follow promotion. A pre-existing final
/// or `.incomplete` entry is rejected, not reused or removed.
///
/// [`Self::DeleteOnError`] is the default; [`Self::RetainOnError`] preserves
/// partial output for inspection or recovery. A failed or unconfirmed cleanup
/// is reported in the returned error with the working path.
///
/// Once the output is confirmed as committed, later errors preserve it.
/// These include a replaced final name, a changed or unconfirmable destination
/// directory, a retained staging link, or a committed file with a link count
/// other than one. The error describes the complete output or replacement;
/// it must not be treated as evidence that nothing was written. Identity
/// comparisons are skipped where the filesystem provides no usable identity;
/// destination-directory confirmation also skips descriptor or memory exhaustion.
///
/// Extraction requires a retained handle to the staged root before streaming
/// content. Failure to obtain it can leave an empty entry if cleanup also
/// fails. Any remaining `.incomplete` entry blocks a retry.
///
/// This policy applies to normal `Err` returns. Extraction does not run its
/// cleanup during panic unwinding; a panic, process termination, or power loss
/// can leave staged plaintext under either policy. The caller must inspect or
/// remove that output explicitly.
///
/// This enum deliberately does not implement `Copy`: future policies may
/// carry owned configuration, such as a destination for retained output.
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
    /// chunk individually. Completeness is established only by successfully
    /// authenticating a final chunk with `last_flag = 1`. An attacker who
    /// truncates the ciphertext at a chunk boundary can choose which
    /// authenticated plaintext prefix is retained. Callers who opt in
    /// to retention and act on partial output must treat the staged
    /// plaintext as a potentially attacker-chosen subset of the original,
    /// not as the full original truncated by storage failure.
    RetainOnError,
}
