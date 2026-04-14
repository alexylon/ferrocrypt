use thiserror::Error;

/// Errors that can occur during key generation, encryption, or decryption.
///
/// All `Display` messages are short, user-facing, and free of internal
/// type names so that consumers can surface them directly without
/// additional mapping. Variants are identity-only: none of them carry
/// per-operation context like paths or byte offsets — that context
/// belongs at the caller, not in the error.
///
/// # Examples
///
/// ```rust
/// use std::path::Path;
/// use ferrocrypt::{symmetric_encrypt, CryptoError, secrecy::SecretString};
///
/// fn example() -> Result<(), CryptoError> {
///     let passphrase = SecretString::from("test".to_string());
///     match symmetric_encrypt(Path::new("./missing.txt"), Path::new("./out"), &passphrase, None, |_| {}) {
///         Ok(path) => println!("Output: {}", path.display()),
///         Err(CryptoError::InputPath(msg)) => eprintln!("Missing input: {}", msg),
///         Err(e) => eprintln!("{e}"),
///     }
///     Ok(())
/// }
/// ```
#[derive(Error, Debug)]
pub enum CryptoError {
    // ─── Input & filesystem ──────────────────────────────────────────────
    /// Filesystem or stream I/O failure.
    #[error(transparent)]
    Io(std::io::Error),
    /// Input file or directory does not exist.
    #[error("Input file or folder missing: {0}")]
    InputPath(String),
    /// Invalid caller input with a human-readable explanation.
    #[error("{0}")]
    InvalidInput(String),

    // ─── File format & version ───────────────────────────────────────────
    /// Encrypted file or key-file structure is invalid, truncated, or
    /// corrupted at the format level (not a crypto authentication issue).
    #[error("{0}")]
    InvalidFormat(String),
    /// Encrypted file or key-file version is outside the range this
    /// release can read.
    #[error("{0}")]
    UnsupportedVersion(String),

    // ─── Key derivation & work limits ────────────────────────────────────
    /// Argon2 key-derivation failed.
    #[error(transparent)]
    KeyDerivation(#[from] argon2::Error),
    /// KDF parameters read from an untrusted header are outside safe
    /// structural bounds.
    #[error("{0}")]
    InvalidKdfParams(String),
    /// KDF memory cost exceeds the caller-supplied work limit.
    #[error("KDF needs {required_kib} KiB, limit is {max_kib} KiB")]
    ExcessiveWork { required_kib: u32, max_kib: u32 },

    // ─── Authentication failures ─────────────────────────────────────────
    /// Unlocking the private key file with the supplied passphrase
    /// failed. The key file is structurally valid; the passphrase does
    /// not decrypt it.
    #[error("Private key file unlock failed: wrong passphrase")]
    KeyFileUnlockFailed,
    /// The encrypted file's header failed authentication. Produced when
    /// the symmetric header HMAC does not verify, when the hybrid envelope
    /// AEAD refuses to unwrap, or when the derived X25519 shared secret
    /// is all zero. From the user's perspective: wrong password, wrong
    /// key, or the encrypted file has been tampered with.
    #[error("Header authentication failed: wrong password/key or tampered")]
    HeaderAuthenticationFailed,
    /// An encrypted payload chunk failed AEAD authentication during
    /// streaming decryption. The ciphertext has been tampered with or
    /// corrupted after the header was authenticated.
    #[error("Payload authentication failed: data tampered or corrupted")]
    PayloadAuthenticationFailed,
    /// The encrypted stream ends before the final authenticated chunk.
    /// Usually caused by a truncated file or an aborted download.
    #[error("Encrypted file is truncated")]
    TruncatedStream,

    // ─── Low-level primitives ────────────────────────────────────────────
    /// Fixed-size byte conversion failed due to an unexpected length.
    #[error(transparent)]
    SliceConversion(#[from] std::array::TryFromSliceError),

    // ─── Internal invariants ─────────────────────────────────────────────
    /// A non-cryptographic invariant that should hold by construction did
    /// not hold. Triggered by state-machine misuse (e.g. using a stream
    /// after it was finalized), impossible-size checks, or internal
    /// encoding failures. If this fires, it indicates a library bug.
    #[error("{0}")]
    InternalInvariant(String),
    /// A cryptographic primitive (AEAD encryption, HKDF expansion) returned
    /// an error even though the inputs were well-formed. Unreachable in
    /// practice for valid data; indicates either a library bug or a very
    /// rare underlying-crate failure.
    #[error("{0}")]
    InternalCryptoFailure(String),
}

/// Errors that `DecryptReader` and `EncryptWriter` surface via [`std::io::Error`]
/// through the [`std::io::Read`] / [`std::io::Write`] trait boundary. The
/// `From<io::Error> for CryptoError` impl below downcasts these back into
/// typed [`CryptoError`] variants at the boundary where `?` converts
/// `io::Result` into `Result<_, CryptoError>`.
#[derive(Debug)]
pub(crate) enum StreamError {
    /// Streaming AEAD decryption rejected a chunk's authentication tag.
    DecryptAead,
    /// Streaming AEAD encryption failed (unreachable in practice for valid inputs).
    EncryptAead,
    /// Encrypted stream ended before the final authenticated chunk.
    Truncated,
    /// Writer or reader state was already consumed (programmer bug).
    StateExhausted,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            StreamError::DecryptAead => "payload authentication failed",
            StreamError::EncryptAead => "payload encryption failed",
            StreamError::Truncated => "encrypted stream truncated",
            StreamError::StateExhausted => "stream state exhausted",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for StreamError {}

impl From<std::io::Error> for CryptoError {
    fn from(e: std::io::Error) -> Self {
        // If the io::Error carries one of our typed stream markers,
        // convert it back into the appropriate CryptoError variant
        // instead of wrapping it as an opaque Io. The `EncryptAead` and
        // `StateExhausted` branches reuse `StreamError`'s own `Display`
        // so the message text is defined in one place.
        if let Some(stream_err) = e
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<StreamError>())
        {
            return match stream_err {
                StreamError::DecryptAead => CryptoError::PayloadAuthenticationFailed,
                StreamError::Truncated => CryptoError::TruncatedStream,
                StreamError::EncryptAead => {
                    CryptoError::InternalCryptoFailure(stream_err.to_string())
                }
                StreamError::StateExhausted => {
                    CryptoError::InternalInvariant(stream_err.to_string())
                }
            };
        }
        CryptoError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock in the exact user-facing Display text for the typed decryption
    /// error variants. The CLI and desktop app surface `Display` directly,
    /// so a silent wording change would be a visible UX regression. If a
    /// message genuinely needs to change, update this test in the same
    /// commit so the intent is reviewable.
    #[test]
    fn typed_decryption_errors_display_exact_strings() {
        assert_eq!(
            CryptoError::KeyFileUnlockFailed.to_string(),
            "Private key file unlock failed: wrong passphrase"
        );
        assert_eq!(
            CryptoError::HeaderAuthenticationFailed.to_string(),
            "Header authentication failed: wrong password/key or tampered"
        );
        assert_eq!(
            CryptoError::PayloadAuthenticationFailed.to_string(),
            "Payload authentication failed: data tampered or corrupted"
        );
        assert_eq!(
            CryptoError::TruncatedStream.to_string(),
            "Encrypted file is truncated"
        );
    }

    /// `StreamError` markers must downcast back into their typed
    /// `CryptoError` variants. Guards against an io::Error path accidentally
    /// collapsing into the generic `Io` variant — and pins the split
    /// between `InternalInvariant` and `InternalCryptoFailure`.
    #[test]
    fn stream_error_markers_map_to_typed_variants() {
        fn from_marker(marker: StreamError) -> CryptoError {
            std::io::Error::other(marker).into()
        }
        assert!(matches!(
            from_marker(StreamError::DecryptAead),
            CryptoError::PayloadAuthenticationFailed
        ));
        assert!(matches!(
            from_marker(StreamError::Truncated),
            CryptoError::TruncatedStream
        ));
        assert!(matches!(
            from_marker(StreamError::EncryptAead),
            CryptoError::InternalCryptoFailure(_)
        ));
        assert!(matches!(
            from_marker(StreamError::StateExhausted),
            CryptoError::InternalInvariant(_)
        ));

        // A bare io::Error without a marker must still land in `Io`.
        let plain: CryptoError = std::io::Error::other("bare message").into();
        assert!(
            matches!(plain, CryptoError::Io(_)),
            "unmarked io::Error must map to CryptoError::Io, got {plain:?}"
        );
    }
}
