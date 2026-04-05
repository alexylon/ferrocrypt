use thiserror::Error;

/// Errors that can occur during key generation, encryption, or decryption.
///
/// | Variant | When it happens | Typical fix |
/// | --- | --- | --- |
/// | `Io` | Filesystem or I/O failure | Check paths/permissions and retry |
/// | `ChaCha20Poly1305Error` | Symmetric encryption/decryption failed (bad tag, nonce issues) | Verify key, input integrity, and nonce uniqueness |
/// | `Argon2Error` | Password hashing/KDF failed | Ensure parameters are valid and memory is sufficient |
/// | `OpensslError` | Asymmetric operations failed | Validate PEM/keys; confirm OpenSSL availability |
/// | `TryFromSliceError` | Byte slice could not be converted | Confirm buffer sizes |
/// | `EncryptionDecryptionError` | High-level guard for crypto failures | Recheck keys/passwords and inputs |
/// | `InputPath` | Missing input file or folder | Provide an existing path |
/// | `Message` | Catch-all with human-readable context | Inspect message for details |
///
/// # Examples
///
/// ```rust
/// use ferrocrypt::{symmetric_encryption, CryptoError, secrecy::SecretString};
///
/// fn example() -> Result<(), CryptoError> {
///     let passphrase = SecretString::from("test".to_string());
///     // This will fail with CryptoError::InputPath if file doesn't exist
///     match symmetric_encryption("./missing.txt", "./out", &passphrase, None, |_| {}) {
///         Ok(result) => println!("{}", result),
///         Err(CryptoError::Io(e)) => eprintln!("I/O error: {}", e),
///         Err(CryptoError::InputPath(msg)) => eprintln!("Missing input: {}", msg),
///         Err(e) => eprintln!("Other error: {}", e),
///     }
///     Ok(())
/// }
/// ```
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ChaCha20Poly1305Error(#[from] chacha20poly1305::Error),
    #[error(transparent)]
    Argon2Error(#[from] argon2::Error),
    #[error(transparent)]
    OpensslError(#[from] openssl::error::ErrorStack),
    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("{0}")]
    EncryptionDecryptionError(String),
    #[error("Input file or folder missing: {0}\n")]
    InputPath(String),
    #[error("{0}")]
    Message(String),
}

// We must manually implement serde::Serialize for `tauri`
impl serde::Serialize for CryptoError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}
