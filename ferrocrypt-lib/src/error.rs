use thiserror::Error;

/// Errors that can occur during key generation, encryption, or decryption.
///
/// | Variant | When it happens | Typical fix |
/// | --- | --- | --- |
/// | `Io` | Filesystem or I/O failure | Check paths/permissions and retry |
/// | `KeyDerivation` | Password hashing/KDF failed | Ensure parameters are valid and memory is sufficient |
/// | `Cipher` | Symmetric or asymmetric encryption/decryption failed (bad tag, nonce issues) | Verify key, input integrity, and nonce uniqueness |
/// | `SliceConversion` | Byte slice could not be converted | Confirm buffer sizes |
/// | `CryptoOperation` | High-level guard for crypto failures | Recheck keys/passwords and inputs |
/// | `InputPath` | Missing input file or folder | Provide an existing path |
/// | `InvalidInput` | Validation failure with human-readable context | Inspect message for details |
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
    Cipher(#[from] chacha20poly1305::Error),
    #[error(transparent)]
    KeyDerivation(#[from] argon2::Error),
    #[error(transparent)]
    SliceConversion(#[from] std::array::TryFromSliceError),
    #[error("{0}")]
    CryptoOperation(String),
    #[error("Input file or folder missing: {0}")]
    InputPath(String),
    #[error("{0}")]
    InvalidInput(String),
}
