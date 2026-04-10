use thiserror::Error;

/// Errors that can occur during key generation, encryption, or decryption.
///
/// | Variant | When it happens | Typical fix |
/// | --- | --- | --- |
/// | `Io` | Filesystem or I/O failure | Check paths/permissions and retry |
/// | `KeyDerivation` | Password hashing/KDF failed | Ensure parameters are valid and memory is sufficient |
/// | `Cipher` | Symmetric or asymmetric encryption/decryption failed (bad tag, nonce issues) | Verify key, input integrity, and nonce uniqueness |
/// | `SliceConversion` | Byte slice could not be converted | Confirm buffer sizes |
/// | `AuthenticationFailed` | Password, key, or HMAC verification failed | Verify correct password/key |
/// | `InvalidFormat` | File or key-file structure is invalid or corrupted | Check file integrity |
/// | `UnsupportedVersion` | File or key format version not supported | Upgrade/downgrade FerroCrypt |
/// | `InvalidKdfParams` | KDF parameters out of safe bounds | Re-encrypt with valid parameters |
/// | `ExcessiveWork` | KDF memory cost exceeds caller limit | Raise `--max-kdf-memory` or re-encrypt with lower cost |
/// | `InternalError` | Unexpected internal crypto failure | Report as a bug |
/// | `InputPath` | Missing input file or folder | Provide an existing path |
/// | `InvalidInput` | Validation failure with human-readable context | Inspect message for details |
///
/// # Examples
///
/// ```rust
/// use std::path::Path;
/// use ferrocrypt::{symmetric_encrypt, CryptoError, secrecy::SecretString};
///
/// fn example() -> Result<(), CryptoError> {
///     let passphrase = SecretString::from("test".to_string());
///     // This will fail with CryptoError::InputPath if file doesn't exist
///     match symmetric_encrypt(Path::new("./missing.txt"), Path::new("./out"), &passphrase, None, |_| {}) {
///         Ok(path) => println!("Output: {}", path.display()),
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
    #[error("Authentication failed: wrong password, wrong key, or tampered data")]
    AuthenticationFailed,
    #[error("{0}")]
    InvalidFormat(String),
    #[error("{0}")]
    UnsupportedVersion(String),
    #[error("{0}")]
    InvalidKdfParams(String),
    #[error("KDF needs {required_kib} KiB, limit is {max_kib} KiB")]
    ExcessiveWork { required_kib: u32, max_kib: u32 },
    #[error("{0}")]
    InternalError(String),
    #[error("Input file or folder missing: {0}")]
    InputPath(String),
    #[error("{0}")]
    InvalidInput(String),
}
