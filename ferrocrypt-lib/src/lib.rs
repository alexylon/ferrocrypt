//! # ferrocrypt
//!
//! High-level helpers for encrypting and decrypting files or directories using
//! password-based symmetric encryption or hybrid (asymmetric + symmetric)
//! encryption. Designed for straightforward, scriptable workflows rather than
//! low-level cryptographic building blocks.
//!
//! ## Design goals
//! - **Confidentiality + integrity** for small-to-medium file trees.
//! - **Simple ergonomics**: pick symmetric (password) or hybrid (public/private
//!   key + optional passphrase) based on your distribution needs.
//! - **Batteries included**: streaming encryption pipeline, path handling,
//!   and output file naming are handled for you.
//!
//! ## Quick start (symmetric)
//! ```rust,no_run
//! use std::path::Path;
//! use ferrocrypt::{symmetric_encrypt, symmetric_decrypt, CryptoError, secrecy::SecretString};
//!
//! # fn run() -> Result<(), CryptoError> {
//! let passphrase = SecretString::from("correct horse battery staple".to_string());
//!
//! // Encrypt
//! let encrypted = symmetric_encrypt(Path::new("./secrets"), Path::new("./out"), &passphrase, None, |_| {})?;
//! println!("Encrypted to {}", encrypted.display());
//!
//! // Decrypt
//! let decrypted = symmetric_decrypt(&encrypted, Path::new("./restored"), &passphrase, |_| {})?;
//! println!("Decrypted to {}", decrypted.display());
//! # Ok(()) }
//! # fn main() { run().unwrap(); }
//! ```
//!
//! ## Quick start (hybrid)
//! ```rust,no_run
//! use std::path::Path;
//! use ferrocrypt::{generate_key_pair, hybrid_encrypt, hybrid_decrypt, CryptoError, secrecy::SecretString};
//!
//! # fn run() -> Result<(), CryptoError> {
//! // 1) Generate X25519 keypair
//! let passphrase = SecretString::from("my-key-pass".to_string());
//! let keys = generate_key_pair(&passphrase, Path::new("./keys"), |_| {})?;
//! println!("Fingerprint: {}", keys.fingerprint);
//!
//! // 2) Encrypt with public key (no passphrase needed)
//! let encrypted = hybrid_encrypt(
//!     Path::new("./payload"), Path::new("./out"),
//!     &keys.public_key_path, None, |_| {},
//! )?;
//!
//! // 3) Decrypt with private key + passphrase
//! let decrypted = hybrid_decrypt(
//!     &encrypted, Path::new("./restored"),
//!     &keys.private_key_path, &passphrase, |_| {},
//! )?;
//! println!("Decrypted to {}", decrypted.display());
//! # Ok(()) }
//! # fn main() { run().unwrap(); }
//! ```
//!
//! ## When to choose which mode
//! - **Symmetric**: Fastest; same password encrypts and decrypts. Great for
//!   personal backups or team secrets when you can share the password securely.
//!   Produces `.fcr` files.
//! - **Hybrid**: Safer for distribution—encrypt with a recipient's public key
//!   (no password needed for encryption); only their passphrase-protected
//!   private key can decrypt. Each file gets a unique random key. Produces
//!   `.fcr` files.
//!
//! ## Security notes
//! - All cryptographic operations depend on a secure OS RNG; ensure the target
//!   platform provides one.
//! - Ciphertext integrity is enforced; modification or wrong keys will yield
//!   `CryptoError` results rather than corrupted plaintext.
//! - This crate is **not** third-party audited and is not advertised as
//!   compliance-certified.
//!
//! ## Error handling
//! Every fallible operation returns `Result<T, CryptoError>`. See `CryptoError`
//! for variant meanings and remediation hints.
//!
//! ## License
//! Licensed under GPL-3.0-only. See the LICENSE file in the repository.

#[cfg(all(feature = "fast-kdf", not(debug_assertions)))]
compile_error!("fast-kdf feature must not be used in release builds");

use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret as _, SecretString};

use crate::common::{bytes_to_hex, sha3_32_hash};
pub use crate::error::CryptoError;
pub use crate::format::ENCRYPTED_EXTENSION;

pub use secrecy;

/// The encryption mode used to create an `.fcr` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    /// Password-based symmetric encryption (XChaCha20-Poly1305 + Argon2id).
    Symmetric,
    /// Public/private key hybrid encryption (X25519 + XChaCha20-Poly1305).
    Hybrid,
}

/// Result of a successful key pair generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPairInfo {
    /// Path to the generated private key file.
    pub private_key_path: PathBuf,
    /// Path to the generated public key file.
    pub public_key_path: PathBuf,
    /// SHA3-256 fingerprint of the public key (64-char hex string).
    pub fingerprint: String,
}

/// Reads the header prefix of an `.fcr` file and returns the encryption mode.
///
/// Returns `Ok(None)` if the file is not a valid FerroCrypt file, is too short,
/// or the header prefix cannot be fully read.
/// Returns `Err` if the file cannot be opened.
pub fn detect_encryption_mode(
    file_path: impl AsRef<Path>,
) -> Result<Option<EncryptionMode>, CryptoError> {
    use std::io::Read;
    let mut buf = [0u8; format::HEADER_PREFIX_ENCODED_SIZE];
    let mut file = std::fs::File::open(file_path.as_ref())?;
    if file.read_exact(&mut buf).is_err() {
        return Ok(None);
    }
    let Ok(prefix) = replication::rep_decode(&buf) else {
        return Ok(None);
    };
    if prefix.len() < 2 || prefix[0] != format::MAGIC_BYTE {
        return Ok(None);
    }
    match prefix[1] {
        format::TYPE_SYMMETRIC => Ok(Some(EncryptionMode::Symmetric)),
        format::TYPE_HYBRID => Ok(Some(EncryptionMode::Hybrid)),
        _ => Ok(None),
    }
}

mod archiver;
mod common;
mod error;
mod format;
mod hybrid;
mod replication;
mod symmetric;

/// Computes the SHA3-256 fingerprint of a public key file.
///
/// Returns the hash as a 64-character lowercase hex string.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use ferrocrypt::public_key_fingerprint;
///
/// let fp = public_key_fingerprint(Path::new("./keys/public.key"))?;
/// println!("{}", fp);  // a1b2c3d4...
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
pub fn public_key_fingerprint(key_file: impl AsRef<Path>) -> Result<String, CryptoError> {
    let data = std::fs::read(key_file.as_ref())?;
    let header = format::parse_key_file_header(&data, format::KEY_FILE_TYPE_PUBLIC)?;
    match header.version {
        2 => {
            format::validate_key_v2_layout(&data, &header, format::PUBLIC_KEY_DATA_SIZE)?;
            let key_bytes = &data[format::KEY_FILE_HEADER_SIZE
                ..format::KEY_FILE_HEADER_SIZE + format::PUBLIC_KEY_DATA_SIZE];
            let hash = sha3_32_hash(key_bytes)?;
            Ok(bytes_to_hex(&hash))
        }
        _ => Err(format::unsupported_key_version_error(header.version)),
    }
}

/// Validates that a file is a well-formed FerroCrypt private key file.
///
/// Checks magic byte, key type, version, algorithm, and exact file size.
/// Does **not** attempt to decrypt the key (no passphrase needed).
pub fn validate_secret_key_file(key_file: impl AsRef<Path>) -> Result<(), CryptoError> {
    let data = std::fs::read(key_file.as_ref())?;
    let header = format::parse_key_file_header(&data, format::KEY_FILE_TYPE_SECRET)?;
    match header.version {
        2 => format::validate_key_v2_layout(&data, &header, format::SECRET_KEY_DATA_SIZE),
        _ => Err(format::unsupported_key_version_error(header.version)),
    }
}

/// Returns the default encrypted filename for a given input path (e.g. `"secrets.fcr"`).
/// For files, uses the stem (without extension). For directories, uses the full name.
pub fn default_encrypted_filename(input_path: impl AsRef<Path>) -> Result<String, CryptoError> {
    let base_name = common::get_encryption_base_name(input_path)?;
    Ok(format!("{}.{}", base_name, ENCRYPTED_EXTENSION))
}

fn validate_passphrase(passphrase: &SecretString) -> Result<(), CryptoError> {
    if passphrase.expose_secret().is_empty() {
        return Err(CryptoError::InvalidInput(
            "Passphrase must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_input_path(input_path: &Path) -> Result<(), CryptoError> {
    if !input_path.exists() {
        return Err(CryptoError::InputPath(input_path.display().to_string()));
    }
    Ok(())
}

// ─── Explicit encrypt/decrypt API ─────────────────────────────────────────

/// Encrypts a file or directory with password-based symmetric encryption.
///
/// Returns the path to the created `.fcr` file.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use ferrocrypt::{symmetric_encrypt, secrecy::SecretString};
///
/// let passphrase = SecretString::from("my-secret-password".to_string());
/// let output = symmetric_encrypt(Path::new("./document.txt"), Path::new("./encrypted"), &passphrase, None, |_| {})?;
/// println!("Encrypted to {}", output.display());
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
pub fn symmetric_encrypt(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    passphrase: &SecretString,
    save_as: Option<&Path>,
    on_progress: impl Fn(&str),
) -> Result<PathBuf, CryptoError> {
    validate_passphrase(passphrase)?;
    validate_input_path(input_path.as_ref())?;
    symmetric::encrypt_file(
        input_path.as_ref(),
        output_dir.as_ref(),
        passphrase,
        save_as,
        &on_progress,
    )
}

/// Decrypts a symmetric-encrypted `.fcr` file.
///
/// Returns the path to the extracted output.
pub fn symmetric_decrypt(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    passphrase: &SecretString,
    on_progress: impl Fn(&str),
) -> Result<PathBuf, CryptoError> {
    validate_passphrase(passphrase)?;
    validate_input_path(input_path.as_ref())?;
    symmetric::decrypt_file(
        input_path.as_ref(),
        output_dir.as_ref(),
        passphrase,
        &on_progress,
    )
}

/// Encrypts a file or directory with hybrid (X25519 + XChaCha20-Poly1305) envelope encryption.
///
/// Uses the recipient's public key. No passphrase is needed for encryption.
/// Returns the path to the created `.fcr` file.
pub fn hybrid_encrypt(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    public_key: impl AsRef<Path>,
    save_as: Option<&Path>,
    on_progress: impl Fn(&str),
) -> Result<PathBuf, CryptoError> {
    validate_input_path(input_path.as_ref())?;
    hybrid::encrypt_file(
        input_path.as_ref(),
        output_dir.as_ref(),
        public_key.as_ref(),
        save_as,
        &on_progress,
    )
}

/// Decrypts a hybrid-encrypted `.fcr` file.
///
/// Requires the recipient's private key and its passphrase.
/// Returns the path to the extracted output.
pub fn hybrid_decrypt(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    private_key: impl AsRef<Path>,
    passphrase: &SecretString,
    on_progress: impl Fn(&str),
) -> Result<PathBuf, CryptoError> {
    validate_input_path(input_path.as_ref())?;
    hybrid::decrypt_file(
        input_path.as_ref(),
        output_dir.as_ref(),
        private_key.as_ref(),
        passphrase,
        &on_progress,
    )
}

// ─── Auto-routing convenience wrappers ────────────────────────────────────

/// Auto-detects encrypt vs decrypt by reading the file header.
///
/// Convenience wrapper for CLI/GUI use. Library consumers should prefer
/// the explicit [`symmetric_encrypt`] / [`symmetric_decrypt`] functions.
pub fn symmetric_auto(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    passphrase: &SecretString,
    save_as: Option<&Path>,
    on_progress: impl Fn(&str),
) -> Result<PathBuf, CryptoError> {
    validate_passphrase(passphrase)?;
    let input = input_path.as_ref();
    let output = output_dir.as_ref();
    validate_input_path(input)?;
    if detect_encryption_mode(input)?.is_some() {
        symmetric::decrypt_file(input, output, passphrase, &on_progress)
    } else {
        symmetric::encrypt_file(input, output, passphrase, save_as, &on_progress)
    }
}

/// Auto-detects encrypt vs decrypt by reading the file header.
///
/// Convenience wrapper for CLI/GUI use. Library consumers should prefer
/// the explicit [`hybrid_encrypt`] / [`hybrid_decrypt`] functions.
pub fn hybrid_auto(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    key_file: impl AsRef<Path>,
    passphrase: &SecretString,
    save_as: Option<&Path>,
    on_progress: impl Fn(&str),
) -> Result<PathBuf, CryptoError> {
    let input = input_path.as_ref();
    let output = output_dir.as_ref();
    let key = key_file.as_ref();
    validate_input_path(input)?;
    if detect_encryption_mode(input)?.is_some() {
        hybrid::decrypt_file(input, output, key, passphrase, &on_progress)
    } else {
        hybrid::encrypt_file(input, output, key, save_as, &on_progress)
    }
}

// ─── Key generation ───────────────────────────────────────────────────────

/// Generates and stores an X25519 key pair for hybrid encryption.
///
/// Keys are written into `output_dir` as `private.key` and `public.key`.
/// The `passphrase` encrypts the private key file at rest.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use ferrocrypt::{generate_key_pair, secrecy::SecretString};
///
/// let passphrase = SecretString::from("protect-my-secret-key".to_string());
/// let info = generate_key_pair(&passphrase, Path::new("./my_keys"), |_| {})?;
/// println!("Public key fingerprint: {}", info.fingerprint);
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
pub fn generate_key_pair(
    passphrase: &SecretString,
    output_dir: impl AsRef<Path>,
    on_progress: impl Fn(&str),
) -> Result<KeyPairInfo, CryptoError> {
    let (private_key_path, public_key_path) =
        hybrid::generate_key_pair(passphrase, output_dir.as_ref(), &on_progress)?;
    let fingerprint = public_key_fingerprint(&public_key_path)?;
    Ok(KeyPairInfo {
        private_key_path,
        public_key_path,
        fingerprint,
    })
}
