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
//! ## Quick start (symmetric path, mirrors `ferrocrypt symmetric` CLI)
//! ```rust,no_run
//! use std::path::Path;
//! use ferrocrypt::{symmetric_encryption, CryptoError, secrecy::SecretString};
//!
//! # fn run() -> Result<(), CryptoError> {
//! // Encrypt a folder to out/secrets.fcr
//! let passphrase = SecretString::from("correct horse battery staple".to_string());
//! let produced = symmetric_encryption(Path::new("./secrets"), Path::new("./out"), &passphrase, None, |_| {})?;
//! println!("wrote {produced}");
//!
//! // Decrypt the archive back
//! let recovered = symmetric_encryption(Path::new("./out/secrets.fcr"), Path::new("./restored"), &passphrase, None, |_| {})?;
//! println!("restored to {recovered}");
//! # Ok(()) }
//! # fn main() { run().unwrap(); }
//! ```
//!
//! ## Quick start (hybrid path, mirrors `ferrocrypt hybrid` CLI)
//! ```rust,no_run
//! use std::path::Path;
//! use ferrocrypt::{generate_key_pair, hybrid_encryption, CryptoError, secrecy::SecretString};
//!
//! # fn run() -> Result<(), CryptoError> {
//! // 1) Generate X25519 keypair files under ./keys
//! //    The passphrase encrypts the private key file at rest
//! let passphrase = SecretString::from("my-key-pass".to_string());
//! let _msg = generate_key_pair(&passphrase, Path::new("./keys"), |_| {})?;
//!
//! // 2) Encrypt to out/payload.fcr using the public key (no passphrase needed)
//! let empty_passphrase = SecretString::from("".to_string());
//! let produced = hybrid_encryption(
//!     Path::new("./payload"), Path::new("./out"), Path::new("./keys/public.key"),
//!     &empty_passphrase, None, |_| {},
//! )?;
//! println!("wrote {produced}");
//!
//! // 3) Decrypt out/payload.fcr using the private key + passphrase to unlock it
//! let restored = hybrid_encryption(
//!     Path::new("./out/payload.fcr"), Path::new("./restored"), Path::new("./keys/private.key"),
//!     &passphrase, None, |_| {},
//! )?;
//! println!("restored to {restored}");
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

use std::path::Path;

use secrecy::{ExposeSecret, SecretString};

use crate::common::{bytes_to_hex, sha3_32_hash};
pub use crate::error::CryptoError;
pub use crate::format::ENCRYPTED_EXTENSION;

pub use secrecy;

/// The encryption mode used to create an `.fcr` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    Symmetric,
    Hybrid,
}

/// Reads the triple-replicated header prefix of an `.fcr` file and returns the encryption mode.
/// Returns `None` if the file is not a valid FerroCrypt file.
pub fn detect_encryption_mode(file_path: impl AsRef<Path>) -> Option<EncryptionMode> {
    use std::io::Read;
    let mut buf = [0u8; format::HEADER_PREFIX_ENCODED_SIZE];
    let mut file = std::fs::File::open(file_path.as_ref()).ok()?;
    file.read_exact(&mut buf).ok()?;
    let prefix = replication::rep_decode(&buf).ok()?;
    if prefix.len() < 2 || prefix[0] != format::MAGIC_BYTE {
        return None;
    }
    match prefix[1] {
        format::TYPE_SYMMETRIC => Some(EncryptionMode::Symmetric),
        format::TYPE_HYBRID => Some(EncryptionMode::Hybrid),
        _ => None,
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
    format::validate_key_file_header(
        &data,
        format::KEY_FILE_TYPE_PUBLIC,
        format::PUBLIC_KEY_DATA_SIZE,
    )?;
    let key_bytes = &data
        [format::KEY_FILE_HEADER_SIZE..format::KEY_FILE_HEADER_SIZE + format::PUBLIC_KEY_DATA_SIZE];
    let hash = sha3_32_hash(key_bytes)?;
    Ok(bytes_to_hex(&hash))
}

/// Validates that a file is a well-formed FerroCrypt private key file.
///
/// Checks magic byte, key type, version, algorithm, and exact file size.
/// Does **not** attempt to decrypt the key (no passphrase needed).
pub fn validate_secret_key_file(key_file: impl AsRef<Path>) -> Result<(), CryptoError> {
    let data = std::fs::read(key_file.as_ref())?;
    format::validate_key_file_header(
        &data,
        format::KEY_FILE_TYPE_SECRET,
        format::SECRET_KEY_DATA_SIZE,
    )
}

/// Returns the default encrypted filename for a given input path (e.g. `"secrets.fcr"`).
/// For files, uses the stem (without extension). For directories, uses the full name.
pub fn default_encrypted_filename(input_path: impl AsRef<Path>) -> Result<String, CryptoError> {
    let base_name = common::get_encryption_base_name(input_path)?;
    Ok(format!("{}.{}", base_name, ENCRYPTED_EXTENSION))
}

fn validate_input_path(input_path: &Path) -> Result<(), CryptoError> {
    if !input_path.exists() {
        return Err(CryptoError::InputPath(input_path.display().to_string()));
    }
    Ok(())
}

/// Encrypt or decrypt files/directories using password-based symmetric crypto.
///
/// - **Encrypt**: if `input_path` is not a FerroCrypt symmetric file, it is
///   packaged and encrypted to `output_dir` (writing `<name>.fcr`).
/// - **Decrypt**: if `input_path` is a FerroCrypt symmetric file (detected by
///   magic bytes), it is decrypted and extracted into `output_dir`.
///
/// `save_as` overrides the output file path during encryption (ignored for
/// decryption). `on_progress` receives stage descriptions like "Deriving key…".
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use ferrocrypt::{symmetric_encryption, secrecy::SecretString};
///
/// let passphrase = SecretString::from("my-secret-password".to_string());
/// // Encrypt
/// let result = symmetric_encryption(Path::new("./document.txt"), Path::new("./encrypted"), &passphrase, None, |_| {})?;
/// // Decrypt
/// let result = symmetric_encryption(Path::new("./encrypted/document.fcr"), Path::new("./decrypted"), &passphrase, None, |_| {})?;
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
pub fn symmetric_encryption(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    password: &SecretString,
    save_as: Option<&Path>,
    on_progress: impl Fn(&str),
) -> Result<String, CryptoError> {
    if password.expose_secret().is_empty() {
        return Err(CryptoError::InvalidInput(
            "Passphrase must not be empty for symmetric encryption".to_string(),
        ));
    }
    let input = input_path.as_ref();
    let output = output_dir.as_ref();
    validate_input_path(input)?;
    if detect_encryption_mode(input).is_some() {
        symmetric::decrypt_file(input, output, password, &on_progress)
    } else {
        symmetric::encrypt_file(input, output, password, save_as, &on_progress)
    }
}

/// Encrypt or decrypt using hybrid (X25519 + XChaCha20-Poly1305) envelope encryption.
///
/// - `key_file` is a **file path** to the key (not the key contents).
/// - **Encrypt** when `input_path` is not a FerroCrypt file: uses the public
///   key file at `key_file` to seal a random symmetric key, producing
///   `<name>.fcr`. The `passphrase` parameter is **ignored during encryption**
///   (pass empty string).
/// - **Decrypt** when `input_path` is a FerroCrypt hybrid file: uses the
///   private key file at `key_file`. The `passphrase` is **required** to
///   decrypt the private key file (must match the passphrase used when
///   generating the keypair).
///
/// `save_as` overrides the output file path during encryption (ignored for
/// decryption). `on_progress` receives stage descriptions at each major step.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use ferrocrypt::{hybrid_encryption, secrecy::SecretString};
///
/// let empty = SecretString::from("".to_string());
/// // Encrypt
/// let result = hybrid_encryption(
///     Path::new("./secrets"), Path::new("./encrypted"), Path::new("./keys/public.key"),
///     &empty, None, |_| {},
/// )?;
/// // Decrypt
/// let passphrase = SecretString::from("my-key-passphrase".to_string());
/// let result = hybrid_encryption(
///     Path::new("./encrypted/secrets.fcr"), Path::new("./decrypted"), Path::new("./keys/private.key"),
///     &passphrase, None, |_| {},
/// )?;
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
pub fn hybrid_encryption(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    key_file: impl AsRef<Path>,
    passphrase: &SecretString,
    save_as: Option<&Path>,
    on_progress: impl Fn(&str),
) -> Result<String, CryptoError> {
    let input = input_path.as_ref();
    let output = output_dir.as_ref();
    let key = key_file.as_ref();
    validate_input_path(input)?;
    if detect_encryption_mode(input).is_some() {
        hybrid::decrypt_file(input, output, key, passphrase, &on_progress)
    } else {
        hybrid::encrypt_file(input, output, key, save_as, &on_progress)
    }
}

/// Generate and store an X25519 key pair for hybrid encryption.
///
/// - Keys are written into `output_dir` as `private.key` and `public.key`.
/// - The `passphrase` **encrypts the private key file** for protection at rest
///   (via Argon2id + XChaCha20-Poly1305); the same passphrase is needed later
///   when decrypting. The public key file is unencrypted.
///
/// `on_progress` receives stage descriptions at each major step.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use ferrocrypt::{generate_key_pair, secrecy::SecretString};
///
/// let passphrase = SecretString::from("protect-my-secret-key".to_string());
/// let result = generate_key_pair(&passphrase, Path::new("./my_keys"), |_| {})?;
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
pub fn generate_key_pair(
    passphrase: &SecretString,
    output_dir: impl AsRef<Path>,
    on_progress: impl Fn(&str),
) -> Result<String, CryptoError> {
    hybrid::generate_key_pair(passphrase, output_dir.as_ref(), &on_progress)
}
