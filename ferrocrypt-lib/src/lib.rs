//! # ferrocrypt
//!
//! High-level helpers for encrypting and decrypting files or directories using
//! password-based symmetric encryption or hybrid (asymmetric + symmetric)
//! encryption. Designed for straightforward, scriptable workflows rather than
//! low-level cryptographic building blocks.
//!
//! ## Design goals
//! - **Confidentiality + integrity** for small-to-medium file trees.
//! - **Simple ergonomics**: pick symmetric (password) or hybrid (recipient
//!   public key for encryption, passphrase-protected private key for
//!   decryption) based on your distribution needs.
//! - **Batteries included**: streaming encryption pipeline, path handling,
//!   and output file naming are handled for you.
//!
//! ## Quick start (symmetric / passphrase)
//! ```rust,no_run
//! use ferrocrypt::{Decryptor, Encryptor, CryptoError, secrecy::SecretString};
//!
//! # fn run() -> Result<(), CryptoError> {
//! let passphrase = SecretString::from("correct horse battery staple".to_string());
//!
//! // Encrypt
//! let encrypted = Encryptor::with_passphrase(passphrase.clone())
//!     .write("./secrets", "./out", |ev| eprintln!("{ev}"))?;
//! println!("Encrypted to {}", encrypted.output_path.display());
//!
//! // Decrypt
//! let restored = match Decryptor::open(&encrypted.output_path)? {
//!     Decryptor::Passphrase(d) => d.decrypt(passphrase, "./restored", |ev| eprintln!("{ev}"))?,
//!     Decryptor::Recipient(_) => unreachable!("we just encrypted with a passphrase"),
//!     _ => unreachable!("Decryptor is non_exhaustive; v1 has only Passphrase + Recipient"),
//! };
//! println!("Decrypted to {}", restored.output_path.display());
//! # Ok(()) }
//! # fn main() { run().unwrap(); }
//! ```
//!
//! ## Quick start (hybrid / public-key recipients)
//! ```rust,no_run
//! use ferrocrypt::{
//!     Decryptor, Encryptor, generate_key_pair, PublicKey, PrivateKey,
//!     CryptoError, secrecy::SecretString,
//! };
//!
//! # fn run() -> Result<(), CryptoError> {
//! // 1) Generate X25519 keypair
//! let passphrase = SecretString::from("my-key-pass".to_string());
//! let keys = generate_key_pair("./keys", passphrase.clone(), |ev| eprintln!("{ev}"))?;
//! println!("Fingerprint: {}", keys.fingerprint);
//!
//! // 2) Encrypt with the recipient's public key (no passphrase required)
//! let encrypted = Encryptor::with_recipient(PublicKey::from_key_file(&keys.public_key_path))
//!     .write("./payload", "./out", |ev| eprintln!("{ev}"))?;
//!
//! // 3) Decrypt with the recipient's private key + passphrase
//! let restored = match Decryptor::open(&encrypted.output_path)? {
//!     Decryptor::Recipient(d) => d.decrypt(
//!         PrivateKey::from_key_file(&keys.private_key_path),
//!         passphrase,
//!         "./restored",
//!         |ev| eprintln!("{ev}"),
//!     )?,
//!     Decryptor::Passphrase(_) => unreachable!("we just encrypted to a public key"),
//!     _ => unreachable!("Decryptor is non_exhaustive; v1 has only Passphrase + Recipient"),
//! };
//! println!("Decrypted to {}", restored.output_path.display());
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
//! ## Migrating from 0.2.x
//! Version 0.3.0 introduces on-disk format **v1** (unified across `.fcr` files,
//! `public.key`, and `private.key`) and replaces RSA-4096 with X25519 for hybrid
//! encryption. Files and keys from 0.2.x are **not compatible**. Decrypt any
//! existing data with the old version first, then re-encrypt with 0.3.0.
//!
//! All patch and minor releases within the 0.3.x series will remain backward
//! compatible — files encrypted with 0.3.0 will be readable by any 0.3.x
//! release.
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

#![forbid(unsafe_code)]

#[cfg(all(feature = "fast-kdf", not(debug_assertions)))]
compile_error!("fast-kdf feature must not be used in release builds");

use std::path::PathBuf;

pub use crate::api::{
    Decryptor, Encryptor, PassphraseDecryptor, RecipientDecryptor, default_encrypted_filename,
    detect_encryption_mode, generate_key_pair, validate_private_key_file, validate_public_key_file,
};
pub use crate::archiver::ArchiveLimits;
pub use crate::crypto::kdf::KdfLimit;
pub use crate::error::{CryptoError, FormatDefect, InvalidKdfParams, UnsupportedVersion};
pub use crate::format::ENCRYPTED_EXTENSION;
pub use crate::key::files::{PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME};
pub use crate::recipient::policy::MixingPolicy;

pub use secrecy;

/// The encryption mode used to create an `.fcr` file. Classified from
/// the recipient list per `FORMAT.md` §3.4 / §3.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncryptionMode {
    /// File is sealed by exactly one `argon2id` recipient — the user
    /// decrypts with a passphrase.
    Passphrase,
    /// File is sealed to one or more `x25519` public-key recipients —
    /// the user decrypts with a `PrivateKey` whose public material
    /// matches one of the recipient slots.
    Recipient,
}

/// Structured progress signal emitted during encrypt, decrypt, and key
/// generation.
///
/// Callers receive a reference to a `ProgressEvent` through the closure
/// passed to each operation. The enum is `#[non_exhaustive]` so future
/// phases (per-entry archive progress, byte counters, domain-specific
/// stages) can be added without a breaking change — match arms in caller
/// code must include a `_` wildcard.
///
/// For quick rendering, `ProgressEvent` implements [`std::fmt::Display`]
/// with stable user-facing wording. Consumers that want richer UX
/// (localization, phase-based icons, percent progress once available)
/// can `match` on the variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProgressEvent {
    /// Argon2id is running (passphrase wrap-key derivation, or
    /// `private.key` unlock on the recipient decrypt path) and may
    /// block for multiple seconds.
    DerivingKey,
    /// Encrypting a payload. Emitted once per encrypt call.
    Encrypting,
    /// Decrypting a payload. Emitted once per decrypt call.
    Decrypting,
    /// Generating an X25519 key pair.
    GeneratingKeyPair,
}

impl std::fmt::Display for ProgressEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::DerivingKey => "Deriving key\u{2026}",
            Self::Encrypting => "Encrypting\u{2026}",
            Self::Decrypting => "Decrypting\u{2026}",
            Self::GeneratingKeyPair => "Generating key pair\u{2026}",
        };
        f.write_str(msg)
    }
}

pub use crate::key::private::PrivateKey;
pub use crate::key::public::PublicKey;

/// Alternative name for [`PublicKey`] using the `FORMAT.md` recipient
/// vocabulary. Identical type — choose whichever name reads more
/// naturally at the call site.
pub type RecipientKey = PublicKey;

/// Alternative name for [`PrivateKey`] using the `FORMAT.md` identity
/// vocabulary. Identical type — choose whichever name reads more
/// naturally at the call site.
pub type IdentityKey = PrivateKey;

/// Successful outcome of an [`Encryptor::write`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncryptOutcome {
    /// Path of the resulting `.fcr` file.
    pub output_path: PathBuf,
}

/// Successful outcome of [`PassphraseDecryptor::decrypt`] or
/// [`RecipientDecryptor::decrypt`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecryptOutcome {
    /// Path to the extracted file or directory.
    pub output_path: PathBuf,
}

/// Successful outcome of [`generate_key_pair`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyGenOutcome {
    /// Path to the generated private key file.
    pub private_key_path: PathBuf,
    /// Path to the generated public key file.
    pub public_key_path: PathBuf,
    /// SHA3-256 fingerprint of the public key (64-char hex string).
    pub fingerprint: String,
}

mod api;
mod archiver;
mod container;
mod crypto;
mod error;
mod format;
mod fs;
mod key;
mod protocol;
mod recipient;

#[cfg(feature = "fuzzing")]
pub mod fuzz_exports;

/// Decodes a Bech32 recipient string (`fcr1…`) into raw 32-byte
/// X25519 public-key material.
///
/// Validates HRP, BIP 173 checksum, internal SHA3-256 checksum,
/// payload structural fields, type-name grammar, the
/// [`key::public::RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT`] character
/// cap, and (for v1 X25519 recipients) the recipient `type_name ==
/// "x25519"` and exactly 32-byte key-material length.
///
/// This is the low-level primitive; most callers should prefer
/// [`PublicKey::from_recipient_string`] or
/// `"fcr1…".parse::<PublicKey>()`, which wrap this function and yield
/// a typed [`PublicKey`].
pub fn decode_recipient(recipient: &str) -> Result<[u8; 32], CryptoError> {
    let decoded = key::public::decode_recipient_string(
        recipient,
        key::public::RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT,
    )?;
    if decoded.type_name != recipient::x25519::TYPE_NAME {
        return Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey));
    }
    let bytes: [u8; recipient::x25519::PUBKEY_SIZE] = decoded
        .key_material
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Routes a `.fcr` file with a single `argon2id` recipient as
    /// `EncryptionMode::Passphrase`, mirroring v1's "exactly one
    /// argon2id => Passphrase" classification rule. Builds the file
    /// via `container::build_encrypted_header` so the test exercises
    /// the same byte path the real encrypt would write.
    #[test]
    fn detect_encryption_mode_routes_argon2id_recipient_as_passphrase() {
        let header_key =
            crypto::keys::HeaderKey::from_bytes_for_tests([0x42u8; crypto::mac::HMAC_KEY_SIZE]);
        let payload_key = crypto::keys::PayloadKey::from_bytes_for_tests(
            [0u8; crypto::keys::ENCRYPTION_KEY_SIZE],
        );
        let stream_nonce = [0x07u8; format::STREAM_NONCE_SIZE];
        let entry = recipient::RecipientEntry::native(
            recipient::policy::NativeRecipientType::Argon2id,
            vec![0u8; recipient::argon2id::BODY_LENGTH],
        )
        .unwrap();
        let built = container::build_encrypted_header(
            &[entry],
            b"",
            stream_nonce,
            payload_key,
            &header_key,
        )
        .unwrap();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&built.prefix_bytes);
        bytes.extend_from_slice(&built.header_bytes);
        bytes.extend_from_slice(&built.header_mac);
        std::fs::write(tmp.path(), &bytes).unwrap();

        assert_eq!(
            detect_encryption_mode(tmp.path()).unwrap(),
            Some(EncryptionMode::Passphrase)
        );
    }

    /// Routes a `.fcr` file with one `x25519` recipient as
    /// `EncryptionMode::Recipient`.
    #[test]
    fn detect_encryption_mode_routes_x25519_recipient_as_recipient() {
        let header_key =
            crypto::keys::HeaderKey::from_bytes_for_tests([0x42u8; crypto::mac::HMAC_KEY_SIZE]);
        let payload_key = crypto::keys::PayloadKey::from_bytes_for_tests(
            [0u8; crypto::keys::ENCRYPTION_KEY_SIZE],
        );
        let stream_nonce = [0x07u8; format::STREAM_NONCE_SIZE];
        let entry = recipient::RecipientEntry::native(
            recipient::policy::NativeRecipientType::X25519,
            vec![0u8; recipient::x25519::BODY_LENGTH],
        )
        .unwrap();
        let built = container::build_encrypted_header(
            &[entry],
            b"",
            stream_nonce,
            payload_key,
            &header_key,
        )
        .unwrap();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&built.prefix_bytes);
        bytes.extend_from_slice(&built.header_bytes);
        bytes.extend_from_slice(&built.header_mac);
        std::fs::write(tmp.path(), &bytes).unwrap();

        assert_eq!(
            detect_encryption_mode(tmp.path()).unwrap(),
            Some(EncryptionMode::Recipient)
        );
    }

    /// A non-FerroCrypt file (first 4 bytes are not `FCR\0`) must
    /// route to `Ok(None)` so the encrypt path can treat it as
    /// plaintext. The strict-detection refactor must not regress
    /// this.
    #[test]
    fn detect_encryption_mode_returns_none_for_non_fcr_file() {
        let plaintext = b"this is just a regular text file with no magic at all";
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), plaintext).unwrap();
        assert_eq!(detect_encryption_mode(tmp.path()).unwrap(), None);
    }

    /// An empty file must route to `Ok(None)` (0 bytes < 4 magic
    /// bytes; the magic test fails and detection returns None).
    #[test]
    fn detect_encryption_mode_returns_none_for_empty_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"").unwrap();
        assert_eq!(detect_encryption_mode(tmp.path()).unwrap(), None);
    }

    /// Lock in the exact user-facing Display text for every `ProgressEvent`
    /// variant. CLI and desktop surface `{event}` directly, so a silent
    /// wording change would be a visible UX regression and a format-level
    /// regression for any tooling that parses the strings. If a message
    /// needs to change, update this test in the same commit so the intent
    /// is reviewable.
    #[test]
    fn progress_events_display_exact_strings() {
        assert_eq!(
            ProgressEvent::DerivingKey.to_string(),
            "Deriving key\u{2026}"
        );
        assert_eq!(ProgressEvent::Encrypting.to_string(), "Encrypting\u{2026}");
        assert_eq!(ProgressEvent::Decrypting.to_string(), "Decrypting\u{2026}");
        assert_eq!(
            ProgressEvent::GeneratingKeyPair.to_string(),
            "Generating key pair\u{2026}"
        );
    }
}
