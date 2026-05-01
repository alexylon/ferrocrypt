//! # ferrocrypt
//!
//! High-level file encryption for files and directories.
//!
//! FerroCrypt writes `.fcr` files using one recipient-oriented v1 container:
//! one random per-file key, one streamed authenticated payload, and one or more
//! typed recipient entries that independently wrap the same file key. The public
//! API exposes this through [`Encryptor`] and [`Decryptor`] rather than through
//! low-level cryptographic building blocks.
//!
//! ## Design goals
//!
//! - **Recipient-oriented encryption**: passphrases and public keys are native
//!   recipient schemes over the same `.fcr` container.
//! - **Path-based file workflows**: archiving, streaming encryption, staging,
//!   and output naming are handled by the library.
//! - **Typed routing**: [`Decryptor::open`] inspects the recipient list and
//!   returns a passphrase or public-recipient decryptor variant.
//! - **Typed diagnostics**: operations return [`CryptoError`] values with
//!   structured format, KDF, recipient, authentication, and I/O failures.
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
//! ## Choosing a recipient path
//!
//! - **Passphrase / symmetric**: use [`Encryptor::with_passphrase`] when the
//!   same passphrase should encrypt and decrypt the file. The resulting `.fcr`
//!   contains exactly one native `argon2id` recipient.
//! - **Public-key / hybrid**: use [`Encryptor::with_recipient`] or
//!   [`Encryptor::with_recipients`] when the sender should encrypt to one or
//!   more public recipient keys. Decryption requires a matching [`PrivateKey`]
//!   file and that key file's passphrase. This does not authenticate the sender.
//!
//! ## Format compatibility
//!
//! The current on-disk format is FerroCrypt v1 for `.fcr`, `public.key`, and
//! `private.key`. Files written by any release that produces format v1 will
//! decrypt under any later release that supports format v1. If a future release
//! introduces format v2, format v1 reading will be maintained for compatibility
//! with older files.
//!
//! Older pre-v1 files and key pairs use a different format family and, for
//! historical hybrid encryption, a different key-agreement stack. To migrate
//! older data, decrypt it with the release that created it, then re-encrypt it
//! with the current release.
//!
//! ## API stability
//!
//! The on-disk format is stable and versioned independently from the crate.
//! The public Rust API ([`Encryptor`], [`Decryptor`], [`PublicKey`],
//! [`PrivateKey`], the error types) is pre-1.0; it may change in minor releases
//! (0.x → 0.y), while patch releases (0.x.y → 0.x.z) preserve it. See the
//! repository [`CHANGELOG.md`](https://github.com/alexylon/ferrocrypt/blob/main/CHANGELOG.md)
//! for release notes.
//!
//! ## Security notes
//!
//! - All cryptographic operations depend on a secure OS RNG; ensure the target
//!   platform provides one.
//! - Sender authentication is out of scope; public-key encryption identifies who
//!   can decrypt, not who encrypted.
//! - Ciphertext integrity is enforced; modification or wrong keys yield
//!   [`CryptoError`] results rather than corrupted plaintext.
//! - This crate is **not** third-party audited and is not advertised as
//!   compliance-certified.
//!
//! ## Error handling
//!
//! Every fallible operation returns `Result<T, CryptoError>`. See
//! [`CryptoError`] for variant meanings and remediation hints.
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
pub use crate::archive::ArchiveLimits;
pub use crate::crypto::kdf::KdfLimit;
pub use crate::error::{CryptoError, FormatDefect, InvalidKdfParams, UnsupportedVersion};
pub use crate::format::{ENCRYPTED_EXTENSION, MAGIC};
pub use crate::key::files::{PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME};
pub use crate::recipient::policy::MixingPolicy;

pub use secrecy;

/// Public classification of the native recipients in an `.fcr` file.
///
/// This is derived from the recipient list by structural inspection only. No
/// passphrase derivation, private-key operation, header MAC verification, or
/// payload decryption is performed during classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncryptionMode {
    /// File contains exactly one native `argon2id` recipient and is decrypted
    /// with a passphrase.
    Passphrase,
    /// File contains one or more native `x25519` public-key recipients and is
    /// decrypted with a matching [`PrivateKey`].
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
mod archive;
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

/// Decodes a Bech32 recipient string (`fcr1…`) into raw X25519 public-key
/// material.
///
/// Validates HRP, BIP 173 checksum, internal SHA3-256 checksum,
/// payload structural fields, type-name grammar, a 1,024-byte local
/// recipient-string cap, and the v1 X25519 payload constraints:
/// `type_name == "x25519"` and exactly 32 bytes of key material.
///
/// This is the low-level primitive; most callers should prefer
/// [`PublicKey::from_recipient_string`] or
/// `"fcr1…".parse::<PublicKey>()`, which wrap this function and yield
/// a typed [`PublicKey`].
pub fn decode_recipient(recipient: &str) -> Result<[u8; 32], CryptoError> {
    key::public::decode_x25519_recipient(recipient)
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

    /// `decode_recipient`'s docstring inlines the recipient-string
    /// local cap as the literal "1,024" because the underlying
    /// constant lives in a private module and rustdoc cannot resolve
    /// an intra-doc link across the privacy boundary. Pin the literal
    /// against the constant so a future bump (e.g. wider caps for
    /// post-quantum recipient strings) cannot silently drift the
    /// docstring out of sync.
    #[test]
    fn decode_recipient_doc_cap_matches_constant() {
        assert_eq!(
            key::public::RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT,
            1_024,
            "decode_recipient docstring inlines the cap value; \
             update both lib.rs:decode_recipient and this test in \
             the same commit if the cap changes"
        );
    }

    /// `decode_recipient` shares the canonical `decode_x25519_recipient`
    /// path with `PublicKey::from_recipient_string`, so it must inherit
    /// the all-zero ingress reject. Pin the contract directly at the
    /// free-function entry so a future refactor that bypasses the
    /// canonical decoder (e.g. inlining the bech32 path) cannot let a
    /// degenerate value through this surface.
    #[test]
    fn decode_recipient_rejects_all_zero_pubkey() {
        let s =
            key::public::encode_recipient_string(recipient::x25519::TYPE_NAME, &[0u8; 32]).unwrap();
        match decode_recipient(&s) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey, got {other:?}"),
        }
    }
}
