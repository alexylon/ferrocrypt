//! # ferrocrypt
//!
//! High-level file encryption for files and directories.
//!
//! FerroCrypt writes `.fcr` files using one recipient-oriented container:
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
//!   returns a passphrase or private-key decryptor variant.
//! - **Typed diagnostics**: operations return [`CryptoError`] values with
//!   structured format, KDF, recipient, authentication, and I/O failures.
//!
//! ## Quick start (passphrase recipient)
//! ```rust,no_run
//! use ferrocrypt::{Decryptor, Encryptor, CryptoError, Passphrase};
//!
//! # fn run() -> Result<(), CryptoError> {
//! // Encrypt
//! let encrypted = Encryptor::with_passphrase(Passphrase::new("correct horse battery staple"))
//!     .write("./secrets", "./out", |ev| eprintln!("{ev}"))?;
//! println!("Encrypted to {}", encrypted.output_path.display());
//!
//! // Decrypt — each operation consumes its own `Passphrase` value
//! let restored = match Decryptor::open(&encrypted.output_path)? {
//!     Decryptor::Passphrase(d) => d.decrypt(
//!         Passphrase::new("correct horse battery staple"),
//!         "./restored",
//!         |ev| eprintln!("{ev}"),
//!     )?,
//!     Decryptor::PrivateKey(_) => unreachable!("we just encrypted with a passphrase"),
//!     _ => unreachable!("Decryptor is non_exhaustive; only Passphrase and PrivateKey exist today"),
//! };
//! println!("Decrypted to {}", restored.output_path.display());
//! # Ok(()) }
//! # fn main() { run().unwrap(); }
//! ```
//!
//! ## Quick start (public-key recipients)
//! ```rust,no_run
//! use ferrocrypt::{
//!     Decryptor, Encryptor, generate_key_pair, PublicKey, PrivateKey,
//!     CryptoError, Passphrase,
//! };
//!
//! # fn run() -> Result<(), CryptoError> {
//! // 1) Generate X25519 keypair
//! let keys = generate_key_pair("./keys", Passphrase::new("my-key-pass"), |ev| eprintln!("{ev}"))?;
//! println!("Fingerprint: {}", keys.fingerprint);
//!
//! // 2) Encrypt with the recipient's public key (no passphrase required)
//! let encrypted = Encryptor::with_public_key(PublicKey::from_key_file(&keys.public_key_path))
//!     .write("./payload", "./out", |ev| eprintln!("{ev}"))?;
//!
//! // 3) Decrypt with the recipient's private key + its passphrase
//! let restored = match Decryptor::open(&encrypted.output_path)? {
//!     Decryptor::PrivateKey(d) => d.decrypt(
//!         PrivateKey::from_key_file(&keys.private_key_path, Passphrase::new("my-key-pass")),
//!         "./restored",
//!         |ev| eprintln!("{ev}"),
//!     )?,
//!     Decryptor::Passphrase(_) => unreachable!("we just encrypted to a public key"),
//!     _ => unreachable!("Decryptor is non_exhaustive; only Passphrase and PrivateKey exist today"),
//! };
//! println!("Decrypted to {}", restored.output_path.display());
//! # Ok(()) }
//! # fn main() { run().unwrap(); }
//! ```
//!
//! ## Choosing a recipient path
//!
//! - **Passphrase recipient**: use [`Encryptor::with_passphrase`] when the
//!   same passphrase should encrypt and decrypt the file. The resulting `.fcr`
//!   contains exactly one native `argon2id` recipient.
//! - **Public-key recipient**: use [`Encryptor::with_public_key`] or
//!   [`Encryptor::with_public_keys`] when the sender should encrypt to one or
//!   more public recipient keys. Decryption requires a matching [`PrivateKey`]
//!   file and that key file's passphrase. This does not authenticate the sender.
//!
//! ## Format compatibility
//!
//! FerroCrypt stores four independent version bytes: `.fcr` outer-container
//! version `0x01`, FCA archive version `0x01`, public-key encoding version
//! `0x01`, and private-key encoding version `0x01`. The compatibility
//! guarantee starts with the first stable `0.3.0` release. During the
//! `0.3.0` pre-release series (`-alpha.N`, `-beta.N`, `-rc.N`), the format
//! is not yet frozen: files written by a pre-release or by `main` carry no
//! cross-version guarantee and may fail to decrypt under a later pre-release.
//!
//! Stable `0.3.0` establishes the `0.3.0` compatibility baseline
//! (`FORMAT.md` §11.4): artifacts that use only the four stored versions
//! above stay readable under every later release. A future release may
//! introduce a new version in any one domain; that adds support without
//! removing baseline read support.
//!
//! Older pre-`0.3.0` files and key pairs use a different format family and, for
//! historical hybrid encryption, a different key-agreement stack. To migrate
//! older data, decrypt it with the release that created it, then re-encrypt it
//! with the current release.
//!
//! ## API stability
//!
//! The on-disk format is versioned independently from the crate; see
//! *Format compatibility* above for its stability guarantee.
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
//! - Passphrase and key-pair writing reject Argon2id memory below a fixed
//!   19 MiB floor with [`CryptoError::KdfBelowWriteFloor`], so a `.fcr` or
//!   `private.key` cannot be sealed with a weak passphrase work factor by
//!   accident. The floor applies only when writing; decryption accepts any
//!   structurally valid file.
//! - FerroCrypt authenticates each file as written, but it does not detect
//!   replay or rollback to an older valid `.fcr`; use external versioning or a
//!   freshness check if that matters.
//! - FerroCrypt encrypts file contents and, for directory inputs, internal
//!   names, tree structure, and per-file sizes. It does not hide the total
//!   ciphertext length (an approximate plaintext-size signal), recipient count,
//!   or that the file is a FerroCrypt `.fcr` container.
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
#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]
#![warn(rustdoc::bare_urls)]

use std::path::PathBuf;

/// The version of this crate, captured from `Cargo.toml` at compile time.
///
/// Exposed as a single source of truth so dependents — notably the FerroCrypt
/// desktop app — can show the version that the release process actually bumps,
/// rather than each crate carrying its own copy that can drift.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use crate::api::{
    Decryptor, Encryptor, KeyPairGenerator, PassphraseDecryptor, PrivateKeyDecryptor,
    default_encrypted_filename, generate_key_pair, probe_recipient_mode,
    probe_recipient_mode_with_limits, validate_private_key_file, validate_public_key_file,
};
pub use crate::archive::{ArchiveLimits, IncompleteOutputPolicy};
pub use crate::container::HeaderReadLimits;
pub use crate::crypto::kdf::{ARGON2_SALT_SIZE, KDF_PARAMS_SIZE, KdfLimit, KdfParams};
pub use crate::error::{CryptoError, FormatDefect, InvalidKdfParams, UnsupportedVersion};
pub use crate::format::{ENCRYPTED_EXTENSION, FCR_FILE_V1_VERSION, FCR_FILE_VERSION, MAGIC};
pub use crate::key::files::{PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME};
pub use crate::key::limits::KeyReadLimits;
pub use crate::key::private::{PRIVATE_KEY_V1_VERSION, PRIVATE_KEY_VERSION};
pub use crate::key::public::{PUBLIC_KEY_V1_VERSION, PUBLIC_KEY_VERSION};
pub use crate::passphrase::Passphrase;
pub use crate::recipient::policy::MixingPolicy;

/// Result of a cheap structural probe of an `.fcr` file's recipient list.
///
/// **Not a security claim.** [`probe_recipient_mode`] performs no KDF, no
/// private-key operation, no credential prompt, no header-MAC verification,
/// and no payload decryption. A positive result is not evidence that the file
/// is authentic, decryptable, untampered, or well-formed beyond the structural
/// shape required to classify it. Use only for UI / routing hints.
///
/// For an authenticated mode value — produced only after a recipient unwraps
/// and the header MAC verifies — see [`AuthenticatedRecipientMode`] on
/// [`DecryptOutcome`].
///
/// The variants are categorical and carry no data, which is what lets the
/// enum stay `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnauthenticatedRecipientMode {
    /// File contains exactly one native `argon2id` recipient and is decrypted
    /// with a passphrase.
    Passphrase,
    /// File contains one or more native `x25519` public-key recipients and is
    /// decrypted with a matching [`PrivateKey`].
    PublicKey,
}

impl std::fmt::Display for UnauthenticatedRecipientMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Passphrase => "passphrase",
            Self::PublicKey => "public-key",
        };
        f.write_str(label)
    }
}

impl UnauthenticatedRecipientMode {
    /// Name of the credential the caller must supply to decrypt a file in
    /// this mode. Used by the `DecryptorModeMismatch` error wording so the
    /// message tells the caller which credential to switch to instead of
    /// leaving them to infer it from the recipient kind.
    pub(crate) const fn credential_name(self) -> &'static str {
        match self {
            Self::Passphrase => "a passphrase",
            Self::PublicKey => "a private key",
        }
    }
}

/// Recipient mode established by a successful authenticated decrypt.
///
/// Constructed only inside the decrypt path after a recipient unwraps **and**
/// the header MAC verifies. Cannot be forged from an
/// [`UnauthenticatedRecipientMode`]: the wrapping struct has a private field
/// and a `pub(crate)` constructor, so external callers can match on the
/// exposed [`AuthenticatedRecipientModeKind`] but cannot manufacture a value
/// that claims to be authenticated.
///
/// The struct holds only that kind value, which is what lets it stay
/// `Copy`.
///
/// Surfaced on [`DecryptOutcome::recipient_mode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedRecipientMode {
    kind: AuthenticatedRecipientModeKind,
}

/// Public, forward-compatible discriminant for
/// [`AuthenticatedRecipientMode`]. The variant carries no authentication
/// authority on its own — only an [`AuthenticatedRecipientMode`] value does,
/// and that wrapper is unforgeable outside the crate.
///
/// `#[non_exhaustive]` keeps the door open for future native recipient kinds
/// (post-quantum, hardware-backed) without breaking downstream `match`
/// arms; callers must include a `_` wildcard arm. This is match
/// ergonomics, not exhaustive matching. Those future kinds are
/// discriminants carrying no data, which is what lets the enum stay
/// `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthenticatedRecipientModeKind {
    /// File was sealed with a passphrase recipient (`argon2id`).
    Passphrase,
    /// File was sealed to one or more public-key recipients (`x25519`).
    PublicKey,
}

impl AuthenticatedRecipientMode {
    pub(crate) const fn passphrase() -> Self {
        Self {
            kind: AuthenticatedRecipientModeKind::Passphrase,
        }
    }

    pub(crate) const fn public_key() -> Self {
        Self {
            kind: AuthenticatedRecipientModeKind::PublicKey,
        }
    }

    /// Returns the public discriminant for `match` ergonomics.
    pub const fn kind(&self) -> AuthenticatedRecipientModeKind {
        self.kind
    }

    /// `true` if the file authenticated as a passphrase recipient.
    pub const fn is_passphrase(&self) -> bool {
        matches!(self.kind, AuthenticatedRecipientModeKind::Passphrase)
    }

    /// `true` if the file authenticated as a public-key recipient.
    pub const fn is_public_key(&self) -> bool {
        matches!(self.kind, AuthenticatedRecipientModeKind::PublicKey)
    }
}

impl std::fmt::Display for AuthenticatedRecipientModeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Passphrase => "passphrase",
            Self::PublicKey => "public-key",
        };
        f.write_str(label)
    }
}

impl std::fmt::Display for AuthenticatedRecipientMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.kind.fmt(f)
    }
}

/// Structured progress signal emitted during encrypt, decrypt, and key
/// generation.
///
/// Callers receive a reference to a `ProgressEvent` through the closure
/// passed to each operation. The enum is `#[non_exhaustive]` so future
/// phases (per-entry archive progress, byte counters, domain-specific
/// stages) can be added without a breaking change — match arms in caller
/// code must include a `_` wildcard. Future variant payloads stay
/// `Eq`-comparable (progress quantities are integers, never
/// floating-point), so the derived `PartialEq` / `Eq` are stable. The
/// enum deliberately does not implement `Copy`: those future payloads
/// are not closed to `Copy`-compatible data, and an entry path or label
/// would carry an owned `String`.
///
/// For quick rendering, `ProgressEvent` implements [`std::fmt::Display`]
/// with stable user-facing wording. Consumers that want richer UX
/// (localization, phase-based icons, percent progress once available)
/// can `match` on the variants.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProgressEvent {
    /// Argon2id is about to run to derive the passphrase wrap key for
    /// an `argon2id` recipient. Emitted at the work boundary inside the
    /// recipient module — after structural validation and resource-cap
    /// checks, immediately before the KDF call. Fires zero times for a
    /// pure public-key (X25519) `.fcr` and zero times when a malformed
    /// `.fcr` is rejected before any KDF runs. May block for multiple
    /// seconds.
    DerivingPassphraseWrapKey,
    /// Argon2id is about to run to unlock a `private.key` file. Emitted
    /// at the work boundary inside the key-file reader — after structural
    /// validation and resource-cap checks, immediately before the KDF
    /// call. Fires zero times when the `private.key` is malformed and
    /// rejected before any KDF runs. May block for multiple seconds.
    UnlockingPrivateKey,
    /// Encrypting a payload. Emitted once per encrypt call.
    Encrypting,
    /// Decrypting a payload. Emitted once per decrypt call.
    Decrypting,
    /// Generating an X25519 key pair. Covers the entire generation flow,
    /// including the Argon2id-driven sealing of `private.key`. The library
    /// does not emit a nested [`Self::DerivingPassphraseWrapKey`] inside
    /// keygen; this event already signals the long pause.
    GeneratingKeyPair,
}

impl std::fmt::Display for ProgressEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::DerivingPassphraseWrapKey => "Deriving passphrase key\u{2026}",
            Self::UnlockingPrivateKey => "Unlocking private key\u{2026}",
            Self::Encrypting => "Encrypting\u{2026}",
            Self::Decrypting => "Decrypting\u{2026}",
            Self::GeneratingKeyPair => "Generating key pair\u{2026}",
        };
        f.write_str(msg)
    }
}

pub use crate::key::private::PrivateKey;
pub use crate::key::public::PublicKey;

/// Successful outcome of an [`Encryptor::write`] call.
///
/// Fields added later stay `Eq`-comparable (quantities are integers,
/// never floating-point), so the derived `Eq` is stable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncryptOutcome {
    /// Path of the resulting `.fcr` file.
    pub output_path: PathBuf,
}

/// Successful outcome of [`PassphraseDecryptor::decrypt`] or
/// [`PrivateKeyDecryptor::decrypt`].
///
/// Fields added later stay `Eq`-comparable (quantities are integers,
/// never floating-point), so the derived `Eq` is stable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecryptOutcome {
    /// Path to the extracted file or directory.
    pub output_path: PathBuf,
    /// Recipient mode established by the authenticated decrypt: recipient
    /// unwrap plus header MAC verification. This value is unforgeable by
    /// callers; only the decrypt path can construct it. Distinct from the
    /// cheap pre-authentication [`UnauthenticatedRecipientMode`] returned by
    /// [`probe_recipient_mode`].
    pub recipient_mode: AuthenticatedRecipientMode,
}

/// Successful outcome of [`generate_key_pair`] or
/// [`KeyPairGenerator::write`].
///
/// Fields added later stay `Eq`-comparable (quantities are integers,
/// never floating-point), so the derived `Eq` is stable.
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
mod passphrase;
mod protocol;
mod recipient;

#[cfg(feature = "unstable-fuzzing")]
#[doc(hidden)]
pub mod fuzz_exports;

#[cfg(test)]
mod suite_vector_gen;

/// Decodes a Bech32 recipient string (`fcr1…`) into raw X25519 public-key
/// material.
///
/// Validates HRP, BIP 173 checksum, internal SHA3-256 checksum,
/// payload structural fields, type-name grammar, the
/// [`KeyReadLimits::RECIPIENT_STRING_CHARS_DEFAULT`] recipient-string
/// cap, and the X25519 payload constraints:
/// `type_name == "x25519"` and exactly 32 bytes of non-zero,
/// canonically encoded key material (`FORMAT.md` §2.4 / §7).
///
/// This is the low-level primitive; most callers should prefer
/// [`PublicKey::from_recipient_string`] or
/// `"fcr1…".parse::<PublicKey>()`, which wrap this function and yield
/// a typed [`PublicKey`].
///
/// # Errors
///
/// Returns [`CryptoError::InvalidFormat`] with
/// [`FormatDefect::MalformedPublicKey`] for non-ASCII, uppercase, invalid
/// Bech32, or wrong-HRP strings, for malformed typed payloads and checksum
/// mismatches, and for all-zero or non-canonical X25519 public keys; a payload
/// type name that is not valid UTF-8 or breaks the type-name grammar reports
/// [`FormatDefect::MalformedTypeName`] instead. Returns
/// [`CryptoError::UnsupportedVersion`] for a recipient string from an
/// unsupported keypair suite. Returns [`CryptoError::UnsupportedKeyType`] for a
/// valid recipient string of a key type this build does not support. Returns
/// [`CryptoError::RecipientStringCapExceeded`] when the input exceeds the local
/// recipient-string cap.
pub fn decode_x25519_recipient_string(recipient_string: &str) -> Result<[u8; 32], CryptoError> {
    key::public::decode_x25519_recipient(recipient_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Routes a `.fcr` file with a single `argon2id` recipient as
    /// `UnauthenticatedRecipientMode::Passphrase`, mirroring the "exactly one
    /// argon2id => Passphrase" classification rule. Builds the file
    /// via `container::build_encrypted_header` so the test exercises
    /// the same byte path the real encrypt would write.
    #[test]
    fn probe_recipient_mode_routes_argon2id_recipient_as_passphrase() {
        let header_key =
            crypto::keys::HeaderKey::from_bytes_for_tests([0x42u8; crypto::mac::HMAC_KEY_SIZE]);
        let payload_key = crypto::keys::PayloadKey::from_bytes_for_tests(
            [0u8; crypto::keys::ENCRYPTION_KEY_SIZE],
        );
        let stream_nonce = [0x07u8; crypto::stream::STREAM_NONCE_SIZE];
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
            probe_recipient_mode(tmp.path()).unwrap(),
            Some(UnauthenticatedRecipientMode::Passphrase)
        );
    }

    /// Routes a `.fcr` file with one `x25519` recipient as
    /// `UnauthenticatedRecipientMode::PublicKey`.
    #[test]
    fn probe_recipient_mode_routes_x25519_recipient_as_public_key() {
        let header_key =
            crypto::keys::HeaderKey::from_bytes_for_tests([0x42u8; crypto::mac::HMAC_KEY_SIZE]);
        let payload_key = crypto::keys::PayloadKey::from_bytes_for_tests(
            [0u8; crypto::keys::ENCRYPTION_KEY_SIZE],
        );
        let stream_nonce = [0x07u8; crypto::stream::STREAM_NONCE_SIZE];
        // 0x11 filler keeps the ephemeral-key field non-zero and
        // canonical, so the body passes the structural preflight.
        let entry = recipient::RecipientEntry::native(
            recipient::policy::NativeRecipientType::X25519,
            vec![0x11u8; recipient::x25519::BODY_LENGTH],
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
            probe_recipient_mode(tmp.path()).unwrap(),
            Some(UnauthenticatedRecipientMode::PublicKey)
        );
    }

    /// A non-FerroCrypt file (first 4 bytes are not `FCR\0`) must
    /// route to `Ok(None)` so the encrypt path can treat it as
    /// plaintext. The strict-detection refactor must not regress
    /// this.
    #[test]
    fn probe_recipient_mode_returns_none_for_non_fcr_file() {
        let plaintext = b"this is just a regular text file with no magic at all";
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), plaintext).unwrap();
        assert_eq!(probe_recipient_mode(tmp.path()).unwrap(), None);
    }

    /// An empty file must route to `Ok(None)` (0 bytes < 4 magic
    /// bytes; the magic test fails and detection returns None).
    #[test]
    fn probe_recipient_mode_returns_none_for_empty_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"").unwrap();
        assert_eq!(probe_recipient_mode(tmp.path()).unwrap(), None);
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
            ProgressEvent::DerivingPassphraseWrapKey.to_string(),
            "Deriving passphrase key\u{2026}"
        );
        assert_eq!(
            ProgressEvent::UnlockingPrivateKey.to_string(),
            "Unlocking private key\u{2026}"
        );
        assert_eq!(ProgressEvent::Encrypting.to_string(), "Encrypting\u{2026}");
        assert_eq!(ProgressEvent::Decrypting.to_string(), "Decrypting\u{2026}");
        assert_eq!(
            ProgressEvent::GeneratingKeyPair.to_string(),
            "Generating key pair\u{2026}"
        );
    }

    /// `decode_x25519_recipient_string` shares the canonical
    /// `decode_x25519_recipient` path with `PublicKey::from_recipient_string`,
    /// so it must inherit the all-zero input rejection. Pin the contract
    /// directly at the free-function entry so a future refactor that bypasses
    /// the canonical decoder cannot let a degenerate value through this
    /// surface.
    #[test]
    fn decode_x25519_recipient_string_rejects_all_zero_public_key() {
        let s = key::public::encode_recipient_string_unchecked(
            recipient::x25519::TYPE_NAME,
            &[0u8; 32],
        )
        .unwrap();
        match decode_x25519_recipient_string(&s) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey, got {other:?}"),
        }
    }

    /// Pin `UnauthenticatedRecipientMode`'s rendered strings at the type's
    /// home so a future variant rename or label tweak surfaces here, not only
    /// via the indirect `DecryptorModeMismatch` Display test in `error.rs`.
    /// `#[non_exhaustive]` is irrelevant inside the defining crate — adding a
    /// new variant produces a compile error here until the test handles it.
    #[test]
    fn unauthenticated_recipient_mode_display_pinned_strings() {
        assert_eq!(
            UnauthenticatedRecipientMode::Passphrase.to_string(),
            "passphrase"
        );
        assert_eq!(
            UnauthenticatedRecipientMode::PublicKey.to_string(),
            "public-key"
        );
        match UnauthenticatedRecipientMode::Passphrase {
            UnauthenticatedRecipientMode::Passphrase | UnauthenticatedRecipientMode::PublicKey => {}
        }
    }

    /// Mirror the `UnauthenticatedRecipientMode` Display pin for the
    /// authenticated kind discriminant. The strings are deliberately
    /// identical to the unauthenticated side so downstream rendering
    /// (logs, audit trails) does not need to branch on authentication
    /// state. The two enums (`UnauthenticatedRecipientMode` and
    /// `AuthenticatedRecipientModeKind`) keep separate Display impls so
    /// either side can drift without dragging the other; the wrapper
    /// `AuthenticatedRecipientMode::Display` delegates to its `kind`, so
    /// the wrapper inherits whatever the discriminant prints.
    #[test]
    fn authenticated_recipient_mode_display_pinned_strings() {
        assert_eq!(
            AuthenticatedRecipientModeKind::Passphrase.to_string(),
            "passphrase"
        );
        assert_eq!(
            AuthenticatedRecipientModeKind::PublicKey.to_string(),
            "public-key"
        );
        // Wrapper delegates to its kind.
        assert_eq!(
            AuthenticatedRecipientMode::passphrase().to_string(),
            "passphrase"
        );
        assert_eq!(
            AuthenticatedRecipientMode::public_key().to_string(),
            "public-key"
        );
    }

    /// Lock in the kind discriminator so the public exhaustive-match surface
    /// stays a stable shape: callers use `kind()` to switch on the variant
    /// without touching the sealed wrapper.
    #[test]
    fn authenticated_recipient_mode_kind_round_trips() {
        assert_eq!(
            AuthenticatedRecipientMode::passphrase().kind(),
            AuthenticatedRecipientModeKind::Passphrase
        );
        assert_eq!(
            AuthenticatedRecipientMode::public_key().kind(),
            AuthenticatedRecipientModeKind::PublicKey
        );
        assert!(AuthenticatedRecipientMode::passphrase().is_passphrase());
        assert!(!AuthenticatedRecipientMode::passphrase().is_public_key());
        assert!(AuthenticatedRecipientMode::public_key().is_public_key());
        assert!(!AuthenticatedRecipientMode::public_key().is_passphrase());
    }
}
