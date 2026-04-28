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
//! ## Quick start (symmetric)
//! ```rust,no_run
//! use ferrocrypt::{
//!     symmetric_encrypt, symmetric_decrypt, SymmetricEncryptConfig,
//!     SymmetricDecryptConfig, CryptoError, secrecy::SecretString,
//! };
//!
//! # fn run() -> Result<(), CryptoError> {
//! let passphrase = SecretString::from("correct horse battery staple".to_string());
//!
//! // Encrypt
//! let encrypted = symmetric_encrypt(
//!     SymmetricEncryptConfig::new("./secrets", "./out", passphrase.clone()),
//!     |ev| eprintln!("{ev}"),
//! )?;
//! println!("Encrypted to {}", encrypted.output_path.display());
//!
//! // Decrypt
//! let decrypted = symmetric_decrypt(
//!     SymmetricDecryptConfig::new(&encrypted.output_path, "./restored", passphrase),
//!     |ev| eprintln!("{ev}"),
//! )?;
//! println!("Decrypted to {}", decrypted.output_path.display());
//! # Ok(()) }
//! # fn main() { run().unwrap(); }
//! ```
//!
//! ## Quick start (hybrid)
//! ```rust,no_run
//! use ferrocrypt::{
//!     generate_key_pair, hybrid_encrypt, hybrid_decrypt,
//!     KeyGenConfig, HybridEncryptConfig, HybridDecryptConfig,
//!     PublicKey, PrivateKey,
//!     CryptoError, secrecy::SecretString,
//! };
//!
//! # fn run() -> Result<(), CryptoError> {
//! // 1) Generate X25519 keypair
//! let passphrase = SecretString::from("my-key-pass".to_string());
//! let keys = generate_key_pair(
//!     KeyGenConfig::new("./keys", passphrase.clone()),
//!     |ev| eprintln!("{ev}"),
//! )?;
//! println!("Fingerprint: {}", keys.fingerprint);
//!
//! // 2) Encrypt with public key (no passphrase needed)
//! let encrypted = hybrid_encrypt(
//!     HybridEncryptConfig::new(
//!         "./payload", "./out",
//!         PublicKey::from_key_file(&keys.public_key_path),
//!     ),
//!     |ev| eprintln!("{ev}"),
//! )?;
//!
//! // 3) Decrypt with private key + passphrase
//! let decrypted = hybrid_decrypt(
//!     HybridDecryptConfig::new(
//!         &encrypted.output_path, "./restored",
//!         PrivateKey::from_key_file(&keys.private_key_path), passphrase,
//!     ),
//!     |ev| eprintln!("{ev}"),
//! )?;
//! println!("Decrypted to {}", decrypted.output_path.display());
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

use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret as _, SecretString};

pub use crate::common::KdfLimit;
pub use crate::error::{CryptoError, FormatDefect, InvalidKdfParams, UnsupportedVersion};
pub use crate::format::ENCRYPTED_EXTENSION;
pub use crate::hybrid::{PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME};

pub use secrecy;

/// The encryption mode used to create an `.fcr` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncryptionMode {
    /// Password-based symmetric encryption (XChaCha20-Poly1305 + Argon2id).
    Symmetric,
    /// Public/private key hybrid encryption (X25519 + XChaCha20-Poly1305).
    Hybrid,
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
    /// Argon2id or hybrid KDF is running and may block for multiple seconds.
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

/// A FerroCrypt X25519 public key.
///
/// Abstracts over the source of the key material: a stored public-key
/// file on disk, raw 32-byte key material, or a decoded Bech32 `fcr1…`
/// recipient string. Filesystem sources defer I/O until the key is
/// actually used, so construction is infallible for the file and bytes
/// variants.
///
/// Once constructed, a `PublicKey` can be:
/// - passed to [`hybrid_encrypt`] via [`HybridEncryptConfig::new`] as the
///   recipient for envelope encryption,
/// - rendered as a Bech32 `fcr1…` recipient string via
///   [`PublicKey::to_recipient_string`],
/// - fingerprinted via [`PublicKey::fingerprint`].
///
/// The struct is `#[non_exhaustive]` so future sources (key servers,
/// hardware-backed keys) can be added without a breaking change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PublicKey {
    source: PublicKeySource,
}

#[derive(Debug, Clone)]
enum PublicKeySource {
    KeyFile(PathBuf),
    Bytes([u8; 32]),
}

impl PublicKey {
    /// References a FerroCrypt public-key file at the given path. The
    /// file is not opened until a method that needs the key material
    /// (e.g. [`fingerprint`](Self::fingerprint),
    /// [`to_recipient_string`](Self::to_recipient_string)) is called.
    pub fn from_key_file(path: impl AsRef<Path>) -> Self {
        Self {
            source: PublicKeySource::KeyFile(path.as_ref().to_path_buf()),
        }
    }

    /// Wraps raw 32-byte X25519 public-key material directly.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            source: PublicKeySource::Bytes(bytes),
        }
    }

    /// Decodes a canonical lowercase Bech32 `fcr1…` recipient string
    /// (as produced by [`PublicKey::to_recipient_string`] or the
    /// `ferrocrypt recipient` subcommand) into a `PublicKey`. Validates
    /// HRP, BIP 173 checksum, internal SHA3-256 checksum, payload
    /// structural fields, type-name grammar, and (for v1 X25519
    /// recipients) the recipient `type_name == "x25519"` and 32-byte
    /// key-material length.
    pub fn from_recipient_string(recipient: &str) -> Result<Self, CryptoError> {
        Ok(Self::from_bytes(decode_recipient(recipient)?))
    }

    /// Computes the SHA3-256 fingerprint of the X25519 recipient as a
    /// 64-character lowercase hex string. Domain-separated by the
    /// recipient `type_name` ("x25519") so future native types
    /// (post-quantum, hybrid KEMs, etc.) cannot collide with this
    /// namespace. Output matches `public_key::fingerprint_hex` and the
    /// `ferrocrypt recipient` subcommand.
    pub fn fingerprint(&self) -> Result<String, CryptoError> {
        let bytes = self.resolve()?;
        Ok(public_key::fingerprint_hex(
            recipients::x25519::TYPE_NAME,
            &bytes,
        ))
    }

    /// Encodes the key as the canonical Bech32 `fcr1…` recipient
    /// string. Routes through `public_key::encode_recipient_string`
    /// with the X25519 type name. Performs filesystem I/O for the
    /// key-file source.
    pub fn to_recipient_string(&self) -> Result<String, CryptoError> {
        let bytes = self.resolve()?;
        public_key::encode_recipient_string(recipients::x25519::TYPE_NAME, &bytes)
    }

    /// Returns the raw 32-byte X25519 public-key material as an owned
    /// array. Performs filesystem I/O for the key-file source.
    pub fn to_bytes(&self) -> Result<[u8; 32], CryptoError> {
        self.resolve()
    }

    /// Validates that the key source is well-formed without exposing
    /// the bytes. For a key-file source this opens the file, parses
    /// the header, and checks the layout; for a bytes source this is
    /// always `Ok(())`.
    pub fn validate(&self) -> Result<(), CryptoError> {
        self.resolve().map(|_| ())
    }

    /// Resolves the key to raw 32-byte material, reading the key file
    /// from disk if the source is a path.
    fn resolve(&self) -> Result<[u8; 32], CryptoError> {
        match &self.source {
            PublicKeySource::KeyFile(path) => hybrid::read_public_key(path),
            PublicKeySource::Bytes(bytes) => Ok(*bytes),
        }
    }
}

impl std::str::FromStr for PublicKey {
    type Err = CryptoError;

    /// Parses a Bech32 `fcr1…` recipient string into a `PublicKey`.
    /// Equivalent to [`PublicKey::from_recipient_string`], enabling
    /// `"fcr1…".parse::<PublicKey>()`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_recipient_string(s)
    }
}

/// Source of a private key for hybrid decryption.
///
/// Today the only supported source is a passphrase-protected FerroCrypt
/// private-key file on disk. The wrapper is kept deliberately thin and
/// `#[non_exhaustive]` so future sources (for example in-memory encrypted
/// secrets or hardware-backed keys) can be added without a breaking
/// change to [`HybridDecryptConfig`].
///
/// Construct with [`PrivateKey::from_key_file`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PrivateKey {
    source: PrivateKeySource,
}

#[derive(Debug, Clone)]
enum PrivateKeySource {
    KeyFile(PathBuf),
}

impl PrivateKey {
    /// References a passphrase-protected FerroCrypt private-key file at
    /// the given path. The file is not opened until the private key is
    /// used in a decrypt operation.
    pub fn from_key_file(path: impl AsRef<Path>) -> Self {
        Self {
            source: PrivateKeySource::KeyFile(path.as_ref().to_path_buf()),
        }
    }

    /// Internal: returns the key-file path for source variants that
    /// point at one. Every current variant does; future non-path
    /// sources would extend this enum and the decrypt path with a
    /// different resolution strategy.
    fn key_file_path(&self) -> &Path {
        match &self.source {
            PrivateKeySource::KeyFile(path) => path,
        }
    }
}

/// Configuration for [`symmetric_encrypt`].
///
/// Built via [`SymmetricEncryptConfig::new`]. Optional fields are set
/// with builder-style methods. The struct is `#[non_exhaustive]` so
/// future fields can be added without a breaking change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SymmetricEncryptConfig {
    /// Input file or directory to encrypt.
    pub input: PathBuf,
    /// Destination directory for the encrypted output. Ignored when
    /// [`save_as`](Self::save_as) is set.
    pub output_dir: PathBuf,
    /// Password that drives the Argon2id KDF.
    pub passphrase: SecretString,
    /// Explicit output file path. Overrides the default
    /// `{stem}.fcr` naming inside `output_dir`.
    pub save_as: Option<PathBuf>,
}

impl SymmetricEncryptConfig {
    /// Starts a config with the required fields. `save_as` defaults to
    /// `None`.
    pub fn new(
        input: impl AsRef<Path>,
        output_dir: impl AsRef<Path>,
        passphrase: SecretString,
    ) -> Self {
        Self {
            input: input.as_ref().to_path_buf(),
            output_dir: output_dir.as_ref().to_path_buf(),
            passphrase,
            save_as: None,
        }
    }

    /// Sets the explicit output file path.
    pub fn save_as(mut self, path: impl AsRef<Path>) -> Self {
        self.save_as = Some(path.as_ref().to_path_buf());
        self
    }
}

/// Configuration for [`symmetric_decrypt`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SymmetricDecryptConfig {
    /// Input `.fcr` file produced by symmetric encryption.
    pub input: PathBuf,
    /// Directory into which the decrypted output is written.
    pub output_dir: PathBuf,
    /// Password that drives the Argon2id KDF.
    pub passphrase: SecretString,
    /// Optional cap on the KDF memory cost accepted from the file header.
    /// `None` uses the built-in default ceiling.
    pub kdf_limit: Option<KdfLimit>,
}

impl SymmetricDecryptConfig {
    /// Starts a config with the required fields. `kdf_limit` defaults
    /// to `None`.
    pub fn new(
        input: impl AsRef<Path>,
        output_dir: impl AsRef<Path>,
        passphrase: SecretString,
    ) -> Self {
        Self {
            input: input.as_ref().to_path_buf(),
            output_dir: output_dir.as_ref().to_path_buf(),
            passphrase,
            kdf_limit: None,
        }
    }

    /// Sets the KDF memory-cost ceiling.
    pub fn kdf_limit(mut self, limit: KdfLimit) -> Self {
        self.kdf_limit = Some(limit);
        self
    }
}

/// Configuration for [`hybrid_encrypt`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HybridEncryptConfig {
    /// Input file or directory to encrypt.
    pub input: PathBuf,
    /// Destination directory for the encrypted output. Ignored when
    /// [`save_as`](Self::save_as) is set.
    pub output_dir: PathBuf,
    /// Recipient's X25519 public key. Used to wrap the per-file
    /// encryption key via the envelope construction.
    pub public_key: PublicKey,
    /// Explicit output file path. Overrides the default
    /// `{stem}.fcr` naming inside `output_dir`.
    pub save_as: Option<PathBuf>,
}

impl HybridEncryptConfig {
    /// Starts a config with the required fields.
    pub fn new(
        input: impl AsRef<Path>,
        output_dir: impl AsRef<Path>,
        public_key: PublicKey,
    ) -> Self {
        Self {
            input: input.as_ref().to_path_buf(),
            output_dir: output_dir.as_ref().to_path_buf(),
            public_key,
            save_as: None,
        }
    }

    /// Sets the explicit output file path.
    pub fn save_as(mut self, path: impl AsRef<Path>) -> Self {
        self.save_as = Some(path.as_ref().to_path_buf());
        self
    }
}

/// Configuration for [`hybrid_decrypt`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HybridDecryptConfig {
    /// Input `.fcr` file produced by hybrid encryption.
    pub input: PathBuf,
    /// Directory into which the decrypted output is written.
    pub output_dir: PathBuf,
    /// Recipient's private key.
    pub private_key: PrivateKey,
    /// Passphrase that unlocks the private key.
    pub passphrase: SecretString,
    /// Optional cap on the KDF memory cost accepted when unlocking
    /// the private key. `None` uses the built-in default ceiling.
    pub kdf_limit: Option<KdfLimit>,
}

impl HybridDecryptConfig {
    /// Starts a config with the required fields. `kdf_limit` defaults
    /// to `None`.
    pub fn new(
        input: impl AsRef<Path>,
        output_dir: impl AsRef<Path>,
        private_key: PrivateKey,
        passphrase: SecretString,
    ) -> Self {
        Self {
            input: input.as_ref().to_path_buf(),
            output_dir: output_dir.as_ref().to_path_buf(),
            private_key,
            passphrase,
            kdf_limit: None,
        }
    }

    /// Sets the KDF memory-cost ceiling for unlocking the private key.
    pub fn kdf_limit(mut self, limit: KdfLimit) -> Self {
        self.kdf_limit = Some(limit);
        self
    }
}

/// Configuration for [`generate_key_pair`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct KeyGenConfig {
    /// Directory into which the `private.key` and `public.key` files
    /// are written.
    pub output_dir: PathBuf,
    /// Passphrase that encrypts the private-key file at rest.
    pub passphrase: SecretString,
}

impl KeyGenConfig {
    /// Starts a config with the required fields.
    pub fn new(output_dir: impl AsRef<Path>, passphrase: SecretString) -> Self {
        Self {
            output_dir: output_dir.as_ref().to_path_buf(),
            passphrase,
        }
    }
}

/// Successful outcome of a symmetric or hybrid encrypt operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncryptOutcome {
    /// Path of the resulting `.fcr` file.
    pub output_path: PathBuf,
}

/// Successful outcome of a symmetric or hybrid decrypt operation.
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

/// Reads the structural header of an `.fcr` file and classifies its
/// encryption mode from the recipient list.
///
/// Returns `Ok(None)` if the path is a directory, the file is empty,
/// or the first 4 bytes are not the FerroCrypt magic. These cases
/// mean "this isn't a FerroCrypt file at all" — callers route to
/// plaintext encrypt.
///
/// Returns `Ok(Some(EncryptionMode))` when the prefix matches and the
/// header parses + classifies cleanly. The mode is derived from the
/// recipient list per `FORMAT.md` §3.4 / §3.5 (one `argon2id` →
/// `Symmetric`, one or more supported `x25519` → `Hybrid`); see
/// [`recipients::classify_encryption_mode`] for the full rule set.
///
/// Returns `Err(InvalidFormat)` when the magic matches but the
/// prefix or header is malformed (bad version / kind / flags,
/// oversized `header_len`, malformed recipient entries, etc.). The
/// detection pre-check therefore enforces the same structural
/// invariants the decrypt path would, so bit-rotten or
/// attacker-tampered files surface their specific diagnostic at
/// detection time.
///
/// Returns `Err(...)` typed under the recipient classification rules
/// when the recipient list is structurally valid but cannot be
/// classified: `UnknownCriticalRecipient` for an unknown critical
/// entry, `PassphraseRecipientMixed` for a mixed-passphrase file,
/// `NoSupportedRecipient` for a list with no supported native entry.
///
/// Returns `Err(Io)` if the file cannot be opened or read.
///
/// **Detection is structural, not cryptographic.** No recipient
/// unwrap runs (no Argon2id, no X25519 ECDH, no private-key
/// operations), no header MAC is verified, and no payload bytes are
/// decrypted. A canonical header that would later fail recipient
/// unwrap or MAC verify still returns `Ok(Some(_))` here — those
/// checks require running the full decrypt.
pub fn detect_encryption_mode(
    file_path: impl AsRef<Path>,
) -> Result<Option<EncryptionMode>, CryptoError> {
    use std::io::{Read, Seek, SeekFrom};
    let path = file_path.as_ref();

    // Short-circuit directories up-front so the behavior is uniform across
    // platforms. Without this pre-check, Unix lets us open a directory and
    // only fails at `read()` with `IsADirectory`, while Windows' `CreateFile`
    // refuses to open directories outright (requires `FILE_FLAG_BACKUP_SEMANTICS`)
    // and surfaces as `ERROR_ACCESS_DENIED` — indistinguishable from a real
    // permission error. One explicit check, one answer, on every platform.
    if path.is_dir() {
        return Ok(None);
    }

    let mut file = std::fs::File::open(path)?;

    // Peek the 4-byte magic. Anything that doesn't claim to be a
    // FerroCrypt file (empty, too short, wrong magic) routes to
    // plaintext-encrypt as `Ok(None)`. Once magic matches, `Ok(None)`
    // is no longer reachable: a magic-claiming file must surface as
    // a valid header or a typed structural error.
    let mut magic_buf = [0u8; format::MAGIC_SIZE];
    let mut filled = 0;
    while filled < magic_buf.len() {
        match file.read(&mut magic_buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // Defensive: on Unix, a TOCTOU race could swap the pre-checked
            // path for a directory between `is_dir()` and `File::open()`.
            // Keep the runtime handler so the race is still classified
            // correctly instead of surfacing as a generic I/O error.
            Err(e) if e.kind() == std::io::ErrorKind::IsADirectory => return Ok(None),
            Err(e) => return Err(CryptoError::Io(e)),
        }
    }
    if filled < magic_buf.len() || magic_buf != format::MAGIC {
        return Ok(None);
    }

    // Magic matched. Rewind the same handle and run the structural
    // reader against the full prefix + header. Using `seek` instead
    // of dropping and re-opening avoids both an extra syscall and a
    // TOCTOU window where the path could be swapped between checks.
    file.seek(SeekFrom::Start(0))?;
    let parsed = encrypted_file::read_encrypted_header(
        &mut file,
        encrypted_file::HeaderReadLimits::default(),
    )?;

    // Structural classification only. `classify_encryption_mode`
    // does not verify the header MAC or run any recipient unwrap.
    let mode = recipients::classify_encryption_mode(&parsed.recipient_entries)?;
    Ok(Some(mode))
}

mod archiver;
mod atomic_output;
mod common;
mod encrypted_file;
mod error;
mod format;
mod hybrid;
mod private_key;
mod public_key;
mod recipients;
mod symmetric;

#[cfg(feature = "fuzzing")]
pub mod fuzz_exports;

/// Decodes a Bech32 recipient string (`fcr1…`) into raw 32-byte
/// X25519 public-key material.
///
/// Validates HRP, BIP 173 checksum, internal SHA3-256 checksum,
/// payload structural fields, type-name grammar, the
/// [`public_key::RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT`] character
/// cap, and (for v1 X25519 recipients) the recipient `type_name ==
/// "x25519"` and exactly 32-byte key-material length.
///
/// This is the low-level primitive; most callers should prefer
/// [`PublicKey::from_recipient_string`] or
/// `"fcr1…".parse::<PublicKey>()`, which wrap this function and yield
/// a typed [`PublicKey`].
pub fn decode_recipient(recipient: &str) -> Result<[u8; 32], CryptoError> {
    let decoded = public_key::decode_recipient_string(
        recipient,
        public_key::RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT,
    )?;
    if decoded.type_name != recipients::x25519::TYPE_NAME {
        return Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey));
    }
    let bytes: [u8; recipients::x25519::PUBKEY_SIZE] =
        decoded
            .key_material
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey))?;
    Ok(bytes)
}

/// Validates that a file is a well-formed FerroCrypt `private.key` file.
///
/// Checks magic bytes, version, type, algorithm, `ext_len` bound, and
/// total file size. Does **not** attempt to decrypt the key (no
/// passphrase needed). If the caller accidentally points this at a
/// text `public.key`, the friendly
/// [`FormatDefect::WrongKeyFileType`] surfaces instead of a generic
/// `NotAKeyFile`.
pub fn validate_private_key_file(key_file: impl AsRef<Path>) -> Result<(), CryptoError> {
    let data = std::fs::read(key_file.as_ref()).map_err(hybrid::map_user_path_io_error)?;
    if matches!(
        hybrid::KeyFileKind::classify(&data),
        hybrid::KeyFileKind::Public
    ) {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }
    hybrid::validate_private_key_shape(&data)
}

/// Validates that a file is a well-formed FerroCrypt `public.key`
/// text file.
///
/// Checks the canonical `fcr1…` recipient string grammar (Bech32
/// checksum, HRP, algorithm byte, key-material length). Does
/// **not** require any passphrase. If the caller accidentally
/// points this at a binary `private.key`, the friendly
/// [`FormatDefect::WrongKeyFileType`] surfaces instead of a UTF-8
/// decode error.
///
/// Symmetric to [`validate_private_key_file`]; thin wrapper
/// around [`PublicKey::from_key_file`] + [`PublicKey::validate`]
/// for callers who already have a path and want a free function.
pub fn validate_public_key_file(key_file: impl AsRef<Path>) -> Result<(), CryptoError> {
    PublicKey::from_key_file(key_file).validate()
}

/// Returns the default encrypted filename for a given input path (e.g. `"secrets.fcr"`).
/// For files, uses the stem (without extension). For directories, uses the full name.
pub fn default_encrypted_filename(input_path: impl AsRef<Path>) -> Result<String, CryptoError> {
    let base_name = common::encryption_base_name(input_path)?;
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
        return Err(CryptoError::InputPath);
    }
    Ok(())
}

// ─── Operation API ────────────────────────────────────────────────────────

/// Encrypts a file or directory with password-based symmetric encryption.
///
/// # Examples
///
/// ```no_run
/// use ferrocrypt::{symmetric_encrypt, SymmetricEncryptConfig, secrecy::SecretString};
///
/// let passphrase = SecretString::from("my-secret-password".to_string());
/// let config = SymmetricEncryptConfig::new("./document.txt", "./encrypted", passphrase);
/// let outcome = symmetric_encrypt(config, |ev| eprintln!("{ev}"))?;
/// println!("Encrypted to {}", outcome.output_path.display());
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
pub fn symmetric_encrypt(
    config: SymmetricEncryptConfig,
    on_event: impl Fn(&ProgressEvent),
) -> Result<EncryptOutcome, CryptoError> {
    validate_passphrase(&config.passphrase)?;
    archiver::validate_encrypt_input(&config.input)?;
    let output_path = symmetric::encrypt_file(
        &config.input,
        &config.output_dir,
        &config.passphrase,
        config.save_as.as_deref(),
        &on_event,
    )?;
    Ok(EncryptOutcome { output_path })
}

/// Decrypts a symmetric-encrypted `.fcr` file.
pub fn symmetric_decrypt(
    config: SymmetricDecryptConfig,
    on_event: impl Fn(&ProgressEvent),
) -> Result<DecryptOutcome, CryptoError> {
    validate_passphrase(&config.passphrase)?;
    validate_input_path(&config.input)?;
    let output_path = symmetric::decrypt_file(
        &config.input,
        &config.output_dir,
        &config.passphrase,
        config.kdf_limit.as_ref(),
        &on_event,
    )?;
    Ok(DecryptOutcome { output_path })
}

/// Encrypts a file or directory with hybrid (X25519 + XChaCha20-Poly1305)
/// envelope encryption.
///
/// The recipient is supplied as a [`PublicKey`] inside
/// [`HybridEncryptConfig`]. The `PublicKey` can wrap a public-key file
/// path, raw 32-byte key material, or a decoded Bech32 `fcr1…` string
/// — see [`PublicKey`] for the available constructors.
///
/// # Examples
///
/// ```no_run
/// use ferrocrypt::{hybrid_encrypt, HybridEncryptConfig, PublicKey};
///
/// let public_key = PublicKey::from_key_file("./keys/public.key");
/// let config = HybridEncryptConfig::new("./payload", "./out", public_key);
/// let outcome = hybrid_encrypt(config, |ev| eprintln!("{ev}"))?;
/// println!("Encrypted to {}", outcome.output_path.display());
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
pub fn hybrid_encrypt(
    config: HybridEncryptConfig,
    on_event: impl Fn(&ProgressEvent),
) -> Result<EncryptOutcome, CryptoError> {
    archiver::validate_encrypt_input(&config.input)?;
    let public_key_bytes = config.public_key.resolve()?;
    let output_path = hybrid::encrypt_file_from_bytes(
        &config.input,
        &config.output_dir,
        &public_key_bytes,
        config.save_as.as_deref(),
        &on_event,
    )?;
    Ok(EncryptOutcome { output_path })
}

/// Decrypts a hybrid-encrypted `.fcr` file.
pub fn hybrid_decrypt(
    config: HybridDecryptConfig,
    on_event: impl Fn(&ProgressEvent),
) -> Result<DecryptOutcome, CryptoError> {
    validate_passphrase(&config.passphrase)?;
    validate_input_path(&config.input)?;
    let output_path = hybrid::decrypt_file(
        &config.input,
        &config.output_dir,
        config.private_key.key_file_path(),
        &config.passphrase,
        config.kdf_limit.as_ref(),
        &on_event,
    )?;
    Ok(DecryptOutcome { output_path })
}

// ─── Key generation ───────────────────────────────────────────────────────

/// Generates and stores an X25519 key pair for hybrid encryption.
///
/// Keys are written into `config.output_dir` as `private.key` and
/// `public.key`. The passphrase encrypts the private key file at rest.
///
/// # Examples
///
/// ```no_run
/// use ferrocrypt::{generate_key_pair, KeyGenConfig, secrecy::SecretString};
///
/// let passphrase = SecretString::from("protect-my-secret-key".to_string());
/// let config = KeyGenConfig::new("./my_keys", passphrase);
/// let outcome = generate_key_pair(config, |ev| eprintln!("{ev}"))?;
/// println!("Public key fingerprint: {}", outcome.fingerprint);
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
pub fn generate_key_pair(
    config: KeyGenConfig,
    on_event: impl Fn(&ProgressEvent),
) -> Result<KeyGenOutcome, CryptoError> {
    validate_passphrase(&config.passphrase)?;
    let (private_key_path, public_key_path) =
        hybrid::generate_key_pair(&config.passphrase, &config.output_dir, &on_event)?;
    let fingerprint = PublicKey::from_key_file(&public_key_path).fingerprint()?;
    Ok(KeyGenOutcome {
        private_key_path,
        public_key_path,
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Routes a `.fcr` file with a single `argon2id` recipient as
    /// `EncryptionMode::Symmetric`, mirroring v1's "exactly one
    /// argon2id => Symmetric" classification rule. Builds the file
    /// via `encrypted_file::build_encrypted_header` so the test
    /// exercises the same byte path the real encrypt would write.
    #[test]
    fn detect_encryption_mode_routes_argon2id_recipient_as_symmetric() {
        let header_key = [0x42u8; common::HMAC_KEY_SIZE];
        let payload_key = zeroize::Zeroizing::new([0u8; common::ENCRYPTION_KEY_SIZE]);
        let stream_nonce = [0x07u8; format::STREAM_NONCE_SIZE];
        let entry = recipients::RecipientEntry::native(
            recipients::NativeRecipientType::Argon2id,
            vec![0u8; recipients::argon2id::BODY_LENGTH],
        )
        .unwrap();
        let built = encrypted_file::build_encrypted_header(
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
            Some(EncryptionMode::Symmetric)
        );
    }

    /// Routes a `.fcr` file with one `x25519` recipient as
    /// `EncryptionMode::Hybrid`.
    #[test]
    fn detect_encryption_mode_routes_x25519_recipient_as_hybrid() {
        let header_key = [0x42u8; common::HMAC_KEY_SIZE];
        let payload_key = zeroize::Zeroizing::new([0u8; common::ENCRYPTION_KEY_SIZE]);
        let stream_nonce = [0x07u8; format::STREAM_NONCE_SIZE];
        let entry = recipients::RecipientEntry::native(
            recipients::NativeRecipientType::X25519,
            vec![0u8; recipients::x25519::BODY_LENGTH],
        )
        .unwrap();
        let built = encrypted_file::build_encrypted_header(
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
            Some(EncryptionMode::Hybrid)
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

    /// `Debug` on every config struct that holds a passphrase must not
    /// leak the passphrase contents. The `secrecy` crate's
    /// `SecretString` implements Debug as a redaction marker; this test
    /// pins the invariant against accidental `#[derive(Debug)]` drift
    /// (e.g. replacing the `SecretString` field with a raw `String`)
    /// for every current passphrase-carrying config.
    #[test]
    fn config_debug_does_not_leak_passphrase() {
        const PASSPHRASE: &str = "super-secret-passphrase";
        let pass = || SecretString::from(PASSPHRASE.to_string());

        let assert_no_leak = |rendered: String, label: &str| {
            assert!(
                !rendered.contains(PASSPHRASE),
                "{label} leaked passphrase into Debug output: {rendered}"
            );
        };

        assert_no_leak(
            format!(
                "{:?}",
                SymmetricEncryptConfig::new("/tmp/in", "/tmp/out", pass())
            ),
            "SymmetricEncryptConfig",
        );
        assert_no_leak(
            format!(
                "{:?}",
                SymmetricDecryptConfig::new("/tmp/in", "/tmp/out", pass())
            ),
            "SymmetricDecryptConfig",
        );
        assert_no_leak(
            format!(
                "{:?}",
                HybridDecryptConfig::new(
                    "/tmp/in",
                    "/tmp/out",
                    PrivateKey::from_key_file("/tmp/key"),
                    pass(),
                )
            ),
            "HybridDecryptConfig",
        );
        assert_no_leak(
            format!("{:?}", KeyGenConfig::new("/tmp/dir", pass())),
            "KeyGenConfig",
        );
    }
}
