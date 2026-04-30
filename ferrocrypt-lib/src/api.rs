//! Public façade for FerroCrypt's encrypt / decrypt / keygen API.
//!
//! `api.rs` translates stable public types ([`Encryptor`], [`Decryptor`],
//! [`PublicKey`], [`PrivateKey`]) into internal protocol-level calls. It
//! does not derive keys, build headers, compute MACs, or fire progress
//! events directly; that work lives in [`crate::protocol`] and the
//! supporting modules. The module boundary is enforced by visibility:
//! `api.rs` is the only module that surfaces public-API types beyond
//! the helpers re-exported from [`crate`].
//!
//! ## Recipient model
//!
//! - `Encryptor::with_passphrase` — exactly one `argon2id` recipient
//!   (`MixingPolicy::Exclusive`).
//! - `Encryptor::with_recipient` / `with_recipients` — one or more
//!   `x25519` recipients (`MixingPolicy::PublicKeyMixable`). Empty
//!   lists reject as [`CryptoError::EmptyRecipientList`]; lists that
//!   mix incompatible scheme policies (impossible in v1, where every
//!   [`PublicKey`] is X25519) reject as
//!   [`CryptoError::IncompatibleRecipients`].
//!
//! ## Decryptor type-safety
//!
//! [`Decryptor::open`] inspects the file's recipient list (no crypto)
//! and returns a typed variant: [`Decryptor::Passphrase`] for files
//! sealed with a passphrase, [`Decryptor::Recipient`] for files sealed
//! to public keys. Each variant's `decrypt` method accepts only the
//! credentials that variant can actually use, so a mismatched-credential
//! call — e.g. passing a [`PrivateKey`] to a passphrase-sealed file — is
//! a compile error rather than a runtime "no supported recipient" failure.

use std::fs;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret as _, SecretString};

use crate::archive::{self, ArchiveLimits};
use crate::container;
use crate::crypto::kdf::{KdfLimit, KdfParams};
use crate::error::FormatDefect;
use crate::format;
use crate::fs::paths;
use crate::key::files::KeyFileKind;
use crate::key::private::PrivateKey;
use crate::key::public::PublicKey;
use crate::protocol;
use crate::recipient;
use crate::{
    CryptoError, DecryptOutcome, ENCRYPTED_EXTENSION, EncryptOutcome, EncryptionMode,
    KeyGenOutcome, ProgressEvent,
};

// ─── Encryptor ─────────────────────────────────────────────────────────────

/// Builder-style entry point for encryption.
///
/// Pick the recipient kind via the constructor — passphrase
/// ([`Encryptor::with_passphrase`]) or one or more public keys
/// ([`Encryptor::with_recipient`], [`Encryptor::with_recipients`]).
/// Then optionally set an explicit output path
/// ([`Encryptor::save_as`]) or override archive resource caps
/// ([`Encryptor::archive_limits`]). Finalize with
/// [`Encryptor::write`], which streams plaintext through TAR + STREAM
/// directly to disk.
///
/// ## Examples
///
/// Passphrase:
///
/// ```no_run
/// use ferrocrypt::{Encryptor, secrecy::SecretString};
/// let pass = SecretString::from("correct horse battery staple".to_string());
/// let outcome = Encryptor::with_passphrase(pass)
///     .write("./payload", "./out", |ev| eprintln!("{ev}"))?;
/// println!("Encrypted to {}", outcome.output_path.display());
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
///
/// Single public-key recipient:
///
/// ```no_run
/// use ferrocrypt::{Encryptor, PublicKey};
/// let pk = PublicKey::from_key_file("./keys/public.key");
/// let outcome = Encryptor::with_recipient(pk)
///     .write("./payload", "./out", |ev| eprintln!("{ev}"))?;
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
///
/// Multiple public-key recipients:
///
/// ```no_run
/// use ferrocrypt::{Encryptor, PublicKey};
/// let alice = PublicKey::from_key_file("./alice/public.key");
/// let bob = PublicKey::from_key_file("./bob/public.key");
/// let outcome = Encryptor::with_recipients([alice, bob])?
///     .write("./payload", "./out", |ev| eprintln!("{ev}"))?;
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub struct Encryptor {
    state: EncryptorState,
    save_as: Option<PathBuf>,
    archive_limits: Option<ArchiveLimits>,
}

#[derive(Debug)]
enum EncryptorState {
    Passphrase(SecretString),
    Recipients(Vec<PublicKey>),
}

impl Encryptor {
    /// Configures passphrase encryption.
    ///
    /// The resulting `.fcr` contains exactly one native `argon2id`
    /// recipient. The passphrase is checked for non-emptiness when
    /// [`Encryptor::write`] runs; constructing this builder is
    /// infallible.
    pub fn with_passphrase(passphrase: SecretString) -> Self {
        Self {
            state: EncryptorState::Passphrase(passphrase),
            save_as: None,
            archive_limits: None,
        }
    }

    /// Configures encryption to one public-key recipient.
    ///
    /// This is a convenience wrapper around [`Encryptor::with_recipients`]
    /// for the common single-recipient case.
    pub fn with_recipient(recipient: PublicKey) -> Self {
        Self {
            state: EncryptorState::Recipients(vec![recipient]),
            save_as: None,
            archive_limits: None,
        }
    }

    /// Configures encryption to one or more public-key recipients.
    ///
    /// Each recipient entry wraps the same per-file `file_key`
    /// independently, so any listed recipient can decrypt the resulting
    /// `.fcr` with their matching private key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::EmptyRecipientList`] if the iterator is empty.
    /// All public keys in the current v1 implementation are X25519 recipients;
    /// future key kinds may add additional mixing-policy checks.
    pub fn with_recipients(
        recipients: impl IntoIterator<Item = PublicKey>,
    ) -> Result<Self, CryptoError> {
        let recipients: Vec<PublicKey> = recipients.into_iter().collect();
        if recipients.is_empty() {
            return Err(CryptoError::EmptyRecipientList);
        }
        // v1 PublicKey is always X25519 (PublicKeyMixable). When future
        // PublicKey variants carry different mixing policies, the check
        // expands here; protocol::encrypt re-checks as defense-in-depth.
        Ok(Self {
            state: EncryptorState::Recipients(recipients),
            save_as: None,
            archive_limits: None,
        })
    }

    /// Sets the encrypted output file path.
    ///
    /// When set, this path is used instead of the default
    /// `{output_dir}/{stem}.fcr` destination chosen by [`Encryptor::write`].
    pub fn save_as(mut self, path: impl AsRef<Path>) -> Self {
        self.save_as = Some(path.as_ref().to_path_buf());
        self
    }

    /// Overrides the default archive resource caps applied during
    /// the writer-side preflight. Useful for callers operating on
    /// trusted trees that legitimately exceed the defaults.
    pub fn archive_limits(mut self, limits: ArchiveLimits) -> Self {
        self.archive_limits = Some(limits);
        self
    }

    /// Encrypts `input` and writes the resulting `.fcr` file.
    ///
    /// `input` may be a regular file or a directory. Directory inputs are
    /// encoded as FerroCrypt's safe ustar subset before payload encryption.
    /// The default destination is `{output_dir}/{stem}.fcr`; use
    /// [`Encryptor::save_as`] to supply an explicit output file path.
    ///
    /// Errors include invalid inputs, output conflicts, unsupported archive
    /// entries, passphrase validation failure, key wrapping failure, archive
    /// resource-cap failure, and I/O errors.
    pub fn write(
        self,
        input: impl AsRef<Path>,
        output_dir: impl AsRef<Path>,
        on_event: impl Fn(&ProgressEvent),
    ) -> Result<EncryptOutcome, CryptoError> {
        let input = input.as_ref();
        let output_dir = output_dir.as_ref();
        let archive_limits = self.archive_limits.unwrap_or_default();
        let save_as = self.save_as.as_deref();

        // Cheap caller-supplied invariant first so an empty passphrase
        // surfaces before any filesystem syscall — fail fast on the
        // O(1) check before the kernel-side syscall.
        if let EncryptorState::Passphrase(p) = &self.state {
            validate_passphrase(p)?;
        }
        archive::validate_encrypt_input(input)?;

        let output_path = match self.state {
            EncryptorState::Passphrase(passphrase) => {
                let recipient = recipient::argon2id::PassphraseRecipient {
                    passphrase: &passphrase,
                    kdf_params: KdfParams::default(),
                };
                protocol::encrypt(
                    std::slice::from_ref(&recipient),
                    archive_limits,
                    input,
                    output_dir,
                    save_as,
                    &on_event,
                )?
            }
            EncryptorState::Recipients(public_keys) => {
                // Resolve each PublicKey to its 32-byte material once.
                // The local Vec owns the bytes; X25519Recipient borrows
                // from it for the lifetime of this match arm.
                let pubkey_bytes_vec: Vec<[u8; 32]> = public_keys
                    .iter()
                    .map(|pk| pk.to_bytes())
                    .collect::<Result<_, _>>()?;
                let recipients: Vec<recipient::x25519::X25519Recipient> = pubkey_bytes_vec
                    .iter()
                    .map(|bytes| recipient::x25519::X25519Recipient {
                        recipient_pubkey: bytes,
                    })
                    .collect();
                protocol::encrypt(
                    &recipients,
                    archive_limits,
                    input,
                    output_dir,
                    save_as,
                    &on_event,
                )?
            }
        };

        Ok(EncryptOutcome { output_path })
    }
}

// ─── Decryptor ─────────────────────────────────────────────────────────────

/// Type-safe entry point for decryption.
///
/// [`Decryptor::open`] reads the `.fcr` header (no crypto) and returns
/// the variant that matches the file's recipient kind. Each variant
/// takes only the credentials it can use:
///
/// - [`Decryptor::Passphrase`] takes a passphrase.
/// - [`Decryptor::Recipient`] takes a [`PrivateKey`] plus its unlock
///   passphrase.
///
/// A mismatched-credential call — e.g. trying to decrypt a passphrase-sealed
/// file with a [`PrivateKey`] — is therefore a compile error rather than a
/// runtime `NoSupportedRecipient` failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum Decryptor {
    /// File is sealed with a passphrase. Decrypt via
    /// [`PassphraseDecryptor::decrypt`].
    Passphrase(PassphraseDecryptor),
    /// File is sealed to one or more public-key recipients. Decrypt
    /// via [`RecipientDecryptor::decrypt`].
    Recipient(RecipientDecryptor),
}

impl Decryptor {
    /// Probes the `.fcr` header (cheap structural read; no recipient
    /// unwrap, no MAC, no payload bytes touched) and returns the
    /// matching variant.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InputPath`] if `input` does not exist and
    /// [`CryptoError::InvalidInput`] if `input` is a directory. Files that do
    /// not contain a FerroCrypt header return [`CryptoError::InvalidFormat`]
    /// with [`FormatDefect::BadMagic`]. Malformed headers, unsupported
    /// versions, unknown critical recipients, and illegal recipient mixes return
    /// their corresponding `CryptoError` or [`FormatDefect`] variants.
    pub fn open(input: impl AsRef<Path>) -> Result<Self, CryptoError> {
        let input = input.as_ref().to_path_buf();
        validate_input_path(&input)?;
        if input.is_dir() {
            return Err(CryptoError::InvalidInput(format!(
                "Cannot decrypt a directory: {}",
                input.display()
            )));
        }
        let mode = detect_encryption_mode(&input)?
            .ok_or(CryptoError::InvalidFormat(FormatDefect::BadMagic))?;
        match mode {
            EncryptionMode::Passphrase => Ok(Self::Passphrase(PassphraseDecryptor {
                input,
                kdf_limit: None,
            })),
            EncryptionMode::Recipient => Ok(Self::Recipient(RecipientDecryptor {
                input,
                kdf_limit: None,
            })),
        }
    }
}

/// Decryptor for password-sealed `.fcr` files. Returned from
/// [`Decryptor::open`] when the file's recipient list classifies as
/// [`EncryptionMode::Passphrase`].
#[derive(Debug)]
#[non_exhaustive]
pub struct PassphraseDecryptor {
    input: PathBuf,
    kdf_limit: Option<KdfLimit>,
}

impl PassphraseDecryptor {
    /// Sets the maximum Argon2id memory cost accepted from the file header.
    ///
    /// If unset, the decrypt path applies [`KdfLimit::default`].
    pub fn kdf_limit(mut self, limit: KdfLimit) -> Self {
        self.kdf_limit = Some(limit);
        self
    }

    /// Decrypts this passphrase-sealed `.fcr` into `output_dir`.
    ///
    /// The passphrase is checked for non-emptiness, then used to unwrap the
    /// file's `argon2id` recipient. The recovered candidate file key is
    /// accepted only after the header MAC verifies. On success, the decrypted
    /// file or directory is promoted into `output_dir` and returned in
    /// [`DecryptOutcome::output_path`].
    pub fn decrypt(
        self,
        passphrase: SecretString,
        output_dir: impl AsRef<Path>,
        on_event: impl Fn(&ProgressEvent),
    ) -> Result<DecryptOutcome, CryptoError> {
        validate_passphrase(&passphrase)?;
        let identity = recipient::argon2id::PassphraseIdentity {
            passphrase: &passphrase,
            kdf_limit: self.kdf_limit.as_ref(),
        };
        on_event(&ProgressEvent::DerivingKey);
        let output_path =
            protocol::decrypt(&identity, &self.input, output_dir.as_ref(), &on_event)?;
        Ok(DecryptOutcome { output_path })
    }
}

/// Decryptor for public-key-sealed `.fcr` files. Returned from
/// [`Decryptor::open`] when the file's recipient list classifies as
/// [`EncryptionMode::Recipient`].
#[derive(Debug)]
#[non_exhaustive]
pub struct RecipientDecryptor {
    input: PathBuf,
    kdf_limit: Option<KdfLimit>,
}

impl RecipientDecryptor {
    /// Sets the maximum Argon2id memory cost accepted when unlocking
    /// `private.key`.
    ///
    /// If unset, the decrypt path applies [`KdfLimit::default`].
    pub fn kdf_limit(mut self, limit: KdfLimit) -> Self {
        self.kdf_limit = Some(limit);
        self
    }

    /// Decrypts this public-key-recipient `.fcr` into `output_dir`.
    ///
    /// `identity` must reference a FerroCrypt `private.key` file. The private
    /// key is unlocked with `identity_passphrase`, then the decryptor tries the
    /// supported `x25519` recipient slots until one yields a candidate file key
    /// that verifies the header MAC. On success, the decrypted file or directory
    /// is promoted into `output_dir` and returned in
    /// [`DecryptOutcome::output_path`].
    pub fn decrypt(
        self,
        identity: PrivateKey,
        identity_passphrase: SecretString,
        output_dir: impl AsRef<Path>,
        on_event: impl Fn(&ProgressEvent),
    ) -> Result<DecryptOutcome, CryptoError> {
        validate_passphrase(&identity_passphrase)?;
        on_event(&ProgressEvent::DerivingKey);
        let recipient_secret = recipient::native::x25519::open_x25519_private_key(
            identity.key_file_path(),
            &identity_passphrase,
            self.kdf_limit.as_ref(),
        )?;
        let identity_scheme = recipient::x25519::X25519Identity { recipient_secret };
        let output_path = protocol::decrypt(
            &identity_scheme,
            &self.input,
            output_dir.as_ref(),
            &on_event,
        )?;
        Ok(DecryptOutcome { output_path })
    }
}

// ─── Key generation ─────────────────────────────────────────────────────────

/// Generates and stores an X25519 key pair for public-key
/// (recipient) encryption.
///
/// Writes `private.key` (passphrase-wrapped at rest) and `public.key`
/// (UTF-8 `fcr1…` recipient string) into `output_dir`. Returns the
/// final paths plus the SHA3-256 fingerprint of the public key.
///
/// ## Examples
///
/// ```no_run
/// use ferrocrypt::{generate_key_pair, secrecy::SecretString};
/// let pass = SecretString::from("protect-my-key".to_string());
/// let outcome = generate_key_pair("./keys", pass, |ev| eprintln!("{ev}"))?;
/// println!("Fingerprint: {}", outcome.fingerprint);
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
pub fn generate_key_pair(
    output_dir: impl AsRef<Path>,
    passphrase: SecretString,
    on_event: impl Fn(&ProgressEvent),
) -> Result<KeyGenOutcome, CryptoError> {
    validate_passphrase(&passphrase)?;
    let (private_key_path, public_key_path) =
        protocol::generate_key_pair(&passphrase, output_dir.as_ref(), &on_event)?;
    let fingerprint = PublicKey::from_key_file(&public_key_path).fingerprint()?;
    Ok(KeyGenOutcome {
        private_key_path,
        public_key_path,
        fingerprint,
    })
}

// ─── Mode detection ─────────────────────────────────────────────────────────

/// Reads the structural header of an `.fcr` file and classifies its
/// encryption mode from the recipient list.
///
/// Returns `Ok(None)` if the path is a directory, the file is empty,
/// or the first 4 bytes are not the FerroCrypt magic. These cases
/// mean "this isn't a FerroCrypt file at all" — callers route to
/// plaintext encrypt.
///
/// Returns `Ok(Some(EncryptionMode))` when the prefix matches and the
/// header parses and classifies cleanly. The mode is derived from the
/// recipient list: exactly one native `argon2id` recipient maps to
/// [`EncryptionMode::Passphrase`], and one or more supported `x25519`
/// recipients with no `argon2id` recipient map to
/// [`EncryptionMode::Recipient`].
///
/// Returns [`CryptoError::InvalidFormat`] when the magic matches but the
/// prefix or header is malformed (bad version / kind / flags,
/// oversized `header_len`, malformed recipient entries, etc.). The
/// detection pre-check therefore enforces the same structural
/// invariants the decrypt path would, so bit-rotten or
/// attacker-tampered files surface their specific diagnostic at
/// detection time.
///
/// Returns typed recipient-classification errors when the recipient list is
/// structurally valid but cannot be classified: unknown critical recipients,
/// illegal passphrase mixing, or no supported native recipient.
///
/// Returns [`CryptoError::Io`] if the file cannot be opened or read.
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

    let mut file = fs::File::open(path)?;

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
    let parsed =
        container::read_encrypted_header(&mut file, container::HeaderReadLimits::default())?;

    // Structural classification only. `classify_encryption_mode`
    // does not verify the header MAC or run any recipient unwrap.
    let mode = recipient::classify_encryption_mode(&parsed.recipient_entries)?;
    Ok(Some(mode))
}

// ─── Filename + key-file helpers ────────────────────────────────────────────

/// Returns the default encrypted filename for a given input path
/// (e.g. `"secrets.fcr"`). For files, uses the stem (without
/// extension); for directories, uses the full name.
pub fn default_encrypted_filename(input_path: impl AsRef<Path>) -> Result<String, CryptoError> {
    let base_name = paths::encryption_base_name(input_path)?;
    Ok(format!("{}.{}", base_name, ENCRYPTED_EXTENSION))
}

/// Validates that a file is a well-formed FerroCrypt `private.key` file.
///
/// Checks the cleartext v1 structure: magic bytes, version, key-file kind,
/// flags, length fields, X25519 type name, X25519 public-material length, and
/// total file size. This does **not** attempt to decrypt the key and does not
/// require a passphrase. If the caller accidentally points this at a text
/// `public.key`, [`FormatDefect::WrongKeyFileType`] is returned instead of a
/// generic key-file parse error.
pub fn validate_private_key_file(key_file: impl AsRef<Path>) -> Result<(), CryptoError> {
    let data = fs::read(key_file.as_ref()).map_err(paths::map_user_path_io_error)?;
    if matches!(KeyFileKind::classify(&data), KeyFileKind::Public) {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }
    recipient::native::x25519::validate_private_key_shape(&data)
}

/// Validates that a file is a well-formed FerroCrypt `public.key`
/// text file.
///
/// Checks the canonical `fcr1…` recipient string grammar, including
/// Bech32 checksum, HRP, typed payload lengths, type name, key-material
/// length, and internal SHA3-256 checksum. Does **not** require a
/// passphrase. If the caller accidentally
/// points this at a binary `private.key`, [`FormatDefect::WrongKeyFileType`] is
/// returned instead of a UTF-8 decode error.
///
/// Companion to [`validate_private_key_file`].
pub fn validate_public_key_file(key_file: impl AsRef<Path>) -> Result<(), CryptoError> {
    PublicKey::from_key_file(key_file).validate()
}

// ─── Internal validators ────────────────────────────────────────────────────

/// Rejects empty passphrases. Shared by every API entry point that
/// takes a passphrase so the CLI / desktop see the same error class
/// regardless of whether they call the deprecated free functions or
/// the new `Encryptor` / `Decryptor` builders.
pub(crate) fn validate_passphrase(passphrase: &SecretString) -> Result<(), CryptoError> {
    if passphrase.expose_secret().is_empty() {
        return Err(CryptoError::InvalidInput(
            "Passphrase must not be empty".to_string(),
        ));
    }
    Ok(())
}

/// Rejects non-existent input paths early with a typed error
/// ([`CryptoError::InputPath`]) instead of letting the first I/O syscall
/// surface a less informative `Io(NotFound)`.
pub(crate) fn validate_input_path(input_path: &Path) -> Result<(), CryptoError> {
    if !input_path.exists() {
        return Err(CryptoError::InputPath);
    }
    Ok(())
}
