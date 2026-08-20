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
//! - `Encryptor::with_public_key` / `with_public_keys` — one or more
//!   `x25519` recipients (`MixingPolicy::PublicKeyMixable`). Empty
//!   lists reject as [`CryptoError::EmptyRecipientList`]; lists that
//!   mix incompatible scheme policies (impossible today, where every
//!   [`PublicKey`] is X25519) reject as
//!   [`CryptoError::IncompatibleRecipients`].
//!
//! ## Decryptor type-safety
//!
//! [`Decryptor::open`] inspects the file's recipient list without
//! cryptographic work and returns a typed variant: [`Decryptor::Passphrase`]
//! for files sealed with a passphrase, [`Decryptor::PrivateKey`] for files
//! sealed to public keys. Each variant's `decrypt` method accepts only the
//! credentials that variant can use, so a mismatched-credential call — for
//! example, passing a [`PrivateKey`] to a passphrase-sealed file — is a compile
//! error rather than a runtime "no supported recipient" failure.

use std::path::{Path, PathBuf};

use crate::passphrase::Passphrase;

use crate::archive::{self, ArchiveLimits, IncompleteOutputPolicy};
use crate::container::{self, HeaderReadLimits};
use crate::crypto::kdf::{KdfLimit, KdfParams};
use crate::error::{FormatDefect, sanitize_path_for_display};
use crate::format;
use crate::fs::paths;
use crate::key::files::KeyFileKind;
use crate::key::limits::KeyReadLimits;
use crate::key::private::PrivateKey;
use crate::key::public::PublicKey;
use crate::protocol;
use crate::recipient;
use crate::recipient::policy::NativeRecipientType;
use crate::{
    AuthenticatedRecipientMode, CryptoError, DecryptOutcome, ENCRYPTED_EXTENSION, EncryptOutcome,
    KeyGenOutcome, ProgressEvent, UnauthenticatedRecipientMode,
};

// ─── Encryptor ─────────────────────────────────────────────────────────────

/// Builder-style entry point for encryption.
///
/// Pick the recipient kind via the constructor — passphrase
/// ([`Encryptor::with_passphrase`]) or one or more public keys
/// ([`Encryptor::with_public_key`], [`Encryptor::with_public_keys`]).
/// Then optionally set an explicit output path
/// ([`Encryptor::save_as`]) or override archive resource caps
/// ([`Encryptor::archive_limits`]). Finalize with
/// [`Encryptor::write`], which streams plaintext through the FCA
/// archive layer + XChaCha20-Poly1305 STREAM-BE32 directly to disk.
///
/// # Examples
///
/// Passphrase:
///
/// ```no_run
/// use ferrocrypt::{Encryptor, Passphrase};
/// let pass = Passphrase::new("correct horse battery staple");
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
/// let pk = PublicKey::from_key_file("./keys/public.key")?;
/// let outcome = Encryptor::with_public_key(pk)
///     .write("./payload", "./out", |ev| eprintln!("{ev}"))?;
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
///
/// Multiple public-key recipients:
///
/// ```no_run
/// use ferrocrypt::{Encryptor, PublicKey};
/// let alice = PublicKey::from_key_file("./alice/public.key")?;
/// let bob = PublicKey::from_key_file("./bob/public.key")?;
/// let outcome = Encryptor::with_public_keys([alice, bob])?
///     .write("./payload", "./out", |ev| eprintln!("{ev}"))?;
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub struct Encryptor {
    state: EncryptorState,
    save_as: Option<PathBuf>,
    archive_limits: Option<ArchiveLimits>,
    kdf_params: Option<KdfParams>,
    header_read_limits: Option<HeaderReadLimits>,
    kdf_limit: Option<KdfLimit>,
}

#[derive(Debug)]
enum EncryptorState {
    Passphrase(Passphrase),
    Recipients(Vec<PublicKey>),
}

/// Collects `public_keys` into a `Vec`, stopping as soon as it yields more
/// recipients than `FORMAT.md` §3.2 can encode.
///
/// The caller's own recipient-count policy is not applied here, because
/// [`Encryptor::header_read_limits`] can still raise or tighten it after
/// construction; [`Encryptor::write`] is where that check belongs. What this
/// bounds is the ceiling no configuration can lift: a list above
/// [`HeaderReadLimits::RECIPIENT_COUNT_STRUCTURAL_MAX`] could never produce a
/// writable file, so reading all of it is wasted memory and time.
///
/// At most one item beyond the ceiling is ever pulled — enough to know the
/// ceiling was passed — so an iterator of any length, including one with no
/// end, returns here after a bounded amount of work. The reported count is
/// therefore where collection stopped, not the length of the supplied
/// iterator, which is deliberately never established.
fn collect_recipients_within_structural_max(
    public_keys: impl IntoIterator<Item = PublicKey>,
) -> Result<Vec<PublicKey>, CryptoError> {
    let ceiling = HeaderReadLimits::RECIPIENT_COUNT_STRUCTURAL_MAX;
    let iter = public_keys.into_iter();
    // The lower size hint comes from the caller's iterator and is not
    // trustworthy, so it only ever shrinks the reservation.
    let mut collected = Vec::with_capacity(iter.size_hint().0.min(usize::from(ceiling)));
    for public_key in iter {
        if collected.len() == usize::from(ceiling) {
            return Err(CryptoError::RecipientCountCapExceeded {
                count: ceiling.saturating_add(1),
                local_cap: ceiling,
            });
        }
        collected.push(public_key);
    }
    Ok(collected)
}

impl Encryptor {
    /// Configures passphrase encryption.
    ///
    /// The resulting `.fcr` contains exactly one native `argon2id`
    /// recipient. The passphrase is checked against the fixed bound
    /// of 1 to 4,096 bytes when [`Encryptor::write`] runs;
    /// constructing this builder is infallible.
    pub fn with_passphrase(passphrase: Passphrase) -> Self {
        Self {
            state: EncryptorState::Passphrase(passphrase),
            save_as: None,
            archive_limits: None,
            kdf_params: None,
            header_read_limits: None,
            kdf_limit: None,
        }
    }

    /// Configures encryption to one public-key recipient.
    ///
    /// This is a convenience wrapper around [`Encryptor::with_public_keys`]
    /// for the common single-recipient case. As with that constructor,
    /// public-key encryption does not authenticate the sender.
    pub fn with_public_key(public_key: PublicKey) -> Self {
        Self {
            state: EncryptorState::Recipients(vec![public_key]),
            save_as: None,
            archive_limits: None,
            kdf_params: None,
            header_read_limits: None,
            kdf_limit: None,
        }
    }

    /// Configures encryption to one or more public-key recipients.
    ///
    /// Each recipient entry wraps the same per-file `file_key`
    /// independently, so any listed recipient can decrypt the resulting
    /// `.fcr` with their matching private key.
    ///
    /// # Security
    ///
    /// Public-key encryption controls who can decrypt the file, not who
    /// created it. Anyone with a recipient's public key can produce a file
    /// for that recipient. Use a separate signing layer if recipients must
    /// verify sender identity.
    ///
    /// # Default-decrypt round-trip
    ///
    /// By default the writer caps `public_keys.len()` at the same
    /// [`HeaderReadLimits::RECIPIENT_COUNT_DEFAULT`] (64) the reader
    /// applies via [`HeaderReadLimits::default`], so a default-configured
    /// [`Decryptor::open`] can read every file the default
    /// `Encryptor` produces. Lists above the default reject with
    /// [`CryptoError::RecipientCountCapExceeded`] at
    /// [`Encryptor::write`] time. To produce a file with more
    /// recipients, the caller must opt in via
    /// [`Encryptor::header_read_limits`] with a raised
    /// recipient-count limit; the receiving decryptor must be opened
    /// via [`Decryptor::open_with_limits`] with matching limits. Past
    /// roughly 750 X25519 recipients the aggregate header-MAC budget
    /// binds before the count does: the same [`HeaderReadLimits`] must
    /// then also raise
    /// [`HeaderReadLimits::max_header_mac_work_bytes`], on both sides,
    /// or [`Encryptor::write`] refuses with
    /// [`CryptoError::HeaderMacWorkCapExceeded`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::EmptyRecipientList`] if the iterator is empty,
    /// and [`CryptoError::RecipientCountCapExceeded`] if it yields more than
    /// [`HeaderReadLimits::RECIPIENT_COUNT_STRUCTURAL_MAX`] recipients — the
    /// ceiling `FORMAT.md` §3.2 imposes, which no configuration can raise.
    /// Collection stops one item past that ceiling, so an iterator far longer
    /// than it — or one with no end at all — is rejected having held no more
    /// recipients than the ceiling allows. The reported count is where
    /// collection stopped rather than the iterator's length, which is never
    /// established. The default recipient-count cap is a separate,
    /// caller-configurable check that runs at [`Encryptor::write`].
    ///
    /// All public keys in the current implementation are X25519 recipients;
    /// future key kinds may add additional mixing-policy checks.
    pub fn with_public_keys(
        public_keys: impl IntoIterator<Item = PublicKey>,
    ) -> Result<Self, CryptoError> {
        let public_keys = collect_recipients_within_structural_max(public_keys)?;
        if public_keys.is_empty() {
            return Err(CryptoError::EmptyRecipientList);
        }
        // Today PublicKey is always X25519 (PublicKeyMixable). When future
        // PublicKey variants carry different mixing policies, the check
        // expands here; protocol::encrypt re-checks as defense-in-depth.
        Ok(Self {
            state: EncryptorState::Recipients(public_keys),
            save_as: None,
            archive_limits: None,
            kdf_params: None,
            header_read_limits: None,
            kdf_limit: None,
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
    ///
    /// # Default-decrypt round-trip
    ///
    /// Raising `archive_limits` above [`ArchiveLimits::default`] can
    /// produce a `.fcr` whose archive payload exceeds what a
    /// default-configured [`PassphraseDecryptor`] /
    /// [`PrivateKeyDecryptor`] will extract. The receiving decryptor
    /// must be configured via
    /// [`PassphraseDecryptor::archive_limits`] /
    /// [`PrivateKeyDecryptor::archive_limits`] with limits that match
    /// (or exceed) the file's actual content. Lowering
    /// `archive_limits` only tightens what the encrypt-side preflight
    /// accepts and never breaks default round-trip.
    pub fn archive_limits(mut self, limits: ArchiveLimits) -> Self {
        self.archive_limits = Some(limits);
        self
    }

    /// Overrides the Argon2id parameters used by the passphrase recipient
    /// (`Encryptor::with_passphrase`). Has no effect on public-key
    /// (`Encryptor::with_public_key` / `with_public_keys`) flows, which use
    /// X25519 ECDH and never run Argon2id during encryption.
    ///
    /// If unset, the writer uses [`KdfParams::default`] (1 GiB memory,
    /// time_cost 4, parallelism 4). A `params.mem_cost` below the 19 MiB
    /// production memory floor rejects at [`Encryptor::write`] time with
    /// [`CryptoError::KdfBelowWriteFloor`], so a caller cannot seal a `.fcr`
    /// with weak Argon2id memory; the floor is hard and has no override.
    ///
    /// # Default-decrypt round-trip
    ///
    /// `kdf_params` is also checked at [`Encryptor::write`] time against
    /// the writer's [`KdfLimit`] policy. By default, memory is capped at
    /// 1 GiB and combined work at the writer's own budget, while time cost
    /// and lanes are capped at the format maximum, so [`KdfParams::default`]
    /// is accepted. A value above the effective policy rejects with the
    /// matching typed cap error. To write a `.fcr` with memory above 1 GiB or
    /// more total work than [`KdfParams::default`], or to use a deliberately
    /// tightened policy, configure [`Encryptor::kdf_limit`] and set a
    /// compatible [`PassphraseDecryptor::kdf_limit`] on the receiving decryptor
    /// before calling [`PassphraseDecryptor::decrypt`].
    pub fn kdf_params(mut self, params: KdfParams) -> Self {
        self.kdf_params = Some(params);
        self
    }

    /// Sets the writer-side header limits.
    ///
    /// By default the writer caps the header shape at the same
    /// [`HeaderReadLimits`] values the default reader uses, so a default
    /// [`Decryptor::open`] can read every file the default `Encryptor`
    /// produces. This builder raises or tightens those writer-side caps;
    /// the receiving decryptor must be opened via
    /// [`Decryptor::open_with_limits`] with limits that are at least as
    /// permissive. Past roughly 750 X25519 recipients the aggregate
    /// header-MAC budget binds before the recipient count does; see
    /// [`Encryptor::with_public_keys`].
    ///
    /// All four axes are checked before encryption work begins:
    /// `recipient_count`, canonical native recipient `body_len`, the exact
    /// `header_len` that the writer will emit (`ext_len = 0` for current
    /// writers), and the aggregate header-MAC work those two imply.
    /// Tightening any axis below the emitted header shape rejects at
    /// [`Encryptor::write`] time with the same typed cap error the reader
    /// would later return.
    pub fn header_read_limits(mut self, limits: HeaderReadLimits) -> Self {
        self.header_read_limits = Some(limits);
        self
    }

    /// Sets the writer-side KDF resource policy for passphrase encryption.
    ///
    /// The policy caps Argon2id memory cost, time cost, lane count, and
    /// combined work before any encryption work begins. The default policy
    /// accepts [`KdfParams::default`], which sits exactly at the default work
    /// budget, and rejects memory above 1 GiB unless the caller opts into a
    /// higher memory cap. Time cost and lanes default to the format maximum,
    /// so they only reject when the caller tightens them.
    ///
    /// Use this builder together with [`Encryptor::kdf_params`] to raise the
    /// memory or work ceiling, or to tighten any dimension. Raising memory does
    /// not raise the work budget, so parameters above
    /// [`KdfParams::default`]'s work need [`KdfLimit::max_work`] as well. The
    /// receiving passphrase decryptor must be configured via
    /// [`PassphraseDecryptor::kdf_limit`] with a policy that accepts the same
    /// parameters.
    ///
    /// Has no effect on public-key (`Encryptor::with_public_key` /
    /// `with_public_keys`) flows, which never run Argon2id during
    /// encryption.
    pub fn kdf_limit(mut self, limit: KdfLimit) -> Self {
        self.kdf_limit = Some(limit);
        self
    }

    /// Encrypts `input` and writes the resulting `.fcr` file.
    ///
    /// `input` may be a regular file or a directory. Directory inputs are
    /// encoded as a FerroCrypt Archive (FCA) payload before payload encryption.
    /// The default destination is `{output_dir}/{stem}.fcr`; use
    /// [`Encryptor::save_as`] to supply an explicit output file path.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidInput`] for invalid input paths, output
    /// conflicts, unsupported archive entries, empty or too-long passphrases,
    /// archive cap violations, invalid KDF settings, or a source file or
    /// directory that was replaced or removed while it was being read. On Unix, that variant
    /// can also report a committed output path that resolves to a different
    /// object before return. Returns [`CryptoError::Io`] for filesystem
    /// failures, including a committed output that carries more than one
    /// filesystem name. Either post-commit condition can leave the complete
    /// encrypted file under its final, temporary, or moved name.
    /// Returns authentication or internal crypto errors if key wrapping or
    /// payload streaming fails.
    pub fn write(
        self,
        input: impl AsRef<Path>,
        output_dir: impl AsRef<Path>,
        on_event: impl Fn(&ProgressEvent),
    ) -> Result<EncryptOutcome, CryptoError> {
        let input = input.as_ref();
        let output_dir = output_dir.as_ref();
        let archive_limits = self.archive_limits.unwrap_or_default();
        let header_read_limits = self.header_read_limits.unwrap_or_default();
        let kdf_limit = self.kdf_limit.unwrap_or_default();
        // Resolved once: the value the preflight validates below is by
        // construction the value serialized into the recipient body.
        let kdf_params = self.kdf_params.unwrap_or_default();
        let save_as = self.save_as.as_deref();

        // Check the fixed passphrase byte-length bound before filesystem
        // work. A value outside the bound is a caller error, and reporting it
        // first avoids unnecessary syscalls.
        if let EncryptorState::Passphrase(p) = &self.state {
            validate_passphrase(p)?;
        }

        // Writer caps mirror reader defaults via the same `enforce_*`
        // helpers the reader uses, so default-encrypt and default-
        // decrypt cannot drift. Checked here so a misconfiguration
        // fails before recipient key files are read;
        // `protocol::encrypt` re-enforces the same gates for any
        // other caller.
        match &self.state {
            EncryptorState::Recipients(rs) => {
                protocol::preflight_header_write_limits(
                    header_read_limits,
                    rs.len(),
                    NativeRecipientType::X25519,
                    protocol::WRITE_EXT_BYTES,
                )?;
            }
            EncryptorState::Passphrase(_) => {
                protocol::preflight_header_write_limits(
                    header_read_limits,
                    1,
                    NativeRecipientType::Argon2id,
                    protocol::WRITE_EXT_BYTES,
                )?;
                kdf_params.validate_for_write(Some(&kdf_limit))?;
            }
        }

        archive::validate_encrypt_input(input)?;

        let output_path = match self.state {
            EncryptorState::Passphrase(passphrase) => {
                // The passphrase moves into the recipient, which
                // `protocol::encrypt` drops once the body is wrapped, so it
                // is gone before the payload is streamed.
                let recipient = recipient::argon2id::PassphraseRecipient {
                    passphrase,
                    kdf_params,
                    kdf_limit,
                };
                protocol::encrypt(
                    vec![recipient],
                    archive_limits,
                    header_read_limits,
                    input,
                    output_dir,
                    save_as,
                    &on_event,
                )?
            }
            EncryptorState::Recipients(public_keys) => {
                // Collect the 32-byte material into a local Vec that owns the
                // bytes; X25519Recipient borrows from it for the lifetime of
                // this match arm.
                let public_key_bytes_vec: Vec<[u8; 32]> = public_keys
                    .iter()
                    .map(|pk| pk.to_x25519_bytes())
                    .collect::<Result<_, _>>()?;
                let recipients: Vec<recipient::x25519::X25519Recipient> = public_key_bytes_vec
                    .iter()
                    .map(|bytes| recipient::x25519::X25519Recipient {
                        recipient_public_key_bytes: bytes,
                    })
                    .collect();
                protocol::encrypt(
                    recipients,
                    archive_limits,
                    header_read_limits,
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
/// [`Decryptor::open`] reads the `.fcr` header without cryptographic work and
/// returns the variant that matches the file's recipient kind. Each variant
/// takes only the credentials it can use:
///
/// - [`Decryptor::Passphrase`] takes a passphrase.
/// - [`Decryptor::PrivateKey`] takes a [`PrivateKey`], which carries its
///   own unlock passphrase.
///
/// A mismatched-credential call — e.g. trying to decrypt a passphrase-sealed
/// file with a [`PrivateKey`] — is therefore a compile error rather than a
/// runtime [`CryptoError::DecryptorModeMismatch`] failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum Decryptor {
    /// File is sealed with a passphrase. Decrypt via
    /// [`PassphraseDecryptor::decrypt`].
    Passphrase(PassphraseDecryptor),
    /// File is sealed to one or more public-key recipients. Decrypt
    /// via [`PrivateKeyDecryptor::decrypt`].
    PrivateKey(PrivateKeyDecryptor),
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
    /// their corresponding `CryptoError` or [`FormatDefect`] variants. A
    /// passphrase recipient whose stored Argon2id parameters are outside the
    /// bounds `FORMAT.md` §2.2 permits returns
    /// [`CryptoError::InvalidKdfParams`]. A header shape, or an aggregate
    /// header-MAC work total, above [`HeaderReadLimits::default`] returns the
    /// matching `*CapExceeded` variant; use [`Decryptor::open_with_limits`] to
    /// raise the caps.
    pub fn open(input: impl AsRef<Path>) -> Result<Self, CryptoError> {
        Self::open_inner(input.as_ref(), None)
    }

    /// Same as [`Decryptor::open`] but uses the supplied
    /// [`HeaderReadLimits`] for the structural header read instead of
    /// the conservative defaults.
    ///
    /// Callers handling files whose recipient strings, recipient
    /// counts, or header lengths legitimately exceed the defaults
    /// (for example, forward-compatible files with larger future recipient
    /// bodies) should construct a `HeaderReadLimits` via the builder
    /// methods and pass it here. The same limits are stashed on the
    /// returned variant so the second header read inside
    /// [`PassphraseDecryptor::decrypt`] / [`PrivateKeyDecryptor::decrypt`]
    /// uses them too — callers do not need to set them twice.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Decryptor::open`], but applies the supplied
    /// [`HeaderReadLimits`] during structural header parsing.
    pub fn open_with_limits(
        input: impl AsRef<Path>,
        header_read_limits: HeaderReadLimits,
    ) -> Result<Self, CryptoError> {
        Self::open_inner(input.as_ref(), Some(header_read_limits))
    }

    fn open_inner(
        input: &Path,
        header_read_limits: Option<HeaderReadLimits>,
    ) -> Result<Self, CryptoError> {
        let input = input.to_path_buf();
        if input.is_dir() {
            return Err(CryptoError::InvalidInput(format!(
                "Cannot decrypt a directory: {}",
                sanitize_path_for_display(&input)
            )));
        }
        let mode =
            probe_recipient_mode_with_limits(&input, header_read_limits.unwrap_or_default())?
                .ok_or(CryptoError::InvalidFormat(FormatDefect::BadMagic))?;
        match mode {
            UnauthenticatedRecipientMode::Passphrase => Ok(Self::Passphrase(PassphraseDecryptor {
                input,
                kdf_limit: None,
                archive_limits: None,
                header_read_limits,
                incomplete_output_policy: None,
            })),
            UnauthenticatedRecipientMode::PublicKey => Ok(Self::PrivateKey(PrivateKeyDecryptor {
                input,
                kdf_limit: None,
                key_read_limits: None,
                archive_limits: None,
                header_read_limits,
                incomplete_output_policy: None,
            })),
        }
    }
}

/// Decryptor for passphrase-sealed `.fcr` files. Returned from
/// [`Decryptor::open`] when the file's recipient list classifies as
/// [`UnauthenticatedRecipientMode::Passphrase`].
#[derive(Debug)]
#[non_exhaustive]
pub struct PassphraseDecryptor {
    input: PathBuf,
    kdf_limit: Option<KdfLimit>,
    archive_limits: Option<ArchiveLimits>,
    header_read_limits: Option<HeaderReadLimits>,
    incomplete_output_policy: Option<IncompleteOutputPolicy>,
}

impl PassphraseDecryptor {
    /// Sets the reader-side KDF resource policy for this decrypt.
    ///
    /// The policy caps Argon2id memory cost, time cost, lane count, and
    /// combined work accepted from the file header, before any derivation work
    /// begins. If unset, the decrypt path applies [`KdfLimit::default`], a
    /// desktop-sized budget of 1 GiB and the writer's own work budget,
    /// matching what this library writes.
    ///
    /// A service that decrypts untrusted files unattended should set a
    /// smaller limit and bound how many decrypts run at once: the header
    /// chooses the Argon2id cost, and the derivation runs before the file
    /// is authenticated, so every concurrent call can hold the full budget.
    pub fn kdf_limit(mut self, limit: KdfLimit) -> Self {
        self.kdf_limit = Some(limit);
        self
    }

    /// Overrides the default archive resource caps applied during
    /// extraction. Must match (or exceed) the limits the writer used —
    /// a file produced with [`Encryptor::archive_limits`] above the
    /// default cannot be decrypted under [`ArchiveLimits::default`].
    pub fn archive_limits(mut self, limits: ArchiveLimits) -> Self {
        self.archive_limits = Some(limits);
        self
    }

    /// Overrides the header-read caps applied while parsing the
    /// `.fcr` header during decrypt. The same limits used at
    /// [`Decryptor::open`] / [`Decryptor::open_with_limits`] are
    /// carried into the variant; this builder lets callers tighten or
    /// loosen them between open and decrypt for advanced flows.
    pub fn header_read_limits(mut self, limits: HeaderReadLimits) -> Self {
        self.header_read_limits = Some(limits);
        self
    }

    /// Sets the policy that governs the `.incomplete` working tree
    /// when this decrypt fails.
    ///
    /// Defaults to [`IncompleteOutputPolicy::DeleteOnError`], which
    /// removes this run's `.incomplete` plaintext while the output is
    /// still treated as staged, and reports in the returned error a
    /// removal that failed or could not be confirmed. It does not remove
    /// a complete output confirmed before a later filesystem namespace
    /// error. Pass
    /// [`IncompleteOutputPolicy::RetainOnError`] for backup-recovery or
    /// forensic flows where partial output is more useful than no output. See
    /// that variant for the truncation-prefix caveat callers must understand
    /// before acting on a retained partial.
    pub fn incomplete_output_policy(mut self, policy: IncompleteOutputPolicy) -> Self {
        self.incomplete_output_policy = Some(policy);
        self
    }

    /// Decrypts this passphrase-sealed `.fcr` into `output_dir`.
    ///
    /// The passphrase is checked against the fixed bound of 1 to
    /// 4,096 bytes, then used to unwrap the file's `argon2id` recipient. The
    /// recovered candidate file key is accepted only after the header MAC
    /// verifies. On success, the decrypted file or directory is promoted
    /// into `output_dir` and returned in [`DecryptOutcome::output_path`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidInput`] for an empty or too-long
    /// passphrase, archive cap violations, output conflicts, or unsafe archived
    /// paths. Returns [`CryptoError::KdfResourceCapExceeded`] for rejected KDF costs.
    /// Returns [`CryptoError::InvalidFormat`] if the encrypted container or
    /// authenticated payload stream is structurally malformed. Returns
    /// authentication errors such as [`CryptoError::RecipientUnwrapFailed`],
    /// [`CryptoError::HeaderTampered`], [`CryptoError::PayloadTampered`], or
    /// [`CryptoError::PayloadTruncated`] when credentials are wrong or the file
    /// is modified. Returns [`CryptoError::InputPath`] if the encrypted file
    /// no longer exists, and [`CryptoError::Io`] for other filesystem
    /// failures, including a namespace check or a committed output that carries
    /// more than one filesystem name, either of which can report an error
    /// after the complete plaintext output was committed;
    /// [`IncompleteOutputPolicy`] does not remove a confirmed output in
    /// that case.
    pub fn decrypt(
        self,
        passphrase: Passphrase,
        output_dir: impl AsRef<Path>,
        on_event: impl Fn(&ProgressEvent),
    ) -> Result<DecryptOutcome, CryptoError> {
        validate_passphrase(&passphrase)?;
        // Hand the passphrase to the credential so the protocol layer can
        // scrub it once the recipient slot loop is done, rather than holding
        // it here for the whole payload extraction.
        let credential = recipient::argon2id::PassphraseCredential {
            passphrase,
            kdf_limit: self.kdf_limit.as_ref(),
        };
        let archive_limits = self.archive_limits.unwrap_or_default();
        let header_read_limits = self.header_read_limits.unwrap_or_default();
        let incomplete_output_policy = self.incomplete_output_policy.unwrap_or_default();
        // No early progress event here. `protocol::decrypt` parses the
        // header structurally before any KDF runs; if the file is
        // malformed or mode-mismatched, no event should fire. The
        // `DerivingPassphraseWrapKey` event fires from inside
        // `argon2id::unwrap` once the slot loop reaches a structurally
        // valid `argon2id` body whose `kdf_params` are within the
        // resource cap — i.e. immediately before Argon2id actually runs.
        let output_path = protocol::decrypt(
            credential,
            &self.input,
            output_dir.as_ref(),
            archive_limits,
            header_read_limits,
            incomplete_output_policy,
            &on_event,
        )?;
        Ok(DecryptOutcome {
            output_path,
            recipient_mode: AuthenticatedRecipientMode::passphrase(),
        })
    }
}

/// Decryptor for public-key-sealed `.fcr` files. Returned from
/// [`Decryptor::open`] when the file's recipient list classifies as
/// [`UnauthenticatedRecipientMode::PublicKey`].
#[derive(Debug)]
#[non_exhaustive]
pub struct PrivateKeyDecryptor {
    input: PathBuf,
    kdf_limit: Option<KdfLimit>,
    key_read_limits: Option<KeyReadLimits>,
    archive_limits: Option<ArchiveLimits>,
    header_read_limits: Option<HeaderReadLimits>,
    incomplete_output_policy: Option<IncompleteOutputPolicy>,
}

impl PrivateKeyDecryptor {
    /// Sets the reader-side KDF resource policy for unlocking `private.key`.
    ///
    /// The policy caps Argon2id memory cost, time cost, lane count, and
    /// combined work accepted from the key file's cleartext header, before any
    /// derivation work begins. If unset, the decrypt path applies
    /// [`KdfLimit::default`], a desktop-sized budget of 1 GiB and the writer's
    /// own work budget, matching what this library writes.
    ///
    /// A service that unlocks untrusted key files unattended should set a
    /// smaller limit and bound how many unlocks run at once: the key file's
    /// cleartext header chooses the Argon2id cost, and the derivation runs
    /// before the wrapped secret is authenticated.
    pub fn kdf_limit(mut self, limit: KdfLimit) -> Self {
        self.kdf_limit = Some(limit);
        self
    }

    /// Overrides the key-file caps applied while reading the supplied
    /// `private.key`.
    ///
    /// If unset, the decrypt path applies [`KeyReadLimits::default`].
    /// Raise [`KeyReadLimits::max_private_key_wrapped_secret_len`] for a
    /// key file whose wrapped secret legitimately exceeds the default.
    pub fn key_read_limits(mut self, limits: KeyReadLimits) -> Self {
        self.key_read_limits = Some(limits);
        self
    }

    /// Overrides the default archive resource caps applied during
    /// extraction. Must match (or exceed) the limits the writer used —
    /// a file produced with [`Encryptor::archive_limits`] above the
    /// default cannot be decrypted under [`ArchiveLimits::default`].
    pub fn archive_limits(mut self, limits: ArchiveLimits) -> Self {
        self.archive_limits = Some(limits);
        self
    }

    /// Overrides the header-read caps applied while parsing the
    /// `.fcr` header during decrypt. The same limits used at
    /// [`Decryptor::open`] / [`Decryptor::open_with_limits`] are
    /// carried into the variant; this builder lets callers tighten or
    /// loosen them between open and decrypt for advanced flows.
    pub fn header_read_limits(mut self, limits: HeaderReadLimits) -> Self {
        self.header_read_limits = Some(limits);
        self
    }

    /// Sets the policy that governs the `.incomplete` working tree
    /// when this decrypt fails.
    ///
    /// Defaults to [`IncompleteOutputPolicy::DeleteOnError`], which
    /// removes this run's `.incomplete` plaintext while the output is
    /// still treated as staged, and reports in the returned error a
    /// removal that failed or could not be confirmed. It does not remove
    /// a complete output confirmed before a later filesystem namespace
    /// error. Pass
    /// [`IncompleteOutputPolicy::RetainOnError`] for backup-recovery or
    /// forensic flows where partial output is more useful than no output. See
    /// that variant for the truncation-prefix caveat callers must understand
    /// before acting on a retained partial.
    pub fn incomplete_output_policy(mut self, policy: IncompleteOutputPolicy) -> Self {
        self.incomplete_output_policy = Some(policy);
        self
    }

    /// Decrypts this public-key-recipient `.fcr` into `output_dir`.
    ///
    /// `private_key` must reference a FerroCrypt `private.key` file. The
    /// private key is unlocked with the passphrase bound by
    /// [`PrivateKey::from_key_file`], then the decryptor tries the supported
    /// `x25519` recipient slots until one yields a candidate file key that
    /// verifies the header MAC. On success, the decrypted file or directory
    /// is promoted into `output_dir` and returned in
    /// [`DecryptOutcome::output_path`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidInput`] for an empty or too-long
    /// private-key passphrase, archive cap violations, output conflicts, or
    /// unsafe archived paths.
    /// Returns [`CryptoError::InvalidFormat`] if the private key, encrypted
    /// container, or authenticated payload stream is structurally malformed;
    /// returns [`CryptoError::KeyFileUnlockFailed`] if the private key is
    /// tampered or protected by a different passphrase.
    /// Returns [`CryptoError::KdfResourceCapExceeded`] for rejected
    /// `private.key` KDF costs. Returns [`CryptoError::UnsupportedKeyType`]
    /// if the private key wraps a key type this build does not support.
    /// Returns authentication errors such as
    /// [`CryptoError::RecipientUnwrapFailed`],
    /// [`CryptoError::HeaderMacFailedAfterUnwrap`],
    /// [`CryptoError::NoSupportedRecipient`], [`CryptoError::PayloadTampered`],
    /// or [`CryptoError::PayloadTruncated`]. `RecipientUnwrapFailed` means the
    /// private key matched no supported recipient slot, or a recipient body was
    /// modified; `NoSupportedRecipient` means the file contains no recipient
    /// type this build can process. Returns [`CryptoError::InputPath`] if the
    /// encrypted file or the private key file does not exist, and
    /// [`CryptoError::Io`] for other filesystem failures, including a namespace
    /// check or a committed output that carries more than one filesystem
    /// name, either of which can report an error after the complete
    /// plaintext output was committed; [`IncompleteOutputPolicy`] does not
    /// remove a confirmed output in that case.
    pub fn decrypt(
        self,
        private_key: PrivateKey,
        output_dir: impl AsRef<Path>,
        on_event: impl Fn(&ProgressEvent),
    ) -> Result<DecryptOutcome, CryptoError> {
        let (key_file_path, private_key_passphrase) = private_key.into_key_file_parts();
        validate_passphrase(&private_key_passphrase)?;
        let archive_limits = self.archive_limits.unwrap_or_default();
        let header_read_limits = self.header_read_limits.unwrap_or_default();
        let incomplete_output_policy = self.incomplete_output_policy.unwrap_or_default();

        // Open and classify the encrypted file before unlocking the
        // private key, then retain that open file for decryption.
        // Structural errors must be reported before Argon2id starts.
        // Keeping one file open also prevents a path replacement during
        // the unlock from changing which bytes are decrypted.
        let session = protocol::DecryptSession::open(&self.input, header_read_limits)?;
        if session.mode() != UnauthenticatedRecipientMode::PublicKey {
            return Err(CryptoError::DecryptorModeMismatch {
                expected: UnauthenticatedRecipientMode::PublicKey,
                found: session.mode(),
            });
        }

        // No early progress event here. `open_x25519_private_key` first
        // applies the generic binary-shape, resource-cap, type-name
        // grammar, and passphrase-length gates. Only immediately before
        // Argon2id does `key::private::open_private_key` emit
        // `UnlockingPrivateKey`. Those pre-KDF failures and a concrete
        // public/private key-file mix-up therefore emit no event. Verdicts
        // that require authenticated bytes, including
        // `UnsupportedKeyType`, occur after the event.
        let private_key_bytes = recipient::native::x25519::open_x25519_private_key(
            &key_file_path,
            &private_key_passphrase,
            self.kdf_limit.as_ref(),
            self.key_read_limits.unwrap_or_default(),
            &on_event,
        )?;
        // The passphrase unlocks `private.key` and nothing else. Scrub it now
        // rather than carrying it through the payload phase below.
        drop(private_key_passphrase);

        let decryption_credential = recipient::x25519::X25519Credential { private_key_bytes };
        let output_path = protocol::decrypt_session(
            decryption_credential,
            session,
            output_dir.as_ref(),
            archive_limits,
            incomplete_output_policy,
            &on_event,
        )?;
        Ok(DecryptOutcome {
            output_path,
            recipient_mode: AuthenticatedRecipientMode::public_key(),
        })
    }
}

// ─── Key generation ─────────────────────────────────────────────────────────

/// Builder for X25519 key-pair generation.
///
/// Mirrors the [`Encryptor`] builder pattern: pick the passphrase at
/// construction, optionally override the Argon2id parameters used to
/// seal the resulting `private.key`, then call [`KeyPairGenerator::write`]
/// with the destination directory.
///
/// The free function [`generate_key_pair`] is a thin convenience wrapper
/// around this builder for callers that do not need to override KDF
/// parameters.
#[derive(Debug)]
#[non_exhaustive]
pub struct KeyPairGenerator {
    passphrase: Passphrase,
    kdf_params: Option<KdfParams>,
    kdf_limit: Option<KdfLimit>,
}

impl KeyPairGenerator {
    /// Constructs a key-pair generator with the passphrase that will be
    /// used to seal the resulting `private.key`. The passphrase is
    /// checked against the fixed bound of 1 to 4,096 bytes when
    /// [`KeyPairGenerator::write`] runs; constructing this builder is
    /// infallible.
    pub fn with_passphrase(passphrase: Passphrase) -> Self {
        Self {
            passphrase,
            kdf_params: None,
            kdf_limit: None,
        }
    }

    /// Overrides the Argon2id parameters used to seal `private.key`.
    /// If unset, the generator uses [`KdfParams::default`] (1 GiB memory,
    /// time_cost 4, parallelism 4).
    ///
    /// Same production memory floor as [`Encryptor::kdf_params`]: a
    /// `params.mem_cost` below the 19 MiB production memory floor rejects
    /// at [`KeyPairGenerator::write`] time with
    /// [`CryptoError::KdfBelowWriteFloor`], so a caller cannot seal a
    /// `private.key` with weak Argon2id memory; the floor is hard and has
    /// no override.
    ///
    /// # Default-decrypt round-trip
    ///
    /// `kdf_params` is also checked at [`KeyPairGenerator::write`] time
    /// against the writer's [`KdfLimit`] policy. By default, memory is capped
    /// at 1 GiB and combined work at the writer's own budget, while time cost
    /// and lanes are capped at the format maximum, so [`KdfParams::default`]
    /// is accepted. A value above the effective policy rejects with the
    /// matching typed cap error. To write a `private.key` with memory above
    /// 1 GiB or more total work than [`KdfParams::default`], or to use a
    /// deliberately tightened policy, configure
    /// [`KeyPairGenerator::kdf_limit`] and configure the unlocking
    /// [`PrivateKeyDecryptor`] with a compatible
    /// [`PrivateKeyDecryptor::kdf_limit`].
    pub fn kdf_params(mut self, params: KdfParams) -> Self {
        self.kdf_params = Some(params);
        self
    }

    /// Sets the writer-side KDF resource policy for sealing `private.key`.
    ///
    /// The policy caps Argon2id memory cost, time cost, lane count, and
    /// combined work before key generation begins. The default policy accepts
    /// [`KdfParams::default`], which sits exactly at the default work budget,
    /// and rejects memory above 1 GiB unless the caller opts into a higher
    /// memory cap. Time cost and lanes default to the format maximum, so
    /// they only reject when the caller tightens them.
    ///
    /// Use this builder together with [`KeyPairGenerator::kdf_params`] to raise
    /// the memory or work ceiling, or to tighten any dimension. Raising memory
    /// does not raise the work budget, so parameters above
    /// [`KdfParams::default`]'s work need [`KdfLimit::max_work`] as well. The
    /// receiving [`PrivateKeyDecryptor`] must be configured via
    /// [`PrivateKeyDecryptor::kdf_limit`] with a policy that accepts the same
    /// parameters.
    pub fn kdf_limit(mut self, limit: KdfLimit) -> Self {
        self.kdf_limit = Some(limit);
        self
    }

    /// Generates the X25519 key pair and writes `private.key` +
    /// `public.key` into `output_dir`.
    ///
    /// Both files are written and synced before either receives its final
    /// name. `private.key` is committed first, and the output directory is
    /// flushed after each commit. This order prevents process interruption
    /// from leaving a usable `public.key` without its matching `private.key`.
    ///
    /// On filesystems that support directory flushing, the same guarantee
    /// covers power loss, and a successful return means the two files and
    /// their directory entries have reached stable storage. Other filesystems
    /// depend on their own ordering after power loss.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidInput`] if the passphrase is empty or too
    /// long, KDF parameters are outside the accepted writer policy, or either
    /// key file already exists. On Unix, [`CryptoError::InvalidInput`] can also
    /// report that a committed final path resolves to a different filesystem
    /// object before return; any completed commits are preserved.
    ///
    /// Returns [`CryptoError::Io`] for filesystem failures, including a
    /// directory flush failure or a committed key file that carries more than
    /// one filesystem name. If the flush after committing
    /// `public.key` fails, the method makes a best-effort attempt to remove
    /// `public.key` but keeps `private.key`. Removing both without a successful
    /// directory flush could leave only the public key after power loss. A
    /// remaining `private.key` is safe to delete. Any error after a commit can
    /// therefore leave one or both complete key files for the caller to inspect.
    /// If a removal cannot be confirmed — the key file was replaced during the
    /// operation, or it still had another name — the error message says so.
    pub fn write(
        self,
        output_dir: impl AsRef<Path>,
        on_event: impl Fn(&ProgressEvent),
    ) -> Result<KeyGenOutcome, CryptoError> {
        validate_passphrase(&self.passphrase)?;
        let kdf_params = self.kdf_params.unwrap_or_default();
        let kdf_limit = self.kdf_limit.unwrap_or_default();
        // Moved in, not borrowed: `protocol::generate_key_pair` scrubs it as
        // soon as `private.key` is sealed, before the files reach disk.
        let (private_key_path, public_key_path, recipient_string, fingerprint) =
            protocol::generate_key_pair(
                self.passphrase,
                &kdf_params,
                Some(&kdf_limit),
                output_dir.as_ref(),
                &on_event,
            )?;
        Ok(KeyGenOutcome {
            private_key_path,
            public_key_path,
            recipient_string,
            fingerprint,
        })
    }
}

/// Generates and stores an X25519 key pair for public-key
/// (recipient) encryption.
///
/// Writes `private.key` (passphrase-wrapped at rest) and `public.key`
/// (UTF-8 `fcr1…` recipient string) into `output_dir`. Returns the
/// final paths plus the SHA3-256 fingerprint of the public key.
///
/// Thin convenience wrapper around [`KeyPairGenerator`]. Callers that
/// need to override Argon2id parameters should use the builder directly:
/// `KeyPairGenerator::with_passphrase(pass).kdf_params(p).write(dir, ev)`.
///
/// # Errors
///
/// Returns the same errors as [`KeyPairGenerator::write`].
///
/// # Examples
///
/// ```no_run
/// use ferrocrypt::{generate_key_pair, Passphrase};
/// let pass = Passphrase::new("protect-my-key");
/// let outcome = generate_key_pair("./keys", pass, |ev| eprintln!("{ev}"))?;
/// println!("Fingerprint: {}", outcome.fingerprint);
/// # Ok::<(), ferrocrypt::CryptoError>(())
/// ```
pub fn generate_key_pair(
    output_dir: impl AsRef<Path>,
    passphrase: Passphrase,
    on_event: impl Fn(&ProgressEvent),
) -> Result<KeyGenOutcome, CryptoError> {
    KeyPairGenerator::with_passphrase(passphrase).write(output_dir, on_event)
}

// ─── Recipient-mode probe ───────────────────────────────────────────────────

/// Cheap structural probe of an `.fcr` file's recipient list. **Not a
/// security claim.**
///
/// Performs a single bounded header parse on one file handle (no path reopen
/// between magic check and header read). It does not run a KDF, perform a
/// private-key operation, prompt for credentials, verify the header MAC, or
/// decrypt payload bytes. Allocations are bounded by [`HeaderReadLimits`].
///
/// A positive result is **not** evidence that the file is authentic,
/// decryptable, untampered, or well-formed beyond the structural shape
/// required to classify it. A canonical header that would later fail
/// recipient unwrap or MAC verify still returns `Ok(Some(_))` here — those
/// checks require running the full decrypt. Use only for UI / routing hints;
/// for an authenticated mode value see [`AuthenticatedRecipientMode`] on
/// [`DecryptOutcome`].
///
/// Returns `Ok(None)` if the path is a directory, the file is empty, or the
/// first 4 bytes are not the FerroCrypt magic. These cases mean "this isn't
/// a FerroCrypt file at all" — callers route to plaintext encrypt.
///
/// Returns `Ok(Some(UnauthenticatedRecipientMode))` when the prefix matches
/// and the header parses and classifies cleanly. The mode is derived from
/// the recipient list: exactly one native `argon2id` recipient maps to
/// [`UnauthenticatedRecipientMode::Passphrase`], and one or more supported
/// `x25519` recipients with no `argon2id` recipient map to
/// [`UnauthenticatedRecipientMode::PublicKey`].
///
/// Returns [`CryptoError::InvalidFormat`] when the magic matches but the
/// prefix or header is malformed (bad version / kind / flags, oversized
/// `header_len`, malformed recipient entries, etc.). The probe therefore
/// enforces the same structural invariants the decrypt path would, so
/// corrupt or attacker-modified files surface their specific diagnostic
/// at probe time.
///
/// Returns typed recipient-classification errors when the recipient list is
/// structurally valid but cannot be classified: unknown critical recipients,
/// illegal passphrase mixing, no supported native recipient, or a passphrase
/// recipient whose stored Argon2id parameters are out of range.
///
/// # Errors
///
/// Returns [`CryptoError::InputPath`] if the file does not exist, and
/// [`CryptoError::Io`] for other open or read failures. Returns
/// [`CryptoError::InvalidInput`] if the path is not a regular file (for
/// example a FIFO or device node) — such inputs are refused without
/// blocking. Returns [`CryptoError::InvalidFormat`] when the magic matches
/// but the prefix, header, recipient entries, or recipient mixing policy are
/// malformed or unsupported, and [`CryptoError::InvalidKdfParams`] when a
/// passphrase recipient's stored Argon2id parameters are outside the bounds
/// `FORMAT.md` §2.2 permits. Returns cap-exceeded variants when the declared
/// header shape, or the aggregate header-MAC work its recipient list implies,
/// exceeds [`HeaderReadLimits::default`].
pub fn probe_recipient_mode(
    file_path: impl AsRef<Path>,
) -> Result<Option<UnauthenticatedRecipientMode>, CryptoError> {
    probe_recipient_mode_with_limits(file_path, HeaderReadLimits::default())
}

/// Same as [`probe_recipient_mode`] but uses the supplied
/// [`HeaderReadLimits`] for the structural header read instead of the
/// conservative defaults.
///
/// Use this when probing files whose recipient strings, recipient counts,
/// or header lengths legitimately exceed the default local caps (for example,
/// forward-compatible files with larger future recipient bodies). All other
/// behavior — directory short-circuit, magic-byte fast path, typed-error
/// surface, and "not a security claim" semantics — is identical.
///
/// # Errors
///
/// Returns the same errors as [`probe_recipient_mode`], but applies the
/// supplied [`HeaderReadLimits`] instead of the default caps.
pub fn probe_recipient_mode_with_limits(
    file_path: impl AsRef<Path>,
    limits: HeaderReadLimits,
) -> Result<Option<UnauthenticatedRecipientMode>, CryptoError> {
    use std::io::{Read, Seek, SeekFrom};
    let path = file_path.as_ref();

    // Handle directories before opening the path so all platforms return the
    // same result. Unix may open a directory and fail later at `read()` with
    // `IsADirectory`; Windows refuses the open up front and reports access
    // denied, which is indistinguishable from a real permission error here.
    if path.is_dir() {
        return Ok(None);
    }

    // `open_input_file` refuses FIFOs, sockets, and device nodes
    // without blocking — `File::open` on an attacker-placed FIFO would
    // otherwise block the probe inside `open(2)` indefinitely.
    let mut file = paths::open_input_file(path)?;

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
    let parsed = container::read_encrypted_header(&mut file, limits)?;

    // Structural classification and resource policy only — the same
    // preflight the decrypt path runs, so this probe cannot report a
    // file the reader would then refuse under these limits. No header
    // MAC and no recipient unwrap happen here.
    let mode = protocol::classify_recipients_within_limits(&parsed, limits)?;
    Ok(Some(mode))
}

// ─── Filename + key-file helpers ────────────────────────────────────────────

/// Returns the default encrypted filename for a given input path.
///
/// For example, a regular file named `secrets.txt` maps to `secrets.fcr`; a
/// directory named `secrets` maps to `secrets.fcr`. An input of `.` or `..`
/// takes the name of the directory it points at.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidInput`] if the path has no usable file name or
/// contains a non-UTF-8 file name.
pub fn default_encrypted_filename(input_path: impl AsRef<Path>) -> Result<String, CryptoError> {
    let base_name = paths::encryption_base_name(input_path)?;
    Ok(format!("{}.{}", base_name, ENCRYPTED_EXTENSION))
}

/// Validates that a file is a well-formed FerroCrypt `private.key` file.
///
/// Checks the cleartext structure: magic bytes, version, key-file kind,
/// flags, length fields, X25519 type name, X25519 public-material length, and
/// total file size. This does **not** attempt to decrypt the key and does not
/// require a passphrase. If the caller accidentally points this at a text
/// `public.key`, [`FormatDefect::WrongKeyFileType`] is returned instead of a
/// generic key-file parse error.
///
/// Companion to [`validate_public_key_file`]. Applies no resource caps of
/// its own: the verdict follows what `FORMAT.md` §8 allows, not what a
/// default reader would accept.
///
/// # Errors
///
/// Returns [`CryptoError::InputPath`] if the file does not exist, and
/// [`CryptoError::Io`] for other read failures. Returns
/// [`CryptoError::InvalidFormat`] or [`CryptoError::UnsupportedVersion`] if the
/// file is not a supported private key, is malformed, or is a public key. Returns
/// [`CryptoError::UnsupportedKeyType`] for a well-formed private key of a key
/// type this build does not support.
pub fn validate_private_key_file(key_file: impl AsRef<Path>) -> Result<(), CryptoError> {
    // No resource policy of its own: this validates structure only, so the
    // read and the public-key probe both run at the structural maxima.
    let limits = KeyReadLimits::structural_max();
    let data = crate::key::private::read_private_key_file(
        key_file.as_ref(),
        limits.private_key_wrapped_secret_len(),
    )?;
    if matches!(KeyFileKind::classify(&data, limits), KeyFileKind::Public) {
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
/// passphrase. If the caller accidentally points this at a binary
/// `private.key`, [`FormatDefect::WrongKeyFileType`] is returned instead of a
/// UTF-8 decode error.
///
/// Companion to [`validate_private_key_file`]. Applies no resource caps
/// of its own: the verdict follows what `FORMAT.md` §7 allows, not what
/// a default reader would accept.
///
/// # Errors
///
/// Returns [`CryptoError::InputPath`] if the file does not exist, and
/// [`CryptoError::Io`] for other read failures. Returns
/// [`CryptoError::InvalidFormat`] or
/// [`CryptoError::RecipientStringCapExceeded`] if the text file or recipient
/// string is malformed, beyond the structural ceiling, or is a private key.
/// Returns [`CryptoError::UnsupportedVersion`] for a public key from an
/// unsupported keypair suite. Returns
/// [`CryptoError::UnsupportedKeyType`] for a valid public key of a
/// key type this build does not support.
pub fn validate_public_key_file(key_file: impl AsRef<Path>) -> Result<(), CryptoError> {
    // No resource policy of its own: this validates structure only, so the
    // recipient-string cap and the private-key probe both run at the
    // structural maxima.
    PublicKey::from_key_file_with_limits(key_file, KeyReadLimits::structural_max()).map(|_| ())
}

// ─── Internal validators ────────────────────────────────────────────────────

/// Enforces the `FORMAT.md` §2.2 passphrase byte-length bound (1 to
/// [`MAX_PASSPHRASE_LEN_BYTES`](crate::crypto::kdf::MAX_PASSPHRASE_LEN_BYTES),
/// inclusive) at the public boundary, so an out-of-bound passphrase is
/// rejected before any input or archive work. Shares
/// [`crate::crypto::kdf::check_passphrase_len`] with the pre-Argon2id
/// gates, so the boundary and the key-derivation paths cannot drift.
pub(crate) fn validate_passphrase(passphrase: &Passphrase) -> Result<(), CryptoError> {
    crate::crypto::kdf::check_passphrase_len(passphrase.expose())
}
