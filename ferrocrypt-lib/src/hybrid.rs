//! Hybrid (X25519 recipient) `.fcr` encrypt and decrypt, plus thin
//! wrappers around the v1 `private.key` reader for the X25519 case.
//!
//! Pipeline:
//!   per-file random `file_key` (32 B)
//!   X25519 ECDH (caller pubkey on encrypt, recipient privkey on decrypt) →
//!     HKDF-SHA3-256 → `wrap_key`
//!   `wrap_key` + XChaCha20-Poly1305 seals `file_key` into the
//!     x25519 recipient body (104 B; see `recipients::x25519`)
//!   `file_key` + `stream_nonce` + HKDF-SHA3-256 → `payload_key` + `header_key`
//!   `payload_key` encrypts the TAR payload via STREAM-BE32
//!   `header_key` HMAC-SHA3-256 authenticates the on-disk header
//!
//! Decryption requires the recipient's `private.key` (passphrase-
//! wrapped via `private_key.rs`); on multi-recipient files the
//! decrypt loop iterates `x25519` slots in declared order, accepting
//! the first slot whose unwrap and header MAC both verify.
//!
//! Wire format: a v1 `.fcr` container with one or more `x25519`
//! recipient entries. See `ferrocrypt-lib/FORMAT.md` §3 and
//! `encrypted_file.rs` for the shared header layout.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::OsRng;
use secrecy::SecretString;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::archiver::{ArchiveLimits, unarchive};
use crate::atomic_output;
use crate::common::{
    DerivedSubkeys, KdfLimit, KdfParams, STREAM_NONCE_SIZE, derive_subkeys, encryption_base_name,
    generate_file_key, payload_decryptor, random_bytes, validate_tlv,
};
use crate::encrypted_file::{
    HeaderReadLimits, build_encrypted_header, read_encrypted_header, write_encrypted_file,
};
use crate::error::FormatDefect;
use crate::format;
use crate::private_key::{
    PRIVATE_KEY_HEADER_FIXED_SIZE, PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT, PrivateKeyHeader,
    open_private_key, seal_private_key,
};
use crate::public_key::{
    RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT, decode_recipient_string, encode_recipient_string,
};
use crate::recipients::{NativeRecipientType, RecipientEntry, classify_encryption_mode, x25519};
use crate::{CryptoError, EncryptionMode, ProgressEvent};

/// Default filename for the hybrid public key file (text form).
pub const PUBLIC_KEY_FILENAME: &str = "public.key";
/// Default filename for the hybrid private key file (binary, wrapped).
pub const PRIVATE_KEY_FILENAME: &str = "private.key";

// ─── Encrypt ───────────────────────────────────────────────────────────────

/// Encrypts under a recipient's raw 32-byte X25519 public key. The
/// caller (typically `lib.rs`) is responsible for obtaining the bytes
/// from a `fcr1…` recipient string or a `public.key` text file.
///
/// Wire format: a v1 `.fcr` container with exactly one `x25519`
/// recipient entry. Per `FORMAT.md` §3.4, `x25519` is public-key-
/// mixable, so future callers may encrypt to multiple recipients;
/// today's API exposes the single-recipient path. The recipient body
/// (`ephemeral_pubkey || wrap_nonce || wrapped_file_key`, 104 B) is
/// built by [`crate::recipients::x25519::wrap`], which generates the
/// ephemeral X25519 keypair, runs ECDH against `public_key_bytes`,
/// rejects an all-zero shared secret, derives the wrap key via
/// HKDF-SHA3-256, and AEAD-seals `file_key`. The rest of the header
/// (prefix, fixed, recipient_entries, MAC) is assembled by
/// [`crate::encrypted_file::build_encrypted_header`], which is the
/// single source of truth for header MAC scope across both modes.
pub fn encrypt_file_from_bytes(
    input_path: &Path,
    output_dir: &Path,
    public_key_bytes: &[u8; 32],
    output_file: Option<&Path>,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    on_event(&ProgressEvent::DerivingKey);

    // Generate per-file random material first so the rest of the
    // build is a pure function of (file_key, recipient_pubkey,
    // stream_nonce, input bytes). file_key lives in `Zeroizing`, so
    // an early return wipes it.
    let file_key = generate_file_key();
    let stream_nonce = random_bytes::<STREAM_NONCE_SIZE>();
    let DerivedSubkeys {
        payload_key,
        header_key,
    } = derive_subkeys(&file_key, &stream_nonce)?;

    // Wrap the file_key for the X25519 recipient. Ephemeral keypair
    // generation, ECDH, all-zero-shared rejection, wrap-key
    // derivation, and AEAD seal all run inside this call. After the
    // body is built, the raw file_key is no longer needed; drop it
    // immediately so the plaintext window in memory is minimal.
    let body = x25519::wrap(&file_key, public_key_bytes)?;
    drop(file_key);

    let entry = RecipientEntry::native(NativeRecipientType::X25519, body.to_vec())?;

    // Assemble prefix + header + MAC. `build_encrypted_header` is the
    // single byte-arithmetic implementation; encrypt and decrypt
    // share its MAC scope. `payload_key` and `stream_nonce` move into
    // the returned bundle so the writer cannot be paired with material
    // from a different derivation.
    let built = build_encrypted_header(
        std::slice::from_ref(&entry),
        b"", // v1.0 writers emit ext_len = 0
        stream_nonce,
        payload_key,
        &header_key,
    )?;
    drop(header_key);

    let base_name = encryption_base_name(input_path)?;
    on_event(&ProgressEvent::Encrypting);

    write_encrypted_file(
        input_path,
        output_dir,
        output_file,
        &base_name,
        &built,
        ArchiveLimits::default(),
    )
}

// ─── Decrypt ───────────────────────────────────────────────────────────────

/// Decrypts a hybrid `.fcr` file using the recipient's `private.key`
/// (passphrase-wrapped via `private_key.rs`). Follows the FORMAT.md
/// §3.7 acceptance order, extended to multi-recipient files:
///
/// 1. read + structurally validate the header (`read_encrypted_header`)
/// 2. classify the recipient list — rejects unknown critical entries,
///    enforces `argon2id` exclusivity, requires the file to carry at
///    least one supported `x25519` recipient. All checks fire BEFORE
///    Argon2id runs on the `private.key`.
/// 3. unlock the recipient's `private.key` via
///    [`open_x25519_private_key`] (Argon2id + AEAD-AAD validation).
/// 4. iterate `x25519` recipient slots in declared order, attempting
///    every supported entry before deciding (per `FORMAT.md` §3.7
///    SHOULD-level mitigation and `MIGRATION.md` §1.2's "default to
///    attempting all" — reduces timing leakage about which slot
///    matched). Per slot:
///    - flags must be zero (native v1 — critical bit unused on
///      types the reader handles natively);
///    - body length must be 104;
///    - try `recipients::x25519::unwrap`. On failure, continue.
///    - on success, derive `payload_key` + `header_key` and verify
///      the header MAC. On MAC success, keep this slot's
///      `payload_key` as the selected one (first MAC-verified slot
///      wins; later candidates are dropped) but keep scanning the
///      remaining slots so the loop's wall time does not betray
///      which slot matched.
/// 5. after the loop:
///    - selected `payload_key` present → validate TLV, STREAM-
///      decrypt the payload;
///    - no selection but had a successful unwrap →
///      [`CryptoError::HeaderMacFailedAfterUnwrap`] with
///      `type_name = "x25519"` (a slot unwrapped a `file_key` but the
///      derived `header_key` did not verify the MAC; reserved for the
///      hybrid path because the slot identity is meaningful here);
///    - no successful unwrap →
///      [`CryptoError::RecipientUnwrapFailed`] with `type_name = "x25519"`.
pub fn decrypt_file(
    input_path: &Path,
    output_dir: &Path,
    private_key_path: &Path,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    let mut encrypted_file = fs::File::open(input_path)?;

    // 1. Structural read. Performs zero crypto, enforces local caps.
    let parsed = read_encrypted_header(&mut encrypted_file, HeaderReadLimits::default())?;

    // 2. Classify the recipient list. Unknown critical entries,
    //    argon2id-exclusivity violations, and "no supported native
    //    recipient" all surface here BEFORE any KDF runs (the
    //    private.key Argon2id work in step 3 is gated by this check
    //    succeeding).
    match classify_encryption_mode(&parsed.recipient_entries)? {
        EncryptionMode::Hybrid => {}
        EncryptionMode::Symmetric => {
            // Caller invoked `hybrid_decrypt` on a passphrase file.
            // The right path is `symmetric_decrypt`; surface the
            // generic "no recipient could unlock the file" diagnostic.
            return Err(CryptoError::NoSupportedRecipient);
        }
    }

    // 3. Unlock the recipient's private key. Argon2id and AEAD-AAD
    //    validation happen inside `open_x25519_private_key` →
    //    `private_key::open_private_key`.
    on_event(&ProgressEvent::DerivingKey);
    let recipient_secret = open_x25519_private_key(private_key_path, passphrase, kdf_limit)?;

    // 4. Iterate x25519 recipient slots, looking for the slot whose
    //    unwrap recovers a `file_key` whose `header_key` verifies the
    //    header MAC. Per FORMAT.md §3.7, MAC verification is the final
    //    acceptance gate — until it succeeds, the candidate is not
    //    final.
    //
    //    Per FORMAT.md §3.7 SHOULD-level mitigation and MIGRATION.md
    //    §1.2's "default to attempting all", the loop visits EVERY
    //    supported `x25519` entry before deciding rather than
    //    short-circuiting on the first MAC-verified slot. This makes
    //    the wall-clock cost a function of `recipient_count` (capped
    //    by `HeaderReadLimits`) rather than of which slot matched, so
    //    elapsed time does not leak the recipient's position in the
    //    list. The first MAC-verified slot wins; later candidates are
    //    dropped.
    let stream_nonce = parsed.fixed.stream_nonce;
    let mut had_successful_unwrap = false;
    let mut selected_payload_key: Option<Zeroizing<[u8; 32]>> = None;

    for entry in parsed.recipient_entries.iter() {
        if entry.type_name != x25519::TYPE_NAME {
            // Unknown non-critical entries are skipped per FORMAT.md
            // §3.4; classification above already rejected unknown
            // critical entries, so anything we encounter here that is
            // not `x25519` is a non-critical slot we are entitled to
            // ignore.
            continue;
        }

        // Per-slot structural validation: flags must be zero (native
        // v1 critical bit is unused on types the reader handles
        // natively) and body length must match the canonical 104-byte
        // x25519 body. A set flag or wrong size is a structural
        // anomaly that aborts the whole file, not a slot to skip.
        let body: [u8; x25519::BODY_LENGTH] = entry.expect_native_body()?;

        // Try unwrap. Wrong recipient key, all-zero shared secret, and
        // tampered body all surface from `unwrap` as
        // `RecipientUnwrapFailed`; skip to the next slot rather than
        // aborting — a multi-recipient file may have a slot for us
        // later in the list.
        let file_key = match x25519::unwrap(&body, &recipient_secret) {
            Ok(k) => k,
            Err(_) => continue,
        };
        had_successful_unwrap = true;

        let DerivedSubkeys {
            payload_key,
            header_key,
        } = derive_subkeys(&file_key, &stream_nonce)?;
        drop(file_key);

        // Header MAC is the FINAL acceptance gate. On success, keep
        // this slot's `payload_key` as the selected one IF none has
        // been selected yet; on failure, continue to the next slot.
        // We deliberately do NOT short-circuit on first match: scanning
        // all remaining supported slots costs constant time per slot
        // and is what makes the loop's wall time independent of which
        // slot matched.
        if format::verify_header_mac(
            &parsed.prefix_bytes,
            &parsed.header_bytes,
            &header_key,
            &parsed.header_mac,
        )
        .is_ok()
            && selected_payload_key.is_none()
        {
            selected_payload_key = Some(payload_key);
        }
        drop(header_key);
    }

    drop(recipient_secret);

    let Some(payload_key) = selected_payload_key else {
        // Per FORMAT.md §3.7 the per-candidate variant
        // `HeaderMacFailedAfterUnwrap` carries the slot's `type_name`;
        // the bare `HeaderTampered` is reserved for single-recipient
        // symmetric files where there's no slot identity to attach.
        // `had_successful_unwrap` distinguishes "this private.key isn't
        // a recipient of the file at all" from "we unwrapped a slot
        // but its derived header_key didn't verify the MAC".
        let type_name = x25519::TYPE_NAME.to_string();
        return Err(if had_successful_unwrap {
            CryptoError::HeaderMacFailedAfterUnwrap { type_name }
        } else {
            CryptoError::RecipientUnwrapFailed { type_name }
        });
    };

    // SUCCESS: TLV validation runs AFTER MAC verify, so the validator
    // is operating on authenticated bytes.
    validate_tlv(&parsed.ext_bytes)?;

    on_event(&ProgressEvent::Decrypting);
    let decrypt_reader = payload_decryptor(&payload_key, &stream_nonce, encrypted_file);
    unarchive(decrypt_reader, output_dir, ArchiveLimits::default())
}

/// Reads and unlocks a v1 `private.key` file, returning the raw 32-byte
/// X25519 secret. Wraps [`crate::private_key::open_private_key`] with
/// the X25519-specific type-name and length checks plus TLV validation.
///
/// Errors:
/// - [`CryptoError::InputPath`] if the file does not exist
/// - [`CryptoError::Io`] for other read errors
/// - [`CryptoError::KeyFileUnlockFailed`] for wrong passphrase or
///   tampered cleartext (AEAD cannot distinguish)
/// - [`FormatDefect::WrongKeyFileType`] for a private.key that wraps a
///   non-X25519 secret (e.g. a future native key kind)
/// - [`FormatDefect::MalformedPrivateKey`] for a structurally valid
///   private.key whose authenticated `public_material` is not 32 bytes,
///   whose decrypted `secret_material` is not 32 bytes, or whose
///   stored public material does not match
///   `X25519(secret_material, basepoint)` (the FORMAT.md §8 native
///   recipient-specific check)
/// - [`FormatDefect::MalformedTlv`] / [`FormatDefect::UnknownCriticalTag`]
///   for malformed or unknown-critical entries in `ext_bytes`
fn open_x25519_private_key(
    path: &Path,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
) -> Result<Zeroizing<[u8; x25519::PRIVATE_KEY_SIZE]>, CryptoError> {
    let bytes = fs::read(path).map_err(map_user_path_io_error)?;

    // Friendly diagnostic for the cross-mix-up: a user pointing the
    // private-key reader at a `public.key` text file gets
    // `WrongKeyFileType` rather than the generic `NotAKeyFile` that
    // `open_private_key`'s magic check would surface.
    if matches!(KeyFileKind::classify(&bytes), KeyFileKind::Public) {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }

    let opened = open_private_key(
        &bytes,
        passphrase,
        kdf_limit,
        PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT,
    )?;

    if opened.type_name != x25519::TYPE_NAME {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }

    let public_material: [u8; x25519::PUBKEY_SIZE] =
        opened
            .public_material
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey))?;

    if opened.secret_material.len() != x25519::PRIVATE_KEY_SIZE {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ));
    }

    // TLV validation is safe to run after AEAD-AAD authentication
    // succeeded — `private_key::open_private_key` only returns Ok
    // after the AEAD pass that bound `ext_bytes` as AAD.
    validate_tlv(&opened.ext_bytes)?;

    let mut secret = Zeroizing::new([0u8; x25519::PRIVATE_KEY_SIZE]);
    secret.copy_from_slice(&opened.secret_material);

    // FORMAT.md §8: native X25519 readers MUST compute
    // X25519(secret_material, basepoint) and reject unless the result
    // exactly equals the authenticated `public_material`. AEAD-AAD
    // already authenticated `public_material` against tampering, but a
    // file produced by a buggy or malicious writer can still seal a
    // mismatched pair; this check rejects that case before the secret
    // is ever used to unwrap a recipient body.
    let derived_public = PublicKey::from(&StaticSecret::from(*secret));
    if derived_public.as_bytes() != &public_material {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ));
    }

    Ok(secret)
}

// ─── Key-file readers ──────────────────────────────────────────────────────

/// Heuristic classification of key-file bytes. Cheap, non-
/// authenticating: callers use it to surface the friendly
/// `WrongKeyFileType` diagnostic when a user hands the wrong
/// kind of key file to a reader. The strict parse — Bech32 +
/// algorithm + length for public, magic + version + type +
/// algorithm + size + AEAD for private — runs downstream in
/// each reader against the actual unlock or extract path.
///
/// Adding a new variant is a deliberate breaking change inside
/// the crate: every `match` over a `KeyFileKind` becomes a
/// compile error until the new kind is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyFileKind {
    /// Bytes look like a v1 `public.key`: a UTF-8 string that
    /// decodes as a canonical Bech32 `fcr1…` recipient (with
    /// surrounding whitespace tolerated for the heuristic — the
    /// strict parser in `read_public_key` enforces canonical
    /// whitespace separately).
    Public,
    /// Bytes carry the v1 `private.key` signature: at least 9
    /// bytes of `FCR\0 || ?? || 'K'`. Magic + type byte is
    /// sufficient regardless of `version`, so a future v2
    /// `private.key` still classifies as `Private` and surfaces
    /// the friendly diagnostic instead of `NotAKeyFile`.
    Private,
    /// Neither signature matches.
    Unknown,
}

impl KeyFileKind {
    /// Classifies `data` against the two v1 key-file shapes.
    /// Probes the cheap binary signature first; falls back to
    /// the more expensive Bech32 decode for the public-key
    /// text shape.
    ///
    /// The binary signature is `magic(4) || version(1) || kind(1)
    /// = 'K'`. The version byte is intentionally not constrained,
    /// so a future v2 `private.key` still classifies as `Private`
    /// and surfaces the friendly diagnostic instead of `NotAKeyFile`.
    ///
    /// Adversarial inputs that do NOT match either signature
    /// (a `.fcr` encrypted file whose `kind` byte is `'E'`,
    /// random binary without magic, garbage `fcr1…` text with a
    /// bad checksum) classify as `Unknown` and fall through to
    /// the caller's generic rejection path. Probability of an
    /// accidental `Private` match on truly random binary is
    /// `2^-40` (the five specific bytes in the signature).
    pub(crate) fn classify(data: &[u8]) -> Self {
        // Smallest prefix needed to read the kind byte at offset 5:
        // magic(4) || version(1) || kind(1).
        const SIGNATURE_LEN: usize = 6;
        if data.len() >= SIGNATURE_LEN
            && data[0..4] == format::MAGIC
            && data[5] == format::KIND_PRIVATE_KEY
        {
            return Self::Private;
        }
        if let Ok(text) = std::str::from_utf8(data) {
            if decode_recipient_string(text.trim(), RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT).is_ok()
            {
                return Self::Public;
            }
        }
        Self::Unknown
    }
}

/// Converts an [`io::Error`] from a user-provided path read into a
/// typed [`CryptoError`]. `NotFound` maps to [`CryptoError::InputPath`]
/// so "file does not exist" gives the same pretty message here as it
/// does from the upfront `validate_input_path` check. Everything else
/// falls through to [`CryptoError::Io`].
pub(crate) fn map_user_path_io_error(e: io::Error) -> CryptoError {
    if e.kind() == io::ErrorKind::NotFound {
        CryptoError::InputPath
    } else {
        CryptoError::Io(e)
    }
}

// ─── generate_key_pair ─────────────────────────────────────────────────────

/// Generates an X25519 key pair and writes both files to `output_dir`.
/// Returns `(private_key_path, public_key_path)`.
///
/// - `private.key` is the v1 passphrase-wrapped binary keyfile.
///   `private_key::seal_private_key` owns the byte layout (cleartext
///   header → AEAD-AAD-bound → wrapped secret). Permissions: `0o600`
///   on Unix.
/// - `public.key` is a UTF-8 text file containing the canonical
///   `fcr1…` Bech32 recipient string. Permissions: `0o644` on Unix
///   (public keys are not secret).
pub fn generate_key_pair(
    passphrase: &SecretString,
    output_dir: &Path,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<(PathBuf, PathBuf), CryptoError> {
    fs::create_dir_all(output_dir)?;

    // Existence pre-check BEFORE Argon2id so re-running `keygen` against
    // a populated directory returns a helpful error in milliseconds
    // instead of after ~1 GiB / multi-second KDF work. The atomic
    // no-clobber rename at `finalize_file` below is still what actually
    // guarantees we never overwrite an existing key; this check is just
    // a fast-path user-experience win.
    let private_key_path = output_dir.join(PRIVATE_KEY_FILENAME);
    let public_key_path = output_dir.join(PUBLIC_KEY_FILENAME);
    if private_key_path.exists() {
        return Err(CryptoError::InvalidInput(format!(
            "Key file already exists: {}",
            private_key_path.display()
        )));
    }
    if public_key_path.exists() {
        return Err(CryptoError::InvalidInput(format!(
            "Key file already exists: {}",
            public_key_path.display()
        )));
    }

    on_event(&ProgressEvent::GeneratingKeyPair);

    // Generate the X25519 keypair. `secret_material` is held in
    // `Zeroizing` so the 32-byte private bytes are wiped from memory
    // when this stack frame unwinds, regardless of whether the
    // subsequent seal/write succeeds.
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let secret_material = Zeroizing::new(secret.to_bytes());
    drop(secret);
    let public_material = *public.as_bytes();

    // Hand off all `private.key` byte-layout, AEAD, and AAD scope to
    // `private_key.rs` — this used to be hand-rolled here and is now
    // the single source of truth.
    let private_key_bytes = seal_private_key(
        secret_material.as_ref(),
        x25519::TYPE_NAME,
        &public_material,
        &[], // no v1 ext_bytes for the X25519 case
        passphrase,
        &KdfParams::default(),
    )?;
    drop(secret_material);

    // Encode the canonical `fcr1…` recipient string via `public_key.rs`
    // (validates type-name grammar, computes the internal SHA3-256
    // checksum, emits BIP 173 lowercase Bech32).
    let recipient_string = encode_recipient_string(x25519::TYPE_NAME, &public_material)?;

    // Write public.key (text file, `fcr1…\n`). Public key isn't secret
    // so permissions relax to 0o644 on Unix.
    let mut public_builder = tempfile::Builder::new();
    public_builder.prefix(".ferrocrypt-pubkey-").suffix(".tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        public_builder.permissions(fs::Permissions::from_mode(0o644));
    }
    let mut public_tmp = public_builder.tempfile_in(output_dir)?;
    public_tmp
        .as_file_mut()
        .write_all(recipient_string.as_bytes())?;
    public_tmp.as_file_mut().write_all(b"\n")?;
    public_tmp.as_file().sync_all()?;
    atomic_output::finalize_file(public_tmp, &public_key_path)?;

    // Write private.key. If this fails, clean up the public.key we
    // just wrote (public keys are not secret, but leaving orphaned
    // output is unfriendly). The `tempfile` 3.x default on Unix already
    // uses 0o600, but we set it explicitly so the permission invariant
    // is visible here and cannot silently regress if the upstream
    // default ever changes.
    let private_write: Result<(), CryptoError> = (|| {
        let mut private_builder = tempfile::Builder::new();
        private_builder
            .prefix(".ferrocrypt-privkey-")
            .suffix(".tmp");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            private_builder.permissions(fs::Permissions::from_mode(0o600));
        }
        let mut private_tmp = private_builder.tempfile_in(output_dir)?;
        private_tmp.as_file_mut().write_all(&private_key_bytes)?;
        private_tmp.as_file().sync_all()?;
        atomic_output::finalize_file(private_tmp, &private_key_path)?;
        Ok(())
    })();

    if let Err(e) = private_write {
        let _ = fs::remove_file(&public_key_path);
        return Err(e);
    }

    Ok((private_key_path, public_key_path))
}

/// Reads a v1 `public.key` text file and returns the raw 32-byte
/// X25519 public key. The file content MUST be the canonical
/// lowercase `fcr1…` recipient string, optionally followed by
/// exactly one trailing `\n` (FORMAT.md §7). Anything else
/// — leading whitespace, CRLF line endings, extra blank lines,
/// trailing spaces or tabs, internal whitespace — is rejected as
/// [`FormatDefect::MalformedPublicKey`].
///
/// If the caller accidentally points this at a binary `private.key`
/// (magic `FCR\0`), the reader surfaces
/// [`FormatDefect::WrongKeyFileType`] instead of a cryptic UTF-8
/// decode error.
///
/// Decoding delegates to [`crate::public_key::decode_recipient_string`],
/// which is the single source of truth for the Bech32 grammar,
/// internal SHA3-256 checksum, and resource caps.
pub fn read_public_key(path: &Path) -> Result<[u8; 32], CryptoError> {
    let bytes = fs::read(path).map_err(map_user_path_io_error)?;
    if matches!(KeyFileKind::classify(&bytes), KeyFileKind::Private) {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }
    let contents = String::from_utf8(bytes)
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::NotAKeyFile))?;
    // Non-whitespace junk (BOM, ZWSP, non-Bech32 chars) is left for
    // `decode_recipient_string` to reject — a format violation in the
    // whitespace grammar deserves its own bucket.
    let recipient = contents.strip_suffix('\n').unwrap_or(&contents);
    if recipient.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey));
    }
    let decoded = decode_recipient_string(recipient, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT)?;
    if decoded.type_name != x25519::TYPE_NAME {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }
    decoded
        .key_material
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey))
}

// ─── Structural validator (kept for fuzz exports) ──────────────────────────

/// Validates the structural shape of a v1 `private.key` file. Does not
/// attempt to decrypt or derive any keys. Used by
/// [`crate::validate_private_key_file`] and re-exported via
/// `fuzz_exports` for the fuzz harness.
///
/// Checks (in order):
/// - file is large enough to hold the 90-byte cleartext fixed header;
/// - [`crate::private_key::PrivateKeyHeader::parse`] accepts the
///   header (magic, version, kind, `key_flags == 0`, length-field
///   structural ranges);
/// - `type_name` is `"x25519"` (the only v1 native key kind);
/// - `public_len` equals the X25519 public-key size (32);
/// - the file's total length matches `90 + type_name_len + public_len
///   + ext_len + wrapped_secret_len`.
///
/// Does NOT validate `ext_bytes` TLV canonicity. TLV canonicity runs
/// only after AEAD-AAD authentication, which structural validation by
/// definition does not perform.
pub fn validate_private_key_shape(data: &[u8]) -> Result<(), CryptoError> {
    let header_bytes =
        data.first_chunk::<PRIVATE_KEY_HEADER_FIXED_SIZE>()
            .ok_or(CryptoError::InvalidFormat(
                FormatDefect::MalformedPrivateKey,
            ))?;
    let header = PrivateKeyHeader::parse(header_bytes)?;

    let type_name_start = PRIVATE_KEY_HEADER_FIXED_SIZE;
    let type_name_end = type_name_start
        .checked_add(header.type_name_len as usize)
        .ok_or(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ))?;
    if data.len() < type_name_end {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ));
    }
    let type_name = std::str::from_utf8(&data[type_name_start..type_name_end])
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedTypeName))?;
    if type_name != x25519::TYPE_NAME {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }

    if header.public_len != x25519::PUBKEY_SIZE as u32 {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ));
    }

    let expected_total = (PRIVATE_KEY_HEADER_FIXED_SIZE as u64)
        .checked_add(header.type_name_len as u64)
        .and_then(|v| v.checked_add(header.public_len as u64))
        .and_then(|v| v.checked_add(header.ext_len as u64))
        .and_then(|v| v.checked_add(header.wrapped_secret_len as u64))
        .ok_or(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ))?;
    if (data.len() as u64) != expected_total {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ));
    }

    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{WRAP_NONCE_SIZE, payload_encryptor};
    use crate::format::{HEADER_FIXED_SIZE, PREFIX_SIZE};
    use crate::recipients::{ENTRY_HEADER_SIZE, RECIPIENT_FLAG_CRITICAL, argon2id};

    /// File offset of `stream_nonce`. Mirrors the symmetric-side
    /// constant: `stream_nonce` is the trailing field of `header_fixed`,
    /// so the offset within `header_fixed` is `HEADER_FIXED_SIZE -
    /// STREAM_NONCE_SIZE`; add `PREFIX_SIZE` for the absolute file
    /// offset.
    const STREAM_NONCE_FILE_OFFSET: usize = PREFIX_SIZE + HEADER_FIXED_SIZE - STREAM_NONCE_SIZE;

    /// File offset of the start of the lone `x25519` recipient body
    /// (per `FORMAT.md` §3.5): prefix + fixed header + entry header
    /// + the `"x25519"` `type_name`.
    const X25519_BODY_FILE_OFFSET: usize =
        PREFIX_SIZE + HEADER_FIXED_SIZE + ENTRY_HEADER_SIZE + x25519::TYPE_NAME.len();

    /// Offset of `wrapped_file_key` inside the `x25519` body
    /// (per `FORMAT.md` §4.2): `ephemeral_pubkey || wrap_nonce`
    /// precede it.
    const X25519_WRAPPED_FILE_KEY_BODY_OFFSET: usize = x25519::PUBKEY_SIZE + WRAP_NONCE_SIZE;

    /// Harness: generate a key pair, write a test file, and encrypt it.
    /// Returns the tempdir, encrypted file path, decrypted-output dir,
    /// private-key path, and the passphrase used to wrap the private
    /// key. Every hybrid test starts from this setup.
    fn hybrid_fixture(
        content: &str,
        key_passphrase: &str,
    ) -> Result<(tempfile::TempDir, PathBuf, PathBuf, PathBuf, SecretString), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let enc_dir = tmp.path().join("encrypted");
        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&keys_dir)?;
        fs::create_dir_all(&enc_dir)?;
        fs::create_dir_all(&dec_dir)?;

        let pass = SecretString::from(key_passphrase.to_string());
        let (privkey_path, pubkey_path) = generate_key_pair(&pass, &keys_dir, &|_| {})?;

        let pubkey_bytes = read_public_key(&pubkey_path)?;
        let input = tmp.path().join("data.txt");
        fs::write(&input, content)?;

        encrypt_file_from_bytes(&input, &enc_dir, &pubkey_bytes, None, &|_| {})?;
        let fcr = enc_dir.join("data.fcr");
        Ok((tmp, fcr, dec_dir, privkey_path, pass))
    }

    #[test]
    fn encrypt_decrypt_round_trip() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, privkey, pass) = hybrid_fixture("hybrid round trip", "kp")?;
        assert!(fcr.exists());
        decrypt_file(&fcr, &dec_dir, &privkey, &pass, None, &|_| {})?;
        let restored = fs::read_to_string(dec_dir.join("data.txt"))?;
        assert_eq!(restored, "hybrid round trip");
        Ok(())
    }

    /// Encrypting to Alice but decrypting with Bob's private key must
    /// surface `RecipientUnwrapFailed { type_name: "x25519" }` at the
    /// recipient-unwrap step (single-recipient file, so the loop
    /// terminates with the per-candidate error rather than
    /// `NoSupportedRecipient`).
    #[test]
    fn decrypt_with_wrong_private_key_fails_at_envelope() -> Result<(), CryptoError> {
        // Alice's keys: hybrid_fixture gives us Alice.
        let (tmp, fcr, dec_dir, _alice_privkey, _alice_pass) = hybrid_fixture("x", "alice")?;
        // Bob's separate key pair.
        let bob_keys = tmp.path().join("bob_keys");
        fs::create_dir_all(&bob_keys)?;
        let bob_pass = SecretString::from("bob".to_string());
        let (bob_privkey, _bob_pubkey) = generate_key_pair(&bob_pass, &bob_keys, &|_| {})?;

        match decrypt_file(&fcr, &dec_dir, &bob_privkey, &bob_pass, None, &|_| {}) {
            Err(CryptoError::RecipientUnwrapFailed { ref type_name })
                if type_name == x25519::TYPE_NAME =>
            {
                Ok(())
            }
            other => panic!("expected RecipientUnwrapFailed(x25519), got {other:?}"),
        }
    }

    /// Wrong passphrase for the correct private-key file must surface
    /// as `KeyFileUnlockFailed` — distinct from envelope failure.
    #[test]
    fn decrypt_with_wrong_private_key_passphrase_fails_at_keyfile() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, privkey, _pass) = hybrid_fixture("x", "right")?;
        let wrong = SecretString::from("wrong".to_string());
        match decrypt_file(&fcr, &dec_dir, &privkey, &wrong, None, &|_| {}) {
            Err(CryptoError::KeyFileUnlockFailed) => Ok(()),
            other => panic!("expected KeyFileUnlockFailed, got {other:?}"),
        }
    }

    /// Tampering the stream_nonce must be caught by the header MAC
    /// AFTER successful recipient unwrap — surfaces as
    /// `HeaderMacFailedAfterUnwrap { type_name: "x25519" }`. The
    /// hybrid loop attaches the slot identity rather than collapsing
    /// to bare `HeaderTampered` (the latter is reserved for symmetric
    /// files, which have no slot to identify).
    #[test]
    fn decrypt_with_tampered_stream_nonce_fails_at_hmac() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, privkey, pass) = hybrid_fixture("x", "kp")?;
        let mut bytes = fs::read(&fcr)?;
        bytes[STREAM_NONCE_FILE_OFFSET] ^= 0xFF;
        fs::write(&fcr, &bytes)?;
        match decrypt_file(&fcr, &dec_dir, &privkey, &pass, None, &|_| {}) {
            Err(CryptoError::HeaderMacFailedAfterUnwrap { ref type_name })
                if type_name == x25519::TYPE_NAME =>
            {
                Ok(())
            }
            other => panic!("expected HeaderMacFailedAfterUnwrap(x25519), got {other:?}"),
        }
    }

    /// Tampering `wrapped_file_key` inside the x25519 recipient body
    /// surfaces as `RecipientUnwrapFailed { type_name: "x25519" }` at
    /// AEAD-open time.
    #[test]
    fn decrypt_with_tampered_envelope_fails_at_unwrap() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, privkey, pass) = hybrid_fixture("x", "kp")?;
        let mut bytes = fs::read(&fcr)?;
        let wrapped_offset = X25519_BODY_FILE_OFFSET + X25519_WRAPPED_FILE_KEY_BODY_OFFSET;
        bytes[wrapped_offset] ^= 0x01;
        fs::write(&fcr, &bytes)?;
        match decrypt_file(&fcr, &dec_dir, &privkey, &pass, None, &|_| {}) {
            Err(CryptoError::RecipientUnwrapFailed { ref type_name })
                if type_name == x25519::TYPE_NAME =>
            {
                Ok(())
            }
            other => panic!("expected RecipientUnwrapFailed(x25519), got {other:?}"),
        }
    }

    /// Recipient string encode + decode must round-trip bit-for-bit
    /// through `crate::public_key::*`.
    #[test]
    fn recipient_string_round_trip() -> Result<(), CryptoError> {
        let mut pk = [0u8; 32];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = i as u8;
        }
        let s = encode_recipient_string(x25519::TYPE_NAME, &pk)?;
        assert!(s.starts_with("fcr1"));
        let decoded = decode_recipient_string(&s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT)?;
        assert_eq!(decoded.type_name, x25519::TYPE_NAME);
        assert_eq!(decoded.key_material.as_slice(), pk.as_slice());
        Ok(())
    }

    /// Non-canonical recipient strings MUST be rejected: uppercase-only
    /// and mixed-case both fail even though Bech32 itself can decode
    /// either case in isolation.
    #[test]
    fn recipient_string_rejects_non_canonical_case() {
        let canonical = encode_recipient_string(x25519::TYPE_NAME, &[0x42; 32]).unwrap();

        let cap = RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT;
        let upper = canonical.to_uppercase();
        match decode_recipient_string(&upper, cap) {
            Err(CryptoError::InvalidInput(_))
            | Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected lowercase rejection for uppercase-only, got {other:?}"),
        }

        let mut mixed = canonical.clone();
        mixed.replace_range(4..5, &mixed[4..5].to_uppercase());
        match decode_recipient_string(&mixed, cap) {
            Err(CryptoError::InvalidInput(_))
            | Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected lowercase rejection for mixed case, got {other:?}"),
        }
    }

    /// `public.key` round-trip as text file.
    #[test]
    fn public_key_file_round_trip() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let pass = SecretString::from("kp".to_string());
        let (_privkey, pubkey_path) = generate_key_pair(&pass, tmp.path(), &|_| {})?;
        // Verify text format: single fcr1 line + newline.
        let contents = fs::read_to_string(&pubkey_path)?;
        assert!(contents.starts_with("fcr1"));
        assert!(contents.ends_with('\n'));
        assert_eq!(contents.lines().count(), 1);
        // Parse roundtrip.
        let pk_bytes = read_public_key(&pubkey_path)?;
        assert_eq!(pk_bytes.len(), 32);
        Ok(())
    }

    /// Pointing `read_public_key` at a binary `private.key` must
    /// surface `WrongKeyFileType` — the user swapped the key-file
    /// kind, not the file family. (No raw UTF-8 decode error.)
    #[test]
    fn read_public_key_rejects_private_key_file_as_wrong_type() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let pass = SecretString::from("kp".to_string());
        let (privkey_path, _pubkey_path) = generate_key_pair(&pass, tmp.path(), &|_| {})?;
        match read_public_key(&privkey_path) {
            Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType)) => Ok(()),
            other => panic!("expected WrongKeyFileType, got {other:?}"),
        }
    }

    /// Pointing `read_private_key` at a text `public.key` must
    /// surface `WrongKeyFileType` — the Bech32 `fcr1…` prefix is
    /// unambiguous enough to identify the mix-up rather than
    /// surfacing the generic `NotAKeyFile`.
    ///
    /// This also locks in the leading-whitespace tolerance: a
    /// `public.key` that an editor saved with a stray leading blank
    /// line must still be classified as "wrong kind", not
    /// "structural garbage".
    #[test]
    fn read_private_key_rejects_public_key_file_as_wrong_type() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let pass = SecretString::from("kp".to_string());
        let (_privkey_path, pubkey_path) = generate_key_pair(&pass, tmp.path(), &|_| {})?;

        // Baseline: canonical public.key file.
        match open_x25519_private_key(&pubkey_path, &pass, None).map(|_| ()) {
            Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType)) => {}
            other => panic!("expected WrongKeyFileType (canonical), got {other:?}"),
        }

        // With leading ASCII whitespace — trim must run before the
        // `fcr1` probe so the friendly diagnostic still fires.
        let original = fs::read_to_string(&pubkey_path)?;
        for decorated in [
            format!("  {original}"),
            format!("\n{original}"),
            format!("\r\n{original}"),
            format!("\t \n{original}"),
        ] {
            fs::write(&pubkey_path, decorated.as_bytes())?;
            match open_x25519_private_key(&pubkey_path, &pass, None).map(|_| ()) {
                Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType)) => {}
                other => panic!(
                    "expected WrongKeyFileType for leading-whitespace variant, got {other:?}"
                ),
            }
        }
        Ok(())
    }

    /// `KeyFileKind::classify` is the single source of truth for
    /// the cross-mix-up heuristic. Pin every classification arm so
    /// a future refactor that drifts the order or weakens a branch
    /// fails loudly.
    #[test]
    fn key_file_kind_classifies_each_shape() -> Result<(), CryptoError> {
        // Real public.key text → Public.
        let tmp = tempfile::TempDir::new().unwrap();
        let pass = SecretString::from("kp".to_string());
        let (privkey_path, pubkey_path) = generate_key_pair(&pass, tmp.path(), &|_| {})?;
        let pub_bytes = fs::read(&pubkey_path)?;
        assert_eq!(KeyFileKind::classify(&pub_bytes), KeyFileKind::Public);

        // Real private.key binary → Private.
        let priv_bytes = fs::read(&privkey_path)?;
        assert_eq!(KeyFileKind::classify(&priv_bytes), KeyFileKind::Private);

        // Magic + future version + type K (a v2 private.key) → Private.
        let v2_priv = b"FCR\0\x02K\x01\x00\x00";
        assert_eq!(KeyFileKind::classify(v2_priv), KeyFileKind::Private);

        // Magic but type byte is 'S' (a symmetric .fcr) → Unknown,
        // not Private. The `.fcr` mix-up heuristic lives elsewhere
        // (`detect_encryption_mode`); a key-file path should not
        // claim it.
        let fcr_symmetric = b"FCR\0\x01Sxx\x00\x00";
        assert_eq!(KeyFileKind::classify(fcr_symmetric), KeyFileKind::Unknown);

        // Bare magic, too short for the signature → Unknown.
        assert_eq!(KeyFileKind::classify(b"FCR\0"), KeyFileKind::Unknown);

        // Random binary without magic → Unknown.
        assert_eq!(
            KeyFileKind::classify(b"this isn't ours at all"),
            KeyFileKind::Unknown
        );

        // `fcr1`-prefixed garbage that fails Bech32 checksum →
        // Unknown (NOT Public). We don't claim ownership of files
        // we can't actually read.
        assert_eq!(KeyFileKind::classify(b"fcr1foobar"), KeyFileKind::Unknown);

        // Empty input → Unknown.
        assert_eq!(KeyFileKind::classify(b""), KeyFileKind::Unknown);
        Ok(())
    }

    /// `validate_private_key_file` must agree with `read_private_key`
    /// on the pub/priv mix-up verdict. Before this fix, the two paths
    /// disagreed: `read_private_key` returned `WrongKeyFileType` but
    /// `validate_private_key_file` surfaced the generic `NotAKeyFile`
    /// because it went through `parse_private_key_header` directly.
    #[test]
    fn validate_private_key_file_rejects_public_key_as_wrong_type() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let pass = SecretString::from("kp".to_string());
        let (_privkey_path, pubkey_path) = generate_key_pair(&pass, tmp.path(), &|_| {})?;
        match crate::validate_private_key_file(&pubkey_path) {
            Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType)) => Ok(()),
            other => panic!("expected WrongKeyFileType, got {other:?}"),
        }
    }

    /// Symmetric companion: `validate_public_key_file` accepts a
    /// real public.key and rejects a private.key with the same
    /// `WrongKeyFileType` diagnostic that `read_public_key` would
    /// produce. Pins the public-side validator against silent
    /// drift away from the read path.
    #[test]
    fn validate_public_key_file_round_trips_and_rejects_private() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let pass = SecretString::from("kp".to_string());
        let (privkey_path, pubkey_path) = generate_key_pair(&pass, tmp.path(), &|_| {})?;

        // Happy path: a real public.key validates cleanly.
        crate::validate_public_key_file(&pubkey_path)?;

        // Mix-up path: a private.key surfaces WrongKeyFileType.
        match crate::validate_public_key_file(&privkey_path) {
            Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType)) => Ok(()),
            other => panic!("expected WrongKeyFileType for private.key, got {other:?}"),
        }
    }

    /// Missing-file paths surface as `InputPath` for both
    /// `validate_*_key_file` functions, matching the rest of the
    /// key-reader API.
    #[test]
    fn validate_key_file_functions_map_missing_to_input_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let missing = tmp.path().join("no-such.key");
        assert!(matches!(
            crate::validate_public_key_file(&missing),
            Err(CryptoError::InputPath)
        ));
        assert!(matches!(
            crate::validate_private_key_file(&missing),
            Err(CryptoError::InputPath)
        ));
    }

    /// A file whose contents merely *start with* `fcr1` but don't
    /// parse as a valid recipient string (e.g. truncated garbage like
    /// `fcr1foobar`, or a public.key with a corrupted checksum) must
    /// NOT be labelled `WrongKeyFileType` — that wording claims the
    /// file *is* a public.key, just the wrong kind. Such junk should
    /// fall through to the generic private-key-header diagnostics.
    #[test]
    fn read_private_key_does_not_claim_garbage_fcr1_as_public_key() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let pass = SecretString::from("kp".to_string());
        let path = tmp.path().join("junk.key");

        for junk in ["fcr1foobar", "fcr1", "fcr1aaaaaa", "fcr1 with space"] {
            fs::write(&path, junk)?;
            match open_x25519_private_key(&path, &pass, None).map(|_| ()) {
                Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType)) => {
                    panic!("junk `{junk}` must not be classified as WrongKeyFileType");
                }
                // Anything else is fine — NotAKeyFile, Truncated, etc.
                // are all legitimate "we can't tell what this is" verdicts.
                Err(CryptoError::InvalidFormat(_)) => {}
                other => panic!("expected InvalidFormat for junk `{junk}`, got {other:?}"),
            }
        }
        Ok(())
    }

    /// `WrongKeyFileType` fires only when the file carries the
    /// private-key signature: at least 9 bytes of `FCR\0 || ?? || 'K'`.
    /// Files without that signature — bare magic, magic with the
    /// wrong type byte (e.g. a symmetric `.fcr`), random binary —
    /// must fall through to the generic rejection path.
    #[test]
    fn read_public_key_only_claims_private_key_on_magic_and_type_byte() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("junk.key");

        // No private-key signature → must NOT surface WrongKeyFileType.
        let no_signature: &[(&str, Vec<u8>)] = &[
            ("bare magic (under header size)", b"FCR\0".to_vec()),
            (
                "magic + type byte `S` (a symmetric `.fcr`)",
                b"FCR\0\x01Sxx\x00\x00".to_vec(),
            ),
            (
                "magic + type byte `H` (a hybrid `.fcr`)",
                b"FCR\0\x01Hxx\x00\x00".to_vec(),
            ),
            ("just random binary", b"this isn't ours at all".to_vec()),
        ];
        for (label, junk) in no_signature {
            fs::write(&path, junk)?;
            match read_public_key(&path) {
                Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType)) => {
                    panic!("`{label}` must not be classified as WrongKeyFileType");
                }
                Err(_) => {}
                Ok(_) => panic!("`{label}` must not parse as a valid public.key"),
            }
        }

        // Has the signature — even if otherwise malformed (truncated
        // body, unsupported version) — MUST surface WrongKeyFileType.
        // Closes the cross-version friendliness gap: a future v2
        // private.key file passed to a v1 reader is "the wrong kind
        // of key" from the user's perspective, not generic "garbage".
        let signature_cases: &[(&str, Vec<u8>)] = &[
            (
                "magic + version 1 + type K + truncated body",
                b"FCR\0\x01K\x01\x00\x00".to_vec(),
            ),
            (
                "magic + future version 2 + type K (v2 private.key)",
                b"FCR\0\x02K\x01\x00\x00".to_vec(),
            ),
        ];
        for (label, junk) in signature_cases {
            fs::write(&path, junk)?;
            match read_public_key(&path) {
                Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType)) => {}
                other => panic!("`{label}` must surface WrongKeyFileType, got {other:?}"),
            }
        }
        Ok(())
    }

    /// A missing key file must surface as `InputPath`, the same
    /// friendly "Input file or folder missing" variant that the
    /// upfront `validate_input_path` check produces — not the raw
    /// OS error text that `fs::read` returns by default. Covers all
    /// three key-reading entry points so they stay aligned.
    #[test]
    fn key_readers_map_missing_file_to_input_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let missing = tmp.path().join("no-such.key");
        let pass = SecretString::from("kp".to_string());

        assert!(matches!(
            read_public_key(&missing),
            Err(CryptoError::InputPath)
        ));
        assert!(matches!(
            open_x25519_private_key(&missing, &pass, None).map(|_| ()),
            Err(CryptoError::InputPath)
        ));
        assert!(matches!(
            crate::validate_private_key_file(&missing),
            Err(CryptoError::InputPath)
        ));
    }

    /// FORMAT.md §8 mandates that native X25519 readers compute
    /// `X25519(secret_material, basepoint)` and reject the file unless
    /// the result equals the authenticated `public_material`. AEAD-AAD
    /// authentication alone cannot catch a structurally valid
    /// `private.key` whose two halves were sealed inconsistently (a
    /// buggy or malicious writer can do this); only the native
    /// derivation check does.
    #[test]
    fn open_private_key_rejects_x25519_public_secret_mismatch() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("private.key");
        let pass = SecretString::from("pw".to_string());

        let secret = StaticSecret::random_from_rng(OsRng);
        let secret_material = secret.to_bytes();
        let other_secret = StaticSecret::random_from_rng(OsRng);
        let wrong_public = PublicKey::from(&other_secret);

        let bytes = seal_private_key(
            &secret_material,
            x25519::TYPE_NAME,
            wrong_public.as_bytes(),
            &[],
            &pass,
            &KdfParams::default(),
        )?;
        fs::write(&path, bytes)?;

        match open_x25519_private_key(&path, &pass, None).map(|_| ()) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => Ok(()),
            other => {
                panic!("expected MalformedPrivateKey for public/secret mismatch, got {other:?}")
            }
        }
    }

    /// A `private.key` whose `public_len` is a structurally valid value
    /// other than 32 (the X25519 size) decodes through the generic
    /// private-key reader, but the X25519 adapter MUST reject it: the
    /// stored public material cannot represent an X25519 point at any
    /// length other than 32. Surfaces as `MalformedPrivateKey`.
    #[test]
    fn open_private_key_rejects_x25519_public_len_mismatch() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("private.key");
        let pass = SecretString::from("pw".to_string());

        let secret = StaticSecret::random_from_rng(OsRng);
        let secret_material = secret.to_bytes();
        let malformed_public = [0u8; x25519::PUBKEY_SIZE - 1];

        let bytes = seal_private_key(
            &secret_material,
            x25519::TYPE_NAME,
            &malformed_public,
            &[],
            &pass,
            &KdfParams::default(),
        )?;
        fs::write(&path, bytes)?;

        match open_x25519_private_key(&path, &pass, None).map(|_| ()) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => Ok(()),
            other => panic!("expected MalformedPrivateKey for public_len mismatch, got {other:?}"),
        }
    }

    /// FORMAT.md §7 accepts exactly two encodings of `public.key`:
    /// the canonical `fcr1…` string with no trailer, and the same
    /// string followed by a single `\n`. Any other surrounding
    /// whitespace — CRLF, leading blanks, trailing spaces, extra
    /// blank lines — is a format violation and must surface as
    /// [`FormatDefect::MalformedPublicKey`], not be silently
    /// trimmed.
    #[test]
    fn read_public_key_accepts_only_canonical_forms() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let pass = SecretString::from("kp".to_string());
        let (_privkey_path, pubkey_path) = generate_key_pair(&pass, tmp.path(), &|_| {})?;
        let canonical = fs::read_to_string(&pubkey_path)?;
        let canonical = canonical.trim();
        let expected = read_public_key(&pubkey_path)?;

        // Two canonical encodings — both accepted.
        for decorated in [canonical.to_string(), format!("{canonical}\n")] {
            fs::write(&pubkey_path, decorated.as_bytes())?;
            let got = read_public_key(&pubkey_path)?;
            assert_eq!(got, expected, "canonical form `{decorated:?}` must parse");
        }

        // Every other surrounding-whitespace variant must be
        // rejected as MalformedPublicKey.
        for decorated in [
            format!("{canonical}\r\n"),     // Windows line ending
            format!("{canonical}\n\n"),     // double trailing LF
            format!("  {canonical}\n"),     // leading spaces
            format!("{canonical}  \n"),     // trailing spaces
            format!("\n\n{canonical}\n\n"), // leading + trailing blank lines
            format!("\t{canonical}\t\r\n"), // tabs and CRLF
            format!("{canonical}\r"),       // bare trailing CR
        ] {
            fs::write(&pubkey_path, decorated.as_bytes())?;
            match read_public_key(&pubkey_path) {
                Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
                other => panic!("expected MalformedPublicKey for `{decorated:?}`, got {other:?}"),
            }
        }
        Ok(())
    }

    /// Payload corruptions that [`read_public_key`]'s own
    /// `is_ascii_whitespace` guard does NOT catch — specifically
    /// Unicode `Format` chars (ZWSP U+200B, BOM U+FEFF) and NBSP
    /// (U+00A0, Unicode-but-not-ASCII whitespace) — MUST still be
    /// rejected by the Bech32 decoder. This test pins that
    /// invariant so a future `bech32` crate upgrade loosening
    /// charset enforcement surfaces as a test regression. Internal
    /// ASCII whitespace is included for completeness (now handled
    /// by the MalformedPublicKey arm upstream of Bech32).
    #[test]
    fn read_public_key_rejects_internal_non_bech32_chars() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let pass = SecretString::from("kp".to_string());
        let (_privkey_path, pubkey_path) = generate_key_pair(&pass, tmp.path(), &|_| {})?;
        let raw = fs::read_to_string(&pubkey_path)?;
        let canonical: &str = raw.trim();

        // Pick a split point inside the payload (after the `fcr1`
        // HRP + separator) so we inject into the data body rather
        // than into the HRP.
        assert!(canonical.starts_with("fcr1"));
        let split = canonical.len() / 2;
        let (head, tail) = canonical.split_at(split);

        // HRP-corrupted variant: space inside the `fcr` HRP.
        let hrp_ws = format!("fc r1{}", &canonical["fcr1".len()..]);

        // NBSP / ZWSP / BOM are NOT ASCII whitespace — the
        // MalformedPublicKey guard doesn't catch them, so the
        // Bech32 decoder has to reject them as non-ASCII on its own.
        let corrupted: &[(&str, String)] = &[
            ("internal space", format!("{head} {tail}")),
            ("internal LF", format!("{head}\n{tail}")),
            ("internal tab", format!("{head}\t{tail}")),
            ("internal CR", format!("{head}\r{tail}")),
            ("internal NBSP", format!("{head}\u{00A0}{tail}")),
            ("leading ZWSP", format!("\u{200B}{canonical}")),
            ("leading BOM", format!("\u{FEFF}{canonical}")),
            ("HRP whitespace", hrp_ws),
        ];

        for (label, bad) in corrupted {
            fs::write(&pubkey_path, bad.as_bytes())?;
            let res = read_public_key(&pubkey_path);
            assert!(
                res.is_err(),
                "expected rejection for `{label}`, got Ok: {bad:?}"
            );
        }
        Ok(())
    }

    // ─── Forward-compat multi-recipient tests (FORMAT.md §3.4 / §3.5) ───
    //
    // The single-recipient public encrypt API can't produce multi-recipient
    // files, so these tests build the on-disk bytes by hand using
    // `encrypted_file::build_encrypted_header` and exercise the decrypt
    // path against the resulting fixtures. They lock in the rules
    // `MIGRATION.md §1.10` calls out: list iteration on `x25519`, skip
    // unknown non-critical, reject unknown critical, reject argon2id
    // mixing before any KDF runs, enforce the local body cap on unknown
    // entries.

    /// Build a complete `.fcr` byte sequence with the given recipient
    /// entries and plaintext. The caller has already wrapped `file_key`
    /// for each entry that actually needs to unwrap; entries with
    /// arbitrary bodies (synthetic unknown types, hostile mixes) are
    /// kept verbatim.
    fn build_multi_recipient_fcr(
        entries: &[RecipientEntry],
        file_key: &Zeroizing<[u8; 32]>,
        plaintext: &[u8],
        path: &Path,
    ) -> Result<(), CryptoError> {
        let stream_nonce = random_bytes::<STREAM_NONCE_SIZE>();
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = derive_subkeys(file_key, &stream_nonce)?;

        // The bundle now owns `payload_key` and `stream_nonce`. The
        // payload-encryption block below borrows them back through
        // `built`; the original locals would be moved into the call.
        let built = build_encrypted_header(entries, b"", stream_nonce, payload_key, &header_key)?;

        // Encrypt the TAR payload into a separate buffer so the
        // `EncryptWriter`'s mutable borrow over the buffer is released
        // before we concatenate. `EncryptWriter::finish` consumes the
        // writer and returns the inner `W`; binding to `_` drops it
        // and the embedded `&mut payload_buf`.
        let mut payload_buf: Vec<u8> = Vec::new();
        {
            let writer =
                payload_encryptor(&built.payload_key, &built.stream_nonce, &mut payload_buf);
            let mut tar_builder = tar::Builder::new(writer);
            let mut header = tar::Header::new_ustar();
            header.set_path("data.txt").map_err(CryptoError::Io)?;
            header.set_size(plaintext.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            tar_builder
                .append(&header, plaintext)
                .map_err(CryptoError::Io)?;
            tar_builder.finish().map_err(CryptoError::Io)?;
            let writer = tar_builder.into_inner().map_err(CryptoError::Io)?;
            let _ = writer.finish()?;
        }

        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&built.prefix_bytes);
        buf.extend_from_slice(&built.header_bytes);
        buf.extend_from_slice(&built.header_mac);
        buf.extend_from_slice(&payload_buf);
        fs::write(path, &buf)?;
        Ok(())
    }

    /// Generates an X25519 keypair, persists a v1 `private.key` for
    /// it, and returns `(public_bytes, private_key_path, passphrase)`.
    fn keypair_fixture(
        keys_dir: &Path,
        label: &str,
        pass: &str,
    ) -> Result<([u8; 32], PathBuf, SecretString), CryptoError> {
        let pass = SecretString::from(pass.to_string());
        let dir = keys_dir.join(label);
        fs::create_dir_all(&dir)?;
        let (privkey_path, pubkey_path) = generate_key_pair(&pass, &dir, &|_| {})?;
        let pub_bytes = read_public_key(&pubkey_path)?;
        Ok((pub_bytes, privkey_path, pass))
    }

    /// 1-entry round-trip is already covered by `encrypt_decrypt_round_trip`
    /// above. This case exercises **two** supported `x25519` recipients
    /// in the same file: the decrypt loop must iterate the list and
    /// accept whichever slot the caller's private key matches. Per
    /// `FORMAT.md` §3.7, the candidate is final only after the header
    /// MAC also verifies against the unwrapped `file_key`.
    #[test]
    fn multi_x25519_decrypts_via_either_recipient() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;
        let (pub_b, priv_b, pass_b) = keypair_fixture(&keys_dir, "bob", "bob-pass")?;

        let file_key = generate_file_key();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let body_b = x25519::wrap(&file_key, &pub_b)?;
        let entries = [
            RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?,
            RecipientEntry::native(NativeRecipientType::X25519, body_b.to_vec())?,
        ];

        let payload = b"two-x25519 round trip";
        let fcr = tmp.path().join("multi.fcr");
        build_multi_recipient_fcr(&entries, &file_key, payload, &fcr)?;

        for (label, privkey, pass) in [("alice", &priv_a, &pass_a), ("bob", &priv_b, &pass_b)] {
            let dec_dir = tmp.path().join(format!("decrypted-{label}"));
            fs::create_dir_all(&dec_dir)?;
            decrypt_file(&fcr, &dec_dir, privkey, pass, None, &|_| {})?;
            let restored = fs::read(dec_dir.join("data.txt"))?;
            assert_eq!(
                restored, payload,
                "{label} should decrypt the same plaintext"
            );
        }
        Ok(())
    }

    /// FORMAT.md §3.7 SHOULD-level mitigation: the decrypt loop must
    /// visit every supported `x25519` slot before deciding, not
    /// short-circuit on the first MAC-verified one. Observable proof:
    /// place a malformed `x25519` slot AFTER a valid one. The
    /// short-circuit behavior (pre-FC-AUDIT-006) would return success
    /// from slot 1 without ever inspecting slot 2; the attempt-all
    /// behavior visits slot 2, fails the body-length check, and
    /// rejects the whole file as malformed.
    #[test]
    fn multi_x25519_attempt_all_visits_every_slot() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = generate_file_key();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let valid_slot = RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?;
        // Construct directly via public fields to bypass `native`'s
        // body-length validation; the parser accepts any body_len
        // within the local resource cap, so an attacker-forged file
        // can carry a wrong-length `x25519` slot that we must reject.
        let malformed_slot = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_string(),
            recipient_flags: 0,
            body: vec![0u8; x25519::BODY_LENGTH - 4],
        };
        let entries = [valid_slot, malformed_slot];

        let fcr = tmp.path().join("multi-attempt-all.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"x", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        let err = decrypt_file(&fcr, &dec_dir, &priv_a, &pass_a, None, &|_| {}).unwrap_err();
        match err {
            CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry) => Ok(()),
            other => panic!(
                "expected MalformedRecipientEntry from slot-2 inspection (proves attempt-all); got {other:?}"
            ),
        }
    }

    /// One supported `x25519` recipient plus one unknown non-critical
    /// recipient: the decrypt loop must skip the unknown entry and
    /// decrypt via the supported one. Entry order matters here — we
    /// place the unknown FIRST to prove the loop doesn't bail out on
    /// the first unsupported entry it sees.
    #[test]
    fn multi_x25519_plus_unknown_non_critical_skips_unknown() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = generate_file_key();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let unknown_entry = RecipientEntry {
            type_name: "example.com/unknown".to_string(),
            recipient_flags: 0,
            body: vec![0xCDu8; 64],
        };
        let entries = [
            unknown_entry,
            RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?,
        ];

        let payload = b"skip unknown non-critical";
        let fcr = tmp.path().join("skip.fcr");
        build_multi_recipient_fcr(&entries, &file_key, payload, &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        decrypt_file(&fcr, &dec_dir, &priv_a, &pass_a, None, &|_| {})?;
        let restored = fs::read(dec_dir.join("data.txt"))?;
        assert_eq!(restored, payload);
        Ok(())
    }

    /// One supported `x25519` recipient plus one unknown CRITICAL
    /// recipient: the file MUST be rejected as
    /// `UnknownCriticalRecipient` before any recipient unwrap or KDF
    /// runs. Per `FORMAT.md` §3.4, an implementation that doesn't
    /// recognise a critical entry cannot safely process the file.
    #[test]
    fn multi_unknown_critical_rejected_before_any_unwrap() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = generate_file_key();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let unknown_critical = RecipientEntry {
            type_name: "example.com/critical".to_string(),
            recipient_flags: RECIPIENT_FLAG_CRITICAL,
            body: vec![0u8; 32],
        };
        let entries = [
            RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?,
            unknown_critical,
        ];

        let fcr = tmp.path().join("critical.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"x", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        match decrypt_file(&fcr, &dec_dir, &priv_a, &pass_a, None, &|_| {}) {
            Err(CryptoError::UnknownCriticalRecipient { ref type_name })
                if type_name == "example.com/critical" =>
            {
                Ok(())
            }
            other => {
                panic!("expected UnknownCriticalRecipient(example.com/critical), got {other:?}")
            }
        }
    }

    /// Mixing `argon2id` with any other recipient (here `x25519`) MUST
    /// be rejected as `PassphraseRecipientMixed` BEFORE Argon2id runs.
    /// Per `FORMAT.md` §3.4, `argon2id` is `MixingPolicy::Exclusive`;
    /// the structural rejection prevents a hostile file from forcing
    /// expensive KDF work.
    ///
    /// The `argon2id` body here is synthetic (the right length but
    /// arbitrary bytes) to prove rejection happens without ever
    /// calling `argon2id::unwrap`. If the mixing-policy check were
    /// dropped, the test would still fail later — but with an AEAD
    /// rather than a structural error.
    #[test]
    fn multi_argon2id_plus_x25519_rejected_as_mixed() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = generate_file_key();
        let body_x = x25519::wrap(&file_key, &pub_a)?;
        let synthetic_argon2id = RecipientEntry {
            type_name: argon2id::TYPE_NAME.to_string(),
            recipient_flags: 0,
            body: vec![0u8; argon2id::BODY_LENGTH],
        };
        let entries = [
            synthetic_argon2id,
            RecipientEntry::native(NativeRecipientType::X25519, body_x.to_vec())?,
        ];

        let fcr = tmp.path().join("mixed.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"x", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        match decrypt_file(&fcr, &dec_dir, &priv_a, &pass_a, None, &|_| {}) {
            Err(CryptoError::PassphraseRecipientMixed) => Ok(()),
            other => panic!("expected PassphraseRecipientMixed, got {other:?}"),
        }
    }

    /// An unknown non-critical recipient whose body sits **at** the
    /// local cap must be accepted (and skipped); a recipient whose
    /// body sits **above** the cap must be rejected as a resource-cap
    /// violation, not silently skipped. Otherwise an attacker could
    /// pad a file with one supported entry plus one 60 MiB "unknown"
    /// entry to DoS readers that "skip" unknowns blindly.
    #[test]
    fn multi_unknown_body_at_local_cap_decrypts() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = generate_file_key();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let unknown_at_cap = RecipientEntry {
            type_name: "example.com/at-cap".to_string(),
            recipient_flags: 0,
            body: vec![0xAB; format::BODY_LEN_LOCAL_CAP_DEFAULT as usize],
        };
        let entries = [
            unknown_at_cap,
            RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?,
        ];

        let fcr = tmp.path().join("at-cap.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"at-cap payload", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        decrypt_file(&fcr, &dec_dir, &priv_a, &pass_a, None, &|_| {})?;
        Ok(())
    }

    #[test]
    fn multi_unknown_body_above_local_cap_rejected() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = generate_file_key();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let oversize = (format::BODY_LEN_LOCAL_CAP_DEFAULT as usize) + 1;
        let unknown_oversize = RecipientEntry {
            type_name: "example.com/oversize".to_string(),
            recipient_flags: 0,
            body: vec![0xAB; oversize],
        };
        let entries = [
            unknown_oversize,
            RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?,
        ];

        let fcr = tmp.path().join("oversize.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"x", &fcr)?;

        // The parser rejects on body-len cap before recipient unwrap
        // runs, so the private key never gets exercised in this case;
        // we still pass valid credentials to prove the rejection
        // happens in the structural-parse stage rather than later.
        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        match decrypt_file(&fcr, &dec_dir, &priv_a, &pass_a, None, &|_| {}) {
            Err(CryptoError::RecipientBodyCapExceeded {
                body_len,
                local_cap,
            }) => {
                assert_eq!(body_len as usize, oversize);
                assert_eq!(local_cap, format::BODY_LEN_LOCAL_CAP_DEFAULT);
                Ok(())
            }
            other => panic!("expected RecipientBodyCapExceeded, got {other:?}"),
        }
    }

    /// Slot A wraps a *decoy* `file_key` for alice; the file's MAC and
    /// payload are keyed off a *different* real `file_key`. Alice's
    /// private key unwraps slot A successfully (yielding the decoy),
    /// but the resulting `header_key` does not verify the MAC. Slot B
    /// targets bob, so alice's privkey fails to unwrap it. The decrypt
    /// loop must surface
    /// `HeaderMacFailedAfterUnwrap { type_name: "x25519" }`
    /// — distinct from `HeaderTampered` (single-recipient symmetric
    /// final error) and `RecipientUnwrapFailed` (no slot unwrapped at
    /// all). Locks the post-loop branch in
    /// [`hybrid::decrypt_file`].
    #[test]
    fn multi_x25519_decoy_unwrap_returns_mac_failed_after_unwrap() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;
        let (pub_b, _priv_b, _pass_b) = keypair_fixture(&keys_dir, "bob", "bob-pass")?;

        // Two distinct file_keys: `real_file_key` drives the MAC and
        // payload; `decoy_file_key` is what slot A wraps. Collision
        // probability is 2^-256.
        let real_file_key = generate_file_key();
        let decoy_file_key = generate_file_key();

        let body_a = x25519::wrap(&decoy_file_key, &pub_a)?;
        let body_b = x25519::wrap(&decoy_file_key, &pub_b)?;
        let entries = [
            RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?,
            RecipientEntry::native(NativeRecipientType::X25519, body_b.to_vec())?,
        ];

        let fcr = tmp.path().join("decoy-unwrap.fcr");
        build_multi_recipient_fcr(&entries, &real_file_key, b"payload", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        match decrypt_file(&fcr, &dec_dir, &priv_a, &pass_a, None, &|_| {}) {
            Err(CryptoError::HeaderMacFailedAfterUnwrap { ref type_name })
                if type_name == x25519::TYPE_NAME =>
            {
                Ok(())
            }
            other => panic!("expected HeaderMacFailedAfterUnwrap(x25519), got {other:?}"),
        }
    }
}
