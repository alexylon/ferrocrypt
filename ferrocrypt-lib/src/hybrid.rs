//! Hybrid (X25519 recipient) `.fcr` encrypt and decrypt, plus the
//! passphrase-wrapped `private.key` format.
//!
//! Pipeline:
//!
//!   - **Encrypt:** ephemeral X25519 key → ECDH with recipient pubkey
//!     → HKDF-SHA3-256 → `wrap_key`. `wrap_key` seals a random 32-byte
//!     `file_key`. `file_key` → HKDF-SHA3-256 → `payload_key` +
//!     `header_key`. `payload_key` encrypts the TAR payload via
//!     STREAM-BE32. `header_key` HMAC-SHA3-256 authenticates the
//!     on-disk header.
//!
//!   - **Decrypt:** read `private.key` (passphrase + Argon2id +
//!     HKDF-SHA3-256 + XChaCha20-Poly1305 with AAD binding every
//!     cleartext byte). Derive `wrap_key` from ECDH and unwrap
//!     `file_key`. Rest matches symmetric.
//!
//! Wire format (see `ferrocrypt-lib/FORMAT.md` §4.3, §4.4, §8):
//!
//! ```text
//! .fcr:
//!   [ replicated_prefix (27 B) ]
//!   [ envelope (104 B) = ephemeral_pubkey(32) | wrap_nonce(24) | wrapped_file_key(48) ]
//!   [ stream_nonce (19 B) ]
//!   [ ext_bytes (ext_len B) ]
//!   [ hmac_tag (32 B) ]
//!   [ payload (STREAM) ]
//!
//! private.key (125 B when ext_len = 0):
//!   header(9) | argon2_salt(32) | kdf_params(12) | wrap_nonce(24) | ext_bytes | wrapped_privkey(48)
//!   AEAD-AAD binds every cleartext byte before wrapped_privkey.
//! ```

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use bech32::{Bech32, Hrp};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit as AeadKeyInit, OsRng, Payload, stream},
};
use secrecy::SecretString;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::atomic_output;
use crate::common::{
    ARGON2_SALT_SIZE, DecryptReader, EncryptWriter, HKDF_INFO_HYB_WRAP, HKDF_INFO_PRIVATE_KEY_WRAP,
    HMAC_TAG_SIZE, KDF_PARAMS_SIZE, KdfLimit, KdfParams, STREAM_NONCE_SIZE, WRAP_NONCE_SIZE,
    WRAPPED_FILE_KEY_SIZE, build_header_hmac_input, ct_eq_32, derive_passphrase_wrap_key,
    derive_subkeys, encryption_base_name, generate_file_key, hkdf_expand_sha3_256, hmac_sha3_256,
    hmac_sha3_256_verify, open_file_key, random_bytes, read_exact_or_truncated, seal_file_key,
    validate_tlv,
};
use crate::error::FormatDefect;
use crate::format::{
    self, KEY_FILE_ALG_X25519, PRIVATE_KEY_CIPHERTEXT_SIZE, PRIVATE_KEY_FIXED_BODY_SIZE,
    PRIVATE_KEY_HEADER_SIZE,
};
use crate::{CryptoError, ProgressEvent, archiver};

/// Default filename for the hybrid public key file (text form).
pub const PUBLIC_KEY_FILENAME: &str = "public.key";
/// Default filename for the hybrid private key file (binary, wrapped).
pub const PRIVATE_KEY_FILENAME: &str = "private.key";

/// Bech32 HRP for v1 recipient strings (`fcr1…`). Parsed at compile
/// time via `parse_unchecked` so runtime encode/decode paths don't
/// repeat the validation.
const RECIPIENT_HRP: Hrp = Hrp::parse_unchecked("fcr");
/// Size of the X25519 ephemeral public key carried in the hybrid envelope.
const EPHEMERAL_PUBKEY_SIZE: usize = 32;
/// Raw X25519 private-key size (the plaintext wrapped inside `private.key`).
const PRIVATE_KEY_PLAINTEXT_SIZE: usize = 32;

/// Total hybrid envelope size, raw on disk:
/// `ephemeral_pubkey(32) || wrap_nonce(24) || wrapped_file_key(48)` = 104 bytes.
pub const HYBRID_ENVELOPE_SIZE: usize =
    EPHEMERAL_PUBKEY_SIZE + WRAP_NONCE_SIZE + WRAPPED_FILE_KEY_SIZE;

// ─── Envelope ──────────────────────────────────────────────────────────────

/// In-memory view of the 104-byte hybrid envelope. Writer, reader, and
/// HMAC input all go through this struct's byte layout so field order
/// cannot drift.
struct HybridEnvelope {
    ephemeral_pubkey: [u8; EPHEMERAL_PUBKEY_SIZE],
    wrap_nonce: [u8; WRAP_NONCE_SIZE],
    wrapped_file_key: [u8; WRAPPED_FILE_KEY_SIZE],
}

impl HybridEnvelope {
    fn to_bytes(&self) -> [u8; HYBRID_ENVELOPE_SIZE] {
        let mut out = [0u8; HYBRID_ENVELOPE_SIZE];
        let mut off = 0;
        out[off..off + EPHEMERAL_PUBKEY_SIZE].copy_from_slice(&self.ephemeral_pubkey);
        off += EPHEMERAL_PUBKEY_SIZE;
        out[off..off + WRAP_NONCE_SIZE].copy_from_slice(&self.wrap_nonce);
        off += WRAP_NONCE_SIZE;
        out[off..].copy_from_slice(&self.wrapped_file_key);
        out
    }

    fn from_bytes(bytes: &[u8; HYBRID_ENVELOPE_SIZE]) -> Self {
        let mut off = 0;
        let mut ephemeral_pubkey = [0u8; EPHEMERAL_PUBKEY_SIZE];
        ephemeral_pubkey.copy_from_slice(&bytes[off..off + EPHEMERAL_PUBKEY_SIZE]);
        off += EPHEMERAL_PUBKEY_SIZE;
        let mut wrap_nonce = [0u8; WRAP_NONCE_SIZE];
        wrap_nonce.copy_from_slice(&bytes[off..off + WRAP_NONCE_SIZE]);
        off += WRAP_NONCE_SIZE;
        let mut wrapped_file_key = [0u8; WRAPPED_FILE_KEY_SIZE];
        wrapped_file_key.copy_from_slice(&bytes[off..]);
        Self {
            ephemeral_pubkey,
            wrap_nonce,
            wrapped_file_key,
        }
    }
}

/// Derives the hybrid envelope wrap key from an X25519 ECDH shared
/// secret. Salt binds both public keys so a single ECDH session
/// produces a single wrap key bound to this specific exchange.
fn derive_hybrid_wrap_key(
    ephemeral_pubkey: &[u8; 32],
    recipient_pubkey: &[u8; 32],
    shared_secret: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral_pubkey);
    salt[32..].copy_from_slice(recipient_pubkey);
    hkdf_expand_sha3_256(Some(&salt), shared_secret, HKDF_INFO_HYB_WRAP)
}

/// Small-order public-key defence: rejects all-zero X25519 shared
/// secrets via constant-time compare.
fn shared_secret_is_all_zero(shared: &[u8; 32]) -> bool {
    ct_eq_32(shared, &[0u8; 32])
}

// ─── Encrypt ───────────────────────────────────────────────────────────────

/// Encrypts under a recipient's raw 32-byte X25519 public key. The
/// caller (typically `lib.rs`) is responsible for obtaining the bytes
/// from a `fcr1…` recipient string or a `public.key` text file.
pub fn encrypt_file_from_bytes(
    input_path: &Path,
    output_dir: &Path,
    public_key_bytes: &[u8; 32],
    output_file: Option<&Path>,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    on_event(&ProgressEvent::DerivingKey);

    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let recipient_public = PublicKey::from(*public_key_bytes);
    let shared = ephemeral_secret.diffie_hellman(&recipient_public);

    if shared_secret_is_all_zero(shared.as_bytes()) {
        return Err(CryptoError::InvalidInput(
            "Invalid recipient public key".to_string(),
        ));
    }

    let wrap_key = derive_hybrid_wrap_key(
        ephemeral_public.as_bytes(),
        recipient_public.as_bytes(),
        shared.as_bytes(),
    )?;

    let file_key = generate_file_key();
    let wrap_nonce = random_bytes::<WRAP_NONCE_SIZE>();
    let wrapped_file_key = seal_file_key(&wrap_key, &wrap_nonce, &file_key)?;
    drop(wrap_key);

    let stream_nonce = random_bytes::<STREAM_NONCE_SIZE>();
    let (payload_key, header_key) = derive_subkeys(&file_key, &stream_nonce)?;

    let envelope = HybridEnvelope {
        ephemeral_pubkey: *ephemeral_public.as_bytes(),
        wrap_nonce,
        wrapped_file_key,
    };
    let envelope_bytes = envelope.to_bytes();

    let ext_bytes: Vec<u8> = Vec::new();
    let on_disk_prefix =
        format::build_encoded_header_prefix(format::TYPE_HYBRID, ext_bytes.len() as u16)?;

    let tag = hmac_sha3_256(
        header_key.as_ref(),
        &build_header_hmac_input(&on_disk_prefix, &envelope_bytes, &stream_nonce, &ext_bytes),
    )?;

    let base_name = &encryption_base_name(input_path)?;
    on_event(&ProgressEvent::Encrypting);

    let output_path = match output_file {
        Some(p) => p.to_path_buf(),
        None => output_dir.join(format!("{}.{}", base_name, format::ENCRYPTED_EXTENSION)),
    };
    if output_path.exists() {
        return Err(CryptoError::InvalidInput(format!(
            "Output file already exists: {}",
            output_path.display()
        )));
    }

    let temp_dir = output_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".ferrocrypt-")
        .suffix(".incomplete")
        .tempfile_in(temp_dir)?;

    let encrypt_result: Result<tempfile::NamedTempFile, CryptoError> = (|| {
        tmp.as_file_mut().write_all(&on_disk_prefix)?;
        tmp.as_file_mut().write_all(&envelope_bytes)?;
        tmp.as_file_mut().write_all(&stream_nonce)?;
        tmp.as_file_mut().write_all(&ext_bytes)?;
        tmp.as_file_mut().write_all(&tag)?;

        let cipher = XChaCha20Poly1305::new(payload_key.as_ref().into());
        let stream_encryptor =
            stream::EncryptorBE32::from_aead(cipher, stream_nonce.as_ref().into());

        let encrypt_writer = EncryptWriter::new(stream_encryptor, tmp);
        let (_, encrypt_writer) = archiver::archive(input_path, encrypt_writer)?;
        let tmp = encrypt_writer.finish()?;
        tmp.as_file().sync_all()?;
        Ok(tmp)
    })();

    let tmp = encrypt_result?;
    atomic_output::finalize_file(tmp, &output_path)?;
    Ok(output_path)
}

// ─── Decrypt ───────────────────────────────────────────────────────────────

/// Decrypts a hybrid `.fcr` file using the recipient's `private.key`
/// (which is passphrase-wrapped on disk). Follows the eight-step order
/// from `ferrocrypt-lib/FORMAT.md` §4.8, adapted to the hybrid path
/// (steps 3–5 are ECDH + envelope unwrap instead of Argon2id).
pub fn decrypt_file(
    input_path: &Path,
    output_dir: &Path,
    private_key_path: &Path,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    let mut encrypted_file = fs::File::open(input_path)?;

    // 1. Prefix + canonicity + magic/type/version/ext_len checks.
    let (on_disk_prefix, header) =
        format::read_header_from_reader(&mut encrypted_file, format::TYPE_HYBRID)?;

    // 2. Fixed header fields after the prefix.
    let mut envelope_bytes = [0u8; HYBRID_ENVELOPE_SIZE];
    read_exact_or_truncated(&mut encrypted_file, &mut envelope_bytes)?;
    let mut stream_nonce = [0u8; STREAM_NONCE_SIZE];
    read_exact_or_truncated(&mut encrypted_file, &mut stream_nonce)?;
    let mut ext_bytes = vec![0u8; header.ext_len as usize];
    read_exact_or_truncated(&mut encrypted_file, &mut ext_bytes)?;
    let mut tag = [0u8; HMAC_TAG_SIZE];
    read_exact_or_truncated(&mut encrypted_file, &mut tag)?;

    let envelope = HybridEnvelope::from_bytes(&envelope_bytes);

    // 3. Unlock recipient's private key (runs Argon2id on the passphrase).
    on_event(&ProgressEvent::DerivingKey);
    let recipient_secret = read_private_key(private_key_path, passphrase, kdf_limit)?;

    // 4. X25519 ECDH with the ephemeral pubkey from the envelope.
    let ephemeral_public = PublicKey::from(envelope.ephemeral_pubkey);
    let recipient_public = PublicKey::from(&recipient_secret);
    let shared = recipient_secret.diffie_hellman(&ephemeral_public);
    drop(recipient_secret);

    if shared_secret_is_all_zero(shared.as_bytes()) {
        return Err(CryptoError::HybridEnvelopeUnlockFailed);
    }

    let wrap_key = derive_hybrid_wrap_key(
        &envelope.ephemeral_pubkey,
        recipient_public.as_bytes(),
        shared.as_bytes(),
    )?;

    // 5. Unwrap file_key. Wrong recipient key and tampered envelope
    //    are indistinguishable at the AEAD layer, by design.
    let file_key = open_file_key(
        &wrap_key,
        &envelope.wrap_nonce,
        &envelope.wrapped_file_key,
        || CryptoError::HybridEnvelopeUnlockFailed,
    )?;
    drop(wrap_key);

    // 6. Post-unwrap subkeys.
    let (payload_key, header_key) = derive_subkeys(&file_key, &stream_nonce)?;

    // 7. HMAC verify — right key, tampered rest-of-header → HeaderTampered.
    hmac_sha3_256_verify(
        header_key.as_ref(),
        &build_header_hmac_input(&on_disk_prefix, &envelope_bytes, &stream_nonce, &ext_bytes),
        &tag,
    )?;

    // 8. TLV canonicity, after authentication.
    validate_tlv(&ext_bytes)?;

    // 9. STREAM payload. (The hybrid path numbers 1..=9 because
    // steps 3..=5 — private-key unlock, X25519 ECDH, envelope unwrap —
    // expand what the symmetric FORMAT.md §4.8 path collapses into a
    // single "unwrap file_key" step.)
    on_event(&ProgressEvent::Decrypting);
    let cipher = XChaCha20Poly1305::new(payload_key.as_ref().into());
    let stream_decryptor = stream::DecryptorBE32::from_aead(cipher, stream_nonce.as_ref().into());
    let decrypt_reader = DecryptReader::new(stream_decryptor, encrypted_file);
    archiver::unarchive(decrypt_reader, output_dir)
}

// ─── private.key read ──────────────────────────────────────────────────────

/// In-memory view of the `private.key` body (everything after the 9-byte
/// cleartext header). Field order is fixed by the wire format.
struct PrivateKeyBody {
    argon2_salt: [u8; ARGON2_SALT_SIZE],
    kdf_bytes: [u8; KDF_PARAMS_SIZE],
    wrap_nonce: [u8; WRAP_NONCE_SIZE],
    ext_bytes: Vec<u8>,
    wrapped_privkey: [u8; PRIVATE_KEY_CIPHERTEXT_SIZE],
}

impl PrivateKeyBody {
    /// Parses the body (everything after the 9-byte cleartext header)
    /// given the header's declared `ext_len`.
    fn from_bytes(body: &[u8], ext_len: usize) -> Result<Self, CryptoError> {
        let expected = PRIVATE_KEY_FIXED_BODY_SIZE + ext_len + PRIVATE_KEY_CIPHERTEXT_SIZE;
        if body.len() != expected {
            return Err(CryptoError::InvalidFormat(FormatDefect::BadKeyFileSize));
        }
        let mut off = 0;
        let mut argon2_salt = [0u8; ARGON2_SALT_SIZE];
        argon2_salt.copy_from_slice(&body[off..off + ARGON2_SALT_SIZE]);
        off += ARGON2_SALT_SIZE;
        let mut kdf_bytes = [0u8; KDF_PARAMS_SIZE];
        kdf_bytes.copy_from_slice(&body[off..off + KDF_PARAMS_SIZE]);
        off += KDF_PARAMS_SIZE;
        let mut wrap_nonce = [0u8; WRAP_NONCE_SIZE];
        wrap_nonce.copy_from_slice(&body[off..off + WRAP_NONCE_SIZE]);
        off += WRAP_NONCE_SIZE;
        let ext_bytes = body[off..off + ext_len].to_vec();
        off += ext_len;
        let mut wrapped_privkey = [0u8; PRIVATE_KEY_CIPHERTEXT_SIZE];
        wrapped_privkey.copy_from_slice(&body[off..off + PRIVATE_KEY_CIPHERTEXT_SIZE]);
        Ok(Self {
            argon2_salt,
            kdf_bytes,
            wrap_nonce,
            ext_bytes,
            wrapped_privkey,
        })
    }
}

/// AEAD-AAD for `private.key` wrap/unwrap: every cleartext byte before
/// `wrapped_privkey` (header + argon2_salt + kdf_params + wrap_nonce +
/// ext_bytes). Shared by writer and reader so the AAD sequence cannot
/// drift.
fn private_key_aad(
    header: &[u8; PRIVATE_KEY_HEADER_SIZE],
    argon2_salt: &[u8; ARGON2_SALT_SIZE],
    kdf_bytes: &[u8; KDF_PARAMS_SIZE],
    wrap_nonce: &[u8; WRAP_NONCE_SIZE],
    ext_bytes: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        PRIVATE_KEY_HEADER_SIZE
            + ARGON2_SALT_SIZE
            + KDF_PARAMS_SIZE
            + WRAP_NONCE_SIZE
            + ext_bytes.len(),
    );
    aad.extend_from_slice(header);
    aad.extend_from_slice(argon2_salt);
    aad.extend_from_slice(kdf_bytes);
    aad.extend_from_slice(wrap_nonce);
    aad.extend_from_slice(ext_bytes);
    aad
}

/// Reads and unlocks a `private.key` file. Returns the raw X25519
/// private key as a [`StaticSecret`]. KDF parameter bounds are checked
/// BEFORE Argon2id fires, so a hostile file cannot force unbounded work
/// ahead of authentication.
fn read_private_key(
    path: &Path,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
) -> Result<StaticSecret, CryptoError> {
    let data = fs::read(path)?;
    if data.len() < PRIVATE_KEY_HEADER_SIZE {
        return Err(CryptoError::InvalidFormat(FormatDefect::Truncated));
    }

    let header = format::parse_private_key_header(&data)?;

    let body_start = PRIVATE_KEY_HEADER_SIZE;
    let body = &data[body_start..];
    let parsed = PrivateKeyBody::from_bytes(body, header.ext_len as usize)?;

    // KDF param bounds BEFORE Argon2id runs.
    let kdf_params = KdfParams::from_bytes(&parsed.kdf_bytes, kdf_limit)?;

    let header_bytes: [u8; PRIVATE_KEY_HEADER_SIZE] = data[..PRIVATE_KEY_HEADER_SIZE]
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::Truncated))?;
    let aad = private_key_aad(
        &header_bytes,
        &parsed.argon2_salt,
        &parsed.kdf_bytes,
        &parsed.wrap_nonce,
        &parsed.ext_bytes,
    );

    let wrap_key = derive_passphrase_wrap_key(
        passphrase,
        &parsed.argon2_salt,
        &kdf_params,
        HKDF_INFO_PRIVATE_KEY_WRAP,
    )?;

    let cipher = XChaCha20Poly1305::new(wrap_key.as_ref().into());
    let nonce = XNonce::from_slice(&parsed.wrap_nonce);
    let mut plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: parsed.wrapped_privkey.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| CryptoError::KeyFileUnlockFailed)?;
    drop(wrap_key);

    // Validate TLV only after AEAD-AAD authentication succeeded.
    validate_tlv(&parsed.ext_bytes)?;

    if plaintext.len() != PRIVATE_KEY_PLAINTEXT_SIZE {
        plaintext.zeroize();
        return Err(CryptoError::InvalidFormat(
            FormatDefect::UnexpectedKeyLength,
        ));
    }

    let mut private_bytes = Zeroizing::new([0u8; PRIVATE_KEY_PLAINTEXT_SIZE]);
    private_bytes.copy_from_slice(&plaintext);
    plaintext.zeroize();

    Ok(StaticSecret::from(*private_bytes))
}

// ─── generate_key_pair ─────────────────────────────────────────────────────

/// Generates an X25519 key pair and writes both files to `output_dir`.
/// Returns `(private_key_path, public_key_path)`.
///
/// - `private.key` is binary, passphrase-wrapped, with every cleartext
///   byte AAD-bound.
/// - `public.key` is a UTF-8 text file containing the canonical
///   `fcr1…` Bech32 recipient string.
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

    let private_key = StaticSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);

    // Derive wrap_key from passphrase + Argon2id + HKDF-SHA3-256.
    let argon2_salt = random_bytes::<ARGON2_SALT_SIZE>();
    let kdf_params = KdfParams::default();
    let kdf_bytes = kdf_params.to_bytes();
    let wrap_key = derive_passphrase_wrap_key(
        passphrase,
        &argon2_salt,
        &kdf_params,
        HKDF_INFO_PRIVATE_KEY_WRAP,
    )?;

    let wrap_nonce = random_bytes::<WRAP_NONCE_SIZE>();
    let ext_bytes: Vec<u8> = Vec::new();

    let private_header = format::build_private_key_header(ext_bytes.len() as u16);
    let aad = private_key_aad(
        &private_header,
        &argon2_salt,
        &kdf_bytes,
        &wrap_nonce,
        &ext_bytes,
    );

    let raw_private_key = Zeroizing::new(private_key.to_bytes());
    drop(private_key);

    let cipher = XChaCha20Poly1305::new(wrap_key.as_ref().into());
    let nonce = XNonce::from_slice(&wrap_nonce);
    let wrapped_vec = cipher
        .encrypt(
            nonce,
            Payload {
                msg: raw_private_key.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| {
            CryptoError::InternalCryptoFailure("internal error: private key encryption failed")
        })?;
    drop(raw_private_key);
    drop(wrap_key);

    let wrapped_privkey: [u8; PRIVATE_KEY_CIPHERTEXT_SIZE] =
        wrapped_vec.as_slice().try_into().map_err(|_| {
            CryptoError::InternalInvariant("internal error: wrapped private key size mismatch")
        })?;

    // Write public.key (text file, `fcr1…\n`). Public key isn't secret
    // so permissions relax to 0o644 on Unix.
    let recipient_string = encode_recipient_string(public_key.as_bytes())?;
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
        private_tmp.as_file_mut().write_all(&private_header)?;
        private_tmp.as_file_mut().write_all(&argon2_salt)?;
        private_tmp.as_file_mut().write_all(&kdf_bytes)?;
        private_tmp.as_file_mut().write_all(&wrap_nonce)?;
        private_tmp.as_file_mut().write_all(&ext_bytes)?;
        private_tmp.as_file_mut().write_all(&wrapped_privkey)?;
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

// ─── Bech32 recipient string ───────────────────────────────────────────────

/// Canonical `algorithm(1) || public_key_material(32)` byte form used
/// both by [`encode_recipient_string`] (as the Bech32 data payload)
/// and by [`crate::PublicKey::fingerprint`] (as the SHA3-256 input).
/// Single source of truth so the fingerprint and the `fcr1…` encoding
/// cannot silently diverge.
pub fn recipient_canonical_bytes(pubkey_bytes: &[u8; 32]) -> [u8; 1 + 32] {
    let mut out = [0u8; 1 + 32];
    out[0] = KEY_FILE_ALG_X25519;
    out[1..].copy_from_slice(pubkey_bytes);
    out
}

/// Encodes a 32-byte X25519 public key as the canonical `fcr1…` Bech32
/// recipient string. `DATA = algorithm(1) || public_key_material(32)`
/// per `ferrocrypt-lib/FORMAT.md` §7.1.
pub fn encode_recipient_string(pubkey_bytes: &[u8; 32]) -> Result<String, CryptoError> {
    let data = recipient_canonical_bytes(pubkey_bytes);
    bech32::encode::<Bech32>(RECIPIENT_HRP, &data)
        .map_err(|_| CryptoError::InternalInvariant("internal error: Bech32 encode failed"))
}

/// Decodes a canonical lowercase `fcr1…` Bech32 recipient string into
/// the raw 32-byte X25519 public key. Rejects non-canonical encodings
/// (including uppercase or mixed case), unknown algorithm bytes, bad
/// material length, and malformed Bech32 per `ferrocrypt-lib/FORMAT.md`
/// §7.1.
pub fn decode_recipient_string(s: &str) -> Result<[u8; 32], CryptoError> {
    // Canonical v1 recipient strings are lowercase only.
    if s.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(CryptoError::InvalidInput(
            "Recipient string must be lowercase".to_string(),
        ));
    }

    let (hrp, data) = bech32::decode(s)
        .map_err(|_| CryptoError::InvalidInput(format!("Invalid recipient string: {s}")))?;

    if hrp != RECIPIENT_HRP {
        return Err(CryptoError::InvalidInput(format!(
            "Unexpected recipient prefix (want '{}', got '{}')",
            RECIPIENT_HRP.as_str(),
            hrp.as_str()
        )));
    }

    if data.len() != 33 {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::UnexpectedKeyLength,
        ));
    }

    let algorithm = data[0];
    if algorithm != KEY_FILE_ALG_X25519 {
        return Err(CryptoError::InvalidFormat(FormatDefect::UnknownAlgorithm {
            algorithm,
        }));
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&data[1..]);
    Ok(pubkey)
}

/// Reads a v1 `public.key` text file and returns the raw 32-byte
/// X25519 public key. Strict parser: one Bech32 line, optional single
/// trailing LF, no extra whitespace, canonical lowercase only.
pub fn read_public_key(path: &Path) -> Result<[u8; 32], CryptoError> {
    let contents = fs::read_to_string(path)?;
    // Accept exactly one trailing `\n`, nothing else.
    let trimmed = contents.strip_suffix('\n').unwrap_or(&contents);
    if trimmed.contains('\n') || trimmed != trimmed.trim() {
        return Err(CryptoError::InvalidInput(
            "public.key: extra whitespace or lines".to_string(),
        ));
    }
    decode_recipient_string(trimmed)
}

// ─── Structural validator (kept for fuzz exports) ──────────────────────────

/// Validates the structural shape of a `private.key` file. Does not
/// attempt to decrypt or derive any keys. Re-exported via
/// `fuzz_exports` so the fuzz harness can exercise the parser in
/// isolation.
pub fn validate_private_key_shape(
    data: &[u8],
    header: &format::PrivateKeyHeader,
) -> Result<(), CryptoError> {
    if header.algorithm != KEY_FILE_ALG_X25519 {
        return Err(CryptoError::InvalidFormat(FormatDefect::UnknownAlgorithm {
            algorithm: header.algorithm,
        }));
    }
    let expected_total = PRIVATE_KEY_HEADER_SIZE
        + PRIVATE_KEY_FIXED_BODY_SIZE
        + header.ext_len as usize
        + PRIVATE_KEY_CIPHERTEXT_SIZE;
    if data.len() != expected_total {
        return Err(CryptoError::InvalidFormat(FormatDefect::BadKeyFileSize));
    }
    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
    /// surface `HybridEnvelopeUnlockFailed`, not `HeaderTampered`.
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
            Err(CryptoError::HybridEnvelopeUnlockFailed) => Ok(()),
            other => panic!("expected HybridEnvelopeUnlockFailed, got {other:?}"),
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

    /// Tampering the stream_nonce must be caught by the header HMAC
    /// AFTER successful envelope unwrap — surfaces as `HeaderTampered`.
    #[test]
    fn decrypt_with_tampered_stream_nonce_fails_at_hmac() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, privkey, pass) = hybrid_fixture("x", "kp")?;
        let mut bytes = fs::read(&fcr)?;
        // stream_nonce starts at format::HEADER_PREFIX_ENCODED_SIZE + HYBRID_ENVELOPE_SIZE.
        let nonce_offset = format::HEADER_PREFIX_ENCODED_SIZE + HYBRID_ENVELOPE_SIZE;
        bytes[nonce_offset] ^= 0xFF;
        fs::write(&fcr, &bytes)?;
        match decrypt_file(&fcr, &dec_dir, &privkey, &pass, None, &|_| {}) {
            Err(CryptoError::HeaderTampered) => Ok(()),
            other => panic!("expected HeaderTampered, got {other:?}"),
        }
    }

    /// Tampering `wrapped_file_key` inside the envelope surfaces as
    /// `HybridEnvelopeUnlockFailed` at AEAD-open time.
    #[test]
    fn decrypt_with_tampered_envelope_fails_at_unwrap() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, privkey, pass) = hybrid_fixture("x", "kp")?;
        let mut bytes = fs::read(&fcr)?;
        // wrapped_file_key lives at offset: prefix(27) + ephemeral(32) + wrap_nonce(24) = 83.
        let wrapped_offset =
            format::HEADER_PREFIX_ENCODED_SIZE + EPHEMERAL_PUBKEY_SIZE + WRAP_NONCE_SIZE;
        bytes[wrapped_offset] ^= 0x01;
        fs::write(&fcr, &bytes)?;
        match decrypt_file(&fcr, &dec_dir, &privkey, &pass, None, &|_| {}) {
            Err(CryptoError::HybridEnvelopeUnlockFailed) => Ok(()),
            other => panic!("expected HybridEnvelopeUnlockFailed, got {other:?}"),
        }
    }

    /// Recipient string encode + decode must round-trip bit-for-bit.
    #[test]
    fn recipient_string_round_trip() -> Result<(), CryptoError> {
        let mut pk = [0u8; 32];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = i as u8;
        }
        let s = encode_recipient_string(&pk)?;
        assert!(s.starts_with("fcr1"));
        let back = decode_recipient_string(&s)?;
        assert_eq!(pk, back);
        Ok(())
    }

    /// Non-canonical recipient strings MUST be rejected: uppercase-only
    /// and mixed-case both fail even though Bech32 itself can decode
    /// either case in isolation.
    #[test]
    fn recipient_string_rejects_non_canonical_case() {
        let canonical = encode_recipient_string(&[0x42; 32]).unwrap();

        let upper = canonical.to_uppercase();
        match decode_recipient_string(&upper) {
            Err(CryptoError::InvalidInput(_)) => {}
            other => panic!("expected InvalidInput for uppercase-only, got {other:?}"),
        }

        let mut mixed = canonical.clone();
        mixed.replace_range(4..5, &mixed[4..5].to_uppercase());
        match decode_recipient_string(&mixed) {
            Err(CryptoError::InvalidInput(_)) => {}
            other => panic!("expected InvalidInput for mixed case, got {other:?}"),
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
}
