use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit, OsRng, rand_core::RngCore, stream},
};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::atomic_output;
use crate::common::{
    ARGON2_SALT_SIZE, DecryptReader, ENCRYPTION_KEY_SIZE, EncryptWriter, HMAC_KEY_SIZE,
    HMAC_TAG_SIZE, KDF_PARAMS_SIZE, KdfLimit, KdfParams, STREAM_NONCE_SIZE, TAG_SIZE, ct_eq_32,
    encryption_base_name, hmac_sha3_256, hmac_sha3_256_verify,
};
use crate::error::FormatDefect;
use crate::format::{self, HEADER_PREFIX_SIZE, PRIVATE_KEY_FIXED_BODY_SIZE, PUBLIC_KEY_DATA_SIZE};
use crate::replication::encode;
use crate::{CryptoError, ProgressEvent, archiver};

// Both keys are packed into a single envelope: [encryption_key | hmac_key]
const COMBINED_KEY_SIZE: usize = ENCRYPTION_KEY_SIZE + HMAC_KEY_SIZE;

const EPHEMERAL_PUB_SIZE: usize = 32;
const ENVELOPE_NONCE_SIZE: usize = 24;
const ENVELOPE_CIPHERTEXT_SIZE: usize = COMBINED_KEY_SIZE + TAG_SIZE;
const ENVELOPE_SIZE: usize = EPHEMERAL_PUB_SIZE + ENVELOPE_NONCE_SIZE + ENVELOPE_CIPHERTEXT_SIZE;

/// Authenticated core of a hybrid `.fcr` header.
///
/// Sits between the 8-byte prefix (which carries `ext_len`) and the trailing
/// HMAC tag. Field order is the single source of truth for the hybrid wire
/// format — every code path (encrypt, decrypt, HMAC computation) goes through
/// this struct so writer and reader cannot drift.
struct HybridHeaderCore {
    envelope: [u8; ENVELOPE_SIZE],
    stream_nonce: [u8; STREAM_NONCE_SIZE],
    ext_bytes: Vec<u8>,
}

impl HybridHeaderCore {
    /// Constructs a core after validating the `ext_bytes` length bound.
    ///
    /// `ext_bytes.len()` must fit in a `u16` because the header prefix stores
    /// `ext_len` as a big-endian `u16`. This is the single enforcement point:
    /// once a `HybridHeaderCore` exists, `ext_len()` is infallible by
    /// construction.
    fn new(
        envelope: [u8; ENVELOPE_SIZE],
        stream_nonce: [u8; STREAM_NONCE_SIZE],
        ext_bytes: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        if ext_bytes.len() > u16::MAX as usize {
            return Err(CryptoError::InvalidInput(
                "ext_bytes exceeds u16::MAX".to_string(),
            ));
        }
        Ok(Self {
            envelope,
            stream_nonce,
            ext_bytes,
        })
    }

    /// Writes every field, in canonical order, using triple replication.
    fn write_to(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(&encode(&self.envelope))?;
        writer.write_all(&encode(&self.stream_nonce))?;
        writer.write_all(&encode(&self.ext_bytes))?;
        Ok(())
    }

    /// Reads every field, in canonical order, from a triple-replicated stream.
    /// `ext_len` is the logical size of the `ext_bytes` region, taken from the
    /// authenticated header prefix.
    fn read_from(reader: &mut impl io::Read, ext_len: usize) -> Result<Self, CryptoError> {
        Self::new(
            format::read_replicated_field::<ENVELOPE_SIZE>(reader)?,
            format::read_replicated_field::<STREAM_NONCE_SIZE>(reader)?,
            format::read_replicated_vec(reader, ext_len)?,
        )
    }

    /// Canonical HMAC-SHA3-256 input: `prefix || envelope || stream_nonce || ext_bytes`.
    fn hmac_input(&self, prefix: &[u8; HEADER_PREFIX_SIZE]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(
            prefix.len() + ENVELOPE_SIZE + STREAM_NONCE_SIZE + self.ext_bytes.len(),
        );
        msg.extend_from_slice(prefix);
        msg.extend_from_slice(&self.envelope);
        msg.extend_from_slice(&self.stream_nonce);
        msg.extend_from_slice(&self.ext_bytes);
        msg
    }

    /// Returns the `ext_len` value to pack into the header prefix.
    /// Infallible by construction: `Self::new` rejects oversized `ext_bytes`.
    fn ext_len(&self) -> u16 {
        self.ext_bytes.len() as u16
    }
}

const PRIVATE_KEY_NONCE_SIZE: usize = 24;
const PRIVATE_KEY_SIZE: usize = 32;
const PRIVATE_KEY_BLOB_SIZE: usize = PRIVATE_KEY_SIZE + TAG_SIZE;
const PRIVATE_KEY_EXT_LEN_SIZE: usize = 2;

// Compile-time guard: the v4 body's fixed-minimum footprint (everything
// except the optional `ext_bytes`) must match the format-level
// `PRIVATE_KEY_FIXED_BODY_SIZE` constant. If a future change touches
// one without the other the build breaks here.
const _: () = assert!(
    KDF_PARAMS_SIZE
        + ARGON2_SALT_SIZE
        + PRIVATE_KEY_NONCE_SIZE
        + PRIVATE_KEY_EXT_LEN_SIZE
        + PRIVATE_KEY_BLOB_SIZE
        == PRIVATE_KEY_FIXED_BODY_SIZE
);

// Byte offset of the `ext_len` u16 within a v4 private-key body.
const PRIVATE_KEY_EXT_LEN_OFFSET: usize =
    KDF_PARAMS_SIZE + ARGON2_SALT_SIZE + PRIVATE_KEY_NONCE_SIZE;

/// X25519 hybrid envelope wire format: ephemeral public key, AEAD nonce, AEAD
/// ciphertext (the encrypted combined key). Centralizes field offsets so
/// `seal_envelope` and `open_envelope` work in field accesses, not index math.
struct Envelope {
    ephemeral_public: [u8; EPHEMERAL_PUB_SIZE],
    nonce: [u8; ENVELOPE_NONCE_SIZE],
    ciphertext: [u8; ENVELOPE_CIPHERTEXT_SIZE],
}

impl Envelope {
    fn to_bytes(&self) -> [u8; ENVELOPE_SIZE] {
        let mut out = [0u8; ENVELOPE_SIZE];
        let (pk_slot, rest) = out.split_at_mut(EPHEMERAL_PUB_SIZE);
        let (nonce_slot, ct_slot) = rest.split_at_mut(ENVELOPE_NONCE_SIZE);
        pk_slot.copy_from_slice(&self.ephemeral_public);
        nonce_slot.copy_from_slice(&self.nonce);
        ct_slot.copy_from_slice(&self.ciphertext);
        out
    }

    fn from_bytes(bytes: &[u8; ENVELOPE_SIZE]) -> Self {
        let (pk, rest) = bytes.split_at(EPHEMERAL_PUB_SIZE);
        let (nonce, ciphertext) = rest.split_at(ENVELOPE_NONCE_SIZE);
        let mut out = Self {
            ephemeral_public: [0u8; EPHEMERAL_PUB_SIZE],
            nonce: [0u8; ENVELOPE_NONCE_SIZE],
            ciphertext: [0u8; ENVELOPE_CIPHERTEXT_SIZE],
        };
        out.ephemeral_public.copy_from_slice(pk);
        out.nonce.copy_from_slice(nonce);
        out.ciphertext.copy_from_slice(ciphertext);
        out
    }
}

/// Body of a v4 `private.key` file: KDF params, Argon2 salt, AEAD nonce,
/// a forward-compatible authenticated `ext_bytes` region, and the
/// AEAD-encrypted X25519 private key. The AEAD decrypt step binds the
/// cleartext header + every field above as associated data, so every
/// byte on disk is cryptographically authenticated.
///
/// AEAD limitation: the primitive returns a single undifferentiated
/// failure for both "wrong passphrase" and "tampered cleartext". Both
/// surface as [`CryptoError::KeyFileUnlockFailed`]; its Display
/// wording reflects both causes.
///
/// `ext_bytes` is opaque to the current release: v4 writers emit an
/// empty region (`ext_len = 0`), and v4 readers authenticate the
/// bytes via the AEAD tag and then ignore the contents. Future 0.3.x
/// minors can populate it with TLV-encoded metadata; readers that
/// don't recognize a tag skip it.
struct PrivateKeyBody {
    kdf_bytes: [u8; KDF_PARAMS_SIZE],
    salt: [u8; ARGON2_SALT_SIZE],
    nonce: [u8; PRIVATE_KEY_NONCE_SIZE],
    ext_bytes: Vec<u8>,
    ciphertext: [u8; PRIVATE_KEY_BLOB_SIZE],
}

impl PrivateKeyBody {
    /// Returns the total body size in bytes (fixed minimum + extension region).
    fn total_len(&self) -> usize {
        PRIVATE_KEY_FIXED_BODY_SIZE + self.ext_bytes.len()
    }

    /// `ext_len` field packed into the body. Infallible by construction:
    /// callers never build a body with more than `u16::MAX` extension bytes.
    fn ext_len_be_bytes(&self) -> [u8; PRIVATE_KEY_EXT_LEN_SIZE] {
        (self.ext_bytes.len() as u16).to_be_bytes()
    }

    /// Builds the AEAD associated-data buffer. Bound fields in order:
    /// the 8-byte cleartext key-file header, the KDF params, the Argon2
    /// salt, the AEAD nonce, the big-endian `ext_len`, and the
    /// `ext_bytes` payload. Tamper on any of these causes AEAD
    /// authentication to fail on decrypt.
    fn aad(&self, header: &[u8; format::KEY_FILE_HEADER_SIZE]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            format::KEY_FILE_HEADER_SIZE
                + KDF_PARAMS_SIZE
                + ARGON2_SALT_SIZE
                + PRIVATE_KEY_NONCE_SIZE
                + PRIVATE_KEY_EXT_LEN_SIZE
                + self.ext_bytes.len(),
        );
        aad.extend_from_slice(header);
        aad.extend_from_slice(&self.kdf_bytes);
        aad.extend_from_slice(&self.salt);
        aad.extend_from_slice(&self.nonce);
        aad.extend_from_slice(&self.ext_len_be_bytes());
        aad.extend_from_slice(&self.ext_bytes);
        aad
    }

    /// Serializes the body for on-disk writing: kdf params, salt,
    /// nonce, big-endian `ext_len`, `ext_bytes`, ciphertext+tag.
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.total_len());
        out.extend_from_slice(&self.kdf_bytes);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ext_len_be_bytes());
        out.extend_from_slice(&self.ext_bytes);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parses an on-disk v4 body. Caller must have already run
    /// [`validate_private_key_body_shape`] on the full file bytes,
    /// which enforces `data_len ≥ fixed_minimum` and the internal
    /// consistency between `data_len` and the parsed `ext_len`. `body`
    /// here is the slice after the 8-byte header and has length
    /// `header.data_len`.
    fn from_bytes(body: &[u8]) -> Result<Self, CryptoError> {
        if body.len() < PRIVATE_KEY_FIXED_BODY_SIZE {
            return Err(CryptoError::InvalidFormat(FormatDefect::BadKeyFileSize));
        }
        let mut kdf_bytes = [0u8; KDF_PARAMS_SIZE];
        let mut salt = [0u8; ARGON2_SALT_SIZE];
        let mut nonce = [0u8; PRIVATE_KEY_NONCE_SIZE];
        let mut ciphertext = [0u8; PRIVATE_KEY_BLOB_SIZE];

        let mut offset = 0;
        kdf_bytes.copy_from_slice(&body[offset..offset + KDF_PARAMS_SIZE]);
        offset += KDF_PARAMS_SIZE;
        salt.copy_from_slice(&body[offset..offset + ARGON2_SALT_SIZE]);
        offset += ARGON2_SALT_SIZE;
        nonce.copy_from_slice(&body[offset..offset + PRIVATE_KEY_NONCE_SIZE]);
        offset += PRIVATE_KEY_NONCE_SIZE;

        let ext_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += PRIVATE_KEY_EXT_LEN_SIZE;

        if body.len() != PRIVATE_KEY_FIXED_BODY_SIZE + ext_len {
            return Err(CryptoError::InvalidFormat(FormatDefect::BadKeyFileSize));
        }

        let ext_bytes = body[offset..offset + ext_len].to_vec();
        offset += ext_len;
        ciphertext.copy_from_slice(&body[offset..offset + PRIVATE_KEY_BLOB_SIZE]);

        Ok(Self {
            kdf_bytes,
            salt,
            nonce,
            ext_bytes,
            ciphertext,
        })
    }
}

/// Structural validator for a v4 `private.key` file: checks the key
/// type byte, algorithm byte, unknown-flags rejection, body-size lower
/// bound, and the internal consistency between `data_len` and the
/// parsed `ext_len`. Does **not** attempt to decrypt or derive any
/// keys. Re-exported to the fuzz target via `fuzz_exports`.
pub fn validate_private_key_body_shape(
    data: &[u8],
    header: &format::KeyFileHeader,
) -> Result<(), CryptoError> {
    if header.algorithm != format::KEY_FILE_ALG_X25519 {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::UnsupportedKeyFileAlgorithm(header.algorithm),
        ));
    }
    if header.flags != 0 {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::UnknownKeyFileFlags(header.flags),
        ));
    }
    let data_len = header.data_len as usize;
    if data_len < PRIVATE_KEY_FIXED_BODY_SIZE {
        return Err(CryptoError::InvalidFormat(FormatDefect::BadKeyFileSize));
    }
    if data.len() != format::KEY_FILE_HEADER_SIZE + data_len {
        return Err(CryptoError::InvalidFormat(FormatDefect::BadKeyFileSize));
    }
    let ext_len_offset = format::KEY_FILE_HEADER_SIZE + PRIVATE_KEY_EXT_LEN_OFFSET;
    let ext_len = u16::from_be_bytes([data[ext_len_offset], data[ext_len_offset + 1]]) as usize;
    if data_len != PRIVATE_KEY_FIXED_BODY_SIZE + ext_len {
        return Err(CryptoError::InvalidFormat(FormatDefect::BadKeyFileSize));
    }
    Ok(())
}

/// Default filename for the hybrid public key file.
pub const PUBLIC_KEY_FILENAME: &str = "public.key";
/// Default filename for the hybrid private key file.
pub const PRIVATE_KEY_FILENAME: &str = "private.key";

const HYBRID_ENVELOPE_INFO: &[u8] = b"ferrocrypt hybrid envelope key v4";

/// Derives a 32-byte wrapping key for the hybrid envelope AEAD.
///
/// HKDF-SHA256 with:
/// - IKM: X25519 shared secret
/// - salt: ephemeral_public || recipient_public
/// - info: version-specific domain label
fn derive_envelope_key(
    ephemeral_public: &PublicKey,
    recipient_public: &PublicKey,
    shared_secret: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral_public.as_bytes());
    salt[32..].copy_from_slice(recipient_public.as_bytes());

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(HYBRID_ENVELOPE_INFO, key.as_mut())
        .map_err(|_| {
            CryptoError::InternalCryptoFailure("internal error: failed to derive envelope key")
        })?;
    Ok(key)
}

/// Detects all-zero X25519 shared secrets (small-order public key defense).
/// Uses constant-time comparison to avoid timing side channels.
fn shared_secret_is_all_zero(shared: &[u8; 32]) -> bool {
    ct_eq_32(shared, &[0u8; 32])
}

// Only used by in-module tests now that the public API resolves the
// recipient's public key to raw bytes via `PublicKey` and calls
// `encrypt_file_from_bytes` directly. Kept so the existing test
// scenarios (path-based encrypt against freshly generated key files)
// remain self-contained.
#[cfg(test)]
fn encrypt_file(
    input_path: &Path,
    output_dir: &Path,
    public_key_path: &Path,
    output_file: Option<&Path>,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    let recipient_public = read_public_key(public_key_path)?;
    encrypt_file_inner(
        input_path,
        output_dir,
        &recipient_public,
        output_file,
        on_event,
    )
}

pub fn encrypt_file_from_bytes(
    input_path: &Path,
    output_dir: &Path,
    public_key_bytes: &[u8; 32],
    output_file: Option<&Path>,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    let recipient_public = PublicKey::from(*public_key_bytes);
    encrypt_file_inner(
        input_path,
        output_dir,
        &recipient_public,
        output_file,
        on_event,
    )
}

fn encrypt_file_inner(
    input_path: &Path,
    output_dir: &Path,
    recipient_public: &PublicKey,
    output_file: Option<&Path>,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    let base_name = &encryption_base_name(input_path)?;
    on_event(&ProgressEvent::Encrypting);

    let output_path = match output_file {
        Some(path) => path.to_path_buf(),
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
    let tmp = tempfile::Builder::new()
        .prefix(".ferrocrypt-")
        .suffix(".incomplete")
        .tempfile_in(temp_dir)?;

    let mut encryption_key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let mut hmac_key = [0u8; HMAC_KEY_SIZE];
    OsRng.fill_bytes(&mut hmac_key);

    let result: Result<tempfile::NamedTempFile, CryptoError> = (|| {
        let mut tmp = tmp;
        let cipher = XChaCha20Poly1305::new(&encryption_key);

        let mut stream_nonce = [0u8; STREAM_NONCE_SIZE];
        OsRng.fill_bytes(&mut stream_nonce);

        let mut combined_key = Zeroizing::new(vec![0u8; COMBINED_KEY_SIZE]);
        combined_key[..ENCRYPTION_KEY_SIZE].copy_from_slice(&encryption_key);
        combined_key[ENCRYPTION_KEY_SIZE..].copy_from_slice(&hmac_key);

        let envelope = seal_envelope(&combined_key, recipient_public)?;

        // No extensions today. `ext_bytes` is an empty authenticated region;
        // future minor versions append optional data here and it will be
        // bound to the file by the HMAC.
        let core = HybridHeaderCore::new(envelope, stream_nonce, Vec::new())?;

        let prefix = format::build_header_prefix(
            format::TYPE_HYBRID,
            format::HYBRID_VERSION_MAJOR,
            0,
            core.ext_len(),
        );
        let hmac_tag = hmac_sha3_256(&hmac_key, &core.hmac_input(&prefix))?;

        let stream_encryptor =
            stream::EncryptorBE32::from_aead(cipher, stream_nonce.as_ref().into());

        tmp.as_file_mut().write_all(&encode(&prefix))?;
        core.write_to(tmp.as_file_mut())?;
        tmp.as_file_mut().write_all(&encode(&hmac_tag))?;

        let encrypt_writer = EncryptWriter::new(stream_encryptor, tmp);
        let (_, encrypt_writer) = archiver::archive(input_path, encrypt_writer)?;
        let tmp = encrypt_writer.finish()?;
        tmp.as_file().sync_all()?;

        stream_nonce.zeroize();
        Ok(tmp)
    })();

    encryption_key.zeroize();
    hmac_key.zeroize();

    let tmp = result?;
    atomic_output::finalize_file(tmp, &output_path)?;
    Ok(output_path)
}

pub fn decrypt_file(
    input_path: &Path,
    output_dir: &Path,
    private_key_path: &Path,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    on_event(&ProgressEvent::Decrypting);

    let mut encrypted_file = fs::File::open(input_path)?;

    let (prefix_bytes, header) =
        format::read_header_from_reader(&mut encrypted_file, format::TYPE_HYBRID)?;

    match header.major {
        4 => decrypt_file_v4(
            encrypted_file,
            prefix_bytes,
            header,
            output_dir,
            private_key_path,
            passphrase,
            kdf_limit,
            on_event,
        ),
        _ => Err(format::unsupported_file_version_error(
            header.major,
            header.minor,
            format::HYBRID_VERSION_MAJOR,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn decrypt_file_v4(
    mut encrypted_file: fs::File,
    prefix_bytes: [u8; format::HEADER_PREFIX_SIZE],
    header: format::FileHeader,
    output_dir: &Path,
    private_key_path: &Path,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
    _on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    format::validate_file_flags(&header)?;

    // v4 minor-version dispatch: every 4.x minor decrypts identically — the
    // ext_bytes region is authenticated by HMAC and the contents are ignored.
    // Bound here so the field is read on the success path and the contract
    // is visible at the call site. Per FORMAT.md §10.2, minor versions are
    // always forward-compatible (never rejected); a future 4.x minor that
    // needs special behavior would replace this with a `match header.minor`
    // where the wildcard arm is still the default ignore.
    let _minor: u8 = header.minor;

    let core = HybridHeaderCore::read_from(&mut encrypted_file, header.ext_len as usize)?;
    let hmac_tag = format::read_replicated_field::<HMAC_TAG_SIZE>(&mut encrypted_file)?;

    let recipient_secret = read_private_key(private_key_path, passphrase, kdf_limit)?;
    let envelope_result = open_envelope(&core.envelope, &recipient_secret);
    drop(recipient_secret);
    let mut decrypted_combined_key = envelope_result?;

    let result = (|| -> Result<PathBuf, CryptoError> {
        let hmac_key = &decrypted_combined_key[ENCRYPTION_KEY_SIZE..COMBINED_KEY_SIZE];
        hmac_sha3_256_verify(hmac_key, &core.hmac_input(&prefix_bytes), &hmac_tag)?;

        let cipher =
            XChaCha20Poly1305::new((&decrypted_combined_key[..ENCRYPTION_KEY_SIZE]).into());
        let stream_decryptor =
            stream::DecryptorBE32::from_aead(cipher, core.stream_nonce.as_slice().into());

        let decrypt_reader = DecryptReader::new(stream_decryptor, encrypted_file);
        archiver::unarchive(decrypt_reader, output_dir)
    })();

    decrypted_combined_key.zeroize();
    result
}

#[cfg(test)]
fn read_public_key(path: &Path) -> Result<PublicKey, CryptoError> {
    let data = fs::read(path)?;
    let header = format::parse_key_file_header(&data, format::KEY_FILE_TYPE_PUBLIC)?;
    match header.version {
        format::PUBLIC_KEY_VERSION => read_public_key_data(&data, &header),
        other => Err(format::unsupported_key_version_error(
            other,
            format::PUBLIC_KEY_VERSION,
        )),
    }
}

#[cfg(test)]
fn read_public_key_data(
    data: &[u8],
    header: &format::KeyFileHeader,
) -> Result<PublicKey, CryptoError> {
    format::validate_key_layout(data, header, PUBLIC_KEY_DATA_SIZE)?;
    let body_start = format::KEY_FILE_HEADER_SIZE;
    let key_bytes: [u8; PUBLIC_KEY_DATA_SIZE] = data[body_start..body_start + PUBLIC_KEY_DATA_SIZE]
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::UnexpectedKeyLength))?;
    Ok(PublicKey::from(key_bytes))
}

fn read_private_key(
    path: &Path,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
) -> Result<StaticSecret, CryptoError> {
    let data = fs::read(path)?;
    let header = format::parse_key_file_header(&data, format::KEY_FILE_TYPE_PRIVATE)?;
    match header.version {
        format::PRIVATE_KEY_VERSION => read_private_key_data(&data, &header, passphrase, kdf_limit),
        other => Err(format::unsupported_key_version_error(
            other,
            format::PRIVATE_KEY_VERSION,
        )),
    }
}

fn read_private_key_data(
    data: &[u8],
    header: &format::KeyFileHeader,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
) -> Result<StaticSecret, CryptoError> {
    validate_private_key_body_shape(data, header)?;

    let body_start = format::KEY_FILE_HEADER_SIZE;
    let body = &data[body_start..body_start + header.data_len as usize];
    let parsed = PrivateKeyBody::from_bytes(body)?;

    let header_bytes: [u8; format::KEY_FILE_HEADER_SIZE] = data[..format::KEY_FILE_HEADER_SIZE]
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::Truncated))?;
    let aad = parsed.aad(&header_bytes);

    let kdf_params = KdfParams::from_bytes(&parsed.kdf_bytes, kdf_limit)?;
    let derived_key =
        kdf_params.hash_passphrase(passphrase.expose_secret().as_bytes(), &parsed.salt)?;

    let cipher = XChaCha20Poly1305::new(derived_key.as_ref().into());
    let nonce = chacha20poly1305::XNonce::from_slice(&parsed.nonce);
    let mut plaintext = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: parsed.ciphertext.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| CryptoError::KeyFileUnlockFailed)?;

    drop(derived_key);

    if plaintext.len() != PRIVATE_KEY_SIZE {
        plaintext.zeroize();
        return Err(CryptoError::InvalidFormat(
            FormatDefect::UnexpectedKeyLength,
        ));
    }

    let mut private_key_bytes = [0u8; PRIVATE_KEY_SIZE];
    private_key_bytes.copy_from_slice(&plaintext);
    plaintext.zeroize();

    let key = StaticSecret::from(private_key_bytes);
    private_key_bytes.zeroize();
    Ok(key)
}

fn seal_envelope(
    combined_key: &[u8],
    recipient_public: &PublicKey,
) -> Result<[u8; ENVELOPE_SIZE], CryptoError> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(recipient_public);
    if shared_secret_is_all_zero(shared.as_bytes()) {
        return Err(CryptoError::InvalidInput(
            "Invalid recipient public key".to_string(),
        ));
    }

    let wrapping_key = derive_envelope_key(&ephemeral_public, recipient_public, shared.as_bytes())?;

    let cipher = XChaCha20Poly1305::new(wrapping_key.as_ref().into());
    let aead_nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext_vec = cipher.encrypt(&aead_nonce, combined_key).map_err(|_| {
        CryptoError::InternalCryptoFailure("internal error: envelope encryption failed")
    })?;

    let mut nonce = [0u8; ENVELOPE_NONCE_SIZE];
    nonce.copy_from_slice(&aead_nonce);
    let ciphertext: [u8; ENVELOPE_CIPHERTEXT_SIZE] =
        ciphertext_vec.as_slice().try_into().map_err(|_| {
            CryptoError::InternalInvariant(
                "internal error: envelope ciphertext has an unexpected length",
            )
        })?;

    Ok(Envelope {
        ephemeral_public: *ephemeral_public.as_bytes(),
        nonce,
        ciphertext,
    }
    .to_bytes())
}

fn open_envelope(
    envelope: &[u8; ENVELOPE_SIZE],
    recipient_secret: &StaticSecret,
) -> Result<[u8; COMBINED_KEY_SIZE], CryptoError> {
    let parsed = Envelope::from_bytes(envelope);
    let ephemeral_public = PublicKey::from(parsed.ephemeral_public);

    let shared = recipient_secret.diffie_hellman(&ephemeral_public);
    if shared_secret_is_all_zero(shared.as_bytes()) {
        return Err(CryptoError::HeaderAuthenticationFailed);
    }

    let recipient_public = PublicKey::from(recipient_secret);
    let wrapping_key =
        derive_envelope_key(&ephemeral_public, &recipient_public, shared.as_bytes())?;

    let cipher = XChaCha20Poly1305::new(wrapping_key.as_ref().into());
    let nonce = chacha20poly1305::XNonce::from_slice(&parsed.nonce);
    let mut plaintext = cipher
        .decrypt(nonce, parsed.ciphertext.as_slice())
        .map_err(|_| CryptoError::HeaderAuthenticationFailed)?;

    if plaintext.len() != COMBINED_KEY_SIZE {
        plaintext.zeroize();
        return Err(CryptoError::InvalidFormat(
            FormatDefect::UnexpectedKeyLength,
        ));
    }

    let mut result = [0u8; COMBINED_KEY_SIZE];
    result.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(result)
}

/// Returns (private_key_path, public_key_path) on success.
pub fn generate_key_pair(
    passphrase: &SecretString,
    output_dir: &Path,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<(PathBuf, PathBuf), CryptoError> {
    if passphrase.expose_secret().is_empty() {
        return Err(CryptoError::InvalidInput(
            "Passphrase must not be empty for private key encryption".to_string(),
        ));
    }
    fs::create_dir_all(output_dir)?;
    on_event(&ProgressEvent::GeneratingKeyPair);

    let private_key = StaticSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);

    // Encrypt private key at rest with passphrase via Argon2id + XChaCha20-Poly1305
    let kdf_params = KdfParams::default();
    let kdf_bytes = kdf_params.to_bytes();
    let mut salt = [0u8; ARGON2_SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let derived_key = kdf_params.hash_passphrase(passphrase.expose_secret().as_bytes(), &salt)?;

    // v4 writers emit an empty extension region. The field is
    // authenticated by the AEAD tag either way, so a future 0.3.x minor
    // can populate `ext_bytes` without breaking v4 readers.
    let ext_bytes: Vec<u8> = Vec::new();

    let cipher = XChaCha20Poly1305::new(derived_key.as_ref().into());
    let aead_nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut nonce = [0u8; PRIVATE_KEY_NONCE_SIZE];
    nonce.copy_from_slice(&aead_nonce);

    // The AAD binds the cleartext header + every cleartext body field
    // (kdf, salt, nonce, ext_len, ext_bytes) to the ciphertext so
    // every byte on disk is cryptographically authenticated. Tamper
    // on any of those cleartext fields, and wrong-passphrase, both
    // surface as the same `KeyFileUnlockFailed` error (the AEAD
    // primitive returns a single undifferentiated failure).
    let private_body_data_len = (PRIVATE_KEY_FIXED_BODY_SIZE + ext_bytes.len()) as u16;
    let private_header = format::build_key_file_header(
        format::KEY_FILE_TYPE_PRIVATE,
        format::PRIVATE_KEY_VERSION,
        private_body_data_len,
    );
    let public_header = format::build_key_file_header(
        format::KEY_FILE_TYPE_PUBLIC,
        format::PUBLIC_KEY_VERSION,
        PUBLIC_KEY_DATA_SIZE as u16,
    );

    let aad = {
        let mut aad = Vec::with_capacity(
            format::KEY_FILE_HEADER_SIZE
                + KDF_PARAMS_SIZE
                + ARGON2_SALT_SIZE
                + PRIVATE_KEY_NONCE_SIZE
                + PRIVATE_KEY_EXT_LEN_SIZE
                + ext_bytes.len(),
        );
        aad.extend_from_slice(&private_header);
        aad.extend_from_slice(&kdf_bytes);
        aad.extend_from_slice(&salt);
        aad.extend_from_slice(&nonce);
        aad.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
        aad.extend_from_slice(&ext_bytes);
        aad
    };

    let raw_private_key = Zeroizing::new(private_key.to_bytes());
    drop(private_key);
    let encrypted_private_key = cipher
        .encrypt(
            chacha20poly1305::XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: raw_private_key.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| {
            CryptoError::InternalCryptoFailure("internal error: private key encryption failed")
        })?;
    drop(raw_private_key);
    drop(derived_key);

    let ciphertext: [u8; PRIVATE_KEY_BLOB_SIZE] =
        encrypted_private_key.as_slice().try_into().map_err(|_| {
            CryptoError::InternalInvariant(
                "internal error: encrypted private key blob has an unexpected length",
            )
        })?;
    let private_body = PrivateKeyBody {
        kdf_bytes,
        salt,
        nonce,
        ext_bytes,
        ciphertext,
    };

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

    // Write public key first, then the private key. If the private-key
    // write fails, a successfully persisted public key is orphaned but
    // harmless (public keys are meant to be public); we still remove it
    // so the user's output directory is clean.
    //
    // Public key permissions are relaxed to 0o644 on Unix so the file is
    // world-readable (public keys are not secret); the private-key
    // tempfile keeps tempfile's default 0o600.
    let mut public_builder = tempfile::Builder::new();
    public_builder.prefix(".ferrocrypt-pubkey-").suffix(".tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        public_builder.permissions(fs::Permissions::from_mode(0o644));
    }
    let mut public_tmp = public_builder.tempfile_in(output_dir)?;
    public_tmp.as_file_mut().write_all(&public_header)?;
    public_tmp.as_file_mut().write_all(public_key.as_bytes())?;
    public_tmp.as_file().sync_all()?;
    atomic_output::finalize_file(public_tmp, &public_key_path)?;

    let private_write: Result<(), CryptoError> = (|| {
        let mut private_tmp = tempfile::Builder::new()
            .prefix(".ferrocrypt-privkey-")
            .suffix(".tmp")
            .tempfile_in(output_dir)?;
        private_tmp.as_file_mut().write_all(&private_header)?;
        private_tmp
            .as_file_mut()
            .write_all(&private_body.to_bytes())?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::HEADER_PREFIX_ENCODED_SIZE;
    use crate::replication::{decode_exact, encoded_size};
    use std::io::{Cursor, Read};

    /// Proves the forward-compatibility mechanism for hybrid files: a synthetic
    /// v4.1 file with a non-empty authenticated `ext_bytes` region (and correctly
    /// recomputed HMAC) is decrypted successfully by the current v4 reader.
    #[test]
    fn future_minor_version_forward_compatible_hybrid() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let encrypt_dir = tmp.path().join("encrypted");
        let decrypt_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&keys_dir)?;
        fs::create_dir_all(&encrypt_dir)?;
        fs::create_dir_all(&decrypt_dir)?;

        let key_pass = SecretString::from("kp".to_string());
        generate_key_pair(&key_pass, &keys_dir, &|_| {})?;

        let input_file = tmp.path().join("data.txt");
        fs::write(&input_file, "hybrid forward compat test")?;

        encrypt_file(
            &input_file,
            &encrypt_dir,
            &keys_dir.join(PUBLIC_KEY_FILENAME),
            None,
            &|_| {},
        )?;

        let encrypted_path = encrypt_dir.join("data.fcr");
        let original = fs::read(&encrypted_path)?;

        // Read v4.0 fixed header fields (ext_len = 0 in the current writer).
        let mut cursor = Cursor::new(&original[HEADER_PREFIX_ENCODED_SIZE..]);
        let mut enc_envelope = vec![0u8; encoded_size(ENVELOPE_SIZE)];
        let mut enc_nonce = vec![0u8; encoded_size(STREAM_NONCE_SIZE)];
        let mut enc_old_ext = vec![0u8; encoded_size(0)];
        let mut enc_hmac = vec![0u8; encoded_size(HMAC_TAG_SIZE)];
        cursor.read_exact(&mut enc_envelope)?;
        cursor.read_exact(&mut enc_nonce)?;
        cursor.read_exact(&mut enc_old_ext)?;
        cursor.read_exact(&mut enc_hmac)?;

        let ciphertext_offset = HEADER_PREFIX_ENCODED_SIZE + cursor.position() as usize;

        let envelope_vec = decode_exact(&enc_envelope, ENVELOPE_SIZE)?;
        let nonce = decode_exact(&enc_nonce, STREAM_NONCE_SIZE)?;
        let envelope: [u8; ENVELOPE_SIZE] = envelope_vec.as_slice().try_into().unwrap();

        // Open envelope to get the HMAC key
        let private_key = read_private_key(&keys_dir.join(PRIVATE_KEY_FILENAME), &key_pass, None)?;
        let decrypted = open_envelope(&envelope, &private_key)?;
        drop(private_key);
        let hmac_key = &decrypted[ENCRYPTION_KEY_SIZE..COMBINED_KEY_SIZE];

        // Synthetic v4.1 extension: 16 opaque authenticated bytes.
        let ext_bytes: Vec<u8> = (0..16u8).collect();
        let mut new_prefix = format::build_header_prefix(
            format::TYPE_HYBRID,
            format::HYBRID_VERSION_MAJOR,
            0,
            ext_bytes.len() as u16,
        );
        new_prefix[3] = 1; // minor = 1

        // Recompute HMAC over prefix || envelope || nonce || ext_bytes.
        let mut hmac_message = Vec::new();
        hmac_message.extend_from_slice(&new_prefix);
        hmac_message.extend_from_slice(&envelope);
        hmac_message.extend_from_slice(&nonce);
        hmac_message.extend_from_slice(&ext_bytes);
        let new_hmac_tag = hmac_sha3_256(hmac_key, &hmac_message)?;

        // Reassemble: new prefix + envelope + nonce + ext_bytes + HMAC + ciphertext.
        let ciphertext = &original[ciphertext_offset..];
        let mut output = Vec::new();
        output.extend_from_slice(&encode(&new_prefix));
        output.extend_from_slice(&enc_envelope);
        output.extend_from_slice(&enc_nonce);
        output.extend_from_slice(&encode(&ext_bytes));
        output.extend_from_slice(&encode(&new_hmac_tag));
        output.extend_from_slice(ciphertext);

        fs::write(&encrypted_path, &output)?;

        let output = decrypt_file(
            &encrypted_path,
            &decrypt_dir,
            &keys_dir.join(PRIVATE_KEY_FILENAME),
            &key_pass,
            None,
            &|_| {},
        )?;
        assert!(output.exists());

        let decrypted_content = fs::read_to_string(decrypt_dir.join("data.txt"))?;
        assert_eq!(decrypted_content, "hybrid forward compat test");

        Ok(())
    }

    /// Tampering any byte inside the authenticated `ext_bytes` region of a
    /// hybrid file must break HMAC verification. This is the structural
    /// property introduced by the new header layout.
    #[test]
    fn ext_bytes_tamper_detected_hybrid() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let encrypt_dir = tmp.path().join("encrypted");
        let decrypt_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&keys_dir)?;
        fs::create_dir_all(&encrypt_dir)?;
        fs::create_dir_all(&decrypt_dir)?;

        let key_pass = SecretString::from("kp".to_string());
        generate_key_pair(&key_pass, &keys_dir, &|_| {})?;

        let input_file = tmp.path().join("data.txt");
        fs::write(&input_file, "hybrid tamper test")?;

        encrypt_file(
            &input_file,
            &encrypt_dir,
            &keys_dir.join(PUBLIC_KEY_FILENAME),
            None,
            &|_| {},
        )?;

        let encrypted_path = encrypt_dir.join("data.fcr");
        let original = fs::read(&encrypted_path)?;

        let mut cursor = Cursor::new(&original[HEADER_PREFIX_ENCODED_SIZE..]);
        let mut enc_envelope = vec![0u8; encoded_size(ENVELOPE_SIZE)];
        let mut enc_nonce = vec![0u8; encoded_size(STREAM_NONCE_SIZE)];
        let mut enc_old_ext = vec![0u8; encoded_size(0)];
        let mut enc_hmac = vec![0u8; encoded_size(HMAC_TAG_SIZE)];
        cursor.read_exact(&mut enc_envelope)?;
        cursor.read_exact(&mut enc_nonce)?;
        cursor.read_exact(&mut enc_old_ext)?;
        cursor.read_exact(&mut enc_hmac)?;
        let ciphertext_offset = HEADER_PREFIX_ENCODED_SIZE + cursor.position() as usize;

        let envelope_vec = decode_exact(&enc_envelope, ENVELOPE_SIZE)?;
        let nonce = decode_exact(&enc_nonce, STREAM_NONCE_SIZE)?;
        let envelope: [u8; ENVELOPE_SIZE] = envelope_vec.as_slice().try_into().unwrap();

        let private_key = read_private_key(&keys_dir.join(PRIVATE_KEY_FILENAME), &key_pass, None)?;
        let decrypted = open_envelope(&envelope, &private_key)?;
        drop(private_key);
        let hmac_key = &decrypted[ENCRYPTION_KEY_SIZE..COMBINED_KEY_SIZE];

        // Build a legitimate v4.1 file with 8 bytes of ext_bytes, authenticated.
        let ext_bytes = vec![0xAAu8; 8];
        let new_prefix = format::build_header_prefix(
            format::TYPE_HYBRID,
            format::HYBRID_VERSION_MAJOR,
            0,
            ext_bytes.len() as u16,
        );
        let mut hmac_message = Vec::new();
        hmac_message.extend_from_slice(&new_prefix);
        hmac_message.extend_from_slice(&envelope);
        hmac_message.extend_from_slice(&nonce);
        hmac_message.extend_from_slice(&ext_bytes);
        let hmac_tag = hmac_sha3_256(hmac_key, &hmac_message)?;

        // Replace the real ext_bytes with a tampered value before encoding.
        let tampered_ext = vec![0xBBu8; 8];
        let ciphertext = &original[ciphertext_offset..];

        let mut output = Vec::new();
        output.extend_from_slice(&encode(&new_prefix));
        output.extend_from_slice(&enc_envelope);
        output.extend_from_slice(&enc_nonce);
        output.extend_from_slice(&encode(&tampered_ext));
        output.extend_from_slice(&encode(&hmac_tag));
        output.extend_from_slice(ciphertext);

        fs::write(&encrypted_path, &output)?;

        let result = decrypt_file(
            &encrypted_path,
            &decrypt_dir,
            &keys_dir.join(PRIVATE_KEY_FILENAME),
            &key_pass,
            None,
            &|_| {},
        );
        assert!(result.is_err(), "tampered ext_bytes must fail HMAC");
        Ok(())
    }

    #[test]
    fn all_zero_shared_secret_detected() {
        assert!(shared_secret_is_all_zero(&[0u8; 32]));
    }

    #[test]
    fn nonzero_shared_secret_not_detected() {
        let mut val = [0u8; 32];
        val[31] = 1;
        assert!(!shared_secret_is_all_zero(&val));
    }

    /// Regression test: a known small-order X25519 public key must be rejected
    /// through the real envelope path, not just the helper.
    /// The identity point [1, 0, ..., 0] is a small-order point that produces
    /// an all-zero shared secret with any private key.
    #[test]
    fn small_order_public_key_rejected_in_seal() {
        let mut identity_point = [0u8; 32];
        identity_point[0] = 1; // Montgomery u-coordinate of the identity
        let bad_pk = PublicKey::from(identity_point);

        let combined_key = [0xAA; COMBINED_KEY_SIZE];
        let result = seal_envelope(&combined_key, &bad_pk);
        assert!(result.is_err());
    }

    /// Regression test: a small-order ephemeral public key in an envelope must
    /// be rejected during decryption.
    #[test]
    fn small_order_ephemeral_key_rejected_in_open() {
        let mut identity_point = [0u8; 32];
        identity_point[0] = 1;

        // Build a fake envelope with the identity point as ephemeral public key
        let mut envelope = [0u8; ENVELOPE_SIZE];
        envelope[..EPHEMERAL_PUB_SIZE].copy_from_slice(&identity_point);
        // Rest is arbitrary — should fail before AEAD decryption

        let private_key = StaticSecret::random_from_rng(OsRng);
        let result = open_envelope(&envelope, &private_key);
        assert!(result.is_err());
    }

    /// Envelope round-trip: seal with a recipient's public key, open with the
    /// matching private key, verify the combined key is recovered exactly.
    #[test]
    fn seal_open_envelope_round_trip() {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private_key);

        let mut combined_key = [0u8; COMBINED_KEY_SIZE];
        OsRng.fill_bytes(&mut combined_key);

        let envelope = seal_envelope(&combined_key, &public).unwrap();
        let recovered = open_envelope(&envelope, &private_key).unwrap();
        assert_eq!(combined_key, recovered);
    }

    /// Wrong private key must fail to open an envelope.
    #[test]
    fn open_envelope_wrong_key_fails() {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private_key);
        let wrong_secret = StaticSecret::random_from_rng(OsRng);

        let combined_key = [0xBB; COMBINED_KEY_SIZE];
        let envelope = seal_envelope(&combined_key, &public).unwrap();
        let result = open_envelope(&envelope, &wrong_secret);
        assert!(result.is_err());
    }

    /// Well-sized but garbage envelope bytes must fail AEAD decryption.
    #[test]
    fn garbage_envelope_fails() {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let mut garbage = [0xCC; ENVELOPE_SIZE];
        // Put a valid-looking (but wrong) public key so DH doesn't produce all-zero
        let decoy_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        garbage[..EPHEMERAL_PUB_SIZE].copy_from_slice(decoy_pk.as_bytes());

        let result = open_envelope(&garbage, &private_key);
        assert!(result.is_err());
    }

    /// Flipping one bit in an otherwise valid envelope must fail.
    #[test]
    fn envelope_single_bit_flip_detected() {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private_key);
        let combined_key = [0xAA; COMBINED_KEY_SIZE];

        let mut envelope = seal_envelope(&combined_key, &public).unwrap();
        // Flip one bit in the ciphertext region
        envelope[EPHEMERAL_PUB_SIZE + ENVELOPE_NONCE_SIZE + 10] ^= 0x01;

        let result = open_envelope(&envelope, &private_key);
        assert!(result.is_err());
    }

    /// Key file with unsupported algorithm byte must be rejected.
    #[test]
    fn key_file_wrong_algorithm_rejected() {
        let tmp = tempfile::TempDir::new().unwrap();
        let key_pass = SecretString::from("p".to_string());
        generate_key_pair(&key_pass, tmp.path(), &|_| {}).unwrap();

        // Patch algorithm byte (offset 3) to an unknown value
        let pub_path = tmp.path().join(PUBLIC_KEY_FILENAME);
        let mut data = fs::read(&pub_path).unwrap();
        data[3] = 0xFF;
        fs::write(&pub_path, &data).unwrap();

        let result = read_public_key(&pub_path);
        assert!(result.is_err());
    }

    /// Key file truncated to just the header must be rejected.
    #[test]
    fn truncated_key_file_rejected() {
        let tmp = tempfile::TempDir::new().unwrap();
        let key_pass = SecretString::from("p".to_string());
        generate_key_pair(&key_pass, tmp.path(), &|_| {}).unwrap();

        let pub_path = tmp.path().join(PUBLIC_KEY_FILENAME);
        let data = fs::read(&pub_path).unwrap();
        // Write only the 8-byte header, no key data
        fs::write(&pub_path, &data[..format::KEY_FILE_HEADER_SIZE]).unwrap();

        let result = read_public_key(&pub_path);
        assert!(result.is_err());
    }

    /// Reserved-bit fail-closed: a v4.0 hybrid file with `flags = 0x0001` must
    /// be rejected with the typed `UnknownHeaderFlags` variant. Since the
    /// header HMAC covers the prefix (flags included), this test re-opens the
    /// envelope to recover the HMAC key and recomputes a valid HMAC for the
    /// patched prefix — without that, an HMAC failure could mask what the
    /// flag check actually does, and the assertion would not pin the
    /// flag-rejection path independently.
    #[test]
    fn nonzero_flags_rejected_with_valid_hmac() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let encrypt_dir = tmp.path().join("encrypted");
        let decrypt_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&keys_dir)?;
        fs::create_dir_all(&encrypt_dir)?;
        fs::create_dir_all(&decrypt_dir)?;

        let key_pass = SecretString::from("kp".to_string());
        generate_key_pair(&key_pass, &keys_dir, &|_| {})?;

        let input_file = tmp.path().join("data.txt");
        fs::write(&input_file, "flag rejection test")?;

        encrypt_file(
            &input_file,
            &encrypt_dir,
            &keys_dir.join(PUBLIC_KEY_FILENAME),
            None,
            &|_| {},
        )?;

        let encrypted_path = encrypt_dir.join("data.fcr");
        let original = fs::read(&encrypted_path)?;

        let mut cursor = Cursor::new(&original[HEADER_PREFIX_ENCODED_SIZE..]);
        let mut enc_envelope = vec![0u8; encoded_size(ENVELOPE_SIZE)];
        let mut enc_nonce = vec![0u8; encoded_size(STREAM_NONCE_SIZE)];
        let mut enc_old_ext = vec![0u8; encoded_size(0)];
        let mut enc_hmac = vec![0u8; encoded_size(HMAC_TAG_SIZE)];
        cursor.read_exact(&mut enc_envelope)?;
        cursor.read_exact(&mut enc_nonce)?;
        cursor.read_exact(&mut enc_old_ext)?;
        cursor.read_exact(&mut enc_hmac)?;
        let ciphertext_offset = HEADER_PREFIX_ENCODED_SIZE + cursor.position() as usize;

        let envelope_vec = decode_exact(&enc_envelope, ENVELOPE_SIZE)?;
        let nonce = decode_exact(&enc_nonce, STREAM_NONCE_SIZE)?;
        let envelope: [u8; ENVELOPE_SIZE] = envelope_vec.as_slice().try_into().unwrap();

        let private_key = read_private_key(&keys_dir.join(PRIVATE_KEY_FILENAME), &key_pass, None)?;
        let decrypted = open_envelope(&envelope, &private_key)?;
        drop(private_key);
        let hmac_key = &decrypted[ENCRYPTION_KEY_SIZE..COMBINED_KEY_SIZE];

        // Build a v4.0 header with flags = 0x0001 and a recomputed valid HMAC.
        let new_prefix = format::build_header_prefix(
            format::TYPE_HYBRID,
            format::HYBRID_VERSION_MAJOR,
            0x0001,
            0,
        );
        let mut hmac_message = Vec::new();
        hmac_message.extend_from_slice(&new_prefix);
        hmac_message.extend_from_slice(&envelope);
        hmac_message.extend_from_slice(&nonce);
        let hmac_tag = hmac_sha3_256(hmac_key, &hmac_message)?;

        let ciphertext = &original[ciphertext_offset..];
        let mut output = Vec::new();
        output.extend_from_slice(&encode(&new_prefix));
        output.extend_from_slice(&enc_envelope);
        output.extend_from_slice(&enc_nonce);
        output.extend_from_slice(&encode(&[])); // ext_bytes = empty
        output.extend_from_slice(&encode(&hmac_tag));
        output.extend_from_slice(ciphertext);

        fs::write(&encrypted_path, &output)?;

        let result = decrypt_file(
            &encrypted_path,
            &decrypt_dir,
            &keys_dir.join(PRIVATE_KEY_FILENAME),
            &key_pass,
            None,
            &|_| {},
        );
        match result {
            Err(CryptoError::InvalidFormat(crate::error::FormatDefect::UnknownHeaderFlags(
                0x0001,
            ))) => Ok(()),
            other => panic!("expected UnknownHeaderFlags(0x0001), got: {other:?}"),
        }
    }

    /// Reserved-bit fail-closed: a key file with `flags = 0x0001` (any nonzero
    /// value) must be rejected with the typed `UnknownKeyFileFlags` variant.
    /// Key files have no separate HMAC over their own header — the layout
    /// validator is the only fail-closed gate for unknown bits.
    #[test]
    fn key_file_nonzero_flags_rejected() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let key_pass = SecretString::from("p".to_string());
        generate_key_pair(&key_pass, tmp.path(), &|_| {})?;

        // Patch flags (header bytes 6..=7) to 0x0001 in the public key file.
        let pub_path = tmp.path().join(PUBLIC_KEY_FILENAME);
        let mut data = fs::read(&pub_path)?;
        data[6] = 0x00;
        data[7] = 0x01;
        fs::write(&pub_path, &data)?;

        let result = read_public_key(&pub_path);
        match result {
            Err(CryptoError::InvalidFormat(crate::error::FormatDefect::UnknownKeyFileFlags(
                0x0001,
            ))) => Ok(()),
            other => panic!("expected UnknownKeyFileFlags(0x0001), got: {other:?}"),
        }
    }

    /// `HybridHeaderCore::new` must accept an `ext_bytes` exactly the size of
    /// `u16::MAX` and reject anything larger. The on-disk prefix stores
    /// `ext_len` as a `u16`, so this is the wire-format boundary.
    #[test]
    fn new_rejects_oversized_ext_bytes() {
        let envelope = [0u8; ENVELOPE_SIZE];
        let stream_nonce = [0u8; STREAM_NONCE_SIZE];

        // Max u16 accepted.
        let accepted = HybridHeaderCore::new(envelope, stream_nonce, vec![0u8; u16::MAX as usize]);
        assert!(accepted.is_ok(), "u16::MAX ext_bytes must be accepted");

        // One byte over max is rejected.
        let rejected =
            HybridHeaderCore::new(envelope, stream_nonce, vec![0u8; u16::MAX as usize + 1]);
        match rejected {
            Ok(_) => panic!("u16::MAX + 1 ext_bytes must be rejected"),
            Err(CryptoError::InvalidInput(_)) => {}
            Err(other) => panic!("expected InvalidInput, got: {other:?}"),
        }
    }

    /// `Envelope::to_bytes` and `from_bytes` must round-trip: the parsed
    /// struct equals the original, and field bytes land at the canonical
    /// offsets. Locks the wire layout so a future field reorder fails the
    /// suite immediately instead of via a downstream HMAC mismatch.
    #[test]
    fn envelope_round_trip() {
        let original = Envelope {
            ephemeral_public: [0x11; EPHEMERAL_PUB_SIZE],
            nonce: [0x22; ENVELOPE_NONCE_SIZE],
            ciphertext: [0x33; ENVELOPE_CIPHERTEXT_SIZE],
        };
        let bytes = original.to_bytes();

        // Wire-format offsets: pk || nonce || ciphertext.
        assert!(bytes[..EPHEMERAL_PUB_SIZE].iter().all(|&b| b == 0x11));
        assert!(
            bytes[EPHEMERAL_PUB_SIZE..EPHEMERAL_PUB_SIZE + ENVELOPE_NONCE_SIZE]
                .iter()
                .all(|&b| b == 0x22)
        );
        assert!(
            bytes[EPHEMERAL_PUB_SIZE + ENVELOPE_NONCE_SIZE..]
                .iter()
                .all(|&b| b == 0x33)
        );

        let parsed = Envelope::from_bytes(&bytes);
        assert_eq!(parsed.ephemeral_public, original.ephemeral_public);
        assert_eq!(parsed.nonce, original.nonce);
        assert_eq!(parsed.ciphertext, original.ciphertext);
    }

    /// `PrivateKeyBody::to_bytes` and `from_bytes` must round-trip and
    /// place fields at their canonical offsets, including the
    /// big-endian `ext_len` and the variable `ext_bytes` region. Uses
    /// a non-empty `ext_bytes` to exercise the variable-length path.
    #[test]
    fn private_key_body_round_trip() {
        let ext_payload: Vec<u8> = (0..5u8).collect();
        let original = PrivateKeyBody {
            kdf_bytes: [0x44; KDF_PARAMS_SIZE],
            salt: [0x55; ARGON2_SALT_SIZE],
            nonce: [0x66; PRIVATE_KEY_NONCE_SIZE],
            ext_bytes: ext_payload.clone(),
            ciphertext: [0x77; PRIVATE_KEY_BLOB_SIZE],
        };
        let bytes = original.to_bytes();

        // Wire-format offsets: kdf || salt || nonce || ext_len || ext_bytes || ciphertext.
        let kdf_end = KDF_PARAMS_SIZE;
        let salt_end = kdf_end + ARGON2_SALT_SIZE;
        let nonce_end = salt_end + PRIVATE_KEY_NONCE_SIZE;
        let ext_len_end = nonce_end + PRIVATE_KEY_EXT_LEN_SIZE;
        let ext_end = ext_len_end + ext_payload.len();
        assert!(bytes[..kdf_end].iter().all(|&b| b == 0x44));
        assert!(bytes[kdf_end..salt_end].iter().all(|&b| b == 0x55));
        assert!(bytes[salt_end..nonce_end].iter().all(|&b| b == 0x66));
        assert_eq!(
            u16::from_be_bytes([bytes[nonce_end], bytes[nonce_end + 1]]) as usize,
            ext_payload.len()
        );
        assert_eq!(&bytes[ext_len_end..ext_end], ext_payload.as_slice());
        assert!(bytes[ext_end..].iter().all(|&b| b == 0x77));

        let parsed = PrivateKeyBody::from_bytes(&bytes).expect("round-trip must parse");
        assert_eq!(parsed.kdf_bytes, original.kdf_bytes);
        assert_eq!(parsed.salt, original.salt);
        assert_eq!(parsed.nonce, original.nonce);
        assert_eq!(parsed.ext_bytes, original.ext_bytes);
        assert_eq!(parsed.ciphertext, original.ciphertext);
    }
}
