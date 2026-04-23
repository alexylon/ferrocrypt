//! Symmetric (passphrase-based) `.fcr` encrypt and decrypt.
//!
//! Pipeline:
//!   passphrase → Argon2id → HKDF-SHA3-256 → `wrap_key`
//!   `wrap_key` + XChaCha20-Poly1305 seals a random 32-byte `file_key`
//!   `file_key` → HKDF-SHA3-256 → `payload_key` + `header_key`
//!   `payload_key` encrypts the TAR payload via STREAM-BE32
//!   `header_key` HMAC-SHA3-256 authenticates the on-disk header
//!
//! Wire format (see `ferrocrypt-lib/FORMAT.md` §4.2, §4.4):
//!
//! ```text
//! [ replicated_prefix (27 B) ]
//! [ envelope (116 B)          = salt(32) | kdf(12) | wrap_nonce(24) | wrapped_file_key(48) ]
//! [ stream_nonce (19 B)       ]
//! [ ext_bytes (ext_len B)     ]
//! [ hmac_tag (32 B)           ]
//! [ payload (STREAM)          ]
//! ```

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{KeyInit, stream},
};
use secrecy::SecretString;

use crate::atomic_output;
use crate::common::{
    ARGON2_SALT_SIZE, DecryptReader, EncryptWriter, HKDF_INFO_SYM_WRAP, HMAC_TAG_SIZE,
    KDF_PARAMS_SIZE, KdfLimit, KdfParams, STREAM_NONCE_SIZE, WRAP_NONCE_SIZE,
    WRAPPED_FILE_KEY_SIZE, build_header_hmac_input, derive_passphrase_wrap_key, derive_subkeys,
    encryption_base_name, generate_file_key, hmac_sha3_256, hmac_sha3_256_verify, open_file_key,
    random_bytes, read_exact_or_truncated, seal_file_key, validate_tlv,
};
use crate::format;
use crate::{CryptoError, ProgressEvent, archiver};

/// Symmetric envelope size (raw, not replicated):
/// `argon2_salt(32) || kdf_params(12) || wrap_nonce(24) || wrapped_file_key(48)`.
pub const SYMMETRIC_ENVELOPE_SIZE: usize =
    ARGON2_SALT_SIZE + KDF_PARAMS_SIZE + WRAP_NONCE_SIZE + WRAPPED_FILE_KEY_SIZE;

/// In-memory view of the 116-byte symmetric envelope. Writer, reader,
/// and HMAC input all go through the same field order so the on-disk
/// contract cannot drift.
struct SymmetricEnvelope {
    argon2_salt: [u8; ARGON2_SALT_SIZE],
    kdf_bytes: [u8; KDF_PARAMS_SIZE],
    wrap_nonce: [u8; WRAP_NONCE_SIZE],
    wrapped_file_key: [u8; WRAPPED_FILE_KEY_SIZE],
}

impl SymmetricEnvelope {
    fn to_bytes(&self) -> [u8; SYMMETRIC_ENVELOPE_SIZE] {
        let mut out = [0u8; SYMMETRIC_ENVELOPE_SIZE];
        let mut off = 0;
        out[off..off + ARGON2_SALT_SIZE].copy_from_slice(&self.argon2_salt);
        off += ARGON2_SALT_SIZE;
        out[off..off + KDF_PARAMS_SIZE].copy_from_slice(&self.kdf_bytes);
        off += KDF_PARAMS_SIZE;
        out[off..off + WRAP_NONCE_SIZE].copy_from_slice(&self.wrap_nonce);
        off += WRAP_NONCE_SIZE;
        out[off..].copy_from_slice(&self.wrapped_file_key);
        out
    }

    fn from_bytes(bytes: &[u8; SYMMETRIC_ENVELOPE_SIZE]) -> Self {
        let mut off = 0;
        let mut argon2_salt = [0u8; ARGON2_SALT_SIZE];
        argon2_salt.copy_from_slice(&bytes[off..off + ARGON2_SALT_SIZE]);
        off += ARGON2_SALT_SIZE;
        let mut kdf_bytes = [0u8; KDF_PARAMS_SIZE];
        kdf_bytes.copy_from_slice(&bytes[off..off + KDF_PARAMS_SIZE]);
        off += KDF_PARAMS_SIZE;
        let mut wrap_nonce = [0u8; WRAP_NONCE_SIZE];
        wrap_nonce.copy_from_slice(&bytes[off..off + WRAP_NONCE_SIZE]);
        off += WRAP_NONCE_SIZE;
        let mut wrapped_file_key = [0u8; WRAPPED_FILE_KEY_SIZE];
        wrapped_file_key.copy_from_slice(&bytes[off..]);
        Self {
            argon2_salt,
            kdf_bytes,
            wrap_nonce,
            wrapped_file_key,
        }
    }
}

/// Encrypts a file or directory under a passphrase. Input is archived
/// into a TAR stream and encrypted directly to the output file — no
/// plaintext intermediate files touch disk.
pub fn encrypt_file(
    input_path: &Path,
    output_dir: &Path,
    passphrase: &SecretString,
    output_file: Option<&Path>,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    on_event(&ProgressEvent::DerivingKey);

    let argon2_salt = random_bytes::<ARGON2_SALT_SIZE>();
    let kdf_params = KdfParams::default();
    let wrap_key =
        derive_passphrase_wrap_key(passphrase, &argon2_salt, &kdf_params, HKDF_INFO_SYM_WRAP)?;

    let file_key = generate_file_key();
    let wrap_nonce = random_bytes::<WRAP_NONCE_SIZE>();
    let wrapped_file_key = seal_file_key(&wrap_key, &wrap_nonce, &file_key)?;

    let stream_nonce = random_bytes::<STREAM_NONCE_SIZE>();
    let (payload_key, header_key) = derive_subkeys(&file_key, &stream_nonce)?;

    let envelope = SymmetricEnvelope {
        argon2_salt,
        kdf_bytes: kdf_params.to_bytes(),
        wrap_nonce,
        wrapped_file_key,
    };
    let envelope_bytes = envelope.to_bytes();

    // v1.0 writers emit `ext_len = 0`. Still HMAC the empty region so
    // the decrypt path's HMAC scope matches.
    let ext_bytes: Vec<u8> = Vec::new();

    let on_disk_prefix =
        format::build_encoded_header_prefix(format::TYPE_SYMMETRIC, ext_bytes.len() as u16)?;

    let tag = hmac_sha3_256(
        header_key.as_ref(),
        &build_header_hmac_input(&on_disk_prefix, &envelope_bytes, &stream_nonce, &ext_bytes),
    )?;

    let base_name = &encryption_base_name(input_path)?;
    on_event(&ProgressEvent::Encrypting);

    let output_path = match output_file {
        Some(path) => path.to_path_buf(),
        None => output_dir.join(format!("{}.{}", base_name, format::ENCRYPTED_EXTENSION)),
    };
    if output_path.exists() {
        return Err(CryptoError::InvalidInput(format!(
            "Output already exists: {}",
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

/// Decrypts a `.fcr` file produced by [`encrypt_file`]. Follows the
/// eight-step order from `ferrocrypt-lib/FORMAT.md` §4.8:
///
/// 1. read + validate prefix (magic, version, type, ext_len, canonicity)
/// 2. read rest of fixed header
/// 3. validate KDF param bounds
/// 4. unwrap `file_key` from envelope
/// 5. derive `header_key` + `payload_key`
/// 6. verify HMAC
/// 7. parse/validate TLV
/// 8. decrypt STREAM payload
pub fn decrypt_file(
    input_path: &Path,
    output_dir: &Path,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    let mut encrypted_file = fs::File::open(input_path)?;

    // 1. Prefix read + canonicity + magic/type/version/ext_len checks.
    let (on_disk_prefix, header) =
        format::read_header_from_reader(&mut encrypted_file, format::TYPE_SYMMETRIC)?;

    // 2. Fixed header fields after the prefix.
    let mut envelope_bytes = [0u8; SYMMETRIC_ENVELOPE_SIZE];
    read_exact_or_truncated(&mut encrypted_file, &mut envelope_bytes)?;
    let mut stream_nonce = [0u8; STREAM_NONCE_SIZE];
    read_exact_or_truncated(&mut encrypted_file, &mut stream_nonce)?;
    let mut ext_bytes = vec![0u8; header.ext_len as usize];
    read_exact_or_truncated(&mut encrypted_file, &mut ext_bytes)?;
    let mut tag = [0u8; HMAC_TAG_SIZE];
    read_exact_or_truncated(&mut encrypted_file, &mut tag)?;

    let envelope = SymmetricEnvelope::from_bytes(&envelope_bytes);

    // 3. KDF param structural bounds (also triggers `ExcessiveWork` if
    //    the file's cost exceeds `kdf_limit`), BEFORE Argon2id fires.
    let kdf_params = KdfParams::from_bytes(&envelope.kdf_bytes, kdf_limit)?;

    on_event(&ProgressEvent::DerivingKey);

    // 4. Envelope unwrap. Wrong passphrase and tampered envelope are
    //    indistinguishable at the AEAD layer, by design.
    let wrap_key = derive_passphrase_wrap_key(
        passphrase,
        &envelope.argon2_salt,
        &kdf_params,
        HKDF_INFO_SYM_WRAP,
    )?;
    let file_key = open_file_key(
        &wrap_key,
        &envelope.wrap_nonce,
        &envelope.wrapped_file_key,
        || CryptoError::SymmetricEnvelopeUnlockFailed,
    )?;

    // 5. Post-unwrap subkeys.
    let (payload_key, header_key) = derive_subkeys(&file_key, &stream_nonce)?;

    // 6. HMAC verify. Failure here means the right key opened the
    //    envelope but the rest of the header was tampered — a distinct
    //    diagnostic from envelope-unlock failure.
    hmac_sha3_256_verify(
        header_key.as_ref(),
        &build_header_hmac_input(&on_disk_prefix, &envelope_bytes, &stream_nonce, &ext_bytes),
        &tag,
    )?;

    // 7. TLV canonicity, after authentication.
    validate_tlv(&ext_bytes)?;

    // 8. STREAM payload.
    on_event(&ProgressEvent::Decrypting);
    let cipher = XChaCha20Poly1305::new(payload_key.as_ref().into());
    let stream_decryptor = stream::DecryptorBE32::from_aead(cipher, stream_nonce.as_ref().into());
    let decrypt_reader = DecryptReader::new(stream_decryptor, encrypted_file);
    archiver::unarchive(decrypt_reader, output_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FormatDefect;

    /// Harness: set up a tempdir with encrypted/ and decrypted/
    /// subdirs, write `content` to a `data.txt` input, and encrypt it
    /// under `passphrase`. Returns `(tempdir, encrypted_fcr_path,
    /// decrypted_dir, passphrase)`. The tempdir is returned so tests
    /// can keep it alive through the decrypt step.
    fn encrypt_fixture(
        content: &str,
        passphrase: &str,
    ) -> Result<(tempfile::TempDir, PathBuf, PathBuf, SecretString), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let input = tmp.path().join("data.txt");
        let enc_dir = tmp.path().join("encrypted");
        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&enc_dir)?;
        fs::create_dir_all(&dec_dir)?;
        fs::write(&input, content)?;
        let pass = SecretString::from(passphrase.to_string());
        encrypt_file(&input, &enc_dir, &pass, None, &|_| {})?;
        let fcr = enc_dir.join("data.fcr");
        Ok((tmp, fcr, dec_dir, pass))
    }

    /// Minimal round-trip: encrypt a file, decrypt it, compare contents.
    #[test]
    fn encrypt_decrypt_round_trip() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, pass) = encrypt_fixture("round trip payload", "pass")?;
        assert!(fcr.exists());
        decrypt_file(&fcr, &dec_dir, &pass, None, &|_| {})?;
        let restored = fs::read_to_string(dec_dir.join("data.txt"))?;
        assert_eq!(restored, "round trip payload");
        Ok(())
    }

    /// Wrong passphrase must surface as `SymmetricEnvelopeUnlockFailed`
    /// at the AEAD-open step — NOT `HeaderTampered` — so the user sees
    /// a passphrase-specific diagnostic.
    #[test]
    fn decrypt_with_wrong_passphrase_fails_at_envelope() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, _right) = encrypt_fixture("x", "right")?;
        let wrong = SecretString::from("wrong".to_string());
        match decrypt_file(&fcr, &dec_dir, &wrong, None, &|_| {}) {
            Err(CryptoError::SymmetricEnvelopeUnlockFailed) => Ok(()),
            other => panic!("expected SymmetricEnvelopeUnlockFailed, got {other:?}"),
        }
    }

    /// After successful envelope unwrap, tampering with `stream_nonce`
    /// must surface as `HeaderTampered` (not envelope failure) because
    /// the right passphrase unlocked the envelope but the HMAC no
    /// longer matches. This is the key distinction the new error
    /// taxonomy introduces.
    #[test]
    fn decrypt_with_tampered_stream_nonce_fails_at_hmac() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, pass) = encrypt_fixture("x", "pass")?;
        let mut bytes = fs::read(&fcr)?;
        // Flip one byte inside stream_nonce (offset 27 + 116 = 143).
        let nonce_offset = format::HEADER_PREFIX_ENCODED_SIZE + SYMMETRIC_ENVELOPE_SIZE;
        bytes[nonce_offset] ^= 0xFF;
        fs::write(&fcr, &bytes)?;
        match decrypt_file(&fcr, &dec_dir, &pass, None, &|_| {}) {
            Err(CryptoError::HeaderTampered) => Ok(()),
            other => panic!("expected HeaderTampered, got {other:?}"),
        }
    }

    /// Tampering inside the envelope's ciphertext (the
    /// `wrapped_file_key`) must surface at AEAD-open time as
    /// `SymmetricEnvelopeUnlockFailed`.
    #[test]
    fn decrypt_with_tampered_envelope_fails_at_unwrap() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, pass) = encrypt_fixture("x", "pass")?;
        let mut bytes = fs::read(&fcr)?;
        // Envelope layout inside the file starts at
        // format::HEADER_PREFIX_ENCODED_SIZE; wrapped_file_key starts after
        // salt(32) + kdf(12) + wrap_nonce(24) = 68 bytes.
        let wrapped_offset = format::HEADER_PREFIX_ENCODED_SIZE
            + ARGON2_SALT_SIZE
            + KDF_PARAMS_SIZE
            + WRAP_NONCE_SIZE;
        bytes[wrapped_offset] ^= 0x01;
        fs::write(&fcr, &bytes)?;
        match decrypt_file(&fcr, &dec_dir, &pass, None, &|_| {}) {
            Err(CryptoError::SymmetricEnvelopeUnlockFailed) => Ok(()),
            other => panic!("expected SymmetricEnvelopeUnlockFailed, got {other:?}"),
        }
    }

    /// A flipped byte in the replicated prefix is detected at
    /// canonicity-check time before any crypto runs — the specific
    /// diagnostic error carries the decoded view so callers can still
    /// say "upgrade FerroCrypt" on a bit-rotten newer file.
    #[test]
    fn decrypt_with_tampered_prefix_fails_at_canonicity() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, pass) = encrypt_fixture("x", "pass")?;
        let mut bytes = fs::read(&fcr)?;
        // Flip a single byte inside the middle copy (offset 12 = 3
        // pads + copy_0(8) + byte 1 of copy_1).
        bytes[12] ^= 0xFF;
        fs::write(&fcr, &bytes)?;
        match decrypt_file(&fcr, &dec_dir, &pass, None, &|_| {}) {
            Err(CryptoError::InvalidFormat(FormatDefect::CorruptedPrefix { .. })) => Ok(()),
            other => panic!("expected CorruptedPrefix, got {other:?}"),
        }
    }

    /// A truncated file (cut mid-STREAM) surfaces as
    /// `PayloadTruncated` or `PayloadTampered` depending on where the
    /// cut lands; either way, the header stage must have succeeded
    /// first. Confirms the header is independently authenticated.
    #[test]
    fn decrypt_truncated_payload_fails_after_header() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, pass) = encrypt_fixture("truncation test", "pass")?;
        let mut bytes = fs::read(&fcr)?;
        // Drop the last 16 bytes so the STREAM final-flag chunk's tag
        // is missing / mid-chunk.
        bytes.truncate(bytes.len() - 16);
        fs::write(&fcr, &bytes)?;
        match decrypt_file(&fcr, &dec_dir, &pass, None, &|_| {}) {
            Err(CryptoError::PayloadTruncated) | Err(CryptoError::PayloadTampered) => Ok(()),
            other => panic!("expected PayloadTruncated or PayloadTampered, got {other:?}"),
        }
    }
}
