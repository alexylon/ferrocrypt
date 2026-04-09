use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore, stream},
};
use crypto_box::{ChaChaBox, PublicKey, SecretKey, aead::AeadCore};
use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, Zeroizing};

use crate::common::{
    ARGON2_SALT_SIZE, DecryptReader, ENCRYPTION_KEY_SIZE, ERR_FILE_TOO_SHORT, EncryptWriter,
    HMAC_KEY_SIZE, HMAC_TAG_SIZE, KDF_PARAMS_SIZE, KdfParams, NONCE_SIZE, TAG_SIZE,
    get_encryption_base_name, hmac_sha3_256, hmac_sha3_256_verify,
};
use crate::format::{self, HEADER_PREFIX_ENCODED_SIZE, PUBLIC_KEY_DATA_SIZE, SECRET_KEY_DATA_SIZE};
use crate::replication::{rep_decode_exact, rep_encode, rep_encoded_size};
use crate::{CryptoError, archiver};

// Both keys are packed into a single envelope: [encryption_key | hmac_key]
const COMBINED_KEY_SIZE: usize = ENCRYPTION_KEY_SIZE + HMAC_KEY_SIZE;

const EPHEMERAL_PUB_SIZE: usize = 32;
const ENVELOPE_NONCE_SIZE: usize = 24;
const ENVELOPE_CIPHERTEXT_SIZE: usize = COMBINED_KEY_SIZE + TAG_SIZE;
const ENVELOPE_SIZE: usize = EPHEMERAL_PUB_SIZE + ENVELOPE_NONCE_SIZE + ENVELOPE_CIPHERTEXT_SIZE;

const SECRET_KEY_NONCE_SIZE: usize = 24;
const SECRET_KEY_SIZE: usize = 32;

const PUBLIC_KEY_FILENAME: &str = "public.key";
const SECRET_KEY_FILENAME: &str = "private.key";

// Compile-time guard: if crypto_box changes SecretKey's layout (fields added,
// removed, or reordered), this assertion fails and forces a review of the
// unsafe zeroization below. Verified against crypto_box 0.9.1 where SecretKey
// is [u8; 32] (bytes) + Scalar (32 bytes) = 64 bytes.
const _: () = assert!(size_of::<SecretKey>() == 64);

/// Zeroizes the entire `SecretKey` struct including the raw `bytes` field.
/// Upstream `Drop` (crypto_box 0.9.1) only zeroizes the `scalar` field,
/// leaving the 32-byte key material in `bytes` intact. This function
/// compensates by wiping all bytes of the struct via volatile writes.
fn zeroize_secret_key(key: &mut SecretKey) {
    // SAFETY: SecretKey is a plain data struct ([u8; 32] + Scalar) with no
    // pointer or reference fields. The size assertion above guarantees the
    // layout matches our expectation. Writing zeros via the zeroize crate's
    // volatile writes is safe and prevents the compiler from eliding them.
    unsafe {
        let ptr = key as *mut SecretKey as *mut u8;
        let len = size_of::<SecretKey>();
        std::slice::from_raw_parts_mut(ptr, len).zeroize();
    }
}

/// Internal RAII wrapper that guarantees full key zeroization on drop.
///
/// This keeps the `unsafe` wipe centralized and prevents call sites from
/// needing to remember explicit zeroization.
struct ManagedSecretKey(SecretKey);

impl ManagedSecretKey {
    fn new(key: SecretKey) -> Self {
        Self(key)
    }
}

impl std::ops::Deref for ManagedSecretKey {
    type Target = SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ManagedSecretKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ManagedSecretKey {
    fn drop(&mut self) {
        zeroize_secret_key(&mut self.0);
    }
}

pub fn encrypt_file(
    input_path: &Path,
    output_dir: &Path,
    public_key_path: &Path,
    output_file: Option<&Path>,
    on_progress: &dyn Fn(&str),
) -> Result<PathBuf, CryptoError> {
    let base_name = &get_encryption_base_name(input_path)?;
    on_progress("Encrypting\u{2026}");

    let mut encryption_key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let mut hmac_key = [0u8; HMAC_KEY_SIZE];
    OsRng.fill_bytes(&mut hmac_key);

    let output_path = match output_file {
        Some(path) => path.to_path_buf(),
        None => output_dir.join(format!("{}.{}", base_name, format::ENCRYPTED_EXTENSION)),
    };

    let mut file_created = false;

    let result = (|| -> Result<PathBuf, CryptoError> {
        let cipher = XChaCha20Poly1305::new(&encryption_key);

        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        let mut combined_key = Zeroizing::new(vec![0u8; COMBINED_KEY_SIZE]);
        combined_key[..ENCRYPTION_KEY_SIZE].copy_from_slice(&encryption_key);
        combined_key[ENCRYPTION_KEY_SIZE..].copy_from_slice(&hmac_key);

        let recipient_public = read_public_key(public_key_path)?;
        let envelope = seal_envelope(&combined_key, &recipient_public)?;

        if output_path.exists() {
            return Err(CryptoError::InvalidInput(format!(
                "Output file already exists: {}",
                output_path.display()
            )));
        }

        let encoded_envelope = rep_encode(&envelope);
        let encoded_nonce = rep_encode(&nonce);

        let header_len = (HEADER_PREFIX_ENCODED_SIZE
            + encoded_envelope.len()
            + encoded_nonce.len()
            + rep_encoded_size(HMAC_TAG_SIZE)) as u16;
        let prefix = format::build_header_prefix(format::TYPE_HYBRID, 0, header_len);
        let encoded_prefix = rep_encode(&prefix);

        let stream_encryptor = stream::EncryptorBE32::from_aead(cipher, nonce.as_ref().into());

        let mut hmac_message = Vec::with_capacity(prefix.len() + envelope.len() + nonce.len());
        hmac_message.extend_from_slice(&prefix);
        hmac_message.extend_from_slice(&envelope);
        hmac_message.extend_from_slice(&nonce);
        let hmac_tag = hmac_sha3_256(&hmac_key, &hmac_message)?;
        let encoded_hmac_tag = rep_encode(&hmac_tag);

        let mut dest = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(&output_path)?;
        file_created = true;

        dest.write_all(&encoded_prefix)?;
        dest.write_all(&encoded_envelope)?;
        dest.write_all(&encoded_nonce)?;
        dest.write_all(&encoded_hmac_tag)?;

        let encrypt_writer = EncryptWriter::new(stream_encryptor, dest);
        let (_, encrypt_writer) = archiver::archive(input_path, encrypt_writer)?;
        let dest = encrypt_writer.finish()?;
        dest.sync_all()?;

        nonce.zeroize();

        Ok(output_path.clone())
    })();

    if result.is_err() && file_created {
        let _ = fs::remove_file(&output_path);
    }

    encryption_key.zeroize();
    hmac_key.zeroize();
    result
}

pub fn decrypt_file(
    input_path: &Path,
    output_dir: &Path,
    secret_key_path: &Path,
    passphrase: &SecretString,
    on_progress: &dyn Fn(&str),
) -> Result<PathBuf, CryptoError> {
    on_progress("Decrypting\u{2026}");

    // Parse and validate the file header before loading the private key —
    // no point running Argon2id if the file is invalid.
    let mut encrypted_file = fs::File::open(input_path)?;

    let (prefix_bytes, header) =
        format::read_header_from_reader(&mut encrypted_file, format::TYPE_HYBRID)?;

    match header.major {
        3 => decrypt_file_v3(
            encrypted_file,
            prefix_bytes,
            header,
            output_dir,
            secret_key_path,
            passphrase,
            on_progress,
        ),
        _ => Err(format::unsupported_file_version_error(
            header.major,
            header.minor,
        )),
    }
}

// If a future 3.x minor introduces non-trivial behavior, add explicit gating here:
//   match header.minor { 0 => ..., 1 => ..., _ => unsupported }
// instead of relying solely on skip_unknown_header_bytes.
fn decrypt_file_v3(
    mut encrypted_file: fs::File,
    prefix_bytes: [u8; format::HEADER_PREFIX_SIZE],
    header: format::FileHeader,
    output_dir: &Path,
    secret_key_path: &Path,
    passphrase: &SecretString,
    _on_progress: &dyn Fn(&str),
) -> Result<PathBuf, CryptoError> {
    format::validate_file_flags(&header)?;

    let min_header_size = HEADER_PREFIX_ENCODED_SIZE
        + rep_encoded_size(ENVELOPE_SIZE)
        + rep_encoded_size(NONCE_SIZE)
        + rep_encoded_size(HMAC_TAG_SIZE);
    if (header.header_len as usize) < min_header_size {
        return Err(CryptoError::CryptoOperation(ERR_FILE_TOO_SHORT.to_string()));
    }

    let mut encoded_envelope = vec![0u8; rep_encoded_size(ENVELOPE_SIZE)];
    let mut encoded_nonce = vec![0u8; rep_encoded_size(NONCE_SIZE)];
    let mut encoded_hmac_tag = vec![0u8; rep_encoded_size(HMAC_TAG_SIZE)];

    encrypted_file
        .read_exact(&mut encoded_envelope)
        .map_err(|_| CryptoError::CryptoOperation(ERR_FILE_TOO_SHORT.to_string()))?;
    encrypted_file
        .read_exact(&mut encoded_nonce)
        .map_err(|_| CryptoError::CryptoOperation(ERR_FILE_TOO_SHORT.to_string()))?;
    encrypted_file
        .read_exact(&mut encoded_hmac_tag)
        .map_err(|_| CryptoError::CryptoOperation(ERR_FILE_TOO_SHORT.to_string()))?;

    let bytes_after_prefix = encoded_envelope.len() + encoded_nonce.len() + encoded_hmac_tag.len();
    format::skip_unknown_header_bytes(&mut encrypted_file, header.header_len, bytes_after_prefix)?;

    let envelope_vec = rep_decode_exact(&encoded_envelope, ENVELOPE_SIZE)?;
    let nonce = rep_decode_exact(&encoded_nonce, NONCE_SIZE)?;
    let hmac_tag = rep_decode_exact(&encoded_hmac_tag, HMAC_TAG_SIZE)?;

    let envelope: [u8; ENVELOPE_SIZE] = envelope_vec
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::CryptoOperation("Envelope has unexpected length".to_string()))?;

    let recipient_secret = read_secret_key(secret_key_path, passphrase)?;
    let envelope_result = open_envelope(&envelope, &recipient_secret);
    drop(recipient_secret);
    let mut decrypted_combined_key = envelope_result?;

    let result = (|| -> Result<PathBuf, CryptoError> {
        let hmac_key = &decrypted_combined_key[ENCRYPTION_KEY_SIZE..COMBINED_KEY_SIZE];

        let mut hmac_message =
            Vec::with_capacity(prefix_bytes.len() + envelope.len() + nonce.len());
        hmac_message.extend_from_slice(&prefix_bytes);
        hmac_message.extend_from_slice(&envelope);
        hmac_message.extend_from_slice(&nonce);
        hmac_sha3_256_verify(hmac_key, &hmac_message, &hmac_tag)?;

        let cipher =
            XChaCha20Poly1305::new((&decrypted_combined_key[..ENCRYPTION_KEY_SIZE]).into());
        let stream_decryptor = stream::DecryptorBE32::from_aead(cipher, nonce.as_slice().into());

        let decrypt_reader = DecryptReader::new(stream_decryptor, encrypted_file);
        archiver::unarchive(decrypt_reader, output_dir)
    })();

    decrypted_combined_key.zeroize();
    result
}

fn read_public_key(path: &Path) -> Result<PublicKey, CryptoError> {
    let data = fs::read(path)?;
    let header = format::parse_key_file_header(&data, format::KEY_FILE_TYPE_PUBLIC)?;
    match header.version {
        2 => read_public_key_v2(&data, &header),
        _ => Err(format::unsupported_key_version_error(header.version)),
    }
}

fn read_public_key_v2(
    data: &[u8],
    header: &format::ParsedKeyHeader,
) -> Result<PublicKey, CryptoError> {
    format::validate_key_v2_layout(data, header, PUBLIC_KEY_DATA_SIZE)?;
    let body_start = format::KEY_FILE_HEADER_SIZE;
    let mut key_bytes = [0u8; PUBLIC_KEY_DATA_SIZE];
    key_bytes.copy_from_slice(&data[body_start..body_start + PUBLIC_KEY_DATA_SIZE]);
    Ok(PublicKey::from(key_bytes))
}

fn read_secret_key(
    path: &Path,
    passphrase: &SecretString,
) -> Result<ManagedSecretKey, CryptoError> {
    let data = fs::read(path)?;
    let header = format::parse_key_file_header(&data, format::KEY_FILE_TYPE_SECRET)?;
    match header.version {
        2 => read_secret_key_v2(&data, &header, passphrase),
        _ => Err(format::unsupported_key_version_error(header.version)),
    }
}

fn read_secret_key_v2(
    data: &[u8],
    header: &format::ParsedKeyHeader,
    passphrase: &SecretString,
) -> Result<ManagedSecretKey, CryptoError> {
    format::validate_key_v2_layout(data, header, SECRET_KEY_DATA_SIZE)?;

    let body_start = format::KEY_FILE_HEADER_SIZE;
    let body = &data[body_start..body_start + SECRET_KEY_DATA_SIZE];
    let kdf_params = KdfParams::from_bytes(body[..KDF_PARAMS_SIZE].try_into()?)?;
    let salt = &body[KDF_PARAMS_SIZE..KDF_PARAMS_SIZE + ARGON2_SALT_SIZE];
    let nonce = chacha20poly1305::XNonce::from_slice(
        &body[KDF_PARAMS_SIZE + ARGON2_SALT_SIZE
            ..KDF_PARAMS_SIZE + ARGON2_SALT_SIZE + SECRET_KEY_NONCE_SIZE],
    );
    let ciphertext = &body[KDF_PARAMS_SIZE + ARGON2_SALT_SIZE + SECRET_KEY_NONCE_SIZE..];

    let derived_key = kdf_params.hash_passphrase(passphrase.expose_secret().as_bytes(), salt)?;

    let cipher = XChaCha20Poly1305::new(derived_key.as_ref().into());
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        CryptoError::CryptoOperation("Incorrect password or wrong private key provided".to_string())
    })?;

    drop(derived_key);

    let mut secret_bytes: [u8; SECRET_KEY_SIZE] =
        plaintext.as_slice().try_into().map_err(|_| {
            CryptoError::CryptoOperation("Decrypted key has unexpected length".to_string())
        })?;
    let mut plaintext = plaintext;
    plaintext.zeroize();

    let key = ManagedSecretKey::new(SecretKey::from(secret_bytes));
    secret_bytes.zeroize();
    Ok(key)
}

fn seal_envelope(
    combined_key: &[u8],
    recipient_public: &PublicKey,
) -> Result<[u8; ENVELOPE_SIZE], CryptoError> {
    let ephemeral_secret = ManagedSecretKey::new(SecretKey::generate(&mut OsRng));
    let ephemeral_public = ephemeral_secret.public_key();
    let chacha_box = ChaChaBox::new(recipient_public, &ephemeral_secret);
    drop(ephemeral_secret);
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let ciphertext = chacha_box
        .encrypt(&nonce, combined_key)
        .map_err(|_| CryptoError::CryptoOperation("Envelope encryption failed".to_string()))?;

    let mut envelope = [0u8; ENVELOPE_SIZE];
    envelope[..EPHEMERAL_PUB_SIZE].copy_from_slice(ephemeral_public.as_bytes());
    envelope[EPHEMERAL_PUB_SIZE..EPHEMERAL_PUB_SIZE + ENVELOPE_NONCE_SIZE].copy_from_slice(&nonce);
    envelope[EPHEMERAL_PUB_SIZE + ENVELOPE_NONCE_SIZE..].copy_from_slice(&ciphertext);
    Ok(envelope)
}

fn open_envelope(
    envelope: &[u8; ENVELOPE_SIZE],
    recipient_secret: &SecretKey,
) -> Result<[u8; COMBINED_KEY_SIZE], CryptoError> {
    let ephemeral_public =
        PublicKey::from_slice(&envelope[..EPHEMERAL_PUB_SIZE]).map_err(|_| {
            CryptoError::CryptoOperation("Invalid ephemeral public key in envelope".to_string())
        })?;
    let nonce = chacha20poly1305::XNonce::from_slice(
        &envelope[EPHEMERAL_PUB_SIZE..EPHEMERAL_PUB_SIZE + ENVELOPE_NONCE_SIZE],
    );
    let ciphertext = &envelope[EPHEMERAL_PUB_SIZE + ENVELOPE_NONCE_SIZE..];

    let chacha_box = ChaChaBox::new(&ephemeral_public, recipient_secret);
    let mut plaintext = chacha_box.decrypt(nonce, ciphertext).map_err(|_| {
        CryptoError::CryptoOperation(
            "Envelope decryption failed: wrong key or corrupted data".to_string(),
        )
    })?;

    if plaintext.len() != COMBINED_KEY_SIZE {
        plaintext.zeroize();
        return Err(CryptoError::CryptoOperation(
            "Decrypted envelope has unexpected length".to_string(),
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
    on_progress: &dyn Fn(&str),
) -> Result<(PathBuf, PathBuf), CryptoError> {
    if passphrase.expose_secret().is_empty() {
        return Err(CryptoError::InvalidInput(
            "Passphrase must not be empty for private key encryption".to_string(),
        ));
    }
    fs::create_dir_all(output_dir)?;
    on_progress("Generating key pair…");

    let secret_key = ManagedSecretKey::new(SecretKey::generate(&mut OsRng));
    let public_key = secret_key.public_key();

    // Encrypt private key at rest with passphrase via Argon2id + XChaCha20-Poly1305
    let kdf_params = KdfParams::default_params();
    let kdf_bytes = kdf_params.to_bytes();
    let mut salt = [0u8; ARGON2_SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let derived_key = kdf_params.hash_passphrase(passphrase.expose_secret().as_bytes(), &salt)?;

    let cipher = XChaCha20Poly1305::new(derived_key.as_ref().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let raw_secret = Zeroizing::new(secret_key.to_bytes());
    drop(secret_key);
    let encrypted_secret = cipher
        .encrypt(&nonce, raw_secret.as_slice())
        .map_err(|_| CryptoError::CryptoOperation("Failed to encrypt private key".to_string()))?;
    drop(raw_secret);
    drop(derived_key);

    let secret_header =
        format::build_key_file_header(format::KEY_FILE_TYPE_SECRET, SECRET_KEY_DATA_SIZE as u16);
    let public_header =
        format::build_key_file_header(format::KEY_FILE_TYPE_PUBLIC, PUBLIC_KEY_DATA_SIZE as u16);

    let secret_key_path = output_dir.join(SECRET_KEY_FILENAME);
    let public_key_path = output_dir.join(PUBLIC_KEY_FILENAME);
    let tmp_secret = output_dir.join(".private.key.tmp");
    let tmp_public = output_dir.join(".public.key.tmp");

    if secret_key_path.exists() {
        return Err(CryptoError::InvalidInput(format!(
            "Key file already exists: {}",
            secret_key_path.display()
        )));
    }
    if public_key_path.exists() {
        return Err(CryptoError::InvalidInput(format!(
            "Key file already exists: {}",
            public_key_path.display()
        )));
    }

    // Clean up stale temp files from a previous crashed run
    let _ = fs::remove_file(&tmp_secret);
    let _ = fs::remove_file(&tmp_public);

    // Write both key files to temp names first, then rename atomically.
    // If anything fails, clean up temp files so no partial state remains.
    let write_result: Result<(), CryptoError> = (|| {
        let mut secret_key_opts = OpenOptions::new();
        secret_key_opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            secret_key_opts.mode(0o600);
        }
        let mut secret_key_file = secret_key_opts.open(&tmp_secret)?;
        secret_key_file.write_all(&secret_header)?;
        secret_key_file.write_all(&kdf_bytes)?;
        secret_key_file.write_all(&salt)?;
        secret_key_file.write_all(&nonce)?;
        secret_key_file.write_all(&encrypted_secret)?;

        let mut public_key_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_public)?;
        public_key_file.write_all(&public_header)?;
        public_key_file.write_all(public_key.as_bytes())?;

        fs::rename(&tmp_secret, &secret_key_path)?;
        if let Err(e) = fs::rename(&tmp_public, &public_key_path) {
            let _ = fs::remove_file(&secret_key_path);
            return Err(e.into());
        }
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp_secret);
        let _ = fs::remove_file(&tmp_public);
        return Err(e);
    }

    Ok((secret_key_path, public_key_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Proves the forward-compatibility mechanism for hybrid files: a synthetic
    /// v3.1 file with extra trailing header bytes (and correctly recomputed HMAC)
    /// is decrypted successfully by the current v3 reader.
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

        // --- Decode the v3.0 header ---
        let encoded_prefix = &original[..HEADER_PREFIX_ENCODED_SIZE];
        let prefix_bytes = rep_decode_exact(encoded_prefix, format::HEADER_PREFIX_SIZE)?;
        let old_header_len = u16::from_be_bytes([prefix_bytes[4], prefix_bytes[5]]) as usize;

        let mut cursor = Cursor::new(&original[HEADER_PREFIX_ENCODED_SIZE..]);
        let mut enc_envelope = vec![0u8; rep_encoded_size(ENVELOPE_SIZE)];
        let mut enc_nonce = vec![0u8; rep_encoded_size(NONCE_SIZE)];
        let mut enc_hmac = vec![0u8; rep_encoded_size(HMAC_TAG_SIZE)];
        cursor.read_exact(&mut enc_envelope)?;
        cursor.read_exact(&mut enc_nonce)?;
        cursor.read_exact(&mut enc_hmac)?;

        let envelope_vec = rep_decode_exact(&enc_envelope, ENVELOPE_SIZE)?;
        let nonce = rep_decode_exact(&enc_nonce, NONCE_SIZE)?;
        let envelope: [u8; ENVELOPE_SIZE] = envelope_vec.as_slice().try_into().unwrap();

        // Open envelope to get the HMAC key
        let secret = read_secret_key(&keys_dir.join(SECRET_KEY_FILENAME), &key_pass)?;
        let decrypted = open_envelope(&envelope, &secret)?;
        drop(secret);
        let hmac_key = &decrypted[ENCRYPTION_KEY_SIZE..COMBINED_KEY_SIZE];

        // --- Build a synthetic v3.1 prefix with larger header_len ---
        let extra_bytes = 16usize;
        let new_header_len = (old_header_len + extra_bytes) as u16;
        let new_prefix = [
            format::MAGIC_BYTE,
            format::TYPE_HYBRID,
            format::ENCRYPTED_FILE_VERSION_MAJOR,
            1, // minor = 1
            (new_header_len >> 8) as u8,
            (new_header_len & 0xFF) as u8,
            0,
            0,
        ];

        // --- Recompute HMAC over the new prefix + same decoded fields ---
        let mut hmac_message = Vec::new();
        hmac_message.extend_from_slice(&new_prefix);
        hmac_message.extend_from_slice(&envelope);
        hmac_message.extend_from_slice(&nonce);
        let new_hmac_tag = hmac_sha3_256(hmac_key, &hmac_message)?;

        // --- Reassemble: new prefix + same fields + new HMAC + trailing + ciphertext ---
        let ciphertext = &original[old_header_len..];
        let mut output = Vec::new();
        output.extend_from_slice(&rep_encode(&new_prefix));
        output.extend_from_slice(&enc_envelope);
        output.extend_from_slice(&enc_nonce);
        output.extend_from_slice(&rep_encode(&new_hmac_tag));
        output.extend_from_slice(&vec![0xBB; extra_bytes]);
        output.extend_from_slice(ciphertext);

        fs::write(&encrypted_path, &output)?;

        // --- Decrypt with the current v3 reader ---
        let output = decrypt_file(
            &encrypted_path,
            &decrypt_dir,
            &keys_dir.join(SECRET_KEY_FILENAME),
            &key_pass,
            &|_| {},
        )?;
        assert!(output.exists());

        let decrypted_content = fs::read_to_string(decrypt_dir.join("data.txt"))?;
        assert_eq!(decrypted_content, "hybrid forward compat test");

        Ok(())
    }
}
