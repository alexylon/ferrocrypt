use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
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

use crate::common::{
    ARGON2_SALT_SIZE, DecryptReader, ENCRYPTION_KEY_SIZE, EncryptWriter, FILE_TOO_SHORT,
    HMAC_KEY_SIZE, HMAC_TAG_SIZE, KDF_PARAMS_SIZE, KdfLimit, KdfParams, STREAM_NONCE_SIZE,
    TAG_SIZE, ct_eq_32, encryption_base_name, hmac_sha3_256, hmac_sha3_256_verify,
};
use crate::format::{self, HEADER_PREFIX_ENCODED_SIZE, PUBLIC_KEY_DATA_SIZE, SECRET_KEY_DATA_SIZE};
use crate::replication::{decode_exact, encode, encoded_size};
use crate::{CryptoError, archiver};

// Both keys are packed into a single envelope: [encryption_key | hmac_key]
const COMBINED_KEY_SIZE: usize = ENCRYPTION_KEY_SIZE + HMAC_KEY_SIZE;

const EPHEMERAL_PUB_SIZE: usize = 32;
const ENVELOPE_NONCE_SIZE: usize = 24;
const ENVELOPE_CIPHERTEXT_SIZE: usize = COMBINED_KEY_SIZE + TAG_SIZE;
const ENVELOPE_SIZE: usize = EPHEMERAL_PUB_SIZE + ENVELOPE_NONCE_SIZE + ENVELOPE_CIPHERTEXT_SIZE;

const SECRET_KEY_NONCE_SIZE: usize = 24;
const SECRET_KEY_SIZE: usize = 32;

pub const PUBLIC_KEY_FILENAME: &str = "public.key";
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
        .map_err(|_| CryptoError::InternalError("Envelope HKDF expand failed".to_string()))?;
    Ok(key)
}

/// Detects all-zero X25519 shared secrets (small-order public key defense).
/// Uses constant-time comparison to avoid timing side channels.
fn shared_secret_is_all_zero(shared: &[u8; 32]) -> bool {
    ct_eq_32(shared, &[0u8; 32])
}

pub fn encrypt_file(
    input_path: &Path,
    output_dir: &Path,
    public_key_path: &Path,
    output_file: Option<&Path>,
    on_progress: &dyn Fn(&str),
) -> Result<PathBuf, CryptoError> {
    let recipient_public = read_public_key(public_key_path)?;
    encrypt_file_inner(
        input_path,
        output_dir,
        &recipient_public,
        output_file,
        on_progress,
    )
}

pub fn encrypt_file_from_bytes(
    input_path: &Path,
    output_dir: &Path,
    public_key_bytes: &[u8; 32],
    output_file: Option<&Path>,
    on_progress: &dyn Fn(&str),
) -> Result<PathBuf, CryptoError> {
    let recipient_public = PublicKey::from(*public_key_bytes);
    encrypt_file_inner(
        input_path,
        output_dir,
        &recipient_public,
        output_file,
        on_progress,
    )
}

fn encrypt_file_inner(
    input_path: &Path,
    output_dir: &Path,
    recipient_public: &PublicKey,
    output_file: Option<&Path>,
    on_progress: &dyn Fn(&str),
) -> Result<PathBuf, CryptoError> {
    let base_name = &encryption_base_name(input_path)?;
    on_progress("Encrypting\u{2026}");

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
    let mut working_name = output_path.as_os_str().to_os_string();
    working_name.push(".incomplete");
    let working_path = PathBuf::from(working_name);
    if working_path.exists() {
        return Err(CryptoError::InvalidInput(format!(
            "Previous .incomplete exists: {}",
            working_path.display()
        )));
    }

    let mut encryption_key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let mut hmac_key = [0u8; HMAC_KEY_SIZE];
    OsRng.fill_bytes(&mut hmac_key);

    let mut file_created = false;
    let result = (|| -> Result<(), CryptoError> {
        let cipher = XChaCha20Poly1305::new(&encryption_key);

        let mut nonce = [0u8; STREAM_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        let mut combined_key = Zeroizing::new(vec![0u8; COMBINED_KEY_SIZE]);
        combined_key[..ENCRYPTION_KEY_SIZE].copy_from_slice(&encryption_key);
        combined_key[ENCRYPTION_KEY_SIZE..].copy_from_slice(&hmac_key);

        let envelope = seal_envelope(&combined_key, recipient_public)?;

        let encoded_envelope = encode(&envelope);
        let encoded_nonce = encode(&nonce);

        let header_len = (HEADER_PREFIX_ENCODED_SIZE
            + encoded_envelope.len()
            + encoded_nonce.len()
            + encoded_size(HMAC_TAG_SIZE)) as u16;
        let prefix = format::build_header_prefix(
            format::TYPE_HYBRID,
            format::HYBRID_VERSION_MAJOR,
            0,
            header_len,
        );
        let encoded_prefix = encode(&prefix);

        let stream_encryptor = stream::EncryptorBE32::from_aead(cipher, nonce.as_ref().into());

        let mut hmac_message = Vec::with_capacity(prefix.len() + envelope.len() + nonce.len());
        hmac_message.extend_from_slice(&prefix);
        hmac_message.extend_from_slice(&envelope);
        hmac_message.extend_from_slice(&nonce);
        let hmac_tag = hmac_sha3_256(&hmac_key, &hmac_message)?;
        let encoded_hmac_tag = encode(&hmac_tag);

        let mut dest = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(&working_path)?;
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
        Ok(())
    })();

    if let Err(e) = result {
        if file_created {
            let _ = fs::remove_file(&working_path);
        }
        encryption_key.zeroize();
        hmac_key.zeroize();
        return Err(e);
    }

    encryption_key.zeroize();
    hmac_key.zeroize();
    archiver::rename_no_clobber(&working_path, &output_path)?;
    Ok(output_path)
}

pub fn decrypt_file(
    input_path: &Path,
    output_dir: &Path,
    secret_key_path: &Path,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
    on_progress: &dyn Fn(&str),
) -> Result<PathBuf, CryptoError> {
    on_progress("Decrypting\u{2026}");

    let mut encrypted_file = fs::File::open(input_path)?;

    let (prefix_bytes, header) =
        format::read_header_from_reader(&mut encrypted_file, format::TYPE_HYBRID)?;

    match header.major {
        4 => decrypt_file_v4(
            encrypted_file,
            prefix_bytes,
            header,
            output_dir,
            secret_key_path,
            passphrase,
            kdf_limit,
            on_progress,
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
    secret_key_path: &Path,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
    _on_progress: &dyn Fn(&str),
) -> Result<PathBuf, CryptoError> {
    format::validate_file_flags(&header)?;

    let min_header_size = HEADER_PREFIX_ENCODED_SIZE
        + encoded_size(ENVELOPE_SIZE)
        + encoded_size(STREAM_NONCE_SIZE)
        + encoded_size(HMAC_TAG_SIZE);
    if (header.header_len as usize) < min_header_size {
        return Err(CryptoError::InvalidFormat(FILE_TOO_SHORT.to_string()));
    }

    let mut encoded_envelope = vec![0u8; encoded_size(ENVELOPE_SIZE)];
    let mut encoded_nonce = vec![0u8; encoded_size(STREAM_NONCE_SIZE)];
    let mut encoded_hmac_tag = vec![0u8; encoded_size(HMAC_TAG_SIZE)];

    encrypted_file
        .read_exact(&mut encoded_envelope)
        .map_err(|_| CryptoError::InvalidFormat(FILE_TOO_SHORT.to_string()))?;
    encrypted_file
        .read_exact(&mut encoded_nonce)
        .map_err(|_| CryptoError::InvalidFormat(FILE_TOO_SHORT.to_string()))?;
    encrypted_file
        .read_exact(&mut encoded_hmac_tag)
        .map_err(|_| CryptoError::InvalidFormat(FILE_TOO_SHORT.to_string()))?;

    let bytes_after_prefix = encoded_envelope.len() + encoded_nonce.len() + encoded_hmac_tag.len();
    format::skip_unknown_header_bytes(&mut encrypted_file, header.header_len, bytes_after_prefix)?;

    let envelope_vec = decode_exact(&encoded_envelope, ENVELOPE_SIZE)?;
    let nonce = decode_exact(&encoded_nonce, STREAM_NONCE_SIZE)?;
    let hmac_tag = decode_exact(&encoded_hmac_tag, HMAC_TAG_SIZE)?;

    let envelope: [u8; ENVELOPE_SIZE] = envelope_vec
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat("Envelope has unexpected length".to_string()))?;

    let recipient_secret = read_secret_key(secret_key_path, passphrase, kdf_limit)?;
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
        2 | 3 => read_public_key_data(&data, &header),
        _ => Err(format::unsupported_key_version_error(header.version)),
    }
}

fn read_public_key_data(
    data: &[u8],
    header: &format::KeyFileHeader,
) -> Result<PublicKey, CryptoError> {
    format::validate_key_v2_layout(data, header, PUBLIC_KEY_DATA_SIZE)?;
    let body_start = format::KEY_FILE_HEADER_SIZE;
    let key_bytes: [u8; PUBLIC_KEY_DATA_SIZE] = data[body_start..body_start + PUBLIC_KEY_DATA_SIZE]
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat("Invalid public key data".to_string()))?;
    Ok(PublicKey::from(key_bytes))
}

fn read_secret_key(
    path: &Path,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
) -> Result<StaticSecret, CryptoError> {
    let data = fs::read(path)?;
    let header = format::parse_key_file_header(&data, format::KEY_FILE_TYPE_SECRET)?;
    match header.version {
        2 | 3 => read_secret_key_data(&data, &header, passphrase, kdf_limit),
        _ => Err(format::unsupported_key_version_error(header.version)),
    }
}

fn read_secret_key_data(
    data: &[u8],
    header: &format::KeyFileHeader,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
) -> Result<StaticSecret, CryptoError> {
    format::validate_key_v2_layout(data, header, SECRET_KEY_DATA_SIZE)?;

    let body_start = format::KEY_FILE_HEADER_SIZE;
    let body = &data[body_start..body_start + SECRET_KEY_DATA_SIZE];
    let kdf_params = KdfParams::from_bytes(body[..KDF_PARAMS_SIZE].try_into()?, kdf_limit)?;
    let salt = &body[KDF_PARAMS_SIZE..KDF_PARAMS_SIZE + ARGON2_SALT_SIZE];
    let nonce = chacha20poly1305::XNonce::from_slice(
        &body[KDF_PARAMS_SIZE + ARGON2_SALT_SIZE
            ..KDF_PARAMS_SIZE + ARGON2_SALT_SIZE + SECRET_KEY_NONCE_SIZE],
    );
    let ciphertext = &body[KDF_PARAMS_SIZE + ARGON2_SALT_SIZE + SECRET_KEY_NONCE_SIZE..];

    let derived_key = kdf_params.hash_passphrase(passphrase.expose_secret().as_bytes(), salt)?;

    let cipher = XChaCha20Poly1305::new(derived_key.as_ref().into());
    let mut plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    drop(derived_key);

    if plaintext.len() != SECRET_KEY_SIZE {
        plaintext.zeroize();
        return Err(CryptoError::InvalidFormat(
            "Decrypted key has unexpected length".to_string(),
        ));
    }

    let mut secret_bytes = [0u8; SECRET_KEY_SIZE];
    secret_bytes.copy_from_slice(&plaintext);
    plaintext.zeroize();

    let key = StaticSecret::from(secret_bytes);
    secret_bytes.zeroize();
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
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, combined_key)
        .map_err(|_| CryptoError::InternalError("Envelope encryption failed".to_string()))?;

    let mut envelope = [0u8; ENVELOPE_SIZE];
    envelope[..EPHEMERAL_PUB_SIZE].copy_from_slice(ephemeral_public.as_bytes());
    envelope[EPHEMERAL_PUB_SIZE..EPHEMERAL_PUB_SIZE + ENVELOPE_NONCE_SIZE].copy_from_slice(&nonce);
    envelope[EPHEMERAL_PUB_SIZE + ENVELOPE_NONCE_SIZE..].copy_from_slice(&ciphertext);
    Ok(envelope)
}

fn open_envelope(
    envelope: &[u8; ENVELOPE_SIZE],
    recipient_secret: &StaticSecret,
) -> Result<[u8; COMBINED_KEY_SIZE], CryptoError> {
    let ephemeral_public_bytes: [u8; EPHEMERAL_PUB_SIZE] =
        envelope[..EPHEMERAL_PUB_SIZE].try_into().map_err(|_| {
            CryptoError::InvalidFormat("Invalid ephemeral public key in envelope".to_string())
        })?;
    let ephemeral_public = PublicKey::from(ephemeral_public_bytes);

    let nonce = chacha20poly1305::XNonce::from_slice(
        &envelope[EPHEMERAL_PUB_SIZE..EPHEMERAL_PUB_SIZE + ENVELOPE_NONCE_SIZE],
    );
    let ciphertext = &envelope[EPHEMERAL_PUB_SIZE + ENVELOPE_NONCE_SIZE..];

    let shared = recipient_secret.diffie_hellman(&ephemeral_public);
    if shared_secret_is_all_zero(shared.as_bytes()) {
        return Err(CryptoError::AuthenticationFailed);
    }

    let recipient_public = PublicKey::from(recipient_secret);
    let wrapping_key =
        derive_envelope_key(&ephemeral_public, &recipient_public, shared.as_bytes())?;

    let cipher = XChaCha20Poly1305::new(wrapping_key.as_ref().into());
    let mut plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    if plaintext.len() != COMBINED_KEY_SIZE {
        plaintext.zeroize();
        return Err(CryptoError::InvalidFormat(
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

    let secret_key = StaticSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&secret_key);

    // Encrypt private key at rest with passphrase via Argon2id + XChaCha20-Poly1305
    let kdf_params = KdfParams::default();
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
        .map_err(|_| CryptoError::InternalError("Failed to encrypt private key".to_string()))?;
    drop(raw_secret);
    drop(derived_key);

    let secret_header =
        format::build_key_file_header(format::KEY_FILE_TYPE_SECRET, SECRET_KEY_DATA_SIZE as u16);
    let public_header =
        format::build_key_file_header(format::KEY_FILE_TYPE_PUBLIC, PUBLIC_KEY_DATA_SIZE as u16);

    let secret_key_path = output_dir.join(PRIVATE_KEY_FILENAME);
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
        secret_key_file.sync_all()?;

        let mut public_key_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_public)?;
        public_key_file.write_all(&public_header)?;
        public_key_file.write_all(public_key.as_bytes())?;
        public_key_file.sync_all()?;

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
    /// v4.1 file with extra trailing header bytes (and correctly recomputed HMAC)
    /// is decrypted successfully by the current v4 reader.
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

        // --- Decode the v4.0 header ---
        let encoded_prefix = &original[..HEADER_PREFIX_ENCODED_SIZE];
        let prefix_bytes = decode_exact(encoded_prefix, format::HEADER_PREFIX_SIZE)?;
        let old_header_len = u16::from_be_bytes([prefix_bytes[4], prefix_bytes[5]]) as usize;

        let mut cursor = Cursor::new(&original[HEADER_PREFIX_ENCODED_SIZE..]);
        let mut enc_envelope = vec![0u8; encoded_size(ENVELOPE_SIZE)];
        let mut enc_nonce = vec![0u8; encoded_size(STREAM_NONCE_SIZE)];
        let mut enc_hmac = vec![0u8; encoded_size(HMAC_TAG_SIZE)];
        cursor.read_exact(&mut enc_envelope)?;
        cursor.read_exact(&mut enc_nonce)?;
        cursor.read_exact(&mut enc_hmac)?;

        let envelope_vec = decode_exact(&enc_envelope, ENVELOPE_SIZE)?;
        let nonce = decode_exact(&enc_nonce, STREAM_NONCE_SIZE)?;
        let envelope: [u8; ENVELOPE_SIZE] = envelope_vec.as_slice().try_into().unwrap();

        // Open envelope to get the HMAC key
        let secret = read_secret_key(&keys_dir.join(PRIVATE_KEY_FILENAME), &key_pass, None)?;
        let decrypted = open_envelope(&envelope, &secret)?;
        drop(secret);
        let hmac_key = &decrypted[ENCRYPTION_KEY_SIZE..COMBINED_KEY_SIZE];

        // --- Build a synthetic v4.1 prefix with larger header_len ---
        let extra_bytes = 16usize;
        let new_header_len = (old_header_len + extra_bytes) as u16;
        let new_prefix = [
            format::MAGIC_BYTE,
            format::TYPE_HYBRID,
            format::HYBRID_VERSION_MAJOR,
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
        output.extend_from_slice(&encode(&new_prefix));
        output.extend_from_slice(&enc_envelope);
        output.extend_from_slice(&enc_nonce);
        output.extend_from_slice(&encode(&new_hmac_tag));
        output.extend_from_slice(&vec![0xBB; extra_bytes]);
        output.extend_from_slice(ciphertext);

        fs::write(&encrypted_path, &output)?;

        // --- Decrypt with the current v4 reader ---
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

        let secret = StaticSecret::random_from_rng(OsRng);
        let result = open_envelope(&envelope, &secret);
        assert!(result.is_err());
    }

    /// Envelope round-trip: seal with a recipient's public key, open with the
    /// matching secret key, verify the combined key is recovered exactly.
    #[test]
    fn seal_open_envelope_round_trip() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        let mut combined_key = [0u8; COMBINED_KEY_SIZE];
        OsRng.fill_bytes(&mut combined_key);

        let envelope = seal_envelope(&combined_key, &public).unwrap();
        let recovered = open_envelope(&envelope, &secret).unwrap();
        assert_eq!(combined_key, recovered);
    }

    /// Wrong secret key must fail to open an envelope.
    #[test]
    fn open_envelope_wrong_key_fails() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let wrong_secret = StaticSecret::random_from_rng(OsRng);

        let combined_key = [0xBB; COMBINED_KEY_SIZE];
        let envelope = seal_envelope(&combined_key, &public).unwrap();
        let result = open_envelope(&envelope, &wrong_secret);
        assert!(result.is_err());
    }

    /// Well-sized but garbage envelope bytes must fail AEAD decryption.
    #[test]
    fn garbage_envelope_fails() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let mut garbage = [0xCC; ENVELOPE_SIZE];
        // Put a valid-looking (but wrong) public key so DH doesn't produce all-zero
        let decoy_pk = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        garbage[..EPHEMERAL_PUB_SIZE].copy_from_slice(decoy_pk.as_bytes());

        let result = open_envelope(&garbage, &secret);
        assert!(result.is_err());
    }

    /// Flipping one bit in an otherwise valid envelope must fail.
    #[test]
    fn envelope_single_bit_flip_detected() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let combined_key = [0xAA; COMBINED_KEY_SIZE];

        let mut envelope = seal_envelope(&combined_key, &public).unwrap();
        // Flip one bit in the ciphertext region
        envelope[EPHEMERAL_PUB_SIZE + ENVELOPE_NONCE_SIZE + 10] ^= 0x01;

        let result = open_envelope(&envelope, &secret);
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
}
