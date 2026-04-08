use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{KeyInit, OsRng, rand_core::RngCore, stream},
};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretString};
use sha3::Sha3_256;
use zeroize::Zeroizing;

use crate::common::{
    ARGON2_SALT_SIZE, DecryptReader, ENCRYPTION_KEY_SIZE, ERR_FILE_TOO_SHORT, EncryptWriter,
    HMAC_KEY_SIZE, HMAC_TAG_SIZE, KDF_PARAMS_SIZE, KdfParams, NONCE_SIZE,
    constant_time_compare_256_bit, get_duration, get_encryption_base_name, hmac_sha3_256,
    hmac_sha3_256_verify, sha3_32_hash,
};
use crate::format::{self, HEADER_PREFIX_ENCODED_SIZE};
use crate::replication::{rep_decode_exact, rep_encode, rep_encoded_size};
use crate::{CryptoError, archiver};

const HKDF_SALT_SIZE: usize = 32;
const HKDF_INFO_ENC: &[u8] = b"ferrocrypt-enc";
const HKDF_INFO_HMAC: &[u8] = b"ferrocrypt-hmac";

type DerivedKeys = (
    Zeroizing<[u8; ENCRYPTION_KEY_SIZE]>,
    Zeroizing<[u8; HMAC_KEY_SIZE]>,
);

/// Derives domain-separated encryption and HMAC subkeys from a passphrase.
///
/// Pipeline: passphrase + salt → Argon2id (32 bytes IKM) → HKDF-SHA3-256 → (encryption_key, hmac_key)
fn derive_keys(
    passphrase: &SecretString,
    salt: &[u8],
    hkdf_salt: &[u8],
    kdf_params: &KdfParams,
) -> Result<DerivedKeys, CryptoError> {
    let argon2_config = kdf_params.to_argon2_config();
    let ikm = Zeroizing::new(argon2::hash_raw(
        passphrase.expose_secret().as_bytes(),
        salt,
        &argon2_config,
    )?);

    let hkdf = Hkdf::<Sha3_256>::new(Some(hkdf_salt), &ikm);
    let mut encryption_key = Zeroizing::new([0u8; ENCRYPTION_KEY_SIZE]);
    let mut hmac_key = Zeroizing::new([0u8; HMAC_KEY_SIZE]);
    hkdf.expand(HKDF_INFO_ENC, encryption_key.as_mut())
        .map_err(|_| {
            CryptoError::CryptoOperation("HKDF expand failed for encryption key".to_string())
        })?;
    hkdf.expand(HKDF_INFO_HMAC, hmac_key.as_mut())
        .map_err(|_| CryptoError::CryptoOperation("HKDF expand failed for HMAC key".to_string()))?;

    Ok((encryption_key, hmac_key))
}

/// Encrypts a file or directory with XChaCha20-Poly1305 streaming encryption.
/// Input is archived into a TAR stream and encrypted directly to the output
/// file — no plaintext intermediate files touch disk.
pub fn encrypt_file(
    input_path: &Path,
    output_dir: &Path,
    passphrase: &SecretString,
    output_file: Option<&Path>,
    on_progress: &dyn Fn(&str),
) -> Result<String, CryptoError> {
    let start_time = std::time::Instant::now();

    on_progress("Deriving key\u{2026}");
    let kdf_params = KdfParams::default_params();
    let mut salt = [0u8; ARGON2_SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    let mut hkdf_salt = [0u8; HKDF_SALT_SIZE];
    OsRng.fill_bytes(&mut hkdf_salt);

    let (encryption_key, hmac_key) = derive_keys(passphrase, &salt, &hkdf_salt, &kdf_params)?;

    let cipher = XChaCha20Poly1305::new(encryption_key.as_ref().into());
    let verification_hash: [u8; ENCRYPTION_KEY_SIZE] = sha3_32_hash(encryption_key.as_ref())?;

    let base_name = &get_encryption_base_name(input_path)?;
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

    let encrypt_result: Result<(), CryptoError> = (|| {
        let mut dest = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(&output_path)?;

        let encoded_salt = rep_encode(&salt);
        let encoded_hkdf_salt = rep_encode(&hkdf_salt);
        let kdf_bytes = kdf_params.to_bytes();
        let encoded_kdf = rep_encode(&kdf_bytes);
        let encoded_key_hash = rep_encode(&verification_hash);

        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        let encoded_nonce = rep_encode(&nonce);

        let header_len = (HEADER_PREFIX_ENCODED_SIZE
            + encoded_salt.len()
            + encoded_hkdf_salt.len()
            + encoded_kdf.len()
            + encoded_nonce.len()
            + encoded_key_hash.len()
            + rep_encoded_size(HMAC_TAG_SIZE)) as u16;
        let prefix = format::build_header_prefix(format::TYPE_SYMMETRIC, 0, header_len);
        let encoded_prefix = rep_encode(&prefix);

        let stream_encryptor = stream::EncryptorBE32::from_aead(cipher, nonce.as_ref().into());

        let mut hmac_message = Vec::with_capacity(
            prefix.len()
                + ARGON2_SALT_SIZE
                + HKDF_SALT_SIZE
                + KDF_PARAMS_SIZE
                + NONCE_SIZE
                + ENCRYPTION_KEY_SIZE,
        );
        hmac_message.extend_from_slice(&prefix);
        hmac_message.extend_from_slice(&salt);
        hmac_message.extend_from_slice(&hkdf_salt);
        hmac_message.extend_from_slice(&kdf_bytes);
        hmac_message.extend_from_slice(&nonce);
        hmac_message.extend_from_slice(&verification_hash);
        let hmac_tag = hmac_sha3_256(hmac_key.as_ref(), &hmac_message)?;
        let encoded_hmac_tag = rep_encode(&hmac_tag);

        dest.write_all(&encoded_prefix)?;
        dest.write_all(&encoded_salt)?;
        dest.write_all(&encoded_hkdf_salt)?;
        dest.write_all(&encoded_kdf)?;
        dest.write_all(&encoded_nonce)?;
        dest.write_all(&encoded_key_hash)?;
        dest.write_all(&encoded_hmac_tag)?;

        let encrypt_writer = EncryptWriter::new(stream_encryptor, dest);
        let (_, encrypt_writer) = archiver::archive(input_path, encrypt_writer)?;
        encrypt_writer.finish()?;
        Ok(())
    })();

    if let Err(e) = encrypt_result {
        let _ = fs::remove_file(&output_path);
        return Err(e);
    }

    let result = format!(
        "Encrypted to {} in {}",
        output_path.display(),
        get_duration(start_time.elapsed().as_secs_f64())
    );

    Ok(result)
}

/// Decrypts a file with XChaCha20-Poly1305 streaming decryption.
/// Ciphertext is decrypted into a TAR stream and unpacked directly to the
/// output directory — no plaintext intermediate files touch disk.
pub fn decrypt_file(
    input_path: &Path,
    output_dir: &Path,
    passphrase: &SecretString,
    on_progress: &dyn Fn(&str),
) -> Result<String, CryptoError> {
    let start_time = std::time::Instant::now();
    let mut encrypted_file = fs::File::open(input_path)?;

    let (prefix_bytes, header) =
        format::read_header_from_reader(&mut encrypted_file, format::TYPE_SYMMETRIC)?;

    let min_header_size = HEADER_PREFIX_ENCODED_SIZE
        + rep_encoded_size(ARGON2_SALT_SIZE)
        + rep_encoded_size(HKDF_SALT_SIZE)
        + rep_encoded_size(KDF_PARAMS_SIZE)
        + rep_encoded_size(NONCE_SIZE)
        + rep_encoded_size(ENCRYPTION_KEY_SIZE)
        + rep_encoded_size(HMAC_TAG_SIZE);
    if (header.header_len as usize) < min_header_size {
        return Err(CryptoError::CryptoOperation(ERR_FILE_TOO_SHORT.to_string()));
    }

    let mut encoded_salt = vec![0u8; rep_encoded_size(ARGON2_SALT_SIZE)];
    let mut encoded_hkdf_salt = vec![0u8; rep_encoded_size(HKDF_SALT_SIZE)];
    let mut encoded_kdf = vec![0u8; rep_encoded_size(KDF_PARAMS_SIZE)];
    let mut encoded_nonce = vec![0u8; rep_encoded_size(NONCE_SIZE)];
    let mut encoded_key_hash = vec![0u8; rep_encoded_size(ENCRYPTION_KEY_SIZE)];
    let mut encoded_hmac_tag = vec![0u8; rep_encoded_size(HMAC_TAG_SIZE)];

    encrypted_file
        .read_exact(&mut encoded_salt)
        .map_err(|_| CryptoError::CryptoOperation(ERR_FILE_TOO_SHORT.to_string()))?;
    encrypted_file
        .read_exact(&mut encoded_hkdf_salt)
        .map_err(|_| CryptoError::CryptoOperation(ERR_FILE_TOO_SHORT.to_string()))?;
    encrypted_file
        .read_exact(&mut encoded_kdf)
        .map_err(|_| CryptoError::CryptoOperation(ERR_FILE_TOO_SHORT.to_string()))?;
    encrypted_file
        .read_exact(&mut encoded_nonce)
        .map_err(|_| CryptoError::CryptoOperation(ERR_FILE_TOO_SHORT.to_string()))?;
    encrypted_file
        .read_exact(&mut encoded_key_hash)
        .map_err(|_| CryptoError::CryptoOperation(ERR_FILE_TOO_SHORT.to_string()))?;
    encrypted_file
        .read_exact(&mut encoded_hmac_tag)
        .map_err(|_| CryptoError::CryptoOperation(ERR_FILE_TOO_SHORT.to_string()))?;

    let bytes_after_prefix = encoded_salt.len()
        + encoded_hkdf_salt.len()
        + encoded_kdf.len()
        + encoded_nonce.len()
        + encoded_key_hash.len()
        + encoded_hmac_tag.len();
    format::skip_unknown_header_bytes(&mut encrypted_file, header.header_len, bytes_after_prefix)?;

    let salt = rep_decode_exact(&encoded_salt, ARGON2_SALT_SIZE)?;
    let hkdf_salt = rep_decode_exact(&encoded_hkdf_salt, HKDF_SALT_SIZE)?;
    let kdf_bytes = rep_decode_exact(&encoded_kdf, KDF_PARAMS_SIZE)?;
    let kdf_params = KdfParams::from_bytes(kdf_bytes.as_slice().try_into()?)?;
    let nonce = rep_decode_exact(&encoded_nonce, NONCE_SIZE)?;
    let verification_hash = rep_decode_exact(&encoded_key_hash, ENCRYPTION_KEY_SIZE)?;
    let hmac_tag = rep_decode_exact(&encoded_hmac_tag, HMAC_TAG_SIZE)?;

    on_progress("Deriving key\u{2026}");
    let (encryption_key, hmac_key) = derive_keys(passphrase, &salt, &hkdf_salt, &kdf_params)?;

    let mut hmac_message = Vec::with_capacity(
        prefix_bytes.len()
            + salt.len()
            + hkdf_salt.len()
            + KDF_PARAMS_SIZE
            + nonce.len()
            + verification_hash.len(),
    );
    hmac_message.extend_from_slice(&prefix_bytes);
    hmac_message.extend_from_slice(&salt);
    hmac_message.extend_from_slice(&hkdf_salt);
    hmac_message.extend_from_slice(&kdf_bytes);
    hmac_message.extend_from_slice(&nonce);
    hmac_message.extend_from_slice(&verification_hash);

    if let Err(hmac_err) = hmac_sha3_256_verify(hmac_key.as_ref(), &hmac_message, &hmac_tag) {
        let key_hash: [u8; ENCRYPTION_KEY_SIZE] = sha3_32_hash(encryption_key.as_ref())?;
        let key_correct =
            constant_time_compare_256_bit(&key_hash, verification_hash.as_slice().try_into()?);
        if !key_correct {
            return Err(CryptoError::CryptoOperation(
                "Password incorrect or file header corrupted".to_string(),
            ));
        }
        return Err(hmac_err);
    }

    on_progress("Decrypting\u{2026}");
    let cipher = XChaCha20Poly1305::new(encryption_key.as_ref().into());
    let stream_decryptor = stream::DecryptorBE32::from_aead(cipher, nonce.as_slice().into());

    let decrypt_reader = DecryptReader::new(stream_decryptor, encrypted_file);
    let output_path = archiver::unarchive(decrypt_reader, output_dir)?;

    let result = format!(
        "Decrypted to {} in {}",
        output_path,
        get_duration(start_time.elapsed().as_secs_f64())
    );

    Ok(result)
}
