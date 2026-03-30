use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use argon2::Variant;
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{KeyInit, OsRng, rand_core::RngCore, stream},
};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretString};
use sha3::Sha3_256;
use zeroize::Zeroizing;

use crate::common::{
    NONCE_SIZE, constant_time_compare_256_bit, get_duration, get_file_stem_to_string,
    hmac_sha3_256, hmac_sha3_256_verify, sha3_32_hash, stream_decrypt, stream_encrypt,
};
use crate::format::{self, HEADER_PREFIX_SIZE};
use crate::replication::{rep_decode_exact, rep_encode, rep_encoded_size};
use crate::{CryptoError, archiver};

const SALT_SIZE: usize = 32;
const HKDF_SALT_SIZE: usize = 32;
const KEY_SIZE: usize = 32;
const HMAC_KEY_SIZE: usize = 32;
const ARGON2_OUTPUT_SIZE: usize = 32;
const HKDF_INFO_ENC: &[u8] = b"ferrocrypt-enc";
const HKDF_INFO_HMAC: &[u8] = b"ferrocrypt-hmac";

/// Derives domain-separated encryption and HMAC subkeys from a passphrase.
///
/// Pipeline: passphrase + salt → Argon2id (32 bytes IKM) → HKDF-SHA3-256 → (enc_key, hmac_key)
fn derive_keys(
    passphrase: &SecretString,
    salt: &[u8],
    hkdf_salt: &[u8],
) -> Result<(Zeroizing<[u8; KEY_SIZE]>, Zeroizing<[u8; HMAC_KEY_SIZE]>), CryptoError> {
    let argon2_config = argon2_config();
    let ikm = Zeroizing::new(argon2::hash_raw(
        passphrase.expose_secret().as_bytes(),
        salt,
        &argon2_config,
    )?);

    let hkdf = Hkdf::<Sha3_256>::new(Some(hkdf_salt), &ikm);
    let mut enc_key = Zeroizing::new([0u8; KEY_SIZE]);
    let mut hmac_key = Zeroizing::new([0u8; HMAC_KEY_SIZE]);
    hkdf.expand(HKDF_INFO_ENC, enc_key.as_mut())
        .map_err(|_| CryptoError::Message("HKDF expand failed for encryption key".to_string()))?;
    hkdf.expand(HKDF_INFO_HMAC, hmac_key.as_mut())
        .map_err(|_| CryptoError::Message("HKDF expand failed for HMAC key".to_string()))?;

    Ok((enc_key, hmac_key))
}

/// Encrypts a file with XChaCha20Poly1305 streaming algorithm.
pub fn encrypt_file(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    passphrase: &SecretString,
    tmp_dir_path: impl AsRef<Path>,
) -> Result<String, CryptoError> {
    let start_time = std::time::Instant::now();
    let output_dir = output_dir.as_ref();
    let tmp_dir_path = tmp_dir_path.as_ref();

    println!("\nDeriving key ...");
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    let mut hkdf_salt = [0u8; HKDF_SALT_SIZE];
    OsRng.fill_bytes(&mut hkdf_salt);

    let (enc_key, hmac_key) = derive_keys(passphrase, &salt, &hkdf_salt)?;

    let cipher = XChaCha20Poly1305::new(enc_key.as_ref().into());
    let stored_key_hash: [u8; KEY_SIZE] = sha3_32_hash(enc_key.as_ref())?;

    let encrypted_extension = "fcr";
    let file_stem = &archiver::archive(input_path, tmp_dir_path)?;
    let zipped_file_name = tmp_dir_path.join(format!("{}.zip", file_stem));
    println!("Encrypting ...");

    let output_path = output_dir.join(format!("{}.{}", file_stem, encrypted_extension));
    if output_path.exists() {
        return Err(CryptoError::Message(format!(
            "Output file already exists: {}\n",
            output_path.display()
        )));
    }
    let mut output_file = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        .open(&output_path)?;

    let encoded_salt = rep_encode(&salt);
    let encoded_hkdf_salt = rep_encode(&hkdf_salt);
    let encoded_key_hash = rep_encode(&stored_key_hash);

    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let encoded_nonce = rep_encode(&nonce);

    let header_len = (HEADER_PREFIX_SIZE
        + encoded_salt.len()
        + encoded_hkdf_salt.len()
        + encoded_nonce.len()
        + encoded_key_hash.len()
        + rep_encoded_size(HMAC_KEY_SIZE)) as u16;
    let prefix = format::build_header_prefix(format::TYPE_SYMMETRIC, 0, header_len);

    let stream_encryptor = stream::EncryptorBE32::from_aead(cipher, nonce.as_ref().into());

    let mut header_bytes = Vec::with_capacity(
        prefix.len()
            + encoded_salt.len()
            + encoded_hkdf_salt.len()
            + encoded_nonce.len()
            + encoded_key_hash.len(),
    );
    header_bytes.extend_from_slice(&prefix);
    header_bytes.extend_from_slice(&encoded_salt);
    header_bytes.extend_from_slice(&encoded_hkdf_salt);
    header_bytes.extend_from_slice(&encoded_nonce);
    header_bytes.extend_from_slice(&encoded_key_hash);
    let hmac_tag = hmac_sha3_256(hmac_key.as_ref(), &header_bytes)?;
    let encoded_hmac_tag = rep_encode(&hmac_tag);

    output_file.write_all(&prefix)?;
    output_file.write_all(&encoded_salt)?;
    output_file.write_all(&encoded_hkdf_salt)?;
    output_file.write_all(&encoded_nonce)?;
    output_file.write_all(&encoded_key_hash)?;
    output_file.write_all(&encoded_hmac_tag)?;

    let mut source_file = File::open(&zipped_file_name)?;
    stream_encrypt(stream_encryptor, &mut source_file, &mut output_file)?;

    let result = format!(
        "Encrypted to {} in {}\n",
        output_path.display(),
        get_duration(start_time.elapsed().as_secs_f64())
    );
    println!("{}", result);

    Ok(result)
}

/// Decrypts a file with XChaCha20Poly1305 streaming algorithm.
pub fn decrypt_file(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    passphrase: &SecretString,
    tmp_dir_path: impl AsRef<Path>,
) -> Result<String, CryptoError> {
    let start_time = std::time::Instant::now();
    let input_path = input_path.as_ref();
    let tmp_dir_path = tmp_dir_path.as_ref();
    let mut encrypted_file = File::open(input_path)?;

    let (prefix_bytes, _header) =
        format::read_header_from_reader(&mut encrypted_file, format::TYPE_SYMMETRIC)?;

    let mut encoded_salt = vec![0u8; rep_encoded_size(SALT_SIZE)];
    let mut encoded_hkdf_salt = vec![0u8; rep_encoded_size(HKDF_SALT_SIZE)];
    let mut encoded_nonce = vec![0u8; rep_encoded_size(NONCE_SIZE)];
    let mut encoded_key_hash = vec![0u8; rep_encoded_size(KEY_SIZE)];
    let mut encoded_hmac_tag = vec![0u8; rep_encoded_size(HMAC_KEY_SIZE)];

    encrypted_file.read_exact(&mut encoded_salt).map_err(|_| {
        CryptoError::EncryptionDecryptionError("File is too short or corrupted".to_string())
    })?;
    encrypted_file
        .read_exact(&mut encoded_hkdf_salt)
        .map_err(|_| {
            CryptoError::EncryptionDecryptionError("File is too short or corrupted".to_string())
        })?;
    encrypted_file.read_exact(&mut encoded_nonce).map_err(|_| {
        CryptoError::EncryptionDecryptionError("File is too short or corrupted".to_string())
    })?;
    encrypted_file
        .read_exact(&mut encoded_key_hash)
        .map_err(|_| {
            CryptoError::EncryptionDecryptionError("File is too short or corrupted".to_string())
        })?;
    encrypted_file
        .read_exact(&mut encoded_hmac_tag)
        .map_err(|_| {
            CryptoError::EncryptionDecryptionError("File is too short or corrupted".to_string())
        })?;

    let salt = rep_decode_exact(&encoded_salt, SALT_SIZE)?;
    let hkdf_salt = rep_decode_exact(&encoded_hkdf_salt, HKDF_SALT_SIZE)?;
    let nonce = rep_decode_exact(&encoded_nonce, NONCE_SIZE)?;
    let stored_key_hash = rep_decode_exact(&encoded_key_hash, KEY_SIZE)?;
    let hmac_tag = rep_decode_exact(&encoded_hmac_tag, HMAC_KEY_SIZE)?;

    println!("\nDeriving key ...");
    let (enc_key, hmac_key) = derive_keys(passphrase, &salt, &hkdf_salt)?;

    let key_hash: [u8; KEY_SIZE] = sha3_32_hash(enc_key.as_ref())?;
    let key_correct =
        constant_time_compare_256_bit(&key_hash, stored_key_hash.as_slice().try_into()?);

    if !key_correct {
        return Err(CryptoError::EncryptionDecryptionError(
            "The provided password is incorrect".to_string(),
        ));
    }

    let mut header_bytes = Vec::with_capacity(
        prefix_bytes.len()
            + encoded_salt.len()
            + encoded_hkdf_salt.len()
            + encoded_nonce.len()
            + encoded_key_hash.len(),
    );
    header_bytes.extend_from_slice(&prefix_bytes);
    header_bytes.extend_from_slice(&encoded_salt);
    header_bytes.extend_from_slice(&encoded_hkdf_salt);
    header_bytes.extend_from_slice(&encoded_nonce);
    header_bytes.extend_from_slice(&encoded_key_hash);
    hmac_sha3_256_verify(hmac_key.as_ref(), &header_bytes, &hmac_tag)?;

    println!("Decrypting ...");
    let cipher = XChaCha20Poly1305::new(enc_key.as_ref().into());
    let stream_decryptor = stream::DecryptorBE32::from_aead(cipher, nonce.as_slice().into());
    let decrypted_file_stem = &get_file_stem_to_string(input_path)?;
    let decrypted_file_path = tmp_dir_path.join(format!("{}.zip", decrypted_file_stem));
    let mut decrypted_file = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        .open(&decrypted_file_path)?;

    stream_decrypt(stream_decryptor, &mut encrypted_file, &mut decrypted_file)?;

    let output_path = archiver::unarchive(&decrypted_file_path, output_dir)?;

    let result = format!(
        "Decrypted to {} in {}\n",
        output_path,
        get_duration(start_time.elapsed().as_secs_f64())
    );
    println!("{}", result);

    Ok(result)
}

fn argon2_config() -> argon2::Config<'static> {
    let (mem_cost, time_cost) = if cfg!(debug_assertions) {
        (8192, 1)
    } else {
        (1048576, 4)
    };
    argon2::Config {
        variant: Variant::Argon2id,
        hash_length: ARGON2_OUTPUT_SIZE as u32,
        lanes: 4,
        mem_cost,
        time_cost,
        ..Default::default()
    }
}
