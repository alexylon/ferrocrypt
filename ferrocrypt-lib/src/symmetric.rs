use std::fs::OpenOptions;
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
    DecryptReader, EncryptWriter, NONCE_SIZE, constant_time_compare_256_bit, get_duration,
    get_file_stem_to_string, hmac_sha3_256, hmac_sha3_256_verify, sha3_32_hash,
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

/// Encrypts a file or directory with XChaCha20-Poly1305 streaming encryption.
/// Input is archived into a TAR stream and encrypted directly to the output
/// file — no plaintext intermediate files touch disk.
pub fn encrypt_file(
    input_path: &str,
    output_dir: &str,
    passphrase: &SecretString,
    output_file: Option<&Path>,
    on_progress: &dyn Fn(&str),
) -> Result<String, CryptoError> {
    let start_time = std::time::Instant::now();

    println!("\nDeriving key ...");
    on_progress("Deriving key\u{2026}");
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    let mut hkdf_salt = [0u8; HKDF_SALT_SIZE];
    OsRng.fill_bytes(&mut hkdf_salt);

    let (enc_key, hmac_key) = derive_keys(passphrase, &salt, &hkdf_salt)?;

    let cipher = XChaCha20Poly1305::new(enc_key.as_ref().into());
    let stored_key_hash: [u8; KEY_SIZE] = sha3_32_hash(enc_key.as_ref())?;

    let file_stem = &get_file_stem_to_string(input_path)?;
    println!("Encrypting ...");
    on_progress("Encrypting\u{2026}");

    let output_path = match output_file {
        Some(path) => path.to_path_buf(),
        None => {
            Path::new(output_dir).join(format!("{}.{}", file_stem, format::ENCRYPTED_EXTENSION))
        }
    };
    if output_path.exists() {
        return Err(CryptoError::Message(format!(
            "Output file already exists: {}\n",
            output_path.display()
        )));
    }
    let mut dest = OpenOptions::new()
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

    let mut hmac_message =
        Vec::with_capacity(prefix.len() + SALT_SIZE + HKDF_SALT_SIZE + NONCE_SIZE + KEY_SIZE);
    hmac_message.extend_from_slice(&prefix);
    hmac_message.extend_from_slice(&salt);
    hmac_message.extend_from_slice(&hkdf_salt);
    hmac_message.extend_from_slice(&nonce);
    hmac_message.extend_from_slice(&stored_key_hash);
    let hmac_tag = hmac_sha3_256(hmac_key.as_ref(), &hmac_message)?;
    let encoded_hmac_tag = rep_encode(&hmac_tag);

    dest.write_all(&prefix)?;
    dest.write_all(&encoded_salt)?;
    dest.write_all(&encoded_hkdf_salt)?;
    dest.write_all(&encoded_nonce)?;
    dest.write_all(&encoded_key_hash)?;
    dest.write_all(&encoded_hmac_tag)?;

    let encrypt_writer = EncryptWriter::new(stream_encryptor, dest);
    let (_, encrypt_writer) = archiver::archive(input_path, encrypt_writer)?;
    encrypt_writer.finish()?;

    let result = format!(
        "Encrypted to {} in {}\n",
        output_path.display(),
        get_duration(start_time.elapsed().as_secs_f64())
    );
    println!("{}", result);

    Ok(result)
}

/// Decrypts a file with XChaCha20-Poly1305 streaming decryption.
/// Ciphertext is decrypted into a TAR stream and unpacked directly to the
/// output directory — no plaintext intermediate files touch disk.
pub fn decrypt_file(
    input_path: &str,
    output_dir: &str,
    passphrase: &SecretString,
    on_progress: &dyn Fn(&str),
) -> Result<String, CryptoError> {
    let start_time = std::time::Instant::now();
    let mut encrypted_file = std::fs::File::open(input_path)?;

    let (prefix_bytes, header) =
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

    let bytes_after_prefix = encoded_salt.len()
        + encoded_hkdf_salt.len()
        + encoded_nonce.len()
        + encoded_key_hash.len()
        + encoded_hmac_tag.len();
    format::skip_unknown_header_bytes(&mut encrypted_file, header.header_len, bytes_after_prefix)?;

    let salt = rep_decode_exact(&encoded_salt, SALT_SIZE)?;
    let hkdf_salt = rep_decode_exact(&encoded_hkdf_salt, HKDF_SALT_SIZE)?;
    let nonce = rep_decode_exact(&encoded_nonce, NONCE_SIZE)?;
    let stored_key_hash = rep_decode_exact(&encoded_key_hash, KEY_SIZE)?;
    let hmac_tag = rep_decode_exact(&encoded_hmac_tag, HMAC_KEY_SIZE)?;

    println!("\nDeriving key ...");
    on_progress("Deriving key\u{2026}");
    let (enc_key, hmac_key) = derive_keys(passphrase, &salt, &hkdf_salt)?;

    let key_hash: [u8; KEY_SIZE] = sha3_32_hash(enc_key.as_ref())?;
    let key_correct =
        constant_time_compare_256_bit(&key_hash, stored_key_hash.as_slice().try_into()?);

    if !key_correct {
        return Err(CryptoError::EncryptionDecryptionError(
            "The provided password is incorrect".to_string(),
        ));
    }

    let mut hmac_message = Vec::with_capacity(
        prefix_bytes.len() + salt.len() + hkdf_salt.len() + nonce.len() + stored_key_hash.len(),
    );
    hmac_message.extend_from_slice(&prefix_bytes);
    hmac_message.extend_from_slice(&salt);
    hmac_message.extend_from_slice(&hkdf_salt);
    hmac_message.extend_from_slice(&nonce);
    hmac_message.extend_from_slice(&stored_key_hash);
    hmac_sha3_256_verify(hmac_key.as_ref(), &hmac_message, &hmac_tag)?;

    println!("Decrypting ...");
    on_progress("Decrypting\u{2026}");
    let cipher = XChaCha20Poly1305::new(enc_key.as_ref().into());
    let stream_decryptor = stream::DecryptorBE32::from_aead(cipher, nonce.as_slice().into());

    let decrypt_reader = DecryptReader::new(stream_decryptor, encrypted_file);
    let output_path = archiver::unarchive(decrypt_reader, output_dir)?;

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
