use std::fs::{self, File, OpenOptions, read};
use std::io::{Read, Write};
use std::path::Path;

use argon2::Variant;
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore, stream},
};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::common::{
    constant_time_compare_256_bit, get_duration, get_file_stem_to_string, hmac_sha3_256,
    hmac_sha3_256_verify, sha3_32_hash,
};
use crate::format::{self, HEADER_PREFIX_SIZE};
use crate::reed_solomon::{rs_decode_exact, rs_encode, rs_encoded_size};
use crate::{CryptoError, archiver};

const BUFFER_SIZE: usize = 65536;
const SALT_SIZE: usize = 32;
const NONCE_24_SIZE: usize = 24;
const NONCE_19_SIZE: usize = 19;
const KEY_SIZE: usize = 32;
const HMAC_KEY_SIZE: usize = 32;
// Argon2 derives 64 bytes: first 32 for encryption, second 32 for header HMAC
const KEY_MATERIAL_SIZE: usize = KEY_SIZE + HMAC_KEY_SIZE;

/// Encrypts a file with XChaCha20Poly1305 algorithm.
pub fn encrypt_file(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    passphrase: &SecretString,
    large: bool,
    tmp_dir_path: impl AsRef<Path>,
) -> Result<String, CryptoError> {
    let start_time = std::time::Instant::now();
    let output_dir = output_dir.as_ref();
    let tmp_dir_path = tmp_dir_path.as_ref();

    let flags: u16 = if large { format::FLAG_LARGE_FILE } else { 0 };

    let argon2_config = argon2_config();
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let key_material = Zeroizing::new(argon2::hash_raw(
        passphrase.expose_secret().as_bytes(),
        &salt,
        &argon2_config,
    )?);
    let cipher = XChaCha20Poly1305::new(key_material[..KEY_SIZE].as_ref().into());
    let hmac_key = &key_material[KEY_SIZE..KEY_MATERIAL_SIZE];

    let stored_key_hash: [u8; KEY_SIZE] = sha3_32_hash(&key_material[..KEY_SIZE])?;

    let encrypted_extension = "fcr";
    let file_stem = &archiver::archive(input_path, tmp_dir_path)?;
    let zipped_file_name = tmp_dir_path.join(format!("{}.zip", file_stem));
    println!("\nEncrypting {} ...", zipped_file_name.display());

    let output_path = output_dir.join(format!("{}.{}", file_stem, encrypted_extension));
    if output_path.exists() {
        return Err(CryptoError::Message(format!(
            "Output file already exists: {}",
            output_path.display()
        )));
    }
    let mut output_file = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        .open(&output_path)?;

    // Encode with reed-solomon. The resulting size is three times that of the original
    let encoded_salt: Vec<u8> = rs_encode(&salt)?;
    let encoded_key_hash: Vec<u8> = rs_encode(&stored_key_hash)?;

    if !large {
        let mut nonce_24 = [0u8; NONCE_24_SIZE];
        OsRng.fill_bytes(&mut nonce_24);

        let encoded_nonce: Vec<u8> = rs_encode(&nonce_24)?;

        let header_len = (HEADER_PREFIX_SIZE
            + encoded_salt.len()
            + encoded_nonce.len()
            + encoded_key_hash.len()
            + rs_encoded_size(HMAC_KEY_SIZE)) as u16;
        let prefix = format::build_header_prefix(format::TYPE_SYMMETRIC, flags, header_len);

        let zipped_file = read(&zipped_file_name)?;
        let ciphertext = cipher.encrypt(nonce_24.as_ref().into(), &*zipped_file)?;

        let mut header_bytes = Vec::new();
        header_bytes.extend_from_slice(&prefix);
        header_bytes.extend_from_slice(&encoded_salt);
        header_bytes.extend_from_slice(&encoded_nonce);
        header_bytes.extend_from_slice(&encoded_key_hash);
        let hmac_tag = hmac_sha3_256(hmac_key, &header_bytes)?;
        let encoded_hmac_tag: Vec<u8> = rs_encode(&hmac_tag)?;

        output_file.write_all(&prefix)?;
        output_file.write_all(&encoded_salt)?;
        output_file.write_all(&encoded_nonce)?;
        output_file.write_all(&encoded_key_hash)?;
        output_file.write_all(&encoded_hmac_tag)?;
        output_file.write_all(&ciphertext)?;
    } else {
        let mut nonce_19 = [0u8; NONCE_19_SIZE];
        OsRng.fill_bytes(&mut nonce_19);
        let encoded_nonce: Vec<u8> = rs_encode(&nonce_19)?;

        let header_len = (HEADER_PREFIX_SIZE
            + encoded_salt.len()
            + encoded_nonce.len()
            + encoded_key_hash.len()
            + rs_encoded_size(HMAC_KEY_SIZE)) as u16;
        let prefix = format::build_header_prefix(format::TYPE_SYMMETRIC, flags, header_len);

        let mut stream_encryptor =
            stream::EncryptorBE32::from_aead(cipher, nonce_19.as_ref().into());

        let mut header_bytes = Vec::new();
        header_bytes.extend_from_slice(&prefix);
        header_bytes.extend_from_slice(&encoded_salt);
        header_bytes.extend_from_slice(&encoded_nonce);
        header_bytes.extend_from_slice(&encoded_key_hash);
        let hmac_tag = hmac_sha3_256(hmac_key, &header_bytes)?;
        let encoded_hmac_tag: Vec<u8> = rs_encode(&hmac_tag)?;

        let mut buffer = [0u8; BUFFER_SIZE];

        output_file.write_all(&prefix)?;
        output_file.write_all(&encoded_salt)?;
        output_file.write_all(&encoded_nonce)?;
        output_file.write_all(&encoded_key_hash)?;
        output_file.write_all(&encoded_hmac_tag)?;

        let mut source_file = File::open(&zipped_file_name)?;
        loop {
            let read_count = source_file.read(&mut buffer)?;

            if read_count == BUFFER_SIZE {
                let ciphertext = stream_encryptor
                    .encrypt_next(buffer.as_slice())
                    .map_err(CryptoError::ChaCha20Poly1305Error)?;
                output_file.write_all(&ciphertext)?;
            } else {
                let ciphertext = stream_encryptor
                    .encrypt_last(&buffer[..read_count])
                    .map_err(CryptoError::ChaCha20Poly1305Error)?;
                output_file.write_all(&ciphertext)?;
                break;
            }
        }
    }

    let encrypted_file_name = output_dir.join(format!("{}.{}", file_stem, encrypted_extension));
    let result = format!(
        "Encrypted to {} for {}",
        encrypted_file_name.display(),
        get_duration(start_time.elapsed().as_secs_f64())
    );
    println!("\n{}", result);

    Ok(result)
}

/// Decrypts a file with XChaCha20Poly1305 algorithm.
pub fn decrypt_file(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    passphrase: &SecretString,
    tmp_dir_path: impl AsRef<Path>,
) -> Result<String, CryptoError> {
    let start_time = std::time::Instant::now();
    let input_path = input_path.as_ref();

    // Only read the prefix, not the whole file — the file may not fit in RAM (large mode)
    let mut file = File::open(input_path)?;
    let (_, header) = format::read_header_from_reader(&mut file, format::TYPE_SYMMETRIC)?;
    drop(file);

    let output_path = if header.flags & format::FLAG_LARGE_FILE != 0 {
        decrypt_large_file(input_path, output_dir, passphrase, tmp_dir_path)?
    } else {
        decrypt_normal_file(input_path, output_dir, passphrase, tmp_dir_path)?
    };

    let result = format!(
        "Decrypted to {} for {}",
        output_path,
        get_duration(start_time.elapsed().as_secs_f64())
    );
    println!("\n{}", result);

    Ok(result)
}

/// Decrypts a normal-sized file with XChaCha20Poly1305 algorithm.
fn decrypt_normal_file(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    passphrase: &SecretString,
    tmp_dir_path: impl AsRef<Path>,
) -> Result<String, CryptoError> {
    let input_path = input_path.as_ref();
    let tmp_dir_path = tmp_dir_path.as_ref();
    println!("Decrypting {} ...\n", input_path.display());
    let encrypted_file: Vec<u8> = read(input_path)?;

    let header = format::read_header(&encrypted_file, format::TYPE_SYMMETRIC)?;
    let min_header_size = HEADER_PREFIX_SIZE
        + rs_encoded_size(SALT_SIZE)
        + rs_encoded_size(NONCE_24_SIZE)
        + rs_encoded_size(KEY_SIZE)
        + rs_encoded_size(HMAC_KEY_SIZE);
    if (header.header_len as usize) < min_header_size
        || encrypted_file.len() < header.header_len as usize
    {
        return Err(CryptoError::EncryptionDecryptionError(
            "File is too short or corrupted".to_string(),
        ));
    }

    let (header_data, ciphertext) = encrypted_file.split_at(header.header_len as usize);
    let rem = &header_data[HEADER_PREFIX_SIZE..];
    let (encoded_salt, rem) = rem.split_at(rs_encoded_size(SALT_SIZE));
    let (encoded_nonce, rem) = rem.split_at(rs_encoded_size(NONCE_24_SIZE));
    let (encoded_key_hash, rem) = rem.split_at(rs_encoded_size(KEY_SIZE));
    let (encoded_hmac_tag, _) = rem.split_at(rs_encoded_size(HMAC_KEY_SIZE));

    let salt = rs_decode_exact(encoded_salt, SALT_SIZE)?;
    let nonce = rs_decode_exact(encoded_nonce, NONCE_24_SIZE)?;
    let stored_key_hash = rs_decode_exact(encoded_key_hash, KEY_SIZE)?;
    let hmac_tag = rs_decode_exact(encoded_hmac_tag, HMAC_KEY_SIZE)?;

    let argon2_config = argon2_config();
    let key_material = Zeroizing::new(argon2::hash_raw(
        passphrase.expose_secret().as_bytes(),
        &salt,
        &argon2_config,
    )?);

    let key_hash: [u8; KEY_SIZE] = sha3_32_hash(&key_material[..KEY_SIZE])?;
    let key_correct =
        constant_time_compare_256_bit(&key_hash, stored_key_hash.as_slice().try_into()?);

    if !key_correct {
        return Err(CryptoError::EncryptionDecryptionError(
            "The provided password is incorrect".to_string(),
        ));
    }

    let hmac_input = &header_data[..header_data.len() - rs_encoded_size(HMAC_KEY_SIZE)];
    hmac_sha3_256_verify(
        &key_material[KEY_SIZE..KEY_MATERIAL_SIZE],
        hmac_input,
        &hmac_tag,
    )?;

    let cipher = XChaCha20Poly1305::new(key_material[..KEY_SIZE].as_ref().into());
    let plaintext: Vec<u8> = cipher.decrypt(nonce.as_slice().into(), ciphertext.as_ref())?;
    let decrypted_file_stem = &get_file_stem_to_string(input_path)?;
    let decrypted_file_path = tmp_dir_path.join(format!("{}.zip", decrypted_file_stem));

    fs::write(&decrypted_file_path, plaintext)?;

    let output_path = archiver::unarchive(&decrypted_file_path, output_dir)?;

    Ok(output_path)
}

/// Decrypts a large file that doesn't fit in RAM with XChaCha20Poly1305 algorithm. This is slower.
fn decrypt_large_file(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    passphrase: &SecretString,
    tmp_dir_path: impl AsRef<Path>,
) -> Result<String, CryptoError> {
    let input_path = input_path.as_ref();
    let tmp_dir_path = tmp_dir_path.as_ref();
    println!("Decrypting {} ...\n", input_path.display());

    let mut encrypted_file = File::open(input_path)?;

    let (prefix_bytes, _header) =
        format::read_header_from_reader(&mut encrypted_file, format::TYPE_SYMMETRIC)?;

    let mut encoded_salt = vec![0u8; rs_encoded_size(SALT_SIZE)];
    let mut encoded_nonce = vec![0u8; rs_encoded_size(NONCE_19_SIZE)];
    let mut encoded_key_hash = vec![0u8; rs_encoded_size(KEY_SIZE)];
    let mut encoded_hmac_tag = vec![0u8; rs_encoded_size(HMAC_KEY_SIZE)];

    encrypted_file.read_exact(&mut encoded_salt).map_err(|_| {
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

    let salt = rs_decode_exact(&encoded_salt, SALT_SIZE)?;
    let nonce = rs_decode_exact(&encoded_nonce, NONCE_19_SIZE)?;
    let stored_key_hash = rs_decode_exact(&encoded_key_hash, KEY_SIZE)?;
    let hmac_tag = rs_decode_exact(&encoded_hmac_tag, HMAC_KEY_SIZE)?;

    let argon2_config = argon2_config();
    let key_material = Zeroizing::new(argon2::hash_raw(
        passphrase.expose_secret().as_bytes(),
        &salt,
        &argon2_config,
    )?);

    let key_hash: [u8; KEY_SIZE] = sha3_32_hash(&key_material[..KEY_SIZE])?;
    let key_correct =
        constant_time_compare_256_bit(&key_hash, stored_key_hash.as_slice().try_into()?);

    if !key_correct {
        return Err(CryptoError::EncryptionDecryptionError(
            "The provided password is incorrect".to_string(),
        ));
    }

    let mut header_bytes = Vec::new();
    header_bytes.extend_from_slice(&prefix_bytes);
    header_bytes.extend_from_slice(&encoded_salt);
    header_bytes.extend_from_slice(&encoded_nonce);
    header_bytes.extend_from_slice(&encoded_key_hash);
    hmac_sha3_256_verify(
        &key_material[KEY_SIZE..KEY_MATERIAL_SIZE],
        &header_bytes,
        &hmac_tag,
    )?;

    let cipher = XChaCha20Poly1305::new(key_material[..KEY_SIZE].as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(cipher, nonce.as_slice().into());
    let decrypted_file_stem = &get_file_stem_to_string(input_path)?;
    let decrypted_file_path = tmp_dir_path.join(format!("{}.zip", decrypted_file_stem));
    let mut decrypted_file = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        .open(&decrypted_file_path)?;

    // Streaming decryption: BUFFER_SIZE + 16 bytes for the Poly1305 authentication tag
    const ENCRYPTED_BUFFER_SIZE: usize = BUFFER_SIZE + 16;
    let mut buffer = [0u8; ENCRYPTED_BUFFER_SIZE];

    loop {
        let read_count = encrypted_file.read(&mut buffer)?;

        if read_count == ENCRYPTED_BUFFER_SIZE {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(CryptoError::ChaCha20Poly1305Error)?;
            decrypted_file.write_all(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(CryptoError::ChaCha20Poly1305Error)?;
            decrypted_file.write_all(&plaintext)?;
            break;
        }
    }

    let output_path = archiver::unarchive(&decrypted_file_path, output_dir)?;

    Ok(output_path)
}

fn argon2_config() -> argon2::Config<'static> {
    argon2::Config {
        variant: Variant::Argon2id,
        hash_length: KEY_MATERIAL_SIZE as u32,
        lanes: 8,
        mem_cost: 65536,
        time_cost: 2,
        ..Default::default()
    }
}
