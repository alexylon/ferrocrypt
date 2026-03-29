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
use crate::reed_solomon::{rs_decode, rs_encode, rs_encoded_size};
use crate::{CryptoError, archiver};

const BUFFER_SIZE: usize = 65536;
const SALT_SIZE: usize = 32;
const NONCE_24_SIZE: usize = 24;
const NONCE_19_SIZE: usize = 19;
const KEY_SIZE: usize = 32;
const HMAC_KEY_SIZE: usize = 32;
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

    let mut flags: [bool; 4] = [false; 4];
    if large {
        flags[0] = true;
    }
    let serialized_flags: Vec<u8> = bincode::encode_to_vec(&flags, bincode::config::standard())?;

    let argon2_config = argon2_config();
    let mut salt_32 = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt_32);

    let key_material = Zeroizing::new(argon2::hash_raw(
        passphrase.expose_secret().as_bytes(),
        &salt_32,
        &argon2_config,
    )?);
    let cipher = XChaCha20Poly1305::new(key_material[..KEY_SIZE].as_ref().into());
    let hmac_key = &key_material[KEY_SIZE..KEY_MATERIAL_SIZE];

    // Hash the encryption key for comparison when decrypting
    let key_hash_ref: [u8; KEY_SIZE] = sha3_32_hash(&key_material[..KEY_SIZE])?;

    let encrypted_extension = "fcs";
    let file_stem = &archiver::archive(input_path, tmp_dir_path)?;
    let zipped_file_name = tmp_dir_path.join(format!("{}.zip", file_stem));
    println!("\nEncrypting {} ...", zipped_file_name.display());

    let mut encrypted_file_path = OpenOptions::new()
        .write(true)
        .append(true)
        .create_new(true)
        .open(output_dir.join(format!("{}.{}", file_stem, encrypted_extension)))?;

    // Encode with reed-solomon. The resulting size is three times that of the original
    let encoded_salt_32: Vec<u8> = rs_encode(&salt_32)?;
    let encoded_key_hash_ref: Vec<u8> = rs_encode(&key_hash_ref)?;

    if !large {
        let mut nonce_24 = [0u8; NONCE_24_SIZE];
        OsRng.fill_bytes(&mut nonce_24);

        let encoded_nonce_24: Vec<u8> = rs_encode(&nonce_24)?;
        let zipped_file = read(&zipped_file_name)?;
        let ciphertext = cipher.encrypt(nonce_24.as_ref().into(), &*zipped_file)?;

        // Compute HMAC over the header
        let mut header_bytes = Vec::new();
        header_bytes.extend_from_slice(&serialized_flags);
        header_bytes.extend_from_slice(&encoded_salt_32);
        header_bytes.extend_from_slice(&encoded_nonce_24);
        header_bytes.extend_from_slice(&encoded_key_hash_ref);
        let hmac_tag = hmac_sha3_256(hmac_key, &header_bytes)?;
        let encoded_hmac_tag: Vec<u8> = rs_encode(&hmac_tag)?;

        encrypted_file_path.write_all(&serialized_flags)?;
        encrypted_file_path.write_all(&encoded_salt_32)?;
        encrypted_file_path.write_all(&encoded_nonce_24)?;
        encrypted_file_path.write_all(&encoded_key_hash_ref)?;
        encrypted_file_path.write_all(&encoded_hmac_tag)?;
        encrypted_file_path.write_all(&ciphertext)?;
    } else {
        let mut nonce_19 = [0u8; NONCE_19_SIZE];
        OsRng.fill_bytes(&mut nonce_19);
        let encoded_nonce_19: Vec<u8> = rs_encode(&nonce_19)?;
        let mut stream_encryptor =
            stream::EncryptorBE32::from_aead(cipher, nonce_19.as_ref().into());

        // Compute HMAC over the header
        let mut header_bytes = Vec::new();
        header_bytes.extend_from_slice(&serialized_flags);
        header_bytes.extend_from_slice(&encoded_salt_32);
        header_bytes.extend_from_slice(&encoded_nonce_19);
        header_bytes.extend_from_slice(&encoded_key_hash_ref);
        let hmac_tag = hmac_sha3_256(hmac_key, &header_bytes)?;
        let encoded_hmac_tag: Vec<u8> = rs_encode(&hmac_tag)?;

        let mut buffer = [0u8; BUFFER_SIZE];

        encrypted_file_path.write_all(&serialized_flags)?;
        encrypted_file_path.write_all(&encoded_salt_32)?;
        encrypted_file_path.write_all(&encoded_nonce_19)?;
        encrypted_file_path.write_all(&encoded_key_hash_ref)?;
        encrypted_file_path.write_all(&encoded_hmac_tag)?;

        let mut source_file = File::open(&zipped_file_name)?;
        loop {
            let read_count = source_file.read(&mut buffer)?;

            if read_count == BUFFER_SIZE {
                let ciphertext = stream_encryptor
                    .encrypt_next(buffer.as_slice())
                    .map_err(CryptoError::ChaCha20Poly1305Error)?;
                encrypted_file_path.write_all(&ciphertext)?;
            } else {
                let ciphertext = stream_encryptor
                    .encrypt_last(&buffer[..read_count])
                    .map_err(CryptoError::ChaCha20Poly1305Error)?;
                encrypted_file_path.write_all(&ciphertext)?;
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
    let file_bytes = read(input_path)?;
    let (flags, _): ([bool; 4], usize) =
        bincode::decode_from_slice(&file_bytes[..4], bincode::config::standard())?;

    let output_path = if flags[0] {
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

    let min_header_size = 4
        + rs_encoded_size(SALT_SIZE)
        + rs_encoded_size(NONCE_24_SIZE)
        + rs_encoded_size(KEY_SIZE)
        + rs_encoded_size(HMAC_KEY_SIZE);
    if encrypted_file.len() < min_header_size {
        return Err(CryptoError::EncryptionDecryptionError(
            "File is too short or corrupted".to_string(),
        ));
    }

    // Split salt, nonce, key hash, HMAC and the encrypted file, and reconstruct with reed-solomon
    let (serialized_flags, rem_data) = encrypted_file.split_at(4);
    let (_flags, _): ([bool; 4], usize) =
        bincode::decode_from_slice(serialized_flags, bincode::config::standard())?;
    let (encoded_salt_32, rem_data) = rem_data.split_at(rs_encoded_size(SALT_SIZE));
    let (encoded_nonce_24, rem_data) = rem_data.split_at(rs_encoded_size(NONCE_24_SIZE));
    let (encoded_key_hash_ref, rem_data) = rem_data.split_at(rs_encoded_size(KEY_SIZE));
    let (encoded_hmac_tag, ciphertext) = rem_data.split_at(rs_encoded_size(HMAC_KEY_SIZE));

    let salt_32 = rs_decode(encoded_salt_32)?;
    let nonce_24 = rs_decode(encoded_nonce_24)?;
    let key_hash_ref = rs_decode(encoded_key_hash_ref)?;
    let hmac_tag = rs_decode(encoded_hmac_tag)?;

    let argon2_config = argon2_config();
    let key_material = Zeroizing::new(argon2::hash_raw(
        passphrase.expose_secret().as_bytes(),
        &salt_32[0..32],
        &argon2_config,
    )?);

    // Hash the encryption key for comparison and compare it in constant time with the ref key hash
    let key_hash: [u8; 32] = sha3_32_hash(&key_material[..KEY_SIZE])?;
    let key_correct = constant_time_compare_256_bit(&key_hash, key_hash_ref[0..32].try_into()?);

    if !key_correct {
        return Err(CryptoError::EncryptionDecryptionError(
            "The provided password is incorrect".to_string(),
        ));
    }

    // Verify HMAC over the header before decrypting
    let header_bytes = [
        serialized_flags,
        encoded_salt_32,
        encoded_nonce_24,
        encoded_key_hash_ref,
    ]
    .concat();
    hmac_sha3_256_verify(
        &key_material[KEY_SIZE..KEY_MATERIAL_SIZE],
        &header_bytes,
        &hmac_tag,
    )?;

    let cipher = XChaCha20Poly1305::new(key_material[..KEY_SIZE].as_ref().into());
    let plaintext: Vec<u8> = cipher.decrypt(
        nonce_24[0..NONCE_24_SIZE].as_ref().into(),
        ciphertext.as_ref(),
    )?;
    let decrypted_file_stem = &get_file_stem_to_string(input_path)?;
    let decrypted_file_path = tmp_dir_path.join(format!("{}.zip", decrypted_file_stem));

    File::create(&decrypted_file_path)?;
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

    let mut serialized_flags = [0u8; 4];
    let mut encoded_salt_32 = vec![0u8; rs_encoded_size(SALT_SIZE)];
    let mut encoded_nonce_19 = vec![0u8; rs_encoded_size(NONCE_19_SIZE)];
    let mut encoded_key_hash_ref = vec![0u8; rs_encoded_size(KEY_SIZE)];
    let mut encoded_hmac_tag = vec![0u8; rs_encoded_size(HMAC_KEY_SIZE)];
    let mut encrypted_file = File::open(input_path)?;

    let mut read_count = encrypted_file.read(&mut serialized_flags)?;
    if read_count != serialized_flags.len() {
        return Err(CryptoError::Message("Error reading flags".to_string()));
    }
    let (_flags, _): ([bool; 4], usize) =
        bincode::decode_from_slice(&serialized_flags, bincode::config::standard())?;

    read_count = encrypted_file.read(&mut encoded_salt_32)?;
    if read_count != encoded_salt_32.len() {
        return Err(CryptoError::Message("Error reading salt".to_string()));
    }

    read_count = encrypted_file.read(&mut encoded_nonce_19)?;
    if read_count != encoded_nonce_19.len() {
        return Err(CryptoError::Message("Error reading nonce".to_string()));
    }

    read_count = encrypted_file.read(&mut encoded_key_hash_ref)?;
    if read_count != encoded_key_hash_ref.len() {
        return Err(CryptoError::Message(
            "Error reading key_hash_ref".to_string(),
        ));
    }

    read_count = encrypted_file.read(&mut encoded_hmac_tag)?;
    if read_count != encoded_hmac_tag.len() {
        return Err(CryptoError::Message("Error reading HMAC tag".to_string()));
    }

    let salt_32 = rs_decode(&encoded_salt_32)?;
    let nonce_19: Vec<u8> = rs_decode(&encoded_nonce_19)?;
    let key_hash_ref = rs_decode(&encoded_key_hash_ref)?;
    let hmac_tag = rs_decode(&encoded_hmac_tag)?;

    let argon2_config = argon2_config();
    let key_material = Zeroizing::new(argon2::hash_raw(
        passphrase.expose_secret().as_bytes(),
        &salt_32,
        &argon2_config,
    )?);

    let key_hash: [u8; KEY_SIZE] = sha3_32_hash(&key_material[..KEY_SIZE])?;
    let key_correct =
        constant_time_compare_256_bit(&key_hash, key_hash_ref[..KEY_SIZE].try_into()?);

    if !key_correct {
        return Err(CryptoError::EncryptionDecryptionError(
            "The provided password is incorrect".to_string(),
        ));
    }

    // Verify HMAC over the header before decrypting
    let mut header_bytes = Vec::new();
    header_bytes.extend_from_slice(&serialized_flags);
    header_bytes.extend_from_slice(&encoded_salt_32);
    header_bytes.extend_from_slice(&encoded_nonce_19);
    header_bytes.extend_from_slice(&encoded_key_hash_ref);
    hmac_sha3_256_verify(
        &key_material[KEY_SIZE..KEY_MATERIAL_SIZE],
        &header_bytes,
        &hmac_tag,
    )?;

    let cipher = XChaCha20Poly1305::new(key_material[..KEY_SIZE].as_ref().into());
    let mut stream_decryptor =
        stream::DecryptorBE32::from_aead(cipher, nonce_19[..NONCE_19_SIZE].as_ref().into());
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
