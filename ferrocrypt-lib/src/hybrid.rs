use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{KeyInit, OsRng, rand_core::RngCore, stream},
};
use openssl::encrypt::{Decrypter, Encrypter};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::{Padding, Rsa};
use openssl::symm::Cipher;
use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, Zeroizing};

use crate::common::{
    NONCE_SIZE, get_duration, get_file_stem_to_string, hmac_sha3_256, hmac_sha3_256_verify,
    stream_decrypt, stream_encrypt,
};
use crate::format::{self, HEADER_PREFIX_SIZE};
use crate::reed_solomon::{rs_decode_exact, rs_encode, rs_encoded_size};
use crate::{CryptoError, archiver};

const KEY_SIZE: usize = 32;
const HMAC_KEY_SIZE: usize = 32;
// Both keys are packed into a single RSA envelope: [enc_key | hmac_key]
const COMBINED_KEY_SIZE: usize = KEY_SIZE + HMAC_KEY_SIZE;

pub fn encrypt_file(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    rsa_public_pem: impl AsRef<Path>,
    tmp_dir_path: impl AsRef<Path>,
) -> Result<String, CryptoError> {
    let start_time = std::time::Instant::now();
    let output_dir = output_dir.as_ref();
    let tmp_dir_path = tmp_dir_path.as_ref();
    let file_stem = &archiver::archive(input_path, tmp_dir_path)?;
    let zipped_file_name = tmp_dir_path.join(format!("{}.zip", file_stem));
    println!("\nEncrypting ...");

    let mut symmetric_key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let mut hmac_key = [0u8; HMAC_KEY_SIZE];
    OsRng.fill_bytes(&mut hmac_key);

    let result = (|| -> Result<String, CryptoError> {
        let cipher = XChaCha20Poly1305::new(&symmetric_key);

        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        let mut combined_key = Zeroizing::new(vec![0u8; COMBINED_KEY_SIZE]);
        combined_key[..KEY_SIZE].copy_from_slice(&symmetric_key);
        combined_key[KEY_SIZE..].copy_from_slice(&hmac_key);

        let pub_key_str = fs::read_to_string(rsa_public_pem)?;
        let encrypted_combined_key: Vec<u8> = match encrypt_key(&combined_key, &pub_key_str) {
            Ok(encrypted_combined_key) => encrypted_combined_key,
            Err(_) => {
                return Err(CryptoError::EncryptionDecryptionError(
                    "The provided public key is not valid".to_string(),
                ));
            }
        };

        let output_path = output_dir.join(format!("{}.fcr", file_stem));
        if output_path.exists() {
            return Err(CryptoError::EncryptionDecryptionError(format!(
                "Output file already exists: {}\n",
                output_path.display()
            )));
        }
        let mut output_file = OpenOptions::new()
            .write(true)
            .append(true)
            .create_new(true)
            .open(&output_path)?;

        let encoded_encrypted_combined_key: Vec<u8> = rs_encode(&encrypted_combined_key)?;
        let encoded_nonce: Vec<u8> = rs_encode(&nonce)?;

        let header_len = (HEADER_PREFIX_SIZE
            + encoded_encrypted_combined_key.len()
            + encoded_nonce.len()
            + rs_encoded_size(HMAC_KEY_SIZE)) as u16;
        let prefix = format::build_header_prefix(format::TYPE_HYBRID, 0, header_len);

        let stream_encryptor = stream::EncryptorBE32::from_aead(cipher, nonce.as_ref().into());

        let mut header_bytes = Vec::with_capacity(
            prefix.len() + encoded_encrypted_combined_key.len() + encoded_nonce.len(),
        );
        header_bytes.extend_from_slice(&prefix);
        header_bytes.extend_from_slice(&encoded_encrypted_combined_key);
        header_bytes.extend_from_slice(&encoded_nonce);
        let hmac_tag = hmac_sha3_256(&hmac_key, &header_bytes)?;
        let encoded_hmac_tag: Vec<u8> = rs_encode(&hmac_tag)?;

        output_file.write_all(&prefix)?;
        output_file.write_all(&encoded_encrypted_combined_key)?;
        output_file.write_all(&encoded_nonce)?;
        output_file.write_all(&encoded_hmac_tag)?;

        let mut source_file = File::open(&zipped_file_name)?;
        stream_encrypt(stream_encryptor, &mut source_file, &mut output_file)?;

        nonce.zeroize();

        let msg = format!(
            "Encrypted to {} in {}\n",
            output_path.display(),
            get_duration(start_time.elapsed().as_secs_f64())
        );
        println!("{}", msg);

        Ok(msg)
    })();

    symmetric_key.zeroize();
    hmac_key.zeroize();
    result
}

pub fn decrypt_file(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    rsa_private_pem: &mut str,
    passphrase: &SecretString,
    tmp_dir_path: impl AsRef<Path>,
) -> Result<String, CryptoError> {
    let start_time = std::time::Instant::now();
    let input_path = input_path.as_ref();
    let tmp_dir_path = tmp_dir_path.as_ref();

    // Zeroizing wraps the PEM content so it's cleared on all exit paths
    let priv_key_str = Zeroizing::new(fs::read_to_string(&rsa_private_pem)?);

    println!("\nDecrypting ...");

    let rsa_key_size =
        match get_public_key_size_from_private_key(&priv_key_str, passphrase.expose_secret()) {
            Ok(rsa_key_size) => rsa_key_size,
            Err(_) => {
                rsa_private_pem.zeroize();
                return Err(CryptoError::EncryptionDecryptionError(
                    "Incorrect password or wrong private key provided".to_string(),
                ));
            }
        };

    let mut encrypted_file = File::open(input_path)?;

    let (prefix_bytes, header) =
        format::read_header_from_reader(&mut encrypted_file, format::TYPE_HYBRID)?;

    let min_header_size = HEADER_PREFIX_SIZE
        + rs_encoded_size(rsa_key_size as usize)
        + rs_encoded_size(NONCE_SIZE)
        + rs_encoded_size(HMAC_KEY_SIZE);
    if (header.header_len as usize) < min_header_size {
        rsa_private_pem.zeroize();
        return Err(CryptoError::EncryptionDecryptionError(
            "File is too short or corrupted".to_string(),
        ));
    }

    let mut encoded_encrypted_combined_key = vec![0u8; rs_encoded_size(rsa_key_size as usize)];
    let mut encoded_nonce = vec![0u8; rs_encoded_size(NONCE_SIZE)];
    let mut encoded_hmac_tag = vec![0u8; rs_encoded_size(HMAC_KEY_SIZE)];

    encrypted_file
        .read_exact(&mut encoded_encrypted_combined_key)
        .map_err(|_| {
            CryptoError::EncryptionDecryptionError("File is too short or corrupted".to_string())
        })?;
    encrypted_file.read_exact(&mut encoded_nonce).map_err(|_| {
        CryptoError::EncryptionDecryptionError("File is too short or corrupted".to_string())
    })?;
    encrypted_file
        .read_exact(&mut encoded_hmac_tag)
        .map_err(|_| {
            CryptoError::EncryptionDecryptionError("File is too short or corrupted".to_string())
        })?;

    let encrypted_combined_key =
        rs_decode_exact(&encoded_encrypted_combined_key, rsa_key_size as usize)?;
    let nonce = rs_decode_exact(&encoded_nonce, NONCE_SIZE)?;
    let hmac_tag = rs_decode_exact(&encoded_hmac_tag, HMAC_KEY_SIZE)?;

    let mut decrypted_combined_key = decrypt_key(
        &encrypted_combined_key,
        &priv_key_str,
        passphrase.expose_secret(),
    )?;

    // Closure captures the result so zeroization always runs after it
    let result = (|| -> Result<String, CryptoError> {
        let hmac_key = &decrypted_combined_key[KEY_SIZE..COMBINED_KEY_SIZE];

        let mut header_bytes = Vec::with_capacity(
            prefix_bytes.len() + encoded_encrypted_combined_key.len() + encoded_nonce.len(),
        );
        header_bytes.extend_from_slice(&prefix_bytes);
        header_bytes.extend_from_slice(&encoded_encrypted_combined_key);
        header_bytes.extend_from_slice(&encoded_nonce);
        hmac_sha3_256_verify(hmac_key, &header_bytes, &hmac_tag)?;

        let cipher = XChaCha20Poly1305::new((&decrypted_combined_key[..KEY_SIZE]).into());
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

        let msg = format!(
            "Decrypted to {} in {}\n",
            output_path,
            get_duration(start_time.elapsed().as_secs_f64())
        );
        println!("{}", msg);

        Ok(msg)
    })();

    decrypted_combined_key.zeroize();
    rsa_private_pem.zeroize();
    result
}

fn get_public_key_size_from_private_key(
    rsa_private_pem: &str,
    passphrase: &str,
) -> Result<u32, CryptoError> {
    let rsa_private =
        Rsa::private_key_from_pem_passphrase(rsa_private_pem.as_bytes(), passphrase.as_bytes())?;
    let rsa_public_pem: Vec<u8> = rsa_private.public_key_to_pem()?;
    let rsa_public = Rsa::public_key_from_pem(&rsa_public_pem)?;

    Ok(rsa_public.size())
}

fn encrypt_key(key_data: &[u8], rsa_public_pem: &str) -> Result<Vec<u8>, CryptoError> {
    let rsa = Rsa::public_key_from_pem(rsa_public_pem.as_bytes())?;
    let pkey = PKey::from_rsa(rsa)?;
    let mut encrypter = Encrypter::new(&pkey)?;
    encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    encrypter.set_rsa_oaep_md(MessageDigest::sha256())?;
    encrypter.set_rsa_mgf1_md(MessageDigest::sha256())?;
    let buf_len = encrypter.encrypt_len(key_data)?;
    let mut buf = vec![0u8; buf_len];
    let len = encrypter.encrypt(key_data, &mut buf)?;
    buf.truncate(len);

    Ok(buf)
}

fn decrypt_key(
    encrypted_key: &[u8],
    rsa_private_pem: &str,
    passphrase: &str,
) -> Result<[u8; COMBINED_KEY_SIZE], CryptoError> {
    let rsa =
        Rsa::private_key_from_pem_passphrase(rsa_private_pem.as_bytes(), passphrase.as_bytes())?;
    let pkey = PKey::from_rsa(rsa)?;
    let mut decrypter = Decrypter::new(&pkey)?;
    decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    decrypter.set_rsa_oaep_md(MessageDigest::sha256())?;
    decrypter.set_rsa_mgf1_md(MessageDigest::sha256())?;
    let buf_len = decrypter.decrypt_len(encrypted_key)?;
    let mut buf = vec![0u8; buf_len];
    let len = decrypter.decrypt(encrypted_key, &mut buf)?;
    if len != COMBINED_KEY_SIZE {
        buf.zeroize();
        return Err(CryptoError::EncryptionDecryptionError(
            "RSA-decrypted key has unexpected length".to_string(),
        ));
    }

    let mut result = [0u8; COMBINED_KEY_SIZE];
    result.copy_from_slice(&buf[..COMBINED_KEY_SIZE]);
    buf.zeroize();

    Ok(result)
}

pub fn generate_asymmetric_key_pair(
    bit_size: u32,
    passphrase: &SecretString,
    output_dir: impl AsRef<Path>,
) -> Result<String, CryptoError> {
    let output_dir = output_dir.as_ref();
    let rsa: Rsa<Private> = Rsa::generate(bit_size)?;

    let private_key: Vec<u8> = rsa.private_key_to_pem_passphrase(
        Cipher::chacha20_poly1305(),
        passphrase.expose_secret().as_bytes(),
    )?;
    let public_key: Vec<u8> = rsa.public_key_to_pem()?;
    let private_key_path = output_dir.join(format!("rsa-{}-priv-key.pem", bit_size));
    let public_key_path = output_dir.join(format!("rsa-{}-pub-key.pem", bit_size));

    let mut private_key_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&private_key_path)?;
    private_key_file.write_all(&private_key)?;

    let mut public_key_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&public_key_path)?;
    public_key_file.write_all(&public_key)?;

    let result = format!("Generated key pair in {}", output_dir.display());
    println!("\n{}", result);

    Ok(result)
}
