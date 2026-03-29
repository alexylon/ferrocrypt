use std::fs::{self, File, OpenOptions, read};
use std::io::Write;
use std::path::Path;

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{
        Aead, KeyInit, OsRng,
        generic_array::{GenericArray, typenum},
        rand_core::RngCore,
    },
};
use openssl::pkey::Private;
use openssl::rsa::{Padding, Rsa};
use openssl::symm::Cipher;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

use crate::common::{get_duration, get_file_stem_to_string};
use crate::reed_solomon::{rs_decode, rs_encode, rs_encoded_size};
use crate::{CryptoError, archiver};

const NONCE_24_SIZE: usize = 24;
const KEY_SIZE: usize = 32;

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
    println!("\nEncrypting {} ...", zipped_file_name.display());

    let mut symmetric_key = XChaCha20Poly1305::generate_key(&mut OsRng);

    let result = (|| -> Result<String, CryptoError> {
        let cipher = XChaCha20Poly1305::new(&symmetric_key);

        let mut nonce_24 = [0u8; NONCE_24_SIZE];
        OsRng.fill_bytes(&mut nonce_24);

        let zipped_file = read(&zipped_file_name)?;
        let ciphertext = cipher.encrypt(nonce_24.as_ref().into(), &*zipped_file)?;

        let pub_key_str = fs::read_to_string(rsa_public_pem)?;
        let encrypted_symmetric_key: Vec<u8> =
            match encrypt_key(symmetric_key.to_vec(), &pub_key_str) {
                Ok(encrypted_symmetric_key) => encrypted_symmetric_key,
                Err(_) => {
                    return Err(CryptoError::EncryptionDecryptionError(
                        "The provided public key is not valid".to_string(),
                    ));
                }
            };

        let mut encrypted_file_path = OpenOptions::new()
            .write(true)
            .append(true)
            .create_new(true)
            .open(output_dir.join(format!("{}.fch", file_stem)))?;

        // Reserve header information for decryption
        let flags: [bool; 4] = [false, false, false, false];
        let serialized_flags: Vec<u8> =
            bincode::encode_to_vec(&flags, bincode::config::standard())?;

        let encoded_encrypted_symmetric_key: Vec<u8> = rs_encode(&encrypted_symmetric_key)?;
        let encoded_nonce_24: Vec<u8> = rs_encode(&nonce_24)?;

        encrypted_file_path.write_all(&serialized_flags)?;
        encrypted_file_path.write_all(&encoded_encrypted_symmetric_key)?;
        encrypted_file_path.write_all(&encoded_nonce_24)?;
        encrypted_file_path.write_all(&ciphertext)?;

        nonce_24.zeroize();

        let encrypted_file_name = output_dir.join(format!("{}.fch", file_stem));
        let msg = format!(
            "Encrypted to {} for {}",
            encrypted_file_name.display(),
            get_duration(start_time.elapsed().as_secs_f64())
        );
        println!("\n{}", msg);

        Ok(msg)
    })();

    symmetric_key.zeroize();
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

    let priv_key_str = fs::read_to_string(&rsa_private_pem)?;

    println!("Decrypting {} ...\n", input_path.display());

    let encrypted_file: Vec<u8> = read(input_path)?;

    let rsa_pub_pem_size =
        match get_public_key_size_from_private_key(&priv_key_str, passphrase.expose_secret()) {
            Ok(rsa_pub_pem_size) => rsa_pub_pem_size,
            Err(_) => {
                rsa_private_pem.zeroize();
                return Err(CryptoError::EncryptionDecryptionError(
                    "Incorrect password or wrong private key provided".to_string(),
                ));
            }
        };

    let min_header_size =
        4 + rs_encoded_size(rsa_pub_pem_size as usize) + rs_encoded_size(NONCE_24_SIZE);
    if encrypted_file.len() < min_header_size {
        rsa_private_pem.zeroize();
        return Err(CryptoError::EncryptionDecryptionError(
            "File is too short or corrupted".to_string(),
        ));
    }

    let (serialized_flags, rem_data) = encrypted_file.split_at(4);
    let (_flags, _): ([bool; 4], usize) =
        bincode::decode_from_slice(serialized_flags, bincode::config::standard())?;
    let (encoded_encrypted_symmetric_key, rem_data) =
        rem_data.split_at(rs_encoded_size(rsa_pub_pem_size as usize));
    let (encoded_nonce_24, ciphertext) = rem_data.split_at(rs_encoded_size(NONCE_24_SIZE));

    let encrypted_symmetric_key = rs_decode(encoded_encrypted_symmetric_key)?;
    let nonce_24 = rs_decode(encoded_nonce_24)?;

    let decrypted_symmetric_key = decrypt_key(
        &encrypted_symmetric_key,
        &priv_key_str,
        passphrase.expose_secret(),
    )?;

    let mut symmetric_key: GenericArray<u8, typenum::U32> =
        GenericArray::from(decrypted_symmetric_key);

    let result = (|| -> Result<String, CryptoError> {
        let cipher = XChaCha20Poly1305::new(&symmetric_key);
        let file_decrypted = cipher.decrypt(
            nonce_24[0..NONCE_24_SIZE].as_ref().into(),
            ciphertext.as_ref(),
        )?;
        let file_stem_decrypted = &get_file_stem_to_string(input_path)?;
        let decrypted_file_path = tmp_dir_path.join(format!("{}.zip", file_stem_decrypted));

        File::create(&decrypted_file_path)?;
        fs::write(&decrypted_file_path, file_decrypted)?;
        let output_path = archiver::unarchive(&decrypted_file_path, output_dir)?;

        let msg = format!(
            "Decrypted to {} for {}",
            output_path,
            get_duration(start_time.elapsed().as_secs_f64())
        );
        println!("\n{}", msg);

        Ok(msg)
    })();

    symmetric_key.zeroize();
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

fn encrypt_key(symmetric_key: Vec<u8>, rsa_public_pem: &str) -> Result<Vec<u8>, CryptoError> {
    let rsa = Rsa::public_key_from_pem(rsa_public_pem.as_bytes())?;
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    rsa.public_encrypt(&symmetric_key, &mut buf, Padding::PKCS1_OAEP)?;

    Ok(buf)
}

fn decrypt_key(
    symmetric_key: &[u8],
    rsa_private_pem: &str,
    passphrase: &str,
) -> Result<[u8; KEY_SIZE], CryptoError> {
    let rsa =
        Rsa::private_key_from_pem_passphrase(rsa_private_pem.as_bytes(), passphrase.as_bytes())?;
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    rsa.private_decrypt(symmetric_key, &mut buf, Padding::PKCS1_OAEP)?;

    let mut result: [u8; KEY_SIZE] = Default::default();
    result.copy_from_slice(&buf[0..KEY_SIZE]);

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

    println!("Writing private key to {} ...", private_key_path.display());
    let mut private_key_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&private_key_path)?;
    private_key_file.write_all(&private_key)?;

    println!("Writing public key to {} ...", public_key_path.display());
    let mut public_key_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&public_key_path)?;
    public_key_file.write_all(&public_key)?;

    let result = format!("Generated key pair to {}", output_dir.display());
    println!("\n{}", result);

    Ok(result)
}
