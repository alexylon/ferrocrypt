use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{KeyInit, OsRng, rand_core::RngCore, stream},
};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretString};
use sha3::Sha3_256;
use zeroize::Zeroizing;

use crate::common::{
    ARGON2_SALT_SIZE, DecryptReader, ENCRYPTION_KEY_SIZE, EncryptWriter, FILE_TOO_SHORT,
    HMAC_KEY_SIZE, HMAC_TAG_SIZE, KDF_PARAMS_SIZE, KdfLimit, KdfParams, STREAM_NONCE_SIZE,
    ct_eq_32, encryption_base_name, hmac_sha3_256, hmac_sha3_256_verify, sha3_256_hash,
};
use crate::format::{self, HEADER_PREFIX_ENCODED_SIZE};
use crate::replication::{decode_exact, encode, encoded_size};
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
    let ikm = kdf_params.hash_passphrase(passphrase.expose_secret().as_bytes(), salt)?;

    let hkdf = Hkdf::<Sha3_256>::new(Some(hkdf_salt), ikm.as_ref());
    let mut encryption_key = Zeroizing::new([0u8; ENCRYPTION_KEY_SIZE]);
    let mut hmac_key = Zeroizing::new([0u8; HMAC_KEY_SIZE]);
    hkdf.expand(HKDF_INFO_ENC, encryption_key.as_mut())
        .map_err(|_| {
            CryptoError::InternalError("HKDF expand failed for encryption key".to_string())
        })?;
    hkdf.expand(HKDF_INFO_HMAC, hmac_key.as_mut())
        .map_err(|_| CryptoError::InternalError("HKDF expand failed for HMAC key".to_string()))?;

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
) -> Result<PathBuf, CryptoError> {
    on_progress("Deriving key\u{2026}");
    let kdf_params = KdfParams::default();
    let mut salt = [0u8; ARGON2_SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    let mut hkdf_salt = [0u8; HKDF_SALT_SIZE];
    OsRng.fill_bytes(&mut hkdf_salt);

    let (encryption_key, hmac_key) = derive_keys(passphrase, &salt, &hkdf_salt, &kdf_params)?;

    let cipher = XChaCha20Poly1305::new(encryption_key.as_ref().into());
    let verification_hash: [u8; ENCRYPTION_KEY_SIZE] = sha3_256_hash(encryption_key.as_ref())?;

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

    let mut file_created = false;
    let encrypt_result: Result<(), CryptoError> = (|| {
        let mut dest = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(&working_path)?;
        file_created = true;

        let encoded_salt = encode(&salt);
        let encoded_hkdf_salt = encode(&hkdf_salt);
        let kdf_bytes = kdf_params.to_bytes();
        let encoded_kdf = encode(&kdf_bytes);
        let encoded_key_hash = encode(&verification_hash);

        let mut nonce = [0u8; STREAM_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        let encoded_nonce = encode(&nonce);

        let header_len = (HEADER_PREFIX_ENCODED_SIZE
            + encoded_salt.len()
            + encoded_hkdf_salt.len()
            + encoded_kdf.len()
            + encoded_nonce.len()
            + encoded_key_hash.len()
            + encoded_size(HMAC_TAG_SIZE)) as u16;
        let prefix = format::build_header_prefix(
            format::TYPE_SYMMETRIC,
            format::VERSION_MAJOR,
            0,
            header_len,
        );
        let encoded_prefix = encode(&prefix);

        let stream_encryptor = stream::EncryptorBE32::from_aead(cipher, nonce.as_ref().into());

        let mut hmac_message = Vec::with_capacity(
            prefix.len()
                + ARGON2_SALT_SIZE
                + HKDF_SALT_SIZE
                + KDF_PARAMS_SIZE
                + STREAM_NONCE_SIZE
                + ENCRYPTION_KEY_SIZE,
        );
        hmac_message.extend_from_slice(&prefix);
        hmac_message.extend_from_slice(&salt);
        hmac_message.extend_from_slice(&hkdf_salt);
        hmac_message.extend_from_slice(&kdf_bytes);
        hmac_message.extend_from_slice(&nonce);
        hmac_message.extend_from_slice(&verification_hash);
        let hmac_tag = hmac_sha3_256(hmac_key.as_ref(), &hmac_message)?;
        let encoded_hmac_tag = encode(&hmac_tag);

        dest.write_all(&encoded_prefix)?;
        dest.write_all(&encoded_salt)?;
        dest.write_all(&encoded_hkdf_salt)?;
        dest.write_all(&encoded_kdf)?;
        dest.write_all(&encoded_nonce)?;
        dest.write_all(&encoded_key_hash)?;
        dest.write_all(&encoded_hmac_tag)?;

        let encrypt_writer = EncryptWriter::new(stream_encryptor, dest);
        let (_, encrypt_writer) = archiver::archive(input_path, encrypt_writer)?;
        let dest = encrypt_writer.finish()?;
        dest.sync_all()?;
        Ok(())
    })();

    if let Err(e) = encrypt_result {
        if file_created {
            let _ = fs::remove_file(&working_path);
        }
        return Err(e);
    }

    archiver::rename_no_clobber(&working_path, &output_path)?;
    Ok(output_path)
}

/// Decrypts a file with XChaCha20-Poly1305 streaming decryption.
/// Ciphertext is decrypted into a TAR stream and unpacked directly to the
/// output directory — no plaintext intermediate files touch disk.
pub fn decrypt_file(
    input_path: &Path,
    output_dir: &Path,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
    on_progress: &dyn Fn(&str),
) -> Result<PathBuf, CryptoError> {
    let mut encrypted_file = fs::File::open(input_path)?;

    let (prefix_bytes, header) =
        format::read_header_from_reader(&mut encrypted_file, format::TYPE_SYMMETRIC)?;

    match header.major {
        3 => decrypt_file_v3(
            encrypted_file,
            prefix_bytes,
            header,
            output_dir,
            passphrase,
            kdf_limit,
            on_progress,
        ),
        _ => Err(format::unsupported_file_version_error(
            header.major,
            header.minor,
            format::VERSION_MAJOR,
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
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
    on_progress: &dyn Fn(&str),
) -> Result<PathBuf, CryptoError> {
    format::validate_file_flags(&header)?;

    let min_header_size = HEADER_PREFIX_ENCODED_SIZE
        + encoded_size(ARGON2_SALT_SIZE)
        + encoded_size(HKDF_SALT_SIZE)
        + encoded_size(KDF_PARAMS_SIZE)
        + encoded_size(STREAM_NONCE_SIZE)
        + encoded_size(ENCRYPTION_KEY_SIZE)
        + encoded_size(HMAC_TAG_SIZE);
    if (header.header_len as usize) < min_header_size {
        return Err(CryptoError::InvalidFormat(FILE_TOO_SHORT.to_string()));
    }

    let mut encoded_salt = vec![0u8; encoded_size(ARGON2_SALT_SIZE)];
    let mut encoded_hkdf_salt = vec![0u8; encoded_size(HKDF_SALT_SIZE)];
    let mut encoded_kdf = vec![0u8; encoded_size(KDF_PARAMS_SIZE)];
    let mut encoded_nonce = vec![0u8; encoded_size(STREAM_NONCE_SIZE)];
    let mut encoded_key_hash = vec![0u8; encoded_size(ENCRYPTION_KEY_SIZE)];
    let mut encoded_hmac_tag = vec![0u8; encoded_size(HMAC_TAG_SIZE)];

    encrypted_file
        .read_exact(&mut encoded_salt)
        .map_err(|_| CryptoError::InvalidFormat(FILE_TOO_SHORT.to_string()))?;
    encrypted_file
        .read_exact(&mut encoded_hkdf_salt)
        .map_err(|_| CryptoError::InvalidFormat(FILE_TOO_SHORT.to_string()))?;
    encrypted_file
        .read_exact(&mut encoded_kdf)
        .map_err(|_| CryptoError::InvalidFormat(FILE_TOO_SHORT.to_string()))?;
    encrypted_file
        .read_exact(&mut encoded_nonce)
        .map_err(|_| CryptoError::InvalidFormat(FILE_TOO_SHORT.to_string()))?;
    encrypted_file
        .read_exact(&mut encoded_key_hash)
        .map_err(|_| CryptoError::InvalidFormat(FILE_TOO_SHORT.to_string()))?;
    encrypted_file
        .read_exact(&mut encoded_hmac_tag)
        .map_err(|_| CryptoError::InvalidFormat(FILE_TOO_SHORT.to_string()))?;

    let bytes_after_prefix = encoded_salt.len()
        + encoded_hkdf_salt.len()
        + encoded_kdf.len()
        + encoded_nonce.len()
        + encoded_key_hash.len()
        + encoded_hmac_tag.len();
    format::skip_unknown_header_bytes(&mut encrypted_file, header.header_len, bytes_after_prefix)?;

    let salt = decode_exact(&encoded_salt, ARGON2_SALT_SIZE)?;
    let hkdf_salt = decode_exact(&encoded_hkdf_salt, HKDF_SALT_SIZE)?;
    let kdf_bytes = decode_exact(&encoded_kdf, KDF_PARAMS_SIZE)?;
    let kdf_params = KdfParams::from_bytes(kdf_bytes.as_slice().try_into()?, kdf_limit)?;
    let nonce = decode_exact(&encoded_nonce, STREAM_NONCE_SIZE)?;
    let verification_hash = decode_exact(&encoded_key_hash, ENCRYPTION_KEY_SIZE)?;
    let hmac_tag = decode_exact(&encoded_hmac_tag, HMAC_TAG_SIZE)?;

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
        let key_hash: [u8; ENCRYPTION_KEY_SIZE] = sha3_256_hash(encryption_key.as_ref())?;
        let key_correct = ct_eq_32(&key_hash, verification_hash.as_slice().try_into()?);
        if !key_correct {
            return Err(CryptoError::AuthenticationFailed);
        }
        return Err(hmac_err);
    }

    on_progress("Decrypting\u{2026}");
    let cipher = XChaCha20Poly1305::new(encryption_key.as_ref().into());
    let stream_decryptor = stream::DecryptorBE32::from_aead(cipher, nonce.as_slice().into());

    let decrypt_reader = DecryptReader::new(stream_decryptor, encrypted_file);
    archiver::unarchive(decrypt_reader, output_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Proves the forward-compatibility mechanism: a synthetic v3.1 file with
    /// extra trailing header bytes (and correctly recomputed HMAC) is decrypted
    /// successfully by the current v3 reader via `skip_unknown_header_bytes`.
    #[test]
    fn future_minor_version_forward_compatible() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("data.txt");
        let encrypt_dir = tmp.path().join("encrypted");
        let decrypt_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&encrypt_dir)?;
        fs::create_dir_all(&decrypt_dir)?;
        fs::write(&input_file, "forward compat test")?;

        let passphrase = SecretString::from("pass".to_string());
        encrypt_file(&input_file, &encrypt_dir, &passphrase, None, &|_| {})?;

        let encrypted_path = encrypt_dir.join("data.fcr");
        let original = fs::read(&encrypted_path)?;

        // --- Decode the v3.0 header to extract fields and derive keys ---
        let encoded_prefix = &original[..HEADER_PREFIX_ENCODED_SIZE];
        let prefix_bytes = decode_exact(encoded_prefix, format::HEADER_PREFIX_SIZE)?;
        let old_header_len = u16::from_be_bytes([prefix_bytes[4], prefix_bytes[5]]) as usize;

        let mut cursor = Cursor::new(&original[HEADER_PREFIX_ENCODED_SIZE..]);
        let mut enc_salt = vec![0u8; encoded_size(ARGON2_SALT_SIZE)];
        let mut enc_hkdf = vec![0u8; encoded_size(HKDF_SALT_SIZE)];
        let mut enc_kdf = vec![0u8; encoded_size(KDF_PARAMS_SIZE)];
        let mut enc_nonce = vec![0u8; encoded_size(STREAM_NONCE_SIZE)];
        let mut enc_keyhash = vec![0u8; encoded_size(ENCRYPTION_KEY_SIZE)];
        let mut enc_hmac = vec![0u8; encoded_size(HMAC_TAG_SIZE)];
        cursor.read_exact(&mut enc_salt)?;
        cursor.read_exact(&mut enc_hkdf)?;
        cursor.read_exact(&mut enc_kdf)?;
        cursor.read_exact(&mut enc_nonce)?;
        cursor.read_exact(&mut enc_keyhash)?;
        cursor.read_exact(&mut enc_hmac)?;

        let salt = decode_exact(&enc_salt, ARGON2_SALT_SIZE)?;
        let hkdf_salt = decode_exact(&enc_hkdf, HKDF_SALT_SIZE)?;
        let kdf_bytes = decode_exact(&enc_kdf, KDF_PARAMS_SIZE)?;
        let kdf_params = KdfParams::from_bytes(kdf_bytes.as_slice().try_into()?, None)?;
        let nonce = decode_exact(&enc_nonce, STREAM_NONCE_SIZE)?;
        let verification_hash = decode_exact(&enc_keyhash, ENCRYPTION_KEY_SIZE)?;

        let (_encryption_key, hmac_key) = derive_keys(&passphrase, &salt, &hkdf_salt, &kdf_params)?;

        // --- Build a synthetic v3.1 prefix with larger header_len ---
        let extra_bytes = 16usize;
        let new_header_len = (old_header_len + extra_bytes) as u16;
        let new_prefix = [
            format::MAGIC_BYTE,
            format::TYPE_SYMMETRIC,
            format::VERSION_MAJOR,
            1, // minor = 1
            (new_header_len >> 8) as u8,
            (new_header_len & 0xFF) as u8,
            0,
            0,
        ];

        // --- Recompute HMAC over the new prefix + same decoded fields ---
        let mut hmac_message = Vec::new();
        hmac_message.extend_from_slice(&new_prefix);
        hmac_message.extend_from_slice(&salt);
        hmac_message.extend_from_slice(&hkdf_salt);
        hmac_message.extend_from_slice(&kdf_bytes);
        hmac_message.extend_from_slice(&nonce);
        hmac_message.extend_from_slice(&verification_hash);
        let new_hmac_tag = hmac_sha3_256(hmac_key.as_ref(), &hmac_message)?;

        // --- Reassemble: new prefix + same fields + new HMAC + trailing + ciphertext ---
        let ciphertext = &original[old_header_len..];
        let mut output = Vec::new();
        output.extend_from_slice(&encode(&new_prefix));
        output.extend_from_slice(&enc_salt);
        output.extend_from_slice(&enc_hkdf);
        output.extend_from_slice(&enc_kdf);
        output.extend_from_slice(&enc_nonce);
        output.extend_from_slice(&enc_keyhash);
        output.extend_from_slice(&encode(&new_hmac_tag));
        output.extend_from_slice(&vec![0xAA; extra_bytes]); // synthetic trailing field
        output.extend_from_slice(ciphertext);

        fs::write(&encrypted_path, &output)?;

        // --- Decrypt with the current v3 reader ---
        let output = decrypt_file(&encrypted_path, &decrypt_dir, &passphrase, None, &|_| {})?;
        assert!(output.exists());

        let decrypted = fs::read_to_string(decrypt_dir.join("data.txt"))?;
        assert_eq!(decrypted, "forward compat test");

        Ok(())
    }
}
