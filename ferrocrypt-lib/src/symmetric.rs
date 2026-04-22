use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{KeyInit, OsRng, rand_core::RngCore, stream},
};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretString};
use sha3::Sha3_256;
use zeroize::Zeroizing;

use crate::atomic_output;
use crate::common::{
    ARGON2_SALT_SIZE, DecryptReader, ENCRYPTION_KEY_SIZE, EncryptWriter, HMAC_KEY_SIZE,
    HMAC_TAG_SIZE, KDF_PARAMS_SIZE, KdfLimit, KdfParams, STREAM_NONCE_SIZE, encryption_base_name,
    hmac_sha3_256, hmac_sha3_256_verify,
};
use crate::format::{self, HEADER_PREFIX_SIZE};
use crate::replication::encode;
use crate::{CryptoError, ProgressEvent, archiver};

const HKDF_SALT_SIZE: usize = 32;
const HKDF_INFO_ENC: &[u8] = b"ferrocrypt-enc";
const HKDF_INFO_HMAC: &[u8] = b"ferrocrypt-hmac";

type DerivedKeys = (
    Zeroizing<[u8; ENCRYPTION_KEY_SIZE]>,
    Zeroizing<[u8; HMAC_KEY_SIZE]>,
);

/// Authenticated core of a symmetric `.fcr` header.
///
/// Sits between the 8-byte prefix (which carries `ext_len`) and the trailing
/// HMAC tag. Field order is the single source of truth for the symmetric
/// wire format — every code path (encrypt, decrypt, HMAC computation) goes
/// through this struct so writer and reader cannot drift.
struct SymmetricHeaderCore {
    salt: [u8; ARGON2_SALT_SIZE],
    hkdf_salt: [u8; HKDF_SALT_SIZE],
    kdf_bytes: [u8; KDF_PARAMS_SIZE],
    stream_nonce: [u8; STREAM_NONCE_SIZE],
    ext_bytes: Vec<u8>,
}

impl SymmetricHeaderCore {
    /// Constructs a core after validating the `ext_bytes` length bound.
    ///
    /// `ext_bytes.len()` must fit in a `u16` because the header prefix stores
    /// `ext_len` as a big-endian `u16`. This is the single enforcement point:
    /// once a `SymmetricHeaderCore` exists, `ext_len()` is infallible by
    /// construction.
    fn new(
        salt: [u8; ARGON2_SALT_SIZE],
        hkdf_salt: [u8; HKDF_SALT_SIZE],
        kdf_bytes: [u8; KDF_PARAMS_SIZE],
        stream_nonce: [u8; STREAM_NONCE_SIZE],
        ext_bytes: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        if ext_bytes.len() > u16::MAX as usize {
            return Err(CryptoError::InvalidInput(
                "ext_bytes exceeds u16::MAX".to_string(),
            ));
        }
        Ok(Self {
            salt,
            hkdf_salt,
            kdf_bytes,
            stream_nonce,
            ext_bytes,
        })
    }

    /// Writes every field, in canonical order, using triple replication.
    fn write_to(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(&encode(&self.salt))?;
        writer.write_all(&encode(&self.hkdf_salt))?;
        writer.write_all(&encode(&self.kdf_bytes))?;
        writer.write_all(&encode(&self.stream_nonce))?;
        writer.write_all(&encode(&self.ext_bytes))?;
        Ok(())
    }

    /// Reads every field, in canonical order, from a triple-replicated stream.
    /// `ext_len` is the logical size of the `ext_bytes` region, taken from
    /// the authenticated header prefix.
    fn read_from(reader: &mut impl io::Read, ext_len: usize) -> Result<Self, CryptoError> {
        Self::new(
            format::read_replicated_field::<ARGON2_SALT_SIZE>(reader)?,
            format::read_replicated_field::<HKDF_SALT_SIZE>(reader)?,
            format::read_replicated_field::<KDF_PARAMS_SIZE>(reader)?,
            format::read_replicated_field::<STREAM_NONCE_SIZE>(reader)?,
            format::read_replicated_vec(reader, ext_len)?,
        )
    }

    /// Canonical HMAC-SHA3-256 input: `prefix || fixed_core || ext_bytes`.
    fn hmac_input(&self, prefix: &[u8; HEADER_PREFIX_SIZE]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(
            prefix.len()
                + ARGON2_SALT_SIZE
                + HKDF_SALT_SIZE
                + KDF_PARAMS_SIZE
                + STREAM_NONCE_SIZE
                + self.ext_bytes.len(),
        );
        msg.extend_from_slice(prefix);
        msg.extend_from_slice(&self.salt);
        msg.extend_from_slice(&self.hkdf_salt);
        msg.extend_from_slice(&self.kdf_bytes);
        msg.extend_from_slice(&self.stream_nonce);
        msg.extend_from_slice(&self.ext_bytes);
        msg
    }

    /// Returns the `ext_len` value to pack into the header prefix.
    /// Infallible by construction: `Self::new` rejects oversized `ext_bytes`.
    fn ext_len(&self) -> u16 {
        self.ext_bytes.len() as u16
    }
}

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
            CryptoError::InternalCryptoFailure("internal error: failed to derive encryption key")
        })?;
    hkdf.expand(HKDF_INFO_HMAC, hmac_key.as_mut())
        .map_err(|_| {
            CryptoError::InternalCryptoFailure(
                "internal error: failed to derive header authentication key",
            )
        })?;

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
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    on_event(&ProgressEvent::DerivingKey);
    let kdf_params = KdfParams::default();
    let mut salt = [0u8; ARGON2_SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    let mut hkdf_salt = [0u8; HKDF_SALT_SIZE];
    OsRng.fill_bytes(&mut hkdf_salt);

    let (encryption_key, hmac_key) = derive_keys(passphrase, &salt, &hkdf_salt, &kdf_params)?;

    let cipher = XChaCha20Poly1305::new(encryption_key.as_ref().into());

    let base_name = &encryption_base_name(input_path)?;
    on_event(&ProgressEvent::Encrypting);

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

    let temp_dir = output_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".ferrocrypt-")
        .suffix(".incomplete")
        .tempfile_in(temp_dir)?;

    let encrypt_result: Result<tempfile::NamedTempFile, CryptoError> = (|| {
        let mut stream_nonce = [0u8; STREAM_NONCE_SIZE];
        OsRng.fill_bytes(&mut stream_nonce);

        // No extensions today. `ext_bytes` is an empty authenticated region;
        // future minor versions append optional data here and it will be
        // bound to the file by the HMAC.
        let core = SymmetricHeaderCore::new(
            salt,
            hkdf_salt,
            kdf_params.to_bytes(),
            stream_nonce,
            Vec::new(),
        )?;

        let prefix = format::build_header_prefix(
            format::TYPE_SYMMETRIC,
            format::VERSION_MAJOR,
            0,
            core.ext_len(),
        );
        let hmac_tag = hmac_sha3_256(hmac_key.as_ref(), &core.hmac_input(&prefix))?;

        let stream_encryptor =
            stream::EncryptorBE32::from_aead(cipher, stream_nonce.as_ref().into());

        tmp.as_file_mut().write_all(&encode(&prefix))?;
        core.write_to(tmp.as_file_mut())?;
        tmp.as_file_mut().write_all(&encode(&hmac_tag))?;

        // Pass the temp file by value so the encrypted stream writes
        // through the same handle used for the header, then recover it
        // for sync + persist.
        let encrypt_writer = EncryptWriter::new(stream_encryptor, tmp);
        let (_, encrypt_writer) = archiver::archive(input_path, encrypt_writer)?;
        let tmp = encrypt_writer.finish()?;
        tmp.as_file().sync_all()?;
        Ok(tmp)
    })();

    let tmp = encrypt_result?;
    atomic_output::finalize_file(tmp, &output_path)?;
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
    on_event: &dyn Fn(&ProgressEvent),
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
            on_event,
        ),
        _ => Err(format::unsupported_file_version_error(
            header.major,
            header.minor,
            format::VERSION_MAJOR,
        )),
    }
}

fn decrypt_file_v3(
    mut encrypted_file: fs::File,
    prefix_bytes: [u8; format::HEADER_PREFIX_SIZE],
    header: format::FileHeader,
    output_dir: &Path,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    format::validate_file_flags(&header)?;

    // v3 minor-version dispatch: every 3.x minor decrypts identically — the
    // ext_bytes region is authenticated by HMAC and the contents are ignored.
    // Bound here so the field is read on the success path and the contract
    // is visible at the call site. Per FORMAT.md §10.2, minor versions are
    // always forward-compatible (never rejected); a future 3.x minor that
    // needs special behavior would replace this with a `match header.minor`
    // where the wildcard arm is still the default ignore.
    let _minor: u8 = header.minor;

    let core = SymmetricHeaderCore::read_from(&mut encrypted_file, header.ext_len as usize)?;
    let hmac_tag = format::read_replicated_field::<HMAC_TAG_SIZE>(&mut encrypted_file)?;

    let kdf_params = KdfParams::from_bytes(&core.kdf_bytes, kdf_limit)?;

    on_event(&ProgressEvent::DerivingKey);
    let (encryption_key, hmac_key) =
        derive_keys(passphrase, &core.salt, &core.hkdf_salt, &kdf_params)?;

    hmac_sha3_256_verify(
        hmac_key.as_ref(),
        &core.hmac_input(&prefix_bytes),
        &hmac_tag,
        || CryptoError::SymmetricHeaderAuthenticationFailed,
    )?;

    on_event(&ProgressEvent::Decrypting);
    let cipher = XChaCha20Poly1305::new(encryption_key.as_ref().into());
    let stream_decryptor =
        stream::DecryptorBE32::from_aead(cipher, core.stream_nonce.as_slice().into());

    let decrypt_reader = DecryptReader::new(stream_decryptor, encrypted_file);
    archiver::unarchive(decrypt_reader, output_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::HEADER_PREFIX_ENCODED_SIZE;
    use crate::replication::{decode_exact, encoded_size};
    use std::io::{Cursor, Read};

    /// Helper: reads the v3.0 header of a freshly-encrypted file and returns the
    /// decoded fields plus the byte offset at which ciphertext begins.
    #[allow(clippy::type_complexity)]
    fn read_v3_header_fields(
        bytes: &[u8],
    ) -> Result<
        (
            Vec<u8>, // salt
            Vec<u8>, // hkdf_salt
            Vec<u8>, // kdf_bytes
            Vec<u8>, // nonce
            usize,   // ciphertext_offset
        ),
        CryptoError,
    > {
        let mut cursor = Cursor::new(&bytes[HEADER_PREFIX_ENCODED_SIZE..]);
        let mut enc_salt = vec![0u8; encoded_size(ARGON2_SALT_SIZE)];
        let mut enc_hkdf = vec![0u8; encoded_size(HKDF_SALT_SIZE)];
        let mut enc_kdf = vec![0u8; encoded_size(KDF_PARAMS_SIZE)];
        let mut enc_nonce = vec![0u8; encoded_size(STREAM_NONCE_SIZE)];
        let mut enc_ext = vec![0u8; encoded_size(0)]; // v3.0 ships ext_len = 0
        let mut enc_hmac = vec![0u8; encoded_size(HMAC_TAG_SIZE)];
        cursor.read_exact(&mut enc_salt)?;
        cursor.read_exact(&mut enc_hkdf)?;
        cursor.read_exact(&mut enc_kdf)?;
        cursor.read_exact(&mut enc_nonce)?;
        cursor.read_exact(&mut enc_ext)?;
        cursor.read_exact(&mut enc_hmac)?;

        let ciphertext_offset = HEADER_PREFIX_ENCODED_SIZE + cursor.position() as usize;
        Ok((
            decode_exact(&enc_salt, ARGON2_SALT_SIZE)?,
            decode_exact(&enc_hkdf, HKDF_SALT_SIZE)?,
            decode_exact(&enc_kdf, KDF_PARAMS_SIZE)?,
            decode_exact(&enc_nonce, STREAM_NONCE_SIZE)?,
            ciphertext_offset,
        ))
    }

    /// Proves the forward-compatibility mechanism: a synthetic v3.1 file with a
    /// non-empty authenticated `ext_bytes` region (and correctly recomputed HMAC)
    /// is decrypted successfully by the current v3 reader. The reader reads
    /// `ext_len` bytes, feeds them into the HMAC verification, and then ignores
    /// their contents.
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

        let (salt, hkdf_salt, kdf_bytes, nonce, ciphertext_offset) =
            read_v3_header_fields(&original)?;
        let kdf_params = KdfParams::from_bytes(kdf_bytes.as_slice().try_into()?, None)?;
        let (_encryption_key, hmac_key) = derive_keys(&passphrase, &salt, &hkdf_salt, &kdf_params)?;

        // Synthetic v3.1 extension: 16 opaque authenticated bytes.
        let ext_bytes: Vec<u8> = (0..16u8).collect();
        let new_prefix = format::build_header_prefix(
            format::TYPE_SYMMETRIC,
            format::VERSION_MAJOR,
            0,
            ext_bytes.len() as u16,
        );
        let mut new_prefix_with_minor = new_prefix;
        new_prefix_with_minor[3] = 1; // minor = 1

        // Recompute HMAC over prefix || fixed_core || ext_bytes.
        let mut hmac_message = Vec::new();
        hmac_message.extend_from_slice(&new_prefix_with_minor);
        hmac_message.extend_from_slice(&salt);
        hmac_message.extend_from_slice(&hkdf_salt);
        hmac_message.extend_from_slice(&kdf_bytes);
        hmac_message.extend_from_slice(&nonce);
        hmac_message.extend_from_slice(&ext_bytes);
        let new_hmac_tag = hmac_sha3_256(hmac_key.as_ref(), &hmac_message)?;

        // Reassemble: new prefix + fixed core + ext_bytes + new HMAC + ciphertext.
        let ciphertext = &original[ciphertext_offset..];
        let mut output = Vec::new();
        output.extend_from_slice(&encode(&new_prefix_with_minor));
        // Copy fixed core bytes verbatim from the original file.
        let fixed_core_end = HEADER_PREFIX_ENCODED_SIZE
            + encoded_size(ARGON2_SALT_SIZE)
            + encoded_size(HKDF_SALT_SIZE)
            + encoded_size(KDF_PARAMS_SIZE)
            + encoded_size(STREAM_NONCE_SIZE);
        output.extend_from_slice(&original[HEADER_PREFIX_ENCODED_SIZE..fixed_core_end]);
        output.extend_from_slice(&encode(&ext_bytes));
        output.extend_from_slice(&encode(&new_hmac_tag));
        output.extend_from_slice(ciphertext);

        fs::write(&encrypted_path, &output)?;

        let output = decrypt_file(&encrypted_path, &decrypt_dir, &passphrase, None, &|_| {})?;
        assert!(output.exists());

        let decrypted = fs::read_to_string(decrypt_dir.join("data.txt"))?;
        assert_eq!(decrypted, "forward compat test");

        Ok(())
    }

    /// Tampering any byte inside the authenticated `ext_bytes` region must break
    /// HMAC verification and cause decryption to fail. This is the structural
    /// property introduced by the new header layout — older designs could not
    /// detect tampering of trailing extension bytes.
    #[test]
    fn ext_bytes_tamper_detected() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("data.txt");
        let encrypt_dir = tmp.path().join("encrypted");
        let decrypt_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&encrypt_dir)?;
        fs::create_dir_all(&decrypt_dir)?;
        fs::write(&input_file, "tamper test")?;

        let passphrase = SecretString::from("pass".to_string());
        encrypt_file(&input_file, &encrypt_dir, &passphrase, None, &|_| {})?;

        let encrypted_path = encrypt_dir.join("data.fcr");
        let original = fs::read(&encrypted_path)?;

        let (salt, hkdf_salt, kdf_bytes, nonce, ciphertext_offset) =
            read_v3_header_fields(&original)?;
        let kdf_params = KdfParams::from_bytes(kdf_bytes.as_slice().try_into()?, None)?;
        let (_enc_key, hmac_key) = derive_keys(&passphrase, &salt, &hkdf_salt, &kdf_params)?;

        // Build a legitimate v3.1 file with 8 bytes of ext_bytes, authenticated.
        let ext_bytes = vec![0xAAu8; 8];
        let new_prefix = format::build_header_prefix(
            format::TYPE_SYMMETRIC,
            format::VERSION_MAJOR,
            0,
            ext_bytes.len() as u16,
        );
        let mut hmac_message = Vec::new();
        hmac_message.extend_from_slice(&new_prefix);
        hmac_message.extend_from_slice(&salt);
        hmac_message.extend_from_slice(&hkdf_salt);
        hmac_message.extend_from_slice(&kdf_bytes);
        hmac_message.extend_from_slice(&nonce);
        hmac_message.extend_from_slice(&ext_bytes);
        let hmac_tag = hmac_sha3_256(hmac_key.as_ref(), &hmac_message)?;

        let ciphertext = &original[ciphertext_offset..];
        let fixed_core_end = HEADER_PREFIX_ENCODED_SIZE
            + encoded_size(ARGON2_SALT_SIZE)
            + encoded_size(HKDF_SALT_SIZE)
            + encoded_size(KDF_PARAMS_SIZE)
            + encoded_size(STREAM_NONCE_SIZE);

        // Tamper ext_bytes: flip every byte to 0xBB before encoding.
        let tampered_ext = vec![0xBBu8; 8];

        let mut output = Vec::new();
        output.extend_from_slice(&encode(&new_prefix));
        output.extend_from_slice(&original[HEADER_PREFIX_ENCODED_SIZE..fixed_core_end]);
        output.extend_from_slice(&encode(&tampered_ext));
        output.extend_from_slice(&encode(&hmac_tag));
        output.extend_from_slice(ciphertext);

        fs::write(&encrypted_path, &output)?;

        let result = decrypt_file(&encrypted_path, &decrypt_dir, &passphrase, None, &|_| {});
        assert!(result.is_err(), "tampered ext_bytes must fail HMAC");
        Ok(())
    }

    /// Reserved-bit fail-closed: a v3.0 file with `flags = 0x0001` must be
    /// rejected with the typed `UnknownHeaderFlags` variant. Since the header
    /// HMAC covers the prefix (flags included), this test recomputes a valid
    /// HMAC for the patched prefix — without that, an HMAC failure could
    /// mask what the flag check actually does, and the assertion would not
    /// pin the flag-rejection path independently.
    #[test]
    fn nonzero_flags_rejected_with_valid_hmac() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("data.txt");
        let encrypt_dir = tmp.path().join("encrypted");
        let decrypt_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&encrypt_dir)?;
        fs::create_dir_all(&decrypt_dir)?;
        fs::write(&input_file, "flag rejection test")?;

        let passphrase = SecretString::from("pass".to_string());
        encrypt_file(&input_file, &encrypt_dir, &passphrase, None, &|_| {})?;

        let encrypted_path = encrypt_dir.join("data.fcr");
        let original = fs::read(&encrypted_path)?;

        let (salt, hkdf_salt, kdf_bytes, nonce, ciphertext_offset) =
            read_v3_header_fields(&original)?;
        let kdf_params = KdfParams::from_bytes(kdf_bytes.as_slice().try_into()?, None)?;
        let (_enc_key, hmac_key) = derive_keys(&passphrase, &salt, &hkdf_salt, &kdf_params)?;

        // Build a v3.0 header with flags = 0x0001 and a recomputed valid HMAC.
        let new_prefix =
            format::build_header_prefix(format::TYPE_SYMMETRIC, format::VERSION_MAJOR, 0x0001, 0);
        let mut hmac_message = Vec::new();
        hmac_message.extend_from_slice(&new_prefix);
        hmac_message.extend_from_slice(&salt);
        hmac_message.extend_from_slice(&hkdf_salt);
        hmac_message.extend_from_slice(&kdf_bytes);
        hmac_message.extend_from_slice(&nonce);
        let hmac_tag = hmac_sha3_256(hmac_key.as_ref(), &hmac_message)?;

        let ciphertext = &original[ciphertext_offset..];
        let fixed_core_end = HEADER_PREFIX_ENCODED_SIZE
            + encoded_size(ARGON2_SALT_SIZE)
            + encoded_size(HKDF_SALT_SIZE)
            + encoded_size(KDF_PARAMS_SIZE)
            + encoded_size(STREAM_NONCE_SIZE);

        let mut output = Vec::new();
        output.extend_from_slice(&encode(&new_prefix));
        output.extend_from_slice(&original[HEADER_PREFIX_ENCODED_SIZE..fixed_core_end]);
        output.extend_from_slice(&encode(&[])); // ext_bytes = empty
        output.extend_from_slice(&encode(&hmac_tag));
        output.extend_from_slice(ciphertext);

        fs::write(&encrypted_path, &output)?;

        let result = decrypt_file(&encrypted_path, &decrypt_dir, &passphrase, None, &|_| {});
        match result {
            Err(CryptoError::InvalidFormat(crate::error::FormatDefect::UnknownHeaderFlags(
                0x0001,
            ))) => Ok(()),
            other => panic!("expected UnknownHeaderFlags(0x0001), got: {other:?}"),
        }
    }

    /// `SymmetricHeaderCore::new` must accept an `ext_bytes` exactly the size
    /// of `u16::MAX` (the on-disk maximum) and reject anything larger. This
    /// is the single enforcement point for the wire-format bound; an untested
    /// check is an aspirational check.
    #[test]
    fn new_rejects_oversized_ext_bytes() {
        let salt = [0u8; ARGON2_SALT_SIZE];
        let hkdf_salt = [0u8; HKDF_SALT_SIZE];
        let kdf_bytes = [0u8; KDF_PARAMS_SIZE];
        let stream_nonce = [0u8; STREAM_NONCE_SIZE];

        // Max u16 accepted.
        let accepted = SymmetricHeaderCore::new(
            salt,
            hkdf_salt,
            kdf_bytes,
            stream_nonce,
            vec![0u8; u16::MAX as usize],
        );
        assert!(accepted.is_ok(), "u16::MAX ext_bytes must be accepted");

        // One byte over max is rejected.
        let rejected = SymmetricHeaderCore::new(
            salt,
            hkdf_salt,
            kdf_bytes,
            stream_nonce,
            vec![0u8; u16::MAX as usize + 1],
        );
        match rejected {
            Ok(_) => panic!("u16::MAX + 1 ext_bytes must be rejected"),
            Err(CryptoError::InvalidInput(_)) => {}
            Err(other) => panic!("expected InvalidInput, got: {other:?}"),
        }
    }
}
