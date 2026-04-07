use std::cmp;
use std::io::{self, Read, Write};
use std::path::Path;

use chacha20poly1305::{XChaCha20Poly1305, aead::stream};
use constant_time_eq::constant_time_eq_32;
use hmac::{Hmac, KeyInit, Mac};
use sha3::{Digest, Sha3_256};

use crate::CryptoError;

type HmacSha3_256 = Hmac<Sha3_256>;

/// KDF parameters stored in file headers and key files so that decryption
/// uses the same cost parameters that were used during encryption.
pub struct KdfParams {
    pub mem_cost: u32,
    pub time_cost: u32,
    pub lanes: u32,
}

pub const KDF_PARAMS_SIZE: usize = 12; // 3 × u32 big-endian

impl KdfParams {
    pub fn default_params() -> Self {
        // "fast-kdf" uses minimal Argon2 params so tests finish quickly.
        // The feature is auto-enabled via [dev-dependencies] and blocked
        // in release builds by a compile_error! guard in lib.rs.
        let (mem_cost, time_cost) = if cfg!(feature = "fast-kdf") {
            (8192, 1)
        } else {
            (1048576, 4)
        };
        Self {
            mem_cost,
            time_cost,
            lanes: 4,
        }
    }

    pub fn to_bytes(&self) -> [u8; KDF_PARAMS_SIZE] {
        let mut buf = [0u8; KDF_PARAMS_SIZE];
        buf[0..4].copy_from_slice(&self.mem_cost.to_be_bytes());
        buf[4..8].copy_from_slice(&self.time_cost.to_be_bytes());
        buf[8..12].copy_from_slice(&self.lanes.to_be_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8; KDF_PARAMS_SIZE]) -> Result<Self, CryptoError> {
        let params = Self {
            mem_cost: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            time_cost: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            lanes: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        };
        // Cap at 8 GiB to prevent malicious files from triggering OOM
        if params.mem_cost > 8 * 1024 * 1024 {
            return Err(CryptoError::CryptoOperation(format!(
                "KDF memory cost {} KiB exceeds maximum (8 GiB)",
                params.mem_cost
            )));
        }
        Ok(params)
    }

    pub fn to_argon2_config(&self) -> argon2::Config<'static> {
        argon2::Config {
            variant: argon2::Variant::Argon2id,
            hash_length: 32,
            lanes: self.lanes,
            mem_cost: self.mem_cost,
            time_cost: self.time_cost,
            ..Default::default()
        }
    }
}

// ─── Shared crypto sizes ──────────────────────────────────────────────────
pub const ENCRYPTION_KEY_SIZE: usize = 32;
pub const HMAC_KEY_SIZE: usize = 32;
/// HMAC-SHA3-256 output size in bytes (distinct from `HMAC_KEY_SIZE`).
pub const HMAC_TAG_SIZE: usize = 32;
pub const ARGON2_SALT_SIZE: usize = 32;

// ─── Streaming encryption sizes ───────────────────────────────────────────
/// Streaming I/O buffer size.
pub const BUFFER_SIZE: usize = 65536;
/// Poly1305 authentication tag size in bytes.
pub const TAG_SIZE: usize = 16;
/// STREAM nonce size: XChaCha20's 24-byte nonce minus 5 bytes for counter and last-block flag.
pub const NONCE_SIZE: usize = 19;

// ─── Error messages ───────────────────────────────────────────────────────
pub const ERR_FILE_TOO_SHORT: &str = "File is too short or corrupted";

pub fn get_file_stem_to_string(filename: impl AsRef<Path>) -> Result<String, CryptoError> {
    let file_stem_string = filename
        .as_ref()
        .file_stem()
        .ok_or_else(|| CryptoError::InvalidInput("Cannot get file stem".to_string()))?
        .to_str()
        .ok_or_else(|| CryptoError::InvalidInput("Cannot convert file stem to &str".to_string()))?
        .to_string();

    Ok(file_stem_string)
}

pub fn sha3_32_hash(data: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let digest: [u8; 32] = hasher.finalize().as_slice().try_into()?;

    Ok(digest)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Compares two 256-bit byte strings in constant time.
pub fn constant_time_compare_256_bit(a: &[u8; 32], b: &[u8; 32]) -> bool {
    constant_time_eq_32(a, b)
}

pub fn hmac_sha3_256(key: &[u8], data: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut mac = HmacSha3_256::new_from_slice(key)
        .map_err(|e| CryptoError::CryptoOperation(format!("HMAC key error: {}", e)))?;
    mac.update(data);
    let result = mac.finalize();
    let bytes: [u8; 32] = result.into_bytes().into();
    Ok(bytes)
}

/// Verifies HMAC-SHA3-256 in constant time. Returns error if mismatch.
pub fn hmac_sha3_256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
    let mut mac = HmacSha3_256::new_from_slice(key)
        .map_err(|e| CryptoError::CryptoOperation(format!("HMAC key error: {}", e)))?;
    mac.update(data);
    mac.verify_slice(tag).map_err(|_| {
        CryptoError::CryptoOperation(
            "Header authentication failed: file may be corrupted or tampered with".to_string(),
        )
    })
}

pub fn get_duration(seconds: f64) -> String {
    if seconds < 60_f64 {
        format!("{:.2} sec", seconds)
    } else {
        format!("{} min, {:.2} sec", seconds as u32 / 60, seconds % 60_f64)
    }
}

/// Streaming encryption writer: buffers plaintext writes into `BUFFER_SIZE`
/// chunks, encrypts each chunk with `encrypt_next`, and writes ciphertext to
/// the inner writer. Call `finish()` after all data is written to encrypt the
/// final (possibly partial) chunk with `encrypt_last`.
///
/// Full `BUFFER_SIZE` chunks use `encrypt_next`; the final chunk (0..BUFFER_SIZE
/// bytes) uses `encrypt_last`.
pub struct EncryptWriter<W: Write> {
    encryptor: Option<stream::EncryptorBE32<XChaCha20Poly1305>>,
    buffer: Vec<u8>,
    output: W,
}

impl<W: Write> EncryptWriter<W> {
    pub fn new(encryptor: stream::EncryptorBE32<XChaCha20Poly1305>, output: W) -> Self {
        Self {
            encryptor: Some(encryptor),
            buffer: Vec::with_capacity(BUFFER_SIZE),
            output,
        }
    }

    /// Encrypts the remaining buffer as the final AEAD chunk and flushes.
    /// Must be called exactly once after all plaintext has been written.
    pub fn finish(mut self) -> Result<(), CryptoError> {
        let encryptor = self.encryptor.take().ok_or_else(|| {
            CryptoError::InvalidInput("EncryptWriter already finished".to_string())
        })?;
        let ciphertext = encryptor
            .encrypt_last(self.buffer.as_slice())
            .map_err(CryptoError::Cipher)?;
        self.output.write_all(&ciphertext)?;
        self.output.flush()?;
        Ok(())
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let encryptor = self.encryptor.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "EncryptWriter already finished")
        })?;

        self.buffer.extend_from_slice(buf);

        while self.buffer.len() >= BUFFER_SIZE {
            let remaining = self.buffer.split_off(BUFFER_SIZE);
            let chunk = std::mem::replace(&mut self.buffer, remaining);
            let ciphertext = encryptor
                .encrypt_next(chunk.as_slice())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            self.output.write_all(&ciphertext)?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

/// Streaming decryption reader: reads ciphertext chunks of `BUFFER_SIZE + TAG_SIZE`
/// from the inner reader, decrypts each with `decrypt_next` / `decrypt_last`,
/// and serves plaintext through the `Read` interface.
///
/// A full-size ciphertext chunk (`BUFFER_SIZE + TAG_SIZE` bytes) is a non-final
/// chunk; a shorter read indicates the final chunk.
pub struct DecryptReader<R: Read> {
    decryptor: Option<stream::DecryptorBE32<XChaCha20Poly1305>>,
    input: R,
    plaintext: Vec<u8>,
    pos: usize,
    done: bool,
}

impl<R: Read> DecryptReader<R> {
    pub fn new(decryptor: stream::DecryptorBE32<XChaCha20Poly1305>, input: R) -> Self {
        Self {
            decryptor: Some(decryptor),
            input,
            plaintext: Vec::new(),
            pos: 0,
            done: false,
        }
    }

    fn fill_buffer(&mut self) -> io::Result<()> {
        const ENCRYPTED_CHUNK_SIZE: usize = BUFFER_SIZE + TAG_SIZE;
        let mut encrypted = vec![0u8; ENCRYPTED_CHUNK_SIZE];
        let mut filled = 0;
        while filled < ENCRYPTED_CHUNK_SIZE {
            let n = self.input.read(&mut encrypted[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }

        if filled == 0 {
            // A valid stream always ends with an encrypt_last chunk (>= TAG_SIZE
            // bytes). Reading 0 bytes means the final chunk is missing — the
            // ciphertext was truncated at a chunk boundary.
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "encrypted stream truncated: missing final chunk",
            ));
        }

        if filled == ENCRYPTED_CHUNK_SIZE {
            let decryptor = self.decryptor.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "decryptor already consumed")
            })?;
            self.plaintext = decryptor
                .decrypt_next(encrypted.as_slice())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        } else {
            let decryptor = self.decryptor.take().ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "decryptor already consumed")
            })?;
            self.plaintext = decryptor
                .decrypt_last(&encrypted[..filled])
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            self.done = true;
        }

        self.pos = 0;
        Ok(())
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.plaintext.len() {
            if self.done {
                return Ok(0);
            }
            self.fill_buffer()?;
            if self.done && self.plaintext.is_empty() {
                return Ok(0);
            }
        }

        let available = self.plaintext.len() - self.pos;
        let n = cmp::min(buf.len(), available);
        buf[..n].copy_from_slice(&self.plaintext[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn test_get_file_stem() {
        let stem = get_file_stem_to_string("path/to/file.txt").unwrap();
        assert_eq!(stem, "file");
    }

    #[test]
    fn test_get_file_stem_no_extension() {
        let stem = get_file_stem_to_string("path/to/file").unwrap();
        assert_eq!(stem, "file");
    }

    #[test]
    fn test_sha3_hash_consistency() {
        let data = b"test data for hashing";
        let hash1 = sha3_32_hash(data).unwrap();
        let hash2 = sha3_32_hash(data).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha3_hash_different_inputs() {
        let hash1 = sha3_32_hash(b"data1").unwrap();
        let hash2 = sha3_32_hash(b"data2").unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_sha3_hash_empty_input() {
        let hash = sha3_32_hash(b"").unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_constant_time_compare_equal() {
        let data = [42u8; 32];
        assert!(constant_time_compare_256_bit(&data, &data));
    }

    #[test]
    fn test_constant_time_compare_not_equal() {
        let data1 = [42u8; 32];
        let mut data2 = [42u8; 32];
        data2[0] = 43;
        assert!(!constant_time_compare_256_bit(&data1, &data2));
    }

    #[test]
    fn test_constant_time_compare_all_zeros() {
        let data1 = [0u8; 32];
        let data2 = [0u8; 32];
        assert!(constant_time_compare_256_bit(&data1, &data2));
    }

    #[test]
    fn test_get_duration_seconds() {
        let duration_str = get_duration(45.67);
        assert!(duration_str.contains("45.67 sec"));
    }

    #[test]
    fn test_get_duration_minutes() {
        let duration_str = get_duration(125.5);
        assert!(duration_str.contains("2 min"));
        assert!(duration_str.contains("5.50 sec"));
    }

    #[test]
    fn test_get_duration_zero() {
        let duration_str = get_duration(0.0);
        assert!(duration_str.contains("0.00 sec"));
    }

    #[test]
    fn test_get_duration_less_than_second() {
        let duration_str = get_duration(0.123);
        assert!(duration_str.contains("0.12 sec"));
    }

    #[test]
    fn test_secret_string_creation() {
        let secret = SecretString::from("my_secret_password".to_string());
        let debug_str = format!("{:?}", secret);
        assert!(debug_str.contains("Secret"));
    }
}
