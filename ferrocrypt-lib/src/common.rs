use std::cmp;
use std::io::{self, Read, Write};
use std::path::Path;

use chacha20poly1305::{XChaCha20Poly1305, aead::stream};
use constant_time_eq::constant_time_eq_32;
use hmac::{Hmac, Mac};
use sha3::{Digest, Sha3_256};

use crate::CryptoError;

type HmacSha3_256 = Hmac<Sha3_256>;

pub fn argon2_config() -> argon2::Config<'static> {
    // "fast-kdf" uses minimal Argon2 params so tests finish quickly.
    // The feature is auto-enabled via [dev-dependencies] and blocked
    // in release builds by a compile_error! guard in lib.rs.
    let (mem_cost, time_cost) = if cfg!(feature = "fast-kdf") {
        (8192, 1)
    } else {
        (1048576, 4)
    };
    argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 4,
        mem_cost,
        time_cost,
        ..Default::default()
    }
}

/// Streaming I/O buffer size.
pub const BUFFER_SIZE: usize = 65536;
/// Poly1305 authentication tag size in bytes.
pub const TAG_SIZE: usize = 16;
/// STREAM nonce size: XChaCha20's 24-byte nonce minus 5 bytes for counter and last-block flag.
pub const NONCE_SIZE: usize = 19;

pub fn normalize_paths(src_file_path: &str, dest_dir_path: &str) -> (String, String) {
    let src_file_path_norm = src_file_path.replace('\\', "/");
    let mut dest_dir_path_norm = dest_dir_path.replace('\\', "/");

    if !dest_dir_path_norm.ends_with('/') && !dest_dir_path_norm.is_empty() {
        dest_dir_path_norm = format!("{}/", dest_dir_path_norm);
    }

    (src_file_path_norm, dest_dir_path_norm)
}

pub fn get_file_stem_to_string(filename: impl AsRef<Path>) -> Result<String, CryptoError> {
    let file_stem_string = filename
        .as_ref()
        .file_stem()
        .ok_or_else(|| CryptoError::Message("Cannot get file stem".to_string()))?
        .to_str()
        .ok_or_else(|| CryptoError::Message("Cannot convert file stem to &str".to_string()))?
        .to_string();

    Ok(file_stem_string)
}

pub fn sha3_32_hash(data: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let digest: [u8; 32] = hasher.finalize().as_slice().try_into()?;

    Ok(digest)
}

/// Compares two 256-bit byte strings in constant time.
pub fn constant_time_compare_256_bit(a: &[u8; 32], b: &[u8; 32]) -> bool {
    constant_time_eq_32(a, b)
}

pub fn hmac_sha3_256(key: &[u8], data: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut mac = HmacSha3_256::new_from_slice(key)
        .map_err(|e| CryptoError::Message(format!("HMAC key error: {}", e)))?;
    mac.update(data);
    let result = mac.finalize();
    let bytes: [u8; 32] = result.into_bytes().into();
    Ok(bytes)
}

/// Verifies HMAC-SHA3-256 in constant time. Returns error if mismatch.
pub fn hmac_sha3_256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
    let mut mac = HmacSha3_256::new_from_slice(key)
        .map_err(|e| CryptoError::Message(format!("HMAC key error: {}", e)))?;
    mac.update(data);
    mac.verify_slice(tag).map_err(|_| {
        CryptoError::EncryptionDecryptionError(
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
        let encryptor = self
            .encryptor
            .take()
            .ok_or_else(|| CryptoError::Message("EncryptWriter already finished".to_string()))?;
        let ciphertext = encryptor
            .encrypt_last(self.buffer.as_slice())
            .map_err(CryptoError::ChaCha20Poly1305Error)?;
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
    fn test_normalize_paths_unix_style() {
        let (src, dest) = normalize_paths("path/to/file", "path/to/dest");
        assert_eq!(src, "path/to/file");
        assert_eq!(dest, "path/to/dest/");
    }

    #[test]
    fn test_normalize_paths_windows_style() {
        let (src, dest) = normalize_paths("path\\to\\file", "path\\to\\dest");
        assert_eq!(src, "path/to/file");
        assert_eq!(dest, "path/to/dest/");
    }

    #[test]
    fn test_normalize_paths_empty_dest() {
        let (src, dest) = normalize_paths("file.txt", "");
        assert_eq!(src, "file.txt");
        assert_eq!(dest, "");
    }

    #[test]
    fn test_normalize_paths_trailing_slash() {
        let (src, dest) = normalize_paths("file.txt", "dest/");
        assert_eq!(src, "file.txt");
        assert_eq!(dest, "dest/");
    }

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
