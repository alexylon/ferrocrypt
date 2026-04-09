use std::cmp;
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::path::Path;

use chacha20poly1305::{XChaCha20Poly1305, aead::stream};
use constant_time_eq::constant_time_eq_32;
use hmac::{Hmac, KeyInit, Mac};
use sha3::{Digest, Sha3_256};

use zeroize::Zeroizing;

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
    const DEFAULT_MEM_COST: u32 = 1_048_576; // 1 GiB
    const DEFAULT_TIME_COST: u32 = 4;
    const DEFAULT_LANES: u32 = 4;

    // Minimal params for fast test execution.
    // Auto-enabled via [dev-dependencies]; blocked in release builds
    // by a compile_error! guard in lib.rs.
    const FAST_KDF_MEM_COST: u32 = 8192;
    const FAST_KDF_TIME_COST: u32 = 1;

    pub fn default_params() -> Self {
        if cfg!(feature = "fast-kdf") {
            Self {
                mem_cost: Self::FAST_KDF_MEM_COST,
                time_cost: Self::FAST_KDF_TIME_COST,
                lanes: Self::DEFAULT_LANES,
            }
        } else {
            Self {
                mem_cost: Self::DEFAULT_MEM_COST,
                time_cost: Self::DEFAULT_TIME_COST,
                lanes: Self::DEFAULT_LANES,
            }
        }
    }

    pub fn to_bytes(&self) -> [u8; KDF_PARAMS_SIZE] {
        let mut buf = [0u8; KDF_PARAMS_SIZE];
        buf[0..4].copy_from_slice(&self.mem_cost.to_be_bytes());
        buf[4..8].copy_from_slice(&self.time_cost.to_be_bytes());
        buf[8..12].copy_from_slice(&self.lanes.to_be_bytes());
        buf
    }

    // Upper bounds for KDF parameters from untrusted headers.
    // These prevent malicious files from causing excessive CPU/memory usage.
    const MAX_MEM_COST: u32 = 2 * 1024 * 1024; // 2 GiB
    const MAX_TIME_COST: u32 = 12;
    const MAX_LANES: u32 = 8;

    pub fn from_bytes(bytes: &[u8; KDF_PARAMS_SIZE]) -> Result<Self, CryptoError> {
        let params = Self {
            mem_cost: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            time_cost: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            lanes: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        };
        if params.mem_cost == 0 || params.mem_cost > Self::MAX_MEM_COST {
            return Err(CryptoError::CryptoOperation(format!(
                "Invalid KDF memory cost: {} KiB",
                params.mem_cost
            )));
        }
        if params.time_cost == 0 || params.time_cost > Self::MAX_TIME_COST {
            return Err(CryptoError::CryptoOperation(format!(
                "Invalid KDF time cost: {}",
                params.time_cost
            )));
        }
        if params.lanes == 0 || params.lanes > Self::MAX_LANES {
            return Err(CryptoError::CryptoOperation(format!(
                "Invalid KDF parallelism: {}",
                params.lanes
            )));
        }
        Ok(params)
    }

    pub fn hash_passphrase(
        &self,
        passphrase: &[u8],
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; ENCRYPTION_KEY_SIZE]>, CryptoError> {
        let params = argon2::Params::new(
            self.mem_cost,
            self.time_cost,
            self.lanes,
            Some(ENCRYPTION_KEY_SIZE),
        )?;
        let hasher =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut output = Zeroizing::new([0u8; ENCRYPTION_KEY_SIZE]);
        hasher.hash_password_into(passphrase, salt, output.as_mut())?;
        Ok(output)
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

pub fn get_file_stem(filename: &Path) -> Result<&OsStr, CryptoError> {
    filename
        .file_stem()
        .ok_or_else(|| CryptoError::InvalidInput("Cannot get file stem".to_string()))
}

/// Returns the base name for building the default encrypted output filename.
/// For regular files, returns the file stem (without extension).
/// For directories, returns the full directory name (preserving dots like `photos.v1`).
pub fn get_encryption_base_name(path: impl AsRef<Path>) -> Result<String, CryptoError> {
    let path = path.as_ref();
    if path.is_dir() {
        Ok(path
            .file_name()
            .ok_or_else(|| CryptoError::InvalidInput("Cannot get directory name".to_string()))?
            .to_string_lossy()
            .into_owned())
    } else {
        Ok(get_file_stem(path)?.to_string_lossy().into_owned())
    }
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
        let encryptor = self
            .encryptor
            .as_mut()
            .ok_or_else(|| io::Error::other("EncryptWriter already finished"))?;

        self.buffer.extend_from_slice(buf);

        while self.buffer.len() >= BUFFER_SIZE {
            let remaining = self.buffer.split_off(BUFFER_SIZE);
            let chunk = std::mem::replace(&mut self.buffer, remaining);
            let ciphertext = encryptor
                .encrypt_next(chunk.as_slice())
                .map_err(|e| io::Error::other(e.to_string()))?;
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
            let decryptor = self
                .decryptor
                .as_mut()
                .ok_or_else(|| io::Error::other("decryptor already consumed"))?;
            self.plaintext = decryptor
                .decrypt_next(encrypted.as_slice())
                .map_err(|e| io::Error::other(e.to_string()))?;
        } else {
            let decryptor = self
                .decryptor
                .take()
                .ok_or_else(|| io::Error::other("decryptor already consumed"))?;
            self.plaintext = decryptor
                .decrypt_last(&encrypted[..filled])
                .map_err(|e| io::Error::other(e.to_string()))?;
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
    fn test_get_encryption_base_name_file() {
        let stem = get_encryption_base_name("path/to/file.txt").unwrap();
        assert_eq!(stem, "file");
    }

    #[test]
    fn test_get_encryption_base_name_no_extension() {
        let stem = get_encryption_base_name("path/to/file").unwrap();
        assert_eq!(stem, "file");
    }

    #[test]
    fn test_get_encryption_base_name_dotted_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dotted_dir = tmp.path().join("photos.v1");
        std::fs::create_dir(&dotted_dir).unwrap();
        let name = get_encryption_base_name(&dotted_dir).unwrap();
        assert_eq!(name, "photos.v1");
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
    fn test_secret_string_creation() {
        let secret = SecretString::from("my_secret_password".to_string());
        let debug_str = format!("{:?}", secret);
        assert!(debug_str.contains("Secret"));
    }

    #[test]
    fn test_kdf_params_valid_defaults() {
        let params = KdfParams::default_params();
        let bytes = params.to_bytes();
        assert!(KdfParams::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn test_kdf_params_rejects_zero_mem_cost() {
        let mut bytes = KdfParams::default_params().to_bytes();
        bytes[0..4].copy_from_slice(&0u32.to_be_bytes());
        assert!(KdfParams::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_kdf_params_rejects_zero_time_cost() {
        let mut bytes = KdfParams::default_params().to_bytes();
        bytes[4..8].copy_from_slice(&0u32.to_be_bytes());
        assert!(KdfParams::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_kdf_params_rejects_zero_lanes() {
        let mut bytes = KdfParams::default_params().to_bytes();
        bytes[8..12].copy_from_slice(&0u32.to_be_bytes());
        assert!(KdfParams::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_kdf_params_rejects_excessive_time_cost() {
        let mut bytes = KdfParams::default_params().to_bytes();
        bytes[4..8].copy_from_slice(&13u32.to_be_bytes());
        assert!(KdfParams::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_kdf_params_rejects_excessive_lanes() {
        let mut bytes = KdfParams::default_params().to_bytes();
        bytes[8..12].copy_from_slice(&9u32.to_be_bytes());
        assert!(KdfParams::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_kdf_params_accepts_max_bounds() {
        let bytes = KdfParams {
            mem_cost: 2 * 1024 * 1024,
            time_cost: 12,
            lanes: 8,
        }
        .to_bytes();
        assert!(KdfParams::from_bytes(&bytes).is_ok());
    }
}
