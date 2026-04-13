use std::cmp;
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::path::Path;

use chacha20poly1305::{XChaCha20Poly1305, aead::stream};
use constant_time_eq::constant_time_eq_32;
use hmac::{Hmac, KeyInit, Mac};
use sha3::{Digest, Sha3_256};

use zeroize::{Zeroize, Zeroizing};

use crate::CryptoError;

type HmacSha3_256 = Hmac<Sha3_256>;

/// Caller-controlled limit on KDF memory cost accepted during decryption.
///
/// When processing untrusted files, this prevents a malicious header from
/// forcing arbitrarily expensive key derivation. Pass `None` to decrypt
/// functions to use the built-in default ceiling.
pub struct KdfLimit {
    /// Maximum accepted memory cost in KiB.
    pub max_mem_cost_kib: u32,
}

impl KdfLimit {
    pub fn new(max_mem_cost_kib: u32) -> Self {
        Self { max_mem_cost_kib }
    }

    pub fn from_mib(mib: u32) -> Result<Self, CryptoError> {
        let kib = mib.checked_mul(1024).ok_or_else(|| {
            CryptoError::InvalidInput(format!("KDF memory limit overflow: {} MiB", mib))
        })?;
        Ok(Self::new(kib))
    }
}

impl Default for KdfLimit {
    fn default() -> Self {
        Self {
            max_mem_cost_kib: KdfParams::MAX_MEM_COST,
        }
    }
}

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

    pub fn to_bytes(&self) -> [u8; KDF_PARAMS_SIZE] {
        let mut buf = [0u8; KDF_PARAMS_SIZE];
        buf[0..4].copy_from_slice(&self.mem_cost.to_be_bytes());
        buf[4..8].copy_from_slice(&self.time_cost.to_be_bytes());
        buf[8..12].copy_from_slice(&self.lanes.to_be_bytes());
        buf
    }

    // Upper bounds for KDF parameters from untrusted headers.
    // These prevent malicious files from causing excessive CPU/memory usage.
    pub(crate) const MAX_MEM_COST: u32 = 2 * 1024 * 1024; // 2 GiB
    const MAX_TIME_COST: u32 = 12;
    const MAX_LANES: u32 = 8;

    pub fn from_bytes(
        bytes: &[u8; KDF_PARAMS_SIZE],
        limit: Option<&KdfLimit>,
    ) -> Result<Self, CryptoError> {
        let params = Self {
            mem_cost: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            time_cost: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            lanes: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        };
        if params.lanes == 0 || params.lanes > Self::MAX_LANES {
            return Err(CryptoError::InvalidKdfParams(format!(
                "Invalid KDF parallelism: {}",
                params.lanes
            )));
        }
        let min_mem_cost = 8 * params.lanes;
        if params.mem_cost < min_mem_cost || params.mem_cost > Self::MAX_MEM_COST {
            return Err(CryptoError::InvalidKdfParams(format!(
                "Invalid KDF memory cost: {} KiB",
                params.mem_cost
            )));
        }
        if params.time_cost == 0 || params.time_cost > Self::MAX_TIME_COST {
            return Err(CryptoError::InvalidKdfParams(format!(
                "Invalid KDF time cost: {}",
                params.time_cost
            )));
        }

        let effective_max = limit
            .map(|l| l.max_mem_cost_kib)
            .unwrap_or(Self::MAX_MEM_COST);
        if params.mem_cost > effective_max {
            return Err(CryptoError::ExcessiveWork {
                required_kib: params.mem_cost,
                max_kib: effective_max,
            });
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

impl Default for KdfParams {
    fn default() -> Self {
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
}

// ─── Shared crypto sizes ──────────────────────────────────────────────────
pub const ENCRYPTION_KEY_SIZE: usize = 32;
pub const HMAC_KEY_SIZE: usize = 32;
/// HMAC-SHA3-256 output size in bytes (distinct from `HMAC_KEY_SIZE`).
pub const HMAC_TAG_SIZE: usize = 32;
pub const ARGON2_SALT_SIZE: usize = 32;

// ─── Streaming encryption sizes ───────────────────────────────────────────
/// Plaintext chunk size for streaming XChaCha20-Poly1305 AEAD (64 KiB).
/// Non-final chunks produce `BUFFER_SIZE + TAG_SIZE` ciphertext bytes; the
/// final chunk may be shorter. Part of the `.fcr` on-disk format — changing
/// this shifts every chunk boundary and breaks existing files.
pub const BUFFER_SIZE: usize = 65536;
/// Poly1305 authentication tag size in bytes.
pub const TAG_SIZE: usize = 16;
/// STREAM nonce size: XChaCha20's 24-byte nonce minus 5 bytes for counter and last-block flag.
pub const STREAM_NONCE_SIZE: usize = 19;

// ─── Error messages ───────────────────────────────────────────────────────
pub const FILE_TOO_SHORT: &str = "File is too short or corrupted";

pub fn file_stem(filename: &Path) -> Result<&OsStr, CryptoError> {
    filename
        .file_stem()
        .ok_or_else(|| CryptoError::InvalidInput("Cannot get file stem".to_string()))
}

/// Returns the base name for building the default encrypted output filename.
/// For regular files, returns the file stem (without extension).
/// For directories, returns the full directory name (preserving dots like `photos.v1`).
pub fn encryption_base_name(path: impl AsRef<Path>) -> Result<String, CryptoError> {
    let path = path.as_ref();
    if path.is_dir() {
        Ok(path
            .file_name()
            .ok_or_else(|| CryptoError::InvalidInput("Cannot get directory name".to_string()))?
            .to_string_lossy()
            .into_owned())
    } else {
        Ok(file_stem(path)?.to_string_lossy().into_owned())
    }
}

pub fn sha3_256_hash(data: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let digest: [u8; 32] = hasher.finalize().as_slice().try_into()?;

    Ok(digest)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Compares two 256-bit byte strings in constant time.
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    constant_time_eq_32(a, b)
}

pub fn hmac_sha3_256(key: &[u8], data: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut mac = HmacSha3_256::new_from_slice(key)
        .map_err(|e| CryptoError::InternalError(format!("HMAC key error: {}", e)))?;
    mac.update(data);
    let result = mac.finalize();
    let bytes: [u8; 32] = result.into_bytes().into();
    Ok(bytes)
}

/// Verifies HMAC-SHA3-256 in constant time. Returns error if mismatch.
pub fn hmac_sha3_256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
    let mut mac = HmacSha3_256::new_from_slice(key)
        .map_err(|e| CryptoError::InternalError(format!("HMAC key error: {}", e)))?;
    mac.update(data);
    mac.verify_slice(tag)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Streaming encryption writer: buffers plaintext writes into `BUFFER_SIZE`
/// chunks, encrypts each chunk in place with `encrypt_next_in_place`, and
/// writes ciphertext to the inner writer. Call `finish()` after all data is
/// written to encrypt the final (possibly partial) chunk with
/// `encrypt_last_in_place`.
///
/// Full `BUFFER_SIZE` chunks use `encrypt_next_in_place`; the final chunk
/// (0..BUFFER_SIZE bytes) uses `encrypt_last_in_place`.
///
/// ## Memory hygiene
///
/// A single `chunk` buffer is pre-allocated with capacity `BUFFER_SIZE +
/// TAG_SIZE` and reused across every chunk. The same allocation holds
/// plaintext on entry and ciphertext on exit (the in-place AEAD appends the
/// authentication tag without growing the underlying allocation), and is
/// zeroized between chunks and on drop. There are no per-chunk plaintext
/// `Vec`s left to the allocator.
pub struct EncryptWriter<W: Write> {
    encryptor: Option<stream::EncryptorBE32<XChaCha20Poly1305>>,
    chunk: Vec<u8>,
    output: Option<W>,
}

impl<W: Write> EncryptWriter<W> {
    pub fn new(encryptor: stream::EncryptorBE32<XChaCha20Poly1305>, output: W) -> Self {
        Self {
            encryptor: Some(encryptor),
            // Pre-allocate plaintext-plus-tag capacity so the in-place AEAD
            // tag append never triggers a `Vec` reallocation (which would
            // copy old bytes to a new allocation and free the old one
            // without zeroizing).
            chunk: Vec::with_capacity(BUFFER_SIZE + TAG_SIZE),
            output: Some(output),
        }
    }

    /// Encrypts the remaining buffer as the final AEAD chunk and flushes.
    /// Must be called exactly once after all plaintext has been written.
    /// Returns the inner writer so the caller can finalize it (e.g. `sync_all`).
    pub fn finish(mut self) -> Result<W, CryptoError> {
        let encryptor = self.encryptor.take().ok_or_else(|| {
            CryptoError::InvalidInput("EncryptWriter already finished".to_string())
        })?;
        let mut output = self.output.take().ok_or_else(|| {
            CryptoError::InvalidInput("EncryptWriter already finished".to_string())
        })?;
        encryptor
            .encrypt_last_in_place(b"", &mut self.chunk)
            .map_err(CryptoError::Cipher)?;
        output.write_all(&self.chunk)?;
        output.flush()?;
        self.chunk.zeroize();
        Ok(output)
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            let space = BUFFER_SIZE - self.chunk.len();
            let take = cmp::min(space, buf.len() - written);
            self.chunk.extend_from_slice(&buf[written..written + take]);
            written += take;

            if self.chunk.len() == BUFFER_SIZE {
                let encryptor = self
                    .encryptor
                    .as_mut()
                    .ok_or_else(|| io::Error::other("EncryptWriter already finished"))?;
                encryptor
                    .encrypt_next_in_place(b"", &mut self.chunk)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let output = self
                    .output
                    .as_mut()
                    .ok_or_else(|| io::Error::other("EncryptWriter already finished"))?;
                output.write_all(&self.chunk)?;
                // Zeroize the chunk (plaintext + tag) before refilling for
                // the next chunk. `zeroize` resets length to 0 and preserves
                // capacity, so the next `extend_from_slice` reuses the
                // same allocation.
                self.chunk.zeroize();
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.output.as_mut() {
            Some(output) => output.flush(),
            None => Ok(()),
        }
    }
}

impl<W: Write> Drop for EncryptWriter<W> {
    fn drop(&mut self) {
        self.chunk.zeroize();
    }
}

/// Streaming decryption reader: reads ciphertext chunks of `BUFFER_SIZE + TAG_SIZE`
/// from the inner reader, decrypts each in place with `decrypt_next_in_place`
/// / `decrypt_last_in_place`, and serves plaintext through the `Read`
/// interface.
///
/// A full-size ciphertext chunk (`BUFFER_SIZE + TAG_SIZE` bytes) is a non-final
/// chunk; a shorter read indicates the final chunk.
///
/// ## Memory hygiene
///
/// A single `chunk` buffer is pre-allocated with capacity `BUFFER_SIZE +
/// TAG_SIZE` and reused across every chunk. The same allocation holds
/// ciphertext on entry and plaintext on exit (the in-place AEAD truncates the
/// authentication tag during decryption), and is zeroized before each refill
/// and on drop. There are no per-chunk `Vec`s left to the allocator.
pub struct DecryptReader<R: Read> {
    decryptor: Option<stream::DecryptorBE32<XChaCha20Poly1305>>,
    input: R,
    chunk: Vec<u8>,
    pos: usize,
    done: bool,
}

impl<R: Read> DecryptReader<R> {
    pub fn new(decryptor: stream::DecryptorBE32<XChaCha20Poly1305>, input: R) -> Self {
        Self {
            decryptor: Some(decryptor),
            input,
            // Pre-allocate the worst-case chunk size so neither the read
            // refill nor the in-place AEAD ever triggers a `Vec`
            // reallocation.
            chunk: Vec::with_capacity(BUFFER_SIZE + TAG_SIZE),
            pos: 0,
            done: false,
        }
    }

    fn fill_buffer(&mut self) -> io::Result<()> {
        const ENCRYPTED_CHUNK_SIZE: usize = BUFFER_SIZE + TAG_SIZE;

        // Zeroize the previous chunk (plaintext from the last call) before
        // refilling. `zeroize` sets length to 0 and preserves capacity.
        self.chunk.zeroize();
        self.chunk.resize(ENCRYPTED_CHUNK_SIZE, 0);

        let mut filled = 0;
        while filled < ENCRYPTED_CHUNK_SIZE {
            let n = self.input.read(&mut self.chunk[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        // Drop trailing zero bytes that weren't filled by the read. Crucial
        // for the final (short) chunk: in-place decrypt expects the buffer
        // length to equal the ciphertext length.
        self.chunk.truncate(filled);

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
            decryptor
                .decrypt_next_in_place(b"", &mut self.chunk)
                .map_err(|e| io::Error::other(e.to_string()))?;
        } else {
            let decryptor = self
                .decryptor
                .take()
                .ok_or_else(|| io::Error::other("decryptor already consumed"))?;
            decryptor
                .decrypt_last_in_place(b"", &mut self.chunk)
                .map_err(|e| io::Error::other(e.to_string()))?;
            self.done = true;
        }

        self.pos = 0;
        Ok(())
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.chunk.len() {
            if self.done {
                return Ok(0);
            }
            self.fill_buffer()?;
            if self.done && self.chunk.is_empty() {
                return Ok(0);
            }
        }

        let available = self.chunk.len() - self.pos;
        let n = cmp::min(buf.len(), available);
        buf[..n].copy_from_slice(&self.chunk[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl<R: Read> Drop for DecryptReader<R> {
    fn drop(&mut self) {
        self.chunk.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::KeyInit;
    use secrecy::SecretString;

    // ─── Streaming AEAD adapter helpers ───────────────────────────────────
    //
    // Lock the chunked encrypt/decrypt boundary cases in `EncryptWriter` and
    // `DecryptReader` with a fixed test key+nonce so each test produces
    // deterministic ciphertext. These adapters are exercised end-to-end by
    // the integration suite, but the cases below pin specific edge cases
    // (exact `BUFFER_SIZE` boundary, byte-at-a-time writes, empty final
    // chunk, small consumer buffers) at the adapter level so a regression
    // in `fill_buffer` or the in-place AEAD wiring fails immediately.

    const TEST_KEY: [u8; ENCRYPTION_KEY_SIZE] = [0x42; ENCRYPTION_KEY_SIZE];
    const TEST_NONCE: [u8; STREAM_NONCE_SIZE] = [0x37; STREAM_NONCE_SIZE];

    fn fresh_encryptor() -> stream::EncryptorBE32<XChaCha20Poly1305> {
        let cipher = XChaCha20Poly1305::new((&TEST_KEY).into());
        stream::EncryptorBE32::from_aead(cipher, TEST_NONCE.as_ref().into())
    }

    fn fresh_decryptor() -> stream::DecryptorBE32<XChaCha20Poly1305> {
        let cipher = XChaCha20Poly1305::new((&TEST_KEY).into());
        stream::DecryptorBE32::from_aead(cipher, TEST_NONCE.as_ref().into())
    }

    fn encrypt_to_vec(plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext: Vec<u8> = Vec::new();
        let mut writer = EncryptWriter::new(fresh_encryptor(), &mut ciphertext);
        writer.write_all(plaintext).unwrap();
        let _ = writer.finish().unwrap();
        ciphertext
    }

    fn decrypt_to_vec(ciphertext: &[u8]) -> Vec<u8> {
        let mut reader = DecryptReader::new(fresh_decryptor(), ciphertext);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        out
    }

    /// Plaintext exactly equal to one chunk: the writer hands off a full
    /// `BUFFER_SIZE` block via `encrypt_next_in_place`, then `finish()`
    /// encrypts an **empty** buffer via `encrypt_last_in_place`, producing
    /// a tag-only final chunk. The total ciphertext is one full encrypted
    /// chunk plus one 16-byte tag-only final chunk.
    #[test]
    fn streaming_aead_round_trip_exact_buffer_size() {
        let plaintext: Vec<u8> = (0..BUFFER_SIZE).map(|i| (i % 251) as u8).collect();
        let ciphertext = encrypt_to_vec(&plaintext);
        assert_eq!(
            ciphertext.len(),
            BUFFER_SIZE + TAG_SIZE + TAG_SIZE,
            "expected one full chunk plus a tag-only final chunk"
        );
        let decrypted = decrypt_to_vec(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// Many 1-byte writes that together cross multiple chunk boundaries.
    /// Exercises `EncryptWriter::write`'s buffer-accumulation path: most
    /// calls only extend `self.chunk`, and `encrypt_next_in_place` fires
    /// only at the exact `BUFFER_SIZE` boundary. A regression that drops
    /// any byte in the accumulation logic produces wrong ciphertext.
    #[test]
    fn streaming_aead_round_trip_byte_at_a_time_writes() {
        let plaintext: Vec<u8> = (0..(BUFFER_SIZE * 2 + 50))
            .map(|i| (i % 251) as u8)
            .collect();
        let mut ciphertext: Vec<u8> = Vec::new();
        let mut writer = EncryptWriter::new(fresh_encryptor(), &mut ciphertext);
        for byte in &plaintext {
            writer.write_all(std::slice::from_ref(byte)).unwrap();
        }
        let _ = writer.finish().unwrap();
        let decrypted = decrypt_to_vec(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// Plaintext is an exact multiple of `BUFFER_SIZE`. Every full chunk
    /// goes through `encrypt_next_in_place`, then `finish()` encrypts an
    /// empty buffer via `encrypt_last_in_place`. The decoder must serve
    /// every plaintext byte and then return `Ok(0)` on the empty final
    /// chunk without spuriously appending tag bytes to the plaintext.
    #[test]
    fn streaming_aead_round_trip_empty_final_chunk() {
        let plaintext: Vec<u8> = (0..(BUFFER_SIZE * 3)).map(|i| (i % 251) as u8).collect();
        let ciphertext = encrypt_to_vec(&plaintext);
        assert_eq!(
            ciphertext.len(),
            3 * (BUFFER_SIZE + TAG_SIZE) + TAG_SIZE,
            "expected three full chunks plus a tag-only final chunk"
        );
        let decrypted = decrypt_to_vec(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// Drain `DecryptReader` through tiny consumer buffers. The reader
    /// must serve plaintext correctly when the caller's buffer is much
    /// smaller than the AEAD chunk: most `read()` calls return 7 bytes
    /// from `self.chunk[self.pos..]`, and `fill_buffer` only fires when
    /// the chunk is fully drained. Locks the pos/len bookkeeping in the
    /// `Read` impl across multi-chunk boundaries.
    #[test]
    fn streaming_aead_decrypt_with_small_read_buffers() {
        let plaintext: Vec<u8> = (0..(BUFFER_SIZE * 2 + 1234))
            .map(|i| (i % 251) as u8)
            .collect();
        let ciphertext = encrypt_to_vec(&plaintext);

        let mut reader = DecryptReader::new(fresh_decryptor(), ciphertext.as_slice());
        let mut decrypted = Vec::with_capacity(plaintext.len());
        let mut tiny_buf = [0u8; 7];
        loop {
            let n = reader.read(&mut tiny_buf).unwrap();
            if n == 0 {
                break;
            }
            decrypted.extend_from_slice(&tiny_buf[..n]);
        }
        assert_eq!(decrypted, plaintext);
    }

    /// Drains a `DecryptReader` through `Read::read` directly until either
    /// `Ok(0)` or `Err`. Returns the (collected_plaintext, optional_error).
    /// `Read::read`'s contract about partial reads is crisper than
    /// `read_to_end`'s — using it here means the partial-output assertions
    /// in the truncation and tamper tests stay robust against future std
    /// changes to `read_to_end`'s error-path append behavior.
    fn drain_decrypt_reader(reader: &mut DecryptReader<&[u8]>) -> (Vec<u8>, Option<io::Error>) {
        let mut out = Vec::new();
        let mut scratch = [0u8; 4096];
        loop {
            match reader.read(&mut scratch) {
                Ok(0) => return (out, None),
                Ok(n) => out.extend_from_slice(&scratch[..n]),
                Err(e) => return (out, Some(e)),
            }
        }
    }

    /// Exact-buffer plaintext produces a full encrypted chunk followed by a
    /// tag-only final chunk. If that final chunk is missing, `DecryptReader`
    /// must reject the stream through the dedicated `filled == 0` truncation
    /// path instead of silently treating EOF as success — and the
    /// already-authenticated first chunk's plaintext must still be served
    /// before the error is raised.
    #[test]
    fn streaming_aead_missing_tag_only_final_chunk_rejected() {
        let plaintext: Vec<u8> = (0..BUFFER_SIZE).map(|i| (i % 251) as u8).collect();
        let mut ciphertext = encrypt_to_vec(&plaintext);
        ciphertext.truncate(ciphertext.len() - TAG_SIZE);

        let mut reader = DecryptReader::new(fresh_decryptor(), ciphertext.as_slice());
        let (out, err) = drain_decrypt_reader(&mut reader);
        let err = err.expect("expected truncation error, got clean EOF");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(
            err.to_string().contains("missing final chunk"),
            "unexpected error: {err}"
        );
        // The first chunk was fully authenticated before truncation was
        // discovered, so its plaintext must have been served before the
        // error. Bounds the unauthenticated-output property under truncation.
        assert_eq!(out.as_slice(), plaintext.as_slice());
    }

    /// Flip one byte in a late ciphertext chunk. The reader should return the
    /// already-verified first plaintext chunk, then fail when it reaches the
    /// corrupted later chunk instead of silently accepting modified data.
    /// Bounds unauthenticated output to at most one chunk past the last
    /// verified chunk.
    #[test]
    fn streaming_aead_late_ciphertext_bit_flip_rejected() {
        let plaintext: Vec<u8> = (0..(BUFFER_SIZE * 2 + 1234))
            .map(|i| (i % 251) as u8)
            .collect();
        let mut ciphertext = encrypt_to_vec(&plaintext);

        // Ciphertext layout here is:
        //   chunk 1: BUFFER_SIZE + TAG_SIZE
        //   chunk 2: BUFFER_SIZE + TAG_SIZE
        //   final  : 1234 + TAG_SIZE
        // Flip a byte well inside the second encrypted chunk.
        let second_chunk_offset = BUFFER_SIZE + TAG_SIZE;
        ciphertext[second_chunk_offset + 100] ^= 0x01;

        let mut reader = DecryptReader::new(fresh_decryptor(), ciphertext.as_slice());
        let (out, err) = drain_decrypt_reader(&mut reader);
        let err = err.expect("expected AEAD tamper error, got clean EOF");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        // Exactly the first chunk's plaintext must have been served:
        //  - chunk 1 was fully verified, so its plaintext is delivered;
        //  - chunk 2 failed AEAD verification, so none of its bytes leak;
        //  - the final chunk is never reached.
        assert_eq!(out.as_slice(), &plaintext[..BUFFER_SIZE]);
    }

    #[test]
    fn test_encryption_base_name_file() {
        let stem = encryption_base_name("path/to/file.txt").unwrap();
        assert_eq!(stem, "file");
    }

    #[test]
    fn test_encryption_base_name_no_extension() {
        let stem = encryption_base_name("path/to/file").unwrap();
        assert_eq!(stem, "file");
    }

    #[test]
    fn test_encryption_base_name_dotted_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dotted_dir = tmp.path().join("photos.v1");
        std::fs::create_dir(&dotted_dir).unwrap();
        let name = encryption_base_name(&dotted_dir).unwrap();
        assert_eq!(name, "photos.v1");
    }

    #[test]
    fn test_sha3_hash_consistency() {
        let data = b"test data for hashing";
        let hash1 = sha3_256_hash(data).unwrap();
        let hash2 = sha3_256_hash(data).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha3_hash_different_inputs() {
        let hash1 = sha3_256_hash(b"data1").unwrap();
        let hash2 = sha3_256_hash(b"data2").unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_sha3_hash_empty_input() {
        let hash = sha3_256_hash(b"").unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_constant_time_compare_equal() {
        let data = [42u8; 32];
        assert!(ct_eq_32(&data, &data));
    }

    #[test]
    fn test_constant_time_compare_not_equal() {
        let data1 = [42u8; 32];
        let mut data2 = [42u8; 32];
        data2[0] = 43;
        assert!(!ct_eq_32(&data1, &data2));
    }

    #[test]
    fn test_constant_time_compare_all_zeros() {
        let data1 = [0u8; 32];
        let data2 = [0u8; 32];
        assert!(ct_eq_32(&data1, &data2));
    }

    #[test]
    fn test_secret_string_creation() {
        let secret = SecretString::from("my_secret_password".to_string());
        let debug_str = format!("{:?}", secret);
        assert!(debug_str.contains("Secret"));
    }

    #[test]
    fn test_kdf_params_valid_defaults() {
        let params = KdfParams::default();
        let bytes = params.to_bytes();
        assert!(KdfParams::from_bytes(&bytes, None).is_ok());
    }

    #[test]
    fn test_kdf_params_rejects_zero_mem_cost() {
        let mut bytes = KdfParams::default().to_bytes();
        bytes[0..4].copy_from_slice(&0u32.to_be_bytes());
        assert!(KdfParams::from_bytes(&bytes, None).is_err());
    }

    #[test]
    fn test_kdf_params_rejects_zero_time_cost() {
        let mut bytes = KdfParams::default().to_bytes();
        bytes[4..8].copy_from_slice(&0u32.to_be_bytes());
        assert!(KdfParams::from_bytes(&bytes, None).is_err());
    }

    #[test]
    fn test_kdf_params_rejects_zero_lanes() {
        let mut bytes = KdfParams::default().to_bytes();
        bytes[8..12].copy_from_slice(&0u32.to_be_bytes());
        assert!(KdfParams::from_bytes(&bytes, None).is_err());
    }

    #[test]
    fn test_kdf_params_rejects_excessive_time_cost() {
        let mut bytes = KdfParams::default().to_bytes();
        bytes[4..8].copy_from_slice(&13u32.to_be_bytes());
        assert!(KdfParams::from_bytes(&bytes, None).is_err());
    }

    #[test]
    fn test_kdf_params_rejects_excessive_lanes() {
        let mut bytes = KdfParams::default().to_bytes();
        bytes[8..12].copy_from_slice(&9u32.to_be_bytes());
        assert!(KdfParams::from_bytes(&bytes, None).is_err());
    }

    #[test]
    fn test_kdf_params_rejects_mem_cost_below_argon2_minimum() {
        // Argon2 requires mem_cost >= 8 * lanes
        let bytes = KdfParams {
            mem_cost: 31,
            time_cost: 4,
            lanes: 4,
        }
        .to_bytes();
        assert!(KdfParams::from_bytes(&bytes, None).is_err());
    }

    #[test]
    fn test_kdf_params_accepts_max_bounds() {
        let bytes = KdfParams {
            mem_cost: 2 * 1024 * 1024,
            time_cost: 12,
            lanes: 8,
        }
        .to_bytes();
        assert!(KdfParams::from_bytes(&bytes, None).is_ok());
    }

    #[test]
    fn test_kdf_limit_rejects_excessive_mem_cost() {
        let bytes = KdfParams {
            mem_cost: 1_048_576, // 1 GiB
            time_cost: 4,
            lanes: 4,
        }
        .to_bytes();
        let limit = KdfLimit::new(512 * 1024); // 512 MiB
        match KdfParams::from_bytes(&bytes, Some(&limit)) {
            Err(CryptoError::ExcessiveWork {
                required_kib: 1_048_576,
                max_kib: 524_288,
            }) => {}
            Err(other) => panic!("expected ExcessiveWork, got: {other}"),
            Ok(_) => panic!("expected ExcessiveWork error, got Ok"),
        }
    }

    #[test]
    fn test_kdf_limit_accepts_within_bound() {
        let bytes = KdfParams {
            mem_cost: 1_048_576, // 1 GiB
            time_cost: 4,
            lanes: 4,
        }
        .to_bytes();
        let limit = KdfLimit::new(2 * 1024 * 1024); // 2 GiB
        assert!(KdfParams::from_bytes(&bytes, Some(&limit)).is_ok());
    }

    #[test]
    fn test_kdf_limit_default_accepts_default_params() {
        let bytes = KdfParams::default().to_bytes();
        let limit = KdfLimit::default();
        assert!(KdfParams::from_bytes(&bytes, Some(&limit)).is_ok());
    }
}
