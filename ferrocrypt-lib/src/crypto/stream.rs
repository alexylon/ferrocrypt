//! STREAM-BE32 payload encryptor/decryptor adapters.
//!
//! Per `FORMAT.md` §5, payload AEAD is XChaCha20-Poly1305 STREAM-BE32 over
//! 64 KiB plaintext chunks. Writers MUST NOT emit an empty trailing chunk
//! after non-empty plaintext that ends on a [`BUFFER_SIZE`] boundary; the
//! final non-empty chunk uses `last_flag = 1`. Empty plaintext is encoded
//! as a single tag-only `last` chunk.
//!
//! [`EncryptWriter`] defers committing a full chunk until either more
//! plaintext arrives (then `encrypt_next`) or `finish()` is called (then
//! `encrypt_last`). [`DecryptReader`] uses a one-byte peek past each
//! `ENCRYPTED_CHUNK_SIZE` boundary to distinguish "exact-N final chunk"
//! from "exact-N then more data".

use std::cmp;
use std::io::{self, Read, Write};

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{KeyInit as AeadKeyInit, stream},
};
use zeroize::Zeroize;

use crate::CryptoError;
use crate::crypto::aead::TAG_SIZE;
use crate::crypto::keys::PayloadKey;
use crate::error::StreamError;

/// Plaintext chunk size for streaming XChaCha20-Poly1305 AEAD (64 KiB).
/// Non-final chunks produce `BUFFER_SIZE + TAG_SIZE` ciphertext bytes; the
/// final chunk may be shorter. Part of the `.fcr` on-disk format — changing
/// this shifts every chunk boundary and breaks existing files.
pub const BUFFER_SIZE: usize = 65536;

/// STREAM nonce size: XChaCha20's 24-byte nonce minus 5 bytes for counter and last-block flag.
pub const STREAM_NONCE_SIZE: usize = 19;

/// Wraps a [`StreamError`] as an [`io::Error`] with the given kind so that
/// the typed marker can traverse [`Read`]/[`Write`] trait boundaries and
/// later be downcast by `From<io::Error> for CryptoError`.
fn stream_io_error(kind: io::ErrorKind, err: StreamError) -> io::Error {
    io::Error::new(kind, err)
}

/// Streaming encryption writer: buffers plaintext writes into
/// `BUFFER_SIZE` chunks and emits AEAD-encrypted chunks per
/// `FORMAT.md` §5.
///
/// Per `FORMAT.md` §5, a non-empty plaintext whose length is an exact
/// multiple of `BUFFER_SIZE` MUST end with a full-size **final** chunk
/// (`last_flag = 1`) — writers MUST NOT append an extra empty final
/// chunk. To satisfy this rule, this writer cannot eagerly call
/// `encrypt_next_in_place` the moment the buffer fills, because the
/// fill might be the last data the caller ever writes. Instead, when
/// the buffer reaches `BUFFER_SIZE` we **defer**: the chunk stays
/// buffered. On the next [`Write::write`] call (more data exists →
/// previous chunk is non-final) we flush the deferred chunk via
/// `encrypt_next_in_place`. On [`finish`](Self::finish) (no more data
/// exists → buffered chunk, however many bytes, is the final chunk)
/// we flush via `encrypt_last_in_place`.
///
/// ## Memory hygiene
///
/// A single `chunk` buffer is pre-allocated with capacity `BUFFER_SIZE +
/// TAG_SIZE` and reused across every chunk. The same allocation holds
/// plaintext on entry and ciphertext on exit (the in-place AEAD
/// appends the authentication tag without growing the underlying
/// allocation), and is zeroized between chunks and on drop. There are
/// no per-chunk plaintext `Vec`s left to the allocator.
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

    /// Encrypts the buffered chunk (whatever its length, including
    /// `0` for empty plaintext or `BUFFER_SIZE` for an exact-multiple
    /// boundary) as the AEAD final chunk and flushes.
    ///
    /// MUST be called exactly once after all plaintext has been
    /// written. Returns the inner writer so the caller can finalize
    /// it (e.g. `sync_all`).
    pub fn finish(mut self) -> Result<W, CryptoError> {
        let encryptor = self.encryptor.take().ok_or(CryptoError::InternalInvariant(
            "Internal error: encrypt writer already finished",
        ))?;
        let mut output = self.output.take().ok_or(CryptoError::InternalInvariant(
            "Internal error: encrypt writer already finished",
        ))?;
        encryptor
            .encrypt_last_in_place(b"", &mut self.chunk)
            .map_err(|_| {
                CryptoError::InternalCryptoFailure("Internal error: payload encryption failed")
            })?;
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
            // If the buffer already holds a full chunk, the previous
            // `write` call left it deferred. Now that more plaintext
            // is arriving, we know the deferred chunk is non-final
            // and can flush it via `encrypt_next_in_place`. This is
            // the FORMAT.md §5 conformance check: writers must wait
            // until they observe more data before committing a chunk
            // as non-final, so an exact-`BUFFER_SIZE`-multiple
            // plaintext ends with a full-size FINAL chunk rather than
            // a stray empty trailing chunk.
            if self.chunk.len() == BUFFER_SIZE {
                let encryptor = self.encryptor.as_mut().ok_or_else(|| {
                    stream_io_error(io::ErrorKind::Other, StreamError::StateExhausted)
                })?;
                encryptor
                    .encrypt_next_in_place(b"", &mut self.chunk)
                    .map_err(|_| stream_io_error(io::ErrorKind::Other, StreamError::EncryptAead))?;
                let output = self.output.as_mut().ok_or_else(|| {
                    stream_io_error(io::ErrorKind::Other, StreamError::StateExhausted)
                })?;
                output.write_all(&self.chunk)?;
                // Zeroize the chunk (plaintext + tag) before refilling
                // for the next chunk. `zeroize` resets length to 0 and
                // preserves capacity, so the next `extend_from_slice`
                // reuses the same allocation.
                self.chunk.zeroize();
            }

            let space = BUFFER_SIZE - self.chunk.len();
            let take = cmp::min(space, buf.len() - written);
            self.chunk.extend_from_slice(&buf[written..written + take]);
            written += take;
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

/// Streaming decryption reader: reads ciphertext chunks of
/// `BUFFER_SIZE + TAG_SIZE` from the inner reader, decrypts each in
/// place with `decrypt_next_in_place` / `decrypt_last_in_place`, and
/// serves plaintext through the `Read` interface.
///
/// Per `FORMAT.md` §5 a non-empty plaintext whose length is an exact
/// multiple of `BUFFER_SIZE` ends with a full-size **final** chunk
/// (`last_flag = 1`). The reader therefore cannot rely on "short
/// read = final chunk" alone; it must inspect end-of-input
/// explicitly. After reading a full `ENCRYPTED_CHUNK_SIZE`, we probe
/// the inner reader for one byte:
/// - probe returns `0` (EOF) → the chunk we just read is the final
///   chunk; decrypt with `decrypt_last_in_place`.
/// - probe returns `1` byte → another chunk follows; decrypt the
///   current chunk with `decrypt_next_in_place` and stash the probe
///   byte as the first byte of the next chunk.
///
/// A short read (filled < `ENCRYPTED_CHUNK_SIZE`) always indicates the
/// final chunk; AEAD authentication on `decrypt_last_in_place` rejects
/// any mid-chunk truncation as a tamper failure.
///
/// ## Memory hygiene
///
/// A single `chunk` buffer is pre-allocated with capacity
/// `BUFFER_SIZE + TAG_SIZE` and reused across every chunk. The same
/// allocation holds ciphertext on entry and plaintext on exit (the
/// in-place AEAD truncates the authentication tag during decryption),
/// and is zeroized before each refill and on drop. There are no
/// per-chunk `Vec`s left to the allocator.
pub struct DecryptReader<R: Read> {
    decryptor: Option<stream::DecryptorBE32<XChaCha20Poly1305>>,
    input: R,
    chunk: Vec<u8>,
    pos: usize,
    done: bool,
    /// One byte read from the inner reader past the current chunk
    /// boundary. `Some(b)` means the previous fill confirmed more
    /// data exists, so the byte belongs to the *next* chunk. `None`
    /// means no peek byte is held (initial state, or after the final
    /// chunk has been consumed).
    lookahead: Option<u8>,
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
            lookahead: None,
        }
    }

    /// Refill the plaintext window by reading and decrypting the next
    /// encrypted chunk. The "is this the final chunk?" decision is
    /// resolved by a one-byte peek past `ENCRYPTED_CHUNK_SIZE`:
    ///
    /// - peek returns `0` → final chunk; `decrypt_last_in_place`.
    /// - peek returns `1` byte → non-final chunk;
    ///   `decrypt_next_in_place`, stash the byte as `lookahead` for
    ///   the next call.
    ///
    /// Truncation is reported via two distinct paths:
    ///
    /// - **Chunk-boundary truncation** — `read` returns 0 immediately
    ///   AND no `lookahead` is held, meaning the final authenticated
    ///   chunk is missing entirely. Surfaces as
    ///   [`StreamError::Truncated`] → [`CryptoError::PayloadTruncated`].
    /// - **Mid-chunk truncation** — some bytes were read but fewer
    ///   than a full `ENCRYPTED_CHUNK_SIZE`. The short buffer is
    ///   treated as the final chunk and run through
    ///   `decrypt_last_in_place`. AEAD authentication will reject it,
    ///   surfacing as [`StreamError::DecryptAead`] →
    ///   [`CryptoError::PayloadTampered`]. This is the correct
    ///   outcome — we cannot distinguish a mid-chunk truncation from
    ///   a tampered tail, and both must fail closed.
    ///
    /// **Trailing-data probe.** After `decrypt_last_in_place` succeeds
    /// we probe the inner reader for one additional byte. With the
    /// peek-ahead model the probe can only fire if the inner reader
    /// returned `Ok(0)` and then later produced more bytes — a
    /// pathological case (non-blocking sockets, mis-implemented
    /// `Take`-style wrappers). Kept as defense-in-depth so any such
    /// reader still surfaces [`StreamError::ExtraData`] →
    /// [`CryptoError::ExtraDataAfterPayload`].
    fn fill_buffer(&mut self) -> io::Result<()> {
        const ENCRYPTED_CHUNK_SIZE: usize = BUFFER_SIZE + TAG_SIZE;

        // Zeroize the previous chunk (plaintext from the last call) before
        // refilling. `zeroize` sets length to 0 and preserves capacity.
        self.chunk.zeroize();
        self.chunk.resize(ENCRYPTED_CHUNK_SIZE, 0);

        // Seed with any byte stashed from the previous chunk's lookahead.
        let mut filled = 0;
        if let Some(b) = self.lookahead.take() {
            self.chunk[0] = b;
            filled = 1;
        }
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
            // A valid stream always ends with an encrypt_last chunk
            // (>= TAG_SIZE bytes). Reading 0 bytes here, with no
            // lookahead either, means the final authenticated chunk is
            // missing — the ciphertext was truncated at a chunk boundary.
            return Err(stream_io_error(
                io::ErrorKind::UnexpectedEof,
                StreamError::Truncated,
            ));
        }

        // Resolve "is this the final chunk?" via a one-byte peek when we
        // filled exactly `ENCRYPTED_CHUNK_SIZE`. A short read already
        // signalled EOF inside the loop, so it's the final chunk.
        let mut probe = [0u8; 1];
        let probe_n = if filled == ENCRYPTED_CHUNK_SIZE {
            self.input.read(&mut probe)?
        } else {
            0
        };

        if filled == ENCRYPTED_CHUNK_SIZE && probe_n > 0 {
            // Non-final chunk: stash the peek byte for the next refill.
            self.lookahead = Some(probe[0]);
            let decryptor = self.decryptor.as_mut().ok_or_else(|| {
                stream_io_error(io::ErrorKind::Other, StreamError::StateExhausted)
            })?;
            decryptor
                .decrypt_next_in_place(b"", &mut self.chunk)
                .map_err(|_| {
                    stream_io_error(io::ErrorKind::InvalidData, StreamError::DecryptAead)
                })?;
        } else {
            // Final chunk: short read OR exact-`ENCRYPTED_CHUNK_SIZE` with EOF.
            let decryptor = self.decryptor.take().ok_or_else(|| {
                stream_io_error(io::ErrorKind::Other, StreamError::StateExhausted)
            })?;
            decryptor
                .decrypt_last_in_place(b"", &mut self.chunk)
                .map_err(|_| {
                    stream_io_error(io::ErrorKind::InvalidData, StreamError::DecryptAead)
                })?;
            self.done = true;

            // Defense-in-depth trailing-data probe. With the peek-ahead
            // model this can only fire if the inner reader returned 0
            // earlier and then later produced more bytes; well-behaved
            // readers never trigger it.
            let mut probe2 = [0u8; 1];
            let n = self.input.read(&mut probe2)?;
            if n > 0 {
                return Err(stream_io_error(
                    io::ErrorKind::InvalidData,
                    StreamError::ExtraData,
                ));
            }
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

// ─── Payload AEAD-stream factories ────────────────────────────────────────

/// Constructs an [`EncryptWriter`] for the per-file payload pipeline.
///
/// Wraps the boilerplate `XChaCha20Poly1305::new` then
/// `EncryptorBE32::from_aead` then `EncryptWriter::new` chain so the
/// passphrase, recipient, and forward-compat test paths share a single
/// source of truth for the payload-streaming constructor.
///
/// `payload_key` and `stream_nonce` MUST come from the same successful
/// subkey derivation (see [`crate::crypto::keys::derive_subkeys`]) —
/// pairing them with material from a different derivation produces
/// ciphertext that no reader will accept.
pub(crate) fn payload_encryptor<W: Write>(
    payload_key: &PayloadKey,
    stream_nonce: &[u8; STREAM_NONCE_SIZE],
    writer: W,
) -> EncryptWriter<W> {
    let cipher = XChaCha20Poly1305::new(payload_key.expose().into());
    let stream_encryptor = stream::EncryptorBE32::from_aead(cipher, stream_nonce.into());
    EncryptWriter::new(stream_encryptor, writer)
}

/// Constructs a [`DecryptReader`] for the per-file payload pipeline.
///
/// The decrypt counterpart of [`payload_encryptor`]. `payload_key` and
/// `stream_nonce` MUST come from a header whose MAC has been verified
/// (see `format::verify_header_mac`); per `FORMAT.md` §3.7 a candidate
/// `file_key` is not final until the header MAC also verifies, so this
/// helper does not authenticate either input on its own.
pub(crate) fn payload_decryptor<R: Read>(
    payload_key: &PayloadKey,
    stream_nonce: &[u8; STREAM_NONCE_SIZE],
    reader: R,
) -> DecryptReader<R> {
    let cipher = XChaCha20Poly1305::new(payload_key.expose().into());
    let stream_decryptor = stream::DecryptorBE32::from_aead(cipher, stream_nonce.into());
    DecryptReader::new(stream_decryptor, reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::ENCRYPTION_KEY_SIZE;

    // ─── Streaming AEAD adapter helpers ───────────────────────────────────
    //
    // Lock the chunked encrypt/decrypt boundary cases in `EncryptWriter` and
    // `DecryptReader` with a fixed test key+nonce so each test produces
    // deterministic ciphertext. These adapters are exercised end-to-end by
    // the integration suite, but the cases below pin specific edge cases
    // (exact `BUFFER_SIZE` boundary, byte-at-a-time writes, empty final
    // chunk, small consumer buffers) at the adapter level so a regression
    // in `fill_buffer` or the in-place AEAD wiring fails immediately.

    const TEST_NONCE: [u8; STREAM_NONCE_SIZE] = [0x37; STREAM_NONCE_SIZE];

    fn test_key() -> PayloadKey {
        PayloadKey::from_bytes_for_tests([0x42; ENCRYPTION_KEY_SIZE])
    }

    fn encrypt_to_vec(plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext: Vec<u8> = Vec::new();
        let mut writer = payload_encryptor(&test_key(), &TEST_NONCE, &mut ciphertext);
        writer.write_all(plaintext).unwrap();
        let _ = writer.finish().unwrap();
        ciphertext
    }

    fn decrypt_to_vec(ciphertext: &[u8]) -> Vec<u8> {
        let mut reader = payload_decryptor(&test_key(), &TEST_NONCE, ciphertext);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        out
    }

    /// Plaintext exactly equal to one chunk: per `FORMAT.md` §5,
    /// writers MUST NOT append an extra empty final chunk after
    /// non-empty plaintext whose length is a multiple of `BUFFER_SIZE`.
    /// The writer therefore defers the full `BUFFER_SIZE` chunk
    /// until `finish()` and emits it as a single full-size **final**
    /// chunk via `encrypt_last_in_place`. Total ciphertext is exactly
    /// one full encrypted chunk (no separate tag-only trailer).
    #[test]
    fn streaming_aead_round_trip_exact_buffer_size() {
        let plaintext: Vec<u8> = (0..BUFFER_SIZE).map(|i| (i % 251) as u8).collect();
        let ciphertext = encrypt_to_vec(&plaintext);
        assert_eq!(
            ciphertext.len(),
            BUFFER_SIZE + TAG_SIZE,
            "expected exactly one full final chunk (FORMAT.md §5: no empty trailer)"
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
        let mut writer = payload_encryptor(&test_key(), &TEST_NONCE, &mut ciphertext);
        for byte in &plaintext {
            writer.write_all(std::slice::from_ref(byte)).unwrap();
        }
        let _ = writer.finish().unwrap();
        let decrypted = decrypt_to_vec(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// Plaintext is an exact 3× multiple of `BUFFER_SIZE`. Per
    /// `FORMAT.md` §5, the file is laid out as two `next` chunks
    /// followed by a full-size `last` chunk — no empty trailer.
    /// The reader must use its 1-byte peek to distinguish
    /// "exact-N-final" from "exact-N-then-more" without misclassifying
    /// either.
    #[test]
    fn streaming_aead_exact_multiple_no_empty_trailer() {
        let plaintext: Vec<u8> = (0..(BUFFER_SIZE * 3)).map(|i| (i % 251) as u8).collect();
        let ciphertext = encrypt_to_vec(&plaintext);
        assert_eq!(
            ciphertext.len(),
            3 * (BUFFER_SIZE + TAG_SIZE),
            "expected three full chunks (last one is the FINAL chunk; FORMAT.md §5)"
        );
        let decrypted = decrypt_to_vec(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// Empty plaintext is encoded as one empty FINAL chunk (just the
    /// 16-byte AEAD tag). FORMAT.md §5 calls this out as the only
    /// case where an empty final chunk is permitted.
    #[test]
    fn streaming_aead_empty_plaintext_is_single_tag_only_chunk() {
        let ciphertext = encrypt_to_vec(&[]);
        assert_eq!(
            ciphertext.len(),
            TAG_SIZE,
            "empty plaintext must produce exactly one tag-only final chunk"
        );
        let decrypted = decrypt_to_vec(&ciphertext);
        assert_eq!(decrypted, &[] as &[u8]);
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

        let mut reader = payload_decryptor(&test_key(), &TEST_NONCE, ciphertext.as_slice());
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

    /// A completely empty input (0 bytes) hits the dedicated
    /// `filled == 0` truncation path: there is no final
    /// authenticated chunk at all, and the reader rejects via
    /// `StreamError::Truncated` → `CryptoError::PayloadTruncated`
    /// rather than silently returning empty plaintext. (Empty
    /// **plaintext** is a different case: the writer still emits one
    /// tag-only `encrypt_last` chunk; see
    /// `streaming_aead_empty_plaintext_is_single_tag_only_chunk`.)
    #[test]
    fn streaming_aead_empty_input_rejected_as_truncation() {
        let mut reader = payload_decryptor(&test_key(), &TEST_NONCE, &[][..]);
        let (out, err) = drain_decrypt_reader(&mut reader);
        let err = err.expect("expected truncation error, got clean EOF");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        let marker = err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<StreamError>())
            .expect("expected StreamError marker");
        assert!(
            matches!(marker, StreamError::Truncated),
            "expected StreamError::Truncated, got {marker:?}"
        );
        assert!(
            out.is_empty(),
            "no plaintext should be served on empty input"
        );
    }

    /// Truncating a multi-chunk stream at an exact chunk boundary
    /// (so the file ends after a `next` chunk with no `last` chunk
    /// at all) surfaces as AEAD authentication failure on the
    /// remaining chunk: AEAD-BE32 binds the `last_flag` in the
    /// chunk nonce, so a truncated `next` chunk cannot be
    /// re-authenticated as `last`. This test pins the behavior so a
    /// future regression that bypasses the AEAD binding would be
    /// caught.
    #[test]
    fn streaming_aead_chunk_boundary_truncation_rejected() {
        // 2× BUFFER_SIZE plaintext → 1 `next` chunk + 1 full-size
        // `last` chunk under FORMAT.md §5.
        let plaintext: Vec<u8> = (0..(BUFFER_SIZE * 2)).map(|i| (i % 251) as u8).collect();
        let mut ciphertext = encrypt_to_vec(&plaintext);
        // Drop the entire `last` chunk: file now ends right after a
        // `next` chunk.
        ciphertext.truncate(BUFFER_SIZE + TAG_SIZE);

        let mut reader = payload_decryptor(&test_key(), &TEST_NONCE, ciphertext.as_slice());
        let (out, err) = drain_decrypt_reader(&mut reader);
        let err = err.expect("expected AEAD error on chunk-boundary truncation");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let marker = err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<StreamError>())
            .expect("expected StreamError marker");
        assert!(
            matches!(marker, StreamError::DecryptAead),
            "expected StreamError::DecryptAead, got {marker:?}"
        );
        // No plaintext was served: the reader's 1-byte peek returned 0
        // (EOF) immediately after the only chunk, so it tried to
        // decrypt the chunk as `last`, which fails AEAD because the
        // chunk was actually written with `last_flag = 0`.
        assert!(
            out.is_empty(),
            "no plaintext should leak from a truncated `next` chunk"
        );
    }

    /// Flip one byte in a late ciphertext chunk. The reader should return the
    /// already-verified first plaintext chunk, then fail when it reaches the
    /// corrupted later chunk instead of silently accepting modified data.
    /// Confirms that no bytes from the failing chunk are returned.
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

        let mut reader = payload_decryptor(&test_key(), &TEST_NONCE, ciphertext.as_slice());
        let (out, err) = drain_decrypt_reader(&mut reader);
        let err = err.expect("expected AEAD tamper error, got clean EOF");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let marker = err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<StreamError>())
            .expect("expected StreamError marker");
        assert!(
            matches!(marker, StreamError::DecryptAead),
            "expected StreamError::DecryptAead, got {marker:?}"
        );
        // Exactly the first chunk's plaintext must have been served:
        //  - chunk 1 was fully verified, so its plaintext is delivered;
        //  - chunk 2 failed AEAD verification, so none of its bytes leak;
        //  - the final chunk is never reached.
        assert_eq!(out.as_slice(), &plaintext[..BUFFER_SIZE]);
    }

    /// Mid-chunk truncation: the final encrypted chunk is partially present
    /// but shorter than `BUFFER_SIZE + TAG_SIZE`. `fill_buffer` treats the
    /// short buffer as the final chunk and runs `decrypt_last_in_place`,
    /// which must fail AEAD authentication. The user-visible variant is
    /// `PayloadTampered`, not `PayloadTruncated`: we cannot distinguish a
    /// truncated tail from a tampered tail, and either way the tail must
    /// be rejected.
    #[test]
    fn streaming_aead_mid_chunk_truncation_rejected() {
        let plaintext: Vec<u8> = (0..(BUFFER_SIZE + 500)).map(|i| (i % 251) as u8).collect();
        let mut ciphertext = encrypt_to_vec(&plaintext);
        // Drop 10 bytes from inside the final (short) chunk, leaving a
        // partial chunk that still has data but is not a valid AEAD frame.
        ciphertext.truncate(ciphertext.len() - 10);

        let mut reader = payload_decryptor(&test_key(), &TEST_NONCE, ciphertext.as_slice());
        let (out, err) = drain_decrypt_reader(&mut reader);
        let err = err.expect("expected AEAD error on mid-chunk truncation");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let marker = err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<StreamError>())
            .expect("expected StreamError marker");
        assert!(
            matches!(marker, StreamError::DecryptAead),
            "expected StreamError::DecryptAead, got {marker:?}"
        );
        // First chunk verified cleanly and its plaintext was delivered;
        // mid-chunk truncation aborts the final chunk with no leaked bytes.
        assert_eq!(out.as_slice(), &plaintext[..BUFFER_SIZE]);
    }

    /// Reader that first yields the "legitimate" ciphertext segment (the
    /// valid stream, as written by `EncryptWriter::finish`) signalling EOF
    /// at its end, then — on the *next* `read()` call — returns additional
    /// bytes. This is exactly the pathological pattern the `ExtraData`
    /// probe defends against: a non-blocking socket or Take-style wrapper
    /// that returns `Ok(0)` prematurely and then later produces more data.
    ///
    /// A plain `&[u8]` reader cannot exercise this branch because its
    /// read loop reads all remaining bytes in one pass and lets AEAD
    /// authentication reject the trailing bytes as `PayloadTampered`.
    struct LegitThenExtraReader<'a> {
        legit: &'a [u8],
        extra: &'a [u8],
        legit_pos: usize,
        extra_pos: usize,
        /// Flips to `true` the first time we hit EOF inside `legit`, so
        /// the subsequent `read` call is the one that starts dispensing
        /// bytes from `extra`.
        legit_exhausted: bool,
    }

    impl<'a> LegitThenExtraReader<'a> {
        fn new(legit: &'a [u8], extra: &'a [u8]) -> Self {
            Self {
                legit,
                extra,
                legit_pos: 0,
                extra_pos: 0,
                legit_exhausted: false,
            }
        }
    }

    impl<'a> Read for LegitThenExtraReader<'a> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.legit_exhausted {
                let remaining = self.legit.len() - self.legit_pos;
                if remaining == 0 {
                    // First EOF on the legit segment: caller (fill_buffer
                    // inner loop) will treat this as "done" and proceed
                    // into decrypt_last. The probe then calls read again
                    // and we start dispensing `extra`.
                    self.legit_exhausted = true;
                    return Ok(0);
                }
                let n = cmp::min(buf.len(), remaining);
                buf[..n].copy_from_slice(&self.legit[self.legit_pos..self.legit_pos + n]);
                self.legit_pos += n;
                return Ok(n);
            }

            let remaining = self.extra.len() - self.extra_pos;
            if remaining == 0 {
                return Ok(0);
            }
            let n = cmp::min(buf.len(), remaining);
            buf[..n].copy_from_slice(&self.extra[self.extra_pos..self.extra_pos + n]);
            self.extra_pos += n;
            Ok(n)
        }
    }

    /// Pathological-reader trailing-data case: a reader that returns the
    /// valid ciphertext, signals EOF, and then produces extra bytes.
    /// `fill_buffer` treats the EOF as the end of the final chunk and
    /// runs `decrypt_last_in_place` successfully; the trailing-data probe
    /// then catches the stray bytes and rejects the stream with
    /// [`StreamError::ExtraData`]. Locks in the L3 defense-in-depth
    /// wiring so the dedicated error variant cannot silently regress to
    /// unreachable code.
    #[test]
    fn streaming_aead_extra_data_after_final_chunk_rejected() {
        // Use multi-chunk plaintext so the first chunk is served through
        // `Read` before the probe fires. On a single-chunk plaintext the whole
        // authenticated payload would be dropped when the probe returns Err (the
        // plaintext in `self.chunk` is only dispensed by subsequent
        // `read()` calls, and `fill_buffer`'s Err propagates first) —
        // that's correct fail-closed behaviour but makes the partial-
        // output assertion trivially empty.
        let plaintext: Vec<u8> = (0..(BUFFER_SIZE + 500)).map(|i| (i % 251) as u8).collect();
        let ciphertext = encrypt_to_vec(&plaintext);
        let trailing = b"garbage-appended-by-attacker";

        let reader_wrapper = LegitThenExtraReader::new(&ciphertext, trailing);
        // `DecryptReader` requires the reader type to be `Read`; the
        // wrapper above satisfies that contract. We cannot reuse
        // `drain_decrypt_reader` here because it's hard-coded to
        // `&[u8]`; inline the drain loop instead.
        let mut reader = payload_decryptor(&test_key(), &TEST_NONCE, reader_wrapper);
        let mut out = Vec::new();
        let mut scratch = [0u8; 4096];
        let err = loop {
            match reader.read(&mut scratch) {
                Ok(0) => panic!("expected ExtraData error, got clean EOF"),
                Ok(n) => out.extend_from_slice(&scratch[..n]),
                Err(e) => break e,
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let marker = err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<StreamError>())
            .expect("expected StreamError marker");
        assert!(
            matches!(marker, StreamError::ExtraData),
            "expected StreamError::ExtraData, got {marker:?}"
        );
        // The first chunk (BUFFER_SIZE bytes) is fully authenticated and
        // served through `read()` before the second `fill_buffer` call
        // decrypts the final chunk and the probe fires. The final chunk's
        // 500 authenticated plaintext bytes are dropped on the Err path —
        // that's the correct fail-closed outcome for a tainted stream.
        assert_eq!(out.as_slice(), &plaintext[..BUFFER_SIZE]);
    }
}
