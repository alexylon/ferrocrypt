//! FerroCrypt on-disk format v1.
//!
//! Normative spec: `ferrocrypt-lib/FORMAT.md`.
//!
//! ## `.fcr` wire format
//!
//! ```text
//! [replicated_prefix (27 bytes)]
//! [mode_envelope]              -- 116 B symmetric, 104 B hybrid
//! [stream_nonce (19 bytes)]
//! [ext_bytes (ext_len bytes)]
//! [hmac_tag (32 bytes)]
//! [payload]                    -- XChaCha20-Poly1305 STREAM-BE32
//! ```
//!
//! ## Logical prefix (8 bytes, stored replicated)
//!
//! | Offset | Size | Field     | Value / meaning                              |
//! |--------|------|-----------|----------------------------------------------|
//! | 0–3    | 4    | `magic`   | `"FCR\0"` = `0x46 0x43 0x52 0x00`            |
//! | 4      | 1    | `version` | `0x01`                                       |
//! | 5      | 1    | `type`    | `0x53 'S'` symmetric · `0x48 'H'` hybrid     |
//! | 6–7    | 2    | `ext_len` | `u16 BE`; byte length of `ext_bytes`         |
//!
//! The 8-byte logical prefix is written to disk as:
//!
//! ```text
//! 3 pad bytes (all zero) || copy_0 (8 B) || copy_1 (8 B) || copy_2 (8 B)  = 27 bytes
//! ```
//!
//! Writers MUST emit three byte-identical copies with all pad bytes zero.
//! Readers validate canonicity by majority-vote decoding the logical
//! prefix and comparing the on-disk bytes to the canonical re-encoding;
//! a mismatch is rejected as [`FormatDefect::CorruptedPrefix`], carrying
//! the decoded view so upgrade diagnostics (e.g. "file says v2") still
//! surface on a bit-rotten file. See
//! [`decode_and_canonicalize_prefix`].
//!
//! Replication scope is **only** the 8-byte prefix. All other header
//! fields (salts, nonces, envelope, ext_bytes, HMAC tag) are stored raw
//! and authenticated cryptographically.
//!
//! ## `private.key` layout (v1, 125 bytes when `ext_len = 0`)
//!
//! | Offset | Size | Field         |
//! |--------|------|---------------|
//! | 0–3    | 4    | `magic`       |
//! | 4      | 1    | `version`     |
//! | 5      | 1    | `type` (`0x4B 'K'`) |
//! | 6      | 1    | `algorithm` (`0x01` X25519) |
//! | 7–8    | 2    | `ext_len`     |
//! | 9–40   | 32   | `argon2_salt` |
//! | 41–52  | 12   | `kdf_params`  |
//! | 53–76  | 24   | `wrap_nonce`  |
//! | 77…    | ext_len | `ext_bytes` |
//! | next   | 48   | `wrapped_privkey` (32 B + 16 B AEAD tag) |
//!
//! The AEAD that unwraps `wrapped_privkey` binds every cleartext byte
//! before `wrapped_privkey` as associated data, so tampering with any
//! cleartext field surfaces as [`CryptoError::KeyFileUnlockFailed`].
//!
//! ## `public.key`
//!
//! `public.key` is a UTF-8 **text** file containing the canonical
//! `fcr1…` Bech32 recipient string followed by an optional trailing
//! line feed. There is no binary `public.key` format in v1. The
//! parsing and Bech32 grammar for `fcr1…` live in `lib.rs`.

use std::io::Read;

use crate::CryptoError;
use crate::error::{FormatDefect, UnsupportedVersion};
use crate::replication::{decode, encode, encoded_size};

// ─── Shared ────────────────────────────────────────────────────────────────

/// 4-byte ASCII magic identifying every FerroCrypt v1 artefact.
pub const MAGIC: [u8; 4] = [b'F', b'C', b'R', 0];
pub const MAGIC_SIZE: usize = MAGIC.len();

// ─── Encrypted file format (.fcr) — v1 ─────────────────────────────────────

/// Encrypted-file version byte. Reset to 1 for v1; future breaking
/// changes bump this.
pub const VERSION: u8 = 1;

/// Symmetric `.fcr` type byte.
pub const TYPE_SYMMETRIC: u8 = 0x53; // 'S'
/// Hybrid `.fcr` type byte.
pub const TYPE_HYBRID: u8 = 0x48; // 'H'

pub const HEADER_PREFIX_SIZE: usize = 8;
pub const HEADER_PREFIX_ENCODED_SIZE: usize = encoded_size(HEADER_PREFIX_SIZE);

/// Maximum `ext_len` a reader will accept, in both `.fcr` prefixes and
/// `private.key` headers. Readers MUST reject larger values with
/// [`FormatDefect::ExtTooLarge`]. Writers SHOULD stay well under.
pub const EXT_LEN_MAX: u16 = 32 * 1024;

/// Default file extension for encrypted FerroCrypt payload files.
pub const ENCRYPTED_EXTENSION: &str = "fcr";

/// Parsed v1 `.fcr` prefix. `format_type` is validated against the
/// caller's expected type at parse time.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct FileHeader {
    pub format_type: u8,
    pub version: u8,
    pub ext_len: u16,
}

/// Builds the 8-byte logical prefix for a v1 `.fcr` file.
pub fn build_header_prefix(format_type: u8, ext_len: u16) -> [u8; HEADER_PREFIX_SIZE] {
    let mut out = [0u8; HEADER_PREFIX_SIZE];
    out[0..4].copy_from_slice(&MAGIC);
    out[4] = VERSION;
    out[5] = format_type;
    out[6..8].copy_from_slice(&ext_len.to_be_bytes());
    out
}

/// Build and triple-replicate the 8-byte logical prefix in one step,
/// returning the 27-byte on-disk form as a fixed-size array. Encrypt
/// paths that need the on-disk prefix as HMAC input skip the
/// `Vec<u8>` → `[u8; 27]` conversion boilerplate.
pub fn build_encoded_header_prefix(
    format_type: u8,
    ext_len: u16,
) -> Result<[u8; HEADER_PREFIX_ENCODED_SIZE], CryptoError> {
    let logical = build_header_prefix(format_type, ext_len);
    encode(&logical).as_slice().try_into().map_err(|_| {
        CryptoError::InternalInvariant("internal error: prefix encoding size mismatch")
    })
}

/// Reads and validates the triple-replicated 8-byte prefix from a
/// reader. Returns the **on-disk canonical 27 bytes** (for HMAC input)
/// and the parsed logical header.
///
/// Validates, in order:
/// - truncation (read_exact);
/// - canonicity (on-disk bytes equal the canonical re-encoding of the
///   majority-voted logical prefix);
/// - magic bytes;
/// - version;
/// - type byte matches `expected_type`;
/// - `ext_len` is within [`EXT_LEN_MAX`].
pub fn read_header_from_reader(
    reader: &mut impl Read,
    expected_type: u8,
) -> Result<([u8; HEADER_PREFIX_ENCODED_SIZE], FileHeader), CryptoError> {
    let mut on_disk = [0u8; HEADER_PREFIX_ENCODED_SIZE];
    reader
        .read_exact(&mut on_disk)
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::Truncated))?;

    let (logical, canonical) = decode_and_canonicalize_prefix(&on_disk)?;
    let header = parse_header_bytes(&logical, expected_type)?;
    Ok((canonical, header))
}

/// Decodes a 27-byte replicated prefix to its 8-byte logical form AND
/// verifies canonicity. Returns `(logical_prefix, canonical_on_disk_bytes)`.
///
/// Canonicity check: writers MUST emit three byte-identical copies of
/// the logical prefix, preceded by three zero pad bytes. Readers
/// compare the on-disk bytes to the canonical re-encoding of the
/// decoded logical prefix. Any mismatch — from a single-byte flip in a
/// replica, from nonzero pad bytes, or from copies that outright
/// disagree — is rejected as [`FormatDefect::CorruptedPrefix`]. The
/// decoded view is preserved in the error so upgrade messages ("file
/// says v2") can still be surfaced on a bit-rotten file.
pub fn decode_and_canonicalize_prefix(
    on_disk: &[u8; HEADER_PREFIX_ENCODED_SIZE],
) -> Result<([u8; HEADER_PREFIX_SIZE], [u8; HEADER_PREFIX_ENCODED_SIZE]), CryptoError> {
    let decoded = decode(on_disk)?;
    if decoded.len() != HEADER_PREFIX_SIZE {
        return Err(CryptoError::InvalidFormat(FormatDefect::CorruptedHeader));
    }
    let mut logical = [0u8; HEADER_PREFIX_SIZE];
    logical.copy_from_slice(&decoded);

    let canonical = encode(&logical);
    debug_assert_eq!(canonical.len(), HEADER_PREFIX_ENCODED_SIZE);
    if canonical.as_slice() != on_disk.as_slice() {
        return Err(CryptoError::InvalidFormat(FormatDefect::CorruptedPrefix {
            decoded_view: logical,
        }));
    }

    let mut canonical_arr = [0u8; HEADER_PREFIX_ENCODED_SIZE];
    canonical_arr.copy_from_slice(&canonical);
    Ok((logical, canonical_arr))
}

/// Parses a decoded 8-byte logical prefix into a [`FileHeader`]. Does
/// NOT enforce canonicity (the caller is expected to have done so via
/// [`decode_and_canonicalize_prefix`]).
fn parse_header_bytes(
    logical: &[u8; HEADER_PREFIX_SIZE],
    expected_type: u8,
) -> Result<FileHeader, CryptoError> {
    if logical[0..4] != MAGIC {
        return Err(CryptoError::InvalidFormat(FormatDefect::BadMagic));
    }

    let version = logical[4];
    if version != VERSION {
        return Err(unsupported_file_version_error(version));
    }

    let format_type = logical[5];
    if format_type != expected_type {
        // Distinguish "unknown type byte" from "known type but not what
        // we were asked to parse". The former hints "upgrade"; the
        // latter hints "you picked the wrong operation".
        if format_type != TYPE_SYMMETRIC && format_type != TYPE_HYBRID {
            return Err(CryptoError::InvalidFormat(FormatDefect::UnknownType {
                type_byte: format_type,
            }));
        }
        return Err(CryptoError::InvalidFormat(
            FormatDefect::WrongEncryptedFileType,
        ));
    }

    let ext_len = u16::from_be_bytes([logical[6], logical[7]]);
    check_ext_len(ext_len)?;

    Ok(FileHeader {
        format_type,
        version,
        ext_len,
    })
}

/// Rejects an `ext_len` that exceeds [`EXT_LEN_MAX`]. Shared by the
/// `.fcr` prefix parser and the `private.key` header parser.
fn check_ext_len(ext_len: u16) -> Result<(), CryptoError> {
    if ext_len > EXT_LEN_MAX {
        return Err(CryptoError::InvalidFormat(FormatDefect::ExtTooLarge {
            len: ext_len,
        }));
    }
    Ok(())
}

pub fn unsupported_file_version_error(version: u8) -> CryptoError {
    if version < VERSION {
        CryptoError::UnsupportedVersion(UnsupportedVersion::OlderFile { version })
    } else {
        CryptoError::UnsupportedVersion(UnsupportedVersion::NewerFile { version })
    }
}

// ─── Key file format — v1 ──────────────────────────────────────────────────
//
// Only `private.key` is binary in v1. `public.key` is a text file
// containing a canonical `fcr1…` Bech32 recipient string; its parsing
// lives in `lib.rs`.

/// `private.key` type byte ('K'). Disambiguated from symmetric `.fcr`'s
/// `'S'` (0x53) so `file(1)`-style matchers can tell them apart.
pub const KEY_FILE_TYPE_PRIVATE: u8 = 0x4B;

/// `private.key` version byte. Reset to 1 for v1.
pub const PRIVATE_KEY_VERSION: u8 = 1;

/// Algorithm byte: X25519 is the only algorithm defined in v1.
pub const KEY_FILE_ALG_X25519: u8 = 1;

/// Cleartext header of `private.key`: `magic(4) | version(1) | type(1) |
/// algorithm(1) | ext_len(2)`.
pub const PRIVATE_KEY_HEADER_SIZE: usize = 9;

/// Fixed-size portion of `private.key` body between the header and
/// `ext_bytes || wrapped_privkey`: `argon2_salt(32) | kdf_params(12) |
/// wrap_nonce(24)` = 68 bytes.
pub const PRIVATE_KEY_FIXED_BODY_SIZE: usize = 68;

/// AEAD ciphertext + Poly1305 tag for the wrapped private-key material
/// (32-byte plaintext + 16-byte tag).
pub const PRIVATE_KEY_CIPHERTEXT_SIZE: usize = 48;

/// Parsed `private.key` header fields.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct PrivateKeyHeader {
    pub version: u8,
    pub algorithm: u8,
    pub ext_len: u16,
}

/// Builds the 9-byte cleartext header of a v1 `private.key`.
pub fn build_private_key_header(ext_len: u16) -> [u8; PRIVATE_KEY_HEADER_SIZE] {
    let mut out = [0u8; PRIVATE_KEY_HEADER_SIZE];
    out[0..4].copy_from_slice(&MAGIC);
    out[4] = PRIVATE_KEY_VERSION;
    out[5] = KEY_FILE_TYPE_PRIVATE;
    out[6] = KEY_FILE_ALG_X25519;
    out[7..9].copy_from_slice(&ext_len.to_be_bytes());
    out
}

/// Parses the 9-byte `private.key` cleartext header. Validates magic,
/// version, type, algorithm, and `ext_len` bound. Does NOT check file
/// size; the caller does that after reading the full body.
pub fn parse_private_key_header(data: &[u8]) -> Result<PrivateKeyHeader, CryptoError> {
    if data.len() < PRIVATE_KEY_HEADER_SIZE {
        return Err(CryptoError::InvalidFormat(FormatDefect::Truncated));
    }
    if data[0..4] != MAGIC {
        return Err(CryptoError::InvalidFormat(FormatDefect::NotAKeyFile));
    }
    let version = data[4];
    if version != PRIVATE_KEY_VERSION {
        return Err(unsupported_key_version_error(version));
    }
    if data[5] != KEY_FILE_TYPE_PRIVATE {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }
    let algorithm = data[6];
    if algorithm != KEY_FILE_ALG_X25519 {
        return Err(CryptoError::InvalidFormat(FormatDefect::UnknownAlgorithm {
            algorithm,
        }));
    }
    let ext_len = u16::from_be_bytes([data[7], data[8]]);
    check_ext_len(ext_len)?;
    Ok(PrivateKeyHeader {
        version,
        algorithm,
        ext_len,
    })
}

/// Classifies a rejected key-file version as older-than or newer-than
/// the version the reader expects.
pub fn unsupported_key_version_error(version: u8) -> CryptoError {
    if version < PRIVATE_KEY_VERSION {
        CryptoError::UnsupportedVersion(UnsupportedVersion::OlderKey { version })
    } else {
        CryptoError::UnsupportedVersion(UnsupportedVersion::NewerKey { version })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a logical prefix and return it as a fixed-size on-disk
    /// array. Every prefix test goes through this helper to keep the
    /// setup uniform.
    fn encode_to_array(prefix: &[u8; HEADER_PREFIX_SIZE]) -> [u8; HEADER_PREFIX_ENCODED_SIZE] {
        encode(prefix).try_into().unwrap()
    }

    /// Wraps an on-disk prefix in a cursor and calls
    /// [`read_header_from_reader`]. Saves every prefix test from
    /// declaring its own `Cursor` and threading `&mut cur`.
    fn parse_on_disk(
        on_disk: &[u8; HEADER_PREFIX_ENCODED_SIZE],
        expected_type: u8,
    ) -> Result<([u8; HEADER_PREFIX_ENCODED_SIZE], FileHeader), CryptoError> {
        read_header_from_reader(&mut std::io::Cursor::new(on_disk), expected_type)
    }

    #[test]
    fn prefix_round_trip_symmetric() {
        let prefix = build_header_prefix(TYPE_SYMMETRIC, 0);
        let on_disk = encode_to_array(&prefix);
        let (canonical, header) = parse_on_disk(&on_disk, TYPE_SYMMETRIC).unwrap();
        assert_eq!(canonical, on_disk);
        assert_eq!(header.format_type, TYPE_SYMMETRIC);
        assert_eq!(header.version, VERSION);
        assert_eq!(header.ext_len, 0);
    }

    #[test]
    fn prefix_round_trip_hybrid_nonzero_ext_len() {
        let prefix = build_header_prefix(TYPE_HYBRID, 0x1234);
        let on_disk = encode_to_array(&prefix);
        let (_, header) = parse_on_disk(&on_disk, TYPE_HYBRID).unwrap();
        assert_eq!(header.format_type, TYPE_HYBRID);
        assert_eq!(header.ext_len, 0x1234);
    }

    #[test]
    fn prefix_rejects_wrong_magic() {
        let mut prefix = build_header_prefix(TYPE_SYMMETRIC, 0);
        prefix[0] = 0;
        let on_disk = encode_to_array(&prefix);
        match parse_on_disk(&on_disk, TYPE_SYMMETRIC) {
            Err(CryptoError::InvalidFormat(FormatDefect::BadMagic)) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn prefix_rejects_wrong_type_asked() {
        let prefix = build_header_prefix(TYPE_SYMMETRIC, 0);
        let on_disk = encode_to_array(&prefix);
        match parse_on_disk(&on_disk, TYPE_HYBRID) {
            Err(CryptoError::InvalidFormat(FormatDefect::WrongEncryptedFileType)) => {}
            other => panic!("expected WrongEncryptedFileType, got {other:?}"),
        }
    }

    #[test]
    fn prefix_rejects_unknown_type() {
        let mut prefix = build_header_prefix(TYPE_SYMMETRIC, 0);
        prefix[5] = 0x5A; // not 'S' or 'H'
        let on_disk = encode_to_array(&prefix);
        match parse_on_disk(&on_disk, TYPE_SYMMETRIC) {
            Err(CryptoError::InvalidFormat(FormatDefect::UnknownType { type_byte: 0x5A })) => {}
            other => panic!("expected UnknownType(0x5A), got {other:?}"),
        }
    }

    #[test]
    fn prefix_rejects_unsupported_version() {
        let mut prefix = build_header_prefix(TYPE_SYMMETRIC, 0);
        prefix[4] = 2; // future version
        let on_disk = encode_to_array(&prefix);
        match parse_on_disk(&on_disk, TYPE_SYMMETRIC) {
            Err(CryptoError::UnsupportedVersion(UnsupportedVersion::NewerFile { version: 2 })) => {}
            other => panic!("expected NewerFile(v2), got {other:?}"),
        }
    }

    #[test]
    fn prefix_rejects_ext_len_over_bound() {
        let prefix = build_header_prefix(TYPE_SYMMETRIC, EXT_LEN_MAX + 1);
        let on_disk = encode_to_array(&prefix);
        match parse_on_disk(&on_disk, TYPE_SYMMETRIC) {
            Err(CryptoError::InvalidFormat(FormatDefect::ExtTooLarge { .. })) => {}
            other => panic!("expected ExtTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn canonicity_check_rejects_flipped_replica_with_diagnostic() {
        // Build a well-formed prefix, then flip a byte inside copy_1
        // (byte 12 of the 27-byte on-disk layout: 3 pad + copy_0(8) +
        // first byte of copy_1 at index 11, so 12 is still inside
        // copy_1). Majority vote still recovers the logical prefix, but
        // the on-disk bytes are no longer canonical.
        let prefix = build_header_prefix(TYPE_SYMMETRIC, 0);
        let mut on_disk = encode_to_array(&prefix);
        on_disk[12] ^= 0xFF;
        match parse_on_disk(&on_disk, TYPE_SYMMETRIC) {
            Err(CryptoError::InvalidFormat(FormatDefect::CorruptedPrefix { decoded_view })) => {
                assert_eq!(decoded_view, prefix);
            }
            other => panic!("expected CorruptedPrefix, got {other:?}"),
        }
    }

    #[test]
    fn canonicity_check_preserves_version_diagnostic_on_flipped_replica() {
        // Synthesize a v2 file (future version) and flip one replica
        // byte. The canonicity check rejects, but the decoded view must
        // still surface version = 2 so the reader can produce upgrade
        // messaging.
        let mut prefix = build_header_prefix(TYPE_SYMMETRIC, 0);
        prefix[4] = 2;
        let mut on_disk = encode_to_array(&prefix);
        on_disk[12] ^= 0xFF;
        match parse_on_disk(&on_disk, TYPE_SYMMETRIC) {
            Err(CryptoError::InvalidFormat(FormatDefect::CorruptedPrefix { decoded_view })) => {
                assert_eq!(decoded_view[4], 2);
            }
            other => panic!("expected CorruptedPrefix with v=2, got {other:?}"),
        }
    }

    #[test]
    fn canonicity_check_rejects_nonzero_pad_byte() {
        let prefix = build_header_prefix(TYPE_SYMMETRIC, 0);
        let mut on_disk = encode_to_array(&prefix);
        // Corrupt one pad byte. `decode` treats any two-of-three pad
        // bytes agreeing as the indicator; the canonical re-encoding of
        // an even-length (8-byte) prefix has all three pad bytes = 0,
        // so any non-zero pad byte breaks canonicity.
        on_disk[0] = 1;
        match parse_on_disk(&on_disk, TYPE_SYMMETRIC) {
            Err(CryptoError::InvalidFormat(FormatDefect::CorruptedPrefix { .. })) => {}
            other => panic!("expected CorruptedPrefix (nonzero pad), got {other:?}"),
        }
    }

    /// Wire-format regression: prefix byte offsets are part of the
    /// on-disk contract. Reordering them is a breaking change that must
    /// be noticed immediately rather than caught by downstream failures.
    #[test]
    fn prefix_wire_format_offsets() {
        let prefix = build_header_prefix(TYPE_SYMMETRIC, 0x5678);
        assert_eq!(&prefix[0..4], b"FCR\0");
        assert_eq!(prefix[4], VERSION);
        assert_eq!(prefix[5], TYPE_SYMMETRIC);
        assert_eq!(prefix[6], 0x56);
        assert_eq!(prefix[7], 0x78);
    }

    #[test]
    fn private_key_header_round_trip() {
        let raw = build_private_key_header(16);
        let header = parse_private_key_header(&raw).unwrap();
        assert_eq!(header.version, PRIVATE_KEY_VERSION);
        assert_eq!(header.algorithm, KEY_FILE_ALG_X25519);
        assert_eq!(header.ext_len, 16);
    }

    #[test]
    fn private_key_header_wire_format_offsets() {
        let raw = build_private_key_header(0xAABB);
        assert_eq!(&raw[0..4], b"FCR\0");
        assert_eq!(raw[4], PRIVATE_KEY_VERSION);
        assert_eq!(raw[5], KEY_FILE_TYPE_PRIVATE);
        assert_eq!(raw[6], KEY_FILE_ALG_X25519);
        assert_eq!(raw[7], 0xAA);
        assert_eq!(raw[8], 0xBB);
    }

    #[test]
    fn private_key_header_rejects_wrong_magic() {
        let mut raw = build_private_key_header(0);
        raw[0] = 0;
        match parse_private_key_header(&raw) {
            Err(CryptoError::InvalidFormat(FormatDefect::NotAKeyFile)) => {}
            other => panic!("expected NotAKeyFile, got {other:?}"),
        }
    }

    #[test]
    fn private_key_header_rejects_wrong_type() {
        let mut raw = build_private_key_header(0);
        raw[5] = 0x53; // old symmetric .fcr value, not 0x4B
        match parse_private_key_header(&raw) {
            Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType)) => {}
            other => panic!("expected WrongKeyFileType, got {other:?}"),
        }
    }

    #[test]
    fn private_key_header_rejects_unknown_algorithm() {
        let mut raw = build_private_key_header(0);
        raw[6] = 0xFF;
        match parse_private_key_header(&raw) {
            Err(CryptoError::InvalidFormat(FormatDefect::UnknownAlgorithm { algorithm: 0xFF })) => {
            }
            other => panic!("expected UnknownAlgorithm(0xFF), got {other:?}"),
        }
    }

    #[test]
    fn private_key_header_rejects_unsupported_version() {
        let mut raw = build_private_key_header(0);
        raw[4] = 2;
        match parse_private_key_header(&raw) {
            Err(CryptoError::UnsupportedVersion(UnsupportedVersion::NewerKey { version: 2 })) => {}
            other => panic!("expected NewerKey(2), got {other:?}"),
        }
    }

    #[test]
    fn private_key_header_rejects_ext_len_over_bound() {
        let raw = build_private_key_header(EXT_LEN_MAX + 1);
        match parse_private_key_header(&raw) {
            Err(CryptoError::InvalidFormat(FormatDefect::ExtTooLarge { .. })) => {}
            other => panic!("expected ExtTooLarge, got {other:?}"),
        }
    }
}
