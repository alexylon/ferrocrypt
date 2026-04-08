/// FerroCrypt file format header.
///
/// Every encrypted file starts with a triple-replicated 8-byte prefix that
/// identifies the format, version, and structure. The prefix is stored on disk
/// as 27 bytes (3 padding bytes + 3 × 8-byte copies) and decoded via majority vote,
/// giving the same error-correction coverage as all other header fields.
///
/// ## Logical prefix layout (8 bytes, after decoding)
///
/// | Offset | Size | Field         | Description                                      |
/// |--------|------|---------------|--------------------------------------------------|
/// | 0      | 1    | Magic         | `0xFC` — identifies this as a FerroCrypt file    |
/// | 1      | 1    | Type          | `0x53` ('S') symmetric, `0x48` ('H') hybrid      |
/// | 2      | 1    | Major version | Breaking format changes increment this            |
/// | 3      | 1    | Minor version | Backward-compatible additions increment this      |
/// | 4-5    | 2    | Header length | Big-endian u16: bytes from offset 0 to ciphertext |
/// | 6-7    | 2    | Flags         | Big-endian u16: reserved for future use            |
///
/// ## Version handling
///
/// The format version is independent of the crate version. It only changes when
/// the on-disk byte layout changes:
///
/// - **Major bump** (e.g., 1 → 2): new cipher, different header layout, or other
///   breaking change. Older versions reject the file with a clear upgrade message.
/// - **Minor bump** (e.g., 1.0 → 1.1): backward-compatible addition such as an
///   optional metadata field. New fields must be placed **after** the HMAC tag so
///   that older readers can verify the HMAC over known fields, then use the header
///   length to skip the unknown trailing fields before ciphertext.
///
/// Most crate releases do not change the format version at all.
///
/// ## Minor-version contract
///
/// A minor bump is only valid for changes that older readers of the same major
/// can safely ignore. Minor versions **must not** introduce:
/// - required crypto or AEAD changes
/// - required KDF behavior changes
/// - required authentication semantics
/// - any field that older readers must understand to decrypt correctly
///
/// If a change requires the reader to understand the new field to decrypt
/// safely, it **must** be a major bump.
///
/// ## HMAC trust boundary for trailing fields
///
/// The current HMAC authenticates the decoded prefix and all known header fields
/// **before** the stored HMAC tag. Any trailing bytes appended
/// by a future minor version (skipped via `header_len`) are **outside** the
/// HMAC coverage as understood by older readers. This means skipped trailing
/// fields are not authenticated by older readers and must therefore be:
/// - optional (not required for decryption)
/// - non-security-critical (not trusted for access control or key derivation)
/// - ignorable (older readers produce correct output without them)
///
/// ## Detection of old files
///
/// Files created before this header existed start with bincode-serialized flags.
/// After reading and decoding the replicated prefix, the magic byte check
/// (`0xFC`) rejects them with a clear error instead of a misleading "wrong
/// password."
use std::io::{self, Read};

use crate::CryptoError;
use crate::common::ERR_FILE_TOO_SHORT;
use crate::replication::{rep_decode_exact, rep_encoded_size};

// ─── Shared ────────────────────────────────────────────────────────────────

pub const MAGIC_BYTE: u8 = 0xFC;

// ─── Encrypted file format (.fcr) ──────────────────────────────────────────

pub const TYPE_SYMMETRIC: u8 = 0x53; // 'S'
pub const TYPE_HYBRID: u8 = 0x48; // 'H'
pub const ENCRYPTED_FILE_VERSION_MAJOR: u8 = 3;
pub const ENCRYPTED_FILE_VERSION_MINOR: u8 = 0;
pub const HEADER_PREFIX_SIZE: usize = 8;
pub const HEADER_PREFIX_ENCODED_SIZE: usize = rep_encoded_size(HEADER_PREFIX_SIZE);
pub const ENCRYPTED_EXTENSION: &str = "fcr";

#[allow(dead_code)]
pub struct FileHeader {
    pub format_type: u8,
    pub major: u8,
    pub minor: u8,
    pub header_len: u16,
    pub flags: u16,
}

#[allow(dead_code)]
pub struct ParsedKeyHeader {
    pub key_type: u8,
    pub version: u8,
    pub algorithm: u8,
    pub data_len: u16,
    pub flags: u16,
}

/// Builds the 8-byte header prefix as a byte array.
pub fn build_header_prefix(
    format_type: u8,
    flags: u16,
    header_len: u16,
) -> [u8; HEADER_PREFIX_SIZE] {
    [
        MAGIC_BYTE,
        format_type,
        ENCRYPTED_FILE_VERSION_MAJOR,
        ENCRYPTED_FILE_VERSION_MINOR,
        (header_len >> 8) as u8,
        (header_len & 0xFF) as u8,
        (flags >> 8) as u8,
        (flags & 0xFF) as u8,
    ]
}

/// Reads and validates the triple-replicated header prefix from a reader.
/// Returns both the decoded prefix bytes (needed for HMAC) and the parsed header.
pub fn read_header_from_reader(
    reader: &mut impl Read,
    expected_type: u8,
) -> Result<([u8; HEADER_PREFIX_SIZE], FileHeader), CryptoError> {
    let mut encoded = [0u8; HEADER_PREFIX_ENCODED_SIZE];
    reader
        .read_exact(&mut encoded)
        .map_err(|_| CryptoError::CryptoOperation(ERR_FILE_TOO_SHORT.to_string()))?;

    let decoded = rep_decode_exact(&encoded, HEADER_PREFIX_SIZE)?;
    let mut prefix = [0u8; HEADER_PREFIX_SIZE];
    prefix.copy_from_slice(&decoded);

    let header = parse_header_bytes(&prefix, expected_type)?;
    Ok((prefix, header))
}

/// Advances the reader past any header bytes not consumed by this version.
/// Enables forward compatibility: a newer minor version may append fields
/// after the HMAC tag, and older readers use `header_len` to skip them.
pub fn skip_unknown_header_bytes(
    reader: &mut impl Read,
    header_len: u16,
    bytes_read_after_prefix: usize,
) -> Result<(), CryptoError> {
    let expected_after_prefix = (header_len as usize).saturating_sub(HEADER_PREFIX_ENCODED_SIZE);
    if bytes_read_after_prefix > expected_after_prefix {
        return Err(CryptoError::CryptoOperation(
            "Header is corrupted (read more bytes than header declares)".to_string(),
        ));
    }
    let to_skip = expected_after_prefix - bytes_read_after_prefix;
    if to_skip > 0 {
        let skipped = io::copy(&mut reader.take(to_skip as u64), &mut io::sink())
            .map_err(|_| CryptoError::CryptoOperation(ERR_FILE_TOO_SHORT.to_string()))?;
        if (skipped as usize) < to_skip {
            return Err(CryptoError::CryptoOperation(ERR_FILE_TOO_SHORT.to_string()));
        }
    }
    Ok(())
}

/// Parses the decoded 8-byte prefix into a `FileHeader`.
/// Validates magic byte, type, and minimum header length.
/// Does NOT enforce version or flags policy — callers dispatch on `header.major`.
fn parse_header_bytes(
    prefix: &[u8; HEADER_PREFIX_SIZE],
    expected_type: u8,
) -> Result<FileHeader, CryptoError> {
    if prefix[0] != MAGIC_BYTE {
        return Err(CryptoError::CryptoOperation(
            "Not a valid FerroCrypt file. If this file was created with an older version, \
             it cannot be decrypted by this version."
                .to_string(),
        ));
    }

    if prefix[1] != expected_type {
        let expected = match expected_type {
            TYPE_SYMMETRIC => "symmetric",
            TYPE_HYBRID => "hybrid",
            _ => "unknown",
        };
        return Err(CryptoError::CryptoOperation(format!(
            "Expected {} format, but file has a different format type",
            expected
        )));
    }

    let header_len = u16::from_be_bytes([prefix[4], prefix[5]]);
    if (header_len as usize) < HEADER_PREFIX_ENCODED_SIZE {
        return Err(CryptoError::CryptoOperation(
            "File header is corrupted (invalid header length)".to_string(),
        ));
    }

    Ok(FileHeader {
        format_type: prefix[1],
        major: prefix[2],
        minor: prefix[3],
        header_len,
        flags: u16::from_be_bytes([prefix[6], prefix[7]]),
    })
}

pub fn validate_file_flags(header: &FileHeader) -> Result<(), CryptoError> {
    if header.flags != 0 {
        return Err(CryptoError::CryptoOperation(format!(
            "Unknown header flags (0x{:04X}). Upgrade FerroCrypt.",
            header.flags
        )));
    }
    Ok(())
}

pub fn unsupported_file_version_error(major: u8, minor: u8) -> CryptoError {
    if major < ENCRYPTED_FILE_VERSION_MAJOR {
        CryptoError::CryptoOperation(format!(
            "Format version {}.{} is not supported. \
             Files created with older versions must be decrypted \
             using those versions, available on crates.io.",
            major, minor
        ))
    } else {
        CryptoError::CryptoOperation(format!(
            "Format version {}.{} not supported (current: {}). Upgrade FerroCrypt.",
            major, minor, ENCRYPTED_FILE_VERSION_MAJOR
        ))
    }
}

pub fn unsupported_key_version_error(version: u8) -> CryptoError {
    if version < KEY_FILE_VERSION {
        CryptoError::CryptoOperation(format!(
            "Key file version {} is not supported. \
             Keys created with older versions must be used \
             with those versions, available on crates.io.",
            version
        ))
    } else {
        CryptoError::CryptoOperation(format!(
            "Key file version {} not supported (current: {}). Upgrade FerroCrypt.",
            version, KEY_FILE_VERSION
        ))
    }
}

// ─── Key file format ───────────────────────────────────────────────────────
//
// Both `public.key` and `private.key` share the same 8-byte header prefix:
//
// | Offset | Size | Field     | Description                                  |
// |--------|------|-----------|----------------------------------------------|
// | 0      | 1    | Magic     | `0xFC` — identifies this as a FerroCrypt file|
// | 1      | 1    | Type      | `0x50` ('P') public, `0x53` ('S') secret     |
// | 2      | 1    | Version   | Key file format version (currently 2)        |
// | 3      | 1    | Algorithm | `0x01` = X25519                              |
// | 4-5    | 2    | Data len  | Big-endian u16: bytes after this header       |
// | 6-7    | 2    | Flags     | Big-endian u16: reserved for future use       |

pub const KEY_FILE_HEADER_SIZE: usize = 8;
pub const KEY_FILE_TYPE_PUBLIC: u8 = 0x50; // 'P'
pub const KEY_FILE_TYPE_SECRET: u8 = 0x53; // 'S'
pub const PUBLIC_KEY_DATA_SIZE: usize = 32;
// kdf_params(12) + salt(32) + nonce(24) + encrypted_key(32) + tag(16)
pub const SECRET_KEY_DATA_SIZE: usize = 116;
pub const KEY_FILE_VERSION: u8 = 2;
pub const KEY_FILE_ALG_X25519: u8 = 1;

pub fn build_key_file_header(key_type: u8, data_len: u16) -> [u8; KEY_FILE_HEADER_SIZE] {
    [
        MAGIC_BYTE,
        key_type,
        KEY_FILE_VERSION,
        KEY_FILE_ALG_X25519,
        (data_len >> 8) as u8,
        (data_len & 0xFF) as u8,
        0,
        0,
    ]
}

/// Parses the 8-byte key file header without enforcing version policy.
/// Validates magic byte and key type only. Callers dispatch on `header.version`.
pub fn parse_key_file_header(
    data: &[u8],
    expected_type: u8,
) -> Result<ParsedKeyHeader, CryptoError> {
    if data.len() < KEY_FILE_HEADER_SIZE {
        return Err(CryptoError::CryptoOperation(
            "Key file is too short or corrupted".to_string(),
        ));
    }
    if data[0] != MAGIC_BYTE {
        return Err(CryptoError::CryptoOperation(
            "Not a FerroCrypt key file".to_string(),
        ));
    }
    let actual_type = data[1];
    if actual_type != expected_type {
        let expected = if expected_type == KEY_FILE_TYPE_PUBLIC {
            "public"
        } else {
            "private"
        };
        let actual = if actual_type == KEY_FILE_TYPE_PUBLIC {
            "public"
        } else if actual_type == KEY_FILE_TYPE_SECRET {
            "private"
        } else {
            "unknown"
        };
        return Err(CryptoError::CryptoOperation(format!(
            "Expected a {expected} key file but got a {actual} key file"
        )));
    }
    Ok(ParsedKeyHeader {
        key_type: actual_type,
        version: data[2],
        algorithm: data[3],
        data_len: u16::from_be_bytes([data[4], data[5]]),
        flags: u16::from_be_bytes([data[6], data[7]]),
    })
}

/// Validates key file v2 layout: algorithm, data length, flags, and total file size.
pub fn validate_key_v2_layout(
    data: &[u8],
    header: &ParsedKeyHeader,
    expected_data_size: usize,
) -> Result<(), CryptoError> {
    if header.algorithm != KEY_FILE_ALG_X25519 {
        return Err(CryptoError::CryptoOperation(format!(
            "Key file algorithm {} not supported",
            header.algorithm
        )));
    }
    if header.data_len as usize != expected_data_size {
        return Err(CryptoError::CryptoOperation(format!(
            "Key file has unexpected data length ({}, expected {})",
            header.data_len, expected_data_size
        )));
    }
    if header.flags != 0 {
        return Err(CryptoError::CryptoOperation(format!(
            "Unknown key file flags (0x{:04X}). Upgrade FerroCrypt.",
            header.flags
        )));
    }
    if data.len() != KEY_FILE_HEADER_SIZE + expected_data_size {
        return Err(CryptoError::CryptoOperation(format!(
            "Key file has unexpected size ({}, expected {})",
            data.len(),
            KEY_FILE_HEADER_SIZE + expected_data_size
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn skip_is_noop_when_all_bytes_consumed() {
        let data = vec![0xAA; 10];
        let mut cursor = Cursor::new(data);
        let header_len = (HEADER_PREFIX_ENCODED_SIZE + 5) as u16;
        skip_unknown_header_bytes(&mut cursor, header_len, 5).unwrap();
        assert_eq!(cursor.position(), 0);
    }

    #[test]
    fn skip_advances_past_unknown_fields() {
        let data = vec![0xBB; 40];
        let mut cursor = Cursor::new(data);
        // header_len = 37 total, encoded prefix = 27, so 10 bytes after prefix.
        // 6 already consumed → skip 4.
        skip_unknown_header_bytes(&mut cursor, 37, 6).unwrap();
        assert_eq!(cursor.position(), 4);
    }

    #[test]
    fn skip_fails_when_file_too_short() {
        let data = vec![0xCC; 2];
        let mut cursor = Cursor::new(data);
        let header_len = (HEADER_PREFIX_ENCODED_SIZE + 15) as u16;
        assert!(skip_unknown_header_bytes(&mut cursor, header_len, 5).is_err());
    }
}
