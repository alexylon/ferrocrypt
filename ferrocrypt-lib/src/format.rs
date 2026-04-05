/// FerroCrypt file format header.
///
/// Every encrypted file starts with an 8-byte prefix that identifies the format,
/// version, and structure before any cryptographic parsing begins.
///
/// ## Header layout
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
/// ## Detection of old files
///
/// Files created before this header existed start with bincode-serialized flags,
/// which never begin with `0xFC`. The first byte alone distinguishes old from new
/// files, producing a clear error instead of a misleading "wrong password."
use std::io::{self, Read};

use crate::CryptoError;

// ─── Shared ────────────────────────────────────────────────────────────────

pub const MAGIC_BYTE: u8 = 0xFC;

// ─── Encrypted file format (.fcr) ──────────────────────────────────────────

pub const TYPE_SYMMETRIC: u8 = 0x53; // 'S'
pub const TYPE_HYBRID: u8 = 0x48; // 'H'
pub const FORMAT_MAJOR: u8 = 3;
pub const FORMAT_MINOR: u8 = 0;
pub const HEADER_PREFIX_SIZE: usize = 8;
pub const ENCRYPTED_EXTENSION: &str = "fcr";
pub const ENCRYPTED_DOT_EXTENSION: &str = ".fcr";

#[allow(dead_code)]
pub struct FileHeader {
    pub format_type: u8,
    pub major: u8,
    pub minor: u8,
    pub header_len: u16,
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
        FORMAT_MAJOR,
        FORMAT_MINOR,
        (header_len >> 8) as u8,
        (header_len & 0xFF) as u8,
        (flags >> 8) as u8,
        (flags & 0xFF) as u8,
    ]
}

/// Reads and validates the header prefix from a reader (for streaming reads).
/// Returns both the raw prefix bytes (needed for HMAC) and the parsed header.
pub fn read_header_from_reader(
    reader: &mut impl Read,
    expected_type: u8,
) -> Result<([u8; HEADER_PREFIX_SIZE], FileHeader), CryptoError> {
    let mut prefix = [0u8; HEADER_PREFIX_SIZE];
    reader.read_exact(&mut prefix).map_err(|_| {
        CryptoError::EncryptionDecryptionError("File is too short or corrupted".to_string())
    })?;

    let header = validate_header_bytes(&prefix, expected_type)?;
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
    let expected_after_prefix = (header_len as usize).saturating_sub(HEADER_PREFIX_SIZE);
    if bytes_read_after_prefix > expected_after_prefix {
        return Err(CryptoError::EncryptionDecryptionError(
            "Header is corrupted (read more bytes than header declares)".to_string(),
        ));
    }
    let to_skip = expected_after_prefix - bytes_read_after_prefix;
    if to_skip > 0 {
        let skipped =
            io::copy(&mut reader.take(to_skip as u64), &mut io::sink()).map_err(|_| {
                CryptoError::EncryptionDecryptionError("File is too short or corrupted".to_string())
            })?;
        if (skipped as usize) < to_skip {
            return Err(CryptoError::EncryptionDecryptionError(
                "File is too short or corrupted".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_header_bytes(
    prefix: &[u8; HEADER_PREFIX_SIZE],
    expected_type: u8,
) -> Result<FileHeader, CryptoError> {
    if prefix[0] != MAGIC_BYTE {
        return Err(CryptoError::EncryptionDecryptionError(
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
        return Err(CryptoError::EncryptionDecryptionError(format!(
            "Expected {} format, but file has a different format type",
            expected
        )));
    }

    let major = prefix[2];
    let minor = prefix[3];

    if major > FORMAT_MAJOR {
        return Err(CryptoError::EncryptionDecryptionError(format!(
            "Format version {}.{} not supported (max: {}.{}). Upgrade FerroCrypt.",
            major, minor, FORMAT_MAJOR, FORMAT_MINOR
        )));
    }
    if major < FORMAT_MAJOR {
        return Err(CryptoError::EncryptionDecryptionError(format!(
            "Format version {}.{} no longer supported (current: {}.{})",
            major, minor, FORMAT_MAJOR, FORMAT_MINOR
        )));
    }

    let header_len = u16::from_be_bytes([prefix[4], prefix[5]]);
    if (header_len as usize) < HEADER_PREFIX_SIZE {
        return Err(CryptoError::EncryptionDecryptionError(
            "File header is corrupted (invalid header length)".to_string(),
        ));
    }
    let flags = u16::from_be_bytes([prefix[6], prefix[7]]);
    if flags != 0 {
        return Err(CryptoError::EncryptionDecryptionError(format!(
            "Unknown header flags (0x{:04X}). Upgrade FerroCrypt.",
            flags
        )));
    }

    Ok(FileHeader {
        format_type: prefix[1],
        major,
        minor,
        header_len,
        flags,
    })
}

// ─── Key file format ───────────────────────────────────────────────────────
//
// Both `public.key` and `secret.key` share the same 8-byte header prefix:
//
// | Offset | Size | Field     | Description                                  |
// |--------|------|-----------|----------------------------------------------|
// | 0      | 1    | Magic     | `0xFC` — identifies this as a FerroCrypt file|
// | 1      | 1    | Type      | `0x50` ('P') public, `0x53` ('S') secret     |
// | 2      | 1    | Version   | Key file format version (currently 1)        |
// | 3      | 1    | Algorithm | `0x01` = X25519                              |
// | 4-5    | 2    | Data len  | Big-endian u16: bytes after this header       |
// | 6-7    | 2    | Flags     | Big-endian u16: reserved for future use       |

pub const KEY_FILE_HEADER_SIZE: usize = 8;
pub const KEY_FILE_TYPE_PUBLIC: u8 = 0x50; // 'P'
pub const KEY_FILE_TYPE_SECRET: u8 = 0x53; // 'S'
pub const KEY_FILE_VERSION: u8 = 1;
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

pub fn validate_key_file_header(
    data: &[u8],
    expected_type: u8,
    expected_data_size: usize,
) -> Result<(), CryptoError> {
    if data.len() < KEY_FILE_HEADER_SIZE {
        return Err(CryptoError::EncryptionDecryptionError(
            "Key file is too short or corrupted".to_string(),
        ));
    }
    if data[0] != MAGIC_BYTE {
        return Err(CryptoError::EncryptionDecryptionError(
            "Not a FerroCrypt key file".to_string(),
        ));
    }
    let actual_type = data[1];
    if actual_type != expected_type {
        let expected = if expected_type == KEY_FILE_TYPE_PUBLIC {
            "public"
        } else {
            "secret"
        };
        let actual = if actual_type == KEY_FILE_TYPE_PUBLIC {
            "public"
        } else if actual_type == KEY_FILE_TYPE_SECRET {
            "secret"
        } else {
            "unknown"
        };
        return Err(CryptoError::EncryptionDecryptionError(format!(
            "Expected a {expected} key file but got a {actual} key file"
        )));
    }
    if data[2] != KEY_FILE_VERSION {
        return Err(CryptoError::EncryptionDecryptionError(format!(
            "Key file version {} not supported (expected {})",
            data[2], KEY_FILE_VERSION
        )));
    }
    if data[3] != KEY_FILE_ALG_X25519 {
        return Err(CryptoError::EncryptionDecryptionError(format!(
            "Key file algorithm {} not supported",
            data[3]
        )));
    }
    let data_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    if data_len != expected_data_size {
        return Err(CryptoError::EncryptionDecryptionError(format!(
            "Key file has unexpected data length ({}, expected {})",
            data_len, expected_data_size
        )));
    }
    let flags = u16::from_be_bytes([data[6], data[7]]);
    if flags != 0 {
        return Err(CryptoError::EncryptionDecryptionError(format!(
            "Unknown key file flags (0x{:04X}). Upgrade FerroCrypt.",
            flags
        )));
    }
    if data.len() < KEY_FILE_HEADER_SIZE + data_len {
        return Err(CryptoError::EncryptionDecryptionError(
            "Key file is truncated".to_string(),
        ));
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
        let header_len = (HEADER_PREFIX_SIZE + 5) as u16;
        skip_unknown_header_bytes(&mut cursor, header_len, 5).unwrap();
        assert_eq!(cursor.position(), 0);
    }

    #[test]
    fn skip_advances_past_unknown_fields() {
        let data = vec![0xBB; 20];
        let mut cursor = Cursor::new(data);
        // header_len = 18 total, prefix = 8, so 10 bytes after prefix.
        // 6 already consumed → skip 4.
        skip_unknown_header_bytes(&mut cursor, 18, 6).unwrap();
        assert_eq!(cursor.position(), 4);
    }

    #[test]
    fn skip_fails_when_file_too_short() {
        let data = vec![0xCC; 2];
        let mut cursor = Cursor::new(data);
        let header_len = (HEADER_PREFIX_SIZE + 15) as u16;
        assert!(skip_unknown_header_bytes(&mut cursor, header_len, 5).is_err());
    }
}
