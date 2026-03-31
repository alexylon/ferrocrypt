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
///   optional metadata field. Older versions use the header length to skip unknown
///   fields and decrypt normally.
///
/// Most crate releases do not change the format version at all.
///
/// ## Detection of old files
///
/// Files created before this header existed start with bincode-serialized flags,
/// which never begin with `0xFC`. The first byte alone distinguishes old from new
/// files, producing a clear error instead of a misleading "wrong password."
use std::io::Read;

use crate::CryptoError;

pub const MAGIC_BYTE: u8 = 0xFC;
pub const TYPE_SYMMETRIC: u8 = 0x53; // 'S'
pub const TYPE_HYBRID: u8 = 0x48; // 'H'
pub const FORMAT_MAJOR: u8 = 1;
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
            "This file uses format version {}.{} which is not supported. \
             Please upgrade FerroCrypt (max supported: {}.{}).",
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

    Ok(FileHeader {
        format_type: prefix[1],
        major,
        minor,
        header_len,
        flags,
    })
}
