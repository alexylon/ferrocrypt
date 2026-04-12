/// FerroCrypt file format header.
///
/// Every encrypted file starts with a triple-replicated 8-byte prefix that
/// identifies the format, version, and structure. The prefix is stored on disk
/// as 27 bytes (3 padding bytes + 3 × 8-byte copies) and decoded via majority vote,
/// giving the same error-correction coverage as all other header fields.
///
/// ## Logical prefix layout (8 bytes, after decoding)
///
/// | Offset | Size | Field         | Description                                         |
/// |--------|------|---------------|-----------------------------------------------------|
/// | 0      | 1    | Magic         | `0xFC` — identifies this as a FerroCrypt file        |
/// | 1      | 1    | Type          | `0x53` ('S') symmetric, `0x48` ('H') hybrid          |
/// | 2      | 1    | Major version | Breaking format changes increment this               |
/// | 3      | 1    | Minor version | Backward-compatible additions increment this         |
/// | 4-5    | 2    | Flags         | Big-endian u16: reserved, must be `0` for now        |
/// | 6-7    | 2    | Ext length    | Big-endian u16: logical size of authenticated ext    |
///
/// ## Logical header layout (everything before the ciphertext)
///
/// ```text
/// [ prefix ][ fixed core fields ][ ext_bytes (ext_len bytes) ][ hmac_tag ][ ciphertext ]
///  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
///  authenticated by hmac_tag (HMAC-SHA3-256)
/// ```
///
/// - The fixed core fields are defined per-format (symmetric / hybrid).
/// - `ext_bytes` is a single opaque authenticated extension region of `ext_len`
///   logical bytes (zero-length when no extensions are present).
/// - The HMAC tag is stored immediately after `ext_bytes` and covers
///   `prefix || fixed_core || ext_bytes` (all values in their decoded form).
///
/// ## Version handling
///
/// The format version is independent of the crate version. It only changes when
/// the on-disk byte layout changes:
///
/// - **Major bump**: new cipher, incompatible header layout, or any change that
///   older readers cannot safely interpret. Older versions reject the file with
///   a clear upgrade message.
/// - **Minor bump**: backward-compatible addition placed inside the authenticated
///   `ext_bytes` region. Older readers still authenticate the extension bytes via
///   the HMAC (so tampering is detected), then ignore the unknown contents.
///
/// ## Minor-version contract
///
/// Minor bumps are only valid for changes that older readers of the same major
/// can safely ignore. Minor versions **must not** introduce:
/// - required crypto or AEAD changes
/// - required KDF behavior changes
/// - required authentication semantics
/// - any field that older readers must understand to decrypt correctly
///
/// If a change requires the reader to understand the new field to decrypt
/// safely, it **must** be a major bump.
///
/// ## Authentication of extension bytes
///
/// Unlike earlier designs that appended minor-version fields **after** the HMAC
/// tag (outside HMAC coverage), `ext_bytes` sits **before** the HMAC tag and is
/// fully authenticated. An attacker cannot tamper with the extension contents
/// without breaking HMAC verification. Older readers still skip the contents,
/// but the bytes themselves are bound to the file by the HMAC.
///
/// ## Detection of old files
///
/// Files created before this header existed start with bincode-serialized flags.
/// After reading and decoding the replicated prefix, the magic byte check
/// (`0xFC`) rejects them with a clear error instead of a misleading "wrong
/// password."
use std::io::Read;

use crate::CryptoError;
use crate::common::FILE_TOO_SHORT;
use crate::replication::{decode_exact, encoded_size};

/// Reads a single triple-replicated field of logical size `N` from the reader
/// and returns the decoded bytes as a fixed-size array.
///
/// Fails with `InvalidFormat(FILE_TOO_SHORT)` if the reader is short, and with
/// the error from `decode_exact` if the decoded length doesn't match `N`
/// (e.g., corrupted padding indicator that survives majority vote).
pub fn read_replicated_field<const N: usize>(
    reader: &mut impl Read,
) -> Result<[u8; N], CryptoError> {
    let mut encoded = vec![0u8; encoded_size(N)];
    reader
        .read_exact(&mut encoded)
        .map_err(|_| CryptoError::InvalidFormat(FILE_TOO_SHORT.to_string()))?;
    let decoded = decode_exact(&encoded, N)?;
    decoded
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat("Header field length mismatch".to_string()))
}

/// Reads a triple-replicated variable-length region of logical size `len`.
/// Used for the authenticated `ext_bytes` region whose length comes from the
/// header prefix.
pub fn read_replicated_vec(reader: &mut impl Read, len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut encoded = vec![0u8; encoded_size(len)];
    reader
        .read_exact(&mut encoded)
        .map_err(|_| CryptoError::InvalidFormat(FILE_TOO_SHORT.to_string()))?;
    decode_exact(&encoded, len)
}

// ─── Shared ────────────────────────────────────────────────────────────────

pub const MAGIC_BYTE: u8 = 0xFC;

// ─── Encrypted file format (.fcr) ──────────────────────────────────────────

pub const TYPE_SYMMETRIC: u8 = 0x53; // 'S'
pub const TYPE_HYBRID: u8 = 0x48; // 'H'
pub const VERSION_MAJOR: u8 = 3;
pub const HYBRID_VERSION_MAJOR: u8 = 4;
pub const VERSION_MINOR: u8 = 0;
pub const HEADER_PREFIX_SIZE: usize = 8;
pub const HEADER_PREFIX_ENCODED_SIZE: usize = encoded_size(HEADER_PREFIX_SIZE);
pub const ENCRYPTED_EXTENSION: &str = "fcr";

#[allow(dead_code)]
pub struct FileHeader {
    pub format_type: u8,
    pub major: u8,
    pub minor: u8,
    pub flags: u16,
    pub ext_len: u16,
}

#[allow(dead_code)]
pub struct KeyFileHeader {
    pub key_type: u8,
    pub version: u8,
    pub algorithm: u8,
    pub data_len: u16,
    pub flags: u16,
}

/// Builds the 8-byte header prefix for the current writer minor version.
///
/// This helper always writes `VERSION_MINOR` into byte 3. Tests that need to
/// synthesize future-compatible minor versions may mutate that byte after
/// construction.
pub fn build_header_prefix(
    format_type: u8,
    major: u8,
    flags: u16,
    ext_len: u16,
) -> [u8; HEADER_PREFIX_SIZE] {
    [
        MAGIC_BYTE,
        format_type,
        major,
        VERSION_MINOR,
        (flags >> 8) as u8,
        (flags & 0xFF) as u8,
        (ext_len >> 8) as u8,
        (ext_len & 0xFF) as u8,
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
        .map_err(|_| CryptoError::InvalidFormat(FILE_TOO_SHORT.to_string()))?;

    let decoded = decode_exact(&encoded, HEADER_PREFIX_SIZE)?;
    let mut prefix = [0u8; HEADER_PREFIX_SIZE];
    prefix.copy_from_slice(&decoded);

    let header = parse_header_bytes(&prefix, expected_type)?;
    Ok((prefix, header))
}

/// Parses the decoded 8-byte prefix into a `FileHeader`.
/// Validates magic byte and type. Does NOT enforce version or flags policy —
/// callers dispatch on `header.major`.
fn parse_header_bytes(
    prefix: &[u8; HEADER_PREFIX_SIZE],
    expected_type: u8,
) -> Result<FileHeader, CryptoError> {
    if prefix[0] != MAGIC_BYTE {
        return Err(CryptoError::InvalidFormat(
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
        return Err(CryptoError::InvalidFormat(format!(
            "Expected {} format, but file has a different format type",
            expected
        )));
    }

    Ok(FileHeader {
        format_type: prefix[1],
        major: prefix[2],
        minor: prefix[3],
        flags: u16::from_be_bytes([prefix[4], prefix[5]]),
        ext_len: u16::from_be_bytes([prefix[6], prefix[7]]),
    })
}

pub fn validate_file_flags(header: &FileHeader) -> Result<(), CryptoError> {
    if header.flags != 0 {
        return Err(CryptoError::InvalidFormat(format!(
            "Unknown header flags (0x{:04X}). Upgrade FerroCrypt.",
            header.flags
        )));
    }
    Ok(())
}

pub fn unsupported_file_version_error(major: u8, minor: u8, expected_major: u8) -> CryptoError {
    if major < expected_major {
        CryptoError::UnsupportedVersion(format!(
            "Older file format (v{}.{}). Use a previous release.",
            major, minor
        ))
    } else {
        CryptoError::UnsupportedVersion(format!(
            "Newer file format (v{}.{}). Upgrade FerroCrypt.",
            major, minor
        ))
    }
}

pub fn unsupported_key_version_error(version: u8) -> CryptoError {
    if version < KEY_FILE_VERSION {
        CryptoError::UnsupportedVersion(format!(
            "Older key format (v{}). Use a previous release.",
            version
        ))
    } else {
        CryptoError::UnsupportedVersion(format!(
            "Newer key format (v{}). Upgrade FerroCrypt.",
            version
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
pub const KEY_FILE_VERSION: u8 = 3;
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
pub fn parse_key_file_header(data: &[u8], expected_type: u8) -> Result<KeyFileHeader, CryptoError> {
    if data.len() < KEY_FILE_HEADER_SIZE {
        return Err(CryptoError::InvalidFormat(
            "Key file is too short or corrupted".to_string(),
        ));
    }
    if data[0] != MAGIC_BYTE {
        return Err(CryptoError::InvalidFormat(
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
        return Err(CryptoError::InvalidFormat(format!(
            "Expected a {expected} key file but got a {actual} key file"
        )));
    }
    Ok(KeyFileHeader {
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
    header: &KeyFileHeader,
    expected_data_size: usize,
) -> Result<(), CryptoError> {
    if header.algorithm != KEY_FILE_ALG_X25519 {
        return Err(CryptoError::InvalidFormat(format!(
            "Key file algorithm {} not supported",
            header.algorithm
        )));
    }
    if header.data_len as usize != expected_data_size {
        return Err(CryptoError::InvalidFormat(format!(
            "Key file has unexpected data length ({}, expected {})",
            header.data_len, expected_data_size
        )));
    }
    if header.flags != 0 {
        return Err(CryptoError::InvalidFormat(format!(
            "Unknown key file flags (0x{:04X}). Upgrade FerroCrypt.",
            header.flags
        )));
    }
    if data.len() != KEY_FILE_HEADER_SIZE + expected_data_size {
        return Err(CryptoError::InvalidFormat(format!(
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

    #[test]
    fn prefix_round_trip_ext_len_zero() {
        let prefix = build_header_prefix(TYPE_SYMMETRIC, VERSION_MAJOR, 0, 0);
        let header = parse_header_bytes(&prefix, TYPE_SYMMETRIC).unwrap();
        assert_eq!(header.format_type, TYPE_SYMMETRIC);
        assert_eq!(header.major, VERSION_MAJOR);
        assert_eq!(header.minor, VERSION_MINOR);
        assert_eq!(header.flags, 0);
        assert_eq!(header.ext_len, 0);
    }

    #[test]
    fn prefix_round_trip_nonzero_ext_len() {
        let prefix = build_header_prefix(TYPE_HYBRID, HYBRID_VERSION_MAJOR, 0, 0x1234);
        let header = parse_header_bytes(&prefix, TYPE_HYBRID).unwrap();
        assert_eq!(header.format_type, TYPE_HYBRID);
        assert_eq!(header.ext_len, 0x1234);
    }

    #[test]
    fn prefix_rejects_wrong_magic() {
        let mut prefix = build_header_prefix(TYPE_SYMMETRIC, VERSION_MAJOR, 0, 0);
        prefix[0] = 0x00;
        assert!(parse_header_bytes(&prefix, TYPE_SYMMETRIC).is_err());
    }

    #[test]
    fn prefix_rejects_wrong_type() {
        let prefix = build_header_prefix(TYPE_SYMMETRIC, VERSION_MAJOR, 0, 0);
        assert!(parse_header_bytes(&prefix, TYPE_HYBRID).is_err());
    }

    /// Wire-format regression: prefix byte offsets are part of the on-disk
    /// contract. Reordering them is a breaking change that must be noticed
    /// immediately rather than caught by downstream HMAC failures.
    #[test]
    fn prefix_wire_format_offsets() {
        let prefix = build_header_prefix(TYPE_SYMMETRIC, VERSION_MAJOR, 0x1234, 0x5678);
        assert_eq!(prefix[0], MAGIC_BYTE);
        assert_eq!(prefix[1], TYPE_SYMMETRIC);
        assert_eq!(prefix[2], VERSION_MAJOR);
        assert_eq!(prefix[3], VERSION_MINOR);
        assert_eq!(prefix[4], 0x12);
        assert_eq!(prefix[5], 0x34);
        assert_eq!(prefix[6], 0x56);
        assert_eq!(prefix[7], 0x78);
    }
}
