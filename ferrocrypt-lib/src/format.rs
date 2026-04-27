//! FerroCrypt on-disk format v1.
//!
//! Normative spec: `ferrocrypt-lib/FORMAT.md`.
//!
//! ## `.fcr` wire format
//!
//! ```text
//! [prefix (12 bytes)]                  -- magic|version|kind|prefix_flags|header_len
//! [header (header_len bytes)]          -- header_fixed|recipient_entries|ext_bytes
//! [header_mac (32 bytes)]              -- HMAC-SHA3-256(header_key, prefix || header)
//! [payload]                            -- XChaCha20-Poly1305 STREAM-BE32
//! ```
//!
//! ## Prefix (12 bytes, plain at offset 0)
//!
//! | Offset | Size | Field          | Value / meaning                   |
//! |-------:|-----:|----------------|-----------------------------------|
//! | 0–3    | 4    | `magic`        | `"FCR\0"` = `0x46 0x43 0x52 0x00` |
//! | 4      | 1    | `version`      | `0x01`                            |
//! | 5      | 1    | `kind`         | `0x45 'E'` for `.fcr`             |
//! | 6–7    | 2    | `prefix_flags` | `u16 BE`; MUST be zero            |
//! | 8–11   | 4    | `header_len`   | `u32 BE`; ≤ 16,777,216            |
//!
//! Per `FORMAT.md` §3.1, the prefix is plain (no replication) and is
//! authenticated as part of the header MAC input. Failures (bad magic,
//! unsupported version, wrong kind, non-zero prefix flags, oversized
//! header_len) are rejected before any cryptographic operation runs.
//!
//! ## `header_fixed` (31 bytes)
//!
//! | Offset | Size | Field                   | Meaning                  |
//! |-------:|-----:|-------------------------|--------------------------|
//! | 0–1    | 2    | `header_flags`          | `u16 BE`; MUST be zero   |
//! | 2–3    | 2    | `recipient_count`       | `u16 BE`; 1..=4096       |
//! | 4–7    | 4    | `recipient_entries_len` | `u32 BE`                 |
//! | 8–11   | 4    | `ext_len`               | `u32 BE`; ≤ 65,536       |
//! | 12–30  | 19   | `stream_nonce`          | payload STREAM base nonce |

use std::io::Read;

use crate::CryptoError;
use crate::common::{
    HMAC_KEY_SIZE, HMAC_TAG_SIZE, hmac_sha3_256_parts, hmac_sha3_256_parts_verify,
};
use crate::error::{FormatDefect, UnsupportedVersion};

// ─── Shared constants ──────────────────────────────────────────────────────

/// 4-byte ASCII magic identifying every FerroCrypt v1 artefact.
pub const MAGIC: [u8; 4] = [b'F', b'C', b'R', 0];

/// Length of [`MAGIC`] in bytes (`4`).
pub const MAGIC_SIZE: usize = MAGIC.len();

/// Version byte for both `.fcr` and `private.key` artefacts.
pub const VERSION: u8 = 0x01;

/// `.fcr` encrypted-file kind byte (`Kind::Encrypted` on the wire).
pub const KIND_ENCRYPTED: u8 = 0x45; // 'E'
/// `private.key` kind byte (`Kind::PrivateKey` on the wire).
pub const KIND_PRIVATE_KEY: u8 = 0x4B; // 'K'

/// Default file extension for encrypted FerroCrypt payload files.
pub const ENCRYPTED_EXTENSION: &str = "fcr";

// ─── Encrypted file format (.fcr) — v1 ─────────────────────────────────────

/// Plain 12-byte prefix at file offset 0 (no replication, no padding).
pub const PREFIX_SIZE: usize = 12;

/// Maximum `header_len` accepted by readers (structural limit per
/// `FORMAT.md` §3.1).
pub const HEADER_LEN_MAX: u32 = 16_777_216; // 16 MiB

/// Recommended local cap on `header_len` for untrusted input
/// (`FORMAT.md` §3.2). Implementations MUST allow callers to raise
/// this for specific use cases.
pub const HEADER_LEN_LOCAL_CAP_DEFAULT: u32 = 1_048_576; // 1 MiB

/// `header_fixed` size in bytes (`FORMAT.md` §3.2).
pub const HEADER_FIXED_SIZE: usize = 31;

/// `stream_nonce` size in bytes — stored inside `header_fixed` as the
/// XChaCha20-Poly1305 STREAM base nonce.
pub const STREAM_NONCE_SIZE: usize = 19;

/// Maximum number of recipient entries in a single `.fcr` file
/// (structural limit, `FORMAT.md` §3.2).
pub const RECIPIENT_COUNT_MAX: u16 = 4096;

/// Recommended local cap on `recipient_count` for untrusted input.
pub const RECIPIENT_COUNT_LOCAL_CAP_DEFAULT: u16 = 64;

/// Maximum `ext_len` accepted by readers (`FORMAT.md` §3.2 + §6).
pub const EXT_LEN_MAX: u32 = 65_536;

/// Maximum per-recipient `body_len` (structural limit, `FORMAT.md` §3.3).
pub const BODY_LEN_MAX: u32 = 16_777_216;

/// Recommended local cap on `body_len` for untrusted input.
pub const BODY_LEN_LOCAL_CAP_DEFAULT: u32 = 8_192;

/// Size of the v1 header MAC tag (`HMAC-SHA3-256`), in bytes. Per
/// `FORMAT.md` §3.6, the tag immediately follows `header` and precedes
/// the encrypted payload.
pub const HEADER_MAC_SIZE: usize = HMAC_TAG_SIZE;

// ─── Kind (artefact-type byte) ─────────────────────────────────────────────

/// Strongly typed view of the `kind` byte that distinguishes `.fcr`
/// encrypted files from `private.key` files. Adding a variant here is
/// a deliberate breaking change inside the crate: every `match` on
/// [`Kind`] becomes a compile error until the new variant is handled,
/// which is the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `.fcr` encrypted file. Wire byte: [`KIND_ENCRYPTED`].
    Encrypted,
    /// `private.key` passphrase-wrapped private key. Wire byte:
    /// [`KIND_PRIVATE_KEY`].
    PrivateKey,
}

impl Kind {
    /// Wire-format byte for this variant.
    pub const fn byte(self) -> u8 {
        match self {
            Self::Encrypted => KIND_ENCRYPTED,
            Self::PrivateKey => KIND_PRIVATE_KEY,
        }
    }

    /// Decodes a wire-format `kind` byte. `None` for any byte that is
    /// not a recognised v1 artefact kind; callers surface
    /// [`FormatDefect::WrongKind`] for that case.
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            KIND_ENCRYPTED => Some(Self::Encrypted),
            KIND_PRIVATE_KEY => Some(Self::PrivateKey),
            _ => None,
        }
    }
}

// ─── Prefix ─────────────────────────────────────────────────────────────────

/// Parsed `.fcr` / `private.key` 12-byte prefix. Round-trips through
/// [`Prefix::to_bytes`] and [`Prefix::parse`] are the writer/reader
/// surface; structural validation lives in [`Prefix::validate`] and is
/// called from both sides so the two paths cannot drift.
#[derive(Debug, Clone, Copy)]
pub struct Prefix {
    pub version: u8,
    pub kind: Kind,
    pub prefix_flags: u16,
    pub header_len: u32,
}

impl Prefix {
    /// Constructs the prefix for an encrypted `.fcr` file with the given
    /// `header_len`. Does not validate; use [`Self::build_encrypted`]
    /// for the validate-and-serialise convenience.
    pub const fn for_encrypted(header_len: u32) -> Self {
        Self {
            version: VERSION,
            kind: Kind::Encrypted,
            prefix_flags: 0,
            header_len,
        }
    }

    /// Structural validation shared between writer and reader paths.
    /// Checks the spec rules from `FORMAT.md` §3.1 in spec order:
    /// version → prefix_flags → header_len.
    ///
    /// Magic is implicit (a `Prefix` value cannot exist without it),
    /// and `kind` is type-checked by the [`Kind`] enum, so neither
    /// appears here.
    pub fn validate(&self) -> Result<(), CryptoError> {
        check_version(self.version)?;
        check_prefix_flags(self.prefix_flags)?;
        check_header_len(self.header_len)?;
        Ok(())
    }

    /// Serialises the 12-byte on-disk prefix. Does not validate; call
    /// [`Self::validate`] first if the prefix may have been
    /// constructed with caller-supplied values.
    pub fn to_bytes(self) -> [u8; PREFIX_SIZE] {
        let mut out = [0u8; PREFIX_SIZE];
        out[0..4].copy_from_slice(&MAGIC);
        out[4] = self.version;
        out[5] = self.kind.byte();
        out[6..8].copy_from_slice(&self.prefix_flags.to_be_bytes());
        out[8..PREFIX_SIZE].copy_from_slice(&self.header_len.to_be_bytes());
        out
    }

    /// Parses and structurally validates a 12-byte prefix from disk.
    /// Checks fire in `FORMAT.md` §3.1 spec order: magic → version →
    /// kind → flags → header_len. Failures surface as the precise
    /// structural diagnostic (`BadMagic`, `UnsupportedVersion`,
    /// `WrongKind`, `MalformedHeader`, `OversizedHeader`).
    pub fn parse(bytes: &[u8; PREFIX_SIZE], expected_kind: Kind) -> Result<Self, CryptoError> {
        if bytes[0..4] != MAGIC {
            return Err(CryptoError::InvalidFormat(FormatDefect::BadMagic));
        }
        let version = bytes[4];
        check_version(version)?;
        let kind_byte = bytes[5];
        let kind = match Kind::from_byte(kind_byte) {
            Some(k) if k == expected_kind => k,
            _ => {
                return Err(CryptoError::InvalidFormat(FormatDefect::WrongKind {
                    kind: kind_byte,
                }));
            }
        };
        let prefix_flags = u16::from_be_bytes([bytes[6], bytes[7]]);
        check_prefix_flags(prefix_flags)?;
        let header_len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        check_header_len(header_len)?;
        Ok(Self {
            version,
            kind,
            prefix_flags,
            header_len,
        })
    }

    /// Validates and serialises an encrypted-file prefix in one call.
    /// Convenience for encrypt paths that just need the bytes.
    pub fn build_encrypted(header_len: u32) -> Result<[u8; PREFIX_SIZE], CryptoError> {
        let prefix = Self::for_encrypted(header_len);
        prefix.validate()?;
        Ok(prefix.to_bytes())
    }
}

// Per-field structural checks. Shared by [`Prefix::parse`] (spec-order
// reader path) and [`Prefix::validate`] (writer path / sanity check).

fn check_version(version: u8) -> Result<(), CryptoError> {
    if version != VERSION {
        return Err(unsupported_file_version_error(version));
    }
    Ok(())
}

fn check_prefix_flags(flags: u16) -> Result<(), CryptoError> {
    if flags != 0 {
        return Err(CryptoError::InvalidFormat(FormatDefect::MalformedHeader));
    }
    Ok(())
}

fn check_header_len(header_len: u32) -> Result<(), CryptoError> {
    if header_len > HEADER_LEN_MAX {
        return Err(CryptoError::InvalidFormat(FormatDefect::OversizedHeader {
            header_len,
        }));
    }
    if (header_len as usize) < HEADER_FIXED_SIZE {
        return Err(CryptoError::InvalidFormat(FormatDefect::MalformedHeader));
    }
    Ok(())
}

/// Reads, kind-checks, and structurally validates a 12-byte `.fcr`
/// prefix from a reader. Returns the on-disk bytes (for HMAC input)
/// and the parsed [`Prefix`].
///
/// Per `FORMAT.md` §3.7 step 1–2, this fires before any cryptographic
/// operation runs. `UnexpectedEof` surfaces as
/// [`FormatDefect::Truncated`]; other I/O errors surface as
/// [`CryptoError::Io`] so downstream callers can distinguish "the file
/// is malformed" from "we couldn't read it."
pub fn read_prefix_from_reader(
    reader: &mut impl Read,
    expected_kind: Kind,
) -> Result<([u8; PREFIX_SIZE], Prefix), CryptoError> {
    let mut bytes = [0u8; PREFIX_SIZE];
    reader.read_exact(&mut bytes).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            CryptoError::InvalidFormat(FormatDefect::Truncated)
        } else {
            CryptoError::Io(e)
        }
    })?;
    let prefix = Prefix::parse(&bytes, expected_kind)?;
    Ok((bytes, prefix))
}

// ─── header_fixed ───────────────────────────────────────────────────────────

/// Parsed `header_fixed` (31-byte fixed section at the start of `header`).
#[derive(Debug, Clone, Copy)]
pub struct HeaderFixed {
    pub header_flags: u16,
    pub recipient_count: u16,
    pub recipient_entries_len: u32,
    pub ext_len: u32,
    pub stream_nonce: [u8; STREAM_NONCE_SIZE],
}

impl HeaderFixed {
    /// Serialises the 31-byte fixed-header section.
    pub fn to_bytes(self) -> [u8; HEADER_FIXED_SIZE] {
        let mut out = [0u8; HEADER_FIXED_SIZE];
        out[0..2].copy_from_slice(&self.header_flags.to_be_bytes());
        out[2..4].copy_from_slice(&self.recipient_count.to_be_bytes());
        out[4..8].copy_from_slice(&self.recipient_entries_len.to_be_bytes());
        out[8..12].copy_from_slice(&self.ext_len.to_be_bytes());
        out[12..HEADER_FIXED_SIZE].copy_from_slice(&self.stream_nonce);
        out
    }

    /// Parses and validates a 31-byte `header_fixed`.
    ///
    /// Validates per `FORMAT.md` §3.2 structural limits:
    /// - `header_flags == 0`;
    /// - `1 <= recipient_count <= RECIPIENT_COUNT_MAX`;
    /// - `ext_len <= EXT_LEN_MAX`;
    /// - `recipient_entries_len + ext_len + HEADER_FIXED_SIZE == header_len`.
    pub fn parse(bytes: &[u8; HEADER_FIXED_SIZE], header_len: u32) -> Result<Self, CryptoError> {
        let header_flags = u16::from_be_bytes([bytes[0], bytes[1]]);
        if header_flags != 0 {
            return Err(CryptoError::InvalidFormat(FormatDefect::MalformedHeader));
        }
        let recipient_count = u16::from_be_bytes([bytes[2], bytes[3]]);
        if recipient_count == 0 || recipient_count > RECIPIENT_COUNT_MAX {
            return Err(CryptoError::InvalidFormat(
                FormatDefect::RecipientCountOutOfRange {
                    count: recipient_count,
                },
            ));
        }
        let recipient_entries_len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let ext_len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if ext_len > EXT_LEN_MAX {
            return Err(CryptoError::InvalidFormat(FormatDefect::MalformedHeader));
        }
        // Overflow-safe arithmetic per `FORMAT.md` §1 conventions.
        let computed = (HEADER_FIXED_SIZE as u64)
            .checked_add(recipient_entries_len as u64)
            .and_then(|v| v.checked_add(ext_len as u64))
            .ok_or(CryptoError::InvalidFormat(FormatDefect::MalformedHeader))?;
        if computed != header_len as u64 {
            return Err(CryptoError::InvalidFormat(FormatDefect::MalformedHeader));
        }
        let mut stream_nonce = [0u8; STREAM_NONCE_SIZE];
        stream_nonce.copy_from_slice(&bytes[12..HEADER_FIXED_SIZE]);
        Ok(Self {
            header_flags,
            recipient_count,
            recipient_entries_len,
            ext_len,
            stream_nonce,
        })
    }
}

// ─── Header MAC ─────────────────────────────────────────────────────────────

/// Computes the v1 `header_mac` over `prefix(12) || header(header_len)`
/// as defined in `FORMAT.md` §3.6. Inputs are streamed through HMAC
/// without a concatenated copy, so a 16 MiB header does not allocate.
///
/// The MAC scope binds the prefix bytes (including `magic`, `version`,
/// `kind`, `prefix_flags`, `header_len`), the entire `header` region
/// (including `header_flags`, `recipient_count`, `recipient_entries_len`,
/// `ext_len`, `stream_nonce`, the on-wire recipient list in
/// declared order, and `ext_bytes`), but excludes both the MAC tag
/// itself and the encrypted payload.
pub fn compute_header_mac(
    prefix_bytes: &[u8; PREFIX_SIZE],
    header_bytes: &[u8],
    header_key: &[u8; HMAC_KEY_SIZE],
) -> Result<[u8; HEADER_MAC_SIZE], CryptoError> {
    hmac_sha3_256_parts(header_key, &[prefix_bytes, header_bytes])
}

/// Constant-time verification of a v1 `header_mac` over `prefix(12) ||
/// header(header_len)`. See [`compute_header_mac`] for the MAC scope.
///
/// Returns [`CryptoError::HeaderTampered`] on tag mismatch. In a
/// multi-recipient decrypt loop, callers map the failure to the
/// per-candidate "wrong recipient slot" diagnostic before continuing
/// iteration; the bare `HeaderTampered` is correct only when no further
/// recipient slot remains to try.
pub fn verify_header_mac(
    prefix_bytes: &[u8; PREFIX_SIZE],
    header_bytes: &[u8],
    header_key: &[u8; HMAC_KEY_SIZE],
    tag: &[u8; HEADER_MAC_SIZE],
) -> Result<(), CryptoError> {
    hmac_sha3_256_parts_verify(header_key, &[prefix_bytes, header_bytes], tag)
}

// ─── Errors ─────────────────────────────────────────────────────────────────

/// Classifies a rejected `.fcr` version as older-than or newer-than the
/// version this release supports.
pub fn unsupported_file_version_error(version: u8) -> CryptoError {
    if version < VERSION {
        CryptoError::UnsupportedVersion(UnsupportedVersion::OlderFile { version })
    } else {
        CryptoError::UnsupportedVersion(UnsupportedVersion::NewerFile { version })
    }
}

/// Classifies a rejected key-file version as older-than or newer-than
/// the version this release supports.
pub fn unsupported_key_version_error(version: u8) -> CryptoError {
    if version < VERSION {
        CryptoError::UnsupportedVersion(UnsupportedVersion::OlderKey { version })
    } else {
        CryptoError::UnsupportedVersion(UnsupportedVersion::NewerKey { version })
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_round_trips_through_byte() {
        for variant in [Kind::Encrypted, Kind::PrivateKey] {
            assert_eq!(Kind::from_byte(variant.byte()), Some(variant));
        }
        assert_eq!(Kind::Encrypted.byte(), KIND_ENCRYPTED);
        assert_eq!(Kind::PrivateKey.byte(), KIND_PRIVATE_KEY);
    }

    #[test]
    fn kind_from_unknown_byte_returns_none() {
        assert_eq!(Kind::from_byte(0x00), None);
        assert_eq!(Kind::from_byte(0x53), None); // old 'S' (symmetric)
        assert_eq!(Kind::from_byte(0xFF), None);
    }

    #[test]
    fn prefix_round_trips_for_encrypted_kind() {
        let prefix = Prefix::for_encrypted(200);
        let bytes = prefix.to_bytes();
        let parsed = Prefix::parse(&bytes, Kind::Encrypted).unwrap();
        assert_eq!(parsed.version, VERSION);
        assert_eq!(parsed.kind, Kind::Encrypted);
        assert_eq!(parsed.prefix_flags, 0);
        assert_eq!(parsed.header_len, 200);
    }

    #[test]
    fn prefix_wire_format_has_magic_at_offset_0() {
        let prefix = Prefix {
            header_len: 0xAABBCCDD,
            ..Prefix::for_encrypted(0)
        };
        let bytes = prefix.to_bytes();
        assert_eq!(&bytes[0..4], b"FCR\0");
        assert_eq!(bytes[4], VERSION);
        assert_eq!(bytes[5], KIND_ENCRYPTED);
        assert_eq!(&bytes[6..8], &[0, 0]);
        assert_eq!(&bytes[8..12], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn prefix_rejects_bad_magic() {
        let mut bytes = Prefix::build_encrypted(200).unwrap();
        bytes[0] = 0;
        match Prefix::parse(&bytes, Kind::Encrypted) {
            Err(CryptoError::InvalidFormat(FormatDefect::BadMagic)) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn prefix_rejects_unsupported_version() {
        let mut bytes = Prefix::build_encrypted(200).unwrap();
        bytes[4] = 2;
        match Prefix::parse(&bytes, Kind::Encrypted) {
            Err(CryptoError::UnsupportedVersion(UnsupportedVersion::NewerFile { version: 2 })) => {}
            other => panic!("expected NewerFile(2), got {other:?}"),
        }
    }

    #[test]
    fn prefix_rejects_wrong_kind() {
        let bytes = Prefix::build_encrypted(200).unwrap();
        match Prefix::parse(&bytes, Kind::PrivateKey) {
            Err(CryptoError::InvalidFormat(FormatDefect::WrongKind { kind })) => {
                assert_eq!(kind, KIND_ENCRYPTED);
            }
            other => panic!("expected WrongKind, got {other:?}"),
        }
    }

    #[test]
    fn prefix_rejects_unknown_kind_byte() {
        let mut bytes = Prefix::build_encrypted(200).unwrap();
        bytes[5] = 0x53; // any byte other than KIND_ENCRYPTED / KIND_PRIVATE_KEY
        match Prefix::parse(&bytes, Kind::Encrypted) {
            Err(CryptoError::InvalidFormat(FormatDefect::WrongKind { kind })) => {
                assert_eq!(kind, 0x53);
            }
            other => panic!("expected WrongKind, got {other:?}"),
        }
    }

    #[test]
    fn prefix_rejects_non_zero_flags() {
        let mut bytes = Prefix::build_encrypted(200).unwrap();
        bytes[6] = 1;
        match Prefix::parse(&bytes, Kind::Encrypted) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedHeader)) => {}
            other => panic!("expected MalformedHeader, got {other:?}"),
        }
    }

    #[test]
    fn prefix_rejects_oversized_header_len_at_parse() {
        let oversized = Prefix {
            header_len: HEADER_LEN_MAX + 1,
            ..Prefix::for_encrypted(0)
        };
        // Bypass build_encrypted's validation so we can test the parse path.
        let bytes = oversized.to_bytes();
        match Prefix::parse(&bytes, Kind::Encrypted) {
            Err(CryptoError::InvalidFormat(FormatDefect::OversizedHeader { header_len })) => {
                assert_eq!(header_len, HEADER_LEN_MAX + 1);
            }
            other => panic!("expected OversizedHeader, got {other:?}"),
        }
    }

    #[test]
    fn build_encrypted_rejects_oversized_header_len() {
        match Prefix::build_encrypted(HEADER_LEN_MAX + 1) {
            Err(CryptoError::InvalidFormat(FormatDefect::OversizedHeader { header_len })) => {
                assert_eq!(header_len, HEADER_LEN_MAX + 1);
            }
            other => panic!("expected OversizedHeader from writer side, got {other:?}"),
        }
    }

    #[test]
    fn build_encrypted_rejects_undersized_header_len() {
        match Prefix::build_encrypted((HEADER_FIXED_SIZE as u32) - 1) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedHeader)) => {}
            other => panic!("expected MalformedHeader from writer side, got {other:?}"),
        }
    }

    #[test]
    fn prefix_rejects_header_len_below_header_fixed_size() {
        let too_small = Prefix {
            header_len: (HEADER_FIXED_SIZE as u32) - 1,
            ..Prefix::for_encrypted(0)
        };
        let bytes = too_small.to_bytes();
        match Prefix::parse(&bytes, Kind::Encrypted) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedHeader)) => {}
            other => panic!("expected MalformedHeader, got {other:?}"),
        }
    }

    #[test]
    fn build_encrypted_accepts_header_len_at_lower_boundary() {
        let bytes = Prefix::build_encrypted(HEADER_FIXED_SIZE as u32).unwrap();
        let parsed = Prefix::parse(&bytes, Kind::Encrypted).unwrap();
        assert_eq!(parsed.header_len, HEADER_FIXED_SIZE as u32);
    }

    #[test]
    fn build_encrypted_accepts_header_len_at_upper_boundary() {
        let bytes = Prefix::build_encrypted(HEADER_LEN_MAX).unwrap();
        let parsed = Prefix::parse(&bytes, Kind::Encrypted).unwrap();
        assert_eq!(parsed.header_len, HEADER_LEN_MAX);
    }

    #[test]
    fn parse_prefers_unsupported_version_over_wrong_kind() {
        // Spec UX preference: when both version and kind are wrong,
        // surface UnsupportedVersion (actionable: "upgrade FerroCrypt")
        // rather than WrongKind (which would imply a known v1 kind).
        let mut bytes = Prefix::build_encrypted(HEADER_FIXED_SIZE as u32).unwrap();
        bytes[4] = 2; // future version
        bytes[5] = 0x99; // unknown kind
        match Prefix::parse(&bytes, Kind::Encrypted) {
            Err(CryptoError::UnsupportedVersion(UnsupportedVersion::NewerFile { version: 2 })) => {}
            other => panic!("expected NewerFile(2) before WrongKind, got {other:?}"),
        }
    }

    #[test]
    fn header_fixed_round_trips() {
        let hf = HeaderFixed {
            header_flags: 0,
            recipient_count: 1,
            recipient_entries_len: 100,
            ext_len: 0,
            stream_nonce: [0xAB; STREAM_NONCE_SIZE],
        };
        let bytes = hf.to_bytes();
        let parsed = HeaderFixed::parse(&bytes, HEADER_FIXED_SIZE as u32 + 100).unwrap();
        assert_eq!(parsed.header_flags, 0);
        assert_eq!(parsed.recipient_count, 1);
        assert_eq!(parsed.recipient_entries_len, 100);
        assert_eq!(parsed.ext_len, 0);
        assert_eq!(parsed.stream_nonce, [0xAB; STREAM_NONCE_SIZE]);
    }

    #[test]
    fn header_fixed_rejects_non_zero_flags() {
        let hf = HeaderFixed {
            header_flags: 0x0001,
            recipient_count: 1,
            recipient_entries_len: 100,
            ext_len: 0,
            stream_nonce: [0; STREAM_NONCE_SIZE],
        };
        match HeaderFixed::parse(&hf.to_bytes(), HEADER_FIXED_SIZE as u32 + 100) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedHeader)) => {}
            other => panic!("expected MalformedHeader, got {other:?}"),
        }
    }

    #[test]
    fn header_fixed_rejects_zero_recipient_count() {
        let hf = HeaderFixed {
            header_flags: 0,
            recipient_count: 0,
            recipient_entries_len: 100,
            ext_len: 0,
            stream_nonce: [0; STREAM_NONCE_SIZE],
        };
        match HeaderFixed::parse(&hf.to_bytes(), HEADER_FIXED_SIZE as u32 + 100) {
            Err(CryptoError::InvalidFormat(FormatDefect::RecipientCountOutOfRange {
                count: 0,
            })) => {}
            other => panic!("expected RecipientCountOutOfRange(0), got {other:?}"),
        }
    }

    #[test]
    fn header_fixed_rejects_excessive_recipient_count() {
        let hf = HeaderFixed {
            header_flags: 0,
            recipient_count: RECIPIENT_COUNT_MAX + 1,
            recipient_entries_len: 100,
            ext_len: 0,
            stream_nonce: [0; STREAM_NONCE_SIZE],
        };
        let expected = RECIPIENT_COUNT_MAX + 1;
        match HeaderFixed::parse(&hf.to_bytes(), HEADER_FIXED_SIZE as u32 + 100) {
            Err(CryptoError::InvalidFormat(FormatDefect::RecipientCountOutOfRange { count }))
                if count == expected => {}
            other => panic!("expected RecipientCountOutOfRange({expected}), got {other:?}"),
        }
    }

    #[test]
    fn header_fixed_rejects_oversized_ext_len() {
        let hf = HeaderFixed {
            header_flags: 0,
            recipient_count: 1,
            recipient_entries_len: 100,
            ext_len: EXT_LEN_MAX + 1,
            stream_nonce: [0; STREAM_NONCE_SIZE],
        };
        let total = HEADER_FIXED_SIZE as u32 + 100 + (EXT_LEN_MAX + 1);
        match HeaderFixed::parse(&hf.to_bytes(), total) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedHeader)) => {}
            other => panic!("expected MalformedHeader, got {other:?}"),
        }
    }

    #[test]
    fn header_fixed_accepts_recipient_count_at_upper_boundary() {
        let hf = HeaderFixed {
            header_flags: 0,
            recipient_count: RECIPIENT_COUNT_MAX,
            recipient_entries_len: 100,
            ext_len: 0,
            stream_nonce: [0; STREAM_NONCE_SIZE],
        };
        let parsed = HeaderFixed::parse(&hf.to_bytes(), HEADER_FIXED_SIZE as u32 + 100).unwrap();
        assert_eq!(parsed.recipient_count, RECIPIENT_COUNT_MAX);
    }

    #[test]
    fn header_fixed_accepts_ext_len_at_upper_boundary() {
        let hf = HeaderFixed {
            header_flags: 0,
            recipient_count: 1,
            recipient_entries_len: 0,
            ext_len: EXT_LEN_MAX,
            stream_nonce: [0; STREAM_NONCE_SIZE],
        };
        let total = HEADER_FIXED_SIZE as u32 + EXT_LEN_MAX;
        let parsed = HeaderFixed::parse(&hf.to_bytes(), total).unwrap();
        assert_eq!(parsed.ext_len, EXT_LEN_MAX);
    }

    #[test]
    fn read_prefix_distinguishes_eof_as_truncated() {
        // Short read (only 5 bytes) → UnexpectedEof from read_exact →
        // Truncated diagnostic.
        let truncated: &[u8] = &[b'F', b'C', b'R', 0, VERSION];
        let mut cur = std::io::Cursor::new(truncated);
        match read_prefix_from_reader(&mut cur, Kind::Encrypted) {
            Err(CryptoError::InvalidFormat(FormatDefect::Truncated)) => {}
            other => panic!("expected Truncated for short read, got {other:?}"),
        }
    }

    #[test]
    fn read_prefix_propagates_non_eof_io_errors() {
        // A reader that returns PermissionDenied (or any non-EOF
        // io::Error) must surface as `CryptoError::Io`, not as
        // `Truncated`. Regression guard: an earlier version mapped
        // every io::Error to Truncated, which masked real I/O failures.
        struct PermissionDenied;
        impl std::io::Read for PermissionDenied {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "test",
                ))
            }
        }
        let mut reader = PermissionDenied;
        match read_prefix_from_reader(&mut reader, Kind::Encrypted) {
            Err(CryptoError::Io(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected Io(PermissionDenied), got {other:?}"),
        }
    }

    #[test]
    fn prefix_rejects_older_version_with_older_file_diagnostic() {
        let mut bytes = Prefix::build_encrypted(HEADER_FIXED_SIZE as u32).unwrap();
        bytes[4] = 0;
        match Prefix::parse(&bytes, Kind::Encrypted) {
            Err(CryptoError::UnsupportedVersion(UnsupportedVersion::OlderFile { version: 0 })) => {}
            other => panic!("expected OlderFile(0), got {other:?}"),
        }
    }

    #[test]
    fn unsupported_key_version_error_classifies_older_and_newer() {
        // Older-key path (version < VERSION).
        match unsupported_key_version_error(0) {
            CryptoError::UnsupportedVersion(UnsupportedVersion::OlderKey { version: 0 }) => {}
            other => panic!("expected OlderKey(0), got {other:?}"),
        }
        // Newer-key path (version > VERSION).
        match unsupported_key_version_error(2) {
            CryptoError::UnsupportedVersion(UnsupportedVersion::NewerKey { version: 2 }) => {}
            other => panic!("expected NewerKey(2), got {other:?}"),
        }
    }

    #[test]
    fn header_fixed_rejects_inconsistent_lengths() {
        let hf = HeaderFixed {
            header_flags: 0,
            recipient_count: 1,
            recipient_entries_len: 100,
            ext_len: 0,
            stream_nonce: [0; STREAM_NONCE_SIZE],
        };
        // Caller's header_len doesn't match 31 + 100 + 0 = 131.
        match HeaderFixed::parse(&hf.to_bytes(), 200) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedHeader)) => {}
            other => panic!("expected MalformedHeader, got {other:?}"),
        }
    }

    // ─── Header MAC ─────────────────────────────────────────────────────────

    /// Builds a representative `(prefix_bytes, header_bytes, header_key)`
    /// triple for header-MAC tests. The header bytes are arbitrary
    /// stand-ins for `header_fixed || recipient_entries || ext_bytes`;
    /// the MAC primitive is content-agnostic.
    fn header_mac_fixture() -> ([u8; PREFIX_SIZE], Vec<u8>, [u8; HMAC_KEY_SIZE]) {
        let prefix = Prefix::build_encrypted(200).unwrap();
        let header = vec![0xCDu8; 200];
        let key = [0xABu8; HMAC_KEY_SIZE];
        (prefix, header, key)
    }

    #[test]
    fn header_mac_round_trips() {
        let (prefix, header, key) = header_mac_fixture();
        let tag = compute_header_mac(&prefix, &header, &key).unwrap();
        verify_header_mac(&prefix, &header, &key, &tag).unwrap();
    }

    #[test]
    fn header_mac_is_deterministic() {
        let (prefix, header, key) = header_mac_fixture();
        let a = compute_header_mac(&prefix, &header, &key).unwrap();
        let b = compute_header_mac(&prefix, &header, &key).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn header_mac_rejects_tampered_prefix() {
        let (mut prefix, header, key) = header_mac_fixture();
        let tag = compute_header_mac(&prefix, &header, &key).unwrap();
        prefix[8] ^= 0x01;
        match verify_header_mac(&prefix, &header, &key, &tag) {
            Err(CryptoError::HeaderTampered) => {}
            other => panic!("expected HeaderTampered for prefix tamper, got {other:?}"),
        }
    }

    #[test]
    fn header_mac_rejects_tampered_header() {
        let (prefix, mut header, key) = header_mac_fixture();
        let tag = compute_header_mac(&prefix, &header, &key).unwrap();
        header[10] ^= 0x01;
        match verify_header_mac(&prefix, &header, &key, &tag) {
            Err(CryptoError::HeaderTampered) => {}
            other => panic!("expected HeaderTampered for header tamper, got {other:?}"),
        }
    }

    #[test]
    fn header_mac_rejects_tampered_tag() {
        let (prefix, header, key) = header_mac_fixture();
        let mut tag = compute_header_mac(&prefix, &header, &key).unwrap();
        tag[0] ^= 0x01;
        match verify_header_mac(&prefix, &header, &key, &tag) {
            Err(CryptoError::HeaderTampered) => {}
            other => panic!("expected HeaderTampered for tag tamper, got {other:?}"),
        }
    }

    #[test]
    fn header_mac_rejects_wrong_key() {
        let (prefix, header, key) = header_mac_fixture();
        let tag = compute_header_mac(&prefix, &header, &key).unwrap();
        let mut other_key = key;
        other_key[0] ^= 0x01;
        match verify_header_mac(&prefix, &header, &other_key, &tag) {
            Err(CryptoError::HeaderTampered) => {}
            other => panic!("expected HeaderTampered for wrong key, got {other:?}"),
        }
    }

    #[test]
    fn header_mac_input_is_prefix_then_header_in_order() {
        // Splitting the same bytes differently between prefix and header
        // would change the meaning. Prefix is fixed at 12 bytes; header
        // is everything else. Here we verify that swapping any portion
        // of prefix/header (a content move that an attacker could try
        // to argue is "equivalent") changes the MAC.
        let (prefix, header, key) = header_mac_fixture();
        let tag = compute_header_mac(&prefix, &header, &key).unwrap();
        // Swap two bytes between prefix and header.
        let mut swapped_prefix = prefix;
        let mut swapped_header = header.clone();
        std::mem::swap(&mut swapped_prefix[0], &mut swapped_header[0]);
        let swapped_tag = compute_header_mac(&swapped_prefix, &swapped_header, &key).unwrap();
        assert_ne!(tag, swapped_tag);
    }

    #[test]
    fn header_mac_binds_recipient_entry_order() {
        // Two distinct entry orderings inside `header` must produce
        // different MACs. This locks in `FORMAT.md` §3.6: reorder
        // attacks invalidate the MAC.
        let prefix = Prefix::build_encrypted(200).unwrap();
        let key = [0x77u8; HMAC_KEY_SIZE];
        let entry_a = [0x11u8; 50];
        let entry_b = [0x22u8; 50];
        let header_ab: Vec<u8> = entry_a.iter().chain(entry_b.iter()).copied().collect();
        let header_ba: Vec<u8> = entry_b.iter().chain(entry_a.iter()).copied().collect();
        let mac_ab = compute_header_mac(&prefix, &header_ab, &key).unwrap();
        let mac_ba = compute_header_mac(&prefix, &header_ba, &key).unwrap();
        assert_ne!(mac_ab, mac_ba);
    }

    #[test]
    fn header_mac_size_matches_hmac_tag_size() {
        assert_eq!(HEADER_MAC_SIZE, HMAC_TAG_SIZE);
        assert_eq!(HEADER_MAC_SIZE, 32);
    }
}
