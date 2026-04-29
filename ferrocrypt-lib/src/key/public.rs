//! v1 public-key encoding (`FORMAT.md` §7).
//!
//! Recipient string Bech32 typed payload:
//!
//! ```text
//! data = type_name_len:u16  || key_material_len:u32
//!     || type_name:N        || key_material:M
//!     || checksum:16
//! ```
//!
//! `checksum = first 16 bytes of`
//! `SHA3-256("ferrocrypt/v1/public-key/checksum" || type_name || 0x00 || key_material)`.
//!
//! The recipient string itself is **strict Bech32 (BIP 173, not
//! Bech32m)** with HRP `"fcr"` and the lowercase data part. Mixed-case
//! input, Bech32m strings, and non-canonical 5-to-8 padding are
//! rejected by the decoder.
//!
//! ## Fingerprints
//!
//! `fingerprint = SHA3-256(type_name || 0x00 || key_material)`. The
//! domain separator `"ferrocrypt/v1/public-key/checksum"` is *not*
//! included in the fingerprint hash so the user-displayed identity is
//! independent of the checksum-domain string. Canonical display is 64
//! lowercase hex chars; short display is the first 16 of those; the
//! grouped form (per `FORMAT.md` §7.2) renders as four-character
//! lowercase hex groups joined by `:` for voice or out-of-band
//! verification.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Checksum, Hrp};
use sha3::{Digest, Sha3_256};

use crate::CryptoError;
use crate::error::FormatDefect;
use crate::format::{read_u16_be, read_u32_be};
use crate::recipient::{TYPE_NAME_MAX_LEN, validate_type_name};

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Bech32 HRP for FerroCrypt recipient strings.
pub const RECIPIENT_HRP: Hrp = Hrp::parse_unchecked("fcr");

/// Domain separator for the internal SHA3-256 recipient-payload
/// checksum. Distinct from any other v1 hash input so a future
/// extension cannot accidentally collide with this digest.
pub const PUBLIC_KEY_CHECKSUM_DOMAIN: &[u8] = b"ferrocrypt/v1/public-key/checksum";

/// Truncated SHA3-256 checksum size in the typed payload, in bytes.
pub const PUBLIC_KEY_CHECKSUM_SIZE: usize = 16;

/// Total size of the typed-payload header (`type_name_len(2) ||
/// key_material_len(4)`), in bytes.
pub const PAYLOAD_HEADER_SIZE: usize = size_of::<u16>() + size_of::<u32>();

const PAYLOAD_TYPE_NAME_LEN_OFFSET: usize = 0;
const PAYLOAD_KEY_MATERIAL_LEN_OFFSET: usize = PAYLOAD_TYPE_NAME_LEN_OFFSET + size_of::<u16>();
const _: () = assert!(PAYLOAD_KEY_MATERIAL_LEN_OFFSET + size_of::<u32>() == PAYLOAD_HEADER_SIZE);

/// Spec maximum for the recipient string length in ASCII characters
/// (`FORMAT.md` §7.1). [`KEY_MATERIAL_LEN_MAX`] derives from this
/// ceiling so the worst-case payload still encodes within it.
pub const RECIPIENT_STRING_LEN_MAX: usize = 20_000;

/// Recommended local cap on recipient-string length for untrusted
/// input. X25519 produces ~106 ASCII chars; 1 KiB leaves headroom for
/// future native key types without forcing every caller to raise the
/// cap.
pub const RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT: usize = 1_024;

/// Bech32 envelope overhead in characters: HRP `"fcr"` (3) +
/// separator `'1'` (1) + 6-char Bech32 checksum.
const RECIPIENT_STRING_OVERHEAD_CHARS: usize = 3 + 1 + 6;

/// Structural maximum for `key_material_len` in the typed payload.
/// Derived from [`RECIPIENT_STRING_LEN_MAX`] so a max-length type_name
/// (255 bytes) plus the largest legal `key_material` still encodes
/// within the spec's 20,000-char ceiling. Shorter type_names leave
/// proportionally more headroom; the decoder accepts any
/// `key_material_len` up to this structural cap regardless of the
/// particular type_name length in the payload.
pub const KEY_MATERIAL_LEN_MAX: u32 = max_key_material_len();

const fn max_key_material_len() -> u32 {
    // Each Bech32 data char encodes 5 bits.
    let data_chars = RECIPIENT_STRING_LEN_MAX - RECIPIENT_STRING_OVERHEAD_CHARS;
    let max_data_bytes = data_chars * 5 / 8;
    let max_payload =
        max_data_bytes - PAYLOAD_HEADER_SIZE - PUBLIC_KEY_CHECKSUM_SIZE - TYPE_NAME_MAX_LEN;
    max_payload as u32
}

/// BIP 173 Bech32 with v1's lifted code-length cap. The crate's
/// built-in [`bech32::Bech32`] type fixes `CODE_LENGTH = 1023`, below
/// v1's 20,000-char spec ceiling and below the largest payload that
/// [`KEY_MATERIAL_LEN_MAX`] permits. We forward every other Checksum
/// constant from `bech32::Bech32` so the on-the-wire checksum
/// polynomial is byte-identical to BIP 173; only the length tolerance
/// differs.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Bech32V1 {}

impl Checksum for Bech32V1 {
    type MidstateRepr = <Bech32 as Checksum>::MidstateRepr;
    const CHECKSUM_LENGTH: usize = <Bech32 as Checksum>::CHECKSUM_LENGTH;
    const CODE_LENGTH: usize = RECIPIENT_STRING_LEN_MAX;
    const GENERATOR_SH: [Self::MidstateRepr; 5] = <Bech32 as Checksum>::GENERATOR_SH;
    const TARGET_RESIDUE: Self::MidstateRepr = <Bech32 as Checksum>::TARGET_RESIDUE;
}

/// Decoded payload of a recipient string. Owned values so the caller
/// can route them independently of the input string's lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRecipient {
    pub type_name: String,
    pub key_material: Vec<u8>,
}

/// Encodes a public-key recipient string in canonical lowercase
/// Bech32 (BIP 173). Validates `type_name` against the §3.3 grammar
/// and computes the internal SHA3-256 checksum so a corrupt copy fails
/// closed at the decoder.
pub fn encode_recipient_string(
    type_name: &str,
    key_material: &[u8],
) -> Result<String, CryptoError> {
    validate_type_name(type_name)?;
    let type_name_bytes = type_name.as_bytes();
    let type_name_len = u16::try_from(type_name_bytes.len())
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedTypeName))?;
    let key_material_len = u32::try_from(key_material.len()).map_err(|_| malformed_public_key())?;
    check_key_material_len(key_material_len)?;

    let cs = compute_checksum(type_name, key_material);

    let total_data =
        PAYLOAD_HEADER_SIZE + type_name_bytes.len() + key_material.len() + PUBLIC_KEY_CHECKSUM_SIZE;
    let mut data = Vec::with_capacity(total_data);
    data.extend_from_slice(&type_name_len.to_be_bytes());
    data.extend_from_slice(&key_material_len.to_be_bytes());
    data.extend_from_slice(type_name_bytes);
    data.extend_from_slice(key_material);
    data.extend_from_slice(&cs);

    bech32::encode::<Bech32V1>(RECIPIENT_HRP, &data)
        .map_err(|_| CryptoError::InternalInvariant("Internal error: Bech32 encode failed"))
}

/// Decodes a canonical lowercase Bech32 recipient string into the
/// typed payload. Validates, in order: input length cap, lowercase
/// grammar, **strict** Bech32 (rejecting Bech32m), HRP equals `"fcr"`,
/// structural length fields, type_name UTF-8 + grammar, and the
/// internal SHA3-256 checksum.
///
/// `local_max_chars` caps the input length before any decode work
/// runs. The spec ceiling is [`RECIPIENT_STRING_LEN_MAX`] (20,000);
/// callers SHOULD pass the smaller [`RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT`]
/// for untrusted input unless they have a reason to widen it.
pub fn decode_recipient_string(
    s: &str,
    local_max_chars: usize,
) -> Result<DecodedRecipient, CryptoError> {
    if s.len() > local_max_chars {
        // Saturating cast: pathological gigabyte-plus inputs report
        // `u32::MAX` for `input_chars`, but the cap rejection itself
        // is correct (the bare comparison ran on usize).
        return Err(CryptoError::RecipientStringCapExceeded {
            input_chars: u32::try_from(s.len()).unwrap_or(u32::MAX),
            local_cap: u32::try_from(local_max_chars).unwrap_or(u32::MAX),
        });
    }
    if s.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(CryptoError::InvalidInput(
            "Recipient string must be lowercase".to_string(),
        ));
    }

    // Strict Bech32 (BIP 173 polynomial via `Bech32V1`, which also
    // accepts strings up to v1's 20 000-char spec cap rather than the
    // crate's default 1023). `CheckedHrpstring` rejects Bech32m
    // strings, mixed case, and non-canonical 5-to-8 padding.
    let checked = CheckedHrpstring::new::<Bech32V1>(s)
        .map_err(|_| CryptoError::InvalidInput(format!("Invalid recipient string: {s}")))?;
    let hrp = checked.hrp();
    if hrp != RECIPIENT_HRP {
        return Err(CryptoError::InvalidInput(format!(
            "Unexpected recipient prefix (want '{}', got '{}')",
            RECIPIENT_HRP.as_str(),
            hrp.as_str()
        )));
    }
    let data: Vec<u8> = checked.byte_iter().collect();

    check_payload_data_len(data.len())?;

    let type_name_len = read_u16_be(&data, PAYLOAD_TYPE_NAME_LEN_OFFSET);
    check_type_name_len(type_name_len)?;
    let key_material_len = read_u32_be(&data, PAYLOAD_KEY_MATERIAL_LEN_OFFSET);
    check_key_material_len(key_material_len)?;
    check_total_payload_size(data.len(), type_name_len, key_material_len)?;

    let type_name_start = PAYLOAD_HEADER_SIZE;
    let type_name_end = type_name_start + type_name_len as usize;
    let key_material_end = type_name_end + key_material_len as usize;
    let checksum_end = key_material_end + PUBLIC_KEY_CHECKSUM_SIZE;

    let type_name_bytes = &data[type_name_start..type_name_end];
    let type_name = std::str::from_utf8(type_name_bytes)
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedTypeName))?;
    validate_type_name(type_name)?;

    let key_material = data[type_name_end..key_material_end].to_vec();
    let stored_checksum = &data[key_material_end..checksum_end];

    let computed_checksum = compute_checksum(type_name, &key_material);
    // The recipient string is public, the checksum is for typo
    // detection rather than secret-comparison; ordinary `!=` is fine
    // and timing-safety is not required here.
    if stored_checksum != computed_checksum {
        return Err(malformed_public_key());
    }

    Ok(DecodedRecipient {
        type_name: type_name.to_owned(),
        key_material,
    })
}

// Per-field structural checks. `check_key_material_len` is shared by
// `encode_recipient_string` (writer) and `decode_recipient_string` (reader)
// so the cap rule cannot drift between the two paths. The remaining checks
// are reader-only because the writer constructs validated lengths directly
// from caller-supplied byte slices.

fn check_payload_data_len(data_len: usize) -> Result<(), CryptoError> {
    if data_len < PAYLOAD_HEADER_SIZE + PUBLIC_KEY_CHECKSUM_SIZE {
        return Err(malformed_public_key());
    }
    Ok(())
}

fn check_type_name_len(len: u16) -> Result<(), CryptoError> {
    if len == 0 || (len as usize) > TYPE_NAME_MAX_LEN {
        return Err(malformed_public_key());
    }
    Ok(())
}

fn check_key_material_len(len: u32) -> Result<(), CryptoError> {
    if len > KEY_MATERIAL_LEN_MAX {
        return Err(malformed_public_key());
    }
    Ok(())
}

// Overflow-safe arithmetic: every length comes from untrusted bytes, so
// the four-term sum is widened/checked before comparison. Mirrors the
// `format::HeaderFixed::check_header_section_lengths` pattern.
fn check_total_payload_size(
    data_len: usize,
    type_name_len: u16,
    key_material_len: u32,
) -> Result<(), CryptoError> {
    let total_expected = PAYLOAD_HEADER_SIZE
        .checked_add(type_name_len as usize)
        .and_then(|v| v.checked_add(key_material_len as usize))
        .and_then(|v| v.checked_add(PUBLIC_KEY_CHECKSUM_SIZE))
        .ok_or_else(malformed_public_key)?;
    if data_len != total_expected {
        return Err(malformed_public_key());
    }
    Ok(())
}

/// SHA3-256-based internal checksum, truncated to
/// [`PUBLIC_KEY_CHECKSUM_SIZE`] bytes. Detects typed-payload
/// corruption that the outer Bech32 checksum can't catch (e.g. a
/// hand-edited recipient string with a coincidentally-valid Bech32
/// checksum but mismatched inner data).
fn compute_checksum(type_name: &str, key_material: &[u8]) -> [u8; PUBLIC_KEY_CHECKSUM_SIZE] {
    let full = domain_keyed_hash(PUBLIC_KEY_CHECKSUM_DOMAIN, type_name, key_material);
    let mut truncated = [0u8; PUBLIC_KEY_CHECKSUM_SIZE];
    truncated.copy_from_slice(&full[..PUBLIC_KEY_CHECKSUM_SIZE]);
    truncated
}

/// Canonical SHA3-256 hash of `domain || type_name || 0x00 ||
/// key_material`. Single source of truth for the pre-image shape used
/// by both the recipient-string internal checksum (with
/// [`PUBLIC_KEY_CHECKSUM_DOMAIN`]) and the user-visible fingerprint
/// (with an empty domain). Centralising the structure keeps the two
/// hashes from silently diverging if the pre-image is ever extended.
///
/// `0x00` is unambiguous as a separator because the §3.3 type_name
/// grammar disallows the null byte.
fn domain_keyed_hash(domain: &[u8], type_name: &str, key_material: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update(type_name.as_bytes());
    hasher.update([0x00]);
    hasher.update(key_material);
    hasher.finalize().into()
}

fn malformed_public_key() -> CryptoError {
    CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)
}

// ─── Fingerprint ───────────────────────────────────────────────────────────

/// Canonical fingerprint hash of `type_name || 0x00 || key_material`
/// as a 32-byte SHA3-256 digest. The domain separator used in
/// [`PUBLIC_KEY_CHECKSUM_DOMAIN`] is intentionally absent so the
/// fingerprint is a stable identity over the (type_name, key_material)
/// pair, not over the encoding-checksum domain.
pub fn fingerprint_bytes(type_name: &str, key_material: &[u8]) -> [u8; 32] {
    domain_keyed_hash(b"", type_name, key_material)
}

/// 64-character lowercase hex of [`fingerprint_bytes`].
pub fn fingerprint_hex(type_name: &str, key_material: &[u8]) -> String {
    hex_encode(&fingerprint_bytes(type_name, key_material))
}

// ─── public.key text reader ────────────────────────────────────────────────

/// Reads a v1 `public.key` text file and returns the raw 32-byte
/// X25519 public key. The file content MUST be the canonical
/// lowercase `fcr1…` recipient string, optionally followed by
/// exactly one trailing `\n` (FORMAT.md §7). Anything else
/// — leading whitespace, CRLF line endings, extra blank lines,
/// trailing spaces or tabs, internal whitespace — is rejected as
/// [`FormatDefect::MalformedPublicKey`].
///
/// If the caller accidentally points this at a binary `private.key`
/// (magic `FCR\0`), the reader surfaces
/// [`FormatDefect::WrongKeyFileType`] instead of a cryptic UTF-8
/// decode error.
///
/// Decoding delegates to [`decode_recipient_string`], the single
/// source of truth for the Bech32 grammar, internal SHA3-256
/// checksum, and resource caps.
pub fn read_public_key(path: &std::path::Path) -> Result<[u8; 32], CryptoError> {
    let bytes = std::fs::read(path).map_err(crate::fs::paths::map_user_path_io_error)?;
    if matches!(
        crate::key::files::KeyFileKind::classify(&bytes),
        crate::key::files::KeyFileKind::Private
    ) {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }
    let contents = String::from_utf8(bytes)
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::NotAKeyFile))?;
    // Non-whitespace junk (BOM, ZWSP, non-Bech32 chars) is left for
    // `decode_recipient_string` to reject — a format violation in the
    // whitespace grammar deserves its own bucket.
    let recipient = contents.strip_suffix('\n').unwrap_or(&contents);
    if recipient.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey));
    }
    let decoded = decode_recipient_string(recipient, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT)?;
    if decoded.type_name != crate::recipient::x25519::TYPE_NAME {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }
    decoded
        .key_material
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey))
}

// ─── Public-recipient wrapper ──────────────────────────────────────────────

/// A FerroCrypt X25519 public key.
///
/// Abstracts over the source of the key material: a stored public-key
/// file on disk, raw 32-byte key material, or a decoded Bech32 `fcr1…`
/// recipient string. Filesystem sources defer I/O until the key is
/// actually used, so construction is infallible for the file and bytes
/// variants.
///
/// Once constructed, a `PublicKey` can be:
/// - passed to [`crate::hybrid_encrypt`] via
///   [`crate::HybridEncryptConfig::new`] as the recipient for envelope
///   encryption,
/// - rendered as a Bech32 `fcr1…` recipient string via
///   [`PublicKey::to_recipient_string`],
/// - fingerprinted via [`PublicKey::fingerprint`].
///
/// The struct is `#[non_exhaustive]` so future sources (key servers,
/// hardware-backed keys) can be added without a breaking change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PublicKey {
    source: PublicKeySource,
}

#[derive(Debug, Clone)]
enum PublicKeySource {
    KeyFile(std::path::PathBuf),
    Bytes([u8; 32]),
}

impl PublicKey {
    /// References a FerroCrypt public-key file at the given path. The
    /// file is not opened until a method that needs the key material
    /// (e.g. [`fingerprint`](Self::fingerprint),
    /// [`to_recipient_string`](Self::to_recipient_string)) is called.
    pub fn from_key_file(path: impl AsRef<std::path::Path>) -> Self {
        Self {
            source: PublicKeySource::KeyFile(path.as_ref().to_path_buf()),
        }
    }

    /// Wraps raw 32-byte X25519 public-key material directly.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            source: PublicKeySource::Bytes(bytes),
        }
    }

    /// Decodes a canonical lowercase Bech32 `fcr1…` recipient string
    /// (as produced by [`PublicKey::to_recipient_string`] or the
    /// `ferrocrypt recipient` subcommand) into a `PublicKey`. Validates
    /// HRP, BIP 173 checksum, internal SHA3-256 checksum, payload
    /// structural fields, type-name grammar, and (for v1 X25519
    /// recipients) the recipient `type_name == "x25519"` and 32-byte
    /// key-material length.
    pub fn from_recipient_string(recipient: &str) -> Result<Self, CryptoError> {
        Ok(Self::from_bytes(crate::decode_recipient(recipient)?))
    }

    /// Computes the SHA3-256 fingerprint of the X25519 recipient as a
    /// 64-character lowercase hex string. Domain-separated by the
    /// recipient `type_name` ("x25519") so future native types
    /// (post-quantum, hybrid KEMs, etc.) cannot collide with this
    /// namespace. Output matches `key::public::fingerprint_hex` and the
    /// `ferrocrypt recipient` subcommand.
    pub fn fingerprint(&self) -> Result<String, CryptoError> {
        let bytes = self.resolve()?;
        Ok(fingerprint_hex(crate::recipient::x25519::TYPE_NAME, &bytes))
    }

    /// Encodes the key as the canonical Bech32 `fcr1…` recipient
    /// string. Routes through `key::public::encode_recipient_string`
    /// with the X25519 type name. Performs filesystem I/O for the
    /// key-file source.
    pub fn to_recipient_string(&self) -> Result<String, CryptoError> {
        let bytes = self.resolve()?;
        encode_recipient_string(crate::recipient::x25519::TYPE_NAME, &bytes)
    }

    /// Returns the raw 32-byte X25519 public-key material as an owned
    /// array. Performs filesystem I/O for the key-file source.
    pub fn to_bytes(&self) -> Result<[u8; 32], CryptoError> {
        self.resolve()
    }

    /// Validates that the key source is well-formed without exposing
    /// the bytes. For a key-file source this opens the file, parses
    /// the header, and checks the layout; for a bytes source this is
    /// always `Ok(())`.
    pub fn validate(&self) -> Result<(), CryptoError> {
        self.resolve().map(|_| ())
    }

    /// Resolves the key to raw 32-byte material, reading the key file
    /// from disk if the source is a path.
    fn resolve(&self) -> Result<[u8; 32], CryptoError> {
        match &self.source {
            PublicKeySource::KeyFile(path) => read_public_key(path),
            PublicKeySource::Bytes(bytes) => Ok(*bytes),
        }
    }
}

impl std::str::FromStr for PublicKey {
    type Err = CryptoError;

    /// Parses a Bech32 `fcr1…` recipient string into a `PublicKey`.
    /// Equivalent to [`PublicKey::from_recipient_string`], enabling
    /// `"fcr1…".parse::<PublicKey>()`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_recipient_string(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 32-byte X25519-shaped fixture key for tests. Contents arbitrary;
    /// public_key encoding is type_name-agnostic.
    fn x25519_key() -> [u8; 32] {
        [0x33u8; 32]
    }

    #[test]
    fn round_trip_x25519() {
        let key = x25519_key();
        let s = encode_recipient_string("x25519", &key).unwrap();
        assert!(s.starts_with("fcr1"));
        let decoded = decode_recipient_string(&s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(decoded.type_name, "x25519");
        assert_eq!(decoded.key_material, key);
    }

    #[test]
    fn round_trip_lifts_default_bech32_code_length_cap() {
        // The bech32 crate's built-in `Bech32` type fixes
        // `CODE_LENGTH = 1023`. A v1 recipient string for a future
        // ~1 KiB key would exceed that cap; the spec explicitly lifts
        // it to 20,000 (`FORMAT.md` §7.1). This test locks in that
        // our `Bech32V1` Checksum impl actually applies the lifted
        // cap on both the encode and the strict-variant decode paths.
        let large_key = vec![0xA5u8; 1024];
        let s = encode_recipient_string("future", &large_key).unwrap();
        assert!(
            s.len() > 1023,
            "expected encoded length > 1023, got {}",
            s.len()
        );
        // Caller raises the local cap to accept the larger string.
        let decoded = decode_recipient_string(&s, RECIPIENT_STRING_LEN_MAX).unwrap();
        assert_eq!(decoded.type_name, "future");
        assert_eq!(decoded.key_material, large_key);
    }

    #[test]
    fn encoded_string_is_lowercase() {
        let s = encode_recipient_string("x25519", &x25519_key()).unwrap();
        assert!(s.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn encode_rejects_malformed_type_name() {
        match encode_recipient_string("X25519", &x25519_key()) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for uppercase, got {other:?}"),
        }
    }

    #[test]
    fn encode_rejects_oversized_key_material() {
        let oversize = vec![0u8; (KEY_MATERIAL_LEN_MAX as usize) + 1];
        match encode_recipient_string("x25519", &oversize) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_uppercase_input() {
        let s = encode_recipient_string("x25519", &x25519_key()).unwrap();
        let upper = s.to_uppercase();
        match decode_recipient_string(&upper, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidInput(_)) => {}
            other => panic!("expected InvalidInput for uppercase, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_local_cap_with_typed_variant() {
        // Per `FORMAT.md` §3.2, a local-cap exceedance MUST surface
        // as a distinct resource-cap error rather than a generic
        // malformed-file error or a string-tagged generic.
        // `RecipientStringCapExceeded` is the typed counterpart of
        // `RecipientBodyCapExceeded` for recipient strings: callers
        // can match on the variant and read both `input_chars` and
        // `local_cap` programmatically.
        let s = encode_recipient_string("x25519", &x25519_key()).unwrap();
        match decode_recipient_string(&s, 10) {
            Err(CryptoError::RecipientStringCapExceeded {
                input_chars,
                local_cap,
            }) => {
                assert_eq!(input_chars as usize, s.len());
                assert_eq!(local_cap, 10);
            }
            other => panic!("expected RecipientStringCapExceeded, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_wrong_hrp() {
        // Build a syntactically valid Bech32 string with a different HRP.
        let other_hrp = Hrp::parse_unchecked("foo");
        let data = b"abcdefghijklmnopqrstuvwxyz0123";
        let s = bech32::encode::<Bech32>(other_hrp, data).unwrap();
        match decode_recipient_string(&s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidInput(msg)) => {
                assert!(msg.contains("Unexpected recipient prefix"), "msg: {msg}");
            }
            other => panic!("expected InvalidInput for HRP, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_invalid_bech32() {
        match decode_recipient_string(
            "fcr1notavalidbech32",
            RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT,
        ) {
            Err(CryptoError::InvalidInput(_)) => {}
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_bech32m_strings() {
        // The migration plan explicitly mandates strict Bech32 (BIP 173)
        // and rejection of Bech32m. Without this test, a regression
        // that swapped `CheckedHrpstring::new::<Bech32V1>` for the
        // variant-permissive `bech32::decode` would silently accept
        // Bech32m strings — Bech32 (TARGET_RESIDUE = 1) and Bech32m
        // (TARGET_RESIDUE = 0x2bc830a3) are mutually distinguishable,
        // and confusing them downstream is exactly the variant-
        // confusion bug `Bech32V1` is here to prevent.
        let key = x25519_key();
        let cs = compute_checksum("x25519", &key);
        let mut data = Vec::new();
        data.extend_from_slice(&6u16.to_be_bytes());
        data.extend_from_slice(&32u32.to_be_bytes());
        data.extend_from_slice(b"x25519");
        data.extend_from_slice(&key);
        data.extend_from_slice(&cs);
        let bech32m = bech32::encode::<bech32::Bech32m>(RECIPIENT_HRP, &data).unwrap();
        match decode_recipient_string(&bech32m, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidInput(_)) => {}
            other => panic!("expected InvalidInput for Bech32m, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_non_utf8_type_name_bytes() {
        // The Bech32 alphabet is ASCII, but data bytes inside the typed
        // payload (after the 5-to-8 expansion) can be arbitrary.
        // Non-UTF-8 type_name bytes MUST surface as `MalformedTypeName`
        // via `std::str::from_utf8`, not silently flow into
        // `validate_type_name` (which expects `&str`).
        let mut data = Vec::new();
        data.extend_from_slice(&6u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&[0xFFu8; 6]); // non-UTF-8 type_name region
        data.extend_from_slice(&[0u8; PUBLIC_KEY_CHECKSUM_SIZE]);
        let s = bech32::encode::<Bech32V1>(RECIPIENT_HRP, &data).unwrap();
        match decode_recipient_string(&s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for non-UTF-8, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_internal_checksum_mismatch() {
        // Encode a valid string, decode at the Bech32 layer, flip a
        // bit inside the type_name region (within the lowercase ASCII
        // grammar so validate_type_name still passes), re-encode at
        // the Bech32 layer with a fresh outer checksum. The inner
        // SHA3-256 checksum, computed from the *original* type_name,
        // will not match the modified type_name → MalformedPublicKey.
        let key = x25519_key();
        let original = encode_recipient_string("x25519", &key).unwrap();
        let checked = CheckedHrpstring::new::<Bech32>(&original).unwrap();
        let mut data: Vec<u8> = checked.byte_iter().collect();
        // type_name starts at offset PAYLOAD_HEADER_SIZE (= 6).
        // Original byte is 'x' (0x78). Flip bit 0 to get 'y' (0x79).
        data[PAYLOAD_HEADER_SIZE] ^= 0x01;
        let tampered = bech32::encode::<Bech32>(RECIPIENT_HRP, &data).unwrap();
        match decode_recipient_string(&tampered, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => {
                panic!("expected MalformedPublicKey for inner-checksum mismatch, got {other:?}")
            }
        }
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        // Build a payload that's too short to contain the typed
        // header + checksum. This exercises the early structural
        // length check in `decode_recipient_string`.
        let too_short = vec![0u8; PAYLOAD_HEADER_SIZE + PUBLIC_KEY_CHECKSUM_SIZE - 1];
        let s = bech32::encode::<Bech32>(RECIPIENT_HRP, &too_short).unwrap();
        match decode_recipient_string(&s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey for truncated, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_zero_type_name_len() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_be_bytes()); // type_name_len = 0
        data.extend_from_slice(&0u32.to_be_bytes()); // key_material_len = 0
        data.extend_from_slice(&[0u8; PUBLIC_KEY_CHECKSUM_SIZE]);
        let s = bech32::encode::<Bech32>(RECIPIENT_HRP, &data).unwrap();
        match decode_recipient_string(&s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey for zero type_name_len, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_overlong_type_name_len() {
        let mut data = Vec::new();
        data.extend_from_slice(&((TYPE_NAME_MAX_LEN as u16) + 1).to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&[0u8; PUBLIC_KEY_CHECKSUM_SIZE]);
        let s = bech32::encode::<Bech32>(RECIPIENT_HRP, &data).unwrap();
        match decode_recipient_string(&s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_oversized_key_material_len() {
        let mut data = Vec::new();
        data.extend_from_slice(&6u16.to_be_bytes());
        data.extend_from_slice(&(KEY_MATERIAL_LEN_MAX + 1).to_be_bytes());
        data.extend_from_slice(b"x25519");
        data.extend_from_slice(&[0u8; PUBLIC_KEY_CHECKSUM_SIZE]);
        let s = bech32::encode::<Bech32>(RECIPIENT_HRP, &data).unwrap();
        match decode_recipient_string(&s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_total_size_mismatch() {
        // Header claims type_name_len=6, key_material_len=32 →
        // expected total = 6 + 32 + 6 + 16 = 60. Provide a payload
        // of size 60 + 1.
        let mut data = Vec::new();
        data.extend_from_slice(&6u16.to_be_bytes());
        data.extend_from_slice(&32u32.to_be_bytes());
        data.extend_from_slice(b"x25519");
        data.extend(std::iter::repeat_n(0u8, 32));
        data.extend(std::iter::repeat_n(0u8, PUBLIC_KEY_CHECKSUM_SIZE));
        data.push(0); // extra trailing byte
        let s = bech32::encode::<Bech32>(RECIPIENT_HRP, &data).unwrap();
        match decode_recipient_string(&s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey for total mismatch, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_malformed_type_name_grammar() {
        // type_name "X25519" passes the structural lengths but fails
        // validate_type_name (uppercase). Compute the inner checksum
        // for "X25519" first so the only thing left to fail is grammar.
        let key = x25519_key();
        let cs = compute_checksum("X25519", &key);
        let mut data = Vec::new();
        data.extend_from_slice(&6u16.to_be_bytes());
        data.extend_from_slice(&32u32.to_be_bytes());
        data.extend_from_slice(b"X25519");
        data.extend_from_slice(&key);
        data.extend_from_slice(&cs);
        let s = bech32::encode::<Bech32>(RECIPIENT_HRP, &data).unwrap();
        // Bech32 itself round-trips "fcr1..." in lowercase regardless
        // of input data, so the lowercase check at decode passes.
        match decode_recipient_string(&s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for uppercase, got {other:?}"),
        }
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let key = x25519_key();
        let a = fingerprint_bytes("x25519", &key);
        let b = fingerprint_bytes("x25519", &key);
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_separates_type_name_namespace() {
        // Same key bytes under different type_names MUST produce
        // different fingerprints. Catches a regression where the
        // type_name input is silently ignored.
        let key = x25519_key();
        let a = fingerprint_bytes("x25519", &key);
        let b = fingerprint_bytes("y25519", &key);
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_is_independent_of_checksum_domain() {
        // The fingerprint hash MUST NOT include the checksum domain
        // string (fingerprint identity vs internal checksum are
        // distinct concerns). Asserting the exact bytes here guards
        // against an accidental drift where the fingerprint helper
        // routes through `compute_checksum`'s domain.
        let key = x25519_key();
        let mut hasher = Sha3_256::new();
        hasher.update(b"x25519");
        hasher.update([0x00]);
        hasher.update(key);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(fingerprint_bytes("x25519", &key), expected);
    }

    #[test]
    fn fingerprint_hex_is_64_lowercase_chars() {
        let hex = fingerprint_hex("x25519", &x25519_key());
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn checksum_domain_is_canonical() {
        // Pin the wire bytes — the domain is part of every encoded
        // recipient string's inner checksum. A typo here invalidates
        // every existing fixture.
        assert_eq!(
            PUBLIC_KEY_CHECKSUM_DOMAIN,
            b"ferrocrypt/v1/public-key/checksum"
        );
    }

    #[test]
    fn recipient_hrp_is_canonical() {
        assert_eq!(RECIPIENT_HRP.as_str(), "fcr");
    }

    #[test]
    fn key_material_len_max_fits_within_spec_ceiling() {
        // The derived `KEY_MATERIAL_LEN_MAX` MUST be such that a
        // worst-case payload (max-length type_name + max-length
        // key_material) encodes within the 20,000-char spec ceiling.
        // Locks in the const-fn derivation so a future bump of
        // `RECIPIENT_STRING_LEN_MAX` or `TYPE_NAME_MAX_LEN` doesn't
        // silently let us emit out-of-spec strings.
        let big_type_name = "a".repeat(TYPE_NAME_MAX_LEN);
        let big_key = vec![0xA5u8; KEY_MATERIAL_LEN_MAX as usize];
        let s = encode_recipient_string(&big_type_name, &big_key).unwrap();
        assert!(
            s.len() <= RECIPIENT_STRING_LEN_MAX,
            "encoded length {} exceeds spec ceiling {}",
            s.len(),
            RECIPIENT_STRING_LEN_MAX
        );
        // And one byte more on the key MUST be rejected at our
        // structural layer (before bech32 ever runs).
        let one_too_big = vec![0u8; (KEY_MATERIAL_LEN_MAX as usize) + 1];
        match encode_recipient_string(&big_type_name, &one_too_big) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey for key_material > cap, got {other:?}"),
        }
    }
}
