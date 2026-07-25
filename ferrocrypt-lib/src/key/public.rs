//! Public-key encoding (`FORMAT.md` §7).
//!
//! Recipient string Bech32 typed payload:
//!
//! ```text
//! data = public_key_version:u8 || type_name_len:u16 || key_material_len:u32
//!     || type_name:N           || key_material:M
//!     || checksum:16
//! ```
//!
//! `checksum = first 16 bytes of SHA3-256(`
//! `"ferrocrypt/v1/public-key/checksum" || public_key_version || type_name || 0x00 || key_material)`.
//!
//! Every recipient payload carries an explicit `public_key_version` byte at
//! offset 0. The current public-key encoding version is `0x01`; `0x00` is
//! reserved (a writer that forgets to set the version byte fails closed at
//! the reader).
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
//! lowercase hex groups joined by `:` for spoken or out-of-band
//! verification.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Checksum, Hrp};
use sha3::{Digest, Sha3_256};

use crate::CryptoError;
use crate::error::{FormatDefect, UnsupportedVersion};
use crate::format::{
    KeypairSuite, KeypairVersionRejection, WRITER_KEYPAIR_SUITE,
    keypair_suite_from_public_key_version, keypair_suite_is_supported, read_u16_be, read_u32_be,
};
use crate::recipient::native::x25519::TYPE_NAME as X25519_TYPE_NAME;
use crate::recipient::{TYPE_NAME_MAX_LEN, validate_type_name_grammar};

/// Wire-version byte the current writer emits at offset 0 of every
/// `public.key` recipient payload. Derived from `WRITER_KEYPAIR_SUITE`
/// (crate-internal); mirrors [`crate::key::private::PRIVATE_KEY_VERSION`]
/// so a future suite bump flows through both writers in lockstep.
pub const PUBLIC_KEY_VERSION: u8 = WRITER_KEYPAIR_SUITE.public_key_version();

/// Public-key encoding version byte (`0x01`) for key-pair suite KPS-1.
/// Mirrors the suite constant from `KeypairSuite::V1` (crate-internal)
/// so bumping the keypair suite flows through this constant automatically.
pub const PUBLIC_KEY_V1_VERSION: u8 = KeypairSuite::V1.public_key_version();

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Bech32 HRP for FerroCrypt recipient strings.
pub(crate) const RECIPIENT_HRP: Hrp = Hrp::parse_unchecked("fcr");

/// Domain separator for the internal SHA3-256 recipient-payload
/// checksum. Distinct from any other hash input in the format so a future
/// extension cannot accidentally collide with this digest.
pub(crate) const PUBLIC_KEY_CHECKSUM_DOMAIN: &[u8] = b"ferrocrypt/v1/public-key/checksum";

/// Truncated SHA3-256 checksum size in the typed payload, in bytes.
pub(crate) const PUBLIC_KEY_CHECKSUM_SIZE: usize = 16;

/// Total size of the typed-payload header (`public_key_version(1) ||
/// type_name_len(2) || key_material_len(4)`), in bytes.
pub(crate) const PAYLOAD_HEADER_SIZE: usize = 1 + size_of::<u16>() + size_of::<u32>();

const PAYLOAD_VERSION_OFFSET: usize = 0;
const PAYLOAD_TYPE_NAME_LEN_OFFSET: usize = PAYLOAD_VERSION_OFFSET + 1;
const PAYLOAD_KEY_MATERIAL_LEN_OFFSET: usize = PAYLOAD_TYPE_NAME_LEN_OFFSET + size_of::<u16>();
const _: () = assert!(PAYLOAD_KEY_MATERIAL_LEN_OFFSET + size_of::<u32>() == PAYLOAD_HEADER_SIZE);

/// Spec maximum for the recipient string length in ASCII characters
/// (`FORMAT.md` §7.1). [`KEY_MATERIAL_LEN_MAX`] derives from this
/// ceiling so the worst-case payload still encodes within it.
pub(crate) const RECIPIENT_STRING_LEN_MAX: usize = 20_000;

/// File-read cap for `public.key`: [`RECIPIENT_STRING_LEN_MAX`] ASCII
/// chars plus one optional trailing `LF`. Anything larger cannot
/// be a valid `public.key` file, so the reader rejects before allocating
/// a multi-gigabyte buffer for adversarial input.
pub(crate) const PUBLIC_KEY_FILE_READ_CAP_BYTES: usize = RECIPIENT_STRING_LEN_MAX + 1;

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
pub(crate) const KEY_MATERIAL_LEN_MAX: u32 = max_key_material_len();

const fn max_key_material_len() -> u32 {
    // Each Bech32 data char encodes 5 bits.
    let data_chars = RECIPIENT_STRING_LEN_MAX - RECIPIENT_STRING_OVERHEAD_CHARS;
    let max_data_bytes = data_chars * 5 / 8;
    let max_payload =
        max_data_bytes - PAYLOAD_HEADER_SIZE - PUBLIC_KEY_CHECKSUM_SIZE - TYPE_NAME_MAX_LEN;
    max_payload as u32
}

/// BIP 173 Bech32 with the spec's lifted code-length cap. The crate's
/// built-in [`bech32::Bech32`] type fixes `CODE_LENGTH = 1023`, below
/// the spec's 20,000-char ceiling and below the largest payload that
/// [`KEY_MATERIAL_LEN_MAX`] permits. All other [`Checksum`] constants are
/// forwarded from `bech32::Bech32`, so the on-wire checksum polynomial is
/// byte-identical to BIP 173; only the length tolerance differs.
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
///
/// The `keypair_suite` field carries the **logical compatibility class**
/// recovered from the wire-version byte. Both `public.key` and
/// `private.key` parsers translate their on-disk version byte into a
/// [`KeypairSuite`] before any support decision; a release must reject a
/// public recipient whenever the same suite would be rejected for
/// private-key decryption (`FORMAT.md` §7, §11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRecipient {
    pub keypair_suite: KeypairSuite,
    pub type_name: String,
    pub key_material: Vec<u8>,
}

/// Encodes a public-key recipient string in canonical lowercase
/// Bech32 (BIP 173) for the current writer's keypair suite. Thin
/// wrapper over [`encode_recipient_string_for_suite`] that pins the
/// suite to `WRITER_KEYPAIR_SUITE` (crate-internal); use this when
/// emitting a recipient string for a freshly generated keypair (which
/// is, by definition, in the writer suite). When re-encoding a
/// `PublicKey` whose suite was recovered from an existing recipient
/// string or key file, route through
/// [`encode_recipient_string_for_suite`] with the resolved suite so
/// the original wire-version byte is preserved.
pub(crate) fn encode_recipient_string(
    type_name: &str,
    key_material: &[u8],
) -> Result<String, CryptoError> {
    encode_recipient_string_for_suite(WRITER_KEYPAIR_SUITE, type_name, key_material)
}

/// Suite-explicit variant of [`encode_recipient_string`]. Emits the
/// supplied `suite`'s wire-version byte at offset 0 of the typed
/// payload, validates `type_name` against the §3.3 grammar, and
/// computes the internal SHA3-256 checksum (with the version byte
/// mixed into the hash input) so a corrupt copy fails closed at the
/// decoder. Crate-internal because the suite type is itself
/// crate-internal — external callers go through the writer-suite
/// wrapper.
pub(crate) fn encode_recipient_string_for_suite(
    suite: KeypairSuite,
    type_name: &str,
    key_material: &[u8],
) -> Result<String, CryptoError> {
    let version = suite.public_key_version();
    validate_type_name_grammar(type_name)?;
    let type_name_bytes = type_name.as_bytes();
    let type_name_len = u16::try_from(type_name_bytes.len())
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedTypeName))?;
    let key_material_len = u32::try_from(key_material.len()).map_err(|_| malformed_public_key())?;
    check_key_material_len(key_material_len)?;

    let cs = compute_checksum(version, type_name, key_material);

    let total_data =
        PAYLOAD_HEADER_SIZE + type_name_bytes.len() + key_material.len() + PUBLIC_KEY_CHECKSUM_SIZE;
    let mut data = Vec::with_capacity(total_data);
    data.push(version);
    data.extend_from_slice(&type_name_len.to_be_bytes());
    data.extend_from_slice(&key_material_len.to_be_bytes());
    data.extend_from_slice(type_name_bytes);
    data.extend_from_slice(key_material);
    data.extend_from_slice(&cs);

    bech32::encode::<Bech32V1>(RECIPIENT_HRP, &data)
        .map_err(|_| CryptoError::InternalInvariant("Bech32 encode failed"))
}

/// Decodes a canonical lowercase Bech32 recipient string into the
/// typed payload.
///
/// Validates, in order: local input-length cap, lowercase grammar,
/// strict Bech32 (BIP 173, rejecting Bech32m), HRP `"fcr"`, structural
/// length fields, `type_name` UTF-8 and grammar, and the internal
/// SHA3-256 checksum.
///
/// Every grammar failure surfaces as
/// [`FormatDefect::MalformedPublicKey`], the `malformed_public_key`
/// diagnostic class of `FORMAT.md` §12.1, so a caller can classify a
/// rejected recipient string from the error type alone. The only other
/// rejection this function raises is
/// [`CryptoError::RecipientStringCapExceeded`] for the resource cap.
///
/// `local_max_chars` is a local policy cap checked before decode work runs.
/// The structural ceiling is `RECIPIENT_STRING_LEN_MAX` (20,000 ASCII
/// characters); callers should normally pass the smaller
/// [`RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT`] for untrusted input unless they
/// intentionally accept larger future recipient strings.
pub fn decode_recipient_string(
    s: &str,
    local_max_chars: usize,
) -> Result<DecodedRecipient, CryptoError> {
    // Bech32 (BIP 173) is an ASCII-only grammar, so reject non-ASCII
    // input up front. This also makes the cap check below honest:
    // `RecipientStringCapExceeded` advertises `input_chars`, but
    // `str::len()` returns bytes — only after the ASCII check are the
    // two equal. Without this, a 600-character non-ASCII string whose
    // UTF-8 byte length exceeds the cap would misclassify as a cap
    // exceedance instead of a malformed-key rejection.
    if !s.is_ascii() {
        return Err(malformed_public_key());
    }
    let char_count = s.len(); // bytes == chars after the ASCII check
    if char_count > local_max_chars {
        // Saturating cast: pathological gigabyte-plus inputs report
        // `u32::MAX` for `input_chars`, but the cap rejection itself
        // is correct (the bare comparison ran on usize).
        return Err(CryptoError::RecipientStringCapExceeded {
            input_chars: u32::try_from(char_count).unwrap_or(u32::MAX),
            local_cap: u32::try_from(local_max_chars).unwrap_or(u32::MAX),
        });
    }
    if s.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(malformed_public_key());
    }

    // Strict Bech32 (BIP 173 polynomial via `Bech32V1`, which also
    // accepts strings up to the spec's 20 000-char cap rather than the
    // crate's default 1023). `CheckedHrpstring` rejects Bech32m
    // strings and mixed case, but NOT non-canonical 5-to-8 padding:
    // in `bech32` that check runs only on the segwit decode path, and
    // `byte_iter` silently drops the trailing bits. Enforced below.
    let checked = CheckedHrpstring::new::<Bech32V1>(s).map_err(|_| malformed_public_key())?;
    if checked.hrp() != RECIPIENT_HRP {
        return Err(malformed_public_key());
    }
    let data: Vec<u8> = checked.byte_iter().collect();

    check_payload_data_len(data.len())?;

    // `FORMAT.md` §7: reject non-canonical 5-to-8 padding. The dropped
    // padding bits are covered by neither checksum, so two distinct
    // strings could otherwise decode to the same accepted payload. A
    // canonical re-encode must reproduce the input byte-for-byte
    // (lowercase was already enforced above, so no legal input fails).
    let canonical =
        bech32::encode::<Bech32V1>(RECIPIENT_HRP, &data).map_err(|_| malformed_public_key())?;
    if canonical != s {
        return Err(malformed_public_key());
    }

    let wire_version = data[PAYLOAD_VERSION_OFFSET];
    let suite = public_key_wire_version_to_suite(wire_version)?;
    ensure_public_key_suite_supported(suite)?;

    let type_name_len = read_u16_be(&data, PAYLOAD_TYPE_NAME_LEN_OFFSET)?;
    check_type_name_len(type_name_len)?;
    let key_material_len = read_u32_be(&data, PAYLOAD_KEY_MATERIAL_LEN_OFFSET)?;
    check_key_material_len(key_material_len)?;
    check_total_payload_size(data.len(), type_name_len, key_material_len)?;

    let type_name_start = PAYLOAD_HEADER_SIZE;
    let type_name_end = type_name_start + type_name_len as usize;
    let key_material_end = type_name_end + key_material_len as usize;
    let checksum_end = key_material_end + PUBLIC_KEY_CHECKSUM_SIZE;

    let type_name_bytes = &data[type_name_start..type_name_end];
    let type_name = std::str::from_utf8(type_name_bytes)
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedTypeName))?;
    validate_type_name_grammar(type_name)?;

    let key_material = data[type_name_end..key_material_end].to_vec();
    let stored_checksum = &data[key_material_end..checksum_end];

    let computed_checksum = compute_checksum(wire_version, type_name, &key_material);
    // The recipient string is public, the checksum is for typo
    // detection rather than secret-comparison; ordinary `!=` is fine
    // and timing-safety is not required here.
    if stored_checksum != computed_checksum {
        return Err(malformed_public_key());
    }

    Ok(DecodedRecipient {
        keypair_suite: suite,
        type_name: type_name.to_owned(),
        key_material,
    })
}

/// Translates a `public.key` wire-version byte into a logical
/// [`KeypairSuite`]. Thin domain-specific translation layer over
/// [`keypair_suite_from_public_key_version`] — the centralised reverse
/// mapper in `format.rs` decides "which suite is this byte / why is it
/// rejected", and this function wraps the rejection in the
/// public-key-flavoured diagnostics:
/// [`FormatDefect::MalformedPublicKey`] for the reserved `0x00` byte,
/// [`UnsupportedVersion::OlderPublicKey`] / [`UnsupportedVersion::NewerPublicKey`]
/// for the older / newer arms.
///
/// Symmetric counterpart of
/// [`crate::key::private::private_key_wire_version_to_suite`]; both
/// route through the same centralised mapper. Adding a future suite
/// only requires updating the mapper's literal-byte arm in `format.rs`,
/// not this translation layer.
fn public_key_wire_version_to_suite(version: u8) -> Result<KeypairSuite, CryptoError> {
    keypair_suite_from_public_key_version(version).map_err(|r| match r {
        KeypairVersionRejection::Reserved => malformed_public_key(),
        KeypairVersionRejection::Older { version: v } => {
            CryptoError::UnsupportedVersion(UnsupportedVersion::OlderPublicKey { version: v })
        }
        KeypairVersionRejection::Newer { version: v } => {
            CryptoError::UnsupportedVersion(UnsupportedVersion::NewerPublicKey { version: v })
        }
    })
}

/// Asserts the suite is in this build's support list. The wire-version
/// byte for the diagnostic is derived from `suite` so the on-disk byte
/// and the reported number cannot drift apart. Used at encryption-time
/// recipient acceptance — the same gate the private-key parser uses for
/// decryption-time private-key acceptance.
fn ensure_public_key_suite_supported(suite: KeypairSuite) -> Result<(), CryptoError> {
    if keypair_suite_is_supported(suite) {
        Ok(())
    } else {
        Err(CryptoError::UnsupportedVersion(
            UnsupportedVersion::OlderPublicKey {
                version: suite.public_key_version(),
            },
        ))
    }
}

/// Canonical X25519-typed Bech32 decoder. Single source of truth for
/// "given a `fcr1…` recipient string, return raw 32-byte X25519 key
/// material." [`crate::decode_recipient_string`] (the public free function)
/// routes through here so a future cap-policy or type-name change
/// cannot drift between the public entry points.
///
/// Suite-discarding wrapper around [`decode_x25519_recipient_resolved`]:
/// callers who only need the bytes (the public `decode_recipient_string` API)
/// drop the suite, while in-tree callers that need to preserve the
/// suite on a resulting `PublicKey` use the resolved variant.
///
/// Validates HRP, BIP 173 checksum, internal SHA3-256 checksum, the
/// recipient `type_name == "x25519"` constraint, and the 32-byte
/// key-material length. Applies [`RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT`]
/// as the local resource cap.
pub(crate) fn decode_x25519_recipient(recipient: &str) -> Result<[u8; 32], CryptoError> {
    Ok(decode_x25519_recipient_resolved(recipient)?.bytes)
}

/// Suite-preserving X25519-typed Bech32 decoder. Returns a
/// [`ResolvedPublicKey`] so [`PublicKey::from_recipient_string`] can
/// store the recovered keypair suite on the value rather than discard
/// it and re-tag it with the current writer suite. Same validation as
/// [`decode_x25519_recipient`].
pub(crate) fn decode_x25519_recipient_resolved(
    recipient: &str,
) -> Result<ResolvedPublicKey, CryptoError> {
    let decoded = decode_recipient_string(recipient, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT)?;
    let suite = decoded.keypair_suite;
    let bytes = decoded_x25519_bytes(decoded)?;
    Ok(ResolvedPublicKey { suite, bytes })
}

/// Once a recipient string has been decoded, verify it carries
/// X25519 material and extract the raw 32-byte key.
///
/// Shared by the recipient-string and key-file parsers. A decoded
/// non-X25519 type has passed the grammar, checksum, and suite gates,
/// so it rejects as [`CryptoError::UnsupportedKeyType`], not as a
/// malformed input. X25519 material must be exactly 32 bytes, not all
/// zero, and the canonical `FORMAT.md` §2.4 encoding — an RFC 7748
/// alias of a valid key is rejected, never normalized, so one curve
/// point cannot carry two recipient strings or fingerprints.
fn decoded_x25519_bytes(decoded: DecodedRecipient) -> Result<[u8; 32], CryptoError> {
    if decoded.type_name != X25519_TYPE_NAME {
        return Err(CryptoError::UnsupportedKeyType {
            type_name: decoded.type_name,
        });
    }
    let bytes: [u8; 32] = decoded
        .key_material
        .as_slice()
        .try_into()
        .map_err(|_| malformed_public_key())?;
    if crate::recipient::x25519::is_zero_public_key(&bytes)
        || !crate::recipient::x25519::is_canonical_public_key_encoding(&bytes)
    {
        return Err(malformed_public_key());
    }
    Ok(bytes)
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

/// SHA3-256 over a `prefix || type_name || 0x00 || key_material`
/// pre-image. Single source of truth for the recipient-payload tail
/// shape shared by [`compute_checksum`] (with the
/// [`PUBLIC_KEY_CHECKSUM_DOMAIN`] domain + version byte as prefix) and
/// [`fingerprint_bytes`] (with an empty prefix). If the tail shape ever
/// extends, both hashes pick up the change automatically.
///
/// `0x00` between `type_name` and `key_material` is unambiguous as a
/// separator because the §3.3 `type_name` grammar disallows the null
/// byte.
fn public_key_hash(prefix: &[&[u8]], type_name: &str, key_material: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for chunk in prefix {
        hasher.update(chunk);
    }
    hasher.update(type_name.as_bytes());
    hasher.update([0x00]);
    hasher.update(key_material);
    hasher.finalize().into()
}

/// SHA3-256-based internal checksum, truncated to
/// [`PUBLIC_KEY_CHECKSUM_SIZE`] bytes (`FORMAT.md` §7).
///
/// Pre-image: `PUBLIC_KEY_CHECKSUM_DOMAIN || version || type_name ||
/// 0x00 || key_material`. Mixing the version byte into the hash binds
/// the typed payload to its declared version and rules out
/// cross-version transplant accidents — a payload with the right inner
/// fields but a different version byte fails this check. Detects typed-payload
/// corruption that the outer Bech32 checksum cannot catch (for example, a
/// hand-edited recipient string with a valid Bech32 checksum but mismatched
/// inner data).
fn compute_checksum(
    version: u8,
    type_name: &str,
    key_material: &[u8],
) -> [u8; PUBLIC_KEY_CHECKSUM_SIZE] {
    let full = public_key_hash(
        &[PUBLIC_KEY_CHECKSUM_DOMAIN, &[version]],
        type_name,
        key_material,
    );
    let mut truncated = [0u8; PUBLIC_KEY_CHECKSUM_SIZE];
    truncated.copy_from_slice(&full[..PUBLIC_KEY_CHECKSUM_SIZE]);
    truncated
}

fn malformed_public_key() -> CryptoError {
    CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)
}

// ─── Fingerprint ───────────────────────────────────────────────────────────

/// Canonical fingerprint hash of `type_name || 0x00 || key_material`
/// as a 32-byte SHA3-256 digest. The domain separator used in
/// [`PUBLIC_KEY_CHECKSUM_DOMAIN`] is intentionally absent — the
/// fingerprint is a stable identity over the `(type_name, key_material)`
/// pair, not over the encoding-checksum domain. The version byte is
/// also absent: bumping the wire version of an existing key pair must
/// not change its user-visible identity.
pub(crate) fn fingerprint_bytes(type_name: &str, key_material: &[u8]) -> [u8; 32] {
    public_key_hash(&[], type_name, key_material)
}

/// 64-character lowercase hex of [`fingerprint_bytes`].
pub(crate) fn fingerprint_hex(type_name: &str, key_material: &[u8]) -> String {
    hex_encode(&fingerprint_bytes(type_name, key_material))
}

// ─── public.key file grammar and reader ────────────────────────────────────

/// Parses the bytes of a `public.key` file into a resolved X25519
/// public key. [`read_public_key`] owns the bounded filesystem read;
/// this function is the single implementation of the content grammar
/// and provides the arbitrary-byte entry point used by fuzzing.
///
/// The content must be the canonical lowercase `fcr1…` recipient
/// string, optionally followed by exactly one trailing `\n`
/// (`FORMAT.md` §7). Anything else — leading whitespace, CRLF line
/// endings, extra blank lines, trailing spaces or tabs, or internal
/// whitespace — is rejected as [`FormatDefect::MalformedPublicKey`].
///
/// A binary `private.key` signature is classified before UTF-8
/// decoding and returns [`FormatDefect::WrongKeyFileType`]. A valid
/// recipient string of a non-X25519 type returns
/// [`CryptoError::UnsupportedKeyType`] naming the type.
///
/// Decoding delegates to [`decode_recipient_string`], the single
/// source of truth for the Bech32 grammar, internal SHA3-256
/// checksum, and resource caps. The keypair suite recovered from the
/// recipient-string wire-version byte is preserved in the returned
/// [`ResolvedPublicKey`].
pub(crate) fn parse_public_key_file_bytes(bytes: &[u8]) -> Result<ResolvedPublicKey, CryptoError> {
    if bytes.is_empty() {
        // Reject here so an empty file reports as a malformed public
        // key rather than as an invalid recipient string from the
        // Bech32 decoder.
        return Err(malformed_public_key());
    }
    if matches!(
        crate::key::files::KeyFileKind::classify(bytes),
        crate::key::files::KeyFileKind::Private
    ) {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }
    let contents = std::str::from_utf8(bytes)
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::NotAKeyFile))?;
    // Leave non-whitespace text, such as a BOM or an invalid Bech32
    // character, to the recipient-string decoder.
    let recipient = contents.strip_suffix('\n').unwrap_or(contents);
    if recipient.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(malformed_public_key());
    }
    let decoded = decode_recipient_string(recipient, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT)?;
    let suite = decoded.keypair_suite;
    let key = decoded_x25519_bytes(decoded)?;
    Ok(ResolvedPublicKey { suite, bytes: key })
}

/// Reads and parses a `public.key` file.
///
/// Enforces [`PUBLIC_KEY_FILE_READ_CAP_BYTES`] before allocation, then
/// delegates all content validation to [`parse_public_key_file_bytes`].
pub(crate) fn read_public_key(path: &std::path::Path) -> Result<ResolvedPublicKey, CryptoError> {
    let bytes = crate::fs::paths::read_file_capped(
        path,
        PUBLIC_KEY_FILE_READ_CAP_BYTES,
        malformed_public_key,
    )?;
    parse_public_key_file_bytes(&bytes)
}

// ─── Public-recipient wrapper ──────────────────────────────────────────────

/// Public recipient key for FerroCrypt public-key encryption.
///
/// Today, public recipient keys are native X25519 public keys. A `PublicKey`
/// can reference a `public.key` file, hold raw 32-byte X25519 public material,
/// or be constructed from a Bech32 `fcr1…` recipient string. Filesystem sources
/// defer I/O until a method needs the key material.
///
/// Once constructed, a `PublicKey` can be:
///
/// - passed to [`crate::Encryptor::with_public_key`] or
///   [`crate::Encryptor::with_public_keys`];
/// - rendered as a Bech32 `fcr1…` recipient string with
///   [`PublicKey::to_recipient_string`];
/// - fingerprinted with [`PublicKey::fingerprint`].
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
    X25519 {
        suite: KeypairSuite,
        bytes: [u8; 32],
    },
}

/// Internal resolved public-key form: X25519 bytes plus the
/// [`KeypairSuite`] (crate-internal) the bytes belong to. All three
/// `PublicKey` construction paths (`from_bytes`, `from_recipient_string`,
/// `from_key_file` via `read_public_key`) materialise this shape so a
/// caller of [`PublicKey::resolve`] always sees the suite alongside the
/// key material. Every byte that reaches the encryption pipeline or the
/// recipient-string encoder is paired with the suite it belongs to,
/// not silently re-tagged with the current writer suite.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResolvedPublicKey {
    pub suite: KeypairSuite,
    pub bytes: [u8; 32],
}

impl PublicKey {
    /// References a FerroCrypt `public.key` file.
    ///
    /// The file is not opened until a method that needs the key material is
    /// called, such as [`fingerprint`](Self::fingerprint),
    /// [`to_recipient_string`](Self::to_recipient_string),
    /// [`to_bytes`](Self::to_bytes), or [`validate`](Self::validate).
    pub fn from_key_file(path: impl AsRef<std::path::Path>) -> Self {
        Self {
            source: PublicKeySource::KeyFile(path.as_ref().to_path_buf()),
        }
    }

    /// Wraps raw 32-byte X25519 public-key material directly.
    ///
    /// The resulting `PublicKey` is tagged with this build's writer
    /// keypair suite (`WRITER_KEYPAIR_SUITE`, crate-internal). Raw
    /// bytes carry no suite marker, so this constructor cannot represent a
    /// public key from a different suite. A future release that drops support
    /// for an older suite will tag every `from_bytes` value with the current
    /// writer suite, ensuring the matching private-key suite is also still
    /// supported. Callers who need to load a non-writer-suite public key must
    /// go through [`PublicKey::from_recipient_string`] or
    /// [`PublicKey::from_key_file`], where the wire-version byte selects the
    /// suite explicitly.
    ///
    /// Rejects the all-zero point and any non-canonical encoding
    /// structurally. Per `FORMAT.md` §2.4 the accepted material is a
    /// 32-byte little-endian integer strictly below the Curve25519
    /// field prime; the X25519 math would accept an alias of a valid
    /// key (for example with the top bit set), but the raw bytes are
    /// bound into fingerprints, recipient strings, and the wrap-key
    /// derivation, so an alias is rejected rather than normalized.
    /// Other degenerate inputs are caught at the ECDH site by `wrap` /
    /// `unwrap`'s shared-secret check.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidFormat`] with
    /// [`FormatDefect::MalformedPublicKey`](crate::FormatDefect::MalformedPublicKey)
    /// if `bytes` is the all-zero X25519 public key or a non-canonical
    /// encoding.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        if crate::recipient::x25519::is_zero_public_key(&bytes)
            || !crate::recipient::x25519::is_canonical_public_key_encoding(&bytes)
        {
            return Err(malformed_public_key());
        }
        Ok(Self {
            source: PublicKeySource::X25519 {
                suite: WRITER_KEYPAIR_SUITE,
                bytes,
            },
        })
    }

    /// Decodes a canonical lowercase Bech32 `fcr1…` recipient string
    /// into a `PublicKey`. The accepted grammar is the string produced by
    /// [`PublicKey::to_recipient_string`], which is also the content of a
    /// `public.key` file without the optional trailing newline. Validates
    /// HRP, BIP 173 checksum, internal SHA3-256 checksum, payload structural
    /// fields, type-name grammar, and, for X25519 recipients,
    /// `type_name == "x25519"` with exactly 32 bytes of non-zero,
    /// canonically encoded key material (`FORMAT.md` §2.4 / §7).
    ///
    /// The keypair suite recovered from the wire-version byte is
    /// preserved on the resulting `PublicKey`. Re-encoding via
    /// [`PublicKey::to_recipient_string`] uses the parsed suite, not
    /// the current writer suite, so a recipient string round-trips
    /// byte-identically as long as the original suite is still
    /// supported by this build.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidFormat`] with
    /// [`FormatDefect::MalformedPublicKey`] for text that is not a
    /// canonical recipient string and for a malformed payload,
    /// [`CryptoError::UnsupportedKeyType`] for a valid recipient string
    /// of a key type this build does not support, and
    /// [`CryptoError::RecipientStringCapExceeded`] when the input
    /// exceeds the local recipient-string cap.
    pub fn from_recipient_string(recipient: &str) -> Result<Self, CryptoError> {
        let resolved = decode_x25519_recipient_resolved(recipient)?;
        Ok(Self {
            source: PublicKeySource::X25519 {
                suite: resolved.suite,
                bytes: resolved.bytes,
            },
        })
    }

    /// Computes the public-key fingerprint.
    ///
    /// Returns 64 lowercase hexadecimal characters: SHA3-256 over
    /// `type_name || 0x00 || key_material`, using the `"x25519"` type
    /// name. The `type_name` prefix and length-separator byte
    /// domain-separate the fingerprint by recipient kind, so future
    /// native types (post-quantum, hybrid KEMs) cannot collide with this
    /// namespace. Matches the `ferrocrypt fingerprint` subcommand.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`PublicKey::to_bytes`] when this key source
    /// must be read from disk or decoded from a key file.
    pub fn fingerprint(&self) -> Result<String, CryptoError> {
        let resolved = self.resolve()?;
        Ok(fingerprint_hex(X25519_TYPE_NAME, &resolved.bytes))
    }

    /// Encodes the key as the canonical lowercase Bech32 `fcr1…`
    /// recipient string.
    ///
    /// Re-encodes using the keypair suite the key was originally
    /// constructed with (preserved on every `PublicKey` ingress path),
    /// not the current writer suite. A `PublicKey` parsed from a
    /// `fcr1…` string round-trips byte-identically; a `PublicKey`
    /// built from raw bytes via [`PublicKey::from_bytes`] re-encodes
    /// using the writer suite (the suite `from_bytes` pins).
    ///
    /// Performs filesystem I/O if this `PublicKey` references a key file.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`PublicKey::to_bytes`] when this key source
    /// must be read from disk or decoded from a key file. Returns
    /// [`CryptoError::InternalInvariant`] only if canonical Bech32 encoding fails
    /// for already-validated X25519 bytes.
    pub fn to_recipient_string(&self) -> Result<String, CryptoError> {
        let resolved = self.resolve()?;
        encode_recipient_string_for_suite(resolved.suite, X25519_TYPE_NAME, &resolved.bytes)
    }

    /// Returns the raw 32-byte X25519 public-key material as an owned
    /// array.
    ///
    /// Performs filesystem I/O for the key-file source.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InputPath`] if a referenced key file does not
    /// exist, and [`CryptoError::Io`] for other read failures. Returns
    /// [`CryptoError::InvalidFormat`] or
    /// [`CryptoError::RecipientStringCapExceeded`] if a referenced key file is
    /// not a valid `public.key` file.
    pub fn to_bytes(&self) -> Result<[u8; 32], CryptoError> {
        self.resolve().map(|resolved| resolved.bytes)
    }

    /// Validates that the key source is well-formed without exposing the
    /// bytes to the caller.
    ///
    /// For a key-file source this opens and parses the `public.key`
    /// text file. For a raw-bytes source this is always `Ok(())` —
    /// structural rejection of degenerate keys (e.g. all-zero) already
    /// happens inside [`PublicKey::from_bytes`], so a constructed
    /// `PublicKey` cannot wrap a value that fails this check.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`PublicKey::to_bytes`] when this key source
    /// must be read from disk or decoded from a key file.
    pub fn validate(&self) -> Result<(), CryptoError> {
        self.resolve().map(|_| ())
    }

    /// Resolves the key to its [`ResolvedPublicKey`] (suite + 32-byte
    /// material), reading the key file from disk if the source is a
    /// path. Every `PublicKey` ingress path stores or recovers the
    /// keypair suite, so the resolved value always carries an
    /// already-supported [`KeypairSuite`].
    fn resolve(&self) -> Result<ResolvedPublicKey, CryptoError> {
        match &self.source {
            PublicKeySource::KeyFile(path) => read_public_key(path),
            PublicKeySource::X25519 { suite, bytes } => Ok(ResolvedPublicKey {
                suite: *suite,
                bytes: *bytes,
            }),
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

    /// A rejected recipient string is never echoed, so a malicious
    /// value cannot carry terminal escape sequences into the message.
    #[test]
    fn rejected_recipient_string_is_not_echoed() {
        let input = "fcr1\u{1b}]0;spoof\u{7}";
        let err =
            decode_recipient_string(input, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT).unwrap_err();
        match &err {
            CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey) => {}
            other => panic!("expected MalformedPublicKey, got {other:?}"),
        }
        let msg = err.to_string();
        assert!(!msg.contains('\u{1b}'), "raw ESC must not appear: {msg:?}");
        assert!(!msg.contains("spoof"), "input must not be echoed: {msg}");
    }

    /// Pins the wire-version-to-suite mapping. Boundary cases:
    /// - `0x00`: reserved — rejected as malformed (not a real version).
    /// - `0x01` (= [`PUBLIC_KEY_V1_VERSION`]): maps to V1 (the only
    ///   supported suite today).
    /// - `0x02..=0xFF`: "newer" today; the `Older` arm is only reachable
    ///   once `PUBLIC_KEY_VERSION` advances past `0x01`.
    ///
    /// Mirrors `private.rs::private_key_wire_version_to_suite_classifies_v1_and_neighbours`:
    /// the two helpers must classify analogously so the encrypt/decrypt
    /// symmetry rule (`FORMAT.md` §11) cannot drift.
    #[test]
    fn public_key_wire_version_to_suite_classifies_v1_and_neighbours() {
        assert_eq!(
            public_key_wire_version_to_suite(PUBLIC_KEY_V1_VERSION).unwrap(),
            KeypairSuite::V1,
        );
        match public_key_wire_version_to_suite(0x00) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey for 0x00, got {other:?}"),
        }
        match public_key_wire_version_to_suite(0x02) {
            Err(CryptoError::UnsupportedVersion(UnsupportedVersion::NewerPublicKey {
                version: 0x02,
            })) => {}
            other => panic!("expected NewerPublicKey(0x02), got {other:?}"),
        }
        match public_key_wire_version_to_suite(0x7F) {
            Err(CryptoError::UnsupportedVersion(UnsupportedVersion::NewerPublicKey {
                version: 0x7F,
            })) => {}
            other => panic!("expected NewerPublicKey(0x7F), got {other:?}"),
        }
    }

    /// `DecodedRecipient` carries the logical [`KeypairSuite`] alongside
    /// the typed payload fields. Recipient strings with public-key
    /// encoding version `0x01` must decode to `KeypairSuite::V1`
    /// (key-pair suite KPS-1) — symmetric with private-key parsing's
    /// mapping of the `0x01` wire byte to `KeypairSuite::V1`.
    #[test]
    fn v1_recipient_string_decodes_with_keypair_suite_v1() {
        let s = encode_recipient_string("x25519", &x25519_key()).unwrap();
        let decoded = decode_recipient_string(&s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(decoded.keypair_suite, KeypairSuite::V1);
    }

    /// Cross-domain symmetry pin: both `public.key` and `private.key`
    /// parsers translate their wire-level encoding into the same
    /// [`KeypairSuite`] gate. For key-pair suite KPS-1 (wire byte `0x01`
    /// on both sides) both paths converge on `KeypairSuite::V1`. Without
    /// this, a future refactor that picked up a private-only or
    /// public-only suite-mapping helper could reintroduce the original
    /// asymmetry bug.
    #[test]
    fn public_and_private_v1_wire_encodings_share_keypair_suite() {
        use crate::key::private::{PRIVATE_KEY_V1_VERSION, private_key_wire_version_to_suite};
        let public_suite = public_key_wire_version_to_suite(PUBLIC_KEY_V1_VERSION).unwrap();
        let private_suite = private_key_wire_version_to_suite(PRIVATE_KEY_V1_VERSION).unwrap();
        assert_eq!(public_suite, private_suite);
        assert_eq!(public_suite, KeypairSuite::V1);
    }

    /// Mirror of `private_key_version_derives_from_keypair_suite_not_fcr_file_version`
    /// for the public-key side. [`PUBLIC_KEY_VERSION`] must flow through
    /// [`WRITER_KEYPAIR_SUITE`], not through any independent constant.
    #[test]
    fn public_key_version_derives_from_keypair_suite() {
        assert_eq!(
            PUBLIC_KEY_VERSION,
            WRITER_KEYPAIR_SUITE.public_key_version()
        );
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

    /// `FORMAT.md` §7 requires decoders to reject non-canonical 5-to-8
    /// padding. Builds a second, distinct `fcr1…` string for the same
    /// payload by setting the lowest padding bit of the final data
    /// character and recomputing the BIP 173 checksum. The dropped
    /// padding bits are covered by neither checksum, so without the
    /// canonical re-encode check this string is accepted.
    #[test]
    fn decode_rejects_non_canonical_bech32_padding() {
        use bech32::Fe32;
        use bech32::primitives::iter::{ByteIterExt, Fe32IterExt};

        let canonical = encode_recipient_string("x25519", &x25519_key()).unwrap();
        decode_recipient_string(&canonical, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT)
            .expect("canonical string must decode");

        let payload: Vec<u8> = CheckedHrpstring::new::<Bech32V1>(&canonical)
            .unwrap()
            .byte_iter()
            .collect();
        let pad_bits = (5 - (payload.len() * 8) % 5) % 5;
        assert!(
            pad_bits > 0,
            "payload length leaves no padding bits; vary key_material length"
        );

        let mut fes: Vec<Fe32> = payload.iter().copied().bytes_to_fes().collect();
        let last = fes.pop().expect("payload is non-empty");
        let tweaked = Fe32::try_from(last.to_u8() | 0x01).unwrap();
        assert_ne!(last, tweaked, "lowest padding bit must start unset");
        fes.push(tweaked);
        let non_canonical: String = fes
            .iter()
            .copied()
            .with_checksum::<Bech32V1>(&RECIPIENT_HRP)
            .chars()
            .collect();
        assert_ne!(non_canonical, canonical);

        match decode_recipient_string(&non_canonical, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_lifts_default_bech32_code_length_cap() {
        // The bech32 crate's built-in `Bech32` type fixes
        // `CODE_LENGTH = 1023`. A recipient string for a future
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
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey for uppercase, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_local_cap_with_typed_variant() {
        // Per `FORMAT.md` §3.2, a local-cap exceedance must surface
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

    /// Bech32 is ASCII-only, so non-ASCII text is not a recipient
    /// string at all and rejects as a malformed public key. The
    /// companion test below covers why that check runs before the
    /// length cap.
    #[test]
    fn decode_rejects_non_ascii_before_cap_check() {
        let s = "fcr1日本語";
        match decode_recipient_string(s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey for non-ASCII, got {other:?}"),
        }
    }

    /// `decode_recipient_string` advertises `input_chars` in its cap
    /// diagnostic, but `str::len()` is bytes. A non-ASCII string whose
    /// byte length exceeds the cap while its char count does not would
    /// therefore be reported as `RecipientStringCapExceeded`; the ASCII
    /// check runs first, so the cap variant never fires here.
    #[test]
    fn decode_rejects_non_ascii_with_byte_length_above_cap_as_malformed() {
        // 8 chars × 3 bytes each = 24 bytes. Cap of 10 chars would let
        // 8 chars through if we counted chars, but the byte length is
        // 24 > 10. Either way the answer must be `MalformedPublicKey`,
        // never `RecipientStringCapExceeded`, because the input is not
        // ASCII.
        let s = "日本語日本語日本";
        assert_eq!(s.chars().count(), 8);
        assert_eq!(s.len(), 24);
        match decode_recipient_string(s, 10) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey for non-ASCII, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_wrong_hrp() {
        // Build a syntactically valid Bech32 string with a different HRP.
        let other_hrp = Hrp::parse_unchecked("foo");
        let data = b"abcdefghijklmnopqrstuvwxyz0123";
        let s = bech32::encode::<Bech32>(other_hrp, data).unwrap();
        match decode_recipient_string(&s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey for a wrong HRP, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_invalid_bech32() {
        match decode_recipient_string(
            "fcr1notavalidbech32",
            RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT,
        ) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey for invalid Bech32, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_bech32m_strings() {
        // FORMAT.md §7 mandates strict Bech32 (BIP 173) and rejects
        // Bech32m. Without this test, a regression that swapped
        // `CheckedHrpstring::new::<Bech32V1>` for the variant-permissive
        // `bech32::decode` would silently accept Bech32m strings —
        // Bech32 (TARGET_RESIDUE = 1) and Bech32m (TARGET_RESIDUE =
        // 0x2bc830a3) are mutually distinguishable, and confusing them
        // downstream is exactly the variant-confusion bug `Bech32V1` is
        // here to prevent.
        let key = x25519_key();
        let cs = compute_checksum(PUBLIC_KEY_VERSION, "x25519", &key);
        let mut data = Vec::new();
        data.push(PUBLIC_KEY_VERSION);
        data.extend_from_slice(&6u16.to_be_bytes());
        data.extend_from_slice(&32u32.to_be_bytes());
        data.extend_from_slice(b"x25519");
        data.extend_from_slice(&key);
        data.extend_from_slice(&cs);
        let bech32m = bech32::encode::<bech32::Bech32m>(RECIPIENT_HRP, &data).unwrap();
        match decode_recipient_string(&bech32m, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey for Bech32m, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_non_utf8_type_name_bytes() {
        // The Bech32 alphabet is ASCII, but data bytes inside the typed
        // payload (after the 5-to-8 expansion) can be arbitrary.
        // Non-UTF-8 type_name bytes must surface as `MalformedTypeName`
        // via `std::str::from_utf8`, not silently flow into
        // `validate_type_name_grammar` (which expects `&str`).
        let mut data = Vec::new();
        data.push(PUBLIC_KEY_VERSION);
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
        // grammar so validate_type_name_grammar still passes), re-encode at
        // the Bech32 layer with a fresh outer checksum. The inner
        // SHA3-256 checksum, computed from the *original* type_name,
        // will not match the modified type_name → MalformedPublicKey.
        let key = x25519_key();
        let original = encode_recipient_string("x25519", &key).unwrap();
        let checked = CheckedHrpstring::new::<Bech32>(&original).unwrap();
        let mut data: Vec<u8> = checked.byte_iter().collect();
        // type_name starts at offset PAYLOAD_HEADER_SIZE (= 7 = version
        // byte + type_name_len + key_material_len). Original byte is 'x'
        // (0x78). Flip bit 0 to get 'y' (0x79).
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
        data.push(PUBLIC_KEY_VERSION);
        data.extend_from_slice(&0u16.to_be_bytes()); // type_name_len = 0
        data.extend_from_slice(&0u32.to_be_bytes()); // key_material_len = 0
        data.extend_from_slice(&[0u8; PUBLIC_KEY_CHECKSUM_SIZE]);
        let s = bech32::encode::<Bech32>(RECIPIENT_HRP, &data).unwrap();
        match decode_recipient_string(&s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey for zero type_name_len, got {other:?}"),
        }
    }

    /// `type_name_len > TYPE_NAME_MAX_LEN` is rejected by the structural
    /// length check before any UTF-8 / grammar work.
    #[test]
    fn decode_rejects_overlong_type_name_len() {
        let mut data = Vec::new();
        data.push(PUBLIC_KEY_VERSION);
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
        data.push(PUBLIC_KEY_VERSION);
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
        // expected total = 7 + 6 + 32 + 16 = 61. Provide 61 + 1 bytes.
        let mut data = Vec::new();
        data.push(PUBLIC_KEY_VERSION);
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
        // validate_type_name_grammar (uppercase). Compute the inner checksum
        // for "X25519" first so the only thing left to fail is grammar.
        let key = x25519_key();
        let cs = compute_checksum(PUBLIC_KEY_VERSION, "X25519", &key);
        let mut data = Vec::new();
        data.push(PUBLIC_KEY_VERSION);
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
        // Same key bytes under different type_names must produce
        // different fingerprints. Catches a regression where the
        // type_name input is silently ignored.
        let key = x25519_key();
        let a = fingerprint_bytes("x25519", &key);
        let b = fingerprint_bytes("y25519", &key);
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_is_independent_of_checksum_domain() {
        // The fingerprint hash must not include the checksum domain
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
        // The derived `KEY_MATERIAL_LEN_MAX` must be such that a
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
        // And one byte more on the key must be rejected at our
        // structural layer (before bech32 ever runs).
        let one_too_big = vec![0u8; (KEY_MATERIAL_LEN_MAX as usize) + 1];
        match encode_recipient_string(&big_type_name, &one_too_big) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey for key_material > cap, got {other:?}"),
        }
    }

    /// Spec/code agreement pin: `FORMAT.md` §7 specifies the structural
    /// `key_material_len` cap as `12,215`, derived from the 20,000-char
    /// recipient-string ceiling, the 7-byte typed-payload header, the
    /// 16-byte internal checksum, and the 255-byte max `type_name`. If
    /// any upstream constant moves and the const-fn derivation changes,
    /// either FORMAT.md §7 must be updated alongside it or this test
    /// fails — preventing silent drift between the spec text and the
    /// implementation's enforced cap.
    #[test]
    fn key_material_len_max_matches_spec_text() {
        assert_eq!(KEY_MATERIAL_LEN_MAX, 12_215);
    }

    /// Pin the structural ingress reject for the all-zero X25519 public
    /// key. Three paths exist for materialising a `PublicKey` (raw
    /// bytes, Bech32 string, on-disk file); each must reject the
    /// degenerate value at construction so a downstream consumer
    /// cannot inherit it. The ECDH-time check inside
    /// [`crate::recipient::x25519::wrap`] / `unwrap` remains as
    /// defense-in-depth for other small-order points.
    #[test]
    fn public_key_from_bytes_rejects_all_zero() {
        match PublicKey::from_bytes([0u8; 32]) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey for all-zero public_key, got {other:?}"),
        }
    }

    #[test]
    fn public_key_from_recipient_string_rejects_all_zero() {
        let s = encode_recipient_string(X25519_TYPE_NAME, &[0u8; 32]).unwrap();
        match PublicKey::from_recipient_string(&s) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => {
                panic!("expected MalformedPublicKey for all-zero recipient string, got {other:?}")
            }
        }
    }

    #[test]
    fn read_public_key_rejects_all_zero_on_disk() {
        let s = encode_recipient_string(X25519_TYPE_NAME, &[0u8; 32]).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), s.as_bytes()).unwrap();
        match read_public_key(tmp.path()) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => {
                panic!("expected MalformedPublicKey for all-zero on-disk public key, got {other:?}")
            }
        }
    }

    /// A high-bit alias is a non-canonical RFC 7748 encoding of a valid
    /// key. Every ingress must reject it (`FORMAT.md` §2.4 / §7) so one
    /// curve point cannot acquire a second recipient string or
    /// fingerprint, and so encryption cannot bind bytes the matching
    /// private key would never reproduce.
    #[test]
    fn public_key_ingress_rejects_non_canonical_alias() {
        let mut alias = x25519_key();
        alias[31] |= 0x80;

        match PublicKey::from_bytes(alias) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("from_bytes must reject a non-canonical alias, got {other:?}"),
        }

        let s = encode_recipient_string(X25519_TYPE_NAME, &alias).unwrap();
        match PublicKey::from_recipient_string(&s) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => {
                panic!("from_recipient_string must reject a non-canonical alias, got {other:?}")
            }
        }

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), s.as_bytes()).unwrap();
        match read_public_key(tmp.path()) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("read_public_key must reject a non-canonical alias, got {other:?}"),
        }
    }

    /// `PublicKey::from_bytes` carries no suite marker on the input, so
    /// it must tag the resulting value with the current writer suite
    /// (`WRITER_KEYPAIR_SUITE`, crate-internal). This pins audit finding 2:
    /// a future build that drops an older suite cannot use raw bytes to create
    /// a `PublicKey` for the dropped suite; every `from_bytes` value tags as
    /// the writer.
    #[test]
    fn from_bytes_pins_writer_keypair_suite() {
        let pk = PublicKey::from_bytes(x25519_key()).unwrap();
        let resolved = pk.resolve().unwrap();
        assert_eq!(resolved.suite, WRITER_KEYPAIR_SUITE);
        assert_eq!(resolved.bytes, x25519_key());
    }

    /// `PublicKey::from_recipient_string` recovers the keypair suite
    /// from the wire-version byte of the input string and stores it on
    /// the resulting value. Re-encoding via
    /// `PublicKey::to_recipient_string` emits the original suite's
    /// wire-version byte — today V1 == writer so the round-trip is
    /// byte-identical, but the structural pin guarantees a future V2
    /// build that still supports V1 will not silently reserialize V1
    /// strings as V2. Closes audit finding 3.
    ///
    /// Sources the input via `encode_recipient_string_for_suite` with
    /// an explicit `KeypairSuite::V1` so the test pins V1-round-trips-V1
    /// regardless of which suite is `WRITER_KEYPAIR_SUITE` in a future
    /// build. Sourcing from the writer-default `encode_recipient_string`
    /// would collapse to "writer-round-trips-writer" today and fail
    /// with a misleading assertion in a V2 build that still supports V1.
    #[test]
    fn from_recipient_string_preserves_suite_in_round_trip() {
        let key = x25519_key();
        let original =
            encode_recipient_string_for_suite(KeypairSuite::V1, X25519_TYPE_NAME, &key).unwrap();
        let pk = PublicKey::from_recipient_string(&original).unwrap();
        let resolved = pk.resolve().unwrap();
        assert_eq!(resolved.suite, KeypairSuite::V1);
        assert_eq!(resolved.bytes, key);
        let re_encoded = pk.to_recipient_string().unwrap();
        assert_eq!(re_encoded, original);
    }

    /// Accepts canonical content with or without the optional trailing
    /// `LF`, and resolves both forms identically. Key generation writes
    /// the `LF` form, so losing either arm would make the reader reject
    /// the writer's own output.
    #[test]
    fn parse_public_key_file_accepts_optional_trailing_newline() {
        let key = x25519_key();
        let recipient = encode_recipient_string(X25519_TYPE_NAME, &key).unwrap();
        let bare = parse_public_key_file_bytes(recipient.as_bytes()).unwrap();
        let with_newline =
            parse_public_key_file_bytes(format!("{recipient}\n").as_bytes()).unwrap();
        assert_eq!(bare.bytes, key);
        assert_eq!(with_newline.bytes, key);
        assert_eq!(bare.suite, with_newline.suite);
    }

    /// Rejects ASCII whitespace other than the single optional trailing
    /// `LF`, including CRLF line endings.
    #[test]
    fn parse_public_key_file_rejects_non_canonical_whitespace() {
        let recipient = encode_recipient_string(X25519_TYPE_NAME, &x25519_key()).unwrap();
        let cases = [
            format!(" {recipient}"),
            format!("{recipient} "),
            format!("{recipient}\t"),
            format!("{recipient}\r\n"),
            format!("{recipient}\n\n"),
            format!("\n{recipient}\n"),
            format!("{}\n", recipient.replace("fcr1", "fcr1 ")),
        ];
        for content in cases {
            match parse_public_key_file_bytes(content.as_bytes()) {
                Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
                other => panic!("expected MalformedPublicKey for {content:?}, got {other:?}"),
            }
        }
    }

    /// Rejects empty content as a malformed public key.
    #[test]
    fn parse_public_key_file_rejects_empty_content() {
        match parse_public_key_file_bytes(b"") {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPublicKey)) => {}
            other => panic!("expected MalformedPublicKey for empty content, got {other:?}"),
        }
    }

    /// Routes a binary `private.key` to the wrong-kind diagnostic
    /// instead of the UTF-8 decode error its bytes would otherwise
    /// produce.
    #[test]
    fn parse_public_key_file_rejects_private_key_bytes() {
        let private_key = b"FCR\0\x01K\x00\x00\x00\x06";
        match parse_public_key_file_bytes(private_key) {
            Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType)) => {}
            other => panic!("expected WrongKeyFileType for private.key bytes, got {other:?}"),
        }
    }

    /// Classifies unrelated non-UTF-8 bytes as not a key file.
    #[test]
    fn parse_public_key_file_rejects_non_utf8_content() {
        match parse_public_key_file_bytes(&[0xFF, 0xFE, 0x00, 0x80]) {
            Err(CryptoError::InvalidFormat(FormatDefect::NotAKeyFile)) => {}
            other => panic!("expected NotAKeyFile for non-UTF-8 content, got {other:?}"),
        }
    }

    /// A valid recipient of an unknown key type is the planned
    /// forward-compatibility case from `FORMAT.md` §11, so the file and
    /// string surfaces both report `UnsupportedKeyType` naming the
    /// type, never a malformed-input class.
    #[test]
    fn parse_public_key_file_rejects_non_x25519_recipient() {
        let recipient = encode_recipient_string("future", &[0x11u8; 32]).unwrap();
        match parse_public_key_file_bytes(recipient.as_bytes()) {
            Err(CryptoError::UnsupportedKeyType { type_name }) => {
                assert_eq!(type_name, "future");
            }
            other => panic!("expected UnsupportedKeyType for non-X25519 type, got {other:?}"),
        }
        match decode_x25519_recipient(&recipient) {
            Err(CryptoError::UnsupportedKeyType { type_name }) => {
                assert_eq!(type_name, "future");
            }
            other => panic!("expected UnsupportedKeyType on the string surface, got {other:?}"),
        }
    }

    /// `read_public_key` (the on-disk reader behind
    /// `PublicKey::from_key_file`) preserves the recovered keypair
    /// suite alongside the 32 bytes, mirroring
    /// `from_recipient_string`'s suite-preservation rule for the file
    /// surface. Closes audit finding 3 for the on-disk path. Sources
    /// the on-disk string via the suite-explicit encoder for the same
    /// future-build robustness as
    /// `from_recipient_string_preserves_suite_in_round_trip`.
    #[test]
    fn read_public_key_preserves_keypair_suite() {
        let key = x25519_key();
        let s =
            encode_recipient_string_for_suite(KeypairSuite::V1, X25519_TYPE_NAME, &key).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), s.as_bytes()).unwrap();
        let resolved = read_public_key(tmp.path()).unwrap();
        assert_eq!(resolved.suite, KeypairSuite::V1);
        assert_eq!(resolved.bytes, key);
    }

    /// `to_recipient_string` for a `from_bytes`-built `PublicKey`
    /// emits the writer suite's wire-version byte at offset 0. Pairs
    /// with `from_bytes_pins_writer_keypair_suite` to lock in the rule
    /// that raw-bytes ingress always re-emits as the current writer.
    #[test]
    fn from_bytes_to_recipient_string_uses_writer_suite_wire_byte() {
        let pk = PublicKey::from_bytes(x25519_key()).unwrap();
        let s = pk.to_recipient_string().unwrap();
        let decoded = decode_recipient_string(&s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(decoded.keypair_suite, WRITER_KEYPAIR_SUITE);
    }

    /// Cross-suite encode pin: `encode_recipient_string_for_suite`
    /// emits the supplied suite's wire-version byte at offset 0, not
    /// the current writer's. Today both arms collapse to V1, but the
    /// structural pin guards against a future regression that quietly
    /// hard-codes `WRITER_KEYPAIR_SUITE` inside the suite-explicit
    /// helper.
    #[test]
    fn encode_recipient_string_for_suite_emits_supplied_suite() {
        let key = x25519_key();
        let s =
            encode_recipient_string_for_suite(KeypairSuite::V1, X25519_TYPE_NAME, &key).unwrap();
        let decoded = decode_recipient_string(&s, RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(decoded.keypair_suite, KeypairSuite::V1);
    }
}
