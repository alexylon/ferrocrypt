//! Generic recipient-entry framing per `FORMAT.md` §3.3.
//!
//! Wire shape:
//!
//! ```text
//! type_name_len:u16 || recipient_flags:u16 || body_len:u32
//!                   || type_name:N || body:M
//! ```
//!
//! This module owns the 8-byte header parsing, structural bounds,
//! reserved-flag-bit enforcement, type-name grammar dispatch, and the
//! local body-size resource cap. The body itself is opaque to this
//! layer; per-recipient modules in [`crate::recipient::native`] parse
//! and operate on body bytes.

use crate::CryptoError;
use crate::error::FormatDefect;
use crate::format::{BODY_LEN_MAX, read_u16_be, read_u32_be};
use crate::recipient::name::{TYPE_NAME_MAX_LEN, validate_type_name};
use crate::recipient::policy::NativeRecipientType;

/// On-wire size of a recipient-entry header (`type_name_len:u16 ||
/// recipient_flags:u16 || body_len:u32`), per `FORMAT.md` §3.3.
pub const ENTRY_HEADER_SIZE: usize = 8;

const ENTRY_TYPE_NAME_LEN_OFFSET: usize = 0;
const ENTRY_RECIPIENT_FLAGS_OFFSET: usize = ENTRY_TYPE_NAME_LEN_OFFSET + size_of::<u16>();
const ENTRY_BODY_LEN_OFFSET: usize = ENTRY_RECIPIENT_FLAGS_OFFSET + size_of::<u16>();
const _: () = assert!(ENTRY_BODY_LEN_OFFSET + size_of::<u32>() == ENTRY_HEADER_SIZE);

/// Bit 0 of `recipient_flags`. When set, an unknown recipient type
/// MUST cause file rejection (`FORMAT.md` §3.4); when clear, an unknown
/// recipient is skipped.
pub const RECIPIENT_FLAG_CRITICAL: u16 = 1 << 0;

/// Mask of all `recipient_flags` bits other than
/// [`RECIPIENT_FLAG_CRITICAL`]. Per `FORMAT.md` §3.5, these MUST be
/// zero on the wire; readers reject any entry with a reserved bit set.
pub const RECIPIENT_FLAGS_RESERVED_MASK: u16 = !RECIPIENT_FLAG_CRITICAL;

/// Recipient body bytes plus their declared scheme `type_name`. The
/// type produced by [`crate::protocol::RecipientScheme::wrap_file_key`]
/// and consumed by [`crate::protocol::IdentityScheme::unwrap_file_key`]
/// — schemes never construct or parse full recipient entries; that is
/// `protocol.rs`'s responsibility.
#[derive(Debug, Clone)]
pub(crate) struct RecipientBody {
    pub type_name: &'static str,
    pub bytes: Vec<u8>,
}

/// A parsed recipient entry per `FORMAT.md` §3.3. Owns its
/// `type_name` (validated against the §3.3 grammar) and `body` (opaque
/// to the framing layer; per-recipient modules parse the body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientEntry {
    /// Canonical recipient `type_name`, e.g. `"argon2id"` or `"x25519"`.
    pub type_name: String,
    /// `recipient_flags` field as stored on the wire. The only defined
    /// bit in v1 is [`RECIPIENT_FLAG_CRITICAL`]; reserved bits are
    /// rejected at parse time.
    pub recipient_flags: u16,
    /// Recipient body bytes. Length matches the on-wire `body_len`
    /// field; structural bounds and the local resource cap are checked
    /// at parse time.
    pub body: Vec<u8>,
}

impl RecipientEntry {
    /// Constructs a `RecipientEntry` for a native v1 recipient type
    /// from a body produced by the corresponding per-recipient `wrap`
    /// helper (e.g. [`crate::recipient::native::argon2id::wrap`] or
    /// [`crate::recipient::native::x25519::wrap`]).
    ///
    /// The `type_name` is taken from the `NativeRecipientType` so
    /// callers cannot accidentally construct an entry with a typo'd
    /// or off-spec name. The body length is checked against the
    /// type's expected `body_len()`. Native entries default to
    /// `recipient_flags = 0` (non-critical); critical bit is reserved
    /// for plugin / opt-in semantics that v1 native types do not use.
    pub fn native(ty: NativeRecipientType, body: Vec<u8>) -> Result<Self, CryptoError> {
        if body.len() != ty.body_len() {
            return Err(CryptoError::InvalidFormat(
                FormatDefect::MalformedRecipientEntry,
            ));
        }
        Ok(Self {
            type_name: ty.type_name().to_owned(),
            recipient_flags: 0,
            body,
        })
    }

    /// Returns `true` if [`RECIPIENT_FLAG_CRITICAL`] is set. Per
    /// `FORMAT.md` §3.4, unknown critical entries MUST cause file
    /// rejection; unknown non-critical entries are skipped.
    pub const fn is_critical(&self) -> bool {
        (self.recipient_flags & RECIPIENT_FLAG_CRITICAL) != 0
    }

    /// Serialises this entry as `type_name_len(2) || recipient_flags(2)
    /// || body_len(4) || type_name || body`. Casts assume the entry was
    /// constructed from a valid native call site (`type_name.len() <=
    /// TYPE_NAME_MAX_LEN`, `body.len() <= BODY_LEN_MAX as usize`),
    /// which holds for every native call path in this crate.
    pub fn to_bytes(&self) -> Vec<u8> {
        let type_name_len = self.type_name.len();
        let body_len = self.body.len();
        let mut out = Vec::with_capacity(ENTRY_HEADER_SIZE + type_name_len + body_len);
        out.extend_from_slice(&(type_name_len as u16).to_be_bytes());
        out.extend_from_slice(&self.recipient_flags.to_be_bytes());
        out.extend_from_slice(&(body_len as u32).to_be_bytes());
        out.extend_from_slice(self.type_name.as_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    /// Parses one recipient entry from the start of `bytes`. Returns
    /// the parsed entry and the number of bytes consumed
    /// (`ENTRY_HEADER_SIZE + type_name_len + body_len`).
    ///
    /// Validates per `FORMAT.md` §3.3 and §3.4 in cheap-to-expensive order:
    /// header is large enough, length fields are in range, reserved
    /// flag bits are zero, body is within the local resource cap, the
    /// declared total fits in `bytes`, and the `type_name` satisfies
    /// the §3.3 grammar.
    pub fn parse_one(bytes: &[u8], local_body_cap: u32) -> Result<(Self, usize), CryptoError> {
        let malformed = || CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry);
        if bytes.len() < ENTRY_HEADER_SIZE {
            return Err(malformed());
        }
        let type_name_len = read_u16_be(bytes, ENTRY_TYPE_NAME_LEN_OFFSET);
        let recipient_flags = read_u16_be(bytes, ENTRY_RECIPIENT_FLAGS_OFFSET);
        let body_len = read_u32_be(bytes, ENTRY_BODY_LEN_OFFSET);

        if type_name_len == 0 || type_name_len as usize > TYPE_NAME_MAX_LEN {
            return Err(malformed());
        }
        if body_len > BODY_LEN_MAX {
            return Err(malformed());
        }
        if (recipient_flags & RECIPIENT_FLAGS_RESERVED_MASK) != 0 {
            return Err(CryptoError::InvalidFormat(
                FormatDefect::RecipientFlagsReserved,
            ));
        }
        if body_len > local_body_cap {
            return Err(CryptoError::RecipientBodyCapExceeded {
                body_len,
                local_cap: local_body_cap,
            });
        }

        let type_name_end = ENTRY_HEADER_SIZE
            .checked_add(type_name_len as usize)
            .ok_or_else(malformed)?;
        let total = type_name_end
            .checked_add(body_len as usize)
            .ok_or_else(malformed)?;
        if bytes.len() < total {
            return Err(malformed());
        }

        let type_name_bytes = &bytes[ENTRY_HEADER_SIZE..type_name_end];
        let type_name = std::str::from_utf8(type_name_bytes)
            .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedTypeName))?;
        validate_type_name(type_name)?;

        let body = bytes[type_name_end..total].to_vec();

        Ok((
            Self {
                type_name: type_name.to_owned(),
                recipient_flags,
                body,
            },
            total,
        ))
    }
}

/// Parses a contiguous `recipient_entries` region containing exactly
/// `expected_count` entries. The region length MUST equal the sum of
/// per-entry sizes — trailing or unaccounted bytes surface as
/// [`FormatDefect::MalformedRecipientEntry`].
///
/// `local_body_cap` is forwarded to each [`RecipientEntry::parse_one`]
/// call. Per `FORMAT.md` §3.2, the local cap applies to every entry,
/// including unknown entries that will later be skipped, so an
/// attacker-supplied unknown entry cannot DoS a reader that "skips" it.
pub fn parse_recipient_entries(
    region: &[u8],
    expected_count: u16,
    local_body_cap: u32,
) -> Result<Vec<RecipientEntry>, CryptoError> {
    let mut entries = Vec::with_capacity(expected_count as usize);
    let mut offset = 0usize;
    for _ in 0..expected_count {
        let (entry, consumed) = RecipientEntry::parse_one(&region[offset..], local_body_cap)?;
        entries.push(entry);
        offset += consumed;
    }
    if offset != region.len() {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedRecipientEntry,
        ));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::BODY_LEN_LOCAL_CAP_DEFAULT;
    use crate::recipient::native::{argon2id, x25519};

    /// Builds a raw 8-byte entry header so tests can inject arbitrary
    /// out-of-spec values without going through `RecipientEntry::to_bytes`.
    fn entry_header(type_name_len: u16, recipient_flags: u16, body_len: u32) -> [u8; 8] {
        let mut hdr = [0u8; ENTRY_HEADER_SIZE];
        hdr[0..2].copy_from_slice(&type_name_len.to_be_bytes());
        hdr[2..4].copy_from_slice(&recipient_flags.to_be_bytes());
        hdr[4..8].copy_from_slice(&body_len.to_be_bytes());
        hdr
    }

    #[test]
    fn recipient_entry_round_trips_minimal_x25519() {
        let entry = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_owned(),
            recipient_flags: 0,
            body: vec![0xAB; x25519::BODY_LENGTH],
        };
        let bytes = entry.to_bytes();
        let (parsed, consumed) =
            RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed, entry);
        assert!(!parsed.is_critical());
    }

    #[test]
    fn recipient_entry_round_trips_with_critical_flag() {
        let entry = RecipientEntry {
            type_name: argon2id::TYPE_NAME.to_owned(),
            recipient_flags: RECIPIENT_FLAG_CRITICAL,
            body: vec![0u8; argon2id::BODY_LENGTH],
        };
        let bytes = entry.to_bytes();
        let (parsed, _) = RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(parsed, entry);
        assert!(parsed.is_critical());
    }

    #[test]
    fn recipient_entry_to_bytes_layout_matches_spec() {
        let entry = RecipientEntry {
            type_name: "x25519".to_owned(),
            recipient_flags: RECIPIENT_FLAG_CRITICAL,
            body: vec![0xCD, 0xEF],
        };
        let bytes = entry.to_bytes();
        // type_name_len = 6
        assert_eq!(&bytes[0..2], &6u16.to_be_bytes());
        // recipient_flags = 1
        assert_eq!(&bytes[2..4], &1u16.to_be_bytes());
        // body_len = 2
        assert_eq!(&bytes[4..8], &2u32.to_be_bytes());
        // type_name bytes
        assert_eq!(&bytes[8..14], b"x25519");
        // body bytes
        assert_eq!(&bytes[14..16], &[0xCD, 0xEF]);
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn parse_one_rejects_truncated_header() {
        let bytes = [0u8; ENTRY_HEADER_SIZE - 1];
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => panic!("expected MalformedRecipientEntry for short header, got {other:?}"),
        }
    }

    #[test]
    fn parse_one_rejects_zero_type_name_len() {
        let bytes = entry_header(0, 0, 0);
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => {
                panic!("expected MalformedRecipientEntry for zero type_name_len, got {other:?}")
            }
        }
    }

    #[test]
    fn parse_one_rejects_overlong_type_name_len() {
        let bytes = entry_header((TYPE_NAME_MAX_LEN as u16) + 1, 0, 0);
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => {
                panic!("expected MalformedRecipientEntry for type_name_len=256, got {other:?}")
            }
        }
    }

    #[test]
    fn parse_one_rejects_body_above_structural_max() {
        // body_len = BODY_LEN_MAX + 1 must reject before any allocation
        // — local_body_cap = u32::MAX so the cap check cannot fire.
        let bytes = entry_header(6, 0, BODY_LEN_MAX + 1);
        match RecipientEntry::parse_one(&bytes, u32::MAX) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => panic!(
                "expected MalformedRecipientEntry for body_len > BODY_LEN_MAX, got {other:?}"
            ),
        }
    }

    #[test]
    fn parse_one_rejects_body_above_local_cap() {
        let oversized = BODY_LEN_LOCAL_CAP_DEFAULT + 1;
        let bytes = entry_header(6, 0, oversized);
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::RecipientBodyCapExceeded {
                body_len,
                local_cap,
            }) => {
                assert_eq!(body_len, oversized);
                assert_eq!(local_cap, BODY_LEN_LOCAL_CAP_DEFAULT);
            }
            other => panic!("expected RecipientBodyCapExceeded, got {other:?}"),
        }
    }

    #[test]
    fn parse_one_rejects_reserved_flag_bits() {
        // Bit 1 is reserved per FORMAT.md §3.5.
        let bytes = entry_header(6, 1u16 << 1, 0);
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::RecipientFlagsReserved)) => {}
            other => panic!("expected RecipientFlagsReserved, got {other:?}"),
        }
    }

    #[test]
    fn parse_one_rejects_each_reserved_bit() {
        // Every non-critical bit (1..=15) must be rejected individually.
        for bit in 1..16 {
            let bytes = entry_header(6, 1u16 << bit, 0);
            match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
                Err(CryptoError::InvalidFormat(FormatDefect::RecipientFlagsReserved)) => {}
                other => panic!("expected RecipientFlagsReserved for bit {bit}, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_one_rejects_entry_exceeding_remaining_bytes() {
        // Header claims 6-byte type_name + 100-byte body, but only the
        // header is provided.
        let bytes = entry_header(6, 0, 100);
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => panic!("expected MalformedRecipientEntry for entry > bytes, got {other:?}"),
        }
    }

    #[test]
    fn parse_one_rejects_malformed_type_name_grammar() {
        // Uppercase type_name violates the §3.3 grammar.
        let mut bytes = entry_header(6, 0, 0).to_vec();
        bytes.extend_from_slice(b"X25519");
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for uppercase, got {other:?}"),
        }
    }

    #[test]
    fn parse_one_rejects_non_utf8_type_name() {
        let mut bytes = entry_header(6, 0, 0).to_vec();
        bytes.extend_from_slice(&[0xFF; 6]);
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for non-UTF8, got {other:?}"),
        }
    }

    #[test]
    fn parse_one_accepts_zero_body_len() {
        // Body length zero is structurally valid at the framing layer;
        // recipient modules enforce their own body-size invariants.
        let mut bytes = entry_header(6, 0, 0).to_vec();
        bytes.extend_from_slice(b"x25519");
        let (parsed, consumed) =
            RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.type_name, "x25519");
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn parse_one_consumes_only_declared_extent() {
        // When extra trailing bytes exist after the declared entry, the
        // parser returns the consumed length; trailing data is the
        // multi-entry parser's concern.
        let entry = RecipientEntry {
            type_name: "x25519".to_owned(),
            recipient_flags: 0,
            body: vec![0xAA, 0xBB],
        };
        let mut bytes = entry.to_bytes();
        let original_len = bytes.len();
        bytes.extend_from_slice(b"trailing");
        let (parsed, consumed) =
            RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(consumed, original_len);
        assert_eq!(parsed, entry);
    }

    #[test]
    fn parse_recipient_entries_handles_zero_count_empty_region() {
        let parsed = parse_recipient_entries(&[], 0, BODY_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_recipient_entries_rejects_zero_count_with_trailing_bytes() {
        let bytes = [0u8; 4];
        match parse_recipient_entries(&bytes, 0, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => panic!("expected MalformedRecipientEntry, got {other:?}"),
        }
    }

    #[test]
    fn parse_recipient_entries_handles_single() {
        let entry = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_owned(),
            recipient_flags: 0,
            body: vec![0xCD; x25519::BODY_LENGTH],
        };
        let bytes = entry.to_bytes();
        let parsed = parse_recipient_entries(&bytes, 1, BODY_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(parsed, vec![entry]);
    }

    #[test]
    fn parse_recipient_entries_handles_multiple() {
        let e1 = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_owned(),
            recipient_flags: 0,
            body: vec![0xAB; x25519::BODY_LENGTH],
        };
        let e2 = RecipientEntry {
            type_name: argon2id::TYPE_NAME.to_owned(),
            recipient_flags: RECIPIENT_FLAG_CRITICAL,
            body: vec![0xCD; argon2id::BODY_LENGTH],
        };
        let mut bytes = e1.to_bytes();
        bytes.extend(e2.to_bytes());
        let parsed = parse_recipient_entries(&bytes, 2, BODY_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(parsed, vec![e1, e2]);
    }

    #[test]
    fn parse_recipient_entries_rejects_count_below_actual_entries() {
        // Region contains 2 entries' worth of bytes, but caller claims 1.
        let e1 = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_owned(),
            recipient_flags: 0,
            body: vec![0xAB; x25519::BODY_LENGTH],
        };
        let e2 = RecipientEntry {
            type_name: argon2id::TYPE_NAME.to_owned(),
            recipient_flags: 0,
            body: vec![0xCD; argon2id::BODY_LENGTH],
        };
        let mut bytes = e1.to_bytes();
        bytes.extend(e2.to_bytes());
        match parse_recipient_entries(&bytes, 1, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => {
                panic!("expected MalformedRecipientEntry for trailing entry bytes, got {other:?}")
            }
        }
    }

    #[test]
    fn parse_recipient_entries_rejects_count_above_actual_entries() {
        // Region contains 1 entry but caller claims 2.
        let entry = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_owned(),
            recipient_flags: 0,
            body: vec![0xAB; x25519::BODY_LENGTH],
        };
        let bytes = entry.to_bytes();
        match parse_recipient_entries(&bytes, 2, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => panic!("expected MalformedRecipientEntry for missing entries, got {other:?}"),
        }
    }

    #[test]
    fn parse_recipient_entries_propagates_per_entry_resource_cap() {
        // The cap applies to every entry, even ones the multi-entry
        // parser would otherwise skip past.
        let oversized = BODY_LEN_LOCAL_CAP_DEFAULT + 1;
        let mut bytes = entry_header(6, 0, oversized).to_vec();
        bytes.extend_from_slice(b"x25519");
        bytes.extend(std::iter::repeat_n(0u8, oversized as usize));
        match parse_recipient_entries(&bytes, 1, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::RecipientBodyCapExceeded { .. }) => {}
            other => panic!("expected RecipientBodyCapExceeded, got {other:?}"),
        }
    }

    #[test]
    fn parse_recipient_entries_handles_body_at_local_cap_boundary() {
        // body_len = local_cap is allowed (cap is inclusive).
        let cap = BODY_LEN_LOCAL_CAP_DEFAULT;
        let mut bytes = entry_header(6, 0, cap).to_vec();
        bytes.extend_from_slice(b"x25519");
        bytes.extend(std::iter::repeat_n(0xAAu8, cap as usize));
        let parsed = parse_recipient_entries(&bytes, 1, cap).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].body.len(), cap as usize);
    }

    #[test]
    fn parse_recipient_entries_propagates_structural_error_from_inner_entry() {
        // First entry parses cleanly; second has a reserved flag bit set.
        // The multi-entry parser MUST surface the inner error rather than
        // silently masking it as MalformedRecipientEntry.
        let e1 = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_owned(),
            recipient_flags: 0,
            body: vec![0xAB; x25519::BODY_LENGTH],
        };
        let mut bad_entry = entry_header(6, 1u16 << 1, 0).to_vec();
        bad_entry.extend_from_slice(b"x25519");
        let mut bytes = e1.to_bytes();
        bytes.extend(bad_entry);
        match parse_recipient_entries(&bytes, 2, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::RecipientFlagsReserved)) => {}
            other => panic!("expected RecipientFlagsReserved propagation, got {other:?}"),
        }
    }
}
