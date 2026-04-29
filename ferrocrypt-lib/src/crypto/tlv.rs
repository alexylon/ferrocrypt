//! Authenticated TLV grammar validator (`FORMAT.md` §6).
//!
//! Encrypted-file `ext_bytes` and `private.key` `ext_bytes` are both
//! validated through [`validate_tlv`]. TLV interpretation runs only
//! after the relevant authentication step — header MAC verify for
//! `.fcr`, AEAD-AAD for `private.key` — so the validator operates on
//! authenticated bytes.

use crate::CryptoError;
use crate::error::FormatDefect;
use crate::format::{EXT_LEN_MAX, read_u16_be, read_u32_be};

/// Validates the TLV extension region per FORMAT.md §6.
///
/// Per `FORMAT.md` §6, each entry is `tag(u16) || len(u32) || value`
/// (6-byte entry header, big-endian). Checks:
/// - each entry's `tag(u16) || len(u32)` fits within the region;
/// - `len` is authoritative (the entry's `value` does not extend past
///   the end of the region);
/// - declared `len` does not exceed the region cap (catches a
///   bogus 4-billion-byte length declaration before per-byte
///   accounting could underflow);
/// - tags appear in strictly ascending numeric order (rejects
///   duplicates by construction);
/// - no reserved tag (`0x0000`, `0x8000`) is emitted;
/// - no critical tag (`0x8001..=0xFFFF`) appears — v1.0 defines none,
///   so any critical tag is an upgrade-required signal.
///
/// Ignorable tags (`0x0001..=0x7FFF`) are accepted silently once
/// canonicity is verified; v1.0 writers emit an empty region so
/// callers don't yet need to extract tag values. Future v1.x releases
/// that define a known tag will extract its value by extending this
/// path or adding a sibling helper.
pub fn validate_tlv(ext_bytes: &[u8]) -> Result<(), CryptoError> {
    let region_len = u32::try_from(ext_bytes.len()).unwrap_or(u32::MAX);
    if region_len > EXT_LEN_MAX {
        return Err(CryptoError::InvalidFormat(FormatDefect::ExtTooLarge {
            len: region_len,
        }));
    }

    // Entry header = tag(u16) + len(u32) = 6 bytes.
    const ENTRY_HEADER_SIZE: usize = 6;

    let mut cursor = 0;
    let mut prev_tag: Option<u16> = None;
    while cursor < ext_bytes.len() {
        if ext_bytes.len() - cursor < ENTRY_HEADER_SIZE {
            return Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv));
        }
        let tag = read_u16_be(ext_bytes, cursor);
        let len = read_u32_be(ext_bytes, cursor + size_of::<u16>());
        cursor += ENTRY_HEADER_SIZE;

        if tag == 0x0000 || tag == 0x8000 {
            return Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv));
        }

        if let Some(prev) = prev_tag {
            if tag <= prev {
                return Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv));
            }
        }
        prev_tag = Some(tag);

        // Reject a declared `len` that exceeds the region cap before
        // converting to `usize`. The region cap is already enforced
        // above, so any per-entry length larger than that cannot fit;
        // catching it here gives a precise diagnostic and removes
        // any risk of integer-conversion edge cases on smaller
        // address-space targets.
        if len > EXT_LEN_MAX {
            return Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv));
        }
        let len = len as usize;
        if ext_bytes.len() - cursor < len {
            return Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv));
        }
        cursor += len;

        // Critical-range tag: v1.0 knows none, so reject.
        if tag & 0x8000 != 0 {
            return Err(CryptoError::InvalidFormat(
                FormatDefect::UnknownCriticalTag { tag },
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a single TLV entry `tag(u16) || len(u32) || value` per
    /// `FORMAT.md` §6. Callers concatenate results for multi-entry
    /// cases.
    fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + value.len());
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    #[test]
    fn validate_tlv_accepts_empty_region() {
        assert!(validate_tlv(&[]).is_ok());
    }

    #[test]
    fn validate_tlv_accepts_single_ignorable_tag() {
        let region = tlv(0x0001, &[0xAA; 8]);
        assert!(validate_tlv(&region).is_ok());
    }

    #[test]
    fn validate_tlv_accepts_zero_length_ignorable_tag() {
        let region = tlv(0x0001, &[]);
        assert!(validate_tlv(&region).is_ok());
    }

    #[test]
    fn validate_tlv_accepts_ascending_ignorable_tags() {
        let mut region = tlv(0x0001, &[0xAA]);
        region.extend_from_slice(&tlv(0x0002, &[0xBB; 3]));
        region.extend_from_slice(&tlv(0x7FFF, &[0xCC; 16]));
        assert!(validate_tlv(&region).is_ok());
    }

    #[test]
    fn validate_tlv_rejects_unknown_critical_tag() {
        let region = tlv(0x8001, &[0xAA; 4]);
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::UnknownCriticalTag { tag: 0x8001 })) => {}
            other => panic!("expected UnknownCriticalTag(0x8001), got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_reserved_tag_0x0000() {
        let region = tlv(0x0000, &[]);
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => {}
            other => panic!("expected MalformedTlv for 0x0000, got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_reserved_tag_0x8000() {
        let region = tlv(0x8000, &[]);
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => {}
            other => panic!("expected MalformedTlv for 0x8000, got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_descending_tags() {
        let mut region = tlv(0x0002, &[0xAA]);
        region.extend_from_slice(&tlv(0x0001, &[0xBB]));
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => {}
            other => panic!("expected MalformedTlv for descending, got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_duplicate_tags() {
        let mut region = tlv(0x0001, &[0xAA]);
        region.extend_from_slice(&tlv(0x0001, &[0xBB]));
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => {}
            other => panic!("expected MalformedTlv for duplicate, got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_len_past_end() {
        // tag=0x0001, len=100 but only 3 bytes of value follow.
        let mut region = Vec::new();
        region.extend_from_slice(&0x0001u16.to_be_bytes());
        region.extend_from_slice(&100u32.to_be_bytes());
        region.extend_from_slice(&[0xAA; 3]);
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => {}
            other => panic!("expected MalformedTlv for len-past-end, got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_truncated_entry_header() {
        // Only 5 bytes of TLV header (need at least 6 = tag(u16) + len(u32)).
        let region = vec![0x00, 0x01, 0x00, 0x00, 0x00];
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => {}
            other => panic!("expected MalformedTlv for truncated header, got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_len_above_region_cap() {
        // tag=0x0001, len=u32::MAX. Even though the on-disk region
        // is sized within `EXT_LEN_MAX`, a per-entry `len` field that
        // exceeds the cap must be rejected before integer
        // conversion to `usize`.
        let mut region = Vec::new();
        region.extend_from_slice(&0x0001u16.to_be_bytes());
        region.extend_from_slice(&u32::MAX.to_be_bytes());
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => {}
            other => panic!("expected MalformedTlv for len-over-cap, got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_region_over_cap() {
        // A region > 32 KiB is rejected structurally, before per-entry parsing.
        let region = vec![0u8; EXT_LEN_MAX as usize + 1];
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::ExtTooLarge { .. })) => {}
            other => panic!("expected ExtTooLarge, got {other:?}"),
        }
    }
}
