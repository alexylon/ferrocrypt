//! Authenticated TLV grammar validator (`FORMAT.md` §6).
//!
//! One TLV grammar covers four FerroCrypt extension regions:
//! encrypted-file header `ext_bytes`, `private.key` `ext_bytes`, FCA
//! `archive_ext`, and FCA per-entry `entry_ext`. Each region has its
//! own tag namespace and its own containing length field, but the
//! structural rules (`tag(u16) || len(u32) || value` framing,
//! strictly-ascending tags, reserved-tag rejection, region-bounded
//! `len`) are shared.
//!
//! Callers run TLV interpretation only after the relevant
//! authentication step — header MAC verify for `.fcr`, AEAD-AAD for
//! `private.key`, outer `.fcr` payload AEAD for FCA — so the validator
//! always operates on authenticated bytes.

use crate::CryptoError;
use crate::error::FormatDefect;
use crate::format::{EXT_LEN_MAX, read_u16_be, read_u32_be};

/// TLV tag classification per `FORMAT.md` §6. Cached on [`RawTlv`] at
/// scan time so validators don't recompute it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TlvClass {
    /// Tag in `0x0001..=0x7FFF`. Unknown ignorable tags are skipped.
    Ignorable,
    /// Tag in `0x8001..=0xFFFF`. Unknown critical tags reject.
    Critical,
}

/// One scanned TLV entry with its bytes borrowed from the source
/// region. `class` is cached at scan time so callers don't recompute
/// it. `value` is the raw bytes between the entry header and the next
/// entry (or end of region).
#[derive(Debug, Clone, Copy)]
pub(crate) struct RawTlv<'a> {
    pub(crate) tag: u16,
    pub(crate) class: TlvClass,
    // `value` is read only by tests at present; FCA archive- and
    // entry-level TLV consumers will read it in production once the
    // first known FCA TLV is defined. Until then, suppress the
    // dead-code lint rather than reshaping the type.
    #[allow(dead_code)]
    pub(crate) value: &'a [u8],
}

/// Classifies a TLV tag and rejects the two reserved values
/// (`0x0000`, `0x8000`). Pure function; no allocation.
///
/// Written as an if/else ladder rather than a `match` because
/// rust-analyzer's match-exhaustiveness checker mis-flags the
/// equivalent `match tag { 0x0000 | 0x8000 => …, 0x0001..=0x7FFF
/// => …, 0x8001..=0xFFFF => … }` form as non-exhaustive (rustc
/// accepts it, but rust-analyzer surfaces a false-positive E0004).
/// The ladder is functionally identical and lints clean in both.
pub(crate) fn classify_tlv_tag(tag: u16) -> Result<TlvClass, CryptoError> {
    if tag == 0x0000 || tag == 0x8000 {
        Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv))
    } else if tag < 0x8000 {
        Ok(TlvClass::Ignorable)
    } else {
        Ok(TlvClass::Critical)
    }
}

/// TLV entry header size: `tag(u16) || len(u32) = 6` bytes.
const ENTRY_HEADER_SIZE: usize = 6;

/// Scans a TLV region into [`RawTlv`] entries with full canonicality
/// checks: each entry header fits, declared `len` fits in the region
/// and `<= max_value_len`, tags strictly ascending (rejects duplicates
/// by construction), reserved tags rejected. Does NOT enforce a
/// per-region critical-tag policy — the caller decides whether to
/// reject unknown criticals (see [`reject_unknown_critical`]).
///
/// `max_region_len` and `max_value_len` are passed by the caller so
/// each containing region (FCR header `ext_bytes`, FCA `archive_ext`,
/// FCA `entry_ext`, etc.) can apply its own caps.
pub(crate) fn scan_tlv_region(
    bytes: &[u8],
    max_region_len: u32,
    max_value_len: u32,
) -> Result<Vec<RawTlv<'_>>, CryptoError> {
    let region_len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    if region_len > max_region_len {
        return Err(CryptoError::InvalidFormat(FormatDefect::ExtTooLarge {
            len: region_len,
        }));
    }

    let mut out = Vec::new();
    let mut cursor = 0;
    let mut prev_tag: Option<u16> = None;

    while cursor < bytes.len() {
        if bytes.len() - cursor < ENTRY_HEADER_SIZE {
            return Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv));
        }
        let tag = read_u16_be(bytes, cursor)?;
        let len = read_u32_be(bytes, cursor + size_of::<u16>())?;
        cursor += ENTRY_HEADER_SIZE;

        let class = classify_tlv_tag(tag)?;

        if let Some(prev) = prev_tag {
            if tag <= prev {
                return Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv));
            }
        }
        prev_tag = Some(tag);

        // Reject a declared `len` larger than the per-value cap before
        // converting to `usize`. Catches a bogus 4-billion-byte length
        // declaration with a precise diagnostic and removes any risk
        // of integer-conversion edge cases on smaller address-space
        // targets.
        if len > max_value_len {
            return Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv));
        }
        let len = len as usize;
        if bytes.len() - cursor < len {
            return Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv));
        }

        out.push(RawTlv {
            tag,
            class,
            value: &bytes[cursor..cursor + len],
        });
        cursor += len;
    }

    Ok(out)
}

/// Rejects any [`TlvClass::Critical`] entry with
/// [`FormatDefect::UnknownCriticalTag`]. Used by every v1.0 caller
/// because v1.0 defines no known critical tags in any region. Future
/// versions that define known criticals will iterate the scanned TLVs
/// against a registry instead of using this blanket helper.
pub(crate) fn reject_unknown_critical(tlvs: &[RawTlv<'_>]) -> Result<(), CryptoError> {
    for tlv in tlvs {
        if matches!(tlv.class, TlvClass::Critical) {
            return Err(CryptoError::InvalidFormat(
                FormatDefect::UnknownCriticalTag { tag: tlv.tag },
            ));
        }
    }
    Ok(())
}

/// Scans a TLV region with caller-supplied caps and applies the v1.0
/// no-known-critical policy in one call: every critical-range tag is
/// rejected. Used by every v1.0 caller (FCR header, `private.key`,
/// FCA `archive_ext`, FCA `entry_ext`) since v1.0 defines no known
/// critical tags in any region. Returns nothing — callers that need
/// the parsed entries for value extraction should use
/// [`scan_tlv_region`] directly.
pub(crate) fn validate_no_known_critical(
    bytes: &[u8],
    max_region_len: u32,
    max_value_len: u32,
) -> Result<(), CryptoError> {
    let tlvs = scan_tlv_region(bytes, max_region_len, max_value_len)?;
    reject_unknown_critical(&tlvs)
}

/// Validates a TLV extension region per FORMAT.md §6 with the
/// encrypted-file header policy: region cap = `EXT_LEN_MAX`,
/// per-value cap = `EXT_LEN_MAX`, every critical tag rejects (v1.0
/// defines no known criticals).
///
/// Used by FCR header `ext_bytes` and `private.key` `ext_bytes`.
/// FCA archive- and entry-level extension regions call the
/// crate-internal `validate_no_known_critical` with their own caps.
pub fn validate_tlv(ext_bytes: &[u8]) -> Result<(), CryptoError> {
    validate_no_known_critical(ext_bytes, EXT_LEN_MAX, EXT_LEN_MAX)
}

/// Builds the on-wire bytes for a single TLV entry
/// (`tag(u16) || len(u32) || value`) per `FORMAT.md` §6. Test-only
/// shared helper so `crypto::tlv::tests`, `archive::format::tests`,
/// and `archive::decode::tests` don't each hand-roll the same byte
/// sequence (e.g. `[0x00, 0x01, 0x00, 0x00, 0x00, 0x04, b'm', b'e',
/// b't', b'a']` for `tlv_bytes(0x0001, b"meta")`). Callers
/// concatenate results for multi-entry regions.
#[cfg(test)]
pub(crate) fn tlv_bytes(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENTRY_HEADER_SIZE + value.len());
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlv_bytes as tlv;

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
        // A region > `EXT_LEN_MAX` is rejected structurally, before per-entry parsing.
        let region = vec![0u8; EXT_LEN_MAX as usize + 1];
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::ExtTooLarge { .. })) => {}
            other => panic!("expected ExtTooLarge, got {other:?}"),
        }
    }

    // -- New shared scanner API --------------------------------------------

    /// `scan_tlv_region` returns the full set of parsed TLVs with
    /// cached classes. Pin the basic happy path so callers can rely on
    /// the order and class fields.
    #[test]
    fn scan_tlv_region_returns_classified_tlvs() {
        let mut region = tlv(0x0001, &[0xAA]);
        region.extend_from_slice(&tlv(0x0042, &[0xBB; 3]));
        let tlvs = scan_tlv_region(&region, EXT_LEN_MAX, EXT_LEN_MAX).unwrap();
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[0].tag, 0x0001);
        assert_eq!(tlvs[0].class, TlvClass::Ignorable);
        assert_eq!(tlvs[0].value, &[0xAA]);
        assert_eq!(tlvs[1].tag, 0x0042);
        assert_eq!(tlvs[1].class, TlvClass::Ignorable);
        assert_eq!(tlvs[1].value, &[0xBB; 3]);
    }

    /// The scanner DOES NOT reject critical tags — it only classifies
    /// them. Critical-rejection is the caller's responsibility (via
    /// `reject_unknown_critical` for v1, or a known-tag registry
    /// later). This decoupling lets future FCA writers emit known
    /// critical tags through the same scanner.
    #[test]
    fn scan_tlv_region_classifies_critical_without_rejecting() {
        let region = tlv(0x8001, &[0xAA]);
        let tlvs = scan_tlv_region(&region, EXT_LEN_MAX, EXT_LEN_MAX).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].class, TlvClass::Critical);
    }

    /// `reject_unknown_critical` is the v1.0 policy wrapper that turns
    /// any critical tag into an `UnknownCriticalTag` error.
    #[test]
    fn reject_unknown_critical_rejects_critical_tag() {
        let region = tlv(0x8001, &[0xAA]);
        let tlvs = scan_tlv_region(&region, EXT_LEN_MAX, EXT_LEN_MAX).unwrap();
        match reject_unknown_critical(&tlvs) {
            Err(CryptoError::InvalidFormat(FormatDefect::UnknownCriticalTag { tag: 0x8001 })) => {}
            other => panic!("expected UnknownCriticalTag(0x8001), got {other:?}"),
        }
    }

    /// Per-region caps are honored: a 64 KiB region cap rejects a
    /// 64 KiB + 1 byte input even though `EXT_LEN_MAX` would have
    /// accepted it. Pins that the cap is the caller-supplied parameter,
    /// not a global constant.
    #[test]
    fn scan_tlv_region_honors_caller_region_cap() {
        let small_cap: u32 = 64;
        let region = vec![0u8; small_cap as usize + 1];
        match scan_tlv_region(&region, small_cap, EXT_LEN_MAX) {
            Err(CryptoError::InvalidFormat(FormatDefect::ExtTooLarge { len })) => {
                assert_eq!(len, small_cap + 1);
            }
            other => panic!("expected ExtTooLarge, got {other:?}"),
        }
    }

    /// Per-value caps are honored: a TLV declaring `len > max_value_len`
    /// rejects even when the region itself fits.
    #[test]
    fn scan_tlv_region_honors_caller_value_cap() {
        // tag=0x0001, len=200 — fits in the region but violates the
        // explicit per-value cap of 100.
        let mut region = Vec::new();
        region.extend_from_slice(&0x0001u16.to_be_bytes());
        region.extend_from_slice(&200u32.to_be_bytes());
        region.extend_from_slice(&[0u8; 200]);
        match scan_tlv_region(&region, 1024, 100) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => {}
            other => panic!("expected MalformedTlv for value-over-cap, got {other:?}"),
        }
    }

    /// `>` vs `>=` regression guard on the per-value cap. A TLV
    /// declaring `len == max_value_len` is admissible; `cap + 1`
    /// rejects. Mirrors the limits-side at-cap admissibility tests.
    #[test]
    fn scan_tlv_region_value_at_cap_admissible() {
        let region = tlv(0x0001, &[0xAA; 100]);
        let tlvs = scan_tlv_region(&region, 1024, 100).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].value.len(), 100);

        let oversize = tlv(0x0001, &[0xBB; 101]);
        assert!(scan_tlv_region(&oversize, 1024, 100).is_err());
    }

    /// `>` vs `>=` regression guard on the region cap. A region of
    /// exactly `max_region_len` is admissible; one byte over rejects
    /// with `ExtTooLarge`.
    #[test]
    fn scan_tlv_region_region_at_cap_admissible() {
        // Build a region of exactly 100 bytes: 6-byte TLV header +
        // 94-byte value.
        let region = tlv(0x0001, &[0xAA; 94]);
        assert_eq!(region.len(), 100);
        let tlvs = scan_tlv_region(&region, 100, 100).unwrap();
        assert_eq!(tlvs.len(), 1);

        // 101-byte region rejects.
        let mut oversize = region.clone();
        oversize.push(0);
        match scan_tlv_region(&oversize, 100, 100) {
            Err(CryptoError::InvalidFormat(FormatDefect::ExtTooLarge { .. })) => {}
            other => panic!("expected ExtTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn classify_tlv_tag_rejects_reserved() {
        assert!(classify_tlv_tag(0x0000).is_err());
        assert!(classify_tlv_tag(0x8000).is_err());
        assert_eq!(classify_tlv_tag(0x0001).unwrap(), TlvClass::Ignorable);
        assert_eq!(classify_tlv_tag(0x7FFF).unwrap(), TlvClass::Ignorable);
        assert_eq!(classify_tlv_tag(0x8001).unwrap(), TlvClass::Critical);
        assert_eq!(classify_tlv_tag(0xFFFF).unwrap(), TlvClass::Critical);
    }
}
