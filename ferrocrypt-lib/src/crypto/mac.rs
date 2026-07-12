//! HMAC-SHA3-256 helpers and constant-time byte comparison.
//!
//! The header MAC covers `prefix(12) || header(header_len)` per
//! `FORMAT.md` §3.6 and is computed/verified through these helpers.
//! Tag verification is constant-time inside the `hmac` crate
//! (`verify_slice`); AEAD tags are checked inside `chacha20poly1305`.
//! [`ct_eq_32`] is the shared constant-time comparison for fixed
//! 32-byte values outside tag verification, such as the X25519
//! all-zero shared-secret checks.

use constant_time_eq::constant_time_eq_32;
use hmac::{Hmac, KeyInit, Mac};
use sha3::Sha3_256;

use crate::CryptoError;

/// HMAC-SHA3-256 key size in bytes.
pub(crate) const HMAC_KEY_SIZE: usize = 32;

/// HMAC-SHA3-256 output size in bytes (distinct from [`HMAC_KEY_SIZE`]).
pub(crate) const HMAC_TAG_SIZE: usize = 32;

type HmacSha3_256 = Hmac<Sha3_256>;

/// HMAC-SHA3-256 over a sequence of byte parts, fed into the MAC in
/// order with no separator. Equivalent to MAC'ing the concatenation
/// of `parts` but does not allocate. Used by the v1 header MAC, which
/// covers `prefix(12) || header(header_len)` per `FORMAT.md` §3.6.
pub(crate) fn hmac_sha3_256_parts(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], CryptoError> {
    Ok(hmac_state_for_parts(key, parts)?
        .finalize()
        .into_bytes()
        .into())
}

/// Constant-time HMAC-SHA3-256 verification over a sequence of byte
/// parts. On tag mismatch returns the caller-supplied `on_fail` error,
/// so this generic layer never hard-codes a use-site-specific failure
/// class (mirroring `crypto::aead`'s `open_*` helpers). See
/// [`hmac_sha3_256_parts`] for the input layout.
pub(crate) fn hmac_sha3_256_parts_verify(
    key: &[u8],
    parts: &[&[u8]],
    tag: &[u8],
    on_fail: impl FnOnce() -> CryptoError,
) -> Result<(), CryptoError> {
    hmac_state_for_parts(key, parts)?
        .verify_slice(tag)
        .map_err(|_| on_fail())
}

// Internal helper: builds a fresh HMAC-SHA3-256 state and updates it
// with `parts` in declared order. Both the compute and verify entry
// points share this so the key-init wording, the parts iteration
// order, and the empty-parts behaviour cannot drift between them.
fn hmac_state_for_parts(key: &[u8], parts: &[&[u8]]) -> Result<HmacSha3_256, CryptoError> {
    let mut mac = HmacSha3_256::new_from_slice(key)
        .map_err(|_| CryptoError::InternalInvariant("invalid HMAC key length"))?;
    for part in parts {
        mac.update(part);
    }
    Ok(mac)
}

/// Compares two 256-bit byte strings in constant time.
pub(crate) fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    constant_time_eq_32(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare_equal() {
        let data = [42u8; 32];
        assert!(ct_eq_32(&data, &data));
    }

    #[test]
    fn test_constant_time_compare_not_equal() {
        let data1 = [42u8; 32];
        let mut data2 = [42u8; 32];
        data2[0] = 43;
        assert!(!ct_eq_32(&data1, &data2));
    }

    #[test]
    fn test_constant_time_compare_all_zeros() {
        let data1 = [0u8; 32];
        let data2 = [0u8; 32];
        assert!(ct_eq_32(&data1, &data2));
    }

    /// The header MAC feeds `prefix` and `header` as separate parts
    /// (`FORMAT.md` §3.6 authenticates `prefix(12) || header`). This pins
    /// that feeding parts in order is byte-identical to MAC'ing their
    /// concatenation — the property a reader in another language must
    /// match. A bug that inserted a length prefix or separator between
    /// parts would pass every round-trip test but break interop; it fails
    /// here.
    #[test]
    fn hmac_sha3_256_parts_equals_concatenated_input() {
        let key = [0x0bu8; 32];
        let p1 = b"ferrocrypt-prefix";
        let p2 = b"ferrocrypt-header-bytes";
        let mut concat = Vec::new();
        concat.extend_from_slice(p1);
        concat.extend_from_slice(p2);
        let split = hmac_sha3_256_parts(&key, &[p1, p2]).unwrap();
        let whole = hmac_sha3_256_parts(&key, &[&concat]).unwrap();
        assert_eq!(split, whole);
    }

    /// Known-answer test against an independent HMAC-SHA3-256 reference.
    ///
    /// The expected tag comes from `testvectors/kat/hkdf_hmac_oracle.py`,
    /// which computes `hmac.new(key, msg, hashlib.sha3_256)` — a different
    /// implementation than the `hmac` / `sha3` crates here. Combined with
    /// the parts-equals-concatenated test above, this pins that the header
    /// MAC is a correct HMAC-SHA3-256 over the concatenated input, not
    /// merely self-consistent with FerroCrypt's own verifier.
    #[test]
    fn hmac_sha3_256_parts_matches_independent_oracle() {
        let key = [0x0bu8; 32];
        let parts: [&[u8]; 2] = [b"ferrocrypt-prefix", b"ferrocrypt-header-bytes"];
        let expected: [u8; 32] = [
            0x55, 0xe3, 0xcf, 0x23, 0xb9, 0x60, 0x24, 0x68, 0xc4, 0xa5, 0xd3, 0xe0, 0x62, 0x81,
            0xf1, 0x01, 0x47, 0x32, 0x4a, 0x8e, 0xa7, 0x96, 0x57, 0x53, 0xde, 0x1f, 0xb0, 0xc1,
            0x84, 0x11, 0xa8, 0x5a,
        ];
        let got = hmac_sha3_256_parts(&key, &parts).unwrap();
        assert_eq!(got, expected);
    }
}
