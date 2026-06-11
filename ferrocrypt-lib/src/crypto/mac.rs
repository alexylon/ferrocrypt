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
        .map_err(|_| CryptoError::InternalInvariant("Internal error: invalid HMAC key length"))?;
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
}
