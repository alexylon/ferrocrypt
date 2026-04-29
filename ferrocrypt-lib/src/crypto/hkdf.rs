//! HKDF-SHA3-256 expansion adapter.
//!
//! Every v1 HKDF derivation goes through this helper so the hash family
//! and output length are fixed in one place. Recipient-specific info
//! strings live with their recipient scheme. Header/payload/private-key
//! labels live with the module that owns that derivation.

use hkdf::Hkdf;
use sha3::Sha3_256;
use zeroize::Zeroizing;

use crate::CryptoError;

/// HKDF-SHA3-256 expansion to a 32-byte key. Every v1 HKDF derivation
/// goes through this helper so the hash family and output length are
/// fixed in one place.
pub fn hkdf_expand_sha3_256(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hkdf = Hkdf::<Sha3_256>::new(salt, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, out.as_mut())
        .map_err(|_| CryptoError::InternalCryptoFailure("Internal error: HKDF expand failed"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{HKDF_INFO_HEADER, HKDF_INFO_PAYLOAD};

    #[test]
    fn hkdf_expand_sha3_256_is_deterministic() {
        let ikm = [0x11u8; 32];
        let salt = [0x22u8; 16];
        let info = b"ferrocrypt/v1/test";
        let a = hkdf_expand_sha3_256(Some(&salt), &ikm, info).unwrap();
        let b = hkdf_expand_sha3_256(Some(&salt), &ikm, info).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn hkdf_expand_sha3_256_domain_separates_on_info() {
        let ikm = [0x11u8; 32];
        let a = hkdf_expand_sha3_256(None, &ikm, HKDF_INFO_PAYLOAD).unwrap();
        let b = hkdf_expand_sha3_256(None, &ikm, HKDF_INFO_HEADER).unwrap();
        assert_ne!(*a, *b, "different info strings must produce different keys");
    }

    #[test]
    fn hkdf_expand_sha3_256_domain_separates_on_salt() {
        let ikm = [0x11u8; 32];
        let info = HKDF_INFO_PAYLOAD;
        let salt_a = [0x22u8; 16];
        let salt_b = [0x33u8; 16];
        let a = hkdf_expand_sha3_256(Some(&salt_a), &ikm, info).unwrap();
        let b = hkdf_expand_sha3_256(Some(&salt_b), &ikm, info).unwrap();
        assert_ne!(*a, *b, "different salts must produce different keys");
    }
}
