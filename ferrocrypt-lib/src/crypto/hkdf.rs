//! HKDF-SHA3-256 expansion adapter.
//!
//! Every HKDF derivation goes through this helper so the hash family
//! and output length are fixed in one place. Recipient-specific info
//! strings live with their recipient scheme. Header/payload/private-key
//! labels live with the module that owns that derivation.

use hkdf::Hkdf;
use sha3::Sha3_256;
use zeroize::Zeroizing;

use crate::CryptoError;

/// HKDF-SHA3-256 expansion to a 32-byte key.
pub(crate) fn hkdf_expand_sha3_256(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hkdf = Hkdf::<Sha3_256>::new(salt, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, out.as_mut())
        .map_err(|_| crate::error::internal_crypto_failure!("HKDF expand failed"))?;
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

    /// Known-answer test against an independent RFC 5869 reference.
    ///
    /// The expected bytes come from `testvectors/kat/hkdf_hmac_oracle.py`,
    /// which recomputes HKDF-SHA3-256 with the Python standard library
    /// (`hashlib.sha3_256` + `hmac`) — a different implementation than the
    /// `hkdf` / `sha3` crates this code uses. Agreement proves the
    /// Extract-then-Expand construction and 32-byte output length match a
    /// reference, not just that the crate agrees with itself. See
    /// `FORMAT.md` §2.3.
    #[test]
    fn hkdf_expand_sha3_256_matches_independent_oracle() {
        let salt = [0x22u8; 16];
        let ikm = [0x11u8; 32];
        let info = b"ferrocrypt/v1/test";
        let expected: [u8; 32] = [
            0x57, 0xf9, 0x6f, 0xb3, 0x25, 0x55, 0xc2, 0x91, 0x5c, 0x23, 0xb1, 0xf5, 0xd4, 0xc3,
            0x2a, 0xb6, 0x6e, 0xb0, 0xce, 0x4e, 0x6b, 0x24, 0x96, 0xaa, 0x39, 0xc4, 0x24, 0xc0,
            0xbf, 0xb0, 0xeb, 0xd1,
        ];
        let got = hkdf_expand_sha3_256(Some(&salt), &ikm, info).unwrap();
        assert_eq!(*got, expected);
    }
}
