//! File-key generation, payload/header subkey derivation, and shared
//! key-size constants.
//!
//! Both symmetric and hybrid `.fcr` modes produce one per-file random
//! `file_key`; the recipient body wraps it, and [`derive_subkeys`]
//! derives the payload AEAD key and header MAC key from it. A
//! compromise of one subkey does not reveal the other.

use chacha20poly1305::aead::{OsRng, rand_core::RngCore};
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::crypto::hkdf::hkdf_expand_sha3_256;
use crate::crypto::kdf::{ARGON2_SALT_SIZE, KdfParams};
use crate::crypto::mac::HMAC_KEY_SIZE;

/// XChaCha20-Poly1305 key size in bytes.
pub const ENCRYPTION_KEY_SIZE: usize = 32;

/// Size of the per-file random key that both symmetric and hybrid
/// `.fcr` modes wrap via their mode envelope. Post-unwrap subkey
/// derivation keys off this value; see [`derive_subkeys`].
pub const FILE_KEY_SIZE: usize = 32;

/// HKDF info for the per-file payload AEAD key, derived from
/// `file_key` with `stream_nonce` as HKDF salt.
pub const HKDF_INFO_PAYLOAD: &[u8] = b"ferrocrypt/v1/payload";

/// HKDF info for the per-file header HMAC key, derived from `file_key`
/// with an empty HKDF salt.
pub const HKDF_INFO_HEADER: &[u8] = b"ferrocrypt/v1/header";

/// Fill a fresh stack-allocated `[u8; N]` from the OS CSPRNG. Use this
/// for **non-secret** random material (salts, nonces, ephemeral-public
/// scratch) where zero-on-drop provides no security benefit.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Fill a fresh `Zeroizing<[u8; N]>` from the OS CSPRNG. Use this for
/// **secret** random material (file keys, ephemeral secret keys) where
/// drop-time clearing is the right default.
pub fn random_secret<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut buf = Zeroizing::new([0u8; N]);
    OsRng.fill_bytes(buf.as_mut());
    buf
}

/// Generates a fresh 32-byte file key using the OS CSPRNG. Both
/// symmetric and hybrid `.fcr` modes produce one per-file `file_key`;
/// the mode envelope wraps it, and [`derive_subkeys`] derives the
/// payload and header subkeys from it.
pub fn generate_file_key() -> Zeroizing<[u8; FILE_KEY_SIZE]> {
    random_secret::<FILE_KEY_SIZE>()
}

/// Derives a 32-byte wrap key from a passphrase via
/// `Argon2id → HKDF-SHA3-256`. Used by:
/// - the `argon2id` recipient body wrap
///   (`info = "ferrocrypt/v1/recipient/argon2id/wrap"`)
/// - the `private.key` wrap (`info = "ferrocrypt/v1/private-key/wrap"`)
///
/// `argon2_salt` doubles as the Argon2id salt AND the HKDF salt.
/// Saves storing two distinct salts on disk.
pub fn derive_passphrase_wrap_key(
    passphrase: &SecretString,
    argon2_salt: &[u8; ARGON2_SALT_SIZE],
    kdf_params: &KdfParams,
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    use secrecy::ExposeSecret;
    let ikm = kdf_params.hash_passphrase(passphrase.expose_secret().as_bytes(), argon2_salt)?;
    hkdf_expand_sha3_256(Some(argon2_salt), ikm.as_ref(), info)
}

/// Payload AEAD key + header HMAC key, derived from a successfully
/// unwrapped [`FILE_KEY_SIZE`]-byte `file_key` via [`derive_subkeys`].
///
/// Named-field struct rather than a tuple so callers cannot
/// accidentally swap `payload_key` and `header_key` at the destructure
/// (both are `Zeroizing<[u8; 32]>` and would compile either way).
pub struct DerivedSubkeys {
    /// XChaCha20-Poly1305 key for the streaming payload AEAD.
    /// Derived with HKDF info `"ferrocrypt/v1/payload"` and
    /// `salt = stream_nonce`.
    pub payload_key: Zeroizing<[u8; ENCRYPTION_KEY_SIZE]>,
    /// HMAC-SHA3-256 key for the on-disk header MAC. Derived with
    /// HKDF info `"ferrocrypt/v1/header"` and an empty salt.
    pub header_key: Zeroizing<[u8; HMAC_KEY_SIZE]>,
}

/// Derives the payload and header subkeys from `file_key`.
///
/// - `payload_key = HKDF-SHA3-256(salt = stream_nonce, ikm = file_key,
///    info = "ferrocrypt/v1/payload", L = 32)`
/// - `header_key  = HKDF-SHA3-256(salt = empty,        ikm = file_key,
///    info = "ferrocrypt/v1/header",  L = 32)`
///
/// Binding the payload key to `stream_nonce` (rather than using an
/// empty salt) is defence-in-depth: it ties the derived key to every
/// byte of the stored nonce, matching age's "file key + nonce → payload
/// key" pattern.
pub fn derive_subkeys(
    file_key: &[u8; FILE_KEY_SIZE],
    stream_nonce: &[u8; crate::crypto::stream::STREAM_NONCE_SIZE],
) -> Result<DerivedSubkeys, CryptoError> {
    let payload_key = hkdf_expand_sha3_256(Some(stream_nonce), file_key, HKDF_INFO_PAYLOAD)?;
    let header_key = hkdf_expand_sha3_256(None, file_key, HKDF_INFO_HEADER)?;
    Ok(DerivedSubkeys {
        payload_key,
        header_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::stream::STREAM_NONCE_SIZE;

    #[test]
    fn generate_file_key_has_correct_size() {
        let key = generate_file_key();
        assert_eq!(key.len(), FILE_KEY_SIZE);
    }

    #[test]
    fn generate_file_key_is_random() {
        let a = generate_file_key();
        let b = generate_file_key();
        assert_ne!(*a, *b, "two consecutive file keys must differ");
    }

    #[test]
    fn derive_subkeys_round_trip() {
        let file_key = [0x11u8; FILE_KEY_SIZE];
        let nonce = [0x22u8; STREAM_NONCE_SIZE];
        let a = derive_subkeys(&file_key, &nonce).unwrap();
        let b = derive_subkeys(&file_key, &nonce).unwrap();
        assert_eq!(*a.payload_key, *b.payload_key);
        assert_eq!(*a.header_key, *b.header_key);
    }

    #[test]
    fn derive_subkeys_payload_depends_on_stream_nonce() {
        let file_key = [0x11u8; FILE_KEY_SIZE];
        let nonce_a = [0x22u8; STREAM_NONCE_SIZE];
        let nonce_b = [0x33u8; STREAM_NONCE_SIZE];
        let a = derive_subkeys(&file_key, &nonce_a).unwrap();
        let b = derive_subkeys(&file_key, &nonce_b).unwrap();
        assert_ne!(
            *a.payload_key, *b.payload_key,
            "payload key depends on stream_nonce"
        );
        // Header key uses empty salt so stream_nonce must NOT affect it.
        assert_eq!(
            *a.header_key, *b.header_key,
            "header key is independent of stream_nonce"
        );
    }

    #[test]
    fn derive_subkeys_depends_on_file_key() {
        let file_a = [0x11u8; FILE_KEY_SIZE];
        let file_b = [0x33u8; FILE_KEY_SIZE];
        let nonce = [0x22u8; STREAM_NONCE_SIZE];
        let a = derive_subkeys(&file_a, &nonce).unwrap();
        let b = derive_subkeys(&file_b, &nonce).unwrap();
        assert_ne!(*a.payload_key, *b.payload_key);
    }

    #[test]
    fn random_bytes_produces_different_outputs() {
        let a = random_bytes::<32>();
        let b = random_bytes::<32>();
        assert_ne!(a, b);
    }

    #[test]
    fn random_secret_has_correct_size_and_is_random() {
        let a = random_secret::<24>();
        let b = random_secret::<24>();
        assert_eq!(a.len(), 24);
        assert_ne!(*a, *b);
    }

    /// Pins the exact HKDF info strings against silent typos. The info
    /// bytes become part of the on-disk wire derivation; changing them
    /// invalidates every fixture. Recipient-type wrap info strings are
    /// pinned alongside their recipient module's tests.
    #[test]
    fn hkdf_info_strings_are_canonical() {
        assert_eq!(HKDF_INFO_PAYLOAD, b"ferrocrypt/v1/payload");
        assert_eq!(HKDF_INFO_HEADER, b"ferrocrypt/v1/header");
    }
}
