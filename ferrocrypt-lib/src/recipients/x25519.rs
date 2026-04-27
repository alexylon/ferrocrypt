//! `x25519` public-key recipient (`FORMAT.md` §4.2).
//!
//! Wrapping pipeline:
//!
//! ```text
//! ephemeral_secret = random 32-byte X25519 scalar
//! ephemeral_pubkey = X25519(ephemeral_secret, basepoint)
//! shared           = X25519(ephemeral_secret, recipient_pubkey)
//! wrap_key         = HKDF-SHA3-256(salt = ephemeral_pubkey || recipient_pubkey,
//!                                  ikm  = shared,
//!                                  info = "ferrocrypt/v1/recipient/x25519/wrap")
//! body             = ephemeral_pubkey(32) || wrap_nonce(24) || wrapped_file_key(48)
//! ```
//!
//! `wrapped_file_key` is XChaCha20-Poly1305 with empty AAD; the
//! recipient body and its containing recipient entry are authenticated
//! by the outer header MAC (`FORMAT.md` §3.6).
//!
//! ## Mixing rule
//!
//! `x25519` is **public-key-mixable** — multiple `x25519` recipient
//! entries may appear in the same file. Mixing-rule enforcement
//! against exclusive recipient types (`argon2id`) is a header-level
//! concern.
//!
//! ## All-zero shared-secret rejection
//!
//! Both [`wrap`] and [`unwrap`] reject an all-zero X25519 shared
//! secret per `FORMAT.md` §2.4. This catches a small-order ephemeral /
//! recipient key combination; the check uses constant-time compare.

use chacha20poly1305::aead::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::common::{
    FILE_KEY_SIZE, WRAP_NONCE_SIZE, WRAPPED_FILE_KEY_SIZE, ct_eq_32, hkdf_expand_sha3_256,
    open_file_key, random_bytes, seal_file_key,
};

/// Wire-format `type_name` for this recipient.
pub const TYPE_NAME: &str = "x25519";

/// X25519 public-key length in bytes.
pub const PUBKEY_SIZE: usize = 32;

/// X25519 private-key (scalar input) length in bytes.
pub const PRIVATE_KEY_SIZE: usize = 32;

/// Recipient body length in bytes (`FORMAT.md` §4.2).
pub const BODY_LENGTH: usize = PUBKEY_SIZE + WRAP_NONCE_SIZE + WRAPPED_FILE_KEY_SIZE;

/// HKDF-SHA3-256 `info` for the X25519 ECDH-derived wrap key.
pub const HKDF_INFO_WRAP: &[u8] = b"ferrocrypt/v1/recipient/x25519/wrap";

const EPHEMERAL_PUBKEY_OFFSET: usize = 0;
const WRAP_NONCE_OFFSET: usize = EPHEMERAL_PUBKEY_OFFSET + PUBKEY_SIZE;
const WRAPPED_FILE_KEY_OFFSET: usize = WRAP_NONCE_OFFSET + WRAP_NONCE_SIZE;

/// Wraps `file_key` for an X25519 recipient.
///
/// Generates a fresh ephemeral X25519 keypair, performs ECDH against
/// `recipient_pubkey`, and rejects an all-zero shared secret. Derives
/// the wrap key via HKDF-SHA3-256 with a salt binding both ephemeral
/// and recipient public keys, then seals `file_key` via
/// XChaCha20-Poly1305 with empty AAD. Returns the canonical 104-byte
/// recipient body.
///
/// An all-zero shared secret surfaces as
/// [`CryptoError::InvalidInput`] with the "Invalid recipient public
/// key" message, since this is an encrypt-time user error (the
/// caller-supplied recipient public key is degenerate).
pub fn wrap(
    file_key: &[u8; FILE_KEY_SIZE],
    recipient_pubkey: &[u8; PUBKEY_SIZE],
) -> Result<[u8; BODY_LENGTH], CryptoError> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pubkey = PublicKey::from(&ephemeral_secret);
    let recipient_public = PublicKey::from(*recipient_pubkey);
    let shared = ephemeral_secret.diffie_hellman(&recipient_public);
    if ct_eq_32(shared.as_bytes(), &[0u8; PUBKEY_SIZE]) {
        return Err(CryptoError::InvalidInput(
            "Invalid recipient public key".to_string(),
        ));
    }
    let wrap_key = derive_wrap_key(
        ephemeral_pubkey.as_bytes(),
        recipient_public.as_bytes(),
        shared.as_bytes(),
    )?;
    let wrap_nonce = random_bytes::<WRAP_NONCE_SIZE>();
    let wrapped_file_key = seal_file_key(&wrap_key, &wrap_nonce, file_key)?;

    let mut body = [0u8; BODY_LENGTH];
    body[EPHEMERAL_PUBKEY_OFFSET..EPHEMERAL_PUBKEY_OFFSET + PUBKEY_SIZE]
        .copy_from_slice(ephemeral_pubkey.as_bytes());
    body[WRAP_NONCE_OFFSET..WRAP_NONCE_OFFSET + WRAP_NONCE_SIZE].copy_from_slice(&wrap_nonce);
    body[WRAPPED_FILE_KEY_OFFSET..].copy_from_slice(&wrapped_file_key);
    Ok(body)
}

/// Opens an `x25519` recipient body and recovers a candidate
/// `file_key` using the recipient's static X25519 private key.
///
/// Rejects all-zero shared secrets per `FORMAT.md` §2.4. Wrong private
/// key and tampered envelope are indistinguishable at the AEAD layer;
/// both surface as [`CryptoError::RecipientUnwrapFailed`] with
/// `type_name = "x25519"`. Per `FORMAT.md` §3.7, the candidate
/// `file_key` is not considered final until the header MAC also
/// verifies.
pub fn unwrap(
    body: &[u8; BODY_LENGTH],
    recipient_secret_bytes: &[u8; PRIVATE_KEY_SIZE],
) -> Result<Zeroizing<[u8; FILE_KEY_SIZE]>, CryptoError> {
    let mut ephemeral_pubkey_bytes = [0u8; PUBKEY_SIZE];
    ephemeral_pubkey_bytes
        .copy_from_slice(&body[EPHEMERAL_PUBKEY_OFFSET..EPHEMERAL_PUBKEY_OFFSET + PUBKEY_SIZE]);

    let mut wrap_nonce = [0u8; WRAP_NONCE_SIZE];
    wrap_nonce.copy_from_slice(&body[WRAP_NONCE_OFFSET..WRAP_NONCE_OFFSET + WRAP_NONCE_SIZE]);

    let mut wrapped_file_key = [0u8; WRAPPED_FILE_KEY_SIZE];
    wrapped_file_key.copy_from_slice(&body[WRAPPED_FILE_KEY_OFFSET..]);

    let recipient_secret = StaticSecret::from(*recipient_secret_bytes);
    let recipient_public = PublicKey::from(&recipient_secret);
    let ephemeral_public = PublicKey::from(ephemeral_pubkey_bytes);
    let shared = recipient_secret.diffie_hellman(&ephemeral_public);
    if ct_eq_32(shared.as_bytes(), &[0u8; PUBKEY_SIZE]) {
        return Err(CryptoError::RecipientUnwrapFailed {
            type_name: TYPE_NAME.to_string(),
        });
    }
    let wrap_key = derive_wrap_key(
        &ephemeral_pubkey_bytes,
        recipient_public.as_bytes(),
        shared.as_bytes(),
    )?;
    open_file_key(&wrap_key, &wrap_nonce, &wrapped_file_key, || {
        CryptoError::RecipientUnwrapFailed {
            type_name: TYPE_NAME.to_string(),
        }
    })
}

/// Derives the X25519 wrap key. Salt binds both public keys so the
/// wrap key is unique per `(ephemeral, recipient)` exchange.
fn derive_wrap_key(
    ephemeral_pubkey: &[u8; PUBKEY_SIZE],
    recipient_pubkey: &[u8; PUBKEY_SIZE],
    shared_secret: &[u8; PUBKEY_SIZE],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut salt = [0u8; 2 * PUBKEY_SIZE];
    salt[..PUBKEY_SIZE].copy_from_slice(ephemeral_pubkey);
    salt[PUBKEY_SIZE..].copy_from_slice(recipient_pubkey);
    hkdf_expand_sha3_256(Some(&salt), shared_secret, HKDF_INFO_WRAP)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> ([u8; PRIVATE_KEY_SIZE], [u8; PUBKEY_SIZE]) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret.to_bytes(), *public.as_bytes())
    }

    #[test]
    fn body_length_matches_field_sum() {
        assert_eq!(
            BODY_LENGTH,
            PUBKEY_SIZE + WRAP_NONCE_SIZE + WRAPPED_FILE_KEY_SIZE
        );
        assert_eq!(BODY_LENGTH, 104);
    }

    #[test]
    fn type_name_is_canonical_lowercase() {
        assert_eq!(TYPE_NAME, "x25519");
    }

    /// Pins the wire-bytes of the HKDF info string. The info bytes
    /// become part of the on-disk derivation; changing them invalidates
    /// every existing fixture.
    #[test]
    fn hkdf_info_wrap_is_canonical() {
        assert_eq!(HKDF_INFO_WRAP, b"ferrocrypt/v1/recipient/x25519/wrap");
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let file_key = [0x42u8; FILE_KEY_SIZE];
        let (sk, pk) = keypair();
        let body = wrap(&file_key, &pk).unwrap();
        let recovered = unwrap(&body, &sk).unwrap();
        assert_eq!(*recovered, file_key);
    }

    #[test]
    fn unwrap_with_wrong_private_key_fails_with_recipient_unwrap_failed() {
        let file_key = [0u8; FILE_KEY_SIZE];
        let (_alice_sk, alice_pk) = keypair();
        let (bob_sk, _bob_pk) = keypair();
        let body = wrap(&file_key, &alice_pk).unwrap();
        match unwrap(&body, &bob_sk) {
            Err(CryptoError::RecipientUnwrapFailed { type_name }) => {
                assert_eq!(type_name, TYPE_NAME);
            }
            other => panic!("expected RecipientUnwrapFailed, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_with_tampered_wrapped_file_key_fails_with_recipient_unwrap_failed() {
        let file_key = [0u8; FILE_KEY_SIZE];
        let (sk, pk) = keypair();
        let mut body = wrap(&file_key, &pk).unwrap();
        body[WRAPPED_FILE_KEY_OFFSET] ^= 0x01;
        match unwrap(&body, &sk) {
            Err(CryptoError::RecipientUnwrapFailed { type_name }) => {
                assert_eq!(type_name, TYPE_NAME);
            }
            other => panic!("expected RecipientUnwrapFailed, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_with_tampered_ephemeral_pubkey_fails_with_recipient_unwrap_failed() {
        let file_key = [0u8; FILE_KEY_SIZE];
        let (sk, pk) = keypair();
        let mut body = wrap(&file_key, &pk).unwrap();
        body[EPHEMERAL_PUBKEY_OFFSET] ^= 0x01;
        match unwrap(&body, &sk) {
            Err(CryptoError::RecipientUnwrapFailed { type_name }) => {
                assert_eq!(type_name, TYPE_NAME);
            }
            other => panic!("expected RecipientUnwrapFailed, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_with_tampered_wrap_nonce_fails_with_recipient_unwrap_failed() {
        let file_key = [0u8; FILE_KEY_SIZE];
        let (sk, pk) = keypair();
        let mut body = wrap(&file_key, &pk).unwrap();
        body[WRAP_NONCE_OFFSET] ^= 0x01;
        match unwrap(&body, &sk) {
            Err(CryptoError::RecipientUnwrapFailed { type_name }) => {
                assert_eq!(type_name, TYPE_NAME);
            }
            other => panic!("expected RecipientUnwrapFailed, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_rejects_small_order_ephemeral_via_all_zero_shared() {
        // An all-zero ephemeral pubkey is a known X25519 small-order
        // point: X25519(any_secret, all_zero_pubkey) = all_zero_shared.
        // Per `FORMAT.md` §2.4 this MUST be rejected by readers before
        // deriving the wrap key.
        let file_key = [0u8; FILE_KEY_SIZE];
        let (sk, pk) = keypair();
        let mut body = wrap(&file_key, &pk).unwrap();
        body[EPHEMERAL_PUBKEY_OFFSET..EPHEMERAL_PUBKEY_OFFSET + PUBKEY_SIZE].fill(0);
        match unwrap(&body, &sk) {
            Err(CryptoError::RecipientUnwrapFailed { type_name }) => {
                assert_eq!(type_name, TYPE_NAME);
            }
            other => panic!("expected RecipientUnwrapFailed for all-zero ephemeral, got {other:?}"),
        }
    }

    #[test]
    fn wrap_rejects_all_zero_recipient_pubkey() {
        let file_key = [0u8; FILE_KEY_SIZE];
        let zero_pk = [0u8; PUBKEY_SIZE];
        match wrap(&file_key, &zero_pk) {
            Err(CryptoError::InvalidInput(msg)) => {
                assert!(msg.contains("Invalid recipient"));
            }
            other => panic!("expected InvalidInput for all-zero pubkey, got {other:?}"),
        }
    }

    #[test]
    fn body_field_offsets_are_correct() {
        // Wire-format regression: the body layout MUST be exactly
        // ephemeral_pubkey(32) || wrap_nonce(24) || wrapped(48). A
        // reordering would produce a body that this reader rejects
        // and that conforming readers reject the same way.
        let file_key = [0x11u8; FILE_KEY_SIZE];
        let (_, pk) = keypair();
        let body = wrap(&file_key, &pk).unwrap();
        assert_eq!(EPHEMERAL_PUBKEY_OFFSET, 0);
        assert_eq!(WRAP_NONCE_OFFSET, 32);
        assert_eq!(WRAPPED_FILE_KEY_OFFSET, 56);
        assert_eq!(body.len(), 104);
    }
}
