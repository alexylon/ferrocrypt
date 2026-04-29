//! XChaCha20-Poly1305 single-shot seal/open helpers.
//!
//! Used to wrap the per-file `file_key` inside recipient bodies (both
//! `argon2id` and `x25519`) and inside the `private.key` AEAD. AEAD
//! nonce sizes for the wrap step live here too so the nonce shape and
//! the AEAD primitive share a single source of truth.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit as AeadKeyInit},
};
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::crypto::keys::FILE_KEY_SIZE;

/// XChaCha20-Poly1305 single-shot nonce size, used for both mode
/// envelopes (`wrap_nonce`) and the `private.key` AEAD.
pub const WRAP_NONCE_SIZE: usize = 24;

/// Poly1305 authentication tag size in bytes.
pub const TAG_SIZE: usize = 16;

/// Size of an AEAD-wrapped 32-byte file key: 32-byte ciphertext +
/// 16-byte Poly1305 tag.
pub const WRAPPED_FILE_KEY_SIZE: usize = FILE_KEY_SIZE + TAG_SIZE;

/// Seals a 32-byte `file_key` with XChaCha20-Poly1305. Returns the
/// 48-byte wrapped form (ciphertext + tag) suitable for placement in
/// a mode envelope. `AAD` is empty — both modes' other fields are
/// covered by the outer HMAC.
pub fn seal_file_key(
    wrap_key: &[u8; 32],
    wrap_nonce: &[u8; WRAP_NONCE_SIZE],
    file_key: &[u8; FILE_KEY_SIZE],
) -> Result<[u8; WRAPPED_FILE_KEY_SIZE], CryptoError> {
    let cipher = XChaCha20Poly1305::new(wrap_key.into());
    let nonce = XNonce::from_slice(wrap_nonce);
    let ciphertext = cipher
        .encrypt(nonce, file_key.as_ref())
        .map_err(|_| CryptoError::InternalCryptoFailure("Internal error: envelope seal failed"))?;
    ciphertext.as_slice().try_into().map_err(|_| {
        CryptoError::InternalInvariant("Internal error: envelope ciphertext size mismatch")
    })
}

/// Opens an AEAD-wrapped file key. `on_fail` is called on AEAD-tag
/// mismatch so callers can route the failure to a recipient-specific
/// variant — typically [`CryptoError::RecipientUnwrapFailed`] with the
/// recipient's `type_name`, per `FORMAT.md` §3.7.
pub fn open_file_key(
    wrap_key: &[u8; 32],
    wrap_nonce: &[u8; WRAP_NONCE_SIZE],
    wrapped: &[u8; WRAPPED_FILE_KEY_SIZE],
    on_fail: impl FnOnce() -> CryptoError,
) -> Result<Zeroizing<[u8; FILE_KEY_SIZE]>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(wrap_key.into());
    let nonce = XNonce::from_slice(wrap_nonce);
    let plaintext = cipher
        .decrypt(nonce, wrapped.as_ref())
        .map_err(|_| on_fail())?;
    let mut out = Zeroizing::new([0u8; FILE_KEY_SIZE]);
    if plaintext.len() != FILE_KEY_SIZE {
        return Err(CryptoError::InternalInvariant(
            "Internal error: unwrapped file key size mismatch",
        ));
    }
    out.copy_from_slice(&plaintext);
    Ok(out)
}
