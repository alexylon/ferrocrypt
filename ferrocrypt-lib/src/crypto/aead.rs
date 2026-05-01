//! XChaCha20-Poly1305 single-shot seal/open helpers.
//!
//! Used to wrap the per-file `file_key` inside recipient bodies (both
//! `argon2id` and `x25519`) and inside the `private.key` AEAD. AEAD
//! nonce sizes for the wrap step live here too so the nonce shape and
//! the AEAD primitive share a single source of truth.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit as AeadKeyInit, Payload},
};
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::crypto::keys::{FILE_KEY_SIZE, FileKey};

/// XChaCha20-Poly1305 single-shot nonce size, used for both mode
/// envelopes (`wrap_nonce`) and the `private.key` AEAD.
pub const WRAP_NONCE_SIZE: usize = 24;

/// Poly1305 authentication tag size in bytes.
pub const TAG_SIZE: usize = 16;

/// Size of an AEAD-wrapped 32-byte file key: 32-byte ciphertext +
/// 16-byte Poly1305 tag.
pub const WRAPPED_FILE_KEY_SIZE: usize = FILE_KEY_SIZE + TAG_SIZE;

/// Seals a [`FileKey`] with XChaCha20-Poly1305. Returns the
/// 48-byte wrapped form (ciphertext + tag) suitable for placement in
/// a mode envelope. `AAD` is empty — both modes' other fields are
/// covered by the outer HMAC.
pub(crate) fn seal_file_key(
    wrap_key: &[u8; 32],
    wrap_nonce: &[u8; WRAP_NONCE_SIZE],
    file_key: &FileKey,
) -> Result<[u8; WRAPPED_FILE_KEY_SIZE], CryptoError> {
    let cipher = XChaCha20Poly1305::new(wrap_key.into());
    let nonce = XNonce::from_slice(wrap_nonce);
    let ciphertext = cipher
        .encrypt(nonce, file_key.expose().as_ref())
        .map_err(|_| CryptoError::InternalCryptoFailure("Internal error: envelope seal failed"))?;
    ciphertext.as_slice().try_into().map_err(|_| {
        CryptoError::InternalInvariant("Internal error: envelope ciphertext size mismatch")
    })
}

/// Opens an AEAD-wrapped file key. `on_fail` is called on AEAD-tag
/// mismatch so callers can route the failure to a recipient-specific
/// variant — typically [`CryptoError::RecipientUnwrapFailed`] with the
/// recipient's `type_name`, per `FORMAT.md` §3.7.
pub(crate) fn open_file_key(
    wrap_key: &[u8; 32],
    wrap_nonce: &[u8; WRAP_NONCE_SIZE],
    wrapped: &[u8; WRAPPED_FILE_KEY_SIZE],
    on_fail: impl FnOnce() -> CryptoError,
) -> Result<FileKey, CryptoError> {
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
    Ok(FileKey::from_zeroizing(out))
}

/// XChaCha20-Poly1305 AEAD seal with caller-supplied AAD. Returns
/// `ciphertext || Poly1305_tag` as an owned `Vec<u8>`.
///
/// `aad` is bound by the AEAD construction — any tamper to either the
/// ciphertext or the AAD surfaces as a decrypt failure indistinguishable
/// from a wrong key, which is the right semantics for cleartext-bound
/// headers (e.g. `private.key` per `FORMAT.md` §8). Callers that do not
/// need AAD use [`seal_file_key`] instead.
pub(crate) fn seal_with_aad(
    wrap_key: &[u8; 32],
    wrap_nonce: &[u8; WRAP_NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
    on_fail: impl FnOnce() -> CryptoError,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(wrap_key.into());
    let nonce = XNonce::from_slice(wrap_nonce);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| on_fail())
}

/// XChaCha20-Poly1305 AEAD open with caller-supplied AAD. `on_fail` is
/// invoked on tag mismatch so the caller can route to the appropriate
/// typed error (wrong-passphrase, tampered-AAD, wrong-recipient, …).
///
/// The plaintext is wrapped in [`Zeroizing`] **inside** the decrypt
/// expression so it never lives as a bare `Vec<u8>` on the stack — a
/// panic between decrypt-success and the wrapper would otherwise free
/// the allocation without zeroing and leave cleartext in released memory.
pub(crate) fn open_with_aad(
    wrap_key: &[u8; 32],
    wrap_nonce: &[u8; WRAP_NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
    on_fail: impl FnOnce() -> CryptoError,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(wrap_key.into());
    let nonce = XNonce::from_slice(wrap_nonce);
    Ok(Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| on_fail())?,
    ))
}
