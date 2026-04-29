//! `argon2id` passphrase recipient (`FORMAT.md` §4.1).
//!
//! Wrapping pipeline:
//!
//! ```text
//! ikm      = Argon2id(passphrase, argon2_salt, kdf_params)
//! wrap_key = HKDF-SHA3-256(salt = argon2_salt, ikm = ikm,
//!                          info = "ferrocrypt/v1/recipient/argon2id/wrap")
//! body     = argon2_salt(32) || kdf_params(12) || wrap_nonce(24) || wrapped_file_key(48)
//! ```
//!
//! `wrapped_file_key` is XChaCha20-Poly1305 with empty AAD; the
//! recipient body and its containing recipient entry are authenticated
//! by the outer header MAC (`FORMAT.md` §3.6).
//!
//! ## Mixing rule
//!
//! `argon2id` is **exclusive**: a file containing an `argon2id` entry
//! MUST contain exactly one recipient entry. The mixing-rule
//! enforcement is a header-level concern and lives in the recipient
//! list parser, not here.

use secrecy::SecretString;

use crate::CryptoError;
use crate::crypto::aead::{WRAP_NONCE_SIZE, WRAPPED_FILE_KEY_SIZE, open_file_key, seal_file_key};
use crate::crypto::kdf::{ARGON2_SALT_SIZE, KDF_PARAMS_SIZE, KdfLimit, KdfParams};
use crate::crypto::keys::{FileKey, derive_passphrase_wrap_key, random_bytes};

/// Wire-format `type_name` for this recipient.
pub const TYPE_NAME: &str = "argon2id";

/// Recipient body length in bytes (`FORMAT.md` §4.1).
pub const BODY_LENGTH: usize =
    ARGON2_SALT_SIZE + KDF_PARAMS_SIZE + WRAP_NONCE_SIZE + WRAPPED_FILE_KEY_SIZE;

/// HKDF-SHA3-256 `info` for the passphrase-derived wrap key.
pub const HKDF_INFO_WRAP: &[u8] = b"ferrocrypt/v1/recipient/argon2id/wrap";

const SALT_OFFSET: usize = 0;
const KDF_PARAMS_OFFSET: usize = SALT_OFFSET + ARGON2_SALT_SIZE;
const WRAP_NONCE_OFFSET: usize = KDF_PARAMS_OFFSET + KDF_PARAMS_SIZE;
const WRAPPED_FILE_KEY_OFFSET: usize = WRAP_NONCE_OFFSET + WRAP_NONCE_SIZE;

/// Wraps `file_key` for a passphrase recipient.
///
/// Generates fresh random `argon2_salt` and `wrap_nonce`, runs Argon2id
/// then HKDF-SHA3-256 to derive the wrap key, and seals `file_key`
/// via XChaCha20-Poly1305 with empty AAD. Returns the canonical
/// 116-byte recipient body.
pub(crate) fn wrap(
    file_key: &FileKey,
    passphrase: &SecretString,
    kdf_params: &KdfParams,
) -> Result<[u8; BODY_LENGTH], CryptoError> {
    let argon2_salt = random_bytes::<ARGON2_SALT_SIZE>();
    let wrap_key =
        derive_passphrase_wrap_key(passphrase, &argon2_salt, kdf_params, HKDF_INFO_WRAP)?;
    let wrap_nonce = random_bytes::<WRAP_NONCE_SIZE>();
    let wrapped_file_key = seal_file_key(&wrap_key, &wrap_nonce, file_key)?;

    let mut body = [0u8; BODY_LENGTH];
    body[SALT_OFFSET..SALT_OFFSET + ARGON2_SALT_SIZE].copy_from_slice(&argon2_salt);
    body[KDF_PARAMS_OFFSET..KDF_PARAMS_OFFSET + KDF_PARAMS_SIZE]
        .copy_from_slice(&kdf_params.to_bytes());
    body[WRAP_NONCE_OFFSET..WRAP_NONCE_OFFSET + WRAP_NONCE_SIZE].copy_from_slice(&wrap_nonce);
    body[WRAPPED_FILE_KEY_OFFSET..].copy_from_slice(&wrapped_file_key);
    Ok(body)
}

/// Opens an `argon2id` recipient body and recovers a candidate
/// `file_key`. Caller-supplied `kdf_limit` caps `mem_kib` for untrusted
/// input; KDF parameter structural bounds are validated **before**
/// Argon2id runs so a hostile file cannot force unbounded work.
///
/// Wrong passphrase and tampered envelope are indistinguishable at the
/// AEAD layer; both surface as
/// [`CryptoError::RecipientUnwrapFailed`] with `type_name = "argon2id"`.
/// Per `FORMAT.md` §3.7, the candidate `file_key` is not considered
/// final until the header MAC also verifies.
pub(crate) fn unwrap(
    body: &[u8; BODY_LENGTH],
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
) -> Result<FileKey, CryptoError> {
    let mut argon2_salt = [0u8; ARGON2_SALT_SIZE];
    argon2_salt.copy_from_slice(&body[SALT_OFFSET..SALT_OFFSET + ARGON2_SALT_SIZE]);

    let mut kdf_bytes = [0u8; KDF_PARAMS_SIZE];
    kdf_bytes.copy_from_slice(&body[KDF_PARAMS_OFFSET..KDF_PARAMS_OFFSET + KDF_PARAMS_SIZE]);
    let kdf_params = KdfParams::from_bytes(&kdf_bytes, kdf_limit)?;

    let mut wrap_nonce = [0u8; WRAP_NONCE_SIZE];
    wrap_nonce.copy_from_slice(&body[WRAP_NONCE_OFFSET..WRAP_NONCE_OFFSET + WRAP_NONCE_SIZE]);

    let mut wrapped_file_key = [0u8; WRAPPED_FILE_KEY_SIZE];
    wrapped_file_key.copy_from_slice(&body[WRAPPED_FILE_KEY_OFFSET..]);

    let wrap_key =
        derive_passphrase_wrap_key(passphrase, &argon2_salt, &kdf_params, HKDF_INFO_WRAP)?;
    open_file_key(&wrap_key, &wrap_nonce, &wrapped_file_key, || {
        CryptoError::RecipientUnwrapFailed {
            type_name: TYPE_NAME.to_string(),
        }
    })
}

// ─── Protocol-trait impls ──────────────────────────────────────────────────

/// Encrypt-side handle for the `argon2id` recipient: borrows a
/// passphrase and KDF parameters.
pub(crate) struct PassphraseRecipient<'a> {
    pub passphrase: &'a SecretString,
    pub kdf_params: KdfParams,
}

impl<'a> crate::protocol::RecipientScheme for PassphraseRecipient<'a> {
    const TYPE_NAME: &'static str = TYPE_NAME;
    const MIXING_POLICY: crate::recipient::policy::MixingPolicy =
        crate::recipient::policy::MixingPolicy::Exclusive;

    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<crate::recipient::entry::RecipientBody, CryptoError> {
        let bytes = wrap(file_key, self.passphrase, &self.kdf_params)?;
        Ok(crate::recipient::entry::RecipientBody {
            type_name: TYPE_NAME,
            bytes: bytes.to_vec(),
        })
    }
}

/// Decrypt-side handle for the `argon2id` recipient.
pub(crate) struct PassphraseIdentity<'a> {
    pub passphrase: &'a SecretString,
    pub kdf_limit: Option<&'a KdfLimit>,
}

impl<'a> crate::protocol::IdentityScheme for PassphraseIdentity<'a> {
    const TYPE_NAME: &'static str = TYPE_NAME;

    fn unwrap_file_key(
        &self,
        body: &crate::recipient::entry::RecipientBody,
    ) -> Result<Option<FileKey>, CryptoError> {
        let body_array: &[u8; BODY_LENGTH] = body.bytes.as_slice().try_into().map_err(|_| {
            CryptoError::InvalidFormat(crate::error::FormatDefect::MalformedRecipientEntry)
        })?;
        // KDF cap and structural KDF-param validation happen inside
        // `unwrap` BEFORE Argon2id runs. Wrong passphrase / tampered
        // body surface as `RecipientUnwrapFailed` from `unwrap`; per
        // `IdentityScheme` semantics we collapse those into `Ok(None)`
        // and propagate everything else (including the cap-exceeded
        // error) as `Err`.
        match unwrap(body_array, self.passphrase, self.kdf_limit) {
            Ok(file_key) => Ok(Some(file_key)),
            Err(CryptoError::RecipientUnwrapFailed { .. }) => Ok(None),
            Err(other) => Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::FILE_KEY_SIZE;

    fn passphrase(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    #[test]
    fn body_length_matches_field_sum() {
        assert_eq!(
            BODY_LENGTH,
            ARGON2_SALT_SIZE + KDF_PARAMS_SIZE + WRAP_NONCE_SIZE + WRAPPED_FILE_KEY_SIZE
        );
        assert_eq!(BODY_LENGTH, 116);
    }

    #[test]
    fn type_name_is_canonical_lowercase() {
        assert_eq!(TYPE_NAME, "argon2id");
    }

    /// Pins the wire-bytes of the HKDF info string. The info bytes
    /// become part of the on-disk derivation; changing them invalidates
    /// every existing fixture.
    #[test]
    fn hkdf_info_wrap_is_canonical() {
        assert_eq!(HKDF_INFO_WRAP, b"ferrocrypt/v1/recipient/argon2id/wrap");
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let file_key = FileKey::from_bytes_for_tests([0x42u8; FILE_KEY_SIZE]);
        let pass = passphrase("correct horse battery staple");
        let kdf = KdfParams::default();
        let body = wrap(&file_key, &pass, &kdf).unwrap();
        let recovered = unwrap(&body, &pass, None).unwrap();
        assert_eq!(recovered.expose(), file_key.expose());
    }

    #[test]
    fn unwrap_with_wrong_passphrase_fails_with_recipient_unwrap_failed() {
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
        let right = passphrase("right");
        let wrong = passphrase("wrong");
        let kdf = KdfParams::default();
        let body = wrap(&file_key, &right, &kdf).unwrap();
        match unwrap(&body, &wrong, None) {
            Err(CryptoError::RecipientUnwrapFailed { type_name }) => {
                assert_eq!(type_name, TYPE_NAME);
            }
            other => panic!("expected RecipientUnwrapFailed, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_with_tampered_wrapped_file_key_fails_with_recipient_unwrap_failed() {
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
        let pass = passphrase("p");
        let kdf = KdfParams::default();
        let mut body = wrap(&file_key, &pass, &kdf).unwrap();
        body[WRAPPED_FILE_KEY_OFFSET] ^= 0x01;
        match unwrap(&body, &pass, None) {
            Err(CryptoError::RecipientUnwrapFailed { type_name }) => {
                assert_eq!(type_name, TYPE_NAME);
            }
            other => panic!("expected RecipientUnwrapFailed, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_with_tampered_argon2_salt_fails_with_recipient_unwrap_failed() {
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
        let pass = passphrase("p");
        let kdf = KdfParams::default();
        let mut body = wrap(&file_key, &pass, &kdf).unwrap();
        body[SALT_OFFSET] ^= 0x01;
        match unwrap(&body, &pass, None) {
            Err(CryptoError::RecipientUnwrapFailed { type_name }) => {
                assert_eq!(type_name, TYPE_NAME);
            }
            other => panic!("expected RecipientUnwrapFailed, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_with_tampered_kdf_params_within_bounds_fails_with_recipient_unwrap_failed() {
        // Flip bit 1 (XOR 0x02) of the low byte of `time_cost`. The
        // value stays within structural bounds (`1..=12`) regardless of
        // the original (fast-kdf: 1 → 3; default: 4 → 6). Argon2id with
        // different params produces a different ikm → different wrap
        // key → AEAD fails → RecipientUnwrapFailed.
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
        let pass = passphrase("p");
        let kdf = KdfParams::default();
        let mut body = wrap(&file_key, &pass, &kdf).unwrap();
        body[KDF_PARAMS_OFFSET + 7] ^= 0x02;
        match unwrap(&body, &pass, None) {
            Err(CryptoError::RecipientUnwrapFailed { type_name }) => {
                assert_eq!(type_name, TYPE_NAME);
            }
            other => panic!("expected RecipientUnwrapFailed, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_with_tampered_wrap_nonce_fails_with_recipient_unwrap_failed() {
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
        let pass = passphrase("p");
        let kdf = KdfParams::default();
        let mut body = wrap(&file_key, &pass, &kdf).unwrap();
        body[WRAP_NONCE_OFFSET] ^= 0x01;
        match unwrap(&body, &pass, None) {
            Err(CryptoError::RecipientUnwrapFailed { type_name }) => {
                assert_eq!(type_name, TYPE_NAME);
            }
            other => panic!("expected RecipientUnwrapFailed, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_with_malformed_kdf_params_fails_before_argon2id_runs() {
        // Set `lanes = 0` (out of structural bounds 1..=8). Per
        // `FORMAT.md` §2.2 this MUST be rejected before Argon2id runs.
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
        let pass = passphrase("p");
        let kdf = KdfParams::default();
        let mut body = wrap(&file_key, &pass, &kdf).unwrap();
        // `lanes` is the third u32 in `kdf_params`; offset KDF_PARAMS_OFFSET + 8.
        body[KDF_PARAMS_OFFSET + 8..KDF_PARAMS_OFFSET + 12].fill(0);
        match unwrap(&body, &pass, None) {
            Err(CryptoError::InvalidKdfParams(_)) => {}
            other => panic!("expected InvalidKdfParams, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_rejects_kdf_params_above_resource_cap() {
        // Construct a body with mem_cost = 2 GiB (the structural max),
        // then unwrap with a kdf_limit of 64 KiB. The resource cap
        // MUST surface as KdfResourceCapExceeded before Argon2id runs.
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
        let pass = passphrase("p");
        let high_mem_kdf = KdfParams {
            mem_cost: 2 * 1024 * 1024,
            time_cost: 1,
            lanes: 1,
        };
        // We can't actually run wrap() with 2 GiB mem cost in a test; instead
        // construct the body directly with the high-mem KDF params field.
        let kdf_low = KdfParams::default();
        let mut body = wrap(&file_key, &pass, &kdf_low).unwrap();
        body[KDF_PARAMS_OFFSET..KDF_PARAMS_OFFSET + KDF_PARAMS_SIZE]
            .copy_from_slice(&high_mem_kdf.to_bytes());
        let limit = KdfLimit::new(64);
        match unwrap(&body, &pass, Some(&limit)) {
            Err(CryptoError::KdfResourceCapExceeded {
                mem_cost_kib,
                local_cap_kib,
            }) => {
                assert_eq!(mem_cost_kib, 2 * 1024 * 1024);
                assert_eq!(local_cap_kib, 64);
            }
            other => panic!("expected KdfResourceCapExceeded, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_field_offsets_are_correct() {
        // Wire-format regression: the body layout MUST be exactly
        // salt(32) || kdf_params(12) || wrap_nonce(24) || wrapped(48).
        // A reordering would produce a body that this reader rejects
        // and that conforming readers reject the same way.
        let file_key = FileKey::from_bytes_for_tests([0x11u8; FILE_KEY_SIZE]);
        let pass = passphrase("p");
        let kdf = KdfParams::default();
        let body = wrap(&file_key, &pass, &kdf).unwrap();
        assert_eq!(SALT_OFFSET, 0);
        assert_eq!(KDF_PARAMS_OFFSET, 32);
        assert_eq!(WRAP_NONCE_OFFSET, 44);
        assert_eq!(WRAPPED_FILE_KEY_OFFSET, 68);
        assert_eq!(body.len(), 116);
    }
}
