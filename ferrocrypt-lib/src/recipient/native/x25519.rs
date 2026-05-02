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
//! Both [`wrap`] and [`unwrap`] reject an all-zero X25519 shared secret
//! per `FORMAT.md` §2.4 / §4.2. This catches a small-order ephemeral /
//! recipient key combination; the check uses constant-time compare.
//!
//! On the decrypt side the rejection is **file-fatal**, not
//! slot-skippable: an all-zero shared secret is identity-independent
//! (any decryptor would compute the same value), so [`unwrap`] surfaces
//! it as `InvalidFormat(MalformedRecipientEntry)` and the
//! [`X25519Identity`] adapter propagates the error rather than
//! collapsing it to the slot-skip channel reserved for AEAD failures.

use chacha20poly1305::aead::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::crypto::aead::{WRAP_NONCE_SIZE, WRAPPED_FILE_KEY_SIZE, open_file_key, seal_file_key};
use crate::crypto::hkdf::hkdf_expand_sha3_256;
use crate::crypto::keys::{FileKey, random_bytes};
use crate::crypto::mac::ct_eq_32;
use crate::error::FormatDefect;

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

/// Structurally rejects the all-zero X25519 public key — the only
/// small-order point we can pre-screen without baking in an explicit
/// RFC 7748 §6.1 list. Public-key ingress points (`PublicKey::from_bytes`,
/// `decode_x25519_recipient`, `read_public_key`) call this so a
/// degenerate key cannot construct a `PublicKey` value in the first
/// place. Other small-order points are still backstopped by the
/// shared-secret all-zero check inside [`wrap`] and [`unwrap`].
///
/// Constant-time compare so timing of structural rejection cannot leak
/// the input bytes.
pub(crate) fn is_zero_public_key(bytes: &[u8; PUBKEY_SIZE]) -> bool {
    ct_eq_32(bytes, &[0u8; PUBKEY_SIZE])
}

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
pub(crate) fn wrap(
    file_key: &FileKey,
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
/// Two failure classes, deliberately distinguished:
///
/// - **Structural malformation:** an all-zero ECDH shared secret per
///   `FORMAT.md` §2.4 / §4.2 — surfaces as
///   `CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)`.
///   Identity-independent: any decryptor would observe the same all-zero
///   value, so the spec mandates file-fatal rejection. The
///   [`X25519Identity`] adapter propagates this error rather than
///   collapsing it to `Ok(None)`.
/// - **AEAD authentication failure:** wrong recipient private key or
///   tampered wrapped envelope — both surface as
///   [`CryptoError::RecipientUnwrapFailed`] with `type_name = "x25519"`.
///   Indistinguishable at the AEAD layer and identity-dependent (a
///   different key holder might still unwrap a sibling slot), so the
///   adapter collapses these into the slot-skip channel.
///
/// Per `FORMAT.md` §3.7 the candidate `file_key` is not considered
/// final until the header MAC also verifies.
pub(crate) fn unwrap(
    body: &[u8; BODY_LENGTH],
    recipient_secret_bytes: &[u8; PRIVATE_KEY_SIZE],
) -> Result<FileKey, CryptoError> {
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
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedRecipientEntry,
        ));
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

// ─── Protocol-trait impls ──────────────────────────────────────────────────

/// Encrypt-side handle for the `x25519` recipient: borrows a 32-byte
/// recipient public key.
pub(crate) struct X25519Recipient<'a> {
    pub recipient_pubkey: &'a [u8; PUBKEY_SIZE],
}

impl<'a> crate::protocol::RecipientScheme for X25519Recipient<'a> {
    const TYPE_NAME: &'static str = TYPE_NAME;
    const MIXING_POLICY: crate::recipient::policy::MixingPolicy =
        crate::recipient::policy::MixingPolicy::PublicKeyMixable;

    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<crate::recipient::entry::RecipientBody, CryptoError> {
        let bytes = wrap(file_key, self.recipient_pubkey)?;
        Ok(crate::recipient::entry::RecipientBody {
            type_name: TYPE_NAME,
            bytes: bytes.to_vec(),
        })
    }
}

/// Decrypt-side handle for the `x25519` recipient. Owns the 32-byte
/// recipient secret in `Zeroizing` so it's wiped on drop.
pub(crate) struct X25519Identity {
    pub recipient_secret: Zeroizing<[u8; PRIVATE_KEY_SIZE]>,
}

impl crate::protocol::IdentityScheme for X25519Identity {
    const TYPE_NAME: &'static str = TYPE_NAME;
    const EXPECTED_MODE: crate::EncryptionMode = crate::EncryptionMode::Recipient;

    fn unwrap_file_key(
        &self,
        body: &crate::recipient::entry::RecipientBody,
    ) -> Result<Option<FileKey>, CryptoError> {
        let body_array: &[u8; BODY_LENGTH] = body
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry))?;
        // Per [`unwrap`]'s contract, wrong-recipient-key and tampered-body
        // surface as `RecipientUnwrapFailed` (identity-dependent: collapse
        // to `Ok(None)` so the slot loop tries the next supported entry).
        // An all-zero ECDH shared secret surfaces as
        // `InvalidFormat(MalformedRecipientEntry)` (identity-independent
        // structural defect per FORMAT.md §2.4 / §4.2: propagate so the
        // entire file is rejected).
        match unwrap(body_array, &self.recipient_secret) {
            Ok(file_key) => Ok(Some(file_key)),
            Err(CryptoError::RecipientUnwrapFailed { .. }) => Ok(None),
            Err(other) => Err(other),
        }
    }
}

// ─── Key-pair generation ───────────────────────────────────────────────────

/// Generates a fresh X25519 key pair via the OS CSPRNG. Returns
/// `(secret_material, public_material)` where the secret bytes live in
/// `Zeroizing` so they're wiped from memory when the caller drops them.
///
/// Used by [`crate::generate_key_pair`] for the X25519-specific portion;
/// orchestration (file naming, `private.key` sealing, `public.key`
/// encoding, atomic finalize) lives in the higher-level entry point.
pub(crate) fn generate_keypair() -> (Zeroizing<[u8; PRIVATE_KEY_SIZE]>, [u8; PUBKEY_SIZE]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let secret_material = Zeroizing::new(secret.to_bytes());
    drop(secret);
    let public_material = *public.as_bytes();
    (secret_material, public_material)
}

// ─── private.key reader (X25519-specific glue) ─────────────────────────────

/// Reads and unlocks a v1 `private.key` file, returning the raw 32-byte
/// X25519 secret. Wraps [`crate::key::private::open_private_key`] with
/// the X25519-specific type-name and length checks plus TLV validation.
///
/// Errors:
/// - [`CryptoError::InputPath`] if the file does not exist
/// - [`CryptoError::Io`] for other read errors
/// - [`CryptoError::KeyFileUnlockFailed`] for wrong passphrase or
///   tampered cleartext (AEAD cannot distinguish)
/// - [`crate::error::FormatDefect::WrongKeyFileType`] for a private.key that wraps a
///   non-X25519 secret (e.g. a future native key kind)
/// - [`crate::error::FormatDefect::MalformedPrivateKey`] for a structurally valid
///   private.key whose authenticated `public_material` is not 32 bytes,
///   whose decrypted `secret_material` is not 32 bytes, or whose
///   stored public material does not match
///   `X25519(secret_material, basepoint)` (the FORMAT.md §8 native
///   recipient-specific check)
/// - [`crate::error::FormatDefect::MalformedTlv`] / [`crate::error::FormatDefect::UnknownCriticalTag`]
///   for malformed or unknown-critical entries in `ext_bytes`
pub(crate) fn open_x25519_private_key(
    path: &std::path::Path,
    passphrase: &secrecy::SecretString,
    kdf_limit: Option<&crate::crypto::kdf::KdfLimit>,
) -> Result<Zeroizing<[u8; PRIVATE_KEY_SIZE]>, CryptoError> {
    use crate::crypto::tlv::validate_tlv;
    use crate::error::FormatDefect;
    use crate::fs::paths::map_user_path_io_error;
    use crate::key::files::KeyFileKind;
    use crate::key::private::{PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT, open_private_key};

    let bytes = std::fs::read(path).map_err(map_user_path_io_error)?;

    // Friendly diagnostic for the cross-mix-up: a user pointing the
    // private-key reader at a `public.key` text file gets
    // `WrongKeyFileType` rather than the generic `NotAKeyFile` that
    // `open_private_key`'s magic check would surface.
    if matches!(KeyFileKind::classify(&bytes), KeyFileKind::Public) {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }

    let opened = open_private_key(
        &bytes,
        passphrase,
        kdf_limit,
        PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT,
    )?;

    if opened.type_name != TYPE_NAME {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }

    let public_material: [u8; PUBKEY_SIZE] = opened
        .public_material
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey))?;

    if opened.secret_material.len() != PRIVATE_KEY_SIZE {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ));
    }

    // TLV validation is safe to run after AEAD-AAD authentication
    // succeeded — `key::private::open_private_key` only returns Ok
    // after the AEAD pass that bound `ext_bytes` as AAD.
    validate_tlv(&opened.ext_bytes)?;

    let mut secret = Zeroizing::new([0u8; PRIVATE_KEY_SIZE]);
    secret.copy_from_slice(&opened.secret_material);

    // FORMAT.md §8: native X25519 readers MUST compute
    // X25519(secret_material, basepoint) and reject unless the result
    // exactly equals the authenticated `public_material`. AEAD-AAD
    // already authenticated `public_material` against tampering, but a
    // file produced by a buggy or malicious writer can still seal a
    // mismatched pair; this check rejects that case before the secret
    // is ever used to unwrap a recipient body.
    let derived_public = PublicKey::from(&StaticSecret::from(*secret));
    if derived_public.as_bytes() != &public_material {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ));
    }

    Ok(secret)
}

// ─── private.key structural validator (used by fuzz exports) ───────────────

/// Validates the structural shape of a v1 `private.key` file. Does not
/// attempt to decrypt or derive any keys. Used by
/// [`crate::validate_private_key_file`] and re-exported via
/// `fuzz_exports` for the fuzz harness.
///
/// Checks (in order):
/// - file is large enough to hold the 90-byte cleartext fixed header;
/// - [`crate::key::private::PrivateKeyHeader::parse`] accepts the
///   header (magic, version, kind, `key_flags == 0`, length-field
///   structural ranges);
/// - `type_name` is `"x25519"` (the only v1 native key kind);
/// - `public_len` equals the X25519 public-key size (32);
/// - the file's total length matches `90 + type_name_len + public_len
///   + ext_len + wrapped_secret_len`.
///
/// Does NOT validate `ext_bytes` TLV canonicity. TLV canonicity runs
/// only after AEAD-AAD authentication, which structural validation by
/// definition does not perform.
pub fn validate_private_key_shape(data: &[u8]) -> Result<(), CryptoError> {
    use crate::error::FormatDefect;
    use crate::key::private::{PRIVATE_KEY_HEADER_FIXED_SIZE, PrivateKeyHeader};

    let header_bytes =
        data.first_chunk::<PRIVATE_KEY_HEADER_FIXED_SIZE>()
            .ok_or(CryptoError::InvalidFormat(
                FormatDefect::MalformedPrivateKey,
            ))?;
    let header = PrivateKeyHeader::parse(header_bytes)?;

    let type_name_start = PRIVATE_KEY_HEADER_FIXED_SIZE;
    let type_name_end = type_name_start
        .checked_add(header.type_name_len as usize)
        .ok_or(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ))?;
    if data.len() < type_name_end {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ));
    }
    let type_name = std::str::from_utf8(&data[type_name_start..type_name_end])
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedTypeName))?;
    if type_name != TYPE_NAME {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }

    if header.public_len != PUBKEY_SIZE as u32 {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ));
    }

    let expected_total = (PRIVATE_KEY_HEADER_FIXED_SIZE as u64)
        .checked_add(header.type_name_len as u64)
        .and_then(|v| v.checked_add(header.public_len as u64))
        .and_then(|v| v.checked_add(header.ext_len as u64))
        .and_then(|v| v.checked_add(header.wrapped_secret_len as u64))
        .ok_or(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ))?;
    if (data.len() as u64) != expected_total {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CryptoError;
    use crate::crypto::kdf::KdfParams;
    use crate::crypto::keys::FILE_KEY_SIZE;
    use crate::error::FormatDefect;
    use crate::key::private::seal_private_key;
    use secrecy::SecretString;
    use std::fs;

    /// FORMAT.md §8 mandates that native X25519 readers compute
    /// `X25519(secret_material, basepoint)` and reject the file unless
    /// the result equals the authenticated `public_material`. AEAD-AAD
    /// authentication alone cannot catch a structurally valid
    /// `private.key` whose two halves were sealed inconsistently (a
    /// buggy or malicious writer can do this); only the native
    /// derivation check does.
    #[test]
    fn open_private_key_rejects_x25519_public_secret_mismatch() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("private.key");
        let pass = SecretString::from("pw".to_string());

        let secret = StaticSecret::random_from_rng(OsRng);
        let secret_material = secret.to_bytes();
        let other_secret = StaticSecret::random_from_rng(OsRng);
        let wrong_public = PublicKey::from(&other_secret);

        let bytes = seal_private_key(
            &secret_material,
            TYPE_NAME,
            wrong_public.as_bytes(),
            &[],
            &pass,
            &KdfParams::default(),
        )?;
        fs::write(&path, bytes)?;

        match open_x25519_private_key(&path, &pass, None).map(|_| ()) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => Ok(()),
            other => {
                panic!("expected MalformedPrivateKey for public/secret mismatch, got {other:?}")
            }
        }
    }

    /// A `private.key` whose `public_len` is a structurally valid value
    /// other than 32 (the X25519 size) decodes through the generic
    /// private-key reader, but the X25519 adapter MUST reject it: the
    /// stored public material cannot represent an X25519 point at any
    /// length other than 32. Surfaces as `MalformedPrivateKey`.
    #[test]
    fn open_private_key_rejects_x25519_public_len_mismatch() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("private.key");
        let pass = SecretString::from("pw".to_string());

        let secret = StaticSecret::random_from_rng(OsRng);
        let secret_material = secret.to_bytes();
        let malformed_public = [0u8; PUBKEY_SIZE - 1];

        let bytes = seal_private_key(
            &secret_material,
            TYPE_NAME,
            &malformed_public,
            &[],
            &pass,
            &KdfParams::default(),
        )?;
        fs::write(&path, bytes)?;

        match open_x25519_private_key(&path, &pass, None).map(|_| ()) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => Ok(()),
            other => panic!("expected MalformedPrivateKey for public_len mismatch, got {other:?}"),
        }
    }

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
        let file_key = FileKey::from_bytes_for_tests([0x42u8; FILE_KEY_SIZE]);
        let (sk, pk) = keypair();
        let body = wrap(&file_key, &pk).unwrap();
        let recovered = unwrap(&body, &sk).unwrap();
        assert_eq!(recovered.expose(), file_key.expose());
    }

    #[test]
    fn unwrap_with_wrong_private_key_fails_with_recipient_unwrap_failed() {
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
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
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
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
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
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
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
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
        // Per `FORMAT.md` §2.4 / §4.2 this MUST be rejected by readers
        // before deriving the wrap key, and the rejection is
        // identity-independent — readers MUST surface it as a structural
        // defect (file-fatal) rather than as a slot-skippable AEAD
        // failure, so the [`X25519Identity`] adapter propagates the
        // error instead of collapsing to `Ok(None)`.
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
        let (sk, pk) = keypair();
        let mut body = wrap(&file_key, &pk).unwrap();
        body[EPHEMERAL_PUBKEY_OFFSET..EPHEMERAL_PUBKEY_OFFSET + PUBKEY_SIZE].fill(0);
        match unwrap(&body, &sk) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => {
                panic!("expected MalformedRecipientEntry for all-zero ephemeral, got {other:?}")
            }
        }
    }

    /// Identity-adapter contract: an all-zero shared secret must NOT be
    /// collapsed into the slot-skip channel. The adapter propagates
    /// `InvalidFormat(MalformedRecipientEntry)` so the surrounding
    /// decrypt loop rejects the whole file (FORMAT.md §2.4 / §4.2).
    /// Wrong-key AEAD failures keep their existing `Ok(None)` mapping —
    /// covered by the dedicated wrong-key test above.
    #[test]
    fn identity_adapter_propagates_all_zero_shared_secret() {
        use crate::protocol::IdentityScheme;
        use crate::recipient::entry::RecipientBody;

        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
        let (sk, pk) = keypair();
        let mut body_bytes = wrap(&file_key, &pk).unwrap();
        body_bytes[EPHEMERAL_PUBKEY_OFFSET..EPHEMERAL_PUBKEY_OFFSET + PUBKEY_SIZE].fill(0);

        let identity = X25519Identity {
            recipient_secret: Zeroizing::new(sk),
        };
        let body = RecipientBody {
            type_name: TYPE_NAME,
            bytes: body_bytes.to_vec(),
        };
        match identity.unwrap_file_key(&body) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => panic!(
                "adapter must propagate all-zero shared as MalformedRecipientEntry, got {other:?}"
            ),
        }
    }

    #[test]
    fn wrap_rejects_all_zero_recipient_pubkey() {
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
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
        let file_key = FileKey::from_bytes_for_tests([0x11u8; FILE_KEY_SIZE]);
        let (_, pk) = keypair();
        let body = wrap(&file_key, &pk).unwrap();
        assert_eq!(EPHEMERAL_PUBKEY_OFFSET, 0);
        assert_eq!(WRAP_NONCE_OFFSET, 32);
        assert_eq!(WRAPPED_FILE_KEY_OFFSET, 56);
        assert_eq!(body.len(), 104);
    }
}
