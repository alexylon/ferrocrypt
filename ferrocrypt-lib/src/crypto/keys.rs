//! File-key generation, payload/header subkey derivation, and shared
//! key-size constants.
//!
//! Every `.fcr` produces exactly one per-file random `file_key`,
//! regardless of recipient kind; each recipient entry wraps it, and
//! [`derive_subkeys`] derives the payload AEAD key and header MAC key
//! from it. A compromise of one subkey does not reveal the other.
//!
//! ## Typed key newtypes
//!
//! [`FileKey`], [`PayloadKey`], and [`HeaderKey`] are `pub(crate)`
//! newtypes around `Zeroizing<[u8; 32]>`. Their constructors are
//! `pub(crate)` so external code cannot synthesize one; downstream
//! crypto modules borrow the underlying bytes through narrow `expose()`
//! accessors. The type system makes it a compile error to pass a
//! payload key into header-MAC code, or vice versa.

use chacha20poly1305::aead::{OsRng, rand_core::RngCore};
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::crypto::hkdf::hkdf_expand_sha3_256;
use crate::crypto::kdf::{ARGON2_SALT_SIZE, KdfParams};
use crate::crypto::mac::HMAC_KEY_SIZE;

/// XChaCha20-Poly1305 key size in bytes.
pub const ENCRYPTION_KEY_SIZE: usize = 32;

/// Size of the per-file random key that every `.fcr` wraps via its
/// recipient entries. Post-unwrap subkey derivation keys off this
/// value; see [`derive_subkeys`].
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

/// Per-file random key. Every `.fcr` produces one of these regardless
/// of recipient kind; each recipient entry wraps it, and
/// [`derive_subkeys`] derives the payload AEAD key and header MAC key
/// from its bytes.
///
/// Construct via [`FileKey::generate`] (fresh random) or
/// [`FileKey::from_zeroizing`] (recipient-unwrap path). The
/// constructor is `pub(crate)` so external code cannot synthesize a
/// `FileKey` — it must originate from the OS CSPRNG or from an
/// authenticated AEAD unwrap.
pub(crate) struct FileKey(Zeroizing<[u8; FILE_KEY_SIZE]>);

// Manual `Debug` redacts the underlying bytes. `Zeroizing<[u8; N]>`
// derives `Debug` transparently from `[u8; N]`, which would print the
// raw key bytes via `{:?}` (used by `Result::unwrap_err`, panic
// messages, `eprintln!("{:?}", ...)`, etc.). Per `CLAUDE.md` "Never
// leak secrets through logs, errors, debug output, or UI", this impl
// emits a fixed redaction marker instead.
impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileKey(<redacted>)")
    }
}

impl FileKey {
    /// Generates a fresh `FileKey` from the OS CSPRNG.
    pub(crate) fn generate() -> Self {
        Self(random_secret::<FILE_KEY_SIZE>())
    }

    /// Wraps existing zeroizing bytes (typically from a successful
    /// AEAD unwrap in [`crate::crypto::aead::open_file_key`]) as a
    /// `FileKey`.
    pub(crate) fn from_zeroizing(bytes: Zeroizing<[u8; FILE_KEY_SIZE]>) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying 32-byte material. Narrow accessor —
    /// callers should use this only at the actual call to a low-level
    /// primitive (HKDF, AEAD seal/open).
    pub(crate) fn expose(&self) -> &[u8; FILE_KEY_SIZE] {
        &self.0
    }

    /// Test-only constructor for deterministic fixed-byte file keys.
    /// Outside tests, a `FileKey` originates only from
    /// [`FileKey::generate`] (OS CSPRNG) or [`FileKey::from_zeroizing`]
    /// (post-AEAD unwrap path), preserving the security invariant that
    /// callers cannot synthesize a `FileKey` from arbitrary bytes.
    #[cfg(test)]
    pub(crate) fn from_bytes_for_tests(bytes: [u8; FILE_KEY_SIZE]) -> Self {
        Self::from_zeroizing(Zeroizing::new(bytes))
    }
}

/// XChaCha20-Poly1305 key for the streaming payload AEAD. Derived
/// from a [`FileKey`] via [`derive_subkeys`] with HKDF info
/// `"ferrocrypt/v1/payload"` and `salt = stream_nonce`. Cannot be
/// passed to header-MAC code.
pub(crate) struct PayloadKey(Zeroizing<[u8; ENCRYPTION_KEY_SIZE]>);

impl std::fmt::Debug for PayloadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PayloadKey(<redacted>)")
    }
}

impl PayloadKey {
    pub(crate) fn from_zeroizing(bytes: Zeroizing<[u8; ENCRYPTION_KEY_SIZE]>) -> Self {
        Self(bytes)
    }

    pub(crate) fn expose(&self) -> &[u8; ENCRYPTION_KEY_SIZE] {
        &self.0
    }

    /// Test-only constructor for deterministic fixed-byte payload keys.
    /// Production code receives a `PayloadKey` only from
    /// [`derive_subkeys`].
    #[cfg(test)]
    pub(crate) fn from_bytes_for_tests(bytes: [u8; ENCRYPTION_KEY_SIZE]) -> Self {
        Self::from_zeroizing(Zeroizing::new(bytes))
    }
}

/// HMAC-SHA3-256 key for the on-disk header MAC. Derived from a
/// [`FileKey`] via [`derive_subkeys`] with HKDF info
/// `"ferrocrypt/v1/header"` and an empty salt. Cannot be passed to
/// payload-AEAD code.
pub(crate) struct HeaderKey(Zeroizing<[u8; HMAC_KEY_SIZE]>);

impl std::fmt::Debug for HeaderKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HeaderKey(<redacted>)")
    }
}

impl HeaderKey {
    pub(crate) fn from_zeroizing(bytes: Zeroizing<[u8; HMAC_KEY_SIZE]>) -> Self {
        Self(bytes)
    }

    pub(crate) fn expose(&self) -> &[u8; HMAC_KEY_SIZE] {
        &self.0
    }

    /// Test-only constructor for deterministic fixed-byte header keys.
    /// Production code receives a `HeaderKey` only from
    /// [`derive_subkeys`].
    #[cfg(test)]
    pub(crate) fn from_bytes_for_tests(bytes: [u8; HMAC_KEY_SIZE]) -> Self {
        Self::from_zeroizing(Zeroizing::new(bytes))
    }
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
/// unwrapped [`FileKey`] via [`derive_subkeys`].
///
/// Named-field struct rather than a tuple so callers cannot
/// accidentally swap `payload_key` and `header_key` at the destructure
/// — and the type system enforces that anyway, since the two fields
/// are distinct newtypes.
pub(crate) struct DerivedSubkeys {
    /// XChaCha20-Poly1305 key for the streaming payload AEAD.
    /// Derived with HKDF info `"ferrocrypt/v1/payload"` and
    /// `salt = stream_nonce`.
    pub payload_key: PayloadKey,
    /// HMAC-SHA3-256 key for the on-disk header MAC. Derived with
    /// HKDF info `"ferrocrypt/v1/header"` and an empty salt.
    pub header_key: HeaderKey,
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
pub(crate) fn derive_subkeys(
    file_key: &FileKey,
    stream_nonce: &[u8; crate::crypto::stream::STREAM_NONCE_SIZE],
) -> Result<DerivedSubkeys, CryptoError> {
    let payload_bytes =
        hkdf_expand_sha3_256(Some(stream_nonce), file_key.expose(), HKDF_INFO_PAYLOAD)?;
    let header_bytes = hkdf_expand_sha3_256(None, file_key.expose(), HKDF_INFO_HEADER)?;
    Ok(DerivedSubkeys {
        payload_key: PayloadKey::from_zeroizing(payload_bytes),
        header_key: HeaderKey::from_zeroizing(header_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::stream::STREAM_NONCE_SIZE;

    #[test]
    fn file_key_generate_has_correct_size() {
        let key = FileKey::generate();
        assert_eq!(key.expose().len(), FILE_KEY_SIZE);
    }

    #[test]
    fn file_key_generate_is_random() {
        let a = FileKey::generate();
        let b = FileKey::generate();
        assert_ne!(
            a.expose(),
            b.expose(),
            "two consecutive file keys must differ"
        );
    }

    #[test]
    fn derive_subkeys_round_trip() {
        let file_key = FileKey::from_bytes_for_tests([0x11u8; FILE_KEY_SIZE]);
        let nonce = [0x22u8; STREAM_NONCE_SIZE];
        let a = derive_subkeys(&file_key, &nonce).unwrap();
        let b = derive_subkeys(&file_key, &nonce).unwrap();
        assert_eq!(a.payload_key.expose(), b.payload_key.expose());
        assert_eq!(a.header_key.expose(), b.header_key.expose());
    }

    #[test]
    fn derive_subkeys_payload_depends_on_stream_nonce() {
        let file_key = FileKey::from_bytes_for_tests([0x11u8; FILE_KEY_SIZE]);
        let nonce_a = [0x22u8; STREAM_NONCE_SIZE];
        let nonce_b = [0x33u8; STREAM_NONCE_SIZE];
        let a = derive_subkeys(&file_key, &nonce_a).unwrap();
        let b = derive_subkeys(&file_key, &nonce_b).unwrap();
        assert_ne!(
            a.payload_key.expose(),
            b.payload_key.expose(),
            "payload key depends on stream_nonce"
        );
        // Header key uses empty salt so stream_nonce must NOT affect it.
        assert_eq!(
            a.header_key.expose(),
            b.header_key.expose(),
            "header key is independent of stream_nonce"
        );
    }

    #[test]
    fn derive_subkeys_depends_on_file_key() {
        let file_a = FileKey::from_bytes_for_tests([0x11u8; FILE_KEY_SIZE]);
        let file_b = FileKey::from_bytes_for_tests([0x33u8; FILE_KEY_SIZE]);
        let nonce = [0x22u8; STREAM_NONCE_SIZE];
        let a = derive_subkeys(&file_a, &nonce).unwrap();
        let b = derive_subkeys(&file_b, &nonce).unwrap();
        assert_ne!(a.payload_key.expose(), b.payload_key.expose());
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
