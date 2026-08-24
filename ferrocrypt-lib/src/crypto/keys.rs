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

use crate::passphrase::Passphrase;
use chacha20poly1305::aead::{OsRng, rand_core::RngCore};
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::crypto::hkdf::hkdf_expand_sha3_256;
use crate::crypto::kdf::{ARGON2_SALT_SIZE, KdfParams};
use crate::crypto::mac::HMAC_KEY_SIZE;

const CSPRNG_FAILURE: CryptoError = crate::error::internal_crypto_failure!("CSPRNG read failed");

/// XChaCha20-Poly1305 key size in bytes.
pub(crate) const ENCRYPTION_KEY_SIZE: usize = 32;

/// Size of the per-file random key that every `.fcr` wraps via its
/// recipient entries. Post-unwrap subkey derivation keys off this
/// value; see [`derive_subkeys`].
pub(crate) const FILE_KEY_SIZE: usize = 32;

/// HKDF info for the per-file payload AEAD key, derived from
/// `file_key` with `stream_nonce` as HKDF salt.
pub(crate) const HKDF_INFO_PAYLOAD: &[u8] = b"ferrocrypt/v1/payload";

/// HKDF info for the per-file header HMAC key, derived from `file_key`
/// with an empty HKDF salt.
pub(crate) const HKDF_INFO_HEADER: &[u8] = b"ferrocrypt/v1/header";

/// Runs `f` with every [`random_bytes`] / [`random_secret`] draw coming from
/// a deterministic seeded stream instead of the OS CSPRNG, then restores the
/// previous state. This lets the `testvectors/suite/` fixture generator
/// produce byte-stable output, so regenerating the committed corpus is a clean
/// diff rather than a full re-randomization.
///
/// Test-only, and the whole seam is compiled out of every non-test build, so
/// the production RNG is `OsRng` and only `OsRng`. The stream is deliberately
/// NOT cryptographic; the fixtures it produces are explicitly non-secret.
#[cfg(test)]
pub(crate) use deterministic_rng::with_seed as with_deterministic_rng;

/// Runs `f` with the deterministic stream sealed: any draw that is not inside
/// a nested [`with_deterministic_rng`] or [`deterministic_seed_scope`] panics
/// instead of reading either the OS CSPRNG or a neighbouring seeded stream.
///
/// The `testvectors/wire/` generator runs under this, because a frozen corpus
/// needs each artifact's bytes to depend on that artifact's own seed alone. A
/// draw that escaped its scope would otherwise couple two artifacts silently.
#[cfg(test)]
pub(crate) use deterministic_rng::with_sealed as with_sealed_rng;

/// Seeds the deterministic stream for as long as the returned [`SeedScope`]
/// lives, restoring the enclosing state when it drops. Use it where the seeded
/// region spans statements that a closure cannot wrap cleanly.
///
/// Opening a scope while another seeded scope is still open panics. A guard
/// left alive past the case it belongs to is otherwise invisible: the next
/// case would continue the previous case's stream instead of its own, which
/// couples two artifacts that the per-case seed exists to keep independent.
#[cfg(test)]
pub(crate) use deterministic_rng::seed_scope as deterministic_seed_scope;

/// Guard returned by [`deterministic_seed_scope`].
#[cfg(test)]
pub(crate) use deterministic_rng::SeedScope;

// Opt-in deterministic RNG override. See [`with_deterministic_rng`].
#[cfg(test)]
mod deterministic_rng {
    use std::cell::RefCell;

    /// State of the deterministic stream on this thread.
    enum Stream {
        /// Draws come from a splitmix64 stream at this position.
        Seeded(u64),
        /// Draws are refused, so a generator that requires every draw to sit
        /// inside a seeded scope fails loudly instead of silently borrowing
        /// the enclosing stream or the OS CSPRNG.
        Sealed,
    }

    thread_local! {
        static STATE: RefCell<Option<Stream>> = const { RefCell::new(None) };
    }

    /// Restores the enclosing stream state on drop, so a panic inside a scope
    /// cannot leave that scope's stream active and poison a later test
    /// sharing this harness thread.
    pub(crate) struct SeedScope(Option<Stream>);

    impl Drop for SeedScope {
        fn drop(&mut self) {
            STATE.with(|s| *s.borrow_mut() = self.0.take());
        }
    }

    fn replace(state: Option<Stream>) -> SeedScope {
        SeedScope(STATE.with(|s| s.replace(state)))
    }

    pub(crate) fn seed_scope(seed: u64) -> SeedScope {
        STATE.with(|s| {
            assert!(
                !matches!(*s.borrow(), Some(Stream::Seeded(_))),
                "a seeded scope is still open; drop it before opening the next one"
            );
        });
        replace(Some(Stream::Seeded(seed)))
    }

    pub(crate) fn with_seed<R>(seed: u64, f: impl FnOnce() -> R) -> R {
        let _restore = seed_scope(seed);
        f()
    }

    pub(crate) fn with_sealed<R>(f: impl FnOnce() -> R) -> R {
        let _restore = replace(Some(Stream::Sealed));
        f()
    }

    /// If the deterministic stream is active, fills `buf` from it and returns
    /// `true`; otherwise leaves `buf` untouched and returns `false`, so the
    /// caller falls through to `OsRng`. Panics while the stream is sealed.
    pub(crate) fn try_fill(buf: &mut [u8]) -> bool {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let state = match guard.as_mut() {
                None => return false,
                Some(Stream::Sealed) => {
                    panic!("random draw outside a seeded scope while the stream is sealed")
                }
                Some(Stream::Seeded(state)) => state,
            };
            for chunk in buf.chunks_mut(8) {
                // splitmix64 step.
                *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = *state;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^= z >> 31;
                let bytes = z.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            true
        })
    }
}

/// Fill a fresh stack-allocated `[u8; N]` from the OS CSPRNG. Use this
/// for **non-secret** random material (salts, nonces, ephemeral-public
/// scratch) where zero-on-drop provides no security benefit. Returns
/// [`CryptoError::InternalCryptoFailure`] on the rare event the OS
/// CSPRNG read fails.
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    #[cfg(test)]
    {
        if deterministic_rng::try_fill(&mut buf) {
            return Ok(buf);
        }
    }
    OsRng.try_fill_bytes(&mut buf).map_err(|_| CSPRNG_FAILURE)?;
    Ok(buf)
}

/// Fill a fresh `Zeroizing<[u8; N]>` from the OS CSPRNG. Use this for
/// **secret** random material (file keys, ephemeral secret keys) where
/// drop-time clearing is the right default. Returns
/// [`CryptoError::InternalCryptoFailure`] on the rare event the OS
/// CSPRNG read fails.
pub(crate) fn random_secret<const N: usize>() -> Result<Zeroizing<[u8; N]>, CryptoError> {
    let mut buf = Zeroizing::new([0u8; N]);
    #[cfg(test)]
    {
        if deterministic_rng::try_fill(buf.as_mut()) {
            return Ok(buf);
        }
    }
    OsRng
        .try_fill_bytes(buf.as_mut())
        .map_err(|_| CSPRNG_FAILURE)?;
    Ok(buf)
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
    /// Generates a fresh `FileKey` from the OS CSPRNG. Returns
    /// [`CryptoError::InternalCryptoFailure`] on the rare event the OS
    /// CSPRNG read fails.
    pub(crate) fn generate() -> Result<Self, CryptoError> {
        Ok(Self(random_secret::<FILE_KEY_SIZE>()?))
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

    /// Test- and fuzz-only constructor for deterministic fixed-byte
    /// payload keys (the STREAM fuzz harness needs a reproducible key;
    /// see `fuzz_exports`). Production code receives a `PayloadKey`
    /// only from [`derive_subkeys`].
    #[cfg(any(test, feature = "unstable-fuzzing"))]
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
pub(crate) fn derive_passphrase_wrap_key(
    passphrase: &Passphrase,
    argon2_salt: &[u8; ARGON2_SALT_SIZE],
    kdf_params: &KdfParams,
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let ikm = kdf_params.hash_passphrase(passphrase.expose(), argon2_salt)?;
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

    /// The `testvectors/wire/` generator seals the stream so that every
    /// draw has to sit inside a per-case scope. A draw that escaped one
    /// would couple two artifacts, so it fails loudly instead.
    #[test]
    #[should_panic(expected = "random draw outside a seeded scope")]
    fn a_draw_outside_a_seeded_scope_is_refused_while_the_stream_is_sealed() {
        with_sealed_rng(|| {
            let _ = random_bytes::<8>();
        });
    }

    /// A guard left alive past its own case would make the next case
    /// continue the previous stream, which no later diff explains. The
    /// generator cannot detect that by reading itself, so opening a scope
    /// over a live one is refused here instead.
    #[test]
    #[should_panic(expected = "a seeded scope is still open")]
    fn opening_a_scope_over_a_live_one_is_refused() {
        with_sealed_rng(|| {
            let _outer = deterministic_seed_scope(7);
            let _inner = deterministic_seed_scope(9);
        });
    }

    /// Two scopes with the same seed draw the same bytes whatever ran
    /// between them, and the stream is sealed again once a scope ends.
    #[test]
    fn a_seeded_scope_is_independent_of_what_ran_before_it() {
        with_sealed_rng(|| {
            let draw = |seed| {
                let _scope = deterministic_seed_scope(seed);
                random_bytes::<8>().expect("seeded draw")
            };
            let first = draw(7);
            let unrelated = draw(9);
            let repeat = draw(7);
            assert_eq!(first, repeat, "the same seed must give the same bytes");
            assert_ne!(
                first, unrelated,
                "different seeds must give different bytes"
            );
        });
    }

    #[test]
    fn file_key_generate_has_correct_size() {
        let key = FileKey::generate().unwrap();
        assert_eq!(key.expose().len(), FILE_KEY_SIZE);
    }

    #[test]
    fn file_key_generate_is_random() {
        let a = FileKey::generate().unwrap();
        let b = FileKey::generate().unwrap();
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
        // Header key uses empty salt so stream_nonce must not affect it.
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
        let a = random_bytes::<32>().unwrap();
        let b = random_bytes::<32>().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn random_secret_has_correct_size_and_is_random() {
        let a = random_secret::<24>().unwrap();
        let b = random_secret::<24>().unwrap();
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

    /// Known-answer test against an independent reference.
    ///
    /// Every committed fixture is produced by this crate's own writer, so
    /// the round-trip tests above cannot catch a derivation that was wrong
    /// on day one — a swapped `payload`/`header` info string or a swapped
    /// salt convention would encrypt and decrypt consistently and still
    /// pass. The expected bytes here come from
    /// `testvectors/kat/hkdf_hmac_oracle.py`, which recomputes the two
    /// subkeys with the Python standard library (a different HKDF/SHA3
    /// implementation), so this test fails if either info string, the
    /// `salt = stream_nonce` payload convention, or the empty-salt header
    /// convention drifts from `FORMAT.md` §3.6 / §5.
    #[test]
    fn derive_subkeys_matches_independent_oracle() {
        let file_key = FileKey::from_bytes_for_tests([0x11u8; FILE_KEY_SIZE]);
        let nonce = [0x22u8; STREAM_NONCE_SIZE];
        let expected_payload: [u8; ENCRYPTION_KEY_SIZE] = [
            0xd5, 0xed, 0x06, 0x0d, 0x6d, 0xf1, 0x38, 0xfd, 0x16, 0x1e, 0x0c, 0x24, 0x72, 0xf1,
            0x2a, 0x5d, 0xc7, 0xaa, 0xb4, 0x5b, 0x1d, 0x0c, 0xc5, 0xb3, 0x23, 0x20, 0x7b, 0xf8,
            0x2f, 0xfb, 0x2e, 0x0e,
        ];
        let expected_header: [u8; HMAC_KEY_SIZE] = [
            0x2e, 0xc1, 0x4f, 0x24, 0x89, 0xc6, 0x32, 0xff, 0x34, 0x88, 0x8c, 0x20, 0x1b, 0x31,
            0x9d, 0xf6, 0x38, 0xd6, 0x17, 0xb2, 0x52, 0x40, 0x30, 0xa6, 0x66, 0x16, 0xeb, 0x3a,
            0x43, 0x36, 0x84, 0x34,
        ];
        let derived = derive_subkeys(&file_key, &nonce).unwrap();
        assert_eq!(*derived.payload_key.expose(), expected_payload);
        assert_eq!(*derived.header_key.expose(), expected_header);
    }
}
