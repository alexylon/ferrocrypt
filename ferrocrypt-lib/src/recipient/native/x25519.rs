//! `x25519` public-key recipient (`FORMAT.md` §4.2).
//!
//! Wrapping pipeline:
//!
//! ```text
//! ephemeral_secret = random 32-byte X25519 scalar
//! ephemeral_public_key_bytes = X25519(ephemeral_secret, basepoint)
//! shared           = X25519(ephemeral_secret, recipient_public_key_bytes)
//! wrap_key         = HKDF-SHA3-256(salt = ephemeral_public_key_bytes || recipient_public_key_bytes,
//!                                  ikm  = shared,
//!                                  info = "ferrocrypt/v1/recipient/x25519/wrap")
//! body             = ephemeral_public_key_bytes(32) || wrap_nonce(24) || wrapped_file_key(48)
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
//! slot-skippable: an all-zero shared secret is credential-independent
//! (any decryptor would compute the same value), so [`unwrap`] surfaces
//! it as `InvalidFormat(MalformedRecipientEntry)` and the
//! [`X25519Credential`] adapter propagates the error rather than
//! collapsing it to the slot-skip channel reserved for AEAD failures.

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::crypto::aead::{
    TAG_SIZE, WRAP_NONCE_SIZE, WRAPPED_FILE_KEY_SIZE, open_file_key, seal_file_key,
};
use crate::crypto::hkdf::hkdf_expand_sha3_256;
use crate::crypto::keys::{FileKey, random_bytes, random_secret};
use crate::crypto::mac::ct_eq_32;
use crate::error::FormatDefect;

/// Wire-format `type_name` for this recipient.
pub(crate) const TYPE_NAME: &str = "x25519";

/// X25519 public-key length in bytes.
pub(crate) const PUBLIC_KEY_SIZE: usize = 32;

/// X25519 private-key (scalar input) length in bytes.
pub(crate) const PRIVATE_KEY_SIZE: usize = 32;

/// Recipient body length in bytes (`FORMAT.md` §4.2).
pub(crate) const BODY_LENGTH: usize = PUBLIC_KEY_SIZE + WRAP_NONCE_SIZE + WRAPPED_FILE_KEY_SIZE;

/// HKDF-SHA3-256 `info` for the X25519 ECDH-derived wrap key.
pub(crate) const HKDF_INFO_WRAP: &[u8] = b"ferrocrypt/v1/recipient/x25519/wrap";

const EPHEMERAL_PUBLIC_KEY_OFFSET: usize = 0;
const WRAP_NONCE_OFFSET: usize = EPHEMERAL_PUBLIC_KEY_OFFSET + PUBLIC_KEY_SIZE;
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
pub(crate) fn is_zero_public_key(bytes: &[u8; PUBLIC_KEY_SIZE]) -> bool {
    ct_eq_32(bytes, &[0u8; PUBLIC_KEY_SIZE])
}

/// Little-endian encoding of the Curve25519 field prime `2^255 - 19`.
/// The canonical `FORMAT.md` §2.4 public-key encoding is strictly
/// below this value.
pub(crate) const FIELD_PRIME_LE: [u8; PUBLIC_KEY_SIZE] = [
    0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
];

/// Returns `true` when `bytes` is the canonical `FORMAT.md` §2.4
/// encoding of an X25519 public value: read as a little-endian
/// integer, it is strictly below the Curve25519 field prime.
///
/// The X25519 primitive masks the top bit and reduces modulo the
/// prime, so several byte patterns can name the same curve point.
/// FerroCrypt accepts exactly one of them, because the serialized
/// bytes are also bound into HKDF salts, checksums, and fingerprints;
/// callers reject the others rather than normalize them.
///
/// Branchless compare so timing of structural rejection cannot leak
/// the input bytes.
pub(crate) fn is_canonical_public_key_encoding(bytes: &[u8; PUBLIC_KEY_SIZE]) -> bool {
    // Little-endian `bytes < FIELD_PRIME_LE`: scanning from the most
    // significant byte, the first differing byte decides.
    let mut is_below = 0u8;
    let mut all_equal_so_far = 1u8;
    for (byte, prime_byte) in bytes.iter().zip(FIELD_PRIME_LE.iter()).rev() {
        is_below |= all_equal_so_far & u8::from(byte < prime_byte);
        all_equal_so_far &= u8::from(byte == prime_byte);
    }
    is_below == 1
}

/// `FORMAT.md` §4.2 pre-cryptographic checks for a parsed `x25519`
/// body: an all-zero or non-canonical `ephemeral_public_key_bytes`
/// rejects the entry with no credential, KDF, or key agreement. The
/// exact 104-byte length is enforced by the caller via the native
/// registry. Small-order ephemerals other than all-zero cannot be
/// screened here and stay covered by [`unwrap`]'s shared-secret check.
pub(crate) fn validate_body_preflight(body: &[u8]) -> Result<(), CryptoError> {
    let ephemeral: &[u8; PUBLIC_KEY_SIZE] = body
        .get(EPHEMERAL_PUBLIC_KEY_OFFSET..EPHEMERAL_PUBLIC_KEY_OFFSET + PUBLIC_KEY_SIZE)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(CryptoError::InvalidFormat(
            FormatDefect::MalformedRecipientEntry,
        ))?;
    if is_zero_public_key(ephemeral) || !is_canonical_public_key_encoding(ephemeral) {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedRecipientEntry,
        ));
    }
    Ok(())
}

/// Wraps `file_key` for an X25519 recipient.
///
/// Rejects a non-canonical `recipient_public_key_bytes` encoding first
/// (`FORMAT.md` §4.2: writers validate before the key agreement; every
/// `PublicKey` ingress already enforces this, so the check here is the
/// writer-side backstop for crate-internal callers). Then generates a
/// fresh ephemeral X25519 keypair, performs ECDH against
/// `recipient_public_key_bytes`, and rejects an all-zero shared secret. Derives
/// the wrap key via HKDF-SHA3-256 with a salt binding both ephemeral
/// and recipient public keys, then seals `file_key` via
/// XChaCha20-Poly1305 with empty AAD. Returns the canonical 104-byte
/// recipient body.
///
/// A non-canonical recipient encoding and an all-zero shared secret
/// both surface as [`CryptoError::InvalidInput`] with the "Invalid
/// recipient public key" message, since either way this is an
/// encrypt-time user error (the caller-supplied recipient public key
/// is unusable).
pub(crate) fn wrap(
    file_key: &FileKey,
    recipient_public_key_bytes: &[u8; PUBLIC_KEY_SIZE],
) -> Result<[u8; BODY_LENGTH], CryptoError> {
    if !is_canonical_public_key_encoding(recipient_public_key_bytes) {
        return Err(CryptoError::InvalidInput(
            "Invalid recipient public key".to_string(),
        ));
    }
    let ephemeral_raw = random_secret::<PRIVATE_KEY_SIZE>()?;
    let ephemeral_secret = StaticSecret::from(*ephemeral_raw);
    let ephemeral_public_key = PublicKey::from(&ephemeral_secret);
    let recipient_public_key = PublicKey::from(*recipient_public_key_bytes);
    let shared = ephemeral_secret.diffie_hellman(&recipient_public_key);
    if ct_eq_32(shared.as_bytes(), &[0u8; PUBLIC_KEY_SIZE]) {
        return Err(CryptoError::InvalidInput(
            "Invalid recipient public key".to_string(),
        ));
    }
    let wrap_key = derive_wrap_key(
        ephemeral_public_key.as_bytes(),
        recipient_public_key.as_bytes(),
        shared.as_bytes(),
    )?;
    let wrap_nonce = random_bytes::<WRAP_NONCE_SIZE>()?;
    let wrapped_file_key = seal_file_key(&wrap_key, &wrap_nonce, file_key)?;

    let mut body = [0u8; BODY_LENGTH];
    body[EPHEMERAL_PUBLIC_KEY_OFFSET..EPHEMERAL_PUBLIC_KEY_OFFSET + PUBLIC_KEY_SIZE]
        .copy_from_slice(ephemeral_public_key.as_bytes());
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
///   Credential-independent: any decryptor would observe the same all-zero
///   value, so the spec mandates file-fatal rejection. The
///   [`X25519Credential`] adapter propagates this error rather than
///   collapsing it to `Ok(None)`.
/// - **AEAD authentication failure:** wrong recipient private key or
///   tampered wrapped envelope — both surface as
///   [`CryptoError::RecipientUnwrapFailed`] with `type_name = "x25519"`.
///   Indistinguishable at the AEAD layer and credential-dependent (a
///   different key holder might still unwrap a sibling slot), so the
///   adapter collapses these into the slot-skip channel.
///
/// Per `FORMAT.md` §3.7 the candidate `file_key` is not considered
/// final until the header MAC also verifies.
pub(crate) fn unwrap(
    body: &[u8; BODY_LENGTH],
    private_key_bytes: &[u8; PRIVATE_KEY_SIZE],
) -> Result<FileKey, CryptoError> {
    let mut ephemeral_public_key_bytes = [0u8; PUBLIC_KEY_SIZE];
    ephemeral_public_key_bytes.copy_from_slice(
        &body[EPHEMERAL_PUBLIC_KEY_OFFSET..EPHEMERAL_PUBLIC_KEY_OFFSET + PUBLIC_KEY_SIZE],
    );

    let mut wrap_nonce = [0u8; WRAP_NONCE_SIZE];
    wrap_nonce.copy_from_slice(&body[WRAP_NONCE_OFFSET..WRAP_NONCE_OFFSET + WRAP_NONCE_SIZE]);

    let mut wrapped_file_key = [0u8; WRAPPED_FILE_KEY_SIZE];
    wrapped_file_key.copy_from_slice(&body[WRAPPED_FILE_KEY_OFFSET..]);

    let x25519_private_key = StaticSecret::from(*private_key_bytes);
    let recipient_public_key = PublicKey::from(&x25519_private_key);
    let ephemeral_public_key = PublicKey::from(ephemeral_public_key_bytes);
    let shared = x25519_private_key.diffie_hellman(&ephemeral_public_key);
    if ct_eq_32(shared.as_bytes(), &[0u8; PUBLIC_KEY_SIZE]) {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedRecipientEntry,
        ));
    }
    let wrap_key = derive_wrap_key(
        &ephemeral_public_key_bytes,
        recipient_public_key.as_bytes(),
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
    ephemeral_public_key_bytes: &[u8; PUBLIC_KEY_SIZE],
    recipient_public_key_bytes: &[u8; PUBLIC_KEY_SIZE],
    shared_secret: &[u8; PUBLIC_KEY_SIZE],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut salt = [0u8; 2 * PUBLIC_KEY_SIZE];
    salt[..PUBLIC_KEY_SIZE].copy_from_slice(ephemeral_public_key_bytes);
    salt[PUBLIC_KEY_SIZE..].copy_from_slice(recipient_public_key_bytes);
    hkdf_expand_sha3_256(Some(&salt), shared_secret, HKDF_INFO_WRAP)
}

// ─── Protocol-trait impls ──────────────────────────────────────────────────

/// Encrypt-side handle for the `x25519` recipient: borrows a 32-byte
/// recipient public key.
pub(crate) struct X25519Recipient<'a> {
    pub recipient_public_key_bytes: &'a [u8; PUBLIC_KEY_SIZE],
}

impl<'a> crate::protocol::RecipientScheme for X25519Recipient<'a> {
    const TYPE_NAME: &'static str = TYPE_NAME;
    // Read the rule from the native registry so adding or changing a
    // policy in `NativeRecipientType::mixing_rule` cannot drift away
    // from the encrypt-side trait const that the orchestrator uses
    // for its defense-in-depth cardinality check.
    const MIXING_RULE: crate::recipient::policy::NativeMixingRule =
        crate::recipient::policy::NativeRecipientType::X25519.mixing_rule();

    fn wrap_file_key(
        &self,
        file_key: &FileKey,
        // X25519 wrap is one ECDH + one HKDF + one AEAD — sub-millisecond
        // even at the structural recipient cap. Emitting a progress
        // event would lie about a long pause that never happens, so
        // the parameter is intentionally ignored (per the
        // `RecipientScheme::wrap_file_key` contract).
        _on_event: &dyn Fn(&crate::ProgressEvent),
    ) -> Result<crate::recipient::entry::RecipientBody, CryptoError> {
        let bytes = wrap(file_key, self.recipient_public_key_bytes)?;
        Ok(crate::recipient::entry::RecipientBody {
            type_name: TYPE_NAME,
            bytes: bytes.to_vec(),
        })
    }
}

/// Decrypt-side handle for the `x25519` recipient. Owns the 32-byte
/// recipient secret in `Zeroizing` so it's wiped on drop.
pub(crate) struct X25519Credential {
    pub private_key_bytes: Zeroizing<[u8; PRIVATE_KEY_SIZE]>,
}

impl crate::protocol::DecryptionCredential for X25519Credential {
    const TYPE_NAME: &'static str = TYPE_NAME;
    const EXPECTED_MODE: crate::UnauthenticatedRecipientMode =
        crate::UnauthenticatedRecipientMode::PublicKey;

    fn unwrap_file_key(
        &self,
        body: &[u8],
        // X25519 unwrap is one ECDH + one HKDF + one AEAD —
        // sub-millisecond. The parameter is intentionally ignored
        // (per the `DecryptionCredential::unwrap_file_key` contract); the
        // expensive `private.key` Argon2id step happens before the
        // slot loop, in `recipient::native::x25519::open_x25519_private_key`.
        _on_event: &dyn Fn(&crate::ProgressEvent),
    ) -> Result<Option<FileKey>, CryptoError> {
        let body_array: &[u8; BODY_LENGTH] = body
            .try_into()
            .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry))?;
        // Per [`unwrap`]'s contract, wrong-recipient-key and tampered-body
        // surface as `RecipientUnwrapFailed` (credential-dependent: collapse
        // to `Ok(None)` so the slot loop tries the next supported entry).
        // An all-zero ECDH shared secret surfaces as
        // `InvalidFormat(MalformedRecipientEntry)` (credential-independent
        // structural defect per FORMAT.md §2.4 / §4.2: propagate so the
        // entire file is rejected).
        match unwrap(body_array, &self.private_key_bytes) {
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
/// Returns [`CryptoError::InternalCryptoFailure`] on the rare event the
/// OS CSPRNG read fails.
///
/// Used by [`crate::generate_key_pair`] for the X25519-specific portion;
/// orchestration (file naming, `private.key` sealing, `public.key`
/// encoding, atomic finalize) lives in the higher-level entry point.
pub(crate) fn generate_keypair()
-> Result<(Zeroizing<[u8; PRIVATE_KEY_SIZE]>, [u8; PUBLIC_KEY_SIZE]), CryptoError> {
    let raw = random_secret::<PRIVATE_KEY_SIZE>()?;
    let secret = StaticSecret::from(*raw);
    let public = PublicKey::from(&secret);
    let secret_material = Zeroizing::new(secret.to_bytes());
    drop(secret);
    let public_material = *public.as_bytes();
    Ok((secret_material, public_material))
}

// ─── private.key reader (X25519-specific glue) ─────────────────────────────

/// Reads and unlocks a v1 `private.key` file, returning the raw 32-byte
/// X25519 secret. Wraps [`crate::key::private::open_private_key`] with
/// the X25519-specific type-name and length checks. Authenticated TLV
/// validation is performed by `open_private_key` itself.
///
/// Errors:
/// - [`CryptoError::InputPath`] if the file does not exist
/// - [`CryptoError::Io`] for other read errors
/// - [`CryptoError::KeyFileUnlockFailed`] for wrong passphrase or
///   tampered cleartext (AEAD cannot distinguish)
/// - [`CryptoError::InvalidInput`] for a passphrase outside the
///   `FORMAT.md` §2.2 byte-length bound
/// - [`CryptoError::InvalidKdfParams`] for header KDF fields outside
///   the v1 structural bounds
/// - [`CryptoError::KdfResourceCapExceeded`] when the header's
///   `mem_cost` exceeds `kdf_limit` (or the library default ceiling)
/// - [`CryptoError::UnsupportedVersion`] for a key file from an
///   unsupported keypair suite
/// - [`crate::error::FormatDefect::NotAKeyFile`] when the magic bytes do
///   not identify a FerroCrypt key file
/// - [`crate::error::FormatDefect::WrongKind`] when a binary FerroCrypt
///   artifact's `kind` byte is not the private-key kind
/// - [`crate::error::FormatDefect::MalformedTypeName`] when the stored
///   `type_name` violates the `FORMAT.md` §3.3 grammar
/// - [`crate::error::FormatDefect::WrongKeyFileType`] when the file is a
///   `public.key` text file rather than a binary `private.key`
/// - [`CryptoError::UnsupportedKeyType`] for a `private.key` that wraps a
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
    on_event: &dyn Fn(&crate::ProgressEvent),
) -> Result<Zeroizing<[u8; PRIVATE_KEY_SIZE]>, CryptoError> {
    use crate::error::FormatDefect;
    use crate::fs::paths::read_file_capped;
    use crate::key::files::KeyFileKind;
    use crate::key::private::{
        PRIVATE_KEY_FILE_READ_CAP_BYTES, PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT,
        open_private_key,
    };

    let bytes = read_file_capped(path, PRIVATE_KEY_FILE_READ_CAP_BYTES, || {
        CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)
    })?;

    // Friendly diagnostic for the cross-mix-up: a user pointing the
    // private-key reader at a `public.key` text file gets
    // `WrongKeyFileType` rather than the generic `NotAKeyFile` that
    // `open_private_key`'s magic check would surface.
    if matches!(KeyFileKind::classify(&bytes), KeyFileKind::Public) {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }

    // Deliberate order: the full unlock runs before the type-name
    // check, so the wrong-type verdict below is made on
    // AEAD-authenticated bytes. Checking the cleartext type name first
    // (via `validate_private_key_shape`) would skip one Argon2id run
    // when the user picks a wrong-type key file by mistake, but would
    // let a tampered cleartext name move the failure out of the
    // ambiguity-preserving `KeyFileUnlockFailed` class.
    let opened = open_private_key(
        &bytes,
        passphrase,
        kdf_limit,
        PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT,
        on_event,
    )?;

    if opened.type_name != TYPE_NAME {
        return Err(CryptoError::UnsupportedKeyType {
            type_name: opened.type_name.clone(),
        });
    }

    let public_material: [u8; PUBLIC_KEY_SIZE] = opened
        .public_material
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey))?;

    if opened.secret_material.len() != PRIVATE_KEY_SIZE {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ));
    }

    let mut secret = Zeroizing::new([0u8; PRIVATE_KEY_SIZE]);
    secret.copy_from_slice(&opened.secret_material);

    // FORMAT.md §8: native X25519 readers must compute
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
/// - `type_name` satisfies the `FORMAT.md` §3.3 grammar and is
///   `"x25519"`; a valid non-X25519 name rejects as
///   [`CryptoError::UnsupportedKeyType`];
/// - `public_len` equals the X25519 public-key size (32);
/// - `wrapped_secret_len` equals the native X25519 wrapped-secret size
///   (32-byte secret + 16-byte AEAD tag = 48, `FORMAT.md` §8);
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
    // Same order as `open_private_key`: grammar first, so a name that
    // violates the §3.3 grammar is malformed, not merely unsupported.
    crate::recipient::name::validate_type_name_grammar(type_name)?;
    if type_name != TYPE_NAME {
        return Err(CryptoError::UnsupportedKeyType {
            type_name: type_name.to_owned(),
        });
    }

    if header.public_len != PUBLIC_KEY_SIZE as u32 {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedPrivateKey,
        ));
    }

    // FORMAT.md §8: a native X25519 wrapped secret is exactly the
    // 32-byte scalar plus the 16-byte AEAD tag. The unlock path
    // re-rejects any other length after decryption; enforcing it here
    // keeps this validator's verdict aligned with what can unlock.
    if header.wrapped_secret_len != (PRIVATE_KEY_SIZE + TAG_SIZE) as u32 {
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
    use chacha20poly1305::aead::OsRng;
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
            &KdfParams::test_fast_default(),
        )?;
        fs::write(&path, bytes)?;

        match open_x25519_private_key(&path, &pass, None, &|_| {}).map(|_| ()) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => Ok(()),
            other => {
                panic!("expected MalformedPrivateKey for public/secret mismatch, got {other:?}")
            }
        }
    }

    /// A `private.key` whose `public_len` is a structurally valid value
    /// other than 32 (the X25519 size) decodes through the generic
    /// private-key reader, but the X25519 adapter must reject it: the
    /// stored public material cannot represent an X25519 point at any
    /// length other than 32. Surfaces as `MalformedPrivateKey`.
    #[test]
    fn open_private_key_rejects_x25519_public_len_mismatch() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("private.key");
        let pass = SecretString::from("pw".to_string());

        let secret = StaticSecret::random_from_rng(OsRng);
        let secret_material = secret.to_bytes();
        let malformed_public = [0u8; PUBLIC_KEY_SIZE - 1];

        let bytes = seal_private_key(
            &secret_material,
            TYPE_NAME,
            &malformed_public,
            &[],
            &pass,
            &KdfParams::test_fast_default(),
        )?;
        fs::write(&path, bytes)?;

        match open_x25519_private_key(&path, &pass, None, &|_| {}).map(|_| ()) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => Ok(()),
            other => panic!("expected MalformedPrivateKey for public_len mismatch, got {other:?}"),
        }
    }

    /// A `private.key` wrapping a valid non-X25519 key kind is the
    /// planned forward-compatibility case from `FORMAT.md` §11. The
    /// unlock path classifies it only after AEAD authentication and
    /// reports `UnsupportedKeyType` naming the stored type.
    #[test]
    fn open_private_key_rejects_unsupported_key_type() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("private.key");
        let pass = SecretString::from("pw".to_string());
        let events = std::cell::RefCell::new(Vec::new());
        let sink = |event: &crate::ProgressEvent| events.borrow_mut().push(*event);

        let (secret_material, public_material) = keypair();
        let bytes = seal_private_key(
            &secret_material,
            "future",
            &public_material,
            &[],
            &pass,
            &KdfParams::test_fast_default(),
        )?;
        fs::write(&path, bytes)?;

        match open_x25519_private_key(&path, &pass, None, &sink).map(|_| ()) {
            Err(CryptoError::UnsupportedKeyType { type_name }) => {
                assert_eq!(type_name, "future");
            }
            other => panic!("expected UnsupportedKeyType for a future key kind, got {other:?}"),
        }
        assert_eq!(
            events.borrow().as_slice(),
            &[crate::ProgressEvent::UnlockingPrivateKey],
            "the type verdict requires an authenticated unlock"
        );
        Ok(())
    }

    /// A real public/private file crossing is classified before the
    /// generic private-key unlock, so it keeps `WrongKeyFileType` and
    /// emits no KDF progress event.
    #[test]
    fn open_private_key_rejects_public_key_file_before_progress() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("public.key");
        let pass = SecretString::from("pw".to_string());
        let (_, public_material) = keypair();
        let recipient = crate::key::public::encode_recipient_string(TYPE_NAME, &public_material)?;
        fs::write(&path, format!("{recipient}\n"))?;

        let events = std::cell::RefCell::new(Vec::new());
        let sink = |event: &crate::ProgressEvent| events.borrow_mut().push(*event);
        match open_x25519_private_key(&path, &pass, None, &sink).map(|_| ()) {
            Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType)) => {}
            other => panic!("expected WrongKeyFileType for public.key, got {other:?}"),
        }
        assert!(
            events.borrow().is_empty(),
            "a public/private crossing must reject before Argon2id"
        );
        Ok(())
    }

    /// The structural validator reaches the same verdict as the unlock
    /// path for a non-X25519 key kind, without needing the passphrase.
    #[test]
    fn validate_private_key_shape_rejects_unsupported_key_type() -> Result<(), CryptoError> {
        let (secret_material, public_material) = keypair();
        let bytes = seal_private_key(
            &secret_material,
            "future",
            &public_material,
            &[],
            &SecretString::from("pw".to_string()),
            &KdfParams::test_fast_default(),
        )?;
        match validate_private_key_shape(&bytes) {
            Err(CryptoError::UnsupportedKeyType { type_name }) => {
                assert_eq!(type_name, "future");
                Ok(())
            }
            other => panic!("expected UnsupportedKeyType from the shape validator, got {other:?}"),
        }
    }

    fn keypair() -> ([u8; PRIVATE_KEY_SIZE], [u8; PUBLIC_KEY_SIZE]) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret.to_bytes(), *public.as_bytes())
    }

    #[test]
    fn body_length_matches_field_sum() {
        assert_eq!(
            BODY_LENGTH,
            PUBLIC_KEY_SIZE + WRAP_NONCE_SIZE + WRAPPED_FILE_KEY_SIZE
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
    fn unwrap_with_tampered_ephemeral_public_key_fails_with_recipient_unwrap_failed() {
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
        let (sk, pk) = keypair();
        let mut body = wrap(&file_key, &pk).unwrap();
        body[EPHEMERAL_PUBLIC_KEY_OFFSET] ^= 0x01;
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
        // An all-zero ephemeral public_key is a known X25519 small-order
        // point: X25519(any_secret, all_zero_public_key) = all_zero_shared.
        // Per `FORMAT.md` §2.4 / §4.2 this must be rejected by readers
        // before deriving the wrap key, and the rejection is
        // credential-independent — readers must surface it as a structural
        // defect (file-fatal) rather than as a slot-skippable AEAD
        // failure, so the [`X25519Credential`] adapter propagates the
        // error instead of collapsing to `Ok(None)`.
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
        let (sk, pk) = keypair();
        let mut body = wrap(&file_key, &pk).unwrap();
        body[EPHEMERAL_PUBLIC_KEY_OFFSET..EPHEMERAL_PUBLIC_KEY_OFFSET + PUBLIC_KEY_SIZE].fill(0);
        match unwrap(&body, &sk) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => {
                panic!("expected MalformedRecipientEntry for all-zero ephemeral, got {other:?}")
            }
        }
    }

    /// Credential-adapter contract: an all-zero shared secret must not be
    /// collapsed into the slot-skip channel. The adapter propagates
    /// `InvalidFormat(MalformedRecipientEntry)` so the surrounding
    /// decrypt loop rejects the whole file (FORMAT.md §2.4 / §4.2).
    /// Wrong-key AEAD failures keep their existing `Ok(None)` mapping —
    /// covered by the dedicated wrong-key test above.
    #[test]
    fn credential_adapter_propagates_all_zero_shared_secret() {
        use crate::protocol::DecryptionCredential;

        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
        let (sk, pk) = keypair();
        let mut body_bytes = wrap(&file_key, &pk).unwrap();
        body_bytes[EPHEMERAL_PUBLIC_KEY_OFFSET..EPHEMERAL_PUBLIC_KEY_OFFSET + PUBLIC_KEY_SIZE]
            .fill(0);

        let credential = X25519Credential {
            private_key_bytes: Zeroizing::new(sk),
        };
        match credential.unwrap_file_key(&body_bytes, &|_| {}) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => panic!(
                "adapter must propagate all-zero shared as MalformedRecipientEntry, got {other:?}"
            ),
        }
    }

    #[test]
    fn wrap_rejects_all_zero_recipient_public_key() {
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
        let zero_pk = [0u8; PUBLIC_KEY_SIZE];
        match wrap(&file_key, &zero_pk) {
            Err(CryptoError::InvalidInput(msg)) => {
                assert!(msg.contains("Invalid recipient"));
            }
            other => panic!("expected InvalidInput for all-zero public_key, got {other:?}"),
        }
    }

    #[test]
    fn wrap_rejects_non_canonical_recipient_public_key() {
        // A generated key with the top bit set is an RFC 7748 alias of
        // the same point; the writer must refuse it rather than emit a
        // body no matching private key can open (FORMAT.md §4.2).
        let file_key = FileKey::from_bytes_for_tests([0u8; FILE_KEY_SIZE]);
        let (_, mut pk) = keypair();
        pk[PUBLIC_KEY_SIZE - 1] |= 0x80;
        match wrap(&file_key, &pk) {
            Err(CryptoError::InvalidInput(msg)) => assert!(msg.contains("Invalid recipient")),
            other => panic!("expected InvalidInput for non-canonical public_key, got {other:?}"),
        }
    }

    #[test]
    fn canonical_encoding_accepts_valid_and_boundary_values() {
        let (_, pk) = keypair();
        assert!(is_canonical_public_key_encoding(&pk));
        // p - 1 is the largest canonical value.
        let mut max_canonical = FIELD_PRIME_LE;
        max_canonical[0] -= 1;
        assert!(is_canonical_public_key_encoding(&max_canonical));
        // All-zero is canonical as an integer; the zero-point reject is
        // a separate check.
        assert!(is_canonical_public_key_encoding(&[0u8; PUBLIC_KEY_SIZE]));
    }

    #[test]
    fn canonical_encoding_rejects_prime_and_aliases() {
        // p, p + 1, ... 2^255 - 1 are the wrap-around aliases.
        assert!(!is_canonical_public_key_encoding(&FIELD_PRIME_LE));
        let mut prime_plus_one = FIELD_PRIME_LE;
        prime_plus_one[0] += 1;
        assert!(!is_canonical_public_key_encoding(&prime_plus_one));
        // High-bit alias of a generated key.
        let (_, mut pk) = keypair();
        pk[PUBLIC_KEY_SIZE - 1] |= 0x80;
        assert!(!is_canonical_public_key_encoding(&pk));
        // Largest 256-bit value.
        assert!(!is_canonical_public_key_encoding(
            &[0xFFu8; PUBLIC_KEY_SIZE]
        ));
    }

    #[test]
    fn preflight_rejects_zero_and_non_canonical_ephemeral() {
        let file_key = FileKey::from_bytes_for_tests([0x22u8; FILE_KEY_SIZE]);
        let (_, pk) = keypair();
        let valid = wrap(&file_key, &pk).unwrap();
        validate_body_preflight(&valid).expect("a wrapped body must pass the preflight");

        let mut zero_ephemeral = valid;
        zero_ephemeral[EPHEMERAL_PUBLIC_KEY_OFFSET..EPHEMERAL_PUBLIC_KEY_OFFSET + PUBLIC_KEY_SIZE]
            .fill(0);
        match validate_body_preflight(&zero_ephemeral) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => panic!("expected reject for all-zero ephemeral, got {other:?}"),
        }

        let mut alias_ephemeral = valid;
        alias_ephemeral[PUBLIC_KEY_SIZE - 1] |= 0x80;
        match validate_body_preflight(&alias_ephemeral) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => panic!("expected reject for non-canonical ephemeral, got {other:?}"),
        }
    }

    #[test]
    fn body_field_offsets_are_correct() {
        // Wire-format regression: the body layout must be exactly
        // ephemeral_public_key(32) || wrap_nonce(24) || wrapped(48). A
        // reordering would produce a body that this reader rejects
        // and that conforming readers reject the same way.
        let file_key = FileKey::from_bytes_for_tests([0x11u8; FILE_KEY_SIZE]);
        let (_, pk) = keypair();
        let body = wrap(&file_key, &pk).unwrap();
        assert_eq!(EPHEMERAL_PUBLIC_KEY_OFFSET, 0);
        assert_eq!(WRAP_NONCE_OFFSET, 32);
        assert_eq!(WRAPPED_FILE_KEY_OFFSET, 56);
        assert_eq!(body.len(), 104);
    }

    /// `FORMAT.md` §8 fixes the native X25519 `wrapped_secret_len` at
    /// 48 (32-byte scalar + 16-byte tag). A header declaring any other
    /// length — with a consistent total file length, so the generic
    /// checks pass — must fail shape validation, because the unlock
    /// path can never accept it and a "well-formed" verdict would be
    /// misleading.
    #[test]
    fn validate_private_key_shape_rejects_wrong_wrapped_secret_len() {
        use crate::crypto::kdf::ARGON2_SALT_SIZE;
        use crate::key::private::PrivateKeyHeader;

        let build = |wrapped_secret_len: u32| {
            let header = PrivateKeyHeader {
                key_flags: 0,
                type_name_len: TYPE_NAME.len() as u16,
                public_len: PUBLIC_KEY_SIZE as u32,
                ext_len: 0,
                wrapped_secret_len,
                argon2_salt: [0u8; ARGON2_SALT_SIZE],
                kdf_params: KdfParams::test_fast_default(),
                wrap_nonce: [0u8; WRAP_NONCE_SIZE],
            };
            let mut data = header.to_bytes().to_vec();
            data.extend_from_slice(TYPE_NAME.as_bytes());
            data.extend_from_slice(&[0x07u8; PUBLIC_KEY_SIZE]);
            data.extend_from_slice(&vec![0u8; wrapped_secret_len as usize]);
            data
        };

        let expected = (PRIVATE_KEY_SIZE + TAG_SIZE) as u32;
        validate_private_key_shape(&build(expected)).expect("canonical length must pass");
        for wrong in [expected - 1, expected + 1] {
            match validate_private_key_shape(&build(wrong)) {
                Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => {}
                other => {
                    panic!(
                        "expected MalformedPrivateKey for wrapped_secret_len {wrong}, got {other:?}"
                    )
                }
            }
        }
    }
}
