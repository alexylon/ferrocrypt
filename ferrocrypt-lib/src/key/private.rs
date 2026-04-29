//! v1 `private.key` artefact (`FORMAT.md` §8).
//!
//! On-disk layout:
//!
//! ```text
//! [fixed_header (90 bytes)]
//!   magic(4)              = "FCR\0"
//!   version(1)            = 0x01
//!   kind(1)               = 0x4B 'K'
//!   key_flags(2)          = 0
//!   type_name_len(2)
//!   public_len(4)
//!   ext_len(4)
//!   wrapped_secret_len(4)
//!   argon2_salt(32)
//!   kdf_params(12)
//!   wrap_nonce(24)
//!
//! [type_name (type_name_len)]
//! [public_material (public_len)]
//! [ext_bytes (ext_len)]
//! [wrapped_secret (wrapped_secret_len)]
//! ```
//!
//! `wrapped_secret` is `XChaCha20-Poly1305(secret_material)` keyed by
//! `HKDF-SHA3-256(salt = argon2_salt, ikm = Argon2id(...), info =
//! "ferrocrypt/v1/private-key/wrap")`, with `nonce = wrap_nonce` and
//! AAD covering every byte before `wrapped_secret`. Tampering any
//! cleartext byte fails AEAD authentication and surfaces as
//! [`CryptoError::KeyFileUnlockFailed`] — wrong passphrase and
//! cleartext-tamper are indistinguishable at the AEAD layer.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::crypto::aead::{TAG_SIZE, WRAP_NONCE_SIZE};
use crate::crypto::kdf::{ARGON2_SALT_SIZE, KDF_PARAMS_SIZE, KdfLimit, KdfParams};
use crate::crypto::keys::{derive_passphrase_wrap_key, random_bytes};
use crate::error::FormatDefect;
use crate::format::{
    KIND_PRIVATE_KEY, MAGIC, MAGIC_SIZE, VERSION, read_u16_be, read_u32_be,
    unsupported_key_version_error, write_u16_be, write_u32_be,
};
use crate::recipients::{TYPE_NAME_MAX_LEN, validate_type_name};

/// HKDF info for deriving the `private.key` wrap key from Argon2id.
pub(crate) const HKDF_INFO_PRIVATE_KEY_WRAP: &[u8] = b"ferrocrypt/v1/private-key/wrap";

/// Size of the cleartext fixed-header section, in bytes.
pub const PRIVATE_KEY_HEADER_FIXED_SIZE: usize = 90;

/// Structural maximum for `public_len` (`FORMAT.md` §8).
pub const PRIVATE_KEY_PUBLIC_LEN_MAX: u32 = 12_288;

/// Structural maximum for `ext_len` in `private.key` (`FORMAT.md` §8).
pub const PRIVATE_KEY_EXT_LEN_MAX: u32 = 65_536;

/// Structural minimum for `wrapped_secret_len` — the Poly1305 tag is 16
/// bytes, so a zero-length plaintext still produces 16 ciphertext bytes.
pub const PRIVATE_KEY_WRAPPED_SECRET_LEN_MIN: u32 = TAG_SIZE as u32;

/// Structural maximum for `wrapped_secret_len` (`FORMAT.md` §8).
pub const PRIVATE_KEY_WRAPPED_SECRET_LEN_MAX: u32 = 16_777_216;

/// Recommended local cap on `wrapped_secret_len` for untrusted input.
/// X25519 needs only 48 bytes (32-byte secret + 16-byte tag); 4 KiB
/// leaves headroom for future native key types without forcing every
/// caller to raise the cap.
pub const PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT: u32 = 4_096;

const VERSION_OFFSET: usize = MAGIC_SIZE;
const KIND_OFFSET: usize = VERSION_OFFSET + 1;
const KEY_FLAGS_OFFSET: usize = KIND_OFFSET + 1;
const TYPE_NAME_LEN_OFFSET: usize = KEY_FLAGS_OFFSET + size_of::<u16>();
const PUBLIC_LEN_OFFSET: usize = TYPE_NAME_LEN_OFFSET + size_of::<u16>();
const EXT_LEN_OFFSET: usize = PUBLIC_LEN_OFFSET + size_of::<u32>();
const WRAPPED_SECRET_LEN_OFFSET: usize = EXT_LEN_OFFSET + size_of::<u32>();
const ARGON2_SALT_OFFSET: usize = WRAPPED_SECRET_LEN_OFFSET + size_of::<u32>();
const KDF_PARAMS_OFFSET: usize = ARGON2_SALT_OFFSET + ARGON2_SALT_SIZE;
const WRAP_NONCE_OFFSET: usize = KDF_PARAMS_OFFSET + KDF_PARAMS_SIZE;
const _: () = assert!(WRAP_NONCE_OFFSET + WRAP_NONCE_SIZE == PRIVATE_KEY_HEADER_FIXED_SIZE);

/// Cleartext fixed-header section of a v1 `private.key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKeyHeader {
    pub key_flags: u16,
    pub type_name_len: u16,
    pub public_len: u32,
    pub ext_len: u32,
    pub wrapped_secret_len: u32,
    pub argon2_salt: [u8; ARGON2_SALT_SIZE],
    pub kdf_params: KdfParams,
    pub wrap_nonce: [u8; WRAP_NONCE_SIZE],
}

impl PrivateKeyHeader {
    /// Serialises the 90-byte cleartext fixed-header section.
    pub fn to_bytes(&self) -> [u8; PRIVATE_KEY_HEADER_FIXED_SIZE] {
        let mut out = [0u8; PRIVATE_KEY_HEADER_FIXED_SIZE];
        out[..MAGIC_SIZE].copy_from_slice(&MAGIC);
        out[VERSION_OFFSET] = VERSION;
        out[KIND_OFFSET] = KIND_PRIVATE_KEY;
        write_u16_be(&mut out, KEY_FLAGS_OFFSET, self.key_flags);
        write_u16_be(&mut out, TYPE_NAME_LEN_OFFSET, self.type_name_len);
        write_u32_be(&mut out, PUBLIC_LEN_OFFSET, self.public_len);
        write_u32_be(&mut out, EXT_LEN_OFFSET, self.ext_len);
        write_u32_be(&mut out, WRAPPED_SECRET_LEN_OFFSET, self.wrapped_secret_len);
        out[ARGON2_SALT_OFFSET..ARGON2_SALT_OFFSET + ARGON2_SALT_SIZE]
            .copy_from_slice(&self.argon2_salt);
        out[KDF_PARAMS_OFFSET..KDF_PARAMS_OFFSET + KDF_PARAMS_SIZE]
            .copy_from_slice(&self.kdf_params.to_bytes());
        out[WRAP_NONCE_OFFSET..WRAP_NONCE_OFFSET + WRAP_NONCE_SIZE]
            .copy_from_slice(&self.wrap_nonce);
        out
    }

    /// Parses and structurally validates the 90-byte cleartext header.
    /// Validates magic → version → kind → key_flags → length-field
    /// structural caps → kdf_params structural ranges. Length-field
    /// consistency against the on-disk file size is checked at the
    /// [`open_private_key`] layer.
    pub fn parse(bytes: &[u8; PRIVATE_KEY_HEADER_FIXED_SIZE]) -> Result<Self, CryptoError> {
        if bytes[..MAGIC_SIZE] != MAGIC {
            return Err(CryptoError::InvalidFormat(FormatDefect::NotAKeyFile));
        }
        let version = bytes[VERSION_OFFSET];
        if version != VERSION {
            return Err(unsupported_key_version_error(version));
        }
        let kind_byte = bytes[KIND_OFFSET];
        if kind_byte != KIND_PRIVATE_KEY {
            return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
        }
        let key_flags = read_u16_be(bytes, KEY_FLAGS_OFFSET);
        check_key_flags(key_flags)?;
        let type_name_len = read_u16_be(bytes, TYPE_NAME_LEN_OFFSET);
        check_type_name_len(type_name_len)?;
        let public_len = read_u32_be(bytes, PUBLIC_LEN_OFFSET);
        check_public_len(public_len)?;
        let ext_len = read_u32_be(bytes, EXT_LEN_OFFSET);
        check_ext_len(ext_len)?;
        let wrapped_secret_len = read_u32_be(bytes, WRAPPED_SECRET_LEN_OFFSET);
        check_wrapped_secret_len(wrapped_secret_len)?;
        let mut argon2_salt = [0u8; ARGON2_SALT_SIZE];
        argon2_salt
            .copy_from_slice(&bytes[ARGON2_SALT_OFFSET..ARGON2_SALT_OFFSET + ARGON2_SALT_SIZE]);
        let mut kdf_params_bytes = [0u8; KDF_PARAMS_SIZE];
        kdf_params_bytes
            .copy_from_slice(&bytes[KDF_PARAMS_OFFSET..KDF_PARAMS_OFFSET + KDF_PARAMS_SIZE]);
        // Structural KDF-parameter validation only (lanes, time_cost,
        // mem_cost against v1 absolute bounds). Caller-supplied resource
        // policy is applied separately in `open_private_key` so a
        // caller's explicit higher `KdfLimit` is not silently overridden
        // by the library's default ceiling at parse time.
        let kdf_params = KdfParams::from_bytes_structural(&kdf_params_bytes)?;
        let mut wrap_nonce = [0u8; WRAP_NONCE_SIZE];
        wrap_nonce.copy_from_slice(&bytes[WRAP_NONCE_OFFSET..WRAP_NONCE_OFFSET + WRAP_NONCE_SIZE]);
        Ok(Self {
            key_flags,
            type_name_len,
            public_len,
            ext_len,
            wrapped_secret_len,
            argon2_salt,
            kdf_params,
            wrap_nonce,
        })
    }
}

// Per-field structural checks. Shared by `PrivateKeyHeader::parse` (reader)
// and `seal_private_key` (writer) for the cap rules so the two paths cannot
// drift. `key_flags` and `type_name_len` are reader-only because the writer
// builds them from validated inputs (`key_flags = 0` literally; type_name
// length is bounded by the prior `validate_type_name` call).

fn check_key_flags(flags: u16) -> Result<(), CryptoError> {
    if flags != 0 {
        return Err(malformed_private_key());
    }
    Ok(())
}

fn check_type_name_len(len: u16) -> Result<(), CryptoError> {
    if len == 0 || len as usize > TYPE_NAME_MAX_LEN {
        return Err(malformed_private_key());
    }
    Ok(())
}

fn check_public_len(len: u32) -> Result<(), CryptoError> {
    if len > PRIVATE_KEY_PUBLIC_LEN_MAX {
        return Err(malformed_private_key());
    }
    Ok(())
}

fn check_ext_len(len: u32) -> Result<(), CryptoError> {
    if len > PRIVATE_KEY_EXT_LEN_MAX {
        return Err(malformed_private_key());
    }
    Ok(())
}

fn check_wrapped_secret_len(len: u32) -> Result<(), CryptoError> {
    if !(PRIVATE_KEY_WRAPPED_SECRET_LEN_MIN..=PRIVATE_KEY_WRAPPED_SECRET_LEN_MAX).contains(&len) {
        return Err(malformed_private_key());
    }
    Ok(())
}

fn malformed_private_key() -> CryptoError {
    CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)
}

/// Decrypted contents of a v1 `private.key`. The unwrapped
/// `secret_material` is held in a [`Zeroizing`] buffer so it clears on
/// drop. `Debug` is implemented manually to redact the secret — auto-
/// deriving would forward through `Zeroizing`'s `Deref` and print the
/// raw bytes.
pub struct OpenedPrivateKey {
    pub type_name: String,
    pub public_material: Vec<u8>,
    pub ext_bytes: Vec<u8>,
    pub secret_material: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for OpenedPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedPrivateKey")
            .field("type_name", &self.type_name)
            .field("public_material", &self.public_material)
            .field("ext_bytes", &self.ext_bytes)
            .field("secret_material", &"<redacted>")
            .finish()
    }
}

/// Seals `secret_material` for the given recipient type into a v1
/// `private.key` byte sequence. Generates fresh `argon2_salt` and
/// `wrap_nonce`, derives the wrap key via Argon2id + HKDF-SHA3-256, and
/// AEAD-encrypts with the cleartext (header + type_name +
/// public_material + ext_bytes) as AAD. Returns the full on-disk file
/// ready for atomic write.
pub fn seal_private_key(
    secret_material: &[u8],
    type_name: &str,
    public_material: &[u8],
    ext_bytes: &[u8],
    passphrase: &SecretString,
    kdf_params: &KdfParams,
) -> Result<Vec<u8>, CryptoError> {
    validate_type_name(type_name)?;

    let type_name_bytes = type_name.as_bytes();
    let type_name_len = u16::try_from(type_name_bytes.len())
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedTypeName))?;
    let public_len = u32::try_from(public_material.len()).map_err(|_| malformed_private_key())?;
    check_public_len(public_len)?;
    let ext_len = u32::try_from(ext_bytes.len()).map_err(|_| malformed_private_key())?;
    check_ext_len(ext_len)?;
    let wrapped_secret_len_usize = secret_material
        .len()
        .checked_add(TAG_SIZE)
        .ok_or_else(malformed_private_key)?;
    let wrapped_secret_len =
        u32::try_from(wrapped_secret_len_usize).map_err(|_| malformed_private_key())?;
    check_wrapped_secret_len(wrapped_secret_len)?;

    let argon2_salt = random_bytes::<ARGON2_SALT_SIZE>();
    let wrap_nonce = random_bytes::<WRAP_NONCE_SIZE>();

    let header = PrivateKeyHeader {
        key_flags: 0,
        type_name_len,
        public_len,
        ext_len,
        wrapped_secret_len,
        argon2_salt,
        kdf_params: *kdf_params,
        wrap_nonce,
    };

    let header_bytes = header.to_bytes();
    let cleartext_len = PRIVATE_KEY_HEADER_FIXED_SIZE
        + type_name_bytes.len()
        + public_material.len()
        + ext_bytes.len();
    let mut cleartext = Vec::with_capacity(cleartext_len);
    cleartext.extend_from_slice(&header_bytes);
    cleartext.extend_from_slice(type_name_bytes);
    cleartext.extend_from_slice(public_material);
    cleartext.extend_from_slice(ext_bytes);

    let wrap_key = derive_passphrase_wrap_key(
        passphrase,
        &argon2_salt,
        kdf_params,
        HKDF_INFO_PRIVATE_KEY_WRAP,
    )?;
    let cipher = XChaCha20Poly1305::new(wrap_key.as_ref().into());
    let nonce = XNonce::from_slice(&wrap_nonce);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: secret_material,
                aad: &cleartext,
            },
        )
        .map_err(|_| {
            CryptoError::InternalCryptoFailure("Internal error: private key seal failed")
        })?;

    let mut out = cleartext;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Parses and unlocks a v1 `private.key` byte sequence. Validates the
/// cleartext header structurally, applies `local_wrapped_secret_cap` as
/// resource policy, slices the variable-length sections, and
/// AEAD-decrypts the wrapped secret using AAD covering all cleartext
/// bytes.
///
/// On AEAD failure surfaces [`CryptoError::KeyFileUnlockFailed`] —
/// wrong passphrase and tampered cleartext fields are
/// indistinguishable at the AEAD layer.
pub fn open_private_key(
    bytes: &[u8],
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
    local_wrapped_secret_cap: u32,
) -> Result<OpenedPrivateKey, CryptoError> {
    let header_bytes = bytes
        .first_chunk::<PRIVATE_KEY_HEADER_FIXED_SIZE>()
        .ok_or_else(malformed_private_key)?;
    let header = PrivateKeyHeader::parse(header_bytes)?;

    // Apply the caller's resource policy. `parse` only enforces the
    // v1 absolute structural ceiling (2 GiB mem); this surfaces the
    // caller's `KdfLimit` (or the library default of 1 GiB when the
    // caller passed `None`) as `KdfResourceCapExceeded` before any
    // Argon2id work runs. Without this split, a structurally valid
    // header in the 1–2 GiB band could not be unlocked even when the
    // caller explicitly opted into a higher limit.
    header.kdf_params.enforce_limit(kdf_limit)?;

    if header.wrapped_secret_len > local_wrapped_secret_cap {
        return Err(malformed_private_key());
    }

    let total = (PRIVATE_KEY_HEADER_FIXED_SIZE as u64)
        .checked_add(header.type_name_len as u64)
        .and_then(|v| v.checked_add(header.public_len as u64))
        .and_then(|v| v.checked_add(header.ext_len as u64))
        .and_then(|v| v.checked_add(header.wrapped_secret_len as u64))
        .ok_or_else(malformed_private_key)?;
    if (bytes.len() as u64) != total {
        return Err(malformed_private_key());
    }

    let type_name_start = PRIVATE_KEY_HEADER_FIXED_SIZE;
    let type_name_end = type_name_start + header.type_name_len as usize;
    let public_end = type_name_end + header.public_len as usize;
    let ext_end = public_end + header.ext_len as usize;
    let wrapped_secret_end = ext_end + header.wrapped_secret_len as usize;

    let type_name_bytes = &bytes[type_name_start..type_name_end];
    let type_name = std::str::from_utf8(type_name_bytes)
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedTypeName))?;
    validate_type_name(type_name)?;

    let public_material = bytes[type_name_end..public_end].to_vec();
    let ext_bytes_slice = bytes[public_end..ext_end].to_vec();
    let wrapped_secret = &bytes[ext_end..wrapped_secret_end];
    let cleartext = &bytes[..ext_end];

    let wrap_key = derive_passphrase_wrap_key(
        passphrase,
        &header.argon2_salt,
        &header.kdf_params,
        HKDF_INFO_PRIVATE_KEY_WRAP,
    )?;
    let cipher = XChaCha20Poly1305::new(wrap_key.as_ref().into());
    let nonce = XNonce::from_slice(&header.wrap_nonce);
    // Wrap into `Zeroizing` *inside* the decrypt expression so the
    // unwrapped secret never lives as a bare `Vec<u8>` on the stack,
    // not even for one statement. A panic between decrypt-success and
    // the wrapper would otherwise free the allocation without zeroing
    // and leave cleartext in the released memory.
    let secret_material = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: wrapped_secret,
                    aad: cleartext,
                },
            )
            .map_err(|_| CryptoError::KeyFileUnlockFailed)?,
    );

    Ok(OpenedPrivateKey {
        type_name: type_name.to_owned(),
        public_material,
        ext_bytes: ext_bytes_slice,
        secret_material,
    })
}

// ─── Private-key wrapper ───────────────────────────────────────────────────

/// Source of a private key for hybrid decryption.
///
/// Today the only supported source is a passphrase-protected FerroCrypt
/// private-key file on disk. The wrapper is kept deliberately thin and
/// `#[non_exhaustive]` so future sources (for example in-memory encrypted
/// secrets or hardware-backed keys) can be added without a breaking
/// change to [`crate::HybridDecryptConfig`].
///
/// Construct with [`PrivateKey::from_key_file`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PrivateKey {
    source: PrivateKeySource,
}

#[derive(Debug, Clone)]
enum PrivateKeySource {
    KeyFile(std::path::PathBuf),
}

impl PrivateKey {
    /// References a passphrase-protected FerroCrypt private-key file at
    /// the given path. The file is not opened until the private key is
    /// used in a decrypt operation.
    pub fn from_key_file(path: impl AsRef<std::path::Path>) -> Self {
        Self {
            source: PrivateKeySource::KeyFile(path.as_ref().to_path_buf()),
        }
    }

    /// Internal: returns the key-file path for source variants that
    /// point at one. Every current variant does; future non-path
    /// sources would extend this enum and the decrypt path with a
    /// different resolution strategy.
    pub(crate) fn key_file_path(&self) -> &std::path::Path {
        match &self.source {
            PrivateKeySource::KeyFile(path) => path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::UnsupportedVersion;

    /// Pins the private-key wrap HKDF info string against silent typos.
    /// Recipient and payload/header info strings are pinned alongside
    /// their owning module's tests.
    #[test]
    fn hkdf_info_string_is_canonical() {
        assert_eq!(
            HKDF_INFO_PRIVATE_KEY_WRAP,
            b"ferrocrypt/v1/private-key/wrap"
        );
    }

    fn test_passphrase(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    /// Returns (secret_material, public_material) for a fixed-byte
    /// X25519-shaped pair. The contents are arbitrary — `private_key`'s
    /// AEAD primitives do not interpret them.
    fn x25519_shaped() -> ([u8; 32], [u8; 32]) {
        ([0x11u8; 32], [0x22u8; 32])
    }

    #[test]
    fn round_trip_x25519_shaped() {
        let (secret, public) = x25519_shaped();
        let pass = test_passphrase("correct horse battery staple");
        let kdf = KdfParams::default();
        let bytes = seal_private_key(&secret, "x25519", &public, &[], &pass, &kdf).unwrap();
        // Total: 90 + 6 (type_name) + 32 (public) + 0 (ext) + 48 (wrap) = 176.
        assert_eq!(bytes.len(), 176);
        let opened = open_private_key(
            &bytes,
            &pass,
            None,
            PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT,
        )
        .unwrap();
        assert_eq!(opened.type_name, "x25519");
        assert_eq!(opened.public_material, public);
        assert!(opened.ext_bytes.is_empty());
        assert_eq!(*opened.secret_material, secret);
    }

    #[test]
    fn round_trip_with_ext_bytes() {
        let (secret, public) = x25519_shaped();
        let pass = test_passphrase("pw");
        let kdf = KdfParams::default();
        let ext = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let bytes = seal_private_key(&secret, "x25519", &public, &ext, &pass, &kdf).unwrap();
        let opened = open_private_key(
            &bytes,
            &pass,
            None,
            PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT,
        )
        .unwrap();
        assert_eq!(opened.ext_bytes, ext);
    }

    /// `seal_private_key` MUST reject `public_material` whose length
    /// would push `public_len` past the structural cap, with the same
    /// `MalformedPrivateKey` diagnostic that `PrivateKeyHeader::parse`
    /// uses on the read side. Locks in the writer/reader cap symmetry
    /// enforced by `check_public_len`. Cap fires before any Argon2id
    /// work, so the test runs cheaply.
    #[test]
    fn seal_rejects_public_material_above_max() {
        let secret = [0x11u8; 32];
        let oversize = vec![0u8; (PRIVATE_KEY_PUBLIC_LEN_MAX as usize) + 1];
        let pass = test_passphrase("pw");
        let kdf = KdfParams::default();
        match seal_private_key(&secret, "x25519", &oversize, &[], &pass, &kdf) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => {}
            other => panic!("expected MalformedPrivateKey for oversize public, got {other:?}"),
        }
    }

    /// Companion of [`seal_rejects_public_material_above_max`] for the
    /// `ext_bytes` cap. Pins the shared `check_ext_len` contract.
    #[test]
    fn seal_rejects_ext_bytes_above_max() {
        let (secret, public) = x25519_shaped();
        let oversize_ext = vec![0u8; (PRIVATE_KEY_EXT_LEN_MAX as usize) + 1];
        let pass = test_passphrase("pw");
        let kdf = KdfParams::default();
        match seal_private_key(&secret, "x25519", &public, &oversize_ext, &pass, &kdf) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => {}
            other => panic!("expected MalformedPrivateKey for oversize ext, got {other:?}"),
        }
    }

    #[test]
    fn wrong_passphrase_fails_with_keyfile_unlock_failed() {
        let (secret, public) = x25519_shaped();
        let right = test_passphrase("right");
        let wrong = test_passphrase("wrong");
        let kdf = KdfParams::default();
        let bytes = seal_private_key(&secret, "x25519", &public, &[], &right, &kdf).unwrap();
        match open_private_key(
            &bytes,
            &wrong,
            None,
            PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT,
        ) {
            Err(CryptoError::KeyFileUnlockFailed) => {}
            other => panic!("expected KeyFileUnlockFailed, got {other:?}"),
        }
    }

    /// AAD-bound regions: every byte in argon2_salt, wrap_nonce, the
    /// variable cleartext sections (type_name, public_material,
    /// ext_bytes), and the wrapped_secret AEAD ciphertext+tag MUST fail
    /// open with [`CryptoError::KeyFileUnlockFailed`] specifically. A
    /// regression that, for instance, dropped public_material from the
    /// AAD would still pass a "fails to open" assertion; pinning the
    /// exact variant per region is what catches that.
    #[test]
    fn tampering_aad_bound_region_specifically_fails_keyfile_unlock() {
        let (secret, public) = x25519_shaped();
        let pass = test_passphrase("pw");
        let kdf = KdfParams::default();
        let ext = vec![0xA5u8; 8];
        let original = seal_private_key(&secret, "x25519", &public, &ext, &pass, &kdf).unwrap();
        let cleartext_end =
            PRIVATE_KEY_HEADER_FIXED_SIZE + "x25519".len() + public.len() + ext.len();
        let probes: &[(&str, usize)] = &[
            ("argon2_salt[0]", ARGON2_SALT_OFFSET),
            (
                "argon2_salt[last]",
                ARGON2_SALT_OFFSET + ARGON2_SALT_SIZE - 1,
            ),
            ("wrap_nonce[0]", WRAP_NONCE_OFFSET),
            ("wrap_nonce[last]", WRAP_NONCE_OFFSET + WRAP_NONCE_SIZE - 1),
            ("type_name[0]", PRIVATE_KEY_HEADER_FIXED_SIZE),
            (
                "public_material[0]",
                PRIVATE_KEY_HEADER_FIXED_SIZE + "x25519".len(),
            ),
            (
                "ext_bytes[0]",
                PRIVATE_KEY_HEADER_FIXED_SIZE + "x25519".len() + public.len(),
            ),
            ("wrapped_secret[ciphertext]", cleartext_end),
            ("wrapped_secret[tag]", original.len() - 1),
        ];
        for (label, offset) in probes {
            let mut tampered = original.clone();
            // Flip a single low bit so that for each region the only
            // way to fail is AEAD authentication: argon2_salt /
            // wrap_nonce / public_material / ext_bytes / wrapped_secret
            // have no structural ranges, and a single-bit flip in
            // type_name leaves it within the lowercase-ASCII grammar
            // (the "x" → "y" substitution for the leading byte at
            // offset PRIVATE_KEY_HEADER_FIXED_SIZE).
            tampered[*offset] ^= 0x01;
            match open_private_key(
                &tampered,
                &pass,
                None,
                PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT,
            ) {
                Err(CryptoError::KeyFileUnlockFailed) => {}
                other => panic!(
                    "expected KeyFileUnlockFailed at `{label}` (offset {offset}), got {other:?}"
                ),
            }
        }
    }

    /// Structural-region tamper: each fixed-header field has its own
    /// pre-AEAD validation path. Asserting the exact variant per region
    /// catches a regression where, for example, the kind check is
    /// silently dropped and the file flows into AEAD-decrypt.
    #[test]
    fn tampering_structural_region_fails_with_specific_error() {
        let (secret, public) = x25519_shaped();
        let pass = test_passphrase("pw");
        let kdf = KdfParams::default();
        let original = seal_private_key(&secret, "x25519", &public, &[], &pass, &kdf).unwrap();
        let cap = PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT;

        let mut bad_magic = original.clone();
        bad_magic[0] ^= 0x01;
        match open_private_key(&bad_magic, &pass, None, cap) {
            Err(CryptoError::InvalidFormat(FormatDefect::NotAKeyFile)) => {}
            other => panic!("expected NotAKeyFile for magic tamper, got {other:?}"),
        }

        let mut bad_version = original.clone();
        bad_version[VERSION_OFFSET] = 2;
        match open_private_key(&bad_version, &pass, None, cap) {
            Err(CryptoError::UnsupportedVersion(UnsupportedVersion::NewerKey { version: 2 })) => {}
            other => panic!("expected NewerKey(2) for version tamper, got {other:?}"),
        }

        let mut bad_kind = original.clone();
        bad_kind[KIND_OFFSET] = 0x99;
        match open_private_key(&bad_kind, &pass, None, cap) {
            Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType)) => {}
            other => panic!("expected WrongKeyFileType for kind tamper, got {other:?}"),
        }

        let mut bad_flags = original.clone();
        bad_flags[KEY_FLAGS_OFFSET + 1] = 0x01;
        match open_private_key(&bad_flags, &pass, None, cap) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => {}
            other => panic!("expected MalformedPrivateKey for key_flags tamper, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_bad_magic_with_not_a_key_file() {
        let mut bytes = [0u8; PRIVATE_KEY_HEADER_FIXED_SIZE];
        bytes[VERSION_OFFSET] = VERSION;
        bytes[KIND_OFFSET] = KIND_PRIVATE_KEY;
        // Magic remains [0,0,0,0].
        match PrivateKeyHeader::parse(&bytes) {
            Err(CryptoError::InvalidFormat(FormatDefect::NotAKeyFile)) => {}
            other => panic!("expected NotAKeyFile, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_wrong_version() {
        let mut bytes = sample_header_bytes();
        bytes[VERSION_OFFSET] = 2;
        match PrivateKeyHeader::parse(&bytes) {
            Err(CryptoError::UnsupportedVersion(UnsupportedVersion::NewerKey { version: 2 })) => {}
            other => panic!("expected NewerKey(2), got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_wrong_kind() {
        let mut bytes = sample_header_bytes();
        bytes[KIND_OFFSET] = 0x99;
        match PrivateKeyHeader::parse(&bytes) {
            Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType)) => {}
            other => panic!("expected WrongKeyFileType, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_non_zero_key_flags() {
        let mut bytes = sample_header_bytes();
        bytes[KEY_FLAGS_OFFSET] = 0x00;
        bytes[KEY_FLAGS_OFFSET + 1] = 0x01;
        match PrivateKeyHeader::parse(&bytes) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => {}
            other => panic!("expected MalformedPrivateKey, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_zero_type_name_len() {
        let mut bytes = sample_header_bytes();
        bytes[TYPE_NAME_LEN_OFFSET] = 0;
        bytes[TYPE_NAME_LEN_OFFSET + 1] = 0;
        match PrivateKeyHeader::parse(&bytes) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => {}
            other => panic!("expected MalformedPrivateKey, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_overlong_type_name_len() {
        // type_name_len = 256 must be rejected at parse time, not
        // deferred to validate_type_name. Earlier rejection is the
        // structural contract for every length field in this header.
        let mut bytes = sample_header_bytes();
        bytes[TYPE_NAME_LEN_OFFSET..TYPE_NAME_LEN_OFFSET + 2]
            .copy_from_slice(&((TYPE_NAME_MAX_LEN as u16) + 1).to_be_bytes());
        match PrivateKeyHeader::parse(&bytes) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => {}
            other => panic!("expected MalformedPrivateKey for type_name_len=256, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_kdf_params_above_structural_max() {
        use crate::error::InvalidKdfParams;
        // Set mem_cost above MAX_MEM_COST (2 GiB). KdfParams::from_bytes
        // surfaces InvalidKdfParams::MemoryCost rather than the generic
        // MalformedPrivateKey, preserving the precise diagnostic.
        let mut bytes = sample_header_bytes();
        let huge_mem = (3u32 * 1024 * 1024).to_be_bytes(); // 3 GiB KiB
        bytes[KDF_PARAMS_OFFSET..KDF_PARAMS_OFFSET + 4].copy_from_slice(&huge_mem);
        match PrivateKeyHeader::parse(&bytes) {
            Err(CryptoError::InvalidKdfParams(InvalidKdfParams::MemoryCost(_))) => {}
            other => panic!("expected InvalidKdfParams::MemoryCost, got {other:?}"),
        }
    }

    /// `parse` performs structural validation only: a `mem_cost` above
    /// the library's default policy ceiling (1 GiB) but within the v1
    /// structural maximum (2 GiB) MUST parse cleanly. The caller-
    /// supplied resource policy is applied separately in
    /// `open_private_key` so a caller that opts into a higher
    /// `KdfLimit` is not silently overridden by the library default at
    /// parse time. This test never runs Argon2id; it only exercises the
    /// structural-vs-policy split.
    #[test]
    fn parse_accepts_structural_kdf_above_default_policy_cap() {
        let high_but_structural = KdfParams {
            mem_cost: KdfParams::MAX_MEM_COST,
            time_cost: 1,
            lanes: 1,
        };
        let mut bytes = sample_header_bytes();
        bytes[KDF_PARAMS_OFFSET..KDF_PARAMS_OFFSET + KDF_PARAMS_SIZE]
            .copy_from_slice(&high_but_structural.to_bytes());
        let parsed = PrivateKeyHeader::parse(&bytes).expect("structural parse must accept");
        assert_eq!(parsed.kdf_params.mem_cost, KdfParams::MAX_MEM_COST);
    }

    #[test]
    fn parse_rejects_public_len_above_max() {
        let mut bytes = sample_header_bytes();
        let oversized = (PRIVATE_KEY_PUBLIC_LEN_MAX + 1).to_be_bytes();
        bytes[PUBLIC_LEN_OFFSET..PUBLIC_LEN_OFFSET + 4].copy_from_slice(&oversized);
        match PrivateKeyHeader::parse(&bytes) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => {}
            other => panic!("expected MalformedPrivateKey, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_ext_len_above_max() {
        let mut bytes = sample_header_bytes();
        let oversized = (PRIVATE_KEY_EXT_LEN_MAX + 1).to_be_bytes();
        bytes[EXT_LEN_OFFSET..EXT_LEN_OFFSET + 4].copy_from_slice(&oversized);
        match PrivateKeyHeader::parse(&bytes) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => {}
            other => panic!("expected MalformedPrivateKey, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_wrapped_secret_len_below_min() {
        let mut bytes = sample_header_bytes();
        let too_small = (PRIVATE_KEY_WRAPPED_SECRET_LEN_MIN - 1).to_be_bytes();
        bytes[WRAPPED_SECRET_LEN_OFFSET..WRAPPED_SECRET_LEN_OFFSET + 4].copy_from_slice(&too_small);
        match PrivateKeyHeader::parse(&bytes) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => {}
            other => panic!("expected MalformedPrivateKey, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_wrapped_secret_len_above_max() {
        let mut bytes = sample_header_bytes();
        let too_large = (PRIVATE_KEY_WRAPPED_SECRET_LEN_MAX + 1).to_be_bytes();
        bytes[WRAPPED_SECRET_LEN_OFFSET..WRAPPED_SECRET_LEN_OFFSET + 4].copy_from_slice(&too_large);
        match PrivateKeyHeader::parse(&bytes) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => {}
            other => panic!("expected MalformedPrivateKey, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_truncated_below_fixed_header() {
        let too_short = vec![0u8; PRIVATE_KEY_HEADER_FIXED_SIZE - 1];
        match open_private_key(
            &too_short,
            &test_passphrase("pw"),
            None,
            PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT,
        ) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => {}
            other => panic!("expected MalformedPrivateKey, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_total_size_mismatch() {
        let (secret, public) = x25519_shaped();
        let pass = test_passphrase("pw");
        let kdf = KdfParams::default();
        let mut bytes = seal_private_key(&secret, "x25519", &public, &[], &pass, &kdf).unwrap();
        bytes.push(0); // Extra trailing byte.
        match open_private_key(
            &bytes,
            &pass,
            None,
            PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT,
        ) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => {}
            other => panic!("expected MalformedPrivateKey for trailing byte, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_wrapped_secret_above_local_cap() {
        let (secret, public) = x25519_shaped();
        let pass = test_passphrase("pw");
        let kdf = KdfParams::default();
        let bytes = seal_private_key(&secret, "x25519", &public, &[], &pass, &kdf).unwrap();
        // Local cap below the actual 48-byte wrapped secret.
        match open_private_key(&bytes, &pass, None, 32) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedPrivateKey)) => {}
            other => panic!("expected MalformedPrivateKey for cap exceeded, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_malformed_type_name_grammar() {
        // Hand-build a minimally-valid file with an uppercase
        // type_name. The header is structurally valid; grammar
        // validation fires after slicing.
        let bytes = file_with_type_name_payload(b"X25519");
        match open_private_key(
            &bytes,
            &test_passphrase("pw"),
            None,
            PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT,
        ) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for uppercase, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_non_utf8_type_name() {
        // Non-UTF-8 bytes in the type_name slot must surface as
        // `MalformedTypeName` via `std::str::from_utf8`, not silently
        // pass to `validate_type_name` (which expects `&str`) or be
        // collapsed into a generic structural error.
        let bytes = file_with_type_name_payload(&[0xFF; 6]);
        match open_private_key(
            &bytes,
            &test_passphrase("pw"),
            None,
            PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT,
        ) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for non-UTF8, got {other:?}"),
        }
    }

    /// Builds a structurally-consistent private.key with the given
    /// 6-byte `type_name_payload`, zero-length public/ext sections, and
    /// a minimal-size wrapped-secret region (just `TAG_SIZE` zeros).
    /// Used to exercise type_name-validation paths without colliding
    /// with structural pre-checks.
    fn file_with_type_name_payload(type_name_payload: &[u8]) -> Vec<u8> {
        assert_eq!(type_name_payload.len(), 6, "helper expects 6-byte payload");
        let header = PrivateKeyHeader {
            key_flags: 0,
            type_name_len: 6,
            public_len: 0,
            ext_len: 0,
            wrapped_secret_len: PRIVATE_KEY_WRAPPED_SECRET_LEN_MIN,
            argon2_salt: [0u8; ARGON2_SALT_SIZE],
            kdf_params: KdfParams::default(),
            wrap_nonce: [0u8; WRAP_NONCE_SIZE],
        };
        let mut bytes = header.to_bytes().to_vec();
        bytes.extend_from_slice(type_name_payload);
        bytes.extend(std::iter::repeat_n(0u8, TAG_SIZE));
        bytes
    }

    #[test]
    fn header_layout_offsets_sum_to_fixed_size() {
        assert_eq!(VERSION_OFFSET, 4);
        assert_eq!(KIND_OFFSET, 5);
        assert_eq!(KEY_FLAGS_OFFSET, 6);
        assert_eq!(TYPE_NAME_LEN_OFFSET, 8);
        assert_eq!(PUBLIC_LEN_OFFSET, 10);
        assert_eq!(EXT_LEN_OFFSET, 14);
        assert_eq!(WRAPPED_SECRET_LEN_OFFSET, 18);
        assert_eq!(ARGON2_SALT_OFFSET, 22);
        assert_eq!(KDF_PARAMS_OFFSET, 54);
        assert_eq!(WRAP_NONCE_OFFSET, 66);
        assert_eq!(
            WRAP_NONCE_OFFSET + WRAP_NONCE_SIZE,
            PRIVATE_KEY_HEADER_FIXED_SIZE
        );
    }

    #[test]
    fn header_round_trips_through_serialise_parse() {
        let header = PrivateKeyHeader {
            key_flags: 0,
            type_name_len: 6,
            public_len: 32,
            ext_len: 0,
            wrapped_secret_len: 48,
            argon2_salt: [0xAB; ARGON2_SALT_SIZE],
            kdf_params: KdfParams::default(),
            wrap_nonce: [0xCD; WRAP_NONCE_SIZE],
        };
        let bytes = header.to_bytes();
        let parsed = PrivateKeyHeader::parse(&bytes).unwrap();
        assert_eq!(parsed, header);
    }

    /// Builds a structurally-valid 90-byte header for tampering tests.
    fn sample_header_bytes() -> [u8; PRIVATE_KEY_HEADER_FIXED_SIZE] {
        PrivateKeyHeader {
            key_flags: 0,
            type_name_len: 6,
            public_len: 32,
            ext_len: 0,
            wrapped_secret_len: 48,
            argon2_salt: [0xAB; ARGON2_SALT_SIZE],
            kdf_params: KdfParams::default(),
            wrap_nonce: [0xCD; WRAP_NONCE_SIZE],
        }
        .to_bytes()
    }
}
