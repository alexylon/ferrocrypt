use std::cmp;
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::path::Path;

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit as AeadKeyInit, OsRng, rand_core::RngCore, stream},
};
use constant_time_eq::constant_time_eq_32;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha3::Sha3_256;

use zeroize::{Zeroize, Zeroizing};

use crate::CryptoError;
use crate::error::{FormatDefect, InvalidKdfParams, StreamError};
use crate::format::EXT_LEN_MAX;

/// Wraps a [`StreamError`] as an [`io::Error`] with the given kind so that
/// the typed marker can traverse [`Read`]/[`Write`] trait boundaries and
/// later be downcast by `From<io::Error> for CryptoError`.
fn stream_io_error(kind: io::ErrorKind, err: StreamError) -> io::Error {
    io::Error::new(kind, err)
}

type HmacSha3_256 = Hmac<Sha3_256>;

/// Caller-controlled limit on KDF memory cost accepted during decryption.
///
/// When processing untrusted files, this prevents a malicious header from
/// forcing arbitrarily expensive key derivation. Pass `None` to decrypt
/// functions to use the built-in default ceiling.
///
/// Construct via [`KdfLimit::new`] or [`KdfLimit::from_mib`]. The struct is
/// `#[non_exhaustive]` so future releases can add additional limit dimensions
/// (e.g. time cost, parallelism) without a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct KdfLimit {
    /// Maximum accepted memory cost in KiB.
    pub max_mem_cost_kib: u32,
}

impl KdfLimit {
    /// Builds a limit directly from a KiB value.
    pub fn new(max_mem_cost_kib: u32) -> Self {
        Self { max_mem_cost_kib }
    }

    /// Builds a limit from MiB, returning an error on integer overflow.
    pub fn from_mib(mib: u32) -> Result<Self, CryptoError> {
        let kib = mib.checked_mul(1024).ok_or_else(|| {
            CryptoError::InvalidInput(format!("KDF memory limit overflow: {} MiB", mib))
        })?;
        Ok(Self::new(kib))
    }
}

impl Default for KdfLimit {
    fn default() -> Self {
        // Matches the writer's `KdfParams::DEFAULT_MEM_COST`: any file
        // produced with the library's own default KDF settings decrypts
        // under the default ceiling, but an attacker-controlled header
        // cannot force more than 1 GiB of Argon2id memory unless the
        // caller opts into a higher `KdfLimit` explicitly.
        Self {
            max_mem_cost_kib: KdfParams::DEFAULT_MEM_COST,
        }
    }
}

/// KDF parameters stored in file headers and key files so that decryption
/// uses the same cost parameters that were used during encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub mem_cost: u32,
    pub time_cost: u32,
    pub lanes: u32,
}

pub const KDF_PARAMS_SIZE: usize = 12; // 3 × u32 big-endian

impl KdfParams {
    pub(crate) const DEFAULT_MEM_COST: u32 = 1_048_576; // 1 GiB
    const DEFAULT_TIME_COST: u32 = 4;
    const DEFAULT_LANES: u32 = 4;

    // Minimal params for fast test execution.
    // Auto-enabled via [dev-dependencies]; blocked in release builds
    // by a compile_error! guard in lib.rs.
    const FAST_KDF_MEM_COST: u32 = 8192;
    const FAST_KDF_TIME_COST: u32 = 1;

    pub fn to_bytes(self) -> [u8; KDF_PARAMS_SIZE] {
        let mut buf = [0u8; KDF_PARAMS_SIZE];
        buf[0..4].copy_from_slice(&self.mem_cost.to_be_bytes());
        buf[4..8].copy_from_slice(&self.time_cost.to_be_bytes());
        buf[8..12].copy_from_slice(&self.lanes.to_be_bytes());
        buf
    }

    // Upper bounds for KDF parameters from untrusted headers.
    // These prevent malicious files from causing excessive CPU/memory usage.
    pub(crate) const MAX_MEM_COST: u32 = 2 * 1024 * 1024; // 2 GiB
    const MAX_TIME_COST: u32 = 12;
    const MAX_LANES: u32 = 8;

    /// Structural-only parse: validates lanes, time_cost, and mem_cost
    /// against the v1 absolute structural bounds (`MAX_LANES`,
    /// `MAX_TIME_COST`, `MAX_MEM_COST`). Does **not** apply any caller
    /// resource policy — call [`enforce_limit`](Self::enforce_limit) on
    /// the result for that. `pub(crate)` deliberately: external callers
    /// must go through [`from_bytes`](Self::from_bytes), which always
    /// applies the policy gate, so a missed call cannot bypass the cap.
    pub(crate) fn from_bytes_structural(
        bytes: &[u8; KDF_PARAMS_SIZE],
    ) -> Result<Self, CryptoError> {
        let params = Self {
            mem_cost: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            time_cost: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            lanes: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        };
        if params.lanes == 0 || params.lanes > Self::MAX_LANES {
            return Err(CryptoError::InvalidKdfParams(
                InvalidKdfParams::Parallelism(params.lanes),
            ));
        }
        let min_mem_cost = 8 * params.lanes;
        if params.mem_cost < min_mem_cost || params.mem_cost > Self::MAX_MEM_COST {
            return Err(CryptoError::InvalidKdfParams(InvalidKdfParams::MemoryCost(
                params.mem_cost,
            )));
        }
        if params.time_cost == 0 || params.time_cost > Self::MAX_TIME_COST {
            return Err(CryptoError::InvalidKdfParams(InvalidKdfParams::TimeCost(
                params.time_cost,
            )));
        }
        Ok(params)
    }

    /// Applies the caller-supplied resource cap on top of structurally
    /// valid params. `None` means "no explicit caller limit", but the
    /// library still applies its own default ceiling
    /// (`DEFAULT_MEM_COST`, 1 GiB) so callers cannot be silently exposed
    /// to attacker-controlled 2 GiB allocations just because they did
    /// not set `.kdf_limit(...)` on their config. `pub(crate)`
    /// deliberately: pairs with [`from_bytes_structural`] and is not
    /// part of the stable public API.
    pub(crate) fn enforce_limit(self, limit: Option<&KdfLimit>) -> Result<Self, CryptoError> {
        let effective_max = limit
            .map(|l| l.max_mem_cost_kib)
            .unwrap_or(Self::DEFAULT_MEM_COST);
        if self.mem_cost > effective_max {
            return Err(CryptoError::KdfResourceCapExceeded {
                mem_cost_kib: self.mem_cost,
                local_cap_kib: effective_max,
            });
        }
        Ok(self)
    }

    pub fn from_bytes(
        bytes: &[u8; KDF_PARAMS_SIZE],
        limit: Option<&KdfLimit>,
    ) -> Result<Self, CryptoError> {
        Self::from_bytes_structural(bytes)?.enforce_limit(limit)
    }

    pub fn hash_passphrase(
        &self,
        passphrase: &[u8],
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; ENCRYPTION_KEY_SIZE]>, CryptoError> {
        let params = argon2::Params::new(
            self.mem_cost,
            self.time_cost,
            self.lanes,
            Some(ENCRYPTION_KEY_SIZE),
        )?;
        let hasher =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut output = Zeroizing::new([0u8; ENCRYPTION_KEY_SIZE]);
        hasher.hash_password_into(passphrase, salt, output.as_mut())?;
        Ok(output)
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        if cfg!(feature = "fast-kdf") {
            Self {
                mem_cost: Self::FAST_KDF_MEM_COST,
                time_cost: Self::FAST_KDF_TIME_COST,
                lanes: Self::DEFAULT_LANES,
            }
        } else {
            Self {
                mem_cost: Self::DEFAULT_MEM_COST,
                time_cost: Self::DEFAULT_TIME_COST,
                lanes: Self::DEFAULT_LANES,
            }
        }
    }
}

// ─── Shared crypto sizes ──────────────────────────────────────────────────
pub const ENCRYPTION_KEY_SIZE: usize = 32;
pub const HMAC_KEY_SIZE: usize = 32;
/// HMAC-SHA3-256 output size in bytes (distinct from `HMAC_KEY_SIZE`).
pub const HMAC_TAG_SIZE: usize = 32;
pub const ARGON2_SALT_SIZE: usize = 32;
/// Size of the per-file random key that both symmetric and hybrid
/// `.fcr` modes wrap via their mode envelope. Post-unwrap subkey
/// derivation keys off this value; see [`derive_subkeys`].
pub const FILE_KEY_SIZE: usize = 32;
/// XChaCha20-Poly1305 single-shot nonce size, used for both mode
/// envelopes (`wrap_nonce`) and the `private.key` AEAD.
pub const WRAP_NONCE_SIZE: usize = 24;
/// Size of an AEAD-wrapped 32-byte file key: 32-byte ciphertext +
/// 16-byte Poly1305 tag.
pub const WRAPPED_FILE_KEY_SIZE: usize = FILE_KEY_SIZE + TAG_SIZE;

// ─── HKDF info strings (pinned wire format) ───────────────────────────────
//
// Every HKDF info string in v1 is literal ASCII of the form
// `"ferrocrypt/v1/<subsystem>"`. Pinning these as constants means a
// silent typo in any single call site regresses test fixtures
// immediately, and a future v2 cannot accidentally reuse a v1 derivation.
//
// Recipient-type wrap-key info strings live next to their recipient
// implementations (see `recipients::argon2id::HKDF_INFO_WRAP` and
// `recipients::x25519::HKDF_INFO_WRAP`) so each recipient module
// is the sole owner of its key-derivation contract.

/// HKDF info for deriving the `private.key` wrap key from Argon2id.
pub const HKDF_INFO_PRIVATE_KEY_WRAP: &[u8] = b"ferrocrypt/v1/private-key/wrap";
/// HKDF info for the per-file payload AEAD key, derived from
/// `file_key` with `stream_nonce` as HKDF salt.
pub const HKDF_INFO_PAYLOAD: &[u8] = b"ferrocrypt/v1/payload";
/// HKDF info for the per-file header HMAC key, derived from `file_key`
/// with an empty HKDF salt.
pub const HKDF_INFO_HEADER: &[u8] = b"ferrocrypt/v1/header";

// ─── Streaming encryption sizes ───────────────────────────────────────────
/// Plaintext chunk size for streaming XChaCha20-Poly1305 AEAD (64 KiB).
/// Non-final chunks produce `BUFFER_SIZE + TAG_SIZE` ciphertext bytes; the
/// final chunk may be shorter. Part of the `.fcr` on-disk format — changing
/// this shifts every chunk boundary and breaks existing files.
pub const BUFFER_SIZE: usize = 65536;
/// Poly1305 authentication tag size in bytes.
pub const TAG_SIZE: usize = 16;
/// STREAM nonce size: XChaCha20's 24-byte nonce minus 5 bytes for counter and last-block flag.
pub const STREAM_NONCE_SIZE: usize = 19;

pub fn file_stem(filename: &Path) -> Result<&OsStr, CryptoError> {
    filename
        .file_stem()
        .ok_or_else(|| CryptoError::InvalidInput("Cannot get file stem".to_string()))
}

/// Returns the base name for building the default encrypted output filename.
/// For regular files, returns the file stem (without extension).
/// For directories, returns the full directory name (preserving dots like `photos.v1`).
///
/// Uses `symlink_metadata` (lstat) rather than `Path::is_dir` so a
/// symlink that races into place between the upstream
/// `validate_encrypt_input` symlink check and this lookup cannot be
/// followed to a directory and silently change the chosen output
/// name. The downstream `open_no_follow` would still abort the
/// archive step, but defending here keeps the directory-vs-file
/// classification honest. Falls back to the file branch when
/// `symlink_metadata` fails (e.g. NotFound after a race), letting
/// the subsequent `file_stem` surface the real error.
pub fn encryption_base_name(path: impl AsRef<Path>) -> Result<String, CryptoError> {
    let path = path.as_ref();
    let is_real_dir = std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_dir())
        .unwrap_or(false);
    if is_real_dir {
        Ok(path
            .file_name()
            .ok_or_else(|| CryptoError::InvalidInput("Cannot get directory name".to_string()))?
            .to_string_lossy()
            .into_owned())
    } else {
        Ok(file_stem(path)?.to_string_lossy().into_owned())
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Compares two 256-bit byte strings in constant time.
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    constant_time_eq_32(a, b)
}

/// HMAC-SHA3-256 over a sequence of byte parts, fed into the MAC in
/// order with no separator. Equivalent to MAC'ing the concatenation
/// of `parts` but does not allocate. Used by the v1 header MAC, which
/// covers `prefix(12) || header(header_len)` per `FORMAT.md` §3.6.
pub fn hmac_sha3_256_parts(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], CryptoError> {
    Ok(hmac_state_for_parts(key, parts)?
        .finalize()
        .into_bytes()
        .into())
}

/// Constant-time HMAC-SHA3-256 verification over a sequence of byte
/// parts. Returns [`CryptoError::HeaderTampered`] on tag mismatch.
/// See [`hmac_sha3_256_parts`] for the input layout.
pub fn hmac_sha3_256_parts_verify(
    key: &[u8],
    parts: &[&[u8]],
    tag: &[u8],
) -> Result<(), CryptoError> {
    hmac_state_for_parts(key, parts)?
        .verify_slice(tag)
        .map_err(|_| CryptoError::HeaderTampered)
}

// Internal helper: builds a fresh HMAC-SHA3-256 state and updates it
// with `parts` in declared order. Both the compute and verify entry
// points share this so the key-init wording, the parts iteration
// order, and the empty-parts behaviour cannot drift between them.
fn hmac_state_for_parts(key: &[u8], parts: &[&[u8]]) -> Result<HmacSha3_256, CryptoError> {
    let mut mac = HmacSha3_256::new_from_slice(key)
        .map_err(|_| CryptoError::InternalInvariant("Internal error: invalid HMAC key length"))?;
    for part in parts {
        mac.update(part);
    }
    Ok(mac)
}

// ─── Random bytes / file-key indirection ──────────────────────────────────

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
    passphrase: &secrecy::SecretString,
    argon2_salt: &[u8; ARGON2_SALT_SIZE],
    kdf_params: &KdfParams,
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    use secrecy::ExposeSecret;
    let ikm = kdf_params.hash_passphrase(passphrase.expose_secret().as_bytes(), argon2_salt)?;
    hkdf_expand_sha3_256(Some(argon2_salt), ikm.as_ref(), info)
}

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

/// Reads exactly `buf.len()` bytes or maps any read failure to
/// [`FormatDefect::Truncated`]. Used by `.fcr` decrypt paths where a
/// short read on a fixed-size header field is a format-level
/// truncation rather than a generic I/O error.
pub fn read_exact_or_truncated(reader: &mut impl Read, buf: &mut [u8]) -> Result<(), CryptoError> {
    reader
        .read_exact(buf)
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::Truncated))
}

/// Opens an AEAD-wrapped file key. `on_fail` is called on AEAD-tag
/// mismatch so callers can route the failure to a mode-specific
/// variant ([`CryptoError::SymmetricEnvelopeUnlockFailed`] or
/// [`CryptoError::HybridEnvelopeUnlockFailed`]).
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

/// HKDF-SHA3-256 expansion to a 32-byte key. Every v1 HKDF derivation
/// goes through this helper so the hash family and output length are
/// fixed in one place.
pub fn hkdf_expand_sha3_256(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hkdf = Hkdf::<Sha3_256>::new(salt, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, out.as_mut())
        .map_err(|_| CryptoError::InternalCryptoFailure("Internal error: HKDF expand failed"))?;
    Ok(out)
}

/// Payload AEAD key + header HMAC key, derived from a successfully
/// unwrapped [`FILE_KEY_SIZE`]-byte `file_key`.
pub type DerivedSubkeys = (
    Zeroizing<[u8; ENCRYPTION_KEY_SIZE]>,
    Zeroizing<[u8; HMAC_KEY_SIZE]>,
);

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
    stream_nonce: &[u8; STREAM_NONCE_SIZE],
) -> Result<DerivedSubkeys, CryptoError> {
    let payload_key = hkdf_expand_sha3_256(Some(stream_nonce), file_key, HKDF_INFO_PAYLOAD)?;
    let header_key = hkdf_expand_sha3_256(None, file_key, HKDF_INFO_HEADER)?;
    Ok((payload_key, header_key))
}

// ─── TLV extension region ─────────────────────────────────────────────────

/// Validates the TLV extension region per FORMAT.md §6.
///
/// Per `FORMAT.md` §6, each entry is `tag(u16) || len(u32) || value`
/// (6-byte entry header, big-endian). Checks:
/// - each entry's `tag(u16) || len(u32)` fits within the region;
/// - `len` is authoritative (the entry's `value` does not extend past
///   the end of the region);
/// - declared `len` does not exceed the region cap (catches a
///   bogus 4-billion-byte length declaration before per-byte
///   accounting could underflow);
/// - tags appear in strictly ascending numeric order (rejects
///   duplicates by construction);
/// - no reserved tag (`0x0000`, `0x8000`) is emitted;
/// - no critical tag (`0x8001..=0xFFFF`) appears — v1.0 defines none,
///   so any critical tag is an upgrade-required signal.
///
/// Ignorable tags (`0x0001..=0x7FFF`) are accepted silently once
/// canonicity is verified; v1.0 writers emit an empty region so
/// callers don't yet need to extract tag values. Future v1.x releases
/// that define a known tag will extract its value by extending this
/// path or adding a sibling helper.
pub fn validate_tlv(ext_bytes: &[u8]) -> Result<(), CryptoError> {
    let region_len = u32::try_from(ext_bytes.len()).unwrap_or(u32::MAX);
    if region_len > EXT_LEN_MAX {
        return Err(CryptoError::InvalidFormat(FormatDefect::ExtTooLarge {
            len: region_len,
        }));
    }

    // Entry header = tag(u16) + len(u32) = 6 bytes.
    const ENTRY_HEADER_SIZE: usize = 6;

    let mut cursor = 0;
    let mut prev_tag: Option<u16> = None;
    while cursor < ext_bytes.len() {
        if ext_bytes.len() - cursor < ENTRY_HEADER_SIZE {
            return Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv));
        }
        let tag = u16::from_be_bytes([ext_bytes[cursor], ext_bytes[cursor + 1]]);
        let len = u32::from_be_bytes([
            ext_bytes[cursor + 2],
            ext_bytes[cursor + 3],
            ext_bytes[cursor + 4],
            ext_bytes[cursor + 5],
        ]);
        cursor += ENTRY_HEADER_SIZE;

        if tag == 0x0000 || tag == 0x8000 {
            return Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv));
        }

        if let Some(prev) = prev_tag {
            if tag <= prev {
                return Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv));
            }
        }
        prev_tag = Some(tag);

        // Reject a declared `len` that exceeds the region cap before
        // converting to `usize`. The region cap is already enforced
        // above, so any per-entry length larger than that cannot fit;
        // catching it here gives a precise diagnostic and removes
        // any risk of integer-conversion edge cases on smaller
        // address-space targets.
        if len > EXT_LEN_MAX {
            return Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv));
        }
        let len = len as usize;
        if ext_bytes.len() - cursor < len {
            return Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv));
        }
        cursor += len;

        // Critical-range tag: v1.0 knows none, so reject.
        if tag & 0x8000 != 0 {
            return Err(CryptoError::InvalidFormat(
                FormatDefect::UnknownCriticalTag { tag },
            ));
        }
    }
    Ok(())
}

/// Streaming encryption writer: buffers plaintext writes into
/// `BUFFER_SIZE` chunks and emits AEAD-encrypted chunks per
/// `FORMAT.md` §5.
///
/// Per `FORMAT.md` §5, a non-empty plaintext whose length is an exact
/// multiple of `BUFFER_SIZE` MUST end with a full-size **final** chunk
/// (`last_flag = 1`) — writers MUST NOT append an extra empty final
/// chunk. To satisfy this rule, this writer cannot eagerly call
/// `encrypt_next_in_place` the moment the buffer fills, because the
/// fill might be the last data the caller ever writes. Instead, when
/// the buffer reaches `BUFFER_SIZE` we **defer**: the chunk stays
/// buffered. On the next [`Write::write`] call (more data exists →
/// previous chunk is non-final) we flush the deferred chunk via
/// `encrypt_next_in_place`. On [`finish`](Self::finish) (no more data
/// exists → buffered chunk, however many bytes, is the final chunk)
/// we flush via `encrypt_last_in_place`.
///
/// ## Memory hygiene
///
/// A single `chunk` buffer is pre-allocated with capacity `BUFFER_SIZE +
/// TAG_SIZE` and reused across every chunk. The same allocation holds
/// plaintext on entry and ciphertext on exit (the in-place AEAD
/// appends the authentication tag without growing the underlying
/// allocation), and is zeroized between chunks and on drop. There are
/// no per-chunk plaintext `Vec`s left to the allocator.
pub struct EncryptWriter<W: Write> {
    encryptor: Option<stream::EncryptorBE32<XChaCha20Poly1305>>,
    chunk: Vec<u8>,
    output: Option<W>,
}

impl<W: Write> EncryptWriter<W> {
    pub fn new(encryptor: stream::EncryptorBE32<XChaCha20Poly1305>, output: W) -> Self {
        Self {
            encryptor: Some(encryptor),
            // Pre-allocate plaintext-plus-tag capacity so the in-place AEAD
            // tag append never triggers a `Vec` reallocation (which would
            // copy old bytes to a new allocation and free the old one
            // without zeroizing).
            chunk: Vec::with_capacity(BUFFER_SIZE + TAG_SIZE),
            output: Some(output),
        }
    }

    /// Encrypts the buffered chunk (whatever its length, including
    /// `0` for empty plaintext or `BUFFER_SIZE` for an exact-multiple
    /// boundary) as the AEAD final chunk and flushes.
    ///
    /// MUST be called exactly once after all plaintext has been
    /// written. Returns the inner writer so the caller can finalize
    /// it (e.g. `sync_all`).
    pub fn finish(mut self) -> Result<W, CryptoError> {
        let encryptor = self.encryptor.take().ok_or(CryptoError::InternalInvariant(
            "Internal error: encrypt writer already finished",
        ))?;
        let mut output = self.output.take().ok_or(CryptoError::InternalInvariant(
            "Internal error: encrypt writer already finished",
        ))?;
        encryptor
            .encrypt_last_in_place(b"", &mut self.chunk)
            .map_err(|_| {
                CryptoError::InternalCryptoFailure("Internal error: payload encryption failed")
            })?;
        output.write_all(&self.chunk)?;
        output.flush()?;
        self.chunk.zeroize();
        Ok(output)
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            // If the buffer already holds a full chunk, the previous
            // `write` call left it deferred. Now that more plaintext
            // is arriving, we know the deferred chunk is non-final
            // and can flush it via `encrypt_next_in_place`. This is
            // the FORMAT.md §5 conformance check: writers must wait
            // until they observe more data before committing a chunk
            // as non-final, so an exact-`BUFFER_SIZE`-multiple
            // plaintext ends with a full-size FINAL chunk rather than
            // a stray empty trailing chunk.
            if self.chunk.len() == BUFFER_SIZE {
                let encryptor = self.encryptor.as_mut().ok_or_else(|| {
                    stream_io_error(io::ErrorKind::Other, StreamError::StateExhausted)
                })?;
                encryptor
                    .encrypt_next_in_place(b"", &mut self.chunk)
                    .map_err(|_| stream_io_error(io::ErrorKind::Other, StreamError::EncryptAead))?;
                let output = self.output.as_mut().ok_or_else(|| {
                    stream_io_error(io::ErrorKind::Other, StreamError::StateExhausted)
                })?;
                output.write_all(&self.chunk)?;
                // Zeroize the chunk (plaintext + tag) before refilling
                // for the next chunk. `zeroize` resets length to 0 and
                // preserves capacity, so the next `extend_from_slice`
                // reuses the same allocation.
                self.chunk.zeroize();
            }

            let space = BUFFER_SIZE - self.chunk.len();
            let take = cmp::min(space, buf.len() - written);
            self.chunk.extend_from_slice(&buf[written..written + take]);
            written += take;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.output.as_mut() {
            Some(output) => output.flush(),
            None => Ok(()),
        }
    }
}

impl<W: Write> Drop for EncryptWriter<W> {
    fn drop(&mut self) {
        self.chunk.zeroize();
    }
}

/// Streaming decryption reader: reads ciphertext chunks of
/// `BUFFER_SIZE + TAG_SIZE` from the inner reader, decrypts each in
/// place with `decrypt_next_in_place` / `decrypt_last_in_place`, and
/// serves plaintext through the `Read` interface.
///
/// Per `FORMAT.md` §5 a non-empty plaintext whose length is an exact
/// multiple of `BUFFER_SIZE` ends with a full-size **final** chunk
/// (`last_flag = 1`). The reader therefore cannot rely on "short
/// read = final chunk" alone; it must inspect end-of-input
/// explicitly. After reading a full `ENCRYPTED_CHUNK_SIZE`, we probe
/// the inner reader for one byte:
/// - probe returns `0` (EOF) → the chunk we just read is the final
///   chunk; decrypt with `decrypt_last_in_place`.
/// - probe returns `1` byte → another chunk follows; decrypt the
///   current chunk with `decrypt_next_in_place` and stash the probe
///   byte as the first byte of the next chunk.
///
/// A short read (filled < `ENCRYPTED_CHUNK_SIZE`) always indicates the
/// final chunk; AEAD authentication on `decrypt_last_in_place` rejects
/// any mid-chunk truncation as a tamper failure.
///
/// ## Memory hygiene
///
/// A single `chunk` buffer is pre-allocated with capacity
/// `BUFFER_SIZE + TAG_SIZE` and reused across every chunk. The same
/// allocation holds ciphertext on entry and plaintext on exit (the
/// in-place AEAD truncates the authentication tag during decryption),
/// and is zeroized before each refill and on drop. There are no
/// per-chunk `Vec`s left to the allocator.
pub struct DecryptReader<R: Read> {
    decryptor: Option<stream::DecryptorBE32<XChaCha20Poly1305>>,
    input: R,
    chunk: Vec<u8>,
    pos: usize,
    done: bool,
    /// One byte read from the inner reader past the current chunk
    /// boundary. `Some(b)` means the previous fill confirmed more
    /// data exists, so the byte belongs to the *next* chunk. `None`
    /// means no peek byte is held (initial state, or after the final
    /// chunk has been consumed).
    lookahead: Option<u8>,
}

impl<R: Read> DecryptReader<R> {
    pub fn new(decryptor: stream::DecryptorBE32<XChaCha20Poly1305>, input: R) -> Self {
        Self {
            decryptor: Some(decryptor),
            input,
            // Pre-allocate the worst-case chunk size so neither the read
            // refill nor the in-place AEAD ever triggers a `Vec`
            // reallocation.
            chunk: Vec::with_capacity(BUFFER_SIZE + TAG_SIZE),
            pos: 0,
            done: false,
            lookahead: None,
        }
    }

    /// Refill the plaintext window by reading and decrypting the next
    /// encrypted chunk. The "is this the final chunk?" decision is
    /// resolved by a one-byte peek past `ENCRYPTED_CHUNK_SIZE`:
    ///
    /// - peek returns `0` → final chunk; `decrypt_last_in_place`.
    /// - peek returns `1` byte → non-final chunk;
    ///   `decrypt_next_in_place`, stash the byte as `lookahead` for
    ///   the next call.
    ///
    /// Truncation is reported via two distinct paths:
    ///
    /// - **Chunk-boundary truncation** — `read` returns 0 immediately
    ///   AND no `lookahead` is held, meaning the final authenticated
    ///   chunk is missing entirely. Surfaces as
    ///   [`StreamError::Truncated`] → [`CryptoError::PayloadTruncated`].
    /// - **Mid-chunk truncation** — some bytes were read but fewer
    ///   than a full `ENCRYPTED_CHUNK_SIZE`. The short buffer is
    ///   treated as the final chunk and run through
    ///   `decrypt_last_in_place`. AEAD authentication will reject it,
    ///   surfacing as [`StreamError::DecryptAead`] →
    ///   [`CryptoError::PayloadTampered`]. This is the correct
    ///   outcome — we cannot distinguish a mid-chunk truncation from
    ///   a tampered tail, and both must fail closed.
    ///
    /// **Trailing-data probe.** After `decrypt_last_in_place` succeeds
    /// we probe the inner reader for one additional byte. With the
    /// peek-ahead model the probe can only fire if the inner reader
    /// returned `Ok(0)` and then later produced more bytes — a
    /// pathological case (non-blocking sockets, mis-implemented
    /// `Take`-style wrappers). Kept as defense-in-depth so any such
    /// reader still surfaces [`StreamError::ExtraData`] →
    /// [`CryptoError::ExtraDataAfterPayload`].
    fn fill_buffer(&mut self) -> io::Result<()> {
        const ENCRYPTED_CHUNK_SIZE: usize = BUFFER_SIZE + TAG_SIZE;

        // Zeroize the previous chunk (plaintext from the last call) before
        // refilling. `zeroize` sets length to 0 and preserves capacity.
        self.chunk.zeroize();
        self.chunk.resize(ENCRYPTED_CHUNK_SIZE, 0);

        // Seed with any byte stashed from the previous chunk's lookahead.
        let mut filled = 0;
        if let Some(b) = self.lookahead.take() {
            self.chunk[0] = b;
            filled = 1;
        }
        while filled < ENCRYPTED_CHUNK_SIZE {
            let n = self.input.read(&mut self.chunk[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        // Drop trailing zero bytes that weren't filled by the read. Crucial
        // for the final (short) chunk: in-place decrypt expects the buffer
        // length to equal the ciphertext length.
        self.chunk.truncate(filled);

        if filled == 0 {
            // A valid stream always ends with an encrypt_last chunk
            // (>= TAG_SIZE bytes). Reading 0 bytes here, with no
            // lookahead either, means the final authenticated chunk is
            // missing — the ciphertext was truncated at a chunk boundary.
            return Err(stream_io_error(
                io::ErrorKind::UnexpectedEof,
                StreamError::Truncated,
            ));
        }

        // Resolve "is this the final chunk?" via a one-byte peek when we
        // filled exactly `ENCRYPTED_CHUNK_SIZE`. A short read already
        // signalled EOF inside the loop, so it's the final chunk.
        let mut probe = [0u8; 1];
        let probe_n = if filled == ENCRYPTED_CHUNK_SIZE {
            self.input.read(&mut probe)?
        } else {
            0
        };

        if filled == ENCRYPTED_CHUNK_SIZE && probe_n > 0 {
            // Non-final chunk: stash the peek byte for the next refill.
            self.lookahead = Some(probe[0]);
            let decryptor = self.decryptor.as_mut().ok_or_else(|| {
                stream_io_error(io::ErrorKind::Other, StreamError::StateExhausted)
            })?;
            decryptor
                .decrypt_next_in_place(b"", &mut self.chunk)
                .map_err(|_| {
                    stream_io_error(io::ErrorKind::InvalidData, StreamError::DecryptAead)
                })?;
        } else {
            // Final chunk: short read OR exact-`ENCRYPTED_CHUNK_SIZE` with EOF.
            let decryptor = self.decryptor.take().ok_or_else(|| {
                stream_io_error(io::ErrorKind::Other, StreamError::StateExhausted)
            })?;
            decryptor
                .decrypt_last_in_place(b"", &mut self.chunk)
                .map_err(|_| {
                    stream_io_error(io::ErrorKind::InvalidData, StreamError::DecryptAead)
                })?;
            self.done = true;

            // Defense-in-depth trailing-data probe. With the peek-ahead
            // model this can only fire if the inner reader returned 0
            // earlier and then later produced more bytes; well-behaved
            // readers never trigger it.
            let mut probe2 = [0u8; 1];
            let n = self.input.read(&mut probe2)?;
            if n > 0 {
                return Err(stream_io_error(
                    io::ErrorKind::InvalidData,
                    StreamError::ExtraData,
                ));
            }
        }

        self.pos = 0;
        Ok(())
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.chunk.len() {
            if self.done {
                return Ok(0);
            }
            self.fill_buffer()?;
            if self.done && self.chunk.is_empty() {
                return Ok(0);
            }
        }

        let available = self.chunk.len() - self.pos;
        let n = cmp::min(buf.len(), available);
        buf[..n].copy_from_slice(&self.chunk[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl<R: Read> Drop for DecryptReader<R> {
    fn drop(&mut self) {
        self.chunk.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::KeyInit;
    use secrecy::SecretString;

    // ─── Streaming AEAD adapter helpers ───────────────────────────────────
    //
    // Lock the chunked encrypt/decrypt boundary cases in `EncryptWriter` and
    // `DecryptReader` with a fixed test key+nonce so each test produces
    // deterministic ciphertext. These adapters are exercised end-to-end by
    // the integration suite, but the cases below pin specific edge cases
    // (exact `BUFFER_SIZE` boundary, byte-at-a-time writes, empty final
    // chunk, small consumer buffers) at the adapter level so a regression
    // in `fill_buffer` or the in-place AEAD wiring fails immediately.

    const TEST_KEY: [u8; ENCRYPTION_KEY_SIZE] = [0x42; ENCRYPTION_KEY_SIZE];
    const TEST_NONCE: [u8; STREAM_NONCE_SIZE] = [0x37; STREAM_NONCE_SIZE];

    fn fresh_encryptor() -> stream::EncryptorBE32<XChaCha20Poly1305> {
        let cipher = XChaCha20Poly1305::new((&TEST_KEY).into());
        stream::EncryptorBE32::from_aead(cipher, TEST_NONCE.as_ref().into())
    }

    fn fresh_decryptor() -> stream::DecryptorBE32<XChaCha20Poly1305> {
        let cipher = XChaCha20Poly1305::new((&TEST_KEY).into());
        stream::DecryptorBE32::from_aead(cipher, TEST_NONCE.as_ref().into())
    }

    fn encrypt_to_vec(plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext: Vec<u8> = Vec::new();
        let mut writer = EncryptWriter::new(fresh_encryptor(), &mut ciphertext);
        writer.write_all(plaintext).unwrap();
        let _ = writer.finish().unwrap();
        ciphertext
    }

    fn decrypt_to_vec(ciphertext: &[u8]) -> Vec<u8> {
        let mut reader = DecryptReader::new(fresh_decryptor(), ciphertext);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        out
    }

    /// Plaintext exactly equal to one chunk: per `FORMAT.md` §5,
    /// writers MUST NOT append an extra empty final chunk after
    /// non-empty plaintext whose length is a multiple of `BUFFER_SIZE`.
    /// The writer therefore defers the full `BUFFER_SIZE` chunk
    /// until `finish()` and emits it as a single full-size **final**
    /// chunk via `encrypt_last_in_place`. Total ciphertext is exactly
    /// one full encrypted chunk (no separate tag-only trailer).
    #[test]
    fn streaming_aead_round_trip_exact_buffer_size() {
        let plaintext: Vec<u8> = (0..BUFFER_SIZE).map(|i| (i % 251) as u8).collect();
        let ciphertext = encrypt_to_vec(&plaintext);
        assert_eq!(
            ciphertext.len(),
            BUFFER_SIZE + TAG_SIZE,
            "expected exactly one full final chunk (FORMAT.md §5: no empty trailer)"
        );
        let decrypted = decrypt_to_vec(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// Many 1-byte writes that together cross multiple chunk boundaries.
    /// Exercises `EncryptWriter::write`'s buffer-accumulation path: most
    /// calls only extend `self.chunk`, and `encrypt_next_in_place` fires
    /// only at the exact `BUFFER_SIZE` boundary. A regression that drops
    /// any byte in the accumulation logic produces wrong ciphertext.
    #[test]
    fn streaming_aead_round_trip_byte_at_a_time_writes() {
        let plaintext: Vec<u8> = (0..(BUFFER_SIZE * 2 + 50))
            .map(|i| (i % 251) as u8)
            .collect();
        let mut ciphertext: Vec<u8> = Vec::new();
        let mut writer = EncryptWriter::new(fresh_encryptor(), &mut ciphertext);
        for byte in &plaintext {
            writer.write_all(std::slice::from_ref(byte)).unwrap();
        }
        let _ = writer.finish().unwrap();
        let decrypted = decrypt_to_vec(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// Plaintext is an exact 3× multiple of `BUFFER_SIZE`. Per
    /// `FORMAT.md` §5, the file is laid out as two `next` chunks
    /// followed by a full-size `last` chunk — no empty trailer.
    /// The reader must use its 1-byte peek to distinguish
    /// "exact-N-final" from "exact-N-then-more" without misclassifying
    /// either.
    #[test]
    fn streaming_aead_exact_multiple_no_empty_trailer() {
        let plaintext: Vec<u8> = (0..(BUFFER_SIZE * 3)).map(|i| (i % 251) as u8).collect();
        let ciphertext = encrypt_to_vec(&plaintext);
        assert_eq!(
            ciphertext.len(),
            3 * (BUFFER_SIZE + TAG_SIZE),
            "expected three full chunks (last one is the FINAL chunk; FORMAT.md §5)"
        );
        let decrypted = decrypt_to_vec(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// Empty plaintext is encoded as one empty FINAL chunk (just the
    /// 16-byte AEAD tag). FORMAT.md §5 calls this out as the only
    /// case where an empty final chunk is permitted.
    #[test]
    fn streaming_aead_empty_plaintext_is_single_tag_only_chunk() {
        let ciphertext = encrypt_to_vec(&[]);
        assert_eq!(
            ciphertext.len(),
            TAG_SIZE,
            "empty plaintext must produce exactly one tag-only final chunk"
        );
        let decrypted = decrypt_to_vec(&ciphertext);
        assert_eq!(decrypted, &[] as &[u8]);
    }

    /// Drain `DecryptReader` through tiny consumer buffers. The reader
    /// must serve plaintext correctly when the caller's buffer is much
    /// smaller than the AEAD chunk: most `read()` calls return 7 bytes
    /// from `self.chunk[self.pos..]`, and `fill_buffer` only fires when
    /// the chunk is fully drained. Locks the pos/len bookkeeping in the
    /// `Read` impl across multi-chunk boundaries.
    #[test]
    fn streaming_aead_decrypt_with_small_read_buffers() {
        let plaintext: Vec<u8> = (0..(BUFFER_SIZE * 2 + 1234))
            .map(|i| (i % 251) as u8)
            .collect();
        let ciphertext = encrypt_to_vec(&plaintext);

        let mut reader = DecryptReader::new(fresh_decryptor(), ciphertext.as_slice());
        let mut decrypted = Vec::with_capacity(plaintext.len());
        let mut tiny_buf = [0u8; 7];
        loop {
            let n = reader.read(&mut tiny_buf).unwrap();
            if n == 0 {
                break;
            }
            decrypted.extend_from_slice(&tiny_buf[..n]);
        }
        assert_eq!(decrypted, plaintext);
    }

    /// Drains a `DecryptReader` through `Read::read` directly until either
    /// `Ok(0)` or `Err`. Returns the (collected_plaintext, optional_error).
    /// `Read::read`'s contract about partial reads is crisper than
    /// `read_to_end`'s — using it here means the partial-output assertions
    /// in the truncation and tamper tests stay robust against future std
    /// changes to `read_to_end`'s error-path append behavior.
    fn drain_decrypt_reader(reader: &mut DecryptReader<&[u8]>) -> (Vec<u8>, Option<io::Error>) {
        let mut out = Vec::new();
        let mut scratch = [0u8; 4096];
        loop {
            match reader.read(&mut scratch) {
                Ok(0) => return (out, None),
                Ok(n) => out.extend_from_slice(&scratch[..n]),
                Err(e) => return (out, Some(e)),
            }
        }
    }

    /// A completely empty input (0 bytes) hits the dedicated
    /// `filled == 0` truncation path: there is no final
    /// authenticated chunk at all, and the reader rejects via
    /// `StreamError::Truncated` → `CryptoError::PayloadTruncated`
    /// rather than silently returning empty plaintext. (Empty
    /// **plaintext** is a different case: the writer still emits one
    /// tag-only `encrypt_last` chunk; see
    /// `streaming_aead_empty_plaintext_is_single_tag_only_chunk`.)
    #[test]
    fn streaming_aead_empty_input_rejected_as_truncation() {
        let mut reader = DecryptReader::new(fresh_decryptor(), &[][..]);
        let (out, err) = drain_decrypt_reader(&mut reader);
        let err = err.expect("expected truncation error, got clean EOF");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        let marker = err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<StreamError>())
            .expect("expected StreamError marker");
        assert!(
            matches!(marker, StreamError::Truncated),
            "expected StreamError::Truncated, got {marker:?}"
        );
        assert!(
            out.is_empty(),
            "no plaintext should be served on empty input"
        );
    }

    /// Truncating a multi-chunk stream at an exact chunk boundary
    /// (so the file ends after a `next` chunk with no `last` chunk
    /// at all) surfaces as AEAD authentication failure on the
    /// remaining chunk: AEAD-BE32 binds the `last_flag` in the
    /// chunk nonce, so a truncated `next` chunk cannot be
    /// re-authenticated as `last`. This test pins the behavior so a
    /// future regression that bypasses the AEAD binding would be
    /// caught.
    #[test]
    fn streaming_aead_chunk_boundary_truncation_rejected() {
        // 2× BUFFER_SIZE plaintext → 1 `next` chunk + 1 full-size
        // `last` chunk under FORMAT.md §5.
        let plaintext: Vec<u8> = (0..(BUFFER_SIZE * 2)).map(|i| (i % 251) as u8).collect();
        let mut ciphertext = encrypt_to_vec(&plaintext);
        // Drop the entire `last` chunk: file now ends right after a
        // `next` chunk.
        ciphertext.truncate(BUFFER_SIZE + TAG_SIZE);

        let mut reader = DecryptReader::new(fresh_decryptor(), ciphertext.as_slice());
        let (out, err) = drain_decrypt_reader(&mut reader);
        let err = err.expect("expected AEAD error on chunk-boundary truncation");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let marker = err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<StreamError>())
            .expect("expected StreamError marker");
        assert!(
            matches!(marker, StreamError::DecryptAead),
            "expected StreamError::DecryptAead, got {marker:?}"
        );
        // No plaintext was served: the reader's 1-byte peek returned 0
        // (EOF) immediately after the only chunk, so it tried to
        // decrypt the chunk as `last`, which fails AEAD because the
        // chunk was actually written with `last_flag = 0`.
        assert!(
            out.is_empty(),
            "no plaintext should leak from a truncated `next` chunk"
        );
    }

    /// Flip one byte in a late ciphertext chunk. The reader should return the
    /// already-verified first plaintext chunk, then fail when it reaches the
    /// corrupted later chunk instead of silently accepting modified data.
    /// Confirms that no bytes from the failing chunk are returned.
    #[test]
    fn streaming_aead_late_ciphertext_bit_flip_rejected() {
        let plaintext: Vec<u8> = (0..(BUFFER_SIZE * 2 + 1234))
            .map(|i| (i % 251) as u8)
            .collect();
        let mut ciphertext = encrypt_to_vec(&plaintext);

        // Ciphertext layout here is:
        //   chunk 1: BUFFER_SIZE + TAG_SIZE
        //   chunk 2: BUFFER_SIZE + TAG_SIZE
        //   final  : 1234 + TAG_SIZE
        // Flip a byte well inside the second encrypted chunk.
        let second_chunk_offset = BUFFER_SIZE + TAG_SIZE;
        ciphertext[second_chunk_offset + 100] ^= 0x01;

        let mut reader = DecryptReader::new(fresh_decryptor(), ciphertext.as_slice());
        let (out, err) = drain_decrypt_reader(&mut reader);
        let err = err.expect("expected AEAD tamper error, got clean EOF");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let marker = err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<StreamError>())
            .expect("expected StreamError marker");
        assert!(
            matches!(marker, StreamError::DecryptAead),
            "expected StreamError::DecryptAead, got {marker:?}"
        );
        // Exactly the first chunk's plaintext must have been served:
        //  - chunk 1 was fully verified, so its plaintext is delivered;
        //  - chunk 2 failed AEAD verification, so none of its bytes leak;
        //  - the final chunk is never reached.
        assert_eq!(out.as_slice(), &plaintext[..BUFFER_SIZE]);
    }

    /// Mid-chunk truncation: the final encrypted chunk is partially present
    /// but shorter than `BUFFER_SIZE + TAG_SIZE`. `fill_buffer` treats the
    /// short buffer as the final chunk and runs `decrypt_last_in_place`,
    /// which must fail AEAD authentication. The user-visible variant is
    /// `PayloadTampered`, not `PayloadTruncated`: we cannot distinguish a
    /// truncated tail from a tampered tail, and either way the tail must
    /// be rejected.
    #[test]
    fn streaming_aead_mid_chunk_truncation_rejected() {
        let plaintext: Vec<u8> = (0..(BUFFER_SIZE + 500)).map(|i| (i % 251) as u8).collect();
        let mut ciphertext = encrypt_to_vec(&plaintext);
        // Drop 10 bytes from inside the final (short) chunk, leaving a
        // partial chunk that still has data but is not a valid AEAD frame.
        ciphertext.truncate(ciphertext.len() - 10);

        let mut reader = DecryptReader::new(fresh_decryptor(), ciphertext.as_slice());
        let (out, err) = drain_decrypt_reader(&mut reader);
        let err = err.expect("expected AEAD error on mid-chunk truncation");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let marker = err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<StreamError>())
            .expect("expected StreamError marker");
        assert!(
            matches!(marker, StreamError::DecryptAead),
            "expected StreamError::DecryptAead, got {marker:?}"
        );
        // First chunk verified cleanly and its plaintext was delivered;
        // mid-chunk truncation aborts the final chunk with no leaked bytes.
        assert_eq!(out.as_slice(), &plaintext[..BUFFER_SIZE]);
    }

    /// Reader that first yields the "legitimate" ciphertext segment (the
    /// valid stream, as written by `EncryptWriter::finish`) signalling EOF
    /// at its end, then — on the *next* `read()` call — returns additional
    /// bytes. This is exactly the pathological pattern the `ExtraData`
    /// probe defends against: a non-blocking socket or Take-style wrapper
    /// that returns `Ok(0)` prematurely and then later produces more data.
    ///
    /// A plain `&[u8]` reader cannot exercise this branch because its
    /// read loop reads all remaining bytes in one pass and lets AEAD
    /// authentication reject the trailing bytes as `PayloadTampered`.
    struct LegitThenExtraReader<'a> {
        legit: &'a [u8],
        extra: &'a [u8],
        legit_pos: usize,
        extra_pos: usize,
        /// Flips to `true` the first time we hit EOF inside `legit`, so
        /// the subsequent `read` call is the one that starts dispensing
        /// bytes from `extra`.
        legit_exhausted: bool,
    }

    impl<'a> LegitThenExtraReader<'a> {
        fn new(legit: &'a [u8], extra: &'a [u8]) -> Self {
            Self {
                legit,
                extra,
                legit_pos: 0,
                extra_pos: 0,
                legit_exhausted: false,
            }
        }
    }

    impl<'a> Read for LegitThenExtraReader<'a> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.legit_exhausted {
                let remaining = self.legit.len() - self.legit_pos;
                if remaining == 0 {
                    // First EOF on the legit segment: caller (fill_buffer
                    // inner loop) will treat this as "done" and proceed
                    // into decrypt_last. The probe then calls read again
                    // and we start dispensing `extra`.
                    self.legit_exhausted = true;
                    return Ok(0);
                }
                let n = cmp::min(buf.len(), remaining);
                buf[..n].copy_from_slice(&self.legit[self.legit_pos..self.legit_pos + n]);
                self.legit_pos += n;
                return Ok(n);
            }

            let remaining = self.extra.len() - self.extra_pos;
            if remaining == 0 {
                return Ok(0);
            }
            let n = cmp::min(buf.len(), remaining);
            buf[..n].copy_from_slice(&self.extra[self.extra_pos..self.extra_pos + n]);
            self.extra_pos += n;
            Ok(n)
        }
    }

    /// Pathological-reader trailing-data case: a reader that returns the
    /// valid ciphertext, signals EOF, and then produces extra bytes.
    /// `fill_buffer` treats the EOF as the end of the final chunk and
    /// runs `decrypt_last_in_place` successfully; the trailing-data probe
    /// then catches the stray bytes and rejects the stream with
    /// [`StreamError::ExtraData`]. Locks in the L3 defense-in-depth
    /// wiring so the dedicated error variant cannot silently regress to
    /// unreachable code.
    #[test]
    fn streaming_aead_extra_data_after_final_chunk_rejected() {
        // Use multi-chunk plaintext so the first chunk is served through
        // `Read` before the probe fires. On a single-chunk plaintext the whole
        // authenticated payload would be dropped when the probe returns Err (the
        // plaintext in `self.chunk` is only dispensed by subsequent
        // `read()` calls, and `fill_buffer`'s Err propagates first) —
        // that's correct fail-closed behaviour but makes the partial-
        // output assertion trivially empty.
        let plaintext: Vec<u8> = (0..(BUFFER_SIZE + 500)).map(|i| (i % 251) as u8).collect();
        let ciphertext = encrypt_to_vec(&plaintext);
        let trailing = b"garbage-appended-by-attacker";

        let reader_wrapper = LegitThenExtraReader::new(&ciphertext, trailing);
        // `DecryptReader` requires the reader type to be `Read`; the
        // wrapper above satisfies that contract. We cannot reuse
        // `drain_decrypt_reader` here because it's hard-coded to
        // `&[u8]`; inline the drain loop instead.
        let mut reader = DecryptReader::new(fresh_decryptor(), reader_wrapper);
        let mut out = Vec::new();
        let mut scratch = [0u8; 4096];
        let err = loop {
            match reader.read(&mut scratch) {
                Ok(0) => panic!("expected ExtraData error, got clean EOF"),
                Ok(n) => out.extend_from_slice(&scratch[..n]),
                Err(e) => break e,
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let marker = err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<StreamError>())
            .expect("expected StreamError marker");
        assert!(
            matches!(marker, StreamError::ExtraData),
            "expected StreamError::ExtraData, got {marker:?}"
        );
        // The first chunk (BUFFER_SIZE bytes) is fully authenticated and
        // served through `read()` before the second `fill_buffer` call
        // decrypts the final chunk and the probe fires. The final chunk's
        // 500 authenticated plaintext bytes are dropped on the Err path —
        // that's the correct fail-closed outcome for a tainted stream.
        assert_eq!(out.as_slice(), &plaintext[..BUFFER_SIZE]);
    }

    #[test]
    fn test_encryption_base_name_file() {
        let stem = encryption_base_name("path/to/file.txt").unwrap();
        assert_eq!(stem, "file");
    }

    #[test]
    fn test_encryption_base_name_no_extension() {
        let stem = encryption_base_name("path/to/file").unwrap();
        assert_eq!(stem, "file");
    }

    #[test]
    fn test_encryption_base_name_dotted_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dotted_dir = tmp.path().join("photos.v1");
        std::fs::create_dir(&dotted_dir).unwrap();
        let name = encryption_base_name(&dotted_dir).unwrap();
        assert_eq!(name, "photos.v1");
    }

    #[test]
    fn test_constant_time_compare_equal() {
        let data = [42u8; 32];
        assert!(ct_eq_32(&data, &data));
    }

    #[test]
    fn test_constant_time_compare_not_equal() {
        let data1 = [42u8; 32];
        let mut data2 = [42u8; 32];
        data2[0] = 43;
        assert!(!ct_eq_32(&data1, &data2));
    }

    #[test]
    fn test_constant_time_compare_all_zeros() {
        let data1 = [0u8; 32];
        let data2 = [0u8; 32];
        assert!(ct_eq_32(&data1, &data2));
    }

    #[test]
    fn test_secret_string_creation() {
        let secret = SecretString::from("my_secret_password".to_string());
        let debug_str = format!("{:?}", secret);
        assert!(debug_str.contains("Secret"));
    }

    #[test]
    fn test_kdf_params_valid_defaults() {
        let params = KdfParams::default();
        let bytes = params.to_bytes();
        assert!(KdfParams::from_bytes(&bytes, None).is_ok());
    }

    #[test]
    fn test_kdf_params_rejects_zero_mem_cost() {
        let mut bytes = KdfParams::default().to_bytes();
        bytes[0..4].copy_from_slice(&0u32.to_be_bytes());
        assert!(KdfParams::from_bytes(&bytes, None).is_err());
    }

    #[test]
    fn test_kdf_params_rejects_zero_time_cost() {
        let mut bytes = KdfParams::default().to_bytes();
        bytes[4..8].copy_from_slice(&0u32.to_be_bytes());
        assert!(KdfParams::from_bytes(&bytes, None).is_err());
    }

    #[test]
    fn test_kdf_params_rejects_zero_lanes() {
        let mut bytes = KdfParams::default().to_bytes();
        bytes[8..12].copy_from_slice(&0u32.to_be_bytes());
        assert!(KdfParams::from_bytes(&bytes, None).is_err());
    }

    #[test]
    fn test_kdf_params_rejects_excessive_time_cost() {
        let mut bytes = KdfParams::default().to_bytes();
        bytes[4..8].copy_from_slice(&13u32.to_be_bytes());
        assert!(KdfParams::from_bytes(&bytes, None).is_err());
    }

    #[test]
    fn test_kdf_params_rejects_excessive_lanes() {
        let mut bytes = KdfParams::default().to_bytes();
        bytes[8..12].copy_from_slice(&9u32.to_be_bytes());
        assert!(KdfParams::from_bytes(&bytes, None).is_err());
    }

    #[test]
    fn test_kdf_params_rejects_mem_cost_below_argon2_minimum() {
        // Argon2 requires mem_cost >= 8 * lanes
        let bytes = KdfParams {
            mem_cost: 31,
            time_cost: 4,
            lanes: 4,
        }
        .to_bytes();
        assert!(KdfParams::from_bytes(&bytes, None).is_err());
    }

    #[test]
    fn test_kdf_params_accepts_max_bounds() {
        let bytes = KdfParams {
            mem_cost: 2 * 1024 * 1024,
            time_cost: 12,
            lanes: 8,
        }
        .to_bytes();
        // Structurally valid at the hard 2 GiB ceiling. Callers who want
        // to accept such a header opt into the matching `KdfLimit`
        // explicitly; the default 1 GiB cap is enforced elsewhere.
        let limit = KdfLimit::new(KdfParams::MAX_MEM_COST);
        assert!(KdfParams::from_bytes(&bytes, Some(&limit)).is_ok());
    }

    #[test]
    fn test_kdf_limit_rejects_excessive_mem_cost() {
        let bytes = KdfParams {
            mem_cost: 1_048_576, // 1 GiB
            time_cost: 4,
            lanes: 4,
        }
        .to_bytes();
        let limit = KdfLimit::new(512 * 1024); // 512 MiB
        match KdfParams::from_bytes(&bytes, Some(&limit)) {
            Err(CryptoError::KdfResourceCapExceeded {
                mem_cost_kib: 1_048_576,
                local_cap_kib: 524_288,
            }) => {}
            Err(other) => panic!("expected KdfResourceCapExceeded, got: {other}"),
            Ok(_) => panic!("expected KdfResourceCapExceeded error, got Ok"),
        }
    }

    #[test]
    fn test_kdf_limit_accepts_within_bound() {
        let bytes = KdfParams {
            mem_cost: 1_048_576, // 1 GiB
            time_cost: 4,
            lanes: 4,
        }
        .to_bytes();
        let limit = KdfLimit::new(2 * 1024 * 1024); // 2 GiB
        assert!(KdfParams::from_bytes(&bytes, Some(&limit)).is_ok());
    }

    #[test]
    fn test_kdf_limit_default_accepts_default_params() {
        let bytes = KdfParams::default().to_bytes();
        let limit = KdfLimit::default();
        assert!(KdfParams::from_bytes(&bytes, Some(&limit)).is_ok());
    }

    /// M-2 regression: `KdfLimit::default()` caps accepted `mem_cost` at the
    /// writer's default (1 GiB). A structurally-valid header requesting the
    /// hard maximum (2 GiB) must be rejected with `KdfResourceCapExceeded`
    /// when the caller does not opt into a wider limit explicitly. Locks
    /// in the post-audit tightening so it cannot silently regress.
    #[test]
    fn test_kdf_limit_default_rejects_max_mem_cost_header() {
        let bytes = KdfParams {
            mem_cost: KdfParams::MAX_MEM_COST, // 2 GiB — structurally valid
            time_cost: 4,
            lanes: 4,
        }
        .to_bytes();
        let limit = KdfLimit::default();
        match KdfParams::from_bytes(&bytes, Some(&limit)) {
            Err(CryptoError::KdfResourceCapExceeded {
                mem_cost_kib,
                local_cap_kib,
            }) => {
                assert_eq!(mem_cost_kib, KdfParams::MAX_MEM_COST);
                assert_eq!(local_cap_kib, KdfParams::DEFAULT_MEM_COST);
            }
            Err(other) => panic!("expected KdfResourceCapExceeded, got: {other}"),
            Ok(_) => panic!("default limit must reject a 2 GiB header"),
        }
    }

    /// M-2 regression: when `limit = None` (the library's "no explicit cap"
    /// convenience), `from_bytes` must still apply the default ceiling so
    /// callers who do not pass a `KdfLimit` are not silently exposed to
    /// 2 GiB allocations from attacker-controlled headers.
    #[test]
    fn test_kdf_limit_none_applies_default_ceiling() {
        let bytes = KdfParams {
            mem_cost: KdfParams::MAX_MEM_COST,
            time_cost: 4,
            lanes: 4,
        }
        .to_bytes();
        match KdfParams::from_bytes(&bytes, None) {
            Err(CryptoError::KdfResourceCapExceeded {
                mem_cost_kib,
                local_cap_kib,
            }) => {
                assert_eq!(mem_cost_kib, KdfParams::MAX_MEM_COST);
                assert_eq!(local_cap_kib, KdfParams::DEFAULT_MEM_COST);
            }
            Err(other) => panic!("expected KdfResourceCapExceeded, got: {other}"),
            Ok(_) => panic!("None limit must apply default ceiling"),
        }
    }

    // ─── File key / subkey derivation / TLV ──────────────────────────────

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
    fn hkdf_expand_sha3_256_is_deterministic() {
        let ikm = [0x11u8; 32];
        let salt = [0x22u8; 16];
        let info = b"ferrocrypt/v1/test";
        let a = hkdf_expand_sha3_256(Some(&salt), &ikm, info).unwrap();
        let b = hkdf_expand_sha3_256(Some(&salt), &ikm, info).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn hkdf_expand_sha3_256_domain_separates_on_info() {
        let ikm = [0x11u8; 32];
        let a = hkdf_expand_sha3_256(None, &ikm, HKDF_INFO_PAYLOAD).unwrap();
        let b = hkdf_expand_sha3_256(None, &ikm, HKDF_INFO_HEADER).unwrap();
        assert_ne!(*a, *b, "different info strings must produce different keys");
    }

    #[test]
    fn hkdf_expand_sha3_256_domain_separates_on_salt() {
        let ikm = [0x11u8; 32];
        let info = HKDF_INFO_PAYLOAD;
        let salt_a = [0x22u8; 16];
        let salt_b = [0x33u8; 16];
        let a = hkdf_expand_sha3_256(Some(&salt_a), &ikm, info).unwrap();
        let b = hkdf_expand_sha3_256(Some(&salt_b), &ikm, info).unwrap();
        assert_ne!(*a, *b, "different salts must produce different keys");
    }

    #[test]
    fn derive_subkeys_round_trip() {
        let file_key = [0x11u8; FILE_KEY_SIZE];
        let nonce = [0x22u8; STREAM_NONCE_SIZE];
        let (payload_a, header_a) = derive_subkeys(&file_key, &nonce).unwrap();
        let (payload_b, header_b) = derive_subkeys(&file_key, &nonce).unwrap();
        assert_eq!(*payload_a, *payload_b);
        assert_eq!(*header_a, *header_b);
    }

    #[test]
    fn derive_subkeys_payload_depends_on_stream_nonce() {
        let file_key = [0x11u8; FILE_KEY_SIZE];
        let nonce_a = [0x22u8; STREAM_NONCE_SIZE];
        let nonce_b = [0x33u8; STREAM_NONCE_SIZE];
        let (payload_a, header_a) = derive_subkeys(&file_key, &nonce_a).unwrap();
        let (payload_b, header_b) = derive_subkeys(&file_key, &nonce_b).unwrap();
        assert_ne!(
            *payload_a, *payload_b,
            "payload key depends on stream_nonce"
        );
        // Header key uses empty salt so stream_nonce must NOT affect it.
        assert_eq!(
            *header_a, *header_b,
            "header key is independent of stream_nonce"
        );
    }

    #[test]
    fn derive_subkeys_depends_on_file_key() {
        let file_a = [0x11u8; FILE_KEY_SIZE];
        let file_b = [0x33u8; FILE_KEY_SIZE];
        let nonce = [0x22u8; STREAM_NONCE_SIZE];
        let (payload_a, _) = derive_subkeys(&file_a, &nonce).unwrap();
        let (payload_b, _) = derive_subkeys(&file_b, &nonce).unwrap();
        assert_ne!(*payload_a, *payload_b);
    }

    /// Builds a single TLV entry `tag(u16) || len(u32) || value` per
    /// `FORMAT.md` §6. Callers concatenate results for multi-entry
    /// cases.
    fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + value.len());
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    #[test]
    fn validate_tlv_accepts_empty_region() {
        assert!(validate_tlv(&[]).is_ok());
    }

    #[test]
    fn validate_tlv_accepts_single_ignorable_tag() {
        let region = tlv(0x0001, &[0xAA; 8]);
        assert!(validate_tlv(&region).is_ok());
    }

    #[test]
    fn validate_tlv_accepts_zero_length_ignorable_tag() {
        let region = tlv(0x0001, &[]);
        assert!(validate_tlv(&region).is_ok());
    }

    #[test]
    fn validate_tlv_accepts_ascending_ignorable_tags() {
        let mut region = tlv(0x0001, &[0xAA]);
        region.extend_from_slice(&tlv(0x0002, &[0xBB; 3]));
        region.extend_from_slice(&tlv(0x7FFF, &[0xCC; 16]));
        assert!(validate_tlv(&region).is_ok());
    }

    #[test]
    fn validate_tlv_rejects_unknown_critical_tag() {
        let region = tlv(0x8001, &[0xAA; 4]);
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::UnknownCriticalTag { tag: 0x8001 })) => {}
            other => panic!("expected UnknownCriticalTag(0x8001), got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_reserved_tag_0x0000() {
        let region = tlv(0x0000, &[]);
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => {}
            other => panic!("expected MalformedTlv for 0x0000, got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_reserved_tag_0x8000() {
        let region = tlv(0x8000, &[]);
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => {}
            other => panic!("expected MalformedTlv for 0x8000, got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_descending_tags() {
        let mut region = tlv(0x0002, &[0xAA]);
        region.extend_from_slice(&tlv(0x0001, &[0xBB]));
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => {}
            other => panic!("expected MalformedTlv for descending, got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_duplicate_tags() {
        let mut region = tlv(0x0001, &[0xAA]);
        region.extend_from_slice(&tlv(0x0001, &[0xBB]));
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => {}
            other => panic!("expected MalformedTlv for duplicate, got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_len_past_end() {
        // tag=0x0001, len=100 but only 3 bytes of value follow.
        let mut region = Vec::new();
        region.extend_from_slice(&0x0001u16.to_be_bytes());
        region.extend_from_slice(&100u32.to_be_bytes());
        region.extend_from_slice(&[0xAA; 3]);
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => {}
            other => panic!("expected MalformedTlv for len-past-end, got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_truncated_entry_header() {
        // Only 5 bytes of TLV header (need at least 6 = tag(u16) + len(u32)).
        let region = vec![0x00, 0x01, 0x00, 0x00, 0x00];
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => {}
            other => panic!("expected MalformedTlv for truncated header, got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_len_above_region_cap() {
        // tag=0x0001, len=u32::MAX. Even though the on-disk region
        // is sized within `EXT_LEN_MAX`, a per-entry `len` field that
        // exceeds the cap must be rejected before integer
        // conversion to `usize`.
        let mut region = Vec::new();
        region.extend_from_slice(&0x0001u16.to_be_bytes());
        region.extend_from_slice(&u32::MAX.to_be_bytes());
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => {}
            other => panic!("expected MalformedTlv for len-over-cap, got {other:?}"),
        }
    }

    #[test]
    fn validate_tlv_rejects_region_over_cap() {
        // A region > 32 KiB is rejected structurally, before per-entry parsing.
        let region = vec![0u8; EXT_LEN_MAX as usize + 1];
        match validate_tlv(&region) {
            Err(CryptoError::InvalidFormat(FormatDefect::ExtTooLarge { .. })) => {}
            other => panic!("expected ExtTooLarge, got {other:?}"),
        }
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
        assert_eq!(
            HKDF_INFO_PRIVATE_KEY_WRAP,
            b"ferrocrypt/v1/private-key/wrap"
        );
        assert_eq!(HKDF_INFO_PAYLOAD, b"ferrocrypt/v1/payload");
        assert_eq!(HKDF_INFO_HEADER, b"ferrocrypt/v1/header");
    }
}
