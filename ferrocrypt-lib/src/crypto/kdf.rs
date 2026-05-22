//! KDF parameter validation and resource-cap policy.
//!
//! Argon2id parameter parsing has one source of truth here: structural
//! bounds in [`KdfParams::from_bytes_structural`], caller resource policy
//! in [`KdfParams::enforce_limit`], and the public composition gate
//! [`KdfParams::from_bytes`] that runs both. The CLI/library `KdfLimit`
//! type carries the resource-cap policy across the public API.

use zeroize::Zeroizing;

use crate::CryptoError;
use crate::crypto::keys::ENCRYPTION_KEY_SIZE;
use crate::error::InvalidKdfParams;
use crate::format::{read_u32_be, write_u32_be};

/// Argon2id salt size in bytes. Stored alongside `KdfParams` in any
/// header that consumes a passphrase (argon2id recipient body,
/// `private.key` cleartext header).
pub(crate) const ARGON2_SALT_SIZE: usize = 32;

/// Structural cap on passphrase byte length. Argon2id itself accepts
/// arbitrarily long inputs, but library-direct callers can otherwise
/// hand a multi-gigabyte buffer to [`KdfParams::hash_passphrase`] and
/// pay that allocation cost upstream of the KDF resource policy.
/// 4 KiB is far above any human-typed passphrase yet small enough that
/// an attacker-shaped input cannot DoS the host. Frontends already cap
/// their input fields well below this; the cap exists for direct
/// callers and as defense-in-depth.
pub(crate) const MAX_PASSPHRASE_LEN_BYTES: usize = 4_096;

/// Local policy limit for Argon2id work accepted during decryption.
///
/// A v1 file or `private.key` stores its Argon2id parameters in the cleartext
/// header. When processing untrusted input, `KdfLimit` prevents a malicious
/// header from forcing arbitrarily expensive key derivation: any structurally
/// valid input whose memory cost exceeds the configured cap is rejected
/// before Argon2id runs. If no limit is configured on a decryptor, the
/// library applies [`KdfLimit::default`], which matches the writer's default
/// memory cost.
///
/// Construct with [`KdfLimit::new`] for KiB or [`KdfLimit::from_mib`] for MiB,
/// then pass it to [`crate::PassphraseDecryptor::kdf_limit`] or
/// [`crate::PrivateKeyDecryptor::kdf_limit`]. The struct is `#[non_exhaustive]`
/// so future releases can add additional limit dimensions without a breaking
/// change.
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

    /// Builds a limit from MiB.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidInput`] if `mib * 1024` overflows `u32`.
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

/// KDF parameters stored in file headers and key files.
///
/// These values are serialized in v1 `argon2id` recipient bodies and
/// `private.key` cleartext headers so decryption repeats the same work factor
/// used during encryption. See `FORMAT.md` §4.1 and §8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Argon2id memory cost in KiB.
    pub mem_cost: u32,
    /// Argon2id iteration count.
    pub time_cost: u32,
    /// Argon2id parallelism lane count.
    pub lanes: u32,
}

/// Serialized size of [`KdfParams`] in bytes (3 × `u32` big-endian).
pub const KDF_PARAMS_SIZE: usize = 12;

const KDF_MEM_COST_OFFSET: usize = 0;
const KDF_TIME_COST_OFFSET: usize = KDF_MEM_COST_OFFSET + size_of::<u32>();
const KDF_LANES_OFFSET: usize = KDF_TIME_COST_OFFSET + size_of::<u32>();
const _: () = assert!(KDF_LANES_OFFSET + size_of::<u32>() == KDF_PARAMS_SIZE);

/// Argon2 spec constraint: `mem_cost` (in KiB) must be at least
/// `ARGON2_MIN_MEM_COST_PER_LANE * lanes` for the per-lane workspace
/// to be sized correctly. Values below this floor force Argon2 into
/// a degraded fallback configuration. Used by [`KdfParams::validate_structural`].
const ARGON2_MIN_MEM_COST_PER_LANE: u32 = 8;

impl KdfParams {
    pub(crate) const DEFAULT_MEM_COST: u32 = 1_048_576; // 1 GiB
    const DEFAULT_TIME_COST: u32 = 4;
    const DEFAULT_LANES: u32 = 4;

    /// Serializes these parameters to the v1 big-endian wire encoding.
    pub fn to_bytes(self) -> [u8; KDF_PARAMS_SIZE] {
        let mut buf = [0u8; KDF_PARAMS_SIZE];
        write_u32_be(&mut buf, KDF_MEM_COST_OFFSET, self.mem_cost);
        write_u32_be(&mut buf, KDF_TIME_COST_OFFSET, self.time_cost);
        write_u32_be(&mut buf, KDF_LANES_OFFSET, self.lanes);
        buf
    }

    // Upper bounds for KDF parameters from untrusted headers.
    // These prevent malicious files from causing excessive CPU/memory usage.
    pub(crate) const MAX_MEM_COST: u32 = 2 * 1024 * 1024; // 2 GiB
    const MAX_TIME_COST: u32 = 12;
    const MAX_LANES: u32 = 8;

    /// Field-level structural validation against v1 absolute bounds
    /// (`MAX_LANES`, `MAX_TIME_COST`, `MAX_MEM_COST`, plus the Argon2
    /// `mem_cost >= ARGON2_MIN_MEM_COST_PER_LANE * lanes` floor).
    /// Shared by [`from_bytes_structural`](Self::from_bytes_structural)
    /// (after parsing wire bytes) and
    /// [`validate_for_write`](Self::validate_for_write) (against
    /// caller-supplied params); single source of truth for the rule
    /// set. Does **not** apply any caller resource policy.
    fn validate_structural(&self) -> Result<(), CryptoError> {
        if self.lanes == 0 || self.lanes > Self::MAX_LANES {
            return Err(CryptoError::InvalidKdfParams(
                InvalidKdfParams::Parallelism(self.lanes),
            ));
        }
        let min_mem_cost = ARGON2_MIN_MEM_COST_PER_LANE * self.lanes;
        if self.mem_cost < min_mem_cost || self.mem_cost > Self::MAX_MEM_COST {
            return Err(CryptoError::InvalidKdfParams(InvalidKdfParams::MemoryCost(
                self.mem_cost,
            )));
        }
        if self.time_cost == 0 || self.time_cost > Self::MAX_TIME_COST {
            return Err(CryptoError::InvalidKdfParams(InvalidKdfParams::TimeCost(
                self.time_cost,
            )));
        }
        Ok(())
    }

    /// Structural-only parse: parses wire bytes into a [`KdfParams`]
    /// and runs [`validate_structural`](Self::validate_structural). Does
    /// **not** apply any caller resource policy — call
    /// [`enforce_limit`](Self::enforce_limit) on the result for that.
    /// `pub(crate)` deliberately: external callers must go through
    /// [`from_bytes`](Self::from_bytes), which always applies the
    /// policy gate, so a missed call cannot bypass the cap.
    pub(crate) fn from_bytes_structural(
        bytes: &[u8; KDF_PARAMS_SIZE],
    ) -> Result<Self, CryptoError> {
        let params = Self {
            mem_cost: read_u32_be(bytes, KDF_MEM_COST_OFFSET)?,
            time_cost: read_u32_be(bytes, KDF_TIME_COST_OFFSET)?,
            lanes: read_u32_be(bytes, KDF_LANES_OFFSET)?,
        };
        params.validate_structural()?;
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

    /// Parses v1 KDF parameter bytes and enforces the caller's memory cap.
    ///
    /// `limit = None` still applies the library default ceiling so untrusted
    /// headers cannot force the structural 2 GiB maximum unless the caller opts
    /// in with [`KdfLimit`]. See `FORMAT.md` §4.1 and §8 for the serialized
    /// locations.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKdfParams`] when the fields violate v1
    /// structural bounds. Returns [`CryptoError::KdfResourceCapExceeded`] when
    /// `mem_cost` is structurally valid but exceeds `limit` or the default cap.
    pub fn from_bytes(
        bytes: &[u8; KDF_PARAMS_SIZE],
        limit: Option<&KdfLimit>,
    ) -> Result<Self, CryptoError> {
        Self::from_bytes_structural(bytes)?.enforce_limit(limit)
    }

    /// Validates caller-supplied writer parameters against the same v1
    /// structural bounds the reader enforces, then applies the caller's
    /// resource policy cap. This is the writer-side counterpart to
    /// [`from_bytes`](Self::from_bytes): public builders accept a raw
    /// [`KdfParams`] value, so they must run the same structural rules
    /// before serialising it into an `argon2id` recipient body or
    /// `private.key` header. Otherwise a caller could produce an artefact
    /// whose KDF fields Argon2 itself accepts but the FerroCrypt reader
    /// rejects before attempting unlock.
    pub(crate) fn validate_for_write(self, limit: Option<&KdfLimit>) -> Result<Self, CryptoError> {
        self.validate_structural()?;
        self.enforce_limit(limit)
    }

    /// Derives a fixed-size Argon2id output for the supplied passphrase and salt.
    ///
    /// The returned buffer zeroizes on drop. The high-level
    /// [`Encryptor`](crate::Encryptor),
    /// [`PassphraseDecryptor`](crate::PassphraseDecryptor), and
    /// [`KeyPairGenerator`](crate::KeyPairGenerator) APIs invoke this internally
    /// — most callers should not call it directly.
    ///
    /// # Security
    ///
    /// Pair every passphrase with a fresh, cryptographically random salt of
    /// `ARGON2_SALT_SIZE` bytes. Do not log or persist the derived output
    /// except as input to the FerroCrypt wrapping steps defined in
    /// `FORMAT.md`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKdfParams`] if `mem_cost`, `time_cost`,
    /// or `lanes` are outside the v1 structural bounds, and
    /// [`CryptoError::InvalidInput`] if the passphrase exceeds the 4 KiB
    /// structural cap. Both are checked before Argon2id runs, so any Argon2
    /// failure on the validated input surfaces as
    /// [`CryptoError::InternalCryptoFailure`].
    pub fn hash_passphrase(
        &self,
        passphrase: &[u8],
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; ENCRYPTION_KEY_SIZE]>, CryptoError> {
        self.validate_structural()?;
        if passphrase.len() > MAX_PASSPHRASE_LEN_BYTES {
            return Err(CryptoError::InvalidInput(format!(
                "Passphrase exceeds {MAX_PASSPHRASE_LEN_BYTES}-byte structural cap"
            )));
        }
        let params = argon2::Params::new(
            self.mem_cost,
            self.time_cost,
            self.lanes,
            Some(ENCRYPTION_KEY_SIZE),
        )
        .map_err(|_| {
            CryptoError::InternalCryptoFailure("Internal error: Argon2id parameter rejected")
        })?;
        let hasher =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut output = Zeroizing::new([0u8; ENCRYPTION_KEY_SIZE]);
        hasher
            .hash_password_into(passphrase, salt, output.as_mut())
            .map_err(|_| {
                CryptoError::InternalCryptoFailure("Internal error: Argon2id derivation failed")
            })?;
        Ok(output)
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            mem_cost: Self::DEFAULT_MEM_COST,
            time_cost: Self::DEFAULT_TIME_COST,
            lanes: Self::DEFAULT_LANES,
        }
    }
}

#[cfg(test)]
impl KdfParams {
    /// In-crate test helper: low-cost Argon2id parameters (8 MiB memory,
    /// time_cost 1, parallelism 4) for the lib's own `mod tests`. Reads
    /// the values from `ferrocrypt-test-support` (a `publish = false`
    /// workspace dev-dep) so the workspace has a single source of truth
    /// for the test-fast-KDF triple. The dev-dep cycle through
    /// `ferrocrypt` is fine here because the constants are plain `u32`
    /// — only typed `KdfParams` values from test-support hit the
    /// "multiple different versions of crate ferrocrypt" trap, which is
    /// why this helper constructs a fresh `Self` rather than calling
    /// `ferrocrypt_test_support::fast_kdf_params()` directly.
    pub(crate) fn test_fast_default() -> Self {
        Self {
            mem_cost: ferrocrypt_test_support::TEST_FAST_KDF_MEM_COST,
            time_cost: ferrocrypt_test_support::TEST_FAST_KDF_TIME_COST,
            lanes: ferrocrypt_test_support::TEST_FAST_KDF_LANES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

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

    /// `KdfLimit::default()` caps accepted `mem_cost` at the writer's
    /// default (1 GiB). A structurally-valid header requesting the hard
    /// maximum (2 GiB) must be rejected with `KdfResourceCapExceeded`
    /// when the caller does not opt into a wider limit explicitly. Pins
    /// the default-decrypt resource ceiling so it cannot silently regress.
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

    /// `hash_passphrase` is `pub`, so a direct caller can hand it a
    /// `KdfParams` with out-of-policy fields. A `time_cost` above the v1
    /// maximum — which `argon2::Params::new` itself would accept — must
    /// reject as `InvalidKdfParams` before Argon2id runs.
    #[test]
    fn hash_passphrase_rejects_structurally_invalid_params() {
        let params = KdfParams {
            mem_cost: 8,
            time_cost: KdfParams::MAX_TIME_COST + 1,
            lanes: 1,
        };
        let err = params
            .hash_passphrase(b"pw", &[0u8; ARGON2_SALT_SIZE])
            .unwrap_err();
        assert!(
            matches!(err, CryptoError::InvalidKdfParams(_)),
            "expected InvalidKdfParams, got {err:?}"
        );
    }
}
