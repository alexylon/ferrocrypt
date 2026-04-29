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
pub const ARGON2_SALT_SIZE: usize = 32;

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

const KDF_MEM_COST_OFFSET: usize = 0;
const KDF_TIME_COST_OFFSET: usize = KDF_MEM_COST_OFFSET + size_of::<u32>();
const KDF_LANES_OFFSET: usize = KDF_TIME_COST_OFFSET + size_of::<u32>();
const _: () = assert!(KDF_LANES_OFFSET + size_of::<u32>() == KDF_PARAMS_SIZE);

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
            mem_cost: read_u32_be(bytes, KDF_MEM_COST_OFFSET),
            time_cost: read_u32_be(bytes, KDF_TIME_COST_OFFSET),
            lanes: read_u32_be(bytes, KDF_LANES_OFFSET),
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
}
