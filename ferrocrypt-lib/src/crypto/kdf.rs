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

/// Argon2id salt size in bytes. Stored alongside [`KdfParams`] in any
/// header that consumes a passphrase (argon2id recipient body,
/// `private.key` cleartext header); the crate's internal Argon2id
/// derivation takes its salt at exactly this width.
pub const ARGON2_SALT_SIZE: usize = 32;

/// Upper end of the `FORMAT.md` §2.2 passphrase byte-length bound. The
/// bound is a fixed credential rule (`1` to this value, inclusive),
/// not a configurable KDF resource cap: readers and writers reject a
/// passphrase outside it before running Argon2id, and the value is not
/// tunable per operation. 4 KiB is well above a human-entered
/// passphrase; frontends may apply smaller input limits on top.
pub(crate) const MAX_PASSPHRASE_LEN_BYTES: usize = 4_096;

/// Enforces the `FORMAT.md` §2.2 passphrase byte-length bound over the
/// exact caller-supplied UTF-8 bytes: at least 1 byte and at most
/// [`MAX_PASSPHRASE_LEN_BYTES`]. Every path that would run Argon2id
/// calls this first, so a passphrase outside the bound is rejected with
/// no key-derivation work. Empty and over-length inputs surface as
/// [`CryptoError::InvalidInput`] with distinct messages.
pub(crate) fn check_passphrase_len(passphrase: &[u8]) -> Result<(), CryptoError> {
    if passphrase.is_empty() {
        return Err(CryptoError::InvalidInput(
            "Passphrase must not be empty".to_string(),
        ));
    }
    if passphrase.len() > MAX_PASSPHRASE_LEN_BYTES {
        return Err(CryptoError::InvalidInput(format!(
            "Passphrase is too long (limit {MAX_PASSPHRASE_LEN_BYTES} bytes)"
        )));
    }
    Ok(())
}

/// Local policy limit for Argon2id work accepted during decryption.
///
/// A `.fcr` file or `private.key` stores Argon2id parameters in the cleartext
/// header. When processing untrusted input, `KdfLimit` prevents a malicious
/// header from forcing arbitrarily expensive key derivation: any structurally
/// valid input whose memory cost, time cost, lane count, or combined work
/// exceeds the configured cap is rejected before Argon2id runs. If no limit is
/// configured on a decryptor, the library applies [`KdfLimit::default`]: memory
/// is capped at the writer's default (1 GiB) and combined work at the writer's
/// own budget (1 GiB × 4 passes), while time cost and lanes are capped at the
/// format maximum and so reject nothing on their own.
///
/// The memory and work caps bound different resources: memory bounds one
/// derivation's peak allocation, work bounds how long it runs. Neither implies
/// the other, which is why both are applied.
///
/// Construct with [`KdfLimit::new`] for KiB or [`KdfLimit::from_mib`] for MiB,
/// optionally adjust the other dimensions with [`KdfLimit::max_time_cost`],
/// [`KdfLimit::max_lanes`], or [`KdfLimit::max_work`], then pass the result to
/// [`crate::PassphraseDecryptor::kdf_limit`] or
/// [`crate::PrivateKeyDecryptor::kdf_limit`]. Raising memory does not raise the
/// work budget; a caller who wants 2 GiB at the writer's four passes sets both.
/// The struct is `#[non_exhaustive]` so future releases can add further limit
/// dimensions without a breaking change. A cap is a numeric bound, which is
/// what lets the struct stay `Copy`.
///
/// # Unattended services
///
/// A service deriving keys from untrusted artefacts must set an explicit limit
/// for its deployment and bound how many derivations run at once. One accepted
/// derivation still holds its full memory cost for its whole runtime, so the
/// exposure that matters is that cost multiplied by concurrency, which no
/// per-operation cap can bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct KdfLimit {
    /// Maximum accepted memory cost in KiB.
    pub(crate) max_mem_cost_kib: u32,
    /// Maximum accepted time cost (Argon2id iteration count). Defaults to the
    /// format maximum, so it rejects nothing the structural check accepts
    /// unless tightened with [`KdfLimit::max_time_cost`].
    pub(crate) max_time_cost: u32,
    /// Maximum accepted lane count (Argon2id parallelism). Defaults to the
    /// format maximum, so it rejects nothing the structural check accepts
    /// unless tightened with [`KdfLimit::max_lanes`].
    pub(crate) max_lanes: u32,
    /// Maximum accepted combined work: memory cost (KiB) multiplied by time
    /// cost (passes over that memory). Argon2's own cost model, so it bounds
    /// runtime without pinning either factor. Defaults to
    /// [`KdfLimit::WORK_DEFAULT`].
    pub(crate) max_work: u64,
}

impl KdfLimit {
    /// Structural maximum for Argon2id memory cost (2 GiB in KiB,
    /// `FORMAT.md` §2.2). A limit at this value accepts every
    /// structurally valid header, which is what §2.2 asks a reader that
    /// applies no policy of its own to do.
    pub const MEM_COST_KIB_STRUCTURAL_MAX: u32 = KdfParams::MAX_MEM_COST;
    /// Structural maximum for Argon2id time cost (`FORMAT.md` §2.2).
    pub const TIME_COST_STRUCTURAL_MAX: u32 = KdfParams::MAX_TIME_COST;
    /// Structural maximum for Argon2id lanes (`FORMAT.md` §2.2).
    pub const LANES_STRUCTURAL_MAX: u32 = KdfParams::MAX_LANES;
    /// Structural maximum for combined Argon2id work: the largest
    /// memory-times-time product `FORMAT.md` §2.2 can express. A limit at
    /// this value accepts every structurally valid header.
    pub const WORK_STRUCTURAL_MAX: u64 =
        KdfParams::MAX_MEM_COST as u64 * KdfParams::MAX_TIME_COST as u64;

    /// Default value used by [`KdfLimit::default`] for
    /// `max_mem_cost_kib` (1 GiB in KiB). Matches the writer's own
    /// default memory cost, so a file this library produced always
    /// decrypts under the default ceiling. The time-cost and lane
    /// defaults are the structural maxima above.
    pub const MEM_COST_KIB_DEFAULT: u32 = KdfParams::DEFAULT_MEM_COST;

    /// Default value used by [`KdfLimit::default`] for `max_work`: the
    /// writer's own default memory cost multiplied by its own default time
    /// cost, so no header may order more Argon2id work than this library
    /// produces at its defaults.
    pub const WORK_DEFAULT: u64 =
        Self::MEM_COST_KIB_DEFAULT as u64 * KdfParams::DEFAULT_TIME_COST as u64;

    /// Builds a limit from a KiB memory value, clamped at
    /// [`Self::MEM_COST_KIB_STRUCTURAL_MAX`], leaving every other dimension at
    /// its default: time cost and lanes at the format maximum, combined work at
    /// [`Self::WORK_DEFAULT`]. The work budget does not follow the memory value
    /// given here, so raising memory alone does not admit more total work —
    /// pair it with [`max_work`](Self::max_work) to raise both.
    pub fn new(max_mem_cost_kib: u32) -> Self {
        Self {
            max_mem_cost_kib: max_mem_cost_kib.min(Self::MEM_COST_KIB_STRUCTURAL_MAX),
            ..Self::default()
        }
    }

    /// Builds a limit from MiB, leaving every other dimension at its default
    /// exactly as [`Self::new`] does.
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

    /// Sets the accepted Argon2id time-cost cap, clamped at
    /// [`Self::TIME_COST_STRUCTURAL_MAX`]. Lower values make decryption
    /// refuse an otherwise-valid header whose iteration count exceeds the
    /// cap.
    pub fn max_time_cost(mut self, value: u32) -> Self {
        self.max_time_cost = value.min(Self::TIME_COST_STRUCTURAL_MAX);
        self
    }

    /// Sets the accepted Argon2id lane-count cap, clamped at
    /// [`Self::LANES_STRUCTURAL_MAX`]. Lower values make decryption refuse
    /// an otherwise-valid header whose lane count exceeds the cap.
    pub fn max_lanes(mut self, value: u32) -> Self {
        self.max_lanes = value.min(Self::LANES_STRUCTURAL_MAX);
        self
    }

    /// Sets the accepted combined-work cap — memory cost in KiB multiplied by
    /// time cost — clamped at [`Self::WORK_STRUCTURAL_MAX`]. Raise it to accept
    /// a header that is legitimately more expensive than the writer's own
    /// defaults; lower it to refuse work an ordinary file never requests.
    pub fn max_work(mut self, value: u64) -> Self {
        self.max_work = value.min(Self::WORK_STRUCTURAL_MAX);
        self
    }
}

impl Default for KdfLimit {
    fn default() -> Self {
        // Memory matches the writer's `KdfParams::DEFAULT_MEM_COST` (1 GiB),
        // below the 2 GiB structural maximum, so a file produced with the
        // library's own default settings decrypts under the default ceiling,
        // but an attacker-controlled header cannot force more than 1 GiB of
        // Argon2id memory unless the caller raises `KdfLimit`.
        //
        // Time cost and lanes default to the format maximum
        // (`MAX_TIME_COST` / `MAX_LANES`). The structural check already
        // enforces those bounds, so on their own they reject nothing new; they
        // exist only so a caller can tighten either dimension.
        //
        // Work is capped instead, at the writer's own memory times its own time
        // cost. Capping time cost per dimension would refuse parameter sets far
        // cheaper than the writer default — 64 MiB at twelve passes costs a
        // fraction of 1 GiB at four — while the product is the shape of the
        // resource being protected, so it accepts every cheaper profile and
        // refuses only headers ordering more work than the writer emits.
        Self {
            max_mem_cost_kib: Self::MEM_COST_KIB_DEFAULT,
            max_time_cost: Self::TIME_COST_STRUCTURAL_MAX,
            max_lanes: Self::LANES_STRUCTURAL_MAX,
            max_work: Self::WORK_DEFAULT,
        }
    }
}

/// KDF parameters stored in file headers and key files.
///
/// These values are serialized in `argon2id` recipient bodies and
/// `private.key` cleartext headers so decryption repeats the same work factor
/// used during encryption. See `FORMAT.md` §4.1 and §8.
///
/// The struct is deliberately exhaustive with public fields: the field set
/// mirrors the fixed 12-byte wire encoding ([`KDF_PARAMS_SIZE`]), so a new
/// parameter would be a wire-format change carried by a new recipient body,
/// not a field added here.
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

    /// Serializes these parameters to the big-endian wire encoding.
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

    /// Minimum Argon2id memory cost (KiB) the writer accepts, the local
    /// writer minimum `FORMAT.md` §2.2 permits. 19 MiB is the OWASP
    /// Argon2id minimum-memory recommendation; below it, passphrase and
    /// `private.key` protection is too weak, so the writer refuses to
    /// seal such an artefact. The floor is hard — there is no caller
    /// opt-in below it. Enforced by
    /// [`validate_for_write`](Self::validate_for_write) only, never on the
    /// read path, so a file written before the floor existed still
    /// decrypts. The structural floor (`ARGON2_MIN_MEM_COST_PER_LANE *
    /// lanes`) is far lower; this is the security-policy floor on top of it.
    pub(crate) const MIN_WRITE_MEM_COST: u32 = 19 * 1024; // 19 MiB (OWASP Argon2id minimum)

    /// Field-level structural validation against the format's absolute bounds
    /// (`MAX_LANES`, `MAX_TIME_COST`, `MAX_MEM_COST`, plus the Argon2
    /// `mem_cost >= ARGON2_MIN_MEM_COST_PER_LANE * lanes` floor).
    /// Single source of truth for the rule set, called by
    /// [`from_bytes_structural`](Self::from_bytes_structural) (reader),
    /// [`validate_for_write`](Self::validate_for_write) (writer preflight),
    /// and `key::private::seal_private_key` (writer-side structural
    /// re-check). Does **not** apply any caller resource policy.
    pub(crate) fn validate_structural(&self) -> Result<(), CryptoError> {
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

    /// Applies the caller-supplied resource caps (memory, time cost, lanes)
    /// on top of structurally valid params. `None` means "no explicit caller
    /// limit", but the library still applies [`KdfLimit::default`] so callers
    /// cannot be silently exposed to attacker-controlled 2 GiB allocations
    /// just because they did not set `.kdf_limit(...)` on their config.
    /// Memory is checked first, then time cost, then lanes, then combined
    /// work. Work is checked last so a header that also breaks a single
    /// dimension keeps reporting that dimension, which names the one cap a
    /// caller would have to change. `pub(crate)`
    /// deliberately: pairs with [`from_bytes_structural`] and is not part of
    /// the stable public API. Both the reader ([`from_bytes`](Self::from_bytes))
    /// and the writer ([`validate_for_write`](Self::validate_for_write)) run
    /// this same gate, so under one `KdfLimit` they accept the same params —
    /// anything the writer emits is decryptable.
    pub(crate) fn enforce_limit(self, limit: Option<&KdfLimit>) -> Result<Self, CryptoError> {
        let limit = limit.copied().unwrap_or_default();
        if self.mem_cost > limit.max_mem_cost_kib {
            return Err(CryptoError::KdfResourceCapExceeded {
                mem_cost_kib: self.mem_cost,
                local_cap_kib: limit.max_mem_cost_kib,
            });
        }
        if self.time_cost > limit.max_time_cost {
            return Err(CryptoError::KdfTimeCostCapExceeded {
                time_cost: self.time_cost,
                local_cap: limit.max_time_cost,
            });
        }
        if self.lanes > limit.max_lanes {
            return Err(CryptoError::KdfLanesCapExceeded {
                lanes: self.lanes,
                local_cap: limit.max_lanes,
            });
        }
        // Widened to `u64`: the product of two `u32` fields cannot overflow it,
        // so no header can wrap this into a small value.
        let work = self.mem_cost as u64 * self.time_cost as u64;
        if work > limit.max_work {
            return Err(CryptoError::KdfWorkCapExceeded {
                work,
                local_cap: limit.max_work,
            });
        }
        Ok(self)
    }

    /// Parses KDF parameter bytes and enforces the caller's resource caps.
    ///
    /// `limit = None` still applies the library default ceiling so untrusted
    /// headers cannot force the structural 2 GiB maximum unless the caller opts
    /// in with [`KdfLimit`]. See `FORMAT.md` §4.1 and §8 for the serialized
    /// locations.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKdfParams`] when the fields violate the
    /// structural bounds. Returns [`CryptoError::KdfResourceCapExceeded`],
    /// [`CryptoError::KdfTimeCostCapExceeded`], or
    /// [`CryptoError::KdfLanesCapExceeded`] when the corresponding field is
    /// structurally valid but exceeds `limit` or the default cap.
    pub fn from_bytes(
        bytes: &[u8; KDF_PARAMS_SIZE],
        limit: Option<&KdfLimit>,
    ) -> Result<Self, CryptoError> {
        Self::from_bytes_structural(bytes)?.enforce_limit(limit)
    }

    /// Validates caller-supplied writer parameters against the same
    /// structural bounds the reader enforces, applies the production
    /// memory floor, then applies the caller's resource policy cap. This
    /// is the writer-side counterpart to [`from_bytes`](Self::from_bytes):
    /// public builders accept a raw [`KdfParams`] value, so they must run
    /// the same structural rules before serialising it into an `argon2id`
    /// recipient body or `private.key` header. Otherwise a caller could
    /// produce an artefact whose KDF fields Argon2 itself accepts but the
    /// FerroCrypt reader rejects before attempting unlock.
    ///
    /// The checks run in order — structural bounds, then the floor, then
    /// the cap — so a structurally invalid value (e.g. `time_cost` above
    /// the maximum) is reported as [`CryptoError::InvalidKdfParams`] even
    /// when its memory cost is also below the floor. The floor is hard:
    /// there is no caller opt-in below it.
    pub(crate) fn validate_for_write(self, limit: Option<&KdfLimit>) -> Result<Self, CryptoError> {
        self.validate_structural()?;
        self.enforce_write_floor()?;
        self.enforce_limit(limit)
    }

    /// Rejects writer parameters whose memory cost is below
    /// [`MIN_WRITE_MEM_COST`](Self::MIN_WRITE_MEM_COST). Applied by
    /// [`validate_for_write`](Self::validate_for_write) on every write,
    /// and never on the read path, so a file written before the floor
    /// existed still decrypts.
    fn enforce_write_floor(&self) -> Result<(), CryptoError> {
        if self.mem_cost < Self::MIN_WRITE_MEM_COST {
            return Err(CryptoError::KdfBelowWriteFloor {
                mem_cost_kib: self.mem_cost,
                floor_kib: Self::MIN_WRITE_MEM_COST,
            });
        }
        Ok(())
    }

    /// Derives a fixed-size Argon2id output for the supplied passphrase and salt.
    ///
    /// The returned buffer zeroizes on drop, and the Argon2id working
    /// memory (`mem_cost` KiB of blocks) is allocated by this function
    /// and zeroized when the derivation completes. This method is
    /// crate-internal. Production code reaches it through
    /// [`derive_passphrase_wrap_key`](crate::crypto::keys::derive_passphrase_wrap_key).
    /// The public API does not expose raw Argon2id output because direct use
    /// would apply structural validation without the [`KdfLimit`] resource
    /// policy enforced by the supported workflows.
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
    /// or `lanes` are outside the structural bounds, and
    /// [`CryptoError::InvalidInput`] if the passphrase is outside the
    /// `FORMAT.md` §2.2 byte-length bound. Both are checked before Argon2id
    /// runs, so any Argon2 failure on the validated input surfaces as
    /// [`CryptoError::InternalCryptoFailure`].
    pub(crate) fn hash_passphrase(
        &self,
        passphrase: &[u8],
        salt: &[u8; ARGON2_SALT_SIZE],
    ) -> Result<Zeroizing<[u8; ENCRYPTION_KEY_SIZE]>, CryptoError> {
        self.validate_structural()?;
        check_passphrase_len(passphrase)?;
        let params = argon2::Params::new(
            self.mem_cost,
            self.time_cost,
            self.lanes,
            Some(ENCRYPTION_KEY_SIZE),
        )
        .map_err(|_| crate::error::internal_crypto_failure!("Argon2id parameter rejected"))?;
        // Own the Argon2id working memory instead of letting
        // `hash_password_into` allocate it: that path frees its block
        // buffer without scrubbing, and the final blocks hold material
        // from which the derived key can be recomputed. `Zeroizing`
        // wipes all `mem_cost` KiB on drop, including error paths.
        //
        // Reserved fallibly rather than with `vec![_; n]`, whose
        // allocation failure aborts the process. At the default 1 GiB
        // memory cost a host with less to spare must get an error the
        // caller can report.
        let block_count = params.block_count();
        let mut blocks = Vec::new();
        blocks.try_reserve_exact(block_count).map_err(|_| {
            crate::error::internal_crypto_failure!("Argon2id memory allocation failed")
        })?;
        blocks.resize(block_count, argon2::Block::default());
        let mut blocks = Zeroizing::new(blocks);
        let hasher =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut output = Zeroizing::new([0u8; ENCRYPTION_KEY_SIZE]);
        hasher
            .hash_password_into_with_memory(
                passphrase,
                salt,
                output.as_mut(),
                blocks.as_mut_slice(),
            )
            .map_err(|_| crate::error::internal_crypto_failure!("Argon2id derivation failed"))?;
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
    /// In-crate test helper: low-cost Argon2id parameters (19 MiB memory,
    /// time_cost 1, parallelism 4) for the lib's own `mod tests`. The
    /// memory cost sits at the writer's production floor, keeping test
    /// writes on the ordinary floored path while avoiding the 1 GiB
    /// production default. Reads the values from `ferrocrypt-test-support`
    /// (a `publish = false` workspace dev-dep) so the workspace has a
    /// single source of truth for the test-fast-KDF triple. The dev-dep
    /// cycle through `ferrocrypt` is fine here because the constants are
    /// plain `u32` — only typed `KdfParams` values from test-support hit
    /// the "multiple different versions of crate ferrocrypt" trap, which
    /// is why this helper constructs a fresh `Self` rather than calling
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

    /// A limit built from the published structural maxima must accept
    /// every structurally valid header, as `FORMAT.md` §2.2 requires of
    /// a reader that applies no policy of its own. Pins the constants
    /// against the bounds the structural check actually enforces.
    #[test]
    fn published_structural_maxima_accept_every_valid_header() {
        let bytes = KdfParams {
            mem_cost: KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX,
            time_cost: KdfLimit::TIME_COST_STRUCTURAL_MAX,
            lanes: KdfLimit::LANES_STRUCTURAL_MAX,
        }
        .to_bytes();
        let widest = KdfLimit::new(KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX)
            .max_time_cost(KdfLimit::TIME_COST_STRUCTURAL_MAX)
            .max_lanes(KdfLimit::LANES_STRUCTURAL_MAX)
            .max_work(KdfLimit::WORK_STRUCTURAL_MAX);
        assert!(KdfParams::from_bytes(&bytes, Some(&widest)).is_ok());

        let defaults = KdfLimit::default();
        assert_eq!(defaults.max_mem_cost_kib, KdfLimit::MEM_COST_KIB_DEFAULT);
        assert_eq!(defaults.max_time_cost, KdfLimit::TIME_COST_STRUCTURAL_MAX);
        assert_eq!(defaults.max_lanes, KdfLimit::LANES_STRUCTURAL_MAX);
        assert_eq!(defaults.max_work, KdfLimit::WORK_DEFAULT);
    }

    /// A cap above what `FORMAT.md` §2.2 can represent is reduced to the
    /// structural maximum in the builder, so two limits that behave the
    /// same compare equal. The fields are private, and `==` is the only
    /// way a caller can inspect a value.
    #[test]
    fn builders_clamp_at_the_published_structural_maxima() {
        let over = KdfLimit::new(u32::MAX)
            .max_time_cost(u32::MAX)
            .max_lanes(u32::MAX)
            .max_work(u64::MAX);
        let widest = KdfLimit::new(KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX)
            .max_time_cost(KdfLimit::TIME_COST_STRUCTURAL_MAX)
            .max_lanes(KdfLimit::LANES_STRUCTURAL_MAX)
            .max_work(KdfLimit::WORK_STRUCTURAL_MAX);
        assert_eq!(over, widest);

        // `from_mib` clamps through `new`: one MiB above the maximum. The work
        // budget is not derived from the memory value, so it stays at its
        // default and the comparison is against a `new`-built limit.
        let over_max_mib = KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX / 1024 + 1;
        assert_eq!(
            KdfLimit::from_mib(over_max_mib).unwrap(),
            KdfLimit::new(KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX)
        );

        // Clamping only reduces values above the maximum: a tightened cap
        // is still stored as given.
        assert_ne!(KdfLimit::default().max_time_cost(3), KdfLimit::default());
        assert_ne!(KdfLimit::default().max_lanes(2), KdfLimit::default());
        assert_ne!(KdfLimit::default().max_work(1), KdfLimit::default());
    }

    #[test]
    fn test_kdf_params_accepts_max_bounds() {
        let bytes = KdfParams {
            mem_cost: KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX,
            time_cost: KdfLimit::TIME_COST_STRUCTURAL_MAX,
            lanes: KdfLimit::LANES_STRUCTURAL_MAX,
        }
        .to_bytes();
        // Structurally valid at every hard ceiling. Callers who want to accept
        // such a header opt into the matching `KdfLimit` explicitly, on both
        // the memory and the work axis; the defaults are enforced elsewhere.
        let limit = KdfLimit::new(KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX)
            .max_work(KdfLimit::WORK_STRUCTURAL_MAX);
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
        let limit = KdfLimit::new(KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX);
        assert!(KdfParams::from_bytes(&bytes, Some(&limit)).is_ok());
    }

    #[test]
    fn test_kdf_limit_rejects_excessive_time_cost() {
        let bytes = KdfParams {
            mem_cost: KdfParams::DEFAULT_MEM_COST,
            time_cost: 8,
            lanes: KdfParams::DEFAULT_LANES,
        }
        .to_bytes();
        let limit = KdfLimit::new(KdfParams::DEFAULT_MEM_COST).max_time_cost(6);
        match KdfParams::from_bytes(&bytes, Some(&limit)) {
            Err(CryptoError::KdfTimeCostCapExceeded {
                time_cost: 8,
                local_cap: 6,
            }) => {}
            other => panic!("expected KdfTimeCostCapExceeded, got: {other:?}"),
        }
    }

    #[test]
    fn test_kdf_limit_rejects_excessive_lanes() {
        let bytes = KdfParams {
            mem_cost: KdfParams::DEFAULT_MEM_COST,
            time_cost: KdfParams::DEFAULT_TIME_COST,
            lanes: 4,
        }
        .to_bytes();
        let limit = KdfLimit::new(KdfParams::DEFAULT_MEM_COST).max_lanes(2);
        match KdfParams::from_bytes(&bytes, Some(&limit)) {
            Err(CryptoError::KdfLanesCapExceeded {
                lanes: 4,
                local_cap: 2,
            }) => {}
            other => panic!("expected KdfLanesCapExceeded, got: {other:?}"),
        }
    }

    /// The time-cost and lane caps default to the format maximum and so reject
    /// nothing on their own: a header at both maxima is accepted whenever its
    /// combined work fits the budget. Uses the lowest memory cost the writer
    /// will seal, which at twelve passes stays far below the default budget.
    #[test]
    fn test_kdf_limit_default_accepts_max_time_cost_and_lanes() {
        let bytes = KdfParams {
            mem_cost: KdfParams::MIN_WRITE_MEM_COST,
            time_cost: KdfParams::MAX_TIME_COST,
            lanes: KdfParams::MAX_LANES,
        }
        .to_bytes();
        assert!(KdfParams::from_bytes(&bytes, Some(&KdfLimit::default())).is_ok());
        assert!(KdfParams::from_bytes(&bytes, None).is_ok());
        let new_limit = KdfLimit::new(KdfParams::DEFAULT_MEM_COST);
        assert!(KdfParams::from_bytes(&bytes, Some(&new_limit)).is_ok());
    }

    /// The combined-work cap is what refuses the format-maximum time cost at
    /// the writer's own memory cost, the case no single-dimension cap catches:
    /// memory is exactly at its ceiling and lanes are irrelevant to the cost.
    #[test]
    fn default_work_cap_rejects_max_time_cost_at_the_default_memory() {
        let over = KdfParams {
            mem_cost: KdfParams::DEFAULT_MEM_COST,
            time_cost: KdfParams::MAX_TIME_COST,
            lanes: KdfParams::DEFAULT_LANES,
        };
        match KdfParams::from_bytes(&over.to_bytes(), Some(&KdfLimit::default())) {
            Err(CryptoError::KdfWorkCapExceeded { work, local_cap }) => {
                // Reported work is the product of exactly `mem_cost` and
                // `time_cost`; a cap reading any other field would differ here.
                assert_eq!(
                    work,
                    KdfParams::DEFAULT_MEM_COST as u64 * KdfParams::MAX_TIME_COST as u64
                );
                assert_eq!(local_cap, KdfLimit::WORK_DEFAULT);
            }
            other => panic!("expected KdfWorkCapExceeded, got: {other:?}"),
        }
        // The writer refuses the same parameters, so the rejected header is one
        // this library will not produce under the same limit either.
        assert!(over.validate_for_write(Some(&KdfLimit::default())).is_err());
        // Raising the budget is the documented way back in.
        let raised = KdfLimit::default().max_work(KdfLimit::WORK_STRUCTURAL_MAX);
        assert!(KdfParams::from_bytes(&over.to_bytes(), Some(&raised)).is_ok());
    }

    /// The budget boundary is exact, and it sits precisely at the writer's own
    /// default parameters so an unconfigured round trip cannot regress.
    #[test]
    fn default_work_cap_boundary_is_the_writer_default() {
        let limit = KdfLimit::default();
        // The writer's default parameters and the reader's default budget are
        // separate items; this pins them to the same value, which is what makes
        // the unconfigured round trip work at all.
        let at = KdfParams::default();
        assert_eq!(
            at.mem_cost as u64 * at.time_cost as u64,
            KdfLimit::WORK_DEFAULT
        );
        assert!(KdfParams::from_bytes(&at.to_bytes(), Some(&limit)).is_ok());

        // One pass more is one budget unit too many.
        let over = KdfParams {
            time_cost: at.time_cost + 1,
            ..at
        };
        assert!(matches!(
            KdfParams::from_bytes(&over.to_bytes(), Some(&limit)),
            Err(CryptoError::KdfWorkCapExceeded { .. })
        ));
    }

    /// Cheap profiles that trade memory for passes stay accepted: the cap is on
    /// the product, not on either factor, so a small-memory header at the
    /// format-maximum time cost costs less than the writer default and passes.
    #[test]
    fn default_work_cap_accepts_low_memory_high_pass_profiles() {
        for mem_cost in [KdfParams::MIN_WRITE_MEM_COST, 64 * 1024, 256 * 1024] {
            let cheap = KdfParams {
                mem_cost,
                time_cost: KdfParams::MAX_TIME_COST,
                lanes: KdfParams::DEFAULT_LANES,
            };
            assert!(
                cheap.mem_cost as u64 * cheap.time_cost as u64 <= KdfLimit::WORK_DEFAULT,
                "{mem_cost} KiB at max time cost must stay within the default budget"
            );
            assert!(
                KdfParams::from_bytes(&cheap.to_bytes(), Some(&KdfLimit::default())).is_ok(),
                "{mem_cost} KiB at max time cost must decrypt under the default limit"
            );
        }
    }

    /// The work budget is anchored to a fixed constant, not derived from the
    /// memory cap. A caller who tightens memory must keep the cheap
    /// high-pass profiles the product cap exists to protect, and a caller who
    /// raises memory must ask for the extra work separately.
    #[test]
    fn work_budget_does_not_follow_the_memory_cap() {
        let tightened = KdfLimit::from_mib(64).expect("64 MiB is a valid limit");
        assert_eq!(tightened.max_work, KdfLimit::WORK_DEFAULT);
        let cheap = KdfParams {
            mem_cost: 64 * 1024,
            time_cost: KdfParams::MAX_TIME_COST,
            lanes: KdfParams::DEFAULT_LANES,
        };
        assert!(KdfParams::from_bytes(&cheap.to_bytes(), Some(&tightened)).is_ok());

        // Raising memory alone leaves the budget where it was, so 2 GiB at the
        // writer's own time cost still needs an explicit `max_work`.
        let raised = KdfLimit::from_mib(2048).expect("2 GiB is a valid limit");
        assert_eq!(raised.max_work, KdfLimit::WORK_DEFAULT);
        let wide = KdfParams {
            mem_cost: KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX,
            time_cost: KdfParams::DEFAULT_TIME_COST,
            lanes: KdfParams::DEFAULT_LANES,
        };
        assert!(matches!(
            KdfParams::from_bytes(&wide.to_bytes(), Some(&raised)),
            Err(CryptoError::KdfWorkCapExceeded { .. })
        ));
        let both = raised.max_work(
            KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX as u64 * KdfParams::DEFAULT_TIME_COST as u64,
        );
        assert!(KdfParams::from_bytes(&wide.to_bytes(), Some(&both)).is_ok());
    }

    /// The work cap bounds runtime, the memory cap bounds allocation, and
    /// neither substitutes for the other. A 2 GiB single-pass header scores
    /// only half the default budget yet doubles the peak allocation, so the
    /// memory cap is the one that must refuse it.
    #[test]
    fn memory_cap_still_refuses_what_the_work_cap_allows() {
        let wide_but_cheap = KdfParams {
            mem_cost: KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX,
            time_cost: 1,
            lanes: KdfParams::DEFAULT_LANES,
        };
        assert!(
            wide_but_cheap.mem_cost as u64 * wide_but_cheap.time_cost as u64
                <= KdfLimit::WORK_DEFAULT,
            "the work cap alone must not be what refuses this header"
        );
        match KdfParams::from_bytes(&wide_but_cheap.to_bytes(), Some(&KdfLimit::default())) {
            Err(CryptoError::KdfResourceCapExceeded { .. }) => {}
            other => panic!("expected KdfResourceCapExceeded, got: {other:?}"),
        }
    }

    /// Writer/reader symmetry across all four caps. Both the writer
    /// (`validate_for_write`) and the reader (`from_bytes`) run the same
    /// `enforce_limit`, so under one `KdfLimit` they agree: whatever the
    /// writer emits the reader accepts, and whatever the writer refuses the
    /// reader refuses too. A written file is therefore always decryptable
    /// under the same limit.
    #[test]
    fn test_kdf_limit_writer_reader_symmetry() {
        // Format-max time cost and lanes under the default limit, at a memory
        // cost the default work budget admits: accepted by both sides.
        let at_max = KdfParams {
            mem_cost: KdfParams::MIN_WRITE_MEM_COST,
            time_cost: KdfParams::MAX_TIME_COST,
            lanes: KdfParams::MAX_LANES,
        };
        let limit = KdfLimit::default();
        at_max
            .validate_for_write(Some(&limit))
            .expect("writer accepts these params under the default limit");
        KdfParams::from_bytes(&at_max.to_bytes(), Some(&limit))
            .expect("reader accepts the same params under the same limit");

        // The work dimension behaves the same way in both directions.
        let over_work = KdfParams {
            mem_cost: KdfParams::DEFAULT_MEM_COST,
            time_cost: KdfParams::MAX_TIME_COST,
            lanes: KdfParams::DEFAULT_LANES,
        };
        assert!(
            over_work.validate_for_write(Some(&limit)).is_err(),
            "writer must refuse params above the work budget"
        );
        assert!(
            KdfParams::from_bytes(&over_work.to_bytes(), Some(&limit)).is_err(),
            "reader must refuse the same params under the same limit"
        );

        // A tightened time-cost limit: the writer refuses (so no unreadable
        // file is produced) and the reader refuses the same bytes.
        let tight = KdfLimit::default().max_time_cost(6);
        let over = KdfParams {
            mem_cost: KdfParams::DEFAULT_MEM_COST,
            time_cost: 8,
            lanes: KdfParams::DEFAULT_LANES,
        };
        assert!(
            over.validate_for_write(Some(&tight)).is_err(),
            "writer must refuse params above a tightened cap"
        );
        assert!(
            KdfParams::from_bytes(&over.to_bytes(), Some(&tight)).is_err(),
            "reader must refuse the same params under the same limit"
        );
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

    /// Known-answer test for FerroCrypt's *wiring into* Argon2id, not
    /// for the primitive: the positional argument order in
    /// `argon2::Params::new`, `Version::V0x13`, `Algorithm::Argon2id`,
    /// the 32-byte output length, and passing the stored salt through
    /// unmodified. The expected bytes come from OpenSSL's `ARGON2ID`
    /// KDF, a separate implementation from the `argon2` crate;
    /// `testvectors/kat/README.md` records the producing command. The
    /// three parameters are deliberately distinct, so swapping any pair
    /// either changes the digest or makes the parameter set invalid.
    #[test]
    fn hash_passphrase_matches_independent_oracle() {
        const EXPECTED: [u8; ENCRYPTION_KEY_SIZE] = [
            0xA3, 0xBA, 0x07, 0xA9, 0xCE, 0xEB, 0xFA, 0xD5, 0xF1, 0xDF, 0xC2, 0x4A, 0x84, 0x18,
            0x57, 0x44, 0x70, 0xC7, 0x0C, 0xB8, 0xEB, 0x61, 0x3D, 0x10, 0x23, 0xD6, 0x29, 0xB0,
            0x91, 0x52, 0x9F, 0xA7,
        ];
        let params = KdfParams {
            mem_cost: 64,
            time_cost: 3,
            lanes: 2,
        };
        let digest = params
            .hash_passphrase(b"ferrocrypt-kat", &[0x5A; ARGON2_SALT_SIZE])
            .expect("the known-answer parameters must be accepted");
        assert_eq!(digest.as_ref(), &EXPECTED);
    }

    /// `hash_passphrase` performs its own structural validation so a direct
    /// crate-internal caller cannot run Argon2id with invalid parameters. A
    /// `time_cost` above `MAX_TIME_COST` must return `InvalidKdfParams` before
    /// Argon2id starts, even though `argon2::Params::new` would accept it.
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

    /// `FORMAT.md` §2.2 passphrase byte-length bound: `check_passphrase_len`
    /// enforces both ends (1 to `MAX_PASSPHRASE_LEN_BYTES`). Empty and
    /// over-length inputs reject with distinct messages; the boundary
    /// values 1 byte and exactly the cap are accepted.
    #[test]
    fn check_passphrase_len_enforces_full_bound() {
        match check_passphrase_len(b"") {
            Err(CryptoError::InvalidInput(msg)) => assert!(msg.contains("must not be empty")),
            other => panic!("expected empty rejection, got {other:?}"),
        }
        let over = vec![b'a'; MAX_PASSPHRASE_LEN_BYTES + 1];
        match check_passphrase_len(&over) {
            Err(CryptoError::InvalidInput(msg)) => assert!(msg.contains("too long")),
            other => panic!("expected over-length rejection, got {other:?}"),
        }
        check_passphrase_len(b"a").expect("one byte is within the bound");
        check_passphrase_len(&vec![b'a'; MAX_PASSPHRASE_LEN_BYTES])
            .expect("exactly the cap is within the bound");
    }

    /// B6-01 regression: a writer whose resource policy is applied
    /// upstream (e.g. `KeyPairGenerator::write`) must re-check KDF
    /// params with `validate_structural`, not `validate_for_write(None)`.
    /// A `mem_cost` between the 1 GiB default and the 2 GiB structural
    /// max is structurally valid and above the write floor;
    /// `validate_for_write(None)` rejects it by re-imposing the
    /// default ceiling.
    #[test]
    fn above_default_mem_cost_passes_structural_but_validate_for_write_none_rejects() {
        let params = KdfParams {
            mem_cost: KdfParams::DEFAULT_MEM_COST + 1,
            time_cost: 4,
            lanes: 4,
        };
        params
            .validate_structural()
            .expect("1-2 GiB band is structurally valid");
        match params.validate_for_write(None) {
            Err(CryptoError::KdfResourceCapExceeded { .. }) => {}
            other => panic!("expected KdfResourceCapExceeded, got {other:?}"),
        }
    }

    /// The floored `kdf_params` path rejects a structurally valid but
    /// below-floor `mem_cost` with the typed `KdfBelowWriteFloor`,
    /// carrying the offending value and the floor. Protects against a
    /// downstream caller accidentally sealing weak Argon2id parameters
    /// through `Encryptor::kdf_params`.
    #[test]
    fn validate_for_write_rejects_below_floor() {
        let weak = KdfParams {
            mem_cost: KdfParams::MIN_WRITE_MEM_COST - 1,
            time_cost: 4,
            lanes: 4,
        };
        weak.validate_structural()
            .expect("below-floor value is still structurally valid");
        match weak.validate_for_write(None) {
            Err(CryptoError::KdfBelowWriteFloor {
                mem_cost_kib,
                floor_kib,
            }) => {
                assert_eq!(mem_cost_kib, KdfParams::MIN_WRITE_MEM_COST - 1);
                assert_eq!(floor_kib, KdfParams::MIN_WRITE_MEM_COST);
            }
            other => panic!("expected KdfBelowWriteFloor, got {other:?}"),
        }
    }

    /// Ordering guarantee: a structurally invalid value that is also
    /// below the floor is reported as `InvalidKdfParams`, not
    /// `KdfBelowWriteFloor` — structural validation runs first, so the
    /// rejection-path tests in `api_tests` keep their expected variants.
    #[test]
    fn validate_for_write_reports_structural_before_floor() {
        let weak_and_invalid = KdfParams {
            mem_cost: 8192,                          // structurally valid, below floor
            time_cost: KdfParams::MAX_TIME_COST + 1, // structurally invalid
            lanes: 4,
        };
        match weak_and_invalid.validate_for_write(None) {
            Err(CryptoError::InvalidKdfParams(InvalidKdfParams::TimeCost(_))) => {}
            other => panic!("expected InvalidKdfParams::TimeCost, got {other:?}"),
        }
    }
}
