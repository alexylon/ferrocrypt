//! Resource caps for FCA archive encoding and extraction.
//!
//! `ArchiveLimits` bounds entry count, total plaintext bytes, path depth,
//! per-path UTF-8 byte length, and serialized manifest byte length.
//! See `notes/archive_format/ARCHIVE_FORMAT.md` §11.
//!
//! Both writer and reader apply these caps before allocation or filesystem
//! work — readers structurally during header / manifest parse, writers
//! progressively during the metadata pass. The same struct is reused on
//! both sides so a tree the default-config decrypt would refuse cannot
//! be encrypted in the first place.

use crate::CryptoError;

/// Resource caps for FCA archive encoding and extraction.
///
/// See `FORMAT.md` §9.12. Defaults: 250,000 entries, 64 GiB cumulative
/// logical regular-file bytes, 64 path components per entry, 4096
/// UTF-8 bytes per path, 64 MiB serialized manifest, 64 KiB per
/// archive- and entry-level TLV region, 64 MiB total per-entry TLV
/// bytes, 16 MiB per individual TLV value.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ArchiveLimits {
    /// Maximum number of manifest entries (regular files plus directories).
    pub max_entry_count: u32,
    /// Maximum cumulative declared logical bytes across regular-file
    /// entries. Directory entries do not contribute.
    pub max_total_plaintext_bytes: u64,
    /// Maximum path component count for any single archive entry.
    pub max_path_depth: u32,
    /// Maximum UTF-8 byte length of any single archive path.
    /// MUST be `<= u16::MAX` because the on-disk `path_len` field is `u16`.
    pub max_path_bytes: u32,
    /// Maximum byte length of the serialized manifest, including the
    /// per-entry TLV regions that live inside it.
    pub max_manifest_bytes: u32,
    /// Maximum byte length of the FCA archive-level TLV region
    /// (`archive_ext`). The FCA fixed header's `archive_ext_len` field
    /// is rejected before allocation if it exceeds this cap.
    pub max_archive_ext_bytes: u32,
    /// Maximum byte length of any single per-entry TLV region
    /// (`entry_ext`).
    pub max_entry_ext_bytes: u32,
    /// Maximum cumulative byte length of all per-entry TLV regions in
    /// one manifest. Bounds memory used by extension metadata across
    /// the archive even when individual entries fit under
    /// `max_entry_ext_bytes`.
    pub max_total_entry_ext_bytes: u64,
    /// Maximum byte length of any single TLV value inside an FCA
    /// archive- or entry-level TLV region. Defense-in-depth: the
    /// containing region cap will fire first for v1, but a future
    /// region with a larger cap still bounds individual values.
    pub max_tlv_value_bytes: u32,
}

impl ArchiveLimits {
    /// Replaces [`ArchiveLimits::max_entry_count`].
    pub fn with_max_entry_count(mut self, n: u32) -> Self {
        self.max_entry_count = n;
        self
    }

    /// Replaces [`ArchiveLimits::max_total_plaintext_bytes`].
    pub fn with_max_total_plaintext_bytes(mut self, n: u64) -> Self {
        self.max_total_plaintext_bytes = n;
        self
    }

    /// Replaces [`ArchiveLimits::max_path_depth`].
    pub fn with_max_path_depth(mut self, n: u32) -> Self {
        self.max_path_depth = n;
        self
    }

    /// Replaces [`ArchiveLimits::max_path_bytes`].
    pub fn with_max_path_bytes(mut self, n: u32) -> Self {
        self.max_path_bytes = n;
        self
    }

    /// Replaces [`ArchiveLimits::max_manifest_bytes`].
    pub fn with_max_manifest_bytes(mut self, n: u32) -> Self {
        self.max_manifest_bytes = n;
        self
    }

    /// Replaces [`ArchiveLimits::max_archive_ext_bytes`].
    pub fn with_max_archive_ext_bytes(mut self, n: u32) -> Self {
        self.max_archive_ext_bytes = n;
        self
    }

    /// Replaces [`ArchiveLimits::max_entry_ext_bytes`].
    pub fn with_max_entry_ext_bytes(mut self, n: u32) -> Self {
        self.max_entry_ext_bytes = n;
        self
    }

    /// Replaces [`ArchiveLimits::max_total_entry_ext_bytes`].
    pub fn with_max_total_entry_ext_bytes(mut self, n: u64) -> Self {
        self.max_total_entry_ext_bytes = n;
        self
    }

    /// Replaces [`ArchiveLimits::max_tlv_value_bytes`].
    pub fn with_max_tlv_value_bytes(mut self, n: u32) -> Self {
        self.max_tlv_value_bytes = n;
        self
    }

    /// Enforces the structural invariant that `max_path_bytes` fits in
    /// the on-disk `u16` path-length field. Other fields are not
    /// otherwise constrained — callers may pick any `u32`/`u64` value.
    pub(crate) fn validate(self) -> Result<Self, CryptoError> {
        if self.max_path_bytes > u16::MAX as u32 {
            return Err(CryptoError::InvalidInput(
                "Archive path byte cap exceeds FCA u16 path length".to_string(),
            ));
        }
        Ok(self)
    }
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_entry_count: 250_000,
            max_total_plaintext_bytes: 64 * 1024 * 1024 * 1024,
            max_path_depth: 64,
            max_path_bytes: 4096,
            max_manifest_bytes: 64 * 1024 * 1024,
            max_archive_ext_bytes: 64 * 1024,
            max_entry_ext_bytes: 64 * 1024,
            max_total_entry_ext_bytes: 64 * 1024 * 1024,
            max_tlv_value_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Per-entry resource-cap check shared by encrypt-side preflight and
/// decrypt-side extraction. Caller has already incremented `entry_count`
/// for the current entry. Path-depth is computed by counting `/`-split
/// components on the FCA UTF-8 path.
pub(crate) fn enforce_per_entry_caps(
    entry_count: u32,
    path_utf8: &str,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    if entry_count > limits.max_entry_count {
        return Err(entry_count_cap_error(entry_count, limits.max_entry_count));
    }
    let depth = u32::try_from(path_utf8.split('/').count()).unwrap_or(u32::MAX);
    if depth > limits.max_path_depth {
        return Err(path_depth_cap_error(
            depth,
            limits.max_path_depth,
            path_utf8,
        ));
    }
    Ok(())
}

/// Per-file-entry total-bytes cap check shared by encrypt-side preflight
/// and decrypt-side extraction. Updates `total_bytes` in place using
/// checked arithmetic so an overflow is rejected even when callers raise
/// `max_total_plaintext_bytes` to `u64::MAX`.
pub(crate) fn enforce_total_bytes_cap(
    entry_size: u64,
    total_bytes: &mut u64,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    let next = total_bytes.checked_add(entry_size).ok_or_else(|| {
        CryptoError::InvalidInput("Archive total file bytes overflow".to_string())
    })?;
    if next > limits.max_total_plaintext_bytes {
        return Err(total_bytes_cap_error(
            next,
            limits.max_total_plaintext_bytes,
        ));
    }
    *total_bytes = next;
    Ok(())
}

/// Single source of truth for the "entry mode contains unsupported
/// bits" diagnostic — emitted on both writer and reader sides when an
/// `ArchiveEntry::mode` carries bits outside [`PERMISSION_BITS_MASK`].
pub(super) const ARCHIVE_ENTRY_MODE_UNSUPPORTED: &str =
    "Archive entry mode contains unsupported bits";

pub(super) fn entry_count_cap_error(entry_count: u32, cap: u32) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "Archive entry-count cap exceeded ({entry_count} entries, cap {cap})"
    ))
}

pub(super) fn total_bytes_cap_error(total: u64, cap: u64) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "Archive total-bytes cap exceeded ({total} bytes, cap {cap})"
    ))
}

pub(super) fn manifest_len_cap_error(len: u64, cap: u32) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "Archive manifest length cap exceeded ({len} bytes, cap {cap})"
    ))
}

pub(super) fn path_bytes_cap_error(declared_len: u32, cap: u32, path: Option<&str>) -> CryptoError {
    let head = format!("Archive path byte-length cap exceeded ({declared_len} bytes, cap {cap})");
    CryptoError::InvalidInput(match path {
        Some(p) => format!("{head}: {p}"),
        None => head,
    })
}

pub(super) fn path_depth_cap_error(depth: u32, cap: u32, path_utf8: &str) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "Archive path depth cap exceeded ({depth} components, cap {cap}): {path_utf8}"
    ))
}

pub(super) fn archive_ext_cap_error(declared_len: u64, cap: u32) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "Archive extension length cap exceeded ({declared_len} bytes, cap {cap})"
    ))
}

pub(super) fn entry_ext_cap_error(declared_len: u64, cap: u32, path: Option<&str>) -> CryptoError {
    let head =
        format!("Archive entry extension length cap exceeded ({declared_len} bytes, cap {cap})");
    CryptoError::InvalidInput(match path {
        Some(p) => format!("{head}: {p}"),
        None => head,
    })
}

pub(super) fn total_entry_ext_cap_error(total: u64, cap: u64) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "Archive total entry-extension bytes cap exceeded ({total} bytes, cap {cap})"
    ))
}

#[cfg(test)]
mod tests {
    use super::{ArchiveLimits, enforce_per_entry_caps, enforce_total_bytes_cap};

    #[test]
    fn defaults_match_spec_values() {
        let l = ArchiveLimits::default();
        assert_eq!(l.max_entry_count, 250_000);
        assert_eq!(l.max_total_plaintext_bytes, 64 * 1024 * 1024 * 1024);
        assert_eq!(l.max_path_depth, 64);
        assert_eq!(l.max_path_bytes, 4096);
        assert_eq!(l.max_manifest_bytes, 64 * 1024 * 1024);
        assert_eq!(l.max_archive_ext_bytes, 64 * 1024);
        assert_eq!(l.max_entry_ext_bytes, 64 * 1024);
        assert_eq!(l.max_total_entry_ext_bytes, 64 * 1024 * 1024);
        assert_eq!(l.max_tlv_value_bytes, 16 * 1024 * 1024);
    }

    #[test]
    fn validate_accepts_defaults() {
        assert!(ArchiveLimits::default().validate().is_ok());
    }

    /// `path_len` is on-disk `u16`, so a cap above `u16::MAX` is
    /// structurally invalid. The boundary is exact: `u16::MAX` admissible,
    /// `u16::MAX + 1` rejected.
    #[test]
    fn validate_rejects_path_bytes_above_u16_max() {
        let l = ArchiveLimits::default().with_max_path_bytes(u16::MAX as u32 + 1);
        let err = l.validate().unwrap_err();
        assert!(format!("{err}").contains("u16 path length"));
    }

    #[test]
    fn validate_accepts_path_bytes_at_u16_max() {
        let l = ArchiveLimits::default().with_max_path_bytes(u16::MAX as u32);
        assert!(l.validate().is_ok());
    }

    /// Each `with_*` builder must replace exactly one field and leave
    /// the others at the receiver's value. Catches an accidental
    /// cross-field assignment if a future refactor reorders or copy-
    /// pastes the builder bodies.
    #[test]
    fn builders_replace_only_targeted_field() {
        let base = ArchiveLimits::default();

        let l = base.with_max_entry_count(7);
        assert_eq!(l.max_entry_count, 7);
        assert_eq!(l.max_total_plaintext_bytes, base.max_total_plaintext_bytes);
        assert_eq!(l.max_path_depth, base.max_path_depth);
        assert_eq!(l.max_path_bytes, base.max_path_bytes);
        assert_eq!(l.max_manifest_bytes, base.max_manifest_bytes);

        let l = base.with_max_total_plaintext_bytes(123);
        assert_eq!(l.max_entry_count, base.max_entry_count);
        assert_eq!(l.max_total_plaintext_bytes, 123);
        assert_eq!(l.max_path_depth, base.max_path_depth);
        assert_eq!(l.max_path_bytes, base.max_path_bytes);
        assert_eq!(l.max_manifest_bytes, base.max_manifest_bytes);

        let l = base.with_max_path_depth(7);
        assert_eq!(l.max_entry_count, base.max_entry_count);
        assert_eq!(l.max_total_plaintext_bytes, base.max_total_plaintext_bytes);
        assert_eq!(l.max_path_depth, 7);
        assert_eq!(l.max_path_bytes, base.max_path_bytes);
        assert_eq!(l.max_manifest_bytes, base.max_manifest_bytes);

        let l = base.with_max_path_bytes(99);
        assert_eq!(l.max_entry_count, base.max_entry_count);
        assert_eq!(l.max_total_plaintext_bytes, base.max_total_plaintext_bytes);
        assert_eq!(l.max_path_depth, base.max_path_depth);
        assert_eq!(l.max_path_bytes, 99);
        assert_eq!(l.max_manifest_bytes, base.max_manifest_bytes);

        let l = base.with_max_manifest_bytes(42);
        assert_eq!(l.max_entry_count, base.max_entry_count);
        assert_eq!(l.max_total_plaintext_bytes, base.max_total_plaintext_bytes);
        assert_eq!(l.max_path_depth, base.max_path_depth);
        assert_eq!(l.max_path_bytes, base.max_path_bytes);
        assert_eq!(l.max_manifest_bytes, 42);

        let l = base.with_max_archive_ext_bytes(1234);
        assert_eq!(l.max_archive_ext_bytes, 1234);
        assert_eq!(l.max_entry_ext_bytes, base.max_entry_ext_bytes);

        let l = base.with_max_entry_ext_bytes(5678);
        assert_eq!(l.max_archive_ext_bytes, base.max_archive_ext_bytes);
        assert_eq!(l.max_entry_ext_bytes, 5678);

        let l = base.with_max_total_entry_ext_bytes(999);
        assert_eq!(l.max_total_entry_ext_bytes, 999);
        assert_eq!(l.max_tlv_value_bytes, base.max_tlv_value_bytes);

        let l = base.with_max_tlv_value_bytes(321);
        assert_eq!(l.max_total_entry_ext_bytes, base.max_total_entry_ext_bytes);
        assert_eq!(l.max_tlv_value_bytes, 321);
    }

    /// `entry_count > limits.max_entry_count` is `>`, not `>=`. Boundary
    /// is "cap admissible, cap+1 rejected." Pinned because integration
    /// tests fire the cap at well-above-cap values and would not catch a
    /// comparison-operator regression.
    #[test]
    fn enforce_per_entry_caps_entry_count_boundary() {
        let limits = ArchiveLimits::default().with_max_entry_count(10);
        assert!(enforce_per_entry_caps(10, "a", &limits).is_ok());
        assert!(enforce_per_entry_caps(11, "a", &limits).is_err());
    }

    /// Same boundary for `max_path_depth`: a path with exactly `cap`
    /// components is admissible; `cap + 1` rejected.
    #[test]
    fn enforce_per_entry_caps_depth_boundary() {
        let limits = ArchiveLimits::default().with_max_path_depth(3);
        assert!(enforce_per_entry_caps(1, "a/b/c", &limits).is_ok());
        assert!(enforce_per_entry_caps(1, "a/b/c/d", &limits).is_err());
    }

    /// Security property: total-byte overflow is rejected even when
    /// the caller raises the cap to `u64::MAX`. The running total is
    /// left unchanged on overflow so callers cannot accidentally keep
    /// using a saturated value as if it were a valid sum.
    #[test]
    fn enforce_total_bytes_cap_rejects_overflow() {
        let limits = ArchiveLimits::default().with_max_total_plaintext_bytes(u64::MAX);
        let mut total = u64::MAX - 100;
        let result = enforce_total_bytes_cap(200, &mut total, &limits);
        assert!(result.is_err());
        assert_eq!(
            total,
            u64::MAX - 100,
            "total_bytes must not wrap or saturate"
        );
    }

    /// Cap boundary on the bytes side: a running total exactly at the
    /// cap is admissible; one byte over rejects. `>` vs `>=` regression
    /// guard symmetric with the entry-count boundary test above.
    #[test]
    fn enforce_total_bytes_cap_boundary() {
        let limits = ArchiveLimits::default().with_max_total_plaintext_bytes(100);
        let mut total = 0;
        assert!(enforce_total_bytes_cap(100, &mut total, &limits).is_ok());
        assert_eq!(total, 100);
        assert!(enforce_total_bytes_cap(1, &mut total, &limits).is_err());
        assert_eq!(total, 100);
    }
}
