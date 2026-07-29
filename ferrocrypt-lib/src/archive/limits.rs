//! Resource caps for FCA archive encoding and extraction.
//!
//! `ArchiveLimits` bounds entry count, total plaintext bytes, path depth,
//! per-path UTF-8 byte length, serialized manifest byte length, and the
//! per-region, total, and per-value caps that bound FCA forward-compatibility
//! TLV regions. See `ferrocrypt-lib/FORMAT.md` §9.12.
//!
//! Both writer and reader apply each cap before the allocation, content copy,
//! or filesystem work that cap bounds — readers during header / manifest
//! parse, writers progressively during the metadata pass. The same struct is
//! reused on both sides so a tree the default-configured decryptor would
//! refuse cannot be encrypted in the first place.

use crate::CryptoError;
use crate::error::sanitize_for_display;

use super::reasons::{TOTAL_ENTRY_EXT_BYTES_OVERFLOW, TOTAL_FILE_BYTES_OVERFLOW};

/// Resource caps for FCA archive encoding and extraction.
///
/// The defaults suit ordinary files and directory trees. Raise a cap only
/// for input of a known origin that legitimately exceeds it, and pass the
/// same value to both sides: an archive written under raised caps needs
/// matching caps to be read back.
///
/// Every cap has a published `*_DEFAULT` constant, so adjusting one cap
/// relative to the defaults does not mean copying a number out of
/// `FORMAT.md` §9.12. Only [`ArchiveLimits::max_path_bytes`] has a
/// structural ceiling — the on-disk `path_len` field is a `u16` — and its
/// builder method clamps there, so safe downstream code cannot construct a
/// cap the format cannot represent. The other caps are resource policy alone
/// and accept any value their type holds.
///
/// Archive caps are enforced at the earliest point their authenticated FCA
/// values are available. Encryption applies them during archive preflight,
/// before key derivation or output staging. Decryption must first authenticate
/// and begin decrypting the FCA payload; each cap then runs before the
/// allocation, content copy, or filesystem work that it bounds, and complete
/// manifest validation still precedes filesystem output.
///
/// The archive count, size, path, and extension-region caps surface as
/// dedicated `Archive*CapExceeded` errors. A TLV value above
/// `max_tlv_value_bytes` is instead a TLV grammar defect and surfaces as
/// `CryptoError::InvalidFormat(FormatDefect::MalformedTlv)`.
///
/// Pass a value to [`crate::Encryptor::archive_limits`],
/// [`crate::PassphraseDecryptor::archive_limits`], or
/// [`crate::PrivateKeyDecryptor::archive_limits`]. The struct is
/// `#[non_exhaustive]` so future releases can add further caps without a
/// breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArchiveLimits {
    /// Maximum number of manifest entries (regular files plus directories).
    pub(crate) max_entry_count: u32,
    /// Maximum cumulative declared logical bytes across regular-file
    /// entries. Directory entries do not contribute.
    pub(crate) max_total_plaintext_bytes: u64,
    /// Maximum path component count for any single archive entry.
    pub(crate) max_path_depth: u32,
    /// Maximum UTF-8 byte length of any single archive path. Public
    /// construction keeps this at or below
    /// [`ArchiveLimits::PATH_BYTES_STRUCTURAL_MAX`], because the on-disk
    /// `path_len` field is a `u16`.
    pub(crate) max_path_bytes: u32,
    /// Maximum byte length of the serialized manifest, including the
    /// per-entry TLV regions that live inside it.
    pub(crate) max_manifest_bytes: u32,
    /// Maximum byte length of the FCA archive-level TLV region
    /// (`archive_ext`). The FCA fixed header's `archive_ext_len` field
    /// is rejected before allocation if it exceeds this cap.
    pub(crate) max_archive_ext_bytes: u32,
    /// Maximum byte length of any single per-entry TLV region
    /// (`entry_ext`).
    pub(crate) max_entry_ext_bytes: u32,
    /// Maximum cumulative byte length of all per-entry TLV regions in
    /// one manifest. Bounds memory used by extension metadata across
    /// the archive even when individual entries fit under
    /// `max_entry_ext_bytes`.
    pub(crate) max_total_entry_ext_bytes: u64,
    /// Maximum byte length of any single TLV value inside an FCA
    /// archive- or entry-level TLV region. Defense-in-depth: the
    /// containing region cap will fire first today, but a future
    /// region with a larger cap still bounds individual values.
    pub(crate) max_tlv_value_bytes: u32,
}

impl ArchiveLimits {
    /// Structural maximum for the per-path byte cap (65,535 bytes): the
    /// on-disk `path_len` field is a `u16` (`FORMAT.md` §9.12).
    /// [`ArchiveLimits::max_path_bytes`] clamps at this value. It is the
    /// only cap the format itself bounds; the rest are resource policy.
    pub const PATH_BYTES_STRUCTURAL_MAX: u32 = u16::MAX as u32;

    /// Default manifest entry count (250,000 entries).
    pub const ENTRY_COUNT_DEFAULT: u32 = 250_000;
    /// Default cumulative logical regular-file byte count (64 GiB).
    pub const TOTAL_PLAINTEXT_BYTES_DEFAULT: u64 = 64 * 1024 * 1024 * 1024;
    /// Default per-path component count (64 components).
    pub const PATH_DEPTH_DEFAULT: u32 = 64;
    /// Default per-path UTF-8 byte length (4,096 bytes).
    pub const PATH_BYTES_DEFAULT: u32 = 4096;
    /// Default serialized manifest byte length (64 MiB).
    pub const MANIFEST_BYTES_DEFAULT: u32 = 64 * 1024 * 1024;
    /// Default archive-level TLV region byte length (64 KiB).
    pub const ARCHIVE_EXT_BYTES_DEFAULT: u32 = 64 * 1024;
    /// Default per-entry TLV region byte length (64 KiB).
    pub const ENTRY_EXT_BYTES_DEFAULT: u32 = 64 * 1024;
    /// Default cumulative per-entry TLV byte length (64 MiB).
    pub const TOTAL_ENTRY_EXT_BYTES_DEFAULT: u64 = 64 * 1024 * 1024;
    /// Default single-TLV value byte length (16 MiB).
    pub const TLV_VALUE_BYTES_DEFAULT: u32 = 16 * 1024 * 1024;

    /// Sets the maximum number of manifest entries. A source tree or a
    /// manifest above the cap rejects with
    /// [`CryptoError::ArchiveEntryCountCapExceeded`] before per-entry
    /// state is allocated.
    pub fn max_entry_count(mut self, value: u32) -> Self {
        self.max_entry_count = value;
        self
    }

    /// Sets the maximum cumulative logical byte count across regular-file
    /// entries. A larger total rejects with
    /// [`CryptoError::ArchiveTotalBytesCapExceeded`] before any file
    /// content is copied.
    pub fn max_total_plaintext_bytes(mut self, value: u64) -> Self {
        self.max_total_plaintext_bytes = value;
        self
    }

    /// Sets the maximum path component count for one archive entry. A
    /// deeper path rejects with
    /// [`CryptoError::ArchivePathDepthCapExceeded`] before filesystem
    /// traversal.
    pub fn max_path_depth(mut self, value: u32) -> Self {
        self.max_path_depth = value;
        self
    }

    /// Sets the maximum UTF-8 byte length of one archive path, clamped at
    /// [`Self::PATH_BYTES_STRUCTURAL_MAX`]. A longer path rejects with
    /// [`CryptoError::ArchivePathBytesCapExceeded`] before the path is
    /// allocated or converted.
    pub fn max_path_bytes(mut self, value: u32) -> Self {
        self.max_path_bytes = value.min(Self::PATH_BYTES_STRUCTURAL_MAX);
        self
    }

    /// Sets the maximum serialized manifest byte length, per-entry TLV
    /// regions included. A larger manifest rejects with
    /// [`CryptoError::ArchiveManifestLenCapExceeded`] before the manifest
    /// buffer is allocated.
    pub fn max_manifest_bytes(mut self, value: u32) -> Self {
        self.max_manifest_bytes = value;
        self
    }

    /// Sets the maximum archive-level TLV region byte length. A larger
    /// declared region rejects with
    /// [`CryptoError::ArchiveExtLenCapExceeded`] before the extension
    /// buffer is allocated.
    pub fn max_archive_ext_bytes(mut self, value: u32) -> Self {
        self.max_archive_ext_bytes = value;
        self
    }

    /// Sets the maximum byte length of one per-entry TLV region. A larger
    /// region rejects with
    /// [`CryptoError::ArchiveEntryExtLenCapExceeded`] before its bytes are
    /// sliced.
    pub fn max_entry_ext_bytes(mut self, value: u32) -> Self {
        self.max_entry_ext_bytes = value;
        self
    }

    /// Sets the maximum cumulative byte length of every per-entry TLV
    /// region in one manifest. A larger total rejects with
    /// [`CryptoError::ArchiveTotalEntryExtCapExceeded`] while the manifest
    /// is parsed.
    pub fn max_total_entry_ext_bytes(mut self, value: u64) -> Self {
        self.max_total_entry_ext_bytes = value;
        self
    }

    /// Sets the maximum byte length of one TLV value inside an FCA
    /// archive- or entry-level region. A longer value rejects the region
    /// as malformed while it is validated.
    pub fn max_tlv_value_bytes(mut self, value: u32) -> Self {
        self.max_tlv_value_bytes = value;
        self
    }
}

/// The default path-byte cap must itself be representable on the wire, or
/// every unconfigured operation would carry an impossible cap.
const _: () =
    assert!(ArchiveLimits::PATH_BYTES_DEFAULT <= ArchiveLimits::PATH_BYTES_STRUCTURAL_MAX);

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_entry_count: Self::ENTRY_COUNT_DEFAULT,
            max_total_plaintext_bytes: Self::TOTAL_PLAINTEXT_BYTES_DEFAULT,
            max_path_depth: Self::PATH_DEPTH_DEFAULT,
            max_path_bytes: Self::PATH_BYTES_DEFAULT,
            max_manifest_bytes: Self::MANIFEST_BYTES_DEFAULT,
            max_archive_ext_bytes: Self::ARCHIVE_EXT_BYTES_DEFAULT,
            max_entry_ext_bytes: Self::ENTRY_EXT_BYTES_DEFAULT,
            max_total_entry_ext_bytes: Self::TOTAL_ENTRY_EXT_BYTES_DEFAULT,
            max_tlv_value_bytes: Self::TLV_VALUE_BYTES_DEFAULT,
        }
    }
}

/// Per-entry resource-cap check for the encrypt-side preflight
/// (`archive::encode`). The decode side does not call this wrapper —
/// manifest parsing and tree validation run the same underlying
/// per-cap helpers directly — so each cap rule still lives in exactly
/// one place. Caller has already incremented `entry_count` for the
/// current entry.
pub(crate) fn enforce_per_entry_caps(
    entry_count: u32,
    path_utf8: &str,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    enforce_entry_count_cap(entry_count, limits)?;
    enforce_path_depth_cap(path_utf8, limits)?;
    Ok(())
}

/// Single source of truth for `entry_count > max_entry_count`. Used by
/// the writer's metadata-pass per-entry check
/// ([`enforce_per_entry_caps`]), the reader's [`parse_fca_header`]
/// header-field check, and the post-parse manifest-tree validator.
pub(crate) fn enforce_entry_count_cap(
    entry_count: u32,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    if entry_count > limits.max_entry_count {
        return Err(entry_count_cap_error(entry_count, limits.max_entry_count));
    }
    Ok(())
}

/// Counts the `/`-separated components of an FCA path. `validate_fca_path`
/// (in `archive::path`) guarantees single `/` separators with no leading
/// or trailing slash, so this count matches the `max_path_depth` cap
/// exactly. The single source of truth for the split, shared by
/// [`enforce_path_depth_cap`] here and `archive::path::canonical_path_order`.
pub(super) fn component_count(path: &str) -> usize {
    path.split('/').count()
}

/// Single source of truth for path-depth cap enforcement. Computes the
/// depth from the FCA UTF-8 path (count of `/`-separated components)
/// so callers don't reimplement the split. Used by [`validate_fca_path`]
/// (path grammar) and [`enforce_per_entry_caps`] (writer metadata pass).
pub(crate) fn enforce_path_depth_cap(
    path_utf8: &str,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    let depth = u32::try_from(component_count(path_utf8)).unwrap_or(u32::MAX);
    if depth > limits.max_path_depth {
        return Err(path_depth_cap_error(
            depth,
            limits.max_path_depth,
            path_utf8,
        ));
    }
    Ok(())
}

/// Single source of truth for the per-entry path-byte cap. Used by:
/// the writer's [`crate::archive::format::checked_manifest_len`] (with
/// the entry path), the reader's
/// [`crate::archive::format::parse_manifest_bytes`] pre-allocation
/// guard (without a path yet), and [`validate_fca_path`] (after the
/// path string has been resolved).
pub(crate) fn enforce_path_bytes_cap(
    path_len: u32,
    path: Option<&str>,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    if path_len > limits.max_path_bytes {
        return Err(path_bytes_cap_error(path_len, limits.max_path_bytes, path));
    }
    Ok(())
}

/// Single source of truth for `manifest_len > max_manifest_bytes`. Used
/// by the reader's [`parse_fca_header`] (header field check) and the
/// writer's [`crate::archive::format::checked_manifest_len`] running
/// total. Takes `u64` so a `u32` wire field and a `usize` running total
/// both fit.
pub(crate) fn enforce_manifest_len_cap(
    manifest_len: u64,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    if manifest_len > u64::from(limits.max_manifest_bytes) {
        return Err(manifest_len_cap_error(
            manifest_len,
            limits.max_manifest_bytes,
        ));
    }
    Ok(())
}

/// Single source of truth for `archive_ext_len > max_archive_ext_bytes`.
/// Used by [`parse_fca_header`] (only call site today; native writers emit
/// `archive_ext_len = 0` so the writer-side check is implicit, but a
/// future writer that emits a non-zero region would call this).
pub(crate) fn enforce_archive_ext_cap(
    archive_ext_len: u64,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    if archive_ext_len > u64::from(limits.max_archive_ext_bytes) {
        return Err(archive_ext_cap_error(
            archive_ext_len,
            limits.max_archive_ext_bytes,
        ));
    }
    Ok(())
}

/// One-shot total-bytes cap check (no running mutator). Used by the
/// reader's [`parse_fca_header`] (header field), reader's
/// [`crate::archive::format::parse_manifest_bytes`] post-sum
/// re-validation, and the manifest-tree validator. The writer's
/// metadata pass uses [`enforce_total_bytes_cap`] (running mutator)
/// instead.
pub(crate) fn enforce_total_plaintext_bytes_cap(
    total_file_bytes: u64,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    if total_file_bytes > limits.max_total_plaintext_bytes {
        return Err(total_bytes_cap_error(
            total_file_bytes,
            limits.max_total_plaintext_bytes,
        ));
    }
    Ok(())
}

/// Per-file-entry total-bytes accumulator for the encrypt-side
/// preflight (`archive::encode`). The decode side keeps its own checked
/// running sum and applies the same `enforce_total_plaintext_bytes_cap`
/// rule during manifest tree validation. Updates `total_bytes` in place
/// using checked arithmetic so an overflow is rejected even when
/// callers raise `max_total_plaintext_bytes` to `u64::MAX`.
pub(crate) fn enforce_total_bytes_cap(
    entry_size: u64,
    total_bytes: &mut u64,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    let next = total_bytes
        .checked_add(entry_size)
        .ok_or(CryptoError::MalformedArchive {
            reason: TOTAL_FILE_BYTES_OVERFLOW,
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

/// Per-entry `entry_ext` cap check, shared by writer-side
/// `checked_manifest_len` (which knows the entry path) and reader-side
/// `parse_manifest_bytes` (which has only parsed the length so far).
/// Single source of truth for the `entry_ext_len > max_entry_ext_bytes`
/// rejection so a future cap rename only touches one place.
pub(crate) fn enforce_entry_ext_cap(
    entry_ext_len: u64,
    path: Option<&str>,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    if entry_ext_len > u64::from(limits.max_entry_ext_bytes) {
        return Err(entry_ext_cap_error(
            entry_ext_len,
            limits.max_entry_ext_bytes,
            path,
        ));
    }
    Ok(())
}

/// Per-entry TLV-region total cap, shared by writer-side
/// `checked_manifest_len` and reader-side `parse_manifest_bytes`.
/// Mirrors [`enforce_total_bytes_cap`]: checked-add + cap, with the
/// same `&mut u64` running-total convention so overflow is rejected
/// even at `max_total_entry_ext_bytes = u64::MAX`.
pub(crate) fn enforce_total_entry_ext_cap(
    entry_ext_len: u64,
    total: &mut u64,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    let next = total
        .checked_add(entry_ext_len)
        .ok_or(CryptoError::MalformedArchive {
            reason: TOTAL_ENTRY_EXT_BYTES_OVERFLOW,
        })?;
    if next > limits.max_total_entry_ext_bytes {
        return Err(total_entry_ext_cap_error(
            next,
            limits.max_total_entry_ext_bytes,
        ));
    }
    *total = next;
    Ok(())
}

pub(super) fn entry_count_cap_error(entry_count: u32, cap: u32) -> CryptoError {
    CryptoError::ArchiveEntryCountCapExceeded {
        entry_count,
        local_cap: cap,
    }
}

pub(super) fn total_bytes_cap_error(total: u64, cap: u64) -> CryptoError {
    CryptoError::ArchiveTotalBytesCapExceeded {
        total_bytes: total,
        local_cap: cap,
    }
}

pub(super) fn manifest_len_cap_error(len: u64, cap: u32) -> CryptoError {
    CryptoError::ArchiveManifestLenCapExceeded {
        manifest_len: len,
        local_cap: cap,
    }
}

pub(super) fn path_bytes_cap_error(declared_len: u32, cap: u32, path: Option<&str>) -> CryptoError {
    CryptoError::ArchivePathBytesCapExceeded {
        path_bytes: declared_len,
        local_cap: cap,
        path: path.map(sanitize_for_display),
    }
}

pub(super) fn path_depth_cap_error(depth: u32, cap: u32, path_utf8: &str) -> CryptoError {
    CryptoError::ArchivePathDepthCapExceeded {
        depth,
        local_cap: cap,
        path: sanitize_for_display(path_utf8),
    }
}

pub(super) fn archive_ext_cap_error(declared_len: u64, cap: u32) -> CryptoError {
    CryptoError::ArchiveExtLenCapExceeded {
        ext_len: declared_len,
        local_cap: cap,
    }
}

pub(super) fn entry_ext_cap_error(declared_len: u64, cap: u32, path: Option<&str>) -> CryptoError {
    CryptoError::ArchiveEntryExtLenCapExceeded {
        ext_len: declared_len,
        local_cap: cap,
        path: path.map(sanitize_for_display),
    }
}

pub(super) fn total_entry_ext_cap_error(total: u64, cap: u64) -> CryptoError {
    CryptoError::ArchiveTotalEntryExtCapExceeded {
        total_ext_bytes: total,
        local_cap: cap,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArchiveLimits, enforce_archive_ext_cap, enforce_entry_ext_cap, enforce_manifest_len_cap,
        enforce_path_bytes_cap, enforce_per_entry_caps, enforce_total_bytes_cap,
        enforce_total_entry_ext_cap,
    };

    /// The `FORMAT.md` §9.12 default table, pinned against the published
    /// constants so a caller reading `ENTRY_COUNT_DEFAULT` and a caller
    /// calling `default()` cannot see different numbers.
    #[test]
    fn defaults_match_spec_values() {
        let l = ArchiveLimits::default();
        assert_eq!(l.max_entry_count, ArchiveLimits::ENTRY_COUNT_DEFAULT);
        assert_eq!(l.max_entry_count, 250_000);
        assert_eq!(
            l.max_total_plaintext_bytes,
            ArchiveLimits::TOTAL_PLAINTEXT_BYTES_DEFAULT
        );
        assert_eq!(l.max_total_plaintext_bytes, 64 * 1024 * 1024 * 1024);
        assert_eq!(l.max_path_depth, ArchiveLimits::PATH_DEPTH_DEFAULT);
        assert_eq!(l.max_path_depth, 64);
        assert_eq!(l.max_path_bytes, ArchiveLimits::PATH_BYTES_DEFAULT);
        assert_eq!(l.max_path_bytes, 4096);
        assert_eq!(l.max_manifest_bytes, ArchiveLimits::MANIFEST_BYTES_DEFAULT);
        assert_eq!(l.max_manifest_bytes, 64 * 1024 * 1024);
        assert_eq!(
            l.max_archive_ext_bytes,
            ArchiveLimits::ARCHIVE_EXT_BYTES_DEFAULT
        );
        assert_eq!(l.max_archive_ext_bytes, 64 * 1024);
        assert_eq!(
            l.max_entry_ext_bytes,
            ArchiveLimits::ENTRY_EXT_BYTES_DEFAULT
        );
        assert_eq!(l.max_entry_ext_bytes, 64 * 1024);
        assert_eq!(
            l.max_total_entry_ext_bytes,
            ArchiveLimits::TOTAL_ENTRY_EXT_BYTES_DEFAULT
        );
        assert_eq!(l.max_total_entry_ext_bytes, 64 * 1024 * 1024);
        assert_eq!(
            l.max_tlv_value_bytes,
            ArchiveLimits::TLV_VALUE_BYTES_DEFAULT
        );
        assert_eq!(l.max_tlv_value_bytes, 16 * 1024 * 1024);
    }

    /// `path_len` is a `u16` on the wire, so the builder clamps rather
    /// than storing a cap the format cannot express. The boundary is
    /// exact: the structural maximum is kept, one above it clamps down.
    #[test]
    fn path_bytes_builder_clamps_at_structural_max() {
        let at = ArchiveLimits::default().max_path_bytes(ArchiveLimits::PATH_BYTES_STRUCTURAL_MAX);
        assert_eq!(at.max_path_bytes, ArchiveLimits::PATH_BYTES_STRUCTURAL_MAX);

        let above = ArchiveLimits::default().max_path_bytes(u32::MAX);
        assert_eq!(
            above.max_path_bytes,
            ArchiveLimits::PATH_BYTES_STRUCTURAL_MAX
        );
    }

    /// Each builder must replace exactly one cap and leave the others at
    /// the receiver's value. Catches an accidental cross-field assignment
    /// if a future refactor reorders or copy-pastes the builder bodies.
    /// `PartialEq` makes each case a single comparison against the
    /// expected result.
    #[test]
    fn builders_replace_only_targeted_field() {
        let base = ArchiveLimits::default();

        let mut want = base;
        want.max_entry_count = 7;
        assert_eq!(base.max_entry_count(7), want);

        let mut want = base;
        want.max_total_plaintext_bytes = 123;
        assert_eq!(base.max_total_plaintext_bytes(123), want);

        let mut want = base;
        want.max_path_depth = 7;
        assert_eq!(base.max_path_depth(7), want);

        let mut want = base;
        want.max_path_bytes = 99;
        assert_eq!(base.max_path_bytes(99), want);

        let mut want = base;
        want.max_manifest_bytes = 42;
        assert_eq!(base.max_manifest_bytes(42), want);

        let mut want = base;
        want.max_archive_ext_bytes = 1234;
        assert_eq!(base.max_archive_ext_bytes(1234), want);

        let mut want = base;
        want.max_entry_ext_bytes = 5678;
        assert_eq!(base.max_entry_ext_bytes(5678), want);

        let mut want = base;
        want.max_total_entry_ext_bytes = 999;
        assert_eq!(base.max_total_entry_ext_bytes(999), want);

        let mut want = base;
        want.max_tlv_value_bytes = 321;
        assert_eq!(base.max_tlv_value_bytes(321), want);
    }

    /// `entry_count > limits.max_entry_count` is `>`, not `>=`. Boundary
    /// is "cap admissible, cap+1 rejected." Pinned because integration
    /// tests fire the cap at well-above-cap values and would not catch a
    /// comparison-operator regression.
    #[test]
    fn enforce_per_entry_caps_entry_count_boundary() {
        let limits = ArchiveLimits::default().max_entry_count(10);
        assert!(enforce_per_entry_caps(10, "a", &limits).is_ok());
        assert!(enforce_per_entry_caps(11, "a", &limits).is_err());
    }

    /// Same boundary for `max_path_depth`: a path with exactly `cap`
    /// components is admissible; `cap + 1` rejected.
    #[test]
    fn enforce_per_entry_caps_depth_boundary() {
        let limits = ArchiveLimits::default().max_path_depth(3);
        assert!(enforce_per_entry_caps(1, "a/b/c", &limits).is_ok());
        assert!(enforce_per_entry_caps(1, "a/b/c/d", &limits).is_err());
    }

    /// Security property: total-byte overflow is rejected even when
    /// the caller raises the cap to `u64::MAX`. The running total is
    /// left unchanged on overflow so callers cannot accidentally keep
    /// using a saturated value as if it were a valid sum.
    #[test]
    fn enforce_total_bytes_cap_rejects_overflow() {
        let limits = ArchiveLimits::default().max_total_plaintext_bytes(u64::MAX);
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
        let limits = ArchiveLimits::default().max_total_plaintext_bytes(100);
        let mut total = 0;
        assert!(enforce_total_bytes_cap(100, &mut total, &limits).is_ok());
        assert_eq!(total, 100);
        assert!(enforce_total_bytes_cap(1, &mut total, &limits).is_err());
        assert_eq!(total, 100);
    }

    /// `>` vs `>=` regression guard for `enforce_path_bytes_cap`.
    /// Path length exactly at cap admissible; cap+1 rejects.
    #[test]
    fn enforce_path_bytes_cap_boundary() {
        let limits = ArchiveLimits::default().max_path_bytes(10);
        assert!(enforce_path_bytes_cap(10, None, &limits).is_ok());
        assert!(enforce_path_bytes_cap(11, None, &limits).is_err());
    }

    /// `>` vs `>=` regression guard for `enforce_manifest_len_cap`.
    /// Manifest length exactly at cap admissible; cap+1 rejects.
    #[test]
    fn enforce_manifest_len_cap_boundary() {
        let limits = ArchiveLimits::default().max_manifest_bytes(100);
        assert!(enforce_manifest_len_cap(100, &limits).is_ok());
        assert!(enforce_manifest_len_cap(101, &limits).is_err());
    }

    /// `>` vs `>=` regression guard for `enforce_archive_ext_cap`.
    /// Archive ext length exactly at cap admissible; cap+1 rejects.
    #[test]
    fn enforce_archive_ext_cap_boundary() {
        let limits = ArchiveLimits::default().max_archive_ext_bytes(100);
        assert!(enforce_archive_ext_cap(100, &limits).is_ok());
        assert!(enforce_archive_ext_cap(101, &limits).is_err());
    }

    /// `>` vs `>=` regression guard for `enforce_entry_ext_cap`.
    /// Entry ext length exactly at cap admissible; cap+1 rejects.
    #[test]
    fn enforce_entry_ext_cap_boundary() {
        let limits = ArchiveLimits::default().max_entry_ext_bytes(100);
        assert!(enforce_entry_ext_cap(100, None, &limits).is_ok());
        assert!(enforce_entry_ext_cap(101, None, &limits).is_err());
    }

    /// `>` vs `>=` regression guard for `enforce_total_entry_ext_cap`.
    /// Running total exactly at cap admissible; cap+1 rejects, total
    /// unchanged on overflow.
    #[test]
    fn enforce_total_entry_ext_cap_boundary() {
        let limits = ArchiveLimits::default().max_total_entry_ext_bytes(100);
        let mut total = 0;
        assert!(enforce_total_entry_ext_cap(100, &mut total, &limits).is_ok());
        assert_eq!(total, 100);
        assert!(enforce_total_entry_ext_cap(1, &mut total, &limits).is_err());
        assert_eq!(total, 100);
    }
}
