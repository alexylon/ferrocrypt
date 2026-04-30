//! Resource caps applied symmetrically on encrypt-side preflight and
//! decrypt-side extraction.

use std::path::Path;

use crate::CryptoError;

/// Resource caps applied during TAR archive AND extract operations.
///
/// On the **extract** side, the `.fcr` payload is post-MAC authenticated,
/// so an external attacker cannot forge a malicious archive — but a
/// sender error or stress-test corpus can still legitimately produce a
/// payload that would exhaust the reader's RAM (`seen_paths` HashSet),
/// file-descriptor table (one `OwnedFd` per intermediate directory on
/// Linux/macOS), or disk. Each cap fires before the next allocation /
/// `io::copy`.
///
/// On the **archive** side, the same caps run as a writer-side
/// preflight: a tree the extractor would refuse must NOT be encryptable
/// in the first place, otherwise a user could encrypt a file they
/// cannot decrypt with the default policy. Encrypt-side rejection
/// fires BEFORE the entry's TAR header is emitted, so the writer
/// short-circuits early and no partial archive is produced.
///
/// Defaults are sized for typical desktop content (large source repos,
/// photo libraries, multi-GiB document trees) while rejecting
/// pathological inputs (millions of empty entries, multi-TiB declared
/// sizes, deeply nested directory trees).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ArchiveLimits {
    /// Maximum number of TAR entries (regular files + directories)
    /// admissible in a single extract. Exceeding this rejects the
    /// archive before the offending entry's `seen_paths` slot is
    /// allocated.
    pub max_entry_count: u32,
    /// Maximum cumulative announced plaintext bytes across all regular
    /// file entries. Directory entries do not contribute. Each entry's
    /// announced size (`entry.header().size()`) is added to a running
    /// total and checked BEFORE the entry's content is copied, so a
    /// hostile size declaration cannot force a partial write.
    pub max_total_plaintext_bytes: u64,
    /// Maximum path component count of any single entry (directory
    /// depth + filename). The ustar `PATH_REPRESENTABLE_MAX` already
    /// caps the byte length of the path; this cap rejects deeply
    /// nested but byte-economical paths (e.g. `a/b/c/.../z`) before
    /// the per-component openat walk.
    pub max_path_depth: u32,
}

impl ArchiveLimits {
    /// Replaces the maximum TAR entry count. See
    /// [`ArchiveLimits::max_entry_count`].
    pub fn with_max_entry_count(mut self, n: u32) -> Self {
        self.max_entry_count = n;
        self
    }

    /// Replaces the maximum cumulative plaintext byte cap. See
    /// [`ArchiveLimits::max_total_plaintext_bytes`].
    pub fn with_max_total_plaintext_bytes(mut self, n: u64) -> Self {
        self.max_total_plaintext_bytes = n;
        self
    }

    /// Replaces the maximum per-entry path-component depth. See
    /// [`ArchiveLimits::max_path_depth`].
    pub fn with_max_path_depth(mut self, n: u32) -> Self {
        self.max_path_depth = n;
        self
    }
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_entry_count: 250_000,
            max_total_plaintext_bytes: 64 * 1024 * 1024 * 1024,
            max_path_depth: 64,
        }
    }
}

/// Per-entry resource-cap check shared by encrypt-side preflight
/// (`encode::archive`) and decrypt-side extraction
/// (`decode::extract_entries`, both arms). Caller has already
/// incremented `entry_count` for the current entry. Rejects with
/// [`CryptoError::InvalidInput`] (the archive-layer escape-hatch class)
/// so the diagnostic carries the offending count or path inline.
pub(crate) fn enforce_per_entry_caps(
    entry_count: u32,
    path: &Path,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    if entry_count > limits.max_entry_count {
        return Err(CryptoError::InvalidInput(format!(
            "Archive entry-count cap exceeded ({} entries, cap {})",
            entry_count, limits.max_entry_count
        )));
    }
    let depth = u32::try_from(path.components().count()).unwrap_or(u32::MAX);
    if depth > limits.max_path_depth {
        return Err(CryptoError::InvalidInput(format!(
            "Archive path depth cap exceeded ({} components, cap {}): {}",
            depth,
            limits.max_path_depth,
            path.display()
        )));
    }
    Ok(())
}

/// Per-file-entry total-bytes cap check shared by encrypt-side preflight
/// and decrypt-side extraction. Updates `total_bytes` in place
/// (saturating to `u64::MAX`) BEFORE the cap comparison so an overflow
/// cannot underflow the rejection — the cap value is bounded by `u64`,
/// so the saturated sum always exceeds it.
pub(crate) fn enforce_total_bytes_cap(
    entry_size: u64,
    total_bytes: &mut u64,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    *total_bytes = total_bytes.saturating_add(entry_size);
    if *total_bytes > limits.max_total_plaintext_bytes {
        return Err(CryptoError::InvalidInput(format!(
            "Archive total-bytes cap exceeded ({} bytes, cap {})",
            *total_bytes, limits.max_total_plaintext_bytes
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ArchiveLimits, enforce_per_entry_caps, enforce_total_bytes_cap};
    use std::path::Path;

    /// Each `with_*` builder must replace exactly one field and leave
    /// the others at the receiver's value. Catches an accidental
    /// cross-field assignment if a future refactor reorders or copy-
    /// pastes the builder bodies.
    #[test]
    fn builders_replace_only_targeted_field() {
        let base = ArchiveLimits::default();

        let entry = base.with_max_entry_count(42);
        assert_eq!(entry.max_entry_count, 42);
        assert_eq!(
            entry.max_total_plaintext_bytes,
            base.max_total_plaintext_bytes
        );
        assert_eq!(entry.max_path_depth, base.max_path_depth);

        let bytes = base.with_max_total_plaintext_bytes(99);
        assert_eq!(bytes.max_entry_count, base.max_entry_count);
        assert_eq!(bytes.max_total_plaintext_bytes, 99);
        assert_eq!(bytes.max_path_depth, base.max_path_depth);

        let depth = base.with_max_path_depth(7);
        assert_eq!(depth.max_entry_count, base.max_entry_count);
        assert_eq!(
            depth.max_total_plaintext_bytes,
            base.max_total_plaintext_bytes
        );
        assert_eq!(depth.max_path_depth, 7);
    }

    /// `entry_count > limits.max_entry_count` is `>`, not `>=`. The
    /// boundary is "cap admissible, cap+1 rejected." Pinned here
    /// because the integration tests fire the cap at well-above-cap
    /// values and would not catch a comparison-operator regression.
    #[test]
    fn enforce_per_entry_caps_entry_count_boundary() {
        let limits = ArchiveLimits::default().with_max_entry_count(10);
        let path = Path::new("a");

        assert!(enforce_per_entry_caps(10, path, &limits).is_ok());
        assert!(enforce_per_entry_caps(11, path, &limits).is_err());
    }

    /// Same boundary semantics for `max_path_depth`: a path with
    /// exactly `cap` components is admissible; `cap + 1` rejected.
    #[test]
    fn enforce_per_entry_caps_depth_boundary() {
        let limits = ArchiveLimits::default().with_max_path_depth(3);

        assert!(enforce_per_entry_caps(1, Path::new("a/b/c"), &limits).is_ok());
        assert!(enforce_per_entry_caps(1, Path::new("a/b/c/d"), &limits).is_err());
    }

    /// The function's security property: an overflow of the running
    /// total cannot underflow the cap rejection. `saturating_add`
    /// pins the sum at `u64::MAX`, which exceeds any cap value, so
    /// the rejection still fires. A future refactor that swaps in
    /// `wrapping_add` or `+` would be caught here.
    #[test]
    fn enforce_total_bytes_cap_saturates_on_overflow() {
        let limits = ArchiveLimits::default();

        let mut total = u64::MAX - 100;
        let result = enforce_total_bytes_cap(200, &mut total, &limits);

        assert!(result.is_err());
        assert_eq!(total, u64::MAX, "total_bytes must saturate, not wrap");
    }

    /// Cap boundary on the bytes side: a running total exactly at
    /// the cap is admissible; one byte over rejects. `>` vs `>=`
    /// regression guard symmetric with the entry-count boundary
    /// test above.
    #[test]
    fn enforce_total_bytes_cap_boundary() {
        let limits = ArchiveLimits::default().with_max_total_plaintext_bytes(100);

        let mut total = 0;
        assert!(enforce_total_bytes_cap(100, &mut total, &limits).is_ok());
        assert_eq!(total, 100);

        // Next byte tips the running total over the cap.
        assert!(enforce_total_bytes_cap(1, &mut total, &limits).is_err());
        assert_eq!(total, 101);
    }
}
