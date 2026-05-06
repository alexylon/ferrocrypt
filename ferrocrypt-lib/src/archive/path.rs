//! Archive path canonicalization, rejection, and POSIX ustar wire-format
//! shared between writer and reader.
//!
//! [`validate_archive_path_components`] is the path-traversal guard run on every
//! decrypt-side entry and re-exported via `fuzz_exports`. The [`ustar`]
//! submodule pins the raw POSIX ustar header offsets so the writer
//! emits and the reader strict-validates the same byte layout.
//!
//! ## Path-subset enforcement (writer ↔ reader)
//!
//! The v1 archive subset's path rules — no NUL or `\` byte, no
//! `.`/`..`/empty components, length ≤ [`ustar::PATH_REPRESENTABLE_MAX`],
//! no path traversal, valid UTF-8, single trailing `/` only on directory
//! entries — are enforced on **both** sides by two complementary helpers
//! that operate on different input shapes:
//!
//! - **Writer** (`archive::encode::ustar_archive_path_string`) walks
//!   [`std::path::Component`] values and refuses anything but
//!   [`Component::Normal`], then byte-checks each component for NUL /
//!   `\`. Repeated `//`, `.`/`..`/empty components are structurally
//!   impossible because the writer joins single-`/` between Normal
//!   components only.
//! - **Reader** (`archive::decode::validate_ustar_entry` plus
//!   [`validate_archive_path_components`]) operates on raw byte slices
//!   (the on-disk header field), so every check is explicit: empty,
//!   length, NUL, `\`, `//`, UTF-8, trailing `/`, per-component
//!   `.`/`..`/empty, and the [`Component`]-level path-traversal subset
//!   on the parsed `&Path`.
//!
//! The two helpers reach the same conclusion via different code paths
//! rather than sharing one function because their inputs are different
//! shapes (typed `&Path` vs raw byte slice). Both sides reference the
//! shared constants in [`ustar`] so structural drift is impossible; a
//! change to one side's rules MUST be mirrored in the other.

use std::path::{Component, Path};

use crate::CryptoError;

/// Raw POSIX ustar header constants (`FORMAT.md` §9). Used by both the
/// writer (canonical emission) and the reader (per-entry strict
/// subset validation).
pub(crate) mod ustar {
    /// POSIX ustar fixed block size — every header is one block, every
    /// entry's data is rounded up to a whole number of blocks, and the
    /// archive ends with two consecutive zero blocks. Used by
    /// `archive::decode::read_required_zero_block` to enforce the
    /// second of those two trailing blocks (`FORMAT.md` §9), and by
    /// hand-crafted test fixtures that build archives at the raw byte
    /// level. Production header reads use `tar::Header::as_bytes()` and
    /// do not reference this constant directly.
    pub(crate) const BLOCK_SIZE: usize = 512;

    pub(crate) const TYPEFLAG_OFFSET: usize = 156;
    pub(crate) const MAGIC_OFFSET: usize = 257;
    pub(crate) const MAGIC: &[u8; 6] = b"ustar\0";
    pub(crate) const VERSION_OFFSET: usize = 263;
    pub(crate) const VERSION: &[u8; 2] = b"00";

    /// Offset of the `size` field in the ustar header. v1 forbids the
    /// GNU binary numeric extension (high bit set on the first byte of
    /// a numeric field), and the size field is the only one realistic
    /// implementations would extend to binary; mode/uid/gid/mtime fit
    /// the octal allotment for any sane value.
    pub(crate) const SIZE_FIELD_OFFSET: usize = 124;
    /// High bit on the first byte of a numeric field marks the GNU
    /// binary numeric extension. Forbidden by `FORMAT.md` §9.
    pub(crate) const NUMERIC_BINARY_FLAG_BIT: u8 = 0x80;

    pub(crate) const NAME_SIZE: usize = 100;
    pub(crate) const PREFIX_SIZE: usize = 155;
    /// Maximum path length representable purely via the ustar
    /// `name` + `/` + `prefix` fields; anything longer requires a GNU
    /// long-name or PAX extension record, which v1 forbids.
    pub(crate) const PATH_REPRESENTABLE_MAX: usize = NAME_SIZE + 1 + PREFIX_SIZE;

    /// Maximum file size representable in the ustar `size` field
    /// (11 octal digits + NUL = 33 bits = 8,589,934,591 bytes, one
    /// byte short of 8 GiB). v1 forbids both the GNU binary-size and
    /// PAX `x_size` extensions, so any file beyond this cap must be
    /// rejected on encrypt; otherwise `tar::Header::set_size` would
    /// silently fall back to the GNU binary-size encoding and the
    /// resulting `.fcr` would be unreadable by a conforming reader.
    pub(crate) const FILE_SIZE_REPRESENTABLE_MAX: u64 = 0o77_777_777_777;

    pub(crate) const TYPEFLAG_REGULAR_NUL: u8 = b'\0';
    pub(crate) const TYPEFLAG_REGULAR_ZERO: u8 = b'0';
    pub(crate) const TYPEFLAG_DIRECTORY: u8 = b'5';

    /// Forbidden typeflags surfaced by `tar::Entries::raw(true)`. v1
    /// forbids both PAX (`'x'` per-entry, `'g'` global) and the GNU
    /// extension family (`'L'` long-name, `'K'` long-link, `'S'`
    /// sparse, `'M'` multi-volume continuation, `'D'` GNU dumpdir,
    /// `'V'` GNU volume-header, `'N'` legacy long-name, `'X'` Solaris
    /// extended). Any of these reaching the typeflag match in the
    /// reader is a v1 conformance violation regardless of payload —
    /// see `FORMAT.md` §9.
    pub(crate) const TYPEFLAG_PAX_EXTENDED: u8 = b'x';
    pub(crate) const TYPEFLAG_PAX_GLOBAL: u8 = b'g';
    pub(crate) const TYPEFLAG_GNU_LONG_NAME: u8 = b'L';
    pub(crate) const TYPEFLAG_GNU_LONG_LINK: u8 = b'K';
    pub(crate) const TYPEFLAG_GNU_SPARSE: u8 = b'S';
    pub(crate) const TYPEFLAG_GNU_MULTI_VOLUME: u8 = b'M';
    pub(crate) const TYPEFLAG_GNU_DUMPDIR: u8 = b'D';
    pub(crate) const TYPEFLAG_GNU_VOLUME_HEADER: u8 = b'V';
    pub(crate) const TYPEFLAG_GNU_NAMES: u8 = b'N';
    pub(crate) const TYPEFLAG_SOLARIS_EXTENDED: u8 = b'X';
}

/// `FORMAT.md` §9 archive subset classification for a successfully
/// validated entry: ferrocrypt v1 recognises only regular files and
/// directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UstarEntryKind {
    File,
    Directory,
}

/// Rejects paths that could escape the output directory (path traversal)
/// or confuse the root-aware extraction logic. `Component::CurDir`
/// (leading `./`) is rejected because ferrocrypt's own archiver never
/// produces it and it turns `root_name` into `.`, which then conflicts
/// with the final rename step.
///
/// An empty path (no components) is permissively accepted: the loop is
/// a no-op and the function returns `Ok(())`. The main decode flow
/// never reaches here with an empty path — `validate_ustar_entry`
/// rejects empty paths up-front — but the function is `pub` and
/// reachable via the `fuzz_exports` surface, so the permissive empty-
/// path contract is intentional and pinned by
/// [`tests::validate_accepts_empty_path`].
pub fn validate_archive_path_components(path: &Path) -> Result<(), CryptoError> {
    for component in path.components() {
        match component {
            Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_)
            | Component::CurDir => {
                return Err(CryptoError::InvalidInput(format!(
                    "Unsafe path in archive: {}",
                    path.display()
                )));
            }
            Component::Normal(_) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_archive_path_components;
    use std::path::Path;

    #[test]
    fn validate_rejects_path_traversal() {
        assert!(validate_archive_path_components(Path::new("safe.txt")).is_ok());
        assert!(validate_archive_path_components(Path::new("dir/file.txt")).is_ok());
        assert!(validate_archive_path_components(Path::new("../escape.txt")).is_err());
        assert!(validate_archive_path_components(Path::new("dir/../../escape.txt")).is_err());
        assert!(validate_archive_path_components(Path::new("/etc/passwd")).is_err());
        // Leading `./` turns root_name into `.` and breaks the final
        // rename, so reject it early. Ferrocrypt's own archiver never
        // produces such paths.
        assert!(validate_archive_path_components(Path::new("./foo/bar")).is_err());
        assert!(validate_archive_path_components(Path::new(".")).is_err());
    }

    /// A bare `..` is a single `Component::ParentDir`. The mid-path case
    /// is covered by `validate_rejects_path_traversal`; this pins the
    /// standalone form so a future change to the component match arms
    /// can't accidentally let it through.
    #[test]
    fn validate_rejects_bare_parent_dir() {
        assert!(validate_archive_path_components(Path::new("..")).is_err());
    }

    /// An empty path has no components, so the loop is a no-op and the
    /// validator returns `Ok(())`. The main decode flow never reaches
    /// here with an empty path (`validate_ustar_entry` rejects empty
    /// paths up front), but the function is `pub` and reachable via the
    /// `fuzz_exports` surface, so pin the permissive empty-path
    /// contract explicitly — a future "reject empty" change is a
    /// behavior break that should be caught here, not in fuzzers.
    #[test]
    fn validate_accepts_empty_path() {
        assert!(validate_archive_path_components(Path::new("")).is_ok());
    }
}
