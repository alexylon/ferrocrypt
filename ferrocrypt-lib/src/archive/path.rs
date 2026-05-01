//! Archive path canonicalization, rejection, and POSIX ustar wire-format
//! shared between writer and reader.
//!
//! [`validate_archive_path_components`] is the path-traversal guard run on every
//! decrypt-side entry and re-exported via `fuzz_exports`. The [`ustar`]
//! submodule pins the raw POSIX ustar header offsets so the writer
//! emits and the reader strict-validates the same byte layout.

use std::path::{Component, Path};

use crate::CryptoError;

/// Raw POSIX ustar header constants (`FORMAT.md` §9). Used by both the
/// writer (canonical emission) and the reader (per-entry strict
/// subset validation).
pub(crate) mod ustar {
    pub(crate) const TYPEFLAG_OFFSET: usize = 156;
    pub(crate) const MAGIC_OFFSET: usize = 257;
    pub(crate) const MAGIC: &[u8; 6] = b"ustar\0";
    pub(crate) const VERSION_OFFSET: usize = 263;
    pub(crate) const VERSION: &[u8; 2] = b"00";

    pub(crate) const NAME_SIZE: usize = 100;
    pub(crate) const PREFIX_SIZE: usize = 155;
    /// Maximum path length representable purely via the ustar
    /// `name` + `/` + `prefix` fields; anything longer requires a GNU
    /// long-name or PAX extension record, which v1 forbids.
    pub(crate) const PATH_REPRESENTABLE_MAX: usize = NAME_SIZE + 1 + PREFIX_SIZE;

    pub(crate) const TYPEFLAG_REGULAR_NUL: u8 = b'\0';
    pub(crate) const TYPEFLAG_REGULAR_ZERO: u8 = b'0';
    pub(crate) const TYPEFLAG_DIRECTORY: u8 = b'5';
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
