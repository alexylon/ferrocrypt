//! FCA manifest tree-shape validation.
//!
//! See `ferrocrypt-lib/FORMAT.md` §9.7 (duplicate / collision policy)
//! and §9.8 (tree shape and canonical entry ordering).
//!
//! Each entry's `path_utf8` must already have passed
//! [`super::path::validate_fca_path`]; this module does not re-run the
//! path grammar. It checks the COLLECTIVE tree-shape invariants — single
//! top-level root, root file vs root directory shape, every non-root
//! entry's parent present, no child under a file path, no exact-
//! duplicate or ASCII-case-insensitive-duplicate paths.
//!
//! The validator is order-independent: HashMap-based parent lookup
//! means a manifest with children listed before parents validates the
//! same as canonically-ordered manifests, per FORMAT.md §9.8
//! ("Readers MUST accept any order that satisfies the manifest and
//! tree-shape rules").
//!
//! Duplicate detection runs three keys per entry: the exact path, the
//! ASCII-case-insensitive key, and the Unicode-form (NFC) key. The
//! reason reported is the first key that collides, in that order.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;

use crate::CryptoError;
use crate::error::sanitize_for_display;

use super::format::empty_archive_error;
use super::limits::{ArchiveLimits, enforce_entry_count_cap, enforce_total_plaintext_bytes_cap};
use super::model::{ArchiveEntry, ArchiveEntryKind};
use super::path::{ascii_case_collision_key, unicode_form_collision_key};
use super::reasons::{
    TREE_CHILD_UNDER_FILE, TREE_DUPLICATE_ASCII_CASE, TREE_DUPLICATE_ENTRY,
    TREE_DUPLICATE_UNICODE_FORM, TREE_MULTIPLE_ROOTS, TREE_PARENT_MISSING,
    TREE_ROOT_FILE_HAS_CHILDREN, TREE_ROOT_MISSING,
};

/// Returns the parent UTF-8 path string for a given entry path: the
/// substring before the last `/`. `None` for top-level entries (no
/// `/` in path).
pub(super) fn parent_path_utf8(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(parent, _)| parent)
}

/// Returns the top-level (first) component of a `/`-separated UTF-8
/// path. On a path without `/`, the whole path is the top-level
/// component.
fn first_component(path: &str) -> &str {
    match path.split_once('/') {
        Some((before, _)) => before,
        None => path,
    }
}

/// Builds the [`CryptoError::InvalidArchiveTree`] rejection with the
/// exposing entry path sanitized for display. Single construction
/// point so every tree-shape arm embeds the path the same way.
fn tree_error(path: &str, reason: &'static str) -> CryptoError {
    CryptoError::InvalidArchiveTree {
        path: sanitize_for_display(path),
        reason,
    }
}

/// Builds the TREE_PARENT_MISSING rejection used both when
/// `parent_path_utf8` returns `None` (top-level orphan) and when the
/// computed parent string is absent from the kinds map (intermediate
/// orphan). Same diagnostic for callers either way.
fn parent_missing(entry: &ArchiveEntry) -> CryptoError {
    tree_error(&entry.path_utf8, TREE_PARENT_MISSING)
}

/// Validates the tree shape of a parsed manifest. Returns
/// `(root_name, root_is_file, root_mode)` on success.
///
/// Caller has already validated each entry's `path_utf8` via
/// [`super::path::validate_fca_path`]; this function does not re-run
/// that grammar.
pub(super) fn validate_manifest_tree(
    entries: &[ArchiveEntry],
    total_file_bytes: u64,
    limits: ArchiveLimits,
) -> Result<(OsString, bool, u32), CryptoError> {
    if entries.is_empty() {
        return Err(empty_archive_error());
    }
    enforce_entry_count_cap(u32::try_from(entries.len()).unwrap_or(u32::MAX), &limits)?;
    enforce_total_plaintext_bytes_cap(total_file_bytes, &limits)?;

    // Root is the top-level component of the first entry. All other
    // entries must share this root. Capturing from `entries[0]`
    // up-front avoids an `Option<&str>` and an associated unwrap /
    // expect / unreachable on the loop's "non-empty by construction"
    // post-condition.
    let root = first_component(&entries[0].path_utf8);

    let mut exact: HashSet<&str> = HashSet::with_capacity(entries.len());
    let mut ascii_ci: HashSet<Vec<u8>> = HashSet::with_capacity(entries.len());
    let mut nfc_ci: HashSet<Vec<u8>> = HashSet::with_capacity(entries.len());
    let mut kinds: HashMap<&str, ArchiveEntryKind> = HashMap::with_capacity(entries.len());
    // Captured during the validation walk so the post-extraction
    // chmod step does not re-scan `entries` on every unarchive.
    let mut root_mode: Option<u32> = None;

    for entry in entries {
        if first_component(&entry.path_utf8) != root {
            return Err(tree_error(&entry.path_utf8, TREE_MULTIPLE_ROOTS));
        }

        if !exact.insert(&entry.path_utf8) {
            return Err(tree_error(&entry.path_utf8, TREE_DUPLICATE_ENTRY));
        }
        if !ascii_ci.insert(ascii_case_collision_key(&entry.path_utf8)) {
            return Err(tree_error(&entry.path_utf8, TREE_DUPLICATE_ASCII_CASE));
        }
        if !nfc_ci.insert(unicode_form_collision_key(&entry.path_utf8)) {
            return Err(tree_error(&entry.path_utf8, TREE_DUPLICATE_UNICODE_FORM));
        }
        kinds.insert(&entry.path_utf8, entry.kind);
        if entry.path_utf8 == root {
            root_mode = Some(entry.mode);
        }
    }

    let root_kind = kinds.get(root).copied();

    let root_is_file = match root_kind {
        Some(ArchiveEntryKind::File) => {
            if entries.len() != 1 {
                return Err(tree_error(root, TREE_ROOT_FILE_HAS_CHILDREN));
            }
            true
        }
        Some(ArchiveEntryKind::Directory) => {
            for entry in entries {
                if entry.path_utf8 == root {
                    continue;
                }
                let parent =
                    parent_path_utf8(&entry.path_utf8).ok_or_else(|| parent_missing(entry))?;
                match kinds.get(parent) {
                    Some(ArchiveEntryKind::Directory) => {}
                    Some(ArchiveEntryKind::File) => {
                        return Err(tree_error(&entry.path_utf8, TREE_CHILD_UNDER_FILE));
                    }
                    None => return Err(parent_missing(entry)),
                }
            }
            false
        }
        None => {
            return Err(tree_error(root, TREE_ROOT_MISSING));
        }
    };

    let root_mode = root_mode.ok_or(crate::error::internal_invariant!(
        "root entry mode missing after validation"
    ))?;

    Ok((OsString::from(root), root_is_file, root_mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> ArchiveLimits {
        ArchiveLimits::default()
    }

    use crate::archive::model::make_entry;

    fn entry(path: &str, kind: ArchiveEntryKind, size: u64) -> ArchiveEntry {
        make_entry(path, kind, size, 0o644)
    }

    /// Asserts `err` is the typed tree rejection carrying `want_reason`.
    fn assert_tree_error(err: &CryptoError, want_reason: &str) {
        match err {
            CryptoError::InvalidArchiveTree { reason, .. } => assert_eq!(*reason, want_reason),
            other => panic!("expected InvalidArchiveTree({want_reason:?}), got {other:?}"),
        }
    }

    #[test]
    fn parent_path_utf8_basic() {
        assert_eq!(parent_path_utf8("a"), None);
        assert_eq!(parent_path_utf8("a/b"), Some("a"));
        assert_eq!(parent_path_utf8("a/b/c"), Some("a/b"));
    }

    // -- Positive cases ----------------------------------------------------

    /// Single-file root: archive contains exactly one entry, a file.
    #[test]
    fn accepts_single_file_root() {
        let entries = vec![entry("hello.txt", ArchiveEntryKind::File, 100)];
        let (root, is_file, _root_mode) = validate_manifest_tree(&entries, 100, limits()).unwrap();
        assert_eq!(root, OsString::from("hello.txt"));
        assert!(is_file);
    }

    /// Single-directory root: archive contains only the root dir entry.
    #[test]
    fn accepts_root_directory_only() {
        let entries = vec![entry("emptydir", ArchiveEntryKind::Directory, 0)];
        let (root, is_file, _root_mode) = validate_manifest_tree(&entries, 0, limits()).unwrap();
        assert_eq!(root, OsString::from("emptydir"));
        assert!(!is_file);
    }

    #[test]
    fn accepts_directory_with_files() {
        let entries = vec![
            entry("photos", ArchiveEntryKind::Directory, 0),
            entry("photos/index.txt", ArchiveEntryKind::File, 50),
            entry("photos/cover.jpg", ArchiveEntryKind::File, 1024),
        ];
        let (root, is_file, _root_mode) = validate_manifest_tree(&entries, 1074, limits()).unwrap();
        assert_eq!(root, OsString::from("photos"));
        assert!(!is_file);
    }

    #[test]
    fn accepts_nested_tree() {
        let entries = vec![
            entry("root", ArchiveEntryKind::Directory, 0),
            entry("root/a", ArchiveEntryKind::Directory, 0),
            entry("root/a/b", ArchiveEntryKind::Directory, 0),
            entry("root/a/b/leaf.txt", ArchiveEntryKind::File, 42),
        ];
        let (root, is_file, _root_mode) = validate_manifest_tree(&entries, 42, limits()).unwrap();
        assert_eq!(root, OsString::from("root"));
        assert!(!is_file);
    }

    /// FORMAT.md §9.8: "Readers MUST accept any order that satisfies
    /// the manifest and tree-shape rules." Pin order-independence by
    /// listing children before parents.
    #[test]
    fn accepts_non_canonical_order() {
        let entries = vec![
            entry("root/a/b/leaf.txt", ArchiveEntryKind::File, 42),
            entry("root/a/b", ArchiveEntryKind::Directory, 0),
            entry("root/a", ArchiveEntryKind::Directory, 0),
            entry("root", ArchiveEntryKind::Directory, 0),
        ];
        let (root, is_file, _root_mode) = validate_manifest_tree(&entries, 42, limits()).unwrap();
        assert_eq!(root, OsString::from("root"));
        assert!(!is_file);
    }

    // -- Tree-shape rejections (FORMAT.md §9.8) ----------------------------

    #[test]
    fn rejects_empty_entries() {
        let entries: Vec<ArchiveEntry> = vec![];
        let err = validate_manifest_tree(&entries, 0, limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::MalformedArchive {
                reason: "no entries declared"
            }
        ));
    }

    #[test]
    fn rejects_multiple_top_level_roots() {
        let entries = vec![
            entry("a.txt", ArchiveEntryKind::File, 1),
            entry("b.txt", ArchiveEntryKind::File, 1),
        ];
        let err = validate_manifest_tree(&entries, 2, limits()).unwrap_err();
        assert_tree_error(&err, "multiple top-level roots");
    }

    #[test]
    fn rejects_root_file_with_children() {
        let entries = vec![
            entry("root", ArchiveEntryKind::File, 10),
            entry("root/child.txt", ArchiveEntryKind::File, 5),
        ];
        let err = validate_manifest_tree(&entries, 15, limits()).unwrap_err();
        assert_tree_error(&err, "root file has child entries");
    }

    /// Directory root entry missing: the archive contains
    /// `root/child.txt` but no `root` directory entry.
    #[test]
    fn rejects_missing_directory_root_entry() {
        let entries = vec![entry("root/child.txt", ArchiveEntryKind::File, 10)];
        let err = validate_manifest_tree(&entries, 10, limits()).unwrap_err();
        assert_tree_error(&err, "root entry is missing");
    }

    /// Intermediate parent directory missing: `root` and
    /// `root/a/b.txt` but no `root/a`.
    #[test]
    fn rejects_missing_intermediate_parent() {
        let entries = vec![
            entry("root", ArchiveEntryKind::Directory, 0),
            entry("root/a/b.txt", ArchiveEntryKind::File, 10),
        ];
        let err = validate_manifest_tree(&entries, 10, limits()).unwrap_err();
        assert_tree_error(&err, "parent directory is missing");
    }

    /// Child appearing under a file-typed parent.
    #[test]
    fn rejects_child_under_file() {
        let entries = vec![
            entry("root", ArchiveEntryKind::Directory, 0),
            entry("root/leaf", ArchiveEntryKind::File, 5),
            entry("root/leaf/illegal", ArchiveEntryKind::File, 1),
        ];
        let err = validate_manifest_tree(&entries, 6, limits()).unwrap_err();
        assert_tree_error(&err, "child under a file path");
    }

    #[test]
    fn rejects_exact_duplicate() {
        let entries = vec![
            entry("root", ArchiveEntryKind::Directory, 0),
            entry("root/file.txt", ArchiveEntryKind::File, 10),
            entry("root/file.txt", ArchiveEntryKind::File, 10),
        ];
        let err = validate_manifest_tree(&entries, 20, limits()).unwrap_err();
        assert_tree_error(&err, "duplicate entry");
    }

    /// Spec §9.7: paths colliding under ASCII-case-insensitive
    /// comparison are rejected at validation, not deferred to
    /// `create_new(true)` at extraction time.
    #[test]
    fn rejects_ascii_ci_duplicate() {
        let entries = vec![
            entry("root", ArchiveEntryKind::Directory, 0),
            entry("root/Foo.txt", ArchiveEntryKind::File, 10),
            entry("root/FOO.TXT", ArchiveEntryKind::File, 10),
        ];
        let err = validate_manifest_tree(&entries, 20, limits()).unwrap_err();
        assert_tree_error(&err, "duplicate entry differing only in letter case");
    }

    /// Symmetric coverage of `rejects_ascii_ci_duplicate` for
    /// directories: `Sub` and `SUB` under the same root collide via
    /// the ASCII-case-insensitive key. Pinned because the existing
    /// test only covers files.
    #[test]
    fn rejects_ascii_ci_duplicate_directories() {
        let entries = vec![
            entry("root", ArchiveEntryKind::Directory, 0),
            entry("root/Sub", ArchiveEntryKind::Directory, 0),
            entry("root/SUB", ArchiveEntryKind::Directory, 0),
        ];
        let err = validate_manifest_tree(&entries, 0, limits()).unwrap_err();
        assert_tree_error(&err, "duplicate entry differing only in letter case");
    }

    /// File-vs-directory ASCII-case collision: `root/Foo` (file) and
    /// `root/foo` (directory) collide via the ASCII-CI key even though
    /// the kinds differ. Pinned because the existing
    /// `rejects_file_directory_collision` only covers EXACT same-path
    /// collisions; this is the case-fold variant.
    #[test]
    fn rejects_ascii_ci_file_vs_directory_collision() {
        let entries = vec![
            entry("root", ArchiveEntryKind::Directory, 0),
            entry("root/Foo", ArchiveEntryKind::File, 5),
            entry("root/foo", ArchiveEntryKind::Directory, 0),
        ];
        let err = validate_manifest_tree(&entries, 5, limits()).unwrap_err();
        assert_tree_error(&err, "duplicate entry differing only in letter case");
    }

    /// Spec §9.7: two spellings of the same visible name — `é` as one
    /// composed character vs `e` plus a combining accent — collide via
    /// the Unicode-form key. Such a pair can exist on a case-sensitive
    /// filesystem but could never extract on macOS, so it is rejected
    /// at validation on both sides.
    #[test]
    fn rejects_unicode_form_duplicate() {
        let entries = vec![
            entry("root", ArchiveEntryKind::Directory, 0),
            entry("root/caf\u{e9}.txt", ArchiveEntryKind::File, 10),
            entry("root/cafe\u{301}.txt", ArchiveEntryKind::File, 10),
        ];
        let err = validate_manifest_tree(&entries, 20, limits()).unwrap_err();
        assert_tree_error(&err, "duplicate entry differing only in Unicode form");
    }

    /// ASCII case and Unicode form fold together: `Café` composed vs
    /// `cafe` plus combining accent differ in both dimensions and
    /// still collide, reported under the Unicode-form reason because
    /// the raw bytes differ beyond ASCII case.
    #[test]
    fn rejects_unicode_form_duplicate_mixed_with_ascii_case() {
        let entries = vec![
            entry("root", ArchiveEntryKind::Directory, 0),
            entry("root/Caf\u{e9}", ArchiveEntryKind::Directory, 0),
            entry("root/cafe\u{301}", ArchiveEntryKind::Directory, 0),
        ];
        let err = validate_manifest_tree(&entries, 0, limits()).unwrap_err();
        assert_tree_error(&err, "duplicate entry differing only in Unicode form");
    }

    /// An exact byte-duplicate in decomposed spelling reports plain
    /// "duplicate entry" — the exact check runs before the Unicode-form
    /// key. Pins the reason precedence.
    #[test]
    fn exact_decomposed_duplicate_reports_duplicate_entry() {
        let entries = vec![
            entry("root", ArchiveEntryKind::Directory, 0),
            entry("root/cafe\u{301}.txt", ArchiveEntryKind::File, 10),
            entry("root/cafe\u{301}.txt", ArchiveEntryKind::File, 10),
        ];
        let err = validate_manifest_tree(&entries, 20, limits()).unwrap_err();
        assert_tree_error(&err, "duplicate entry");
    }

    /// Non-ASCII letter case is deliberately not folded: `École` and
    /// `école` are visually distinct names that a case-sensitive
    /// filesystem keeps apart, so the pair stays archivable. On a
    /// filesystem that folds beyond ASCII, extraction fails closed via
    /// `create_new(true)` instead (§9.7).
    #[test]
    fn accepts_non_ascii_case_pair() {
        let entries = vec![
            entry("root", ArchiveEntryKind::Directory, 0),
            entry("root/\u{c9}cole.txt", ArchiveEntryKind::File, 10),
            entry("root/\u{e9}cole.txt", ArchiveEntryKind::File, 10),
        ];
        validate_manifest_tree(&entries, 20, limits())
            .expect("a non-ASCII case pair must stay archivable");
    }

    /// A lone decomposed name is not a collision: singleton NFD paths
    /// archive and extract unchanged, byte-exact. Only the duplicate
    /// key normalizes, never the stored path.
    #[test]
    fn accepts_singleton_decomposed_name() {
        let entries = vec![
            entry("root", ArchiveEntryKind::Directory, 0),
            entry("root/cafe\u{301}.txt", ArchiveEntryKind::File, 10),
        ];
        validate_manifest_tree(&entries, 10, limits())
            .expect("a singleton decomposed name must validate");
    }

    /// File and directory at the same path (a less-obvious collision
    /// shape than a plain duplicate). Should reject as a duplicate.
    #[test]
    fn rejects_file_directory_collision() {
        let entries = vec![
            entry("root", ArchiveEntryKind::Directory, 0),
            entry("root/x", ArchiveEntryKind::File, 10),
            entry("root/x", ArchiveEntryKind::Directory, 0),
        ];
        let err = validate_manifest_tree(&entries, 10, limits()).unwrap_err();
        assert_tree_error(&err, "duplicate entry");
    }

    #[test]
    fn rejects_total_bytes_above_cap() {
        let l = ArchiveLimits::default().max_total_plaintext_bytes(100);
        let entries = vec![entry("file.txt", ArchiveEntryKind::File, 50)];
        let err = validate_manifest_tree(&entries, 200, l).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::ArchiveTotalBytesCapExceeded { .. }
        ));
    }

    #[test]
    fn rejects_entry_count_above_cap() {
        let l = ArchiveLimits::default().max_entry_count(1);
        let entries = vec![
            entry("root", ArchiveEntryKind::Directory, 0),
            entry("root/a.txt", ArchiveEntryKind::File, 10),
        ];
        let err = validate_manifest_tree(&entries, 10, l).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::ArchiveEntryCountCapExceeded { .. }
        ));
    }
}
