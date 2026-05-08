//! FCA archive reader: header + `archive_ext` + manifest parse, full
//! validation, then content extraction via the hardened cap-std
//! platform backend.
//!
//! See `FORMAT.md` §9 (FCA wire format), §9.11 (reader/extractor
//! sequence), §9.14 (extensibility rules).
//!
//! The extraction pipeline follows FORMAT.md §9.11:
//! 1. parse and validate the FCA fixed header
//! 2. read exactly `archive_ext_len` bytes
//! 3. validate the archive-level TLV region (no-known-critical policy)
//! 4. read exactly `manifest_len` bytes
//! 5. parse manifest entries (each `entry_ext` region scanned and
//!    validated under the same no-known-critical policy)
//! 6. validate every per-entry TLV region
//! 7. validate the complete manifest (entry count, total bytes, paths,
//!    duplicates, tree shape, parents present, resource caps, critical
//!    extension support)
//! 8. pre-check the final output name with `symlink_metadata`
//! 9. reject pre-existing `.incomplete` at first create
//! 10. create `{root}.incomplete` (file or directory) under the
//!     hardened cap-std backend
//! 11. stream file contents in manifest order via `copy_exact_n`
//! 12. apply file modes by handle where supported
//! 13. verify archive EOF (no trailing bytes)
//! 14. apply descendant directory modes deepest-first
//! 15. promote `{root}.incomplete` to `{root}` via no-clobber rename
//! 16. apply the root directory's stored mode AFTER promotion (macOS
//!     compatibility — see FORMAT.md §9.11)
//! 17. return the final output path
//!
//! Steps 1–8 MUST complete before any filesystem output is created.
//! On error before promotion, the [`IncompleteOutputPolicy`] selects
//! whether the staged `.incomplete` working tree is removed
//! (`DeleteOnError`, default) or retained (`RetainOnError`).

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use cap_std::fs::Dir;

use crate::CryptoError;
use crate::crypto::tlv::validate_no_known_critical;
use crate::fs::atomic::rename_no_clobber;
use crate::fs::paths::{INCOMPLETE_SUFFIX, reject_occupied};

use super::IncompleteOutputPolicy;
use super::format::{copy_exact_n, parse_fca_header, parse_manifest_bytes, require_fits_usize};
use super::limits::ArchiveLimits;
use super::model::{ArchiveEntry, ArchiveEntryKind, Manifest};
use super::path::canonical_path_order;
use super::platform;

/// Public entry point. Parses an FCA payload from `reader`, fully
/// validates it before any output is created, and extracts the archive
/// under `output_dir`. Returns the final output path on success.
///
/// On error before final promotion, applies `policy` to the staged
/// `.incomplete` working tree.
pub(crate) fn unarchive<R: Read>(
    reader: R,
    output_dir: &Path,
    limits: ArchiveLimits,
    policy: IncompleteOutputPolicy,
) -> Result<PathBuf, CryptoError> {
    let mut created_incomplete_roots: Vec<OsString> = Vec::new();

    let result = unarchive_inner(reader, output_dir, limits, &mut created_incomplete_roots);

    if result.is_err() && matches!(policy, IncompleteOutputPolicy::DeleteOnError) {
        for root_name in &created_incomplete_roots {
            let working_path = output_dir.join(incomplete_working_name(root_name));
            cleanup_incomplete_path(&working_path);
        }
    }

    result
}

fn unarchive_inner<R: Read>(
    mut reader: R,
    output_dir: &Path,
    limits: ArchiveLimits,
    created_incomplete_roots: &mut Vec<OsString>,
) -> Result<PathBuf, CryptoError> {
    // FORMAT.md §9.11 step 1: parse + structurally validate the header.
    // `parse_fca_header` already enforces all caps for `archive_ext_len`,
    // `manifest_len`, and `total_file_bytes`.
    let header = parse_fca_header(&mut reader, limits)?;

    // §9.11 steps 2–3: read exactly `archive_ext_len` bytes and validate
    // the archive-level TLV region under the no-known-critical policy.
    // v1 defines no archive-level TLV tags; v1 writers emit
    // `archive_ext_len = 0`, so this is normally a zero-length read,
    // but a v1.x writer may legitimately emit ignorable tags.
    let archive_ext_len = require_fits_usize(header.archive_ext_len, "Archive extension length")?;
    let mut archive_ext_bytes = vec![0u8; archive_ext_len];
    reader.read_exact(&mut archive_ext_bytes)?;
    validate_no_known_critical(
        &archive_ext_bytes,
        limits.max_archive_ext_bytes,
        limits.max_tlv_value_bytes,
    )?;

    // §9.11 step 4: read exactly `manifest_len` bytes.
    let manifest_len = require_fits_usize(header.manifest_len, "Archive manifest length")?;
    let mut manifest_bytes = vec![0u8; manifest_len];
    reader.read_exact(&mut manifest_bytes)?;

    // §9.11 steps 5–7: parse manifest entries (including each
    // `entry_ext` region; `parse_manifest_bytes` validates every
    // per-entry TLV under the no-known-critical policy) and validate
    // the manifest tree shape.
    let manifest = parse_manifest_bytes(&manifest_bytes, header, limits)?;

    // §16.1 step 5: `symlink_metadata` (via `reject_occupied`) so a
    // dangling symlink at the final name is treated as occupied.
    let final_path = output_dir.join(&manifest.root_name);
    reject_occupied(&final_path, "Output")?;

    // §16.1 step 6.
    let output_handle = platform::open_anchor(output_dir)?;
    let incomplete_name = incomplete_working_name(&manifest.root_name);

    // §16.1 steps 7–11. Each `extract_*_root` runs `verify_archive_eof`
    // (step 10) between content streaming (step 9) and descendant
    // chmod (step 11) so the spec's literal ordering is preserved.
    if manifest.root_is_file {
        extract_single_file_root(
            &mut reader,
            &output_handle,
            &incomplete_name,
            &manifest,
            created_incomplete_roots,
            output_dir,
        )?;
    } else {
        extract_directory_root(
            &mut reader,
            &output_handle,
            &incomplete_name,
            &manifest,
            created_incomplete_roots,
            output_dir,
        )?;
    }

    // Drop the cap-std handles before the path-based rename. The
    // `output_handle` borrow ends here; descendant `Dir`/`File` handles
    // were already dropped at scope exit inside `extract_*_root`.
    drop(output_handle);

    // §16.1 step 12: promote {root}.incomplete → {root} with no-clobber
    // semantics. A racing attacker who creates the final name between
    // the step-5 pre-check and now is rejected here.
    let working_path = output_dir.join(&incomplete_name);
    rename_no_clobber(&working_path, &final_path).map_err(|e| {
        map_already_exists(CryptoError::Io(e), "Output already exists", &final_path)
    })?;

    // §16.1 step 13: apply root directory mode AFTER promotion. macOS
    // can refuse to rename a directory whose mode lacks search
    // permission, so the root .incomplete stayed at the initial 0o700
    // (search-permitted owner-only) mode through extraction. Re-anchor
    // at output_dir and walk to the renamed root via `open_dir_at_rel`,
    // which routes through `open_dir_nofollow` + Windows reparse-point
    // post-check — a symlink substituted at the final name between
    // rename and chmod is rejected here.
    if !manifest.root_is_file {
        apply_root_directory_mode(output_dir, &manifest)?;
    }

    Ok(final_path)
}

fn extract_single_file_root<R: Read>(
    reader: &mut R,
    output_handle: &Dir,
    incomplete_name: &OsStr,
    manifest: &Manifest,
    created_incomplete_roots: &mut Vec<OsString>,
    output_dir: &Path,
) -> Result<(), CryptoError> {
    debug_assert_eq!(manifest.entries.len(), 1);
    let entry = &manifest.entries[0];
    debug_assert_eq!(entry.kind, ArchiveEntryKind::File);

    let mut outfile = platform::create_file_at(
        output_handle,
        incomplete_name,
        platform::INITIAL_FILE_CREATE_MODE,
    )
    .map_err(|e| {
        map_already_exists(
            CryptoError::Io(e),
            "Previous .incomplete exists",
            &output_dir.join(incomplete_name),
        )
    })?;
    // create_file_at succeeded — this run owns the staging file.
    created_incomplete_roots.push(manifest.root_name.clone());

    copy_exact_n(reader, &mut outfile, entry.size)?;
    platform::chmod_file_handle(&outfile, entry.mode)?;

    // §16.1 step 10: verify archive EOF — no byte may follow the last
    // declared file content. Single-file root has no descendant chmod
    // pass, so this directly precedes the caller's rename (step 12).
    verify_archive_eof(reader)
}

fn extract_directory_root<R: Read>(
    reader: &mut R,
    output_handle: &Dir,
    incomplete_name: &OsStr,
    manifest: &Manifest,
    created_incomplete_roots: &mut Vec<OsString>,
    output_dir: &Path,
) -> Result<(), CryptoError> {
    let root_name_str = manifest_root_name_str(manifest)?;

    let root_dir = platform::mkdir_strict(output_handle, incomplete_name).map_err(|e| {
        map_already_exists(
            e,
            "Previous .incomplete exists",
            &output_dir.join(incomplete_name),
        )
    })?;
    // mkdir_strict succeeded — this run owns the staging directory.
    created_incomplete_roots.push(manifest.root_name.clone());

    // Pass 1: pre-create all descendant directories sorted by depth
    // ascending (parent before child). Spec §16.3 SHOULD; we MUST do
    // this to support content streaming under any manifest order.
    let mut dir_entries: Vec<&ArchiveEntry> = manifest
        .entries
        .iter()
        .filter(|e| e.kind == ArchiveEntryKind::Directory && e.path_utf8 != root_name_str)
        .collect();
    dir_entries.sort_by(|a, b| canonical_path_order(&a.path_utf8, &b.path_utf8));
    for dir_entry in &dir_entries {
        let rel = strip_root_prefix(&dir_entry.path_utf8, root_name_str)?;
        let (parent_dir, dir_name) = platform::walk_to_parent(&root_dir, rel)?;
        let _new_dir = platform::mkdir_strict(&parent_dir, &dir_name)?;
    }

    // Pass 2: stream file contents in MANIFEST ORDER. The content
    // region is laid out in manifest order, so this pass MUST visit
    // file entries in the same order as the writer emitted them.
    for entry in &manifest.entries {
        if entry.kind != ArchiveEntryKind::File {
            continue;
        }
        let rel = strip_root_prefix(&entry.path_utf8, root_name_str)?;
        let (parent_dir, file_name) = platform::walk_to_parent(&root_dir, rel)?;
        let mut outfile =
            platform::create_file_at(&parent_dir, &file_name, platform::INITIAL_FILE_CREATE_MODE)?;
        copy_exact_n(reader, &mut outfile, entry.size)?;
        platform::chmod_file_handle(&outfile, entry.mode)?;
    }

    // §16.1 step 10: verify archive EOF — no byte may follow the last
    // declared file content. Runs BEFORE Pass 3 (descendant chmod) per
    // the spec's literal step ordering.
    verify_archive_eof(reader)?;

    // Pass 3 / §16.1 step 11: apply descendant directory modes
    // deepest-first. Spec §16.3: restrictive parent modes would block
    // child creation, so chmod must run AFTER child writes complete.
    // Root directory mode is applied AFTER the rename (see
    // `apply_root_directory_mode`). `dir_entries` is already sorted
    // ascending by Pass 1; iterating in reverse yields the
    // depth-descending order Pass 3 needs.
    for dir_entry in dir_entries.iter().rev() {
        let rel = strip_root_prefix(&dir_entry.path_utf8, root_name_str)?;
        let dir_handle = platform::open_dir_at_rel(&root_dir, rel)?;
        platform::chmod_dir_handle(dir_handle, dir_entry.mode)?;
    }

    // root_dir is dropped here, closing the cap-std handle so the
    // path-based rename in the caller can proceed.
    Ok(())
}

fn apply_root_directory_mode(output_dir: &Path, manifest: &Manifest) -> Result<(), CryptoError> {
    let root_name_str = manifest_root_name_str(manifest)?;
    let root_entry = manifest
        .entries
        .iter()
        .find(|e| e.path_utf8 == root_name_str)
        .ok_or(CryptoError::InternalInvariant(
            "Root entry missing from validated manifest",
        ))?;
    let output_handle = platform::open_anchor(output_dir)?;
    let root_dir = platform::open_dir_at_rel(&output_handle, Path::new(root_name_str))?;
    platform::chmod_dir_handle(root_dir, root_entry.mode)
}

/// Spec §14.11: rejects any non-EOF byte after the last declared file
/// content. The `?` on `read` threads `StreamError` markers from the
/// underlying decrypt stream through `From<io::Error> for CryptoError`
/// so an authentication / truncation / extra-data signal surfaces as
/// the typed `CryptoError::Payload*` variant rather than as a generic
/// archive error.
fn verify_archive_eof<R: Read>(reader: &mut R) -> Result<(), CryptoError> {
    let mut b = [0u8; 1];
    match reader.read(&mut b) {
        Ok(0) => Ok(()),
        Ok(_) => Err(CryptoError::InvalidInput(
            "Trailing data after archive file contents".to_string(),
        )),
        Err(e) => Err(CryptoError::from(e)),
    }
}

/// Builds the `{root}.incomplete` working name used to stage extraction
/// so plaintext is never visible under the final name during a partial
/// run. Borrows so it accepts both `OsString` and `OsStr` arguments.
fn incomplete_working_name(root_name: &OsStr) -> OsString {
    let mut name = root_name.to_os_string();
    name.push(INCOMPLETE_SUFFIX);
    name
}

/// Best-effort removal of an `.incomplete` working path. Errors at any
/// step are swallowed so the caller surfaces the original failure
/// rather than a cleanup-related I/O error.
fn cleanup_incomplete_path(path: &Path) {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };
    if meta.file_type().is_symlink() {
        let _ = fs::remove_file(path);
    } else if meta.is_dir() {
        let _ = fs::remove_dir_all(path);
    } else {
        let _ = fs::remove_file(path);
    }
}

/// Maps `io::ErrorKind::AlreadyExists` to a typed
/// `CryptoError::InvalidInput("<label>: <path>")` and otherwise
/// preserves the underlying error. Used at both staging boundaries
/// — first-touch `mkdir_strict` / `create_file_at` rejects a stale
/// `.incomplete` from a prior failed run with a recognisable
/// diagnostic AND preserves it (the cleanup path tracks only roots
/// THIS run created), and the final-rename promotion rejects a
/// racing actor that creates the final name between the step-5
/// pre-check and the rename.
fn map_already_exists(e: CryptoError, label: &str, path: &Path) -> CryptoError {
    if let CryptoError::Io(io_err) = &e {
        if io_err.kind() == io::ErrorKind::AlreadyExists {
            return CryptoError::InvalidInput(format!("{}: {}", label, path.display()));
        }
    }
    e
}

fn manifest_root_name_str(manifest: &Manifest) -> Result<&str, CryptoError> {
    manifest
        .root_name
        .to_str()
        .ok_or(CryptoError::InternalInvariant(
            "Manifest root_name is not valid UTF-8",
        ))
}

/// Strips the `{root_name}/` prefix from an entry path and returns
/// the rel-to-root path ready for the platform helpers. Validation
/// has already verified every non-root entry begins with
/// `{root_name}/`, so a missing prefix here is an internal invariant
/// violation. Returning `&Path` directly saves every call site from
/// wrapping the result with `Path::new(rel)` before passing to
/// `walk_to_parent` / `open_dir_at_rel`.
fn strip_root_prefix<'a>(path_utf8: &'a str, root_name: &str) -> Result<&'a Path, CryptoError> {
    path_utf8
        .strip_prefix(root_name)
        .and_then(|rest| rest.strip_prefix('/'))
        .map(Path::new)
        .ok_or(CryptoError::InternalInvariant(
            "Manifest entry missing expected root prefix",
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::format::{serialize_manifest, write_fca_header};
    use std::io::Cursor;

    // -- Test fixtures -----------------------------------------------------

    use crate::archive::model::make_entry;
    use crate::crypto::tlv::tlv_bytes;

    /// Serializes the FCA header + manifest bytes into a fresh
    /// `Vec<u8>`, ready for the caller to append a file-content
    /// region (full per `build_archive`, partial per
    /// `build_partial_archive`).
    fn build_archive_prefix(manifest: &Manifest) -> Vec<u8> {
        build_archive_prefix_with_archive_ext(manifest, &[])
    }

    /// Same as [`build_archive_prefix`] but lets a test inject a
    /// synthetic `archive_ext` region between the fixed header and
    /// the manifest. Used by adversarial-input tests that exercise
    /// the archive-level TLV validation path.
    fn build_archive_prefix_with_archive_ext(manifest: &Manifest, archive_ext: &[u8]) -> Vec<u8> {
        let manifest_bytes = serialize_manifest(manifest, ArchiveLimits::default()).unwrap();
        let entry_count = u32::try_from(manifest.entries.len()).unwrap();
        let archive_ext_len = u32::try_from(archive_ext.len()).unwrap();
        let manifest_len = u32::try_from(manifest_bytes.len()).unwrap();

        let mut archive = Vec::new();
        let _ = write_fca_header(
            &mut archive,
            entry_count,
            archive_ext_len,
            manifest_len,
            manifest.total_file_bytes,
        )
        .unwrap();
        archive.extend_from_slice(archive_ext);
        archive.extend_from_slice(&manifest_bytes);
        archive
    }

    /// Builds a complete FCA archive byte sequence: header + serialized
    /// manifest + file contents in manifest order. `file_contents` maps
    /// path → bytes; every file entry in the manifest must have a
    /// corresponding entry. Total bytes must match the manifest's
    /// `total_file_bytes`.
    fn build_archive(manifest: &Manifest, file_contents: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = build_archive_prefix(manifest);

        let contents: std::collections::HashMap<&str, &[u8]> =
            file_contents.iter().copied().collect();

        for entry in &manifest.entries {
            if entry.kind == ArchiveEntryKind::File {
                let content = contents
                    .get(entry.path_utf8.as_str())
                    .expect("test fixture missing file content");
                assert_eq!(entry.size as usize, content.len(), "size/content mismatch");
                archive.extend_from_slice(content);
            }
        }

        archive
    }

    /// Builds an archive whose declared file-content region is shorter
    /// than `manifest.total_file_bytes`. Used by tests that drive
    /// `unarchive` through the truncation path — the reader rejects
    /// partway and the caller asserts on the staged-output state.
    fn build_partial_archive(manifest: &Manifest, content_bytes: &[u8]) -> Vec<u8> {
        let mut archive = build_archive_prefix(manifest);
        archive.extend_from_slice(content_bytes);
        archive
    }

    fn single_file_manifest(path: &str, content: &[u8]) -> Manifest {
        Manifest {
            entries: vec![make_entry(
                path,
                ArchiveEntryKind::File,
                content.len() as u64,
                0o644,
            )],
            total_file_bytes: content.len() as u64,
            root_name: OsString::from(path),
            root_is_file: true,
        }
    }

    /// Manifest used by both `IncompleteOutputPolicy` tests: a `root/`
    /// dir holding a 100-byte `a.bin`. Paired with
    /// `build_partial_archive(&manifest, b"short")` to drive a
    /// truncation that the reader rejects partway through extraction.
    fn dir_with_one_undersized_file_manifest() -> Manifest {
        Manifest {
            entries: vec![
                make_entry("root", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("root/a.bin", ArchiveEntryKind::File, 100, 0o644),
            ],
            total_file_bytes: 100,
            root_name: OsString::from("root"),
            root_is_file: false,
        }
    }

    /// Wraps `unarchive` with the test-default limits and the supplied
    /// policy so each test reads as one expressive line instead of a
    /// six-line constructor.
    fn unarchive_with_policy(
        archive: Vec<u8>,
        tmp: &Path,
        policy: IncompleteOutputPolicy,
    ) -> Result<PathBuf, CryptoError> {
        unarchive(Cursor::new(archive), tmp, ArchiveLimits::default(), policy)
    }

    /// `unarchive_with_policy` specialised to the default
    /// [`IncompleteOutputPolicy::DeleteOnError`].
    fn unarchive_default(archive: Vec<u8>, tmp: &Path) -> Result<PathBuf, CryptoError> {
        unarchive_with_policy(archive, tmp, IncompleteOutputPolicy::DeleteOnError)
    }

    // -- Positive round-trip tests (§19.1) ---------------------------------

    #[test]
    fn round_trip_single_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let archive = build_archive(&manifest, &[("hello.txt", b"Hello, world!")]);

        let final_path = unarchive_default(archive, tmp.path()).unwrap();

        assert_eq!(final_path, tmp.path().join("hello.txt"));
        assert_eq!(fs::read(&final_path).unwrap(), b"Hello, world!");
    }

    #[test]
    fn round_trip_empty_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("empty.txt", b"");
        let archive = build_archive(&manifest, &[("empty.txt", b"")]);

        let final_path = unarchive_default(archive, tmp.path()).unwrap();
        assert_eq!(fs::read(&final_path).unwrap(), b"");
    }

    #[test]
    fn round_trip_directory_with_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = Manifest {
            entries: vec![
                make_entry("photos", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("photos/index.txt", ArchiveEntryKind::File, 5, 0o644),
                make_entry("photos/cover.jpg", ArchiveEntryKind::File, 7, 0o644),
            ],
            total_file_bytes: 12,
            root_name: OsString::from("photos"),
            root_is_file: false,
        };
        let archive = build_archive(
            &manifest,
            &[
                ("photos/index.txt", b"hello"),
                ("photos/cover.jpg", b"jpegjpe"),
            ],
        );

        let final_path = unarchive_default(archive, tmp.path()).unwrap();

        assert!(final_path.is_dir());
        assert_eq!(fs::read(final_path.join("index.txt")).unwrap(), b"hello");
        assert_eq!(fs::read(final_path.join("cover.jpg")).unwrap(), b"jpegjpe");
    }

    #[test]
    fn round_trip_empty_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = Manifest {
            entries: vec![make_entry(
                "emptydir",
                ArchiveEntryKind::Directory,
                0,
                0o755,
            )],
            total_file_bytes: 0,
            root_name: OsString::from("emptydir"),
            root_is_file: false,
        };
        let archive = build_archive(&manifest, &[]);

        let final_path = unarchive_default(archive, tmp.path()).unwrap();
        assert!(final_path.is_dir());
        assert_eq!(fs::read_dir(&final_path).unwrap().count(), 0);
    }

    #[test]
    fn round_trip_nested_directory_tree() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = Manifest {
            entries: vec![
                make_entry("root", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("root/a", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("root/a/b", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("root/a/b/leaf.txt", ArchiveEntryKind::File, 4, 0o644),
            ],
            total_file_bytes: 4,
            root_name: OsString::from("root"),
            root_is_file: false,
        };
        let archive = build_archive(&manifest, &[("root/a/b/leaf.txt", b"deep")]);

        let final_path = unarchive_default(archive, tmp.path()).unwrap();
        assert_eq!(
            fs::read(final_path.join("a").join("b").join("leaf.txt")).unwrap(),
            b"deep"
        );
    }

    /// Spec §10: readers MUST accept any manifest order satisfying the
    /// tree shape. Pin order-independence by listing children before
    /// parents in the manifest. The content region is still in
    /// manifest order, so the reader's two-pass extraction (pre-create
    /// dirs by depth, then stream files in manifest order) handles
    /// this correctly.
    #[test]
    fn round_trip_non_canonical_manifest_order() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = Manifest {
            entries: vec![
                make_entry("root/a/b/leaf.txt", ArchiveEntryKind::File, 4, 0o644),
                make_entry("root/a/b", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("root/a", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("root", ArchiveEntryKind::Directory, 0, 0o755),
            ],
            total_file_bytes: 4,
            root_name: OsString::from("root"),
            root_is_file: false,
        };
        let archive = build_archive(&manifest, &[("root/a/b/leaf.txt", b"deep")]);

        let final_path = unarchive_default(archive, tmp.path()).unwrap();
        assert_eq!(
            fs::read(final_path.join("a").join("b").join("leaf.txt")).unwrap(),
            b"deep"
        );
    }

    #[test]
    fn round_trip_multiple_files_exact_boundaries() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = Manifest {
            entries: vec![
                make_entry("d", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("d/a.bin", ArchiveEntryKind::File, 10, 0o644),
                make_entry("d/b.bin", ArchiveEntryKind::File, 0, 0o644),
                make_entry("d/c.bin", ArchiveEntryKind::File, 5, 0o644),
            ],
            total_file_bytes: 15,
            root_name: OsString::from("d"),
            root_is_file: false,
        };
        let archive = build_archive(
            &manifest,
            &[
                ("d/a.bin", b"AAAAAAAAAA"),
                ("d/b.bin", b""),
                ("d/c.bin", b"CCCCC"),
            ],
        );

        let final_path = unarchive_default(archive, tmp.path()).unwrap();
        assert_eq!(fs::read(final_path.join("a.bin")).unwrap(), b"AAAAAAAAAA");
        assert_eq!(fs::read(final_path.join("b.bin")).unwrap(), b"");
        assert_eq!(fs::read(final_path.join("c.bin")).unwrap(), b"CCCCC");
    }

    // -- Archive-level TLV rejections (FORMAT.md §9.3) ---------------------

    /// `archive_ext` accepts a non-empty ignorable TLV region: the
    /// reader skips the bytes after canonicality checks and
    /// extraction proceeds normally. Pin so a future refactor that
    /// over-tightens the no-known-critical wrapper doesn't reject
    /// ignorable v1.x metadata.
    #[test]
    fn round_trip_with_ignorable_archive_ext() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let ignorable = tlv_bytes(0x0001, b"meta");
        let mut archive = build_archive_prefix_with_archive_ext(&manifest, &ignorable);
        archive.extend_from_slice(b"Hello, world!");

        let final_path = unarchive_default(archive, tmp.path()).unwrap();
        assert_eq!(fs::read(&final_path).unwrap(), b"Hello, world!");
    }

    /// An unknown critical TLV (`0x8001..=0xFFFF`) in `archive_ext`
    /// rejects with `UnknownCriticalTag` BEFORE any filesystem output
    /// is created. v1 defines no archive-level critical tags.
    #[test]
    fn rejects_unknown_critical_archive_ext_tag() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let critical = tlv_bytes(0x8001, &[]);
        let mut archive = build_archive_prefix_with_archive_ext(&manifest, &critical);
        archive.extend_from_slice(b"Hello, world!");

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        assert!(format!("{err:?}").contains("UnknownCriticalTag"));
        // No filesystem output was created.
        let count = fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(count, 0);
    }

    /// A malformed `archive_ext` TLV (truncated entry header) rejects
    /// via `MalformedTlv` from the shared scanner. Five raw bytes —
    /// one short of the six-byte `tag(u16) || len(u32)` minimum, so
    /// the scanner exits its bounds check before parsing the tag.
    #[test]
    fn rejects_malformed_archive_ext_tlv() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let mut truncated = tlv_bytes(0x0001, &[]);
        truncated.pop();
        let mut archive = build_archive_prefix_with_archive_ext(&manifest, &truncated);
        archive.extend_from_slice(b"Hello, world!");

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        assert!(format!("{err:?}").contains("MalformedTlv"));
    }

    // -- Content-region rejections (§19.5) ---------------------------------

    #[test]
    fn rejects_short_file_content() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let archive = build_partial_archive(&manifest, b"short");

        let err = unarchive_default(archive, tmp.path()).unwrap_err();

        let s = format!("{err}");
        assert!(
            s.contains("shorter than declared") || matches!(err, CryptoError::Io(_)),
            "got: {s}",
        );
    }

    #[test]
    fn rejects_trailing_data_after_last_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let mut archive = build_archive(&manifest, &[("hello.txt", b"Hello, world!")]);
        archive.push(0xAA);

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        assert!(format!("{err}").contains("Trailing data"));
    }

    // -- IncompleteOutputPolicy semantics ----------------------------------

    /// `DeleteOnError` removes the staged `.incomplete` after a failed
    /// extraction, so the output_dir is empty.
    #[test]
    fn delete_on_error_removes_incomplete() {
        let tmp = tempfile::TempDir::new().unwrap();
        let archive = build_partial_archive(&dir_with_one_undersized_file_manifest(), b"short");

        let result =
            unarchive_with_policy(archive, tmp.path(), IncompleteOutputPolicy::DeleteOnError);
        assert!(result.is_err());

        let count = fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(count, 0, "DeleteOnError must clean up .incomplete");
    }

    /// `RetainOnError` keeps the staged `.incomplete` for inspection.
    #[test]
    fn retain_on_error_keeps_incomplete() {
        let tmp = tempfile::TempDir::new().unwrap();
        let archive = build_partial_archive(&dir_with_one_undersized_file_manifest(), b"short");

        let result =
            unarchive_with_policy(archive, tmp.path(), IncompleteOutputPolicy::RetainOnError);
        assert!(result.is_err());

        let incomplete = tmp.path().join("root.incomplete");
        assert!(
            incomplete.exists(),
            "RetainOnError must preserve .incomplete"
        );
    }

    // -- Pre-existing output / .incomplete ---------------------------------

    #[test]
    fn rejects_pre_existing_final_output() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(tmp.path().join("hello.txt"), b"existing").unwrap();

        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let archive = build_archive(&manifest, &[("hello.txt", b"Hello, world!")]);

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        assert!(format!("{err}").contains("Output already exists"));
    }

    /// A pre-existing `.incomplete` from a previous failed run MUST
    /// reject AND MUST be preserved (not cleaned up by DeleteOnError),
    /// because this run did not create it.
    #[test]
    fn rejects_pre_existing_incomplete_and_preserves_it() {
        let tmp = tempfile::TempDir::new().unwrap();
        let stale_path = tmp.path().join("hello.txt.incomplete");
        fs::write(&stale_path, b"stale plaintext from earlier run").unwrap();

        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let archive = build_archive(&manifest, &[("hello.txt", b"Hello, world!")]);

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        assert!(format!("{err}").contains("Previous .incomplete exists"));
        assert!(
            stale_path.exists(),
            "pre-existing .incomplete must be preserved across a retry",
        );
    }

    // -- Security invariant ------------------------------------------------

    /// Spec §16.1 steps 1–5 MUST complete before any filesystem output
    /// is created. Pin this by feeding a manifest that fails tree
    /// validation (multiple top-level roots) and asserting the output
    /// directory is untouched.
    #[test]
    fn invalid_manifest_creates_no_filesystem_output() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = Manifest {
            entries: vec![
                make_entry("a.txt", ArchiveEntryKind::File, 1, 0o644),
                make_entry("b.txt", ArchiveEntryKind::File, 1, 0o644),
            ],
            total_file_bytes: 2,
            root_name: OsString::from("a.txt"),
            root_is_file: true,
        };
        let archive = build_partial_archive(&manifest, b"AB");

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        // Either the multi-root rejection from validate_manifest_tree
        // or any earlier rejection fires before any output is created.
        assert!(
            format!("{err}").contains("multiple top-level roots") || result_is_format_error(&err),
            "got: {err}"
        );

        let count = fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(
            count, 0,
            "no filesystem output may exist when the manifest is invalid",
        );
    }

    fn result_is_format_error(err: &CryptoError) -> bool {
        matches!(err, CryptoError::InvalidInput(_))
    }

    // -- §19.7 filesystem hardening ----------------------------------------

    /// Spec §16.1 step 5: pre-check uses `symlink_metadata`, so a
    /// dangling symlink at the final output name is treated as
    /// occupied. `Path::exists()` would follow the link and report
    /// false, masking the conflict; we MUST reject before any
    /// extraction work runs.
    #[cfg(unix)]
    #[test]
    fn rejects_dangling_symlink_at_final_output() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("absent-target");
        let link = tmp.path().join("hello.txt");
        symlink(&target, &link).unwrap();
        assert!(
            !link.exists(),
            "test setup: symlink target must be absent (dangling)"
        );

        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let archive = build_archive(&manifest, &[("hello.txt", b"Hello, world!")]);

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        assert!(format!("{err}").contains("Output already exists"));

        // Dangling symlink must still be there — extraction was rejected
        // BEFORE any output was created, including overwriting the link.
        assert!(
            fs::symlink_metadata(&link).is_ok(),
            "dangling symlink must be preserved across rejected extraction",
        );
    }

    /// Spec §16.3: directory chmod runs deepest-first AFTER all child
    /// entries are created, AND the root directory's stored mode is
    /// applied AFTER `.incomplete` → final rename. This single test
    /// pins both properties at once: a root dir with mode 0o400
    /// (no execute / no search) is created with restrictive permissions
    /// only after children land. If chmod-before-children leaked, this
    /// would fail on file creation. If root-mode-before-rename leaked,
    /// this would fail on rename (macOS) or set the wrong mode.
    #[cfg(unix)]
    #[test]
    fn extracts_with_restrictive_root_and_parent_modes() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = Manifest {
            entries: vec![
                // 0o400 root: no execute/search/write — exercises the
                // post-rename root-chmod path on macOS.
                make_entry("locked", ArchiveEntryKind::Directory, 0, 0o400),
                make_entry("locked/child", ArchiveEntryKind::Directory, 0, 0o700),
                make_entry("locked/child/secret.txt", ArchiveEntryKind::File, 6, 0o600),
            ],
            total_file_bytes: 6,
            root_name: OsString::from("locked"),
            root_is_file: false,
        };
        let archive = build_archive(&manifest, &[("locked/child/secret.txt", b"secret")]);

        let final_path = unarchive_default(archive, tmp.path()).unwrap();

        let root_mode = fs::metadata(&final_path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(
            root_mode, 0o400,
            "root mode 0o400 must be applied (post-rename), got 0o{root_mode:o}",
        );

        // Restore search permission so we can inspect descendants
        // and tempdir cleanup can remove them. If chmod-deepest-first
        // ordering had been wrong, the unarchive call would have
        // failed before we got here.
        fs::set_permissions(&final_path, fs::Permissions::from_mode(0o700)).unwrap();

        let child_mode = fs::metadata(final_path.join("child"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(child_mode, 0o700);
        assert_eq!(
            fs::read(final_path.join("child").join("secret.txt")).unwrap(),
            b"secret",
        );
    }
}
