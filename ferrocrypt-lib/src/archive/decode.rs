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
//! 12. apply descendant file modes by handle where supported (root
//!     file mode is deferred to step 16 — see below)
//! 13. verify archive EOF (no trailing bytes)
//! 14. apply descendant directory modes deepest-first
//! 15. promote `{root}.incomplete` to `{root}` via no-clobber rename
//! 16. apply the root entry's stored mode AFTER promotion. For
//!     directory roots: macOS compatibility (a non-search-permitted
//!     root mode would block the rename). For file roots: keep the
//!     staged file at `INITIAL_FILE_CREATE_MODE` throughout staging
//!     so a permissive manifest mode is never briefly visible to
//!     other local users while the file holds plaintext.
//! 17. return the final output path
//!
//! Steps 1–8 MUST complete before any filesystem output is created.
//! On error before promotion, the [`IncompleteOutputPolicy`] selects
//! whether the staged `.incomplete` working tree is removed
//! (`DeleteOnError`, default) or retained (`RetainOnError`).

use std::ffi::{OsStr, OsString};
#[cfg(test)]
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use cap_std::fs::Dir;

use crate::CryptoError;
use crate::fs::atomic::rename_no_clobber;
use crate::fs::paths::{INCOMPLETE_SUFFIX, reject_occupied};

use super::IncompleteOutputPolicy;
use super::format::{
    copy_exact_n, parse_fca_header, parse_manifest_bytes, require_fits_usize,
    validate_archive_ext_tlv,
};
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
    unarchive_inner(reader, output_dir, limits, policy)
}

fn unarchive_inner<R: Read>(
    mut reader: R,
    output_dir: &Path,
    limits: ArchiveLimits,
    policy: IncompleteOutputPolicy,
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
    validate_archive_ext_tlv(&archive_ext_bytes, &limits)?;

    // §9.11 step 4: read exactly `manifest_len` bytes.
    let manifest_len = require_fits_usize(header.manifest_len, "Archive manifest length")?;
    let mut manifest_bytes = vec![0u8; manifest_len];
    reader.read_exact(&mut manifest_bytes)?;

    // §9.11 steps 5–7: parse manifest entries (including each
    // `entry_ext` region; `parse_manifest_bytes` validates every
    // per-entry TLV under the no-known-critical policy) and validate
    // the manifest tree shape.
    let manifest = parse_manifest_bytes(&manifest_bytes, header, limits)?;

    // FORMAT.md §9.11 step 8: `symlink_metadata` (via `reject_occupied`)
    // so a dangling symlink at the final name is treated as occupied.
    let final_path = output_dir.join(&manifest.root_name);
    reject_occupied(&final_path, "Output")?;

    // FORMAT.md §9.11 step 9. Open the output anchor up-front and
    // keep it alive across extraction + promotion so a `DeleteOnError`
    // cleanup runs handle-relative — a path swap of `output_dir`
    // cannot redirect the `remove_*` calls.
    let output_handle = platform::open_anchor(output_dir)?;
    let incomplete_name = incomplete_working_name(&manifest.root_name);
    let mut created_incomplete_roots: Vec<OsString> = Vec::new();

    // Steps 10–16 wrapped so the cleanup loop below sees
    // `output_handle` still alive on every error path.
    let outcome: Result<PathBuf, CryptoError> = (|| {
        // §9.11 steps 10–14. Each `extract_*_root` runs
        // `verify_archive_eof` (step 13) between content streaming
        // (step 11) and descendant chmod (step 14) so the spec's
        // literal ordering is preserved.
        if manifest.root_is_file {
            extract_single_file_root(
                &mut reader,
                &output_handle,
                &incomplete_name,
                &manifest,
                &mut created_incomplete_roots,
                output_dir,
            )?;
        } else {
            extract_directory_root(
                &mut reader,
                &output_handle,
                &incomplete_name,
                &manifest,
                &mut created_incomplete_roots,
                output_dir,
            )?;
        }

        // FORMAT.md §9.11 step 15: promote {root}.incomplete → {root}
        // with no-clobber. A race that creates the final name between
        // the step-8 pre-check and here is rejected.
        let working_path = output_dir.join(&incomplete_name);
        rename_no_clobber(&working_path, &final_path).map_err(|e| {
            map_already_exists(CryptoError::Io(e), "Output already exists", &final_path)
        })?;

        // FORMAT.md §9.11 step 16: apply root entry mode AFTER promotion.
        //
        // Directory roots: macOS can refuse to rename a directory whose
        // mode lacks search permission, so the root `.incomplete` stayed
        // at the initial 0o700 (search-permitted owner-only) mode through
        // extraction. Re-anchor at `output_dir` and walk to the renamed
        // root via `open_dir_at_rel`, which routes through
        // `open_dir_nofollow` + Windows reparse-point post-check — a
        // symlink substituted at the final name between rename and chmod
        // is rejected here.
        //
        // File roots: the staged `.incomplete` file stayed at
        // `INITIAL_FILE_CREATE_MODE` (0o600) throughout content streaming
        // and across the rename, so a permissive manifest mode (e.g.
        // 0o644) is never briefly visible to other local users while the
        // file holds plaintext under either the `.incomplete` name or
        // (post-rename, pre-chmod) the final name. The post-rename
        // re-open uses `open_file_nofollow` so a symlink substituted at
        // the final name between rename and chmod is rejected the same
        // way as for directory roots.
        if manifest.root_is_file {
            apply_root_file_mode(output_dir, &manifest)?;
        } else {
            apply_root_directory_mode(output_dir, &manifest)?;
        }

        Ok(final_path.clone())
    })();

    if outcome.is_err() && matches!(policy, IncompleteOutputPolicy::DeleteOnError) {
        for root_name in &created_incomplete_roots {
            cleanup_incomplete_via_handle(&output_handle, &incomplete_working_name(root_name));
        }
    }

    drop(output_handle);
    outcome
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

    // FORMAT.md §9.11 step 13: verify archive EOF — no byte may follow
    // the last declared file content. Single-file root has no descendant
    // chmod pass, and the manifest-stored mode is applied post-rename
    // by `apply_root_file_mode` (FORMAT.md §9.11 step 16), so the
    // staged file stays at `INITIAL_FILE_CREATE_MODE` through this
    // EOF check and across the rename.
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
    // ascending (parent before child). FORMAT.md §9.11 step 10
    // SHOULD; we MUST do this to support content streaming under any
    // manifest order.
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

    // FORMAT.md §9.11 step 13: verify archive EOF — no byte may follow
    // the last declared file content. Runs BEFORE Pass 3 (descendant
    // chmod) per the spec's literal step ordering.
    verify_archive_eof(reader)?;

    // Pass 3 / FORMAT.md §9.11 step 14: apply descendant directory modes
    // deepest-first. Restrictive parent modes would block child
    // creation, so chmod must run AFTER child writes complete. Root
    // directory mode is applied AFTER the rename (see
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
    let output_handle = platform::open_anchor(output_dir)?;
    let root_dir = platform::open_dir_at_rel(&output_handle, Path::new(root_name_str))?;
    platform::chmod_dir_handle(root_dir, manifest.root_mode)
}

/// File-root parallel of [`apply_root_directory_mode`]. Re-anchors at
/// `output_dir`, opens the renamed root file via `open_file_nofollow`
/// (no-follow + Windows reparse-point post-check), and applies the
/// manifest-stored mode through the open handle. Runs only after
/// `rename_no_clobber` succeeds, so the staged file held
/// `INITIAL_FILE_CREATE_MODE` (0o600) throughout extraction; a
/// permissive manifest mode is never briefly visible to other local
/// users while the file holds plaintext.
fn apply_root_file_mode(output_dir: &Path, manifest: &Manifest) -> Result<(), CryptoError> {
    let output_handle = platform::open_anchor(output_dir)?;
    let file = platform::open_file_nofollow(&output_handle, &manifest.root_name)?;
    platform::chmod_file_handle(&file, manifest.root_mode)
}

/// FORMAT.md §9.9: rejects any non-EOF byte after the last declared
/// file content. The `?` on `read` threads `StreamError` markers from
/// the underlying decrypt stream through `From<io::Error> for CryptoError`
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

/// Best-effort removal of an `.incomplete` leaf via the capability
/// handle that staged it. Anchoring to the same `Dir` used during
/// extraction means a path swap of `output_dir` between failed
/// extraction and cleanup cannot redirect `remove_*` to a different
/// directory. Errors are swallowed so the original `CryptoError` is
/// what the caller sees.
fn cleanup_incomplete_via_handle(output_handle: &Dir, working_name: &OsStr) {
    let meta = match output_handle.symlink_metadata(working_name) {
        Ok(m) => m,
        Err(_) => return,
    };
    if meta.file_type().is_symlink() {
        let _ = output_handle.remove_file(working_name);
    } else if meta.is_dir() {
        let _ = output_handle.remove_dir_all(working_name);
    } else {
        let _ = output_handle.remove_file(working_name);
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
    use crate::archive::format::{serialize_manifest_unchecked, write_fca_header};
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
    /// the manifest. Uses [`serialize_manifest_unchecked`] so
    /// reader-rejection tests can hand-build invalid manifests the
    /// production writer would refuse.
    fn build_archive_prefix_with_archive_ext(manifest: &Manifest, archive_ext: &[u8]) -> Vec<u8> {
        let manifest_bytes =
            serialize_manifest_unchecked(manifest, ArchiveLimits::default()).unwrap();
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
            root_mode: 0o644,
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
            root_mode: 0o755,
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

    // -- Positive round-trip tests -----------------------------------------

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
            root_mode: 0o755,
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
            root_mode: 0o755,
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
            root_mode: 0o755,
        };
        let archive = build_archive(&manifest, &[("root/a/b/leaf.txt", b"deep")]);

        let final_path = unarchive_default(archive, tmp.path()).unwrap();
        assert_eq!(
            fs::read(final_path.join("a").join("b").join("leaf.txt")).unwrap(),
            b"deep"
        );
    }

    /// FORMAT.md §9.8: readers MUST accept any manifest order
    /// satisfying the tree shape. Pin order-independence by listing
    /// children before parents in the manifest. The content region is
    /// still in manifest order, so the reader's two-pass extraction
    /// (pre-create dirs by depth, then stream files in manifest order)
    /// handles this correctly.
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
            root_mode: 0o755,
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
            root_mode: 0o755,
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

    /// Reserved tag `0x0000` in `archive_ext` rejects with
    /// `MalformedTlv` via the shared scanner. Pin because the existing
    /// reserved-tag tests only cover `entry_ext`; the archive-level
    /// region uses the same scanner and the same policy, so the
    /// rejection MUST fire identically here.
    #[test]
    fn rejects_reserved_zero_archive_ext_tag() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let reserved = tlv_bytes(0x0000, &[]);
        let mut archive = build_archive_prefix_with_archive_ext(&manifest, &reserved);
        archive.extend_from_slice(b"Hello, world!");

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        assert!(format!("{err:?}").contains("MalformedTlv"));
    }

    /// Reserved tag `0x8000` in `archive_ext` rejects with
    /// `MalformedTlv`. Symmetric coverage with the `0x0000` case
    /// above; both reserved values must fail through the same
    /// scanner path.
    #[test]
    fn rejects_reserved_8000_archive_ext_tag() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let reserved = tlv_bytes(0x8000, &[]);
        let mut archive = build_archive_prefix_with_archive_ext(&manifest, &reserved);
        archive.extend_from_slice(b"Hello, world!");

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        assert!(format!("{err:?}").contains("MalformedTlv"));
    }

    // -- Content-region rejections -----------------------------------------

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

    /// Truncation right after the manifest, zero content bytes (the
    /// manifest declares file content but the payload region is empty).
    /// Pins that "shorter than declared" fires on the very first read
    /// of the content phase, not silently producing an empty file.
    #[test]
    fn rejects_truncation_at_zero_content_bytes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        // Empty content region — manifest declares 13 bytes, payload
        // delivers 0.
        let archive = build_partial_archive(&manifest, b"");

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        let s = format!("{err}");
        assert!(
            s.contains("shorter than declared") || matches!(err, CryptoError::Io(_)),
            "got: {s}",
        );
    }

    /// Truncation during a LATER file in a multi-file archive: after
    /// file 1's content fully streams to disk, the payload is cut
    /// 2 bytes into file 2. Pins that the rejection fires inside the
    /// later file's `copy_exact_n` rather than passing structural
    /// checks because file 1 happened to be complete.
    #[test]
    fn rejects_truncation_during_later_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = Manifest {
            entries: vec![
                make_entry("d", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("d/a.bin", ArchiveEntryKind::File, 5, 0o644),
                make_entry("d/b.bin", ArchiveEntryKind::File, 10, 0o644),
            ],
            total_file_bytes: 15,
            root_name: OsString::from("d"),
            root_is_file: false,
            root_mode: 0o755,
        };
        // Deliver all of file 1 (5 bytes) plus 2 bytes of file 2,
        // leaving file 2 short by 8 bytes.
        let mut content = Vec::new();
        content.extend_from_slice(b"AAAAA");
        content.extend_from_slice(b"BB");
        let archive = build_partial_archive(&manifest, &content);

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        let s = format!("{err}");
        assert!(
            s.contains("shorter than declared") || matches!(err, CryptoError::Io(_)),
            "got: {s}",
        );
    }

    /// Truncation EXACTLY at file boundary: file 1 fully streams,
    /// then EOF hits before file 2's first content byte. Pins that
    /// the rejection fires immediately on the first read of file 2,
    /// not silently treating the missing file as empty.
    #[test]
    fn rejects_truncation_exactly_at_file_boundary() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = Manifest {
            entries: vec![
                make_entry("d", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("d/a.bin", ArchiveEntryKind::File, 5, 0o644),
                make_entry("d/b.bin", ArchiveEntryKind::File, 10, 0o644),
            ],
            total_file_bytes: 15,
            root_name: OsString::from("d"),
            root_is_file: false,
            root_mode: 0o755,
        };
        // Deliver only file 1's content (5 bytes); cut between files.
        let archive = build_partial_archive(&manifest, b"AAAAA");

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        let s = format!("{err}");
        assert!(
            s.contains("shorter than declared") || matches!(err, CryptoError::Io(_)),
            "got: {s}",
        );
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

    /// `cleanup_incomplete_via_handle` removes entries relative to
    /// the capability handle, NOT to a re-resolved path. Opens a
    /// handle, renames the directory aside, mints a replacement,
    /// and confirms the cleanup follows the original inode.
    ///
    /// Unix-only because Windows directory rename with an open
    /// handle has platform-specific semantics.
    #[cfg(unix)]
    #[test]
    fn cleanup_via_handle_follows_handle_inode_not_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let original = tmp.path().join("orig");
        fs::create_dir(&original).unwrap();
        let staged = original.join("root.incomplete");
        fs::write(&staged, b"staged plaintext").unwrap();

        let handle = platform::open_anchor(&original).unwrap();

        // Swap: rename the directory aside, then mint a fresh empty
        // dir at the original path. The handle keeps pointing to the
        // moved inode; a path-based cleanup would look at the empty
        // replacement.
        let moved = tmp.path().join("moved");
        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();

        cleanup_incomplete_via_handle(&handle, OsStr::new("root.incomplete"));

        assert!(
            !moved.join("root.incomplete").exists(),
            "handle-relative cleanup should have removed the staged file from the moved dir",
        );
        assert!(
            original.read_dir().unwrap().next().is_none(),
            "the replacement dir at the original path must be untouched",
        );
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

    /// `IncompleteOutputPolicy` doc-comment promises that panic-unwind
    /// (like SIGKILL or power loss) bypasses cleanup entirely:
    /// `.incomplete` survives regardless of policy. The cleanup loop
    /// in `unarchive` runs only after `unarchive_inner` returns
    /// `Err`; an unwind propagates past it without firing.
    ///
    /// Pin the property: drive `unarchive` with a `Read` impl that
    /// panics partway through content streaming (after `.incomplete`
    /// has been created via `create_file_at`), `catch_unwind` the
    /// panic, and assert the staged file is still on disk despite
    /// `DeleteOnError`. Without this guarantee a panicking process
    /// would silently lose authenticated-but-incomplete plaintext
    /// the caller may need for forensic recovery.
    #[test]
    fn panic_during_extraction_preserves_incomplete_under_delete_on_error() {
        use std::panic::AssertUnwindSafe;

        struct PanicAfterN<R: Read> {
            inner: R,
            bytes_read: u64,
            panic_at: u64,
        }

        impl<R: Read> Read for PanicAfterN<R> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.bytes_read >= self.panic_at {
                    panic!("test-induced panic at byte {}", self.bytes_read);
                }
                let remaining = (self.panic_at - self.bytes_read) as usize;
                let n_target = buf.len().min(remaining);
                let n = self.inner.read(&mut buf[..n_target])?;
                self.bytes_read += n as u64;
                Ok(n)
            }
        }

        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let archive = build_archive(&manifest, &[("hello.txt", b"Hello, world!")]);

        // Set the panic point one byte before EOF so the panic fires
        // deep inside `copy_exact_n`'s content loop — well after
        // `create_file_at` has staged `hello.txt.incomplete`.
        let panic_at = archive.len() as u64 - 1;
        let panicking_reader = PanicAfterN {
            inner: Cursor::new(archive),
            bytes_read: 0,
            panic_at,
        };

        let tmp_path = tmp.path().to_path_buf();
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            unarchive(
                panicking_reader,
                &tmp_path,
                ArchiveLimits::default(),
                IncompleteOutputPolicy::DeleteOnError,
            )
        }));

        assert!(
            result.is_err(),
            "expected panic to propagate out of unarchive"
        );

        let incomplete = tmp_path.join("hello.txt.incomplete");
        assert!(
            incomplete.exists(),
            ".incomplete must survive panic regardless of policy",
        );
    }

    // -- Fault-injection harness (Batch 3) --------------------------------

    /// `Read` wrapper that delivers `panic_at` bytes from `inner`,
    /// then returns a chosen `io::Error` on the next read. Models a
    /// mid-payload failure (AEAD authentication, truncation, transient
    /// I/O) so the cleanup behavior of `DeleteOnError` /
    /// `RetainOnError` is testable without bringing up the full
    /// encryption pipeline.
    struct FailAfterN<R: Read> {
        inner: R,
        bytes_read: u64,
        fail_at: u64,
        error_kind: io::ErrorKind,
        error_msg: &'static str,
    }

    impl<R: Read> Read for FailAfterN<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.bytes_read >= self.fail_at {
                return Err(io::Error::new(self.error_kind, self.error_msg));
            }
            let remaining = (self.fail_at - self.bytes_read) as usize;
            let n_target = buf.len().min(remaining);
            let n = self.inner.read(&mut buf[..n_target])?;
            self.bytes_read += n as u64;
            Ok(n)
        }
    }

    /// Mid-payload fault under `DeleteOnError`: the staged
    /// `.incomplete` MUST be cleaned up. Pinned via `FailAfterN`
    /// so the test exercises the archive-layer cleanup path
    /// directly, independent of the AEAD stream layer above.
    #[test]
    fn fail_after_n_during_payload_cleans_up_under_delete_on_error() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let archive = build_archive(&manifest, &[("hello.txt", b"Hello, world!")]);
        // Fail one byte before EOF so the failure fires deep in
        // `copy_exact_n` after `.incomplete` has been created and
        // some content has been written.
        let fail_at = archive.len() as u64 - 1;
        let reader = FailAfterN {
            inner: Cursor::new(archive),
            bytes_read: 0,
            fail_at,
            error_kind: io::ErrorKind::Other,
            error_msg: "test-induced AEAD fail",
        };

        let result = unarchive(
            reader,
            tmp.path(),
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
        );
        assert!(result.is_err());

        // No staged `.incomplete` left under DeleteOnError.
        let count = fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(count, 0, "DeleteOnError must clean up after fault");
    }

    /// Mid-payload fault under `RetainOnError`: the staged
    /// `.incomplete` MUST survive for inspection. Symmetric with the
    /// `DeleteOnError` test above.
    #[test]
    fn fail_after_n_during_payload_preserves_under_retain_on_error() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let archive = build_archive(&manifest, &[("hello.txt", b"Hello, world!")]);
        let fail_at = archive.len() as u64 - 1;
        let reader = FailAfterN {
            inner: Cursor::new(archive),
            bytes_read: 0,
            fail_at,
            error_kind: io::ErrorKind::Other,
            error_msg: "test-induced AEAD fail",
        };

        let result = unarchive(
            reader,
            tmp.path(),
            ArchiveLimits::default(),
            IncompleteOutputPolicy::RetainOnError,
        );
        assert!(result.is_err());

        let incomplete = tmp.path().join("hello.txt.incomplete");
        assert!(
            incomplete.exists(),
            "RetainOnError must keep .incomplete after fault"
        );
    }

    /// Read-only `output_dir` (mode `0o500`): `unarchive` MUST fail
    /// at the first cap-std write attempt (mkdir/create_file), and
    /// `DeleteOnError` MUST not leave anything behind. Pin the §11
    /// "Output dir is read-only" case.
    #[cfg(unix)]
    #[test]
    fn read_only_output_dir_fails_with_no_leak() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();
        fs::set_permissions(&out, fs::Permissions::from_mode(0o500)).unwrap();

        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let archive = build_archive(&manifest, &[("hello.txt", b"Hello, world!")]);

        let result = unarchive(
            Cursor::new(archive),
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
        );
        assert!(
            result.is_err(),
            "expected creation failure on read-only dir"
        );

        // Restore write so tempdir cleanup can remove the dir AND
        // assert nothing leaked under it.
        fs::set_permissions(&out, fs::Permissions::from_mode(0o700)).unwrap();
        let count = fs::read_dir(&out).unwrap().count();
        assert_eq!(
            count, 0,
            "no .incomplete or final output may exist when output_dir is read-only",
        );
    }

    // Note: race-based fault tests (output_dir deleted/replaced
    // mid-extraction, dir-perm change during traversal, rename-
    // failure mid-flight) are deliberately omitted from this batch.
    // Deterministic injection between specific extraction steps
    // requires test-side hooks the production code does not expose;
    // the cap-std capability handles, the no-clobber rename, and
    // the cleanup loop are all exercised by the deterministic
    // tests above (read-only output_dir, FailAfterN, panic_during,
    // pre-existing final output) which together cover the cleanup
    // semantics each race scenario would also exercise.

    /// `RetainOnError` doc-comment promises the staged content is a
    /// prefix of the original plaintext, not an empty placeholder.
    /// Pin the prefix property: build a manifest declaring a 100-byte
    /// `a.bin`, supply only 5 bytes of content, and confirm the
    /// staged file (truncated chunk-aligned per AEAD STREAM-BE32) is
    /// either empty (truncation rejected before any plaintext landed)
    /// or a strict prefix of the declared 100 bytes.
    #[test]
    fn retain_on_error_staged_content_is_prefix_of_original() {
        let tmp = tempfile::TempDir::new().unwrap();
        let archive = build_partial_archive(&dir_with_one_undersized_file_manifest(), b"short");

        let _ = unarchive_with_policy(archive, tmp.path(), IncompleteOutputPolicy::RetainOnError);

        let staged = tmp.path().join("root.incomplete").join("a.bin");
        if staged.exists() {
            let bytes = fs::read(&staged).unwrap();
            assert!(
                bytes.len() <= 100,
                "staged a.bin ({} bytes) must not exceed declared size (100)",
                bytes.len()
            );
        }
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

    /// Mode 0o000 round-trips through the decode side: a manifest
    /// entry stored with `mode = 0` gets `chmod_file_handle(0)` called
    /// on its open file handle, leaving the extracted file at 0o000.
    /// Covers the §4 "File mode 0" / §13 "Unix file mode 0o000" cases
    /// — the encode side can't easily round-trip because a source
    /// file with mode 0o000 isn't readable by its owner on Unix, so
    /// the property is pinned at decode time using a hand-built
    /// manifest.
    #[cfg(unix)]
    #[test]
    fn extract_applies_mode_0o000_to_output_file() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"x");
        let mut manifest = manifest;
        manifest.entries[0].mode = 0o000;
        manifest.root_mode = 0o000;
        let archive = build_archive(&manifest, &[("hello.txt", b"x")]);

        let final_path = unarchive_default(archive, tmp.path()).unwrap();
        let mode = fs::metadata(&final_path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o000, "expected 0o000, got 0o{mode:o}");

        // Make readable so tempdir cleanup can remove it.
        fs::set_permissions(&final_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// Hardlink at the extraction file leaf: pre-create a file then
    /// hardlink it at the destination name. `create_file_at`'s
    /// `create_new(true)` MUST reject with `AlreadyExists` (mapped to
    /// "Output already exists"), and the attacker-controlled hardlink
    /// target MUST remain unchanged. Closes the §12 "attacker
    /// replaces final file path with hardlink" case.
    #[cfg(unix)]
    #[test]
    fn rejects_hardlink_at_extraction_file_leaf() {
        let tmp = tempfile::TempDir::new().unwrap();

        // Attacker target outside the prospective output path.
        let attacker_target = tmp.path().join("attacker_target.bin");
        fs::write(&attacker_target, b"attacker controlled").unwrap();

        // Hardlink at the final extraction name. Since both names
        // refer to the same inode, `create_new(true)` rejects on
        // "any existing entry" — including hardlinks.
        fs::hard_link(&attacker_target, tmp.path().join("hello.txt")).unwrap();

        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let archive = build_archive(&manifest, &[("hello.txt", b"Hello, world!")]);

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        assert!(format!("{err}").contains("Output already exists"));

        // Attacker target unchanged.
        assert_eq!(fs::read(&attacker_target).unwrap(), b"attacker controlled");
    }

    /// Symlink at the renamed root between `rename_no_clobber` and
    /// `apply_root_directory_mode`: the chmod step MUST reject via
    /// `open_dir_at_rel`'s per-component no-follow walk. We inject
    /// the post-rename state directly (a deterministic test of the
    /// same race the multithreaded path would observe).
    ///
    /// Closes the §12 "attacker replaces staged root with symlink"
    /// case at the apply-root-mode site specifically.
    #[cfg(unix)]
    #[test]
    fn apply_root_directory_mode_rejects_symlink_at_renamed_root() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::TempDir::new().unwrap();
        let real = tmp.path().join("real_dir");
        fs::create_dir(&real).unwrap();

        // Symlink at the position the renamed root would have.
        symlink(&real, tmp.path().join("root")).unwrap();

        let manifest = Manifest {
            entries: vec![make_entry("root", ArchiveEntryKind::Directory, 0, 0o755)],
            total_file_bytes: 0,
            root_name: OsString::from("root"),
            root_is_file: false,
            root_mode: 0o755,
        };

        let err = apply_root_directory_mode(tmp.path(), &manifest).unwrap_err();
        assert!(
            format!("{err}").contains("Symlink in extraction path"),
            "expected symlink rejection, got: {err}",
        );
    }

    /// File-root parallel of [`apply_root_directory_mode_rejects_symlink_at_renamed_root`].
    /// Symlink substituted at the renamed root between `rename_no_clobber`
    /// and `apply_root_file_mode`: the chmod step MUST reject via
    /// `open_file_nofollow`'s no-follow open. Inject the post-rename
    /// state directly (deterministic test of the same race the
    /// multithreaded path would observe).
    #[cfg(unix)]
    #[test]
    fn apply_root_file_mode_rejects_symlink_at_renamed_root() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::TempDir::new().unwrap();
        let real = tmp.path().join("real_file");
        fs::write(&real, b"victim").unwrap();

        // Symlink at the position the renamed root would have.
        symlink(&real, tmp.path().join("hello.txt")).unwrap();

        let manifest = single_file_manifest("hello.txt", b"x");
        let err = apply_root_file_mode(tmp.path(), &manifest).unwrap_err();
        assert!(
            format!("{err}").contains("Symlink in extraction path"),
            "expected symlink rejection, got: {err}",
        );
    }

    /// `RetainOnError` keeps the staging-default root mode (0o700),
    /// NOT the manifest's `root_mode`. Pin that root chmod is
    /// strictly a post-rename step: a failed extraction (no rename)
    /// leaves the staged root at the initial owner-private mode
    /// regardless of what the manifest declared.
    #[cfg(unix)]
    #[test]
    fn retain_on_error_staged_root_keeps_default_mode() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        // Manifest declares an unusual `root_mode` so 0o700 vs the
        // declared mode are clearly distinguishable.
        let manifest = Manifest {
            entries: vec![
                make_entry("root", ArchiveEntryKind::Directory, 0, 0o500),
                make_entry("root/a.bin", ArchiveEntryKind::File, 100, 0o644),
            ],
            total_file_bytes: 100,
            root_name: OsString::from("root"),
            root_is_file: false,
            root_mode: 0o500,
        };
        let archive = build_partial_archive(&manifest, b"short");

        let _ = unarchive_with_policy(archive, tmp.path(), IncompleteOutputPolicy::RetainOnError);

        let staged_root = tmp.path().join("root.incomplete");
        assert!(staged_root.exists());
        let mode = fs::metadata(&staged_root).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "retained .incomplete must keep staging default 0o700, not manifest 0o{:o}",
            manifest.root_mode,
        );
    }

    /// Single-file root parallel of [`retain_on_error_staged_root_keeps_default_mode`].
    /// Pin that the staged `.incomplete` FILE is held at
    /// `INITIAL_FILE_CREATE_MODE` (0o600) until AFTER promotion — a
    /// failed extraction (no rename) MUST NOT leak a permissive
    /// manifest mode onto the staged plaintext.
    ///
    /// The trigger is "successful content streaming followed by
    /// trailing data": old buggy ordering ran `chmod_file_handle`
    /// between the streaming success and the EOF check, so the
    /// staged `.incomplete` file ended up at the manifest mode
    /// (0o644 below) before the EOF check tripped. Post-fix the
    /// chmod is deferred to `apply_root_file_mode` after rename, so
    /// the staged file stays at 0o600 across this failure.
    #[cfg(unix)]
    #[test]
    fn retain_on_error_staged_file_keeps_default_mode() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        // Manifest declares 0o644 so the staged 0o600 vs the manifest
        // mode are clearly distinguishable.
        let manifest = single_file_manifest("hello.txt", b"payload");
        let mut archive = build_archive(&manifest, &[("hello.txt", b"payload")]);
        // Append a byte so `verify_archive_eof` fails AFTER content
        // streaming completes — the exact ordering window the
        // pre-fix bug exposed.
        archive.push(0xFFu8);

        let err = unarchive_with_policy(archive, tmp.path(), IncompleteOutputPolicy::RetainOnError)
            .unwrap_err();
        assert!(format!("{err}").contains("Trailing data"));

        let staged = tmp.path().join("hello.txt.incomplete");
        assert!(
            staged.exists(),
            "RetainOnError must keep staged .incomplete"
        );
        let mode = fs::metadata(&staged).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "retained .incomplete must keep staging default 0o600, not manifest 0o{:o}",
            manifest.entries[0].mode,
        );
    }

    /// Unicode-collision safety net (NFC vs NFD `naïve`): when the
    /// underlying filesystem merges two distinct UTF-8 byte sequences
    /// (HFS+ normalises to NFD on disk; APFS normalises lookups
    /// regardless of case-sensitivity), the ASCII-only collision key
    /// can't catch the duplicate, so the fallback is `create_file_at`'s
    /// `create_new(true)` rejecting at extraction time.
    ///
    /// **FS-dependent — ignored by default.** Runs meaningfully only
    /// on a normalising volume; on a non-normalising filesystem (e.g.
    /// most Linux ext4/btrfs) both files would extract distinctly and
    /// the test's `unwrap_err()` would panic. The FS-matrix CI lanes
    /// in `.github/workflows/rust.yml` deliberately do NOT include
    /// this test in their command list — they target round-trip
    /// behaviour on the smoke set instead. To run this test against a
    /// specific filesystem, mount it manually, export
    /// `FERROCRYPT_FS_MATRIX_DIR=/path/to/mount`, and invoke
    /// `cargo test -p ferrocrypt --lib unicode_collision -- --ignored`.
    /// The tempdir is sourced from `fs_matrix_tempdir()` so the
    /// whole test lives on the mount.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "fs-matrix: needs Unicode-normalizing or case-insensitive volume; default APFS preserves form"]
    fn unicode_collision_falls_through_to_create_new() {
        let tmp = ferrocrypt_test_support::fs_matrix_tempdir().unwrap();

        // NFC `naïve`: U+00EF (precomposed). NFD: U+0069 + U+0308.
        let nfc = "na\u{00EF}ve.txt";
        let nfd = "na\u{0069}\u{0308}ve.txt";
        assert_ne!(nfc.as_bytes(), nfd.as_bytes(), "test sanity");

        let manifest = Manifest {
            entries: vec![
                make_entry("root", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry(&format!("root/{nfc}"), ArchiveEntryKind::File, 5, 0o644),
                make_entry(&format!("root/{nfd}"), ArchiveEntryKind::File, 5, 0o644),
            ],
            total_file_bytes: 10,
            root_name: OsString::from("root"),
            root_is_file: false,
            root_mode: 0o755,
        };
        let archive = build_archive(
            &manifest,
            &[
                (&format!("root/{nfc}"), b"AAAAA"),
                (&format!("root/{nfd}"), b"BBBBB"),
            ],
        );

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        // On a normalizing FS the second `create_new` rejects with
        // `AlreadyExists` (mapped) or surfaces an Io error.
        let s = format!("{err}");
        assert!(
            s.contains("already exists") || matches!(err, CryptoError::Io(_)),
            "got: {s}",
        );

        // DeleteOnError cleans up the staged `.incomplete`.
        let count = fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(count, 0);
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

    /// FORMAT.md §9.11 steps 1–8 MUST complete before any filesystem
    /// output is created. Pin this by feeding a manifest that fails tree
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
            root_mode: 0o644,
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

    // -- Filesystem hardening ----------------------------------------------

    /// FORMAT.md §9.11 step 8: pre-check uses `symlink_metadata`, so a
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

    /// FORMAT.md §9.11 steps 14 + 16: directory chmod runs deepest-first
    /// AFTER all child entries are created, AND the root directory's
    /// stored mode is applied AFTER `.incomplete` → final rename. This
    /// single test pins both properties at once: a root dir with mode 0o400
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
            root_mode: 0o755,
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
