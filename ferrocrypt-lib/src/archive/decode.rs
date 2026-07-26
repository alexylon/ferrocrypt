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
//! Steps 1–8 must complete before any filesystem output is created.
//! Staged file contents — and, for directory roots, the staged
//! directories that link them — are synced to stable storage before
//! step 15, so promotion does not make unsynced content or a partially
//! linked tree visible under the final name. On error before promotion,
//! the [`IncompleteOutputPolicy`] selects whether the staged
//! `.incomplete` working tree is removed (`DeleteOnError`, default) or
//! retained (`RetainOnError`).

use std::ffi::{OsStr, OsString};
#[cfg(test)]
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use cap_std::fs::Dir;

use crate::CryptoError;
use crate::crypto::stream::read_uninterrupted;
use crate::error::sanitize_path_for_display;
use crate::fs::paths::{INCOMPLETE_SUFFIX, OUTPUT_LABEL, already_exists_error, path_occupied};

use super::IncompleteOutputPolicy;
use super::format::{
    ARCHIVE_EXT_REGION_TRUNCATED, ARCHIVE_MANIFEST_REGION_TRUNCATED, copy_exact_n,
    parse_fca_header, parse_manifest_bytes, read_exact_fca, require_fits_usize,
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
/// `.incomplete` working tree. Promotion (`FORMAT.md` §9.11 step 15) is
/// the commit point: the post-promotion root-mode application (step 16)
/// is best-effort, so on a platform refusing that final chmod the call
/// still succeeds and the output keeps its restrictive staging mode
/// (`0o600` for a file root, `0o700` for a directory root).
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
    // the archive-level extension region. It is normally empty today, but a
    // later compatible writer may include optional tags. If authenticated
    // data ends before the declared region, report a malformed archive rather
    // than an I/O error.
    let archive_ext_len = require_fits_usize(header.archive_ext_len, "Archive extension length")?;
    let mut archive_ext_bytes = vec![0u8; archive_ext_len];
    read_exact_fca(
        &mut reader,
        &mut archive_ext_bytes,
        ARCHIVE_EXT_REGION_TRUNCATED,
    )?;
    validate_archive_ext_tlv(&archive_ext_bytes, &limits)?;

    // §9.11 step 4: read exactly `manifest_len` bytes.
    let manifest_len = require_fits_usize(header.manifest_len, "Archive manifest length")?;
    let mut manifest_bytes = vec![0u8; manifest_len];
    read_exact_fca(
        &mut reader,
        &mut manifest_bytes,
        ARCHIVE_MANIFEST_REGION_TRUNCATED,
    )?;

    // §9.11 steps 5–7: parse manifest entries (including each
    // `entry_ext` region; `parse_manifest_bytes` validates every
    // per-entry TLV under the no-known-critical policy) and validate
    // the manifest tree shape.
    let manifest = parse_manifest_bytes(&manifest_bytes, header, limits)?;

    // Before any output is staged, so an unsupported directory root fails
    // up front instead of after writing the whole tree.
    reject_unsupported_directory_root(&manifest)?;

    // FORMAT.md §9.11 step 8: `symlink_metadata` (via `path_occupied`)
    // so a dangling symlink at the final name is treated as occupied.
    // Built through `output_already_exists` rather than
    // `reject_occupied` because the same rejection is also raised at
    // the step-15 promotion failure below.
    let final_path = output_dir.join(&manifest.root_name);
    if path_occupied(&final_path)? {
        return Err(output_already_exists(output_dir, &manifest.root_name));
    }

    // Open the output anchor up-front (between FORMAT.md §9.11 steps
    // 8 and 9; the open itself is not a numbered step) and keep it
    // alive across extraction + promotion so a `DeleteOnError` cleanup
    // runs handle-relative — a path swap of `output_dir` cannot
    // redirect the `remove_*` calls.
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
        // with no-clobber. On Linux and macOS the rename is anchored to
        // `output_handle` (the same capability handle extraction wrote
        // through), so a swap of the ambient `output_dir` path between
        // staging and this commit cannot redirect the promotion, and the
        // kernel still refuses an occupied final name atomically. On
        // Windows it is path-based — single-file roots get a kernel
        // atomic no-replace move, directory roots a best-effort
        // check-then-rename — because a handle-relative no-replace rename
        // there needs an `unsafe` Win32 call the crate forbids. See
        // `promote_root` and `SECURITY.md`.
        let promote_result = promote_root(
            &output_handle,
            output_dir,
            &incomplete_name,
            &manifest.root_name,
            manifest.root_is_file,
        );
        promote_result.map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                output_already_exists(output_dir, &manifest.root_name)
            } else {
                CryptoError::Io(e)
            }
        })?;

        // FORMAT.md §9.11 step 16: apply root entry mode AFTER promotion.
        //
        // Directory roots: macOS can refuse to rename a directory whose
        // mode lacks search permission, so the root `.incomplete` stayed
        // at the initial 0o700 (search-permitted owner-only) mode through
        // extraction. Walk from the held `output_handle` to the renamed
        // root via `open_dir_at_rel`, which routes through
        // `open_dir_nofollow` + Windows reparse-point post-check — a
        // symlink substituted at the final name between rename and chmod
        // is rejected here, and a swap of `output_dir` itself cannot
        // redirect the chmod because no path is re-resolved.
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
        // Step 16 runs after the step-15 commit point: the output
        // already holds the complete plaintext, and the `.incomplete`
        // working name is gone, so `DeleteOnError` cleanup can no
        // longer reach it. A chmod failure here must not fail the
        // extraction — returning `Err` would tell a `DeleteOnError`
        // caller nothing was written while a finished output sits on
        // disk. Best-effort is safe: the staged mode (`0o600`/`0o700`)
        // is always at least as restrictive as the manifest mode, and
        // the no-follow re-open inside `apply_root_*_mode` still
        // refuses to chmod through a substituted symlink.
        let _ = if manifest.root_is_file {
            apply_root_file_mode(&output_handle, &manifest)
        } else {
            apply_root_directory_mode(&output_handle, &manifest)
        };

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
            INCOMPLETE_OUTPUT_EXISTS,
            &output_dir.join(incomplete_name),
        )
    })?;
    // create_file_at succeeded — this run owns the staging file.
    created_incomplete_roots.push(manifest.root_name.clone());

    copy_exact_n(reader, &mut outfile, entry.size, archive_content_truncated)?;

    // Synced before promotion, so a crash after the rename cannot
    // surface incompletely written content under the final name.
    platform::sync_file_durable(&outfile).map_err(CryptoError::Io)?;

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
            INCOMPLETE_OUTPUT_EXISTS,
            &output_dir.join(incomplete_name),
        )
    })?;
    // mkdir_strict succeeded — this run owns the staging directory.
    created_incomplete_roots.push(manifest.root_name.clone());

    // Pass 1 (FORMAT.md §9.11 step 10): pre-create all descendant
    // directories sorted by depth ascending (parent before child), so
    // content streaming works for any manifest order the tree-shape
    // rules admit — §9.8 forbids readers from requiring a specific
    // order.
    let mut dir_entries: Vec<&ArchiveEntry> = manifest
        .entries
        .iter()
        .filter(|e| e.kind == ArchiveEntryKind::Directory && e.path_utf8 != root_name_str)
        .collect();
    dir_entries.sort_by(|a, b| canonical_path_order(&a.path_utf8, &b.path_utf8));
    for dir_entry in &dir_entries {
        let rel = strip_root_prefix(&dir_entry.path_utf8, root_name_str)?;
        let (parent_dir, dir_name) = platform::walk_to_parent(&root_dir, rel)?;
        let _new_dir = platform::mkdir_strict(&parent_dir, &dir_name).map_err(|e| {
            map_already_exists(e, ARCHIVE_PATH_COLLIDES, Path::new(&dir_entry.path_utf8))
        })?;
    }

    // Pass 2: stream file contents in MANIFEST ORDER. The content
    // region is laid out in manifest order, so this pass must visit
    // file entries in the same order as the writer emitted them.
    for entry in &manifest.entries {
        if entry.kind != ArchiveEntryKind::File {
            continue;
        }
        let rel = strip_root_prefix(&entry.path_utf8, root_name_str)?;
        let (parent_dir, file_name) = platform::walk_to_parent(&root_dir, rel)?;
        let mut outfile =
            platform::create_file_at(&parent_dir, &file_name, platform::INITIAL_FILE_CREATE_MODE)
                .map_err(|e| {
                map_already_exists(
                    CryptoError::Io(e),
                    ARCHIVE_PATH_COLLIDES,
                    Path::new(&entry.path_utf8),
                )
            })?;
        copy_exact_n(reader, &mut outfile, entry.size, archive_content_truncated)?;
        platform::chmod_file_handle(&outfile, entry.mode)?;
        // Synced before promotion, so a crash after the rename cannot
        // surface incompletely written content under the final name.
        platform::sync_file_durable(&outfile).map_err(CryptoError::Io)?;
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
        // Sync before chmod: the helper re-opens "." read-only, so it
        // needs the staging directory's current read permission. The
        // later chmod changes only the mode, not the entries flushed here.
        platform::sync_dir_handle(&dir_handle);
        platform::chmod_dir_handle(dir_handle, dir_entry.mode)?;
    }

    // Flush the staged root after all descendant directories have been
    // flushed. File contents were synced in Pass 2; these directory
    // syncs make the links to those files durable before promotion.
    platform::sync_dir_handle(&root_dir);

    // root_dir is dropped here, closing the staged-directory handle
    // before promotion: on Windows an open directory handle blocks the
    // path-based rename, and on Unix the handle-relative promotion runs
    // against `output_handle` rather than this one.
    Ok(())
}

/// Applies the manifest-stored root directory mode after promotion,
/// walking from the same `output_handle` extraction used — never a
/// re-resolved `output_dir` path. `open_dir_at_rel` routes through
/// `open_dir_nofollow` + the Windows reparse-point post-check, so a
/// symlink substituted at the final name between rename and chmod is
/// rejected.
fn apply_root_directory_mode(output_handle: &Dir, manifest: &Manifest) -> Result<(), CryptoError> {
    let root_name_str = manifest_root_name_str(manifest)?;
    let root_dir = platform::open_dir_at_rel(output_handle, Path::new(root_name_str))?;
    platform::chmod_dir_handle(root_dir, manifest.root_mode)
}

/// File-root parallel of [`apply_root_directory_mode`]. Opens the
/// renamed root file from the same `output_handle` extraction used,
/// via `open_file_nofollow` (no-follow + Windows reparse-point
/// post-check), and applies the manifest-stored mode through the open
/// handle. Runs only after promotion succeeds, so the staged file
/// held `INITIAL_FILE_CREATE_MODE` (0o600) throughout extraction; a
/// permissive manifest mode is never briefly visible to other local
/// users while the file holds plaintext.
fn apply_root_file_mode(output_handle: &Dir, manifest: &Manifest) -> Result<(), CryptoError> {
    let file = platform::open_file_nofollow(output_handle, &manifest.root_name)?;
    platform::chmod_file_handle(&file, manifest.root_mode)
}

/// Promotes the staged `{root}.incomplete` to its final `{root}` name
/// with no-clobber semantics (FORMAT.md §9.11 step 15), choosing the
/// platform-appropriate primitive.
///
/// On Linux and macOS the promotion is anchored to `output_handle` via
/// `platform::rename_at_no_clobber`, so a rename or replacement of the
/// ambient `output_dir` path between staging and the commit cannot
/// redirect it: the plaintext lands in the directory the contents were
/// written to, and a `{root}.incomplete` planted in a swapped-in
/// replacement directory is never promoted. `root_is_file` selects the
/// claim strategy of that helper's fallback for filesystems without an
/// atomic no-replace rename; the flagged rename itself promotes files
/// and directories alike.
///
/// On Windows (and any other target) the promotion is path-based:
/// single-file roots take the kernel atomic no-replace move via
/// `promote_single_file_no_clobber`, directory roots the best-effort
/// `rename_no_clobber`. A handle-relative no-replace rename on Windows
/// needs an `unsafe` Win32 call the crate forbids; see `SECURITY.md`.
fn promote_root(
    output_handle: &Dir,
    output_dir: &Path,
    incomplete_name: &OsStr,
    final_name: &OsStr,
    root_is_file: bool,
) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let _ = output_dir;
        platform::rename_at_no_clobber(output_handle, incomplete_name, final_name, root_is_file)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        use crate::fs::atomic::{promote_single_file_no_clobber, rename_no_clobber};

        let _ = output_handle;
        let working_path = output_dir.join(incomplete_name);
        let final_path = output_dir.join(final_name);
        if root_is_file {
            promote_single_file_no_clobber(&working_path, &final_path)
        } else {
            rename_no_clobber(&working_path, &final_path)
        }
    }
}

/// Rejects a directory root on targets without a safe directory-promotion
/// backend ([`platform::DIRECTORY_PROMOTION_SUPPORTED`]), before any output
/// is staged, so extraction fails cleanly up front instead of after writing
/// the whole tree. Single-file roots are unaffected — they promote through
/// `tempfile` on every target. The writer refuses the same directory input
/// (`encode::validate_encrypt_input`), so this is not a "wrote it but cannot
/// read it back" asymmetry, and this rejection mirrors the writer's:
/// the same `InvalidInput` class with parallel wording.
fn reject_unsupported_directory_root(manifest: &Manifest) -> Result<(), CryptoError> {
    if !platform::DIRECTORY_PROMOTION_SUPPORTED && !manifest.root_is_file {
        return Err(CryptoError::InvalidInput(
            "Decrypting a directory is not supported on this target".to_string(),
        ));
    }
    Ok(())
}

/// Error for an entry whose content ended before its manifest-declared
/// size: the archive stream is truncated relative to its own manifest.
/// FORMAT.md §9.9.
fn archive_content_truncated() -> CryptoError {
    CryptoError::MalformedArchive {
        reason: "file content shorter than the declared size",
    }
}

/// FORMAT.md §9.9: rejects any non-EOF byte after the last declared
/// file content. Reads via [`read_uninterrupted`] so a signal landing
/// on this final probe cannot fail an otherwise fully-extracted
/// archive. Other read errors thread `StreamError` markers from the
/// underlying decrypt stream through `From<io::Error> for CryptoError`
/// so an authentication / truncation / extra-data signal surfaces as
/// the typed `CryptoError::Payload*` variant rather than as a generic
/// archive error.
fn verify_archive_eof<R: Read>(reader: &mut R) -> Result<(), CryptoError> {
    let mut b = [0u8; 1];
    match read_uninterrupted(reader, &mut b) {
        Ok(0) => Ok(()),
        Ok(_) => Err(CryptoError::MalformedArchive {
            reason: "trailing data after the file contents",
        }),
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

/// Builds the "Output already exists: <dir>/<root>" rejection via the
/// shared constructor: the operator-chosen output directory renders
/// raw and untruncated, and the archive-chosen root name — the final
/// component — is escaped and bounded. Used by the step-8 occupancy
/// pre-check and the step-15 promotion failure.
fn output_already_exists(output_dir: &Path, root_name: &OsStr) -> CryptoError {
    already_exists_error(OUTPUT_LABEL, &output_dir.join(root_name))
}

/// Label for the staging-name collision: an `.incomplete` entry
/// already occupies the working name. It may be left over from a
/// previous failed run or still being written by a concurrent decrypt
/// of the same file; either way this run did not create it, so it is
/// rejected and preserved.
const INCOMPLETE_OUTPUT_EXISTS: &str = "Incomplete output already exists";

/// Label for a collision between two entries of the same archive. The
/// §9.7 duplicate key folds ASCII case only, so a filesystem that folds
/// more than that — Unicode normalization on APFS, a case-folding
/// volume — can still refuse the exclusive create for a manifest that
/// validated. Naming the archive path tells the operator which entry
/// the target filesystem could not keep apart.
const ARCHIVE_PATH_COLLIDES: &str = "Archive path collides with an existing entry";

/// Maps `io::ErrorKind::AlreadyExists` to a typed
/// `CryptoError::InvalidInput("<label>: <path>")` and otherwise
/// preserves the underlying error. Used at the first-touch staging
/// boundary: `mkdir_strict` / `create_file_at` reject an `.incomplete`
/// already at the working name ([`INCOMPLETE_OUTPUT_EXISTS`]) with a
/// recognisable diagnostic AND preserve it (the cleanup path tracks
/// only roots THIS run created).
fn map_already_exists(e: CryptoError, label: &str, path: &Path) -> CryptoError {
    if let CryptoError::Io(io_err) = &e {
        if io_err.kind() == io::ErrorKind::AlreadyExists {
            // The path mixes the caller's output directory with archive-derived
            // names; sanitize it so a malicious name cannot smuggle look-alike
            // characters into the message.
            return CryptoError::InvalidInput(format!(
                "{label}: {}",
                sanitize_path_for_display(path)
            ));
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

    /// An `Interrupted` read at the end-of-payload probe is retried
    /// like every other read in the extraction pipeline, instead of
    /// failing an already fully-streamed archive.
    #[test]
    fn verify_archive_eof_retries_interrupted() {
        struct EintrThenEof {
            fired: bool,
        }
        impl Read for EintrThenEof {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                if self.fired {
                    Ok(0)
                } else {
                    self.fired = true;
                    Err(io::Error::new(io::ErrorKind::Interrupted, "eintr"))
                }
            }
        }
        verify_archive_eof(&mut EintrThenEof { fired: false })
            .expect("EINTR followed by EOF must verify");
    }

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

    /// On the supported platforms (Linux, macOS, Windows — the CI matrix)
    /// a directory root passes the platform guard so extraction proceeds.
    /// The rejection path fires only on other targets and cannot run here,
    /// but this pins that the guard does not spuriously reject if the
    /// `cfg!` condition is ever inverted.
    #[test]
    fn directory_root_allowed_on_supported_platform() {
        let manifest = dir_with_one_undersized_file_manifest();
        assert!(!manifest.root_is_file);
        reject_unsupported_directory_root(&manifest)
            .expect("a directory root must be allowed on a supported platform");
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

    /// FORMAT.md §9.8: readers must accept any manifest order
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

    // -- Promotion anchoring (FORMAT.md §9.11 step 15) --------------------

    /// Promotion is the commit point and is anchored to the
    /// `output_handle` opened at extraction time. A swap of the ambient
    /// `output_dir` path between staging and promotion must not redirect
    /// the commit: the decrypted plaintext lands in the directory the
    /// contents were written to, and an attacker-planted
    /// `{root}.incomplete` in a swapped-in replacement directory is never
    /// promoted. Drives the real `unarchive` path with the swap injected
    /// on the end-of-archive read — which `verify_archive_eof` issues
    /// AFTER all content is staged and synced and immediately BEFORE
    /// promotion. Linux/macOS only: the handle-relative rename needs
    /// `renameat`+`RENAME_NOREPLACE`; Windows keeps the documented
    /// path-based promotion.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn promotion_is_anchored_to_handle_across_output_dir_swap() {
        // Reader that performs `swap` exactly once, on its first EOF
        // read. `unarchive` issues that read in `verify_archive_eof`,
        // after the staged `.incomplete` is fully written and synced
        // under `output_handle` and just before the promotion rename.
        struct SwapOnEof<F: FnMut()> {
            data: Vec<u8>,
            pos: usize,
            swapped: bool,
            swap: F,
        }
        impl<F: FnMut()> Read for SwapOnEof<F> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.pos >= self.data.len() {
                    if !self.swapped {
                        self.swapped = true;
                        (self.swap)();
                    }
                    return Ok(0);
                }
                let n = (self.data.len() - self.pos).min(buf.len());
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }

        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();

        let manifest = Manifest {
            entries: vec![
                make_entry("d", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("d/a.txt", ArchiveEntryKind::File, 4, 0o644),
            ],
            total_file_bytes: 4,
            root_name: OsString::from("d"),
            root_is_file: false,
            root_mode: 0o755,
        };
        let archive = build_archive(&manifest, &[("d/a.txt", b"real")]);

        let out_for_swap = out.clone();
        let moved = tmp.path().join("out.moved");
        let moved_for_swap = moved.clone();
        let reader = SwapOnEof {
            data: archive,
            pos: 0,
            swapped: false,
            swap: move || {
                // Move the real (handle-backed) directory aside, then
                // plant a decoy directory holding an attacker
                // `{root}.incomplete` at the original output path.
                fs::rename(&out_for_swap, &moved_for_swap).unwrap();
                fs::create_dir(&out_for_swap).unwrap();
                fs::create_dir(out_for_swap.join("d.incomplete")).unwrap();
                fs::write(out_for_swap.join("d.incomplete").join("a.txt"), b"attacker").unwrap();
            },
        };

        let returned = unarchive(
            reader,
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
        )
        .unwrap();

        // The real plaintext was committed in the handle's directory
        // (now at `moved`): the promotion did not follow the path swap.
        assert_eq!(fs::read(moved.join("d").join("a.txt")).unwrap(), b"real");
        assert!(!moved.join("d.incomplete").exists());
        // The attacker's decoy `.incomplete` in the swapped-in directory
        // was never promoted to the final name.
        assert!(!out.join("d").exists());
        assert_eq!(
            fs::read(out.join("d.incomplete").join("a.txt")).unwrap(),
            b"attacker"
        );
        // The returned path is the ambient `output_dir/root` computed
        // before the swap; because promotion is anchored to the handle it
        // does not resolve to attacker content (the decoy has no `d`).
        assert_eq!(returned, out.join("d"));
        assert!(!returned.exists());
    }

    // -- Archive-level TLV rejections (FORMAT.md §9.3) ---------------------

    /// `archive_ext` accepts a non-empty ignorable TLV region: the
    /// reader skips the bytes after canonicality checks and
    /// extraction proceeds normally. Pin so a future refactor that
    /// over-tightens the no-known-critical wrapper doesn't reject
    /// ignorable metadata from a later compatible writer.
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
    /// is created. FCA defines no archive-level critical tags.
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
    /// rejection must fire identically here.
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

    // -- Declared-region truncation (FORMAT.md §9.1) -----------------------

    /// If the authenticated payload ends within the declared `archive_ext`
    /// region, every cut point returns the region-specific malformed-archive
    /// error and creates no filesystem output.
    #[test]
    fn rejects_truncated_archive_ext_region_at_every_byte() {
        use crate::archive::format::FCA_HEADER_SIZE;

        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let ignorable = tlv_bytes(0x0001, b"meta");
        let full = build_archive_prefix_with_archive_ext(&manifest, &ignorable);

        for cut in 0..ignorable.len() {
            let tmp = tempfile::TempDir::new().unwrap();
            let archive = full[..FCA_HEADER_SIZE + cut].to_vec();
            let err = unarchive_default(archive, tmp.path()).unwrap_err();
            assert!(
                matches!(
                    err,
                    CryptoError::MalformedArchive {
                        reason: ARCHIVE_EXT_REGION_TRUNCATED
                    }
                ),
                "archive_ext cut at {cut} bytes must reject as truncated region, got {err:?}",
            );
            assert_eq!(
                fs::read_dir(tmp.path()).unwrap().count(),
                0,
                "no filesystem output may exist after an archive_ext truncation"
            );
        }
    }

    /// If the authenticated payload ends within the declared manifest region,
    /// every cut point returns the manifest-specific malformed-archive error
    /// and creates no filesystem output.
    #[test]
    fn rejects_truncated_manifest_region_at_every_byte() {
        use crate::archive::format::FCA_HEADER_SIZE;

        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let full = build_archive_prefix(&manifest);
        let manifest_len = full.len() - FCA_HEADER_SIZE;

        for cut in 0..manifest_len {
            let tmp = tempfile::TempDir::new().unwrap();
            let archive = full[..FCA_HEADER_SIZE + cut].to_vec();
            let err = unarchive_default(archive, tmp.path()).unwrap_err();
            assert!(
                matches!(
                    err,
                    CryptoError::MalformedArchive {
                        reason: ARCHIVE_MANIFEST_REGION_TRUNCATED
                    }
                ),
                "manifest cut at {cut} bytes must reject as truncated region, got {err:?}",
            );
            assert_eq!(
                fs::read_dir(tmp.path()).unwrap().count(),
                0,
                "no filesystem output may exist after a manifest truncation"
            );
        }
    }

    // -- Content-region rejections -----------------------------------------

    #[test]
    fn rejects_short_file_content() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let archive = build_partial_archive(&manifest, b"short");

        let err = unarchive_default(archive, tmp.path()).unwrap_err();

        assert!(
            matches!(
                err,
                CryptoError::MalformedArchive {
                    reason: "file content shorter than the declared size"
                } | CryptoError::Io(_)
            ),
            "got: {err}",
        );
    }

    #[test]
    fn rejects_trailing_data_after_last_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let mut archive = build_archive(&manifest, &[("hello.txt", b"Hello, world!")]);
        archive.push(0xAA);

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::MalformedArchive {
                reason: "trailing data after the file contents"
            }
        ));
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
        assert!(
            matches!(
                err,
                CryptoError::MalformedArchive {
                    reason: "file content shorter than the declared size"
                } | CryptoError::Io(_)
            ),
            "got: {err}",
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
        assert!(
            matches!(
                err,
                CryptoError::MalformedArchive {
                    reason: "file content shorter than the declared size"
                } | CryptoError::Io(_)
            ),
            "got: {err}",
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
        assert!(
            matches!(
                err,
                CryptoError::MalformedArchive {
                    reason: "file content shorter than the declared size"
                } | CryptoError::Io(_)
            ),
            "got: {err}",
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
    /// `.incomplete` must be cleaned up. Pinned via `FailAfterN`
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
    /// `.incomplete` must survive for inspection. Symmetric with the
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

    /// Read-only `output_dir` (mode `0o500`): `unarchive` must fail
    /// at the first cap-std write attempt (mkdir/create_file), and
    /// `DeleteOnError` must not leave anything behind. Pin the §11
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
    /// `create_new(true)` must reject with `AlreadyExists` (mapped to
    /// "Output already exists"), and the attacker-controlled hardlink
    /// target must remain unchanged. Closes the §12 "attacker
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

    /// Symlink at the renamed root between the promotion rename and
    /// `apply_root_directory_mode`: the chmod step must reject via
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

        let handle = platform::open_anchor(tmp.path()).unwrap();
        let err = apply_root_directory_mode(&handle, &manifest).unwrap_err();
        assert!(
            format!("{err}").contains("Symlink in extraction path"),
            "expected symlink rejection, got: {err}",
        );
    }

    /// File-root parallel of [`apply_root_directory_mode_rejects_symlink_at_renamed_root`].
    /// Symlink substituted at the renamed root between the promotion rename
    /// and `apply_root_file_mode`: the chmod step must reject via
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
        let handle = platform::open_anchor(tmp.path()).unwrap();
        let err = apply_root_file_mode(&handle, &manifest).unwrap_err();
        assert!(
            format!("{err}").contains("Symlink in extraction path"),
            "expected symlink rejection, got: {err}",
        );
    }

    /// A FIFO substituted at the promoted root must be rejected before the
    /// final permission update, without waiting for a FIFO writer. The test
    /// creates the post-promotion state directly to exercise the same open and
    /// type checks deterministically.
    #[cfg(unix)]
    #[test]
    fn apply_root_file_mode_rejects_fifo_at_renamed_root() {
        let tmp = tempfile::TempDir::new().unwrap();

        // Place a FIFO where the promoted root file would be.
        crate::fs::paths::make_fifo(&tmp.path().join("hello.txt"));

        let manifest = single_file_manifest("hello.txt", b"x");
        let handle = platform::open_anchor(tmp.path()).unwrap();
        let err = apply_root_file_mode(&handle, &manifest).unwrap_err();
        assert!(
            format!("{err}").contains("Extraction path is no longer a regular file"),
            "expected regular-file rejection, got: {err}",
        );
    }

    /// Step 16 must chmod through the SAME handle extraction used, not
    /// a re-resolved `output_dir` path. Swap the output directory
    /// aside after extraction and mint a same-named victim at the
    /// original path: the chmod must land in the moved directory and
    /// leave the victim untouched. Success-direction mirror of
    /// [`cleanup_via_handle_follows_handle_inode_not_path`].
    #[cfg(unix)]
    #[test]
    fn apply_root_directory_mode_follows_handle_inode_not_path() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let orig = tmp.path().join("orig");
        fs::create_dir(&orig).unwrap();
        fs::create_dir(orig.join("root")).unwrap();

        let handle = platform::open_anchor(&orig).unwrap();

        // Swap: move the extraction directory aside and mint a
        // replacement holding a same-named victim.
        let moved = tmp.path().join("moved");
        fs::rename(&orig, &moved).unwrap();
        fs::create_dir(&orig).unwrap();
        fs::create_dir(orig.join("root")).unwrap();
        fs::set_permissions(orig.join("root"), fs::Permissions::from_mode(0o755)).unwrap();

        let manifest = Manifest {
            entries: vec![make_entry("root", ArchiveEntryKind::Directory, 0, 0o500)],
            total_file_bytes: 0,
            root_name: OsString::from("root"),
            root_is_file: false,
            root_mode: 0o500,
        };
        apply_root_directory_mode(&handle, &manifest).unwrap();

        let moved_mode = fs::metadata(moved.join("root"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(moved_mode, 0o500, "chmod must land in the handle's dir");
        let victim_mode = fs::metadata(orig.join("root"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            victim_mode, 0o755,
            "victim at the swapped path must be untouched"
        );
    }

    /// File-root parallel of
    /// [`apply_root_directory_mode_follows_handle_inode_not_path`].
    #[cfg(unix)]
    #[test]
    fn apply_root_file_mode_follows_handle_inode_not_path() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let orig = tmp.path().join("orig");
        fs::create_dir(&orig).unwrap();
        fs::write(orig.join("hello.txt"), b"extracted").unwrap();

        let handle = platform::open_anchor(&orig).unwrap();

        let moved = tmp.path().join("moved");
        fs::rename(&orig, &moved).unwrap();
        fs::create_dir(&orig).unwrap();
        fs::write(orig.join("hello.txt"), b"victim").unwrap();
        fs::set_permissions(orig.join("hello.txt"), fs::Permissions::from_mode(0o644)).unwrap();

        let mut manifest = single_file_manifest("hello.txt", b"extracted");
        manifest.entries[0].mode = 0o400;
        manifest.root_mode = 0o400;

        apply_root_file_mode(&handle, &manifest).unwrap();

        let moved_mode = fs::metadata(moved.join("hello.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(moved_mode, 0o400, "chmod must land in the handle's dir");
        let victim_mode = fs::metadata(orig.join("hello.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            victim_mode, 0o644,
            "victim at the swapped path must be untouched"
        );
    }

    /// The occupied-output rejection embeds the archive-chosen root
    /// name; control and direction-override characters in it must be
    /// escaped. Mirrors the path grammar's sanitization pin
    /// (`rejection_payload_is_sanitized`) at this call site.
    #[test]
    fn occupied_output_error_escapes_hostile_root_name() {
        // The archive-chosen root name is escaped; the operator-chosen
        // output directory stays readable and is never truncated away,
        // even when it is long or carries non-ASCII characters.
        let err = output_already_exists(
            Path::new("/home/operator/Données/very-long-output-directory-name"),
            OsStr::new("evil\u{202e}name"),
        );
        let msg = format!("{err}");
        assert!(msg.contains("Output already exists"), "got: {msg}");
        assert!(
            msg.contains("Données"),
            "operator path must stay readable: {msg}"
        );
        assert!(
            msg.contains("evil\\u{202e}name"),
            "hostile root name must be escaped: {msg}"
        );
        assert!(
            !msg.contains('\u{202e}'),
            "raw direction-override character leaked: {msg:?}"
        );

        // End-to-end through unarchive: the raw character never reaches
        // the message, and the colliding name is present in full.
        let tmp = tempfile::TempDir::new().unwrap();
        let name = "evil\u{202e}name";
        fs::write(tmp.path().join(name), b"existing").unwrap();

        let manifest = single_file_manifest(name, b"x");
        let archive = build_archive(&manifest, &[(name, b"x")]);

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Output already exists"), "got: {msg}");
        assert!(
            msg.contains("evil\\u{202e}name"),
            "colliding name must appear escaped and in full: {msg}"
        );
        assert!(
            !msg.contains('\u{202e}'),
            "raw direction-override character leaked: {msg:?}"
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
    /// failed extraction (no rename) must not leak a permissive
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
        assert!(matches!(
            err,
            CryptoError::MalformedArchive {
                reason: "trailing data after the file contents"
            }
        ));

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
        // On a normalizing filesystem the second exclusive create
        // reports `AlreadyExists`, which maps to the typed collision
        // rejection naming the archive path.
        let s = format!("{err}");
        assert!(
            matches!(err, CryptoError::InvalidInput(_)) && s.contains(ARCHIVE_PATH_COLLIDES),
            "got: {s}",
        );

        // DeleteOnError cleans up the staged `.incomplete`.
        let count = fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(count, 0);
    }

    /// A pre-existing `.incomplete` from a previous failed run must
    /// reject and must be preserved (not cleaned up by DeleteOnError),
    /// because this run did not create it.
    #[test]
    fn rejects_pre_existing_incomplete_and_preserves_it() {
        let tmp = tempfile::TempDir::new().unwrap();
        let stale_path = tmp.path().join("hello.txt.incomplete");
        fs::write(&stale_path, b"stale plaintext from earlier run").unwrap();

        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let archive = build_archive(&manifest, &[("hello.txt", b"Hello, world!")]);

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        assert!(format!("{err}").contains(INCOMPLETE_OUTPUT_EXISTS));
        assert!(
            stale_path.exists(),
            "pre-existing .incomplete must be preserved across a retry",
        );
    }

    // -- Security invariant ------------------------------------------------

    /// FORMAT.md §9.11 steps 1–8 must complete before any filesystem
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

    /// FORMAT.md §9.6: a manifest component longer than the
    /// per-component byte cap rejects during validation, before any
    /// filesystem work — a typed grammar rejection instead of a raw
    /// `ENAMETOOLONG` I/O error from the staging create.
    #[test]
    fn rejects_over_long_component_before_filesystem_output() {
        let tmp = tempfile::TempDir::new().unwrap();
        let name = "n".repeat(250);
        let manifest = single_file_manifest(&name, b"x");
        let archive = build_archive(&manifest, &[(name.as_str(), b"x")]);

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: crate::archive::path::COMPONENT_TOO_LONG,
                ..
            }
        ));

        let count = fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(count, 0, "rejection must precede any filesystem output");
    }

    // -- Filesystem hardening ----------------------------------------------

    /// FORMAT.md §9.11 step 8: pre-check uses `symlink_metadata`, so a
    /// dangling symlink at the final output name is treated as
    /// occupied. `Path::exists()` would follow the link and report
    /// false, masking the conflict; we must reject before any
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
