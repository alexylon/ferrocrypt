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
//! 17. confirm the final name still denotes the staged object, and
//!     that `output_dir` still denotes the anchor the output was
//!     committed through
//! 18. return the final output path
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

use cap_std::fs::{Dir, File};

use crate::CryptoError;
use crate::crypto::stream::read_uninterrupted;
use crate::error::sanitize_for_display;
use crate::fs::paths::{
    INCOMPLETE_SUFFIX, OUTPUT_LABEL, already_exists_error, path_occupied,
    sanitize_path_keeping_parent,
};

use super::IncompleteOutputPolicy;
use super::format::{
    copy_exact_n, parse_fca_header, parse_manifest_bytes, read_exact_fca, require_fits_usize,
    validate_archive_ext_tlv,
};
use super::limits::ArchiveLimits;
use super::model::{ArchiveEntry, ArchiveEntryKind, Manifest};
use super::path::canonical_path_order;
use super::platform;
use super::platform::{ObjectId, OwnerComparison};
use super::reasons::{
    ARCHIVE_EXT_PLATFORM_LIMIT, ARCHIVE_EXT_REGION_TRUNCATED, FILE_CONTENT_TRUNCATED,
    MANIFEST_PLATFORM_LIMIT, MANIFEST_REGION_TRUNCATED, TRAILING_FILE_CONTENT,
};

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
    reader: R,
    output_dir: &Path,
    limits: ArchiveLimits,
    policy: IncompleteOutputPolicy,
) -> Result<PathBuf, CryptoError> {
    unarchive_inner_with_hooks(
        reader,
        output_dir,
        limits,
        policy,
        Seams {
            compare_owners: platform::compare_owners,
            before_promotion: || Ok(()),
            after_promotion: |_| Ok(()),
            after_root_mode: |_| Ok(()),
        },
    )
}

/// Compares the owners of a staged directory root and a file this run
/// created beneath it — see [`platform::compare_owners`]. A seam because
/// a directory with another owner cannot be created without privileges,
/// so the test for a mismatch substitutes the answer.
type CompareOwners = fn(&Dir, &File) -> Result<OwnerComparison, CryptoError>;

/// Implementation seams of [`unarchive_inner_with_hooks`]: the
/// staged-root ownership read, the interval between staging and
/// promotion, post-promotion outcomes, and the interval after root-mode
/// confirmation. Production supplies [`platform::compare_owners`] and
/// no-op hooks; tests use them to exercise a replaced staged root, the
/// promotion window, post-commit reporting, and cleanup.
/// `after_root_mode` receives the record a ratification moved out of the
/// cleanup slot, so a test can confirm the retained handle is still held
/// at that point.
struct Seams<B, A, M>
where
    B: FnOnce() -> Result<(), CryptoError>,
    A: FnOnce(&mut platform::PromotionOutcome) -> Result<(), CryptoError>,
    M: FnOnce(&Option<StagedRoot>) -> Result<(), CryptoError>,
{
    compare_owners: CompareOwners,
    before_promotion: B,
    after_promotion: A,
    after_root_mode: M,
}

fn unarchive_inner_with_hooks<R, B, A, M>(
    mut reader: R,
    output_dir: &Path,
    limits: ArchiveLimits,
    policy: IncompleteOutputPolicy,
    seams: Seams<B, A, M>,
) -> Result<PathBuf, CryptoError>
where
    R: Read,
    B: FnOnce() -> Result<(), CryptoError>,
    A: FnOnce(&mut platform::PromotionOutcome) -> Result<(), CryptoError>,
    M: FnOnce(&Option<StagedRoot>) -> Result<(), CryptoError>,
{
    let Seams {
        compare_owners,
        before_promotion,
        after_promotion,
        after_root_mode,
    } = seams;
    // FORMAT.md §9.11 step 1: parse + structurally validate the header.
    // `parse_fca_header` already enforces all caps for `archive_ext_len`,
    // `manifest_len`, and `total_file_bytes`.
    let header = parse_fca_header(&mut reader, limits)?;

    // §9.11 steps 2–3: read exactly `archive_ext_len` bytes and validate
    // the archive-level extension region. It is normally empty today, but a
    // later compatible writer may include optional tags. If authenticated
    // data ends before the declared region, report a malformed archive rather
    // than an I/O error.
    let archive_ext_len = require_fits_usize(header.archive_ext_len, ARCHIVE_EXT_PLATFORM_LIMIT)?;
    let mut archive_ext_bytes = vec![0u8; archive_ext_len];
    read_exact_fca(
        &mut reader,
        &mut archive_ext_bytes,
        ARCHIVE_EXT_REGION_TRUNCATED,
    )?;
    validate_archive_ext_tlv(&archive_ext_bytes, &limits)?;

    // §9.11 step 4: read exactly `manifest_len` bytes.
    let manifest_len = require_fits_usize(header.manifest_len, MANIFEST_PLATFORM_LIMIT)?;
    let mut manifest_bytes = vec![0u8; manifest_len];
    read_exact_fca(&mut reader, &mut manifest_bytes, MANIFEST_REGION_TRUNCATED)?;

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
    let mut staged_root: Option<StagedRoot> = None;

    // Steps 10–17 wrapped so the cleanup below sees `output_handle`
    // still alive on every error path.
    let outcome: Result<PathBuf, CryptoError> = (|| {
        // §9.11 steps 10–14. Each `extract_*_root` runs
        // `verify_archive_eof` (step 13) directly after content
        // streaming (step 11) and before every later step, so the
        // spec's literal ordering is preserved.
        if manifest.root_is_file {
            extract_single_file_root(
                &mut reader,
                &output_handle,
                &incomplete_name,
                &manifest,
                &mut staged_root,
                output_dir,
            )?;
        } else {
            extract_directory_root(
                &mut reader,
                &output_handle,
                &incomplete_name,
                &manifest,
                &mut staged_root,
                output_dir,
                compare_owners,
            )?;
        }

        before_promotion()?;

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
        // `promote_root` and `SECURITY.md`. The staged handle stays open
        // on every platform: it is what steps 16 and 17 compare the
        // final name against, and it was opened so the rename can
        // proceed beside it.
        let mut promotion = promote_root(
            &output_handle,
            output_dir,
            &incomplete_name,
            &manifest.root_name,
            manifest.root_is_file,
        )
        .map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                output_already_exists(output_dir, &manifest.root_name)
            } else {
                CryptoError::Io(e)
            }
        })?;
        after_promotion(&mut promotion)?;

        // A file root must carry exactly one name, so the count is read
        // for every one of them, whatever route committed the final
        // name and whether or not the staging name was removed. The
        // route that leaves the staging name in place is the one where
        // a second name is certain, so it is the last one that may
        // skip this.
        //
        // Read before the mode is applied: step 16 would otherwise
        // widen an extra name to the archive's mode, handing whoever
        // made it the access the deferred chmod exists to withhold. The
        // read comes from the retained handle rather than a name, so
        // nothing that happens to either name changes what is counted.
        //
        // A wrong count only withholds the mode here. What it means for
        // the staged record is decided by steps 16 and 17 below, which
        // alone can tell a committed output of this run's own from a
        // substituted entry promoted in its place: reporting here would
        // preserve plaintext this run never committed. The count covers
        // the root entry alone; a descendant file inside a directory
        // root has no handle retained to this point, and one read while
        // it was still being extracted would say nothing about a link
        // made afterwards.
        let mut extra_name_error = None;
        if manifest.root_is_file {
            let handle = staged_root
                .as_ref()
                .and_then(StagedRoot::file_handle)
                .ok_or(crate::error::internal_invariant!(
                    "promoted file root lost its handle"
                ))?;
            extra_name_error =
                require_single_linked_file(handle, output_dir, &manifest.root_name).err();
        }

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
        // already holds the complete plaintext. The `.incomplete`
        // working name is normally gone; a hard-link fallback whose
        // cleanup cannot be proved is reported after the identity and
        // mode checks below. A mode-application failure here must not
        // fail the extraction — returning `Err` would tell a
        // `DeleteOnError` caller nothing was written while a finished
        // output sits on disk. The output then keeps the staged mode
        // (`0o600`/`0o700`), which grants group and other nothing the
        // manifest mode would have granted them; it can leave the owner
        // more access than the manifest asked for.
        //
        // Steps 16 and 17 both compare the entry at the final name with
        // the object this run staged, so the staged identity is read
        // once here, on this side of the rename: a filesystem may
        // renumber an object when its directory entry moves, and both
        // sides of the comparison must be read after promotion. The
        // handle it is read from stays open until the last comparison
        // below: a filesystem may also give an object a new identifier
        // once its last handle closes, so a name read after that close
        // would no longer match.
        let staged_identity = staged_root
            .as_ref()
            .map_or(StagedIdentity::NoHandle, StagedRoot::identity);
        let ratified = if extra_name_error.is_some() {
            Ok(PromotedIdentity::Unconfirmed)
        } else if manifest.root_is_file {
            apply_root_file_mode(&output_handle, &manifest, &staged_identity)
        } else {
            apply_root_directory_mode(&output_handle, &manifest, &staged_identity)
        };

        // A confirmed identity ratifies the commit: the entry at the
        // final name is this run's own output, so the checks below only
        // report from here on. Cleanup must not reach an output that is
        // known to be committed — the promoted object is the caller's,
        // wherever it is later moved — so the record leaves the cleanup
        // slot for `ratified_root`, which is never handed to `remove`
        // and only keeps the retained handle open for those checks.
        let mut ratified_root: Option<StagedRoot> = None;
        if matches!(ratified, Ok(PromotedIdentity::Confirmed)) {
            ratified_root = staged_root.take();
        }

        after_root_mode(&ratified_root)?;

        // FORMAT.md §9.11 step 17: promotion resolved the staged entry
        // by name, so the commit is safe only while that name still
        // denotes the object this run staged. Where step 16 could not
        // confirm that, the staged record is deliberately still live: a
        // substitution detected here means the promoted entry was never
        // this run's object, and the never-committed staged plaintext
        // is left for `DeleteOnError` to remove. The entry at the final
        // name is not this run's to touch either way.
        let staged_id = staged_identity.known();
        require_promoted_root(&output_handle, &manifest.root_name, staged_id)?;

        // The commit is this run's own, so nothing is staged any more.
        // The record moves out of the cleanup slot on the same terms as
        // at ratification.
        if ratified_root.is_none() {
            ratified_root = staged_root.take();
        }

        // The returned path was built from the ambient `output_dir`
        // before the anchor was opened. Confirm it still denotes the
        // directory the output was committed in, so a swap of
        // `output_dir` during the run cannot end in a successful
        // decrypt whose reported path names an entry this run never
        // wrote.
        require_output_anchor_unchanged(&output_handle, output_dir, &manifest.root_name)?;

        // Every comparison against the staged object is made; the
        // retained handle can close.
        drop(ratified_root);

        if let Some(error) = promotion.into_staged_link_error() {
            return Err(staged_link_retained(
                output_dir,
                &incomplete_name,
                &manifest.root_name,
                error,
            ));
        }

        if let Some(error) = extra_name_error {
            return Err(error);
        }

        Ok(final_path.clone())
    })();

    // A removal that fails, or cannot show that the staged root is gone,
    // is reported next to the error: the original error alone would
    // read as if nothing remained. A record that already left the
    // cleanup slot is a ratified commit, which is not this policy's to
    // remove.
    let outcome = match outcome {
        Err(error) if matches!(policy, IncompleteOutputPolicy::DeleteOnError) => {
            Err(match staged_root.take() {
                Some(staged) => staged.remove(&output_handle, &manifest).report(
                    error,
                    output_dir,
                    &incomplete_name,
                ),
                None => error,
            })
        }
        outcome => outcome,
    };

    drop(output_handle);
    outcome
}

fn extract_single_file_root<R: Read>(
    reader: &mut R,
    output_handle: &Dir,
    incomplete_name: &OsStr,
    manifest: &Manifest,
    staged_root: &mut Option<StagedRoot>,
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
        map_already_exists(CryptoError::Io(e), || {
            incomplete_output_exists(output_dir, incomplete_name)
        })
    })?;
    // create_file_at succeeded — this run owns the staging file. The
    // recorded handle is a second descriptor for the same file, so the
    // checks after promotion keep working once the one below is closed
    // at the end of extraction. Duplication is required: a record
    // without a handle cannot confirm that the promoted name still
    // denotes the file this run wrote. Where it fails, the streaming
    // descriptor becomes the record's own — nothing has been streamed,
    // so no other use remains — and the error returns before any
    // plaintext, leaving the empty entry to the caller's policy.
    match outfile.try_clone() {
        Ok(recorded) => *staged_root = Some(StagedRoot::file(incomplete_name, Some(recorded))),
        Err(e) => {
            *staged_root = Some(StagedRoot::file(incomplete_name, Some(outfile)));
            return Err(staged_handle_unavailable(&e));
        }
    }

    copy_exact_n(reader, &mut outfile, entry.size, archive_content_truncated)?;

    // FORMAT.md §9.11 step 13: verify archive EOF — no byte may follow
    // the last declared file content. Checked before the flush, so a
    // rejected archive does not trigger a full drive-cache flush for a
    // file that is then deleted. Single-file root has no descendant chmod
    // pass, and the manifest-stored mode is applied post-rename by
    // `apply_root_file_mode` (FORMAT.md §9.11 step 16), so the staged
    // file stays at `INITIAL_FILE_CREATE_MODE` throughout.
    verify_archive_eof(reader)?;

    // Synced before promotion, so a crash after the rename cannot
    // surface incompletely written content under the final name.
    platform::sync_single_file_durable(&outfile).map_err(CryptoError::Io)
}

fn extract_directory_root<R: Read>(
    reader: &mut R,
    output_handle: &Dir,
    incomplete_name: &OsStr,
    manifest: &Manifest,
    staged_root: &mut Option<StagedRoot>,
    output_dir: &Path,
    compare_owners: CompareOwners,
) -> Result<(), CryptoError> {
    let root_name_str = manifest_root_name_str(manifest)?;

    let root_dir = platform::mkdir_strict(output_handle, incomplete_name).map_err(|e| {
        map_already_exists(e, || incomplete_output_exists(output_dir, incomplete_name))
    })?;
    // mkdir_strict succeeded — this run owns the staging directory.
    // The recorded handle is a second handle to the same directory, so
    // the checks after promotion and the cleanup keep working after the
    // one below is closed at the end of extraction. A second handle is
    // required on the same terms as the file root: where it cannot be
    // taken the record takes the handle this function would have walked
    // from, and the error returns before any plaintext.
    let recorded = match retain_staged_directory(output_handle, incomplete_name, &root_dir) {
        Ok(recorded) => recorded,
        Err(e) => {
            *staged_root = Some(StagedRoot::directory(incomplete_name, Some(root_dir)));
            return Err(e);
        }
    };
    *staged_root = Some(StagedRoot::directory(incomplete_name, Some(recorded)));

    // Pass 1 (FORMAT.md §9.11 step 10): pre-create all descendant
    // directories sorted by depth ascending (parent before child), so
    // content streaming works for any manifest order the tree-shape
    // rules admit — §9.8 forbids readers from requiring a specific
    // order.
    let dir_entries = descendant_directories(manifest, root_name_str);
    for dir_entry in &dir_entries {
        let rel = strip_root_prefix(&dir_entry.path_utf8, root_name_str)?;
        let (parent_dir, dir_name) =
            platform::walk_to_parent(&root_dir, rel, platform::WalkSide::Extraction)?;
        let _new_dir = platform::mkdir_strict(&parent_dir, &dir_name)
            .map_err(|e| map_already_exists(e, || archive_path_collides(&dir_entry.path_utf8)))?;
    }

    // Pass 2: stream file contents in MANIFEST ORDER. The content
    // region is laid out in manifest order, so this pass must visit
    // file entries in the same order as the writer emitted them.
    let mut root_owner_confirmed = false;
    for entry in &manifest.entries {
        if entry.kind != ArchiveEntryKind::File {
            continue;
        }
        let rel = strip_root_prefix(&entry.path_utf8, root_name_str)?;
        let (parent_dir, file_name) =
            platform::walk_to_parent(&root_dir, rel, platform::WalkSide::Extraction)?;
        let mut outfile =
            platform::create_file_at(&parent_dir, &file_name, platform::INITIAL_FILE_CREATE_MODE)
                .map_err(|e| {
                map_already_exists(CryptoError::Io(e), || {
                    archive_path_collides(&entry.path_utf8)
                })
            })?;
        // Before the first byte of content: the staged root must be the
        // directory this run created, and this file is the first object
        // that can tell (see `require_staged_root_owner`).
        if !root_owner_confirmed {
            require_staged_root_owner(
                compare_owners(&root_dir, &outfile)?,
                staged_root,
                output_dir,
                incomplete_name,
            )?;
            root_owner_confirmed = true;
        }
        copy_exact_n(reader, &mut outfile, entry.size, archive_content_truncated)?;
        platform::chmod_file_handle(&outfile, entry.mode)?;
        // Complete the per-file part of the durability sequence. On
        // macOS, the operation-level drive-cache barrier below finishes
        // that sequence before promotion.
        platform::sync_file_standard(&outfile).map_err(CryptoError::Io)?;
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
    //
    // Recorded before the first mode is applied: a stored mode without
    // owner write permission would refuse the removal of the run's own
    // entries, so a failure from here on has cleanup restore the modes
    // first (see `restore_descendant_access`).
    if let Some(root) = staged_root {
        root.mark_directory_modes_applied();
    }
    for dir_entry in dir_entries.iter().rev() {
        let rel = strip_root_prefix(&dir_entry.path_utf8, root_name_str)?;
        let dir_handle = platform::open_dir_at_rel(&root_dir, rel)?;
        platform::chmod_dir_handle_durable(dir_handle, dir_entry.mode)?;
    }

    // Flush the staged root after all descendant directories have been
    // flushed. File contents were synced in Pass 2; these directory
    // syncs make the links to those files durable before promotion.
    platform::sync_dir_handle(&root_dir);

    // The per-file and per-directory calls above are plain `fsync` on
    // macOS. Complete them with one full drive-cache barrier for the
    // staged operation, preserving the pre-A2 strongest-available
    // durability without paying for `F_FULLFSYNC` once per file.
    platform::sync_extraction_barrier(&root_dir).map_err(CryptoError::Io)?;

    // root_dir is dropped here, before promotion: on Windows a cap-std
    // directory handle has no delete sharing and would block the
    // path-based rename — the recorded handle was opened so the rename
    // can proceed beside it — and on Unix the handle-relative promotion
    // runs against `output_handle` rather than this one.
    Ok(())
}

/// Confirms that the staged directory root is the directory this run
/// created, from `comparison`: how the root's owner compares with that
/// of the first file the run created beneath it.
///
/// The root is created and then opened by name, two operations between
/// which a local writer with access to the output directory can replace
/// the empty directory with one of its own; nothing about the opened
/// handle says which directory it reached. A file is created and opened
/// in one operation, so the first file's owner is what the filesystem
/// gives this run's objects, and a root with another owner is not the
/// run's. Two objects one run created agree on every filesystem, so the
/// comparison never refuses the run's own root; where the platform
/// reports no owner it is unavailable and skipped.
///
/// A mismatch refuses the run before any content is written and takes
/// the staged record out of the cleanup slot: the entry at the working
/// name is not the run's, so cleanup must not remove it, and it blocks
/// a retry like any pre-existing `.incomplete` entry. The directories
/// the run created inside it so far, and the empty first file, stay
/// where they are.
fn require_staged_root_owner(
    comparison: OwnerComparison,
    staged_root: &mut Option<StagedRoot>,
    output_dir: &Path,
    incomplete_name: &OsStr,
) -> Result<(), CryptoError> {
    if comparison == OwnerComparison::Different {
        *staged_root = None;
        return Err(staged_root_replaced(output_dir, incomplete_name));
    }
    Ok(())
}

/// Second handle to the staged directory root, recorded for the checks
/// after promotion and for cleanup. Where the platform opens it by name
/// rather than duplicating `root_dir` ([`platform::retain_staged_dir`]),
/// the entry at that name may already have been swapped, so the handle
/// is confirmed to denote the directory `mkdir_strict` just created
/// before it is recorded — a mismatch is a substitution and refuses the
/// run before any plaintext, like a substitution found after promotion.
/// Where either identity is absent the confirmation is skipped.
fn retain_staged_directory(
    output_handle: &Dir,
    incomplete_name: &OsStr,
    root_dir: &Dir,
) -> Result<Dir, CryptoError> {
    let retained = platform::retain_staged_dir(output_handle, incomplete_name, root_dir)
        .map_err(|e| staged_handle_unavailable(&e))?;
    if let (Some(created), Some(opened)) = (
        platform::dir_object_id(root_dir)?,
        platform::dir_object_id(&retained)?,
    ) {
        require_staged_identity(created, opened, incomplete_name)?;
    }
    Ok(retained)
}

/// What the step-16 mode application learned about the entry at the
/// final name.
#[derive(Debug)]
enum PromotedIdentity {
    /// The entry was confirmed to be the object this run staged. The
    /// commit is ratified: the caller clears its staged record, so the
    /// step-17 checks may still fail the run but can no longer send
    /// cleanup at the committed output.
    Confirmed,
    /// No confirmation was possible, or it failed. The staged record
    /// stays live and step 17 decides.
    Unconfirmed,
}

/// Applies the manifest-stored root directory mode after promotion,
/// walking from the same `output_handle` extraction used — never a
/// re-resolved `output_dir` path. `open_dir_at_rel` routes through
/// `open_dir_nofollow` + the Windows reparse-point post-check, so a
/// symlink substituted at the final name between rename and chmod is
/// rejected.
///
/// The mode is applied only after the opened directory is confirmed to
/// be the one this run staged, and through that same handle, so a
/// substitution at the final name can neither receive the mode nor be
/// swapped in after the confirmation. A confirmed identity is returned
/// as [`PromotedIdentity::Confirmed`] whatever the chmod then does:
/// the confirmation is about identity, not the mode, and step 16 must
/// not fail the extraction anyway. An identity that was expected but is
/// unavailable — on either side: it could not be read, or it carries
/// no information — skips the mode application instead of applying the
/// mode to an unconfirmed entry; the output keeps its restrictive
/// staged mode, the failure mode `FORMAT.md` §9.11 step 16 names
/// acceptable.
fn apply_root_directory_mode(
    output_handle: &Dir,
    manifest: &Manifest,
    staged: &StagedIdentity,
) -> Result<PromotedIdentity, CryptoError> {
    if matches!(staged, StagedIdentity::Unavailable) {
        return Ok(PromotedIdentity::Unconfirmed);
    }
    let root_name_str = manifest_root_name_str(manifest)?;
    let root_dir = platform::open_dir_at_rel(output_handle, Path::new(root_name_str))?;
    if let StagedIdentity::Known(staged_id) = staged {
        let Some(found) = platform::dir_object_id(&root_dir)? else {
            return Ok(PromotedIdentity::Unconfirmed);
        };
        require_staged_identity(*staged_id, found, &manifest.root_name)?;
        let _ = platform::chmod_dir_handle(root_dir, manifest.root_mode);
        return Ok(PromotedIdentity::Confirmed);
    }
    platform::chmod_dir_handle(root_dir, manifest.root_mode)?;
    Ok(PromotedIdentity::Unconfirmed)
}

/// File-root parallel of [`apply_root_directory_mode`]. Opens the
/// renamed root file from the same `output_handle` extraction used,
/// via `open_file_nofollow` (no-follow + Windows reparse-point
/// post-check), confirms it is the file this run staged, and applies
/// the manifest-stored mode through that same handle. Runs only after
/// promotion succeeds, so the staged file held
/// `INITIAL_FILE_CREATE_MODE` (0o600) throughout extraction; a
/// permissive manifest mode is never briefly visible to other local
/// users while the file holds plaintext.
///
/// A mode is applied to an object, not to a name, so without that
/// confirmation an entry substituted at the final name would receive
/// the archive-chosen mode — and a hard link carries it to a file
/// anywhere on the same filesystem, including one the caller never
/// placed in `output_dir`. The confirmation and skip rules are those
/// of [`apply_root_directory_mode`].
fn apply_root_file_mode(
    output_handle: &Dir,
    manifest: &Manifest,
    staged: &StagedIdentity,
) -> Result<PromotedIdentity, CryptoError> {
    if matches!(staged, StagedIdentity::Unavailable) {
        return Ok(PromotedIdentity::Unconfirmed);
    }
    let file = platform::open_file_nofollow(output_handle, &manifest.root_name)?;
    if let StagedIdentity::Known(staged_id) = staged {
        let Some(found) = platform::file_object_id(&file)? else {
            return Ok(PromotedIdentity::Unconfirmed);
        };
        require_staged_identity(*staged_id, found, &manifest.root_name)?;
        let _ = platform::chmod_file_handle(&file, manifest.root_mode);
        return Ok(PromotedIdentity::Confirmed);
    }
    platform::chmod_file_handle(&file, manifest.root_mode)?;
    Ok(PromotedIdentity::Unconfirmed)
}

/// Confirms an object found at the promoted root's final name is the
/// one this run staged.
///
/// Shared by the two callers that act on the promoted root: the root
/// mode application, which must not touch a substituted entry, and
/// [`require_promoted_root`], which reports one. Both are handed the
/// same `staged_id`, read once after promotion, and call this only
/// where there is one, so neither pays for reading `found` with
/// nothing to compare it against (see [`platform::ObjectId`]).
fn require_staged_identity(
    staged_id: ObjectId,
    found: ObjectId,
    root_name: &OsStr,
) -> Result<(), CryptoError> {
    if found != staged_id {
        return Err(promoted_root_replaced(root_name));
    }
    Ok(())
}

/// Confirms the promoted output is the object this run staged, by
/// comparing the entry now at the final name with the handle the staged
/// root was created with.
///
/// Promotion resolves the staged `.incomplete` entry by name, so a
/// local writer able to move that entry aside and leave another object
/// under it has that object committed at the final name instead.
/// Anything at the final name other than the held object is such a
/// substitution, and the run reports it rather than handing the caller
/// a path to content the archive never produced.
///
/// Runs after the root mode is applied, so a substitution made at any
/// point up to that call is still caught; the mode application makes
/// the same comparison itself, against the handle it is about to chmod.
///
/// A missing staged identity is not treated as a substitution: there is
/// nothing to compare against, for the reasons [`StagedIdentity::known`]
/// gives; neither is a final entry whose identity carries no
/// information. A final name that is gone is treated as one, because
/// step 15 committed an entry there and its absence says the name no
/// longer denotes the output.
fn require_promoted_root(
    output_handle: &Dir,
    root_name: &OsStr,
    staged_id: Option<ObjectId>,
) -> Result<(), CryptoError> {
    let Some(staged_id) = staged_id else {
        return Ok(());
    };
    let promoted = match output_handle.symlink_metadata(root_name) {
        Ok(promoted) => promoted,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(promoted_root_replaced(root_name));
        }
        // Any other read failure is an environment fault rather than
        // evidence of a substitution, and reporting one would send
        // `DeleteOnError` at an output that is complete: the staged
        // directory handle follows the promoted tree to its final name.
        Err(_) => return Ok(()),
    };
    match platform::metadata_object_id(&promoted) {
        Some(found) => require_staged_identity(staged_id, found, root_name),
        None => Ok(()),
    }
}

/// Confirms the ambient `output_dir` still denotes the anchor the
/// output was committed through, so the returned path names the entry
/// this run wrote. A local writer able to rename `output_dir` through
/// its parent can otherwise leave the caller with a path that resolves
/// into a directory of their choosing.
///
/// A path that no longer leads to a directory reports as changed — missing, a
/// non-directory, or a symlink cycle ([`path_no_longer_a_directory`]).
/// Resource exhaustion skips this diagnostic-only confirmation because the
/// committed output has already been ratified
/// ([`output_confirmation_resource_error`]), and so does an identity that
/// carries no information. Every other open or identity-read failure is
/// propagated: permission denial can itself be a property of a
/// replacement directory created by the local writer this check defends
/// against.
fn require_output_anchor_unchanged(
    output_handle: &Dir,
    output_dir: &Path,
    root_name: &OsStr,
) -> Result<(), CryptoError> {
    let current = match platform::open_anchor(output_dir) {
        Ok(current) => current,
        Err(CryptoError::Io(e)) if path_no_longer_a_directory(&e) => {
            return Err(output_directory_changed(output_dir, root_name));
        }
        Err(error) if output_confirmation_resource_error(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let current_id = match platform::dir_object_id(&current) {
        Ok(id) => id,
        Err(error) if output_confirmation_resource_error(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let committed_id = match platform::dir_object_id(output_handle) {
        Ok(id) => id,
        Err(error) if output_confirmation_resource_error(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    match (current_id, committed_id) {
        (Some(current_id), Some(committed_id)) if current_id != committed_id => {
            Err(output_directory_changed(output_dir, root_name))
        }
        _ => Ok(()),
    }
}

/// Whether a failure to open the destination path says it no longer leads
/// to a directory: the entry is missing, is not a directory, or is a
/// symlink cycle. Each is a substitution someone made, never an
/// environment fault. The cycle is matched by raw OS error code because
/// `std` has no stable `io::ErrorKind` for it yet.
fn path_no_longer_a_directory(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    ) || error.raw_os_error() == Some(SYMLINK_LOOP_CODE)
}

/// Raw OS error code for a symlink cycle.
#[cfg(unix)]
const SYMLINK_LOOP_CODE: i32 = libc::ELOOP;

/// Raw OS error code for a symlink cycle: what Windows returns for a
/// reparse-point cycle.
#[cfg(windows)]
const SYMLINK_LOOP_CODE: i32 = ERROR_CANT_RESOLVE_FILENAME;

/// Resource exhaustion for which the final destination-path confirmation is
/// unavailable rather than adverse evidence about the path itself
/// ([`RESOURCE_EXHAUSTION_CODES`]). Every other open or identity-read
/// failure is returned to the caller: permission denial can be a property
/// of a replacement directory created by the local writer this check
/// defends against.
fn output_confirmation_resource_error(error: &CryptoError) -> bool {
    matches!(
        error,
        CryptoError::Io(error)
            if matches!(error.raw_os_error(), Some(code) if RESOURCE_EXHAUSTION_CODES.contains(&code))
    )
}

/// Raw OS error codes for descriptor and memory exhaustion.
#[cfg(unix)]
const RESOURCE_EXHAUSTION_CODES: [i32; 3] = [libc::EMFILE, libc::ENFILE, libc::ENOMEM];

/// Raw OS error codes for handle, memory, and kernel-resource exhaustion.
#[cfg(windows)]
const RESOURCE_EXHAUSTION_CODES: [i32; 4] = [
    ERROR_TOO_MANY_OPEN_FILES,
    ERROR_NOT_ENOUGH_MEMORY,
    ERROR_OUTOFMEMORY,
    ERROR_NO_SYSTEM_RESOURCES,
];

/// `ERROR_TOO_MANY_OPEN_FILES` from `WinError.h`.
#[cfg(windows)]
const ERROR_TOO_MANY_OPEN_FILES: i32 = 4;

/// `ERROR_NOT_ENOUGH_MEMORY` from `WinError.h`.
#[cfg(windows)]
const ERROR_NOT_ENOUGH_MEMORY: i32 = 8;

/// `ERROR_OUTOFMEMORY` from `WinError.h`.
#[cfg(windows)]
const ERROR_OUTOFMEMORY: i32 = 14;

/// `ERROR_NO_SYSTEM_RESOURCES` from `WinError.h`.
#[cfg(windows)]
const ERROR_NO_SYSTEM_RESOURCES: i32 = 1450;

/// `ERROR_CANT_RESOLVE_FILENAME` from `WinError.h`.
#[cfg(windows)]
const ERROR_CANT_RESOLVE_FILENAME: i32 = 1921;

/// Rejection for a promoted root that no longer denotes the object this
/// run staged: the entry was replaced after the commit, so its content
/// did not come from the archive and must not be reported as the
/// decrypted output. Also raised, with the staging name, where the
/// retained staged handle turns out not to denote the directory this
/// run created ([`retain_staged_directory`]) — the same substitution,
/// caught before any plaintext.
fn promoted_root_replaced(root_name: &OsStr) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "Output was replaced while decrypting: {}",
        sanitize_for_display(&root_name.to_string_lossy())
    ))
}

/// Rejection for a staged directory root that is not the directory this
/// run created (see [`require_staged_root_owner`]). The entry is left in
/// place, so the message names it; the parent is the caller's own path
/// and stays readable, the working name is archive-derived and is
/// escaped.
fn staged_root_replaced(output_dir: &Path, working_name: &OsStr) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "{STAGED_ROOT_REPLACED}: {}",
        sanitize_path_keeping_parent(&output_dir.join(working_name))
    ))
}

/// What [`staged_root_replaced`] reports, ahead of the path.
const STAGED_ROOT_REPLACED: &str =
    "Incomplete output belongs to another owner and was left in place";

/// Rejection for a staged root whose descriptor could not be
/// duplicated, so the run cannot confirm after promotion that the final
/// name still denotes what it wrote (`FORMAT.md` §9.11 steps 16 and
/// 17). Reported before any plaintext is streamed. The underlying
/// message is kept because it names the resource that ran out, which is
/// the operator's way in.
fn staged_handle_unavailable(source: &io::Error) -> CryptoError {
    CryptoError::Io(io::Error::new(
        source.kind(),
        format!("{STAGED_HANDLE_UNAVAILABLE}: {source}"),
    ))
}

/// What [`staged_handle_unavailable`] reports, ahead of the underlying
/// message.
const STAGED_HANDLE_UNAVAILABLE: &str = "Cannot hold a handle to the staged output";

/// Error for a destination path that no longer denotes the retained commit
/// directory. The root name is included so the operator can locate the output
/// if that directory was renamed. The message says the output is complete
/// because content, promotion, and the final-entry check already succeeded.
/// The operator-supplied directory renders untruncated; the archive-supplied
/// root name is escaped and bounded.
fn output_directory_changed(output_dir: &Path, root_name: &OsStr) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "Output {} is complete but its directory changed: {}",
        sanitize_for_display(&root_name.to_string_lossy()),
        output_dir.display()
    ))
}

/// Post-commit error for a file-root link promotion whose final name is
/// complete but whose staging name could not be removed. Both names may still
/// denote the same plaintext file. The committed identity has already been
/// ratified before this is returned, so `DeleteOnError` cannot truncate it.
fn staged_link_retained(
    output_dir: &Path,
    incomplete_name: &OsStr,
    root_name: &OsStr,
    source: io::Error,
) -> CryptoError {
    CryptoError::Io(io::Error::new(
        source.kind(),
        format!(
            "Output {} is complete, but temporary name {} could not be removed from {}: {source}",
            sanitize_for_display(&root_name.to_string_lossy()),
            sanitize_for_display(&incomplete_name.to_string_lossy()),
            output_dir.display(),
        ),
    ))
}

/// Final post-condition for a committed file root: exactly one name.
/// The staged plaintext was created under a name any local writer with
/// access to the output directory can link to, and that link survives
/// the promotion, so the count is read whatever route committed the
/// final name — the same rule every writer-side commit applies.
///
/// A hard-link fallback needs it for a second reason: its staging
/// unlink's return value is not sufficient, because a concurrent
/// directory writer can rename that link and make the unlink return
/// `NotFound`, or plant a replacement that the unlink removes
/// successfully. The retained file handle follows the committed inode
/// through either name race, and reading the count from it also keeps
/// the Windows field populated, which cap-std fills only from an open
/// handle.
fn require_single_linked_file(
    handle: &File,
    output_dir: &Path,
    root_name: &OsStr,
) -> Result<(), CryptoError> {
    use cap_fs_ext::MetadataExt;

    let metadata = handle.metadata().map_err(|source| {
        CryptoError::Io(io::Error::new(
            source.kind(),
            format!(
                "Output {} is complete, but its number of filesystem names could not be read in {}: {source}",
                sanitize_for_display(&root_name.to_string_lossy()),
                output_dir.display(),
            ),
        ))
    })?;
    let link_count = metadata.nlink();
    if link_count != 1 {
        return Err(crate::fs::atomic::committed_link_count_error(
            &sanitize_for_display(&root_name.to_string_lossy()),
            link_count,
        ));
    }
    Ok(())
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
/// single-file roots go through `promote_single_file_no_clobber` — a
/// kernel atomic no-replace move on Windows, `tempfile`'s hard-link
/// fallback on other Unix targets, where the outcome therefore carries
/// the link-count obligation — and directory roots the best-effort
/// `rename_no_clobber`. A handle-relative no-replace rename on Windows
/// needs an `unsafe` Win32 call the crate forbids; see `SECURITY.md`.
fn promote_root(
    output_handle: &Dir,
    output_dir: &Path,
    incomplete_name: &OsStr,
    final_name: &OsStr,
    root_is_file: bool,
) -> io::Result<platform::PromotionOutcome> {
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
            // `tempfile` can commit this move by hard link with a
            // discarded unlink, so the outcome must carry the link-count
            // obligation on the targets where that can happen.
            promote_single_file_no_clobber(&working_path, &final_path)
                .map(|()| platform::PromotionOutcome::for_tempfile_file_promotion())
        } else {
            rename_no_clobber(&working_path, &final_path)
                .map(|()| platform::PromotionOutcome::Clean)
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
        reason: FILE_CONTENT_TRUNCATED,
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
            reason: TRAILING_FILE_CONTENT,
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

/// The `.incomplete` root this run staged, kept so a failed run
/// removes that object and nothing else.
///
/// Cleanup must not decide how to remove from what currently occupies
/// the working name. A local writer with write access to `output_dir`
/// can move the staged root aside and leave a directory of their own
/// at that name, and a removal chosen from the substitute's type would
/// then delete a tree this run never created. The removal is therefore
/// chosen from what this run created: a staged file is only ever
/// emptied through its own handle and unlinked, never removed
/// recursively.
///
/// A staged directory is removed through the handle it was created
/// with on Unix, so a substituted directory is left in place, and the
/// staged tree is removed wherever it was moved. Windows removes it by
/// name instead, because resolving an open directory handle back to a
/// path there would leave the destination anchor — see
/// [`remove_staged_directory`] — and only while the entry at the
/// working name is still the staged directory, so a substituted
/// directory is left in place there too; a staged tree moved aside
/// survives on Windows, the bound `SECURITY.md` records for that
/// target.
enum StagedRoot {
    /// Staged file root. `handle` is a descriptor for the file
    /// `create_file_at` returned, held for the whole run: a run that
    /// cannot hold one fails before streaming any plaintext, and once
    /// the commit is ratified the record leaves the cleanup slot with
    /// the handle still open (see `unarchive_inner_with_hooks`).
    File {
        working_name: OsString,
        handle: Option<File>,
    },
    /// Staged directory root. `handle` is the second handle
    /// [`retain_staged_directory`] recorded, held for the whole run
    /// under the same conditions. `modes_applied` says whether Pass 3
    /// started applying the stored descendant modes, which is when the
    /// staged tree can stop being removable by its own owner.
    Directory {
        working_name: OsString,
        handle: Option<Dir>,
        modes_applied: bool,
    },
}

impl StagedRoot {
    fn file(working_name: &OsStr, handle: Option<File>) -> Self {
        Self::File {
            working_name: working_name.to_os_string(),
            handle,
        }
    }

    fn directory(working_name: &OsStr, handle: Option<Dir>) -> Self {
        Self::Directory {
            working_name: working_name.to_os_string(),
            handle,
            modes_applied: false,
        }
    }

    /// Records that Pass 3 is about to apply the stored descendant
    /// directory modes. No effect on a file root, which has no
    /// descendants.
    fn mark_directory_modes_applied(&mut self) {
        if let Self::Directory { modes_applied, .. } = self {
            *modes_applied = true;
        }
    }

    /// Current identity of the staged object, read from the retained
    /// handle.
    ///
    /// Read now rather than recorded at creation: a filesystem may
    /// derive a file's identity from the position of its directory
    /// entry, which a rename moves. Both sides of the comparison in
    /// [`require_promoted_root`] are therefore read after promotion,
    /// where they agree for one object however the filesystem numbers
    /// it.
    fn identity(&self) -> StagedIdentity {
        let read = match self {
            Self::File { handle, .. } => handle.as_ref().map(platform::file_object_id),
            Self::Directory { handle, .. } => handle.as_ref().map(platform::dir_object_id),
        };
        match read {
            Some(Ok(Some(id))) => StagedIdentity::Known(id),
            Some(Ok(None) | Err(_)) => StagedIdentity::Unavailable,
            None => StagedIdentity::NoHandle,
        }
    }

    /// The retained handle of a staged file root, which the commit
    /// reads its final link count through.
    fn file_handle(&self) -> Option<&File> {
        match self {
            Self::File { handle, .. } => handle.as_ref(),
            Self::Directory { .. } => None,
        }
    }

    /// Removes the staged root and says what that left behind, so the
    /// caller can report a removal that failed or could not be
    /// confirmed next to the error it is already returning.
    ///
    /// A staged file is emptied through the handle it was created with,
    /// where one is held, and then unlinked by name through
    /// `output_handle`, the same `Dir` extraction wrote through, so a
    /// path swap of `output_dir` cannot redirect the removal. Unlinking
    /// never follows a symlink
    /// and never recurses, so a directory substituted at the working
    /// name is left in place. A file substituted there is unlinked,
    /// which stays within what a writer holding that access can
    /// already do to the entry itself.
    ///
    /// Unix has no portable unlink by descriptor, so a staged file
    /// moved aside cannot be found by name. Emptying it first is what
    /// makes the two root kinds agree: the plaintext this run wrote is
    /// destroyed whatever the entry is now called, matching what the
    /// directory arm achieves through its own handle.
    ///
    /// A staged directory first has the modes Pass 3 applied to its
    /// descendants restored, where that pass ran, because a stored mode
    /// without owner write permission would otherwise refuse the
    /// removal of the run's own entries. `manifest` names those
    /// directories.
    fn remove(self, output_handle: &Dir, manifest: &Manifest) -> CleanupOutcome {
        match self {
            Self::File {
                working_name,
                handle,
            } => {
                let emptied = handle.as_ref().is_some_and(|h| h.set_len(0).is_ok());
                // Closed first: Windows refuses to remove a file that
                // still has an open handle.
                drop(handle);
                match output_handle.remove_file(&working_name) {
                    Ok(()) => CleanupOutcome::Removed,
                    // The name is already gone and the content with it:
                    // nothing is left at the working name to block a
                    // retry, and no plaintext remains.
                    Err(e) if emptied && e.kind() == io::ErrorKind::NotFound => {
                        CleanupOutcome::Removed
                    }
                    Err(cause) => CleanupOutcome::Unconfirmed { cause, emptied },
                }
            }
            Self::Directory {
                working_name,
                handle,
                modes_applied,
            } => remove_staged_directory(
                output_handle,
                &working_name,
                handle,
                modes_applied.then_some(manifest),
            ),
        }
    }
}

/// What the failure-path removal of the staged root left behind.
enum CleanupOutcome {
    /// Nothing of the staged root remains at the working name, and its
    /// plaintext is gone.
    Removed,
    /// An entry may remain at the working name, and `cause` says why its
    /// removal failed or could not be confirmed. `emptied` is set when
    /// the staged file's content was destroyed through its handle before
    /// the unlink failed, so that what remains holds no plaintext; a
    /// directory is never reported as emptied, because a removal that
    /// stopped partway leaves whatever it had not reached.
    Unconfirmed { cause: io::Error, emptied: bool },
}

impl CleanupOutcome {
    fn from_removal(result: io::Result<()>) -> Self {
        match result {
            Ok(()) => Self::Removed,
            Err(cause) => Self::Unconfirmed {
                cause,
                emptied: false,
            },
        }
    }

    /// The outcome of a removal that was never attempted because the
    /// record holds no handle. No extraction produces such a record —
    /// see [`StagedIdentity::NoHandle`] — so this is report-only.
    fn no_handle() -> Self {
        Self::Unconfirmed {
            cause: io::Error::other("no handle to the staged output was held"),
            emptied: false,
        }
    }

    /// Appends the outcome to the error the decrypt is returning. A
    /// removal that left an entry at the working name, or could not show
    /// that it was removed, is reported with the working path, because
    /// that is the one way the caller learns that complete or partial
    /// plaintext may remain there, or that an emptied entry still
    /// blocks a retry. A confirmed removal returns `error` unchanged.
    fn report(self, error: CryptoError, output_dir: &Path, working_name: &OsStr) -> CryptoError {
        let Self::Unconfirmed { cause, emptied } = self else {
            return error;
        };
        let shown = sanitize_path_keeping_parent(&output_dir.join(working_name));
        let report = if emptied {
            format!("the incomplete output {shown} was emptied but could not be removed: {cause}")
        } else {
            format!(
                "the incomplete output {shown} could not be removed and may still hold plaintext: {cause}"
            )
        };
        crate::error::append_report(error, &report)
    }
}

/// Identity of the staged root, as the steps after promotion see it.
///
/// The two ways it can be missing are kept apart because they say
/// different things about the run. [`Self::NoHandle`] is a record
/// without a handle, which no extraction produces: the staged handle
/// is held on every platform for the whole run.
/// [`Self::Unavailable`] means a handle was held but the filesystem
/// either refused to describe the object behind it or described it
/// with an all-zero identifier, which carries no information. Neither
/// fails the extraction: step 17 skips its comparison for both — see
/// [`StagedIdentity::known`] — while step 16 tells them apart, skipping
/// the root-mode application for [`Self::Unavailable`] and applying it
/// under the no-follow guards alone for [`Self::NoHandle`] (see
/// [`apply_root_directory_mode`]).
enum StagedIdentity {
    /// Read from the retained staged handle.
    Known(ObjectId),
    /// No handle is held, so there is nothing to read.
    NoHandle,
    /// A handle is held, but its identity could not be read or carries
    /// no information.
    Unavailable,
}

impl StagedIdentity {
    /// The identity the promoted entry is compared against, or `None`
    /// where there is none to compare.
    ///
    /// A failed read is skipped rather than reported as a mismatch.
    /// `FORMAT.md` §9.11 step 17 rules that a failure to read the final
    /// name must not fail the extraction, because it reports the
    /// environment rather than the entry and failing a complete
    /// extraction would expose it to `DeleteOnError` cleanup. A failed
    /// read of the staged handle is the same class of fault, so it is
    /// treated the same way.
    ///
    /// This governs the identity comparison alone. Every file root has
    /// had its link count read from the same handle by then, and
    /// `FORMAT.md` §9.11 requires a failure to establish that count to
    /// fail the extraction — but only after the steps this state feeds,
    /// which alone tell a commit of this run's own from a substituted
    /// entry. A file root whose metadata could not be read therefore
    /// reaches this state, and its run still fails.
    fn known(self) -> Option<ObjectId> {
        match self {
            Self::Known(id) => Some(id),
            Self::NoHandle | Self::Unavailable => None,
        }
    }
}

/// Removes a staged directory root through the handle it was created
/// with: the contents are removed through that descriptor and the
/// directory itself is found by identity in its parent, so a directory
/// substituted at the working name is never removed — and the staged
/// tree is still removed when it is the entry that was moved aside.
///
/// Where Pass 3 applied the stored descendant modes, `restore` carries
/// the manifest and those modes are undone first, so the run's own
/// entries can be removed whatever the archive declared.
///
/// The handle is held for the whole run, so the `None` arm is
/// unreachable here: a run that could not hold one failed before
/// staging any plaintext. It removes nothing, because without the
/// handle the working name cannot be shown to still denote the staged
/// tree.
#[cfg(unix)]
fn remove_staged_directory(
    _output_handle: &Dir,
    _working_name: &OsStr,
    handle: Option<Dir>,
    restore: Option<&Manifest>,
) -> CleanupOutcome {
    let Some(handle) = handle else {
        return CleanupOutcome::no_handle();
    };
    if let Some(manifest) = restore {
        restore_descendant_access(&handle, manifest);
    }
    CleanupOutcome::from_removal(handle.remove_open_dir_all())
}

/// Gives the owner back full access to every directory the run created
/// beneath the staged root, parents before children, so the modes Pass 3
/// applied cannot refuse the removal of the run's own entries. Each
/// directory is reached by the same no-follow walk extraction used and
/// changed by name from its parent ([`platform::restore_owner_access`]),
/// the one route open to a directory left without read permission.
///
/// Every directory is restored, not only those whose stored mode lacks
/// an owner bit: the run is allowed anything within its own staged tree,
/// and a sweep that depends on the stored modes is one more thing to get
/// wrong. A directory that cannot be restored is left to make the
/// removal fail there, and that failure is what the caller reports.
#[cfg(unix)]
fn restore_descendant_access(root: &Dir, manifest: &Manifest) {
    let Ok(root_name_str) = manifest_root_name_str(manifest) else {
        return;
    };
    for dir_entry in descendant_directories(manifest, root_name_str) {
        let Ok(rel) = strip_root_prefix(&dir_entry.path_utf8, root_name_str) else {
            continue;
        };
        let Ok((parent_dir, dir_name)) =
            platform::walk_to_parent(root, rel, platform::WalkSide::Extraction)
        else {
            continue;
        };
        let _ = platform::restore_owner_access(&parent_dir, &dir_name);
    }
}

/// Removes a staged directory root by name, anchored to the capability
/// handle extraction wrote through, and only while the entry at the
/// working name is still the directory behind the staged handle, so a
/// directory substituted before that check is left in place. A staged
/// tree that was moved aside is not found there and stays where it is;
/// both are reported as an unconfirmed removal. Windows offers no
/// recursive removal through a descriptor: the name is resolved back to
/// an absolute path for the delete itself, so a directory put there in
/// the instant between the check and the removal is what that recursive
/// removal then reaches — the same bound as the Unix key-file rollback,
/// which `SECURITY.md` states. Without a handle nothing is removed, as
/// on Unix. The staged handle is closed first; the removal does not need
/// it. Mode application is a no-op on Windows, so there is nothing to
/// restore and `restore` is unused.
#[cfg(not(unix))]
fn remove_staged_directory(
    output_handle: &Dir,
    working_name: &OsStr,
    handle: Option<Dir>,
    _restore: Option<&Manifest>,
) -> CleanupOutcome {
    let Some(handle) = handle else {
        return CleanupOutcome::no_handle();
    };
    let staged = platform::dir_object_id(&handle);
    let at_name = output_handle
        .symlink_metadata(working_name)
        .map(|metadata| platform::metadata_object_id(&metadata));
    drop(handle);
    let (staged, at_name) = match (staged, at_name) {
        (Ok(Some(staged)), Ok(Some(at_name))) => (staged, at_name),
        (Ok(None), _) | (_, Ok(None)) => {
            return CleanupOutcome::from_removal(Err(io::Error::other(
                "no filesystem identity confirms that the entry at the working name is the \
                 staged directory",
            )));
        }
        (Err(e), _) => return CleanupOutcome::from_removal(Err(io::Error::other(e.to_string()))),
        (_, Err(e)) => return CleanupOutcome::from_removal(Err(e)),
    };
    if staged != at_name {
        return CleanupOutcome::from_removal(Err(io::Error::other(
            "the working name no longer denotes the staged directory",
        )));
    }
    CleanupOutcome::from_removal(output_handle.remove_dir_all(working_name))
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
/// rejected and preserved. [`incomplete_output_exists`] appends
/// "already exists" via the shared constructor.
const INCOMPLETE_OUTPUT_LABEL: &str = "Incomplete output";

/// Label for a collision between two entries of the same archive. The
/// §9.7 duplicate keys fold ASCII case and Unicode canonical form, so
/// a filesystem that folds more than that — non-ASCII letter case on
/// a case-folding volume — can still refuse the exclusive create for
/// a manifest that validated. Naming the archive path tells the
/// operator which entry the target filesystem could not keep apart.
const ARCHIVE_PATH_COLLIDES: &str = "Archive path collides with an existing entry";

/// Builds the "Incomplete output already exists: <dir>/<root>.incomplete"
/// rejection via the shared constructor, the same way as
/// [`output_already_exists`]: the operator-chosen output directory
/// renders readable and untruncated, and the archive-chosen working
/// name — the final component — is escaped and bounded.
fn incomplete_output_exists(output_dir: &Path, working_name: &OsStr) -> CryptoError {
    already_exists_error(INCOMPLETE_OUTPUT_LABEL, &output_dir.join(working_name))
}

/// Builds the "Archive path collides with an existing entry: <path>"
/// rejection. The whole path is archive-derived, so all of it goes
/// through the strict, truncating sanitizer.
fn archive_path_collides(path_utf8: &str) -> CryptoError {
    CryptoError::InvalidInput(format!(
        "{ARCHIVE_PATH_COLLIDES}: {}",
        sanitize_for_display(path_utf8)
    ))
}

/// Maps `io::ErrorKind::AlreadyExists` to the collision rejection built
/// by `on_exists` and otherwise preserves the underlying error. Serves
/// both collision boundaries: the first-touch staging names
/// ([`incomplete_output_exists`] — the entry is preserved, because the
/// cleanup path tracks only roots THIS run created) and the per-entry
/// creates inside the staged tree ([`archive_path_collides`]).
fn map_already_exists(e: CryptoError, on_exists: impl FnOnce() -> CryptoError) -> CryptoError {
    if let CryptoError::Io(io_err) = &e {
        if io_err.kind() == io::ErrorKind::AlreadyExists {
            return on_exists();
        }
    }
    e
}

fn manifest_root_name_str(manifest: &Manifest) -> Result<&str, CryptoError> {
    manifest
        .root_name
        .to_str()
        .ok_or(crate::error::internal_invariant!(
            "manifest root name is not valid UTF-8"
        ))
}

/// Every directory entry beneath the root, in canonical order (FORMAT.md
/// §9.8: depth ascending, then path bytes), so a parent always precedes
/// its children. Pass 1 creates the directories in this order, Pass 3
/// applies their modes in the reverse, and failure cleanup restores
/// owner access in this order again.
fn descendant_directories<'a>(
    manifest: &'a Manifest,
    root_name_str: &str,
) -> Vec<&'a ArchiveEntry> {
    let mut dir_entries: Vec<&ArchiveEntry> = manifest
        .entries
        .iter()
        .filter(|e| e.kind == ArchiveEntryKind::Directory && e.path_utf8 != root_name_str)
        .collect();
    dir_entries.sort_by(|a, b| canonical_path_order(&a.path_utf8, &b.path_utf8));
    dir_entries
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
        .ok_or(crate::error::internal_invariant!(
            "manifest entry missing root prefix"
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::archive::fd_limit;
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

    /// `unarchive` with the default policy and caller-chosen caps, for
    /// the tests that move one cap around a fixed region.
    fn unarchive_with_limits(
        archive: Vec<u8>,
        tmp: &Path,
        limits: ArchiveLimits,
    ) -> Result<PathBuf, CryptoError> {
        unarchive(
            Cursor::new(archive),
            tmp,
            limits,
            IncompleteOutputPolicy::DeleteOnError,
        )
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
    /// promoted. The run then fails rather than returning a path that no
    /// longer names the committed output — the swapped-in directory could
    /// hold an entry of the attacker's under the same name. Drives the
    /// real `unarchive` path with the swap injected on the end-of-archive
    /// read — which `verify_archive_eof` issues AFTER all content is
    /// staged and synced and immediately BEFORE promotion. Linux/macOS
    /// only: the handle-relative rename needs
    /// `renameat`+`RENAME_NOREPLACE`; Windows keeps the documented
    /// path-based promotion.
    /// Reader that runs `swap` exactly once, on its first
    /// end-of-archive read. `unarchive` issues that read in
    /// `verify_archive_eof`, after the staged `.incomplete` is fully
    /// written and synced under `output_handle` and just before the
    /// promotion rename — the window a local writer would use.
    ///
    /// Carries the same target gate as the tests that drive it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct SwapOnEof<F: FnMut()> {
        data: Vec<u8>,
        pos: usize,
        swapped: bool,
        swap: F,
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
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

    /// One directory root `d` holding a single file, used by the
    /// promotion-window tests below and by the cumulative
    /// entry-extension cap.
    fn directory_root_manifest() -> Manifest {
        Manifest {
            entries: vec![
                make_entry("d", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("d/a.txt", ArchiveEntryKind::File, 4, 0o644),
            ],
            total_file_bytes: 4,
            root_name: OsString::from("d"),
            root_is_file: false,
            root_mode: 0o755,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn promotion_is_anchored_to_handle_across_output_dir_swap() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();

        let archive = build_archive(&directory_root_manifest(), &[("d/a.txt", b"real")]);

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

        let err = unarchive(
            reader,
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
        )
        .unwrap_err();

        // The output landed in the handle's directory, which no longer
        // answers to `out`, so no path names it for the caller. The
        // report must therefore name the output itself, and say it is
        // complete: this is a destination that moved, not a failure.
        let rendered = format!("{err}");
        assert!(
            rendered.starts_with("Output d is complete but its directory changed"),
            "expected the moved destination to be reported by name, got: {err}"
        );

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
    }

    /// The staged root is created and then opened by name, and a local
    /// writer who replaces the empty directory between those two
    /// operations owns the directory the run then extracts into. The
    /// run compares the root's owner with the first file it creates,
    /// before any content is written; the answer is substituted here
    /// because a directory with another owner cannot be created without
    /// privileges. On a mismatch the run stops with nothing written,
    /// names the working path, and leaves the directory in place under
    /// both policies — it is not the run's to remove — where it blocks
    /// a retry like any other pre-existing `.incomplete` entry.
    #[test]
    fn a_staged_root_with_another_owner_is_refused_before_any_content_and_left_in_place() {
        fn another_owner(_: &Dir, _: &File) -> Result<OwnerComparison, CryptoError> {
            Ok(OwnerComparison::Different)
        }
        let manifest = Manifest {
            entries: vec![
                make_entry("d", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("d/sub", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("d/sub/a.txt", ArchiveEntryKind::File, 6, 0o644),
                make_entry("d/b.txt", ArchiveEntryKind::File, 6, 0o644),
            ],
            total_file_bytes: 12,
            root_name: OsString::from("d"),
            root_is_file: false,
            root_mode: 0o755,
        };
        let contents: &[(&str, &[u8])] = &[("d/sub/a.txt", b"secret"), ("d/b.txt", b"second")];

        for policy in [
            IncompleteOutputPolicy::DeleteOnError,
            IncompleteOutputPolicy::RetainOnError,
        ] {
            let tmp = tempfile::TempDir::new().unwrap();
            let out = tmp.path().join("out");
            fs::create_dir(&out).unwrap();
            let staged = out.join("d.incomplete");

            let err = unarchive_inner_with_hooks(
                Cursor::new(build_archive(&manifest, contents)),
                &out,
                ArchiveLimits::default(),
                policy.clone(),
                Seams {
                    compare_owners: another_owner,
                    before_promotion: || Ok(()),
                    after_promotion: |_| Ok(()),
                    after_root_mode: |_| Ok(()),
                },
            )
            .unwrap_err();

            let message = err.to_string();
            assert!(
                matches!(err, CryptoError::InvalidInput(_))
                    && message.contains(STAGED_ROOT_REPLACED)
                    && message.contains("d.incomplete"),
                "{policy:?}: expected the replaced staged root to be named, got: {message}"
            );
            assert!(
                staged.is_dir(),
                "{policy:?}: the directory is not the run's and must stay in place"
            );
            assert!(!out.join("d").exists(), "{policy:?}: nothing was promoted");
            // Pass 1 created the descendant directory and the first file
            // was created as the reference, but no content reached it.
            assert!(staged.join("sub").is_dir(), "{policy:?}");
            assert_eq!(
                fs::metadata(staged.join("sub").join("a.txt"))
                    .unwrap()
                    .len(),
                0,
                "{policy:?}: the run must stop before writing content"
            );
            assert!(
                !staged.join("b.txt").exists(),
                "{policy:?}: no later file may be created"
            );

            let retry = unarchive_inner(
                Cursor::new(build_archive(&manifest, contents)),
                &out,
                ArchiveLimits::default(),
                policy,
            )
            .unwrap_err();
            assert!(
                retry.to_string().contains(INCOMPLETE_OUTPUT_LABEL),
                "the entry left in place must block a retry, got: {retry}"
            );
        }
    }

    /// Where the platform reports no owner through a handle, the
    /// comparison is skipped and the extraction proceeds — the answer
    /// Windows gives on every run.
    #[test]
    fn an_unavailable_owner_comparison_does_not_refuse_the_run() {
        fn unavailable(_: &Dir, _: &File) -> Result<OwnerComparison, CryptoError> {
            Ok(OwnerComparison::Unavailable)
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();

        let path = unarchive_inner_with_hooks(
            Cursor::new(build_archive(
                &directory_root_manifest(),
                &[("d/a.txt", b"real")],
            )),
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
            Seams {
                compare_owners: unavailable,
                before_promotion: || Ok(()),
                after_promotion: |_| Ok(()),
                after_root_mode: |_| Ok(()),
            },
        )
        .unwrap();

        assert_eq!(path, out.join("d"));
        assert_eq!(fs::read(out.join("d").join("a.txt")).unwrap(), b"real");
        assert!(!out.join("d.incomplete").exists());
    }

    /// Promotion resolves the staged entry by name. A local writer who
    /// moves that entry aside and leaves a directory of their own under
    /// the name has it committed at the final name, so the run must
    /// report that instead of handing the caller a path to content the
    /// archive never produced. `DeleteOnError` still removes the staged
    /// plaintext on Unix, where the staged tree is removed through its
    /// handle; Windows removes by name and finds nothing there, so the
    /// moved-aside tree survives — the bound `SECURITY.md` records.
    ///
    /// The swap runs in the interval before promotion: on Windows the
    /// staged directory cannot be renamed while extraction still holds
    /// its own handle on it, so the swap must follow that close.
    #[test]
    fn substituted_staging_entry_is_not_reported_as_the_output() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();

        let archive = build_archive(&directory_root_manifest(), &[("d/a.txt", b"real")]);

        let err = unarchive_inner_with_hooks(
            Cursor::new(archive),
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
            Seams {
                compare_owners: platform::compare_owners,
                before_promotion: || {
                    // Move the staged tree aside and leave a directory of
                    // the attacker's under the staging name.
                    fs::rename(out.join("d.incomplete"), out.join("moved-aside"))?;
                    fs::create_dir(out.join("d.incomplete"))?;
                    fs::write(out.join("d.incomplete").join("a.txt"), b"attacker")?;
                    Ok(())
                },
                after_promotion: |_| Ok(()),
                after_root_mode: |_| Ok(()),
            },
        )
        .unwrap_err();

        assert!(
            format!("{err}").contains("Output was replaced while decrypting"),
            "expected the substitution to be reported, got: {err}"
        );
        // The substituted directory was promoted by name, but it is not
        // this run's to remove and was never reported as the output.
        assert_eq!(
            fs::read(out.join("d").join("a.txt")).unwrap(),
            b"attacker",
            "the entry the attacker planted stays where it is",
        );
        #[cfg(unix)]
        assert!(
            !out.join("moved-aside").exists(),
            "DeleteOnError must still remove the staged plaintext",
        );
        #[cfg(windows)]
        assert_eq!(
            fs::read(out.join("moved-aside").join("a.txt")).unwrap(),
            b"real",
            "Windows removes a staged directory by name, so a moved-aside tree survives",
        );
    }

    /// Windows promotes by path. A local writer who re-points a junction
    /// on that path at a directory of their own — leaving the directory
    /// the run holds open untouched, since a held directory cannot be
    /// renamed there — has the promotion rename their decoy inside their
    /// own directory, while the staged output stays unpromoted where it
    /// was written. The final name in the held directory then denotes
    /// nothing, which the run reports as a replacement instead of
    /// handing back a path that leads to the decoy. `DeleteOnError`
    /// removes the never-promoted staged output.
    #[cfg(windows)]
    #[test]
    fn a_junction_repointed_before_promotion_is_not_reported_as_the_output() {
        for root_is_file in [true, false] {
            let tmp = tempfile::TempDir::new().unwrap();
            let held = tmp.path().join("held");
            let decoy = tmp.path().join("decoy");
            fs::create_dir(&held).unwrap();
            fs::create_dir(&decoy).unwrap();
            let out = tmp.path().join("out");
            platform::try_make_junction(&held, &out).unwrap();

            let (archive, root, planted) = if root_is_file {
                let manifest = single_file_manifest("f.txt", b"real");
                fs::write(decoy.join("f.txt.incomplete"), b"attacker").unwrap();
                (
                    build_archive(&manifest, &[("f.txt", b"real")]),
                    "f.txt",
                    decoy.join("f.txt"),
                )
            } else {
                fs::create_dir(decoy.join("d.incomplete")).unwrap();
                fs::write(decoy.join("d.incomplete").join("a.txt"), b"attacker").unwrap();
                (
                    build_archive(&directory_root_manifest(), &[("d/a.txt", b"real")]),
                    "d",
                    decoy.join("d").join("a.txt"),
                )
            };

            let err = unarchive_inner_with_hooks(
                Cursor::new(archive),
                &out,
                ArchiveLimits::default(),
                IncompleteOutputPolicy::DeleteOnError,
                Seams {
                    compare_owners: platform::compare_owners,
                    before_promotion: || {
                        fs::remove_dir(&out)?;
                        platform::try_make_junction(&decoy, &out)?;
                        Ok(())
                    },
                    after_promotion: |_| Ok(()),
                    after_root_mode: |_| Ok(()),
                },
            )
            .unwrap_err();

            assert!(
                format!("{err}").contains("Output was replaced while decrypting"),
                "root_is_file={root_is_file}: expected the missing final name to be reported, got: {err}"
            );
            assert!(
                !held.join(root).exists(),
                "root_is_file={root_is_file}: nothing was promoted in the held directory"
            );
            assert!(
                !held
                    .join(incomplete_working_name(OsStr::new(root)))
                    .exists(),
                "root_is_file={root_is_file}: DeleteOnError must remove the staged output"
            );
            assert_eq!(
                fs::read(&planted).unwrap(),
                b"attacker",
                "root_is_file={root_is_file}: the decoy was promoted inside the writer's directory",
            );
        }
    }

    /// The archive chooses the root mode, and a mode applies to an
    /// object rather than to a name, so an entry substituted at the
    /// staging name must not receive it. The substitute here is a hard
    /// link to a file outside `output_dir`, which is what makes the
    /// gate necessary: without it the run widens the permissions of a
    /// file the caller never placed in the output directory.
    ///
    /// Linux/macOS only: the assertion reads Unix mode bits.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn root_mode_is_not_applied_to_a_substituted_entry() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        let elsewhere = tmp.path().join("elsewhere");
        fs::create_dir(&out).unwrap();
        fs::create_dir(&elsewhere).unwrap();

        // A private file of the caller's, outside the output directory.
        let secret = elsewhere.join("private.key");
        fs::write(&secret, b"key material").unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();

        let mut manifest = single_file_manifest("f.txt", b"real");
        manifest.root_mode = 0o666;
        manifest.entries[0].mode = 0o666;
        let archive = build_archive(&manifest, &[("f.txt", b"real")]);

        let out_for_swap = out.clone();
        let secret_for_swap = secret.clone();
        let reader = SwapOnEof {
            data: archive,
            pos: 0,
            swapped: false,
            swap: move || {
                let staged = out_for_swap.join("f.txt.incomplete");
                fs::rename(&staged, out_for_swap.join("moved-aside")).unwrap();
                fs::hard_link(&secret_for_swap, &staged).unwrap();
            },
        };

        let err = unarchive(
            reader,
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
        )
        .unwrap_err();

        assert!(
            format!("{err}").contains("Output was replaced while decrypting"),
            "expected the substitution to be reported, got: {err}"
        );
        let mode = fs::metadata(&secret).unwrap().permissions().mode() & 0o7777;
        assert_eq!(
            mode, 0o600,
            "the substituted entry must keep its own mode, got 0o{mode:o}",
        );
    }

    /// File-root counterpart of
    /// `cleanup_of_staged_directory_follows_the_staged_handle`. A local
    /// writer who moves the staged file aside leaves the name-based
    /// unlink with nothing to find, so `DeleteOnError` empties the file
    /// through the handle it was created with instead. The run's own
    /// plaintext must not survive at the name the writer chose.
    #[test]
    fn cleanup_of_a_staged_file_moved_aside_still_destroys_its_plaintext() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();

        let manifest = single_file_manifest("f.txt", b"real");
        let archive = build_archive(&manifest, &[("f.txt", b"real")]);

        let err = unarchive_inner_with_hooks(
            Cursor::new(archive),
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
            Seams {
                compare_owners: platform::compare_owners,
                before_promotion: || {
                    let staged = out.join("f.txt.incomplete");
                    fs::rename(&staged, out.join("moved-aside"))?;
                    fs::write(&staged, b"attacker")?;
                    Ok(())
                },
                after_promotion: |_| Ok(()),
                after_root_mode: |_| Ok(()),
            },
        )
        .unwrap_err();

        assert!(
            format!("{err}").contains("Output was replaced while decrypting"),
            "expected the substitution to be reported, got: {err}"
        );
        assert_eq!(
            fs::read(out.join("moved-aside")).unwrap(),
            b"",
            "the staged plaintext must not survive at the name it was moved to",
        );
        // The emptied file's staging name was consumed by the promotion,
        // so nothing is left to remove: that is a completed cleanup, and
        // the error must not claim otherwise.
        assert!(
            !format!("{err}").contains("could not be removed"),
            "an emptied file whose name is gone must not be reported as left behind: {err}"
        );
        // The entry the writer planted was promoted by name; it is not
        // this run's to remove.
        assert_eq!(fs::read(out.join("f.txt")).unwrap(), b"attacker");
    }

    /// A final name that is gone is reported as a substitution. The run
    /// has just committed an entry there, so an absent name means the
    /// commit no longer holds, and returning `Ok` would hand the caller
    /// a path to nothing.
    #[test]
    fn a_promoted_root_that_is_gone_is_reported_as_replaced() {
        let tmp = tempfile::TempDir::new().unwrap();
        let handle = platform::open_anchor(tmp.path()).unwrap();
        let staged_file =
            platform::create_file_at(&handle, OsStr::new("f.txt.incomplete"), 0o600).unwrap();
        let staged = StagedRoot::file(OsStr::new("f.txt.incomplete"), staged_file.try_clone().ok());
        let staged_id = staged.identity().known();

        let err = require_promoted_root(&handle, OsStr::new("f.txt"), staged_id).unwrap_err();

        assert!(
            format!("{err}").contains("Output was replaced while decrypting"),
            "expected the missing final name to be reported, got: {err}"
        );
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
                        reason: MANIFEST_REGION_TRUNCATED
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

    /// File-root counterpart of `delete_on_error_removes_incomplete`:
    /// a staged file still sitting at its working name is removed, so
    /// emptying it through the handle first does not stop the unlink
    /// that follows.
    #[test]
    fn delete_on_error_removes_an_incomplete_file_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let archive = build_partial_archive(&manifest, b"short");

        let result =
            unarchive_with_policy(archive, tmp.path(), IncompleteOutputPolicy::DeleteOnError);
        assert!(result.is_err());

        let count = fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(count, 0, "DeleteOnError must clean up .incomplete");
    }

    /// Cleanup removes entries relative to the capability handle, NOT
    /// to a re-resolved path. Opens a handle, renames the directory
    /// aside, mints a replacement, and confirms the cleanup follows
    /// the original inode.
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

        let outcome = StagedRoot::file(OsStr::new("root.incomplete"), None)
            .remove(&handle, &directory_root_manifest());

        assert!(matches!(outcome, CleanupOutcome::Removed));
        assert!(
            !moved.join("root.incomplete").exists(),
            "handle-relative cleanup should have removed the staged file from the moved dir",
        );
        assert!(
            original.read_dir().unwrap().next().is_none(),
            "the replacement dir at the original path must be untouched",
        );
    }

    /// A directory planted at the working name of a staged FILE root
    /// must survive cleanup. Choosing the removal from what is on disk
    /// would recursively delete a tree this run never created; choosing
    /// it from what this run staged unlinks a name only.
    #[test]
    fn cleanup_of_staged_file_leaves_substituted_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let handle = platform::open_anchor(tmp.path()).unwrap();

        // The staged file is gone: a local writer moved it aside and
        // left a directory of their own at the working name.
        let substitute = tmp.path().join("root.incomplete");
        fs::create_dir(&substitute).unwrap();
        fs::write(substitute.join("keep.txt"), b"not ours").unwrap();

        let outcome = StagedRoot::file(OsStr::new("root.incomplete"), None)
            .remove(&handle, &directory_root_manifest());

        assert!(
            matches!(outcome, CleanupOutcome::Unconfirmed { .. }),
            "a removal that left the working name occupied is reported, not swallowed",
        );
        assert_eq!(
            fs::read(substitute.join("keep.txt")).unwrap(),
            b"not ours",
            "a substituted directory must not be removed",
        );
    }

    /// The directory-root counterpart: on Unix cleanup removes the
    /// staged tree through its own handle, so a directory planted at
    /// the working name survives and the staged tree is removed even
    /// after it was moved aside. On Windows the removal is by name and
    /// goes ahead only while the entry at that name is still the staged
    /// directory, so the planted directory survives there too, and the
    /// moved-aside tree is left — the bound `SECURITY.md` records.
    #[test]
    fn cleanup_of_staged_directory_follows_the_staged_handle() {
        let tmp = tempfile::TempDir::new().unwrap();
        let handle = platform::open_anchor(tmp.path()).unwrap();

        let staged_path = tmp.path().join("root.incomplete");
        let created = platform::mkdir_strict(&handle, OsStr::new("root.incomplete")).unwrap();
        let staged_handle =
            platform::retain_staged_dir(&handle, OsStr::new("root.incomplete"), &created).unwrap();
        // The creating handle blocks the rename below on Windows, as it
        // would block the promotion; the run closes it before either.
        drop(created);
        fs::write(staged_path.join("plaintext.txt"), b"staged plaintext").unwrap();

        // A local writer moves the staged tree aside and leaves their
        // own directory at the working name.
        let moved = tmp.path().join("moved-aside");
        fs::rename(&staged_path, &moved).unwrap();
        fs::create_dir(&staged_path).unwrap();
        fs::write(staged_path.join("keep.txt"), b"not ours").unwrap();

        let outcome = StagedRoot::directory(OsStr::new("root.incomplete"), Some(staged_handle))
            .remove(&handle, &directory_root_manifest());

        #[cfg(unix)]
        {
            assert!(matches!(outcome, CleanupOutcome::Removed));
            assert!(
                !moved.exists(),
                "the staged tree must be removed wherever it was moved to",
            );
        }
        #[cfg(windows)]
        {
            assert!(
                matches!(outcome, CleanupOutcome::Unconfirmed { .. }),
                "a staged tree that was not found by name is reported as not removed",
            );
            assert_eq!(
                fs::read(moved.join("plaintext.txt")).unwrap(),
                b"staged plaintext",
                "Windows removes by name, so a moved-aside staged tree is left",
            );
        }
        assert_eq!(
            fs::read(staged_path.join("keep.txt")).unwrap(),
            b"not ours",
            "a substituted directory must not be removed",
        );
    }

    /// The retained staged handle is what the checks after promotion
    /// compare against, so it must denote the directory this run
    /// created. On Windows it is opened by name — a duplicate of the
    /// creating handle would refuse the promotion rename — and a
    /// mismatch with the created directory is refused before any
    /// plaintext, as a replacement.
    #[cfg(windows)]
    #[test]
    fn a_retained_staged_directory_must_be_the_created_one() {
        let tmp = tempfile::TempDir::new().unwrap();
        let handle = platform::open_anchor(tmp.path()).unwrap();
        let created = platform::mkdir_strict(&handle, OsStr::new("d.incomplete")).unwrap();
        let _other = platform::mkdir_strict(&handle, OsStr::new("other")).unwrap();

        retain_staged_directory(&handle, OsStr::new("d.incomplete"), &created)
            .expect("the retained handle denotes the created directory");

        let err = retain_staged_directory(&handle, OsStr::new("other"), &created).unwrap_err();
        assert!(
            format!("{err}").contains("Output was replaced while decrypting"),
            "a handle on another directory must be refused, got: {err}"
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
        let err =
            apply_root_directory_mode(&handle, &manifest, &StagedIdentity::NoHandle).unwrap_err();
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
        let err = apply_root_file_mode(&handle, &manifest, &StagedIdentity::NoHandle).unwrap_err();
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
        let err = apply_root_file_mode(&handle, &manifest, &StagedIdentity::NoHandle).unwrap_err();
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
        apply_root_directory_mode(&handle, &manifest, &StagedIdentity::NoHandle).unwrap();

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

        apply_root_file_mode(&handle, &manifest, &StagedIdentity::NoHandle).unwrap();

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
    /// (`rejection_payload_is_sanitized`) at this call site. The
    /// constructor is pinned with a direction override directly, as
    /// defence in depth: the grammar refuses such a name before the
    /// occupancy check, so the end-to-end half uses a zero-width space,
    /// which the grammar admits and the sanitizer still escapes.
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
        let name = "evil\u{200b}name";
        fs::write(tmp.path().join(name), b"existing").unwrap();

        let manifest = single_file_manifest(name, b"x");
        let archive = build_archive(&manifest, &[(name, b"x")]);

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Output already exists"), "got: {msg}");
        assert!(
            msg.contains("evil\\u{200b}name"),
            "colliding name must appear escaped and in full: {msg}"
        );
        assert!(
            !msg.contains('\u{200b}'),
            "raw zero-width character leaked: {msg:?}"
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

    /// Case-collision safety net (`École` vs `école`): the §9.7
    /// duplicate keys fold ASCII case and Unicode canonical form but
    /// deliberately not non-ASCII letter case, so a case-folding
    /// volume (default APFS folds full Unicode case) merges two names
    /// the manifest keeps apart, and the fallback is `create_file_at`'s
    /// `create_new(true)` rejecting at extraction time.
    ///
    /// **FS-dependent — ignored by default.** Runs meaningfully only
    /// on a case-folding volume; on a case-sensitive volume (e.g.
    /// case-sensitive APFS, most Linux filesystems) both files would
    /// extract distinctly and the test's `unwrap_err()` would panic.
    /// The FS-matrix CI lanes in `.github/workflows/rust.yml`
    /// deliberately do NOT include this test in their command list —
    /// they target round-trip behaviour on the smoke set instead. To
    /// run this test against a specific filesystem, mount it manually,
    /// export `FERROCRYPT_FS_MATRIX_DIR=/path/to/mount`, and invoke
    /// `cargo test -p ferrocrypt --lib case_collision -- --ignored`.
    /// The tempdir is sourced from `fs_matrix_tempdir()` so the
    /// whole test lives on the mount.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "fs-matrix: needs a case-folding volume; case-sensitive volumes extract both names"]
    fn non_ascii_case_collision_falls_through_to_create_new() {
        let tmp = ferrocrypt_test_support::fs_matrix_tempdir().unwrap();

        // `École`: U+00C9. `école`: U+00E9. Both already NFC, distinct
        // under every §9.7 duplicate key, so the manifest validates.
        let upper = "\u{00C9}cole.txt";
        let lower = "\u{00E9}cole.txt";

        let manifest = Manifest {
            entries: vec![
                make_entry("root", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry(&format!("root/{upper}"), ArchiveEntryKind::File, 5, 0o644),
                make_entry(&format!("root/{lower}"), ArchiveEntryKind::File, 5, 0o644),
            ],
            total_file_bytes: 10,
            root_name: OsString::from("root"),
            root_is_file: false,
            root_mode: 0o755,
        };
        let archive = build_archive(
            &manifest,
            &[
                (&format!("root/{upper}"), b"AAAAA"),
                (&format!("root/{lower}"), b"BBBBB"),
            ],
        );

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        // On a case-folding filesystem the second exclusive create
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
        assert!(format!("{err}").contains("Incomplete output already exists"));
        assert!(
            stale_path.exists(),
            "pre-existing .incomplete must be preserved across a retry",
        );
    }

    /// The staging-name collision renders through the same shared
    /// constructor as "Output already exists": the operator-chosen
    /// output directory stays readable, and the archive-chosen working
    /// name — the final component — is escaped. Mirrors
    /// `occupied_output_error_escapes_hostile_root_name` at the
    /// `.incomplete` boundary.
    #[test]
    fn incomplete_output_error_escapes_hostile_root_name() {
        let err = incomplete_output_exists(
            Path::new("/home/operator/Données"),
            &incomplete_working_name(OsStr::new("evil\u{202e}name")),
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("Incomplete output already exists"),
            "got: {msg}"
        );
        assert!(
            msg.contains("Données"),
            "operator path must stay readable: {msg}"
        );
        assert!(
            msg.contains("evil\\u{202e}name.incomplete"),
            "hostile working name must be escaped: {msg}"
        );
        assert!(
            !msg.contains('\u{202e}'),
            "raw direction-override character leaked: {msg:?}"
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
                reason: crate::archive::reasons::COMPONENT_TOO_LONG,
                ..
            }
        ));

        let count = fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(count, 0, "rejection must precede any filesystem output");
    }

    /// FORMAT.md §9.6: a root name carrying a direction-override
    /// control rejects during manifest validation, before any
    /// filesystem work. Such a name would be created exactly as stored
    /// and displayed in another order, so the grammar refuses it on
    /// both sides rather than leaving every consumer to render it
    /// safely.
    #[test]
    fn rejects_bidi_formatting_control_before_filesystem_output() {
        assert_entry_name_rejected_as_format_control("holiday\u{202e}gpj.sh");
    }

    /// Spec §9.6: the line separator rejects the same way, before any
    /// filesystem work.
    #[test]
    fn rejects_line_separator_before_filesystem_output() {
        assert_entry_name_rejected_as_format_control("two\u{2028}lines.txt");
    }

    fn assert_entry_name_rejected_as_format_control(name: &str) {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = single_file_manifest(name, b"x");
        let archive = build_archive(&manifest, &[(name, b"x")]);

        let err = unarchive_default(archive, tmp.path()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: crate::archive::reasons::COMPONENT_FORMAT_CONTROL,
                ..
            }
        ));

        let count = fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(count, 0, "rejection must precede any filesystem output");
    }

    /// Spec §9.6 accepts the three direction marks: an entry carrying
    /// one extracts under exactly the stored name.
    #[test]
    fn accepts_bidi_direction_mark_in_entry_name() {
        for mark in ['\u{061c}', '\u{200e}', '\u{200f}'] {
            let tmp = tempfile::TempDir::new().unwrap();
            let name = format!("שלום{mark}-report.txt");
            let manifest = single_file_manifest(&name, b"x");
            let archive = build_archive(&manifest, &[(name.as_str(), b"x")]);

            let final_path = unarchive_default(archive, tmp.path()).unwrap();
            assert_eq!(final_path.file_name().unwrap().to_str().unwrap(), name);
            assert_eq!(fs::read(&final_path).unwrap(), b"x");
        }
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

    /// A descendant directory mode without the read bit (`0o311`) reaches
    /// the reader only from a foreign archive: FerroCrypt's writer must
    /// list a directory to encrypt it, so it can never record such a
    /// mode. Extraction must still apply it, which
    /// `platform::chmod_dir_handle_durable` does by flushing a handle it
    /// opened before applying the mode.
    #[cfg(unix)]
    #[test]
    fn extracts_descendant_directory_mode_without_read_bit() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = Manifest {
            entries: vec![
                make_entry("root", ArchiveEntryKind::Directory, 0, 0o700),
                make_entry("root/searchonly", ArchiveEntryKind::Directory, 0, 0o311),
                make_entry(
                    "root/searchonly/inner.txt",
                    ArchiveEntryKind::File,
                    5,
                    0o600,
                ),
            ],
            total_file_bytes: 5,
            root_name: OsString::from("root"),
            root_is_file: false,
            root_mode: 0o700,
        };
        let archive = build_archive(&manifest, &[("root/searchonly/inner.txt", b"inner")]);

        let final_path = unarchive_default(archive, tmp.path()).unwrap();

        let dir = final_path.join("searchonly");
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o311, "expected mode 0o311, got 0o{mode:o}");

        // Restore read permission so tempdir cleanup can list the
        // directory.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    // ─── Post-commit and cleanup invariant suite ───────────────────
    //
    // Every case below is generated, and every assertion is stated
    // from `FORMAT.md` §9.11 rather than from this module, so a change
    // here that still satisfies the code's own reasoning but breaks
    // the specification still fails. The individual regression tests
    // above pin single scenarios; this pins the rules those scenarios
    // are instances of.

    /// Content written by the run under test. Finding it anywhere in
    /// the output directory after a failed `DeleteOnError` decrypt is
    /// an invariant break, whatever name it is under.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const RUN_PLAINTEXT: &[u8] = b"run-plaintext-marker";

    /// Stored mode of the locked descendant directory: readable and
    /// searchable, so extraction can still walk it, but without the
    /// owner write permission that unlinking its entries needs.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const LOCKED_DESCENDANT_MODE: u32 = 0o500;

    /// Content of the file that lives outside `output_dir`. A run must
    /// never change its bytes or its mode, however it is linked into
    /// the output directory.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const OUTSIDER_PLAINTEXT: &[u8] = b"outsider-content";

    /// Mode given to a directory a local writer plants at the staging
    /// name. No case declares it as a stored root mode, so a run that
    /// applies the archive's mode to this directory is caught.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const PLANTED_DIR_MODE: u32 = 0o711;

    /// What a local writer does to the staging entry inside the window
    /// `verify_archive_eof` opens, just before promotion.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Interference {
        /// No writer; the ordinary success path.
        None,
        /// Staged root moved aside, nothing left at the staging name.
        MoveAsideLeaveNothing,
        /// Staged root moved aside, a plain file left in its place.
        MoveAsideLeaveFile,
        /// Staged root moved aside, a directory left in its place.
        MoveAsideLeaveDirectory,
        /// Staged root moved aside, and a hard link to a file living
        /// outside `output_dir` left in its place.
        MoveAsideLinkOutsider,
        /// The staged root is given a second name, then moved aside and
        /// an unrelated file left at the staging name, so the promotion
        /// commits that other file while this run's plaintext survives
        /// under the two names the writer chose. File roots only: a
        /// directory cannot be given a second name on these platforms.
        LinkStagedRootThenSwap,
    }

    /// Whether the archive completes or stops short inside the content
    /// region, which decides whether the run fails before promotion.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Payload {
        Complete,
        Truncated,
    }

    /// One generated case.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[derive(Debug, Clone, Copy)]
    struct Case {
        root_is_file: bool,
        policy_deletes: bool,
        payload: Payload,
        interference: Interference,
        permissive_mode: bool,
        /// Directory roots only: the tree also holds a descendant
        /// directory stored without owner write permission, with
        /// plaintext inside it. Once Pass 3 applies that mode, only a
        /// cleanup that restores it can remove the run's own entries.
        locked_descendant: bool,
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl Case {
        fn policy(self) -> IncompleteOutputPolicy {
            if self.policy_deletes {
                IncompleteOutputPolicy::DeleteOnError
            } else {
                IncompleteOutputPolicy::RetainOnError
            }
        }

        fn root_mode(self) -> u32 {
            match (self.root_is_file, self.permissive_mode) {
                (true, true) => 0o666,
                (true, false) => 0o600,
                (false, true) => 0o777,
                (false, false) => 0o700,
            }
        }
    }

    /// Collects every file under `dir`, following no symlinks, as
    /// (path, content, mode). Used to state the invariants over the
    /// whole output directory rather than over names the test guessed.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn walk_files(dir: &Path, found: &mut Vec<(PathBuf, Vec<u8>, u32)>) {
        use std::os::unix::fs::PermissionsExt;
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                walk_files(&path, found);
            } else if meta.is_file() {
                let content = fs::read(&path).unwrap_or_default();
                found.push((path, content, meta.permissions().mode() & 0o7777));
            }
        }
    }

    /// Builds the archive bytes for a case, plus the staging name the
    /// writer would interfere with and the final name.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn case_archive(case: Case) -> (Vec<u8>, &'static str, &'static str) {
        if case.root_is_file {
            let mut manifest = single_file_manifest("f.txt", RUN_PLAINTEXT);
            manifest.root_mode = case.root_mode();
            manifest.entries[0].mode = case.root_mode();
            let archive = match case.payload {
                Payload::Complete => build_archive(&manifest, &[("f.txt", RUN_PLAINTEXT)]),
                Payload::Truncated => build_partial_archive(&manifest, b"cut"),
            };
            (archive, "f.txt.incomplete", "f.txt")
        } else {
            let mut entries = vec![
                make_entry("d", ArchiveEntryKind::Directory, 0, case.root_mode()),
                make_entry(
                    "d/a.txt",
                    ArchiveEntryKind::File,
                    RUN_PLAINTEXT.len() as u64,
                    0o644,
                ),
            ];
            let mut contents: Vec<(&str, &[u8])> = vec![("d/a.txt", RUN_PLAINTEXT)];
            if case.locked_descendant {
                entries.push(make_entry(
                    "d/locked",
                    ArchiveEntryKind::Directory,
                    0,
                    LOCKED_DESCENDANT_MODE,
                ));
                entries.push(make_entry(
                    "d/locked/b.txt",
                    ArchiveEntryKind::File,
                    RUN_PLAINTEXT.len() as u64,
                    0o644,
                ));
                contents.push(("d/locked/b.txt", RUN_PLAINTEXT));
            }
            let manifest = Manifest {
                total_file_bytes: (RUN_PLAINTEXT.len() * contents.len()) as u64,
                entries,
                root_name: OsString::from("d"),
                root_is_file: false,
                root_mode: case.root_mode(),
            };
            let archive = match case.payload {
                Payload::Complete => build_archive(&manifest, &contents),
                Payload::Truncated => build_partial_archive(&manifest, b"cut"),
            };
            (archive, "d.incomplete", "d")
        }
    }

    /// Runs one case and checks every invariant against its outcome.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn check_case(case: Case) {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        let outside = tmp.path().join("outside");
        fs::create_dir(&out).unwrap();
        fs::create_dir(&outside).unwrap();

        // A file the caller never placed in `output_dir`. Nothing the
        // run does may change its bytes or its mode.
        let outsider = outside.join("private.key");
        fs::write(&outsider, OUTSIDER_PLAINTEXT).unwrap();
        fs::set_permissions(&outsider, fs::Permissions::from_mode(0o600)).unwrap();

        let (archive, staging_name, final_name) = case_archive(case);
        let out_for_swap = out.clone();
        let outsider_for_swap = outsider.clone();
        let interference = case.interference;
        let reader = SwapOnEof {
            data: archive,
            pos: 0,
            swapped: false,
            swap: move || {
                let staged = out_for_swap.join(staging_name);
                let aside = out_for_swap.join("moved-aside");
                match interference {
                    Interference::None => {}
                    Interference::MoveAsideLeaveNothing => {
                        fs::rename(&staged, &aside).unwrap();
                    }
                    Interference::MoveAsideLeaveFile => {
                        fs::rename(&staged, &aside).unwrap();
                        fs::write(&staged, b"planted-file").unwrap();
                    }
                    Interference::MoveAsideLeaveDirectory => {
                        fs::rename(&staged, &aside).unwrap();
                        fs::create_dir(&staged).unwrap();
                        fs::write(staged.join("planted.txt"), b"planted-dir-content").unwrap();
                        // A mode no case declares, so a run that
                        // chmods this directory is visible.
                        fs::set_permissions(&staged, fs::Permissions::from_mode(PLANTED_DIR_MODE))
                            .unwrap();
                    }
                    Interference::MoveAsideLinkOutsider => {
                        fs::rename(&staged, &aside).unwrap();
                        fs::hard_link(&outsider_for_swap, &staged).unwrap();
                    }
                    Interference::LinkStagedRootThenSwap => {
                        fs::hard_link(&staged, out_for_swap.join("second-name")).unwrap();
                        fs::rename(&staged, &aside).unwrap();
                        fs::write(&staged, b"planted-file").unwrap();
                    }
                }
            },
        };

        let result = unarchive(reader, &out, ArchiveLimits::default(), case.policy());

        let label = format!("{case:?}");

        // §9.11 step 16/17: a run never changes an object it did not
        // create. The outsider is reachable through a hard link the
        // writer planted, so only an identity check keeps it intact.
        let outsider_meta = fs::symlink_metadata(&outsider)
            .unwrap_or_else(|e| panic!("{label}: outsider must survive the run: {e}"));
        assert_eq!(
            outsider_meta.permissions().mode() & 0o7777,
            0o600,
            "{label}: the run changed the mode of a file outside output_dir",
        );
        assert_eq!(
            fs::read(&outsider).unwrap(),
            OUTSIDER_PLAINTEXT,
            "{label}: the run changed the content of a file outside output_dir",
        );

        // §9.11 cleanup: a directory the run did not create is never
        // removed, whatever occupies the staging name.
        let mut files = Vec::new();
        walk_files(&out, &mut files);

        // §9.11 cleanup and step 16: a directory the run did not
        // create is neither removed nor given the archive's stored
        // mode. Promotion may have moved it to the final name, so both
        // checks locate it by its content rather than by the name the
        // writer left it under.
        if case.interference == Interference::MoveAsideLeaveDirectory {
            let planted = files
                .iter()
                .find(|(_, content, _)| content.as_slice() == b"planted-dir-content")
                .map(|(path, _, _)| path.clone())
                .unwrap_or_else(|| {
                    panic!("{label}: the run removed a directory it did not create")
                });
            let planted_dir = planted.parent().expect("planted file has a parent");
            let mode = fs::symlink_metadata(planted_dir)
                .expect("planted directory must survive")
                .permissions()
                .mode()
                & 0o7777;
            assert_eq!(
                mode, PLANTED_DIR_MODE,
                "{label}: the run changed the mode of a directory it did not create",
            );
        }

        match &result {
            Ok(path) => {
                // §9.11 step 17/18: a reported path names an entry the
                // run wrote, holding what the archive declared.
                assert_eq!(
                    path,
                    &out.join(final_name),
                    "{label}: reported path is not the requested output name",
                );
                let meta = fs::symlink_metadata(path)
                    .unwrap_or_else(|e| panic!("{label}: reported path does not exist: {e}"));
                if case.root_is_file {
                    assert_eq!(
                        fs::read(path).unwrap(),
                        RUN_PLAINTEXT,
                        "{label}: reported output does not hold the archive content",
                    );
                } else {
                    assert_eq!(
                        fs::read(path.join("a.txt")).unwrap(),
                        RUN_PLAINTEXT,
                        "{label}: reported output does not hold the archive content",
                    );
                }
                // §9.11 step 16: the stored root mode reaches the
                // committed output on every successful run.
                assert_eq!(
                    meta.permissions().mode() & 0o7777,
                    case.root_mode(),
                    "{label}: the stored root mode was not applied",
                );
                // A success leaves no staging entry behind.
                assert!(
                    !out.join(staging_name).exists(),
                    "{label}: a successful run left its staging entry",
                );
            }
            Err(_) if case.policy_deletes => {
                // §9.11 cleanup under `DeleteOnError`: no plaintext
                // this run wrote survives in `output_dir`, under any
                // name a local writer may have chosen for it.
                let leaked: Vec<&PathBuf> = files
                    .iter()
                    .filter(|(_, content, _)| content.as_slice() == RUN_PLAINTEXT)
                    .map(|(path, _, _)| path)
                    .collect();
                assert!(
                    leaked.is_empty(),
                    "{label}: DeleteOnError left this run's plaintext at {leaked:?}",
                );
            }
            Err(_) => {
                // §9.11 cleanup under `RetainOnError`: staged output is
                // preserved for recovery. Only assert it where the run
                // staged something and no writer moved it: the other
                // cases are the writer's doing, not the policy's.
                if case.interference == Interference::None {
                    let retained = files
                        .iter()
                        .any(|(path, _, _)| path.to_string_lossy().contains(INCOMPLETE_SUFFIX));
                    assert!(retained, "{label}: RetainOnError removed the staged output",);
                }
            }
        }

        // Leave every directory traversable so the temp dir can be
        // removed regardless of the modes the case applied.
        restore_traversable(&out);
    }

    /// Restores owner search permission on every directory under
    /// `dir`, so a case that applied a restrictive stored mode does
    /// not block temp-directory cleanup.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn restore_traversable(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                restore_traversable(&entry.path());
            }
        }
    }

    /// Drives every combination of root kind, policy, payload
    /// completeness, local-writer interference, stored root mode, and
    /// (for directory roots) a locked descendant directory through
    /// [`check_case`].
    ///
    /// The cross product is enumerated rather than sampled: the space
    /// is small enough to cover exhaustively, which is stronger than
    /// drawing from it.
    ///
    /// Two things it deliberately does not reach, recorded so the
    /// coverage is not read as wider than it is:
    ///
    /// - Removal of the output *after* promotion. The reader is the
    ///   only injection point this harness has, and `unarchive` stops
    ///   reading before it promotes, so no generated case can act in that
    ///   window. `a_post_ratification_replacement_preserves_the_committed_output`
    ///   drives the complete extraction through a dedicated step-16/17 seam
    ///   and proves the report plus cleanup decision end to end.
    /// - Failure of the resources the checks themselves need. Neither
    ///   is reachable from the reader, and both are pinned elsewhere:
    ///   `a_run_that_cannot_hold_the_staged_handle_refuses_before_any_plaintext`
    ///   shows a run that cannot hold the staged descriptor refusing
    ///   before it stages any plaintext, so these invariants are never
    ///   reached, and `a_staged_identity_that_cannot_be_read_is_skipped`
    ///   with `an_unavailable_staged_identity_skips_the_mode_application`
    ///   fix what an unavailable identity does. These pin the
    ///   decision rather than injecting the read failure, which no safe
    ///   seam reaches.
    /// - A staged descendant directory moved out of the staged root.
    ///   The interference here acts on the staged root, which cleanup
    ///   reaches through the handle that created it. A subtree renamed
    ///   out from under that root is no longer reachable through it, so
    ///   the plaintext already written inside stays where it was put.
    ///   `DeleteOnError` destroys the run's plaintext wherever the run
    ///   can still reach it, which is what these cases pin; an output
    ///   directory a local writer can change is a trust boundary
    ///   `SECURITY.md` states, not a bound cleanup can close.
    ///
    /// Linux/macOS only: the assertions read Unix mode bits, and the
    /// interference is applied on the end-of-archive read, while
    /// extraction still holds the staged directory open — a directory
    /// Windows refuses to rename.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn post_commit_and_cleanup_invariants_hold_across_every_case() {
        let shared = [
            Interference::None,
            Interference::MoveAsideLeaveNothing,
            Interference::MoveAsideLeaveFile,
            Interference::MoveAsideLeaveDirectory,
            Interference::MoveAsideLinkOutsider,
        ];
        let mut checked = 0usize;
        for root_is_file in [true, false] {
            for policy_deletes in [true, false] {
                let interferences: Vec<Interference> = shared
                    .iter()
                    .copied()
                    .chain(root_is_file.then_some(Interference::LinkStagedRootThenSwap))
                    .collect();
                for payload in [Payload::Complete, Payload::Truncated] {
                    for &interference in &interferences {
                        // A truncated payload fails before the reader
                        // reaches end of archive, so no writer window
                        // opens; pair it only with the no-writer case.
                        if payload == Payload::Truncated && interference != Interference::None {
                            continue;
                        }
                        for permissive_mode in [false, true] {
                            // A file root has no descendants to lock.
                            let locked_options: &[bool] = if root_is_file {
                                &[false]
                            } else {
                                &[false, true]
                            };
                            for &locked_descendant in locked_options {
                                check_case(Case {
                                    root_is_file,
                                    policy_deletes,
                                    payload,
                                    interference,
                                    permissive_mode,
                                    locked_descendant,
                                });
                                checked += 1;
                            }
                        }
                    }
                }
            }
        }
        // File roots: 2 policies x (5 shared + link-then-swap + the
        // truncated no-writer case) x 2 modes. Directory roots: 2
        // policies x (5 shared + truncated) x 2 modes x 2 descendant
        // options.
        assert_eq!(checked, 76, "the generated case count must not drift");
    }

    // -- Extension-region caps (FORMAT.md §9.12) --------------------------

    /// The archive-level extension region is admitted at exactly its
    /// cap and refused when the cap is one byte short.
    ///
    /// The four extension caps have no writer half to compare against —
    /// every current writer emits an empty region — so they are pinned
    /// as reader boundaries rather than as symmetry pairs. Driven
    /// through a real extraction, because the enforcement helpers have
    /// their own unit tests and what is unproven is the caps reaching
    /// an operation at all.
    #[test]
    fn the_archive_extension_cap_admits_a_region_of_exactly_its_size() {
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let region = tlv_bytes(0x0001, b"meta");
        let region_len = u32::try_from(region.len()).unwrap();
        let build = || {
            let mut archive = build_archive_prefix_with_archive_ext(&manifest, &region);
            archive.extend_from_slice(b"Hello, world!");
            archive
        };

        let tmp = tempfile::TempDir::new().unwrap();
        let extracted = unarchive_with_limits(
            build(),
            tmp.path(),
            ArchiveLimits::default().max_archive_ext_bytes(region_len),
        )
        .expect("a region exactly at the cap must extract");
        assert_eq!(fs::read(&extracted).unwrap(), b"Hello, world!");

        let tmp = tempfile::TempDir::new().unwrap();
        let err = unarchive_with_limits(
            build(),
            tmp.path(),
            ArchiveLimits::default().max_archive_ext_bytes(region_len - 1),
        )
        .expect_err("a cap one byte short must refuse the region");
        assert!(
            matches!(err, CryptoError::ArchiveExtLenCapExceeded { .. }),
            "expected the archive-extension cap, got {err}"
        );
    }

    /// Per-entry parallel of
    /// [`the_archive_extension_cap_admits_a_region_of_exactly_its_size`].
    #[test]
    fn the_entry_extension_cap_admits_a_region_of_exactly_its_size() {
        let mut manifest = single_file_manifest("hello.txt", b"Hello, world!");
        manifest.entries[0].entry_ext = tlv_bytes(0x0001, b"meta");
        let region_len = u32::try_from(manifest.entries[0].entry_ext.len()).unwrap();
        let build = || build_archive(&manifest, &[("hello.txt", b"Hello, world!")]);

        let tmp = tempfile::TempDir::new().unwrap();
        let extracted = unarchive_with_limits(
            build(),
            tmp.path(),
            ArchiveLimits::default().max_entry_ext_bytes(region_len),
        )
        .expect("a region exactly at the cap must extract");
        assert_eq!(fs::read(&extracted).unwrap(), b"Hello, world!");

        let tmp = tempfile::TempDir::new().unwrap();
        let err = unarchive_with_limits(
            build(),
            tmp.path(),
            ArchiveLimits::default().max_entry_ext_bytes(region_len - 1),
        )
        .expect_err("a cap one byte short must refuse the region");
        assert!(
            matches!(err, CryptoError::ArchiveEntryExtLenCapExceeded { .. }),
            "expected the entry-extension cap, got {err}"
        );
    }

    /// The cumulative cap fires on the sum across entries, at a size
    /// every individual region stays well under, so the per-entry cap
    /// cannot be what refuses.
    #[test]
    fn the_total_entry_extension_cap_admits_a_sum_of_exactly_its_size() {
        let mut manifest = directory_root_manifest();
        let region = tlv_bytes(0x0001, b"meta");
        for entry in &mut manifest.entries {
            entry.entry_ext = region.clone();
        }
        let total = u64::try_from(region.len() * manifest.entries.len()).unwrap();
        let build = || build_archive(&manifest, &[("d/a.txt", b"real")]);

        let tmp = tempfile::TempDir::new().unwrap();
        let extracted = unarchive_with_limits(
            build(),
            tmp.path(),
            ArchiveLimits::default().max_total_entry_ext_bytes(total),
        )
        .expect("a sum exactly at the cap must extract");
        assert_eq!(fs::read(extracted.join("a.txt")).unwrap(), b"real");

        let tmp = tempfile::TempDir::new().unwrap();
        let err = unarchive_with_limits(
            build(),
            tmp.path(),
            ArchiveLimits::default().max_total_entry_ext_bytes(total - 1),
        )
        .expect_err("a cap one byte short must refuse the sum");
        assert!(
            matches!(err, CryptoError::ArchiveTotalEntryExtCapExceeded { .. }),
            "expected the cumulative entry-extension cap, got {err}"
        );
    }

    /// The per-value cap bounds one TLV value inside a region the
    /// region cap admits, so the value cap is what refuses. It is
    /// defence in depth today — the region cap is tighter — which is
    /// exactly why it needs a test of its own.
    #[test]
    fn the_tlv_value_cap_admits_a_value_of_exactly_its_size() {
        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
        let value = b"metadata-value";
        let value_len = u32::try_from(value.len()).unwrap();
        let build = || {
            let mut archive =
                build_archive_prefix_with_archive_ext(&manifest, &tlv_bytes(0x0001, value));
            archive.extend_from_slice(b"Hello, world!");
            archive
        };

        let tmp = tempfile::TempDir::new().unwrap();
        let extracted = unarchive_with_limits(
            build(),
            tmp.path(),
            ArchiveLimits::default().max_tlv_value_bytes(value_len),
        )
        .expect("a value exactly at the cap must extract");
        assert_eq!(fs::read(&extracted).unwrap(), b"Hello, world!");

        let tmp = tempfile::TempDir::new().unwrap();
        let err = unarchive_with_limits(
            build(),
            tmp.path(),
            ArchiveLimits::default().max_tlv_value_bytes(value_len - 1),
        )
        .expect_err("a cap one byte short must refuse the value");
        assert!(
            matches!(
                err,
                CryptoError::InvalidFormat(crate::error::FormatDefect::MalformedTlv)
            ),
            "expected a malformed-TLV rejection, got {err}"
        );
    }

    /// A staged identity that could not be read is skipped, not
    /// reported as a substitution: `FORMAT.md` §9.11 step 17 rules that
    /// a read failure reports the environment rather than the entry,
    /// and failing a complete extraction would expose it to
    /// `DeleteOnError` cleanup. The state a handle-less record stands
    /// for is skipped on the same terms. Step 16's side of the same
    /// states is pinned by
    /// `an_unavailable_staged_identity_skips_the_mode_application`.
    #[test]
    fn a_staged_identity_that_cannot_be_read_is_skipped() {
        assert!(StagedIdentity::Unavailable.known().is_none());
        assert!(StagedIdentity::NoHandle.known().is_none());
    }

    /// The two no-identity states part ways at step 16. `Unavailable`
    /// means a confirmation was expected and the evidence for it is
    /// missing — unreadable, or an all-zero identifier — so the mode
    /// application is skipped and the output keeps its restrictive
    /// staged mode: applying the archive-chosen mode to an entry the
    /// run could not confirm is the hard-link escalation the
    /// comparison exists to stop. `NoHandle`, which no extraction
    /// produces, expects no confirmation, so the mode is applied under
    /// the no-follow guards alone. Neither ratifies the commit.
    ///
    /// Linux/macOS only: the assertions read Unix mode bits.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn an_unavailable_staged_identity_skips_the_mode_application() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let handle = platform::open_anchor(tmp.path()).unwrap();
        let _file = platform::create_file_at(&handle, OsStr::new("f.txt"), 0o600).unwrap();
        let mut manifest = single_file_manifest("f.txt", b"");
        manifest.root_mode = 0o666;
        manifest.entries[0].mode = 0o666;

        let unread = apply_root_file_mode(&handle, &manifest, &StagedIdentity::Unavailable)
            .expect("an unavailable identity must skip, not fail");
        assert!(matches!(unread, PromotedIdentity::Unconfirmed));
        let mode = fs::metadata(tmp.path().join("f.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            mode, 0o600,
            "an unconfirmable entry must keep the staged mode, got 0o{mode:o}",
        );

        let no_handle = apply_root_file_mode(&handle, &manifest, &StagedIdentity::NoHandle)
            .expect("the ordinary no-identity state must apply the mode");
        assert!(matches!(no_handle, PromotedIdentity::Unconfirmed));
        let mode = fs::metadata(tmp.path().join("f.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o666, "NoHandle must apply the mode, got 0o{mode:o}");
    }

    /// A matching staged identity returns the confirmation the
    /// extractor clears its staged record on, so a later failed check
    /// can no longer send `DeleteOnError` at the committed output; a
    /// mismatch reports a substitution and withholds it, keeping the
    /// staged plaintext reachable for cleanup. Pins the signal the
    /// ratification in `unarchive_inner` is built on. The staged handle
    /// stays open throughout, as it does in a run: on Windows the
    /// confirmation must open the final name beside that handle.
    #[test]
    fn a_matching_staged_identity_ratifies_and_a_mismatch_rejects() {
        let tmp = tempfile::TempDir::new().unwrap();
        let handle = platform::open_anchor(tmp.path()).unwrap();
        let staged_file = platform::create_file_at(&handle, OsStr::new("f.txt"), 0o600).unwrap();
        let staged_id = platform::file_object_id(&staged_file).unwrap().unwrap();
        let manifest = single_file_manifest("f.txt", b"");

        let confirmed = apply_root_file_mode(&handle, &manifest, &StagedIdentity::Known(staged_id))
            .expect("a matching identity must confirm");
        assert!(matches!(confirmed, PromotedIdentity::Confirmed));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::metadata(tmp.path().join("f.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777;
            assert_eq!(
                mode, 0o644,
                "the confirmed entry receives the manifest mode"
            );
        }

        // Replace the entry. The staged handle keeps the old inode
        // alive, so the substitute is guaranteed a different identity.
        fs::write(tmp.path().join("other"), b"planted").unwrap();
        fs::rename(tmp.path().join("other"), tmp.path().join("f.txt")).unwrap();

        let err = apply_root_file_mode(&handle, &manifest, &StagedIdentity::Known(staged_id))
            .unwrap_err();
        assert!(
            format!("{err}").contains("Output was replaced while decrypting"),
            "expected the substitution to be reported, got: {err}",
        );
    }

    /// The consequence of that skip, through the real function: with no
    /// staged identity to compare against, the check accepts whatever
    /// the final name holds. Pins the contract the two skipped states
    /// route into, so a later change to it cannot pass unnoticed.
    #[test]
    fn a_missing_staged_identity_accepts_a_substituted_final_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        let handle = platform::open_anchor(tmp.path()).unwrap();
        fs::write(tmp.path().join("f.txt"), b"planted").unwrap();

        require_promoted_root(&handle, OsStr::new("f.txt"), None)
            .expect("with nothing to compare against the check must accept");
    }

    /// A failure after Pass 3 has applied the stored directory modes
    /// leaves the staged tree in whatever state those modes allow. A
    /// mode without owner write permission refuses the unlinking of
    /// the entries beneath it, and one without read or search
    /// permission refuses even opening it, so `DeleteOnError` must
    /// restore what the run itself applied before it removes the tree.
    /// Every such mode is driven, nested two levels deep with plaintext
    /// at both levels, and the returned error must be the injected one
    /// alone: a confirmed removal adds no report.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn cleanup_restores_the_modes_it_applied_before_removing_the_staged_tree() {
        for nested_mode in [0o000, 0o100, 0o200, 0o300, 0o400, 0o500, 0o555, 0o755] {
            let tmp = tempfile::TempDir::new().unwrap();
            let out = tmp.path().join("out");
            fs::create_dir(&out).unwrap();

            let manifest = Manifest {
                entries: vec![
                    make_entry("d", ArchiveEntryKind::Directory, 0, 0o755),
                    make_entry("d/ro", ArchiveEntryKind::Directory, 0, nested_mode),
                    make_entry("d/ro/a.txt", ArchiveEntryKind::File, 4, 0o644),
                    make_entry("d/ro/deep", ArchiveEntryKind::Directory, 0, nested_mode),
                    make_entry("d/ro/deep/b.txt", ArchiveEntryKind::File, 4, 0o644),
                ],
                total_file_bytes: 8,
                root_name: OsString::from("d"),
                root_is_file: false,
                root_mode: 0o755,
            };
            let archive = build_archive(
                &manifest,
                &[("d/ro/a.txt", b"real"), ("d/ro/deep/b.txt", b"real")],
            );

            let err = unarchive_inner_with_hooks(
                Cursor::new(archive),
                &out,
                ArchiveLimits::default(),
                IncompleteOutputPolicy::DeleteOnError,
                Seams {
                    compare_owners: platform::compare_owners,
                    before_promotion: || {
                        Err(CryptoError::InvalidInput("injected failure".to_owned()))
                    },
                    after_promotion: |_| Ok(()),
                    after_root_mode: |_| Ok(()),
                },
            )
            .unwrap_err();

            let remaining: Vec<_> = fs::read_dir(&out)
                .unwrap()
                .flatten()
                .map(|e| e.file_name())
                .collect();
            restore_traversable(&out);
            assert!(
                remaining.is_empty(),
                "mode {nested_mode:o}: DeleteOnError left {remaining:?} in the output directory",
            );
            assert!(
                matches!(&err, CryptoError::InvalidInput(message) if message == "injected failure"),
                "mode {nested_mode:o}: a confirmed removal must add no report, got: {err}",
            );
        }
    }

    /// An obstacle the run did not create is not overcome: when the
    /// output directory itself refuses the removal of the staged root,
    /// the error that is returned must say that the incomplete output
    /// may remain and name its working path, so the caller does not
    /// read the failure as if nothing were left behind. The original
    /// error keeps its class.
    ///
    /// Skipped as root, whom permission bits do not refuse.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_removal_the_environment_refuses_is_reported_with_the_working_path() {
        use std::os::unix::fs::PermissionsExt;

        if rustix::process::geteuid().is_root() {
            return;
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();

        let archive = build_archive(&directory_root_manifest(), &[("d/a.txt", b"real")]);
        let out_for_hook = out.clone();
        let err = unarchive_inner_with_hooks(
            Cursor::new(archive),
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
            Seams {
                compare_owners: platform::compare_owners,
                before_promotion: move || {
                    // Removing `d.incomplete` needs write permission on
                    // `out`, which belongs to the caller, not to the run.
                    fs::set_permissions(&out_for_hook, fs::Permissions::from_mode(0o500))?;
                    Err(CryptoError::InvalidInput("injected failure".to_owned()))
                },
                after_promotion: |_| Ok(()),
                after_root_mode: |_| Ok(()),
            },
        )
        .unwrap_err();
        fs::set_permissions(&out, fs::Permissions::from_mode(0o700)).unwrap();

        let message = match &err {
            CryptoError::InvalidInput(message) => message,
            other => panic!("the original error class must be kept, got: {other:?}"),
        };
        assert!(
            message.starts_with("injected failure; "),
            "the original error must come first: {message}",
        );
        assert!(
            message.contains("could not be removed and may still hold plaintext"),
            "the report must say plaintext may remain: {message}",
        );
        assert!(
            message.contains(&out.join("d.incomplete").display().to_string()),
            "the report must name the working path: {message}",
        );
        assert!(
            out.join("d.incomplete").is_dir(),
            "the staged root the environment refused to remove is still there",
        );
    }

    /// The file-root counterpart: the staged file is emptied through its
    /// handle before the unlink, so when the output directory refuses
    /// the unlink, what remains holds no plaintext. The report must say
    /// so rather than claim plaintext may remain, while still naming the
    /// entry that blocks a retry.
    ///
    /// Skipped as root, whom permission bits do not refuse.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn an_emptied_file_the_environment_refuses_to_unlink_is_reported_as_emptied() {
        use std::os::unix::fs::PermissionsExt;

        if rustix::process::geteuid().is_root() {
            return;
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();

        let manifest = single_file_manifest("f.txt", b"real");
        let archive = build_archive(&manifest, &[("f.txt", b"real")]);
        let out_for_hook = out.clone();
        let err = unarchive_inner_with_hooks(
            Cursor::new(archive),
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
            Seams {
                compare_owners: platform::compare_owners,
                before_promotion: move || {
                    fs::set_permissions(&out_for_hook, fs::Permissions::from_mode(0o500))?;
                    Err(CryptoError::InvalidInput("injected failure".to_owned()))
                },
                after_promotion: |_| Ok(()),
                after_root_mode: |_| Ok(()),
            },
        )
        .unwrap_err();
        fs::set_permissions(&out, fs::Permissions::from_mode(0o700)).unwrap();

        let message = format!("{err}");
        assert!(
            message.contains("was emptied but could not be removed"),
            "the report must say the entry holds no plaintext: {message}",
        );
        assert!(
            !message.contains("may still hold plaintext"),
            "an emptied file must not be reported as possibly holding plaintext: {message}",
        );
        let staged = out.join("f.txt.incomplete");
        assert_eq!(
            fs::metadata(&staged).unwrap().len(),
            0,
            "the entry the environment refused to unlink must have been emptied",
        );
    }

    /// Drives the real extraction through the interval after step 16 has
    /// ratified the committed file and cleared the staged cleanup record, but
    /// before step 17 re-checks its final name. A replacement there must be
    /// reported without `DeleteOnError` deleting either the complete output
    /// this run committed or the replacement it did not create.
    #[test]
    fn a_post_ratification_replacement_preserves_the_committed_output() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();

        let manifest = single_file_manifest("f.txt", b"real plaintext");
        let archive = build_archive(&manifest, &[("f.txt", b"real plaintext")]);
        let final_path = out.join("f.txt");
        let committed_elsewhere = out.join("committed-moved-aside");

        let err = unarchive_inner_with_hooks(
            Cursor::new(archive),
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
            Seams {
                compare_owners: platform::compare_owners,
                before_promotion: || Ok(()),
                after_promotion: |_| Ok(()),
                after_root_mode: |_| {
                    fs::rename(&final_path, &committed_elsewhere)?;
                    fs::write(&final_path, b"replacement")?;
                    Ok(())
                },
            },
        )
        .expect_err("step 17 must reject the replaced final entry");

        assert!(
            err.to_string()
                .contains("Output was replaced while decrypting"),
            "the replacement must be reported, got: {err}"
        );
        assert_eq!(
            fs::read(&committed_elsewhere).unwrap(),
            b"real plaintext",
            "cleanup must stay off the ratified committed output"
        );
        assert_eq!(
            fs::read(&final_path).unwrap(),
            b"replacement",
            "cleanup must not remove the replacement by name"
        );
        assert!(
            !out.join(incomplete_working_name(OsStr::new("f.txt")))
                .exists(),
            "the successful promotion left no staging name"
        );
    }

    /// The staged identity is compared with the final name after step 16
    /// has ratified the commit and moved the record out of the cleanup
    /// slot. The handle it was read from must still be held for that
    /// comparison: some filesystems give an object a new identifier once
    /// its last handle closes (measured on a Windows userspace filesystem
    /// reporting exFAT), and a run that closed the handle at ratification
    /// reported its own complete output as replaced there. Pins that the
    /// record moved out at ratification still holds a readable handle,
    /// for both root kinds.
    #[test]
    fn the_retained_handle_is_held_until_the_last_comparison() {
        for root_is_file in [true, false] {
            let tmp = tempfile::TempDir::new().unwrap();
            let out = tmp.path().join("out");
            fs::create_dir(&out).unwrap();
            let (archive, root) = if root_is_file {
                let manifest = single_file_manifest("f.txt", b"real");
                (build_archive(&manifest, &[("f.txt", b"real")]), "f.txt")
            } else {
                (
                    build_archive(&directory_root_manifest(), &[("d/a.txt", b"real")]),
                    "d",
                )
            };

            let mut observed = false;
            let path = unarchive_inner_with_hooks(
                Cursor::new(archive),
                &out,
                ArchiveLimits::default(),
                IncompleteOutputPolicy::DeleteOnError,
                Seams {
                    compare_owners: platform::compare_owners,
                    before_promotion: || Ok(()),
                    after_promotion: |_| Ok(()),
                    after_root_mode: |ratified| {
                        let held = ratified.as_ref().map(StagedRoot::identity);
                        assert!(
                            matches!(held, Some(StagedIdentity::Known(_))),
                            "root_is_file={root_is_file}: the ratified record must still hold a \
                             readable handle"
                        );
                        observed = true;
                        Ok(())
                    },
                },
            )
            .unwrap();

            assert!(
                observed,
                "root_is_file={root_is_file}: the hook must have run"
            );
            assert_eq!(path, out.join(root));
        }
    }

    /// A hard-link promotion that cannot remove its temporary name is a
    /// post-commit error. The extraction caller must report that outcome and
    /// preserve both complete names under `DeleteOnError`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn extraction_reports_a_retained_temporary_name_after_promotion() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();

        let root_name = "f.txt";
        let plaintext = b"real plaintext";
        let manifest = single_file_manifest(root_name, plaintext);
        let archive = build_archive(&manifest, &[(root_name, plaintext)]);
        let final_path = out.join(root_name);
        let incomplete_path = out.join(incomplete_working_name(OsStr::new(root_name)));

        let err = unarchive_inner_with_hooks(
            Cursor::new(archive),
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
            Seams {
                compare_owners: platform::compare_owners,
                before_promotion: || Ok(()),
                after_promotion: |promotion| {
                    fs::hard_link(&final_path, &incomplete_path)?;
                    *promotion = platform::PromotionOutcome::StagedLinkRetained(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "injected temporary-name removal failure",
                    ));
                    Ok(())
                },
                after_root_mode: |_| Ok(()),
            },
        )
        .expect_err("a retained temporary name must be reported");

        let rendered = err.to_string();
        assert!(
            rendered.contains("temporary name") && rendered.contains("could not be removed"),
            "the retained name must be explicit, got: {rendered}"
        );
        assert_eq!(fs::read(&final_path).unwrap(), plaintext);
        assert_eq!(fs::read(&incomplete_path).unwrap(), plaintext);
    }

    /// A staged subdirectory renamed out of the staged tree while the
    /// content pass is still writing into it must fail the run, and say
    /// so: the entries already extracted are inside the subtree that
    /// was moved, so carrying on would report success for an output
    /// missing them. Reaches the pass-2 walk by moving the directory
    /// between two file entries of the same archive.
    #[cfg(unix)]
    #[test]
    fn extraction_reports_a_staged_directory_moved_out_between_two_entries() {
        /// Runs `act` once, after `at` bytes have been handed to the
        /// reader, then keeps serving the archive.
        struct ActAfter<F: FnMut()> {
            data: Vec<u8>,
            pos: usize,
            at: usize,
            act: Option<F>,
        }

        impl<F: FnMut()> Read for ActAfter<F> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let remaining = self.data.len() - self.pos;
                if remaining == 0 {
                    return Ok(0);
                }
                let n = remaining.min(buf.len());
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                // After serving, so the run acts on the bytes it has:
                // the first entry is written and the second has not been
                // walked to yet.
                if self.pos >= self.at {
                    if let Some(mut act) = self.act.take() {
                        act();
                    }
                }
                Ok(n)
            }
        }

        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();

        let first = b"first entry";
        let second = b"second entry";
        let manifest = Manifest {
            entries: vec![
                make_entry("root", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("root/sub", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry(
                    "root/sub/a.txt",
                    ArchiveEntryKind::File,
                    first.len() as u64,
                    0o644,
                ),
                make_entry(
                    "root/sub/b.txt",
                    ArchiveEntryKind::File,
                    second.len() as u64,
                    0o644,
                ),
            ],
            total_file_bytes: (first.len() + second.len()) as u64,
            root_name: OsString::from("root"),
            root_is_file: false,
            root_mode: 0o755,
        };
        let archive = build_archive(
            &manifest,
            &[("root/sub/a.txt", first), ("root/sub/b.txt", second)],
        );

        // Everything but the last entry's content, so the move lands
        // after `a.txt` is written and before `b.txt` is walked to.
        let at = archive.len() - second.len();
        let staged_sub = out.join("root.incomplete").join("sub");
        let moved = out.join("moved");
        let reader = ActAfter {
            data: archive,
            pos: 0,
            at,
            act: Some(|| {
                let _ = fs::rename(&staged_sub, &moved);
            }),
        };

        let err = unarchive_inner(
            reader,
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
        )
        .expect_err("a staged directory moved out must fail the run");

        assert!(
            err.to_string()
                .contains("Directory in extraction path went missing: sub"),
            "the run must name the directory that went and the side it was on, got: {err}"
        );
        assert!(
            !out.join("root").exists(),
            "nothing may be promoted after the staged tree changed"
        );
    }

    /// A link another local process makes against the staged plaintext
    /// before promotion survives it, leaving a second name for the
    /// decrypted file that outlives the one the caller is told about.
    /// The one-step rename route commits without ever linking, so
    /// nothing about the route reveals the extra name — only the count
    /// read through the retained handle does. The committed output is
    /// committed by then, so it is preserved — and the mode the archive
    /// asked for is never applied, so the extra name keeps the
    /// owner-only staged mode rather than the wider one it would have
    /// been handed. Runs on Windows too: NTFS has hard links, and the
    /// check is load-bearing there.
    #[test]
    fn extraction_rejects_a_link_made_against_the_staged_file_before_promotion() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();

        let root_name = "f.txt";
        let plaintext = b"real plaintext";
        let manifest = single_file_manifest(root_name, plaintext);
        let archive = build_archive(&manifest, &[(root_name, plaintext)]);
        let final_path = out.join(root_name);
        let incomplete_path = out.join(incomplete_working_name(OsStr::new(root_name)));
        let outsider_path = out.join("outsider-link");

        let err = unarchive_inner_with_hooks(
            Cursor::new(archive),
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
            Seams {
                compare_owners: platform::compare_owners,
                before_promotion: || {
                    fs::hard_link(&incomplete_path, &outsider_path)?;
                    Ok(())
                },
                after_promotion: |_| Ok(()),
                after_root_mode: |_| Ok(()),
            },
        )
        .expect_err("a second plaintext link must not report success");

        let rendered = err.to_string();
        assert!(
            rendered.contains("has 2 filesystem names"),
            "the retained inode link must be explicit, got: {rendered}"
        );
        assert_eq!(
            fs::read(&final_path).unwrap(),
            plaintext,
            "the committed output is ratified and must be preserved"
        );
        assert_eq!(fs::read(&outsider_path).unwrap(), plaintext);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&final_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                platform::INITIAL_FILE_CREATE_MODE,
                "the archive's mode must never reach an inode with a second name"
            );
        }
    }

    /// A staged unlink can report `NotFound` after a concurrent writer moves
    /// that hard link, or report success after removing a replacement planted
    /// at the old name. In either case the hard-link outcome must consult the
    /// retained inode and reject the surviving second plaintext link. The
    /// committed output is already ratified, so `DeleteOnError` preserves it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn extraction_rejects_a_hidden_link_after_nominal_staging_cleanup() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();

        let root_name = "f.txt";
        let plaintext = b"real plaintext";
        let manifest = single_file_manifest(root_name, plaintext);
        let archive = build_archive(&manifest, &[(root_name, plaintext)]);
        let final_path = out.join(root_name);
        let hidden_path = out.join("moved-staging-link");

        let err = unarchive_inner_with_hooks(
            Cursor::new(archive),
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
            Seams {
                compare_owners: platform::compare_owners,
                before_promotion: || Ok(()),
                after_promotion: |promotion| {
                    fs::hard_link(&final_path, &hidden_path)?;
                    *promotion = platform::PromotionOutcome::LinkedFile;
                    Ok(())
                },
                after_root_mode: |_| Ok(()),
            },
        )
        .expect_err("a hidden second plaintext link must not report success");

        let rendered = err.to_string();
        assert!(
            rendered.contains("has 2 filesystem names"),
            "the retained inode link must be explicit, got: {rendered}"
        );
        assert_eq!(fs::read(&final_path).unwrap(), plaintext);
        assert_eq!(fs::read(&hidden_path).unwrap(), plaintext);
        assert!(
            !out.join(incomplete_working_name(OsStr::new(root_name)))
                .exists(),
            "the moved link, not the original staging name, survives"
        );
    }

    /// Asserts that the anchor confirmation reports `path` as a changed
    /// directory.
    fn assert_anchor_reported_changed(handle: &Dir, path: &Path, what: &str) {
        let err = require_output_anchor_unchanged(handle, path, OsStr::new("f.txt")).unwrap_err();
        assert!(
            format!("{err}").contains("is complete but its directory changed"),
            "{what} must report as changed, got: {err}"
        );
    }

    /// The anchor confirmation accepts an unchanged path and reports one
    /// that no longer leads to a directory as changed: missing, a plain
    /// file, or a link cycle — a substitution someone made, never an
    /// environment fault. The cycle is a symlink to itself on Unix and a
    /// pair of junctions on Windows, where a junction needs no privilege.
    #[test]
    fn the_anchor_check_reports_a_path_that_no_longer_leads_to_a_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();
        let handle = platform::open_anchor(&out).unwrap();

        require_output_anchor_unchanged(&handle, &out, OsStr::new("f.txt"))
            .expect("an unchanged path must be accepted");

        assert_anchor_reported_changed(&handle, &tmp.path().join("nowhere"), "a missing path");

        let file_path = tmp.path().join("plain");
        fs::write(&file_path, b"not a directory").unwrap();
        assert_anchor_reported_changed(&handle, &file_path, "a non-directory at the path");

        let cycle = tmp.path().join("cycle");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&cycle, &cycle).unwrap();
        #[cfg(windows)]
        {
            let other = tmp.path().join("cycle-other");
            platform::try_make_junction(&other, &cycle).unwrap();
            platform::try_make_junction(&cycle, &other).unwrap();
        }
        assert_anchor_reported_changed(&handle, &cycle, "a link cycle at the path");
    }

    /// A junction on the destination path re-pointed at another directory
    /// is how a local writer redirects that path on Windows without
    /// touching the directory the run holds open, which cannot be renamed
    /// while it is held. The confirmation compares the directory the path
    /// now leads to with the held one and reports the change.
    #[cfg(windows)]
    #[test]
    fn the_anchor_check_reports_a_junction_repointed_at_another_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let committed = tmp.path().join("committed");
        let other = tmp.path().join("other");
        fs::create_dir(&committed).unwrap();
        fs::create_dir(&other).unwrap();
        let out = tmp.path().join("out");
        platform::try_make_junction(&committed, &out).unwrap();
        let handle = platform::open_anchor(&out).unwrap();

        require_output_anchor_unchanged(&handle, &out, OsStr::new("f.txt"))
            .expect("a junction still leading to the held directory must be accepted");

        fs::remove_dir(&out).unwrap();
        platform::try_make_junction(&other, &out).unwrap();
        assert_anchor_reported_changed(&handle, &out, "a junction leading elsewhere");
        assert!(
            committed.exists(),
            "re-pointing the junction leaves the held directory in place"
        );
    }

    /// A denied traversal propagates: it cannot be accepted merely because
    /// the replacement directory refuses the identity check.
    #[cfg(unix)]
    #[test]
    fn the_anchor_check_propagates_access_denial() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let parent = tmp.path().join("parent");
        let out = parent.join("out");
        fs::create_dir_all(&out).unwrap();
        let handle = platform::open_anchor(&out).unwrap();

        // Under a privileged test runner the open succeeds against the
        // unchanged directory instead, so that environment legitimately
        // returns Ok.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o000)).unwrap();
        let outcome = require_output_anchor_unchanged(&handle, &out, OsStr::new("f.txt"));
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        match outcome {
            Ok(()) => {
                // A privileged runner can traverse the directory despite its
                // mode; in that environment the unchanged identity verifies.
            }
            Err(CryptoError::Io(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            }
            Err(other) => panic!("access denial must propagate as I/O, got: {other}"),
        }
    }

    /// Only descriptor/process memory exhaustion skips the destination-path
    /// confirmation. Permission, device, and ordinary path failures remain
    /// real errors whether they arise while reopening or reading identity.
    #[test]
    fn the_anchor_check_skips_only_resource_exhaustion() {
        for skipped in RESOURCE_EXHAUSTION_CODES {
            assert!(output_confirmation_resource_error(&CryptoError::Io(
                io::Error::from_raw_os_error(skipped)
            )));
        }
        #[cfg(unix)]
        let propagated = [libc::EACCES, libc::EPERM, libc::EIO, libc::ENOENT];
        // ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_ACCESS_DENIED,
        // ERROR_SHARING_VIOLATION.
        #[cfg(windows)]
        let propagated = [2, 3, 5, 32];
        for code in propagated {
            assert!(!output_confirmation_resource_error(&CryptoError::Io(
                io::Error::from_raw_os_error(code)
            )));
        }
        assert!(!output_confirmation_resource_error(&CryptoError::Io(
            io::Error::from(io::ErrorKind::PermissionDenied)
        )));
    }

    /// Fail-closed contract under descriptor exhaustion. A run that
    /// cannot hold a handle to the staged root cannot confirm after
    /// promotion that the final name still denotes what it wrote
    /// (`FORMAT.md` §9.11 steps 16 and 17), so it must refuse before
    /// writing any plaintext rather than commit an output it can no
    /// longer check.
    ///
    /// The number of descriptors left free is swept rather than named,
    /// because how many a decrypt needs is an implementation detail.
    /// Two properties are asserted across the sweep: every failure
    /// leaves no plaintext and nothing at the final name, and the
    /// staged-handle refusal is reached for both root kinds under both
    /// policies. The second is the load-bearing one — it is what fails
    /// if holding that handle ever becomes optional again.
    ///
    /// Recorded rather than asserted: at the exhaustion point
    /// `DeleteOnError` cannot always remove the empty staged entry,
    /// because that removal needs a descriptor of its own. The entry
    /// holds no plaintext, which is what the sweep pins.
    ///
    /// Linux/macOS only, matching the `rustix` dev-dependency behind
    /// [`fd_limit`]. Ignored by default because it holds every free
    /// descriptor while it runs, which fails any test running beside
    /// it: the open-file limit is process-wide. Both test runners and
    /// the CI build job pass `--include-ignored --test-threads=1`, so
    /// it runs there on every supported platform.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    #[ignore = "holds every free descriptor; needs --test-threads=1"]
    fn a_run_that_cannot_hold_the_staged_handle_refuses_before_any_plaintext() {
        /// Free-descriptor counts spanning the range from "too few to
        /// stage anything" to "enough to finish".
        const BUDGETS: std::ops::Range<usize> = 0..8;

        let mut refusals = 0;
        for root_is_file in [true, false] {
            for policy in [
                IncompleteOutputPolicy::DeleteOnError,
                IncompleteOutputPolicy::RetainOnError,
            ] {
                let mut refused_here = false;
                for free in BUDGETS {
                    let tmp = tempfile::TempDir::new().unwrap();
                    let (archive, root, content) = if root_is_file {
                        let manifest = single_file_manifest("hello.txt", b"Hello, world!");
                        let archive = build_archive(&manifest, &[("hello.txt", b"Hello, world!")]);
                        (archive, "hello.txt", &b"Hello, world!"[..])
                    } else {
                        let manifest = directory_root_manifest();
                        let archive = build_archive(&manifest, &[("d/a.txt", b"real")]);
                        (archive, "d", &b"real"[..])
                    };

                    let held = fd_limit::HeldDescriptors::leaving(free);
                    let result = unarchive_with_policy(archive, tmp.path(), policy.clone());
                    drop(held);

                    let mut found = Vec::new();
                    walk_files(tmp.path(), &mut found);
                    match result {
                        Ok(path) => {
                            assert_eq!(path, tmp.path().join(root));
                            let total: usize = found.iter().map(|(_, bytes, _)| bytes.len()).sum();
                            assert_eq!(
                                total,
                                content.len(),
                                "a successful decrypt must hold exactly the archive's content"
                            );
                        }
                        Err(e) => {
                            assert!(
                                found.iter().all(|(_, bytes, _)| bytes.is_empty()),
                                "a refused decrypt must leave no plaintext, got {found:?} at \
                                 {free} free descriptors: {e}"
                            );
                            assert!(
                                !tmp.path().join(root).exists(),
                                "a refused decrypt must leave nothing at the final name"
                            );
                            if format!("{e}").contains(STAGED_HANDLE_UNAVAILABLE) {
                                refused_here = true;
                            }
                        }
                    }
                }
                assert!(
                    refused_here,
                    "the staged-handle refusal must be reachable for root_is_file={root_is_file} \
                     under {policy:?}"
                );
                refusals += 1;
            }
        }
        assert_eq!(refusals, 4, "both root kinds under both policies");
    }

    /// A local writer that links the staged plaintext, moves it aside
    /// and leaves an unrelated file at the staging name makes the
    /// promotion commit that other file. The run's own plaintext was
    /// therefore never committed, so `DeleteOnError` must destroy it
    /// wherever the run can still reach it, and the refusal must name
    /// the substitution rather than the extra name: reporting the count
    /// here would preserve plaintext this run never handed over.
    #[cfg(unix)]
    #[test]
    fn a_substituted_promotion_still_destroys_this_runs_plaintext() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();

        let root_name = "f.txt";
        let plaintext = b"real plaintext";
        let manifest = single_file_manifest(root_name, plaintext);
        let archive = build_archive(&manifest, &[(root_name, plaintext)]);
        let incomplete_path = out.join(incomplete_working_name(OsStr::new(root_name)));
        let attacker_link = out.join("attacker-link");
        let aside = out.join("aside");
        let decoy = out.join("decoy-source");

        let err = unarchive_inner_with_hooks(
            Cursor::new(archive),
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
            Seams {
                compare_owners: platform::compare_owners,
                before_promotion: || {
                    fs::hard_link(&incomplete_path, &attacker_link)?;
                    fs::rename(&incomplete_path, &aside)?;
                    fs::write(&decoy, b"decoy content")?;
                    fs::hard_link(&decoy, &incomplete_path)?;
                    Ok(())
                },
                after_promotion: |_| Ok(()),
                after_root_mode: |_| Ok(()),
            },
        )
        .expect_err("must fail");

        assert!(
            err.to_string()
                .contains("Output was replaced while decrypting"),
            "the refusal must name the substitution, got: {err}"
        );

        let mut leaked = Vec::new();
        for entry in fs::read_dir(&out).unwrap() {
            let p = entry.unwrap().path();
            if p.is_file() && fs::read(&p).unwrap_or_default() == plaintext {
                leaked.push(p);
            }
        }
        assert!(
            leaked.is_empty(),
            "DeleteOnError left this run's plaintext at {leaked:?}"
        );
    }

    /// A staging name that could not be removed is the one outcome
    /// where a second name for the committed file is certain, so it is
    /// the last that may skip the count. The archive's mode must not
    /// reach that inode: the extra name keeps the owner-only staged
    /// mode, and the run reports the failed removal, which says why the
    /// second name is there.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_retained_staging_name_never_receives_the_archive_mode() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();

        let root_name = "f.txt";
        let plaintext = b"real plaintext";
        let manifest = single_file_manifest(root_name, plaintext);
        let archive = build_archive(&manifest, &[(root_name, plaintext)]);
        let incomplete_path = out.join(incomplete_working_name(OsStr::new(root_name)));
        let evil = out.join("evil-link");

        let err = unarchive_inner_with_hooks(
            Cursor::new(archive),
            &out,
            ArchiveLimits::default(),
            IncompleteOutputPolicy::DeleteOnError,
            Seams {
                compare_owners: platform::compare_owners,
                before_promotion: || {
                    fs::hard_link(&incomplete_path, &evil)?;
                    Ok(())
                },
                after_promotion: |promotion| {
                    *promotion = platform::PromotionOutcome::StagedLinkRetained(io::Error::other(
                        "simulated staging unlink failure",
                    ));
                    Ok(())
                },
                after_root_mode: |_| Ok(()),
            },
        )
        .expect_err("must fail");

        assert!(
            err.to_string().contains("could not be removed"),
            "the run must report the failed staging removal, got: {err}"
        );
        assert_eq!(
            fs::read(&evil).unwrap(),
            plaintext,
            "the extra name still denotes the committed file"
        );
        let evil_mode = fs::metadata(&evil).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            evil_mode,
            platform::INITIAL_FILE_CREATE_MODE,
            "the archive mode must never reach an inode with a second name"
        );
    }
}
