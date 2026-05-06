//! Decrypt-side TAR reading and output reconstruction.
//!
//! [`unarchive`] streams an authenticated TAR payload into the
//! caller-supplied `output_dir`, writing every output under an
//! `.incomplete` working name and atomically promoting the working
//! root to its final name only after the whole archive validates.
//!
//! Per-entry validation runs before any filesystem write — see
//! [`validate_ustar_entry`] (`FORMAT.md` §9). `extract_entries` uses
//! the unified [`super::platform`] backend: every operation is rooted
//! in a `cap_std::fs::Dir`, every directory component is opened with
//! `cap_fs_ext::DirExt::open_dir_nofollow`, and Windows directory
//! opens also reject NTFS reparse points.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::CryptoError;
use crate::fs::atomic::rename_no_clobber;
use crate::fs::paths::INCOMPLETE_SUFFIX;

use super::limits::{ArchiveLimits, enforce_per_entry_caps, enforce_total_bytes_cap};
use super::path::{UstarEntryKind, ustar, validate_archive_path_components};

/// Decrypt-side per-iteration accounting bundled into one struct so
/// `pre_validate_entry` runs identical resource-cap + duplicate-
/// detection logic on every entry. `entry_count` is checked before
/// the entry is added to `seen_paths`; `total_bytes` is checked
/// before any `io::copy` so an attacker-declared 1 PiB size
/// cannot start a partial write.
#[derive(Default)]
struct ExtractCounters {
    entry_count: u32,
    total_bytes: u64,
    seen_paths: HashSet<PathBuf>,
}

impl ExtractCounters {
    /// Runs `FORMAT.md` §9 archive-subset validation + per-entry resource
    /// caps + canonical-path duplicate detection for one TAR entry.
    /// Returns the normalized entry on success.
    fn pre_validate_entry<R: Read>(
        &mut self,
        entry: &mut tar::Entry<'_, R>,
        limits: &ArchiveLimits,
    ) -> Result<NormalizedEntry, CryptoError> {
        let normalized = validate_ustar_entry(entry)?;
        self.entry_count = self.entry_count.saturating_add(1);
        enforce_per_entry_caps(self.entry_count, &normalized.canonical_path, limits)?;
        if !self.seen_paths.insert(normalized.canonical_path.clone()) {
            return Err(CryptoError::InvalidInput(format!(
                "Duplicate archive entry: {}",
                normalized.canonical_path.display()
            )));
        }
        if matches!(normalized.kind, UstarEntryKind::File) {
            let entry_size = entry
                .header()
                .size()
                .map_err(|e| CryptoError::InvalidInput(format!("Malformed TAR size field: {e}")))?;
            enforce_total_bytes_cap(entry_size, &mut self.total_bytes, limits)?;
        }
        Ok(normalized)
    }
}

/// Per-entry POSIX ustar subset validation result. `canonical_path` has
/// any single trailing `/` from a directory entry stripped, so a file
/// entry `foo` and a directory entry `foo/` are recognised as the same
/// canonical output and rejected as duplicates.
struct NormalizedEntry {
    canonical_path: PathBuf,
    kind: UstarEntryKind,
}

/// Validates a single TAR entry against the v1 archive subset
/// (`FORMAT.md` §9). Catches:
///
/// - non-POSIX-ustar headers (GNU magic, missing `00` version);
/// - typeflags outside `{file, directory}`. The reader runs in raw
///   iteration mode (`tar::Entries::raw(true)`), so PAX `'x'` /
///   `'g'` records and the GNU `'L'` / `'K'` / `'S'` / `'M'` / `'D'`
///   / `'V'` / `'N'` extension records each surface as their own
///   entry with their wire typeflag intact, instead of being merged
///   into the next entry by the tar crate. The match arms below
///   reject every PAX and GNU extension byte explicitly so the
///   error message tells the user what the archive actually
///   contained, rather than a generic "unsupported typeflag";
/// - empty paths, paths with NUL or `\` bytes, repeated `/`
///   separators, paths longer than the ustar representable cap;
/// - non-UTF-8 paths;
/// - file entries whose path ends with `/`, directory entries
///   whose path does not;
/// - `.` and `..` components, absolute paths, Windows path
///   prefixes (covered by `validate_archive_path_components`).
///
/// Because raw iteration surfaces every header block with its own
/// typeflag, no "merged-state" heuristic is needed — a PAX `'x'`
/// record that overrode mtime, uid/gid, mode, or any other
/// attribute is rejected at the typeflag check before any merging
/// could happen. ferrocrypt's own writer never emits PAX or GNU
/// records, so these branches fire only on adversarial input.
fn validate_ustar_entry<R: Read>(
    entry: &mut tar::Entry<'_, R>,
) -> Result<NormalizedEntry, CryptoError> {
    let raw = entry.header().as_bytes();

    if &raw[ustar::MAGIC_OFFSET..ustar::MAGIC_OFFSET + ustar::MAGIC.len()] != ustar::MAGIC {
        return Err(CryptoError::InvalidInput(
            "Archive header is not POSIX ustar".to_string(),
        ));
    }
    if &raw[ustar::VERSION_OFFSET..ustar::VERSION_OFFSET + ustar::VERSION.len()] != ustar::VERSION {
        return Err(CryptoError::InvalidInput(
            "Archive header version is not POSIX ustar 00".to_string(),
        ));
    }

    let typeflag = raw[ustar::TYPEFLAG_OFFSET];
    let kind = match typeflag {
        ustar::TYPEFLAG_REGULAR_NUL | ustar::TYPEFLAG_REGULAR_ZERO => UstarEntryKind::File,
        ustar::TYPEFLAG_DIRECTORY => UstarEntryKind::Directory,
        ustar::TYPEFLAG_PAX_EXTENDED | ustar::TYPEFLAG_PAX_GLOBAL => {
            return Err(CryptoError::InvalidInput(format!(
                "Archive contains forbidden PAX extended header (typeflag 0x{typeflag:02X})"
            )));
        }
        ustar::TYPEFLAG_GNU_LONG_NAME
        | ustar::TYPEFLAG_GNU_LONG_LINK
        | ustar::TYPEFLAG_GNU_SPARSE
        | ustar::TYPEFLAG_GNU_MULTI_VOLUME
        | ustar::TYPEFLAG_GNU_DUMPDIR
        | ustar::TYPEFLAG_GNU_VOLUME_HEADER
        | ustar::TYPEFLAG_GNU_NAMES
        | ustar::TYPEFLAG_SOLARIS_EXTENDED => {
            return Err(CryptoError::InvalidInput(format!(
                "Archive contains forbidden GNU/Solaris extension (typeflag 0x{typeflag:02X})"
            )));
        }
        _ => {
            return Err(CryptoError::InvalidInput(format!(
                "Unsupported archive entry type: typeflag 0x{typeflag:02X}"
            )));
        }
    };

    // `FORMAT.md` §9 forbids the GNU binary numeric encoding (high bit
    // set on the first byte of a numeric field). The size field is the
    // only one that realistically gets extended to binary in practice
    // — mode, uid, gid, and mtime fit the ustar octal allotment for
    // any reasonable value — and an unchecked binary-size field would
    // let an adversarial archive declare a multi-gigabyte regular
    // entry that our writer's symmetric `FILE_SIZE_REPRESENTABLE_MAX`
    // cap rejects on encrypt. Reject the encoding here so encrypt and
    // decrypt agree on the boundary. This check is not redundant with
    // the typeflag match above: a regular-file entry with typeflag
    // `'0'` plus a binary-encoded size passes the typeflag arms.
    if raw[ustar::SIZE_FIELD_OFFSET] & ustar::NUMERIC_BINARY_FLAG_BIT != 0 {
        return Err(CryptoError::InvalidInput(
            "Archive uses forbidden GNU binary numeric encoding for size".to_string(),
        ));
    }

    let entry_path = entry.path_bytes();
    let path_bytes: &[u8] = &entry_path;
    if path_bytes.is_empty() {
        return Err(CryptoError::InvalidInput(
            "Empty archive entry path".to_string(),
        ));
    }
    if path_bytes.len() > ustar::PATH_REPRESENTABLE_MAX {
        return Err(CryptoError::InvalidInput(
            "Archive path exceeds POSIX ustar representable length".to_string(),
        ));
    }
    if path_bytes.contains(&b'\0') {
        return Err(CryptoError::InvalidInput(
            "Archive path contains NUL byte".to_string(),
        ));
    }
    if path_bytes.contains(&b'\\') {
        return Err(CryptoError::InvalidInput(
            "Archive path contains backslash".to_string(),
        ));
    }
    if path_bytes.windows(2).any(|w| w == b"//") {
        return Err(CryptoError::InvalidInput(
            "Archive path contains repeated slash separators".to_string(),
        ));
    }

    let path_str = std::str::from_utf8(path_bytes)
        .map_err(|_| CryptoError::InvalidInput("Archive path is not valid UTF-8".to_string()))?;

    let ends_with_slash = path_str.ends_with('/');
    match (kind, ends_with_slash) {
        (UstarEntryKind::Directory, false) => {
            return Err(CryptoError::InvalidInput(
                "Directory entry path must end with /".to_string(),
            ));
        }
        (UstarEntryKind::File, true) => {
            return Err(CryptoError::InvalidInput(
                "File entry path must not end with /".to_string(),
            ));
        }
        _ => {}
    }

    let canonical_str = if ends_with_slash {
        &path_str[..path_str.len() - 1]
    } else {
        path_str
    };
    for component in canonical_str.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(CryptoError::InvalidInput(format!(
                "Archive path has forbidden component: {path_str}"
            )));
        }
    }

    let canonical_path = PathBuf::from(canonical_str);
    validate_archive_path_components(&canonical_path)?;

    Ok(NormalizedEntry {
        canonical_path,
        kind,
    })
}

/// Drains the underlying reader after the TAR entry iterator has
/// returned `None` and verifies that every remaining byte of the
/// authenticated plaintext is zero. Per `FORMAT.md` §9, the v1
/// archive payload terminates with the standard two 512-byte zero
/// blocks; any non-zero trailing byte is a malformed archive.
fn drain_and_verify_zero_padding<R: Read>(mut reader: R) -> Result<(), CryptoError> {
    let mut buf = [0u8; 4096];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        if buf[..n].iter().any(|&b| b != 0) {
            return Err(CryptoError::InvalidInput(
                "Non-zero trailing data after TAR end-of-archive marker".to_string(),
            ));
        }
    }
}

/// Extracts a TAR archive from `reader` into the specified directory.
///
/// All output is written under an `.incomplete` working name so that
/// plaintext never appears under the final name during streaming
/// decryption. On success, the working name is atomically renamed to the
/// final name. On failure, the `.incomplete` output stays on disk for
/// the user to inspect or delete.
pub(crate) fn unarchive<R: Read>(
    reader: R,
    output_dir: &Path,
    limits: ArchiveLimits,
) -> Result<PathBuf, CryptoError> {
    let mut archive = tar::Archive::new(reader);
    let mut first_entry_root: Option<PathBuf> = None;
    let mut checked_roots: Vec<OsString> = Vec::new();

    let extract_result = extract_entries(
        &mut archive,
        output_dir,
        &mut first_entry_root,
        &mut checked_roots,
        &limits,
    );

    extract_result?;

    // FORMAT.md §9: after the TAR end-of-archive marker the rest of
    // the authenticated plaintext MUST be zero. Drain whatever the tar
    // crate left in the underlying reader and reject any non-zero
    // trailing byte before promoting the `.incomplete` outputs.
    drain_and_verify_zero_padding(archive.into_inner())?;

    // Rename each root from .incomplete working name to final name.
    // A failure here is an environment / I/O condition — not a library
    // invariant violation. `AlreadyExists` means the final name appeared
    // after the extraction-time pre-check (race or attacker) and is
    // mapped to the same user-facing message as the pre-check; everything
    // else surfaces as a generic I/O error.
    for root_name in &checked_roots {
        let working_path = output_dir.join(incomplete_working_name(root_name));
        let final_path = output_dir.join(root_name);
        rename_no_clobber(&working_path, &final_path).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                CryptoError::InvalidInput(format!(
                    "Output already exists: {}",
                    final_path.display()
                ))
            } else {
                CryptoError::Io(e)
            }
        })?;
    }

    first_entry_root.ok_or_else(|| CryptoError::InvalidInput("Empty archive".to_string()))
}

/// Builds the `{root}.incomplete` working name used throughout the
/// extract pipeline so plaintext is never visible under the final name
/// during streaming decryption. Borrows so it works for both `OsString`
/// and `OsStr` arguments without an extra conversion at the call site.
fn incomplete_working_name(root_name: &OsStr) -> OsString {
    let mut name = root_name.to_os_string();
    name.push(INCOMPLETE_SUFFIX);
    name
}

/// Per-iteration root tracking for the unified hardened extractor.
/// Extracts the first path component, rejects a second top-level root,
/// and pre-checks the final output name for collisions (`symlink_metadata`
/// catches dangling symlinks too). The `.incomplete` working name is
/// checked at first touch by `mkdir_strict` / `create_file_at`, which
/// fail closed if anything already exists there. The final-name
/// pre-check runs BEFORE `first_entry_root` and `checked_roots` are
/// mutated, so a rejection leaves the caller's tracking state
/// untouched. Idempotent for already-registered roots (returns the
/// same `root_name` without re-running any check).
fn extract_and_register_root(
    output_dir: &Path,
    path: &Path,
    first_entry_root: &mut Option<PathBuf>,
    checked_roots: &mut Vec<OsString>,
) -> Result<OsString, CryptoError> {
    let first_component = path
        .components()
        .next()
        .ok_or_else(|| CryptoError::InvalidInput("Empty archive entry".to_string()))?;
    let root_name = first_component.as_os_str().to_os_string();

    if checked_roots.contains(&root_name) {
        return Ok(root_name);
    }
    // Ferrocrypt's archiver only produces single-root payloads (one
    // top-level file or one top-level directory — see FORMAT.md §6.4).
    // Reject any crafted archive that smuggles a second top-level root
    // so `unarchive`'s single `PathBuf` return value always accounts for
    // every output it creates.
    if !checked_roots.is_empty() {
        return Err(CryptoError::InvalidInput(format!(
            "Archive has multiple top-level roots: {}",
            path.display()
        )));
    }
    let final_path = output_dir.join(&root_name);
    // `symlink_metadata` does not follow the final symlink, so a dangling
    // symlink at `final_path` is caught here instead of later at rename
    // time.
    match fs::symlink_metadata(&final_path) {
        Ok(_) => {
            return Err(CryptoError::InvalidInput(format!(
                "Output already exists: {}",
                final_path.display()
            )));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(CryptoError::Io(e)),
    }
    // Pre-check on `{root}.incomplete` is no longer needed — the
    // hardened extractor's `mkdir_strict` / `create_file_at` use
    // `O_EXCL` / `create_new` (and on Windows the reparse-point post-
    // check) so anything pre-placed at that name fails with
    // `AlreadyExists` at first touch. Same diagnostic, one fewer
    // syscall on the happy path.
    if first_entry_root.is_none() {
        *first_entry_root = Some(final_path);
    }
    checked_roots.push(root_name.clone());
    Ok(root_name)
}

/// Hardened extraction. Every filesystem operation inside the
/// `.incomplete` working entry is anchored to a `cap_std::fs::Dir`
/// handle and traversed component by component via
/// `cap_fs_ext::DirExt::open_dir_nofollow`, so a concurrent local
/// attacker cannot race a directory component into a symlink and
/// redirect writes outside the destination tree. File creation uses
/// `OpenOptions::create_new(true)` plus
/// `OpenOptionsFollowExt::follow(FollowSymlinks::No)`. Permissions
/// are applied via [`super::platform::chmod_file_handle`] /
/// [`super::platform::chmod_dir_handle`] on open handles so path
/// resolution never happens at chmod time. On Windows, every
/// successful directory open is post-checked against
/// `FILE_ATTRIBUTE_REPARSE_POINT` so junctions and mount points are
/// rejected alongside std-recognised symlinks.
fn extract_entries<R: Read>(
    archive: &mut tar::Archive<R>,
    output_dir: &Path,
    first_entry_root: &mut Option<PathBuf>,
    checked_roots: &mut Vec<OsString>,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    use std::collections::HashMap;

    use cap_std::fs::Dir;

    use super::platform;

    /// Per-root state. A tar root can be either a directory (the usual
    /// multi-entry case) or a regular file (single-file archives where
    /// the root component IS the file). Directories keep an open
    /// `Dir` handle so subsequent child entries resolve under it.
    enum RootKind {
        Directory(Dir),
        SingleFile,
    }

    fn map_incomplete_create_err(
        e: CryptoError,
        output_dir: &Path,
        incomplete_name: &OsStr,
    ) -> CryptoError {
        if let CryptoError::Io(io_err) = &e {
            if io_err.kind() == io::ErrorKind::AlreadyExists {
                return CryptoError::InvalidInput(format!(
                    "Previous .incomplete exists: {}",
                    output_dir.join(incomplete_name).display()
                ));
            }
        }
        e
    }

    fn map_create_file_err(
        e: io::Error,
        output_dir: &Path,
        incomplete_name: &OsStr,
    ) -> CryptoError {
        if e.kind() == io::ErrorKind::AlreadyExists {
            CryptoError::InvalidInput(format!(
                "Previous .incomplete exists: {}",
                output_dir.join(incomplete_name).display()
            ))
        } else {
            CryptoError::Io(e)
        }
    }

    /// Ensures `roots` has a `Directory` entry for `root_name`,
    /// lazily creating its `.incomplete` working directory under
    /// `output_handle` on first occurrence. Rejects with the
    /// canonical "mixes file and directory" error if a `SingleFile`
    /// root has already been recorded under the same name. Returns
    /// a borrow of the registered `Dir` handle.
    fn ensure_root_directory<'a>(
        roots: &'a mut HashMap<OsString, RootKind>,
        root_name: &OsString,
        output_handle: &Dir,
        output_dir: &Path,
        incomplete_name: &OsStr,
        path: &Path,
    ) -> Result<&'a Dir, CryptoError> {
        use std::collections::hash_map::Entry;
        match roots.entry(root_name.clone()) {
            Entry::Occupied(occ) => match occ.into_mut() {
                RootKind::SingleFile => Err(CryptoError::InvalidInput(format!(
                    "Archive mixes file and directory at root: {}",
                    path.display()
                ))),
                RootKind::Directory(dir) => Ok(dir),
            },
            Entry::Vacant(vac) => {
                let dir = platform::mkdir_strict(output_handle, incomplete_name)
                    .map_err(|e| map_incomplete_create_err(e, output_dir, incomplete_name))?;
                match vac.insert(RootKind::Directory(dir)) {
                    RootKind::Directory(dir) => Ok(dir),
                    RootKind::SingleFile => unreachable!("just inserted Directory variant"),
                }
            }
        }
    }

    /// Streams the entry's payload into the just-created `outfile`,
    /// then applies the tar-stored mode via the file's open handle.
    /// `outfile` is consumed (and dropped at scope exit) so the file
    /// is closed before this returns. Used by both the single-file-
    /// root case and the descendant-file case so the on-disk shape
    /// (permissive initial mode → write payload → chmod via handle)
    /// is identical.
    fn copy_payload_and_apply_mode<R: Read>(
        mut outfile: cap_std::fs::File,
        entry: &mut tar::Entry<'_, R>,
    ) -> Result<(), CryptoError> {
        io::copy(entry, &mut outfile)?;
        if let Ok(mode) = entry.header().mode() {
            platform::chmod_file_handle(&outfile, mode)?;
        }
        Ok(())
    }

    let output_handle = platform::open_anchor(output_dir)?;
    let mut roots: HashMap<OsString, RootKind> = HashMap::new();
    // Deferred directory permissions: (root name, rel path under root, mode).
    // `rel` is empty for the root directory itself.
    let mut dir_permissions: Vec<(OsString, PathBuf, u32)> = Vec::new();
    let mut counters = ExtractCounters::default();

    // `raw(true)` disables tar-rs's merge preprocessing so PAX / GNU
    // extension records surface as their own entries with the wire
    // typeflag intact, where `validate_ustar_entry` rejects them.
    // Without raw mode, a PAX `'x'` record overriding only mtime /
    // uid/gid / mode would slip through silently into the merged
    // entry's metadata. See `FORMAT.md` §9.
    for entry_result in archive.entries()?.raw(true) {
        let mut entry = entry_result?;
        let NormalizedEntry {
            canonical_path: path,
            kind,
        } = counters.pre_validate_entry(&mut entry, limits)?;

        let root_name =
            extract_and_register_root(output_dir, &path, first_entry_root, checked_roots)?;

        let Ok(rel) = path.strip_prefix(&root_name).map(Path::to_path_buf) else {
            return Err(CryptoError::InternalInvariant(
                "Internal error: entry path missing root component",
            ));
        };

        let incomplete_name = incomplete_working_name(&root_name);

        // Case A: entry IS the root (single-file archive or a root-level
        // directory entry).
        if rel.as_os_str().is_empty() {
            match kind {
                UstarEntryKind::Directory => {
                    ensure_root_directory(
                        &mut roots,
                        &root_name,
                        &output_handle,
                        output_dir,
                        &incomplete_name,
                        &path,
                    )?;
                    if let Ok(mode) = entry.header().mode() {
                        dir_permissions.push((root_name.clone(), PathBuf::new(), mode));
                    }
                }
                UstarEntryKind::File => {
                    if roots.contains_key(&root_name) {
                        return Err(CryptoError::InvalidInput(format!(
                            "Archive has mixed or duplicate root entries: {}",
                            path.display()
                        )));
                    }
                    let outfile = platform::create_file_at(
                        &output_handle,
                        &incomplete_name,
                        platform::INITIAL_FILE_CREATE_MODE,
                    )
                    .map_err(|e| map_create_file_err(e, output_dir, &incomplete_name))?;
                    copy_payload_and_apply_mode(outfile, &mut entry)?;
                    roots.insert(root_name.clone(), RootKind::SingleFile);
                }
            }
            continue;
        }

        // Case B: entry is a descendant of the root. The root must be a
        // directory; `ensure_root_directory` lazily creates
        // `{root}.incomplete` if no explicit root-level directory entry
        // has been seen yet.
        let root_handle = ensure_root_directory(
            &mut roots,
            &root_name,
            &output_handle,
            output_dir,
            &incomplete_name,
            &path,
        )?;
        let (parent_handle, final_name) = platform::walk_to_parent(root_handle, &rel)?;
        match kind {
            UstarEntryKind::Directory => {
                let _dir = platform::ensure_dir(&parent_handle, &final_name)?;
                if let Ok(mode) = entry.header().mode() {
                    dir_permissions.push((root_name.clone(), rel, mode));
                }
            }
            UstarEntryKind::File => {
                let outfile = platform::create_file_at(
                    &parent_handle,
                    &final_name,
                    platform::INITIAL_FILE_CREATE_MODE,
                )?;
                copy_payload_and_apply_mode(outfile, &mut entry)?;
            }
        }
    }

    // Apply deferred directory permissions deepest-first. Each chmod
    // happens on a fresh no-follow-opened handle; applying descendants
    // before ancestors prevents a restrictive parent mode without
    // execute/search permission (for example 0o400) from blocking the
    // later reopen of a child directory.
    // `open_dir_at_rel` folds the root-vs-descendant case naturally —
    // see its doc-comment for the empty-`rel` contract.
    dir_permissions.sort_by_key(|(_, rel, _)| std::cmp::Reverse(rel.components().count()));
    for (root_name, rel, mode) in &dir_permissions {
        let Some(RootKind::Directory(root_handle)) = roots.get(root_name) else {
            return Err(CryptoError::InternalInvariant(
                "Internal error: root handle missing at dir-perm stage",
            ));
        };
        let dir_handle = platform::open_dir_at_rel(root_handle, rel)?;
        platform::chmod_dir_handle(dir_handle, *mode)?;
    }

    Ok(())
}

// The previous path-based fallback (gated to `not(any(linux, macos))`)
// has been replaced by the unified cap-std + cap-fs-ext extractor
// above. There is no longer a "fallback" code path — the hardened
// extractor runs uniformly on every supported OS, with Windows
// reparse-point rejection layered on top via
// `super::platform::reject_reparse_point` (Windows-only, called from
// `finalize_dir_open`).

#[cfg(test)]
mod tests {
    use super::super::limits::ArchiveLimits;
    use super::super::path::ustar;
    use super::unarchive;

    use std::fs;
    use std::io::Cursor;

    #[test]
    fn unarchive_rejects_multi_root_archive() {
        // Ferrocrypt's archiver only produces single-root payloads
        // (see FORMAT.md §6.4 and §11). A crafted archive with two
        // distinct top-level roots must be rejected so that
        // `unarchive`'s single `PathBuf` return value always accounts
        // for every output it creates.
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);

            let data_a = b"payload a";
            let mut header = tar::Header::new_ustar();
            header.set_size(data_a.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "first.txt", &data_a[..])
                .unwrap();

            let data_b = b"payload b";
            let mut header = tar::Header::new_ustar();
            header.set_size(data_b.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "second.txt", &data_b[..])
                .unwrap();

            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        assert!(
            err.to_string().contains("multiple top-level roots"),
            "expected multi-root rejection, got: {err}"
        );

        // Neither root's final name should have been promoted from
        // `.incomplete`, because the rejection fires mid-extraction.
        assert!(!extract_dir.join("first.txt").exists());
        assert!(!extract_dir.join("second.txt").exists());
    }

    #[test]
    fn unarchive_multi_root_cannot_overwrite_pre_existing_output() {
        // Adversarial scenario: attacker places an innocent first root
        // and a malicious second entry whose name collides with an
        // existing file at the output. The multi-root rejection must
        // fire before any collision/overwrite check, leaving the
        // pre-existing file byte-for-byte intact.
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(extract_dir.join("victim.txt"), "original").unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);

            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "innocent/", &[] as &[u8])
                .unwrap();

            let data = b"malicious payload";
            let mut header = tar::Header::new_ustar();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "victim.txt", &data[..])
                .unwrap();

            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        assert!(
            err.to_string().contains("multiple top-level roots"),
            "expected multi-root rejection, got: {err}"
        );

        let content = fs::read_to_string(extract_dir.join("victim.txt")).unwrap();
        assert_eq!(content, "original");
    }

    #[test]
    fn unarchive_rejects_symlink_entry() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);

            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_link(&mut header, "link.txt", "target.txt")
                .unwrap();

            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        assert!(
            err.to_string().contains("Unsupported archive entry type"),
            "expected unsupported entry error, got: {err}"
        );
    }

    #[test]
    fn unarchive_rejects_duplicate_file_entries() {
        // A maliciously crafted archive with two file entries at the same
        // path must not silently overwrite the first with the second.
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);

            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "mydir/", &[] as &[u8])
                .unwrap();

            let first = b"first payload";
            let mut header = tar::Header::new_ustar();
            header.set_size(first.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "mydir/dup.txt", &first[..])
                .unwrap();

            let second = b"attacker payload";
            let mut header = tar::Header::new_ustar();
            header.set_size(second.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "mydir/dup.txt", &second[..])
                .unwrap();

            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        // FORMAT.md §9 dup detection runs on the canonical path before
        // any filesystem write, so the second entry surfaces as a
        // typed "Duplicate archive entry" rejection rather than the
        // older AlreadyExists race-fallback path.
        let msg = err.to_string();
        assert!(
            msg.contains("Duplicate archive entry"),
            "expected duplicate-entry error, got: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn archive_strips_special_bits_on_extract() {
        use std::os::unix::fs::PermissionsExt;

        let cases: &[(u32, &str)] = &[
            (0o4755, "setuid"),
            (0o2755, "setgid"),
            (0o1755, "sticky"),
            (0o6755, "setuid+setgid"),
            (0o7777, "all special + all rwx"),
        ];

        for &(input_mode, label) in cases {
            let tmp = tempfile::TempDir::new().unwrap();
            let extract_dir = tmp.path().join("extracted");
            fs::create_dir_all(&extract_dir).unwrap();

            let data = b"payload";
            let mut buf = Vec::new();
            {
                let mut builder = tar::Builder::new(&mut buf);
                let mut header = tar::Header::new_ustar();
                header.set_size(data.len() as u64);
                header.set_mode(input_mode);
                header.set_cksum();
                builder
                    .append_data(&mut header, "file.sh", &data[..])
                    .unwrap();
                builder.finish().unwrap();
            }

            unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap();

            let restored = extract_dir.join("file.sh");
            let mode = fs::metadata(&restored).unwrap().permissions().mode() & 0o7777;
            let expected = input_mode & 0o777;
            assert_eq!(
                mode, expected,
                "{label}: expected 0o{expected:o}, got 0o{mode:o}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn archive_strips_special_bits_on_directory_extract() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);

            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o4755); // setuid on directory
            header.set_cksum();
            builder
                .append_data(&mut header, "stickydir/", &[] as &[u8])
                .unwrap();

            let data = b"child";
            let mut header = tar::Header::new_ustar();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "stickydir/child.txt", &data[..])
                .unwrap();

            builder.finish().unwrap();
        }

        unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap();

        let dir_mode = fs::metadata(extract_dir.join("stickydir"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            dir_mode, 0o755,
            "directory setuid should be stripped: expected 0o755, got 0o{dir_mode:o}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn archive_applies_directory_permissions_deepest_first() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);

            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o400); // no execute/search bit on the parent
            header.set_cksum();
            builder
                .append_data(&mut header, "locked/", &[] as &[u8])
                .unwrap();

            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o700);
            header.set_cksum();
            builder
                .append_data(&mut header, "locked/child/", &[] as &[u8])
                .unwrap();

            let data = b"secret";
            let mut header = tar::Header::new_ustar();
            header.set_size(data.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            builder
                .append_data(&mut header, "locked/child/secret.txt", &data[..])
                .unwrap();

            builder.finish().unwrap();
        }

        unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap();

        let root = extract_dir.join("locked");
        let root_mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(root_mode, 0o400, "expected 0o400, got 0o{root_mode:o}");

        // Restore search permission so the test can inspect descendants
        // and TempDir cleanup can remove them. If deferred chmod ran
        // parent-first, unarchive would already have failed before this.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        let child_mode = fs::metadata(root.join("child"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(child_mode, 0o700, "expected 0o700, got 0o{child_mode:o}");
        assert_eq!(
            fs::read_to_string(root.join("child/secret.txt")).unwrap(),
            "secret"
        );
    }

    /// Regression: an attacker-placed symlink at the expected
    /// `.incomplete` root must not let extraction redirect writes into
    /// the symlink target. The outer pre-check refuses the extraction
    /// before any plaintext reaches disk.
    #[cfg(unix)]
    #[test]
    fn unarchive_refuses_preplaced_incomplete_symlink() {
        use std::os::unix::fs as unix_fs;

        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let victim = tmp.path().join("victim_dir");
        fs::create_dir_all(&victim).unwrap();
        unix_fs::symlink(&victim, extract_dir.join("mydir.incomplete")).unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "mydir/", &[] as &[u8])
                .unwrap();

            let data = b"plaintext payload";
            let mut header = tar::Header::new_ustar();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "mydir/child.txt", &data[..])
                .unwrap();
            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(".incomplete exists") || msg.contains("exists") || msg.contains("Symlink"),
            "expected .incomplete / symlink error, got: {msg}"
        );

        assert!(
            victim.read_dir().unwrap().next().is_none(),
            "victim directory must be empty"
        );
    }

    /// Regression: a dangling symlink at the expected final output name
    /// must be caught by the pre-check (via `symlink_metadata`) instead
    /// of slipping through `.exists()` and failing later at rename time.
    #[cfg(unix)]
    #[test]
    fn unarchive_refuses_dangling_symlink_at_final_name() {
        use std::os::unix::fs as unix_fs;

        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        unix_fs::symlink(tmp.path().join("does_not_exist"), extract_dir.join("mydir")).unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "mydir/", &[] as &[u8])
                .unwrap();
            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        assert!(
            err.to_string().contains("Output already exists"),
            "expected output-exists pre-check, got: {err}"
        );

        // The `.incomplete` working dir should not have been created,
        // since the pre-check refused the extraction upfront.
        assert!(
            !extract_dir.join("mydir.incomplete").exists(),
            ".incomplete working dir should not exist"
        );
    }

    /// Regression: a tar entry whose path is a bare `.` is rejected by
    /// `validate_archive_path_components`. tar-rs strips leading `./` from longer
    /// paths on write, so `.` is the only single-component CurDir path
    /// that can round-trip through the builder — it still exercises the
    /// validator's CurDir rejection.
    #[test]
    fn unarchive_rejects_curdir_entry() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, ".", &[] as &[u8]).unwrap();
            builder.finish().unwrap();
        }

        // Per FORMAT.md §9 a directory path must end with `/`; a bare
        // `.` violates that first, before the path-traversal check
        // ever runs. Either rejection is acceptable so long as the
        // archive is refused and the extract directory stays empty.
        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Directory entry path must end with /")
                || msg.contains("Unsafe path")
                || msg.contains("forbidden component"),
            "expected curdir / trailing-slash / forbidden-component error, got: {msg}"
        );

        assert!(
            extract_dir.read_dir().unwrap().next().is_none(),
            "extract dir must remain empty after refused archive"
        );
    }

    /// Reader-side enforcement of `FORMAT.md` §9 directory trailing
    /// slash. A typeflag-`5` entry whose path doesn't end in `/`
    /// is malformed regardless of how it got into the stream.
    #[test]
    fn unarchive_rejects_directory_without_trailing_slash() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "mydir", &[] as &[u8])
                .unwrap();
            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        assert!(
            err.to_string()
                .contains("Directory entry path must end with /"),
            "expected directory-trailing-slash error, got: {err}"
        );
    }

    /// Reader-side enforcement of `FORMAT.md` §9 file-no-trailing-
    /// slash. A typeflag-`0` entry whose path ends in `/` is
    /// malformed.
    #[test]
    fn unarchive_rejects_file_with_trailing_slash() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "weird/", &[] as &[u8])
                .unwrap();
            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        assert!(
            err.to_string()
                .contains("File entry path must not end with /"),
            "expected file-no-trailing-slash error, got: {err}"
        );
    }

    /// Two directory entries declaring the same canonical path form a
    /// duplicate per `FORMAT.md` §9. The dup detection runs on the
    /// canonical (trailing-slash-stripped) path so the rejection
    /// fires even if the entries differ in superficial details.
    #[test]
    fn unarchive_rejects_duplicate_directory_entries() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            for _ in 0..2 {
                let mut header = tar::Header::new_ustar();
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_mode(0o755);
                header.set_cksum();
                builder
                    .append_data(&mut header, "mydir/", &[] as &[u8])
                    .unwrap();
            }
            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        assert!(
            err.to_string().contains("Duplicate archive entry"),
            "expected duplicate-entry error, got: {err}"
        );
    }

    /// A file entry `foo` and a directory entry `foo/` collide on the
    /// canonical path (one trailing `/` stripped from the directory).
    /// Per `FORMAT.md` §9 this is a duplicate, not two distinct
    /// entries.
    #[test]
    fn unarchive_rejects_file_dir_canonical_collision() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);

            let data = b"file";
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, "name", &data[..]).unwrap();

            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "name/", &[] as &[u8])
                .unwrap();
            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        assert!(
            err.to_string().contains("Duplicate archive entry"),
            "expected file/dir canonical collision, got: {err}"
        );
    }

    /// Per `FORMAT.md` §9 the TAR payload terminates with two 512-byte
    /// zero blocks; any non-zero byte after the end-of-archive marker
    /// must be rejected (otherwise an attacker could smuggle data in
    /// the trailing region of an authenticated `.fcr` payload).
    #[test]
    fn unarchive_rejects_nonzero_trailing_data() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            let data = b"payload";
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "hello.txt", &data[..])
                .unwrap();
            builder.finish().unwrap();
        }
        // Smuggle a non-zero byte past the end-of-archive zero blocks.
        buf.push(0xAA);

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        assert!(
            err.to_string().contains("Non-zero trailing data"),
            "expected non-zero-trailing-data rejection, got: {err}"
        );
    }

    /// Helper for the PAX / GNU rejection tests below. Builds a
    /// minimal one-entry archive whose single header carries a chosen
    /// `typeflag` byte but uses POSIX `ustar\000` magic, so the magic
    /// check passes and the typeflag match in `validate_ustar_entry`
    /// is the rejection point under test. The `body` bytes are
    /// arbitrary — the reader rejects on typeflag before reading the
    /// body — but we use realistic PAX `length key=value\n` records in
    /// the call sites so the fixtures double as documentation.
    fn extension_record_archive(typeflag: tar::EntryType, name: &str, body: &[u8]) -> Vec<u8> {
        let mut header = tar::Header::new_ustar();
        header.set_path(name).unwrap();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(typeflag);
        header.set_cksum();

        let mut buf = Vec::new();
        buf.extend_from_slice(header.as_bytes());
        buf.extend_from_slice(body);
        let pad = (ustar::BLOCK_SIZE - body.len() % ustar::BLOCK_SIZE) % ustar::BLOCK_SIZE;
        buf.extend(std::iter::repeat_n(0u8, pad));
        // End-of-archive: two consecutive zero blocks.
        buf.extend(std::iter::repeat_n(0u8, 2 * ustar::BLOCK_SIZE));
        buf
    }

    /// `FORMAT.md` §9 forbids PAX extended headers in any form. A PAX
    /// `'x'` record overriding only `mtime` would not change the
    /// merged entry's path or size, so the legacy "compare merged vs
    /// in-header" detection had no signal to fire on. Raw iteration
    /// now surfaces the `'x'` record as its own entry, where the
    /// typeflag match rejects it directly.
    #[test]
    fn unarchive_rejects_pax_x_mtime_only_override() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        // PAX record format: `length key=value\n`. Self-counting length:
        // the digits of `length` are part of the record, so the body is
        // hand-balanced to be exactly the announced byte count.
        let body = b"30 mtime=1700000000.000000\n\0\0\0".to_vec();
        let buf = extension_record_archive(tar::EntryType::XHeader, "x_header", &body);

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("forbidden PAX"),
            "expected PAX rejection, got: {msg}"
        );
    }

    /// Realistic local-PAX shape: an `'x'` extension immediately
    /// precedes the regular file it would have described under normal
    /// tar-rs preprocessing. Raw iteration must reject the extension
    /// before the following file is extracted, leaving the output
    /// directory empty.
    #[test]
    fn unarchive_rejects_pax_x_before_following_file_without_extracting() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let pax_body = b"22 mtime=1700000000.0\n";
        let file_body = b"payload that must not be extracted";

        let mut buf = Vec::new();

        let mut pax_header = tar::Header::new_ustar();
        pax_header.set_path("pax_header").unwrap();
        pax_header.set_size(pax_body.len() as u64);
        pax_header.set_mode(0o644);
        pax_header.set_entry_type(tar::EntryType::XHeader);
        pax_header.set_cksum();
        buf.extend_from_slice(pax_header.as_bytes());
        buf.extend_from_slice(pax_body);
        let pad = (ustar::BLOCK_SIZE - pax_body.len() % ustar::BLOCK_SIZE) % ustar::BLOCK_SIZE;
        buf.extend(std::iter::repeat_n(0u8, pad));

        let mut file_header = tar::Header::new_ustar();
        file_header.set_path("root.txt").unwrap();
        file_header.set_size(file_body.len() as u64);
        file_header.set_mode(0o644);
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_cksum();
        buf.extend_from_slice(file_header.as_bytes());
        buf.extend_from_slice(file_body);
        let pad = (ustar::BLOCK_SIZE - file_body.len() % ustar::BLOCK_SIZE) % ustar::BLOCK_SIZE;
        buf.extend(std::iter::repeat_n(0u8, pad));

        buf.extend(std::iter::repeat_n(0u8, 2 * ustar::BLOCK_SIZE));

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("forbidden PAX"),
            "expected PAX rejection, got: {msg}"
        );
        assert!(
            extract_dir.read_dir().unwrap().next().is_none(),
            "following file must not be extracted after a refused PAX header"
        );
    }

    #[test]
    fn unarchive_rejects_pax_x_uid_gid_override() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let body = b"13 uid=1234\n13 gid=5678\n".to_vec();
        let buf = extension_record_archive(tar::EntryType::XHeader, "x_header", &body);

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("forbidden PAX"),
            "expected PAX rejection, got: {msg}"
        );
    }

    /// PAX `'x'` overriding `mode`. Same rejection path.
    #[test]
    fn unarchive_rejects_pax_x_mode_only_override() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        // Plain `mode=` is not a standard PAX key, but the body is
        // never parsed by the reader; the typeflag rejection fires
        // first. The contents document attacker intent.
        let body = b"14 mode=0007777\n".to_vec();
        let buf = extension_record_archive(tar::EntryType::XHeader, "x_header", &body);

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("forbidden PAX"),
            "expected PAX rejection, got: {msg}"
        );
    }

    /// PAX `'x'` overriding `path`. The legacy detection caught this
    /// case via the merged-vs-in-header comparison; with raw
    /// iteration the typeflag match rejects it earlier and the error
    /// message names PAX explicitly.
    #[test]
    fn unarchive_rejects_pax_x_path_override() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let body = b"22 path=/etc/passwd\n\0\0".to_vec();
        let buf = extension_record_archive(tar::EntryType::XHeader, "x_header", &body);

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("forbidden PAX"),
            "expected PAX rejection, got: {msg}"
        );
    }

    /// PAX `'x'` overriding `size`. The legacy detection caught this
    /// case via the `entry.size() != header.size()` comparison; raw
    /// iteration rejects at the typeflag match.
    #[test]
    fn unarchive_rejects_pax_x_size_override() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let body = b"19 size=2147483648\n\0".to_vec();
        let buf = extension_record_archive(tar::EntryType::XHeader, "x_header", &body);

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("forbidden PAX"),
            "expected PAX rejection, got: {msg}"
        );
    }

    /// PAX `'g'` global header. The strict no-PAX rule applies to
    /// global headers as well as per-entry `'x'` headers.
    #[test]
    fn unarchive_rejects_pax_g_global_header() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let body = b"15 comment=hi\n\0".to_vec();
        let buf = extension_record_archive(tar::EntryType::XGlobalHeader, "g_header", &body);

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("forbidden PAX"),
            "expected PAX rejection, got: {msg}"
        );
    }

    /// GNU `'L'` long-name record carried in a header with POSIX
    /// `ustar\000` magic (as opposed to GNU magic). The
    /// `unarchive_rejects_gnu_long_name_extension` test below also
    /// exercises this typeflag, but writes a GNU-magic header that
    /// trips the magic check first; this test pins the typeflag-match
    /// rejection branch specifically.
    #[test]
    fn unarchive_rejects_gnu_l_typeflag_with_posix_magic() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let body = b"./long/path/that/would/be/applied/next\0".to_vec();
        let buf = extension_record_archive(tar::EntryType::GNULongName, "@LongLink", &body);

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("forbidden GNU"),
            "expected GNU-extension rejection, got: {msg}"
        );
    }

    /// `FORMAT.md` §9 forbids the GNU binary numeric encoding on any
    /// header field. The size field is the realistic concern: a
    /// regular-file entry with typeflag `'0'` and a binary-encoded
    /// size passes every typeflag-based check but lets the attacker
    /// declare an arbitrary plaintext length. We rely on tar-rs's
    /// `set_size` to do the binary fallback for sizes ≥ 2^33 — the
    /// same fallback our encrypt-side cap is designed to prevent — so
    /// this test doubles as a sanity check that tar-rs hasn't quietly
    /// changed its switching point.
    #[test]
    fn unarchive_rejects_gnu_binary_size_encoding() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let mut header = tar::Header::new_ustar();
        header.set_path("big.bin").unwrap();
        header.set_size(ustar::FILE_SIZE_REPRESENTABLE_MAX + 1);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();

        // Sanity: tar-rs really emitted the binary-size encoding for
        // a value ≥ 2^33 — if a future tar-rs release changes the
        // switching point, this assertion catches it loudly.
        assert_eq!(
            header.as_bytes()[ustar::SIZE_FIELD_OFFSET] & ustar::NUMERIC_BINARY_FLAG_BIT,
            ustar::NUMERIC_BINARY_FLAG_BIT,
            "expected tar-rs to emit GNU binary-size for size ≥ 2^33",
        );

        let mut buf = Vec::new();
        buf.extend_from_slice(header.as_bytes());
        // No body — the rejection fires on the header before any
        // body bytes would be read.
        buf.extend(std::iter::repeat_n(0u8, 2 * ustar::BLOCK_SIZE));

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("forbidden GNU binary numeric"),
            "expected binary-size rejection, got: {msg}"
        );
    }

    /// GNU `'S'` sparse-file record. v1 forbids sparse archives, and
    /// raw iteration surfaces the sparse record's typeflag for the
    /// reader to reject directly.
    #[test]
    fn unarchive_rejects_gnu_sparse_typeflag() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let body = b"sparse-record-payload".to_vec();
        let buf = extension_record_archive(tar::EntryType::GNUSparse, "sparse", &body);

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("forbidden GNU"),
            "expected GNU-extension rejection, got: {msg}"
        );
    }

    /// Reader-side rejection of a GNU long-name extension record. The
    /// `'L'` block uses GNU magic, so the magic check at the start of
    /// `validate_ustar_entry` rejects it as "not POSIX ustar". This
    /// test exists in addition to the POSIX-magic + `'L'` typeflag
    /// test above so both rejection paths are pinned. A 200-char path
    /// forces the long-name path on the writer side regardless of the
    /// `new_gnu()` / `new_ustar()` choice.
    #[test]
    fn unarchive_rejects_gnu_long_name_extension() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        // Build via `new_gnu()` + a 200-char path so the tar crate
        // emits a `././@LongLink` extension record before the regular
        // entry. POSIX ustar can encode up to ~256 chars only with a
        // valid `name + '/' + prefix` split; a path with no `/` of
        // 200 chars cannot be split and must use the GNU extension.
        let long_name: String = "a".repeat(200);
        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            let data = b"x";
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, &long_name, &data[..])
                .unwrap();
            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir, ArchiveLimits::default()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("GNU long-name") || msg.contains("not POSIX ustar"),
            "expected GNU-extension or non-ustar rejection, got: {msg}"
        );
    }

    /// Resource cap: when the entry count exceeds
    /// `ArchiveLimits::max_entry_count`, extraction must reject
    /// before the offending entry's `seen_paths` slot is allocated.
    /// Caller can lift the cap by passing tighter / looser limits.
    #[test]
    fn unarchive_rejects_archive_above_entry_count_cap() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        // 1 directory + 5 files = 6 entries.
        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "myroot/", &[] as &[u8])
                .unwrap();
            for i in 0..5 {
                let name = format!("myroot/file_{i}");
                let mut header = tar::Header::new_ustar();
                header.set_size(0);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, &name, &[] as &[u8])
                    .unwrap();
            }
            builder.finish().unwrap();
        }

        let limits = ArchiveLimits {
            max_entry_count: 3,
            ..ArchiveLimits::default()
        };
        let err = unarchive(Cursor::new(buf), &extract_dir, limits).unwrap_err();
        assert!(
            err.to_string().contains("entry-count cap"),
            "expected entry-count cap rejection, got: {err}"
        );
        // The `.incomplete` directory was created (root entry came in
        // before the cap fired); it must remain on disk for inspection
        // and must NOT have been promoted to the final name.
        assert!(!extract_dir.join("myroot").exists());
    }

    /// Resource cap: when the announced cumulative file size exceeds
    /// `ArchiveLimits::max_total_plaintext_bytes`, extraction
    /// must reject BEFORE `io::copy` starts so a hostile size
    /// declaration cannot force a partial write.
    #[test]
    fn unarchive_rejects_archive_above_total_bytes_cap() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let data = vec![0u8; 1000];
        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            let mut header = tar::Header::new_ustar();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "big.bin", &data[..])
                .unwrap();
            builder.finish().unwrap();
        }

        let limits = ArchiveLimits {
            max_total_plaintext_bytes: 100,
            ..ArchiveLimits::default()
        };
        let err = unarchive(Cursor::new(buf), &extract_dir, limits).unwrap_err();
        assert!(
            err.to_string().contains("total-bytes cap"),
            "expected total-bytes cap rejection, got: {err}"
        );
        // No file was promoted, and the working `.incomplete` was not
        // populated past the cap rejection.
        assert!(!extract_dir.join("big.bin").exists());
    }

    /// Resource cap: when an entry's path component count exceeds
    /// `ArchiveLimits::max_path_depth`, extraction must reject
    /// before the per-component capability walk runs. Catches deeply
    /// nested but byte-economical paths that pass the
    /// `PATH_REPRESENTABLE_MAX` byte-length check.
    #[test]
    fn unarchive_rejects_archive_above_path_depth_cap() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        // Path with 7 components: myroot/a/b/c/d/e/file.txt.
        let data = b"hi";
        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            let mut header = tar::Header::new_ustar();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "myroot/a/b/c/d/e/file.txt", &data[..])
                .unwrap();
            builder.finish().unwrap();
        }

        let limits = ArchiveLimits {
            max_path_depth: 4,
            ..ArchiveLimits::default()
        };
        let err = unarchive(Cursor::new(buf), &extract_dir, limits).unwrap_err();
        assert!(
            err.to_string().contains("path depth cap"),
            "expected path depth cap rejection, got: {err}"
        );
        assert!(!extract_dir.join("myroot").exists());
    }
}
