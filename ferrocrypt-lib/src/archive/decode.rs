//! Decrypt-side TAR reading and output reconstruction.
//!
//! [`unarchive`] streams an authenticated TAR payload into the
//! caller-supplied `output_dir`, writing every output under an
//! `.incomplete` working name and atomically promoting the working
//! root to its final name only after the whole archive validates.
//!
//! Per-entry validation runs before any filesystem write — see
//! [`validate_ustar_entry`] (`FORMAT.md` §9). On Linux and macOS,
//! `extract_entries` anchors every operation to a directory file
//! descriptor opened by [`super::platform::open_anchor`] and uses
//! `openat`/`mkdirat` with `O_NOFOLLOW`; on other platforms the path-
//! based fallback documents its narrower threat model inline.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::CryptoError;
use crate::fs::atomic::rename_no_clobber;
use crate::fs::paths::INCOMPLETE_SUFFIX;

use super::limits::{ArchiveLimits, enforce_per_entry_caps, enforce_total_bytes_cap};
use super::path::{UstarEntryKind, ustar, validate_archive_path};

/// Initial mode for newly-created regular-file extraction outputs
/// (rw-------). Restrictive on purpose: the tar-stored mode is applied
/// via a follow-up `fchmod` (or `set_permissions` on the path-based
/// arm) only AFTER the payload has been written, so a wider mode is
/// never briefly visible to other local users while the file holds
/// plaintext.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const INITIAL_FILE_CREATE_MODE: u32 = 0o600;

/// Decrypt-side per-iteration accounting bundled into one struct so the
/// shared `pre_validate_entry` method runs identical resource-cap +
/// duplicate-detection logic in both `extract_entries` arms (the
/// Linux/macOS NOFOLLOW path and the path-based fallback). `entry_count`
/// is checked before the entry is added to `seen_paths`; `total_bytes`
/// is checked before any `io::copy` so an attacker-declared 1 PiB size
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
/// - typeflags outside `{file, directory}` (symlink, hardlink,
///   device, fifo, GNU/PAX extension records);
/// - GNU long-name / long-link records: when the tar crate
///   transparently merges an extension into the next entry,
///   `entry.path_bytes()` carries the long path while
///   `entry.header().path_bytes()` still carries the truncated
///   in-header name. A mismatch means an extension was applied;
/// - empty paths, paths with NUL or `\` bytes, repeated `/`
///   separators, paths longer than the ustar representable cap;
/// - non-UTF-8 paths;
/// - file entries whose path ends with `/`, directory entries
///   whose path does not;
/// - `.` and `..` components, absolute paths, Windows path
///   prefixes (covered by `validate_archive_path`).
///
/// Known limitation: a non-path-altering PAX extended header (`'x'`
/// typeflag carrying e.g. mtime / size attributes) is consumed by the
/// tar crate before the entry is yielded, leaving
/// `header_path == entry_path`. The practical impact is bounded —
/// such attributes only affect timestamps / permissions, which
/// extraction filters separately, and ferrocrypt's own writer never
/// emits PAX records. A fully strict implementation would replace
/// `tar::Archive::entries()` with a custom 512-byte-block parser.
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
        _ => {
            return Err(CryptoError::InvalidInput(format!(
                "Unsupported archive entry type: typeflag 0x{typeflag:02X}"
            )));
        }
    };

    // GNU long-name / long-link detection. The tar crate transparently
    // consumes `'L'` / `'K'` extension records and applies the long path
    // to the next entry's `entry.path_bytes()`, but `entry.header()`
    // still reflects the next entry's raw header (whose `path_bytes()`
    // returns the in-header name+prefix only). Inequality means an
    // extension record was used. Both Cows borrow `entry` shared so the
    // comparison runs without allocating.
    let header_path = entry.header().path_bytes();
    let entry_path = entry.path_bytes();
    if *header_path != *entry_path {
        return Err(CryptoError::InvalidInput(
            "Archive uses GNU long-name or long-link extension".to_string(),
        ));
    }

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
    validate_archive_path(&canonical_path)?;

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

/// Per-iteration root tracking shared by both `extract_entries` arms.
/// Extracts the first path component, rejects a second top-level root,
/// pre-checks the final output name for collisions (`symlink_metadata`
/// catches dangling symlinks too), and on the path-based fallback arm
/// also pre-checks the `.incomplete` working name. Both pre-checks run
/// BEFORE `first_entry_root` and `checked_roots` are mutated, so a
/// rejection leaves the caller's tracking state untouched. Idempotent
/// for already-registered roots (returns the same `root_name` without
/// re-running any check).
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
    // Path-based fallback: also pre-check `{root}.incomplete` so a
    // pre-placed working entry doesn't get partially overwritten before
    // being detected by the per-entry filesystem syscalls. The
    // hardened Linux/macOS arm doesn't need this — `mkdirat_strict`
    // and `create_file_at` use `O_EXCL` / `O_NOFOLLOW` and fail with
    // `AlreadyExists` if anything is already at that name.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let incomplete_path = output_dir.join(incomplete_working_name(&root_name));
        match fs::symlink_metadata(&incomplete_path) {
            Ok(_) => {
                return Err(CryptoError::InvalidInput(format!(
                    "Previous .incomplete exists: {}",
                    incomplete_path.display()
                )));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(CryptoError::Io(e)),
        }
    }
    if first_entry_root.is_none() {
        *first_entry_root = Some(final_path);
    }
    checked_roots.push(root_name.clone());
    Ok(root_name)
}

/// Hardened extraction for Linux and macOS. Every filesystem operation
/// inside the `.incomplete` working entry is rooted at a dirfd and goes
/// through `openat`/`mkdirat` with `O_NOFOLLOW`, so a concurrent local
/// attacker cannot race a directory component into a symlink and
/// redirect writes outside the destination tree. File creation uses
/// `O_CREAT | O_EXCL | O_NOFOLLOW`, and directory permissions are
/// applied via `fchmod` on the still-open fd so path resolution never
/// happens at chmod time.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn extract_entries<R: Read>(
    archive: &mut tar::Archive<R>,
    output_dir: &Path,
    first_entry_root: &mut Option<PathBuf>,
    checked_roots: &mut Vec<OsString>,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    use std::collections::HashMap;
    use std::fs::File;
    use std::os::fd::{AsFd, OwnedFd};

    use super::platform;

    /// Per-root state. A tar root can be either a directory (the usual
    /// multi-entry case) or a regular file (single-file archives where
    /// the root component IS the file). Directories keep an open dirfd
    /// so subsequent child entries resolve under it.
    enum RootKind {
        Directory(OwnedFd),
        SingleFile,
    }

    fn map_incomplete_create_err(
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

    /// Ensures `roots` has a `Directory` entry for `root_name`, lazily
    /// creating its `.incomplete` working directory under `output_fd` on
    /// first occurrence. Rejects with the canonical "mixes file and
    /// directory" error if a `SingleFile` root has already been recorded
    /// under the same name. Returns a borrow of the registered dirfd.
    fn ensure_root_directory<'a>(
        roots: &'a mut HashMap<OsString, RootKind>,
        root_name: &OsString,
        output_fd: &OwnedFd,
        output_dir: &Path,
        incomplete_name: &OsStr,
        path: &Path,
    ) -> Result<&'a OwnedFd, CryptoError> {
        use std::collections::hash_map::Entry;
        match roots.entry(root_name.clone()) {
            Entry::Occupied(occ) => match occ.into_mut() {
                RootKind::SingleFile => Err(CryptoError::InvalidInput(format!(
                    "Archive mixes file and directory at root: {}",
                    path.display()
                ))),
                RootKind::Directory(fd) => Ok(fd),
            },
            Entry::Vacant(vac) => {
                let fd = platform::mkdirat_strict(output_fd, incomplete_name)
                    .map_err(|e| map_incomplete_create_err(e, output_dir, incomplete_name))?;
                match vac.insert(RootKind::Directory(fd)) {
                    RootKind::Directory(fd) => Ok(fd),
                    RootKind::SingleFile => unreachable!("just inserted Directory variant"),
                }
            }
        }
    }

    /// Streams the entry's payload into the just-created `outfile`, then
    /// applies the tar-stored mode via `fchmod` on the still-open fd.
    /// `outfile` is consumed (and dropped at scope exit) so the file is
    /// closed before this returns. The two file-extraction sites (Case A
    /// single-file root and Case B descendant) share this exact
    /// sequence; `platform::fchmod` strips the special bits internally.
    fn copy_payload_and_apply_mode<R: Read>(
        mut outfile: File,
        entry: &mut tar::Entry<'_, R>,
    ) -> Result<(), CryptoError> {
        io::copy(entry, &mut outfile)?;
        if let Ok(mode) = entry.header().mode() {
            platform::fchmod(outfile.as_fd(), mode)?;
        }
        Ok(())
    }

    let output_fd = platform::open_anchor(output_dir)?;
    let mut roots: HashMap<OsString, RootKind> = HashMap::new();
    // Deferred directory permissions: (root name, rel path under root, mode).
    // `rel` is empty for the root directory itself.
    let mut dir_permissions: Vec<(OsString, PathBuf, u32)> = Vec::new();
    let mut counters = ExtractCounters::default();

    for entry_result in archive.entries()? {
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
                        &output_fd,
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
                        &output_fd,
                        &incomplete_name,
                        INITIAL_FILE_CREATE_MODE,
                    )
                    .map_err(|e| map_incomplete_create_err(e, output_dir, &incomplete_name))?;
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
        let root_fd = ensure_root_directory(
            &mut roots,
            &root_name,
            &output_fd,
            output_dir,
            &incomplete_name,
            &path,
        )?;
        let (parent_fd, final_name) = platform::walk_to_parent(root_fd, &rel)?;
        match kind {
            UstarEntryKind::Directory => {
                let _dir_fd = platform::ensure_dir(&parent_fd, &final_name)?;
                if let Ok(mode) = entry.header().mode() {
                    dir_permissions.push((root_name.clone(), rel, mode));
                }
            }
            UstarEntryKind::File => {
                let outfile =
                    platform::create_file_at(&parent_fd, &final_name, INITIAL_FILE_CREATE_MODE)?;
                copy_payload_and_apply_mode(outfile, &mut entry)?;
            }
        }
    }

    // Apply deferred directory permissions. Each chmod happens on a fresh
    // NOFOLLOW-opened fd, so a restrictive parent mode does not block the
    // operation and order does not matter. `open_dir_at_rel` folds the
    // root-vs-descendant case naturally — see its doc-comment for the
    // empty-`rel` contract.
    for (root_name, rel, mode) in &dir_permissions {
        let Some(RootKind::Directory(root_fd)) = roots.get(root_name) else {
            return Err(CryptoError::InternalInvariant(
                "Internal error: root dirfd missing at dir-perm stage",
            ));
        };
        let dir_fd = platform::open_dir_at_rel(root_fd, rel)?;
        platform::fchmod(&dir_fd, *mode)?;
    }

    Ok(())
}

/// Path-based extraction for platforms where rustix is not pulled in
/// (currently Windows and non-Linux/non-macOS Unix targets).
///
/// **Hardening note (Windows / non-Unix):** unlike the Linux/macOS path,
/// this arm walks plain `&Path` via `fs::create_dir_all`,
/// `OpenOptions::create_new`, and `fs::set_permissions`. There is no
/// `openat`-anchored dirfd, so a local attacker who can write inside
/// `output_dir` can race a directory component into a symlink between
/// the `mkdir` step and the `create_new` step and redirect plaintext
/// outside the destination tree. The Linux/macOS path closes this with
/// `O_NOFOLLOW` on every component; Windows would require
/// `NtCreateFile` with relative-`OBJECT_ATTRIBUTES` (or equivalent
/// winapi work) to match, which the crate does not currently take on
/// because of its zero-`unsafe` stance (`fs/atomic.rs` documents
/// the same trade-off for the rename helper).
///
/// Partial mitigations that DO apply on this path:
///
/// - `create_new(true)` rejects with `AlreadyExists` when a regular
///   file (or a symlink whose target already exists) is pre-placed at
///   the leaf entry path. It does NOT block writing through a
///   pre-placed symlink whose target is missing — Windows
///   `CreateFileW(CREATE_NEW)` follows symlinks/reparse points by
///   default — and it does NOT block races on intermediate directory
///   components.
/// - The canonical-path `seen_paths` set rejects in-archive duplicates,
///   so the loop never tries to overwrite its own outputs.
/// - The post-extract `rename_no_clobber` promotion refuses to clobber
///   a pre-existing final-name target (Windows uses `try_exists()` +
///   `fs::rename`, which is itself best-effort no-clobber).
/// - The caller-driven trust boundary on `output_dir` itself: the
///   directory the user picked is trusted.
///
/// **Operator guidance:** when extracting attacker-influenced archives
/// on Windows, choose an `output_dir` not writable by other local
/// users (e.g. a fresh subdirectory under `%LOCALAPPDATA%`).
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn extract_entries<R: Read>(
    archive: &mut tar::Archive<R>,
    output_dir: &Path,
    first_entry_root: &mut Option<PathBuf>,
    checked_roots: &mut Vec<OsString>,
    limits: &ArchiveLimits,
) -> Result<(), CryptoError> {
    // Directory permissions are applied after all entries are extracted,
    // deepest first, so that a restrictive parent mode (e.g. 0o500) does
    // not block creation of child entries.
    let mut dir_permissions: Vec<(PathBuf, u32)> = Vec::new();
    let mut counters = ExtractCounters::default();

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let NormalizedEntry {
            canonical_path: path,
            kind,
        } = counters.pre_validate_entry(&mut entry, limits)?;

        let root_name =
            extract_and_register_root(output_dir, &path, first_entry_root, checked_roots)?;

        // Rewrite the entry path: replace the root component with {root}.incomplete
        let working_path = incomplete_entry_path(output_dir, &root_name, &path);

        match kind {
            UstarEntryKind::Directory => {
                fs::create_dir_all(&working_path)?;
                if let Ok(mode) = entry.header().mode() {
                    dir_permissions.push((working_path, mode));
                }
            }
            UstarEntryKind::File => {
                if let Some(parent) = working_path.parent() {
                    if !parent.exists() {
                        fs::create_dir_all(parent)?;
                    }
                }
                // `create_new(true)` is now defense-in-depth — the
                // canonical-path `seen_paths` set above already rejects
                // duplicates per `FORMAT.md` §9, before any file is
                // created. The `create_new` guard remains so a TOCTOU
                // race or future refactor cannot silently overwrite.
                let mut outfile = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&working_path)?;
                io::copy(&mut entry, &mut outfile)?;
                drop(outfile);
                if let Ok(mode) = entry.header().mode() {
                    restore_permissions_from_mode(mode, &working_path)?;
                }
            }
        }
    }

    // Apply directory permissions deepest-first so that restricting a parent
    // does not prevent setting permissions on its children.
    dir_permissions.sort_by_key(|entry| std::cmp::Reverse(entry.0.components().count()));
    for (path, mode) in &dir_permissions {
        restore_permissions_from_mode(*mode, path)?;
    }

    Ok(())
}

/// Rewrites a TAR entry path so the root component has an `.incomplete` suffix.
///
/// - Single file `hello.txt` → `output_dir/hello.txt.incomplete`
/// - Directory entry `mydir/sub/file.txt` → `output_dir/mydir.incomplete/sub/file.txt`
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn incomplete_entry_path(output_dir: &Path, root_name: &OsStr, entry_path: &Path) -> PathBuf {
    let base = output_dir.join(incomplete_working_name(root_name));
    match entry_path.strip_prefix(root_name) {
        Ok(rest) if !rest.as_os_str().is_empty() => base.join(rest),
        _ => base,
    }
}

/// Applies a stored mode to a path on the path-based extraction path.
/// The Linux/macOS hardened path uses `fchmod` on an open dirfd instead
/// and does not call this helper.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn restore_permissions_from_mode(mode: u32, path: &Path) -> Result<(), CryptoError> {
    use std::os::unix::fs::PermissionsExt;
    let safe_mode = mode & super::PERMISSION_BITS_MASK;
    fs::set_permissions(path, std::fs::Permissions::from_mode(safe_mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn restore_permissions_from_mode(_mode: u32, _path: &Path) -> Result<(), CryptoError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::limits::ArchiveLimits;
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
    /// `validate_archive_path`. tar-rs strips leading `./` from longer
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

    /// Reader-side rejection of a GNU long-name extension record. The
    /// tar crate transparently consumes `'L'` records and applies the
    /// long path to the next entry; `validate_ustar_entry` detects
    /// the extension by comparing the in-header path to the merged
    /// `entry.path_bytes()`. A 200-char path forces the long-name
    /// path on the writer side regardless of the `new_gnu()` /
    /// `new_ustar()` choice.
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
    /// before the per-component openat walk runs. Catches deeply
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
