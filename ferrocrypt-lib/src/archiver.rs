#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use crate::CryptoError;

/// Default file mode for non-Unix platforms (rw-r--r--).
#[cfg(not(unix))]
const DEFAULT_FILE_MODE: u32 = 0o644;

/// Mask that keeps only owner/group/other rwx bits, stripping
/// setuid, setgid, and sticky bits from tar-stored permissions.
#[cfg(unix)]
const PERMISSION_BITS_MASK: u32 = 0o777;

/// Component-by-component no-follow extraction primitives.
///
/// The hardened extraction walker anchors every operation to a directory
/// file descriptor rooted in the user's trusted `output_dir`. Every
/// intermediate component is resolved via `openat`/`mkdirat` with
/// `O_NOFOLLOW`, so a concurrent local attacker who can write inside the
/// destination tree cannot race a directory into a symlink and redirect
/// the write elsewhere. The final regular file is created with
/// `O_CREAT | O_EXCL | O_NOFOLLOW` so a pre-placed symlink fails closed
/// with `AlreadyExists`.
///
/// Gated to Linux and macOS because rustix is only pulled in there; the
/// other-platform extraction path keeps the existing path-based approach.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod nofollow {
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsFd, OwnedFd};
    use std::path::{Component, Path};

    use rustix::fs::{FileType, Mode, OFlags, RawMode};
    use rustix::io::Errno;

    use crate::CryptoError;

    /// Converts a tar-style u32 permission word into a `rustix::fs::Mode`,
    /// coping with targets where `mode_t` is narrower than `u32`. The
    /// defensive `0o7777` mask keeps only permission and special bits
    /// (rwx + setuid/setgid/sticky), so a stray caller passing a value
    /// with high bits set cannot silently truncate on macOS's `u16`
    /// `RawMode`.
    pub(super) fn mode_from(mode: u32) -> Mode {
        Mode::from_raw_mode((mode & 0o7777) as RawMode)
    }

    /// Opens the user-supplied output directory as a dirfd anchor. The
    /// output directory itself is chosen by the caller (argv / GUI picker)
    /// and is trusted, so NOFOLLOW is not applied here.
    pub(super) fn open_anchor(output_dir: &Path) -> Result<OwnedFd, CryptoError> {
        rustix::fs::open(
            output_dir,
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| CryptoError::Io(io::Error::from(e)))
    }

    /// Opens `name` under `parent_fd` without following symlinks on the
    /// final component and without any assumption about file type. The
    /// combination `O_NOFOLLOW | O_NONBLOCK` catches symlinks (ELOOP)
    /// before resolving, and prevents hangs if an attacker places a FIFO
    /// at the name. `O_DIRECTORY` is intentionally omitted — on macOS
    /// combining it with `O_NOFOLLOW` makes the kernel report `ENOTDIR`
    /// instead of `ELOOP` on a symlink target, so we verify the file
    /// type via `fstat` on the returned fd instead.
    fn openat_nofollow(parent_fd: &OwnedFd, name: &OsStr) -> Result<OwnedFd, Errno> {
        rustix::fs::openat(
            parent_fd.as_fd(),
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
    }

    fn ensure_fd_is_directory(fd: &OwnedFd, name: &OsStr) -> Result<(), CryptoError> {
        let stat =
            rustix::fs::fstat(fd.as_fd()).map_err(|e| CryptoError::Io(io::Error::from(e)))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Err(CryptoError::InvalidInput(format!(
                "Expected directory at: {}",
                Path::new(name).display()
            )));
        }
        Ok(())
    }

    /// Creates a fresh directory `name` under `parent_fd` and opens it
    /// NOFOLLOW. Fails with `AlreadyExists` if anything — including a
    /// symlink — already exists at that name.
    pub(super) fn mkdirat_strict(parent_fd: &OwnedFd, name: &OsStr) -> io::Result<OwnedFd> {
        rustix::fs::mkdirat(parent_fd.as_fd(), name, mode_from(0o755)).map_err(io::Error::from)?;
        let fd = openat_nofollow(parent_fd, name).map_err(io::Error::from)?;
        // fstat the freshly-opened fd to confirm it is a directory —
        // catches a racing attacker who replaced our mkdirat result with
        // a different file type between the syscalls.
        let stat = rustix::fs::fstat(fd.as_fd()).map_err(io::Error::from)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mkdirat target is not a directory after open",
            ));
        }
        Ok(fd)
    }

    /// Ensures `name` exists as a directory under `parent_fd`, returning
    /// its fd. Opens NOFOLLOW first; on `NotFound` creates it then
    /// reopens. A symlink at that name aborts with a typed error, as does
    /// any non-directory file type.
    pub(super) fn ensure_dir(parent_fd: &OwnedFd, name: &OsStr) -> Result<OwnedFd, CryptoError> {
        match openat_nofollow(parent_fd, name) {
            Ok(fd) => {
                ensure_fd_is_directory(&fd, name)?;
                Ok(fd)
            }
            Err(Errno::NOENT) => {
                rustix::fs::mkdirat(parent_fd.as_fd(), name, mode_from(0o755))
                    .map_err(|e| CryptoError::Io(io::Error::from(e)))?;
                let fd = openat_nofollow(parent_fd, name)
                    .map_err(|e| CryptoError::Io(io::Error::from(e)))?;
                ensure_fd_is_directory(&fd, name)?;
                Ok(fd)
            }
            Err(Errno::LOOP) => Err(symlink_err(name)),
            Err(e) => Err(CryptoError::Io(io::Error::from(e))),
        }
    }

    /// Opens an existing directory under `parent_fd` without creating
    /// anything. A symlink at that name aborts with a typed error; a
    /// non-directory file type does the same.
    fn open_existing_dir(parent_fd: &OwnedFd, name: &OsStr) -> Result<OwnedFd, CryptoError> {
        let fd = openat_nofollow(parent_fd, name).map_err(|e| {
            if e == Errno::LOOP {
                symlink_err(name)
            } else {
                CryptoError::Io(io::Error::from(e))
            }
        })?;
        ensure_fd_is_directory(&fd, name)?;
        Ok(fd)
    }

    fn symlink_err(name: &OsStr) -> CryptoError {
        CryptoError::InvalidInput(format!(
            "Symlink in extraction path: {}",
            Path::new(name).display()
        ))
    }

    fn normal_component<'a>(
        component: Component<'a>,
        full: &Path,
    ) -> Result<&'a OsStr, CryptoError> {
        match component {
            Component::Normal(s) => Ok(s),
            _ => Err(CryptoError::InvalidInput(format!(
                "Invalid component in archive entry: {}",
                full.display()
            ))),
        }
    }

    /// Walks `rel` under `root_fd`, creating intermediate directories
    /// as needed. Returns an fd of the final component's parent and
    /// the final component's name. Every step uses `NOFOLLOW`.
    pub(super) fn walk_to_parent(
        root_fd: &OwnedFd,
        rel: &Path,
    ) -> Result<(OwnedFd, OsString), CryptoError> {
        let mut components: Vec<Component<'_>> = rel.components().collect();
        let last = components
            .pop()
            .ok_or_else(|| CryptoError::InvalidInput("Empty entry relative path".to_string()))?;
        let final_name = normal_component(last, rel)?.to_os_string();

        let mut cur = root_fd
            .as_fd()
            .try_clone_to_owned()
            .map_err(CryptoError::Io)?;
        for component in components {
            let name = normal_component(component, rel)?;
            cur = ensure_dir(&cur, name)?;
        }
        Ok((cur, final_name))
    }

    /// Walks `rel` under `root_fd` without creating anything, returning
    /// an fd to the final directory. Used at chmod-time so deferred
    /// directory permissions can be applied against a fresh fd instead
    /// of a re-resolved path.
    pub(super) fn open_dir_at_rel(root_fd: &OwnedFd, rel: &Path) -> Result<OwnedFd, CryptoError> {
        let mut cur = root_fd
            .as_fd()
            .try_clone_to_owned()
            .map_err(CryptoError::Io)?;
        for component in rel.components() {
            let name = normal_component(component, rel)?;
            cur = open_existing_dir(&cur, name)?;
        }
        Ok(cur)
    }

    /// Atomically creates a new regular file under `parent_fd`. Any
    /// pre-existing entry — including a symlink — causes `AlreadyExists`.
    /// The initial permission word is restrictive (`0o600`); callers
    /// apply the tar-stored mode via `fchmod` after writing so plaintext
    /// is never briefly visible to unintended users.
    pub(super) fn create_file_at(
        parent_fd: &OwnedFd,
        name: &OsStr,
        create_mode: u32,
    ) -> io::Result<File> {
        let fd = rustix::fs::openat(
            parent_fd.as_fd(),
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode_from(create_mode),
        )
        .map_err(io::Error::from)?;
        Ok(File::from(fd))
    }

    /// Sets the mode of an already-open fd. Used for both regular files
    /// and directories, so it accepts any `AsFd` rather than just
    /// `&OwnedFd`.
    pub(super) fn fchmod<Fd: AsFd>(fd: Fd, mode: u32) -> Result<(), CryptoError> {
        rustix::fs::fchmod(fd, mode_from(mode)).map_err(|e| CryptoError::Io(io::Error::from(e)))
    }
}

/// Rejects paths that could escape the output directory (path traversal)
/// or confuse the root-aware extraction logic. `Component::CurDir`
/// (leading `./`) is rejected because ferrocrypt's own archiver never
/// produces it and it turns `root_name` into `.`, which then conflicts
/// with the final rename step.
pub fn validate_archive_path(path: &Path) -> Result<(), CryptoError> {
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

/// Archives a file or directory into a TAR stream written to `writer`.
/// Returns a tuple of the file stem (base name without extension for files,
/// directory name for directories) and the writer, so the caller can finalize it.
///
/// For directories, uses a manual recursive walk instead of `append_dir_all`
/// to give per-entry control: symlinks and special entries (sockets, FIFOs,
/// devices) are rejected with a clear error. Hardlinks are archived as regular
/// file contents without preserving link identity.
/// Rejects inputs the archiver will not accept: symlinks (live or dangling)
/// and anything that isn't a regular file or directory. Defined here because
/// these are the archiver's per-entry rules; `lib.rs` also calls this at the
/// top of every encrypt entry point so that the rejection fires before any
/// Argon2id or cipher work runs (up to a gigabyte of RAM and several seconds
/// of CPU on default settings), not only at archive time. The archive-time
/// call remains as defense-in-depth against TOCTOU and direct callers.
///
/// The `is_symlink` check runs before the existence check so that dangling
/// symlinks fail with a clear "Input is a symlink" message instead of a
/// generic `InputPath` not-found.
pub(crate) fn validate_encrypt_input(input_path: &Path) -> Result<(), CryptoError> {
    if input_path.is_symlink() {
        return Err(CryptoError::InvalidInput(format!(
            "Input is a symlink: {}",
            input_path.display()
        )));
    }
    if !input_path.exists() {
        return Err(CryptoError::InputPath);
    }
    if !input_path.is_file() && !input_path.is_dir() {
        return Err(CryptoError::InvalidInput(format!(
            "Unsupported file type: {}",
            input_path.display()
        )));
    }
    Ok(())
}

pub fn archive<W: Write>(
    input_path: impl AsRef<Path>,
    writer: W,
) -> Result<(String, W), CryptoError> {
    let input_path = input_path.as_ref();
    validate_encrypt_input(input_path)?;
    let mut builder = tar::Builder::new(writer);

    let stem = if input_path.is_file() {
        let file_name = input_path
            .file_name()
            .ok_or_else(|| CryptoError::InvalidInput("Cannot get file name".to_string()))?;

        append_file(&mut builder, input_path, Path::new(file_name))?;

        crate::common::file_stem(input_path)?
            .to_string_lossy()
            .into_owned()
    } else {
        let dir_name = input_path
            .file_name()
            .ok_or_else(|| CryptoError::InvalidInput("Cannot get directory name".to_string()))?;

        let archive_root = PathBuf::from(dir_name);
        archive_directory(&mut builder, input_path, &archive_root)?;
        dir_name.to_string_lossy().into_owned()
    };

    let writer = builder.into_inner()?;
    Ok((stem, writer))
}

fn append_file<W: Write>(
    builder: &mut tar::Builder<W>,
    src_path: &Path,
    archive_path: &Path,
) -> Result<(), CryptoError> {
    let mut file = open_no_follow(src_path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(CryptoError::InvalidInput(format!(
            "Path is no longer a regular file: {}",
            src_path.display()
        )));
    }
    let mut header = tar::Header::new_gnu();
    header.set_size(metadata.len());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        header.set_mode(metadata.permissions().mode() & PERMISSION_BITS_MASK);
    }
    #[cfg(not(unix))]
    header.set_mode(DEFAULT_FILE_MODE);
    header.set_cksum();
    builder.append_data(&mut header, archive_path, &mut file)?;
    Ok(())
}

fn append_dir_entry<W: Write>(
    builder: &mut tar::Builder<W>,
    src_path: &Path,
    archive_path: &Path,
) -> Result<(), CryptoError> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(src_path)?;
        header.set_mode(metadata.permissions().mode() & PERMISSION_BITS_MASK);
    }
    #[cfg(not(unix))]
    {
        let _ = src_path;
        header.set_mode(0o755);
    }
    header.set_cksum();
    builder.append_data(&mut header, archive_path, &mut io::empty())?;
    Ok(())
}

/// Opens a file refusing to follow symlinks.
/// On Unix, uses `O_NOFOLLOW` so the open itself is atomic.
/// On other platforms, falls back to a symlink_metadata check before opening.
#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File, CryptoError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                CryptoError::InvalidInput(format!("Path is a symlink: {}", path.display()))
            } else {
                CryptoError::Io(e)
            }
        })
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<File, CryptoError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(CryptoError::InvalidInput(format!(
            "Path is not a regular file: {}",
            path.display()
        )));
    }
    Ok(File::open(path)?)
}

/// Recursively archives a directory. Uses `entry.file_type()` (lstat-based)
/// to classify entries without following symlinks.
fn archive_directory<W: Write>(
    builder: &mut tar::Builder<W>,
    dir_path: &Path,
    archive_prefix: &Path,
) -> Result<(), CryptoError> {
    append_dir_entry(builder, dir_path, archive_prefix)?;

    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let src_path = entry.path();
        let ft = entry.file_type()?;
        let entry_archive_path = archive_prefix.join(entry.file_name());

        if ft.is_symlink() {
            return Err(CryptoError::InvalidInput(format!(
                "Directory contains a symlink: {}",
                src_path.display()
            )));
        } else if ft.is_dir() {
            archive_directory(builder, &src_path, &entry_archive_path)?;
        } else if ft.is_file() {
            append_file(builder, &src_path, &entry_archive_path)?;
        } else {
            return Err(CryptoError::InvalidInput(format!(
                "Unsupported file type in directory: {}",
                src_path.display()
            )));
        }
    }
    Ok(())
}

/// Extracts a TAR archive from `reader` into the specified directory.
///
/// All output is written under an `.incomplete` working name so that
/// plaintext never appears under the final name during streaming
/// decryption. On success, the working name is atomically renamed to the
/// final name. On failure, the `.incomplete` output stays on disk for
/// the user to inspect or delete.
pub fn unarchive<R: Read>(reader: R, output_dir: &Path) -> Result<PathBuf, CryptoError> {
    let mut archive = tar::Archive::new(reader);
    let mut first_entry_root: Option<PathBuf> = None;
    let mut checked_roots: Vec<OsString> = Vec::new();

    let extract_result = extract_entries(
        &mut archive,
        output_dir,
        &mut first_entry_root,
        &mut checked_roots,
    );

    extract_result?;

    // Rename each root from .incomplete working name to final name.
    // A failure here is an environment / I/O condition — not a library
    // invariant violation. `AlreadyExists` means the final name appeared
    // after the extraction-time pre-check (race or attacker) and is
    // mapped to the same user-facing message as the pre-check; everything
    // else surfaces as a generic I/O error.
    for root_name in &checked_roots {
        let mut incomplete_name = root_name.clone();
        incomplete_name.push(".incomplete");
        let working_path = output_dir.join(&incomplete_name);
        let final_path = output_dir.join(root_name);
        if let Err(e) = crate::atomic_output::rename_no_clobber(&working_path, &final_path) {
            return Err(if e.kind() == io::ErrorKind::AlreadyExists {
                CryptoError::InvalidInput(format!(
                    "Output already exists: {}",
                    final_path.display()
                ))
            } else {
                CryptoError::Io(e)
            });
        }
    }

    first_entry_root.ok_or_else(|| CryptoError::InvalidInput("Empty archive".to_string()))
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
) -> Result<(), CryptoError> {
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::os::fd::{AsFd, OwnedFd};

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

    let output_fd = nofollow::open_anchor(output_dir)?;
    let mut roots: HashMap<OsString, RootKind> = HashMap::new();
    // Deferred directory permissions: (root name, rel path under root, mode).
    // `rel` is empty for the root directory itself.
    let mut dir_permissions: Vec<(OsString, PathBuf, u32)> = Vec::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let path = entry.path()?.to_path_buf();
        validate_archive_path(&path)?;

        let first_component = path
            .components()
            .next()
            .ok_or_else(|| CryptoError::InvalidInput("Empty archive entry".to_string()))?;
        let root_name = first_component.as_os_str().to_os_string();

        if !checked_roots.contains(&root_name) {
            // Ferrocrypt's archiver only produces single-root payloads
            // (one top-level file or one top-level directory — see
            // FORMAT.md §6.4). Reject any crafted archive that tries to
            // smuggle a second top-level root so `unarchive`'s single
            // `PathBuf` return value always accounts for every output it
            // creates.
            if !checked_roots.is_empty() {
                return Err(CryptoError::InvalidInput(format!(
                    "Archive has multiple top-level roots: {}",
                    path.display()
                )));
            }
            let final_path = output_dir.join(&root_name);
            // `symlink_metadata` does not follow the final symlink, so a
            // dangling symlink at `final_path` is caught here instead of
            // later at rename time.
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
            if first_entry_root.is_none() {
                *first_entry_root = Some(final_path);
            }
            checked_roots.push(root_name.clone());
        }

        let rel = match path.strip_prefix(&root_name) {
            Ok(r) => r.to_path_buf(),
            Err(_) => {
                return Err(CryptoError::InternalInvariant(
                    "internal error: entry path missing root component",
                ));
            }
        };

        let entry_type = entry.header().entry_type();
        let mut incomplete_name = root_name.clone();
        incomplete_name.push(".incomplete");

        // Case A: entry IS the root (single-file archive or a root-level
        // directory entry).
        if rel.as_os_str().is_empty() {
            if entry_type.is_dir() {
                match roots.get(&root_name) {
                    Some(RootKind::SingleFile) => {
                        return Err(CryptoError::InvalidInput(format!(
                            "Archive mixes file and directory at root: {}",
                            path.display()
                        )));
                    }
                    Some(RootKind::Directory(_)) => {}
                    None => {
                        let fd = nofollow::mkdirat_strict(&output_fd, &incomplete_name).map_err(
                            |e| map_incomplete_create_err(e, output_dir, &incomplete_name),
                        )?;
                        roots.insert(root_name.clone(), RootKind::Directory(fd));
                    }
                }
                if let Ok(mode) = entry.header().mode() {
                    dir_permissions.push((root_name.clone(), PathBuf::new(), mode));
                }
            } else if entry_type.is_file() {
                if roots.contains_key(&root_name) {
                    return Err(CryptoError::InvalidInput(format!(
                        "Archive has mixed or duplicate root entries: {}",
                        path.display()
                    )));
                }
                let mut outfile = nofollow::create_file_at(&output_fd, &incomplete_name, 0o600)
                    .map_err(|e| map_incomplete_create_err(e, output_dir, &incomplete_name))?;
                io::copy(&mut entry, &mut outfile)?;
                if let Ok(mode) = entry.header().mode() {
                    nofollow::fchmod(outfile.as_fd(), mode & PERMISSION_BITS_MASK)?;
                }
                drop(outfile);
                roots.insert(root_name.clone(), RootKind::SingleFile);
            } else {
                return Err(CryptoError::InvalidInput(format!(
                    "Unsupported archive entry type {:?} for path: {}",
                    entry_type,
                    path.display()
                )));
            }
            continue;
        }

        // Case B: entry is a descendant of the root. The root must be a
        // directory; lazily create `{root}.incomplete` as one if no
        // explicit root-level directory entry has been seen yet.
        match roots.get(&root_name) {
            Some(RootKind::SingleFile) => {
                return Err(CryptoError::InvalidInput(format!(
                    "Archive mixes file and directory at root: {}",
                    path.display()
                )));
            }
            Some(RootKind::Directory(_)) => {}
            None => {
                let fd = nofollow::mkdirat_strict(&output_fd, &incomplete_name)
                    .map_err(|e| map_incomplete_create_err(e, output_dir, &incomplete_name))?;
                roots.insert(root_name.clone(), RootKind::Directory(fd));
            }
        }
        let root_fd = match roots.get(&root_name) {
            Some(RootKind::Directory(fd)) => fd,
            _ => {
                return Err(CryptoError::InternalInvariant(
                    "internal error: root dirfd disappeared after insertion",
                ));
            }
        };

        if entry_type.is_dir() {
            let (parent_fd, final_name) = nofollow::walk_to_parent(root_fd, &rel)?;
            let _dir_fd = nofollow::ensure_dir(&parent_fd, &final_name)?;
            if let Ok(mode) = entry.header().mode() {
                dir_permissions.push((root_name.clone(), rel, mode));
            }
        } else if entry_type.is_file() {
            let (parent_fd, final_name) = nofollow::walk_to_parent(root_fd, &rel)?;
            // Initial mode is restrictive; the archived mode is applied
            // via `fchmod` after writing, so plaintext is never briefly
            // visible to unintended users.
            let mut outfile = nofollow::create_file_at(&parent_fd, &final_name, 0o600)?;
            io::copy(&mut entry, &mut outfile)?;
            if let Ok(mode) = entry.header().mode() {
                nofollow::fchmod(outfile.as_fd(), mode & PERMISSION_BITS_MASK)?;
            }
            drop(outfile);
        } else {
            return Err(CryptoError::InvalidInput(format!(
                "Unsupported archive entry type {:?} for path: {}",
                entry_type,
                path.display()
            )));
        }
    }

    // Apply deferred directory permissions. Each chmod happens on a fresh
    // NOFOLLOW-opened fd, so a restrictive parent mode does not block the
    // operation and order does not matter.
    for (root_name, rel, mode) in &dir_permissions {
        let root_fd = match roots.get(root_name) {
            Some(RootKind::Directory(fd)) => fd,
            _ => {
                return Err(CryptoError::InternalInvariant(
                    "internal error: root dirfd missing at dir-perm stage",
                ));
            }
        };
        let dir_fd = if rel.as_os_str().is_empty() {
            root_fd
                .as_fd()
                .try_clone_to_owned()
                .map_err(CryptoError::Io)?
        } else {
            nofollow::open_dir_at_rel(root_fd, rel)?
        };
        let safe_mode = mode & PERMISSION_BITS_MASK;
        nofollow::fchmod(&dir_fd, safe_mode)?;
    }

    Ok(())
}

/// Path-based extraction for platforms where rustix is not pulled in
/// (currently Windows and non-Linux/non-macOS Unix targets). Keeps the
/// pre-hardening behavior: `create_dir_all` + `OpenOptions::create_new` +
/// `fs::set_permissions`. Symlink races on these platforms are discussed
/// in the module comment on `nofollow`.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn extract_entries<R: Read>(
    archive: &mut tar::Archive<R>,
    output_dir: &Path,
    first_entry_root: &mut Option<PathBuf>,
    checked_roots: &mut Vec<OsString>,
) -> Result<(), CryptoError> {
    // Directory permissions are applied after all entries are extracted,
    // deepest first, so that a restrictive parent mode (e.g. 0o500) does
    // not block creation of child entries.
    let mut dir_permissions: Vec<(PathBuf, u32)> = Vec::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let path = entry.path()?.to_path_buf();
        validate_archive_path(&path)?;

        let first_component = path
            .components()
            .next()
            .ok_or_else(|| CryptoError::InvalidInput("Empty archive entry".to_string()))?;
        let root_name = first_component.as_os_str().to_os_string();

        if !checked_roots.contains(&root_name) {
            // See the Linux/macOS arm for the rationale. Ferrocrypt's
            // own archiver only emits single-root payloads, and a
            // second top-level root is rejected to keep `unarchive`'s
            // single `PathBuf` return aligned with what extraction
            // actually creates.
            if !checked_roots.is_empty() {
                return Err(CryptoError::InvalidInput(format!(
                    "Archive has multiple top-level roots: {}",
                    path.display()
                )));
            }
            let final_path = output_dir.join(&root_name);
            // `symlink_metadata` does not follow the final symlink, so a
            // dangling symlink at `final_path` is caught here instead of
            // later at rename time.
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
            let mut incomplete_name = root_name.clone();
            incomplete_name.push(".incomplete");
            let incomplete_path = output_dir.join(&incomplete_name);
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
            if first_entry_root.is_none() {
                *first_entry_root = Some(final_path);
            }
            checked_roots.push(root_name.clone());
        }

        // Rewrite the entry path: replace the root component with {root}.incomplete
        let working_path = incomplete_entry_path(output_dir, &root_name, &path);
        let entry_type = entry.header().entry_type();

        if entry_type.is_dir() {
            fs::create_dir_all(&working_path)?;
            if let Ok(mode) = entry.header().mode() {
                dir_permissions.push((working_path, mode));
            }
        } else if entry_type.is_file() {
            if let Some(parent) = working_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }
            // `create_new(true)` refuses to open a pre-existing file so a
            // malicious archive containing duplicate entries at the same
            // path cannot silently overwrite the first entry.
            let mut outfile = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&working_path)?;
            io::copy(&mut entry, &mut outfile)?;
            drop(outfile);
            restore_permissions(entry.header(), &working_path)?;
        } else {
            return Err(CryptoError::InvalidInput(format!(
                "Unsupported archive entry type {:?} for path: {}",
                entry_type,
                path.display()
            )));
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
    let mut incomplete_root = root_name.to_os_string();
    incomplete_root.push(".incomplete");
    match entry_path.strip_prefix(root_name) {
        Ok(rest) if rest.as_os_str().is_empty() => output_dir.join(&incomplete_root),
        Ok(rest) => output_dir.join(&incomplete_root).join(rest),
        Err(_) => output_dir.join(&incomplete_root),
    }
}

/// Restores file permissions from the TAR header on the path-based
/// extraction path. The Linux/macOS hardened path uses `fchmod` on the
/// still-open fd instead and does not call this helper.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn restore_permissions(header: &tar::Header, path: &Path) -> Result<(), CryptoError> {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(mode) = header.mode() {
        let safe_mode = mode & PERMISSION_BITS_MASK;
        fs::set_permissions(path, std::fs::Permissions::from_mode(safe_mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn restore_permissions(_header: &tar::Header, _path: &Path) -> Result<(), CryptoError> {
    Ok(())
}

/// Applies a stored mode to a path on the path-based extraction path.
/// The Linux/macOS hardened path uses `fchmod` on an open dirfd instead.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn restore_permissions_from_mode(mode: u32, path: &Path) -> Result<(), CryptoError> {
    use std::os::unix::fs::PermissionsExt;
    let safe_mode = mode & PERMISSION_BITS_MASK;
    fs::set_permissions(path, std::fs::Permissions::from_mode(safe_mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn restore_permissions_from_mode(_mode: u32, _path: &Path) -> Result<(), CryptoError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;

    use crate::archiver::{archive, unarchive};

    #[test]
    fn archive_and_unarchive_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("hello.txt");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(&input_file, "file content here").unwrap();

        let mut buf = Vec::new();
        let (stem, _) = archive(&input_file, &mut buf).unwrap();
        assert_eq!(stem, "hello");

        let output = unarchive(Cursor::new(buf), &extract_dir).unwrap();
        assert!(output.exists());

        let restored = fs::read_to_string(extract_dir.join("hello.txt")).unwrap();
        assert_eq!(restored, "file content here");
    }

    #[test]
    fn archive_and_unarchive_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_dir = tmp.path().join("mydir");
        let sub_dir = input_dir.join("sub");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&sub_dir).unwrap();
        fs::create_dir_all(&extract_dir).unwrap();

        fs::write(input_dir.join("a.txt"), "file a").unwrap();
        fs::write(sub_dir.join("b.txt"), "file b").unwrap();

        let mut buf = Vec::new();
        let (stem, _) = archive(&input_dir, &mut buf).unwrap();
        assert_eq!(stem, "mydir");

        let output = unarchive(Cursor::new(buf), &extract_dir).unwrap();
        assert!(output.exists());

        let restored_a = fs::read_to_string(extract_dir.join("mydir/a.txt")).unwrap();
        assert_eq!(restored_a, "file a");
        let restored_b = fs::read_to_string(extract_dir.join("mydir/sub/b.txt")).unwrap();
        assert_eq!(restored_b, "file b");
    }

    #[cfg(unix)]
    #[test]
    fn archive_rejects_directory_with_symlink() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_dir = tmp.path().join("mydir");
        fs::create_dir_all(&input_dir).unwrap();
        fs::write(input_dir.join("real.txt"), "content").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", input_dir.join("link.txt")).unwrap();

        let mut buf = Vec::new();
        let err = archive(&input_dir, &mut buf).unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "expected symlink error, got: {err}"
        );
    }

    #[test]
    fn archive_empty_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("empty.txt");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(&input_file, "").unwrap();

        let mut buf = Vec::new();
        let (stem, _) = archive(&input_file, &mut buf).unwrap();
        assert_eq!(stem, "empty");

        unarchive(Cursor::new(buf), &extract_dir).unwrap();
        let restored = fs::read_to_string(extract_dir.join("empty.txt")).unwrap();
        assert_eq!(restored, "");
    }

    #[test]
    fn validate_rejects_path_traversal() {
        use crate::archiver::validate_archive_path;
        use std::path::Path;

        assert!(validate_archive_path(Path::new("safe.txt")).is_ok());
        assert!(validate_archive_path(Path::new("dir/file.txt")).is_ok());
        assert!(validate_archive_path(Path::new("../escape.txt")).is_err());
        assert!(validate_archive_path(Path::new("dir/../../escape.txt")).is_err());
        assert!(validate_archive_path(Path::new("/etc/passwd")).is_err());
        // Leading `./` turns root_name into `.` and breaks the final
        // rename, so reject it early. Ferrocrypt's own archiver never
        // produces such paths.
        assert!(validate_archive_path(Path::new("./foo/bar")).is_err());
        assert!(validate_archive_path(Path::new(".")).is_err());
    }

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
            let mut header = tar::Header::new_gnu();
            header.set_size(data_a.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "first.txt", &data_a[..])
                .unwrap();

            let data_b = b"payload b";
            let mut header = tar::Header::new_gnu();
            header.set_size(data_b.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "second.txt", &data_b[..])
                .unwrap();

            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
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

            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "innocent/", &[] as &[u8])
                .unwrap();

            let data = b"malicious payload";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "victim.txt", &data[..])
                .unwrap();

            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
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

            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_link(&mut header, "link.txt", "target.txt")
                .unwrap();

            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
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

            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "mydir/", &[] as &[u8])
                .unwrap();

            let first = b"first payload";
            let mut header = tar::Header::new_gnu();
            header.set_size(first.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "mydir/dup.txt", &first[..])
                .unwrap();

            let second = b"attacker payload";
            let mut header = tar::Header::new_gnu();
            header.set_size(second.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "mydir/dup.txt", &second[..])
                .unwrap();

            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
        // The second entry's create_new fails with AlreadyExists, which
        // propagates as CryptoError::Io.
        let msg = err.to_string();
        assert!(
            msg.contains("exists") || msg.contains("File exists"),
            "expected already-exists error, got: {msg}"
        );
    }

    #[test]
    fn archive_binary_content() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("data.bin");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let binary_data: Vec<u8> = (0..=255).collect();
        fs::write(&input_file, &binary_data).unwrap();

        let mut buf = Vec::new();
        let (_, _) = archive(&input_file, &mut buf).unwrap();

        unarchive(Cursor::new(buf), &extract_dir).unwrap();

        let restored = fs::read(extract_dir.join("data.bin")).unwrap();
        assert_eq!(restored, binary_data);
    }

    #[cfg(unix)]
    #[test]
    fn archive_preserves_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("script.sh");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(&input_file, "#!/bin/sh\necho hi").unwrap();
        fs::set_permissions(&input_file, fs::Permissions::from_mode(0o755)).unwrap();

        let mut buf = Vec::new();
        let (_, _) = archive(&input_file, &mut buf).unwrap();

        unarchive(Cursor::new(buf), &extract_dir).unwrap();

        let restored = extract_dir.join("script.sh");
        let mode = fs::metadata(&restored).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "expected 0o755, got 0o{mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn archive_preserves_directory_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let input_dir = tmp.path().join("mydir");
        let sub_dir = input_dir.join("restricted");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&sub_dir).unwrap();
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(sub_dir.join("secret.txt"), "data").unwrap();
        fs::set_permissions(&sub_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let mut buf = Vec::new();
        let (_, _) = archive(&input_dir, &mut buf).unwrap();

        unarchive(Cursor::new(buf), &extract_dir).unwrap();

        let restored_sub = extract_dir.join("mydir/restricted");
        let mode = fs::metadata(&restored_sub).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected 0o700, got 0o{mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn archive_restrictive_dir_does_not_block_children() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let input_dir = tmp.path().join("mydir");
        let sub_dir = input_dir.join("readonly");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&sub_dir).unwrap();
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(sub_dir.join("inner.txt"), "hello").unwrap();
        // r-x------ : no write permission
        fs::set_permissions(&sub_dir, fs::Permissions::from_mode(0o500)).unwrap();

        let mut buf = Vec::new();
        let (_, _) = archive(&input_dir, &mut buf).unwrap();

        // Must not fail with "Permission denied" when extracting inner.txt
        unarchive(Cursor::new(buf), &extract_dir).unwrap();

        let restored_file = extract_dir.join("mydir/readonly/inner.txt");
        assert_eq!(fs::read_to_string(&restored_file).unwrap(), "hello");

        let dir_mode = fs::metadata(extract_dir.join("mydir/readonly"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o500, "expected 0o500, got 0o{dir_mode:o}");
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
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(input_mode);
                header.set_cksum();
                builder
                    .append_data(&mut header, "file.sh", &data[..])
                    .unwrap();
                builder.finish().unwrap();
            }

            unarchive(Cursor::new(buf), &extract_dir).unwrap();

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

            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o4755); // setuid on directory
            header.set_cksum();
            builder
                .append_data(&mut header, "stickydir/", &[] as &[u8])
                .unwrap();

            let data = b"child";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "stickydir/child.txt", &data[..])
                .unwrap();

            builder.finish().unwrap();
        }

        unarchive(Cursor::new(buf), &extract_dir).unwrap();

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
    fn archive_strips_special_bits_on_archive_side() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("script.sh");
        fs::write(&input_file, "#!/bin/sh").unwrap();
        fs::set_permissions(&input_file, fs::Permissions::from_mode(0o4755)).unwrap();

        let mut buf = Vec::new();
        let (_, _) = archive(&input_file, &mut buf).unwrap();

        // Read the mode stored in the tar header directly.
        let mut tar_archive = tar::Archive::new(Cursor::new(buf));
        let entry = tar_archive.entries().unwrap().next().unwrap().unwrap();
        let stored_mode = entry.header().mode().unwrap();
        assert_eq!(
            stored_mode & 0o7000,
            0,
            "special bits should not be stored in archive: mode 0o{stored_mode:o}"
        );
        assert_eq!(
            stored_mode & 0o777,
            0o755,
            "rwx bits should be preserved: mode 0o{stored_mode:o}"
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
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "mydir/", &[] as &[u8])
                .unwrap();

            let data = b"plaintext payload";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "mydir/child.txt", &data[..])
                .unwrap();
            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
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
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "mydir/", &[] as &[u8])
                .unwrap();
            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
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
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, ".", &[] as &[u8]).unwrap();
            builder.finish().unwrap();
        }

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
        assert!(
            err.to_string().contains("Unsafe path"),
            "expected unsafe-path error, got: {err}"
        );

        assert!(
            extract_dir.read_dir().unwrap().next().is_none(),
            "extract dir must remain empty after refused archive"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    mod nofollow_tests {
        use std::ffi::OsStr;
        use std::fs;
        use std::io;
        use std::os::unix::fs as unix_fs;
        use std::path::Path;

        use crate::archiver::nofollow;

        #[test]
        fn ensure_dir_rejects_symlink_at_name() {
            let tmp = tempfile::TempDir::new().unwrap();
            unix_fs::symlink("/tmp", tmp.path().join("evil")).unwrap();

            let parent_fd = nofollow::open_anchor(tmp.path()).unwrap();
            let err = nofollow::ensure_dir(&parent_fd, OsStr::new("evil")).unwrap_err();
            assert!(
                err.to_string().contains("Symlink in extraction path"),
                "expected symlink error, got: {err}"
            );
        }

        #[test]
        fn walk_to_parent_rejects_intermediate_symlink() {
            let tmp = tempfile::TempDir::new().unwrap();
            let root = tmp.path().join("root");
            let a = root.join("a");
            fs::create_dir_all(&a).unwrap();
            let victim = tmp.path().join("victim_dir");
            fs::create_dir_all(&victim).unwrap();
            unix_fs::symlink(&victim, a.join("b")).unwrap();

            let root_fd = nofollow::open_anchor(&root).unwrap();
            let err = nofollow::walk_to_parent(&root_fd, Path::new("a/b/file.txt")).unwrap_err();
            assert!(
                err.to_string().contains("Symlink in extraction path"),
                "expected symlink error, got: {err}"
            );

            assert!(
                victim.read_dir().unwrap().next().is_none(),
                "victim directory must remain empty"
            );
        }

        #[test]
        fn create_file_at_rejects_existing_symlink() {
            let tmp = tempfile::TempDir::new().unwrap();
            let victim = tmp.path().join("victim.txt");
            fs::write(&victim, "original").unwrap();
            unix_fs::symlink(&victim, tmp.path().join("link.txt")).unwrap();

            let parent_fd = nofollow::open_anchor(tmp.path()).unwrap();
            let err =
                nofollow::create_file_at(&parent_fd, OsStr::new("link.txt"), 0o600).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

            assert_eq!(
                fs::read_to_string(&victim).unwrap(),
                "original",
                "victim file must not be touched through the symlink"
            );
        }
    }
}
