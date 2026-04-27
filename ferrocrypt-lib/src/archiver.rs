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

/// Raw POSIX ustar header constants (`FORMAT.md` §9). Used by both the
/// writer (canonical emission) and the reader (per-entry strict
/// subset validation).
mod ustar {
    pub(super) const TYPEFLAG_OFFSET: usize = 156;
    pub(super) const MAGIC_OFFSET: usize = 257;
    pub(super) const MAGIC: &[u8; 6] = b"ustar\0";
    pub(super) const VERSION_OFFSET: usize = 263;
    pub(super) const VERSION: &[u8; 2] = b"00";

    pub(super) const NAME_SIZE: usize = 100;
    pub(super) const PREFIX_SIZE: usize = 155;
    /// Maximum path length representable purely via the ustar
    /// `name` + `/` + `prefix` fields; anything longer requires a GNU
    /// long-name or PAX extension record, which v1 forbids.
    pub(super) const PATH_REPRESENTABLE_MAX: usize = NAME_SIZE + 1 + PREFIX_SIZE;

    pub(super) const TYPEFLAG_REGULAR_NUL: u8 = b'\0';
    pub(super) const TYPEFLAG_REGULAR_ZERO: u8 = b'0';
    pub(super) const TYPEFLAG_DIRECTORY: u8 = b'5';
}

/// `FORMAT.md` §9 archive subset classification for a successfully
/// validated entry: ferrocrypt v1 recognises only regular files and
/// directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UstarEntryKind {
    File,
    Directory,
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
                "Created directory is no longer a directory (race detected)",
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
        // Caller guarantees `rel` is non-empty (the upstream
        // `rel.as_os_str().is_empty()` branch handles the root-
        // level case) and `validate_archive_path` has reduced it to
        // Normal components only, so `pop()` never returns None here.
        let last = components.pop().ok_or(CryptoError::InternalInvariant(
            "Internal error: archive entry resolved to empty path",
        ))?;
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

/// Translates a relative `archive_path` (any platform) into the
/// canonical UTF-8 `/`-separated form required by the v1 archive
/// subset and rejects inputs that cannot be represented in raw POSIX
/// ustar (`name(100) || prefix(155)`). Directory paths get a single
/// trailing `/`; file paths must not end with one.
///
/// `Builder::append_data` would silently fall back to a GNU long-name
/// extension record for paths above the ustar limit; v1 forbids those,
/// so the rejection has to happen here, before any header bytes are
/// emitted.
fn ustar_archive_path_string(
    archive_path: &Path,
    kind: UstarEntryKind,
) -> Result<String, CryptoError> {
    let mut joined = String::new();
    let mut iter = archive_path.components().peekable();
    while let Some(component) = iter.next() {
        let part = match component {
            Component::Normal(s) => s.to_str().ok_or_else(|| {
                CryptoError::InvalidInput(format!(
                    "Archive path is not valid UTF-8: {}",
                    archive_path.display()
                ))
            })?,
            _ => {
                return Err(CryptoError::InvalidInput(format!(
                    "Archive path has forbidden component: {}",
                    archive_path.display()
                )));
            }
        };
        // Symmetric with the reader's `validate_ustar_entry` raw-byte
        // checks: a Unix filename containing `\` or NUL is technically
        // legal at the kernel level but produces an archive that v1
        // readers MUST reject (`FORMAT.md` §9). Rejecting here keeps
        // the writer round-trip-safe rather than emitting bytes our
        // own reader will refuse to decrypt.
        if part.contains('\\') || part.contains('\0') {
            return Err(CryptoError::InvalidInput(format!(
                "Archive path component contains forbidden byte (`\\` or NUL): {}",
                archive_path.display()
            )));
        }
        joined.push_str(part);
        if iter.peek().is_some() {
            joined.push('/');
        }
    }
    if joined.is_empty() {
        return Err(CryptoError::InvalidInput(
            "Empty archive entry path".to_string(),
        ));
    }
    if matches!(kind, UstarEntryKind::Directory) {
        joined.push('/');
    }
    if joined.len() > ustar::PATH_REPRESENTABLE_MAX {
        return Err(CryptoError::InvalidInput(format!(
            "Archive path cannot be represented in POSIX ustar: {}",
            archive_path.display()
        )));
    }
    Ok(joined)
}

/// Builds a v1-conforming ustar header for one archive entry. Pulled
/// out so `append_file` and `append_dir_entry` share the
/// path-normalization → `new_ustar` → `set_path` → `set_entry_type` →
/// `set_mode` → `set_cksum` sequence and the same error-message
/// translation for paths that don't fit the ustar `name + prefix`
/// split. `Header::set_path` would otherwise let `Builder::append_data`
/// silently fall back to a GNU long-name extension; we use
/// `Builder::append` at the call sites so this header is written
/// verbatim, with no auto-extension path.
fn build_ustar_header(
    archive_path: &Path,
    kind: UstarEntryKind,
    size: u64,
    mode: u32,
) -> Result<tar::Header, CryptoError> {
    let path_str = ustar_archive_path_string(archive_path, kind)?;
    let mut header = tar::Header::new_ustar();
    header.set_path(&path_str).map_err(|_| {
        CryptoError::InvalidInput(format!(
            "Archive path cannot be represented in POSIX ustar: {}",
            archive_path.display()
        ))
    })?;
    header.set_entry_type(match kind {
        UstarEntryKind::File => tar::EntryType::Regular,
        UstarEntryKind::Directory => tar::EntryType::Directory,
    });
    header.set_size(size);
    header.set_mode(mode);
    header.set_cksum();
    Ok(header)
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
            "Input is no longer a regular file: {}",
            src_path.display()
        )));
    }

    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & PERMISSION_BITS_MASK
    };
    #[cfg(not(unix))]
    let mode = DEFAULT_FILE_MODE;

    let header = build_ustar_header(archive_path, UstarEntryKind::File, metadata.len(), mode)?;
    builder.append(&header, &mut file)?;
    Ok(())
}

fn append_dir_entry<W: Write>(
    builder: &mut tar::Builder<W>,
    src_path: &Path,
    archive_path: &Path,
) -> Result<(), CryptoError> {
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(src_path)?;
        metadata.permissions().mode() & PERMISSION_BITS_MASK
    };
    #[cfg(not(unix))]
    let mode = {
        let _ = src_path;
        0o755
    };

    let header = build_ustar_header(archive_path, UstarEntryKind::Directory, 0, mode)?;
    builder.append(&header, io::empty())?;
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
                CryptoError::InvalidInput(format!("Input is a symlink: {}", path.display()))
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
            "Input is no longer a regular file: {}",
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
    // Canonical-path duplicate detection (`FORMAT.md` §9): a file `foo`
    // and a directory `foo/` share the same canonical path after the one
    // trailing slash is stripped, so they count as duplicates.
    let mut seen_paths: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let normalized = validate_ustar_entry(&mut entry)?;
        let path = normalized.canonical_path;
        let kind = normalized.kind;

        if !seen_paths.insert(path.clone()) {
            return Err(CryptoError::InvalidInput(format!(
                "Duplicate archive entry: {}",
                path.display()
            )));
        }

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
                    "Internal error: entry path missing root component",
                ));
            }
        };

        let mut incomplete_name = root_name.clone();
        incomplete_name.push(".incomplete");

        // Case A: entry IS the root (single-file archive or a root-level
        // directory entry).
        if rel.as_os_str().is_empty() {
            match kind {
                UstarEntryKind::Directory => {
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
                                .map_err(|e| {
                                    map_incomplete_create_err(e, output_dir, &incomplete_name)
                                })?;
                            roots.insert(root_name.clone(), RootKind::Directory(fd));
                        }
                    }
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
                    let mut outfile = nofollow::create_file_at(&output_fd, &incomplete_name, 0o600)
                        .map_err(|e| map_incomplete_create_err(e, output_dir, &incomplete_name))?;
                    io::copy(&mut entry, &mut outfile)?;
                    if let Ok(mode) = entry.header().mode() {
                        nofollow::fchmod(outfile.as_fd(), mode & PERMISSION_BITS_MASK)?;
                    }
                    drop(outfile);
                    roots.insert(root_name.clone(), RootKind::SingleFile);
                }
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
                    "Internal error: root dirfd disappeared after insertion",
                ));
            }
        };

        match kind {
            UstarEntryKind::Directory => {
                let (parent_fd, final_name) = nofollow::walk_to_parent(root_fd, &rel)?;
                let _dir_fd = nofollow::ensure_dir(&parent_fd, &final_name)?;
                if let Ok(mode) = entry.header().mode() {
                    dir_permissions.push((root_name.clone(), rel, mode));
                }
            }
            UstarEntryKind::File => {
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
            }
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
                    "Internal error: root dirfd missing at dir-perm stage",
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
    // Canonical-path duplicate detection (`FORMAT.md` §9). Equivalent to
    // the `seen_paths` set on the Linux/macOS arm.
    let mut seen_paths: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let normalized = validate_ustar_entry(&mut entry)?;
        let path = normalized.canonical_path;
        let kind = normalized.kind;

        if !seen_paths.insert(path.clone()) {
            return Err(CryptoError::InvalidInput(format!(
                "Duplicate archive entry: {}",
                path.display()
            )));
        }

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
                restore_permissions(entry.header(), &working_path)?;
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
    use std::path::PathBuf;

    use crate::archiver::{UstarEntryKind, archive, unarchive, ustar, ustar_archive_path_string};

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

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
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
                let mut header = tar::Header::new_ustar();
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
        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
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

    /// `FORMAT.md` §9 requires every emitted header to use the POSIX
    /// ustar magic (`"ustar\0" + "00"` at offsets 257..265) and forbids
    /// GNU magic. Pin the writer's per-entry magic + version bytes so a
    /// future regression that switches back to `new_gnu()` (or to a
    /// helper that auto-promotes overlong paths to a long-name
    /// extension) fails this test loudly.
    #[test]
    fn archive_emits_posix_ustar_headers() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input = tmp.path().join("hello.txt");
        fs::write(&input, "hello").unwrap();

        let mut buf = Vec::new();
        let (_, _) = archive(&input, &mut buf).unwrap();

        let mut ar = tar::Archive::new(Cursor::new(buf));
        let mut entries = ar.entries().unwrap();
        let entry = entries.next().expect("one entry").unwrap();
        let raw = entry.header().as_bytes();

        assert_eq!(&raw[257..263], b"ustar\0", "expected POSIX ustar magic");
        assert_eq!(&raw[263..265], b"00", "expected ustar version 00");
        assert_eq!(raw[156], b'0', "expected typeflag '0' for regular file");
    }

    /// `FORMAT.md` §9 forbids GNU long-name records and the writer
    /// must reject overlong paths up-front rather than silently
    /// promoting them to an extension. The exact ustar limit is
    /// `name(100) + '/' + prefix(155)`; any path over that surfaces
    /// as a typed `InvalidInput` rejection.
    ///
    /// We drive the writer-side ustar path normalizer directly rather
    /// than going through `archive()` because some host filesystems
    /// (notably macOS APFS) reject single components ≥255 chars
    /// before our code sees them; the helper is the canonical
    /// rejection point used by both `append_file` and
    /// `append_dir_entry`.
    #[test]
    fn archive_rejects_path_that_cannot_fit_ustar() {
        let too_long: String = "a".repeat(ustar::PATH_REPRESENTABLE_MAX + 4);
        let path = PathBuf::from(too_long);
        let err = ustar_archive_path_string(&path, UstarEntryKind::File).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("POSIX ustar"),
            "expected POSIX ustar rejection, got: {msg}"
        );
    }

    /// Writer-side symmetry with the reader's `\` / NUL rejection
    /// (`FORMAT.md` §9). Unix kernels permit `\` in filenames, so a
    /// naive walker could emit an archive whose paths the reader
    /// would refuse to decrypt. Gated to `#[cfg(unix)]` because on
    /// Windows the `Path` API treats `\` as a separator, so a single
    /// `Normal` component can never contain a literal `\` byte and
    /// the bug doesn't apply.
    #[cfg(unix)]
    #[test]
    fn archive_rejects_backslash_in_path_component() {
        let weird = PathBuf::from("weird\\file.txt");
        let err = ustar_archive_path_string(&weird, UstarEntryKind::File).unwrap_err();
        assert!(
            err.to_string().contains("forbidden byte"),
            "expected backslash rejection, got: {err}"
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

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
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

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
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

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
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

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
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

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
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

        let err = unarchive(Cursor::new(buf), &extract_dir).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("GNU long-name") || msg.contains("not POSIX ustar"),
            "expected GNU-extension or non-ustar rejection, got: {msg}"
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
