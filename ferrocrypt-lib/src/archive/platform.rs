//! Component-by-component no-follow extraction primitives.
//!
//! The hardened extraction walker anchors every operation to a directory
//! file descriptor rooted in the user's trusted `output_dir`. Every
//! intermediate component is resolved via `openat`/`mkdirat` with
//! `O_NOFOLLOW`, so a concurrent local attacker who can write inside the
//! destination tree cannot race a directory into a symlink and redirect
//! the write elsewhere. The final regular file is created with
//! `O_CREAT | O_EXCL | O_NOFOLLOW` so a pre-placed symlink fails closed
//! with `AlreadyExists`.
//!
//! **Platform coverage.** This hardening only applies on Linux and
//! macOS. The fallback path-based extractor used on Windows and other
//! non-Linux/non-macOS Unix targets walks plain `&Path` and HAS a
//! symlink-race window — see the docstring on the `not(linux/macos)`
//! arm of [`extract_entries`] (and on `open_no_follow` in the encode
//! module) for the threat model and the operator-level mitigation
//! (don't extract attacker-influenced archives into a directory writable
//! by other local users). Closing the gap on Windows would require
//! `NtCreateFile` with `OBJECT_ATTRIBUTES`, which the crate does not
//! take on because of its zero-`unsafe` stance.
//!
//! Gated to Linux and macOS because rustix is only pulled in there; the
//! other-platform extraction path keeps the existing path-based approach.
//!
//! [`extract_entries`]: crate::archive::decode

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Component, Path};

use rustix::fs::{FileType, Mode, OFlags, RawMode};
use rustix::io::Errno;

use crate::CryptoError;

/// Default mode passed to `mkdirat` when creating a fresh extraction
/// directory (rwxr-xr-x). The tar-stored directory mode is applied
/// later via `fchmod` so that a restrictive parent (e.g. 0o500)
/// declared higher up in the archive doesn't block creation of its
/// children.
const DIR_CREATE_MODE: u32 = 0o755;

/// Defensive mask for `mode_from`: keeps the rwx + setuid/setgid/
/// sticky bits (4 octal digits) and drops everything else, so a
/// stray caller passing a value with high bits set cannot silently
/// truncate on targets where `RawMode` is narrower than `u32`
/// (notably macOS's `u16`).
const MODE_AND_SPECIAL_BITS_MASK: u32 = 0o7777;

/// Converts a tar-style u32 permission word into a `rustix::fs::Mode`,
/// coping with targets where `mode_t` is narrower than `u32`. The
/// defensive [`MODE_AND_SPECIAL_BITS_MASK`] keeps only permission and
/// special bits, so a stray caller passing a value with high bits
/// set cannot silently truncate on macOS's `u16` `RawMode`.
fn mode_from(mode: u32) -> Mode {
    Mode::from_raw_mode((mode & MODE_AND_SPECIAL_BITS_MASK) as RawMode)
}

/// Opens the user-supplied output directory as a dirfd anchor. The
/// output directory itself is chosen by the caller (argv / GUI picker)
/// and is trusted, so NOFOLLOW is not applied here.
pub(crate) fn open_anchor(output_dir: &Path) -> Result<OwnedFd, CryptoError> {
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
    let stat = rustix::fs::fstat(fd.as_fd()).map_err(|e| CryptoError::Io(io::Error::from(e)))?;
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
pub(crate) fn mkdirat_strict(parent_fd: &OwnedFd, name: &OsStr) -> io::Result<OwnedFd> {
    rustix::fs::mkdirat(parent_fd.as_fd(), name, mode_from(DIR_CREATE_MODE))
        .map_err(io::Error::from)?;
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
pub(crate) fn ensure_dir(parent_fd: &OwnedFd, name: &OsStr) -> Result<OwnedFd, CryptoError> {
    match openat_nofollow(parent_fd, name) {
        Ok(fd) => {
            ensure_fd_is_directory(&fd, name)?;
            Ok(fd)
        }
        Err(Errno::NOENT) => {
            rustix::fs::mkdirat(parent_fd.as_fd(), name, mode_from(DIR_CREATE_MODE))
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

fn normal_component<'a>(component: Component<'a>, full: &Path) -> Result<&'a OsStr, CryptoError> {
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
pub(crate) fn walk_to_parent(
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
///
/// **Empty-`rel` behavior:** when `rel` has no components,
/// `rel.components()` yields nothing and the for-loop is a no-op,
/// so the function returns a freshly-cloned fd of `root_fd` itself.
/// The deferred dir-permissions loop relies on this to fold the
/// "root directory" and "descendant directory" cases into a single
/// call site without an explicit empty-path branch.
pub(crate) fn open_dir_at_rel(root_fd: &OwnedFd, rel: &Path) -> Result<OwnedFd, CryptoError> {
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
pub(crate) fn create_file_at(
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

/// Sets the rwx permission bits of an already-open fd. Special bits
/// (setuid/setgid/sticky) are stripped — extraction never honors a
/// tar-stored special bit, so callers can pass the raw header mode
/// without pre-masking. Accepts any `AsFd` so it works for both
/// regular-file and directory fds.
pub(crate) fn fchmod<Fd: AsFd>(fd: Fd, mode: u32) -> Result<(), CryptoError> {
    rustix::fs::fchmod(fd, mode_from(mode & super::PERMISSION_BITS_MASK))
        .map_err(|e| CryptoError::Io(io::Error::from(e)))
}

#[cfg(test)]
mod tests {
    use super::{create_file_at, ensure_dir, open_anchor, open_dir_at_rel, walk_to_parent};
    use std::ffi::OsStr;
    use std::fs;
    use std::io;
    use std::os::unix::fs as unix_fs;
    use std::path::Path;

    #[test]
    fn ensure_dir_rejects_symlink_at_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        unix_fs::symlink("/tmp", tmp.path().join("evil")).unwrap();

        let parent_fd = open_anchor(tmp.path()).unwrap();
        let err = ensure_dir(&parent_fd, OsStr::new("evil")).unwrap_err();
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

        let root_fd = open_anchor(&root).unwrap();
        let err = walk_to_parent(&root_fd, Path::new("a/b/file.txt")).unwrap_err();
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

        let parent_fd = open_anchor(tmp.path()).unwrap();
        let err = create_file_at(&parent_fd, OsStr::new("link.txt"), 0o600).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            "original",
            "victim file must not be touched through the symlink"
        );
    }

    /// `open_dir_at_rel` documents that an empty `rel` yields a fresh
    /// clone of `root_fd`. The deferred-dir-permissions loop in
    /// `extract_entries` relies on this to fold the root-directory
    /// case into the same call site as descendant directories — if
    /// the helper ever changes to error or panic on empty paths,
    /// root-level dir permissions would stop applying.
    #[test]
    fn open_dir_at_rel_with_empty_rel_returns_root_clone() {
        use std::os::fd::AsRawFd;

        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir_all(&root).unwrap();

        let root_fd = open_anchor(&root).unwrap();
        let cloned = open_dir_at_rel(&root_fd, Path::new("")).unwrap();

        // Distinct fd numbers — proves it's a fresh clone, not the
        // same fd handed back.
        assert_ne!(root_fd.as_raw_fd(), cloned.as_raw_fd());

        // The cloned fd points at the same directory: a file created
        // under it must appear at the root's path.
        let _via_clone = create_file_at(&cloned, OsStr::new("via_clone.txt"), 0o600).unwrap();
        assert!(root.join("via_clone.txt").exists());
    }
}
