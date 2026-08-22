//! The no-clobber commit every staged output reaches where the
//! filesystem cannot perform an atomic no-replace rename.
//!
//! Both writers stage under a temporary name in the destination
//! directory and promote it to the final name only once the content is
//! complete: [`crate::fs::atomic`] for encrypted output and key files,
//! `archive::platform` for a decrypted root. Where the kernel or the
//! filesystem refuses a no-replace rename — macOS exFAT and smbfs, some
//! network and FUSE mounts — both reach the same two-route fallback,
//! which this module owns so the two cannot drift:
//!
//! 1. **Link.** A file is linked at its final name; the caller drops
//!    the staging name afterwards. `link` refuses an existing target
//!    atomically, so no placeholder is created that another process
//!    could replace, and both names denote the finished content in
//!    between.
//! 2. **Claim.** A filesystem without hard links (exFAT and FAT among
//!    them), and every directory root, claims the final name by
//!    creating it and renames the staged entry over that claim. The
//!    claim is an atomic test-and-create, so an entry that predates the
//!    commit is still refused. Between the two steps the claim is an
//!    ordinary entry, so a local writer with access to the destination
//!    directory can remove it and leave one of their own, which step 2
//!    then replaces; that window is why the link route is preferred
//!    wherever it works, and `SECURITY.md` states what remains.
//!
//! Every step resolves through the caller's retained directory handle,
//! so a rename or replacement of the destination path mid-commit can
//! neither redirect the commit nor send a removal into another
//! directory. The staged entry and the final name must both be entries
//! of that directory.
//!
//! A failed step-2 rename leaves the final name as it is. The claim ran
//! with its entry already visible, so by the time the failure is known
//! the entry under that name may be the placeholder or whatever a local
//! writer put in its place, and no Unix operation removes a name only
//! while it still denotes a given open file: an identity check followed
//! by a removal by name would reach an entry substituted in between.
//! No content from this run's staged entry reached that name, so nothing
//! this run wrote is lost by leaving it. The caller is told through
//! [`CommitFailure::claim_left`] that the name may still be occupied and
//! block the next attempt; the report does not state whose the remaining
//! entry is or whether it contains anything.
//!
//! What stays with the caller: the primary route it tries first, the
//! removal of the staging name after a link commit — the two callers
//! hold their staged handle for different lengths of time — the
//! durability barrier, the error taxonomy, and every post-commit
//! confirmation.

use std::ffi::OsStr;
use std::io;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use std::path::Path;

use cap_std::fs::{Dir, File, OpenOptions};

/// Opens `path` as the directory handle a commit resolves through,
/// preferring the narrowest access a commit needs.
///
/// A commit renames, links, creates, and removes entries *inside* the
/// directory; it never lists it. Linux and macOS can open a directory
/// for exactly that — `O_PATH` and `O_SEARCH` — so an output directory
/// that grants write and search but not read still receives output. The
/// handle cannot read the directory's entries, which is what makes the
/// narrower request safe to prefer: it carries no authority the commit
/// does not use.
///
/// A filesystem that refuses the narrow open falls back to an ordinary
/// directory open. That widens what the operation asks for, not what it
/// does: the commit still resolves through one retained handle, which
/// is the property this anchor exists for. Only the ability to commit
/// into a directory that cannot be listed is lost, and the caller is no
/// worse off than before that ability existed.
///
/// The narrow open is Linux and macOS only. Production encrypted output on
/// every other target retains its path-based primary commit and does not call
/// this opener; the ordinary-open counterpart below exists for cross-target
/// test scaffolding. A caller that also has to read the directory — key
/// generation, whose required durability barrier reopens it — opens its own
/// readable handle instead and keeps that requirement.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn open_commit_anchor(path: &Path) -> io::Result<Dir> {
    // Opened through `rustix` so the flag word reaches the system call
    // as written. The standard library removes every `O_ACCMODE` bit
    // from a caller-supplied flag, and musl counts this request as an
    // access mode, which would leave an ordinary read open that a
    // directory without read permission refuses.
    match rustix::fs::open(path, SEARCH_ONLY_FLAGS, rustix::fs::Mode::empty()) {
        Ok(handle) => Ok(Dir::from_std_file(std::fs::File::from(handle))),
        Err(_) => Dir::open_ambient_dir(path, cap_std::ambient_authority()),
    }
}

/// Linux opens a directory for path resolution alone with `O_PATH`.
#[cfg(target_os = "linux")]
const SEARCH_ONLY_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::PATH
    .union(rustix::fs::OFlags::DIRECTORY)
    .union(rustix::fs::OFlags::CLOEXEC);

/// macOS spells the same request `O_SEARCH`, itself `O_EXEC` plus the
/// directory requirement. `rustix` names no flag for it.
#[cfg(target_os = "macos")]
const SEARCH_ONLY_FLAGS: rustix::fs::OFlags =
    rustix::fs::OFlags::from_bits_retain(libc::O_SEARCH as u32).union(rustix::fs::OFlags::CLOEXEC);

/// Ordinary directory open for the targets without a narrow one. The
/// commit still resolves through this handle; only the request is
/// wider.
#[cfg(all(test, not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) fn open_commit_anchor(path: &Path) -> io::Result<Dir> {
    Dir::open_ambient_dir(path, cap_std::ambient_authority())
}

/// What the no-replace rename a commit prefers established.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) enum FlaggedRename {
    /// The rename committed the final name.
    Committed,
    /// The kernel or the filesystem cannot perform a no-replace rename
    /// at all, so the caller falls back to
    /// [`commit_by_link_or_claim`]. An ordinary failure of a supported
    /// rename is an error instead.
    Unsupported,
}

/// Renames `staged` to `final_name`, both resolved through `anchor`,
/// refusing an existing target atomically.
///
/// This is the route every commit prefers on Linux and macOS. Because
/// both endpoints resolve through the retained handle, a rename or
/// replacement of the destination path between staging and the commit
/// cannot redirect it: the output lands in the exact directory its
/// content was written to. `RENAME_NOREPLACE` maps to `renameat2` on
/// Linux and `renameatx_np(RENAME_EXCL)` on macOS, both through
/// `rustix`, and the kernel performs the existence check and the rename
/// as one operation.
///
/// Durability is the caller's: the two callers flush the committed
/// directory at different points and to different requirements.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn rename_no_replace_at(
    anchor: &Dir,
    staged: &OsStr,
    final_name: &OsStr,
) -> io::Result<FlaggedRename> {
    use std::os::fd::AsFd;

    use rustix::fs::{RenameFlags, renameat_with};

    match renameat_with(
        anchor.as_fd(),
        staged,
        anchor.as_fd(),
        final_name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => Ok(FlaggedRename::Committed),
        Err(e) => {
            let error = io::Error::from(e);
            if crate::fs::atomic::no_replace_rename_unsupported(&error) {
                Ok(FlaggedRename::Unsupported)
            } else {
                Err(error)
            }
        }
    }
}

/// Permission word for a regular file this crate creates and later
/// commits: owner read and write, nothing for group or other.
///
/// Restrictive on purpose. A staged file holds plaintext under a name
/// other local users can reach, and the placeholder a claim route
/// creates holds the final name before the content arrives; neither may
/// be readable or writable by anyone else while the operation runs. The
/// stored mode, where the artefact has one, is applied through the open
/// handle after the commit. Unix only — Windows ignores the word and
/// gives the file the access control it inherits from its directory.
pub(crate) const STAGED_FILE_MODE: u32 = 0o600;

/// Permission word for a directory this crate creates and later
/// commits: owner read, write, and traverse, nothing for group or
/// other. [`STAGED_FILE_MODE`]'s reasoning, plus the owner access a
/// failure-path removal of the staged tree needs. Unix only.
#[cfg(unix)]
pub(crate) const STAGED_DIR_MODE: u32 = 0o700;

/// What is being committed. Directories cannot be linked, so the kind
/// selects both the route and the claim primitive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg(unix)]
pub(crate) enum CommitKind {
    File,
    /// Built only by the archive directory promotion, which exists on
    /// Linux and macOS alone; every other Unix target commits files.
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    Directory,
}

/// How a successful commit reached the final name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg(unix)]
pub(crate) enum CommitRoute {
    /// A rename moved the staged entry over the claim, so the staging
    /// name is gone.
    Renamed,
    /// A hard link put the staged file at its final name. The staging
    /// name still exists and the caller must remove it — and must
    /// confirm through its retained handle that the committed file ends
    /// with exactly one name, because a removal that reports success or
    /// a missing name proves neither.
    Linked,
}

/// A commit that did not reach the final name.
#[derive(Debug)]
#[cfg(unix)]
pub(crate) struct CommitFailure {
    /// Why the commit failed. [`io::ErrorKind::AlreadyExists`] is the
    /// no-clobber refusal, which every caller maps to its own occupied-
    /// output error.
    pub(crate) error: io::Error,
    /// Whether the claim route created an entry at the final name, which
    /// the failed commit leaves in place, so that name may still be
    /// occupied — by this run's placeholder, or by whatever replaced it.
    /// The caller reports it, because an occupied name blocks the next
    /// attempt. No content from this run's staged entry reached that name:
    /// the commit failed before it could be moved there.
    pub(crate) claim_left: bool,
}

#[cfg(unix)]
impl CommitFailure {
    /// A failure before any claim was made, so nothing of this run's is
    /// left at the final name.
    pub(crate) fn plain(error: io::Error) -> Self {
        Self {
            error,
            claim_left: false,
        }
    }
}

/// Commits the entry `staged` to `final_name`, both resolved through
/// `anchor`, on a filesystem that cannot perform an atomic no-replace
/// rename. The module documentation describes the two routes and what
/// each guarantees.
///
/// The staged entry is left in place on failure, so a caller whose
/// policy retains staged output after a failed commit still finds it
/// there; a caller that removes its own staging does so itself.
#[cfg(unix)]
pub(crate) fn commit_by_link_or_claim(
    anchor: &Dir,
    staged: &OsStr,
    final_name: &OsStr,
    kind: CommitKind,
) -> Result<CommitRoute, CommitFailure> {
    if kind == CommitKind::File {
        match anchor.hard_link(staged, anchor, final_name) {
            Ok(()) => return Ok(CommitRoute::Linked),
            // The final name was taken before the commit began. Every
            // other link failure falls through: the claim route
            // attempts the same commit and reports its own failure, so
            // the wide fallback cannot weaken the no-clobber guarantee.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(CommitFailure::plain(e));
            }
            Err(_) => {}
        }
    }
    commit_by_claim_with(anchor, staged, final_name, kind, |_| {})
}

/// The claim route on its own: claim the final name by creating it,
/// then rename the staged entry over that claim. Reached from
/// [`commit_by_link_or_claim`] for a directory, and for a file whose
/// link failed for any reason other than an occupied target.
///
/// `after_claim` runs once the placeholder exists and before the rename
/// over it — the window in which a local writer can act on the claim.
/// The route is exposed rather than private so a caller's tests can
/// drive it on a filesystem whose hard links would always win the
/// link-first entry point above.
#[cfg(unix)]
pub(crate) fn commit_by_claim_with(
    anchor: &Dir,
    staged: &OsStr,
    final_name: &OsStr,
    kind: CommitKind,
    after_claim: impl FnOnce(&Dir),
) -> Result<CommitRoute, CommitFailure> {
    claim_final_name(anchor, final_name, kind).map_err(CommitFailure::plain)?;
    after_claim(anchor);
    // The rename replaces the placeholder in one step, so no reader ever
    // sees partial content at the final name. If it fails, the
    // placeholder — or whatever has replaced it since — stays: see the
    // module documentation for why it is not removed.
    anchor
        .rename(staged, anchor, final_name)
        .map(|()| CommitRoute::Renamed)
        .map_err(|error| CommitFailure {
            error,
            claim_left: true,
        })
}

/// Claims `final_name` under `anchor` by creating it: an atomic
/// test-and-create on every filesystem, refusing any pre-existing entry
/// — including a dangling symlink — with [`io::ErrorKind::AlreadyExists`],
/// the same error the no-replace rename reports. The owner-only modes
/// keep other local users from writing into the claimed name where the
/// filesystem enforces modes; on a permissionless filesystem (exFAT) a
/// concurrent local write into a directory claim instead makes the
/// rename over it fail closed with a non-empty-target error.
///
/// The handle a file create returns is closed at once: the commit has no
/// further use for it, since the placeholder is only ever replaced,
/// never removed.
#[cfg(unix)]
fn claim_final_name(anchor: &Dir, final_name: &OsStr, kind: CommitKind) -> io::Result<()> {
    match kind {
        CommitKind::File => create_file_at(anchor, final_name, STAGED_FILE_MODE).map(drop),
        CommitKind::Directory => create_dir_at(anchor, final_name),
    }
}

/// Atomically creates a new regular file `name` under `parent`. Any
/// pre-existing entry — including a symlink whose target exists, a
/// dangling symlink, or (on Windows) a reparse point — fails with
/// [`io::ErrorKind::AlreadyExists`].
///
/// `mode` must already be reduced to the permission bits; the archive
/// extractor masks a manifest-supplied mode before it gets here, and
/// every other caller passes [`STAGED_FILE_MODE`]. Windows ignores it.
///
/// `follow(FollowSymlinks::No)` is set alongside `create_new(true)` for
/// defense in depth: both prevent the open from following a symlink
/// planted at the leaf, on platforms whose underlying open semantics
/// differ.
pub(crate) fn create_file_at(
    parent: &Dir,
    name: &OsStr,
    #[cfg_attr(not(unix), allow(unused_variables))] mode: u32,
) -> io::Result<File> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    options.follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_fs_ext::OpenOptionsExt;
        options.mode(mode);
    }
    parent.open_with(name, &options)
}

/// Creates the directory `name` under `parent` with [`STAGED_DIR_MODE`]
/// applied at create time, so a permissive process umask cannot leave a
/// fresh directory briefly traversable by other local users. Fails with
/// [`io::ErrorKind::AlreadyExists`] if anything is already there.
#[cfg(unix)]
pub(crate) fn create_dir_at(parent: &Dir, name: &OsStr) -> io::Result<()> {
    use cap_std::fs::{DirBuilder, DirBuilderExt};

    let mut builder = DirBuilder::new();
    builder.mode(STAGED_DIR_MODE);
    parent.create_dir_with(name, &builder)
}

/// Non-Unix counterpart of [`create_dir_at`]. There is no mode to
/// apply: the directory takes the access control it inherits.
#[cfg(not(unix))]
pub(crate) fn create_dir_at(parent: &Dir, name: &OsStr) -> io::Result<()> {
    parent.create_dir(name)
}

/// The mode [`SearchOnlyDir`] applies: the owner may write into the
/// directory and traverse it, but not list it.
///
/// Only where [`open_commit_anchor`] exists, which is where the tests
/// that need such a directory are.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
const WRITE_AND_SEARCH_ONLY_MODE: u32 = 0o300;

/// A directory that grants its owner write and search but not read, so
/// a test can drive a commit the way an output directory with those
/// permissions would. The mode is restored on drop, because removing
/// the enclosing temporary directory needs to read this one.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) struct SearchOnlyDir {
    /// Dropped after the mode is restored, which is the order fields
    /// and `Drop` run in.
    _parent: tempfile::TempDir,
    path: std::path::PathBuf,
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
impl SearchOnlyDir {
    pub(crate) fn new() -> Self {
        let parent = tempfile::TempDir::new().unwrap();
        let path = parent.path().join("out");
        std::fs::create_dir(&path).unwrap();
        Self {
            _parent: parent,
            path,
        }
    }

    /// Applies the write-and-search-only mode. Called once the test has
    /// staged whatever it needs, since staging itself reads nothing.
    pub(crate) fn close_reading(&self) {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(
            &self.path,
            std::fs::Permissions::from_mode(WRITE_AND_SEARCH_ONLY_MODE),
        )
        .unwrap();
        assert!(
            std::fs::read_dir(&self.path).is_err(),
            "the directory must not be readable, or the test proves nothing"
        );
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
impl Drop for SearchOnlyDir {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;

        let _ =
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(STAGED_DIR_MODE));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::ffi::OsStr;
    use std::fs;

    use super::*;

    /// Opens `dir` as a commit anchor the way both writers do.
    fn anchor(dir: &std::path::Path) -> Dir {
        Dir::open_ambient_dir(dir, cap_std::ambient_authority()).unwrap()
    }

    /// A file on a filesystem with hard links reaches its final name
    /// without a placeholder, so the staging name still exists and the
    /// caller is told to remove it.
    #[test]
    fn a_file_commits_by_link_and_leaves_the_staging_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(tmp.path().join("out.incomplete"), b"payload").unwrap();
        let anchor = anchor(tmp.path());

        let route = commit_by_link_or_claim(
            &anchor,
            OsStr::new("out.incomplete"),
            OsStr::new("out"),
            CommitKind::File,
        )
        .unwrap();

        assert_eq!(route, CommitRoute::Linked);
        assert_eq!(fs::read(tmp.path().join("out")).unwrap(), b"payload");
        assert!(
            tmp.path().join("out.incomplete").exists(),
            "the staging name is the caller's to remove"
        );
    }

    /// The claim route replaces its own placeholder in one step, so the
    /// staging name is gone and the content arrives whole.
    #[test]
    fn the_claim_route_renames_the_staged_entry_over_its_own_claim() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("out.incomplete")).unwrap();
        fs::write(tmp.path().join("out.incomplete").join("f"), b"payload").unwrap();
        let anchor = anchor(tmp.path());

        let route = commit_by_claim_with(
            &anchor,
            OsStr::new("out.incomplete"),
            OsStr::new("out"),
            CommitKind::Directory,
            |_| {},
        )
        .unwrap();

        assert_eq!(route, CommitRoute::Renamed);
        assert_eq!(
            fs::read(tmp.path().join("out").join("f")).unwrap(),
            b"payload"
        );
        assert!(!tmp.path().join("out.incomplete").exists());
    }

    /// Both routes refuse an entry that predates the commit with the
    /// same error the flagged rename reports, and leave it alone.
    #[test]
    fn an_occupied_final_name_is_refused_and_left_alone() {
        for commit_kind in [CommitKind::File, CommitKind::Directory] {
            let tmp = tempfile::TempDir::new().unwrap();
            fs::write(tmp.path().join("out.incomplete"), b"payload").unwrap();
            fs::write(tmp.path().join("out"), b"existing").unwrap();
            let anchor = anchor(tmp.path());

            let failure = commit_by_link_or_claim(
                &anchor,
                OsStr::new("out.incomplete"),
                OsStr::new("out"),
                commit_kind,
            )
            .expect_err("an occupied final name must refuse the commit");

            assert_eq!(
                failure.error.kind(),
                io::ErrorKind::AlreadyExists,
                "{commit_kind:?}"
            );
            assert!(!failure.claim_left, "no claim was made, so none was left");
            assert_eq!(fs::read(tmp.path().join("out")).unwrap(), b"existing");
            assert!(tmp.path().join("out.incomplete").exists());
        }
    }

    /// A failed rename over the claim leaves the placeholder where it is
    /// and reports the name as occupied, for both kinds of claim. The
    /// next attempt then finds the name taken — the no-clobber refusal,
    /// which makes no claim of its own and so reports none left.
    #[test]
    fn a_failed_rename_leaves_the_claim_and_reports_it() {
        for commit_kind in [CommitKind::File, CommitKind::Directory] {
            let tmp = tempfile::TempDir::new().unwrap();
            let anchor = anchor(tmp.path());
            let out = tmp.path().join("out");

            let failure = commit_by_claim_with(
                &anchor,
                OsStr::new("missing.incomplete"),
                OsStr::new("out"),
                commit_kind,
                |_| {},
            )
            .expect_err("a rename with no staged entry must fail the commit");

            assert_eq!(
                failure.error.kind(),
                io::ErrorKind::NotFound,
                "{commit_kind:?}"
            );
            assert!(failure.claim_left, "{commit_kind:?}");
            let left = fs::symlink_metadata(&out).expect("the claim stays at the final name");
            match commit_kind {
                CommitKind::File => assert!(left.is_file() && left.len() == 0, "{left:?}"),
                CommitKind::Directory => assert!(left.is_dir(), "{left:?}"),
            }

            let retry = commit_by_link_or_claim(
                &anchor,
                OsStr::new("missing.incomplete"),
                OsStr::new("out"),
                commit_kind,
            )
            .expect_err("the name left occupied must refuse the next attempt");
            assert_eq!(
                retry.error.kind(),
                io::ErrorKind::AlreadyExists,
                "{commit_kind:?}"
            );
            assert!(!retry.claim_left, "a refused attempt makes no claim");
            assert!(out.exists(), "a refused attempt removes nothing either");
        }
    }

    /// A local writer able to reach the destination directory can remove
    /// the placeholder and leave an entry of their own. When the rename
    /// then fails, that entry is left where it is with everything in it,
    /// and so is the staged entry: its removal is the caller's policy.
    /// A non-empty directory makes the rename fail for both kinds.
    #[test]
    fn an_entry_put_in_place_of_the_claim_survives_the_failed_commit() {
        for commit_kind in [CommitKind::File, CommitKind::Directory] {
            let tmp = tempfile::TempDir::new().unwrap();
            let staged = tmp.path().join("out.incomplete");
            match commit_kind {
                CommitKind::File => fs::write(&staged, b"payload").unwrap(),
                CommitKind::Directory => fs::create_dir(&staged).unwrap(),
            }
            let anchor = anchor(tmp.path());

            let failure = commit_by_claim_with(
                &anchor,
                OsStr::new("out.incomplete"),
                OsStr::new("out"),
                commit_kind,
                |dir| {
                    match commit_kind {
                        CommitKind::File => dir.remove_file("out").unwrap(),
                        CommitKind::Directory => dir.remove_dir("out").unwrap(),
                    }
                    dir.create_dir("out").unwrap();
                    dir.write(std::path::Path::new("out").join("theirs"), b"planted")
                        .unwrap();
                },
            )
            .expect_err("a rename over a non-empty directory must fail the commit");

            assert!(failure.claim_left, "{commit_kind:?}");
            assert_eq!(
                fs::read(tmp.path().join("out").join("theirs")).unwrap(),
                b"planted",
                "an entry put in place of the placeholder must survive ({commit_kind:?})"
            );
            assert!(
                fs::symlink_metadata(&staged).is_ok(),
                "the staged entry is the caller's to remove ({commit_kind:?})"
            );
        }
    }

    /// An empty file put in place of the placeholder looks exactly like
    /// it and survives all the same: the failure path removes nothing,
    /// so it has no need to tell the two apart.
    #[test]
    fn an_empty_file_put_in_place_of_the_claim_survives_the_failed_commit() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(tmp.path().join("out.incomplete"), b"payload").unwrap();
        let anchor = anchor(tmp.path());
        let mut planted_identity = None;

        let failure = commit_by_claim_with(
            &anchor,
            OsStr::new("out.incomplete"),
            OsStr::new("out"),
            CommitKind::File,
            |dir| {
                dir.remove_file("out").unwrap();
                dir.write("out", b"").unwrap();
                planted_identity = crate::fs::atomic::file_identity(&dir.metadata("out").unwrap());
                dir.remove_file("out.incomplete").unwrap();
            },
        )
        .expect_err("a rename with no staged entry must fail the commit");

        assert!(failure.claim_left);
        let left = crate::fs::atomic::file_identity(&anchor.metadata("out").unwrap());
        assert!(
            planted_identity.is_some(),
            "the test needs identities to compare"
        );
        assert_eq!(
            left, planted_identity,
            "the planted file must be the one left"
        );
    }

    /// The commit anchor asks for only what a commit uses, so an output
    /// directory that grants write and search but not read still
    /// receives output — and the anchor carries no authority to list it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_search_only_anchor_cannot_read_the_directory_it_commits_into() {
        let out = SearchOnlyDir::new();
        fs::write(out.path().join("staged"), b"payload").unwrap();
        out.close_reading();

        let anchor = open_commit_anchor(out.path()).unwrap();
        anchor
            .symlink_metadata("staged")
            .expect("a commit resolves names through the anchor");
        assert!(
            anchor.entries().is_err(),
            "the anchor must not be able to list the directory"
        );
    }

    /// The route every commit prefers, driven in a write-and-search-only
    /// output directory.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_no_replace_rename_commits_through_a_search_only_anchor() {
        let out = SearchOnlyDir::new();
        fs::write(out.path().join("staged"), b"payload").unwrap();
        out.close_reading();
        let anchor = open_commit_anchor(out.path()).unwrap();

        assert!(matches!(
            rename_no_replace_at(&anchor, OsStr::new("staged"), OsStr::new("out")).unwrap(),
            FlaggedRename::Committed
        ));
        assert_eq!(fs::read(out.path().join("out")).unwrap(), b"payload");
    }

    /// The no-clobber refusal survives the narrower anchor: an entry that
    /// predates the commit is still never replaced.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_no_replace_rename_still_refuses_an_occupied_name_through_a_search_only_anchor() {
        let out = SearchOnlyDir::new();
        fs::write(out.path().join("staged"), b"payload").unwrap();
        fs::write(out.path().join("out"), b"existing").unwrap();
        out.close_reading();
        let anchor = open_commit_anchor(out.path()).unwrap();

        let error = rename_no_replace_at(&anchor, OsStr::new("staged"), OsStr::new("out"))
            .expect_err("an occupied final name must refuse the rename");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(out.path().join("out")).unwrap(), b"existing");
    }

    /// Both fallback routes in a write-and-search-only output directory:
    /// the link for a file, the claim for a directory.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn both_fallback_routes_commit_through_a_search_only_anchor() {
        let out = SearchOnlyDir::new();
        fs::write(out.path().join("file.incomplete"), b"payload").unwrap();
        fs::create_dir(out.path().join("dir.incomplete")).unwrap();
        fs::write(out.path().join("dir.incomplete").join("f"), b"inner").unwrap();
        out.close_reading();
        let anchor = open_commit_anchor(out.path()).unwrap();

        let linked = commit_by_link_or_claim(
            &anchor,
            OsStr::new("file.incomplete"),
            OsStr::new("file"),
            CommitKind::File,
        )
        .unwrap();
        assert_eq!(linked, CommitRoute::Linked);
        anchor.remove_file("file.incomplete").unwrap();

        let claimed = commit_by_claim_with(
            &anchor,
            OsStr::new("dir.incomplete"),
            OsStr::new("dir"),
            CommitKind::Directory,
            |_| {},
        )
        .unwrap();
        assert_eq!(claimed, CommitRoute::Renamed);

        assert_eq!(fs::read(out.path().join("file")).unwrap(), b"payload");
        assert_eq!(
            fs::read(out.path().join("dir").join("f")).unwrap(),
            b"inner"
        );
    }

    /// The claim is created owner-only, so another local user cannot
    /// write into the name while it is reserved.
    #[test]
    fn a_file_claim_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let anchor = anchor(tmp.path());
        let claim = create_file_at(&anchor, OsStr::new("claim"), STAGED_FILE_MODE).unwrap();
        drop(claim);

        let mode = fs::metadata(tmp.path().join("claim"))
            .unwrap()
            .permissions()
            .mode()
            & crate::archive::PERMISSION_BITS_MASK;
        assert_eq!(mode, STAGED_FILE_MODE);
    }

    /// The directory create applies its mode at create time, so a
    /// permissive process umask cannot leave a fresh directory
    /// traversable by other local users.
    #[test]
    fn a_directory_is_created_owner_only_whatever_the_umask() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let anchor = anchor(tmp.path());
        create_dir_at(&anchor, OsStr::new("staged")).unwrap();

        let mode = fs::metadata(tmp.path().join("staged"))
            .unwrap()
            .permissions()
            .mode()
            & crate::archive::PERMISSION_BITS_MASK;
        assert_eq!(mode, STAGED_DIR_MODE);
    }
}
