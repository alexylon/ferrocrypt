//! TAR archive subset and directory/file payload semantics.
//!
//! Owns:
//!
//! - [`limits`] — [`ArchiveLimits`] and resource-cap helpers shared by
//!   the encrypt-side preflight and the decrypt-side extraction loop.
//! - [`path`] — archive path canonicalization and rejection
//!   ([`validate_archive_path_components`]), the POSIX ustar wire-format constants
//!   used by both writer and reader, and the [`UstarEntryKind`]
//!   classification.
//! - [`encode`] — encrypt-side traversal: [`validate_encrypt_input`],
//!   [`archive`], TAR header emission, the `open_no_follow` symlink
//!   guard, and the encrypt-side mode helpers.
//! - [`decode`] — decrypt-side TAR reading and output reconstruction:
//!   [`unarchive`], `extract_entries` (Linux/macOS hardened arm and the
//!   path-based fallback), TAR-subset validation, and trailing
//!   zero-block enforcement.
//! - [`platform`] (Linux/macOS only) — directory-fd-anchored extraction
//!   primitives (`openat`/`mkdirat`/`O_NOFOLLOW`).
//!
//! [`ArchiveLimits`]: crate::ArchiveLimits
//! [`validate_archive_path_components`]: crate::archive::validate_archive_path_components
//! [`validate_encrypt_input`]: crate::archive::validate_encrypt_input
//! [`archive`]: crate::archive::archive
//! [`unarchive`]: crate::archive::unarchive
//! [`UstarEntryKind`]: crate::archive::path::UstarEntryKind

pub(crate) mod decode;
pub(crate) mod encode;
pub(crate) mod limits;
pub(crate) mod path;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod platform;

pub use limits::ArchiveLimits;

pub(crate) use decode::unarchive;
pub(crate) use encode::{archive, validate_encrypt_input};

/// Mask that keeps only owner/group/other rwx bits, stripping
/// setuid, setgid, and sticky bits from tar-stored permissions.
/// Shared by the encrypt-side `metadata_perm_mode` reader, the
/// Linux/macOS `platform::fchmod` helper, and the path-based
/// fallback `restore_permissions_from_mode` setter.
#[cfg(unix)]
pub(crate) const PERMISSION_BITS_MASK: u32 = 0o777;
