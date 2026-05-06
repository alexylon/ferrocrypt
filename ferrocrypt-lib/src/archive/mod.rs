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
//!   [`unarchive`], unified hardened `extract_entries`, TAR-subset
//!   validation, and trailing zero-block enforcement.
//! - [`platform`] — capability-based extraction primitives built on
//!   cap-std + cap-fs-ext, universal across Linux / macOS / Windows.
//!   Anchors every operation to a directory handle, refuses every
//!   symlink in the extraction path, and on Windows also rejects
//!   NTFS reparse points (junctions, mount points) via the
//!   `FILE_ATTRIBUTE_REPARSE_POINT` post-check.
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

pub(crate) mod platform;

pub use limits::ArchiveLimits;

pub(crate) use decode::unarchive;
pub(crate) use encode::{archive, validate_encrypt_input};

/// Mask that keeps only owner/group/other rwx bits, stripping
/// setuid, setgid, and sticky bits from tar-stored permissions.
/// Shared by the encrypt-side `metadata_perm_mode` reader and the
/// unified cap-std extraction platform's handle-based chmod helpers.
#[cfg(unix)]
pub(crate) const PERMISSION_BITS_MASK: u32 = 0o777;
