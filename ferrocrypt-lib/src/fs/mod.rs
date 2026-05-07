//! Local filesystem mechanics unrelated to archive-payload semantics.
//!
//! Owns:
//!
//! - [`atomic`] — temporary output names, no-clobber finalization,
//!   same-directory staging, cleanup on encrypt failure, `.incomplete`
//!   behavior on decrypt failure.
//! - [`paths`] — general path helpers: encrypted filename derivation,
//!   base-name and file-stem extraction, parent-directory resolution,
//!   the `.incomplete` suffix constant, and user-facing path error
//!   mapping.

pub(crate) mod atomic;
pub(crate) mod paths;
