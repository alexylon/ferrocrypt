//! Local filesystem mechanics unrelated to archive-payload semantics.
//!
//! Owns:
//!
//! - [`atomic`] — temporary output names, no-clobber finalization,
//!   same-directory staging, cleanup on encrypt failure, and the
//!   path-based decrypt-promotion helpers used on Windows / other
//!   non-Linux/macOS targets. Linux/macOS decrypt promotion is
//!   handle-relative in `archive::platform`.
//! - [`paths`] — general path helpers: encrypted filename derivation,
//!   base-name and file-stem extraction, parent-directory resolution,
//!   the `.incomplete` suffix constant, and user-facing path error
//!   mapping.

pub(crate) mod atomic;
pub(crate) mod paths;
