//! Local filesystem mechanics unrelated to archive-payload semantics.
//!
//! Owns:
//!
//! - [`atomic`] — no-clobber finalization, the file and directory
//!   durability helpers, and the path-based decrypt-promotion helpers
//!   used on Windows / other non-Linux/macOS targets. Linux/macOS
//!   decrypt promotion is handle-relative in `archive::platform`.
//!   Callers stage their own temporary files; this module requires only
//!   that staging happened in the destination directory.
//! - [`paths`] — general path helpers: special-file-safe input opening,
//!   bounded and staged key-file reads, occupied-path rejection,
//!   encrypted filename derivation, base-name and file-stem extraction,
//!   parent-directory resolution, the `.incomplete` suffix constant, and
//!   user-facing path error mapping.

pub(crate) mod atomic;
pub(crate) mod paths;
