//! Local filesystem mechanics unrelated to archive-payload semantics.
//!
//! Owns:
//!
//! - [`commit`] — the link-or-claim no-clobber commit both writers
//!   reach where the filesystem cannot perform an atomic no-replace
//!   rename, plus the restrictive modes and the create primitives a
//!   staged entry is made with.
//! - [`atomic`] — no-clobber finalization, the file and directory
//!   durability helpers, and the path-based decrypt-promotion helpers
//!   used on Windows / other non-Linux/macOS targets. Linux/macOS
//!   decrypt promotion is handle-relative in `archive::platform`.
//!   Callers stage their own temporary files; this module requires only
//!   that staging happened in the destination directory.
//! - [`paths`] — general path helpers: special-file-safe input opening,
//!   bounded and staged key-file reads, occupied-path rejection,
//!   output base-name derivation, input leaf-name and file-stem
//!   extraction, parent-directory resolution, the `.incomplete` suffix
//!   constant, and user-facing path error mapping.

pub(crate) mod atomic;
pub(crate) mod commit;
pub(crate) mod paths;
