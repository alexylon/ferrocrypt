//! Local filesystem mechanics unrelated to TAR semantics.
//!
//! Owns:
//!
//! - [`atomic`] — temporary output names, no-clobber finalization,
//!   same-directory staging, cleanup on encrypt failure, `.incomplete`
//!   behavior on decrypt failure.
//! - [`paths`] — general path helpers (encrypted filename derivation,
//!   base-name extraction, user-path error mapping). Populated in step 3
//!   of the restructure plan; currently empty.

pub(crate) mod atomic;
pub(crate) mod paths;
