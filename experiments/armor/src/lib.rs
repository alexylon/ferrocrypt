//! Parked ASCII-armor implementation lifted out of `ferrocrypt-lib`
//! when the armor module was deferred to a future release.
//!
//! Contents:
//! - [`armor`] — the streaming encoder/decoder (`ArmoredReader`,
//!   `ArmoredWriter`, `Format`, `BEGIN_MARKER`, `END_MARKER`).
//! - [`error`] — the standalone [`error::ArmorDefect`] enum that the
//!   reader surfaces as the inner of an `io::Error::InvalidData`.
//!
//! See `armor_review_findings.md` next to this crate for the full
//! review history that led to parking the module here.

pub mod armor;
pub mod error;

pub use armor::{ArmoredReader, ArmoredWriter, BEGIN_MARKER, END_MARKER, Format, MIN_ARMOR_LEN};
pub use error::ArmorDefect;
