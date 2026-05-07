#![allow(unused)]

//! FerroCrypt Archive (FCA) v1 — native archive payload format.
//!
//! Build-out parallel to [`crate::archive`]; both modules coexist until the
//! Phase 9 switchover. See `notes/archive_format/MIGRATION_PLAN.md` and
//! `notes/archive_format/ARCHIVE_FORMAT.md`.

pub(crate) mod decode;
pub(crate) mod encode;
pub(crate) mod format;
pub(crate) mod limits;
pub(crate) mod model;
pub(crate) mod path;
pub(crate) mod tree;
