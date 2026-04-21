//! Internal parser-surface re-exports for the in-repo fuzz targets.
//!
//! Gated behind the `fuzzing` Cargo feature so library consumers never
//! see these items. The only crate that enables the feature is
//! `ferrocrypt-lib/fuzz`, where each target drives a specific parser at
//! the lowest useful layer (prefix replication + magic-byte/type,
//! key-file header validation, KDF parameter bounds, etc.) without
//! paying the cost of running a full Argon2id derivation.
//!
//! **Not a stable API.** Do not depend on this module from outside the
//! repository. Items here may be renamed, removed, or re-shaped at any
//! time without a semver bump.

#![allow(missing_docs)]

pub use crate::archiver::validate_archive_path;
pub use crate::common::{KDF_PARAMS_SIZE, KdfParams};
pub use crate::format::{
    KEY_FILE_TYPE_PRIVATE, KEY_FILE_TYPE_PUBLIC, PUBLIC_KEY_DATA_SIZE, TYPE_HYBRID, TYPE_SYMMETRIC,
    parse_key_file_header, read_header_from_reader, validate_key_layout,
};
pub use crate::hybrid::validate_private_key_body_shape;
pub use crate::replication::{decode, decode_exact};
