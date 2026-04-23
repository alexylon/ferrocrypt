//! Internal parser-surface re-exports for the in-repo fuzz targets.
//!
//! Gated behind the `fuzzing` Cargo feature so library consumers never
//! see these items. The only crate that enables the feature is
//! `ferrocrypt-lib/fuzz`, where each target drives a specific parser at
//! the lowest useful layer (prefix replication + magic + type,
//! private-key header + body-shape check, KDF-parameter bounds, TLV
//! grammar, etc.) without paying the cost of running a full Argon2id
//! derivation.
//!
//! **Not a stable API.** Do not depend on this module from outside the
//! repository. Items here may be renamed, removed, or re-shaped at any
//! time without a semver bump.

#![allow(missing_docs)]

pub use crate::archiver::validate_archive_path;
pub use crate::common::{KDF_PARAMS_SIZE, KdfParams, validate_tlv};
pub use crate::format::{
    PrivateKeyHeader, TYPE_HYBRID, TYPE_SYMMETRIC, parse_private_key_header,
    read_header_from_reader,
};
pub use crate::hybrid::validate_private_key_shape;
pub use crate::replication::decode;

use crate::CryptoError;
use crate::error::FormatDefect;

/// Decodes a triple-replicated payload and verifies its logical
/// length equals `expected_len`. Wraps [`decode`] with a
/// `FormatDefect::CorruptedHeader` length check.
///
/// Lives here (rather than in `replication.rs`) because the library
/// itself never calls it — the one replicated field in v1, the 8-byte
/// `.fcr` prefix, goes through [`crate::format::decode_and_canonicalize_prefix`],
/// which performs the length check implicitly by fixed-size array
/// typing. The fuzz harness (`fuzz_replication_decode`) drives this
/// path directly to exercise the length-mismatch rejection without
/// paying for a full header parse.
pub fn decode_exact(data: &[u8], expected_len: usize) -> Result<Vec<u8>, CryptoError> {
    let decoded = decode(data)?;
    if decoded.len() != expected_len {
        return Err(CryptoError::InvalidFormat(FormatDefect::CorruptedHeader));
    }
    Ok(decoded)
}
