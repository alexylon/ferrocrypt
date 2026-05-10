//! Internal parser-surface re-exports for the in-repo fuzz targets.
//!
//! Gated behind the `fuzzing` Cargo feature so library consumers never
//! see these items. The only crate that enables the feature is
//! `ferrocrypt-lib/fuzz`, where each target drives a specific parser
//! at the lowest useful layer (encrypted-file header parse, private-
//! key header + body shape, KDF-parameter bounds, TLV grammar,
//! recipient-string Bech32 grammar) without paying the cost of
//! running a full Argon2id derivation.
//!
//! **Not a stable API.** Do not depend on this module from outside
//! the repository. Items here may be renamed, removed, or re-shaped
//! at any time without a semver bump.

#![allow(missing_docs)]

pub use crate::archive::format::{parse_fca_header, parse_manifest_bytes};
pub use crate::archive::model::{ArchiveEntry, ArchiveEntryKind, FcaHeader, Manifest};
pub use crate::archive::path::{ascii_case_collision_key, validate_fca_path};
pub use crate::crypto::kdf::{KDF_PARAMS_SIZE, KdfParams};
pub use crate::crypto::tlv::validate_tlv;
pub use crate::key::private::PrivateKeyHeader;
pub use crate::key::public::RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT;
pub use crate::recipient::native::x25519::validate_private_key_shape;

// `HeaderReadLimits` is part of the stable public API; re-export the
// crate-internal `read_encrypted_header` here so fuzz targets can drive
// the parser without paying the cost of a full Argon2id derivation.
pub use crate::HeaderReadLimits;

pub fn read_encrypted_header<R: std::io::Read>(
    reader: &mut R,
    limits: HeaderReadLimits,
) -> Result<(), crate::CryptoError> {
    crate::container::read_encrypted_header(reader, limits).map(|_| ())
}

/// Wraps the crate-internal `validate_no_known_critical` so fuzz
/// targets can drive the TLV scanner over FCA `archive_ext` /
/// `entry_ext` regions without paying the cost of a full archive
/// extraction. Mirrors the policy production callers use: scan +
/// reject any critical-range tag.
pub fn validate_no_known_critical(
    bytes: &[u8],
    max_region_len: u32,
    max_value_len: u32,
) -> Result<(), crate::CryptoError> {
    crate::crypto::tlv::validate_no_known_critical(bytes, max_region_len, max_value_len)
}

/// Drives `decode_recipient_string` for fuzz targets without leaking
/// the parsed [`crate::key::public::DecodedRecipient`] type (which
/// carries a crate-internal `KeypairSuite` enum). Discards the result
/// so the fuzzer exercises the parser surface without touching
/// internal types.
pub fn decode_recipient_string(s: &str, local_max_chars: usize) -> Result<(), crate::CryptoError> {
    crate::key::public::decode_recipient_string(s, local_max_chars).map(|_| ())
}

pub use crate::archive::IncompleteOutputPolicy;

/// Drives the full FCA reader pipeline (`archive::unarchive`) on
/// arbitrary bytes for the `fuzz_fca_full_pipeline` target: header
/// parse, archive-ext TLV validation, manifest parse, tree
/// validation, content streaming, atomic promotion. Wraps the
/// generic-`R` underlying function so the fuzz target can call
/// through a concrete signature.
///
/// `output_dir` is the per-iteration tempdir the fuzz harness creates;
/// the policy is fixed to `DeleteOnError` so partial extractions are
/// cleaned up before the tempdir drops, keeping per-iteration disk
/// pressure bounded.
pub fn unarchive_for_fuzz(
    bytes: &[u8],
    output_dir: &std::path::Path,
    limits: crate::ArchiveLimits,
) -> Result<std::path::PathBuf, crate::CryptoError> {
    use std::io::Cursor;
    crate::archive::unarchive(
        Cursor::new(bytes),
        output_dir,
        limits,
        IncompleteOutputPolicy::DeleteOnError,
    )
}
