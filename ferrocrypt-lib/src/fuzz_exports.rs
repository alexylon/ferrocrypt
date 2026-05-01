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

pub use crate::archive::path::validate_archive_path_components;
pub use crate::crypto::kdf::{KDF_PARAMS_SIZE, KdfParams};
pub use crate::crypto::tlv::validate_tlv;
pub use crate::key::private::PrivateKeyHeader;
pub use crate::key::public::{RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT, decode_recipient_string};
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
