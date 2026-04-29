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

pub use crate::archiver::validate_archive_path;
pub use crate::crypto::kdf::{KDF_PARAMS_SIZE, KdfParams};
pub use crate::crypto::tlv::validate_tlv;
pub use crate::hybrid::validate_private_key_shape;
pub use crate::key::private::PrivateKeyHeader;
pub use crate::key::public::{RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT, decode_recipient_string};

// Re-exports of `container` items used by `fuzz_header_prefix`.
// The items themselves are `pub(crate)` inside the module; this thin
// wrapper bridges them into the (feature-gated) `fuzz_exports` public
// surface without changing their crate-internal visibility.
pub struct HeaderReadLimits(crate::container::HeaderReadLimits);

impl Default for HeaderReadLimits {
    fn default() -> Self {
        Self(crate::container::HeaderReadLimits::default())
    }
}

pub fn read_encrypted_header<R: std::io::Read>(
    reader: &mut R,
    limits: HeaderReadLimits,
) -> Result<(), crate::CryptoError> {
    crate::container::read_encrypted_header(reader, limits.0).map(|_| ())
}
