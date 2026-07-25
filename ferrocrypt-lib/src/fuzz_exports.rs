//! Internal parser-surface re-exports for the in-repo fuzz targets.
//!
//! Gated behind the `fuzzing` Cargo feature so library consumers never
//! see these items. The only crate that enables the feature is
//! `ferrocrypt-lib/fuzz`, where each target drives a specific parser at
//! the lowest useful layer without paying for unrelated cryptographic
//! work.
//!
//! **Not a stable API.** Do not depend on this module from outside
//! the repository. Items here may be renamed, removed, or re-shaped
//! at any time without a semver bump.

#![allow(missing_docs)]

pub use crate::archive::format::{parse_fca_header, parse_manifest_bytes};
pub use crate::archive::model::{ArchiveEntry, ArchiveEntryKind, FcaHeader, Manifest};
pub use crate::archive::path::{
    FCA_COMPONENT_MAX_BYTES, ascii_case_collision_key, validate_fca_path,
};
pub use crate::crypto::kdf::{KDF_PARAMS_SIZE, KdfParams};
pub use crate::crypto::tlv::validate_tlv;
pub use crate::fs::paths::INCOMPLETE_SUFFIX;
pub use crate::key::private::PrivateKeyHeader;
pub use crate::key::public::RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT;
pub use crate::recipient::native::x25519::validate_private_key_shape;

/// Drives the full `private.key` load + unlock over attacker-controlled bytes
/// with a fixed passphrase and a tight 64 KiB Argon2id memory cap. This reaches
/// past the shape gate that [`validate_private_key_shape`] stops at: the KDF
/// resource cap, the wrapped-secret cap, the total-length check, type-name
/// grammar, AEAD-AAD unlock, and the recipient's public/secret derivation
/// check. Any file demanding more than 64 KiB of KDF memory is rejected before
/// Argon2id runs, so every iteration stays cheap.
pub fn open_private_key_for_fuzz(bytes: &[u8]) -> Result<(), crate::CryptoError> {
    let passphrase = secrecy::SecretString::from("fuzz-passphrase".to_string());
    let limit = crate::KdfLimit::new(64);
    crate::key::private::open_private_key(
        bytes,
        &passphrase,
        Some(&limit),
        crate::KeyReadLimits::default().private_key_wrapped_secret_len(),
        &|_| {},
    )
    .map(|_| ())
}

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

/// Drives the `public.key` content parser over arbitrary bytes without
/// exposing the crate-internal resolved-key type, under the default
/// [`crate::KeyReadLimits`]. The bounded filesystem read remains in
/// `read_public_key`.
pub fn parse_public_key_file_bytes(bytes: &[u8]) -> Result<(), crate::CryptoError> {
    crate::key::public::parse_public_key_file_bytes(bytes, crate::KeyReadLimits::default())
        .map(|_| ())
}

/// Writer-side counterpart for the `fuzz_fca_manifest` round-trip
/// assert: serialises a parsed [`Manifest`] through the production
/// writer gate. Per the encrypt/decrypt symmetry rule, a manifest the
/// reader accepted must pass this gate and serialize byte-identically.
pub fn serialize_manifest(
    manifest: &Manifest,
    limits: crate::ArchiveLimits,
) -> Result<Vec<u8>, crate::CryptoError> {
    crate::archive::format::serialize_manifest(manifest, limits)
}

/// Drives the production FCA writer for corpus-seed generation
/// (`fuzz/examples/gen_seeds.rs`): archives `input_path` into plain
/// FCA bytes under default limits.
pub fn archive_for_fuzz(input_path: &std::path::Path) -> Result<Vec<u8>, crate::CryptoError> {
    crate::archive::archive(input_path, Vec::new(), crate::ArchiveLimits::default())
}

/// Fixed key and nonce for the STREAM fuzz harness. Deterministic on
/// purpose: libfuzzer crash reproduction requires identical behavior
/// for identical input bytes, and corpus seeds built by
/// [`encrypt_stream_for_fuzz`] must stay decryptable across runs.
fn fuzz_payload_key() -> crate::crypto::keys::PayloadKey {
    crate::crypto::keys::PayloadKey::from_bytes_for_tests(
        [0x42; crate::crypto::keys::ENCRYPTION_KEY_SIZE],
    )
}

const FUZZ_STREAM_NONCE: [u8; crate::crypto::stream::STREAM_NONCE_SIZE] =
    [0x24; crate::crypto::stream::STREAM_NONCE_SIZE];

/// Builds a STREAM-BE32 `DecryptReader` over `ciphertext` for the
/// `fuzz_stream_decrypt` target. The target exercises chunk refill,
/// exact-chunk lookahead, error classification, and the rule that all
/// later reads fail after the first error. End-to-end decrypt targets
/// cannot reach this layer with arbitrary ciphertext because the
/// header MAC is verified first; this helper tests the cipher layer
/// directly.
pub fn stream_decryptor_for_fuzz(ciphertext: &[u8]) -> impl std::io::Read + '_ {
    crate::crypto::stream::payload_decryptor(&fuzz_payload_key(), &FUZZ_STREAM_NONCE, ciphertext)
}

/// Decrypts in one call through [`stream_decryptor_for_fuzz`]. Used by
/// the corpus-seed round-trip checks in `fuzz/examples/gen_seeds.rs`.
pub fn decrypt_stream_for_fuzz(ciphertext: &[u8]) -> Result<Vec<u8>, crate::CryptoError> {
    use std::io::Read as _;
    let mut plaintext = Vec::new();
    stream_decryptor_for_fuzz(ciphertext).read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

/// Encrypt counterpart of [`decrypt_stream_for_fuzz`] under the same
/// fixed key and nonce. Used to generate valid corpus seeds and as the
/// round-trip oracle inside the target: STREAM is deterministic, so
/// any accepted ciphertext must re-encrypt byte-identically from its
/// recovered plaintext.
pub fn encrypt_stream_for_fuzz(plaintext: &[u8]) -> Result<Vec<u8>, crate::CryptoError> {
    use std::io::Write as _;
    let mut writer = crate::crypto::stream::payload_encryptor(
        &fuzz_payload_key(),
        &FUZZ_STREAM_NONCE,
        Vec::new(),
    );
    writer.write_all(plaintext)?;
    writer.finish()
}

/// Builds the authenticated but non-canonical STREAM shape that
/// `FORMAT.md` §5 requires readers to reject: one full non-final plaintext
/// chunk followed by an empty final chunk. Kept in the fuzz-only surface so
/// corpus generation can reach a valid-tag negative case that mutation cannot
/// synthesize without the fixed payload key.
pub fn empty_final_after_data_stream_for_fuzz() -> Result<Vec<u8>, crate::CryptoError> {
    use chacha20poly1305::{
        XChaCha20Poly1305,
        aead::{KeyInit as _, stream},
    };

    let payload_key = fuzz_payload_key();
    let cipher = XChaCha20Poly1305::new(payload_key.expose().into());
    let mut encryptor = stream::EncryptorBE32::from_aead(cipher, (&FUZZ_STREAM_NONCE).into());
    let mut ciphertext: Vec<u8> = (0..crate::crypto::stream::BUFFER_SIZE)
        .map(|i| (i % 251) as u8)
        .collect();
    encryptor
        .encrypt_next_in_place(b"", &mut ciphertext)
        .map_err(|_| {
            crate::CryptoError::InternalCryptoFailure("fuzz non-final encryption failed")
        })?;
    let mut empty_final = Vec::new();
    encryptor
        .encrypt_last_in_place(b"", &mut empty_final)
        .map_err(|_| {
            crate::CryptoError::InternalCryptoFailure("fuzz empty-final encryption failed")
        })?;
    ciphertext.extend_from_slice(&empty_final);
    Ok(ciphertext)
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
