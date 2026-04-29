//! Symmetric (passphrase-based) `.fcr` encrypt and decrypt.
//!
//! Pipeline:
//!   per-file random `file_key` (32 B)
//!   passphrase + Argon2id + HKDF-SHA3-256 → `wrap_key`
//!   `wrap_key` + XChaCha20-Poly1305 seals `file_key` into the
//!     argon2id recipient body (116 B; see `recipients::argon2id`)
//!   `file_key` + `stream_nonce` + HKDF-SHA3-256 → `payload_key` + `header_key`
//!   `payload_key` encrypts the TAR payload via STREAM-BE32
//!   `header_key` HMAC-SHA3-256 authenticates the on-disk header
//!
//! Wire format: a v1 `.fcr` container with exactly one `argon2id`
//! recipient entry (the `argon2id::wrap` body lives in the recipient
//! list). See `ferrocrypt-lib/FORMAT.md` §3 and `container.rs` for
//! the shared header layout.

use std::fs;
use std::path::{Path, PathBuf};

use secrecy::SecretString;

use crate::archiver::{ArchiveLimits, unarchive};
use crate::common::{
    DerivedSubkeys, KdfLimit, KdfParams, STREAM_NONCE_SIZE, derive_subkeys, encryption_base_name,
    generate_file_key, payload_decryptor, random_bytes, validate_tlv,
};
use crate::container::{
    HeaderReadLimits, build_encrypted_header, read_encrypted_header, write_encrypted_file,
};
use crate::format;
use crate::recipients::{
    NativeRecipientType, RecipientEntry, argon2id, enforce_recipient_mixing_policy,
};
use crate::{CryptoError, ProgressEvent};

/// Encrypts a file or directory under a passphrase. Input is archived
/// into a TAR stream and encrypted directly to the output file — no
/// plaintext intermediate files touch disk.
///
/// Wire format: a v1 `.fcr` container with exactly one `argon2id`
/// recipient entry. Per `FORMAT.md` §3.4, `argon2id` is exclusive:
/// the recipient list contains only this one entry. The `file_key`
/// is wrapped via [`recipients::argon2id::wrap`]; the rest of the
/// header (prefix, fixed, recipient_entries, MAC) is assembled by
/// [`container::build_encrypted_header`], which is the single
/// source of truth for MAC scope.
pub fn encrypt_file(
    input_path: &Path,
    output_dir: &Path,
    passphrase: &SecretString,
    output_file: Option<&Path>,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    on_event(&ProgressEvent::DerivingKey);

    // Generate per-file random material first so the rest of the
    // build is a pure function of (file_key, passphrase, stream_nonce,
    // input bytes). file_key lives in `Zeroizing`, so an early return
    // wipes it.
    let file_key = generate_file_key();
    let stream_nonce = random_bytes::<STREAM_NONCE_SIZE>();
    let DerivedSubkeys {
        payload_key,
        header_key,
    } = derive_subkeys(&file_key, &stream_nonce)?;

    // Wrap the file_key with the passphrase via `argon2id` — Argon2id
    // and the wrap-key derivation run inside this call. After the
    // body is built, the raw file_key is no longer needed; drop it
    // immediately so the plaintext window in memory is minimal.
    let kdf_params = KdfParams::default();
    let body = argon2id::wrap(&file_key, passphrase, &kdf_params)?;
    drop(file_key);

    let entry = RecipientEntry::native(NativeRecipientType::Argon2id, body.to_vec())?;

    // Assemble prefix + header + MAC. `build_encrypted_header` is the
    // single byte-arithmetic implementation; encrypt and decrypt
    // share its MAC scope. `payload_key` and `stream_nonce` move into
    // the returned bundle so the writer cannot be paired with material
    // from a different derivation.
    let built = build_encrypted_header(
        std::slice::from_ref(&entry),
        b"", // v1.0 writers emit ext_len = 0
        stream_nonce,
        payload_key,
        &header_key,
    )?;
    drop(header_key);

    let base_name = encryption_base_name(input_path)?;
    on_event(&ProgressEvent::Encrypting);

    write_encrypted_file(
        input_path,
        output_dir,
        output_file,
        &base_name,
        &built,
        ArchiveLimits::default(),
    )
}

/// Decrypts a `.fcr` file produced by [`encrypt_file`]. Follows the
/// `FORMAT.md` §3.7 acceptance order:
///
/// 1. read + structurally validate the header (`read_encrypted_header`)
/// 2. enforce recipient mixing policy (BEFORE Argon2id, so a hostile
///    mixed-recipient file cannot force a KDF run)
/// 3. require exactly one `argon2id` recipient (the symmetric mode)
/// 4. require recipient flags == 0
/// 5. require body length == `recipients::argon2id::BODY_LENGTH`
/// 6. unwrap the candidate `file_key` via `recipients::argon2id::unwrap`
/// 7. derive `payload_key` + `header_key` from `file_key + stream_nonce`
/// 8. verify the header MAC under `header_key` (final acceptance gate
///    per `FORMAT.md` §3.7 — until this succeeds, the candidate is not
///    final)
/// 9. validate the TLV `ext_bytes` AFTER MAC verification
/// 10. STREAM-decrypt the payload and unarchive
pub fn decrypt_file(
    input_path: &Path,
    output_dir: &Path,
    passphrase: &SecretString,
    kdf_limit: Option<&KdfLimit>,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    let mut encrypted_file = fs::File::open(input_path)?;

    // 1. Structural read. Performs zero crypto, enforces local caps.
    let parsed = read_encrypted_header(&mut encrypted_file, HeaderReadLimits::default())?;

    // 2. Mixing policy BEFORE any KDF. A hostile mixed-recipient file
    //    (argon2id + anything else) is rejected here without spending
    //    Argon2id work on it.
    enforce_recipient_mixing_policy(&parsed.recipient_entries)?;

    // 3-5. Locate and shape-check the argon2id recipient body. After
    //    step 2, if any `argon2id` entry is present it is the only
    //    entry, so this either succeeds with the unique slot or there
    //    is no passphrase recipient in the file at all (e.g. caller
    //    invoked `symmetric_decrypt` on a hybrid `.fcr` — surfaces as
    //    `NoSupportedRecipient` so the user knows to switch modes).
    let body = find_argon2id_body(&parsed.recipient_entries)?;

    // 6. Argon2id unwrap. KDF parameter bounds and `kdf_limit` are
    //    checked inside `unwrap` BEFORE Argon2id runs; wrong
    //    passphrase and tampered envelope both surface as
    //    `RecipientUnwrapFailed { type_name: "argon2id" }`.
    on_event(&ProgressEvent::DerivingKey);
    let file_key = argon2id::unwrap(&body, passphrase, kdf_limit)?;

    // 7. Subkeys.
    let stream_nonce = parsed.fixed.stream_nonce;
    let DerivedSubkeys {
        payload_key,
        header_key,
    } = derive_subkeys(&file_key, &stream_nonce)?;
    drop(file_key);

    // 8. Header MAC verify — the FINAL acceptance gate. Until this
    //    succeeds the candidate `file_key` is not trusted, per
    //    `FORMAT.md` §3.7. For symmetric there is exactly one
    //    candidate, so a MAC failure is the bare `HeaderTampered`
    //    rather than a per-candidate variant.
    format::verify_header_mac(
        &parsed.prefix_bytes,
        &parsed.header_bytes,
        &header_key,
        &parsed.header_mac,
    )?;
    drop(header_key);

    // 9. TLV validation runs AFTER MAC verify, so the validator is
    //    operating on authenticated bytes.
    validate_tlv(&parsed.ext_bytes)?;

    // 10. STREAM payload decrypt + unarchive.
    on_event(&ProgressEvent::Decrypting);
    let decrypt_reader = payload_decryptor(&payload_key, &stream_nonce, encrypted_file);
    unarchive(decrypt_reader, output_dir, ArchiveLimits::default())
}

/// Locates the unique `argon2id` recipient and returns its body as a
/// canonical `BODY_LENGTH`-sized fixed array. Per `FORMAT.md` §3.7
/// steps 3-5: the entry exists (one and only one — the mixing-policy
/// check upstream guarantees uniqueness), and its structural shape
/// passes [`RecipientEntry::expect_native_body`] (zero flags + correct
/// body length).
///
/// Absence of an `argon2id` entry surfaces as
/// [`CryptoError::NoSupportedRecipient`] (the canonical "wrong mode"
/// diagnostic for callers who invoked `symmetric_decrypt` on a hybrid
/// `.fcr`); structural anomalies surface as
/// [`FormatDefect::MalformedRecipientEntry`].
fn find_argon2id_body(
    entries: &[RecipientEntry],
) -> Result<[u8; argon2id::BODY_LENGTH], CryptoError> {
    entries
        .iter()
        .find(|e| e.type_name == argon2id::TYPE_NAME)
        .ok_or(CryptoError::NoSupportedRecipient)?
        .expect_native_body()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{ARGON2_SALT_SIZE, KDF_PARAMS_SIZE, WRAP_NONCE_SIZE};
    use crate::error::FormatDefect;
    use crate::format::{HEADER_FIXED_SIZE, PREFIX_SIZE};
    use crate::recipients::ENTRY_HEADER_SIZE;

    /// File offset of `stream_nonce`. It is the trailing field of
    /// `header_fixed`, so the offset within `header_fixed` is
    /// `HEADER_FIXED_SIZE - STREAM_NONCE_SIZE`; add `PREFIX_SIZE` for
    /// the absolute file offset.
    const STREAM_NONCE_FILE_OFFSET: usize = PREFIX_SIZE + HEADER_FIXED_SIZE - STREAM_NONCE_SIZE;

    /// File offset of the start of the lone `argon2id` recipient body
    /// (per `FORMAT.md` §3.5): prefix + fixed header + entry header
    /// + the `"argon2id"` `type_name`.
    const ARGON2ID_BODY_FILE_OFFSET: usize =
        PREFIX_SIZE + HEADER_FIXED_SIZE + ENTRY_HEADER_SIZE + argon2id::TYPE_NAME.len();

    /// Offset of `wrapped_file_key` inside the `argon2id` body
    /// (per `FORMAT.md` §4.1): salt || kdf_params || wrap_nonce
    /// precede it.
    const ARGON2ID_WRAPPED_FILE_KEY_BODY_OFFSET: usize =
        ARGON2_SALT_SIZE + KDF_PARAMS_SIZE + WRAP_NONCE_SIZE;

    /// Harness: set up a tempdir with encrypted/ and decrypted/
    /// subdirs, write `content` to a `data.txt` input, and encrypt it
    /// under `passphrase`. Returns `(tempdir, encrypted_fcr_path,
    /// decrypted_dir, passphrase)`. The tempdir is returned so tests
    /// can keep it alive through the decrypt step.
    fn encrypt_fixture(
        content: &str,
        passphrase: &str,
    ) -> Result<(tempfile::TempDir, PathBuf, PathBuf, SecretString), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let input = tmp.path().join("data.txt");
        let enc_dir = tmp.path().join("encrypted");
        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&enc_dir)?;
        fs::create_dir_all(&dec_dir)?;
        fs::write(&input, content)?;
        let pass = SecretString::from(passphrase.to_string());
        encrypt_file(&input, &enc_dir, &pass, None, &|_| {})?;
        let fcr = enc_dir.join("data.fcr");
        Ok((tmp, fcr, dec_dir, pass))
    }

    /// Minimal round-trip: encrypt a file, decrypt it, compare contents.
    #[test]
    fn encrypt_decrypt_round_trip() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, pass) = encrypt_fixture("round trip payload", "pass")?;
        assert!(fcr.exists());
        decrypt_file(&fcr, &dec_dir, &pass, None, &|_| {})?;
        let restored = fs::read_to_string(dec_dir.join("data.txt"))?;
        assert_eq!(restored, "round trip payload");
        Ok(())
    }

    /// Wrong passphrase must surface as `RecipientUnwrapFailed` with
    /// `type_name == "argon2id"` at the recipient-unwrap step — NOT
    /// `HeaderTampered` — so the user sees a passphrase-specific
    /// diagnostic.
    #[test]
    fn decrypt_with_wrong_passphrase_fails_at_envelope() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, _right) = encrypt_fixture("x", "right")?;
        let wrong = SecretString::from("wrong".to_string());
        match decrypt_file(&fcr, &dec_dir, &wrong, None, &|_| {}) {
            Err(CryptoError::RecipientUnwrapFailed { ref type_name })
                if type_name == argon2id::TYPE_NAME =>
            {
                Ok(())
            }
            other => panic!("expected RecipientUnwrapFailed(argon2id), got {other:?}"),
        }
    }

    /// After successful envelope unwrap, tampering with `stream_nonce`
    /// must surface as `HeaderTampered` (not envelope failure) because
    /// the right passphrase unlocked the recipient body but the
    /// header MAC no longer matches.
    #[test]
    fn decrypt_with_tampered_stream_nonce_fails_at_hmac() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, pass) = encrypt_fixture("x", "pass")?;
        let mut bytes = fs::read(&fcr)?;
        bytes[STREAM_NONCE_FILE_OFFSET] ^= 0xFF;
        fs::write(&fcr, &bytes)?;
        match decrypt_file(&fcr, &dec_dir, &pass, None, &|_| {}) {
            Err(CryptoError::HeaderTampered) => Ok(()),
            other => panic!("expected HeaderTampered, got {other:?}"),
        }
    }

    /// Tampering inside the argon2id recipient body's
    /// `wrapped_file_key` must surface at AEAD-open time as
    /// `RecipientUnwrapFailed { type_name: "argon2id" }`.
    #[test]
    fn decrypt_with_tampered_envelope_fails_at_unwrap() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, pass) = encrypt_fixture("x", "pass")?;
        let mut bytes = fs::read(&fcr)?;
        let wrapped_offset = ARGON2ID_BODY_FILE_OFFSET + ARGON2ID_WRAPPED_FILE_KEY_BODY_OFFSET;
        bytes[wrapped_offset] ^= 0x01;
        fs::write(&fcr, &bytes)?;
        match decrypt_file(&fcr, &dec_dir, &pass, None, &|_| {}) {
            Err(CryptoError::RecipientUnwrapFailed { ref type_name })
                if type_name == argon2id::TYPE_NAME =>
            {
                Ok(())
            }
            other => panic!("expected RecipientUnwrapFailed(argon2id), got {other:?}"),
        }
    }

    /// A flipped byte in the magic prefix surfaces as `BadMagic`
    /// before any crypto or recipient work runs. The magic-byte check
    /// at the start of the prefix is the structural gate.
    #[test]
    fn decrypt_with_tampered_magic_fails_at_prefix_check() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, pass) = encrypt_fixture("x", "pass")?;
        let mut bytes = fs::read(&fcr)?;
        bytes[0] ^= 0xFF;
        fs::write(&fcr, &bytes)?;
        match decrypt_file(&fcr, &dec_dir, &pass, None, &|_| {}) {
            Err(CryptoError::InvalidFormat(FormatDefect::BadMagic)) => Ok(()),
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    /// A truncated file (cut mid-STREAM) surfaces as
    /// `PayloadTruncated` or `PayloadTampered` depending on where the
    /// cut lands; either way, the header stage must have succeeded
    /// first. Confirms the header is independently authenticated.
    #[test]
    fn decrypt_truncated_payload_fails_after_header() -> Result<(), CryptoError> {
        let (_tmp, fcr, dec_dir, pass) = encrypt_fixture("truncation test", "pass")?;
        let mut bytes = fs::read(&fcr)?;
        // Drop the last 16 bytes so the STREAM final-flag chunk's tag
        // is missing / mid-chunk.
        bytes.truncate(bytes.len() - 16);
        fs::write(&fcr, &bytes)?;
        match decrypt_file(&fcr, &dec_dir, &pass, None, &|_| {}) {
            Err(CryptoError::PayloadTruncated) | Err(CryptoError::PayloadTampered) => Ok(()),
            other => panic!("expected PayloadTruncated or PayloadTampered, got {other:?}"),
        }
    }
}
