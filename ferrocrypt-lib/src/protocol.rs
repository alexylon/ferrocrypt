//! High-level FerroCrypt operation flow.
//!
//! This is the only module that may coordinate all of:
//!
//! 1. generating a file key,
//! 2. generating the stream nonce,
//! 3. calling recipient schemes to wrap the file key,
//! 4. building the authenticated header,
//! 5. calling archive encoding/decoding,
//! 6. constructing payload stream encryptors/decryptors,
//! 7. finalising staged output,
//! 8. emitting progress events.
//!
//! Algorithm-specific logic plugs in via the [`RecipientScheme`] /
//! [`IdentityScheme`] traits — both `pub(crate)`. Recipient modules
//! produce / consume opaque [`RecipientBody`] bytes; only this module
//! constructs full headers or verifies the header MAC.
//!
//! ## Decrypt acceptance order (`FORMAT.md` §3.7)
//!
//! 1. Read prefix.
//! 2. Reject bad magic / version / kind / flags / header length.
//! 3. Read header and header MAC.
//! 4. Structurally parse header and recipient entries.
//! 5. Reject malformed flags, unknown critical recipients, illegal
//!    mixing.
//! 6. Apply local resource caps.
//! 7. Iterate supported recipient slots in declared order.
//! 8. Verify header MAC with the candidate `FileKey` — final
//!    acceptance gate per slot.
//! 9. Validate authenticated TLV bytes only after MAC success.
//! 10. Derive payload key.
//! 11. STREAM-decrypt the payload.
//! 12. Decode the archive with path / resource checks before writes.
//! 13. Promote staged output only on success.
//!
//! No refactor may move TLV interpretation, archive writes, or payload
//! plaintext release before the relevant authentication step.

use std::fs;
use std::path::{Path, PathBuf};

use crate::archive::{ArchiveLimits, unarchive};
use crate::container::{
    HeaderReadLimits, build_encrypted_header, read_encrypted_header, write_encrypted_file,
};
use crate::crypto::keys::{DerivedSubkeys, FileKey, derive_subkeys, random_bytes};
use crate::crypto::stream::{STREAM_NONCE_SIZE, payload_decryptor};
use crate::crypto::tlv::validate_tlv;
use crate::error::CryptoError;
use crate::format;
use crate::fs::paths::encryption_base_name;
use crate::recipient::entry::{RecipientBody, RecipientEntry};
#[cfg(test)]
use crate::recipient::policy::MixingPolicy;
use crate::recipient::policy::{NativeMixingRule, NativeRecipientType, classify_encryption_mode};
use crate::{EncryptionMode, ProgressEvent};

/// Encrypt-side scheme: turn a [`FileKey`] into a recipient body of
/// scheme-specific bytes.
///
/// `TYPE_NAME` and `MIXING_RULE` are associated constants so the
/// multi-recipient `encrypt` orchestrator can enforce the mixing rule
/// before any KDF runs. Implementations must NOT build full
/// [`RecipientEntry`] framing or compute the header MAC — those
/// concerns live in this module.
pub(crate) trait RecipientScheme {
    const TYPE_NAME: &'static str;
    const MIXING_RULE: NativeMixingRule;

    fn wrap_file_key(&self, file_key: &FileKey) -> Result<RecipientBody, CryptoError>;
}

/// Decrypt-side scheme: try to unwrap a candidate [`FileKey`] from a
/// recipient body whose `type_name` already matched
/// `IdentityScheme::TYPE_NAME` — the orchestrator pre-filters slots
/// before calling this.
///
/// Return shape:
///
/// - `Ok(Some(file_key))` — AEAD authentication succeeded; the caller
///   now MUST verify the header MAC under the derived `header_key`
///   before accepting the candidate (`FORMAT.md` §3.7 step 8).
/// - `Ok(None)` — AEAD authentication failed on a structurally-valid
///   body. Caller skips this slot and tries the next supported one.
///   This is the ONLY meaning of `Ok(None)`; hard failures (KDF cap
///   exceeded, malformed embedded KDF params, structural defects in
///   the body shape) are `Err(CryptoError::*)`.
pub(crate) trait IdentityScheme {
    const TYPE_NAME: &'static str;
    /// File mode this identity scheme can decrypt. Used by the
    /// orchestrator to surface a typed
    /// [`CryptoError::DecryptorModeMismatch`] when a caller drives
    /// `decrypt` with the wrong identity for the file's recipient list.
    const EXPECTED_MODE: EncryptionMode;

    fn unwrap_file_key(&self, body: &RecipientBody) -> Result<Option<FileKey>, CryptoError>;
}

// ─── Encrypt ───────────────────────────────────────────────────────────────

/// Encrypts `input_path` under one or more recipients of a single
/// scheme. Wire format is the v1 `.fcr` container with `recipients.len()`
/// entries whose type matches `R::TYPE_NAME`. Every entry seals the same
/// per-file `file_key` for its respective recipient.
///
/// Defense-in-depth checks:
///
/// - `recipients` MUST be non-empty (the public API enforces this at
///   construction time; the orchestrator double-checks).
/// - If `R::MIXING_RULE.requires_single_entry()` then `recipients.len()`
///   MUST be exactly 1. The public API can only reach this code with a
///   single passphrase, but the assertion stops a future caller bypass
///   from emitting an `argon2id` file with two bodies (`FORMAT.md` §4.1
///   forbids it).
pub(crate) fn encrypt<R: RecipientScheme>(
    recipients: &[R],
    archive_limits: ArchiveLimits,
    input_path: &Path,
    output_dir: &Path,
    output_file: Option<&Path>,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    if recipients.is_empty() {
        return Err(CryptoError::EmptyRecipientList);
    }
    if R::MIXING_RULE.requires_single_entry() && recipients.len() > 1 {
        return Err(CryptoError::IncompatibleRecipients {
            type_name: R::TYPE_NAME.to_string(),
            policy: R::MIXING_RULE.diagnostic_policy(),
        });
    }

    on_event(&ProgressEvent::DerivingKey);

    // Generate per-file random material first so the rest of the build
    // is a pure function of (file_key, recipient input, stream_nonce,
    // input bytes). file_key is held in `Zeroizing` inside the typed
    // newtype, so an early return wipes it.
    let file_key = FileKey::generate();
    let stream_nonce = random_bytes::<STREAM_NONCE_SIZE>();
    let DerivedSubkeys {
        payload_key,
        header_key,
    } = derive_subkeys(&file_key, &stream_nonce)?;

    // Wrap the file_key for each recipient under the same scheme. After
    // the bodies are built, the raw file_key is no longer needed; drop
    // it immediately so the plaintext window in memory is minimal.
    let mut entries = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let body = recipient.wrap_file_key(&file_key)?;
        entries.push(build_native_entry(R::TYPE_NAME, body)?);
    }
    drop(file_key);

    // Assemble prefix + header + MAC. `build_encrypted_header` owns the
    // single byte-arithmetic implementation; encrypt and decrypt share
    // its MAC scope.
    let built = build_encrypted_header(
        &entries,
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
        archive_limits,
    )
}

/// Builds a `RecipientEntry` from a scheme-produced body, validating
/// that the declared scheme is one of the recognised native types.
/// `RecipientEntry::native` enforces the canonical body length for the
/// type, so a scheme that returns the wrong number of bytes fails here.
fn build_native_entry(
    type_name: &'static str,
    body: RecipientBody,
) -> Result<RecipientEntry, CryptoError> {
    debug_assert_eq!(body.type_name, type_name);
    let ty = NativeRecipientType::from_type_name(type_name)
        .ok_or(CryptoError::InternalInvariant("Unknown native scheme"))?;
    RecipientEntry::native(ty, body.bytes)
}

// ─── Decrypt ───────────────────────────────────────────────────────────────

/// Decrypts `input_path` using the supplied identity scheme.
///
/// Iterates every supported recipient slot in declared order before
/// emitting a final verdict. The slot loop is identical for the
/// single-candidate (passphrase) and multi-candidate (X25519) cases —
/// the passphrase path is just a slot loop of length 1. Visiting every
/// supported slot, rather than short-circuiting on the first MAC
/// match, makes wall-clock cost a function of `recipient_count`
/// (capped by `HeaderReadLimits`) rather than of which slot matched,
/// per the `FORMAT.md` §3.7 SHOULD-level mitigation.
pub(crate) fn decrypt<I: IdentityScheme>(
    identity: &I,
    input_path: &Path,
    output_dir: &Path,
    archive_limits: ArchiveLimits,
    header_read_limits: HeaderReadLimits,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    let mut encrypted_file = fs::File::open(input_path)?;

    // 1-4. Structural read + parse. Performs zero crypto; enforces
    //      local caps before any allocation.
    let parsed = read_encrypted_header(&mut encrypted_file, header_read_limits)?;

    // 5. Reject illegal mixing and unknown critical recipients before
    //    any expensive recipient work. `classify_encryption_mode`
    //    runs `enforce_recipient_mixing_policy` internally, so the
    //    mixing-policy check happens here even though it isn't called
    //    by name.
    let mode = classify_encryption_mode(&parsed.recipient_entries)?;

    // Cross-mode mismatch: caller invoked the passphrase decrypt path
    // on a recipient-only file (or vice versa). The classified mode
    // does not match the identity's scheme. Surfaces as a typed
    // `DecryptorModeMismatch` rather than `NoSupportedRecipient`, which
    // would imply "the loop iterated and found nothing" — misleading
    // when the real cause is "wrong tool for this file." The public
    // API can't reach this branch (Decryptor::open routes by mode);
    // it exists for internal callers and any future plugin-style API.
    check_mode_matches_scheme::<I>(mode)?;

    // The caller (`PassphraseDecryptor::decrypt` / `RecipientDecryptor::decrypt`)
    // is responsible for emitting `DerivingKey` before the heaviest KDF
    // op — for the recipient path that's the `private.key` unlock
    // (which runs before this function), for the passphrase path it's
    // the slot-loop Argon2id (which runs inside this function).
    // Emitting it once at the call site keeps the event count to one
    // per decrypt regardless of mode.

    // 7-8. Iterate supported recipient slots. Per FORMAT.md §3.7 the
    //      candidate `file_key` is not final until the header MAC also
    //      verifies under the derived `header_key`.
    let stream_nonce = parsed.fixed.stream_nonce;
    let mut had_successful_unwrap = false;
    let mut selected_payload_key: Option<crate::crypto::keys::PayloadKey> = None;

    for entry in parsed.recipient_entries.iter() {
        if entry.type_name != I::TYPE_NAME {
            // Unknown non-critical entries: skipped. Critical unknowns
            // were rejected in step 5.
            continue;
        }
        // Native v1 recipients do not use the critical bit — the
        // reader handles them natively. A native entry with the bit
        // set is structurally malformed and aborts the whole file.
        if entry.recipient_flags != 0 {
            return Err(CryptoError::InvalidFormat(
                crate::error::FormatDefect::MalformedRecipientEntry,
            ));
        }
        let body = RecipientBody {
            type_name: I::TYPE_NAME,
            bytes: entry.body.clone(),
        };
        let file_key = match identity.unwrap_file_key(&body)? {
            Some(k) => k,
            None => continue,
        };
        had_successful_unwrap = true;

        let DerivedSubkeys {
            payload_key,
            header_key,
        } = derive_subkeys(&file_key, &stream_nonce)?;
        drop(file_key);

        // Header MAC is the final acceptance gate. The first slot
        // whose MAC verifies wins; the loop does NOT short-circuit
        // there — every supported slot still attempts unwrap, so wall
        // time does not betray which MAC-verified slot matched
        // (FORMAT.md §3.7 SHOULD-level mitigation). Slots whose AEAD
        // unwrap fails (`Ok(None)`) skip the `derive_subkeys` and the
        // `verify_header_mac` below, so a residual delta of
        // ~one HKDF + one HMAC remains between AEAD-pass and AEAD-fail
        // slots.
        if format::verify_header_mac(
            &parsed.prefix_bytes,
            &parsed.header_bytes,
            &header_key,
            &parsed.header_mac,
        )
        .is_ok()
            && selected_payload_key.is_none()
        {
            selected_payload_key = Some(payload_key);
        }
        drop(header_key);
    }

    let Some(payload_key) = selected_payload_key else {
        // No slot produced a candidate that MAC-verified. The error
        // wording depends on (a) whether any slot AEAD-unwrapped at
        // all, and (b) which mode the file is in — passphrase
        // single-recipient files surface bare `HeaderTampered` (no
        // slot identity is meaningful), recipient multi-slot files
        // surface the per-candidate `HeaderMacFailedAfterUnwrap`.
        return Err(failure_for(mode, I::TYPE_NAME, had_successful_unwrap));
    };

    // 9. TLV validation runs AFTER MAC verify, so the validator is
    //    operating on authenticated bytes.
    validate_tlv(&parsed.ext_bytes)?;

    // 10-12. STREAM payload decrypt + unarchive. Path / resource caps
    //        are enforced inside `unarchive` before any write.
    on_event(&ProgressEvent::Decrypting);
    let decrypt_reader = payload_decryptor(&payload_key, &stream_nonce, encrypted_file);
    unarchive(decrypt_reader, output_dir, archive_limits)
}

/// Verifies that the classified file mode matches the identity scheme's
/// declared [`IdentityScheme::EXPECTED_MODE`]. On mismatch, returns a
/// typed [`CryptoError::DecryptorModeMismatch`] carrying both modes so
/// the caller can pattern-match without comparing strings.
fn check_mode_matches_scheme<I: IdentityScheme>(mode: EncryptionMode) -> Result<(), CryptoError> {
    if mode == I::EXPECTED_MODE {
        return Ok(());
    }
    Err(CryptoError::DecryptorModeMismatch {
        expected: I::EXPECTED_MODE,
        found: mode,
    })
}

/// Decrypt-time error wording when no slot produced a MAC-verified
/// candidate. Differentiates by mode so the passphrase path keeps
/// emitting bare `HeaderTampered` (single recipient, no slot identity
/// to attach) while the recipient path emits the per-candidate
/// `HeaderMacFailedAfterUnwrap { type_name }` variant.
fn failure_for(mode: EncryptionMode, type_name: &'static str, had_unwrap: bool) -> CryptoError {
    if !had_unwrap {
        return CryptoError::RecipientUnwrapFailed {
            type_name: type_name.to_string(),
        };
    }
    match mode {
        EncryptionMode::Passphrase => CryptoError::HeaderTampered,
        EncryptionMode::Recipient => CryptoError::HeaderMacFailedAfterUnwrap {
            type_name: type_name.to_string(),
        },
    }
}

// ─── Key-pair generation ───────────────────────────────────────────────────

/// Generates an X25519 key pair and writes both files to `output_dir`.
/// Returns `(private_key_path, public_key_path)`.
///
/// - `private.key` is the v1 passphrase-wrapped binary keyfile.
///   `key::private::seal_private_key` owns the byte layout (cleartext
///   header → AEAD-AAD-bound → wrapped secret). Permissions: `0o600`
///   on Unix.
/// - `public.key` is a UTF-8 text file containing the canonical
///   `fcr1…` Bech32 recipient string. Permissions: `0o644` on Unix
///   (public keys are not secret).
pub(crate) fn generate_key_pair(
    passphrase: &secrecy::SecretString,
    output_dir: &Path,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<(PathBuf, PathBuf), CryptoError> {
    use std::io::Write as _;

    use crate::crypto::kdf::KdfParams;
    use crate::fs::atomic;
    use crate::key::files::{PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME};
    use crate::key::private::seal_private_key;
    use crate::key::public::encode_recipient_string;
    use crate::recipient::native::x25519;

    fs::create_dir_all(output_dir)?;

    // Existence pre-check BEFORE Argon2id so re-running `keygen` against
    // a populated directory returns a helpful error in milliseconds
    // instead of after ~1 GiB / multi-second KDF work. The atomic
    // no-clobber rename at `finalize_file` below is still what actually
    // guarantees we never overwrite an existing key; this check is just
    // a fast-path user-experience win.
    let private_key_path = output_dir.join(PRIVATE_KEY_FILENAME);
    let public_key_path = output_dir.join(PUBLIC_KEY_FILENAME);
    if private_key_path.exists() {
        return Err(CryptoError::InvalidInput(format!(
            "Key file already exists: {}",
            private_key_path.display()
        )));
    }
    if public_key_path.exists() {
        return Err(CryptoError::InvalidInput(format!(
            "Key file already exists: {}",
            public_key_path.display()
        )));
    }

    on_event(&ProgressEvent::GeneratingKeyPair);

    // Generate the X25519 keypair via the recipient module. The secret
    // material is returned in `Zeroizing` so it's wiped from memory
    // when this stack frame unwinds, regardless of whether the
    // subsequent seal/write succeeds.
    let (secret_material, public_material) = x25519::generate_keypair();

    // Hand off all `private.key` byte-layout, AEAD, and AAD scope to
    // `key/private.rs` — the single source of truth.
    let private_key_bytes = seal_private_key(
        secret_material.as_ref(),
        x25519::TYPE_NAME,
        &public_material,
        &[], // no v1 ext_bytes for the X25519 case
        passphrase,
        &KdfParams::default(),
    )?;
    drop(secret_material);

    // Encode the canonical `fcr1…` recipient string via `key/public.rs`
    // (validates type-name grammar, computes the internal SHA3-256
    // checksum, emits BIP 173 lowercase Bech32).
    let recipient_string = encode_recipient_string(x25519::TYPE_NAME, &public_material)?;

    // Write public.key (text file, `fcr1…\n`). Public key isn't secret
    // so permissions relax to 0o644 on Unix.
    let mut public_builder = tempfile::Builder::new();
    public_builder.prefix(".ferrocrypt-pubkey-").suffix(".tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        public_builder.permissions(fs::Permissions::from_mode(0o644));
    }
    let mut public_tmp = public_builder.tempfile_in(output_dir)?;
    public_tmp
        .as_file_mut()
        .write_all(recipient_string.as_bytes())?;
    public_tmp.as_file_mut().write_all(b"\n")?;
    public_tmp.as_file().sync_all()?;
    atomic::finalize_file(public_tmp, &public_key_path)?;

    // Write private.key. If this fails, clean up the public.key we
    // just wrote (public keys are not secret, but leaving orphaned
    // output is unfriendly).
    let private_write: Result<(), CryptoError> = (|| {
        let mut private_builder = tempfile::Builder::new();
        private_builder
            .prefix(".ferrocrypt-privkey-")
            .suffix(".tmp");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            private_builder.permissions(fs::Permissions::from_mode(0o600));
        }
        let mut private_tmp = private_builder.tempfile_in(output_dir)?;
        private_tmp.as_file_mut().write_all(&private_key_bytes)?;
        private_tmp.as_file().sync_all()?;
        atomic::finalize_file(private_tmp, &private_key_path)?;
        Ok(())
    })();

    if let Err(e) = private_write {
        let _ = fs::remove_file(&public_key_path);
        return Err(e);
    }

    Ok((private_key_path, public_key_path))
}

#[cfg(test)]
mod tests {
    //! Forward-compat multi-recipient tests (FORMAT.md §3.4 / §3.5).
    //!
    //! The single-recipient public encrypt API can't produce
    //! multi-recipient files, so these tests build the on-disk bytes
    //! by hand using `container::build_encrypted_header` and exercise
    //! the decrypt path against the resulting fixtures. They lock in:
    //! list iteration on `x25519`, skip unknown non-critical, reject
    //! unknown critical, reject argon2id mixing before any KDF runs,
    //! enforce the local body cap on unknown entries, and the
    //! attempt-all-slots timing-leak mitigation.
    //!
    //! Round-trip and basic tampering coverage lives in the
    //! integration test suite (`tests/integration_tests.rs`) plus the
    //! fixture-stability suite (`tests/fixture_stability.rs`).
    use super::*;
    use crate::container::build_encrypted_header;
    use crate::crypto::stream::payload_encryptor;
    use crate::error::FormatDefect;
    use crate::format;
    use crate::key::public::read_public_key;
    use crate::recipient::entry::RECIPIENT_FLAG_CRITICAL;
    use crate::recipient::native::{argon2id, x25519};
    use crate::recipient::policy::NativeRecipientType;
    use secrecy::SecretString;

    /// Build a complete `.fcr` byte sequence with the given recipient
    /// entries and plaintext. The caller has already wrapped `file_key`
    /// for each entry that actually needs to unwrap; entries with
    /// arbitrary bodies (synthetic unknown types, hostile mixes) are
    /// kept verbatim.
    fn build_multi_recipient_fcr(
        entries: &[RecipientEntry],
        file_key: &FileKey,
        plaintext: &[u8],
        path: &Path,
    ) -> Result<(), CryptoError> {
        let stream_nonce = random_bytes::<STREAM_NONCE_SIZE>();
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = derive_subkeys(file_key, &stream_nonce)?;

        let built = build_encrypted_header(entries, b"", stream_nonce, payload_key, &header_key)?;

        // Encrypt the TAR payload into a buffer.
        let mut payload_buf: Vec<u8> = Vec::new();
        {
            let writer =
                payload_encryptor(&built.payload_key, &built.stream_nonce, &mut payload_buf);
            let mut tar_builder = tar::Builder::new(writer);
            let mut header = tar::Header::new_ustar();
            header.set_path("data.txt").map_err(CryptoError::Io)?;
            header.set_size(plaintext.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            tar_builder
                .append(&header, plaintext)
                .map_err(CryptoError::Io)?;
            tar_builder.finish().map_err(CryptoError::Io)?;
            let writer = tar_builder.into_inner().map_err(CryptoError::Io)?;
            let _ = writer.finish()?;
        }

        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&built.prefix_bytes);
        buf.extend_from_slice(&built.header_bytes);
        buf.extend_from_slice(&built.header_mac);
        buf.extend_from_slice(&payload_buf);
        fs::write(path, &buf)?;
        Ok(())
    }

    /// Generates an X25519 keypair, persists a v1 `private.key` for it,
    /// and returns `(public_bytes, private_key_path, passphrase)`.
    fn keypair_fixture(
        keys_dir: &Path,
        label: &str,
        pass: &str,
    ) -> Result<([u8; 32], PathBuf, SecretString), CryptoError> {
        let pass = SecretString::from(pass.to_string());
        let dir = keys_dir.join(label);
        fs::create_dir_all(&dir)?;
        let (privkey_path, pubkey_path) = generate_key_pair(&pass, &dir, &|_| {})?;
        let pub_bytes = read_public_key(&pubkey_path)?;
        Ok((pub_bytes, privkey_path, pass))
    }

    /// Decrypt helper: opens the X25519 `private.key`, builds an
    /// `X25519Identity`, and runs the orchestrator's slot loop directly
    /// (mirrors what `RecipientDecryptor::decrypt` does in `api.rs` but
    /// preserves raw error variants for assertion).
    fn recipient_decrypt(
        fcr: &Path,
        dec_dir: &Path,
        privkey_path: &Path,
        pass: &SecretString,
    ) -> Result<PathBuf, CryptoError> {
        let recipient_secret = x25519::open_x25519_private_key(privkey_path, pass, None)?;
        let identity = x25519::X25519Identity { recipient_secret };
        decrypt(
            &identity,
            fcr,
            dec_dir,
            ArchiveLimits::default(),
            HeaderReadLimits::default(),
            &|_| {},
        )
    }

    /// Two `x25519` recipients in one file: the decrypt loop must
    /// iterate the list and accept whichever slot the caller's
    /// private key matches.
    #[test]
    fn multi_x25519_decrypts_via_either_recipient() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;
        let (pub_b, priv_b, pass_b) = keypair_fixture(&keys_dir, "bob", "bob-pass")?;

        let file_key = FileKey::generate();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let body_b = x25519::wrap(&file_key, &pub_b)?;
        let entries = [
            RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?,
            RecipientEntry::native(NativeRecipientType::X25519, body_b.to_vec())?,
        ];

        let payload = b"two-x25519 round trip";
        let fcr = tmp.path().join("multi.fcr");
        build_multi_recipient_fcr(&entries, &file_key, payload, &fcr)?;

        for (label, privkey, pass) in [("alice", &priv_a, &pass_a), ("bob", &priv_b, &pass_b)] {
            let dec_dir = tmp.path().join(format!("decrypted-{label}"));
            fs::create_dir_all(&dec_dir)?;
            recipient_decrypt(&fcr, &dec_dir, privkey, pass)?;
            let restored = fs::read(dec_dir.join("data.txt"))?;
            assert_eq!(
                restored, payload,
                "{label} should decrypt the same plaintext"
            );
        }
        Ok(())
    }

    /// FORMAT.md §3.7 SHOULD-level mitigation: the decrypt loop must
    /// visit every supported `x25519` slot before deciding, not
    /// short-circuit on the first MAC-verified one.
    #[test]
    fn multi_x25519_attempt_all_visits_every_slot() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let valid_slot = RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?;
        // Bypass `RecipientEntry::native`'s body-length validation —
        // the parser accepts any body_len within the local cap, so an
        // attacker-forged file can carry a wrong-length `x25519` slot
        // that we must reject.
        let malformed_slot = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_string(),
            recipient_flags: 0,
            body: vec![0u8; x25519::BODY_LENGTH - 4],
        };
        let entries = [valid_slot, malformed_slot];

        let fcr = tmp.path().join("multi-attempt-all.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"x", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        let err = recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a).unwrap_err();
        match err {
            CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry) => Ok(()),
            other => panic!(
                "expected MalformedRecipientEntry from slot-2 inspection (proves attempt-all); got {other:?}"
            ),
        }
    }

    /// FORMAT.md §2.4 / §4.2: an `x25519` recipient slot whose ECDH
    /// shared secret is all-zero MUST cause file-fatal rejection, not
    /// slot-skip — the all-zero shared is identity-independent
    /// (every decryptor observes the same value), so it cannot be
    /// confused with "this slot was for someone else." The decrypt
    /// loop must reject the whole file even when an earlier valid
    /// slot has already MAC-verified.
    #[test]
    fn multi_x25519_all_zero_ephemeral_after_valid_is_file_fatal() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let valid_slot = RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?;

        // Hand-craft a malformed `x25519` body: literal all-zero
        // ephemeral pubkey forces an all-zero ECDH shared secret per
        // RFC 7748 regardless of the recipient's private key. The rest
        // of the body is filler — the rejection fires before AEAD.
        let mut malformed_body = vec![0u8; x25519::BODY_LENGTH];
        malformed_body[x25519::BODY_LENGTH - 1] = 0xAB;
        let malformed_slot = RecipientEntry::native(NativeRecipientType::X25519, malformed_body)?;

        let entries = [valid_slot, malformed_slot];
        let fcr = tmp.path().join("zero-ephemeral-after.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"x", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        match recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => Ok(()),
            other => panic!("all-zero shared secret in slot 2 must be file-fatal, got {other:?}"),
        }
    }

    /// Same property as
    /// [`multi_x25519_all_zero_ephemeral_after_valid_is_file_fatal`] but
    /// with the malformed slot first. The decrypt loop encounters the
    /// structural defect before reaching the valid slot; it must still
    /// reject the whole file rather than continuing past the malformed
    /// entry.
    #[test]
    fn multi_x25519_all_zero_ephemeral_before_valid_is_file_fatal() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let valid_slot = RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?;

        let mut malformed_body = vec![0u8; x25519::BODY_LENGTH];
        malformed_body[x25519::BODY_LENGTH - 1] = 0xAB;
        let malformed_slot = RecipientEntry::native(NativeRecipientType::X25519, malformed_body)?;

        let entries = [malformed_slot, valid_slot];
        let fcr = tmp.path().join("zero-ephemeral-before.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"x", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        match recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => Ok(()),
            other => panic!("all-zero shared secret in slot 1 must be file-fatal, got {other:?}"),
        }
    }

    /// Single-recipient case: an `x25519` file with a single
    /// all-zero-ephemeral slot must also be file-fatal. Confirms the
    /// rejection path is independent of recipient cardinality.
    #[test]
    fn single_x25519_all_zero_ephemeral_is_file_fatal() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (_pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate();
        let mut malformed_body = vec![0u8; x25519::BODY_LENGTH];
        malformed_body[x25519::BODY_LENGTH - 1] = 0xAB;
        let entries = [RecipientEntry::native(
            NativeRecipientType::X25519,
            malformed_body,
        )?];

        let fcr = tmp.path().join("single-zero-ephemeral.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"x", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        match recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => Ok(()),
            other => panic!("single all-zero-ephemeral file must be file-fatal, got {other:?}"),
        }
    }

    /// One supported `x25519` recipient plus one unknown non-critical
    /// recipient: the decrypt loop must skip the unknown entry and
    /// decrypt via the supported one. Entry order matters here — we
    /// place the unknown FIRST.
    #[test]
    fn multi_x25519_plus_unknown_non_critical_skips_unknown() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let unknown_entry = RecipientEntry {
            type_name: "example.com/unknown".to_string(),
            recipient_flags: 0,
            body: vec![0xCDu8; 64],
        };
        let entries = [
            unknown_entry,
            RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?,
        ];

        let payload = b"skip unknown non-critical";
        let fcr = tmp.path().join("skip.fcr");
        build_multi_recipient_fcr(&entries, &file_key, payload, &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a)?;
        let restored = fs::read(dec_dir.join("data.txt"))?;
        assert_eq!(restored, payload);
        Ok(())
    }

    /// One supported `x25519` recipient plus one unknown CRITICAL
    /// recipient: the file MUST be rejected as
    /// `UnknownCriticalRecipient` before any recipient unwrap or KDF
    /// runs.
    #[test]
    fn multi_unknown_critical_rejected_before_any_unwrap() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let unknown_critical = RecipientEntry {
            type_name: "example.com/critical".to_string(),
            recipient_flags: RECIPIENT_FLAG_CRITICAL,
            body: vec![0u8; 32],
        };
        let entries = [
            RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?,
            unknown_critical,
        ];

        let fcr = tmp.path().join("critical.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"x", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        match recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a) {
            Err(CryptoError::UnknownCriticalRecipient { ref type_name })
                if type_name == "example.com/critical" =>
            {
                Ok(())
            }
            other => {
                panic!("expected UnknownCriticalRecipient(example.com/critical), got {other:?}")
            }
        }
    }

    /// Mixing `argon2id` with any other recipient (here `x25519`) MUST
    /// be rejected as `IncompatibleRecipients { type_name: "argon2id", .. }`
    /// BEFORE Argon2id runs.
    #[test]
    fn multi_argon2id_plus_x25519_rejected_as_mixed() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate();
        let body_x = x25519::wrap(&file_key, &pub_a)?;
        let synthetic_argon2id = RecipientEntry {
            type_name: argon2id::TYPE_NAME.to_string(),
            recipient_flags: 0,
            body: vec![0u8; argon2id::BODY_LENGTH],
        };
        let entries = [
            synthetic_argon2id,
            RecipientEntry::native(NativeRecipientType::X25519, body_x.to_vec())?,
        ];

        let fcr = tmp.path().join("mixed.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"x", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        match recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a) {
            Err(CryptoError::IncompatibleRecipients { type_name, policy })
                if type_name == argon2id::TYPE_NAME && policy == MixingPolicy::Exclusive =>
            {
                Ok(())
            }
            other => panic!("expected IncompatibleRecipients(argon2id, Exclusive), got {other:?}"),
        }
    }

    /// An unknown non-critical recipient whose body sits at the local
    /// cap must be accepted (and skipped); above the cap must be
    /// rejected as a resource-cap violation.
    #[test]
    fn multi_unknown_body_at_local_cap_decrypts() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let unknown_at_cap = RecipientEntry {
            type_name: "example.com/at-cap".to_string(),
            recipient_flags: 0,
            body: vec![0xAB; format::BODY_LEN_LOCAL_CAP_DEFAULT as usize],
        };
        let entries = [
            unknown_at_cap,
            RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?,
        ];

        let fcr = tmp.path().join("at-cap.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"at-cap payload", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a)?;
        Ok(())
    }

    /// Decoy-unwrap test: slot A wraps a *decoy* `file_key`; the file's
    /// MAC and payload are keyed off a *different* real `file_key`.
    /// Alice's private key unwraps slot A successfully (yielding the
    /// decoy), but the resulting `header_key` does not verify the MAC.
    /// Slot B targets bob, so alice's privkey fails to unwrap it. The
    /// decrypt loop must surface `HeaderMacFailedAfterUnwrap`.
    #[test]
    fn multi_x25519_decoy_unwrap_returns_mac_failed_after_unwrap() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;
        let (pub_b, _priv_b, _pass_b) = keypair_fixture(&keys_dir, "bob", "bob-pass")?;

        let real_file_key = FileKey::generate();
        let decoy_file_key = FileKey::generate();

        let body_a = x25519::wrap(&decoy_file_key, &pub_a)?;
        let body_b = x25519::wrap(&decoy_file_key, &pub_b)?;
        let entries = [
            RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?,
            RecipientEntry::native(NativeRecipientType::X25519, body_b.to_vec())?,
        ];

        let fcr = tmp.path().join("decoy-unwrap.fcr");
        build_multi_recipient_fcr(&entries, &real_file_key, b"payload", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        match recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a) {
            Err(CryptoError::HeaderMacFailedAfterUnwrap { ref type_name })
                if type_name == x25519::TYPE_NAME =>
            {
                Ok(())
            }
            other => panic!("expected HeaderMacFailedAfterUnwrap(x25519), got {other:?}"),
        }
    }

    /// Defense-in-depth: an exclusive scheme (`argon2id`) MUST not be
    /// emitted with more than one recipient. The public API has no path
    /// to construct that, but a future caller bypass would break the
    /// `FORMAT.md` §4.1 mixing rule before any output bytes are
    /// written. The orchestrator catches this before any KDF runs.
    #[test]
    fn encrypt_rejects_multi_passphrase_recipient_list() -> Result<(), CryptoError> {
        let pass = SecretString::from("pass".to_string());
        let kdf_params = crate::crypto::kdf::KdfParams::default();
        let r1 = argon2id::PassphraseRecipient {
            passphrase: &pass,
            kdf_params,
        };
        let r2 = argon2id::PassphraseRecipient {
            passphrase: &pass,
            kdf_params,
        };
        let recipients = [r1, r2];

        let tmp = tempfile::TempDir::new().unwrap();
        let input = tmp.path().join("data.txt");
        fs::write(&input, b"x")?;
        let out_dir = tmp.path().join("out");
        fs::create_dir_all(&out_dir)?;

        let err = encrypt(
            &recipients,
            ArchiveLimits::default(),
            &input,
            &out_dir,
            None,
            &|_| {},
        )
        .unwrap_err();
        match err {
            CryptoError::IncompatibleRecipients {
                ref type_name,
                policy: MixingPolicy::Exclusive,
            } if type_name == argon2id::TYPE_NAME => Ok(()),
            other => panic!("expected IncompatibleRecipients(argon2id, Exclusive), got {other:?}"),
        }
    }

    /// Cross-mode mismatch: a passphrase-only file is opened with an
    /// `X25519Identity`. The orchestrator must surface
    /// `DecryptorModeMismatch { expected: Recipient, found: Passphrase }`
    /// before any slot loop runs — never the legacy
    /// `NoSupportedRecipient`, which would imply "the loop iterated and
    /// found nothing." The public Decryptor::open routes by mode and so
    /// can't reach this branch; the test invokes `protocol::decrypt`
    /// directly to lock in the wording for internal/plugin callers.
    #[test]
    fn decrypt_rejects_passphrase_file_with_x25519_identity() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (_pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        // Single argon2id recipient with a synthetic body. The
        // cross-mode check fires before any AEAD/KDF runs, so the body
        // contents are irrelevant — `classify_encryption_mode` only
        // looks at type_name.
        let synthetic = RecipientEntry::native(
            NativeRecipientType::Argon2id,
            vec![0u8; argon2id::BODY_LENGTH],
        )?;
        let file_key = FileKey::generate();
        let fcr = tmp.path().join("passphrase.fcr");
        build_multi_recipient_fcr(&[synthetic], &file_key, b"x", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        match recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a) {
            Err(CryptoError::DecryptorModeMismatch { expected, found })
                if expected == EncryptionMode::Recipient && found == EncryptionMode::Passphrase =>
            {
                Ok(())
            }
            other => panic!(
                "expected DecryptorModeMismatch(expected=Recipient, found=Passphrase), got {other:?}"
            ),
        }
    }

    /// Cross-mode mismatch in the reverse direction: a recipient-sealed
    /// file opened with a `PassphraseIdentity`. Symmetric assertion to
    /// [`decrypt_rejects_passphrase_file_with_x25519_identity`].
    #[test]
    fn decrypt_rejects_recipient_file_with_passphrase_identity() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, _priv_a, _pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let entries = [RecipientEntry::native(
            NativeRecipientType::X25519,
            body_a.to_vec(),
        )?];
        let fcr = tmp.path().join("recipient.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"x", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        let pass = SecretString::from("doesn't-matter".to_string());
        let identity = argon2id::PassphraseIdentity {
            passphrase: &pass,
            kdf_limit: None,
        };
        let err = decrypt(
            &identity,
            &fcr,
            &dec_dir,
            ArchiveLimits::default(),
            HeaderReadLimits::default(),
            &|_| {},
        )
        .unwrap_err();
        match err {
            CryptoError::DecryptorModeMismatch { expected, found }
                if expected == EncryptionMode::Passphrase && found == EncryptionMode::Recipient =>
            {
                Ok(())
            }
            other => panic!(
                "expected DecryptorModeMismatch(expected=Passphrase, found=Recipient), got {other:?}"
            ),
        }
    }

    /// Defense-in-depth: empty recipient list rejected before any
    /// allocation or KDF. The public API gates this at construction
    /// time (`with_recipients` returns `EmptyRecipientList`), but the
    /// orchestrator re-checks so a callable internal short-circuit
    /// can't bypass the contract.
    #[test]
    fn encrypt_rejects_empty_recipient_list() -> Result<(), CryptoError> {
        let recipients: [argon2id::PassphraseRecipient; 0] = [];
        let tmp = tempfile::TempDir::new().unwrap();
        let input = tmp.path().join("data.txt");
        fs::write(&input, b"x")?;
        let out_dir = tmp.path().join("out");
        fs::create_dir_all(&out_dir)?;

        let err = encrypt(
            &recipients,
            ArchiveLimits::default(),
            &input,
            &out_dir,
            None,
            &|_| {},
        )
        .unwrap_err();
        match err {
            CryptoError::EmptyRecipientList => Ok(()),
            other => panic!("expected EmptyRecipientList, got {other:?}"),
        }
    }
}
