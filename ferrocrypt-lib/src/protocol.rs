//! High-level FerroCrypt operation flow.
//!
//! This is the only module that may coordinate all of:
//!
//! 1. running the writer-side cap and KDF preflight,
//! 2. generating a file key,
//! 3. generating the stream nonce,
//! 4. calling recipient schemes to wrap the file key,
//! 5. building the authenticated header,
//! 6. calling archive encoding/decoding,
//! 7. constructing payload stream encryptors/decryptors,
//! 8. finalising staged output,
//! 9. emitting progress events.
//!
//! Algorithm-specific logic plugs in via the [`RecipientScheme`] /
//! [`DecryptionCredential`] traits — both `pub(crate)`. Recipient modules
//! produce / consume opaque [`RecipientBody`] bytes; only this module
//! constructs full headers or verifies the header MAC.
//!
//! ## Decrypt acceptance order (`FORMAT.md` §3.7)
//!
//! 1. Read prefix.
//! 2. Reject bad magic / version / kind / flags / header length.
//! 3. Read header and header MAC.
//! 4. Structurally parse header and recipient entries.
//! 5. Reject reserved flags, then unknown critical recipients across
//!    the whole list, then native structural defects, then illegal
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

use crate::archive::{ArchiveLimits, IncompleteOutputPolicy, prepare_archive, unarchive};
use crate::container::{
    HeaderReadLimits, ParsedEncryptedHeader, build_encrypted_header, read_encrypted_header,
    resolve_encrypted_output_path, write_encrypted_file,
};
use crate::crypto::keys::{DerivedSubkeys, FileKey, derive_subkeys, random_bytes};
use crate::crypto::stream::{STREAM_NONCE_SIZE, payload_decryptor};
use crate::crypto::tlv::validate_tlv;
use crate::error::CryptoError;
use crate::format;
use crate::fs::paths::{
    KEY_FILE_LABEL, OUTPUT_LABEL, encryption_base_name, open_input_file, reject_occupied,
};
use crate::recipient::entry::{RecipientBody, RecipientEntry};
#[cfg(test)]
use crate::recipient::policy::MixingPolicy;
use crate::recipient::policy::{NativeMixingRule, NativeRecipientType, classify_recipient_mode};
use crate::{ProgressEvent, UnauthenticatedRecipientMode};

/// Encrypt-side scheme: turn a [`FileKey`] into a recipient body of
/// scheme-specific bytes.
///
/// `TYPE_NAME` and `MIXING_RULE` are associated constants so the
/// multi-recipient `encrypt` orchestrator can enforce the mixing rule
/// before any KDF runs. Implementations must not build full
/// [`RecipientEntry`] framing or compute the header MAC — those
/// concerns live in this module.
///
/// `on_event` lets schemes whose wrap step is expensive (today only
/// `argon2id`) emit [`ProgressEvent::DerivingPassphraseWrapKey`] at the
/// actual KDF call site. Schemes whose wrap is cheap (X25519: one
/// scalar mult + one HKDF, sub-millisecond) must ignore the parameter
/// — emitting from them would lie about a long pause that never
/// happens.
pub(crate) trait RecipientScheme {
    const TYPE_NAME: &'static str;
    const MIXING_RULE: NativeMixingRule;

    /// Writer-side preflight for scheme-carried parameters, run by
    /// [`encrypt`] on every recipient before any filesystem, archive,
    /// or key work. `argon2id` validates its caller-supplied
    /// [`crate::KdfParams`] against the same structural bounds,
    /// production floor, and resource policy the reader applies;
    /// `x25519` carries no such parameters and accepts. Required
    /// rather than defaulted so a future scheme must decide
    /// explicitly.
    fn validate_for_write(&self) -> Result<(), CryptoError>;

    fn wrap_file_key(
        &self,
        file_key: &FileKey,
        on_event: &dyn Fn(&ProgressEvent),
    ) -> Result<RecipientBody, CryptoError>;
}

/// Decrypt-side scheme: try to unwrap a candidate [`FileKey`] from a
/// recipient body whose `type_name` already matched
/// `DecryptionCredential::TYPE_NAME` — the orchestrator pre-filters slots
/// before calling this.
///
/// Return shape:
///
/// - `Ok(Some(file_key))` — AEAD authentication succeeded; the caller
///   now must verify the header MAC under the derived `header_key`
///   before accepting the candidate (`FORMAT.md` §3.7 step 8).
/// - `Ok(None)` — AEAD authentication failed on a structurally-valid
///   body. Caller skips this slot and tries the next supported one.
///   This is the ONLY meaning of `Ok(None)`; hard failures (KDF cap
///   exceeded, malformed embedded KDF params, structural defects in
///   the body shape) are `Err(CryptoError::*)`.
///
/// `on_event` lets schemes whose unwrap step is expensive (today only
/// `argon2id`) emit [`ProgressEvent::DerivingPassphraseWrapKey`] at the
/// actual KDF call site. Schemes whose unwrap is cheap (X25519: one
/// scalar mult + one HKDF, sub-millisecond) must ignore the parameter.
pub(crate) trait DecryptionCredential {
    const TYPE_NAME: &'static str;
    /// File mode this credential scheme can decrypt. Used by the
    /// orchestrator to surface a typed
    /// [`CryptoError::DecryptorModeMismatch`] when a caller drives
    /// `decrypt` with the wrong credential for the file's recipient list.
    const EXPECTED_MODE: UnauthenticatedRecipientMode;

    fn unwrap_file_key(
        &self,
        body: &[u8],
        on_event: &dyn Fn(&ProgressEvent),
    ) -> Result<Option<FileKey>, CryptoError>;
}

// ─── Encrypt ───────────────────────────────────────────────────────────────

/// Encrypts `input_path` under one or more recipients of a single
/// scheme. Wire format is the `.fcr` container with `recipients.len()`
/// entries whose type matches `R::TYPE_NAME`. Every entry seals the same
/// per-file `file_key` for its respective recipient.
///
/// Defense-in-depth checks (run by this function regardless of caller):
///
/// - `recipients` must be non-empty (the public API enforces this at
///   construction time; the orchestrator double-checks).
/// - If `R::MIXING_RULE.requires_single_entry()` then `recipients.len()`
///   must be exactly 1. The public API can only reach this code with a
///   single passphrase, but the assertion stops a future caller bypass
///   from emitting an `argon2id` file with two bodies (`FORMAT.md` §4.1
///   forbids it).
///
/// # Writer/reader lockstep
///
/// The emitted header shape is checked against `header_read_limits`
/// through [`preflight_header_write_limits`] — the same
/// [`HeaderReadLimits`] checks the reader applies — and every recipient
/// runs [`RecipientScheme::validate_for_write`], all before any
/// filesystem, archive, or key work. A `.fcr` this function writes is
/// therefore readable under the limits it was checked against; no
/// caller can skip the gates. [`crate::Encryptor::write`] runs the same
/// checks earlier so a misconfiguration fails before recipient key
/// files are read. The fixed passphrase byte-length bound is enforced
/// inside the wrap path (`crypto::kdf::check_passphrase_len`) before
/// Argon2id runs.
pub(crate) fn encrypt<R: RecipientScheme>(
    recipients: &[R],
    archive_limits: ArchiveLimits,
    header_read_limits: HeaderReadLimits,
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

    // The same header-cap and KDF gates the reader applies, enforced
    // here so no in-crate caller can emit a file the same-configured
    // reader rejects. `api::Encryptor::write` runs them earlier too,
    // so misconfiguration fails before recipient key files are read.
    let native_type = NativeRecipientType::from_type_name(R::TYPE_NAME)
        .ok_or(crate::error::internal_invariant!("unknown native scheme"))?;
    preflight_header_write_limits(header_read_limits, recipients.len(), native_type)?;
    for recipient in recipients {
        recipient.validate_for_write()?;
    }

    // Resolve the destination and reject an existing entry before
    // expensive key work. The final no-clobber rename still prevents
    // replacement if the path becomes occupied after this check.
    // `reject_occupied` also detects dangling symlinks.
    let base_name = encryption_base_name(input_path)?;
    let output_path = resolve_encrypted_output_path(output_dir, output_file, &base_name);
    reject_occupied(&output_path, OUTPUT_LABEL)?;

    // Prepare the complete archive before cipher work or output
    // staging. Archive validation then fails before an expensive KDF,
    // and a staging file created inside the input tree cannot be
    // recorded as source content.
    let prepared = prepare_archive(input_path, archive_limits)?;

    // No early progress event here. Each recipient scheme emits its
    // own work-boundary event from inside `wrap_file_key`. For the
    // passphrase-only case, that's exactly one
    // `DerivingPassphraseWrapKey` immediately before Argon2id; for
    // pure X25519 wrapping (sub-millisecond), no event fires until
    // `Encrypting` below — which is what the orchestrator wants:
    // signal what the user can perceive, stay silent for what they
    // can't.

    // Generate per-file random material first so the rest of the build
    // is a pure function of (file_key, recipient input, stream_nonce,
    // input bytes). file_key is held in `Zeroizing` inside the typed
    // newtype, so an early return wipes it.
    let file_key = FileKey::generate()?;
    let stream_nonce = random_bytes::<STREAM_NONCE_SIZE>()?;
    let DerivedSubkeys {
        payload_key,
        header_key,
    } = derive_subkeys(&file_key, &stream_nonce)?;

    // Wrap the file_key for each recipient under the same scheme. After
    // the bodies are built, the raw file_key is no longer needed; drop
    // it immediately so the plaintext window in memory is minimal.
    let mut entries = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let body = recipient.wrap_file_key(&file_key, on_event)?;
        entries.push(build_native_entry(R::TYPE_NAME, body)?);
    }
    drop(file_key);

    // Assemble prefix + header + MAC. `build_encrypted_header` owns the
    // single byte-arithmetic implementation; encrypt and decrypt share
    // its MAC scope.
    let built = build_encrypted_header(
        &entries,
        b"", // current writers emit ext_len = 0
        stream_nonce,
        payload_key,
        &header_key,
    )?;
    drop(header_key);

    on_event(&ProgressEvent::Encrypting);

    write_encrypted_file(prepared, output_dir, output_file, &base_name, &built)
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
        .ok_or(crate::error::internal_invariant!("unknown native scheme"))?;
    RecipientEntry::native(ty, body.bytes)
}

/// Enforces the exact `.fcr` header shape the writer will emit against
/// the caller-supplied [`HeaderReadLimits`]. Mirrors the reader-side cap
/// checks in `container::read_encrypted_header`, but runs before any KDF,
/// ECDH, or output-file work. Called by [`encrypt`] on every write, and
/// earlier by [`crate::Encryptor::write`] so a misconfiguration fails
/// before recipient key files are read.
///
/// Takes a [`NativeRecipientType`] rather than a `(type_name, body_len)`
/// pair so the type-name / body-length pair is bound by the registry
/// (impossible for a caller to mix `argon2id`'s name with `x25519`'s
/// body length), and so adding a future native recipient updates the
/// preflight automatically through the registry's accessors.
pub(crate) fn preflight_header_write_limits(
    limits: HeaderReadLimits,
    recipient_count: usize,
    native: NativeRecipientType,
) -> Result<(), CryptoError> {
    let type_name = native.type_name();
    let body_len = native.body_len();

    // `RECIPIENT_COUNT_MAX = 4096` fits u16; saturating cast keeps the
    // cap diagnostic honest in the theoretical case of an in-memory
    // list above u16::MAX, while still surfacing the cap-exceeded
    // variant before later structural checks.
    let count_u16: u16 = u16::try_from(recipient_count).unwrap_or(u16::MAX);
    limits.enforce_recipient_count(count_u16)?;

    // body_len is bounded by the canonical native `BODY_LENGTH` (≤ 116
    // today), so the saturating cast cannot fire. Defensive
    // fallback for a hypothetical future plugin recipient with a body
    // above `u32::MAX`: `enforce_recipient_body_len` rejects against
    // the per-entry cap (≤ `BODY_LEN_STRUCTURAL_MAX = 16 MiB`), so
    // `u32::MAX` always trips the cap.
    let body_len_u32: u32 = u32::try_from(body_len).unwrap_or(u32::MAX);
    limits.enforce_recipient_body_len(body_len_u32)?;

    // Compute the exact `header_len` the writer will emit
    // (`header_fixed + recipient_count * per_entry`, with `ext_len = 0`
    // for current writers) and check it against the cap. All checked
    // arithmetic funnels into one shared overflow error.
    let overflow_err = || CryptoError::HeaderLenCapExceeded {
        header_len: u32::MAX,
        local_cap: limits.max_header_len,
    };
    let per_entry = (crate::recipient::entry::ENTRY_HEADER_SIZE as u64)
        .checked_add(type_name.len() as u64)
        .and_then(|v| v.checked_add(body_len as u64))
        .ok_or_else(overflow_err)?;
    let total_entries = (recipient_count as u64)
        .checked_mul(per_entry)
        .ok_or_else(overflow_err)?;
    let header_len_u64 = (format::HEADER_FIXED_SIZE as u64)
        .checked_add(total_entries)
        .ok_or_else(overflow_err)?;
    let header_len = u32::try_from(header_len_u64).unwrap_or(u32::MAX);
    limits.enforce_header_len(header_len)?;

    Ok(())
}

// ─── Decrypt ───────────────────────────────────────────────────────────────

/// An encrypted input prepared for decryption. It contains the opened file,
/// its structurally parsed header, and its classified recipient mode.
///
/// [`DecryptSession::open`] performs the non-cryptographic steps from
/// `FORMAT.md` §3.7: bounded header reading, structural parsing, resource-limit
/// checks, and recipient classification. The file remains open at the first
/// payload byte, so [`decrypt_session`] continues from the same file. This is
/// important when credential work occurs between validation and decryption,
/// such as unlocking a private key with Argon2id: replacing the path during
/// that work cannot change the input being decrypted.
pub(crate) struct DecryptSession {
    encrypted_file: fs::File,
    parsed: ParsedEncryptedHeader,
    mode: UnauthenticatedRecipientMode,
}

impl DecryptSession {
    /// Opens `input_path`, reads its header under `header_read_limits`, and
    /// classifies its recipients without performing key operations.
    pub(crate) fn open(
        input_path: &Path,
        header_read_limits: HeaderReadLimits,
    ) -> Result<Self, CryptoError> {
        // `open_input_file` rejects FIFOs, sockets, and device nodes
        // without waiting. Encryption rejects the same input types.
        let mut encrypted_file = open_input_file(input_path)?;

        // Steps 1–4: read and parse the header without cryptographic
        // work, enforcing local limits before allocation.
        let parsed = read_encrypted_header(&mut encrypted_file, header_read_limits)?;

        // Steps 5-9: reject unsupported critical recipients, native
        // entries with invalid flags or body lengths, and invalid
        // recipient combinations before any KDF or private-key work.
        // `classify_recipient_mode` runs the per-entry structural pass
        // and then the mixing policy (FORMAT.md §3.7 preflight).
        let mode = classify_recipient_mode(&parsed.recipient_entries)?;

        Ok(Self {
            encrypted_file,
            parsed,
            mode,
        })
    }

    /// Returns the recipient mode derived from the unverified header. This is
    /// structural classification only and is not an authentication result.
    pub(crate) fn mode(&self) -> UnauthenticatedRecipientMode {
        self.mode
    }
}

/// Opens `input_path` as a [`DecryptSession`] and decrypts it. Callers that
/// need to perform credential work after structural validation can open the
/// session separately and pass it to [`decrypt_session`].
pub(crate) fn decrypt<I: DecryptionCredential>(
    credential: &I,
    input_path: &Path,
    output_dir: &Path,
    archive_limits: ArchiveLimits,
    header_read_limits: HeaderReadLimits,
    incomplete_output_policy: IncompleteOutputPolicy,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    let session = DecryptSession::open(input_path, header_read_limits)?;
    decrypt_session(
        credential,
        session,
        output_dir,
        archive_limits,
        incomplete_output_policy,
        on_event,
    )
}

/// Decrypts a prepared [`DecryptSession`] with the supplied credential.
///
/// Iterates every supported recipient slot in declared order before
/// emitting a final verdict. The slot loop is identical for the
/// single-candidate (passphrase) and multi-candidate (X25519) cases —
/// the passphrase path is just a slot loop of length 1. Visiting every
/// supported slot, rather than short-circuiting on the first MAC
/// match, makes wall-clock cost a function of `recipient_count`
/// (capped by `HeaderReadLimits`) rather than of which slot matched,
/// per the `FORMAT.md` §3.7 SHOULD-level mitigation.
pub(crate) fn decrypt_session<I: DecryptionCredential>(
    credential: &I,
    session: DecryptSession,
    output_dir: &Path,
    archive_limits: ArchiveLimits,
    incomplete_output_policy: IncompleteOutputPolicy,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    let DecryptSession {
        encrypted_file,
        parsed,
        mode,
    } = session;

    // A credential for the wrong recipient mode returns the dedicated
    // mismatch error. `PrivateKeyDecryptor::decrypt` checks before
    // unlocking the private key; this check also covers internal and
    // future callers.
    check_mode_matches_scheme::<I>(mode)?;

    // No early progress event here. Progress events fire at the actual
    // KDF call boundary inside each scheme's `unwrap_file_key`. For the
    // passphrase mode, that means the slot-loop Argon2id emission lives
    // inside `recipient::native::argon2id::unwrap`, which fires
    // `DerivingPassphraseWrapKey` only after the per-slot structural /
    // resource-cap checks have passed. For the recipient (X25519) mode,
    // the heaviest KDF (the `private.key` Argon2id unlock) already ran
    // *before* this function was entered — `PrivateKeyDecryptor::decrypt`
    // calls `open_x25519_private_key` first, and that call emits
    // `UnlockingPrivateKey` at its own work boundary inside
    // `key::private::open_private_key`.

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
        // Native recipients do not use the critical bit — the
        // reader handles them natively. A native entry with the bit
        // set is structurally malformed and aborts the whole file.
        if entry.recipient_flags != 0 {
            return Err(CryptoError::InvalidFormat(
                crate::error::FormatDefect::MalformedRecipientEntry,
            ));
        }
        let file_key = match credential.unwrap_file_key(&entry.body, on_event)? {
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
        // ~one HKDF + one HMAC remains per AEAD-passing slot. The goal
        // §3.7 protects is position anonymity: the delta does NOT depend
        // on which slot matched, so wall time cannot reveal the
        // matching recipient's place in the list. It does scale with the
        // number of slots that pass AEAD under this private key. A file
        // may legitimately carry the same recipient more than once
        // (`Encryptor::with_public_keys` accepts duplicates), so that
        // count can exceed one; the header's cleartext `recipient_count`
        // already bounds it, and no §3.7 goal requires hiding it. Hiding
        // the count would need unconditional derive_subkeys +
        // verify_header_mac on every supported slot, which the format
        // does not mandate.
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
        // No slot MAC-verified. [`failure_for`]'s `(mode × had_unwrap)`
        // matrix picks the surfaced variant.
        return Err(failure_for(mode, I::TYPE_NAME, had_successful_unwrap));
    };

    // 9. TLV validation runs AFTER MAC verify, so the validator is
    //    operating on authenticated bytes.
    validate_tlv(&parsed.ext_bytes)?;

    // 10-12. STREAM payload decrypt + unarchive. Path / resource caps
    //        are enforced inside `unarchive` before any write.
    on_event(&ProgressEvent::Decrypting);
    let decrypt_reader = payload_decryptor(&payload_key, &stream_nonce, encrypted_file);
    unarchive(
        decrypt_reader,
        output_dir,
        archive_limits,
        incomplete_output_policy,
    )
}

/// Verifies that the classified file mode matches the credential scheme's
/// declared [`DecryptionCredential::EXPECTED_MODE`]. On mismatch, returns a
/// typed [`CryptoError::DecryptorModeMismatch`] carrying both modes so
/// the caller can pattern-match without comparing strings.
fn check_mode_matches_scheme<I: DecryptionCredential>(
    mode: UnauthenticatedRecipientMode,
) -> Result<(), CryptoError> {
    if mode == I::EXPECTED_MODE {
        return Ok(());
    }
    Err(CryptoError::DecryptorModeMismatch {
        expected: I::EXPECTED_MODE,
        found: mode,
    })
}

/// No slot MAC-verified. Indexed by `(mode × had_unwrap)`:
///
/// | mode       | had_unwrap | error                                       |
/// |------------|-----------:|---------------------------------------------|
/// | any        | false      | `RecipientUnwrapFailed { type_name }`       |
/// | Passphrase | true       | `HeaderTampered`                            |
/// | PublicKey  | true       | `HeaderMacFailedAfterUnwrap { type_name }`  |
///
/// `had_unwrap == false` means the file has at least one supported slot, but
/// none opened with this credential. That is the `FORMAT.md` §12
/// wrong-passphrase/key class (`RecipientUnwrapFailed`), not
/// `NoSupportedRecipient` (no supported recipient type in the file). The
/// rendered message keeps the credential-or-modified-file ambiguity for the
/// recipient type involved.
fn failure_for(
    mode: UnauthenticatedRecipientMode,
    type_name: &'static str,
    had_unwrap: bool,
) -> CryptoError {
    match (mode, had_unwrap) {
        // No slot opened, yet classification proved that the file has a
        // supported recipient. This is the wrong-credential-or-modified-body
        // class, not `NoSupportedRecipient`.
        (_, false) => CryptoError::RecipientUnwrapFailed {
            type_name: type_name.to_string(),
        },
        (UnauthenticatedRecipientMode::Passphrase, true) => CryptoError::HeaderTampered,
        (UnauthenticatedRecipientMode::PublicKey, true) => {
            CryptoError::HeaderMacFailedAfterUnwrap {
                type_name: type_name.to_string(),
            }
        }
    }
}

// ─── Key-pair generation ───────────────────────────────────────────────────

/// Generates an X25519 key pair and writes both files to `output_dir`.
/// Returns `(private_key_path, public_key_path)`.
///
/// - `private.key` is the passphrase-wrapped binary keyfile.
///   `key::private::seal_private_key` owns the byte layout (cleartext
///   header → AEAD-AAD-bound → wrapped secret). Permissions: `0o600`
///   on Unix.
/// - `public.key` is a UTF-8 text file containing the canonical
///   `fcr1…` Bech32 recipient string. Permissions: `0o644` on Unix
///   (public keys are not secret).
///
/// Both files are staged and synced before either receives its final name.
/// `private.key` is committed first, and the output directory is flushed after
/// each commit. This prevents process interruption from leaving `public.key`
/// without its matching `private.key`. Where directory flushing is supported,
/// the same guarantee covers power loss.
///
/// # Writer/reader lockstep
///
/// The caller-supplied [`crate::KdfParams`] are validated here against
/// the same structural bounds, production floor, and
/// [`crate::KdfLimit`] resource policy the reader applies when
/// unlocking, so a `private.key` this function seals unlocks under the
/// same policy; no caller can skip the gate. `kdf_limit = None`
/// applies [`crate::KdfLimit::default`]. The fixed passphrase
/// byte-length bound is enforced inside the sealing path
/// (`crypto::kdf::check_passphrase_len`) before Argon2id runs.
pub(crate) fn generate_key_pair(
    passphrase: &crate::passphrase::Passphrase,
    kdf_params: &crate::crypto::kdf::KdfParams,
    kdf_limit: Option<&crate::crypto::kdf::KdfLimit>,
    output_dir: &Path,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<(PathBuf, PathBuf, String), CryptoError> {
    use std::io::Write as _;

    use crate::fs::atomic;
    use crate::key::files::{PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME};
    use crate::key::private::seal_private_key;
    use crate::key::public::{encode_recipient_string, fingerprint_hex};
    use crate::recipient::native::x25519;

    // Writer caps mirror reader defaults via the same structural +
    // resource KDF validation the reader uses, so the sealed
    // `private.key` is unlocked by a default `PrivateKeyDecryptor`.
    // To go above default, the caller raises both sides explicitly.
    kdf_params.validate_for_write(kdf_limit)?;

    fs::create_dir_all(output_dir)?;

    // Check both final names before Argon2id so an existing entry fails
    // immediately. `reject_occupied` uses `symlink_metadata`, so it also
    // detects dangling symlinks. The final no-clobber renames still
    // prevent replacement if either name becomes occupied later.
    let private_key_path = output_dir.join(PRIVATE_KEY_FILENAME);
    let public_key_path = output_dir.join(PUBLIC_KEY_FILENAME);
    reject_occupied(&private_key_path, KEY_FILE_LABEL)?;
    reject_occupied(&public_key_path, KEY_FILE_LABEL)?;

    on_event(&ProgressEvent::GeneratingKeyPair);

    // Generate the X25519 keypair via the recipient module. The secret
    // material is returned in `Zeroizing` so it's wiped from memory
    // when this stack frame unwinds, regardless of whether the
    // subsequent seal/write succeeds.
    let (secret_material, public_material) = x25519::generate_keypair()?;

    // Hand off all `private.key` byte-layout, AEAD, and AAD scope to
    // `key/private.rs` — the single source of truth.
    let private_key_bytes = seal_private_key(
        secret_material.as_ref(),
        x25519::TYPE_NAME,
        &public_material,
        &[], // no ext_bytes for the X25519 case
        passphrase,
        kdf_params,
    )?;
    drop(secret_material);

    // Encode the canonical `fcr1…` recipient string via `key/public.rs`
    // (validates type-name grammar, computes the internal SHA3-256
    // checksum, emits BIP 173 lowercase Bech32).
    let recipient_string = encode_recipient_string(x25519::TYPE_NAME, &public_material)?;

    // Stage and sync both key files before either receives its final
    // name. Any failure before the commit step removes both temporary
    // files and publishes nothing.
    let mut private_builder = tempfile::Builder::new();
    private_builder
        .prefix(".ferrocrypt-private_key-")
        .suffix(".tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        private_builder.permissions(fs::Permissions::from_mode(0o600));
    }
    let mut private_tmp = private_builder.tempfile_in(output_dir)?;
    private_tmp.as_file_mut().write_all(&private_key_bytes)?;
    atomic::sync_file_durable(private_tmp.as_file())?;

    // `public.key` is the text form `fcr1…\n`. It is not secret, so
    // Unix permissions are 0o644.
    let mut public_builder = tempfile::Builder::new();
    public_builder
        .prefix(".ferrocrypt-public_key-")
        .suffix(".tmp");
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
    atomic::sync_file_durable(public_tmp.as_file())?;

    commit_key_pair_files(private_tmp, public_tmp, &private_key_path, &public_key_path)?;

    // Compute the fingerprint from the in-memory `public_material`
    // rather than re-reading and re-decoding `public.key` from disk.
    // The bytes here are the same ones the recipient string just
    // encoded, so the fingerprint matches what
    // `PublicKey::from_key_file(...).fingerprint()` would produce —
    // without paying the extra disk read + Bech32 decode + SHA3 in
    // the API layer.
    let fingerprint = fingerprint_hex(x25519::TYPE_NAME, &public_material)?;

    Ok((private_key_path, public_key_path, fingerprint))
}

/// Commits two fully staged key files without overwriting existing files.
/// `private.key` is committed first, followed by a directory flush; then
/// `public.key` is committed and the directory is flushed again.
///
/// The order is required because `public.key` allows others to encrypt to the
/// key pair. It must not become durable unless the matching `private.key` is
/// already durable. The first directory flush establishes that order across
/// power loss. Where directory flushing is supported, the second flush ensures
/// that a successful return means both final names are durable. On filesystems
/// that do not support directory flushing, the private-first order still
/// protects against process interruption, but power-loss ordering depends on
/// the filesystem.
///
/// Failure handling preserves a safe result:
///
/// - If the `private.key` commit fails, neither file is published.
/// - If the first directory flush fails, `private.key` is removed best-effort.
/// - If the `public.key` commit fails, `private.key` is removed best-effort.
/// - If the final directory flush fails, `public.key` is removed and
///   `private.key` is kept. Removing both without a working directory flush
///   could leave only `public.key` after power loss. The remaining private key
///   is safe to delete.
fn commit_key_pair_files(
    private_tmp: tempfile::NamedTempFile,
    public_tmp: tempfile::NamedTempFile,
    private_key_path: &Path,
    public_key_path: &Path,
) -> Result<(), CryptoError> {
    commit_key_pair_files_with_barrier(
        private_tmp,
        public_tmp,
        private_key_path,
        public_key_path,
        crate::fs::atomic::sync_dir_durable,
    )
}

/// Implementation of [`commit_key_pair_files`] with an injectable directory
/// flush function so tests can fail either flush point deterministically.
fn commit_key_pair_files_with_barrier(
    private_tmp: tempfile::NamedTempFile,
    public_tmp: tempfile::NamedTempFile,
    private_key_path: &Path,
    public_key_path: &Path,
    sync_output_dir: impl Fn(&Path) -> std::io::Result<()>,
) -> Result<(), CryptoError> {
    use crate::fs::atomic;
    use crate::fs::paths::parent_or_cwd;

    // Both final paths use the same output directory, so one directory
    // flush covers both entries.
    let output_dir = parent_or_cwd(private_key_path);

    atomic::finalize_file(private_tmp, private_key_path, KEY_FILE_LABEL)?;
    if let Err(e) = sync_output_dir(output_dir) {
        let _ = fs::remove_file(private_key_path);
        return Err(CryptoError::Io(e));
    }
    if let Err(e) = atomic::finalize_file(public_tmp, public_key_path, KEY_FILE_LABEL) {
        let _ = fs::remove_file(private_key_path);
        return Err(e);
    }
    if let Err(e) = sync_output_dir(output_dir) {
        let _ = fs::remove_file(public_key_path);
        return Err(CryptoError::Io(e));
    }
    Ok(())
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
    use crate::key::files::{PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME};
    use crate::key::limits::KeyReadLimits;
    use crate::key::public::read_public_key;
    use crate::passphrase::Passphrase;
    use crate::recipient::entry::RECIPIENT_FLAG_CRITICAL;
    use crate::recipient::native::{argon2id, x25519};
    use crate::recipient::policy::NativeRecipientType;

    /// Builds a complete `.fcr` file whose authenticated plaintext payload is
    /// exactly `payload`, without adding an FCA archive. Tests use it to create
    /// authenticated files with invalid FCA structure that production writers
    /// cannot emit.
    fn build_fcr_with_raw_payload(
        entries: &[RecipientEntry],
        file_key: &FileKey,
        payload: &[u8],
        path: &Path,
    ) -> Result<(), CryptoError> {
        use std::io::Write;

        let stream_nonce = random_bytes::<STREAM_NONCE_SIZE>()?;
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = derive_subkeys(file_key, &stream_nonce)?;

        let built = build_encrypted_header(entries, b"", stream_nonce, payload_key, &header_key)?;

        let mut payload_buf: Vec<u8> = Vec::new();
        let mut writer =
            payload_encryptor(&built.payload_key, &built.stream_nonce, &mut payload_buf);
        writer.write_all(payload).map_err(CryptoError::Io)?;
        let _ = writer.finish()?;

        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&built.prefix_bytes);
        buf.extend_from_slice(&built.header_bytes);
        buf.extend_from_slice(&built.header_mac);
        buf.extend_from_slice(&payload_buf);
        fs::write(path, &buf)?;
        Ok(())
    }

    /// Builds a complete `.fcr` file with the supplied recipient entries and
    /// plaintext. The caller has already wrapped `file_key` for entries that
    /// must decrypt; unknown or intentionally invalid entries are preserved.
    fn build_multi_recipient_fcr(
        entries: &[RecipientEntry],
        file_key: &FileKey,
        plaintext: &[u8],
        path: &Path,
    ) -> Result<(), CryptoError> {
        // Construct an FCA archive containing one file named
        // `data.txt`, matching the production writer's output.
        let fca_bytes = {
            use crate::archive::ArchiveLimits;
            use crate::archive::format::{serialize_manifest, write_fca_header};
            use crate::archive::model::{ArchiveEntryKind, Manifest, make_entry};
            use std::ffi::OsString;

            let manifest = Manifest {
                entries: vec![make_entry(
                    "data.txt",
                    ArchiveEntryKind::File,
                    plaintext.len() as u64,
                    0o644,
                )],
                total_file_bytes: plaintext.len() as u64,
                root_name: OsString::from("data.txt"),
                root_is_file: true,
                root_mode: 0o644,
            };
            let manifest_bytes = serialize_manifest(&manifest, ArchiveLimits::default())?;

            let mut fca = write_fca_header(
                Vec::new(),
                1,
                0,
                manifest_bytes.len() as u32,
                plaintext.len() as u64,
            )?;
            fca.extend_from_slice(&manifest_bytes);
            fca.extend_from_slice(plaintext);
            fca
        };

        build_fcr_with_raw_payload(entries, file_key, &fca_bytes, path)
    }

    /// Generates an X25519 keypair, persists a `private.key` for it,
    /// and returns `(public_bytes, private_key_path, passphrase)`.
    fn keypair_fixture(
        keys_dir: &Path,
        label: &str,
        pass: &str,
    ) -> Result<([u8; 32], PathBuf, Passphrase), CryptoError> {
        let pass = Passphrase::new(pass);
        let dir = keys_dir.join(label);
        fs::create_dir_all(&dir)?;
        let (private_key_path, public_key_path, _fingerprint) = generate_key_pair(
            &pass,
            &crate::crypto::kdf::KdfParams::test_fast_default(),
            None,
            &dir,
            &|_| {},
        )?;
        let pub_bytes = read_public_key(&public_key_path, KeyReadLimits::default())?.bytes;
        Ok((pub_bytes, private_key_path, pass))
    }

    /// Decrypt helper: opens the X25519 `private.key`, builds an
    /// `X25519Credential`, and runs the orchestrator's slot loop directly
    /// (mirrors what `PrivateKeyDecryptor::decrypt` does in `api.rs` but
    /// preserves raw error variants for assertion).
    fn recipient_decrypt(
        fcr: &Path,
        dec_dir: &Path,
        private_key_path: &Path,
        pass: &Passphrase,
    ) -> Result<PathBuf, CryptoError> {
        let private_key_bytes = x25519::open_x25519_private_key(
            private_key_path,
            pass,
            None,
            KeyReadLimits::default(),
            &|_| {},
        )?;
        let credential = x25519::X25519Credential { private_key_bytes };
        decrypt(
            &credential,
            fcr,
            dec_dir,
            ArchiveLimits::default(),
            HeaderReadLimits::default(),
            IncompleteOutputPolicy::default(),
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

        let file_key = FileKey::generate().unwrap();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let body_b = x25519::wrap(&file_key, &pub_b)?;
        let entries = [
            RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?,
            RecipientEntry::native(NativeRecipientType::X25519, body_b.to_vec())?,
        ];

        let payload = b"two-x25519 round trip";
        let fcr = tmp.path().join("multi.fcr");
        build_multi_recipient_fcr(&entries, &file_key, payload, &fcr)?;

        for (label, private_key, pass) in [("alice", &priv_a, &pass_a), ("bob", &priv_b, &pass_b)] {
            let dec_dir = tmp.path().join(format!("decrypted-{label}"));
            fs::create_dir_all(&dec_dir)?;
            recipient_decrypt(&fcr, &dec_dir, private_key, pass)?;
            let restored = fs::read(dec_dir.join("data.txt"))?;
            assert_eq!(
                restored, payload,
                "{label} should decrypt the same plaintext"
            );
        }
        Ok(())
    }

    /// Verifies end-to-end classification of incomplete FCA regions. Each
    /// `.fcr` file has a valid outer header and an authenticated payload, but
    /// its FCA plaintext ends inside the fixed header, extension region, or
    /// manifest. Decryption must return `MalformedArchive` with the matching
    /// region reason rather than `Io`.
    #[test]
    fn truncated_fca_payload_rejects_as_malformed_archive() -> Result<(), CryptoError> {
        use crate::archive::format::{FCA_MAGIC, FCA_VERSION, write_fca_header};
        use crate::archive::reasons::{
            ARCHIVE_EXT_REGION_TRUNCATED, FIXED_HEADER_TRUNCATED, MANIFEST_REGION_TRUNCATED,
        };

        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate().unwrap();
        let body = x25519::wrap(&file_key, &pub_a)?;
        let entries = [RecipientEntry::native(
            NativeRecipientType::X25519,
            body.to_vec(),
        )?];

        // Valid prefix through the flags field, followed by only three
        // bytes of `entry_count`.
        let short_header = {
            let mut fca = Vec::new();
            fca.extend_from_slice(FCA_MAGIC);
            fca.push(FCA_VERSION);
            fca.extend_from_slice(&0u16.to_be_bytes());
            fca.extend_from_slice(&[0u8; 3]);
            fca
        };
        // Valid header declaring an 8-byte `archive_ext` region, then
        // the payload ends three bytes in.
        let short_ext = {
            let mut fca = write_fca_header(Vec::new(), 1, 8, 50, 10)?;
            fca.extend_from_slice(&[0u8; 3]);
            fca
        };
        // Valid header declaring a 50-byte manifest, then the payload
        // ends twenty bytes in.
        let short_manifest = {
            let mut fca = write_fca_header(Vec::new(), 1, 0, 50, 10)?;
            fca.extend_from_slice(&[0u8; 20]);
            fca
        };

        let cases: [(&str, Vec<u8>, &str); 3] = [
            ("fixed-header", short_header, FIXED_HEADER_TRUNCATED),
            ("archive-ext", short_ext, ARCHIVE_EXT_REGION_TRUNCATED),
            ("manifest", short_manifest, MANIFEST_REGION_TRUNCATED),
        ];
        for (label, fca_payload, want_reason) in cases {
            let fcr = tmp.path().join(format!("{label}.fcr"));
            build_fcr_with_raw_payload(&entries, &file_key, &fca_payload, &fcr)?;

            let dec_dir = tmp.path().join(format!("decrypted-{label}"));
            fs::create_dir_all(&dec_dir)?;
            let err = recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a).unwrap_err();
            match err {
                CryptoError::MalformedArchive { reason } => {
                    assert_eq!(reason, want_reason, "wrong truncation reason for {label}");
                }
                other => panic!("{label}: expected MalformedArchive, got {other:?}"),
            }
        }
        Ok(())
    }

    /// FORMAT.md §3.7 step 8: a wrong-length `x25519` slot hiding
    /// behind a well-shaped slot must reject the whole file during the
    /// structural preflight, before any slot unwrap can run — even
    /// though the first slot alone would decrypt.
    #[test]
    fn multi_x25519_wrong_length_second_slot_rejects_in_preflight() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate().unwrap();
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

        let fcr = tmp.path().join("multi-wrong-length.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"x", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        let err = recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a).unwrap_err();
        match err {
            CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry) => Ok(()),
            other => panic!(
                "expected MalformedRecipientEntry from the preflight for slot 2; got {other:?}"
            ),
        }
    }

    /// FORMAT.md §4.2: an all-zero `ephemeral_public_key_bytes` is a
    /// credential-independent structural defect, checked during the
    /// step 8 preflight. Even though the earlier valid slot alone
    /// would decrypt, the whole file is rejected before any unwrap.
    #[test]
    fn multi_x25519_all_zero_ephemeral_after_valid_is_file_fatal() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate().unwrap();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let valid_slot = RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?;

        // Hand-craft a malformed `x25519` body: an all-zero ephemeral
        // public key. The rest of the body is filler — the preflight
        // rejects the entry before any key work could see it.
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
            other => panic!("all-zero ephemeral in slot 2 must be file-fatal, got {other:?}"),
        }
    }

    /// FORMAT.md §4.2: the all-zero-shared-secret check stays mandatory
    /// during X25519 for a preflight-valid ephemeral. A small-order,
    /// canonical, non-zero ephemeral public key cannot be screened
    /// structurally, and every clamped private scalar maps it to an
    /// all-zero shared secret, so the slot loop must reject the whole
    /// file — even when an earlier valid slot has already MAC-verified.
    #[test]
    fn multi_x25519_small_order_ephemeral_after_valid_is_file_fatal() -> Result<(), CryptoError> {
        // u-coordinate of a known small-order Curve25519 point:
        // canonical and non-zero, so it passes the structural
        // preflight, while X25519 with any clamped scalar yields an
        // all-zero shared secret.
        const SMALL_ORDER_U: [u8; x25519::PUBLIC_KEY_SIZE] = [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ];

        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate().unwrap();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let valid_slot = RecipientEntry::native(NativeRecipientType::X25519, body_a.to_vec())?;

        let mut malformed_body = vec![0xABu8; x25519::BODY_LENGTH];
        malformed_body[..x25519::PUBLIC_KEY_SIZE].copy_from_slice(&SMALL_ORDER_U);
        let malformed_slot = RecipientEntry::native(NativeRecipientType::X25519, malformed_body)?;

        let entries = [valid_slot, malformed_slot];
        let fcr = tmp.path().join("small-order-ephemeral-after.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"x", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        match recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => Ok(()),
            other => {
                panic!("small-order ephemeral in slot 2 must be file-fatal, got {other:?}")
            }
        }
    }

    /// Same property as
    /// [`multi_x25519_all_zero_ephemeral_after_valid_is_file_fatal`] but
    /// with the malformed slot first. The preflight walks every entry,
    /// so slot order does not change the verdict.
    #[test]
    fn multi_x25519_all_zero_ephemeral_before_valid_is_file_fatal() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate().unwrap();
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
    /// preflight verdict is independent of recipient cardinality.
    #[test]
    fn single_x25519_all_zero_ephemeral_is_file_fatal() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (_pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate().unwrap();
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

        let file_key = FileKey::generate().unwrap();
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
    /// recipient: the file must be rejected as
    /// `UnknownCriticalRecipient` before any recipient unwrap or KDF
    /// runs.
    #[test]
    fn multi_unknown_critical_rejected_before_any_unwrap() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate().unwrap();
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

    /// Mixing `argon2id` with any other recipient (here `x25519`) must
    /// be rejected as `IncompatibleRecipients { type_name: "argon2id", .. }`
    /// BEFORE Argon2id runs.
    #[test]
    fn multi_argon2id_plus_x25519_rejected_as_mixed() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate().unwrap();
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

        let file_key = FileKey::generate().unwrap();
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

    /// When the caller's private key AEAD-unwraps no slot of a public-key
    /// `.fcr`, the error is `RecipientUnwrapFailed`, not
    /// `NoSupportedRecipient` (reserved for a file with no supported recipient
    /// type). File targets alice; decrypt with bob.
    #[test]
    fn multi_x25519_no_matching_recipient_surfaces_recipient_unwrap_failed()
    -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, _priv_a, _pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;
        let (_pub_b, priv_b, pass_b) = keypair_fixture(&keys_dir, "bob", "bob-pass")?;

        let file_key = FileKey::generate().unwrap();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let entries = [RecipientEntry::native(
            NativeRecipientType::X25519,
            body_a.to_vec(),
        )?];

        let fcr = tmp.path().join("alice-only.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"payload", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        match recipient_decrypt(&fcr, &dec_dir, &priv_b, &pass_b) {
            Err(CryptoError::RecipientUnwrapFailed { ref type_name })
                if type_name == x25519::TYPE_NAME =>
            {
                Ok(())
            }
            other => panic!("expected RecipientUnwrapFailed(x25519), got {other:?}"),
        }
    }

    /// Decoy-unwrap test: slot A wraps a *decoy* `file_key`; the file's
    /// MAC and payload are keyed off a *different* real `file_key`.
    /// Alice's private key unwraps slot A successfully (yielding the
    /// decoy), but the resulting `header_key` does not verify the MAC.
    /// Slot B targets bob, so alice's private_key fails to unwrap it. The
    /// decrypt loop must surface `HeaderMacFailedAfterUnwrap`.
    #[test]
    fn multi_x25519_decoy_unwrap_returns_mac_failed_after_unwrap() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;
        let (pub_b, _priv_b, _pass_b) = keypair_fixture(&keys_dir, "bob", "bob-pass")?;

        let real_file_key = FileKey::generate().unwrap();
        let decoy_file_key = FileKey::generate().unwrap();

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

    /// FORMAT.md §3.7 step 13 — "If HMAC verification fails, continue
    /// trying other candidate recipients." Slot 1 wraps a decoy file key
    /// (alice unwraps it, but the derived header key does not verify the
    /// MAC); slot 2 wraps the real file key for alice. Decrypt must not
    /// stop at slot 1's MAC failure — it must reach slot 2 and succeed. A
    /// "fail fast on first MAC failure" regression turns this into an error.
    #[test]
    fn multi_x25519_continues_past_mac_failure_to_later_slot() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let real_file_key = FileKey::generate().unwrap();
        let decoy_file_key = FileKey::generate().unwrap();

        // Both slots target alice, but slot 1 seals the decoy key.
        let body_decoy = x25519::wrap(&decoy_file_key, &pub_a)?;
        let body_real = x25519::wrap(&real_file_key, &pub_a)?;
        let entries = [
            RecipientEntry::native(NativeRecipientType::X25519, body_decoy.to_vec())?,
            RecipientEntry::native(NativeRecipientType::X25519, body_real.to_vec())?,
        ];

        let payload = b"decrypt must reach slot 2";
        let fcr = tmp.path().join("mac-fail-then-ok.fcr");
        build_multi_recipient_fcr(&entries, &real_file_key, payload, &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a)?;
        assert_eq!(
            fs::read(dec_dir.join("data.txt"))?,
            payload,
            "slot 2 must decrypt after slot 1's MAC failure"
        );
        Ok(())
    }

    /// Order mirror of
    /// [`multi_x25519_continues_past_mac_failure_to_later_slot`]: the REAL
    /// slot is first and the decoy second. The first slot MAC-verifies, so
    /// decrypt succeeds via it; the later decoy slot's MAC failure must not
    /// undo that success.
    #[test]
    fn multi_x25519_later_mac_failure_does_not_undo_earlier_success() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let real_file_key = FileKey::generate().unwrap();
        let decoy_file_key = FileKey::generate().unwrap();

        let body_real = x25519::wrap(&real_file_key, &pub_a)?;
        let body_decoy = x25519::wrap(&decoy_file_key, &pub_a)?;
        let entries = [
            RecipientEntry::native(NativeRecipientType::X25519, body_real.to_vec())?,
            RecipientEntry::native(NativeRecipientType::X25519, body_decoy.to_vec())?,
        ];

        let payload = b"first slot wins";
        let fcr = tmp.path().join("ok-then-mac-fail.fcr");
        build_multi_recipient_fcr(&entries, &real_file_key, payload, &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a)?;
        assert_eq!(fs::read(dec_dir.join("data.txt"))?, payload);
        Ok(())
    }

    /// Defense-in-depth: an exclusive scheme (`argon2id`) must not be
    /// emitted with more than one recipient. The public API has no path
    /// to construct that, but a future caller bypass would break the
    /// `FORMAT.md` §4.1 mixing rule before any output bytes are
    /// written. The orchestrator catches this before any KDF runs.
    #[test]
    fn encrypt_rejects_multi_passphrase_recipient_list() -> Result<(), CryptoError> {
        let pass = Passphrase::new("pass");
        let kdf_params = crate::crypto::kdf::KdfParams::test_fast_default();
        let r1 = argon2id::PassphraseRecipient {
            passphrase: &pass,
            kdf_params,
            kdf_limit: crate::crypto::kdf::KdfLimit::default(),
        };
        let r2 = argon2id::PassphraseRecipient {
            passphrase: &pass,
            kdf_params,
            kdf_limit: crate::crypto::kdf::KdfLimit::default(),
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
            HeaderReadLimits::default(),
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
    /// `X25519Credential`. The orchestrator must surface
    /// `DecryptorModeMismatch { expected: PublicKey, found: Passphrase }`
    /// before any slot loop runs — never the legacy
    /// `NoSupportedRecipient`, which would imply "the loop iterated and
    /// found nothing." The public Decryptor::open routes by mode and so
    /// can't reach this branch; the test invokes `protocol::decrypt`
    /// directly to lock in the wording for internal/plugin callers.
    #[test]
    fn decrypt_rejects_passphrase_file_with_x25519_credential() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (_pub_a, priv_a, pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        // Single argon2id recipient with a synthetic body. The
        // cross-mode check fires before any AEAD/KDF runs, so the body
        // contents are irrelevant — `classify_recipient_mode` only
        // looks at type_name.
        let synthetic = RecipientEntry::native(
            NativeRecipientType::Argon2id,
            vec![0u8; argon2id::BODY_LENGTH],
        )?;
        let file_key = FileKey::generate().unwrap();
        let fcr = tmp.path().join("passphrase.fcr");
        build_multi_recipient_fcr(&[synthetic], &file_key, b"x", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        match recipient_decrypt(&fcr, &dec_dir, &priv_a, &pass_a) {
            Err(CryptoError::DecryptorModeMismatch { expected, found })
                if expected == UnauthenticatedRecipientMode::PublicKey
                    && found == UnauthenticatedRecipientMode::Passphrase =>
            {
                Ok(())
            }
            other => panic!(
                "expected DecryptorModeMismatch(expected=PublicKey, found=Passphrase), got {other:?}"
            ),
        }
    }

    /// Cross-mode mismatch in the reverse direction: a recipient-sealed
    /// file opened with a `PassphraseCredential`. Symmetric assertion to
    /// [`decrypt_rejects_passphrase_file_with_x25519_credential`].
    #[test]
    fn decrypt_rejects_recipient_file_with_passphrase_credential() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let (pub_a, _priv_a, _pass_a) = keypair_fixture(&keys_dir, "alice", "alice-pass")?;

        let file_key = FileKey::generate().unwrap();
        let body_a = x25519::wrap(&file_key, &pub_a)?;
        let entries = [RecipientEntry::native(
            NativeRecipientType::X25519,
            body_a.to_vec(),
        )?];
        let fcr = tmp.path().join("recipient.fcr");
        build_multi_recipient_fcr(&entries, &file_key, b"x", &fcr)?;

        let dec_dir = tmp.path().join("decrypted");
        fs::create_dir_all(&dec_dir)?;
        let pass = Passphrase::new("doesn't-matter");
        let credential = argon2id::PassphraseCredential {
            passphrase: &pass,
            kdf_limit: None,
        };
        let err = decrypt(
            &credential,
            &fcr,
            &dec_dir,
            ArchiveLimits::default(),
            HeaderReadLimits::default(),
            IncompleteOutputPolicy::default(),
            &|_| {},
        )
        .unwrap_err();
        match err {
            CryptoError::DecryptorModeMismatch { expected, found }
                if expected == UnauthenticatedRecipientMode::Passphrase
                    && found == UnauthenticatedRecipientMode::PublicKey =>
            {
                Ok(())
            }
            other => panic!(
                "expected DecryptorModeMismatch(expected=Passphrase, found=PublicKey), got {other:?}"
            ),
        }
    }

    /// Defense-in-depth: empty recipient list rejected before any
    /// allocation or KDF. The public API gates this at construction
    /// time (`with_public_keys` returns `EmptyRecipientList`), but the
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
            HeaderReadLimits::default(),
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

    /// The recipient-count cap gate lives in `encrypt` itself: a list
    /// above the default `HeaderReadLimits` cap rejects before any
    /// ECDH or output work, so no in-crate caller can emit a header
    /// the default reader refuses.
    #[test]
    fn encrypt_rejects_recipient_count_above_local_cap() -> Result<(), CryptoError> {
        let (_secret, public) = x25519::generate_keypair()?;
        let over = HeaderReadLimits::RECIPIENT_COUNT_DEFAULT + 1;
        let recipients: Vec<x25519::X25519Recipient> = (0..over)
            .map(|_| x25519::X25519Recipient {
                recipient_public_key_bytes: &public,
            })
            .collect();

        let tmp = tempfile::TempDir::new().unwrap();
        let input = tmp.path().join("data.txt");
        fs::write(&input, b"x")?;
        let out_dir = tmp.path().join("out");
        fs::create_dir_all(&out_dir)?;

        let err = encrypt(
            &recipients,
            ArchiveLimits::default(),
            HeaderReadLimits::default(),
            &input,
            &out_dir,
            None,
            &|_| {},
        )
        .unwrap_err();
        match err {
            CryptoError::RecipientCountCapExceeded { count, local_cap } => {
                assert_eq!(count, over);
                assert_eq!(local_cap, HeaderReadLimits::RECIPIENT_COUNT_DEFAULT);
                Ok(())
            }
            other => panic!("expected RecipientCountCapExceeded, got {other:?}"),
        }
    }

    /// The KDF write gate lives in `encrypt` itself: passphrase
    /// parameters above the default `KdfLimit` memory policy reject
    /// before any Argon2id run, so no in-crate caller can emit an
    /// `argon2id` body the default reader refuses.
    #[test]
    fn encrypt_rejects_kdf_memory_above_write_policy() -> Result<(), CryptoError> {
        use crate::crypto::kdf::{KdfLimit, KdfParams};

        let pass = Passphrase::new("pass");
        let recipient = argon2id::PassphraseRecipient {
            passphrase: &pass,
            kdf_params: KdfParams {
                mem_cost: KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX,
                time_cost: 1,
                lanes: 1,
            },
            kdf_limit: KdfLimit::default(),
        };

        let tmp = tempfile::TempDir::new().unwrap();
        let input = tmp.path().join("data.txt");
        fs::write(&input, b"x")?;
        let out_dir = tmp.path().join("out");
        fs::create_dir_all(&out_dir)?;

        let err = encrypt(
            std::slice::from_ref(&recipient),
            ArchiveLimits::default(),
            HeaderReadLimits::default(),
            &input,
            &out_dir,
            None,
            &|_| {},
        )
        .unwrap_err();
        match err {
            CryptoError::KdfResourceCapExceeded {
                mem_cost_kib,
                local_cap_kib,
            } => {
                assert_eq!(mem_cost_kib, KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX);
                assert_eq!(local_cap_kib, KdfLimit::MEM_COST_KIB_DEFAULT);
                Ok(())
            }
            other => panic!("expected KdfResourceCapExceeded, got {other:?}"),
        }
    }

    /// The KDF write gate lives in `generate_key_pair` itself:
    /// below-floor memory rejects before the output directory is even
    /// created, so no in-crate caller can seal a weak `private.key`.
    #[test]
    fn generate_key_pair_rejects_kdf_memory_below_write_floor() {
        use crate::crypto::kdf::KdfParams;

        let tmp = tempfile::TempDir::new().unwrap();
        let keys_dir = tmp.path().join("keys");
        let pass = Passphrase::new("pass");
        let weak = KdfParams {
            mem_cost: KdfParams::MIN_WRITE_MEM_COST - 1,
            time_cost: 1,
            lanes: 1,
        };
        let err = generate_key_pair(&pass, &weak, None, &keys_dir, &|_| {}).unwrap_err();
        match err {
            CryptoError::KdfBelowWriteFloor { .. } => {}
            other => panic!("expected KdfBelowWriteFloor, got {other:?}"),
        }
        assert!(
            !keys_dir.exists(),
            "gate must fire before the output directory is created"
        );
    }

    /// Creates a staged key-file temporary file in `dir` containing `bytes`.
    fn staged_key_tempfile(dir: &Path, bytes: &[u8]) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut tmp = tempfile::Builder::new()
            .prefix(".ferrocrypt-keygen-test-")
            .suffix(".tmp")
            .tempfile_in(dir)
            .unwrap();
        tmp.as_file_mut().write_all(bytes).unwrap();
        tmp
    }

    /// Returns the entry names in `dir`, excluding `keep`. Commit-failure
    /// tests use this to verify that no temporary files remain.
    fn leftover_entries(dir: &Path, keep: &str) -> Vec<std::ffi::OsString> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|name| name != keep)
            .collect()
    }

    /// If the `public.key` commit fails after preflight, the newly committed
    /// `private.key` is removed and the existing `public.key` entry is left
    /// unchanged.
    #[test]
    fn keygen_public_commit_failure_removes_private_key() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        let private_key_path = dir.join(PRIVATE_KEY_FILENAME);
        let public_key_path = dir.join(PUBLIC_KEY_FILENAME);
        fs::write(&public_key_path, b"occupant").unwrap();

        let private_tmp = staged_key_tempfile(dir, b"private bytes");
        let public_tmp = staged_key_tempfile(dir, b"public bytes");

        let err =
            commit_key_pair_files(private_tmp, public_tmp, &private_key_path, &public_key_path)
                .expect_err("occupied public.key name must fail the commit");
        assert!(
            matches!(err, CryptoError::InvalidInput(_)),
            "expected the typed already-exists rejection, got {err:?}"
        );
        assert!(
            !private_key_path.exists(),
            "private.key must not remain after the public.key commit failed"
        );
        assert_eq!(
            fs::read(&public_key_path).unwrap(),
            b"occupant",
            "pre-existing occupant of the public.key name must be untouched"
        );
        let leftovers = leftover_entries(dir, PUBLIC_KEY_FILENAME);
        assert!(
            leftovers.is_empty(),
            "no staged tempfiles may remain, found {leftovers:?}"
        );
    }

    /// If the `private.key` commit fails after preflight, `public.key` is not
    /// published, the existing entry remains unchanged, and no temporary files
    /// remain.
    #[test]
    fn keygen_private_commit_failure_publishes_nothing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        let private_key_path = dir.join(PRIVATE_KEY_FILENAME);
        let public_key_path = dir.join(PUBLIC_KEY_FILENAME);
        fs::write(&private_key_path, b"occupant").unwrap();

        let private_tmp = staged_key_tempfile(dir, b"private bytes");
        let public_tmp = staged_key_tempfile(dir, b"public bytes");

        let err =
            commit_key_pair_files(private_tmp, public_tmp, &private_key_path, &public_key_path)
                .expect_err("occupied private.key name must fail the commit");
        assert!(
            matches!(err, CryptoError::InvalidInput(_)),
            "expected the typed already-exists rejection, got {err:?}"
        );
        assert!(
            !public_key_path.exists(),
            "public.key must never appear when the private.key commit failed"
        );
        assert_eq!(
            fs::read(&private_key_path).unwrap(),
            b"occupant",
            "pre-existing occupant of the private.key name must be untouched"
        );
        let leftovers = leftover_entries(dir, PRIVATE_KEY_FILENAME);
        assert!(
            leftovers.is_empty(),
            "no staged tempfiles may remain, found {leftovers:?}"
        );
    }

    /// Records one directory-flush call: the directory and whether each final
    /// key-file name existed at that time.
    #[derive(Debug, PartialEq, Eq)]
    struct BarrierCall {
        dir: PathBuf,
        private_committed: bool,
        public_committed: bool,
    }

    /// Directory-flush test function. It records every call and optionally
    /// returns an injected I/O error on the selected one-based call number.
    fn counting_barrier(
        fail_on: Option<u32>,
        seen: std::rc::Rc<std::cell::RefCell<Vec<BarrierCall>>>,
    ) -> impl Fn(&Path) -> std::io::Result<()> {
        move |dir| {
            seen.borrow_mut().push(BarrierCall {
                dir: dir.to_path_buf(),
                private_committed: dir.join(PRIVATE_KEY_FILENAME).exists(),
                public_committed: dir.join(PUBLIC_KEY_FILENAME).exists(),
            });
            if Some(seen.borrow().len() as u32) == fail_on {
                Err(std::io::Error::other("injected directory flush failure"))
            } else {
                Ok(())
            }
        }
    }

    /// If the directory flush after committing `private.key` fails, the
    /// private key is removed, `public.key` is never published, the original
    /// error is returned, and no temporary files remain.
    #[test]
    fn keygen_barrier_failure_after_private_commit_publishes_nothing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        let private_key_path = dir.join(PRIVATE_KEY_FILENAME);
        let public_key_path = dir.join(PUBLIC_KEY_FILENAME);
        let private_tmp = staged_key_tempfile(dir, b"private bytes");
        let public_tmp = staged_key_tempfile(dir, b"public bytes");
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));

        let err = commit_key_pair_files_with_barrier(
            private_tmp,
            public_tmp,
            &private_key_path,
            &public_key_path,
            counting_barrier(Some(1), seen.clone()),
        )
        .expect_err("a failed directory flush after private.key must fail the commit");
        assert_eq!(
            err.to_string(),
            "injected directory flush failure",
            "the directory flush error must surface unchanged, got {err:?}"
        );
        assert!(
            matches!(err, CryptoError::Io(_)),
            "directory flush failure must map to the I/O error class, got {err:?}"
        );
        assert!(
            !private_key_path.exists(),
            "private.key must be removed when its directory flush failed"
        );
        assert!(
            !public_key_path.exists(),
            "public.key must never appear when the private.key directory flush failed"
        );
        let leftovers = leftover_entries(dir, "");
        assert!(
            leftovers.is_empty(),
            "no key files or staged tempfiles may remain, found {leftovers:?}"
        );
    }

    /// If the directory flush after committing `public.key` fails, only
    /// `public.key` is removed. `private.key` remains because, without a
    /// working directory flush, removing both could be persisted in an order
    /// that leaves only `public.key`.
    #[test]
    fn keygen_barrier_failure_after_public_commit_keeps_only_private_key() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        let private_key_path = dir.join(PRIVATE_KEY_FILENAME);
        let public_key_path = dir.join(PUBLIC_KEY_FILENAME);
        let private_tmp = staged_key_tempfile(dir, b"private bytes");
        let public_tmp = staged_key_tempfile(dir, b"public bytes");
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));

        let err = commit_key_pair_files_with_barrier(
            private_tmp,
            public_tmp,
            &private_key_path,
            &public_key_path,
            counting_barrier(Some(2), seen.clone()),
        )
        .expect_err("a failed directory flush after public.key must fail the commit");
        assert!(
            matches!(err, CryptoError::Io(_)),
            "directory flush failure must map to the I/O error class, got {err:?}"
        );
        assert!(
            !public_key_path.exists(),
            "public.key must be removed when the final directory flush failed"
        );
        assert_eq!(
            fs::read(&private_key_path).unwrap(),
            b"private bytes",
            "private.key must be kept when the final directory flush failed"
        );
        let leftovers = leftover_entries(dir, PRIVATE_KEY_FILENAME);
        assert!(
            leftovers.is_empty(),
            "nothing besides private.key may remain, found {leftovers:?}"
        );
    }

    /// A successful commit flushes the output directory after each key-file
    /// commit. The first flush must observe only `private.key`; the second must
    /// observe both files. This verifies the private-first order.
    #[test]
    fn keygen_commit_flushes_output_directory_after_each_commit() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        let private_key_path = dir.join(PRIVATE_KEY_FILENAME);
        let public_key_path = dir.join(PUBLIC_KEY_FILENAME);
        let private_tmp = staged_key_tempfile(dir, b"private bytes");
        let public_tmp = staged_key_tempfile(dir, b"public bytes");
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));

        commit_key_pair_files_with_barrier(
            private_tmp,
            public_tmp,
            &private_key_path,
            &public_key_path,
            counting_barrier(None, seen.clone()),
        )
        .expect("commit must succeed when directory flushing succeeds");
        assert_eq!(
            *seen.borrow(),
            vec![
                BarrierCall {
                    dir: dir.to_path_buf(),
                    private_committed: true,
                    public_committed: false,
                },
                BarrierCall {
                    dir: dir.to_path_buf(),
                    private_committed: true,
                    public_committed: true,
                },
            ],
            "the output directory must be flushed after each of the two \
             commits, and private.key must commit before public.key"
        );
        assert_eq!(fs::read(&private_key_path).unwrap(), b"private bytes");
        assert_eq!(fs::read(&public_key_path).unwrap(), b"public bytes");
    }
}
