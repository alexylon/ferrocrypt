//! Shared `.fcr` encrypted-file header build/parse path.
//!
//! The format defines **one** encrypted-file container with a typed recipient
//! list — there is no per-mode envelope or "symmetric vs hybrid" type byte.
//! Every encrypt and decrypt path therefore shares the same header
//! arithmetic and MAC scope, and this module is the **single source of
//! truth** for it.
//!
//! Wire layout (`FORMAT.md` §3):
//!
//! ```text
//! [prefix(12)] [header_fixed(31)] [recipient_entries(N)] [ext_bytes] [header_mac(32)] [payload]
//! ```
//!
//! The header MAC covers `prefix || header_fixed || recipient_entries ||
//! ext_bytes` exactly. Keeping the encode and decode paths in one place
//! eliminates a class of "encrypt and decrypt cover different byte ranges"
//! bugs.
//!
//! ## What this module does NOT do
//!
//! - It does not authenticate the header. The MAC is computed/verified by
//!   `format::compute_header_mac` / `verify_header_mac`; this module
//!   *includes* the MAC tag in the on-disk byte stream and the parsed result,
//!   but the caller is responsible for verifying it after they've recovered a
//!   candidate `header_key` from a successful recipient unwrap. Per
//!   `FORMAT.md` §3.7, a candidate `file_key` is not final until the MAC
//!   verifies.
//! - It does not validate `ext_bytes` TLV structure. TLV validation runs
//!   *after* MAC verification (so the validator can trust authenticated
//!   bytes). Callers invoke `crypto::tlv::validate_tlv` on `ext_bytes` after
//!   `format::verify_header_mac` succeeds.
//! - It does not enforce recipient-mixing policy, classify modes, or run
//!   recipient unwrap. Those concerns live in `recipient/policy.rs`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::archive;
use crate::crypto::keys::{HeaderKey, PayloadKey};
use crate::crypto::stream::{STREAM_NONCE_SIZE, payload_encryptor};
use crate::error::{CryptoError, FormatDefect};
use crate::format::{
    self, HEADER_FIXED_SIZE, HEADER_MAC_SIZE, HeaderFixed, Kind, PREFIX_SIZE, Prefix,
    check_recipient_count, read_exact_or_truncated,
};
use crate::fs::atomic;
use crate::fs::paths::{INCOMPLETE_SUFFIX, OUTPUT_LABEL, parent_or_cwd, reject_occupied};
use crate::recipient::{self, RecipientEntry};

/// Tempfile name prefix for the in-flight `.fcr` write. Combined with
/// [`INCOMPLETE_SUFFIX`] this yields a `.ferrocrypt-*.incomplete`
/// staging name in the destination directory; on success
/// [`atomic::finalize_file`] promotes it to the user-visible
/// output path.
const TEMP_FILE_PREFIX: &str = ".ferrocrypt-";

/// Local resource caps applied while reading an encrypted-file header.
///
/// The defaults mirror `format::*_LOCAL_CAP_DEFAULT` and apply to every
/// reader path. Callers may raise individual caps for trusted input
/// (for example, files from a known origin that legitimately use more
/// recipient slots, larger recipient bodies, or a larger header than
/// the conservative defaults allow) by calling the `max_*` builder
/// methods. Each builder clamps at the structural maximum for that
/// field — the `.fcr` format cannot represent values above
/// [`HeaderReadLimits::HEADER_LEN_STRUCTURAL_MAX`],
/// [`HeaderReadLimits::RECIPIENT_COUNT_STRUCTURAL_MAX`], or
/// [`HeaderReadLimits::RECIPIENT_BODY_LEN_STRUCTURAL_MAX`], so callers
/// cannot accidentally request a cap higher than what the structural
/// parser would accept anyway.
///
/// Caps are enforced **before** any cryptographic operation runs. Per
/// `FORMAT.md` §1 and §3.2, malicious input must not be able to force
/// unbounded work, and exceeding a local cap surfaces as a distinct
/// `*CapExceeded` error rather than as a generic format defect.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct HeaderReadLimits {
    /// Hard cap on `prefix.header_len`.
    pub(crate) max_header_len: u32,
    /// Hard cap on `header_fixed.recipient_count`.
    pub(crate) max_recipient_count: u16,
    /// Hard cap on each individual recipient entry's `body_len`. Applies
    /// to known and unknown entries alike, so an unknown-recipient slot
    /// cannot force excessive allocation in a reader that would skip it.
    pub(crate) max_recipient_body_len: u32,
}

impl Default for HeaderReadLimits {
    fn default() -> Self {
        Self {
            max_header_len: Self::HEADER_LEN_DEFAULT,
            max_recipient_count: Self::RECIPIENT_COUNT_DEFAULT,
            max_recipient_body_len: Self::RECIPIENT_BODY_LEN_DEFAULT,
        }
    }
}

impl HeaderReadLimits {
    /// Structural maximum for `prefix.header_len` (16 MiB,
    /// `FORMAT.md` §3.1). Builder methods clamp at this value.
    pub const HEADER_LEN_STRUCTURAL_MAX: u32 = format::HEADER_LEN_MAX;
    /// Structural maximum for `header_fixed.recipient_count` (4096,
    /// `FORMAT.md` §3.2). Builder methods clamp at this value.
    pub const RECIPIENT_COUNT_STRUCTURAL_MAX: u16 = format::RECIPIENT_COUNT_MAX;
    /// Structural maximum for each recipient entry's `body_len`
    /// (16 MiB, `FORMAT.md` §3.3). Builder methods clamp at this
    /// value.
    pub const RECIPIENT_BODY_LEN_STRUCTURAL_MAX: u32 = format::BODY_LEN_MAX;

    /// Default value used by [`HeaderReadLimits::default`] for
    /// `max_header_len`. Mirrored on the writer side so the default
    /// `Encryptor` never produces a header longer than the default
    /// reader will accept.
    pub const HEADER_LEN_DEFAULT: u32 = format::HEADER_LEN_LOCAL_CAP_DEFAULT;
    /// Default value used by [`HeaderReadLimits::default`] for
    /// `max_recipient_count`. Mirrored on the writer side via
    /// [`crate::Encryptor::header_read_limits`] so a default
    /// `Encryptor` rejects recipient lists above this cap before any
    /// X25519 ECDH runs.
    pub const RECIPIENT_COUNT_DEFAULT: u16 = format::RECIPIENT_COUNT_LOCAL_CAP_DEFAULT;
    /// Default value used by [`HeaderReadLimits::default`] for
    /// `max_recipient_body_len`. Applies symmetrically on encrypt
    /// (native entries sit well under this cap) and decrypt.
    pub const RECIPIENT_BODY_LEN_DEFAULT: u32 = format::BODY_LEN_LOCAL_CAP_DEFAULT;

    /// Sets the maximum accepted `prefix.header_len`, clamped at
    /// [`Self::HEADER_LEN_STRUCTURAL_MAX`]. Files declaring a longer
    /// header reject with [`CryptoError::HeaderLenCapExceeded`] before
    /// any allocation.
    pub fn max_header_len(mut self, value: u32) -> Self {
        self.max_header_len = value.min(Self::HEADER_LEN_STRUCTURAL_MAX);
        self
    }

    /// Sets the maximum accepted recipient count, clamped at
    /// [`Self::RECIPIENT_COUNT_STRUCTURAL_MAX`]. Files declaring more
    /// entries reject with [`CryptoError::RecipientCountCapExceeded`].
    pub fn max_recipient_count(mut self, value: u16) -> Self {
        self.max_recipient_count = value.min(Self::RECIPIENT_COUNT_STRUCTURAL_MAX);
        self
    }

    /// Sets the maximum accepted per-entry `body_len`, clamped at
    /// [`Self::RECIPIENT_BODY_LEN_STRUCTURAL_MAX`]. Applies to known and
    /// unknown recipient types alike. Entries with a larger body reject
    /// with [`CryptoError::RecipientBodyCapExceeded`].
    pub fn max_recipient_body_len(mut self, value: u32) -> Self {
        self.max_recipient_body_len = value.min(Self::RECIPIENT_BODY_LEN_STRUCTURAL_MAX);
        self
    }

    /// Single source of truth for the `header_len` cap check. Used by
    /// the reader's `read_encrypted_header` against the header declared
    /// in the prefix; available to writer-side preflight when a future
    /// large-header recipient list could exceed
    /// [`Self::HEADER_LEN_DEFAULT`].
    pub(crate) fn enforce_header_len(&self, header_len: u32) -> Result<(), CryptoError> {
        if header_len > self.max_header_len {
            return Err(CryptoError::HeaderLenCapExceeded {
                header_len,
                local_cap: self.max_header_len,
            });
        }
        Ok(())
    }

    /// Single source of truth for the `recipient_count` cap check.
    /// Called from the reader's `read_encrypted_header` (against the
    /// `header_fixed.recipient_count` declared on disk) AND from the
    /// writer's [`crate::Encryptor::write`] (against the in-memory
    /// recipient list size) so default-encrypt and default-decrypt
    /// stay in lockstep.
    pub(crate) fn enforce_recipient_count(&self, count: u16) -> Result<(), CryptoError> {
        if count > self.max_recipient_count {
            return Err(CryptoError::RecipientCountCapExceeded {
                count,
                local_cap: self.max_recipient_count,
            });
        }
        Ok(())
    }

    /// Single source of truth for the per-recipient `body_len` cap
    /// check. The reader applies this inside `RecipientEntry::parse_one`
    /// (to avoid a dependency cycle); writer-side preflight calls this
    /// method against the canonical native body lengths before any
    /// wrapping/KDF work runs.
    pub(crate) fn enforce_recipient_body_len(&self, body_len: u32) -> Result<(), CryptoError> {
        if body_len > self.max_recipient_body_len {
            return Err(CryptoError::RecipientBodyCapExceeded {
                body_len,
                local_cap: self.max_recipient_body_len,
            });
        }
        Ok(())
    }
}

// The reader enforces `max_recipient_body_len` inside
// `RecipientEntry::parse_one`: that module sits below `container` in the
// dependency graph and cannot import [`HeaderReadLimits`] without a cycle. The
// cap is therefore passed as a `u32`, and `recipient/entry.rs` constructs the
// typed [`CryptoError::RecipientBodyCapExceeded`] error. Writer-side preflight
// calls [`HeaderReadLimits::enforce_recipient_body_len`] directly against the
// canonical native body lengths before any wrapping or KDF work runs. The cap
// value still has a single source of truth
// ([`HeaderReadLimits::max_recipient_body_len`] +
// [`HeaderReadLimits::RECIPIENT_BODY_LEN_DEFAULT`]); only the reader-side check
// site lives in `recipient/entry.rs`.

/// A structurally parsed `.fcr` header. Authenticity has NOT been checked;
/// the caller must call [`format::verify_header_mac`] with a `header_key`
/// derived from a successfully unwrapped candidate `file_key` before
/// trusting `ext_bytes` or accepting the candidate.
///
/// The byte buffers ([`prefix_bytes`](Self::prefix_bytes),
/// [`header_bytes`](Self::header_bytes)) are kept verbatim because the MAC
/// is computed over the on-disk encoding, not over the parsed structs.
pub(crate) struct ParsedEncryptedHeader {
    /// Raw 12-byte prefix as read from disk (input to MAC).
    pub prefix_bytes: [u8; PREFIX_SIZE],
    /// Parsed `header_fixed` fields.
    pub fixed: HeaderFixed,
    /// Raw `header` region as read from disk (input to MAC). This is
    /// `header_fixed || recipient_entries || ext_bytes`, of length
    /// `prefix.header_len`.
    pub header_bytes: Vec<u8>,
    /// Parsed recipient entries, in declared order. Length matches
    /// `fixed.recipient_count`.
    pub recipient_entries: Vec<RecipientEntry>,
    /// Authenticated extension TLV region. Caller must run
    /// `crypto::tlv::validate_tlv` on this after MAC verification.
    pub ext_bytes: Vec<u8>,
    /// On-disk header MAC tag. Caller must verify against
    /// `format::compute_header_mac(prefix_bytes, header_bytes, header_key)`.
    pub header_mac: [u8; HEADER_MAC_SIZE],
}

/// A serialized `.fcr` header bundled with the streaming materials needed
/// to write the rest of the file.
///
/// Wire layout: `prefix_bytes || header_bytes || header_mac || <payload>`.
/// The caller writes these three byte regions in order, then streams the
/// encrypted payload after `header_mac` using `payload_key` + `stream_nonce`.
///
/// `payload_key` and `stream_nonce` are bundled in (rather than threaded
/// through a separate channel) so a caller cannot accidentally pair the
/// header with subkeys derived from a different `file_key`/`stream_nonce`:
/// the only constructor is [`build_encrypted_header`], which derives the
/// MAC from the same `header_key` and binds `payload_key`/`stream_nonce`
/// to the returned header in one move.
pub(crate) struct BuiltEncryptedHeader {
    pub prefix_bytes: [u8; PREFIX_SIZE],
    pub header_bytes: Vec<u8>,
    pub header_mac: [u8; HEADER_MAC_SIZE],
    pub stream_nonce: [u8; STREAM_NONCE_SIZE],
    pub payload_key: PayloadKey,
}

/// Wraps a byte slice so `{:?}` renders as compact lowercase hex
/// instead of `[70, 67, 82, 0, ...]`. Local to the manual `Debug`
/// impl below; not allocating (writes byte-by-byte to the formatter).
struct HexBytes<'a>(&'a [u8]);

impl std::fmt::Debug for HexBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

// Manual `Debug` redacts `payload_key`. `Zeroizing<[u8; 32]>` derives
// `Debug` transparently from `[u8; 32]`, which would print the raw key
// bytes via `{:?}` (used by `Result::unwrap_err`, panic messages, etc.).
// If a future field also holds secret material, redact it here too.
//
// The non-secret byte fields (`prefix_bytes`, `header_mac`,
// `stream_nonce`) render as lowercase hex via `HexBytes` — easier to
// read in panic / log lines than a raw decimal byte array.
// `header_bytes` shows only its length: it can be up to about 16 MiB
// (`HEADER_LEN_MAX`), so dumping its content in every debug print
// would be noisy and expensive.
impl std::fmt::Debug for BuiltEncryptedHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltEncryptedHeader")
            .field("prefix_bytes", &HexBytes(&self.prefix_bytes))
            .field("header_bytes_len", &self.header_bytes.len())
            .field("header_mac", &HexBytes(&self.header_mac))
            .field("stream_nonce", &HexBytes(&self.stream_nonce))
            .field("payload_key", &"<redacted>")
            .finish()
    }
}

// Manual `Debug` mirrors `BuiltEncryptedHeader`: `header_bytes` can be
// up to about 16 MiB (`HEADER_LEN_MAX`) and `ext_bytes` up to 64 KiB, so a
// derived implementation would dump megabytes of byte noise into any panic or
// log line that renders a parsed header. No secret material here; all fields
// are on-disk bytes, so this is log hygiene only.
impl std::fmt::Debug for ParsedEncryptedHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedEncryptedHeader")
            .field("prefix_bytes", &HexBytes(&self.prefix_bytes))
            .field("fixed", &self.fixed)
            .field("header_bytes_len", &self.header_bytes.len())
            .field("recipient_entry_count", &self.recipient_entries.len())
            .field("ext_bytes_len", &self.ext_bytes.len())
            .field("header_mac", &HexBytes(&self.header_mac))
            .finish()
    }
}

/// Reads, structurally validates, and bounds-checks a `.fcr` header from
/// `reader`. Stops after the MAC tag — the caller streams the payload
/// from the same reader afterwards.
///
/// Performs zero cryptographic work. All cap rejections fire before any
/// large allocation is committed:
///
/// 1. read 12-byte prefix → [`Prefix::parse`] (BadMagic / WrongKind /
///    UnsupportedVersion / MalformedHeader / OversizedHeader);
/// 2. enforce `prefix.header_len <= limits.max_header_len`;
/// 3. read the entire `header_len`-byte `header` region into one buffer;
/// 4. read the 32-byte header MAC tag into a fixed-size buffer. Steps 3
///    and 4 are the container's framing reads and complete before any
///    structural parse: per `FORMAT.md` §3.7 step 3, early EOF in either
///    surfaces as [`FormatDefect::Truncated`] rather than a downstream
///    structural defect;
/// 5. parse the leading 31 bytes as `header_fixed` → [`HeaderFixed::parse`]
///    (header_flags == 0, recipient_count in range, ext_len in range,
///    region lengths self-consistent). A `header_len` too small to hold
///    `header_fixed` rejects as `MalformedHeader` here, after the
///    framing reads;
/// 6. enforce `recipient_count <= limits.max_recipient_count`;
/// 7. parse the recipient list from `header[31..31+recipient_entries_len]`,
///    enforcing `body_len <= limits.max_recipient_body_len` per entry;
/// 8. capture the trailing `ext_bytes` slice (TLV validation deferred
///    to AFTER MAC verification — see `FORMAT.md` §3.7);
/// 9. return the parsed header. **MAC is not yet verified.**
pub(crate) fn read_encrypted_header<R: Read>(
    reader: &mut R,
    limits: HeaderReadLimits,
) -> Result<ParsedEncryptedHeader, CryptoError> {
    let (prefix_bytes, prefix) = format::read_prefix_from_reader(reader, Kind::Encrypted)?;

    limits.enforce_header_len(prefix.header_len)?;

    // Cap-bounded above. Cast is safe.
    let header_len = prefix.header_len as usize;
    let mut header_bytes = vec![0u8; header_len];
    read_exact_or_truncated(reader, &mut header_bytes)?;

    // Per `FORMAT.md` §3.7 step 3, the MAC-tag read is a framing read:
    // it must complete, or fail as `Truncated`, before structural parsing
    // starts. Otherwise a file that omits the MAC bytes could surface as
    // `MalformedHeader` and hide the simpler "file is truncated" diagnostic.
    let mut header_mac = [0u8; HEADER_MAC_SIZE];
    read_exact_or_truncated(reader, &mut header_mac)?;

    // Undersized-header rejection point (`FORMAT.md` §3.7): the prefix
    // stage accepts any `header_len` up to the structural maximum, so a
    // header too small to hold `header_fixed` is caught here, after the
    // framing reads above have completed.
    let fixed_bytes: &[u8; HEADER_FIXED_SIZE] = header_bytes
        .first_chunk()
        .ok_or(CryptoError::InvalidFormat(FormatDefect::MalformedHeader))?;
    let fixed = HeaderFixed::parse(fixed_bytes, prefix.header_len)?;

    limits.enforce_recipient_count(fixed.recipient_count)?;

    let entries_start = HEADER_FIXED_SIZE;
    let entries_end = entries_start
        .checked_add(fixed.recipient_entries_len as usize)
        .ok_or(CryptoError::InvalidFormat(FormatDefect::MalformedHeader))?;
    let ext_end = entries_end
        .checked_add(fixed.ext_len as usize)
        .ok_or(CryptoError::InvalidFormat(FormatDefect::MalformedHeader))?;
    if ext_end != header_len {
        return Err(CryptoError::InvalidFormat(FormatDefect::MalformedHeader));
    }

    let recipient_entries = recipient::parse_recipient_entries(
        &header_bytes[entries_start..entries_end],
        fixed.recipient_count,
        limits.max_recipient_body_len,
    )?;

    let ext_bytes = header_bytes[entries_end..ext_end].to_vec();

    Ok(ParsedEncryptedHeader {
        prefix_bytes,
        fixed,
        header_bytes,
        recipient_entries,
        ext_bytes,
        header_mac,
    })
}

/// Builds and authenticates a `.fcr` header from caller-supplied recipient
/// entries, ext_bytes, stream nonce, and the subkeys derived from the
/// per-file `file_key`.
///
/// The caller is responsible for:
/// - generating `stream_nonce` (typically `random_bytes::<STREAM_NONCE_SIZE>()?`);
/// - deriving `payload_key` and `header_key` from the freshly generated
///   `file_key` via `crypto::keys::derive_subkeys` (or equivalent);
/// - constructing `recipient_entries` via the per-recipient `wrap`
///   helpers (`recipient::argon2id::wrap`, `recipient::x25519::wrap`).
///
/// On success returns a [`BuiltEncryptedHeader`] holding the three byte
/// regions to write in order (prefix, header, MAC) plus `stream_nonce`
/// and `payload_key` for the payload streamer. Bundling these together
/// makes a (header, payload_key, stream_nonce) mismatch unrepresentable.
///
/// The combined header length is checked against the 16 MiB structural
/// maximum before the recipient buffer is allocated. Oversized recipient
/// lists therefore fail before aggregate serialization.
pub(crate) fn build_encrypted_header(
    recipient_entries: &[RecipientEntry],
    ext_bytes: &[u8],
    stream_nonce: [u8; STREAM_NONCE_SIZE],
    payload_key: PayloadKey,
    header_key: &HeaderKey,
) -> Result<BuiltEncryptedHeader, CryptoError> {
    // Reject an invalid count before per-entry validation. Saturation is
    // safe here because `u16::MAX` always exceeds the structural cap.
    // `HeaderFixed` revalidates the assembled fields below.
    let recipient_count: u16 = recipient_entries.len().try_into().unwrap_or(u16::MAX);
    check_recipient_count(recipient_count)?;

    // Validate each entry and calculate the combined encoded length
    // before allocating the recipient buffer. Per-entry validation
    // errors are preserved, and the header limit is enforced first.
    let mut entries_len_u64: u64 = 0;
    for entry in recipient_entries {
        entries_len_u64 = entries_len_u64
            .checked_add(entry.checked_wire_len()? as u64)
            .ok_or(CryptoError::InvalidFormat(FormatDefect::MalformedHeader))?;
    }
    let header_len_u64 = (HEADER_FIXED_SIZE as u64)
        .checked_add(entries_len_u64)
        .and_then(|v| v.checked_add(ext_bytes.len() as u64))
        .ok_or(CryptoError::InvalidFormat(FormatDefect::MalformedHeader))?;
    // Compare against the structural max while the value is still u64,
    // so the rejection reports the real computed length; only an
    // unrepresentable above-`u32` total saturates the reported value.
    // `validate_structural` re-checks the narrowed value below.
    if header_len_u64 > u64::from(format::HEADER_LEN_MAX) {
        return Err(CryptoError::InvalidFormat(FormatDefect::OversizedHeader {
            header_len: u32::try_from(header_len_u64).unwrap_or(u32::MAX),
        }));
    }
    let header_len: u32 = header_len_u64
        .try_into()
        .map_err(|_| crate::error::internal_invariant!("header length narrowing failed"))?;

    // The aggregate cap above guarantees that the capacity and casts fit
    // `u32` and `usize` on every supported target.
    let mut entries_bytes = Vec::with_capacity(entries_len_u64 as usize);
    for entry in recipient_entries {
        entries_bytes.extend_from_slice(&entry.to_bytes_checked()?);
    }
    let recipient_entries_len: u32 = entries_bytes.len().try_into().unwrap_or(u32::MAX);
    let ext_len: u32 = ext_bytes.len().try_into().unwrap_or(u32::MAX);

    let fixed = HeaderFixed {
        header_flags: 0,
        recipient_count,
        recipient_entries_len,
        ext_len,
        stream_nonce,
    };
    // Single source of truth for `header_fixed` structural rules,
    // shared with the reader's `HeaderFixed::parse`. Catches:
    // `recipient_count == 0` / `> RECIPIENT_COUNT_MAX`, `ext_len >
    // EXT_LEN_MAX`, and section-length consistency in one call.
    fixed.validate_structural(header_len)?;

    let prefix_bytes = Prefix::build_encrypted(header_len)?;
    let fixed_bytes = fixed.to_bytes();

    let mut header_bytes = Vec::with_capacity(header_len as usize);
    header_bytes.extend_from_slice(&fixed_bytes);
    header_bytes.extend_from_slice(&entries_bytes);
    header_bytes.extend_from_slice(ext_bytes);
    debug_assert_eq!(header_bytes.len(), header_len as usize);

    let header_mac = format::compute_header_mac(&prefix_bytes, &header_bytes, header_key)?;

    Ok(BuiltEncryptedHeader {
        prefix_bytes,
        header_bytes,
        header_mac,
        stream_nonce,
        payload_key,
    })
}

/// Resolves the destination path for an encrypted file. If `output_file`
/// is supplied, it is used verbatim; otherwise the file is written under
/// `output_dir` as `<base_name>.<ENCRYPTED_EXTENSION>`.
pub(crate) fn resolve_encrypted_output_path(
    output_dir: &Path,
    output_file: Option<&Path>,
    base_name: &str,
) -> PathBuf {
    match output_file {
        Some(path) => path.to_path_buf(),
        None => output_dir.join(format!("{}.{}", base_name, format::ENCRYPTED_EXTENSION)),
    }
}

/// Streams a prepared FCA archive into an encrypted `.fcr` file at the
/// resolved output path, using the supplied [`BuiltEncryptedHeader`]
/// bundle.
///
/// On-disk byte order: `prefix(12) || header(31 + entries + ext) || mac(32)
/// || payload(STREAM)`. The header bytes, MAC, payload key, and stream
/// nonce all live in `built` so that they cannot be paired with material
/// from a different `file_key`/`stream_nonce`. The payload is
/// XChaCha20-Poly1305 STREAM-BE32 keyed by `built.payload_key` over the
/// archive captured in `prepared`. No plaintext intermediate files touch
/// disk: the FCA stream is piped directly through [`EncryptWriter`].
///
/// Accepting [`archive::PreparedArchive`] ensures that source metadata was
/// collected before this function creates the ciphertext staging file. An
/// output path inside the input tree therefore cannot add the staging file to
/// the archive.
///
/// Atomicity: the file is written under a `.ferrocrypt-*.incomplete`
/// tempfile in the destination's parent directory, then renamed via
/// [`atomic::finalize_file`] only after [`atomic::sync_file_durable`]
/// has flushed it to stable storage. A pre-existing
/// output path rejects with `CryptoError::InvalidInput` before any
/// tempfile is created, so an unrelated file at the destination is
/// never touched.
pub(crate) fn write_encrypted_file(
    prepared: archive::PreparedArchive,
    output_dir: &Path,
    output_file: Option<&Path>,
    base_name: &str,
    built: &BuiltEncryptedHeader,
) -> Result<PathBuf, CryptoError> {
    let output_path = resolve_encrypted_output_path(output_dir, output_file, base_name);
    reject_occupied(&output_path, OUTPUT_LABEL)?;

    let mut builder = tempfile::Builder::new();
    builder.prefix(TEMP_FILE_PREFIX).suffix(INCOMPLETE_SUFFIX);
    // Pin the on-disk mode at owner-only read/write so the `.fcr`
    // file's permissions cannot drift if `tempfile`'s default changes
    // in a future release. AEAD-protected ciphertext does not need to
    // be unreadable on disk for confidentiality, but the conservative
    // default mirrors the `private.key` writer (`protocol.rs` keygen)
    // and matches what users expect for a freshly-written secret.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o600));
    }
    let mut tmp = builder.tempfile_in(parent_or_cwd(&output_path))?;

    tmp.as_file_mut().write_all(&built.prefix_bytes)?;
    tmp.as_file_mut().write_all(&built.header_bytes)?;
    tmp.as_file_mut().write_all(&built.header_mac)?;

    let encrypt_writer = payload_encryptor(&built.payload_key, &built.stream_nonce, tmp);
    let encrypt_writer = prepared.write_to(encrypt_writer)?;
    let tmp = encrypt_writer.finish()?;
    atomic::sync_file_durable(tmp.as_file())?;

    atomic::finalize_file(tmp, &output_path, OUTPUT_LABEL)?;
    Ok(output_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{DerivedSubkeys, FILE_KEY_SIZE, FileKey, derive_subkeys};
    use crate::recipient::entry::RECIPIENT_FLAG_CRITICAL;
    use crate::recipient::{argon2id, x25519};

    fn dummy_entry(type_name: &str, body_len: usize) -> RecipientEntry {
        RecipientEntry {
            type_name: type_name.to_string(),
            recipient_flags: 0,
            body: vec![0xAB; body_len],
        }
    }

    fn dummy_subkeys() -> DerivedSubkeys {
        // Stable inputs so the test is deterministic.
        let file_key = FileKey::from_bytes_for_tests([0x42u8; FILE_KEY_SIZE]);
        let stream_nonce = [0x07u8; STREAM_NONCE_SIZE];
        derive_subkeys(&file_key, &stream_nonce).unwrap()
    }

    /// Concatenates the three on-disk byte regions a writer emits in
    /// order: `prefix || header || mac`. Used by every round-trip /
    /// reader-side test below to feed the parser.
    fn on_disk_bytes(built: &BuiltEncryptedHeader) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            built.prefix_bytes.len() + built.header_bytes.len() + built.header_mac.len(),
        );
        bytes.extend_from_slice(&built.prefix_bytes);
        bytes.extend_from_slice(&built.header_bytes);
        bytes.extend_from_slice(&built.header_mac);
        bytes
    }

    #[test]
    fn build_then_read_round_trip_single_recipient() {
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let stream_nonce = [0x07u8; STREAM_NONCE_SIZE];
        let entry = dummy_entry(argon2id::TYPE_NAME, argon2id::BODY_LENGTH);

        let built = build_encrypted_header(
            std::slice::from_ref(&entry),
            b"",
            stream_nonce,
            payload_key,
            &header_key,
        )
        .unwrap();

        let bytes = on_disk_bytes(&built);
        let parsed =
            read_encrypted_header(&mut bytes.as_slice(), HeaderReadLimits::default()).unwrap();

        assert_eq!(parsed.prefix_bytes, built.prefix_bytes);
        assert_eq!(parsed.header_bytes, built.header_bytes);
        assert_eq!(parsed.header_mac, built.header_mac);
        assert_eq!(parsed.fixed.recipient_count, 1);
        assert_eq!(parsed.fixed.stream_nonce, stream_nonce);
        assert_eq!(parsed.fixed.ext_len, 0);
        assert_eq!(parsed.recipient_entries.len(), 1);
        assert_eq!(parsed.recipient_entries[0].type_name, argon2id::TYPE_NAME);
        assert_eq!(parsed.recipient_entries[0].body, entry.body);
        assert!(parsed.ext_bytes.is_empty());

        // MAC verifies under the same header_key (sanity check; this
        // is what `protocol::decrypt` does after recipient unwrap).
        format::verify_header_mac(
            &parsed.prefix_bytes,
            &parsed.header_bytes,
            &header_key,
            &parsed.header_mac,
        )
        .unwrap();
    }

    #[test]
    fn build_then_read_round_trip_two_recipients_with_ext() {
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let stream_nonce = [0x09u8; STREAM_NONCE_SIZE];
        let entries = vec![
            dummy_entry(x25519::TYPE_NAME, x25519::BODY_LENGTH),
            RecipientEntry {
                type_name: x25519::TYPE_NAME.to_string(),
                recipient_flags: RECIPIENT_FLAG_CRITICAL,
                body: vec![0xCDu8; x25519::BODY_LENGTH],
            },
        ];
        let ext = b"hello-ext";

        let built =
            build_encrypted_header(&entries, ext, stream_nonce, payload_key, &header_key).unwrap();

        let bytes = on_disk_bytes(&built);
        let parsed =
            read_encrypted_header(&mut bytes.as_slice(), HeaderReadLimits::default()).unwrap();
        assert_eq!(parsed.fixed.recipient_count, 2);
        assert_eq!(parsed.recipient_entries.len(), 2);
        assert_eq!(parsed.recipient_entries[0].body, entries[0].body);
        assert_eq!(parsed.recipient_entries[1].body, entries[1].body);
        assert!(parsed.recipient_entries[1].is_critical());
        assert_eq!(parsed.ext_bytes, ext);

        format::verify_header_mac(
            &parsed.prefix_bytes,
            &parsed.header_bytes,
            &header_key,
            &parsed.header_mac,
        )
        .unwrap();
    }

    #[test]
    fn build_rejects_zero_recipients() {
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let err =
            build_encrypted_header(&[], b"", [0u8; STREAM_NONCE_SIZE], payload_key, &header_key)
                .unwrap_err();
        match err {
            CryptoError::InvalidFormat(FormatDefect::RecipientCountOutOfRange { count: 0 }) => {}
            other => panic!("expected RecipientCountOutOfRange(0), got {other:?}"),
        }
    }

    /// An entry list longer than the structural maximum is rejected
    /// before any entry is serialized, independent of the caller's
    /// preflight.
    #[test]
    fn build_rejects_recipient_count_above_structural_max() {
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let over = usize::from(HeaderReadLimits::RECIPIENT_COUNT_STRUCTURAL_MAX) + 1;
        let entries: Vec<_> = (0..over)
            .map(|_| dummy_entry(argon2id::TYPE_NAME, argon2id::BODY_LENGTH))
            .collect();
        let err = build_encrypted_header(
            &entries,
            b"",
            [0u8; STREAM_NONCE_SIZE],
            payload_key,
            &header_key,
        )
        .unwrap_err();
        match err {
            CryptoError::InvalidFormat(FormatDefect::RecipientCountOutOfRange { count }) => {
                assert_eq!(usize::from(count), over);
            }
            other => panic!("expected RecipientCountOutOfRange, got {other:?}"),
        }
    }

    /// A computed header length above the 16 MiB structural max is
    /// rejected with the real computed value, not a sentinel.
    #[test]
    fn build_rejects_oversized_header_with_computed_length() {
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let entry = dummy_entry(argon2id::TYPE_NAME, argon2id::BODY_LENGTH);
        let big_ext = vec![0u8; format::HEADER_LEN_MAX as usize];
        let err = build_encrypted_header(
            &[entry],
            &big_ext,
            [0u8; STREAM_NONCE_SIZE],
            payload_key,
            &header_key,
        )
        .unwrap_err();
        let expected_len = HEADER_FIXED_SIZE as u32
            + (crate::recipient::entry::ENTRY_HEADER_SIZE
                + argon2id::TYPE_NAME.len()
                + argon2id::BODY_LENGTH) as u32
            + format::HEADER_LEN_MAX;
        match err {
            CryptoError::InvalidFormat(FormatDefect::OversizedHeader { header_len }) => {
                assert_eq!(header_len, expected_len);
            }
            other => panic!("expected OversizedHeader with the computed length, got {other:?}"),
        }
    }

    /// Tests the header-length limit using recipient bytes rather than
    /// `ext_bytes`, including the reported calculated length.
    #[test]
    fn build_rejects_oversized_entries_with_computed_length() {
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let entry = dummy_entry(x25519::TYPE_NAME, format::BODY_LEN_MAX as usize);
        let err = build_encrypted_header(
            &[entry],
            b"",
            [0u8; STREAM_NONCE_SIZE],
            payload_key,
            &header_key,
        )
        .unwrap_err();
        let expected_len = HEADER_FIXED_SIZE as u32
            + (crate::recipient::entry::ENTRY_HEADER_SIZE + x25519::TYPE_NAME.len()) as u32
            + format::BODY_LEN_MAX;
        match err {
            CryptoError::InvalidFormat(FormatDefect::OversizedHeader { header_len }) => {
                assert_eq!(header_len, expected_len);
            }
            other => panic!("expected OversizedHeader with the computed length, got {other:?}"),
        }
    }

    /// `build_encrypted_header` propagates `to_bytes_checked`'s
    /// `type_name` grammar rejection.
    #[test]
    fn build_rejects_entry_with_invalid_type_name_grammar() {
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let bad_entry = RecipientEntry {
            type_name: "X25519".to_owned(),
            recipient_flags: 0,
            body: vec![0u8; crate::recipient::native::x25519::BODY_LENGTH],
        };
        let err = build_encrypted_header(
            &[bad_entry],
            b"",
            [0u8; STREAM_NONCE_SIZE],
            payload_key,
            &header_key,
        )
        .unwrap_err();
        match err {
            CryptoError::InvalidFormat(FormatDefect::MalformedTypeName) => {}
            other => panic!("expected MalformedTypeName, got {other:?}"),
        }
    }

    /// `build_encrypted_header` propagates `to_bytes_checked`'s
    /// reserved-flag-bit rejection.
    #[test]
    fn build_rejects_entry_with_reserved_recipient_flags() {
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let bad_entry = RecipientEntry {
            type_name: crate::recipient::native::x25519::TYPE_NAME.to_owned(),
            recipient_flags: 1u16 << 5,
            body: vec![0u8; crate::recipient::native::x25519::BODY_LENGTH],
        };
        let err = build_encrypted_header(
            &[bad_entry],
            b"",
            [0u8; STREAM_NONCE_SIZE],
            payload_key,
            &header_key,
        )
        .unwrap_err();
        match err {
            CryptoError::InvalidFormat(FormatDefect::RecipientFlagsReserved) => {}
            other => panic!("expected RecipientFlagsReserved, got {other:?}"),
        }
    }

    #[test]
    fn build_rejects_ext_above_structural_cap() {
        // `EXT_LEN_MAX = 65_536`. One byte over fires `ExtTooLarge`
        // (the precise diagnostic), not generic `MalformedHeader`.
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let entry = dummy_entry(argon2id::TYPE_NAME, argon2id::BODY_LENGTH);
        let oversize = vec![0u8; format::EXT_LEN_MAX as usize + 1];
        let err = build_encrypted_header(
            &[entry],
            &oversize,
            [0u8; STREAM_NONCE_SIZE],
            payload_key,
            &header_key,
        )
        .unwrap_err();
        match err {
            CryptoError::InvalidFormat(FormatDefect::ExtTooLarge { .. }) => {}
            other => panic!("expected ExtTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn read_rejects_header_len_above_local_cap() {
        // Build a legitimate header with one large `ext_bytes` region so
        // header_len exceeds the small cap we'll set.
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let stream_nonce = [0x07u8; STREAM_NONCE_SIZE];
        let entry = dummy_entry(argon2id::TYPE_NAME, argon2id::BODY_LENGTH);
        let big_ext = vec![0u8; 4096];
        let built =
            build_encrypted_header(&[entry], &big_ext, stream_nonce, payload_key, &header_key)
                .unwrap();

        let bytes = on_disk_bytes(&built);
        let tight_limits = HeaderReadLimits {
            max_header_len: 256,
            ..HeaderReadLimits::default()
        };
        let err = read_encrypted_header(&mut bytes.as_slice(), tight_limits).unwrap_err();
        match err {
            CryptoError::HeaderLenCapExceeded { local_cap: 256, .. } => {}
            other => panic!("expected HeaderLenCapExceeded, got {other:?}"),
        }
    }

    #[test]
    fn read_reports_undersized_header_without_mac_bytes_as_truncated() {
        // `header_len = 0` and nothing after the prefix: the MAC framing
        // read fails first, so the file is reported as truncated.
        let bytes = Prefix::for_encrypted(0).to_bytes();
        match read_encrypted_header(&mut bytes.as_slice(), HeaderReadLimits::default()) {
            Err(CryptoError::InvalidFormat(FormatDefect::Truncated)) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn read_rejects_undersized_header_with_full_mac_as_malformed() {
        // `header_len = 0` with all 32 MAC bytes present: framing is
        // complete, so a header too small to hold `header_fixed` is
        // the structural defect.
        let mut bytes = Prefix::for_encrypted(0).to_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; HEADER_MAC_SIZE]);
        match read_encrypted_header(&mut bytes.as_slice(), HeaderReadLimits::default()) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedHeader)) => {}
            other => panic!("expected MalformedHeader, got {other:?}"),
        }
    }

    #[test]
    fn read_rejects_undersized_nonzero_header_with_full_framing_as_malformed() {
        let header_len = (HEADER_FIXED_SIZE as u32) - 1;
        let mut bytes = Prefix::for_encrypted(header_len).to_bytes().to_vec();
        bytes.extend_from_slice(&vec![0u8; header_len as usize]);
        bytes.extend_from_slice(&[0u8; HEADER_MAC_SIZE]);
        match read_encrypted_header(&mut bytes.as_slice(), HeaderReadLimits::default()) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedHeader)) => {}
            other => panic!("expected MalformedHeader, got {other:?}"),
        }
    }

    /// Direct boundary unit on [`HeaderReadLimits::enforce_header_len`]:
    /// the comparison must be `>`, not `>=`, so a `header_len` exactly
    /// at the cap is admissible and only `cap + 1` rejects.
    #[test]
    fn enforce_header_len_boundary() {
        let limits = HeaderReadLimits::default().max_header_len(256);
        limits.enforce_header_len(256).expect("at-cap must succeed");
        match limits.enforce_header_len(257) {
            Err(CryptoError::HeaderLenCapExceeded {
                header_len: 257,
                local_cap: 256,
            }) => {}
            other => panic!("expected HeaderLenCapExceeded(257, 256), got {other:?}"),
        }
    }

    /// Direct boundary unit on
    /// [`HeaderReadLimits::enforce_recipient_count`]: same `>` not
    /// `>=` semantics, plus confirm the typed error fields carry
    /// `count` and `local_cap` correctly.
    #[test]
    fn enforce_recipient_count_boundary() {
        let limits = HeaderReadLimits::default().max_recipient_count(2);
        limits
            .enforce_recipient_count(2)
            .expect("at-cap must succeed");
        match limits.enforce_recipient_count(3) {
            Err(CryptoError::RecipientCountCapExceeded {
                count: 3,
                local_cap: 2,
            }) => {}
            other => panic!("expected RecipientCountCapExceeded(3, 2), got {other:?}"),
        }
    }

    /// Builder methods preserve normal in-range values and produce a
    /// struct equal to the chained construction. Pins the field-by-field
    /// effect of each setter.
    #[test]
    fn header_read_limits_builder_round_trips_normal_values() {
        let limits = HeaderReadLimits::default()
            .max_header_len(2 * 1024 * 1024)
            .max_recipient_count(128)
            .max_recipient_body_len(16 * 1024);
        assert_eq!(limits.max_header_len, 2 * 1024 * 1024);
        assert_eq!(limits.max_recipient_count, 128);
        assert_eq!(limits.max_recipient_body_len, 16 * 1024);
    }

    /// Builder methods clamp at the structural maximum so a caller
    /// cannot raise a cap above what the structural parser would
    /// accept. Locks in the security guarantee that the public API
    /// cannot be used to bypass the structural ceilings declared in
    /// `FORMAT.md` §3.1 / §3.2 / §3.3.
    #[test]
    fn header_read_limits_builder_clamps_at_structural_max() {
        let clamped = HeaderReadLimits::default()
            .max_header_len(u32::MAX)
            .max_recipient_count(u16::MAX)
            .max_recipient_body_len(u32::MAX);
        assert_eq!(
            clamped.max_header_len,
            HeaderReadLimits::HEADER_LEN_STRUCTURAL_MAX
        );
        assert_eq!(
            clamped.max_recipient_count,
            HeaderReadLimits::RECIPIENT_COUNT_STRUCTURAL_MAX
        );
        assert_eq!(
            clamped.max_recipient_body_len,
            HeaderReadLimits::RECIPIENT_BODY_LEN_STRUCTURAL_MAX
        );
    }

    /// The three default local caps
    /// ([`HeaderReadLimits::RECIPIENT_COUNT_DEFAULT`],
    /// [`HeaderReadLimits::RECIPIENT_BODY_LEN_DEFAULT`],
    /// [`HeaderReadLimits::HEADER_LEN_DEFAULT`]) plus the structural
    /// maxima [`EXT_LEN_MAX`] / [`HEADER_FIXED_SIZE`] /
    /// [`crate::recipient::entry::ENTRY_HEADER_SIZE`] /
    /// [`crate::recipient::name::TYPE_NAME_MAX_LEN`] must stay mutually
    /// consistent: the worst-case `header_len` a default-cap reader
    /// would still accept entry-by-entry (every recipient slot at the
    /// per-entry body cap, every type-name at the grammar ceiling,
    /// `ext_bytes` at its structural max) must fit inside the
    /// `HEADER_LEN_DEFAULT` envelope. Otherwise the three caps would
    /// silently refuse files the per-cap rules individually allow.
    ///
    /// Pins the inequality so a future cap bump (e.g. raising
    /// `RECIPIENT_BODY_LEN_DEFAULT` for a fat-body post-quantum
    /// recipient body) cannot silently break default round-trip
    /// without surfacing on CI.
    #[test]
    fn default_local_caps_are_mutually_consistent() {
        use crate::format::{EXT_LEN_MAX, HEADER_FIXED_SIZE};
        use crate::recipient::entry::ENTRY_HEADER_SIZE;
        use crate::recipient::name::TYPE_NAME_MAX_LEN;

        // Maximum on-wire bytes a single recipient entry can occupy
        // under the per-entry default cap with the type-name at its
        // grammar ceiling.
        let per_entry_max = ENTRY_HEADER_SIZE as u64
            + TYPE_NAME_MAX_LEN as u64
            + HeaderReadLimits::RECIPIENT_BODY_LEN_DEFAULT as u64;

        // Worst-case header a default-cap reader would individually
        // accept: every slot full, every type-name full, `ext_bytes`
        // at the structural max.
        let worst_case_header = (HeaderReadLimits::RECIPIENT_COUNT_DEFAULT as u64) * per_entry_max
            + EXT_LEN_MAX as u64
            + HEADER_FIXED_SIZE as u64;

        let header_len_default = HeaderReadLimits::HEADER_LEN_DEFAULT as u64;
        assert!(
            worst_case_header <= header_len_default,
            "Default local caps allow a worst-case header of {worst_case_header} bytes, \
             which exceeds HeaderReadLimits::HEADER_LEN_DEFAULT ({header_len_default}). \
             Either lower one of the per-cap defaults or raise \
             HeaderReadLimits::HEADER_LEN_DEFAULT to keep default round-trip viable."
        );
    }

    /// A file with a recipient count above the conservative default
    /// (`RECIPIENT_COUNT_LOCAL_CAP_DEFAULT = 64`) but below the
    /// structural max (`RECIPIENT_COUNT_MAX = 4096`) is rejected by
    /// default and accepted when the caller raises the cap via
    /// [`HeaderReadLimits::max_recipient_count`]. Pins that a caller
    /// can opt into reading a structurally valid file the conservative
    /// defaults would refuse.
    #[test]
    fn read_accepts_when_caller_raises_recipient_count_cap() {
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let stream_nonce = [0x07u8; STREAM_NONCE_SIZE];
        // 80 entries: above the 64-entry default local cap, below the
        // 4096-entry structural max.
        let entries: Vec<_> = (0..80)
            .map(|_| dummy_entry(argon2id::TYPE_NAME, argon2id::BODY_LENGTH))
            .collect();
        let built =
            build_encrypted_header(&entries, b"", stream_nonce, payload_key, &header_key).unwrap();

        let bytes = on_disk_bytes(&built);

        // Default caps: rejected.
        match read_encrypted_header(&mut bytes.as_slice(), HeaderReadLimits::default()) {
            Err(CryptoError::RecipientCountCapExceeded { count: 80, .. }) => {}
            other => panic!("expected RecipientCountCapExceeded with default cap, got {other:?}"),
        }

        // Caller raises the cap: accepted.
        let raised = HeaderReadLimits::default().max_recipient_count(128);
        let parsed = read_encrypted_header(&mut bytes.as_slice(), raised)
            .expect("raised recipient_count cap must accept the file");
        assert_eq!(parsed.recipient_entries.len(), 80);
    }

    /// A file with a per-entry `body_len` above the conservative
    /// default (`BODY_LEN_LOCAL_CAP_DEFAULT = 8 KiB`) but below the
    /// structural max (`BODY_LEN_MAX = 16 MiB`) is rejected by default
    /// and accepted when the caller raises the cap via
    /// [`HeaderReadLimits::max_recipient_body_len`]. Companion to
    /// [`read_accepts_when_caller_raises_recipient_count_cap`].
    #[test]
    fn read_accepts_when_caller_raises_body_len_cap() {
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let stream_nonce = [0x07u8; STREAM_NONCE_SIZE];
        // 10 KiB body: above the 8 KiB default cap, below the 16 MiB
        // structural max.
        let oversize_body_len: usize = 10 * 1024;
        let entry = dummy_entry(argon2id::TYPE_NAME, oversize_body_len);
        let built =
            build_encrypted_header(&[entry], b"", stream_nonce, payload_key, &header_key).unwrap();

        let bytes = on_disk_bytes(&built);

        // Default caps: rejected.
        match read_encrypted_header(&mut bytes.as_slice(), HeaderReadLimits::default()) {
            Err(CryptoError::RecipientBodyCapExceeded { body_len, .. })
                if body_len as usize == oversize_body_len => {}
            other => panic!(
                "expected RecipientBodyCapExceeded({oversize_body_len}, ..) with default cap, got {other:?}"
            ),
        }

        // Caller raises the cap: accepted.
        let raised = HeaderReadLimits::default().max_recipient_body_len(16 * 1024);
        let parsed = read_encrypted_header(&mut bytes.as_slice(), raised)
            .expect("raised body_len cap must accept the file");
        assert_eq!(parsed.recipient_entries.len(), 1);
        assert_eq!(parsed.recipient_entries[0].body.len(), oversize_body_len);
    }

    #[test]
    fn read_rejects_recipient_count_above_local_cap() {
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let stream_nonce = [0x07u8; STREAM_NONCE_SIZE];
        let entries: Vec<_> = (0..3)
            .map(|_| dummy_entry(argon2id::TYPE_NAME, argon2id::BODY_LENGTH))
            .collect();
        let built =
            build_encrypted_header(&entries, b"", stream_nonce, payload_key, &header_key).unwrap();

        let bytes = on_disk_bytes(&built);
        let tight_limits = HeaderReadLimits {
            max_recipient_count: 2,
            ..HeaderReadLimits::default()
        };
        let err = read_encrypted_header(&mut bytes.as_slice(), tight_limits).unwrap_err();
        match err {
            CryptoError::RecipientCountCapExceeded {
                count: 3,
                local_cap: 2,
            } => {}
            other => panic!("expected RecipientCountCapExceeded(3, 2), got {other:?}"),
        }
    }

    #[test]
    fn read_rejects_recipient_body_above_local_cap() {
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let stream_nonce = [0x07u8; STREAM_NONCE_SIZE];
        // Build an entry larger than the per-entry cap we'll set.
        let oversize_body_len = argon2id::BODY_LENGTH + 84;
        let local_body_cap: u32 = (argon2id::BODY_LENGTH + 12) as u32;
        let entry = dummy_entry(argon2id::TYPE_NAME, oversize_body_len);
        let built =
            build_encrypted_header(&[entry], b"", stream_nonce, payload_key, &header_key).unwrap();

        let bytes = on_disk_bytes(&built);
        let tight_limits = HeaderReadLimits {
            max_recipient_body_len: local_body_cap,
            ..HeaderReadLimits::default()
        };
        let err = read_encrypted_header(&mut bytes.as_slice(), tight_limits).unwrap_err();
        match err {
            CryptoError::RecipientBodyCapExceeded {
                body_len,
                local_cap,
            } if body_len as usize == oversize_body_len && local_cap == local_body_cap => {}
            other => panic!(
                "expected RecipientBodyCapExceeded({oversize_body_len}, {local_body_cap}), got {other:?}"
            ),
        }
    }

    /// A file that carries a complete, well-formed `header` region but
    /// stops before the 32-byte MAC tag must reject as
    /// `InvalidFormat(Truncated)`. Pins the framing-vs-structural-parse
    /// ordering required by `FORMAT.md` §3.7 step 3: both the `header`
    /// and `header_mac` reads are framing reads and complete before any
    /// structural parse runs.
    #[test]
    fn read_rejects_missing_mac_tag_as_truncated() {
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let stream_nonce = [0x07u8; STREAM_NONCE_SIZE];
        let entry = dummy_entry(argon2id::TYPE_NAME, argon2id::BODY_LENGTH);
        let built =
            build_encrypted_header(&[entry], b"", stream_nonce, payload_key, &header_key).unwrap();

        // Prefix + header, but the 32-byte MAC tag is missing.
        let mut bytes = Vec::with_capacity(built.prefix_bytes.len() + built.header_bytes.len());
        bytes.extend_from_slice(&built.prefix_bytes);
        bytes.extend_from_slice(&built.header_bytes);

        match read_encrypted_header(&mut bytes.as_slice(), HeaderReadLimits::default()) {
            Err(CryptoError::InvalidFormat(FormatDefect::Truncated)) => {}
            other => panic!("expected InvalidFormat(Truncated), got {other:?}"),
        }
    }

    /// If a file's `header` region is structurally malformed AND the
    /// MAC tag is missing, the framing-level `Truncated` diagnostic must
    /// fire before the structural `MalformedHeader` defect. Otherwise the
    /// reader would surface the downstream parse error and hide the
    /// simpler "file is truncated" cause, contradicting `FORMAT.md`
    /// §3.7 step 3.
    #[test]
    fn read_returns_truncated_before_structural_error_when_mac_missing() {
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let stream_nonce = [0x07u8; STREAM_NONCE_SIZE];
        let entry = dummy_entry(argon2id::TYPE_NAME, argon2id::BODY_LENGTH);
        let built =
            build_encrypted_header(&[entry], b"", stream_nonce, payload_key, &header_key).unwrap();

        // Tamper the high byte of `header_flags` (offset 0 inside
        // `header_fixed`) so a non-zero value is read. If the structural
        // parse ever ran, this would surface as
        // `InvalidFormat(MalformedHeader)` via `check_header_flags`.
        let mut header_bytes = built.header_bytes.clone();
        header_bytes[0] = 0x01;

        let mut bytes = Vec::with_capacity(built.prefix_bytes.len() + header_bytes.len());
        bytes.extend_from_slice(&built.prefix_bytes);
        bytes.extend_from_slice(&header_bytes);
        // No MAC tag appended.

        match read_encrypted_header(&mut bytes.as_slice(), HeaderReadLimits::default()) {
            Err(CryptoError::InvalidFormat(FormatDefect::Truncated)) => {}
            other => panic!(
                "expected InvalidFormat(Truncated) (framing precedes structural parse), got {other:?}"
            ),
        }
    }

    #[test]
    fn mac_verify_rejects_tampered_header_byte() {
        let DerivedSubkeys {
            payload_key,
            header_key,
        } = dummy_subkeys();
        let stream_nonce = [0x07u8; STREAM_NONCE_SIZE];
        let entry = dummy_entry(argon2id::TYPE_NAME, argon2id::BODY_LENGTH);
        let built =
            build_encrypted_header(&[entry], b"", stream_nonce, payload_key, &header_key).unwrap();

        // Flip a byte inside header_bytes; MAC must reject.
        let mut tampered = built.header_bytes.clone();
        tampered[20] ^= 0xFF;

        format::verify_header_mac(
            &built.prefix_bytes,
            &tampered,
            &header_key,
            &built.header_mac,
        )
        .unwrap_err();
    }
}
