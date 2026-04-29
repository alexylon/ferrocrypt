//! Shared `.fcr` encrypted-file header build/parse path.
//!
//! v1 defines **one** encrypted-file container with a typed recipient list —
//! there is no per-mode envelope or "symmetric vs hybrid" type byte. Both
//! `symmetric.rs` and `hybrid.rs` therefore share the same header
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
//!   bytes). Callers invoke `common::validate_tlv` on `ext_bytes` after
//!   `format::verify_header_mac` succeeds.
//! - It does not enforce recipient-mixing policy, classify modes, or run
//!   recipient unwrap. Those concerns live in `recipients/mod.rs`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::archiver;
use crate::common::{
    ENCRYPTION_KEY_SIZE, HMAC_KEY_SIZE, INCOMPLETE_SUFFIX, parent_or_cwd, payload_encryptor,
    read_exact_or_truncated,
};
use crate::error::{CryptoError, FormatDefect};
use crate::format::{
    self, HEADER_FIXED_SIZE, HEADER_MAC_SIZE, HeaderFixed, Kind, PREFIX_SIZE, Prefix,
    STREAM_NONCE_SIZE,
};
use crate::fs::atomic;
use crate::recipients::{self, RecipientEntry};

/// Tempfile name prefix for the in-flight `.fcr` write. Combined with
/// [`INCOMPLETE_SUFFIX`] this yields a `.ferrocrypt-*.incomplete`
/// staging name in the destination directory; on success
/// [`atomic::finalize_file`] promotes it to the user-visible
/// output path.
const TEMP_FILE_PREFIX: &str = ".ferrocrypt-";

/// Local resource caps applied while reading an encrypted-file header. The
/// defaults mirror `format::*_LOCAL_CAP_DEFAULT` and apply to every reader
/// path; callers that legitimately need higher caps (e.g. a fuzz target)
/// may construct this explicitly.
///
/// Caps are enforced **before** any cryptographic operation runs. Per
/// `FORMAT.md` §1, hostile input must not be able to force unbounded work.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HeaderReadLimits {
    /// Hard cap on `prefix.header_len`.
    pub max_header_len: u32,
    /// Hard cap on `header_fixed.recipient_count`.
    pub max_recipient_count: u16,
    /// Hard cap on each individual recipient entry's `body_len`. Applies
    /// to known and unknown entries alike, so an unknown-recipient slot
    /// cannot DoS a reader that would have skipped it.
    pub max_recipient_body_len: u32,
}

impl Default for HeaderReadLimits {
    fn default() -> Self {
        Self {
            max_header_len: format::HEADER_LEN_LOCAL_CAP_DEFAULT,
            max_recipient_count: format::RECIPIENT_COUNT_LOCAL_CAP_DEFAULT,
            max_recipient_body_len: format::BODY_LEN_LOCAL_CAP_DEFAULT,
        }
    }
}

/// A structurally parsed `.fcr` header. Authenticity has NOT been checked;
/// the caller must call [`format::verify_header_mac`] with a `header_key`
/// derived from a successfully unwrapped candidate `file_key` before
/// trusting `ext_bytes` or accepting the candidate.
///
/// The byte buffers ([`prefix_bytes`](Self::prefix_bytes),
/// [`header_bytes`](Self::header_bytes)) are kept verbatim because the MAC
/// is computed over the on-disk encoding, not over the parsed structs.
#[derive(Debug)]
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
    /// Authenticated extension TLV region. Caller MUST run
    /// `common::validate_tlv` on this AFTER MAC verification.
    pub ext_bytes: Vec<u8>,
    /// On-disk header MAC tag. Caller MUST verify against
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
    pub payload_key: Zeroizing<[u8; ENCRYPTION_KEY_SIZE]>,
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
// `header_bytes` shows only its length: it can be up to ~1 MiB
// (`HEADER_LEN_MAX`), so dumping its content in every debug print
// would be hostile.
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
/// 4. parse the leading 31 bytes as `header_fixed` → [`HeaderFixed::parse`]
///    (header_flags == 0, recipient_count in range, ext_len in range,
///    region lengths self-consistent);
/// 5. enforce `recipient_count <= limits.max_recipient_count`;
/// 6. parse the recipient list from `header[31..31+recipient_entries_len]`,
///    enforcing `body_len <= limits.max_recipient_body_len` per entry;
/// 7. capture the trailing `ext_bytes` slice (TLV validation deferred
///    to AFTER MAC verification — see `FORMAT.md` §3.7);
/// 8. read the 32-byte header MAC tag;
/// 9. return the parsed header. **MAC is not yet verified.**
pub(crate) fn read_encrypted_header<R: Read>(
    reader: &mut R,
    limits: HeaderReadLimits,
) -> Result<ParsedEncryptedHeader, CryptoError> {
    let (prefix_bytes, prefix) = format::read_prefix_from_reader(reader, Kind::Encrypted)?;

    if prefix.header_len > limits.max_header_len {
        return Err(CryptoError::HeaderLenCapExceeded {
            header_len: prefix.header_len,
            local_cap: limits.max_header_len,
        });
    }

    // Cap-bounded above. Cast is safe.
    let header_len = prefix.header_len as usize;
    let mut header_bytes = vec![0u8; header_len];
    read_exact_or_truncated(reader, &mut header_bytes)?;

    // `header_len >= HEADER_FIXED_SIZE` was already enforced by
    // `Prefix::parse` via `check_header_len`, so `first_chunk` is
    // structurally guaranteed to return `Some`; the `ok_or` is a
    // belt-and-braces guard so an upstream regression cannot panic here.
    let fixed_bytes: &[u8; HEADER_FIXED_SIZE] = header_bytes
        .first_chunk()
        .ok_or(CryptoError::InvalidFormat(FormatDefect::MalformedHeader))?;
    let fixed = HeaderFixed::parse(fixed_bytes, prefix.header_len)?;

    if fixed.recipient_count > limits.max_recipient_count {
        return Err(CryptoError::RecipientCountCapExceeded {
            count: fixed.recipient_count,
            local_cap: limits.max_recipient_count,
        });
    }

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

    let recipient_entries = recipients::parse_recipient_entries(
        &header_bytes[entries_start..entries_end],
        fixed.recipient_count,
        limits.max_recipient_body_len,
    )?;

    let ext_bytes = header_bytes[entries_end..ext_end].to_vec();

    let mut header_mac = [0u8; HEADER_MAC_SIZE];
    read_exact_or_truncated(reader, &mut header_mac)?;

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
/// - generating `stream_nonce` (typically `random_bytes::<STREAM_NONCE_SIZE>()`);
/// - deriving `payload_key` and `header_key` from the freshly generated
///   `file_key` via `common::derive_subkeys` (or equivalent);
/// - constructing `recipient_entries` via the per-recipient `wrap`
///   helpers (`recipients::argon2id::wrap`, `recipients::x25519::wrap`).
///
/// On success returns a [`BuiltEncryptedHeader`] holding the three byte
/// regions to write in order (prefix, header, MAC) plus `stream_nonce`
/// and `payload_key` for the payload streamer. Bundling these together
/// makes a (header, payload_key, stream_nonce) mismatch unrepresentable.
pub(crate) fn build_encrypted_header(
    recipient_entries: &[RecipientEntry],
    ext_bytes: &[u8],
    stream_nonce: [u8; STREAM_NONCE_SIZE],
    payload_key: Zeroizing<[u8; ENCRYPTION_KEY_SIZE]>,
    header_key: &[u8; HMAC_KEY_SIZE],
) -> Result<BuiltEncryptedHeader, CryptoError> {
    if recipient_entries.is_empty() {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::RecipientCountOutOfRange { count: 0 },
        ));
    }

    let entries_count = recipient_entries.len();
    if entries_count > format::RECIPIENT_COUNT_MAX as usize {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::RecipientCountOutOfRange {
                // Saturate to u16::MAX for the diagnostic when the in-memory
                // count actually exceeds the wire field width (impossible on
                // disk, but the Rust caller handed us a Vec).
                count: entries_count.try_into().unwrap_or(u16::MAX),
            },
        ));
    }
    // Bounded above by `RECIPIENT_COUNT_MAX` (u16). Cast is safe.
    let recipient_count = entries_count as u16;

    let mut entries_bytes = Vec::new();
    for entry in recipient_entries {
        entries_bytes.extend_from_slice(&entry.to_bytes());
    }
    let recipient_entries_len: u32 = entries_bytes
        .len()
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedHeader))?;

    let ext_len: u32 = ext_bytes
        .len()
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedHeader))?;
    if ext_len > format::EXT_LEN_MAX {
        return Err(CryptoError::InvalidFormat(FormatDefect::ExtTooLarge {
            len: ext_len,
        }));
    }

    let header_len_u64 = (HEADER_FIXED_SIZE as u64)
        .checked_add(recipient_entries_len as u64)
        .and_then(|v| v.checked_add(ext_len as u64))
        .ok_or(CryptoError::InvalidFormat(FormatDefect::MalformedHeader))?;
    let header_len: u32 = header_len_u64.try_into().map_err(|_| {
        CryptoError::InvalidFormat(FormatDefect::OversizedHeader {
            header_len: u32::MAX,
        })
    })?;

    let prefix_bytes = Prefix::build_encrypted(header_len)?;

    let fixed = HeaderFixed {
        header_flags: 0,
        recipient_count,
        recipient_entries_len,
        ext_len,
        stream_nonce,
    };
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
/// is supplied, it's used verbatim; otherwise the file is written under
/// `output_dir` as `<base_name>.<ENCRYPTED_EXTENSION>`.
fn resolve_encrypted_output_path(
    output_dir: &Path,
    output_file: Option<&Path>,
    base_name: &str,
) -> PathBuf {
    match output_file {
        Some(path) => path.to_path_buf(),
        None => output_dir.join(format!("{}.{}", base_name, format::ENCRYPTED_EXTENSION)),
    }
}

/// Streams `input_path` into an encrypted `.fcr` file at the resolved
/// output path, using the supplied [`BuiltEncryptedHeader`] bundle.
///
/// On-disk byte order: `prefix(12) || header(31 + entries + ext) || mac(32)
/// || payload(STREAM)`. The header bytes, MAC, payload key, and stream
/// nonce all live in `built` so that they cannot be paired with material
/// from a different `file_key`/`stream_nonce`. The payload is
/// XChaCha20-Poly1305 STREAM-BE32 keyed by `built.payload_key` over the
/// TAR archive of `input_path`. No plaintext intermediate files touch
/// disk: the TAR stream is piped directly through [`EncryptWriter`].
///
/// Atomicity: the file is written under a `.ferrocrypt-*.incomplete`
/// tempfile in the destination's parent directory, then renamed via
/// [`atomic::finalize_file`] only after `sync_all`. A pre-existing
/// output path rejects with `CryptoError::InvalidInput` BEFORE any
/// tempfile is created, so an unrelated file at the destination is
/// never touched.
pub(crate) fn write_encrypted_file(
    input_path: &Path,
    output_dir: &Path,
    output_file: Option<&Path>,
    base_name: &str,
    built: &BuiltEncryptedHeader,
    archive_limits: archiver::ArchiveLimits,
) -> Result<PathBuf, CryptoError> {
    let output_path = resolve_encrypted_output_path(output_dir, output_file, base_name);
    if output_path.exists() {
        return Err(CryptoError::InvalidInput(format!(
            "Output already exists: {}",
            output_path.display()
        )));
    }

    let mut tmp = tempfile::Builder::new()
        .prefix(TEMP_FILE_PREFIX)
        .suffix(INCOMPLETE_SUFFIX)
        .tempfile_in(parent_or_cwd(&output_path))?;

    tmp.as_file_mut().write_all(&built.prefix_bytes)?;
    tmp.as_file_mut().write_all(&built.header_bytes)?;
    tmp.as_file_mut().write_all(&built.header_mac)?;

    let encrypt_writer = payload_encryptor(&built.payload_key, &built.stream_nonce, tmp);
    let (_, encrypt_writer) = archiver::archive(input_path, encrypt_writer, archive_limits)?;
    let tmp = encrypt_writer.finish()?;
    tmp.as_file().sync_all()?;

    atomic::finalize_file(tmp, &output_path)?;
    Ok(output_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{DerivedSubkeys, FILE_KEY_SIZE, derive_subkeys};
    use crate::recipients::{RECIPIENT_FLAG_CRITICAL, argon2id, x25519};

    fn dummy_entry(type_name: &str, body_len: usize) -> RecipientEntry {
        RecipientEntry {
            type_name: type_name.to_string(),
            recipient_flags: 0,
            body: vec![0xAB; body_len],
        }
    }

    fn dummy_subkeys() -> DerivedSubkeys {
        // Stable inputs so the test is deterministic.
        let file_key = [0x42u8; FILE_KEY_SIZE];
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

        // MAC verifies under the same header_key (sanity check; this is
        // what the symmetric/hybrid decrypt path does after recipient unwrap).
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
