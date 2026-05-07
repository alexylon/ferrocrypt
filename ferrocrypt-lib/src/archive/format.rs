//! FCA wire-format constants and primitives: header parse/build,
//! manifest serialize/parse, and big-endian integer helpers.
//!
//! See `notes/archive_format/ARCHIVE_FORMAT.md` §5 (header), §6 (manifest),
//! §14.1 (constants), §14.3 (BE helpers), §14.4 (header writer),
//! §14.5 (header reader).

use std::io::{self, Cursor, Read, Write};

use crate::CryptoError;

use super::limits::{
    ARCHIVE_ENTRY_MODE_UNSUPPORTED, ArchiveLimits, entry_count_cap_error, manifest_len_cap_error,
    path_bytes_cap_error, total_bytes_cap_error,
};
use super::model::{ArchiveEntry, ArchiveEntryKind, FcaHeader, Manifest};
use super::path::validate_fca_path;
use super::tree::validate_manifest_tree;

pub(crate) const FCA_MAGIC: &[u8; 4] = b"FCA\0";
pub(crate) const FCA_VERSION: u8 = 0x01;
/// Size of the fixed FCA header in bytes: `magic(4) || version(1) ||
/// flags(2) || entry_count(4) || manifest_len(4) || total_file_bytes(8)`
/// (spec §5.1). Documented as a spec constant for callers that need it
/// for byte-level inspection or fixture construction; the parser
/// reads each field individually and does not use this constant
/// directly.
#[allow(dead_code)]
pub(crate) const FCA_HEADER_SIZE: usize = 23;
pub(crate) const FCA_ENTRY_FIXED_SIZE: usize = 14;

pub(crate) const KIND_FILE: u8 = 0x01;
pub(crate) const KIND_DIR: u8 = 0x02;

pub(crate) const FCA_FLAGS_V1: u16 = 0;
pub(crate) const FCA_ENTRY_FLAGS_V1: u8 = 0;
pub(crate) const PERMISSION_BITS_MASK: u32 = 0o777;

/// Streaming buffer size for [`copy_exact_n`] (64 KiB). Aligned with
/// [`crate::crypto::stream::BUFFER_SIZE`] — matching the AEAD chunk
/// size avoids stalling the encrypt/decrypt pipeline on internal
/// re-buffering, but the constants are separate because the archive
/// layer does not depend on crypto/stream.
const COPY_BUFFER_SIZE: usize = 64 * 1024;

/// Single source of truth for the "Malformed archive manifest"
/// rejection. Used by every `parse_manifest_bytes` arm whose only
/// useful diagnostic is "the bytes don't match what `header` declared"
/// (truncated entry header, slice overflow on a path region,
/// trailing bytes after the last declared entry).
fn malformed_manifest() -> CryptoError {
    CryptoError::InvalidInput("Malformed archive manifest".to_string())
}

/// Single source of truth for the "Empty archive" rejection. Used by
/// the writer's pre-emit `entry_count == 0` check, the reader's
/// header `entry_count == 0` arm, and the tree validator's
/// `entries.is_empty()` check.
pub(super) fn empty_archive_error() -> CryptoError {
    CryptoError::InvalidInput("Empty archive".to_string())
}

/// Initial capacity hint for the parsed-entries `Vec` in
/// [`parse_manifest_bytes`]. Caps the allocation so an
/// adversary-controlled `header.entry_count` cannot drive a
/// multi-megabyte pre-allocation; small archives still fit in one
/// allocation, larger ones grow the `Vec` organically.
const MANIFEST_PARSE_INITIAL_CAPACITY: usize = 1024;

pub(super) fn read_u8<R: Read>(r: &mut R) -> io::Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

pub(super) fn read_u16_be<R: Read>(r: &mut R) -> io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}

pub(super) fn read_u32_be<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

pub(super) fn read_u64_be<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_be_bytes(b))
}

pub(super) fn write_u8<W: Write>(w: &mut W, n: u8) -> io::Result<()> {
    w.write_all(&[n])
}

/// Reads exactly `size` bytes from `reader` and writes them to `writer`.
/// Used by both the encrypt-side content pass (source file → encrypted
/// stream) and the decrypt-side content extraction (encrypted stream →
/// output file). Spec §14.10: archive content bytes MUST NOT use
/// unbounded `io::copy`, which would happily keep reading past `size`
/// on a misbehaving reader.
///
/// On a short read (reader returns `Ok(0)` while bytes are still
/// expected), returns [`CryptoError::InvalidInput`] with the
/// "shorter than declared size" diagnostic. The `?` on `read` threads
/// `StreamError` markers from the underlying decrypt stream through
/// `From<io::Error> for CryptoError` so authentication / truncation /
/// extra-data signals surface as the typed `CryptoError::Payload*`
/// variant rather than as a generic archive error.
pub(super) fn copy_exact_n<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    size: u64,
) -> Result<(), CryptoError> {
    let mut buf = [0u8; COPY_BUFFER_SIZE];
    let mut remaining = size;
    while remaining > 0 {
        // Buffer is 64 KiB which fits any usize on supported targets;
        // the `min` ensures the cast is bounded by the smaller side.
        let want = std::cmp::min(buf.len() as u64, remaining) as usize;
        let n = reader.read(&mut buf[..want])?;
        if n == 0 {
            return Err(CryptoError::InvalidInput(
                "Archive file content is shorter than declared size".to_string(),
            ));
        }
        writer.write_all(&buf[..n]).map_err(CryptoError::Io)?;
        remaining -= n as u64;
    }
    Ok(())
}

pub(super) fn write_u16_be<W: Write>(w: &mut W, n: u16) -> io::Result<()> {
    w.write_all(&n.to_be_bytes())
}

pub(super) fn write_u32_be<W: Write>(w: &mut W, n: u32) -> io::Result<()> {
    w.write_all(&n.to_be_bytes())
}

pub(super) fn write_u64_be<W: Write>(w: &mut W, n: u64) -> io::Result<()> {
    w.write_all(&n.to_be_bytes())
}

/// Writes the 23-byte FCA fixed header. Returns the writer on success
/// so the caller can chain manifest + content writes. Refuses
/// `entry_count == 0` before emitting any bytes.
pub(crate) fn write_fca_header<W: Write>(
    mut w: W,
    entry_count: u32,
    manifest_len: u32,
    total_file_bytes: u64,
) -> Result<W, CryptoError> {
    if entry_count == 0 {
        return Err(empty_archive_error());
    }
    if manifest_len == 0 {
        return Err(malformed_manifest());
    }

    w.write_all(FCA_MAGIC).map_err(CryptoError::Io)?;
    write_u8(&mut w, FCA_VERSION).map_err(CryptoError::Io)?;
    write_u16_be(&mut w, FCA_FLAGS_V1).map_err(CryptoError::Io)?;
    write_u32_be(&mut w, entry_count).map_err(CryptoError::Io)?;
    write_u32_be(&mut w, manifest_len).map_err(CryptoError::Io)?;
    write_u64_be(&mut w, total_file_bytes).map_err(CryptoError::Io)?;
    Ok(w)
}

/// Parses and structurally validates the 23-byte FCA fixed header.
/// All resource caps are applied here so downstream allocations
/// (manifest buffer, entry vector) are bounded by the time they fire.
pub fn parse_fca_header<R: Read>(
    reader: &mut R,
    limits: ArchiveLimits,
) -> Result<FcaHeader, CryptoError> {
    limits.validate()?;

    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != FCA_MAGIC {
        return Err(CryptoError::InvalidInput(
            "Bad FerroCrypt archive magic".to_string(),
        ));
    }

    let version = read_u8(reader)?;
    if version != FCA_VERSION {
        return Err(CryptoError::InvalidInput(
            "Unsupported FerroCrypt archive version".to_string(),
        ));
    }

    let flags = read_u16_be(reader)?;
    if flags != 0 {
        return Err(CryptoError::InvalidInput(
            "FerroCrypt archive header has non-zero flags".to_string(),
        ));
    }

    let entry_count = read_u32_be(reader)?;
    let manifest_len = read_u32_be(reader)?;
    let total_file_bytes = read_u64_be(reader)?;

    if entry_count == 0 {
        return Err(empty_archive_error());
    }
    if entry_count > limits.max_entry_count {
        return Err(entry_count_cap_error(entry_count, limits.max_entry_count));
    }
    if manifest_len == 0 {
        return Err(malformed_manifest());
    }
    if manifest_len > limits.max_manifest_bytes {
        return Err(manifest_len_cap_error(
            u64::from(manifest_len),
            limits.max_manifest_bytes,
        ));
    }
    if usize::try_from(manifest_len).is_err() {
        return Err(CryptoError::InvalidInput(
            "Archive manifest length cannot fit in memory".to_string(),
        ));
    }
    if total_file_bytes > limits.max_total_plaintext_bytes {
        return Err(total_bytes_cap_error(
            total_file_bytes,
            limits.max_total_plaintext_bytes,
        ));
    }

    Ok(FcaHeader {
        entry_count,
        manifest_len,
        total_file_bytes,
    })
}

/// Pre-computes the serialized manifest length with checked
/// arithmetic before any allocation, validating per-entry mode and
/// path-byte caps along the way. Caller invokes this BEFORE
/// allocating the manifest buffer; if it returns
/// [`CryptoError::InvalidInput`], no allocation has happened.
pub(crate) fn checked_manifest_len(
    entries: &[ArchiveEntry],
    limits: ArchiveLimits,
) -> Result<usize, CryptoError> {
    let limits = limits.validate()?;

    let mut len: usize = 0;
    for entry in entries {
        if entry.mode > PERMISSION_BITS_MASK {
            return Err(CryptoError::InvalidInput(
                ARCHIVE_ENTRY_MODE_UNSUPPORTED.to_string(),
            ));
        }
        let path_len = entry.path_utf8.len();
        if path_len == 0 || path_len > limits.max_path_bytes as usize {
            return Err(path_bytes_cap_error(
                u32::try_from(path_len).unwrap_or(u32::MAX),
                limits.max_path_bytes,
                Some(&entry.path_utf8),
            ));
        }
        if path_len > u16::MAX as usize {
            return Err(CryptoError::InvalidInput(
                "Archive path exceeds FCA u16 length".to_string(),
            ));
        }

        len = len
            .checked_add(FCA_ENTRY_FIXED_SIZE)
            .and_then(|n| n.checked_add(path_len))
            .ok_or_else(|| {
                CryptoError::InvalidInput("Archive manifest length overflow".to_string())
            })?;

        if len > limits.max_manifest_bytes as usize {
            return Err(manifest_len_cap_error(
                len as u64,
                limits.max_manifest_bytes,
            ));
        }
    }

    Ok(len)
}

/// Serializes a [`Manifest`] into the FCA manifest byte sequence.
/// The total byte length matches [`checked_manifest_len`] exactly,
/// asserted via `debug_assert_eq!` post-condition.
pub(crate) fn serialize_manifest(
    manifest: &Manifest,
    limits: ArchiveLimits,
) -> Result<Vec<u8>, CryptoError> {
    let expected_len = checked_manifest_len(&manifest.entries, limits)?;
    let mut out = Vec::with_capacity(expected_len);

    for entry in &manifest.entries {
        let path_bytes = entry.path_utf8.as_bytes();
        // path_len fits in u16 because checked_manifest_len rejected
        // path_len > u16::MAX.
        let path_len = u16::try_from(path_bytes.len()).map_err(|_| {
            CryptoError::InvalidInput("Archive path exceeds FCA u16 length".to_string())
        })?;

        let kind = match entry.kind {
            ArchiveEntryKind::File => KIND_FILE,
            ArchiveEntryKind::Directory => KIND_DIR,
        };

        write_u8(&mut out, kind).map_err(CryptoError::Io)?;
        write_u8(&mut out, FCA_ENTRY_FLAGS_V1).map_err(CryptoError::Io)?;
        // mode fits in u16 because checked_manifest_len rejected
        // mode > 0o777.
        let mode_u16 = u16::try_from(entry.mode).map_err(|_| {
            CryptoError::InvalidInput("Archive entry mode does not fit in u16".to_string())
        })?;
        write_u16_be(&mut out, mode_u16).map_err(CryptoError::Io)?;
        write_u16_be(&mut out, path_len).map_err(CryptoError::Io)?;
        write_u64_be(&mut out, entry.size).map_err(CryptoError::Io)?;
        out.extend_from_slice(path_bytes);
    }

    debug_assert_eq!(out.len(), expected_len);
    Ok(out)
}

/// Parses the manifest byte sequence into a [`Manifest`]. Validates
/// per-entry shape, UTF-8 path grammar (via [`validate_fca_path`]),
/// total-bytes equality against `header.total_file_bytes`, no-trailing-
/// bytes, and the manifest tree shape (via [`validate_manifest_tree`]).
///
/// The caller MUST have already trimmed `bytes` to exactly
/// `header.manifest_len` bytes.
pub fn parse_manifest_bytes(
    bytes: &[u8],
    header: FcaHeader,
    limits: ArchiveLimits,
) -> Result<Manifest, CryptoError> {
    let limits = limits.validate()?;

    if bytes.len()
        != usize::try_from(header.manifest_len).map_err(|_| {
            CryptoError::InvalidInput("Archive manifest length cannot fit in memory".to_string())
        })?
    {
        return Err(malformed_manifest());
    }

    let mut cursor = Cursor::new(bytes);
    let entry_count_usize = usize::try_from(header.entry_count).unwrap_or(usize::MAX);
    let mut entries = Vec::with_capacity(entry_count_usize.min(MANIFEST_PARSE_INITIAL_CAPACITY));
    let mut total_file_bytes: u64 = 0;

    for _ in 0..header.entry_count {
        let pos = cursor.position() as usize;
        let remaining = bytes.len().saturating_sub(pos);
        if remaining < FCA_ENTRY_FIXED_SIZE {
            return Err(malformed_manifest());
        }

        let kind_byte = read_u8(&mut cursor)?;
        let entry_flags = read_u8(&mut cursor)?;
        let mode = read_u16_be(&mut cursor)?;
        let path_len = read_u16_be(&mut cursor)?;
        let size = read_u64_be(&mut cursor)?;

        if entry_flags != 0 {
            return Err(CryptoError::InvalidInput(
                "Archive entry has non-zero reserved flags".to_string(),
            ));
        }
        if u32::from(mode) > PERMISSION_BITS_MASK {
            return Err(CryptoError::InvalidInput(
                ARCHIVE_ENTRY_MODE_UNSUPPORTED.to_string(),
            ));
        }
        if path_len == 0 {
            return Err(CryptoError::InvalidInput(
                "Empty archive entry path".to_string(),
            ));
        }
        if u32::from(path_len) > limits.max_path_bytes {
            return Err(path_bytes_cap_error(
                u32::from(path_len),
                limits.max_path_bytes,
                None,
            ));
        }

        let start = cursor.position() as usize;
        let end = start
            .checked_add(path_len as usize)
            .ok_or_else(malformed_manifest)?;
        if end > bytes.len() {
            return Err(malformed_manifest());
        }

        let path_bytes = &bytes[start..end];
        cursor.set_position(end as u64);

        let path_utf8 = std::str::from_utf8(path_bytes)
            .map_err(|_| CryptoError::InvalidInput("Archive path is not valid UTF-8".to_string()))?
            .to_owned();

        validate_fca_path(&path_utf8, limits)?;

        let kind = match kind_byte {
            KIND_FILE => {
                total_file_bytes = total_file_bytes.checked_add(size).ok_or_else(|| {
                    CryptoError::InvalidInput("Archive total file bytes overflow".to_string())
                })?;
                ArchiveEntryKind::File
            }
            KIND_DIR => {
                if size != 0 {
                    return Err(CryptoError::InvalidInput(
                        "Directory archive entry has non-zero size".to_string(),
                    ));
                }
                ArchiveEntryKind::Directory
            }
            _ => {
                return Err(CryptoError::InvalidInput(
                    "Unsupported archive entry kind".to_string(),
                ));
            }
        };

        entries.push(ArchiveEntry {
            kind,
            path_utf8,
            mode: u32::from(mode),
            size,
            source_path: None,
        });
    }

    if cursor.position() as usize != bytes.len() {
        return Err(malformed_manifest());
    }

    if total_file_bytes != header.total_file_bytes {
        return Err(CryptoError::InvalidInput(
            "Archive total-bytes mismatch".to_string(),
        ));
    }
    if total_file_bytes > limits.max_total_plaintext_bytes {
        return Err(total_bytes_cap_error(
            total_file_bytes,
            limits.max_total_plaintext_bytes,
        ));
    }

    let (root_name, root_is_file) = validate_manifest_tree(&entries, total_file_bytes, limits)?;

    Ok(Manifest {
        entries,
        total_file_bytes,
        root_name,
        root_is_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::io::Cursor;

    /// Constructs raw header bytes from explicit field values for
    /// testing rejections that the writer would otherwise refuse to
    /// emit (e.g. zero entry_count, non-zero flags, bad version).
    fn raw_header_bytes(
        version: u8,
        flags: u16,
        entry_count: u32,
        manifest_len: u32,
        total_file_bytes: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FCA_HEADER_SIZE);
        buf.extend_from_slice(FCA_MAGIC);
        buf.push(version);
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&entry_count.to_be_bytes());
        buf.extend_from_slice(&manifest_len.to_be_bytes());
        buf.extend_from_slice(&total_file_bytes.to_be_bytes());
        debug_assert_eq!(buf.len(), FCA_HEADER_SIZE);
        buf
    }

    #[test]
    fn header_round_trip() {
        let mut buf = Vec::new();
        let _ = write_fca_header(&mut buf, 7, 200, 4096).expect("valid params write");
        assert_eq!(buf.len(), FCA_HEADER_SIZE);

        let mut cur = Cursor::new(&buf);
        let parsed = parse_fca_header(&mut cur, ArchiveLimits::default()).expect("valid parse");
        assert_eq!(parsed.entry_count, 7);
        assert_eq!(parsed.manifest_len, 200);
        assert_eq!(parsed.total_file_bytes, 4096);
    }

    #[test]
    fn header_size_is_exactly_23_bytes() {
        let mut buf = Vec::new();
        let _ = write_fca_header(&mut buf, 1, 1, 0).expect("valid");
        assert_eq!(buf.len(), 23);
        assert_eq!(buf.len(), FCA_HEADER_SIZE);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = raw_header_bytes(FCA_VERSION, 0, 5, 100, 1024);
        bytes[0] = b'X';
        let mut cur = Cursor::new(&bytes);
        let err = parse_fca_header(&mut cur, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("Bad FerroCrypt archive magic"));
    }

    #[test]
    fn rejects_unsupported_version() {
        let bytes = raw_header_bytes(0xFF, 0, 5, 100, 1024);
        let mut cur = Cursor::new(&bytes);
        let err = parse_fca_header(&mut cur, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("Unsupported"));
    }

    #[test]
    fn rejects_nonzero_flags() {
        let bytes = raw_header_bytes(FCA_VERSION, 1, 5, 100, 1024);
        let mut cur = Cursor::new(&bytes);
        let err = parse_fca_header(&mut cur, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("non-zero flags"));
    }

    #[test]
    fn rejects_zero_entry_count() {
        let bytes = raw_header_bytes(FCA_VERSION, 0, 0, 100, 1024);
        let mut cur = Cursor::new(&bytes);
        let err = parse_fca_header(&mut cur, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("Empty archive"));
    }

    #[test]
    fn rejects_oversize_entry_count() {
        let limits = ArchiveLimits::default();
        let bytes = raw_header_bytes(FCA_VERSION, 0, limits.max_entry_count + 1, 100, 1024);
        let mut cur = Cursor::new(&bytes);
        let err = parse_fca_header(&mut cur, limits).unwrap_err();
        assert!(format!("{err}").contains("entry-count cap exceeded"));
    }

    #[test]
    fn rejects_zero_manifest_len() {
        let bytes = raw_header_bytes(FCA_VERSION, 0, 5, 0, 1024);
        let mut cur = Cursor::new(&bytes);
        let err = parse_fca_header(&mut cur, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("Malformed archive manifest"));
    }

    #[test]
    fn rejects_oversize_manifest_len() {
        let limits = ArchiveLimits::default();
        let bytes = raw_header_bytes(FCA_VERSION, 0, 5, limits.max_manifest_bytes + 1, 1024);
        let mut cur = Cursor::new(&bytes);
        let err = parse_fca_header(&mut cur, limits).unwrap_err();
        assert!(format!("{err}").contains("manifest length cap exceeded"));
    }

    #[test]
    fn rejects_oversize_total_file_bytes() {
        let limits = ArchiveLimits::default();
        let bytes = raw_header_bytes(FCA_VERSION, 0, 5, 100, limits.max_total_plaintext_bytes + 1);
        let mut cur = Cursor::new(&bytes);
        let err = parse_fca_header(&mut cur, limits).unwrap_err();
        assert!(format!("{err}").contains("total-bytes cap exceeded"));
    }

    /// Boundary check: `max_entry_count` exactly is admissible,
    /// `max_entry_count + 1` rejected. Same `>` vs `>=` regression
    /// guard as the limits-side enforce-helper test.
    #[test]
    fn entry_count_at_cap_admissible() {
        let limits = ArchiveLimits::default().with_max_entry_count(10);
        let bytes = raw_header_bytes(FCA_VERSION, 0, 10, 100, 1024);
        let mut cur = Cursor::new(&bytes);
        let parsed = parse_fca_header(&mut cur, limits).expect("at-cap is admissible");
        assert_eq!(parsed.entry_count, 10);
    }

    /// Truncated mid-header (valid magic + version + flags, then the
    /// reader runs out of bytes before entry_count) surfaces as
    /// `CryptoError::Io` (typically `UnexpectedEof`). Confirms the
    /// parser fails closed on short input rather than reading past
    /// end-of-stream.
    #[test]
    fn rejects_short_header() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(FCA_MAGIC);
        bytes.push(FCA_VERSION);
        bytes.extend_from_slice(&FCA_FLAGS_V1.to_be_bytes());
        // 7 bytes: header is cut off right before entry_count.
        let mut cur = Cursor::new(&bytes);
        let err = parse_fca_header(&mut cur, ArchiveLimits::default()).unwrap_err();
        assert!(
            matches!(err, CryptoError::Io(_)),
            "short header should surface as CryptoError::Io"
        );
    }

    /// Completely empty input fails at the first `read_exact` for
    /// magic, surfaces as `CryptoError::Io`. Pinned because an empty
    /// stream is a common adversarial probe.
    #[test]
    fn rejects_empty_input() {
        let bytes = Vec::new();
        let mut cur = Cursor::new(&bytes);
        let err = parse_fca_header(&mut cur, ArchiveLimits::default()).unwrap_err();
        assert!(matches!(err, CryptoError::Io(_)));
    }

    /// `write_fca_header` MUST refuse `entry_count == 0` before any
    /// byte is emitted. Pin both the rejection and the "no bytes
    /// written" property — a partial header on disk would be worse
    /// than a clean error.
    #[test]
    fn write_rejects_zero_entry_count_before_emitting_bytes() {
        let mut buf = Vec::new();
        let err = write_fca_header(&mut buf, 0, 100, 1024).unwrap_err();
        assert!(format!("{err}").contains("Empty archive"));
        assert!(
            buf.is_empty(),
            "writer must not emit bytes for invalid params"
        );
    }

    /// `manifest_len == 0` is invalid for every non-empty archive and
    /// the writer must refuse it before emitting a partial header.
    #[test]
    fn write_rejects_zero_manifest_len_before_emitting_bytes() {
        let mut buf = Vec::new();
        let err = write_fca_header(&mut buf, 1, 0, 0).unwrap_err();
        assert!(format!("{err}").contains("Malformed archive manifest"));
        assert!(
            buf.is_empty(),
            "writer must not emit bytes for invalid params"
        );
    }

    /// Magic byte order is `F C A \0`. Pinned because a future
    /// refactor that flipped endianness or got the constant from a
    /// macro would need an explicit byte-by-byte check to fail.
    #[test]
    fn magic_byte_order_is_fca_nul() {
        assert_eq!(FCA_MAGIC, b"FCA\0");
        assert_eq!(FCA_MAGIC[0], b'F');
        assert_eq!(FCA_MAGIC[1], b'C');
        assert_eq!(FCA_MAGIC[2], b'A');
        assert_eq!(FCA_MAGIC[3], 0);
    }

    // -- Manifest serialize / parse ----------------------------------------

    fn make_entry(path: &str, kind: ArchiveEntryKind, size: u64, mode: u32) -> ArchiveEntry {
        ArchiveEntry {
            kind,
            path_utf8: path.to_string(),
            mode,
            size,
            source_path: None,
        }
    }

    fn make_single_file_manifest() -> Manifest {
        Manifest {
            entries: vec![make_entry("hello.txt", ArchiveEntryKind::File, 13, 0o644)],
            total_file_bytes: 13,
            root_name: OsString::from("hello.txt"),
            root_is_file: true,
        }
    }

    fn make_directory_manifest() -> Manifest {
        Manifest {
            entries: vec![
                make_entry("photos", ArchiveEntryKind::Directory, 0, 0o755),
                make_entry("photos/cover.jpg", ArchiveEntryKind::File, 1024, 0o644),
                make_entry("photos/index.txt", ArchiveEntryKind::File, 50, 0o644),
            ],
            total_file_bytes: 1074,
            root_name: OsString::from("photos"),
            root_is_file: false,
        }
    }

    /// Round-trip through serialize → parse for a single-file
    /// manifest. Pin every Manifest field across the round-trip.
    #[test]
    fn manifest_round_trip_single_file() {
        let manifest = make_single_file_manifest();
        let bytes = serialize_manifest(&manifest, ArchiveLimits::default()).unwrap();

        let header = FcaHeader {
            entry_count: 1,
            manifest_len: bytes.len() as u32,
            total_file_bytes: manifest.total_file_bytes,
        };
        let parsed = parse_manifest_bytes(&bytes, header, ArchiveLimits::default()).unwrap();

        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].path_utf8, "hello.txt");
        assert_eq!(parsed.entries[0].mode, 0o644);
        assert_eq!(parsed.entries[0].size, 13);
        assert_eq!(parsed.entries[0].kind, ArchiveEntryKind::File);
        assert_eq!(parsed.total_file_bytes, 13);
        assert_eq!(parsed.root_name, OsString::from("hello.txt"));
        assert!(parsed.root_is_file);
    }

    #[test]
    fn manifest_round_trip_directory_tree() {
        let manifest = make_directory_manifest();
        let bytes = serialize_manifest(&manifest, ArchiveLimits::default()).unwrap();

        let header = FcaHeader {
            entry_count: 3,
            manifest_len: bytes.len() as u32,
            total_file_bytes: manifest.total_file_bytes,
        };
        let parsed = parse_manifest_bytes(&bytes, header, ArchiveLimits::default()).unwrap();

        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.total_file_bytes, 1074);
        assert_eq!(parsed.root_name, OsString::from("photos"));
        assert!(!parsed.root_is_file);
    }

    #[test]
    fn manifest_round_trip_empty_file() {
        let manifest = Manifest {
            entries: vec![make_entry("empty.txt", ArchiveEntryKind::File, 0, 0o644)],
            total_file_bytes: 0,
            root_name: OsString::from("empty.txt"),
            root_is_file: true,
        };
        let bytes = serialize_manifest(&manifest, ArchiveLimits::default()).unwrap();

        let header = FcaHeader {
            entry_count: 1,
            manifest_len: bytes.len() as u32,
            total_file_bytes: 0,
        };
        let parsed = parse_manifest_bytes(&bytes, header, ArchiveLimits::default()).unwrap();
        assert_eq!(parsed.entries[0].size, 0);
    }

    /// Determinism: same Manifest must serialize to byte-identical
    /// output. Pinned so a future refactor that introduced HashMap
    /// ordering or thread-local state would fail.
    #[test]
    fn serialize_is_deterministic() {
        let m = make_directory_manifest();
        let a = serialize_manifest(&m, ArchiveLimits::default()).unwrap();
        let b = serialize_manifest(&m, ArchiveLimits::default()).unwrap();
        assert_eq!(a, b);
    }

    /// Spec §6.1: file `size` is `u64`. Confirm there is no remnant
    /// ustar 8 GiB cap by encoding `u64::MAX` and inspecting the
    /// raw bytes.
    #[test]
    fn serialize_supports_size_u64_max() {
        let m = Manifest {
            entries: vec![make_entry(
                "huge.bin",
                ArchiveEntryKind::File,
                u64::MAX,
                0o644,
            )],
            total_file_bytes: u64::MAX,
            root_name: OsString::from("huge.bin"),
            root_is_file: true,
        };
        // Defaults' max_total_plaintext_bytes is 64 GiB; bump it for
        // this synthetic test only.
        let limits = ArchiveLimits::default().with_max_total_plaintext_bytes(u64::MAX);
        let bytes = serialize_manifest(&m, limits).unwrap();

        // Entry layout: kind(1) flags(1) mode(2) path_len(2) size(8)
        // → size starts at offset 6.
        let size_field = &bytes[6..14];
        assert_eq!(size_field, &u64::MAX.to_be_bytes());
    }

    // -- checked_manifest_len ----------------------------------------------

    #[test]
    fn checked_manifest_len_empty_is_zero() {
        let len = checked_manifest_len(&[], ArchiveLimits::default()).unwrap();
        assert_eq!(len, 0);
    }

    #[test]
    fn checked_manifest_len_one_entry() {
        let entries = [make_entry("hi", ArchiveEntryKind::File, 5, 0o644)];
        let len = checked_manifest_len(&entries, ArchiveLimits::default()).unwrap();
        // 14 fixed + 2 path bytes
        assert_eq!(len, FCA_ENTRY_FIXED_SIZE + 2);
    }

    #[test]
    fn checked_manifest_len_rejects_oversize_mode() {
        let entries = [make_entry("file", ArchiveEntryKind::File, 0, 0o7777)];
        let err = checked_manifest_len(&entries, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("mode contains unsupported bits"));
    }

    #[test]
    fn checked_manifest_len_rejects_path_above_cap() {
        let l = ArchiveLimits::default().with_max_path_bytes(5);
        let entries = [make_entry("toolong.txt", ArchiveEntryKind::File, 0, 0o644)];
        let err = checked_manifest_len(&entries, l).unwrap_err();
        assert!(format!("{err}").contains("byte-length cap exceeded"));
    }

    #[test]
    fn checked_manifest_len_rejects_empty_path() {
        let entries = [make_entry("", ArchiveEntryKind::File, 0, 0o644)];
        let err = checked_manifest_len(&entries, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("byte-length cap exceeded"));
    }

    #[test]
    fn checked_manifest_len_rejects_above_manifest_cap() {
        let l = ArchiveLimits::default().with_max_manifest_bytes(20);
        // Two entries, each 14 + 5 = 19 bytes → total 38 > cap 20.
        let entries = [
            make_entry("file1", ArchiveEntryKind::File, 0, 0o644),
            make_entry("file2", ArchiveEntryKind::File, 0, 0o644),
        ];
        let err = checked_manifest_len(&entries, l).unwrap_err();
        assert!(format!("{err}").contains("manifest length cap exceeded"));
    }

    // -- Manifest parser rejection cases (§19.2) ---------------------------

    /// Helper that constructs raw manifest bytes for one synthetic
    /// entry, allowing each field to be set independently to test
    /// rejection cases.
    fn raw_entry_bytes(
        kind: u8,
        flags: u8,
        mode: u16,
        path_len: u16,
        size: u64,
        path: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FCA_ENTRY_FIXED_SIZE + path.len());
        buf.push(kind);
        buf.push(flags);
        buf.extend_from_slice(&mode.to_be_bytes());
        buf.extend_from_slice(&path_len.to_be_bytes());
        buf.extend_from_slice(&size.to_be_bytes());
        buf.extend_from_slice(path);
        buf
    }

    fn parse_with_header(
        bytes: &[u8],
        entry_count: u32,
        total_file_bytes: u64,
    ) -> Result<Manifest, CryptoError> {
        let header = FcaHeader {
            entry_count,
            manifest_len: bytes.len() as u32,
            total_file_bytes,
        };
        parse_manifest_bytes(bytes, header, ArchiveLimits::default())
    }

    #[test]
    fn parse_rejects_unknown_entry_kind() {
        let bytes = raw_entry_bytes(0xFF, 0, 0o644, 4, 10, b"fake");
        let err = parse_with_header(&bytes, 1, 10).unwrap_err();
        assert!(format!("{err}").contains("Unsupported archive entry kind"));
    }

    #[test]
    fn parse_rejects_nonzero_entry_flags() {
        let bytes = raw_entry_bytes(KIND_FILE, 0x01, 0o644, 4, 10, b"file");
        let err = parse_with_header(&bytes, 1, 10).unwrap_err();
        assert!(format!("{err}").contains("non-zero reserved flags"));
    }

    #[test]
    fn parse_rejects_invalid_mode() {
        let bytes = raw_entry_bytes(KIND_FILE, 0, 0o7777, 4, 10, b"file");
        let err = parse_with_header(&bytes, 1, 10).unwrap_err();
        assert!(format!("{err}").contains("mode contains unsupported bits"));
    }

    #[test]
    fn parse_rejects_directory_with_nonzero_size() {
        let bytes = raw_entry_bytes(KIND_DIR, 0, 0o755, 3, 100, b"dir");
        let err = parse_with_header(&bytes, 1, 0).unwrap_err();
        assert!(format!("{err}").contains("Directory archive entry has non-zero size"));
    }

    #[test]
    fn parse_rejects_zero_path_len() {
        let bytes = raw_entry_bytes(KIND_FILE, 0, 0o644, 0, 10, b"");
        let err = parse_with_header(&bytes, 1, 10).unwrap_err();
        assert!(format!("{err}").contains("Empty archive entry path"));
    }

    #[test]
    fn parse_rejects_invalid_utf8() {
        // 0xFF is not a valid UTF-8 start byte.
        let bytes = raw_entry_bytes(KIND_FILE, 0, 0o644, 1, 10, &[0xFF]);
        let err = parse_with_header(&bytes, 1, 10).unwrap_err();
        assert!(format!("{err}").contains("not valid UTF-8"));
    }

    #[test]
    fn parse_rejects_truncated_manifest() {
        // Header claims 1 entry but bytes are short.
        let bytes = vec![KIND_FILE, 0, 0, 0]; // only 4 bytes — fixed header is 14
        let err = parse_with_header(&bytes, 1, 0).unwrap_err();
        assert!(format!("{err}").contains("Malformed archive manifest"));
    }

    #[test]
    fn parse_rejects_path_running_past_manifest() {
        // Fixed entry header says path_len = 100 but only 4 path bytes
        // are present.
        let bytes = raw_entry_bytes(KIND_FILE, 0, 0o644, 100, 10, b"path");
        let err = parse_with_header(&bytes, 1, 10).unwrap_err();
        assert!(format!("{err}").contains("Malformed archive manifest"));
    }

    #[test]
    fn parse_rejects_trailing_bytes_after_last_entry() {
        // One full entry + one extra byte after it.
        let mut bytes = raw_entry_bytes(KIND_FILE, 0, 0o644, 4, 10, b"file");
        bytes.push(0xAA);
        let err = parse_with_header(&bytes, 1, 10).unwrap_err();
        assert!(format!("{err}").contains("Malformed archive manifest"));
    }

    #[test]
    fn parse_rejects_manifest_len_mismatch() {
        let bytes = raw_entry_bytes(KIND_FILE, 0, 0o644, 4, 10, b"file");
        let header = FcaHeader {
            entry_count: 1,
            manifest_len: bytes.len() as u32 + 1,
            total_file_bytes: 10,
        };
        let err = parse_manifest_bytes(&bytes, header, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("Malformed archive manifest"));
    }

    #[test]
    fn parse_rejects_total_bytes_mismatch() {
        // One file entry of size 10; declared total is 99.
        let bytes = raw_entry_bytes(KIND_FILE, 0, 0o644, 4, 10, b"file");
        let err = parse_with_header(&bytes, 1, 99).unwrap_err();
        assert!(format!("{err}").contains("total-bytes mismatch"));
    }

    /// `total_file_bytes` overflow during summation: two files each
    /// claiming `u64::MAX` — second `checked_add` fails.
    #[test]
    fn parse_rejects_total_bytes_overflow_during_sum() {
        let mut bytes = Vec::new();
        bytes.extend(raw_entry_bytes(KIND_FILE, 0, 0o644, 1, u64::MAX, b"a"));
        bytes.extend(raw_entry_bytes(KIND_FILE, 0, 0o644, 1, 1, b"b"));
        // Header `total_file_bytes` doesn't matter — the overflow
        // fires first.
        let header = FcaHeader {
            entry_count: 2,
            manifest_len: bytes.len() as u32,
            total_file_bytes: 0,
        };
        let err = parse_manifest_bytes(&bytes, header, ArchiveLimits::default()).unwrap_err();
        assert!(format!("{err}").contains("total file bytes overflow"));
    }

    /// Single file entry with `size = u64::MAX` round-trips. Pin
    /// "no remnant ustar 8 GiB cap" on the parse side.
    #[test]
    fn parse_accepts_size_u64_max() {
        let bytes = raw_entry_bytes(KIND_FILE, 0, 0o644, 4, u64::MAX, b"huge");
        let limits = ArchiveLimits::default().with_max_total_plaintext_bytes(u64::MAX);
        let header = FcaHeader {
            entry_count: 1,
            manifest_len: bytes.len() as u32,
            total_file_bytes: u64::MAX,
        };
        let parsed = parse_manifest_bytes(&bytes, header, limits).unwrap();
        assert_eq!(parsed.entries[0].size, u64::MAX);
    }

    /// `validate_fca_path` is invoked from inside `parse_manifest_bytes`
    /// — confirm path-grammar rejection surfaces through the manifest
    /// parser. Use `..` as the grammar trip-wire.
    #[test]
    fn parse_runs_path_grammar() {
        let bytes = raw_entry_bytes(KIND_FILE, 0, 0o644, 2, 10, b"..");
        let err = parse_with_header(&bytes, 1, 10).unwrap_err();
        // Either a path-grammar error or a tree-shape error. The
        // grammar should fire first.
        let s = format!("{err}");
        assert!(
            s.contains("forbidden component") || s.contains("Unsafe path"),
            "got: {s}",
        );
    }

    /// Tree validation runs as the final step — confirm a structurally
    /// valid manifest with bad tree shape rejects through the parser.
    #[test]
    fn parse_runs_tree_validation() {
        // Two files at top level (different roots).
        let mut bytes = Vec::new();
        bytes.extend(raw_entry_bytes(KIND_FILE, 0, 0o644, 1, 10, b"a"));
        bytes.extend(raw_entry_bytes(KIND_FILE, 0, 0o644, 1, 10, b"b"));
        let err = parse_with_header(&bytes, 2, 20).unwrap_err();
        assert!(format!("{err}").contains("multiple top-level roots"));
    }
}
