//! FCA wire-format constants and primitives: header parse/build,
//! manifest serialize/parse, and big-endian integer helpers.
//!
//! See `notes/archive_format/ARCHIVE_FORMAT.md` §5 (header), §6 (manifest),
//! §14.1 (constants), §14.3 (BE helpers), §14.4 (header writer),
//! §14.5 (header reader).

use std::io::{self, Read, Write};

use crate::CryptoError;

use super::limits::ArchiveLimits;
use super::model::FcaHeader;

pub(crate) const FCA_MAGIC: &[u8; 4] = b"FCA\0";
pub(crate) const FCA_VERSION: u8 = 0x01;
pub(crate) const FCA_HEADER_SIZE: usize = 23;
pub(crate) const FCA_ENTRY_FIXED_SIZE: usize = 14;

pub(crate) const KIND_FILE: u8 = 0x01;
pub(crate) const KIND_DIR: u8 = 0x02;

pub(crate) const FCA_FLAGS_V1: u16 = 0;
pub(crate) const FCA_ENTRY_FLAGS_V1: u8 = 0;
pub(crate) const PERMISSION_BITS_MASK: u32 = 0o777;

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
        return Err(CryptoError::InvalidInput("Empty archive".to_string()));
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
pub(crate) fn parse_fca_header<R: Read>(
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
        return Err(CryptoError::InvalidInput("Empty archive".to_string()));
    }
    if entry_count > limits.max_entry_count {
        return Err(CryptoError::InvalidInput(format!(
            "Archive entry-count cap exceeded ({entry_count} entries, cap {})",
            limits.max_entry_count
        )));
    }
    if manifest_len == 0 {
        return Err(CryptoError::InvalidInput(
            "Malformed archive manifest".to_string(),
        ));
    }
    if manifest_len > limits.max_manifest_bytes {
        return Err(CryptoError::InvalidInput(format!(
            "Archive manifest length cap exceeded ({manifest_len} bytes, cap {})",
            limits.max_manifest_bytes
        )));
    }
    if usize::try_from(manifest_len).is_err() {
        return Err(CryptoError::InvalidInput(
            "Archive manifest length cannot fit in memory".to_string(),
        ));
    }
    if total_file_bytes > limits.max_total_plaintext_bytes {
        return Err(CryptoError::InvalidInput(format!(
            "Archive total-bytes cap exceeded ({total_file_bytes} bytes, cap {})",
            limits.max_total_plaintext_bytes
        )));
    }

    Ok(FcaHeader {
        entry_count,
        manifest_len,
        total_file_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
