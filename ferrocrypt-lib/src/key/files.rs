//! Filesystem-level key helpers — default filenames, the check that
//! recognizes a `public.key`, and the read both private-key readers start
//! with.
//!
//! [`looks_like_public_key`] is a cheap, non-authenticating check that lets
//! a private-key reader report the more specific `WrongKeyFileType` when a
//! user hands it a `public.key`. Its counterpart for the `public.key` reader,
//! [`has_private_key_signature`], lives with the `private.key` layout.
//! Neither decides anything else: the full parse of each kind of key file
//! runs later, in its own reader.

use std::path::Path;

use crate::CryptoError;
use crate::error::FormatDefect;
use crate::key::limits::KeyReadLimits;
use crate::key::private::{
    PRIVATE_KEY_FILE_READ_CAP_BYTES, PRIVATE_KEY_HEADER_FIXED_SIZE, PrivateKeyHeader,
    has_private_key_signature,
};
use crate::key::public::decode_recipient_string;

/// Default filename for the public key file (text form).
pub const PUBLIC_KEY_FILENAME: &str = "public.key";

/// Default filename for the private key file (binary, wrapped).
pub const PRIVATE_KEY_FILENAME: &str = "private.key";

/// Whether `data` looks like a `public.key`: its first
/// [`public_key_probe_len`] bytes, once surrounding whitespace is trimmed,
/// decode as a Bech32 `fcr1…` recipient string within the recipient-string
/// cap in `limits`, so a raised cap also recognizes a longer string. The
/// private-key readers use it to report [`FormatDefect::WrongKeyFileType`].
/// The trimming is for this check only: the `public.key` reader refuses any
/// whitespace but one final LF.
pub(crate) fn looks_like_public_key(data: &[u8], limits: KeyReadLimits) -> bool {
    // Checking only the probe keeps the cost independent of the input length.
    let probe_len = data.len().min(public_key_probe_len(limits));
    std::str::from_utf8(&data[..probe_len]).is_ok_and(|text| {
        decode_recipient_string(text.trim(), limits.recipient_string_chars()).is_ok()
    })
}

/// How many leading bytes [`looks_like_public_key`] reads at most under
/// `limits`: a recipient string at the cap, plus one byte so that a longer
/// input reaches the decoder as over the cap rather than cut to a valid
/// prefix. A reader that must tell a `public.key` apart needs no more of a
/// file than this.
pub(crate) fn public_key_probe_len(limits: KeyReadLimits) -> usize {
    limits.recipient_string_chars().saturating_add(1)
}

/// Reads a `private.key` file and refuses a `public.key` handed in its
/// place: the first step of both private-key readers, the unlock and
/// [`crate::validate_private_key_file`].
///
/// The read takes in only what the file's own cleartext header declares,
/// not the structural maximum of every field, with the wrapped secret
/// clamped at the cap in `limits`. A file declaring more than that cap is
/// read short on purpose: [`crate::key::private::open_private_key`] applies
/// the same cap from the fixed header alone, before it compares the buffer
/// length, so the caller still receives
/// [`CryptoError::PrivateKeyWrappedSecretCapExceeded`] rather than a
/// malformed-key rejection. A file whose head is not a parseable
/// private-key header is read only as far as the `public.key` probe needs
/// under `limits`, and the caller then refuses it with the error its header
/// gives, whatever its size.
///
/// A `public.key` reports [`FormatDefect::WrongKeyFileType`] rather than
/// the [`FormatDefect::NotAKeyFile`] that the private-key magic check
/// would give. Each reader passes its own limits: validation the structural
/// maxima, the unlock the caller's. So the unlock recognizes a `public.key`
/// only up to its own recipient-string cap.
pub(crate) fn read_private_key_bytes(
    path: &Path,
    limits: KeyReadLimits,
) -> Result<Vec<u8>, CryptoError> {
    let wrapped_secret_cap = limits.private_key_wrapped_secret_len();
    let bytes = crate::fs::paths::read_file_staged(
        path,
        PRIVATE_KEY_HEADER_FIXED_SIZE,
        PRIVATE_KEY_FILE_READ_CAP_BYTES,
        |head| match head.first_chunk().map(PrivateKeyHeader::parse) {
            // `parse` has already bounded the other three fields, so
            // clamping the wrapped secret keeps the total under the
            // structural read cap.
            Some(Ok(header)) => usize::try_from(header.declared_len_after_fixed_header(
                header.wrapped_secret_len.min(wrapped_secret_cap),
            ))
            .unwrap_or(usize::MAX),
            _ => public_key_probe_len(limits).saturating_sub(PRIVATE_KEY_HEADER_FIXED_SIZE),
        },
    )?;
    // Bytes with the `private.key` signature never decode as a recipient
    // string, so a real key skips the probe.
    if !has_private_key_signature(&bytes) && looks_like_public_key(&bytes, limits) {
        return Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CryptoError;
    use crate::passphrase::Passphrase;
    use std::fs;

    /// A file whose head is not a `private.key` header is read only as far
    /// as the `public.key` probe needs under the caller's limits, plus the
    /// one byte the staged read always adds, however long the file is. The
    /// caller then refuses it with its header's error, and a hostile file
    /// cannot make the reader take in more.
    #[test]
    fn a_head_that_is_not_a_private_key_header_is_read_only_as_far_as_the_probe_needs() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        fs::write(tmp.path(), vec![0x41u8; 64 * 1024]).unwrap();
        for limits in [KeyReadLimits::default(), KeyReadLimits::structural_max()] {
            let read = read_private_key_bytes(tmp.path(), limits).unwrap();
            assert_eq!(read.len(), public_key_probe_len(limits) + 1);
        }
    }

    fn looks_like_public_key_by_default(data: &[u8]) -> bool {
        looks_like_public_key(data, KeyReadLimits::default())
    }

    /// Pin what each check says about every shape, so a later change that
    /// weakens either one fails this test.
    #[test]
    fn the_key_file_checks_tell_each_shape_apart() -> Result<(), CryptoError> {
        let tmp = tempfile::TempDir::new().unwrap();
        let (private_key_path, public_key_path, _recipient, _fingerprint) =
            crate::protocol::generate_key_pair(
                Passphrase::new("kp"),
                &crate::crypto::kdf::KdfParams::test_fast_default(),
                None,
                tmp.path(),
                &|_| {},
            )?;
        // A real public.key looks like one and has no private.key signature.
        let pub_bytes = fs::read(&public_key_path)?;
        assert!(looks_like_public_key_by_default(&pub_bytes));
        assert!(!has_private_key_signature(&pub_bytes));

        // A real private.key carries the signature and is not taken for a
        // public.key.
        let priv_bytes = fs::read(&private_key_path)?;
        assert!(has_private_key_signature(&priv_bytes));
        assert!(!looks_like_public_key_by_default(&priv_bytes));

        // Magic, a future private-key encoding version 0x02, and kind K
        // still carry the signature.
        assert!(has_private_key_signature(b"FCR\0\x02K\x01\x00\x00"));

        // Magic with kind 'E' (an encrypted .fcr), bare magic too short for
        // the kind byte, bytes that are not ours, `fcr1` text that fails its
        // Bech32 checksum, and empty input: neither check claims them.
        // Recognizing an `.fcr` is left to `probe_recipient_mode`.
        for data in [
            &b"FCR\0\x01Exx\x00\x00"[..],
            b"FCR\0",
            b"this isn't ours at all",
            b"fcr1foobar",
            b"",
        ] {
            assert!(!has_private_key_signature(data), "{data:?}");
            assert!(!looks_like_public_key_by_default(data), "{data:?}");
        }
        Ok(())
    }

    /// A multi-megabyte blob that starts like an `fcr1…` recipient string
    /// is not taken for a `public.key`.
    #[test]
    fn an_oversize_blob_that_starts_like_a_recipient_string_is_not_a_public_key() {
        let mut blob = vec![0xFFu8; 4 * 1024 * 1024];
        blob[..4].copy_from_slice(b"fcr1");
        assert!(!looks_like_public_key_by_default(&blob));
    }
}
