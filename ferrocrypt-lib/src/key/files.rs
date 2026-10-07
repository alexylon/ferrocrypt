//! Filesystem-level key helpers: the default key filenames and the read both
//! private-key readers start with.

use std::path::Path;

use crate::CryptoError;
use crate::key::private::{
    PRIVATE_KEY_FILE_READ_CAP_BYTES, PRIVATE_KEY_HEADER_FIXED_SIZE, PrivateKeyHeader,
};

/// Default filename for the public key file (text form).
pub const PUBLIC_KEY_FILENAME: &str = "public.key";

/// Default filename for the private key file (binary, wrapped).
pub const PRIVATE_KEY_FILENAME: &str = "private.key";

/// Reads a `private.key` file for both private-key readers, the unlock and
/// [`crate::validate_private_key_file`], which then parse it from
/// [`PrivateKeyHeader::from_file_bytes`].
///
/// The read is bounded by the header's declared lengths, with the wrapped
/// secret clamped at `wrapped_secret_cap`, plus one byte to detect trailing
/// data. It does not allocate every field's structural maximum. A file
/// declaring more than the cap is read short on purpose:
/// [`crate::key::private::open_private_key`] checks the cap in the header
/// before the file length, so the caller still gets
/// [`CryptoError::PrivateKeyWrappedSecretCapExceeded`]. A file whose head does
/// not parse, a `public.key` included, is read no further than the head and one
/// byte, and the caller refuses it with the error the head gives.
pub(crate) fn read_private_key_bytes(
    path: &Path,
    wrapped_secret_cap: u32,
) -> Result<Vec<u8>, CryptoError> {
    crate::fs::paths::read_file_staged(
        path,
        PRIVATE_KEY_HEADER_FIXED_SIZE,
        PRIVATE_KEY_FILE_READ_CAP_BYTES,
        |head| match PrivateKeyHeader::from_file_bytes(head) {
            // The parse has already bounded the other lengths, so clamping
            // the wrapped secret keeps the total under the read cap.
            Ok(header) => usize::try_from(header.declared_len_after_fixed_header(
                header.wrapped_secret_len.min(wrapped_secret_cap),
            ))
            .unwrap_or(usize::MAX),
            // The caller refuses this head by its own error, which needs no
            // more bytes.
            Err(_) => 0,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A file whose head is not a `private.key` header is read no further than
    /// the head and one byte, however long the file is and whatever the cap.
    #[test]
    fn a_head_that_is_not_a_private_key_header_is_read_no_further() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        fs::write(tmp.path(), vec![0x41u8; 64 * 1024]).unwrap();
        for wrapped_secret_cap in [0, u32::MAX] {
            let read = read_private_key_bytes(tmp.path(), wrapped_secret_cap).unwrap();
            assert_eq!(read.len(), PRIVATE_KEY_HEADER_FIXED_SIZE + 1);
        }
    }
}
