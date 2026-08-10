//! Owned passphrase type consumed by every passphrase-based operation.

use zeroize::Zeroizing;

/// A passphrase held in a buffer that is wiped when the value drops.
///
/// Every operation that takes a passphrase consumes a `Passphrase`:
/// [`Encryptor::with_passphrase`](crate::Encryptor::with_passphrase),
/// [`PassphraseDecryptor::decrypt`](crate::PassphraseDecryptor::decrypt),
/// [`PrivateKey::from_key_file`](crate::PrivateKey::from_key_file),
/// [`KeyPairGenerator::with_passphrase`](crate::KeyPairGenerator::with_passphrase),
/// and [`generate_key_pair`](crate::generate_key_pair).
///
/// The text is readable only inside the crate. There is no public
/// accessor, `Debug` prints `Passphrase(<redacted>)`, and the type
/// implements neither `Display` nor `Clone`, so a passphrase cannot
/// leak through formatting and each operation consumes a value built
/// for it.
///
/// Wiping covers the buffer this value owns. A copy that existed
/// before construction — a prompt library's buffer, a `String` the
/// caller still holds — is outside its reach, so build the
/// `Passphrase` as early as practical and let the source value drop.
/// The wipe also acts only inside this process: it cannot stop the
/// operating system from paging the memory to swap or including it in
/// a crash dump while the value is alive.
#[non_exhaustive]
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    /// Takes ownership of the passphrase text.
    ///
    /// Accepts a `String` or `&str`; passing an owned `String` moves it
    /// into the wiped buffer without an extra copy of the secret. The
    /// length bound of 1 to 4,096 bytes is checked by the operation
    /// that uses the passphrase, not here; construction is infallible.
    pub fn new(text: impl Into<String>) -> Self {
        Self(Zeroizing::new(text.into()))
    }

    /// Read access for the crate's validation and KDF call sites. Bytes
    /// rather than `&str`, because the length bound is in bytes and every
    /// call site either hashes or measures the bytes.
    pub(crate) fn expose(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_the_text() {
        let passphrase = Passphrase::new("visible-secret");
        let printed = format!("{passphrase:?}");
        assert_eq!(printed, "Passphrase(<redacted>)");
        assert!(!printed.contains("visible-secret"));
    }

    #[test]
    fn expose_returns_the_exact_bytes() {
        assert_eq!(Passphrase::new("pw").expose(), b"pw");
    }
}
