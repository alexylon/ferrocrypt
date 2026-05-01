//! Filesystem-level key helpers — default filenames and key-file
//! classification.
//!
//! `KeyFileKind` is a cheap, non-authenticating heuristic used to
//! surface the friendly `WrongKeyFileType` diagnostic when a user
//! hands the wrong kind of key file to a reader. The strict parse —
//! Bech32 + algorithm + length for public, magic + version + type +
//! algorithm + size + AEAD for private — runs downstream in each
//! reader against the actual unlock or extract path.

use crate::format;
use crate::key::public::{RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT, decode_recipient_string};

/// Default filename for the hybrid public key file (text form).
pub const PUBLIC_KEY_FILENAME: &str = "public.key";

/// Default filename for the hybrid private key file (binary, wrapped).
pub const PRIVATE_KEY_FILENAME: &str = "private.key";

/// Heuristic classification of key-file bytes. Cheap, non-
/// authenticating: callers use it to surface the friendly
/// `WrongKeyFileType` diagnostic when a user hands the wrong
/// kind of key file to a reader. The strict parse — Bech32 +
/// algorithm + length for public, magic + version + type +
/// algorithm + size + AEAD for private — runs downstream in
/// each reader against the actual unlock or extract path.
///
/// Adding a new variant is a deliberate breaking change inside
/// the crate: every `match` over a `KeyFileKind` becomes a
/// compile error until the new kind is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyFileKind {
    /// Bytes look like a v1 `public.key`: a UTF-8 string that
    /// decodes as a canonical Bech32 `fcr1…` recipient (with
    /// surrounding whitespace tolerated for the heuristic — the
    /// strict parser in `read_public_key` enforces canonical
    /// whitespace separately).
    Public,
    /// Bytes carry the v1 `private.key` signature: at least 9
    /// bytes of `FCR\0 || ?? || 'K'`. Magic + type byte is
    /// sufficient regardless of `version`, so a future v2
    /// `private.key` still classifies as `Private` and surfaces
    /// the friendly diagnostic instead of `NotAKeyFile`.
    Private,
    /// Neither signature matches.
    Unknown,
}

impl KeyFileKind {
    /// Classifies `data` against the two v1 key-file shapes.
    /// Probes the cheap binary signature first; falls back to
    /// the more expensive Bech32 decode for the public-key
    /// text shape.
    ///
    /// The binary signature is `magic(4) || version(1) || kind(1)
    /// = 'K'`. The version byte is intentionally not constrained,
    /// so a future v2 `private.key` still classifies as `Private`
    /// and surfaces the friendly diagnostic instead of `NotAKeyFile`.
    ///
    /// Adversarial inputs that do NOT match either signature
    /// (a `.fcr` encrypted file whose `kind` byte is `'E'`,
    /// random binary without magic, garbage `fcr1…` text with a
    /// bad checksum) classify as `Unknown` and fall through to
    /// the caller's generic rejection path. Probability of an
    /// accidental `Private` match on truly random binary is
    /// `2^-40` (the five specific bytes in the signature).
    pub(crate) fn classify(data: &[u8]) -> Self {
        // Smallest prefix needed to read the kind byte at offset 5:
        // magic(4) || version(1) || kind(1).
        const SIGNATURE_LEN: usize = 6;
        if data.len() >= SIGNATURE_LEN
            && data[0..4] == format::MAGIC
            && data[5] == format::KIND_PRIVATE_KEY
        {
            return Self::Private;
        }
        // Bound the UTF-8 attempt at one byte past the recipient-string
        // cap. A blob longer than the cap could never decode as a valid
        // recipient anyway (the decoder rejects on length), so paying
        // O(n) UTF-8 validation across the whole input adds no signal.
        // The `+ 1` ensures an at-cap valid recipient still fits while
        // an over-cap input is recognisably over-cap to the decoder
        // rather than being silently truncated into a valid prefix.
        let probe_len = data.len().min(RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT + 1);
        if let Ok(text) = std::str::from_utf8(&data[..probe_len]) {
            if decode_recipient_string(text.trim(), RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT).is_ok()
            {
                return Self::Public;
            }
        }
        Self::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CryptoError;
    use secrecy::SecretString;
    use std::fs;

    /// Pin every `KeyFileKind::classify` arm so a future refactor
    /// that drifts the order or weakens a branch fails loudly.
    #[test]
    fn key_file_kind_classifies_each_shape() -> Result<(), CryptoError> {
        // Real public.key text → Public.
        let tmp = tempfile::TempDir::new().unwrap();
        let pass = SecretString::from("kp".to_string());
        let (privkey_path, pubkey_path) =
            crate::protocol::generate_key_pair(&pass, tmp.path(), &|_| {})?;
        let pub_bytes = fs::read(&pubkey_path)?;
        assert_eq!(KeyFileKind::classify(&pub_bytes), KeyFileKind::Public);

        // Real private.key binary → Private.
        let priv_bytes = fs::read(&privkey_path)?;
        assert_eq!(KeyFileKind::classify(&priv_bytes), KeyFileKind::Private);

        // Magic + future version + type K (a v2 private.key) → Private.
        let v2_priv = b"FCR\0\x02K\x01\x00\x00";
        assert_eq!(KeyFileKind::classify(v2_priv), KeyFileKind::Private);

        // Magic but type byte is 'S' (a symmetric .fcr) → Unknown,
        // not Private. The `.fcr` mix-up heuristic lives elsewhere
        // (`detect_encryption_mode`); a key-file path should not
        // claim it.
        let fcr_symmetric = b"FCR\0\x01Sxx\x00\x00";
        assert_eq!(KeyFileKind::classify(fcr_symmetric), KeyFileKind::Unknown);

        // Bare magic, too short for the signature → Unknown.
        assert_eq!(KeyFileKind::classify(b"FCR\0"), KeyFileKind::Unknown);

        // Random binary without magic → Unknown.
        assert_eq!(
            KeyFileKind::classify(b"this isn't ours at all"),
            KeyFileKind::Unknown
        );

        // `fcr1`-prefixed garbage that fails Bech32 checksum →
        // Unknown (NOT Public). We don't claim ownership of files
        // we can't actually read.
        assert_eq!(KeyFileKind::classify(b"fcr1foobar"), KeyFileKind::Unknown);

        // Empty input → Unknown.
        assert_eq!(KeyFileKind::classify(b""), KeyFileKind::Unknown);
        Ok(())
    }

    /// A multi-MB blob whose first 4 bytes look like an `fcr1…` recipient
    /// must classify as `Unknown` without paying O(n) UTF-8 validation
    /// over every byte. `classify` bounds the probe at the recipient-
    /// string cap (1 KiB + 1), so an oversize input is recognisably
    /// over-cap to the decoder and we return `Unknown`.
    #[test]
    fn classify_does_not_scan_oversize_blob() {
        let mut blob = vec![0xFFu8; 4 * 1024 * 1024];
        blob[0] = b'f';
        blob[1] = b'c';
        blob[2] = b'r';
        blob[3] = b'1';
        assert_eq!(KeyFileKind::classify(&blob), KeyFileKind::Unknown);
    }
}
