//! Local resource caps applied while reading key files.
//!
//! The two caps bound work a key file can demand before its contents
//! are known: how long a `fcr1…` recipient string may be, and how many
//! bytes a `private.key` may declare for its wrapped secret. Both sit
//! far below the structural maxima in `FORMAT.md` §7 and §8, because the
//! native X25519 key pair needs only about 108 characters and 48 bytes.
//! Callers that must read a key whose material legitimately exceeds a
//! default raise that cap instead of patching the library.

use crate::key::private::{
    PRIVATE_KEY_WRAPPED_SECRET_LEN_MAX, PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT,
};
use crate::key::public::{RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT, RECIPIENT_STRING_LEN_MAX};

/// Local resource caps applied while reading a `public.key`, a `fcr1…`
/// recipient string, or a `private.key`.
///
/// The defaults suit every key type FerroCrypt ships. Raise a cap only
/// for keys from a known origin whose material legitimately exceeds it;
/// each builder method clamps at the structural maximum for that field,
/// so a caller cannot request more than the format can represent.
///
/// Caps are enforced before allocation or key derivation, and exceeding
/// one surfaces as a distinct `*CapExceeded` error rather than as a
/// malformed-key defect (`FORMAT.md` §7, §8).
///
/// Pass a value to [`crate::PublicKey::from_key_file_with_limits`],
/// [`crate::PublicKey::from_recipient_string_with_limits`], or
/// [`crate::PrivateKeyDecryptor::key_read_limits`]. The struct is
/// `#[non_exhaustive]` so future releases can add further caps without a
/// breaking change. A cap is a numeric bound, which is what lets the
/// struct stay `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyReadLimits {
    /// Hard cap on the character count of a recipient string, including
    /// the `fcr1` prefix and the Bech32 checksum.
    pub(crate) max_recipient_string_chars: u32,
    /// Hard cap on a `private.key` header's `wrapped_secret_len`.
    pub(crate) max_private_key_wrapped_secret_len: u32,
}

impl Default for KeyReadLimits {
    fn default() -> Self {
        Self {
            max_recipient_string_chars: Self::RECIPIENT_STRING_CHARS_DEFAULT,
            max_private_key_wrapped_secret_len: Self::PRIVATE_KEY_WRAPPED_SECRET_LEN_DEFAULT,
        }
    }
}

impl KeyReadLimits {
    /// Structural maximum for a recipient string (20,000 ASCII
    /// characters, `FORMAT.md` §7). Builder methods clamp at this value.
    pub const RECIPIENT_STRING_CHARS_STRUCTURAL_MAX: u32 = RECIPIENT_STRING_LEN_MAX as u32;
    /// Structural maximum for a `private.key` `wrapped_secret_len`
    /// (16 MiB, `FORMAT.md` §8). Builder methods clamp at this value.
    pub const PRIVATE_KEY_WRAPPED_SECRET_LEN_STRUCTURAL_MAX: u32 =
        PRIVATE_KEY_WRAPPED_SECRET_LEN_MAX;

    /// Default value used by [`KeyReadLimits::default`] for
    /// `max_recipient_string_chars` (1,024 characters).
    pub const RECIPIENT_STRING_CHARS_DEFAULT: u32 = RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT as u32;
    /// Default value used by [`KeyReadLimits::default`] for
    /// `max_private_key_wrapped_secret_len` (4,096 bytes). Mirrored on
    /// the writer side, so a sealed `private.key` always opens under the
    /// default configuration.
    pub const PRIVATE_KEY_WRAPPED_SECRET_LEN_DEFAULT: u32 =
        PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT;

    /// Sets the maximum accepted recipient-string length in characters,
    /// clamped at [`Self::RECIPIENT_STRING_CHARS_STRUCTURAL_MAX`]. A
    /// longer string rejects with
    /// [`CryptoError::RecipientStringCapExceeded`](crate::CryptoError::RecipientStringCapExceeded)
    /// before it is decoded.
    pub fn max_recipient_string_chars(mut self, value: u32) -> Self {
        self.max_recipient_string_chars = value.min(Self::RECIPIENT_STRING_CHARS_STRUCTURAL_MAX);
        self
    }

    /// Sets the maximum accepted `private.key` `wrapped_secret_len` in
    /// bytes, clamped at
    /// [`Self::PRIVATE_KEY_WRAPPED_SECRET_LEN_STRUCTURAL_MAX`]. A larger
    /// declaration rejects with
    /// [`CryptoError::PrivateKeyWrappedSecretCapExceeded`](crate::CryptoError::PrivateKeyWrappedSecretCapExceeded)
    /// before Argon2id runs.
    pub fn max_private_key_wrapped_secret_len(mut self, value: u32) -> Self {
        self.max_private_key_wrapped_secret_len =
            value.min(Self::PRIVATE_KEY_WRAPPED_SECRET_LEN_STRUCTURAL_MAX);
        self
    }

    /// Caps set to the structural maxima, for the callers that apply no
    /// resource policy of their own: [`crate::validate_public_key_file`]
    /// and [`crate::validate_private_key_file`] report what the format
    /// allows rather than what a default reader would accept.
    pub(crate) fn structural_max() -> Self {
        Self {
            max_recipient_string_chars: Self::RECIPIENT_STRING_CHARS_STRUCTURAL_MAX,
            max_private_key_wrapped_secret_len: Self::PRIVATE_KEY_WRAPPED_SECRET_LEN_STRUCTURAL_MAX,
        }
    }

    /// Recipient-string cap as a `usize` for the decoder, which counts
    /// characters of an ASCII string.
    pub(crate) fn recipient_string_chars(self) -> usize {
        self.max_recipient_string_chars as usize
    }

    /// Wrapped-secret cap for the `private.key` reader.
    pub(crate) fn private_key_wrapped_secret_len(self) -> u32 {
        self.max_private_key_wrapped_secret_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every cap this type carries is driven at and over its boundary
    /// on the read side, and a new one belongs with them.
    ///
    /// These caps are reader-only: no writer knob varies the length of
    /// a recipient string or the size of a wrapped secret, so pairing
    /// one with a writer threshold would claim a symmetry that does not
    /// exist. `max_recipient_string_chars` is driven through both
    /// public ingress paths in `key/public.rs`, and
    /// `max_private_key_wrapped_secret_len` in
    /// `recipient/native/x25519.rs` and at integration level in
    /// `tests/api_tests.rs`.
    ///
    /// Rust has no reflection, so this destructure stops compiling when
    /// a field is added, which is the prompt to give it a reader-side
    /// boundary test and then name it here.
    #[test]
    fn every_cap_is_driven_at_its_reader_boundary() {
        let KeyReadLimits {
            max_recipient_string_chars: _,
            max_private_key_wrapped_secret_len: _,
        } = KeyReadLimits::default();
    }
    #[test]
    fn defaults_match_the_reader_constants() {
        let limits = KeyReadLimits::default();
        assert_eq!(
            limits.recipient_string_chars(),
            RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT
        );
        assert_eq!(
            limits.private_key_wrapped_secret_len(),
            PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT
        );
    }

    #[test]
    fn builders_round_trip_in_range_values() {
        let limits = KeyReadLimits::default()
            .max_recipient_string_chars(4_096)
            .max_private_key_wrapped_secret_len(8_192);
        assert_eq!(limits.recipient_string_chars(), 4_096);
        assert_eq!(limits.private_key_wrapped_secret_len(), 8_192);
    }

    /// Both caps must stay reachable at their structural maximum: a
    /// file-read cap below the raised limit would make the top of the
    /// range unusable and turn a cap rejection into a malformed-key one.
    /// `private.key` reads only what its own header declares, but the
    /// structural cap still bounds a header that does not parse.
    #[test]
    fn structural_maxima_fit_the_key_file_read_caps() {
        use crate::key::private::{
            PRIVATE_KEY_EXT_LEN_MAX, PRIVATE_KEY_FILE_READ_CAP_BYTES,
            PRIVATE_KEY_HEADER_FIXED_SIZE, PRIVATE_KEY_PUBLIC_LEN_MAX,
        };
        use crate::key::public::PUBLIC_KEY_FILE_READ_CAP_BYTES;
        use crate::recipient::name::TYPE_NAME_MAX_LEN;

        // A maximum-length recipient string plus its trailing LF.
        let widest_public_key_file =
            KeyReadLimits::RECIPIENT_STRING_CHARS_STRUCTURAL_MAX as usize + 1;
        assert!(
            widest_public_key_file <= PUBLIC_KEY_FILE_READ_CAP_BYTES,
            "a {widest_public_key_file}-byte public.key must fit the \
             {PUBLIC_KEY_FILE_READ_CAP_BYTES}-byte read cap"
        );

        // A private.key at the structural maximum in every field.
        let widest_private_key_file = PRIVATE_KEY_HEADER_FIXED_SIZE
            + TYPE_NAME_MAX_LEN
            + PRIVATE_KEY_PUBLIC_LEN_MAX as usize
            + PRIVATE_KEY_EXT_LEN_MAX as usize
            + KeyReadLimits::PRIVATE_KEY_WRAPPED_SECRET_LEN_STRUCTURAL_MAX as usize;
        assert!(
            widest_private_key_file <= PRIVATE_KEY_FILE_READ_CAP_BYTES,
            "a {widest_private_key_file}-byte private.key must fit the \
             {PRIVATE_KEY_FILE_READ_CAP_BYTES}-byte read cap"
        );
    }

    /// A caller cannot raise a cap above what the format can represent,
    /// mirroring [`crate::HeaderReadLimits`]'s clamping.
    #[test]
    fn builders_clamp_at_structural_maxima() {
        let clamped = KeyReadLimits::default()
            .max_recipient_string_chars(u32::MAX)
            .max_private_key_wrapped_secret_len(u32::MAX);
        assert_eq!(
            clamped.recipient_string_chars(),
            RECIPIENT_STRING_LEN_MAX,
            "recipient-string cap must clamp at the 20,000-character ceiling"
        );
        assert_eq!(
            clamped.private_key_wrapped_secret_len(),
            PRIVATE_KEY_WRAPPED_SECRET_LEN_MAX,
            "wrapped-secret cap must clamp at the 16 MiB ceiling"
        );
    }

    /// The structural-maxima constructor must match what the builders
    /// clamp to, so a caller applying no resource policy and a caller
    /// asking for the highest cap reach the same limits.
    #[test]
    fn structural_max_matches_the_clamped_builders() {
        let clamped = KeyReadLimits::default()
            .max_recipient_string_chars(u32::MAX)
            .max_private_key_wrapped_secret_len(u32::MAX);
        assert_eq!(KeyReadLimits::structural_max(), clamped);
    }
}
