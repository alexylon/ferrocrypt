//! Armor-specific error types lifted from `ferrocrypt-lib/src/error.rs`
//! when the armor module was parked in this experiment.
//!
//! This is a *self-contained* copy: it carries only the variants the
//! armor reader uses (no `CryptoError`, no `FormatDefect` envelope).
//! When/if armor is reintroduced into the main library, fold these
//! variants back under `FormatDefect::MalformedArmor(ArmorDefect)`
//! and reinstate the `From<io::Error> for CryptoError` downcast.

/// Sub-classification of an ASCII-armor parse failure (`FORMAT.md`
/// §10). Each distinct rejection class enumerated by the spec maps
/// to a specific variant rather than collapsing into a single
/// generic error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArmorDefect {
    /// First line did not match `-----BEGIN FERROCRYPT ENCRYPTED FILE-----`.
    BadBeginMarker,
    /// END line was missing, malformed, or didn't match
    /// `-----END FERROCRYPT ENCRYPTED FILE-----`.
    BadEndMarker,
    /// Bytes inside the armor block were not valid UTF-8.
    InvalidUtf8,
    /// A bare `\r` was present inside a line (only `\r\n` or `\n` are
    /// permitted as line terminators).
    LineContainsCr,
    /// A Base64 body line was not exactly 64 characters and was not
    /// the trailing short line.
    NotWrappedAt64Chars,
    /// A short Base64 line appeared before the end of the body
    /// (only the final Base64 line MAY be shorter than 64 chars).
    ShortLineInMiddle,
    /// The final Base64 line's length is not a multiple of 4 (the
    /// Base64 padding is non-canonical).
    NonCanonicalBase64Padding,
    /// A Base64 line contained whitespace, a blank line appeared, or
    /// any other character outside the Base64 alphabet was present
    /// inside the body.
    NonBase64Character,
    /// Bytes other than at most a single trailing line terminator
    /// appeared after the END marker.
    TrailingGarbage,
    /// Underlying Base64 decode rejected the bytes (covers any
    /// failure not caught by the more specific structural classes
    /// above).
    Base64DecodeFailed,
}

impl std::fmt::Display for ArmorDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::BadBeginMarker => "BEGIN marker is malformed",
            Self::BadEndMarker => "END marker is malformed",
            Self::InvalidUtf8 => "armor body is not valid UTF-8",
            Self::LineContainsCr => "armor line contains a bare CR",
            Self::NotWrappedAt64Chars => "armor line is not wrapped at 64 chars",
            Self::ShortLineInMiddle => "short armor line in middle of body",
            Self::NonCanonicalBase64Padding => "non-canonical Base64 padding",
            Self::NonBase64Character => "non-Base64 character in armor body",
            Self::TrailingGarbage => "trailing data after END marker",
            Self::Base64DecodeFailed => "Base64 decode failed",
        };
        f.write_str(msg)
    }
}

/// `ArmorDefect` doubles as an `io::Error` inner-error marker. The
/// armor reader builds `io::Error::new(InvalidData, defect)` whenever
/// it rejects a line; downstream code can downcast the inner back to
/// `ArmorDefect` to recover the typed defect across the
/// `Read` / `Write` trait boundary.
impl std::error::Error for ArmorDefect {}
