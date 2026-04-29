//! Type-name validation and namespace rules (`FORMAT.md` §3.3).
//!
//! Native recipient type names are short (no `/`); plugin / third-party
//! types MUST use a fully qualified name containing `/`
//! (e.g. `example.com/enigma`). Native-name prefixes `mlkem`, `pq`,
//! `hpke`, `tag`, `xwing`, `kem` and any name ending in `tag` are
//! reserved for future FerroCrypt-defined recipient types; plugin
//! registries MUST reject such names.

use crate::CryptoError;
use crate::error::FormatDefect;

/// Maximum byte length of a recipient `type_name`
/// (`FORMAT.md` §3.3, `type_name_len:u16` constrained to `1..=255`).
pub const TYPE_NAME_MAX_LEN: usize = 255;

/// Validates a recipient `type_name` against the grammar in
/// `FORMAT.md` §3.3:
///
/// - 1..=255 bytes;
/// - lowercase ASCII;
/// - allowed characters: `a-z 0-9 . _ + - /`;
/// - no leading or trailing `.`, `_`, `+`, `-`, `/`;
/// - no `..` or `//`.
///
/// On failure surfaces [`crate::error::FormatDefect::MalformedTypeName`].
pub fn validate_type_name(name: &str) -> Result<(), CryptoError> {
    let malformed = || CryptoError::InvalidFormat(FormatDefect::MalformedTypeName);
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > TYPE_NAME_MAX_LEN {
        return Err(malformed());
    }
    for &b in bytes {
        let allowed = matches!(
            b,
            b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'+' | b'-' | b'/'
        );
        if !allowed {
            return Err(malformed());
        }
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    for &edge in &[first, last] {
        if matches!(edge, b'.' | b'_' | b'+' | b'-' | b'/') {
            return Err(malformed());
        }
    }
    for window in bytes.windows(2) {
        if window == b".." || window == b"//" {
            return Err(malformed());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipient::native::{argon2id, x25519};

    #[test]
    fn validate_type_name_accepts_canonical_natives() {
        validate_type_name(argon2id::TYPE_NAME).unwrap();
        validate_type_name(x25519::TYPE_NAME).unwrap();
    }

    #[test]
    fn validate_type_name_accepts_fqn_plugin_names() {
        validate_type_name("example.com/enigma").unwrap();
        validate_type_name("com.example/foo").unwrap();
        validate_type_name("a.b.c/d").unwrap();
    }

    #[test]
    fn validate_type_name_rejects_empty() {
        match validate_type_name("") {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for empty, got {other:?}"),
        }
    }

    #[test]
    fn validate_type_name_rejects_overlong() {
        let long = "a".repeat(256);
        match validate_type_name(&long) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for 256-byte name, got {other:?}"),
        }
    }

    #[test]
    fn validate_type_name_accepts_max_length() {
        let max = "a".repeat(255);
        validate_type_name(&max).unwrap();
    }

    #[test]
    fn validate_type_name_rejects_uppercase() {
        match validate_type_name("Argon2id") {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for uppercase, got {other:?}"),
        }
    }

    #[test]
    fn validate_type_name_rejects_invalid_characters() {
        for bad in &["foo bar", "foo!", "foo:bar", "foo*", "foo\nbar"] {
            match validate_type_name(bad) {
                Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
                other => panic!("expected MalformedTypeName for `{bad}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_type_name_rejects_edge_punctuation() {
        for bad in &[
            ".foo", "_foo", "+foo", "-foo", "/foo", "foo.", "foo_", "foo+", "foo-", "foo/",
        ] {
            match validate_type_name(bad) {
                Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
                other => panic!("expected MalformedTypeName for `{bad}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_type_name_rejects_consecutive_punctuation() {
        for bad in &["foo..bar", "foo//bar", "a.b..c", "a/b//c"] {
            match validate_type_name(bad) {
                Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
                other => panic!("expected MalformedTypeName for `{bad}`, got {other:?}"),
            }
        }
    }
}
