//! Type-name validation and namespace rules (`FORMAT.md` §3.3 and §3.3.1).
//!
//! Two distinct validators live here:
//!
//! * [`validate_type_name_grammar`] enforces only the §3.3 byte-level
//!   grammar. Every wire-format reader and writer in this crate routes
//!   through it. The grammar deliberately accepts unknown short native
//!   names so that a future FerroCrypt version can introduce a new
//!   native recipient type (e.g. `mlkem768`) without breaking
//!   forward-compatible parsing in older readers.
//! * [`validate_external_type_name`] enforces the §3.3.1 plugin
//!   namespace policy on top of the grammar: the name MUST contain `/`
//!   and MUST NOT impersonate a reserved native shape. It is the entry
//!   point any future plugin / third-party recipient registration API
//!   MUST call before accepting a caller-supplied `type_name`.
//!
//! Native-name prefixes `mlkem`, `pq`, `hpke`, `tag`, `xwing`, `kem`
//! and any name ending in `tag` are reserved by the FerroCrypt
//! specification for future native recipient types.
//! [`is_reserved_native_name`] exposes that check as a building block.

use crate::CryptoError;
use crate::error::FormatDefect;

/// Maximum byte length of a recipient `type_name`
/// (`FORMAT.md` §3.3, `type_name_len:u16` constrained to `1..=255`).
pub(crate) const TYPE_NAME_MAX_LEN: usize = 255;

/// Native-name prefixes reserved by the FerroCrypt specification for
/// future FerroCrypt-defined recipient types (`FORMAT.md` §3.3.1).
const RESERVED_NATIVE_PREFIXES: &[&str] = &["mlkem", "pq", "hpke", "tag", "xwing", "kem"];

/// Native-name suffix reserved by the FerroCrypt specification for
/// future FerroCrypt-defined recipient types (`FORMAT.md` §3.3.1).
const RESERVED_NATIVE_SUFFIX: &str = "tag";

/// Validates a recipient `type_name` against the byte-level grammar in
/// `FORMAT.md` §3.3:
///
/// - 1..=255 bytes;
/// - lowercase ASCII;
/// - allowed characters: `a-z 0-9 . _ + - /`;
/// - no leading or trailing `.`, `_`, `+`, `-`, `/`;
/// - no `..` or `//`.
///
/// This validator is deliberately namespace-agnostic so that wire-format
/// readers can parse-and-skip future native short names. Callers that
/// accept third-party-supplied names MUST additionally route through
/// [`validate_external_type_name`].
///
/// On failure surfaces [`crate::error::FormatDefect::MalformedTypeName`].
pub(crate) fn validate_type_name_grammar(name: &str) -> Result<(), CryptoError> {
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

/// Returns `true` when `name` has the shape of a reserved native
/// recipient type (no `/`, plus a reserved native prefix or the
/// reserved `tag` suffix per `FORMAT.md` §3.3.1).
///
/// Performs no grammar validation — callers should treat the result as
/// meaningful only for grammar-accepted names. A qualified plugin name
/// such as `example.com/mlkem768` is not reserved: the reservation
/// applies to the FerroCrypt-owned no-`/` namespace only.
pub(crate) fn is_reserved_native_name(name: &str) -> bool {
    !name.contains('/')
        && (RESERVED_NATIVE_PREFIXES.iter().any(|p| name.starts_with(p))
            || name.ends_with(RESERVED_NATIVE_SUFFIX))
}

/// Validates a `type_name` supplied by a third-party / plugin caller
/// against the §3.3 grammar **and** the §3.3.1 namespace policy:
///
/// - it MUST contain `/` (no native-namespace squatting); and
/// - it MUST NOT impersonate a reserved FerroCrypt native shape (which
///   is structurally implied by the `/` requirement, but checked
///   explicitly so future spec changes that loosen the `/` rule cannot
///   silently re-open the reserved range).
///
/// On failure surfaces [`crate::error::FormatDefect::MalformedTypeName`].
///
/// This crate ships no public plugin / third-party recipient
/// registration surface in v1, so this validator currently has no
/// in-tree caller; it exists so the policy promised in `FORMAT.md`
/// §3.3.1 is enforceable the moment such a surface is added.
#[allow(dead_code)]
pub(crate) fn validate_external_type_name(name: &str) -> Result<(), CryptoError> {
    validate_type_name_grammar(name)?;
    if !name.contains('/') || is_reserved_native_name(name) {
        return Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipient::native::{argon2id, x25519};

    #[test]
    fn validate_type_name_grammar_accepts_canonical_natives() {
        validate_type_name_grammar(argon2id::TYPE_NAME).unwrap();
        validate_type_name_grammar(x25519::TYPE_NAME).unwrap();
    }

    #[test]
    fn validate_type_name_grammar_accepts_fqn_plugin_names() {
        validate_type_name_grammar("example.com/enigma").unwrap();
        validate_type_name_grammar("com.example/foo").unwrap();
        validate_type_name_grammar("a.b.c/d").unwrap();
    }

    #[test]
    fn validate_type_name_grammar_rejects_empty() {
        match validate_type_name_grammar("") {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for empty, got {other:?}"),
        }
    }

    #[test]
    fn validate_type_name_grammar_rejects_overlong() {
        let long = "a".repeat(256);
        match validate_type_name_grammar(&long) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for 256-byte name, got {other:?}"),
        }
    }

    #[test]
    fn validate_type_name_grammar_accepts_max_length() {
        let max = "a".repeat(255);
        validate_type_name_grammar(&max).unwrap();
    }

    #[test]
    fn validate_type_name_grammar_rejects_uppercase() {
        match validate_type_name_grammar("Argon2id") {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for uppercase, got {other:?}"),
        }
    }

    #[test]
    fn validate_type_name_grammar_rejects_invalid_characters() {
        for bad in &["foo bar", "foo!", "foo:bar", "foo*", "foo\nbar"] {
            match validate_type_name_grammar(bad) {
                Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
                other => panic!("expected MalformedTypeName for `{bad}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_type_name_grammar_rejects_edge_punctuation() {
        for bad in &[
            ".foo", "_foo", "+foo", "-foo", "/foo", "foo.", "foo_", "foo+", "foo-", "foo/",
        ] {
            match validate_type_name_grammar(bad) {
                Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
                other => panic!("expected MalformedTypeName for `{bad}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_type_name_grammar_rejects_consecutive_punctuation() {
        for bad in &["foo..bar", "foo//bar", "a.b..c", "a/b//c"] {
            match validate_type_name_grammar(bad) {
                Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
                other => panic!("expected MalformedTypeName for `{bad}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn is_reserved_native_name_covers_all_reserved_prefixes_and_tag_suffix() {
        for reserved in &[
            "mlkem", "mlkem768", "pq", "pqfoo", "hpke", "hpkex", "tag", "tagfoo", "xwing",
            "xwing256", "kem", "kem768", "footag", "mytag",
        ] {
            assert!(
                is_reserved_native_name(reserved),
                "expected `{reserved}` to be reserved"
            );
        }
        for not_reserved in &["argon2id", "x25519", "future", "ed25519"] {
            assert!(
                !is_reserved_native_name(not_reserved),
                "expected `{not_reserved}` to be unreserved"
            );
        }
        for qualified in &["example.com/mlkem768", "example.com/footag"] {
            assert!(
                !is_reserved_native_name(qualified),
                "qualified `{qualified}` MUST NOT be reserved"
            );
        }
    }

    #[test]
    fn external_type_name_rejects_unqualified_native_looking_names() {
        for bad in ["future", "mlkem768", "pqfoo", "xwing", "kem768", "mytag"] {
            assert!(validate_external_type_name(bad).is_err(), "{bad}");
        }
        assert!(validate_external_type_name("example.com/future").is_ok());
    }
}
