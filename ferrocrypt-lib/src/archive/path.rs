//! FCA path grammar — the single shared writer/reader validator.
//!
//! See `ferrocrypt-lib/FORMAT.md` §9.6 (path grammar) and §9.10
//! (writer obligations — same TLV / path canonicality on both sides).
//!
//! The writer/reader symmetry guarantee is satisfied by having a
//! single function — [`validate_fca_path`] — called from both encode
//! and decode paths. There is no separate writer-side and reader-side
//! validator to drift apart.

use std::ops::RangeInclusive;
use std::path::{Component, Path};

use unicode_normalization::{IsNormalized, UnicodeNormalization, is_nfc_quick};

use crate::CryptoError;
use crate::error::sanitize_for_display;
use crate::fs::paths::INCOMPLETE_SUFFIX;

use super::limits::{
    ArchiveLimits, component_count, enforce_path_bytes_cap, enforce_path_depth_cap,
};
use super::reasons::{
    COMPONENT_CONTROL_BYTE, COMPONENT_ENDS_WITH_DOT, COMPONENT_ENDS_WITH_SPACE,
    COMPONENT_FORBIDDEN, COMPONENT_FORMAT_CONTROL, COMPONENT_RESERVED_CHARACTER,
    COMPONENT_RESERVED_DEVICE_NAME, COMPONENT_TOO_LONG, ENTRY_PATH_EMPTY, PATH_ABSOLUTE,
    PATH_CONTAINS_BACKSLASH, PATH_CONTAINS_NUL, PATH_NON_NORMAL_COMPONENT, PATH_REPEATED_SLASHES,
    PATH_TRAILING_SLASH,
};

/// Bytes that cannot appear in any FCA path component on any platform
/// FerroCrypt targets. The Windows-reserved set per FORMAT.md §9.6; rejecting
/// these on every platform makes a valid FCA path representable
/// everywhere FerroCrypt runs.
const WINDOWS_RESERVED_CHARS: &[u8] = b"<>:\"|?*";

/// The 255-byte filename limit shared by the filesystems FerroCrypt
/// targets (ext4, XFS, APFS, NTFS).
const FILESYSTEM_NAME_MAX_BYTES: usize = 255;

/// Maximum UTF-8 byte length of a single FCA path component per
/// FORMAT.md §9.6: the filesystem name limit minus room for the
/// `.incomplete` staging suffix extraction appends to the root
/// component (§9.11 step 10). Without the reserve, a near-limit root
/// name would archive fine and then fail to extract because its
/// working name exceeds what the filesystem can create.
///
/// The over-long-component rejection reason embeds this number; it lives in
/// `super::reasons`, and a unit test below pins the two together.
pub const FCA_COMPONENT_MAX_BYTES: usize = FILESYSTEM_NAME_MAX_BYTES - INCOMPLETE_SUFFIX.len();

/// Validates an FCA archive path against the FORMAT.md §9.6 grammar.
/// Same function called by encode-side metadata-pass and decode-side
/// manifest-parse — the single shared implementation IS the writer /
/// reader symmetry guarantee.
pub fn validate_fca_path(path: &str, limits: ArchiveLimits) -> Result<(), CryptoError> {
    if path.is_empty() {
        return Err(CryptoError::MalformedArchive {
            reason: ENTRY_PATH_EMPTY,
        });
    }
    enforce_path_bytes_cap(
        u32::try_from(path.len()).unwrap_or(u32::MAX),
        Some(path),
        &limits,
    )?;
    let bytes = path.as_bytes();
    if bytes[0] == b'/' {
        return Err(unsafe_path(path, PATH_ABSOLUTE));
    }
    if bytes[bytes.len() - 1] == b'/' {
        return Err(unsafe_path(path, PATH_TRAILING_SLASH));
    }
    if bytes.contains(&0) {
        return Err(unsafe_path(path, PATH_CONTAINS_NUL));
    }
    if bytes.contains(&b'\\') {
        return Err(unsafe_path(path, PATH_CONTAINS_BACKSLASH));
    }
    if bytes.windows(2).any(|w| w == b"//") {
        return Err(unsafe_path(path, PATH_REPEATED_SLASHES));
    }

    enforce_path_depth_cap(path, &limits)?;

    for component in path.split('/') {
        validate_fca_component(component, path)?;
    }

    // Defense-in-depth: walk the host `Path::components()` and reject
    // any kind that is not `Normal`. The `/`-split component checks
    // above already cover `.` and `..`, but a future host-`Path`
    // tweak (e.g., a Windows `Prefix` parsed from a path that snuck
    // past the byte-level checks) would still surface here.
    for component in Path::new(path).components() {
        match component {
            Component::Normal(_) => {}
            Component::RootDir
            | Component::Prefix(_)
            | Component::CurDir
            | Component::ParentDir => {
                return Err(unsafe_path(path, PATH_NON_NORMAL_COMPONENT));
            }
        }
    }

    Ok(())
}

/// Builds the [`CryptoError::UnsafeArchivePath`] rejection with the
/// offending path sanitized for display. Single construction point so
/// every grammar arm embeds the path the same way.
fn unsafe_path(path: &str, reason: &'static str) -> CryptoError {
    CryptoError::UnsafeArchivePath {
        path: sanitize_for_display(path),
        reason,
    }
}

/// Validates a single `/`-delimited path component per FORMAT.md §9.6.
/// `path` is the full entry path, threaded through for the rejection
/// payload only.
fn validate_fca_component(component: &str, path: &str) -> Result<(), CryptoError> {
    if component.is_empty() || component == "." || component == ".." {
        return Err(unsafe_path(path, COMPONENT_FORBIDDEN));
    }
    if component.len() > FCA_COMPONENT_MAX_BYTES {
        return Err(unsafe_path(path, COMPONENT_TOO_LONG));
    }

    let b = component.as_bytes();
    if b.iter().any(u8::is_ascii_control) {
        return Err(unsafe_path(path, COMPONENT_CONTROL_BYTE));
    }
    if component.chars().any(is_format_control) {
        return Err(unsafe_path(path, COMPONENT_FORMAT_CONTROL));
    }
    if b.iter().any(|c| WINDOWS_RESERVED_CHARS.contains(c)) {
        return Err(unsafe_path(path, COMPONENT_RESERVED_CHARACTER));
    }
    if b.last() == Some(&b' ') {
        return Err(unsafe_path(path, COMPONENT_ENDS_WITH_SPACE));
    }
    if b.last() == Some(&b'.') {
        return Err(unsafe_path(path, COMPONENT_ENDS_WITH_DOT));
    }
    if is_windows_reserved_device_component(component) {
        return Err(unsafe_path(path, COMPONENT_RESERVED_DEVICE_NAME));
    }
    Ok(())
}

/// The C1 control characters, which a terminal or log may act on.
/// FORMAT.md §9.6 excludes them from every component.
const C1_CONTROLS: RangeInclusive<char> = '\u{80}'..='\u{9f}';

/// The bidirectional embeddings, overrides, and their terminator
/// (LRE, RLE, PDF, LRO, RLO). An override reverses the displayed order
/// of the letters that follow it, which is the disguise that makes a
/// `.sh` name read as `.jpg`.
const BIDI_EMBEDDINGS_AND_OVERRIDES: RangeInclusive<char> = '\u{202A}'..='\u{202E}';

/// The bidirectional isolates and their terminator (LRI, RLI, FSI,
/// PDI), which set the direction of a whole span of text.
const BIDI_ISOLATES: RangeInclusive<char> = '\u{2066}'..='\u{2069}';

/// The Unicode line and paragraph separators, which a plain-text
/// consumer such as a terminal or a log breaks a line at.
const LINE_SEPARATORS: RangeInclusive<char> = '\u{2028}'..='\u{2029}';

/// Returns whether `c` is one of the non-ASCII code points FORMAT.md
/// §9.6 excludes from every component: the C1 controls, the nine
/// bidirectional span controls, and the two line separators. The ASCII
/// controls are caught by the byte check before this.
///
/// The three direction marks (U+061C, U+200E, U+200F) are accepted:
/// word processors insert them in mixed Hebrew or Arabic text, so
/// legitimate names carry them. They cannot reverse a letter sequence
/// as an override can; what they can still do — move punctuation or
/// digits across a right-to-left run — is left to the displays, which
/// escape them (`error::is_bidi_control` in error messages).
fn is_format_control(c: char) -> bool {
    C1_CONTROLS.contains(&c)
        || BIDI_EMBEDDINGS_AND_OVERRIDES.contains(&c)
        || BIDI_ISOLATES.contains(&c)
        || LINE_SEPARATORS.contains(&c)
}

/// ASCII-only lowercase. Multi-byte UTF-8 bytes (anything `>= 0x80`)
/// pass through unchanged, which is intentional per FORMAT.md §9.6: the
/// reserved-device check is ASCII-only, not Unicode-folded.
fn ascii_lower_byte(b: u8) -> u8 {
    if b.is_ascii_uppercase() { b + 32 } else { b }
}

/// Returns `true` if the component's pre-extension stem matches a
/// Windows reserved device name under ASCII-case-insensitive
/// comparison. The stem is the substring before the first `.`; if there
/// is no `.`, the whole component is the stem. This catches both bare
/// names (`CON`) and stems-with-extension (`CON.txt`, `LPT9.bin`).
///
/// The superscript forms (`COM¹`, `LPT²`, …) are matched on their
/// exact UTF-8 bytes: `¹ ² ³` have no ASCII case and pass through
/// [`ascii_lower_byte`] unchanged, so byte comparison is exact per
/// FORMAT.md §9.6.
fn is_windows_reserved_device_component(component: &str) -> bool {
    // Windows resolves a name to a device by taking the text before the
    // first `.` and then stripping trailing spaces, so `AUX .txt` is the
    // AUX device. Match that: cut at the first `.`, then drop trailing
    // spaces before comparing.
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _)| stem)
        .trim_end_matches(' ');
    let stem_bytes = stem.as_bytes();

    // All reserved device-name stems are 3..=7 bytes (`CONOUT$` is
    // the longest; the superscript forms are 5 bytes as UTF-8);
    // longer stems cannot match. The early return also keeps the
    // stack buffer sizing exact.
    if stem_bytes.is_empty() || stem_bytes.len() > 7 {
        return false;
    }

    // Stack buffer avoids an allocation per component check on the
    // common no-match path. ascii_lower_byte folds the ASCII letters
    // and leaves the superscript UTF-8 bytes unchanged.
    let mut buf = [0u8; 7];
    for (i, &b) in stem_bytes.iter().enumerate() {
        buf[i] = ascii_lower_byte(b);
    }
    let lower = &buf[..stem_bytes.len()];

    matches!(
        lower,
        b"con"
            | b"prn"
            | b"aux"
            | b"nul"
            | b"clock$"
            | b"conin$"
            | b"conout$"
            | b"com0"
            | b"com1"
            | b"com2"
            | b"com3"
            | b"com4"
            | b"com5"
            | b"com6"
            | b"com7"
            | b"com8"
            | b"com9"
            | b"com\xc2\xb9" // COM¹
            | b"com\xc2\xb2" // COM²
            | b"com\xc2\xb3" // COM³
            | b"lpt0"
            | b"lpt1"
            | b"lpt2"
            | b"lpt3"
            | b"lpt4"
            | b"lpt5"
            | b"lpt6"
            | b"lpt7"
            | b"lpt8"
            | b"lpt9"
            | b"lpt\xc2\xb9" // LPT¹
            | b"lpt\xc2\xb2" // LPT²
            | b"lpt\xc2\xb3" // LPT³
    )
}

/// ASCII-case-insensitive collision key per FORMAT.md §9.7. Maps `A..Z` to
/// `a..z`; everything else (digits, punctuation, multi-byte UTF-8)
/// passes through unchanged. Used by tree.rs to detect paths like
/// `Foo.txt` vs `FOO.TXT` that would collide on a case-insensitive
/// filesystem before the platform backend's `create_new(true)` check
/// could surface the conflict.
pub fn ascii_case_collision_key(path: &str) -> Vec<u8> {
    path.bytes().map(ascii_lower_byte).collect()
}

/// Unicode-form collision key per FORMAT.md §9.7: the
/// [`ascii_case_collision_key`] of the path's NFC form. Equates two
/// paths whose bytes differ only in canonical form (`é` precomposed vs
/// `e` plus a combining accent) — visually identical names that macOS
/// filesystems treat as one name. Used by tree.rs alongside the ASCII
/// key; non-ASCII letter case is intentionally NOT folded, so `É.txt`
/// and `é.txt` stay distinct entries. A path already in NFC — every
/// all-ASCII path included — skips the intermediate normalized copy.
pub fn unicode_form_collision_key(path: &str) -> Vec<u8> {
    match is_nfc_quick(path.chars()) {
        IsNormalized::Yes => ascii_case_collision_key(path),
        IsNormalized::No | IsNormalized::Maybe => {
            ascii_case_collision_key(&path.nfc().collect::<String>())
        }
    }
}

/// FORMAT.md §9.8 canonical sort key: depth ascending, then path
/// bytes ascending. Used by the writer's full-manifest sort and the
/// reader's directory pre-creation pass so the two sites cannot
/// drift on what "canonical order" means.
pub(super) fn canonical_path_order(a: &str, b: &str) -> std::cmp::Ordering {
    component_count(a)
        .cmp(&component_count(b))
        .then_with(|| a.cmp(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> ArchiveLimits {
        ArchiveLimits::default()
    }

    // -- Positive cases -----------------------------------------------------

    #[test]
    fn accepts_simple_file() {
        assert!(validate_fca_path("file.txt", limits()).is_ok());
    }

    #[test]
    fn accepts_nested_path() {
        assert!(validate_fca_path("dir/sub/file.txt", limits()).is_ok());
    }

    #[test]
    fn accepts_mixed_case() {
        assert!(validate_fca_path("Some/Mixed/Case.TXT", limits()).is_ok());
    }

    #[test]
    fn accepts_non_ascii() {
        assert!(validate_fca_path("naïve.txt", limits()).is_ok());
        assert!(validate_fca_path("résumé/notes.md", limits()).is_ok());
    }

    #[test]
    fn accepts_emoji() {
        assert!(validate_fca_path("🎉.txt", limits()).is_ok());
    }

    /// `.foo` (hidden file on Unix) has empty stem — empty stem is
    /// not a reserved device name, so accepted.
    #[test]
    fn accepts_dotfile() {
        assert!(validate_fca_path(".gitignore", limits()).is_ok());
        assert!(validate_fca_path(".env", limits()).is_ok());
    }

    /// `auxiliary.txt` shares a prefix with `aux` but the stem is
    /// 9 bytes — over the 7-byte stem cap (`CONOUT$`, the longest
    /// reserved stem, is 7 bytes), so it cannot match.
    #[test]
    fn accepts_long_stem_that_starts_with_reserved_prefix() {
        assert!(validate_fca_path("auxiliary.txt", limits()).is_ok());
        assert!(validate_fca_path("conditional.md", limits()).is_ok());
    }

    // -- Whole-path rejections (FORMAT.md §9.6) ----------------------------

    #[test]
    fn rejects_empty() {
        let err = validate_fca_path("", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::MalformedArchive {
                reason: ENTRY_PATH_EMPTY
            }
        ));
    }

    #[test]
    fn rejects_leading_slash() {
        let err = validate_fca_path("/etc/passwd", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "absolute",
                ..
            }
        ));
    }

    #[test]
    fn rejects_trailing_slash() {
        let err = validate_fca_path("dir/", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "trailing slash",
                ..
            }
        ));
    }

    #[test]
    fn rejects_double_slash() {
        let err = validate_fca_path("a//b", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "repeated slash separators",
                ..
            }
        ));
    }

    #[test]
    fn rejects_nul_byte() {
        let err = validate_fca_path("a\0b", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "contains NUL byte",
                ..
            }
        ));
    }

    #[test]
    fn rejects_backslash() {
        let err = validate_fca_path("a\\b", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "contains backslash",
                ..
            }
        ));
    }

    /// Rejection payloads carry the offending path sanitized: control
    /// bytes and direction-override characters render as escapes, so
    /// the error text cannot smuggle terminal sequences or visually
    /// reordered names.
    #[test]
    fn rejection_payload_is_sanitized() {
        let err = validate_fca_path("dir/\u{202e}gpj.\u{1b}txt", limits()).unwrap_err();
        match err {
            CryptoError::UnsafeArchivePath { path, .. } => {
                assert!(!path.contains('\u{202e}'), "raw bidi override: {path:?}");
                assert!(!path.contains('\u{1b}'), "raw ESC: {path:?}");
                assert!(path.contains("\\u{202e}"), "got: {path}");
                assert!(path.contains("\\u{1b}"), "got: {path}");
            }
            other => panic!("expected UnsafeArchivePath, got {other:?}"),
        }
    }

    #[test]
    fn rejects_oversize_path() {
        let l = ArchiveLimits::default().max_path_bytes(10);
        let err = validate_fca_path("this_is_too_long.txt", l).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::ArchivePathBytesCapExceeded { .. }
        ));
    }

    #[test]
    fn rejects_oversize_depth() {
        let l = ArchiveLimits::default().max_path_depth(3);
        let err = validate_fca_path("a/b/c/d", l).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::ArchivePathDepthCapExceeded { .. }
        ));
    }

    /// Boundary check: depth exactly at cap is admissible, cap+1
    /// rejected. Same `>` vs `>=` regression guard as the limits
    /// helpers carry on the encode side.
    #[test]
    fn depth_at_cap_admissible() {
        let l = ArchiveLimits::default().max_path_depth(3);
        assert!(validate_fca_path("a/b/c", l).is_ok());
    }

    // -- Component rejections (§9.6) ---------------------------------------

    #[test]
    fn rejects_control_byte_tab() {
        let err = validate_fca_path("a\tb", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "contains ASCII control byte",
                ..
            }
        ));
    }

    #[test]
    fn rejects_control_byte_low() {
        let err = validate_fca_path("a\x01b", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "contains ASCII control byte",
                ..
            }
        ));
    }

    /// DEL (`0x7F`) is the one ASCII control above the `0x1F` range.
    #[test]
    fn rejects_delete_as_ascii_control_byte() {
        let err = validate_fca_path("a\x7fb", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "contains ASCII control byte",
                ..
            }
        ));
    }

    /// Every C1 control (`U+0080..=U+009F`) rejects. Each is two bytes
    /// in UTF-8, both above `0x7F`, so a byte-level check cannot catch
    /// them; the loop pins the whole range rather than one sample.
    #[test]
    fn rejects_each_c1_control_character() {
        for code_point in 0x80..=0x9f_u32 {
            let c = char::from_u32(code_point).unwrap();
            let path = format!("a{c}b.txt");
            let err = validate_fca_path(&path, limits()).unwrap_err();
            assert!(
                matches!(
                    err,
                    CryptoError::UnsafeArchivePath {
                        reason: "contains a control, text-direction, or line-break character",
                        ..
                    }
                ),
                "U+{code_point:04X} should reject",
            );
        }
    }

    /// The bidirectional span controls and line separators FORMAT.md
    /// §9.6 lists, restated here code point by code point so the test
    /// pins the specification's set rather than whatever the classifier
    /// currently returns.
    #[test]
    fn rejects_each_bidi_span_control_and_line_separator() {
        const REJECTED: &[char] = &[
            '\u{2028}', '\u{2029}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
            '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ];
        for &c in REJECTED {
            let path = format!("holiday{c}gpj.sh");
            let err = validate_fca_path(&path, limits()).unwrap_err();
            assert!(
                matches!(
                    err,
                    CryptoError::UnsafeArchivePath {
                        reason: "contains a control, text-direction, or line-break character",
                        ..
                    }
                ),
                "U+{:04X} should reject",
                c as u32,
            );
        }
    }

    /// Right-to-left names carry their direction in the letters, so
    /// they need no span control and stay valid.
    #[test]
    fn accepts_right_to_left_names_without_span_controls() {
        assert!(validate_fca_path("مرحبا.txt", limits()).is_ok());
        assert!(validate_fca_path("שלום/קובץ.md", limits()).is_ok());
        assert!(validate_fca_path("mixed-עברית-latin.txt", limits()).is_ok());
    }

    /// The three direction marks FORMAT.md §9.6 accepts, restated code
    /// point by code point: the Arabic letter mark, the left-to-right
    /// mark, and the right-to-left mark, as a word processor leaves them
    /// in a mixed-direction name.
    #[test]
    fn accepts_each_bidi_direction_mark() {
        for c in ['\u{061C}', '\u{200E}', '\u{200F}'] {
            let path = format!("שלום{c}-report.txt");
            assert!(
                validate_fca_path(&path, limits()).is_ok(),
                "U+{:04X} should be accepted",
                c as u32,
            );
        }
    }

    /// The code points on either side of every rejected range stay
    /// valid, so the rejection is exactly the specified set.
    #[test]
    fn accepts_code_points_next_to_the_rejected_ranges() {
        for c in [
            '\u{00A0}', '\u{200D}', '\u{2027}', '\u{202F}', '\u{2065}', '\u{206A}',
        ] {
            let path = format!("a{c}b.txt");
            assert!(
                validate_fca_path(&path, limits()).is_ok(),
                "U+{:04X} should be accepted",
                c as u32,
            );
        }
    }

    /// Every byte in the spec's Windows-reserved set rejects when
    /// embedded in a component. Loop-over-set keeps the test honest
    /// against accidental drift from the spec literal.
    #[test]
    fn rejects_each_windows_reserved_char() {
        for &c in WINDOWS_RESERVED_CHARS {
            let path = format!("a{}b.txt", c as char);
            let err = validate_fca_path(&path, limits()).unwrap_err();
            assert!(
                matches!(
                    err,
                    CryptoError::UnsafeArchivePath {
                        reason: "contains a Windows-reserved character",
                        ..
                    }
                ),
                "char {:?} should reject",
                c as char,
            );
        }
    }

    /// `:` is in the reserved set — pin separately because it's the
    /// alternate-data-stream attack vector on NTFS, the most
    /// security-relevant case in this set.
    #[test]
    fn rejects_colon_for_alternate_data_stream() {
        let err = validate_fca_path("file:stream", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "contains a Windows-reserved character",
                ..
            }
        ));
    }

    #[test]
    fn rejects_trailing_space_in_component() {
        let err = validate_fca_path("file ", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "component ends with space",
                ..
            }
        ));

        let err = validate_fca_path("dir /file", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "component ends with space",
                ..
            }
        ));
    }

    #[test]
    fn rejects_trailing_dot_in_component() {
        let err = validate_fca_path("file.", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "component ends with dot",
                ..
            }
        ));

        let err = validate_fca_path("dir./file", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "component ends with dot",
                ..
            }
        ));
    }

    #[test]
    fn rejects_dot_components() {
        assert!(validate_fca_path(".", limits()).is_err());
        assert!(validate_fca_path("./file", limits()).is_err());
        assert!(validate_fca_path("a/./b", limits()).is_err());
    }

    #[test]
    fn rejects_double_dot_components() {
        assert!(validate_fca_path("..", limits()).is_err());
        assert!(validate_fca_path("../escape", limits()).is_err());
        assert!(validate_fca_path("a/..", limits()).is_err());
        assert!(validate_fca_path("a/../b", limits()).is_err());
    }

    // -- Reserved device names (§9.6) --------------------------------------

    /// All 33 reserved device names from FORMAT.md §9.6 reject. Loop-over
    /// pin keeps the test honest against future spec changes that
    /// add or remove an entry.
    #[test]
    fn rejects_every_reserved_device_name() {
        let names = [
            "CON",
            "PRN",
            "AUX",
            "NUL",
            "CLOCK$",
            "CONIN$",
            "CONOUT$",
            "COM0",
            "COM1",
            "COM2",
            "COM3",
            "COM4",
            "COM5",
            "COM6",
            "COM7",
            "COM8",
            "COM9",
            "COM\u{b9}",
            "COM\u{b2}",
            "COM\u{b3}",
            "LPT0",
            "LPT1",
            "LPT2",
            "LPT3",
            "LPT4",
            "LPT5",
            "LPT6",
            "LPT7",
            "LPT8",
            "LPT9",
            "LPT\u{b9}",
            "LPT\u{b2}",
            "LPT\u{b3}",
        ];
        assert_eq!(names.len(), 33);
        for name in &names {
            let err = validate_fca_path(name, limits()).unwrap_err();
            assert!(
                matches!(
                    err,
                    CryptoError::UnsafeArchivePath {
                        reason: "Windows-reserved device name",
                        ..
                    }
                ),
                "name {name} should reject",
            );
        }
    }

    /// Reserved-stem-with-extension form per FORMAT.md §9.6. The stem
    /// is checked before the first `.`, so `CON.txt` matches `con`
    /// and rejects.
    #[test]
    fn rejects_reserved_stems_with_extension() {
        for stem in &[
            "CON.txt",
            "PRN.bak",
            "AUX.bin",
            "NUL.log",
            "CLOCK$.dat",
            "CONIN$.txt",
            "CONOUT$.log",
            "COM0.dat",
            "COM1.log",
            "COM\u{b9}.txt",
            "LPT0.bak",
            "LPT9.bin",
            "LPT\u{b3}.log",
        ] {
            let err = validate_fca_path(stem, limits()).unwrap_err();
            assert!(
                matches!(
                    err,
                    CryptoError::UnsafeArchivePath {
                        reason: "Windows-reserved device name",
                        ..
                    }
                ),
                "stem {stem} should reject",
            );
        }
    }

    /// Spec §9.6: "ASCII-case-insensitive only". Same reserved name
    /// in any case combination rejects; locale-sensitive folding is
    /// explicitly NOT used (would be wrong for e.g. Turkish dotted
    /// `İ`/`ı`).
    #[test]
    fn reserved_check_is_ascii_case_insensitive() {
        for name in &[
            "con",
            "Con",
            "CON",
            "cOn",
            "lpt9",
            "Lpt9",
            "LPT9",
            "conin$",
            "CONIN$",
            "conout$",
            "ConOut$",
            "com\u{b9}",
            "Com\u{b9}",
            "lpt\u{b2}",
            "Lpt\u{b2}",
        ] {
            let err = validate_fca_path(name, limits()).unwrap_err();
            assert!(
                matches!(
                    err,
                    CryptoError::UnsafeArchivePath {
                        reason: "Windows-reserved device name",
                        ..
                    }
                ),
                "name {name} should reject",
            );
        }
    }

    /// `.foo` has empty stem (text before the first dot is empty),
    /// so it is NOT a reserved-device collision. Pin this to catch
    /// a future refactor that conflates "no dot" and "empty stem".
    #[test]
    fn empty_stem_is_not_reserved() {
        assert!(validate_fca_path(".foo", limits()).is_ok());
        assert!(!is_windows_reserved_device_component(".foo"));
    }

    /// Windows strips trailing spaces from a name's stem before
    /// resolving it to a device, so `AUX .txt` is the AUX device even
    /// though the stem is not byte-equal to `aux`. The whole-component
    /// trailing-space rule does not fire here (the component ends in
    /// `t`), so the device matcher must do the trimming itself.
    #[test]
    fn rejects_space_padded_reserved_stems() {
        for name in &[
            "aux .txt",
            "con  .log",
            "com1 .bin",
            "CONIN$ .dat",
            "lpt9   .x",
        ] {
            let err = validate_fca_path(name, limits()).unwrap_err();
            assert!(
                matches!(
                    err,
                    CryptoError::UnsafeArchivePath {
                        reason: "Windows-reserved device name",
                        ..
                    }
                ),
                "name {name:?} should reject as a reserved device",
            );
        }

        // A trailing space next to a non-reserved stem stays valid.
        assert!(validate_fca_path("notes .txt", limits()).is_ok());
    }

    // -- Component byte cap (§9.6) ------------------------------------------

    /// Boundary check: a component exactly at [`FCA_COMPONENT_MAX_BYTES`]
    /// is admissible, one byte over rejects. The cap leaves room for
    /// the `.incomplete` staging suffix next to the 255-byte filesystem
    /// name limit, so "encrypt succeeds, decrypt fails" cannot happen
    /// for a near-limit name.
    #[test]
    fn component_at_byte_cap_admissible_one_over_rejects() {
        let at_cap = "a".repeat(FCA_COMPONENT_MAX_BYTES);
        assert!(validate_fca_path(&at_cap, limits()).is_ok());

        let over_cap = "a".repeat(FCA_COMPONENT_MAX_BYTES + 1);
        let err = validate_fca_path(&over_cap, limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: COMPONENT_TOO_LONG,
                ..
            }
        ));
    }

    /// The component cap applies to every component, not only the
    /// root: an over-long component nested inside an otherwise valid
    /// path rejects even though the whole path is under the path-byte
    /// cap.
    #[test]
    fn rejects_over_long_nested_component() {
        let long = "b".repeat(FCA_COMPONENT_MAX_BYTES + 1);
        let path = format!("root/{long}/leaf.txt");
        let err = validate_fca_path(&path, limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: COMPONENT_TOO_LONG,
                ..
            }
        ));
    }

    /// The byte count embedded in the rejection text must equal the
    /// constant, and the constant must leave exactly the suffix room
    /// it promises. Locks the human-readable message and the derived
    /// value together so neither can drift alone.
    #[test]
    fn component_cap_reason_matches_constant() {
        assert_eq!(
            COMPONENT_TOO_LONG,
            format!("component exceeds {FCA_COMPONENT_MAX_BYTES} bytes"),
        );
        assert_eq!(
            FCA_COMPONENT_MAX_BYTES + INCOMPLETE_SUFFIX.len(),
            FILESYSTEM_NAME_MAX_BYTES,
        );
    }

    // -- Collision key (§9.7) ----------------------------------------------

    #[test]
    fn collision_key_lowercases_ascii() {
        assert_eq!(ascii_case_collision_key("Foo.TXT"), b"foo.txt");
        assert_eq!(ascii_case_collision_key("ABCdef"), b"abcdef");
        assert_eq!(ascii_case_collision_key(""), Vec::<u8>::new());
    }

    /// Multi-byte UTF-8 bytes pass through unchanged. This key is
    /// intentionally NOT Unicode-aware per FORMAT.md §9.7; canonical-
    /// form collisions belong to [`unicode_form_collision_key`], and
    /// anything neither key catches falls through to `create_new(true)`
    /// at extraction time.
    #[test]
    fn collision_key_passes_through_non_ascii() {
        let input = "naïve";
        assert_eq!(ascii_case_collision_key(input), input.as_bytes());

        // Capital N gets lowercased; ï (multi-byte) stays.
        let key = ascii_case_collision_key("Naïve");
        assert_eq!(key.first(), Some(&b'n'));
        assert_eq!(&key[1..], "aïve".as_bytes());
    }

    /// The two Unicode spellings of the same visible name — `é`
    /// precomposed vs `e` plus combining acute — map to one key, and
    /// ASCII case folds on top, so `Café` in either spelling collides
    /// with `café` in either spelling.
    #[test]
    fn unicode_form_key_equates_nfc_and_nfd() {
        let composed = "caf\u{e9}.txt";
        let decomposed = "cafe\u{301}.txt";
        assert_ne!(composed.as_bytes(), decomposed.as_bytes());
        assert_eq!(
            unicode_form_collision_key(composed),
            unicode_form_collision_key(decomposed),
        );
        assert_eq!(
            unicode_form_collision_key("Caf\u{e9}.txt"),
            unicode_form_collision_key(decomposed),
        );
    }

    /// On a path already in NFC — all-ASCII paths included — the
    /// Unicode-form key equals the plain ASCII key, so the two keys
    /// can only disagree when a combining sequence is present.
    #[test]
    fn unicode_form_key_matches_ascii_key_when_already_nfc() {
        for path in ["dir/File.TXT", "na\u{ef}ve.txt", "\u{1f389}.txt"] {
            assert_eq!(
                unicode_form_collision_key(path),
                ascii_case_collision_key(path),
            );
        }
    }

    /// Non-ASCII letter case is NOT folded: `É.txt` and `é.txt` are
    /// distinct keys per FORMAT.md §9.7, because case-fold tables vary
    /// by filesystem and a byte-distinct case pair stays visually
    /// distinguishable. Pins the deliberate scope of the rule.
    #[test]
    fn unicode_form_key_keeps_non_ascii_case_distinct() {
        assert_ne!(
            unicode_form_collision_key("\u{c9}cole.txt"),
            unicode_form_collision_key("\u{e9}cole.txt"),
        );
    }

    // -- Pin-by-name coverage for platform-specific path attempts ---------

    /// Windows drive-letter paths reject by name. Currently transitive
    /// via the colon-rejection (`<>:"|?*`) and backslash rejection,
    /// but pinning by name keeps coverage explicit so a future split
    /// of the validators doesn't drop the case.
    #[test]
    fn rejects_windows_drive_path_with_backslash() {
        let err = validate_fca_path("C:\\x", limits()).unwrap_err();
        assert!(
            matches!(err, CryptoError::UnsafeArchivePath { .. }),
            "got: {err}",
        );
    }

    #[test]
    fn rejects_windows_drive_path_with_forward_slash() {
        // `C:/x` is an absolute path attempt without backslash. Hits
        // the `:` Windows-reserved-character rejection on the first
        // component.
        let err = validate_fca_path("C:/x", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "contains a Windows-reserved character",
                ..
            }
        ));
    }

    #[test]
    fn rejects_unc_path_attempt() {
        // `\\server\share` UNC attempt. Backslash rejection fires.
        let err = validate_fca_path("\\\\server\\share", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "contains backslash",
                ..
            }
        ));
    }

    #[test]
    fn rejects_double_forward_slash_unc_like() {
        // `//server/share` — POSIX double-slash, would be UNC-equivalent
        // on Windows. Hits the leading-slash rejection.
        let err = validate_fca_path("//server/share", limits()).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::UnsafeArchivePath {
                reason: "absolute",
                ..
            }
        ));
    }

    /// Tar-rs `extracting_malicious_tarball` corpus (CVE-2001-1267
    /// et al. — see `tests/all.rs:768` in tar-rs). Tar's reaction is
    /// to silently strip leading slashes and skip `..` entries; FCA's
    /// posture is fail-closed — every entry must reject with a typed
    /// defect (`UnsafeArchivePath` or `MalformedArchive`). Loop-pin
    /// against the full byte set so a future relaxation of the
    /// rejection is caught.
    #[test]
    fn rejects_every_tar_rs_malicious_path() {
        let corpus: &[&str] = &[
            "/tmp/abs_evil.txt",
            "//tmp/abs_evil2.txt",
            "///tmp/abs_evil3.txt",
            "/./tmp/abs_evil4.txt",
            "//./tmp/abs_evil5.txt",
            "///./tmp/abs_evil6.txt",
            "/../tmp/rel_evil.txt",
            "../rel_evil2.txt",
            "./../rel_evil3.txt",
            "some/../../rel_evil4.txt",
            "",
            "././//./..",
            "..",
            "/////////..",
            "/////////",
        ];
        for path in corpus {
            let result = validate_fca_path(path, limits());
            assert!(
                result.is_err(),
                "tar-rs malicious path {path:?} MUST reject (FCA fails closed; tar silently strips)",
            );
            // Confirm it's the typed path/archive rejection, not a
            // panic or unrelated error class.
            assert!(
                matches!(
                    result.unwrap_err(),
                    CryptoError::UnsafeArchivePath { .. } | CryptoError::MalformedArchive { .. }
                ),
                "tar-rs malicious path {path:?} must reject as a typed archive defect",
            );
        }
    }
}
