//! FCA path grammar — the single shared writer/reader validator.
//!
//! See `ferrocrypt-lib/FORMAT.md` §9.6 (path grammar) and §9.10
//! (writer obligations — same TLV / path canonicality on both sides).
//!
//! The writer/reader symmetry guarantee is satisfied by having a
//! single function — [`validate_fca_path`] — called from both encode
//! and decode paths. There is no separate writer-side and reader-side
//! validator to drift apart.

use std::path::{Component, Path};

use crate::CryptoError;

use super::limits::{ArchiveLimits, enforce_path_bytes_cap, enforce_path_depth_cap};

/// Bytes that cannot appear in any FCA path component on any platform
/// FerroCrypt targets. The Windows-reserved set per FORMAT.md §9.6; rejecting
/// these on every platform makes a valid FCA path representable
/// everywhere FerroCrypt runs.
const WINDOWS_RESERVED_CHARS: &[u8] = b"<>:\"|?*";

/// Validates an FCA archive path against the FORMAT.md §9.6 grammar.
/// Same function called by encode-side metadata-pass and decode-side
/// manifest-parse — the single shared implementation IS the writer /
/// reader symmetry guarantee.
///
/// Caller has already passed `limits` through
/// `ArchiveLimits::validate`; we don't re-run that check here.
pub fn validate_fca_path(path: &str, limits: ArchiveLimits) -> Result<(), CryptoError> {
    if path.is_empty() {
        return Err(CryptoError::InvalidInput(
            "Empty archive entry path".to_string(),
        ));
    }
    enforce_path_bytes_cap(
        u32::try_from(path.len()).unwrap_or(u32::MAX),
        Some(path),
        &limits,
    )?;
    let bytes = path.as_bytes();
    if bytes[0] == b'/' {
        return Err(CryptoError::InvalidInput(
            "Archive path is absolute".to_string(),
        ));
    }
    if bytes[bytes.len() - 1] == b'/' {
        return Err(CryptoError::InvalidInput(
            "Archive path has trailing slash".to_string(),
        ));
    }
    if bytes.contains(&0) {
        return Err(CryptoError::InvalidInput(
            "Archive path contains NUL byte".to_string(),
        ));
    }
    if bytes.contains(&b'\\') {
        return Err(CryptoError::InvalidInput(
            "Archive path contains backslash".to_string(),
        ));
    }
    if bytes.windows(2).any(|w| w == b"//") {
        return Err(CryptoError::InvalidInput(
            "Archive path contains repeated slash separators".to_string(),
        ));
    }

    enforce_path_depth_cap(path, &limits)?;

    for component in path.split('/') {
        validate_fca_component(component)?;
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
                return Err(CryptoError::InvalidInput(format!(
                    "Unsafe path in archive: {path}"
                )));
            }
        }
    }

    Ok(())
}

/// Validates a single `/`-delimited path component per FORMAT.md §9.6.
fn validate_fca_component(component: &str) -> Result<(), CryptoError> {
    if component.is_empty() || component == "." || component == ".." {
        return Err(CryptoError::InvalidInput(
            "Archive path has forbidden component".to_string(),
        ));
    }

    let b = component.as_bytes();
    if b.iter().any(|&c| c <= 0x1f) {
        return Err(CryptoError::InvalidInput(
            "Archive path contains ASCII control byte".to_string(),
        ));
    }
    if b.iter().any(|c| WINDOWS_RESERVED_CHARS.contains(c)) {
        return Err(CryptoError::InvalidInput(
            "Archive path contains a Windows-reserved character".to_string(),
        ));
    }
    if b.last() == Some(&b' ') {
        return Err(CryptoError::InvalidInput(
            "Archive path component ends with space".to_string(),
        ));
    }
    if b.last() == Some(&b'.') {
        return Err(CryptoError::InvalidInput(
            "Archive path component ends with dot".to_string(),
        ));
    }
    if is_windows_reserved_device_component(component) {
        return Err(CryptoError::InvalidInput(
            "Archive path contains a Windows-reserved device name".to_string(),
        ));
    }
    Ok(())
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
fn is_windows_reserved_device_component(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _)| stem);
    let stem_bytes = stem.as_bytes();

    // All reserved device-name stems are 3..=6 ASCII bytes; longer
    // stems cannot match. The early return also keeps the stack
    // buffer sizing exact.
    if stem_bytes.is_empty() || stem_bytes.len() > 6 {
        return false;
    }

    // Stack buffer avoids an allocation per component check on the
    // common no-match path. Reserved names are all ASCII, so byte-wise
    // ascii_lower_byte is the correct (and sufficient) case fold.
    let mut buf = [0u8; 6];
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
            | b"com1"
            | b"com2"
            | b"com3"
            | b"com4"
            | b"com5"
            | b"com6"
            | b"com7"
            | b"com8"
            | b"com9"
            | b"lpt1"
            | b"lpt2"
            | b"lpt3"
            | b"lpt4"
            | b"lpt5"
            | b"lpt6"
            | b"lpt7"
            | b"lpt8"
            | b"lpt9"
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

/// Counts the `/`-separated components of an FCA path. The path is
/// guaranteed by [`validate_fca_path`] to use single `/` separators
/// with no leading/trailing slash, so `split('/').count()` matches
/// the `max_path_depth` cap exactly. Shared by the writer's
/// canonical sort (`encode::sort_entries_canonically`) and the
/// reader's directory pre-creation pass (`decode::extract_directory_root`).
pub(super) fn component_count(path: &str) -> usize {
    path.split('/').count()
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
    /// 9 bytes — over the 6-byte fast-path cap, so it cannot match.
    #[test]
    fn accepts_long_stem_that_starts_with_reserved_prefix() {
        assert!(validate_fca_path("auxiliary.txt", limits()).is_ok());
        assert!(validate_fca_path("conditional.md", limits()).is_ok());
    }

    // -- Whole-path rejections (FORMAT.md §9.6) ----------------------------

    #[test]
    fn rejects_empty() {
        let err = validate_fca_path("", limits()).unwrap_err();
        assert!(format!("{err}").contains("Empty"));
    }

    #[test]
    fn rejects_leading_slash() {
        let err = validate_fca_path("/etc/passwd", limits()).unwrap_err();
        assert!(format!("{err}").contains("absolute"));
    }

    #[test]
    fn rejects_trailing_slash() {
        let err = validate_fca_path("dir/", limits()).unwrap_err();
        assert!(format!("{err}").contains("trailing slash"));
    }

    #[test]
    fn rejects_double_slash() {
        let err = validate_fca_path("a//b", limits()).unwrap_err();
        assert!(format!("{err}").contains("repeated slash"));
    }

    #[test]
    fn rejects_nul_byte() {
        let err = validate_fca_path("a\0b", limits()).unwrap_err();
        assert!(format!("{err}").contains("NUL byte"));
    }

    #[test]
    fn rejects_backslash() {
        let err = validate_fca_path("a\\b", limits()).unwrap_err();
        assert!(format!("{err}").contains("backslash"));
    }

    #[test]
    fn rejects_oversize_path() {
        let l = ArchiveLimits::default().with_max_path_bytes(10);
        let err = validate_fca_path("this_is_too_long.txt", l).unwrap_err();
        assert!(format!("{err}").contains("byte-length cap"));
    }

    #[test]
    fn rejects_oversize_depth() {
        let l = ArchiveLimits::default().with_max_path_depth(3);
        let err = validate_fca_path("a/b/c/d", l).unwrap_err();
        assert!(format!("{err}").contains("depth cap"));
    }

    /// Boundary check: depth exactly at cap is admissible, cap+1
    /// rejected. Same `>` vs `>=` regression guard as the limits
    /// helpers carry on the encode side.
    #[test]
    fn depth_at_cap_admissible() {
        let l = ArchiveLimits::default().with_max_path_depth(3);
        assert!(validate_fca_path("a/b/c", l).is_ok());
    }

    // -- Component rejections (§9.6) ---------------------------------------

    #[test]
    fn rejects_control_byte_tab() {
        let err = validate_fca_path("a\tb", limits()).unwrap_err();
        assert!(format!("{err}").contains("control byte"));
    }

    #[test]
    fn rejects_control_byte_low() {
        let err = validate_fca_path("a\x01b", limits()).unwrap_err();
        assert!(format!("{err}").contains("control byte"));
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
                format!("{err}").contains("Windows-reserved character"),
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
        assert!(format!("{err}").contains("Windows-reserved character"));
    }

    #[test]
    fn rejects_trailing_space_in_component() {
        let err = validate_fca_path("file ", limits()).unwrap_err();
        assert!(format!("{err}").contains("ends with space"));

        let err = validate_fca_path("dir /file", limits()).unwrap_err();
        assert!(format!("{err}").contains("ends with space"));
    }

    #[test]
    fn rejects_trailing_dot_in_component() {
        let err = validate_fca_path("file.", limits()).unwrap_err();
        assert!(format!("{err}").contains("ends with dot"));

        let err = validate_fca_path("dir./file", limits()).unwrap_err();
        assert!(format!("{err}").contains("ends with dot"));
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

    /// All 23 reserved device names from FORMAT.md §9.6 reject. Loop-over
    /// pin keeps the test honest against future spec changes that
    /// add or remove an entry.
    #[test]
    fn rejects_every_reserved_device_name() {
        let names = [
            "CON", "PRN", "AUX", "NUL", "CLOCK$", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
            "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
            "LPT9",
        ];
        for name in &names {
            let err = validate_fca_path(name, limits()).unwrap_err();
            assert!(
                format!("{err}").contains("Windows-reserved device"),
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
            "COM1.log",
            "LPT9.bin",
        ] {
            let err = validate_fca_path(stem, limits()).unwrap_err();
            assert!(
                format!("{err}").contains("Windows-reserved device"),
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
        for name in &["con", "Con", "CON", "cOn", "lpt9", "Lpt9", "LPT9"] {
            let err = validate_fca_path(name, limits()).unwrap_err();
            assert!(
                format!("{err}").contains("Windows-reserved device"),
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

    // -- Collision key (§9.7) ----------------------------------------------

    #[test]
    fn collision_key_lowercases_ascii() {
        assert_eq!(ascii_case_collision_key("Foo.TXT"), b"foo.txt");
        assert_eq!(ascii_case_collision_key("ABCdef"), b"abcdef");
        assert_eq!(ascii_case_collision_key(""), Vec::<u8>::new());
    }

    /// Multi-byte UTF-8 bytes pass through unchanged. The check is
    /// intentionally NOT Unicode-aware per FORMAT.md §9.7; filesystem-
    /// specific Unicode collisions fall through to `create_new(true)`
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

    // -- Pin-by-name coverage for platform-specific path attempts ---------

    /// Windows drive-letter paths reject by name. Currently transitive
    /// via the colon-rejection (`<>:"|?*`) and backslash rejection,
    /// but pinning by name keeps coverage explicit so a future split
    /// of the validators doesn't drop the case.
    #[test]
    fn rejects_windows_drive_path_with_backslash() {
        let err = validate_fca_path("C:\\x", limits()).unwrap_err();
        let s = format!("{err}");
        assert!(
            s.contains("backslash") || s.contains("Windows-reserved character"),
            "got: {s}",
        );
    }

    #[test]
    fn rejects_windows_drive_path_with_forward_slash() {
        // `C:/x` is an absolute path attempt without backslash. Hits
        // the `:` Windows-reserved-character rejection on the first
        // component.
        let err = validate_fca_path("C:/x", limits()).unwrap_err();
        assert!(format!("{err}").contains("Windows-reserved character"));
    }

    #[test]
    fn rejects_unc_path_attempt() {
        // `\\server\share` UNC attempt. Backslash rejection fires.
        let err = validate_fca_path("\\\\server\\share", limits()).unwrap_err();
        assert!(format!("{err}").contains("backslash"));
    }

    #[test]
    fn rejects_double_forward_slash_unc_like() {
        // `//server/share` — POSIX double-slash, would be UNC-equivalent
        // on Windows. Hits the leading-slash rejection.
        let err = validate_fca_path("//server/share", limits()).unwrap_err();
        assert!(format!("{err}").contains("absolute"));
    }

    /// Tar-rs `extracting_malicious_tarball` corpus (CVE-2001-1267
    /// et al. — see `tests/all.rs:768` in tar-rs). Tar's reaction is
    /// to silently strip leading slashes and skip `..` entries; FCA's
    /// posture is fail-closed — every entry MUST reject with a typed
    /// `CryptoError::InvalidInput`. Loop-pin against the full byte set
    /// so a future relaxation of the rejection is caught.
    ///
    /// See `notes/tar_rs_crosscheck.md` §5 for the cross-check finding.
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
            // Confirm it's a typed `InvalidInput`, not a panic or
            // unrelated error class.
            assert!(
                matches!(result.unwrap_err(), CryptoError::InvalidInput(_)),
                "tar-rs malicious path {path:?} must reject as InvalidInput",
            );
        }
    }
}
