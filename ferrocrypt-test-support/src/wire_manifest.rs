//! The manifest grammar of the frozen `testvectors/wire/` conformance corpus
//! (`FORMAT.md` §12.3): the seven tables and their columns, the field rules,
//! the strict table reader, the digest check behind every reference, and the
//! IDs of the limit profiles that both the generator and the replay name.
//!
//! The corpus generator and the crate-internal replays in the library crate,
//! and the public-API replay in `ferrocrypt-lib/tests/wire_corpus.rs`, all go
//! through this module, so the grammar one of them applies cannot drift from
//! another's.
//! `testvectors/wire/tools/verify_manifests.py` implements the same grammar
//! again on purpose: it is the check an outside implementer runs with no
//! FerroCrypt code involved, so it shares nothing with this module.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use ferrocrypt::{ArchiveLimits, HeaderReadLimits, KdfLimit, KeyReadLimits};
use sha3::{Digest, Sha3_256};

/// One manifest row, keyed by column name.
pub type Row = BTreeMap<String, String>;

/// The limit profile holding FerroCrypt's `0.3.0` default caps. A case names
/// it unless it needs a cap those defaults keep out of reach (`FORMAT.md`
/// §12.3).
pub const DEFAULT_LIMIT_PROFILE_ID: &str = "default-0.3.0";

/// The limit profile that sets every cap to exactly what the one-byte
/// passphrase `.fcr` the mutation cases start from and the corpus key pair
/// need. Each of them sits exactly on every cap it meets, and between them
/// they meet every cap of the profile above zero.
pub const SMALL_ARTIFACT_LIMIT_PROFILE_ID: &str = "small-artifact-caps";

/// The seven manifest tables of `FORMAT.md` §12.3 and the exact columns each
/// declares, in order.
pub const MANIFEST_TABLES: &[(&str, &[&str])] = &[
    (
        "baselines.tsv",
        &[
            "baseline_id",
            "established_by_release",
            "parent_baseline_id",
            "introduced_in_corpus_revision",
        ],
    ),
    (
        "diagnostic-classes.tsv",
        &[
            "class_id",
            "description_ref",
            "description_sha3_256",
            "introduced_in_corpus_revision",
        ],
    ),
    (
        "credentials.tsv",
        &[
            "credential_id",
            "kind",
            "primary_ref",
            "primary_sha3_256",
            "secret_ref",
            "secret_sha3_256",
            "introduced_in_release",
            "introduced_in_corpus_revision",
        ],
    ),
    (
        "limit-profiles.tsv",
        &[
            "limit_profile_id",
            "max_header_len",
            "max_recipient_count",
            "max_recipient_body_len",
            "max_header_mac_work_bytes",
            "max_kdf_mem_kib",
            "max_kdf_time",
            "max_kdf_lanes",
            "max_kdf_work",
            "max_recipient_string_chars",
            "max_private_key_wrapped_secret_len",
            "max_entry_count",
            "max_total_plaintext_bytes",
            "max_path_depth",
            "max_path_bytes",
            "max_manifest_bytes",
            "max_archive_ext_bytes",
            "max_entry_ext_bytes",
            "max_total_entry_ext_bytes",
            "max_tlv_value_bytes",
            "introduced_in_corpus_revision",
        ],
    ),
    (
        "origins.tsv",
        &[
            "origin_id",
            "origin_kind",
            "anchor_case_id",
            "payload_key_ref",
            "payload_key_sha3_256",
            "stream_nonce_hex",
            "introduced_in_release",
            "introduced_in_corpus_revision",
        ],
    ),
    (
        "cases.tsv",
        &[
            "case_id",
            "case_type",
            "artifact_ref",
            "artifact_sha3_256",
            "first_required_by_baseline",
            "introduced_in_release",
            "introduced_in_corpus_revision",
            "construction",
            "parent_case_id",
            "payload_transcript_kind",
            "payload_origin_ids",
            "credential_id",
            "limit_profile_id",
            "outcome",
            "expectation_scope",
            "capability_id",
            "condition_id",
            "diagnostic_class",
            "expected_ref",
            "expected_sha3_256",
        ],
    ),
    (
        "errata.tsv",
        &[
            "erratum_id",
            "affected_case_id",
            "effective_corpus_revision",
            "rationale_ref",
            "rationale_sha3_256",
            "replacement_case_id",
            "introduced_in_release",
        ],
    ),
];

/// The columns manifest table `name` declares.
///
/// # Panics
///
/// If `name` is not one of the seven §12.3 tables.
pub fn table_columns(name: &str) -> &'static [&'static str] {
    MANIFEST_TABLES
        .iter()
        .find(|(table, _)| *table == name)
        .map(|(_, columns)| *columns)
        .unwrap_or_else(|| panic!("{name} is not a §12.3 manifest table"))
}

/// The columns holding a baseline, class, credential, limit-profile, origin,
/// case, erratum, or condition ID, and whether each may hold `-`. Capability
/// IDs follow the structured forms of `FORMAT.md` §12.2 instead.
pub const ID_COLUMNS: &[(&str, &[(&str, bool)])] = &[
    (
        "baselines.tsv",
        &[("baseline_id", false), ("parent_baseline_id", true)],
    ),
    ("diagnostic-classes.tsv", &[("class_id", false)]),
    ("credentials.tsv", &[("credential_id", false)]),
    ("limit-profiles.tsv", &[("limit_profile_id", false)]),
    (
        "origins.tsv",
        &[("origin_id", false), ("anchor_case_id", false)],
    ),
    (
        "cases.tsv",
        &[
            ("case_id", false),
            ("first_required_by_baseline", false),
            ("parent_case_id", true),
            ("credential_id", true),
            ("limit_profile_id", true),
            ("condition_id", true),
            ("diagnostic_class", true),
        ],
    ),
    (
        "errata.tsv",
        &[
            ("erratum_id", false),
            ("affected_case_id", false),
            ("replacement_case_id", true),
        ],
    ),
];

/// Every `*_ref` column and the `*_sha3_256` column beside it, for the tables
/// that carry them. `origins.tsv` is absent: its `payload_key_sha3_256` is a
/// commitment to key material that §12.3 defines apart from any file, so a
/// `payload_key_ref` is checked against it only where one is named.
pub const DIGEST_PAIRS: &[(&str, &[(&str, &str)])] = &[
    (
        "diagnostic-classes.tsv",
        &[("description_ref", "description_sha3_256")],
    ),
    (
        "credentials.tsv",
        &[
            ("primary_ref", "primary_sha3_256"),
            ("secret_ref", "secret_sha3_256"),
        ],
    ),
    (
        "cases.tsv",
        &[
            ("artifact_ref", "artifact_sha3_256"),
            ("expected_ref", "expected_sha3_256"),
        ],
    ),
    ("errata.tsv", &[("rationale_ref", "rationale_sha3_256")]),
];

/// The structural maximum of every profiled quantity the format bounds
/// (`FORMAT.md` §2.2, §3.1 to §3.3, §7, §8, §9.12). A limit profile may not
/// set a cap above it, because a reader cannot apply a larger value.
pub const LIMIT_STRUCTURAL_MAXIMA: &[(&str, u64)] = &[
    (
        "max_header_len",
        HeaderReadLimits::HEADER_LEN_STRUCTURAL_MAX as u64,
    ),
    (
        "max_recipient_count",
        HeaderReadLimits::RECIPIENT_COUNT_STRUCTURAL_MAX as u64,
    ),
    (
        "max_recipient_body_len",
        HeaderReadLimits::RECIPIENT_BODY_LEN_STRUCTURAL_MAX as u64,
    ),
    (
        "max_header_mac_work_bytes",
        HeaderReadLimits::HEADER_MAC_WORK_BYTES_STRUCTURAL_MAX,
    ),
    (
        "max_kdf_mem_kib",
        KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX as u64,
    ),
    ("max_kdf_time", KdfLimit::TIME_COST_STRUCTURAL_MAX as u64),
    ("max_kdf_lanes", KdfLimit::LANES_STRUCTURAL_MAX as u64),
    ("max_kdf_work", KdfLimit::WORK_STRUCTURAL_MAX),
    (
        "max_recipient_string_chars",
        KeyReadLimits::RECIPIENT_STRING_CHARS_STRUCTURAL_MAX as u64,
    ),
    (
        "max_private_key_wrapped_secret_len",
        KeyReadLimits::PRIVATE_KEY_WRAPPED_SECRET_LEN_STRUCTURAL_MAX as u64,
    ),
    (
        "max_path_bytes",
        ArchiveLimits::PATH_BYTES_STRUCTURAL_MAX as u64,
    ),
];

/// The first `FORMAT.md` §12.3 field rule `value` breaks in `column` of
/// `table`, or `None`: the rules every field shares, then the identifier,
/// limit, reference, digest, list, and capability forms its column carries.
/// `-` stands for an inapplicable value, which an identifier column admits
/// only where it is optional.
pub fn field_violation(table: &str, column: &str, value: &str) -> Option<&'static str> {
    if value.is_empty() {
        return Some("empty field");
    }
    if value.contains("..") || value.contains('\\') || value.starts_with('/') {
        return Some("contains '..', a backslash, or an absolute path");
    }
    let id_column = ID_COLUMNS
        .iter()
        .find(|(name, _)| *name == table)
        .and_then(|(_, columns)| columns.iter().find(|(name, _)| *name == column));
    if let Some((_, optional)) = id_column {
        let valid = if value == "-" {
            *optional
        } else {
            is_manifest_id(value)
        };
        if !valid {
            return Some("breaks the identifier grammar");
        }
    }
    if table == "limit-profiles.tsv" && column.starts_with("max_") {
        return limit_value_violation(column, value);
    }
    if value == "-" {
        return None;
    }
    if column.ends_with("_ref") && !is_corpus_reference(value) {
        return Some("not a corpus reference");
    }
    if column.ends_with("_sha3_256") && !(value.len() == 64 && is_lower_hex(value)) {
        return Some("not a digest of 64 lowercase hexadecimal characters");
    }
    if column == "payload_origin_ids" {
        let listed: Vec<&str> = value.split(',').collect();
        if !listed.iter().all(|id| is_manifest_id(id)) {
            return Some("breaks the list form");
        }
        if listed.iter().collect::<BTreeSet<_>>().len() != listed.len() {
            return Some("repeats an origin");
        }
    }
    if column == "capability_id" && !is_capability_id(value) {
        return Some("breaks the capability form");
    }
    None
}

/// The rule a `limit-profiles.tsv` value breaks, if any: it is a decimal
/// integer with no leading zero that fits 64 bits, and at most the structural
/// maximum [`LIMIT_STRUCTURAL_MAXIMA`] records for its column.
fn limit_value_violation(column: &str, value: &str) -> Option<&'static str> {
    let canonical =
        value == "0" || (!value.starts_with('0') && value.chars().all(|c| c.is_ascii_digit()));
    let Some(limit) = canonical.then(|| value.parse::<u64>().ok()).flatten() else {
        return Some("not a decimal limit that fits 64 bits");
    };
    let structural_max = LIMIT_STRUCTURAL_MAXIMA
        .iter()
        .find(|(name, _)| *name == column)
        .map(|(_, max)| *max);
    if structural_max.is_some_and(|max| limit > max) {
        return Some("above the structural maximum of the quantity it bounds");
    }
    None
}

/// Whether `value` matches `[a-z0-9][a-z0-9._-]*`, the §12.3 identifier
/// grammar.
pub fn is_manifest_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// Whether `value` is a path relative to the corpus root whose components each
/// match the identifier grammar (`FORMAT.md` §12.3). That rules out absolute
/// paths, drive and UNC prefixes, backslashes, and empty, `.`, or `..`
/// components, so joining a reference onto the root can only name a file
/// inside it.
pub fn is_corpus_reference(value: &str) -> bool {
    value.split('/').all(is_manifest_id)
}

/// Whether `value` has one of the capability-ID forms of `FORMAT.md` §12.2: a
/// stored version domain with two uppercase hexadecimal digits other than the
/// reserved `0x00`, a TLV namespace with four, or a recipient or key type with
/// its name.
pub fn is_capability_id(value: &str) -> bool {
    let Some((domain, subject)) = value.split_once(':') else {
        return false;
    };
    let hex_digits = |digits: usize| {
        subject.strip_prefix("0x").is_some_and(|hex| {
            hex.len() == digits
                && hex
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, 'A'..='F'))
        })
    };
    match domain {
        "outer_version" | "fca_version" | "public_key_version" | "private_key_version" => {
            hex_digits(2) && subject != "0x00"
        }
        "outer_tlv" | "private_key_tlv" | "fca_archive_tlv" | "fca_entry_tlv" => hex_digits(4),
        "recipient_type" | "key_type" => !subject.is_empty(),
        _ => false,
    }
}

/// Whether every character of `value` is a digit or a lowercase `a` to `f`.
pub fn is_lower_hex(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
}

/// SHA3-256 of `bytes` as 64 lowercase hexadecimal characters, the form every
/// corpus digest column holds.
pub fn sha3_hex(bytes: &[u8]) -> String {
    Sha3_256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Parses manifest table `name` under `root` strictly, with the columns
/// `FORMAT.md` §12.3 declares for it; see [`read_table_with_columns`].
///
/// # Panics
///
/// If `name` is not a §12.3 table, or on any violation
/// [`read_table_with_columns`] refuses.
pub fn read_table(root: &Path, name: &str) -> Vec<Row> {
    read_table_with_columns(root, name, table_columns(name))
}

/// Parses a manifest table strictly into column-keyed rows. The file must use
/// LF line endings, its first comment line must name exactly `columns`, every
/// row must have one field per column, and no field may break a rule
/// [`field_violation`] checks, so a reference is validated when its table is
/// read, before anything can read the file it names.
///
/// The match on `columns` is exact, so once a later `SCHEMA-VERSION` changes
/// a table's columns, a reader of the frozen table passes the columns it was
/// published with.
///
/// # Panics
///
/// On an unreadable file or any violation above; this is test tooling, and a
/// malformed corpus is a failure.
pub fn read_table_with_columns(root: &Path, name: &str, columns: &[&str]) -> Vec<Row> {
    let text = fs::read_to_string(root.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
    assert!(!text.contains('\r'), "{name} must use LF line endings");
    let mut header_seen = false;
    let mut rows = Vec::new();
    for line in text.lines() {
        if let Some(header) = line.strip_prefix('#') {
            if !header_seen {
                let declared: Vec<&str> = header.trim().split('\t').collect();
                assert_eq!(
                    declared, columns,
                    "{name}: columns differ from those expected"
                );
                header_seen = true;
            }
            continue;
        }
        assert!(header_seen, "{name}: rows precede the column header");
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), columns.len(), "{name}: row width");
        for (column, value) in columns.iter().zip(&fields) {
            if let Some(violation) = field_violation(name, column, value) {
                panic!("{name}: {column} {value:?}: {violation}");
            }
        }
        rows.push(
            columns
                .iter()
                .map(|column| column.to_string())
                .zip(fields.iter().map(|value| value.to_string()))
                .collect(),
        );
    }
    assert!(header_seen, "{name}: no column header");
    rows
}

/// Reads the file `row[ref_column]` names under `root` and requires the digest
/// committed in `digest_column`, so a caller relies on no byte the manifests
/// do not commit. The reference was validated when its table was read.
///
/// # Panics
///
/// If either column is absent, the reference is `-`, the file cannot be read,
/// or its digest differs.
pub fn read_committed(root: &Path, row: &Row, ref_column: &str, digest_column: &str) -> Vec<u8> {
    let column = |name: &str| {
        row.get(name)
            .unwrap_or_else(|| panic!("the row has no {name} column"))
    };
    let reference = column(ref_column);
    assert_ne!(reference, "-", "{ref_column} names no file");
    let bytes = fs::read(root.join(reference)).unwrap_or_else(|e| panic!("read {reference}: {e}"));
    assert_eq!(
        &sha3_hex(&bytes),
        column(digest_column),
        "{reference} does not match its committed digest"
    );
    bytes
}

/// Whether a corpus-relative path belongs to the corpus's own structure,
/// which no manifest row names: a manifest table, the two version files, the
/// README, or anything under `tools/`. Matching `tools/` by prefix means
/// adding a tool needs no edit here nor in the Python checker, which applies
/// the same rule.
pub fn is_structural_corpus_file(relative: &str) -> bool {
    MANIFEST_TABLES.iter().any(|(table, _)| *table == relative)
        || matches!(relative, "SCHEMA-VERSION" | "CORPUS-REVISION" | "README.md")
        || relative.starts_with("tools/")
}

/// Every file under `root`, recursively.
///
/// # Panics
///
/// If a directory or one of its entries cannot be read.
pub fn corpus_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read corpus directory") {
            let path = entry.expect("read corpus entry").path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every reference column, `origins.tsv`'s `payload_key_ref` included,
    /// admits a corpus path and refuses every form that could name a file
    /// outside the corpus, or a different file on another platform, before
    /// anything reads it (`FORMAT.md` §12.3).
    #[test]
    fn every_reference_column_refuses_paths_outside_the_corpus() {
        let refused = [
            "/etc/passwd",
            "../outside",
            "a/../b",
            "a/./b",
            "./a",
            "a//b",
            "a/",
            "C:/outside",
            "C:outside",
            "a\\b",
            "\\\\server\\share",
            "Artifacts/a",
            "a/b c",
        ];
        let mut checked = 0;
        for (table, columns) in MANIFEST_TABLES {
            for column in columns.iter().filter(|column| column.ends_with("_ref")) {
                assert_eq!(
                    field_violation(table, column, "artifacts/fcr/case-1.fcr"),
                    None
                );
                for reference in refused {
                    assert!(
                        field_violation(table, column, reference).is_some(),
                        "{table}: {column} admits {reference:?}"
                    );
                }
                checked += 1;
            }
        }
        assert_eq!(checked, 7, "every reference column of the seven tables");
    }

    /// Every reference column is paired with its digest column, except the
    /// payload key an origin commits to, whose digest §12.3 defines apart from
    /// any file. A reference left out of [`DIGEST_PAIRS`] would name a file no
    /// digest check reads.
    #[test]
    fn every_reference_column_is_paired_with_its_digest() {
        for (table, columns) in MANIFEST_TABLES {
            let pairs = DIGEST_PAIRS
                .iter()
                .find(|(name, _)| name == table)
                .map_or(&[][..], |(_, pairs)| *pairs);
            for column in columns.iter().filter(|column| column.ends_with("_ref")) {
                if *column == "payload_key_ref" {
                    continue;
                }
                let digest = column.replace("_ref", "_sha3_256");
                assert!(
                    pairs.iter().any(|(r, d)| r == column && *d == digest),
                    "{table}: {column} is not paired with {digest}"
                );
            }
            for (reference, digest) in pairs {
                assert!(
                    columns.contains(reference) && columns.contains(digest),
                    "{table}: a digest pair names a column the table lacks"
                );
            }
        }
    }

    /// Every identifier column enforces the identifier grammar, and a required
    /// one refuses `-` (`FORMAT.md` §12.3). Each column named here exists in
    /// its table, so a renamed column cannot silently drop out of the check.
    #[test]
    fn every_identifier_column_enforces_the_identifier_grammar() {
        for (table, columns) in ID_COLUMNS {
            let declared = table_columns(table);
            for (column, optional) in *columns {
                assert!(declared.contains(column), "{table} has no {column} column");
                assert_eq!(field_violation(table, column, "valid.id_1-2"), None);
                for invalid in ["Upper", "-leading", ".leading", "with space", "a,b"] {
                    assert!(
                        field_violation(table, column, invalid).is_some(),
                        "{table}: {column} admits {invalid:?}"
                    );
                }
                assert_eq!(
                    field_violation(table, column, "-").is_none(),
                    *optional,
                    "{table}: {column} decides '-' by whether the column is optional"
                );
            }
        }
    }

    /// Every limit column holds a decimal value a reader can apply as stated:
    /// no sign, leading zero, or `-`, nothing beyond 64 bits, and nothing above
    /// the structural maximum of the quantity it bounds, which a reader would
    /// clamp (`FORMAT.md` §12.3).
    #[test]
    fn every_limit_column_holds_a_value_a_reader_can_apply() {
        let profile_columns = table_columns("limit-profiles.tsv");
        let limit =
            |column: &str, value: &str| field_violation("limit-profiles.tsv", column, value);
        for column in profile_columns.iter().filter(|c| c.starts_with("max_")) {
            assert_eq!(limit(column, "0"), None, "{column}");
            for invalid in ["-", "01", "+1", "1.0", "0x10", "18446744073709551616"] {
                assert!(
                    limit(column, invalid).is_some(),
                    "{column} admits {invalid:?}"
                );
            }
        }
        for (column, max) in LIMIT_STRUCTURAL_MAXIMA {
            assert!(profile_columns.contains(column), "no {column} column");
            assert_eq!(limit(column, &max.to_string()), None, "{column}");
            assert!(
                limit(column, &(max + 1).to_string()).is_some(),
                "{column} admits a value above its structural maximum"
            );
        }
    }

    /// The origin list and the capability column hold the forms `FORMAT.md`
    /// §12.2 and §12.3 define, and nothing else.
    #[test]
    fn list_and_capability_columns_hold_their_forms() {
        let list = |value| field_violation("cases.tsv", "payload_origin_ids", value);
        assert_eq!(list("origin-a,origin-b"), None);
        for invalid in [
            "origin-a,",
            ",origin-a",
            "origin-a, origin-b",
            "origin-a,origin-a",
        ] {
            assert!(
                list(invalid).is_some(),
                "the origin list admits {invalid:?}"
            );
        }

        let capability = |value| field_violation("cases.tsv", "capability_id", value);
        for valid in [
            "outer_version:0x02",
            "private_key_version:0xFF",
            "fca_entry_tlv:0x8001",
            "recipient_type:test/unknown",
            "key_type:test/unknown",
        ] {
            assert_eq!(capability(valid), None, "{valid:?}");
        }
        for invalid in [
            "outer_version:0x00",
            "outer_version:0x2",
            "outer_version:0x0a",
            "outer_tlv:0x001",
            "fca_version:02",
            "recipient_type:",
            "unknown_domain:0x01",
            "outer_version",
        ] {
            assert!(
                capability(invalid).is_some(),
                "the capability column admits {invalid:?}"
            );
        }
    }

    /// A table whose header names other columns than the reader expects is a
    /// different schema, refused before any of its rows is read.
    #[test]
    #[should_panic(expected = "columns differ from those expected")]
    fn a_table_with_other_columns_is_refused() {
        let dir = tempfile::tempdir().expect("table dir");
        let mut header = table_columns("baselines.tsv").join("\t");
        header.push_str("\textra");
        fs::write(dir.path().join("baselines.tsv"), format!("# {header}\n")).expect("write table");
        read_table(dir.path(), "baselines.tsv");
    }

    /// A reference that could name a file outside the corpus is refused while
    /// its table is read, before any caller can join it onto the root.
    #[test]
    #[should_panic(expected = "not a corpus reference")]
    fn a_reference_outside_the_corpus_is_refused_when_its_table_is_read() {
        let dir = tempfile::tempdir().expect("table dir");
        fs::write(
            dir.path().join("t.tsv"),
            "# case_id\tartifact_ref\nescape\tC:/outside\n",
        )
        .expect("write table");
        read_table_with_columns(dir.path(), "t.tsv", &["case_id", "artifact_ref"]);
    }
}
