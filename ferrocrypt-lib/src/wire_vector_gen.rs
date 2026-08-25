//! Generator for the frozen `testvectors/wire/` conformance corpus
//! (`FORMAT.md` §12.3).
//!
//! The corpus is the public, cross-language conformance contract: committed
//! artifact bytes, committed expected results, and manifest rows naming the
//! outcome each artifact must produce. It is distinct from the mutable
//! `testvectors/suite/` corpus, which is this codebase's own edge-case net and
//! records Rust variant names and English text that §12.1 keeps out of the
//! cross-language contract.
//!
//! Generation needs crate internals, because most rejected artifacts cannot be
//! produced through the public API: crafted recipient lists, extension bytes,
//! out-of-range KDF parameters, and payload streams that violate §5. The
//! generator therefore lives in the library crate as an ignored unit test.
//! Regenerate with:
//!
//! ```bash
//! cargo test --package ferrocrypt --lib wire_vector_gen \
//!     -- --ignored --test-threads=1
//! ```
//!
//! Generation runs under a fixed deterministic RNG seed ([`WIRE_SEED`]) via
//! [`crate::crypto::keys::with_deterministic_rng`], so regenerating without
//! changing the generator produces byte-identical output and an empty diff.
//!
//! Until stable release `0.3.0` is tagged the corpus may be regenerated
//! freely: `FORMAT.md` §11.4 places artifacts from pre-release and untagged
//! revisions outside the cross-release promise, and §12.3 anchors the frozen
//! publication to the `v0.3.0` tag. From that tag the rows and bytes are
//! append-only.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha3::{Digest, Sha3_256};

use crate::crypto::aead::WRAP_NONCE_SIZE;
use crate::crypto::kdf::KdfLimit;
use crate::crypto::kdf::{ARGON2_SALT_SIZE, KDF_PARAMS_SIZE, KdfParams};
use crate::crypto::keys::{DerivedSubkeys, FileKey, derive_subkeys, random_bytes};
use crate::crypto::stream::STREAM_NONCE_SIZE;
use crate::passphrase::Passphrase;
use crate::recipient::RecipientEntry;
use crate::recipient::name::TYPE_NAME_MAX_LEN;
use crate::recipient::native::{argon2id, x25519};
use crate::{ArchiveLimits, CryptoError, KeyPairGenerator, PublicKey};

// ─── Corpus identity ───────────────────────────────────────────────────────

/// Manifest grammar version written to `SCHEMA-VERSION` (`FORMAT.md` §12.3).
const SCHEMA_VERSION: u32 = 1;

/// Append-only content revision written to `CORPUS-REVISION`. Stays `1` until
/// stable `0.3.0` is tagged; after the tag it increments whenever a row is
/// appended.
const CORPUS_REVISION: u32 = 1;

/// The compatibility baseline this publication evidences (`FORMAT.md` §11.4).
const BASELINE_ID: &str = "0.3.0";

/// Release that publishes every revision-1 row.
const INTRODUCED_IN_RELEASE: &str = "0.3.0";

/// Root seed for the deterministic RNG. Every draw derives from it through a
/// per-case sub-seed, so regeneration is byte-identical.
const WIRE_SEED: u64 = 0xFECC_0000_1234_0003;

/// Seeds the random draws that build one artifact from [`WIRE_SEED`] and the
/// case identifier the artifact is anchored to, for as long as the returned
/// guard lives.
///
/// Every draw sits inside one of these scopes and the enclosing stream is
/// sealed, so an artifact's bytes depend on its own case identifier alone and
/// on nothing that ran before it. Adding, removing, or reordering a case
/// leaves every other artifact byte-identical, which is what the append-only
/// freeze in `FORMAT.md` §12.3 needs from this generator once `v0.3.0` is
/// tagged: a case appended later can be reviewed on its own bytes.
fn case_scope(case_id: &str) -> crate::crypto::keys::SeedScope {
    let mut hasher = Sha3_256::new();
    hasher.update(b"ferrocrypt/wire-corpus/case-seed");
    hasher.update(WIRE_SEED.to_be_bytes());
    hasher.update([0x00]);
    hasher.update(case_id.as_bytes());
    let digest = hasher.finalize();
    let seed = u64::from_be_bytes(digest[..8].try_into().expect("digest prefix"));
    crate::crypto::keys::deterministic_seed_scope(seed)
}

/// Passphrase for every `argon2id` artifact and every `private.key` unlock in
/// the corpus. Public test material: anyone with the corpus can open these.
const CORPUS_PASSPHRASE: &str = "wire-corpus-passphrase-not-secret-do-not-reuse";

/// Deliberately wrong passphrase for the wrong-credential cases.
const WRONG_PASSPHRASE: &str = "wire-corpus-wrong-passphrase";

/// Unix modes the corpus pins: on every source file before it is archived, so
/// the umask that created it cannot leak into the encrypted bytes, and on the
/// entries of every hand-built FCA, so a crafted archive describes the same
/// tree as an archived one.
const SOURCE_FILE_MODE: u16 = 0o644;
const SOURCE_DIR_MODE: u16 = 0o755;

/// Grammar-valid recipient type name this build does not implement. Plugin
/// namespaced per `FORMAT.md` §3.3.1, so a future native type cannot claim it.
const UNKNOWN_RECIPIENT_TYPE: &str = "test/unknown";

// ─── Manifest rows ─────────────────────────────────────────────────────────

/// One `cases.tsv` row. Digest columns are computed at write time from the
/// referenced bytes, so a row can never disagree with the file it names.
struct CaseRow {
    case_id: String,
    case_type: &'static str,
    artifact_ref: String,
    construction: &'static str,
    parent_case_id: String,
    payload_transcript_kind: &'static str,
    payload_origin_ids: String,
    credential_id: String,
    outcome: &'static str,
    expectation_scope: &'static str,
    capability_id: String,
    condition_id: String,
    diagnostic_class: String,
    expected_ref: String,
}

impl CaseRow {
    /// A case with every optional column at its inapplicable default. The
    /// outcome is set by [`Self::accept`], [`Self::reject`], or
    /// [`Self::transcript_equal`], each of which fills the columns §12.3
    /// requires for that outcome.
    fn new(case_id: &str, case_type: &'static str, artifact_ref: &str) -> Self {
        Self {
            case_id: case_id.to_string(),
            case_type,
            artifact_ref: artifact_ref.to_string(),
            construction: "original",
            parent_case_id: "-".to_string(),
            // `fcr_decrypt` rows override this; every other case type keeps it.
            payload_transcript_kind: "not_applicable",
            payload_origin_ids: "-".to_string(),
            credential_id: "-".to_string(),
            outcome: "reject",
            expectation_scope: "invariant",
            capability_id: "-".to_string(),
            condition_id: "-".to_string(),
            diagnostic_class: "-".to_string(),
            expected_ref: "-".to_string(),
        }
    }

    /// A `.fcr` case. Defaults to `payload_transcript_kind = none`, the value
    /// §12.3 requires for a `.fcr`-shaped artifact carrying no genuine payload
    /// transcript; [`Self::origin`] switches it to `origins`.
    fn fcr(case_id: &str, artifact_ref: &str) -> Self {
        Self {
            payload_transcript_kind: "none",
            ..Self::new(case_id, "fcr_decrypt", artifact_ref)
        }
    }

    fn origin(mut self, origin_id: &str) -> Self {
        self.payload_transcript_kind = "origins";
        self.payload_origin_ids = origin_id.to_string();
        self
    }

    fn credential(mut self, credential_id: &str) -> Self {
        self.credential_id = credential_id.to_string();
        self
    }

    fn accept(mut self, expected_ref: &str) -> Self {
        self.outcome = "accept";
        self.expected_ref = expected_ref.to_string();
        self
    }

    fn reject(mut self, condition_id: &str, diagnostic_class: &str) -> Self {
        self.outcome = "reject";
        self.condition_id = condition_id.to_string();
        self.diagnostic_class = diagnostic_class.to_string();
        self
    }

    /// The outcome of a known-answer case: the implementation reproduces the
    /// committed transcript byte for byte rather than accepting or rejecting.
    fn transcript_equal(mut self, expected_ref: &str) -> Self {
        self.outcome = "transcript_equal";
        self.expected_ref = expected_ref.to_string();
        self
    }

    fn mutation_of(mut self, parent_case_id: &str) -> Self {
        self.construction = "mutation";
        self.parent_case_id = parent_case_id.to_string();
        self
    }

    fn fabricated(mut self) -> Self {
        self.construction = "fabricated";
        self
    }

    /// Marks the case capability-relative and names the single capability its
    /// outcome depends on (`FORMAT.md` §12.2).
    fn capability(mut self, capability_id: &str) -> Self {
        self.expectation_scope = "capability_relative";
        self.capability_id = capability_id.to_string();
        self
    }
}

struct CredentialRow {
    credential_id: String,
    kind: &'static str,
    primary_ref: String,
    secret_ref: String,
}

struct OriginRow {
    origin_id: String,
    origin_kind: &'static str,
    anchor_case_id: String,
    payload_key_ref: String,
    payload_key_sha3_256: String,
    stream_nonce_hex: String,
}

// ─── Corpus accumulator ────────────────────────────────────────────────────

struct Corpus {
    root: PathBuf,
    cases: Vec<CaseRow>,
    credentials: Vec<CredentialRow>,
    origins: Vec<OriginRow>,
    /// Diagnostic classes actually used, mapped to their stable explanatory
    /// text. Sorted by class id so the emitted table is stable.
    classes: BTreeMap<&'static str, &'static str>,
}

impl Corpus {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            cases: Vec::new(),
            credentials: Vec::new(),
            origins: Vec::new(),
            classes: BTreeMap::new(),
        }
    }

    /// Writes `bytes` at `relative_ref` under the corpus root and returns the
    /// reference for a manifest column.
    fn write_ref(&self, relative_ref: &str, bytes: &[u8]) -> String {
        let path = self.root.join(relative_ref);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create corpus subdirectory");
        }
        fs::write(&path, bytes).expect("write corpus file");
        relative_ref.to_string()
    }

    fn push_case(&mut self, case: CaseRow) {
        if case.diagnostic_class != "-" {
            let (id, text) = DIAGNOSTIC_CLASS_TEXT
                .iter()
                .find(|(id, _)| *id == case.diagnostic_class)
                .unwrap_or_else(|| {
                    panic!("unregistered diagnostic class {}", case.diagnostic_class)
                });
            self.classes.insert(id, text);
        }
        self.cases.push(case);
    }

    fn push_credential(&mut self, credential: CredentialRow) {
        self.credentials.push(credential);
    }

    fn push_origin(&mut self, origin: OriginRow) {
        self.origins.push(origin);
    }
}

/// SHA3-256 of `bytes` as 64 lowercase hexadecimal characters.
fn sha3_hex(bytes: &[u8]) -> String {
    let digest = Sha3_256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA3-256 of the file a manifest reference names, or `-` when the reference
/// itself is `-`.
fn digest_of_ref(root: &Path, reference: &str) -> String {
    if reference == "-" {
        return "-".to_string();
    }
    let bytes = fs::read(root.join(reference))
        .unwrap_or_else(|e| panic!("read referenced corpus file {reference}: {e}"));
    sha3_hex(&bytes)
}

/// Lowercase hexadecimal encoding.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ─── Diagnostic-class registry ─────────────────────────────────────────────

/// Stable explanatory text for every diagnostic class the corpus uses, taken
/// from the `FORMAT.md` §12.1 registry. Each entry is written to its own file
/// under `diagnostic-classes/` and referenced by `diagnostic-classes.tsv`, so
/// a class meaning is committed bytes with its own digest and can never be
/// edited once frozen.
const DIAGNOSTIC_CLASS_TEXT: &[(&str, &str)] = &[
    (
        "truncated",
        "Top-level .fcr framing ended before the prefix, declared header, or header MAC was complete.",
    ),
    ("bad_magic", "The top-level FCR\\0 magic does not match."),
    (
        "not_a_key_file",
        "The input is not a recognized FerroCrypt key artifact.",
    ),
    (
        "wrong_kind",
        "An FCR\\0 artifact has the wrong kind for the requested operation.",
    ),
    (
        "wrong_key_file_type",
        "A recognized key artifact is not the requested public/private key form.",
    ),
    (
        "unsupported_outer_version",
        "A nonzero .fcr outer-container version this implementation does not support.",
    ),
    (
        "unsupported_fca_version",
        "A nonzero FCA archive version this implementation does not support.",
    ),
    (
        "unsupported_public_key_version",
        "A nonzero public-key encoding version this implementation does not support.",
    ),
    (
        "unsupported_private_key_version",
        "A nonzero private-key encoding version this implementation does not support.",
    ),
    (
        "oversized_header",
        "The declared .fcr header exceeds the structural maximum.",
    ),
    (
        "malformed_header",
        "The .fcr prefix or header violates a structural grammar or accounting rule assigned to this class.",
    ),
    (
        "extension_region_too_large",
        "The declared .fcr header extension region exceeds its structural maximum.",
    ),
    (
        "malformed_tlv",
        "A TLV region violates framing or canonicality rules.",
    ),
    (
        "unknown_critical_tlv",
        "A well-formed critical TLV is unsupported.",
    ),
    (
        "recipient_count_out_of_range",
        "The recipient count violates structural bounds.",
    ),
    (
        "malformed_type_name",
        "A recipient type name violates FORMAT.md section 3.3.",
    ),
    (
        "malformed_recipient_entry",
        "Recipient framing or recipient-specific structural validation failed.",
    ),
    (
        "recipient_flags_reserved",
        "A reserved recipient flag bit is nonzero.",
    ),
    (
        "unknown_critical_recipient",
        "A well-formed critical recipient type is unsupported.",
    ),
    (
        "no_supported_recipient",
        "No supported recipient type is present.",
    ),
    (
        "incompatible_recipients",
        "The recipient set violates a mixing policy.",
    ),
    (
        "recipient_unwrap_failed",
        "No supported recipient accepted the supplied credential.",
    ),
    (
        "header_authentication_failed",
        "A candidate file key failed header-MAC verification.",
    ),
    (
        "invalid_kdf_parameters",
        "Stored KDF parameters violate structural rules.",
    ),
    (
        "resource_cap_exceeded",
        "Structurally valid data exceeds configured local resource policy.",
    ),
    (
        "payload_authentication_failed",
        "Payload-chunk authentication failed.",
    ),
    (
        "payload_truncated",
        "The encrypted payload ended before a valid final chunk.",
    ),
    (
        "malformed_payload_stream",
        "The payload STREAM transcript violates structural rules.",
    ),
    (
        "extra_data_after_payload",
        "Bytes follow the authenticated final payload chunk.",
    ),
    (
        "payload_chunk_count_exceeded",
        "The payload exceeds the permitted counter/chunk range.",
    ),
    (
        "malformed_archive",
        "The authenticated FCA payload violates header, manifest, or content-region grammar.",
    ),
    (
        "unsafe_archive_path",
        "An FCA path violates the portable path-safety grammar.",
    ),
    (
        "invalid_archive_tree",
        "The FCA manifest violates tree-shape or collision rules.",
    ),
    (
        "malformed_public_key",
        "A public-key artifact violates its encoding or canonicality rules.",
    ),
    (
        "unsupported_key_type",
        "A well-formed key type is unsupported.",
    ),
    (
        "malformed_private_key",
        "A private-key artifact violates its encoding or post-unlock consistency rules.",
    ),
    (
        "private_key_unlock_failed",
        "Private-key authentication failed for the supplied passphrase or modified file.",
    ),
];

// ─── Manifest emission ─────────────────────────────────────────────────────

/// Rejects any manifest field that would break the §12.3 grammar before it
/// reaches a committed table. A generator bug that produced a tab, a newline,
/// a backslash, a parent-directory component, or an absolute path would
/// otherwise ship as an unreadable frozen row.
fn check_field(table: &str, column: &str, value: &str) {
    assert!(!value.is_empty(), "{table}.{column} must not be empty");
    for forbidden in ['\t', '\r', '\n', '\\'] {
        assert!(
            !value.contains(forbidden),
            "{table}.{column} must not contain {forbidden:?}: {value}"
        );
    }
    assert!(
        !value.contains(".."),
        "{table}.{column} must not contain '..': {value}"
    );
    assert!(
        !value.starts_with('/'),
        "{table}.{column} must not be an absolute path: {value}"
    );
}

/// Writes one table: a header comment naming the columns, then tab-separated
/// rows. Every field is checked against the §12.3 grammar first.
fn write_table(root: &Path, name: &str, columns: &[&str], rows: Vec<Vec<String>>) {
    let mut out = format!("# {}\n", columns.join("\t"));
    for row in &rows {
        assert_eq!(row.len(), columns.len(), "{name} row width");
        for (column, value) in columns.iter().zip(row) {
            check_field(name, column, value);
        }
        out.push_str(&row.join("\t"));
        out.push('\n');
    }
    fs::write(root.join(name), out).unwrap_or_else(|e| panic!("write {name}: {e}"));
}

// ─── Artifact construction ─────────────────────────────────────────────────

/// A `.fcr` built by the generator, with the provenance `origins.tsv` records
/// for its payload STREAM encryption.
struct BuiltFcr {
    bytes: Vec<u8>,
    stream_nonce_hex: String,
    payload_key_sha3_256: String,
}

fn corpus_passphrase() -> Passphrase {
    Passphrase::new(CORPUS_PASSPHRASE)
}

/// Builds a `.fcr` from caller-supplied recipient entries and extension bytes
/// with a genuine encrypted payload over `source`. The caller passes the
/// `file_key` its entries wrap, so the header MAC and the payload belong to
/// the same key. This is the internals-only path: the public `Encryptor`
/// emits neither extension bytes, crafted recipient lists, nor out-of-range
/// KDF parameters.
fn build_fcr(
    source: &Path,
    file_key: &FileKey,
    entries: &[RecipientEntry],
    ext_bytes: &[u8],
) -> Result<BuiltFcr, CryptoError> {
    let stream_nonce = random_bytes::<STREAM_NONCE_SIZE>()?;
    let DerivedSubkeys {
        payload_key,
        header_key,
    } = derive_subkeys(file_key, &stream_nonce)?;
    let payload_key_sha3_256 = sha3_hex(payload_key.expose());
    let built = crate::container::build_encrypted_header(
        entries,
        ext_bytes,
        stream_nonce,
        payload_key,
        &header_key,
    )?;
    let staging = tempfile::tempdir().expect("fcr staging dir");
    let prepared = crate::archive::prepare_archive(source, ArchiveLimits::default())?;
    let written = crate::container::write_encrypted_file(
        prepared,
        staging.path(),
        Some(&staging.path().join("out.fcr")),
        "wire",
        &built,
    )?;
    Ok(BuiltFcr {
        bytes: fs::read(&written).expect("read built fcr"),
        stream_nonce_hex: hex(&stream_nonce),
        payload_key_sha3_256,
    })
}

/// Wraps `file_key` for the corpus passphrase with the fast test parameters.
fn argon2id_entry(file_key: &FileKey) -> RecipientEntry {
    let body = argon2id::wrap(
        file_key,
        &corpus_passphrase(),
        &KdfParams::test_fast_default(),
        &|_| {},
    )
    .expect("wrap argon2id recipient");
    RecipientEntry {
        type_name: argon2id::TYPE_NAME.to_string(),
        recipient_flags: 0,
        body: body.to_vec(),
    }
}

/// Parses a `public.key` file held in memory. The file is one canonical
/// recipient string with an optional trailing LF (`FORMAT.md` §7.1).
/// An `argon2id` entry whose stored `kdf_params` are replaced after wrapping,
/// so the body keeps its canonical length and valid header MAC while the
/// parameters a reader validates are the ones under test.
fn argon2id_entry_with_kdf_params(file_key: &FileKey, params: &KdfParams) -> RecipientEntry {
    let mut entry = argon2id_entry(file_key);
    entry.body[ARGON2_SALT_SIZE..ARGON2_SALT_SIZE + KDF_PARAMS_SIZE]
        .copy_from_slice(&params.to_bytes());
    entry
}

fn decode_public_key_file(bytes: &[u8]) -> PublicKey {
    std::str::from_utf8(bytes)
        .expect("public.key is UTF-8")
        .trim_end_matches('\n')
        .parse()
        .expect("public.key holds a canonical recipient string")
}

/// Wraps `file_key` for the X25519 recipient whose `public.key` bytes are
/// `public_key_file`.
fn x25519_entry(public_key_file: &[u8], file_key: &FileKey) -> RecipientEntry {
    let public = decode_public_key_file(public_key_file)
        .to_x25519_bytes()
        .expect("resolve corpus public key");
    let body = x25519::wrap(file_key, &public).expect("wrap x25519 recipient");
    RecipientEntry {
        type_name: x25519::TYPE_NAME.to_string(),
        recipient_flags: 0,
        body: body.to_vec(),
    }
}

/// Writes a source file of `len` bytes with a fixed mode and deterministic
/// content, so the archived bytes are reproducible on every platform.
fn write_source(dir: &Path, name: &str, len: usize) -> PathBuf {
    let path = dir.join(name);
    let content: Vec<u8> = (0..len).map(|i| (i * 7 + 13) as u8).collect();
    fs::write(&path, &content).expect("write source file");
    set_source_mode(&path);
    path
}

#[cfg(unix)]
fn set_source_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(u32::from(SOURCE_FILE_MODE)),
    )
    .expect("set source mode");
}

#[cfg(not(unix))]
fn set_source_mode(_path: &Path) {}

/// Generates one key pair with the fast test parameters and returns its
/// `(public.key, private.key)` bytes.
fn generate_key_pair() -> (Vec<u8>, Vec<u8>) {
    let staging = tempfile::tempdir().expect("keygen staging dir");
    KeyPairGenerator::with_passphrase(corpus_passphrase())
        .kdf_params(KdfParams::test_fast_default())
        .write(staging.path(), |_| {})
        .expect("generate corpus key pair");
    (
        fs::read(staging.path().join("public.key")).expect("read public.key"),
        fs::read(staging.path().join("private.key")).expect("read private.key"),
    )
}

// ─── Generator ─────────────────────────────────────────────────────────────

fn wire_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testvectors/wire")
}

/// Whether the corpus is on disk at all. `Cargo.toml` excludes it from the
/// published crate, so the replays skip there; a checkout always has the
/// directory, and a file missing from inside it still fails loudly.
fn wire_corpus_present() -> bool {
    wire_dir().is_dir()
}

/// Regenerates the committed corpus. Ignored in normal test runs; see the
/// module docs for the invocation and the freeze rules.
#[test]
#[ignore]
fn regenerate_wire_corpus() {
    crate::crypto::keys::with_sealed_rng(regenerate_wire_corpus_inner);
}

fn regenerate_wire_corpus_inner() {
    let root = wire_dir();
    // `README.md` and `tools/` are hand-written and preserved; everything else
    // is generated, so a stale artifact from an earlier run cannot survive
    // into a frozen publication.
    // `kat/` is deliberately absent: `FORMAT.md` §12.3 requires the STREAM
    // expected bytes to come from the independent PyNaCl oracle in `tools/`,
    // so this generator reads that directory and never rewrites it.
    for generated in ["artifacts", "expected", "credentials", "diagnostic-classes"] {
        let dir = root.join(generated);
        if dir.exists() {
            fs::remove_dir_all(&dir).expect("clean generated corpus subdirectory");
        }
    }
    fs::create_dir_all(&root).expect("create corpus root");

    let mut corpus = Corpus::new(root.clone());
    let sources = tempfile::tempdir().expect("source staging dir");

    write_credentials(&mut corpus);
    let keys = write_key_artifacts(&mut corpus);
    let (base, x25519_base) = write_valid_fcr_cases(&mut corpus, sources.path(), &keys);
    write_prefix_cases(&mut corpus, &base);
    write_header_cases(&mut corpus, &base);
    write_recipient_framing_cases(&mut corpus, sources.path(), &keys, &base);
    write_argon2id_cases(&mut corpus, sources.path(), &base);
    write_x25519_cases(&mut corpus, &x25519_base);
    write_tlv_cases(&mut corpus, sources.path());
    write_payload_stream_cases(&mut corpus, sources.path());
    write_public_key_cases(&mut corpus, &keys);
    write_private_key_cases(&mut corpus, &keys);
    write_fca_cases(&mut corpus);
    write_resource_policy_cases(&mut corpus, &keys);
    write_stream_kat_cases(&mut corpus);

    emit(&corpus);
}

/// The two X25519 key pairs the corpus uses. Only a private half is an artifact
/// in its own right, because `credentials.tsv` references it; the public halves
/// are generation inputs committed only where a `public-key-*` case needs them.
struct CorpusKeys {
    /// `public.key` file bytes.
    public_a: Vec<u8>,
    /// Corpus-relative reference to the committed `private.key`.
    private_a: String,
    /// `public.key` file bytes.
    public_b: Vec<u8>,
}

/// Writes the credential material every case references. All of it is public
/// test material; the corpus README warns against operational reuse.
fn write_credentials(corpus: &mut Corpus) {
    let main = corpus.write_ref(
        "credentials/passphrase-main.txt",
        CORPUS_PASSPHRASE.as_bytes(),
    );
    let wrong = corpus.write_ref(
        "credentials/passphrase-wrong.txt",
        WRONG_PASSPHRASE.as_bytes(),
    );
    corpus.push_credential(CredentialRow {
        credential_id: "passphrase-main".to_string(),
        kind: "passphrase",
        primary_ref: main,
        secret_ref: "-".to_string(),
    });
    corpus.push_credential(CredentialRow {
        credential_id: "passphrase-wrong".to_string(),
        kind: "passphrase",
        primary_ref: wrong,
        secret_ref: "-".to_string(),
    });
    corpus.push_credential(CredentialRow {
        credential_id: "none".to_string(),
        kind: "none",
        primary_ref: "-".to_string(),
        secret_ref: "-".to_string(),
    });
}

/// Commits a `private.key` case opened with a credential, so acceptance can
/// record the key material the unlock decoded.
fn private_key_open_case(
    corpus: &mut Corpus,
    case_id: &str,
    bytes: &[u8],
    credential_id: &str,
    outcome: Result<[u8; 32], (&str, &str)>,
) {
    let artifact_ref = corpus.write_ref(
        &format!("artifacts/private-key/{case_id}.private.key"),
        bytes,
    );
    let row = CaseRow::new(case_id, "private_key_open", &artifact_ref)
        .fabricated()
        .credential(credential_id);
    let row = match outcome {
        Ok(material) => {
            let expected_ref =
                corpus.write_ref(&format!("expected/private-key/{case_id}.bin"), &material);
            row.accept(&expected_ref)
        }
        Err((condition, class)) => row.reject(condition, class),
    };
    corpus.push_case(row);
}

/// Generates the two corpus key pairs, commits their bytes, and registers the
/// private-key credentials that reference them.
fn write_key_artifacts(corpus: &mut Corpus) -> CorpusKeys {
    let mut refs = Vec::new();
    for label in ["a", "b"] {
        let _scope = case_scope(&format!("private-key-{label}"));
        let (public, private) = generate_key_pair();
        let private_ref = corpus.write_ref(
            &format!("artifacts/private-key/recipient-{label}.private.key"),
            &private,
        );
        corpus.push_credential(CredentialRow {
            credential_id: format!("private-key-{label}"),
            kind: "private_key",
            primary_ref: private_ref.clone(),
            secret_ref: "credentials/passphrase-main.txt".to_string(),
        });
        if label == "a" {
            corpus.push_credential(CredentialRow {
                credential_id: "private-key-a-wrong-unlock".to_string(),
                kind: "private_key",
                primary_ref: private_ref.clone(),
                secret_ref: "credentials/passphrase-wrong.txt".to_string(),
            });
        }
        refs.push((public, private_ref));
    }
    let (public_b, _) = refs.pop().expect("recipient b");
    let (public_a, private_a) = refs.pop().expect("recipient a");
    CorpusKeys {
        public_a,
        private_a,
        public_b,
    }
}

/// One accepted `.fcr` case: commits the artifact, its expected plaintext, and
/// the provenance of the payload encryption that produced it.
fn accept_fcr_case(
    corpus: &mut Corpus,
    case_id: &str,
    origin_id: &str,
    credential_id: &str,
    source: &Path,
    built: BuiltFcr,
) {
    let artifact_ref = corpus.write_ref(&format!("artifacts/fcr/{case_id}.fcr"), &built.bytes);
    let expected_ref = corpus.write_ref(
        &format!("expected/plaintext/{case_id}.bin"),
        &fs::read(source).expect("read source for expected plaintext"),
    );
    corpus.push_origin(OriginRow {
        origin_id: origin_id.to_string(),
        origin_kind: "fcr_payload",
        anchor_case_id: case_id.to_string(),
        payload_key_ref: "-".to_string(),
        payload_key_sha3_256: built.payload_key_sha3_256,
        stream_nonce_hex: built.stream_nonce_hex,
    });
    corpus.push_case(
        CaseRow::fcr(case_id, &artifact_ref)
            .origin(origin_id)
            .credential(credential_id)
            .accept(&expected_ref),
    );
}

/// FCA overhead for a single-file root: fixed header, one entry header, and
/// the entry path bytes. Sizing a source against it lets a case land the
/// payload STREAM on an exact chunk boundary.
///
/// Measured by serializing an empty file rather than summing the wire
/// constants, because the sizes derived from it are claims about where the
/// payload STREAM ends. A layout change must move those sizes with it instead
/// of leaving the boundary cases sitting mid-chunk under their old names.
fn fca_overhead(name: &str) -> usize {
    build_fca(&[FcaEntry::file(name, b"")], b"").len()
}

/// Writes every accepted `.fcr` case and returns the small passphrase artifact
/// the rejection areas mutate.
fn write_valid_fcr_cases(
    corpus: &mut Corpus,
    sources: &Path,
    keys: &CorpusKeys,
) -> (MutationBase, MutationBase) {
    const NAME: &str = "p";
    let mut mutation_base = None;
    let chunk = crate::crypto::stream::BUFFER_SIZE;
    let overhead = fca_overhead(NAME);

    // Payload sizes required by FORMAT.md §12.3: an empty source, a one-byte
    // source, a payload STREAM of exactly one chunk, one byte past a chunk,
    // and a multi-chunk payload.
    let sizes: [(&str, usize); 5] = [
        ("empty", 0),
        ("one-byte", 1),
        ("chunk-exact", chunk - overhead),
        ("chunk-plus-one", chunk + 1 - overhead),
        ("multi-chunk", chunk * 3 + 977 - overhead),
    ];

    for (label, len) in sizes {
        let _scope = case_scope(&format!("fcr-argon2id-{label}"));
        let source = write_source(sources, NAME, len);
        let file_key = FileKey::generate().expect("file key");
        let entries = [argon2id_entry(&file_key)];
        let built = build_fcr(&source, &file_key, &entries, b"").expect("build argon2id fcr");
        let case_id = format!("fcr-argon2id-{label}");
        let origin_id = format!("origin-argon2id-{label}");
        if label == "one-byte" {
            mutation_base = Some(MutationBase {
                case_id: case_id.clone(),
                origin_id: origin_id.clone(),
                bytes: built.bytes.clone(),
            });
        }
        accept_fcr_case(
            corpus,
            &case_id,
            &origin_id,
            "passphrase-main",
            &source,
            built,
        );
    }

    // Native X25519, single recipient.
    let scope = case_scope("fcr-x25519-single");
    let source = write_source(sources, NAME, 4096);
    let file_key = FileKey::generate().expect("file key");
    let entries = [x25519_entry(&keys.public_a, &file_key)];
    let built = build_fcr(&source, &file_key, &entries, b"").expect("build x25519 fcr");
    let x25519_base = MutationBase {
        case_id: "fcr-x25519-single".to_string(),
        origin_id: "origin-x25519-single".to_string(),
        bytes: built.bytes.clone(),
    };
    accept_fcr_case(
        corpus,
        "fcr-x25519-single",
        "origin-x25519-single",
        "private-key-a",
        &source,
        built,
    );

    // Multiple X25519 recipients: both keys open the same file, so the corpus
    // carries one case per credential over one artifact.
    drop(scope);
    let scope = case_scope("fcr-x25519-multi-first");
    let file_key = FileKey::generate().expect("file key");
    let entries = [
        x25519_entry(&keys.public_a, &file_key),
        x25519_entry(&keys.public_b, &file_key),
    ];
    let built = build_fcr(&source, &file_key, &entries, b"").expect("build multi-x25519 fcr");
    let multi_bytes = built.bytes.clone();
    accept_fcr_case(
        corpus,
        "fcr-x25519-multi-first",
        "origin-x25519-multi",
        "private-key-a",
        &source,
        built,
    );
    drop(scope);
    let artifact_ref = corpus.write_ref("artifacts/fcr/fcr-x25519-multi-second.fcr", &multi_bytes);
    let expected_ref = corpus.write_ref(
        "expected/plaintext/fcr-x25519-multi-second.bin",
        &fs::read(&source).expect("read source"),
    );
    corpus.push_case(
        CaseRow::fcr("fcr-x25519-multi-second", &artifact_ref)
            .origin("origin-x25519-multi")
            .credential("private-key-b")
            .accept(&expected_ref),
    );

    (mutation_base.expect("mutation base built"), x25519_base)
}

/// The rows `name` already publishes, in `columns` order, or none when the
/// table has not been published yet.
fn published_rows(root: &Path, name: &str, columns: &[&str]) -> Vec<Vec<String>> {
    if !root.join(name).is_file() {
        return Vec::new();
    }
    read_manifest(root, name)
        .into_iter()
        .map(|row| {
            columns
                .iter()
                .map(|column| {
                    row.get(*column)
                        .unwrap_or_else(|| panic!("{name}: a published row has no {column} column"))
                        .clone()
                })
                .collect()
        })
        .collect()
}

/// The provenance columns a row is stamped with: the corpus revision and the
/// release that first published it. A row keeps the values it was published
/// with; every other column is content the freeze pins.
const STAMP_COLUMNS: [&str; 3] = [
    "introduced_in_corpus_revision",
    "introduced_in_release",
    "established_by_release",
];

/// Writes one manifest table under the `FORMAT.md` §12.3 append-only rule.
///
/// The generator stamps every row it builds with the current revision and
/// release, which is right only for a row this run adds. A row an earlier run
/// published keeps the stamps it was published with, because those stamps are
/// what a replay implementation reads to decide which rows its baseline
/// requires; restamping them would silently move the whole corpus to the new
/// revision. Once a row is frozen — published by a revision before this one —
/// no column of it may change at all: a correction goes through `errata.tsv`,
/// and a row that simply disappeared would break the same promise, so both are
/// generator errors rather than something to publish.
fn write_appended_table(
    root: &Path,
    name: &str,
    id_column: &str,
    columns: &[&str],
    mut rows: Vec<Vec<String>>,
) {
    let column_at = |column: &str| {
        columns
            .iter()
            .position(|c| *c == column)
            .unwrap_or_else(|| panic!("{name}: no {column} column"))
    };
    let id_at = column_at(id_column);
    let revision_at = column_at("introduced_in_corpus_revision");
    let stamps: Vec<usize> = STAMP_COLUMNS
        .iter()
        .filter(|column| columns.contains(column))
        .map(|column| column_at(column))
        .collect();

    let published: BTreeMap<String, Vec<String>> = published_rows(root, name, columns)
        .into_iter()
        .map(|row| (row[id_at].clone(), row))
        .collect();

    let mut carried = BTreeSet::new();
    for row in &mut rows {
        let Some(before) = published.get(&row[id_at]) else {
            continue;
        };
        carried.insert(row[id_at].clone());
        for at in &stamps {
            row[*at] = before[*at].clone();
        }
        let revision: u32 = before[revision_at]
            .parse()
            .unwrap_or_else(|e| panic!("{name}: {}: revision column: {e}", row[id_at]));
        if revision < CORPUS_REVISION {
            for (at, column) in columns.iter().enumerate() {
                assert_eq!(
                    row[at], before[at],
                    "{name}: {} is frozen at corpus revision {revision}; \
                     its {column} must be corrected through an erratum, not an edit",
                    row[id_at],
                );
            }
        }
    }
    for (id, before) in &published {
        let revision: u32 = before[revision_at]
            .parse()
            .unwrap_or_else(|e| panic!("{name}: {id}: revision column: {e}"));
        assert!(
            revision >= CORPUS_REVISION || carried.contains(id),
            "{name}: {id} was published by corpus revision {revision} and cannot be withdrawn; \
             retire it through an erratum instead",
        );
    }

    write_table(root, name, columns, rows);
}

/// Columns of the table the append-only tests below publish and rewrite.
const APPEND_TEST_COLUMNS: [&str; 4] = [
    "case_id",
    "artifact_ref",
    "introduced_in_release",
    "introduced_in_corpus_revision",
];

fn append_test_row(case_id: &str, artifact: &str, release: &str, revision: &str) -> Vec<String> {
    vec![
        case_id.to_string(),
        artifact.to_string(),
        release.to_string(),
        revision.to_string(),
    ]
}

/// Publishes a table holding one row frozen by an earlier revision and one row
/// belonging to the revision this build is still writing.
fn publish_append_test_table(dir: &Path) {
    write_table(
        dir,
        "t.tsv",
        &APPEND_TEST_COLUMNS,
        vec![
            append_test_row("frozen", "a.bin", "0.2.0", "0"),
            append_test_row("working", "b.bin", "0.2.0", &CORPUS_REVISION.to_string()),
        ],
    );
}

/// Rebuilds both published rows the way the generator does — stamped with the
/// current constants — plus one row this run adds.
fn append_test_rebuild() -> Vec<Vec<String>> {
    let revision = CORPUS_REVISION.to_string();
    vec![
        append_test_row("frozen", "a.bin", INTRODUCED_IN_RELEASE, &revision),
        append_test_row("working", "b.bin", INTRODUCED_IN_RELEASE, &revision),
        append_test_row("added", "c.bin", INTRODUCED_IN_RELEASE, &revision),
    ]
}

/// A published row keeps the revision and release it was published with, and
/// only a row this run adds is stamped with the current constants. Reading the
/// generator does not show whether that still holds, and the failure is silent:
/// a restamped corpus looks internally consistent to every checker.
#[test]
fn a_published_row_keeps_the_stamps_it_was_published_with() {
    let dir = tempfile::tempdir().expect("append-only table dir");
    publish_append_test_table(dir.path());
    write_appended_table(
        dir.path(),
        "t.tsv",
        "case_id",
        &APPEND_TEST_COLUMNS,
        append_test_rebuild(),
    );

    let rows = read_manifest(dir.path(), "t.tsv");
    let stamps = |case_id: &str| {
        let row = rows
            .iter()
            .find(|r| r["case_id"] == case_id)
            .unwrap_or_else(|| panic!("{case_id} is missing"));
        (
            row["introduced_in_release"].clone(),
            row["introduced_in_corpus_revision"].clone(),
        )
    };
    assert_eq!(
        stamps("frozen"),
        ("0.2.0".to_string(), "0".to_string()),
        "a frozen row keeps its own provenance"
    );
    assert_eq!(
        stamps("working"),
        ("0.2.0".to_string(), CORPUS_REVISION.to_string()),
        "a row of the working revision keeps its release too"
    );
    assert_eq!(
        stamps("added"),
        (
            INTRODUCED_IN_RELEASE.to_string(),
            CORPUS_REVISION.to_string()
        ),
        "only an added row is stamped with the current constants"
    );
}

/// A row of the revision still being written may change; only an earlier
/// revision's rows are frozen.
#[test]
fn a_row_of_the_working_revision_may_still_change() {
    let dir = tempfile::tempdir().expect("append-only table dir");
    publish_append_test_table(dir.path());
    let mut rows = append_test_rebuild();
    rows[1] = append_test_row(
        "working",
        "edited.bin",
        INTRODUCED_IN_RELEASE,
        &CORPUS_REVISION.to_string(),
    );
    write_appended_table(dir.path(), "t.tsv", "case_id", &APPEND_TEST_COLUMNS, rows);

    let rows = read_manifest(dir.path(), "t.tsv");
    let working = rows
        .iter()
        .find(|r| r["case_id"] == "working")
        .expect("working row");
    assert_eq!(working["artifact_ref"], "edited.bin");
}

/// Editing a frozen row is the correction the erratum mechanism exists for, so
/// the generator refuses it rather than publishing a row that no longer says
/// what an earlier baseline pinned.
#[test]
#[should_panic(expected = "must be corrected through an erratum")]
fn an_edited_frozen_row_is_refused() {
    let dir = tempfile::tempdir().expect("append-only table dir");
    publish_append_test_table(dir.path());
    let mut rows = append_test_rebuild();
    rows[0] = append_test_row(
        "frozen",
        "edited.bin",
        INTRODUCED_IN_RELEASE,
        &CORPUS_REVISION.to_string(),
    );
    write_appended_table(dir.path(), "t.tsv", "case_id", &APPEND_TEST_COLUMNS, rows);
}

/// Dropping a frozen row breaks the same promise as editing one: a replay
/// pinned to the earlier baseline would find its case gone.
#[test]
#[should_panic(expected = "cannot be withdrawn")]
fn a_withdrawn_frozen_row_is_refused() {
    let dir = tempfile::tempdir().expect("append-only table dir");
    publish_append_test_table(dir.path());
    let rows = append_test_rebuild().into_iter().skip(1).collect();
    write_appended_table(dir.path(), "t.tsv", "case_id", &APPEND_TEST_COLUMNS, rows);
}

/// Writes the version files, the diagnostic-class descriptions, and the six
/// manifest tables. Digest columns are computed here from the committed bytes,
/// so a row can never name a digest the referenced file does not have.
fn emit(corpus: &Corpus) {
    // Before anything is written: a row that breaks a §12.3 rule must not
    // reach the corpus, because a frozen row cannot be corrected without an
    // erratum.
    check_manifest_invariants(corpus);

    let root = &corpus.root;

    write_appended_table(
        root,
        "baselines.tsv",
        "baseline_id",
        &[
            "baseline_id",
            "established_by_release",
            "parent_baseline_id",
            "introduced_in_corpus_revision",
        ],
        vec![vec![
            BASELINE_ID.to_string(),
            INTRODUCED_IN_RELEASE.to_string(),
            "-".to_string(),
            CORPUS_REVISION.to_string(),
        ]],
    );

    let mut class_rows = Vec::new();
    for (class_id, text) in &corpus.classes {
        let description_ref = corpus.write_ref(
            &format!("diagnostic-classes/{class_id}.txt"),
            format!("{text}\n").as_bytes(),
        );
        let digest = digest_of_ref(root, &description_ref);
        class_rows.push(vec![
            (*class_id).to_string(),
            description_ref,
            digest,
            CORPUS_REVISION.to_string(),
        ]);
    }
    write_appended_table(
        root,
        "diagnostic-classes.tsv",
        "class_id",
        &[
            "class_id",
            "description_ref",
            "description_sha3_256",
            "introduced_in_corpus_revision",
        ],
        class_rows,
    );

    write_appended_table(
        root,
        "credentials.tsv",
        "credential_id",
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
        corpus
            .credentials
            .iter()
            .map(|c| {
                vec![
                    c.credential_id.clone(),
                    c.kind.to_string(),
                    c.primary_ref.clone(),
                    digest_of_ref(root, &c.primary_ref),
                    c.secret_ref.clone(),
                    digest_of_ref(root, &c.secret_ref),
                    INTRODUCED_IN_RELEASE.to_string(),
                    CORPUS_REVISION.to_string(),
                ]
            })
            .collect(),
    );

    write_appended_table(
        root,
        "origins.tsv",
        "origin_id",
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
        corpus
            .origins
            .iter()
            .map(|o| {
                vec![
                    o.origin_id.clone(),
                    o.origin_kind.to_string(),
                    o.anchor_case_id.clone(),
                    o.payload_key_ref.clone(),
                    o.payload_key_sha3_256.clone(),
                    o.stream_nonce_hex.clone(),
                    INTRODUCED_IN_RELEASE.to_string(),
                    CORPUS_REVISION.to_string(),
                ]
            })
            .collect(),
    );

    write_appended_table(
        root,
        "cases.tsv",
        "case_id",
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
            "outcome",
            "expectation_scope",
            "capability_id",
            "condition_id",
            "diagnostic_class",
            "expected_ref",
            "expected_sha3_256",
        ],
        corpus
            .cases
            .iter()
            .map(|c| {
                vec![
                    c.case_id.clone(),
                    c.case_type.to_string(),
                    c.artifact_ref.clone(),
                    digest_of_ref(root, &c.artifact_ref),
                    BASELINE_ID.to_string(),
                    INTRODUCED_IN_RELEASE.to_string(),
                    CORPUS_REVISION.to_string(),
                    c.construction.to_string(),
                    c.parent_case_id.clone(),
                    c.payload_transcript_kind.to_string(),
                    c.payload_origin_ids.clone(),
                    c.credential_id.clone(),
                    c.outcome.to_string(),
                    c.expectation_scope.to_string(),
                    c.capability_id.clone(),
                    c.condition_id.clone(),
                    c.diagnostic_class.clone(),
                    c.expected_ref.clone(),
                    digest_of_ref(root, &c.expected_ref),
                ]
            })
            .collect(),
    );

    // Errata are hand-authored corrections, not generator output, so every
    // published erratum is carried forward unchanged: it is the only way to
    // correct a frozen row, and rewriting the table would discard exactly the
    // corrections the freeze depends on. Revision 1 publishes none, so the
    // table ships with its header only.
    let errata_columns = [
        "erratum_id",
        "affected_case_id",
        "effective_corpus_revision",
        "rationale_ref",
        "rationale_sha3_256",
        "replacement_case_id",
        "introduced_in_release",
    ];
    let errata = published_rows(root, "errata.tsv", &errata_columns);
    write_table(root, "errata.tsv", &errata_columns, errata);

    // Last, because the tables above are what these two files describe: a run
    // that stops on an append-only violation must not leave a revision behind
    // claiming rows it never wrote.
    fs::write(root.join("SCHEMA-VERSION"), format!("{SCHEMA_VERSION}\n"))
        .expect("write SCHEMA-VERSION");
    fs::write(root.join("CORPUS-REVISION"), format!("{CORPUS_REVISION}\n"))
        .expect("write CORPUS-REVISION");

    // After the writes, unlike the row rules above: this one inspects the
    // directory. `kat/` is owned by the oracle and never cleaned between runs,
    // so a renamed case would otherwise leave its old files behind to be frozen
    // into the publication.
    assert_no_unreferenced_files(corpus);
}

/// Every file in the corpus must be named by a manifest row, or be one of the
/// files that carry the corpus rather than being carried by it. An
/// unreferenced file has no committed digest, so nothing would ever detect it
/// changing.
fn assert_no_unreferenced_files(corpus: &Corpus) {
    let mut referenced: std::collections::BTreeSet<String> = corpus
        .cases
        .iter()
        .flat_map(|c| [c.artifact_ref.clone(), c.expected_ref.clone()])
        .chain(
            corpus
                .credentials
                .iter()
                .flat_map(|c| [c.primary_ref.clone(), c.secret_ref.clone()]),
        )
        .chain(corpus.origins.iter().map(|o| o.payload_key_ref.clone()))
        .collect();
    referenced.extend(
        corpus
            .classes
            .keys()
            .map(|class| format!("diagnostic-classes/{class}.txt")),
    );

    for path in walk_corpus_files(&corpus.root) {
        let relative = path
            .strip_prefix(&corpus.root)
            .expect("corpus file is under the corpus root")
            .to_str()
            .expect("corpus path is UTF-8")
            .replace('\\', "/");
        assert!(
            is_structural_corpus_file(&relative) || referenced.contains(&relative),
            "{relative}: the generator left a file no manifest row references"
        );
    }
}

/// The six manifest tables of `FORMAT.md` §12.3.
const MANIFEST_TABLES: &[&str] = &[
    "baselines.tsv",
    "diagnostic-classes.tsv",
    "credentials.tsv",
    "origins.tsv",
    "cases.tsv",
    "errata.tsv",
];

/// Whether a corpus-relative path carries the corpus rather than being carried
/// by it, so no manifest row names it. A rule rather than a list of names:
/// `tools/` is matched by prefix, so adding a tool needs no edit here nor in
/// the two other checkers that apply the same rule.
fn is_structural_corpus_file(relative: &str) -> bool {
    MANIFEST_TABLES.contains(&relative)
        || matches!(relative, "SCHEMA-VERSION" | "CORPUS-REVISION" | "README.md")
        || relative.starts_with("tools/")
}

/// Every file under `root`, recursively.
fn walk_corpus_files(root: &Path) -> Vec<PathBuf> {
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

/// Re-checks the §12.3 row rules the generator is supposed to satisfy by
/// construction. A frozen row that breaks one of them cannot be corrected
/// without an erratum, so the generator refuses to emit it.
fn check_manifest_invariants(corpus: &Corpus) {
    let mut seen = std::collections::BTreeSet::new();
    for case in &corpus.cases {
        assert!(
            seen.insert(case.case_id.clone()),
            "duplicate case id {}",
            case.case_id
        );
        assert!(
            is_manifest_id(&case.case_id),
            "case id {} must match [a-z0-9][a-z0-9._-]*",
            case.case_id
        );
        match case.outcome {
            "reject" => {
                assert_ne!(
                    case.condition_id, "-",
                    "{}: reject needs a condition",
                    case.case_id
                );
                assert_ne!(
                    case.diagnostic_class, "-",
                    "{}: reject needs a diagnostic class",
                    case.case_id
                );
                assert_eq!(
                    case.expected_ref, "-",
                    "{}: reject has no expected result",
                    case.case_id
                );
            }
            "accept" | "transcript_equal" => {
                assert_ne!(
                    case.expected_ref, "-",
                    "{}: non-reject needs a byte-exact expected result",
                    case.case_id
                );
                assert_eq!(
                    case.diagnostic_class, "-",
                    "{}: non-reject uses diagnostic_class '-'",
                    case.case_id
                );
            }
            other => panic!("{}: unknown outcome {other}", case.case_id),
        }
        match case.expectation_scope {
            "invariant" => assert_eq!(
                case.capability_id, "-",
                "{}: an invariant case uses capability_id '-'",
                case.case_id
            ),
            "capability_relative" => assert_ne!(
                case.capability_id, "-",
                "{}: a capability-relative case names one capability",
                case.case_id
            ),
            other => panic!("{}: unknown expectation scope {other}", case.case_id),
        }
        if case.construction == "mutation" {
            assert_ne!(
                case.parent_case_id, "-",
                "{}: a mutation names its parent",
                case.case_id
            );
        } else {
            assert_eq!(
                case.parent_case_id, "-",
                "{}: only a mutation names a parent",
                case.case_id
            );
        }
        if case.case_type == "fcr_decrypt" {
            assert!(
                matches!(case.payload_transcript_kind, "origins" | "none"),
                "{}: an .fcr case uses origins or none",
                case.case_id
            );
        } else {
            assert_eq!(
                case.payload_transcript_kind, "not_applicable",
                "{}: a non-.fcr case uses not_applicable",
                case.case_id
            );
        }
        if case.payload_transcript_kind == "origins" {
            assert!(
                !case.payload_origin_ids.is_empty(),
                "{}: origins list is nonempty",
                case.case_id
            );
            let ids: Vec<&str> = case.payload_origin_ids.split(',').collect();
            assert!(
                ids.iter().all(|id| !id.is_empty()),
                "{}: origins list has no empty entry",
                case.case_id
            );
            let unique: std::collections::BTreeSet<&&str> = ids.iter().collect();
            assert_eq!(
                unique.len(),
                ids.len(),
                "{}: origins are duplicate-free",
                case.case_id
            );
            for id in ids {
                assert!(
                    corpus.origins.iter().any(|o| o.origin_id == id),
                    "{}: origin {id} is not declared",
                    case.case_id
                );
            }
        } else {
            assert_eq!(
                case.payload_origin_ids, "-",
                "{}: only an origins case lists origins",
                case.case_id
            );
        }
        if case.credential_id != "-" {
            assert!(
                corpus
                    .credentials
                    .iter()
                    .any(|c| c.credential_id == case.credential_id),
                "{}: credential {} is not declared",
                case.case_id,
                case.credential_id
            );
        }
    }
    for origin in &corpus.origins {
        assert_eq!(
            origin.stream_nonce_hex.len(),
            STREAM_NONCE_SIZE * 2,
            "{}: stream_nonce_hex is a 19-byte prefix",
            origin.origin_id
        );
        assert!(
            corpus
                .cases
                .iter()
                .any(|c| c.case_id == origin.anchor_case_id),
            "{}: anchor case {} is not declared",
            origin.origin_id,
            origin.anchor_case_id
        );
    }
    let nonces: std::collections::BTreeSet<&String> =
        corpus.origins.iter().map(|o| &o.stream_nonce_hex).collect();
    assert_eq!(
        nonces.len(),
        corpus.origins.len(),
        "independent origins must use distinct nonce prefixes"
    );
}

/// `[a-z0-9][a-z0-9._-]*` — the §12.3 identifier grammar.
fn is_manifest_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

// ─── Mutation helpers ──────────────────────────────────────────────────────

/// A committed artifact later cases mutate. Mutations of a `.fcr` keep its
/// payload provenance, because the mutated bytes still contain that genuine
/// ciphertext (`FORMAT.md` §12.3).
struct MutationBase {
    case_id: String,
    origin_id: String,
    bytes: Vec<u8>,
}

/// Commits a mutated copy of `base` as a rejected `.fcr` case.
fn mutate_fcr(
    corpus: &mut Corpus,
    base: &MutationBase,
    case_id: &str,
    credential_id: &str,
    condition_id: &str,
    diagnostic_class: &str,
    mutate: impl FnOnce(&mut Vec<u8>),
) {
    let mut bytes = base.bytes.clone();
    mutate(&mut bytes);
    assert_ne!(bytes, base.bytes, "{case_id}: mutation changed nothing");
    let artifact_ref = corpus.write_ref(&format!("artifacts/fcr/{case_id}.fcr"), &bytes);
    corpus.push_case(
        CaseRow::fcr(case_id, &artifact_ref)
            .origin(&base.origin_id)
            .mutation_of(&base.case_id)
            .credential(credential_id)
            .reject(condition_id, diagnostic_class),
    );
}

/// Commits a fabricated `.fcr`-shaped artifact that carries no genuine payload
/// transcript, so its `payload_transcript_kind` stays `none`.
fn fabricate_fcr(
    corpus: &mut Corpus,
    case_id: &str,
    credential_id: &str,
    condition_id: &str,
    diagnostic_class: &str,
    bytes: &[u8],
) {
    let artifact_ref = corpus.write_ref(&format!("artifacts/fcr/{case_id}.fcr"), bytes);
    corpus.push_case(
        CaseRow::fcr(case_id, &artifact_ref)
            .fabricated()
            .credential(credential_id)
            .reject(condition_id, diagnostic_class),
    );
}

/// Offset of the payload region: the end of `prefix || header || header_mac`,
/// read from the artifact's own declared header length.
fn payload_offset(bytes: &[u8]) -> usize {
    let header_len = u32::from_be_bytes(
        bytes[OFF_HEADER_LEN..OFF_HEADER_LEN + 4]
            .try_into()
            .expect("header_len"),
    ) as usize;
    crate::format::PREFIX_SIZE + header_len + crate::format::HEADER_MAC_SIZE
}

// ─── Prefix and framing ────────────────────────────────────────────────────

fn write_prefix_cases(corpus: &mut Corpus, base: &MutationBase) {
    use crate::format::{HEADER_LEN_MAX, HEADER_MAC_SIZE, PREFIX_SIZE};

    mutate_fcr(
        corpus,
        base,
        "prefix-bad-magic",
        "passphrase-main",
        "prefix_magic_mismatch",
        "bad_magic",
        |b| b[0] ^= 0xFF,
    );
    mutate_fcr(
        corpus,
        base,
        "prefix-version-zero",
        "passphrase-main",
        "outer_version_reserved_zero",
        "malformed_header",
        |b| b[OFF_OUTER_VERSION] = 0x00,
    );
    mutate_fcr(
        corpus,
        base,
        "prefix-wrong-kind",
        "passphrase-main",
        "prefix_kind_not_encrypted",
        "wrong_kind",
        |b| b[OFF_PREFIX_KIND] = 0x4B,
    );
    mutate_fcr(
        corpus,
        base,
        "prefix-nonzero-flags",
        "passphrase-main",
        "prefix_flags_nonzero",
        "malformed_header",
        |b| b[OFF_PREFIX_FLAGS] = 0x01,
    );
    mutate_fcr(
        corpus,
        base,
        "prefix-header-len-over-structural-max",
        "passphrase-main",
        "prefix_header_len_above_structural_maximum",
        "oversized_header",
        |b| {
            b[OFF_HEADER_LEN..OFF_HEADER_LEN + 4]
                .copy_from_slice(&(HEADER_LEN_MAX + 1).to_be_bytes())
        },
    );
    // The local cap sits far below the structural maximum and is checked
    // straight after the prefix, before the declared header is read, so the
    // declaration alone decides the outcome. This cap has no accepting twin:
    // the recipient-count, per-body, and extension caps together bound a
    // header well under it, so no file that satisfies them can reach it.
    mutate_fcr(
        corpus,
        base,
        "prefix-header-len-over-default-cap",
        "passphrase-main",
        "header_len_above_default_cap",
        "resource_cap_exceeded",
        |b| {
            b[OFF_HEADER_LEN..OFF_HEADER_LEN + 4]
                .copy_from_slice(&(crate::HeaderReadLimits::HEADER_LEN_DEFAULT + 1).to_be_bytes())
        },
    );

    // A newer outer-container version is capability-relative: an
    // implementation that adds support for it stops rejecting these bytes.
    let mut newer = base.bytes.clone();
    newer[OFF_OUTER_VERSION] = 0x02;
    let artifact_ref = corpus.write_ref("artifacts/fcr/prefix-newer-outer-version.fcr", &newer);
    corpus.push_case(
        CaseRow::fcr("prefix-newer-outer-version", &artifact_ref)
            .origin(&base.origin_id)
            .mutation_of(&base.case_id)
            .credential("passphrase-main")
            .capability("outer_version:0x02")
            .reject("outer_version_unsupported", "unsupported_outer_version"),
    );

    // Truncation at each framing boundary: inside the prefix, inside the
    // declared header, and inside the header MAC.
    let header_end = PREFIX_SIZE
        + u32::from_be_bytes(
            base.bytes[OFF_HEADER_LEN..OFF_HEADER_LEN + 4]
                .try_into()
                .expect("header_len"),
        ) as usize;
    for (case_id, keep) in [
        ("framing-truncated-in-prefix", PREFIX_SIZE - 1),
        ("framing-truncated-in-header", header_end - 1),
        (
            "framing-truncated-in-header-mac",
            header_end + HEADER_MAC_SIZE - 1,
        ),
    ] {
        fabricate_fcr(
            corpus,
            case_id,
            "passphrase-main",
            "framing_ends_before_declared_region",
            "truncated",
            &base.bytes[..keep],
        );
    }

    // FORMAT.md §12.1 pins the undersized-header precedence explicitly: with
    // the MAC bytes missing the class is `truncated`; with all 32 present and
    // `header_fixed` unable to fit, it is `malformed_header`.
    let mut zero_header = base.bytes[..PREFIX_SIZE].to_vec();
    zero_header[OFF_HEADER_LEN..OFF_HEADER_LEN + 4].copy_from_slice(&0u32.to_be_bytes());
    fabricate_fcr(
        corpus,
        "framing-header-len-zero-no-mac",
        "passphrase-main",
        "header_len_zero_without_mac_bytes",
        "truncated",
        &zero_header,
    );
    let mut zero_header_with_mac = zero_header.clone();
    zero_header_with_mac.extend_from_slice(&[0u8; HEADER_MAC_SIZE]);
    fabricate_fcr(
        corpus,
        "framing-header-len-zero-with-mac",
        "passphrase-main",
        "header_len_zero_with_complete_mac_bytes",
        "malformed_header",
        &zero_header_with_mac,
    );
}

// ─── Header field offsets ──────────────────────────────────────────────────

// Absolute offsets into a `.fcr`, derived from the §3.1/§3.2 layout so the
// mutation cases below name a field rather than a bare number.
/// `.fcr` plain-prefix field offsets (`FORMAT.md` §3.1).
const OFF_OUTER_VERSION: usize = crate::format::MAGIC_SIZE;
const OFF_PREFIX_KIND: usize = OFF_OUTER_VERSION + 1;
const OFF_PREFIX_FLAGS: usize = OFF_PREFIX_KIND + 1;
const OFF_HEADER_LEN: usize = OFF_PREFIX_FLAGS + 2;
const _: () = assert!(OFF_HEADER_LEN + 4 == crate::format::PREFIX_SIZE);

const OFF_HEADER_FLAGS: usize = crate::format::PREFIX_SIZE;
const OFF_RECIPIENT_COUNT: usize = OFF_HEADER_FLAGS + 2;
const OFF_RECIPIENT_ENTRIES_LEN: usize = OFF_RECIPIENT_COUNT + 2;
const OFF_EXT_LEN: usize = OFF_RECIPIENT_ENTRIES_LEN + 4;
const OFF_STREAM_NONCE: usize = OFF_EXT_LEN + 4;
const OFF_FIRST_ENTRY: usize = crate::format::PREFIX_SIZE + crate::format::HEADER_FIXED_SIZE;

/// Builds a `.fcr` whose payload region is exactly `payload`, bypassing the
/// archive writer. Used by the payload-STREAM cases, which need transcripts
/// no conforming writer emits.
fn assemble_fcr(built: &crate::container::BuiltEncryptedHeader, payload: &[u8]) -> Vec<u8> {
    let mut bytes = built.prefix_bytes.to_vec();
    bytes.extend_from_slice(&built.header_bytes);
    bytes.extend_from_slice(&built.header_mac);
    bytes.extend_from_slice(payload);
    bytes
}

/// Builds a header over `entries` and returns it with the payload key and
/// nonce provenance the corpus records.
fn craft_header(
    file_key: &FileKey,
    entries: &[RecipientEntry],
    ext_bytes: &[u8],
) -> (crate::container::BuiltEncryptedHeader, String, String) {
    let stream_nonce = random_bytes::<STREAM_NONCE_SIZE>().expect("stream nonce");
    let DerivedSubkeys {
        payload_key,
        header_key,
    } = derive_subkeys(file_key, &stream_nonce).expect("derive subkeys");
    let payload_key_digest = sha3_hex(payload_key.expose());
    let built = crate::container::build_encrypted_header(
        entries,
        ext_bytes,
        stream_nonce,
        payload_key,
        &header_key,
    )
    .expect("build header");
    (built, hex(&stream_nonce), payload_key_digest)
}

// ─── Header ────────────────────────────────────────────────────────────────

fn write_header_cases(corpus: &mut Corpus, base: &MutationBase) {
    use crate::format::HEADER_FIXED_SIZE;

    mutate_fcr(
        corpus,
        base,
        "header-flags-nonzero",
        "passphrase-main",
        "header_flags_nonzero",
        "malformed_header",
        |b| b[OFF_HEADER_FLAGS + 1] = 0x01,
    );
    mutate_fcr(
        corpus,
        base,
        "header-recipient-count-zero",
        "passphrase-main",
        "recipient_count_zero",
        "recipient_count_out_of_range",
        |b| b[OFF_RECIPIENT_COUNT..OFF_RECIPIENT_COUNT + 2].copy_from_slice(&0u16.to_be_bytes()),
    );
    mutate_fcr(
        corpus,
        base,
        "header-recipient-count-above-max",
        "passphrase-main",
        "recipient_count_above_structural_maximum",
        "recipient_count_out_of_range",
        |b| {
            b[OFF_RECIPIENT_COUNT..OFF_RECIPIENT_COUNT + 2]
                .copy_from_slice(&(crate::format::RECIPIENT_COUNT_MAX + 1).to_be_bytes())
        },
    );
    // §3.2 accounting: 31 + recipient_entries_len + ext_len MUST equal
    // header_len. Raising the declared entries length alone breaks the sum.
    mutate_fcr(
        corpus,
        base,
        "header-section-lengths-disagree",
        "passphrase-main",
        "header_section_lengths_do_not_sum_to_header_len",
        "malformed_header",
        |b| {
            let current = u32::from_be_bytes(
                b[OFF_RECIPIENT_ENTRIES_LEN..OFF_RECIPIENT_ENTRIES_LEN + 4]
                    .try_into()
                    .expect("entries len"),
            );
            b[OFF_RECIPIENT_ENTRIES_LEN..OFF_RECIPIENT_ENTRIES_LEN + 4]
                .copy_from_slice(&(current + 1).to_be_bytes());
        },
    );
    // The declared bytes must actually be present: a reader reads exactly the
    // declared header and MAC first, so a file that merely claims an oversized
    // extension region ends as `truncated` before the cap is consulted
    // (`FORMAT.md` §12.1). This case pads the region to its declared size and
    // keeps the §3.2 accounting sum, so it isolates the extension-length cap.
    mutate_fcr(
        corpus,
        base,
        "header-ext-len-above-structural-max",
        "passphrase-main",
        "ext_len_above_structural_maximum",
        "extension_region_too_large",
        |b| {
            let entries = u32::from_be_bytes(
                b[OFF_RECIPIENT_ENTRIES_LEN..OFF_RECIPIENT_ENTRIES_LEN + 4]
                    .try_into()
                    .expect("entries len"),
            );
            let ext = crate::format::EXT_LEN_MAX + 1;
            b[OFF_EXT_LEN..OFF_EXT_LEN + 4].copy_from_slice(&ext.to_be_bytes());
            b[OFF_HEADER_LEN..OFF_HEADER_LEN + 4]
                .copy_from_slice(&(HEADER_FIXED_SIZE as u32 + entries + ext).to_be_bytes());
            let insert_at = OFF_FIRST_ENTRY + entries as usize;
            b.splice(insert_at..insert_at, std::iter::repeat_n(0u8, ext as usize));
        },
    );

    // §3.6: the MAC covers the prefix, every header field, the recipient list
    // in declared order, and `ext_bytes`. Flipping an authenticated byte that
    // no structural rule rejects must fail at the MAC, after a successful
    // recipient unwrap.
    mutate_fcr(
        corpus,
        base,
        "header-mac-tamper-stream-nonce",
        "passphrase-main",
        "header_mac_covers_stream_nonce",
        "header_authentication_failed",
        |b| b[OFF_STREAM_NONCE] ^= 0x01,
    );
    mutate_fcr(
        corpus,
        base,
        "header-mac-tamper-tag",
        "passphrase-main",
        "header_mac_tag_modified",
        "header_authentication_failed",
        |b| {
            let mac = payload_offset(b) - crate::format::HEADER_MAC_SIZE;
            b[mac] ^= 0x01;
        },
    );
}

/// Builds a rejected `.fcr` from crafted recipient entries with a genuine
/// payload and a valid header MAC, so the case isolates the recipient rule
/// rather than tripping authentication first.
#[allow(clippy::too_many_arguments)]
fn crafted_reject_case(
    corpus: &mut Corpus,
    sources: &Path,
    case_id: &str,
    origin_id: &str,
    credential_id: &str,
    condition_id: &str,
    diagnostic_class: &str,
    file_key: &FileKey,
    entries: &[RecipientEntry],
    ext_bytes: &[u8],
) {
    let source = write_source(sources, "p", 64);
    let built = build_fcr_with_entries(&source, file_key, entries, ext_bytes);
    let artifact_ref = corpus.write_ref(&format!("artifacts/fcr/{case_id}.fcr"), &built.bytes);
    corpus.push_origin(OriginRow {
        origin_id: origin_id.to_string(),
        origin_kind: "fcr_payload",
        anchor_case_id: case_id.to_string(),
        payload_key_ref: "-".to_string(),
        payload_key_sha3_256: built.payload_key_sha3_256,
        stream_nonce_hex: built.stream_nonce_hex,
    });
    corpus.push_case(
        CaseRow::fcr(case_id, &artifact_ref)
            .origin(origin_id)
            .fabricated()
            .credential(credential_id)
            .reject(condition_id, diagnostic_class),
    );
}

fn build_fcr_with_entries(
    source: &Path,
    file_key: &FileKey,
    entries: &[RecipientEntry],
    ext_bytes: &[u8],
) -> BuiltFcr {
    build_fcr(source, file_key, entries, ext_bytes).expect("build crafted fcr")
}

/// A grammar-valid recipient entry for a type this build does not implement.
fn unknown_entry(critical: bool) -> RecipientEntry {
    RecipientEntry {
        type_name: UNKNOWN_RECIPIENT_TYPE.to_string(),
        recipient_flags: if critical {
            crate::recipient::entry::RECIPIENT_FLAG_CRITICAL
        } else {
            0
        },
        body: vec![0xAA; 64],
    }
}

// ─── Recipient framing ─────────────────────────────────────────────────────

fn write_recipient_framing_cases(
    corpus: &mut Corpus,
    sources: &Path,
    keys: &CorpusKeys,
    base: &MutationBase,
) {
    // Framing mutations of the single-entry passphrase artifact. The entry
    // header is `type_name_len(2) || recipient_flags(2) || body_len(4)`.
    mutate_fcr(
        corpus,
        base,
        "entry-type-name-len-zero",
        "passphrase-main",
        "entry_type_name_len_zero",
        "malformed_recipient_entry",
        |b| b[OFF_FIRST_ENTRY..OFF_FIRST_ENTRY + 2].copy_from_slice(&0u16.to_be_bytes()),
    );
    mutate_fcr(
        corpus,
        base,
        "entry-body-len-past-region",
        "passphrase-main",
        "entry_body_len_runs_past_recipient_region",
        "malformed_recipient_entry",
        |b| b[OFF_FIRST_ENTRY + 4..OFF_FIRST_ENTRY + 8].copy_from_slice(&0xFFFF_u32.to_be_bytes()),
    );
    mutate_fcr(
        corpus,
        base,
        "entry-reserved-flag-set",
        "passphrase-main",
        "entry_reserved_flag_bit_nonzero",
        "recipient_flags_reserved",
        |b| b[OFF_FIRST_ENTRY + 2] = 0x80,
    );
    mutate_fcr(
        corpus,
        base,
        "entry-type-name-malformed",
        "passphrase-main",
        "entry_type_name_violates_grammar",
        "malformed_type_name",
        |b| b[OFF_FIRST_ENTRY + 8] = 0x00,
    );

    // A single unknown non-critical recipient: nothing to try.
    let scope = case_scope("recipient-none-supported");
    crafted_reject_case(
        corpus,
        sources,
        "recipient-none-supported",
        "origin-recipient-none-supported",
        "passphrase-main",
        "no_recipient_of_a_supported_type",
        "no_supported_recipient",
        &FileKey::generate().expect("file key"),
        &[unknown_entry(false)],
        b"",
    );

    // An unknown critical recipient is capability-relative: an implementation
    // of that type stops rejecting it.
    drop(scope);
    let scope = case_scope("recipient-unknown-critical");
    let source = write_source(sources, "p", 64);
    let file_key = FileKey::generate().expect("file key");
    let entries = [unknown_entry(true), x25519_entry(&keys.public_a, &file_key)];
    let built = build_fcr_with_entries(&source, &file_key, &entries, b"");
    let artifact_ref =
        corpus.write_ref("artifacts/fcr/recipient-unknown-critical.fcr", &built.bytes);
    corpus.push_origin(OriginRow {
        origin_id: "origin-recipient-unknown-critical".to_string(),
        origin_kind: "fcr_payload",
        anchor_case_id: "recipient-unknown-critical".to_string(),
        payload_key_ref: "-".to_string(),
        payload_key_sha3_256: built.payload_key_sha3_256,
        stream_nonce_hex: built.stream_nonce_hex,
    });
    corpus.push_case(
        CaseRow::fcr("recipient-unknown-critical", &artifact_ref)
            .origin("origin-recipient-unknown-critical")
            .fabricated()
            .credential("private-key-a")
            .capability("recipient_type:test/unknown")
            .reject(
                "critical_recipient_type_unsupported",
                "unknown_critical_recipient",
            ),
    );

    // An unknown non-critical recipient beside a supported one is skipped, so
    // the file still decrypts.
    drop(scope);
    let scope = case_scope("recipient-unknown-ignorable-skipped");
    let file_key = FileKey::generate().expect("file key");
    let entries = [
        unknown_entry(false),
        x25519_entry(&keys.public_a, &file_key),
    ];
    let built = build_fcr_with_entries(&source, &file_key, &entries, b"");
    accept_fcr_case(
        corpus,
        "recipient-unknown-ignorable-skipped",
        "origin-recipient-unknown-ignorable",
        "private-key-a",
        &source,
        built,
    );

    drop(scope);

    // A type name of exactly the §3.3 maximum, on an entry the reader skips.
    // Paired with the over-maximum case, this fixes where the limit sits: a
    // reader that allowed one byte fewer would refuse a legal file.
    let scope = case_scope("recipient-type-name-at-max");
    let file_key = FileKey::generate().expect("file key");
    let mut longest = unknown_entry(false);
    longest.type_name = format!("test/{}", "u".repeat(TYPE_NAME_MAX_LEN - "test/".len()));
    assert_eq!(
        longest.type_name.len(),
        TYPE_NAME_MAX_LEN,
        "the name must land exactly on the grammar maximum"
    );
    let entries = [longest, x25519_entry(&keys.public_a, &file_key)];
    let built = build_fcr_with_entries(&source, &file_key, &entries, b"");
    accept_fcr_case(
        corpus,
        "recipient-type-name-at-max",
        "origin-recipient-type-name-at-max",
        "private-key-a",
        &source,
        built,
    );

    // §4.1 mixing policy: `argon2id` must appear alone.
    drop(scope);
    let scope = case_scope("recipient-illegal-mixing");
    let file_key = FileKey::generate().expect("file key");
    let entries = [
        argon2id_entry(&file_key),
        x25519_entry(&keys.public_a, &file_key),
    ];
    crafted_reject_case(
        corpus,
        sources,
        "recipient-illegal-mixing",
        "origin-recipient-illegal-mixing",
        "passphrase-main",
        "argon2id_mixed_with_another_recipient",
        "incompatible_recipients",
        &file_key,
        &entries,
        b"",
    );

    drop(scope);

    // §3.7 step 8 runs each of its two passes over every entry before it
    // reports, and settles between recipient types on the §4 registry index,
    // so the same two defective entries yield one class in either order. The
    // first pair fails the framing pass and the body-content pass, which the
    // framing pass wins; the second pair fails only body content, which the
    // lower registry index wins.
    for (case_id, condition_id, argon2id_first, x25519_body_short, class) in [
        (
            "recipient-step8-length-before-content-argon2id-first",
            "argon2id_kdf_invalid_and_x25519_body_short_argon2id_first",
            true,
            true,
            "malformed_recipient_entry",
        ),
        (
            "recipient-step8-length-before-content-x25519-first",
            "argon2id_kdf_invalid_and_x25519_body_short_x25519_first",
            false,
            true,
            "malformed_recipient_entry",
        ),
        (
            "recipient-step8-order-argon2id-first",
            "argon2id_kdf_invalid_and_x25519_ephemeral_zero_argon2id_first",
            true,
            false,
            "invalid_kdf_parameters",
        ),
        (
            "recipient-step8-order-x25519-first",
            "argon2id_kdf_invalid_and_x25519_ephemeral_zero_x25519_first",
            false,
            false,
            "invalid_kdf_parameters",
        ),
    ] {
        let _scope = case_scope(case_id);
        let file_key = FileKey::generate().expect("file key");
        let lanes_zero = KdfParams {
            lanes: 0,
            ..KdfParams::test_fast_default()
        };
        let bad_argon2id = argon2id_entry_with_kdf_params(&file_key, &lanes_zero);
        let mut bad_x25519 = x25519_entry(&keys.public_a, &file_key);
        if x25519_body_short {
            bad_x25519.body.pop();
        } else {
            bad_x25519.body[..x25519::PUBLIC_KEY_SIZE].fill(0);
        }
        let entries = if argon2id_first {
            [bad_argon2id, bad_x25519]
        } else {
            [bad_x25519, bad_argon2id]
        };
        crafted_reject_case(
            corpus,
            sources,
            case_id,
            &format!("origin-{case_id}"),
            "passphrase-main",
            condition_id,
            class,
            &file_key,
            &entries,
            b"",
        );
    }
}

// ─── Native recipient bodies ───────────────────────────────────────────────

/// Offset of a single recipient's body: the entry header plus its type name.
fn body_offset(type_name: &str) -> usize {
    OFF_FIRST_ENTRY + crate::recipient::entry::ENTRY_HEADER_SIZE + type_name.len()
}

/// Commits a copy of an already-published artifact as a new case, for a rule
/// exercised by a different credential rather than by different bytes.
fn recredential_case(
    corpus: &mut Corpus,
    base: &MutationBase,
    case_id: &str,
    credential_id: &str,
    condition_id: &str,
    diagnostic_class: &str,
) {
    let artifact_ref = corpus.write_ref(&format!("artifacts/fcr/{case_id}.fcr"), &base.bytes);
    corpus.push_case(
        CaseRow::fcr(case_id, &artifact_ref)
            .origin(&base.origin_id)
            .mutation_of(&base.case_id)
            .credential(credential_id)
            .reject(condition_id, diagnostic_class),
    );
}

fn write_argon2id_cases(corpus: &mut Corpus, sources: &Path, base: &MutationBase) {
    let body = body_offset(argon2id::TYPE_NAME);
    // §4.1 body: argon2_salt(32) || kdf_params(12) || wrap_nonce(24) ||
    // wrapped_file_key(48).
    let salt = body;
    let kdf = body + ARGON2_SALT_SIZE;
    let nonce = kdf + KDF_PARAMS_SIZE;
    let wrapped = nonce + WRAP_NONCE_SIZE;

    // §3.4 requires `recipient_flags = 0` on a native entry, so bit 0 is
    // rejected by the §3.7 step-8 framing check. That is a different rule from
    // the reserved bits 1..=15, which the §3.3 entry parse rejects, and the two
    // report different classes.
    mutate_fcr(
        corpus,
        base,
        "argon2id-critical-flag-set",
        "passphrase-main",
        "argon2id_native_entry_flags_nonzero",
        "malformed_recipient_entry",
        |b| b[OFF_FIRST_ENTRY + 3] = 0x01,
    );

    recredential_case(
        corpus,
        base,
        "argon2id-wrong-passphrase",
        "passphrase-wrong",
        "argon2id_wrong_passphrase",
        "recipient_unwrap_failed",
    );

    // Each authenticated body field tampered on its own. The recipient unwrap
    // runs before the header MAC (§3.7), so each surfaces as an unwrap
    // failure rather than as authentication of the header.
    for (case_id, offset, condition) in [
        ("argon2id-tamper-salt", salt, "argon2id_salt_modified"),
        (
            "argon2id-tamper-wrap-nonce",
            nonce,
            "argon2id_wrap_nonce_modified",
        ),
        (
            "argon2id-tamper-wrapped-file-key",
            wrapped,
            "argon2id_wrapped_file_key_modified",
        ),
    ] {
        mutate_fcr(
            corpus,
            base,
            case_id,
            "passphrase-main",
            condition,
            "recipient_unwrap_failed",
            |b| b[offset] ^= 0x01,
        );
    }

    // A structurally valid but different work factor still fails the unwrap,
    // because the stored parameters feed the derivation.
    mutate_fcr(
        corpus,
        base,
        "argon2id-tamper-kdf-params",
        "passphrase-main",
        "argon2id_kdf_params_modified",
        "recipient_unwrap_failed",
        // Lowest byte of `mem_cost`, so the tampered value stays inside the
        // §2.2 structural bounds and only the derivation can reject it.
        |b| b[kdf + 3] ^= 0x01,
    );

    mutate_fcr(
        corpus,
        base,
        "argon2id-body-len-invalid",
        "passphrase-main",
        "argon2id_body_length_not_116",
        "malformed_recipient_entry",
        |b| {
            let declared = OFF_FIRST_ENTRY + 4;
            let current =
                u32::from_be_bytes(b[declared..declared + 4].try_into().expect("body_len"));
            b[declared..declared + 4].copy_from_slice(&(current - 1).to_be_bytes());
            b.remove(wrapped);
            let entries_len = OFF_RECIPIENT_ENTRIES_LEN;
            let entries = u32::from_be_bytes(
                b[entries_len..entries_len + 4]
                    .try_into()
                    .expect("entries len"),
            );
            b[entries_len..entries_len + 4].copy_from_slice(&(entries - 1).to_be_bytes());
            let header_len = u32::from_be_bytes(
                b[OFF_HEADER_LEN..OFF_HEADER_LEN + 4]
                    .try_into()
                    .expect("header_len"),
            );
            b[OFF_HEADER_LEN..OFF_HEADER_LEN + 4].copy_from_slice(&(header_len - 1).to_be_bytes());
        },
    );

    // KDF-parameter cases are written before the header MAC, so the MAC stays
    // valid and only the parameter policy can reject them.
    for (case_id, params, condition, class) in [
        (
            "argon2id-kdf-lanes-zero",
            KdfParams {
                mem_cost: 19_456,
                time_cost: 1,
                lanes: 0,
            },
            "argon2id_lanes_below_structural_minimum",
            "invalid_kdf_parameters",
        ),
        (
            "argon2id-kdf-time-above-max",
            KdfParams {
                mem_cost: 19_456,
                time_cost: KdfLimit::TIME_COST_STRUCTURAL_MAX + 1,
                lanes: 1,
            },
            "argon2id_time_cost_above_structural_maximum",
            "invalid_kdf_parameters",
        ),
        (
            "argon2id-kdf-memory-above-max",
            KdfParams {
                mem_cost: KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX + 1,
                time_cost: 1,
                lanes: 1,
            },
            "argon2id_memory_cost_above_structural_maximum",
            "invalid_kdf_parameters",
        ),
        // The two local caps are driven apart. This one sits exactly on the
        // memory cap and passes it, so only the work product can reject it.
        (
            "argon2id-kdf-work-over-local-cap",
            KdfParams {
                mem_cost: KdfLimit::MEM_COST_KIB_DEFAULT,
                time_cost: 5,
                lanes: 1,
            },
            "argon2id_work_above_default_local_cap",
            "resource_cap_exceeded",
        ),
        // One KiB over the memory cap at the cheapest time cost, so the work
        // product stays far below its own cap and only memory can reject it.
        // The default memory cap is below the structural maximum, so this is a
        // policy refusal of a structurally valid file.
        (
            "argon2id-kdf-memory-over-local-cap",
            KdfParams {
                mem_cost: KdfLimit::MEM_COST_KIB_DEFAULT + 1,
                time_cost: 1,
                lanes: 1,
            },
            "argon2id_memory_above_default_local_cap",
            "resource_cap_exceeded",
        ),
    ] {
        let _scope = case_scope(case_id);
        let source = write_source(sources, "p", 64);
        let file_key = FileKey::generate().expect("file key");
        let entry = argon2id_entry_with_kdf_params(&file_key, &params);
        let built = build_fcr_with_entries(&source, &file_key, std::slice::from_ref(&entry), b"");
        let artifact_ref = corpus.write_ref(&format!("artifacts/fcr/{case_id}.fcr"), &built.bytes);
        let origin_id = format!("origin-{case_id}");
        corpus.push_origin(OriginRow {
            origin_id: origin_id.clone(),
            origin_kind: "fcr_payload",
            anchor_case_id: case_id.to_string(),
            payload_key_ref: "-".to_string(),
            payload_key_sha3_256: built.payload_key_sha3_256,
            stream_nonce_hex: built.stream_nonce_hex,
        });
        corpus.push_case(
            CaseRow::fcr(case_id, &artifact_ref)
                .origin(&origin_id)
                .fabricated()
                .credential("passphrase-main")
                .reject(condition, class),
        );
    }
}

/// The canonical, nonzero small-order ephemeral public value `FORMAT.md` §12.3
/// pins by literal bytes for the during-operation all-zero-shared-secret case.
///
/// It passes the credential-independent canonical/nonzero preflight, reaches
/// the X25519 operation, and produces the prohibited all-zero shared secret.
/// [`small_order_vector_reaches_the_during_operation_check`] proves that the
/// rejection comes from the agreement rather than from the preflight, which is
/// what §12.3 requires of crate-internal replay.
const SMALL_ORDER_EPHEMERAL: [u8; x25519::PUBLIC_KEY_SIZE] = [
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
    0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
];

/// `FORMAT.md` §12.3 requires crate-internal replay to prove the canonical
/// small-order vector reaches the during-X25519 all-zero-shared-secret check
/// rather than the zero-ephemeral preflight. Both halves are asserted here: the
/// §3.7 step-8 preflight accepts the body, and the agreement then rejects it.
#[test]
fn small_order_vector_reaches_the_during_operation_check() {
    let mut body = [0u8; x25519::BODY_LENGTH];
    body[..x25519::PUBLIC_KEY_SIZE].copy_from_slice(&SMALL_ORDER_EPHEMERAL);

    x25519::validate_body_preflight(&body)
        .expect("the pinned vector must pass the canonical/nonzero preflight");

    // Any clamped scalar drives the agreement to the identity, so the private
    // key here only has to be a well-formed one.
    let private_key = [0x77u8; x25519::PRIVATE_KEY_SIZE];
    match x25519::unwrap(&body, &private_key) {
        Err(CryptoError::InvalidFormat(crate::error::FormatDefect::MalformedRecipientEntry)) => {}
        other => panic!("expected the all-zero shared-secret rejection, got {other:?}"),
    }
}

fn write_x25519_cases(corpus: &mut Corpus, base: &MutationBase) {
    let body = body_offset(x25519::TYPE_NAME);
    // §4.2 body: ephemeral_public_key_bytes(32) || wrap_nonce(24) ||
    // wrapped_file_key(48).
    let ephemeral = body;
    let nonce = ephemeral + x25519::PUBLIC_KEY_SIZE;
    let wrapped = nonce + WRAP_NONCE_SIZE;

    recredential_case(
        corpus,
        base,
        "x25519-wrong-private-key",
        "private-key-b",
        "x25519_recipient_key_does_not_open_any_slot",
        "recipient_unwrap_failed",
    );

    // Each authenticated body field tampered on its own. Byte 0 of the
    // ephemeral keeps the §2.4 canonical encoding, so the case isolates the
    // key agreement rather than the encoding rule.
    for (case_id, offset, condition) in [
        (
            "x25519-tamper-ephemeral",
            ephemeral,
            "x25519_ephemeral_modified",
        ),
        (
            "x25519-tamper-wrap-nonce",
            nonce,
            "x25519_wrap_nonce_modified",
        ),
        (
            "x25519-tamper-wrapped-file-key",
            wrapped,
            "x25519_wrapped_file_key_modified",
        ),
    ] {
        mutate_fcr(
            corpus,
            base,
            case_id,
            "private-key-a",
            condition,
            "recipient_unwrap_failed",
            |b| b[offset] ^= 0x01,
        );
    }

    mutate_fcr(
        corpus,
        base,
        "x25519-ephemeral-all-zero",
        "private-key-a",
        "x25519_ephemeral_all_zero",
        "malformed_recipient_entry",
        |b| b[ephemeral..ephemeral + x25519::PUBLIC_KEY_SIZE].fill(0),
    );
    // High bit set: X25519 masks it, so only the §2.4 serialization rule can
    // refuse this encoding.
    mutate_fcr(
        corpus,
        base,
        "x25519-ephemeral-noncanonical",
        "private-key-a",
        "x25519_ephemeral_not_canonical_encoding",
        "malformed_recipient_entry",
        |b| b[ephemeral + x25519::PUBLIC_KEY_SIZE - 1] |= 0x80,
    );
    // §12.1 names this condition explicitly: canonical and nonzero, but the
    // agreement produces the prohibited all-zero shared secret.
    mutate_fcr(
        corpus,
        base,
        "x25519-small-order-ephemeral",
        "private-key-a",
        "x25519_all_zero_shared_secret",
        "malformed_recipient_entry",
        |b| {
            b[ephemeral..ephemeral + x25519::PUBLIC_KEY_SIZE]
                .copy_from_slice(&SMALL_ORDER_EPHEMERAL)
        },
    );

    // A body one byte short of the §4.2 length, with the entry, recipient
    // region, and header lengths all reduced to match.
    mutate_fcr(
        corpus,
        base,
        "x25519-body-len-invalid",
        "private-key-a",
        "x25519_body_length_not_104",
        "malformed_recipient_entry",
        |b| {
            let declared = OFF_FIRST_ENTRY + 4;
            let current =
                u32::from_be_bytes(b[declared..declared + 4].try_into().expect("body_len"));
            b[declared..declared + 4].copy_from_slice(&(current - 1).to_be_bytes());
            b.remove(wrapped);
            let entries = u32::from_be_bytes(
                b[OFF_RECIPIENT_ENTRIES_LEN..OFF_RECIPIENT_ENTRIES_LEN + 4]
                    .try_into()
                    .expect("entries len"),
            );
            b[OFF_RECIPIENT_ENTRIES_LEN..OFF_RECIPIENT_ENTRIES_LEN + 4]
                .copy_from_slice(&(entries - 1).to_be_bytes());
            let header_len = u32::from_be_bytes(
                b[OFF_HEADER_LEN..OFF_HEADER_LEN + 4]
                    .try_into()
                    .expect("header_len"),
            );
            b[OFF_HEADER_LEN..OFF_HEADER_LEN + 4].copy_from_slice(&(header_len - 1).to_be_bytes());
        },
    );
    mutate_fcr(
        corpus,
        base,
        "x25519-reserved-flag-set",
        "private-key-a",
        "x25519_reserved_flag_bit_nonzero",
        "recipient_flags_reserved",
        |b| b[OFF_FIRST_ENTRY + 2] = 0x40,
    );
    mutate_fcr(
        corpus,
        base,
        "x25519-critical-flag-set",
        "private-key-a",
        "x25519_native_entry_flags_nonzero",
        "malformed_recipient_entry",
        |b| b[OFF_FIRST_ENTRY + 3] = 0x01,
    );
}

// ─── Header TLV extension region ───────────────────────────────────────────

fn write_tlv_cases(corpus: &mut Corpus, sources: &Path) {
    use crate::crypto::tlv::tlv_bytes;

    // An unknown ignorable tag is authenticated, skipped, and the file still
    // decrypts (`FORMAT.md` §6 rule 6).
    let scope = case_scope("tlv-unknown-ignorable");
    let source = write_source(sources, "p", 64);
    let file_key = FileKey::generate().expect("file key");
    let entries = [argon2id_entry(&file_key)];
    let ext = tlv_bytes(0x0001, b"ignorable");
    let built = build_fcr_with_entries(&source, &file_key, &entries, &ext);
    accept_fcr_case(
        corpus,
        "tlv-unknown-ignorable",
        "origin-tlv-unknown-ignorable",
        "passphrase-main",
        &source,
        built,
    );

    let mut truncated_value = tlv_bytes(0x0001, b"");
    truncated_value[2..6].copy_from_slice(&99u32.to_be_bytes());

    let cases: [(&str, Vec<u8>, &str, &str); 7] = [
        (
            "tlv-reserved-tag-0000",
            tlv_bytes(0x0000, b"x"),
            "tlv_tag_reserved",
            "malformed_tlv",
        ),
        (
            "tlv-reserved-tag-8000",
            tlv_bytes(0x8000, b"x"),
            "tlv_tag_reserved",
            "malformed_tlv",
        ),
        (
            "tlv-duplicate-tags",
            [tlv_bytes(0x0001, b"a"), tlv_bytes(0x0001, b"b")].concat(),
            "tlv_tags_not_strictly_ascending",
            "malformed_tlv",
        ),
        (
            "tlv-out-of-order-tags",
            [tlv_bytes(0x0002, b"a"), tlv_bytes(0x0001, b"b")].concat(),
            "tlv_tags_not_strictly_ascending",
            "malformed_tlv",
        ),
        (
            "tlv-truncated-entry-header",
            vec![0x00, 0x01, 0x00],
            "tlv_entry_header_truncated",
            "malformed_tlv",
        ),
        (
            "tlv-value-runs-past-region",
            truncated_value,
            "tlv_value_runs_past_region",
            "malformed_tlv",
        ),
        (
            "tlv-value-above-cap",
            {
                let mut entry = tlv_bytes(0x0001, b"");
                entry[2..6].copy_from_slice(&(crate::format::EXT_LEN_MAX + 1).to_be_bytes());
                entry
            },
            "tlv_declared_value_above_cap",
            "malformed_tlv",
        ),
    ];
    drop(scope);
    for (case_id, ext_bytes, condition, class) in cases {
        let _scope = case_scope(case_id);
        let file_key = FileKey::generate().expect("file key");
        let entries = [argon2id_entry(&file_key)];
        crafted_reject_case(
            corpus,
            sources,
            case_id,
            &format!("origin-{case_id}"),
            "passphrase-main",
            condition,
            class,
            &file_key,
            &entries,
            &ext_bytes,
        );
    }

    // A declared value length of zero, which leaves the region ending exactly
    // on an entry header. A reader that required at least one value byte, or
    // that demanded more than a bare header remain, would refuse this.
    let scope = case_scope("tlv-empty-value");
    let source = write_source(sources, "p", 64);
    let file_key = FileKey::generate().expect("file key");
    let entries = [argon2id_entry(&file_key)];
    let built = build_fcr_with_entries(&source, &file_key, &entries, &tlv_bytes(0x0001, b""));
    accept_fcr_case(
        corpus,
        "tlv-empty-value",
        "origin-tlv-empty-value",
        "passphrase-main",
        &source,
        built,
    );
    drop(scope);

    // An unknown critical tag is capability-relative: implementing the tag
    // stops the rejection (`FORMAT.md` §12.2).
    let scope = case_scope("tlv-unknown-critical");
    let source = write_source(sources, "p", 64);
    let file_key = FileKey::generate().expect("file key");
    let entries = [argon2id_entry(&file_key)];
    let built = build_fcr_with_entries(&source, &file_key, &entries, &tlv_bytes(0x8001, b"x"));
    let artifact_ref = corpus.write_ref("artifacts/fcr/tlv-unknown-critical.fcr", &built.bytes);
    corpus.push_origin(OriginRow {
        origin_id: "origin-tlv-unknown-critical".to_string(),
        origin_kind: "fcr_payload",
        anchor_case_id: "tlv-unknown-critical".to_string(),
        payload_key_ref: "-".to_string(),
        payload_key_sha3_256: built.payload_key_sha3_256,
        stream_nonce_hex: built.stream_nonce_hex,
    });
    corpus.push_case(
        CaseRow::fcr("tlv-unknown-critical", &artifact_ref)
            .origin("origin-tlv-unknown-critical")
            .fabricated()
            .credential("passphrase-main")
            .capability("outer_tlv:0x8001")
            .reject("tlv_critical_tag_unsupported", "unknown_critical_tlv"),
    );
    drop(scope);
}

// ─── Payload STREAM ────────────────────────────────────────────────────────

/// Encodes `plaintext` as a STREAM-BE32 payload. With `empty_trailer` the last
/// full chunk is committed as non-final and an empty final chunk is appended —
/// the transcript `FORMAT.md` §5 forbids a writer to emit and requires a
/// reader to refuse.
fn encode_payload(
    payload_key: &crate::crypto::keys::PayloadKey,
    stream_nonce: &[u8; STREAM_NONCE_SIZE],
    plaintext: &[u8],
    empty_trailer: bool,
) -> Vec<u8> {
    use chacha20poly1305::{
        XChaCha20Poly1305,
        aead::{KeyInit as AeadKeyInit, stream},
    };
    let cipher = XChaCha20Poly1305::new(payload_key.expose().into());
    let mut encryptor = stream::EncryptorBE32::from_aead(cipher, stream_nonce.into());
    let mut out = Vec::new();
    let chunk = crate::crypto::stream::BUFFER_SIZE;
    assert!(
        !empty_trailer || (!plaintext.is_empty() && plaintext.len().is_multiple_of(chunk)),
        "an empty trailer is only the forbidden transcript after an exact multiple of the chunk size"
    );
    let mut offset = 0;
    loop {
        let take = chunk.min(plaintext.len() - offset);
        let piece = &plaintext[offset..offset + take];
        offset += take;
        let final_chunk = offset == plaintext.len() && !empty_trailer;
        let mut buffer = piece.to_vec();
        if final_chunk {
            encryptor
                .encrypt_last_in_place(b"", &mut buffer)
                .expect("encrypt final chunk");
            out.extend_from_slice(&buffer);
            break;
        }
        encryptor
            .encrypt_next_in_place(b"", &mut buffer)
            .expect("encrypt chunk");
        out.extend_from_slice(&buffer);
        if offset == plaintext.len() {
            let mut trailer = Vec::new();
            encryptor
                .encrypt_last_in_place(b"", &mut trailer)
                .expect("encrypt empty trailer");
            out.extend_from_slice(&trailer);
            break;
        }
    }
    out
}

fn write_payload_stream_cases(corpus: &mut Corpus, sources: &Path) {
    // A two-chunk plaintext, so a chunk-boundary cut leaves a complete frame.
    let scope = case_scope("payload-two-chunk-valid");
    let source = write_source(sources, "p", crate::crypto::stream::BUFFER_SIZE * 2);
    let file_key = FileKey::generate().expect("file key");
    let entries = [argon2id_entry(&file_key)];

    let mut fca = Vec::new();
    fca = crate::archive::prepare_archive(&source, ArchiveLimits::default())
        .expect("prepare archive")
        .write_to(fca)
        .expect("serialize fca payload");

    let (built, stream_nonce_hex, payload_key_digest) = craft_header(&file_key, &entries, b"");
    let honest = encode_payload(&built.payload_key, &built.stream_nonce, &fca, false);
    let bytes = assemble_fcr(&built, &honest);
    let head = bytes.len() - honest.len();

    let artifact_ref = corpus.write_ref("artifacts/fcr/payload-two-chunk-valid.fcr", &bytes);
    let expected_ref = corpus.write_ref(
        "expected/plaintext/payload-two-chunk-valid.bin",
        &fs::read(&source).expect("read source"),
    );
    corpus.push_origin(OriginRow {
        origin_id: "origin-payload-two-chunk".to_string(),
        origin_kind: "fcr_payload",
        anchor_case_id: "payload-two-chunk-valid".to_string(),
        payload_key_ref: "-".to_string(),
        payload_key_sha3_256: payload_key_digest,
        stream_nonce_hex,
    });
    corpus.push_case(
        CaseRow::fcr("payload-two-chunk-valid", &artifact_ref)
            .origin("origin-payload-two-chunk")
            .fabricated()
            .credential("passphrase-main")
            .accept(&expected_ref),
    );

    let base = MutationBase {
        case_id: "payload-two-chunk-valid".to_string(),
        origin_id: "origin-payload-two-chunk".to_string(),
        bytes: bytes.clone(),
    };

    mutate_fcr(
        corpus,
        &base,
        "payload-chunk-tampered",
        "passphrase-main",
        "payload_chunk_ciphertext_modified",
        "payload_authentication_failed",
        |b| {
            let at = head + 8;
            b[at] ^= 0x01;
        },
    );
    // A cut that leaves no payload byte at all: the stream carries no chunk to
    // authenticate, which is the only shape that reaches `payload_truncated`.
    mutate_fcr(
        corpus,
        &base,
        "payload-region-empty",
        "passphrase-main",
        "payload_region_carries_no_chunk",
        "payload_truncated",
        |b| b.truncate(head),
    );
    // A cut at an exact chunk boundary leaves a complete frame that was sealed
    // as non-final. A reader cannot tell that from a tampered tail, so §12.1's
    // authentication class is the outcome, not `payload_truncated`.
    mutate_fcr(
        corpus,
        &base,
        "payload-cut-at-chunk-boundary",
        "passphrase-main",
        "payload_cut_at_chunk_boundary",
        "payload_authentication_failed",
        |b| {
            let frame = crate::crypto::stream::BUFFER_SIZE + crate::crypto::aead::TAG_SIZE;
            b.truncate(head + frame);
        },
    );
    // Appended bytes extend the final frame or turn it into a non-final one;
    // either way the AEAD refuses before any end-of-payload rule applies.
    mutate_fcr(
        corpus,
        &base,
        "payload-trailing-bytes",
        "passphrase-main",
        "payload_bytes_appended_after_final_chunk",
        "payload_authentication_failed",
        |b| b.extend_from_slice(&[0xAA; 16]),
    );

    // A writer must not append an empty final chunk after non-empty plaintext,
    // and a reader must reject one (`FORMAT.md` §5). The transcript only takes
    // that shape when the plaintext ends exactly on a chunk boundary, so this
    // case uses a source sized to make the FCA payload exactly one chunk.
    let exact_source = write_source(
        sources,
        "p",
        crate::crypto::stream::BUFFER_SIZE - fca_overhead("p"),
    );
    drop(scope);
    let scope = case_scope("payload-empty-final-after-data");
    let mut exact_fca = Vec::new();
    exact_fca = crate::archive::prepare_archive(&exact_source, ArchiveLimits::default())
        .expect("prepare archive")
        .write_to(exact_fca)
        .expect("serialize fca payload");
    let file_key = FileKey::generate().expect("file key");
    let entries = [argon2id_entry(&file_key)];
    let (built, stream_nonce_hex, payload_key_digest) = craft_header(&file_key, &entries, b"");
    let forbidden = encode_payload(&built.payload_key, &built.stream_nonce, &exact_fca, true);
    let bytes = assemble_fcr(&built, &forbidden);
    let artifact_ref = corpus.write_ref("artifacts/fcr/payload-empty-final-after-data.fcr", &bytes);
    corpus.push_origin(OriginRow {
        origin_id: "origin-payload-empty-final".to_string(),
        origin_kind: "fcr_payload",
        anchor_case_id: "payload-empty-final-after-data".to_string(),
        payload_key_ref: "-".to_string(),
        payload_key_sha3_256: payload_key_digest,
        stream_nonce_hex,
    });
    corpus.push_case(
        CaseRow::fcr("payload-empty-final-after-data", &artifact_ref)
            .origin("origin-payload-empty-final")
            .fabricated()
            .credential("passphrase-main")
            .reject(
                "payload_empty_final_chunk_after_data",
                "malformed_payload_stream",
            ),
    );
    drop(scope);
}

// ─── Key files ─────────────────────────────────────────────────────────────

/// Commits a `public.key` case. Acceptance records the decoded 32-byte X25519
/// key material, so a replay proves what was decoded rather than only that
/// decoding succeeded.
fn public_key_case(
    corpus: &mut Corpus,
    case_id: &str,
    bytes: &[u8],
    outcome: Result<[u8; 32], (&str, &str)>,
) {
    let artifact_ref =
        corpus.write_ref(&format!("artifacts/public-key/{case_id}.public.key"), bytes);
    let row = CaseRow::new(case_id, "public_key_decode", &artifact_ref)
        .fabricated()
        .credential("none");
    let row = match outcome {
        Ok(material) => {
            let expected_ref =
                corpus.write_ref(&format!("expected/public-key/{case_id}.bin"), &material);
            row.accept(&expected_ref)
        }
        Err((condition, class)) => row.reject(condition, class),
    };
    corpus.push_case(row);
}

fn write_public_key_cases(corpus: &mut Corpus, keys: &CorpusKeys) {
    use crate::key::public::{encode_recipient_payload_with_hrp, recipient_payload_for_tests};

    let canonical = keys.public_a.clone();
    let material = decode_public_key_file(&canonical)
        .to_x25519_bytes()
        .expect("decode canonical public key");
    let text = String::from_utf8(canonical.clone()).expect("public.key is UTF-8");
    let recipient = text.trim_end_matches('\n').to_string();

    public_key_case(corpus, "public-key-canonical", &canonical, Ok(material));
    // §7.1 allows exactly one optional trailing LF, so the same string without
    // it decodes to the same material.
    public_key_case(
        corpus,
        "public-key-without-trailing-lf",
        recipient.as_bytes(),
        Ok(material),
    );

    // The typed payload behind the canonical string. Two cases below re-encode
    // it so their Bech32 checksum is valid and the rule they name is the only
    // one that can reject them.
    let payload = recipient_payload_for_tests(
        crate::format::WRITER_KEYPAIR_SUITE.public_key_version(),
        "x25519",
        &material,
    )
    .expect("build the canonical recipient payload");

    let reject = |s: String| -> Vec<u8> { s.into_bytes() };
    let cases: [(&str, Vec<u8>, &str, &str); 8] = [
        (
            "public-key-checksum-corrupted",
            reject({
                let mut s = recipient.clone();
                let last = s.pop().expect("recipient is nonempty");
                let replacement = if last == 'q' { 'p' } else { 'q' };
                s.push(replacement);
                s
            }),
            "public_key_bech32_checksum_mismatch",
            "malformed_public_key",
        ),
        (
            "public-key-uppercase",
            reject(recipient.to_uppercase()),
            "public_key_not_canonical_lowercase",
            "malformed_public_key",
        ),
        (
            "public-key-leading-whitespace",
            reject(format!(" {recipient}")),
            "public_key_surrounding_whitespace",
            "malformed_public_key",
        ),
        (
            "public-key-two-trailing-newlines",
            reject(format!("{recipient}\n\n")),
            "public_key_more_than_one_trailing_newline",
            "malformed_public_key",
        ),
        (
            "public-key-empty",
            Vec::new(),
            "public_key_file_empty",
            "malformed_public_key",
        ),
        (
            "public-key-wrong-hrp",
            reject(
                encode_recipient_payload_with_hrp("xyz", &payload)
                    .expect("encode under a different human-readable part"),
            ),
            "public_key_human_readable_part_not_fcr",
            "malformed_public_key",
        ),
        (
            "public-key-internal-checksum-corrupted",
            reject({
                // The Bech32 checksum stays valid, so only the internal
                // SHA3-256 payload checksum of `FORMAT.md` §7.1 can reject it.
                let mut corrupted = payload.clone();
                *corrupted.last_mut().expect("payload is nonempty") ^= 0x01;
                encode_recipient_payload_with_hrp("fcr", &corrupted)
                    .expect("re-encode the corrupted payload")
            }),
            "public_key_internal_checksum_mismatch",
            "malformed_public_key",
        ),
        (
            "public-key-truncated",
            reject(recipient[..recipient.len() - 8].to_string()),
            "public_key_string_truncated",
            "malformed_public_key",
        ),
    ];
    for (case_id, bytes, condition, class) in cases {
        public_key_case(corpus, case_id, &bytes, Err((condition, class)));
    }

    write_public_key_version_cases(corpus);
    write_public_key_material_cases(corpus);
}

/// `public_key_version` evidence (`FORMAT.md` §11.2): the reserved `0x00`
/// encoding is malformed for every implementation, while an encoding from a
/// suite this release does not define is capability-relative — an
/// implementation that adds the suite legitimately accepts it.
fn write_public_key_version_cases(corpus: &mut Corpus) {
    use crate::key::public::encode_recipient_string_with_version;

    let material = [7u8; x25519::PUBLIC_KEY_SIZE];
    let reserved = encode_recipient_string_with_version(0x00, "x25519", &material)
        .expect("encode reserved public-key version");
    public_key_case(
        corpus,
        "public-key-version-zero",
        format!("{reserved}\n").as_bytes(),
        Err(("public_key_version_reserved_zero", "malformed_public_key")),
    );

    let newer = encode_recipient_string_with_version(0x02, "x25519", &material)
        .expect("encode newer public-key version");
    let artifact_ref = corpus.write_ref(
        "artifacts/public-key/public-key-newer-version.public.key",
        format!("{newer}\n").as_bytes(),
    );
    corpus.push_case(
        CaseRow::new(
            "public-key-newer-version",
            "public_key_decode",
            &artifact_ref,
        )
        .fabricated()
        .credential("none")
        .capability("public_key_version:0x02")
        .reject(
            "public_key_version_not_supported",
            "unsupported_public_key_version",
        ),
    );

    // A well-formed string for a recipient type this release does not
    // implement. The grammar, checksum, and suite gates all pass, so it is an
    // unsupported type rather than a malformed key.
    let unsupported = encode_recipient_string_with_version(
        crate::key::public::PUBLIC_KEY_VERSION,
        "test/future-kem",
        &material,
    )
    .expect("encode unsupported key type");
    let artifact_ref = corpus.write_ref(
        "artifacts/public-key/public-key-unsupported-type.public.key",
        format!("{unsupported}\n").as_bytes(),
    );
    corpus.push_case(
        CaseRow::new(
            "public-key-unsupported-type",
            "public_key_decode",
            &artifact_ref,
        )
        .fabricated()
        .credential("none")
        .capability("key_type:test/future-kem")
        .reject("public_key_type_not_supported", "unsupported_key_type"),
    );
}

/// X25519 key-material evidence (`FORMAT.md` §7.2): the canonical range is
/// accepted and every RFC 7748 alias is refused rather than reduced, so one
/// curve point can never carry two recipient strings or two fingerprints.
fn write_public_key_material_cases(corpus: &mut Corpus) {
    use crate::key::public::encode_recipient_string_unchecked;

    // The field prime is `2^255 - 19` little-endian; the canonical range ends
    // one below it, and everything from it upwards is an alias.
    let offset_from_prime = |offset: i8| {
        let mut bytes = x25519::FIELD_PRIME_LE;
        bytes[0] = bytes[0].wrapping_add_signed(offset);
        bytes
    };
    let below_prime = offset_from_prime(-1);
    // The largest value 255 bits can hold, `2^255 - 1`: every byte set except
    // the top bit of the last.
    let mut max_255_bit = [0xFFu8; x25519::PUBLIC_KEY_SIZE];
    max_255_bit[x25519::PUBLIC_KEY_SIZE - 1] = 0x7F;
    // The same value with bit 255 set. RFC 7748 lets an implementation ignore
    // that bit during the operation; `FORMAT.md` §7.2 refuses the encoding
    // outright, so one curve point cannot carry two recipient strings.
    let high_bit_set = [0xFFu8; x25519::PUBLIC_KEY_SIZE];

    // The largest canonical value: one below the prime, and so accepted.
    let canonical = encode_recipient_string_unchecked("x25519", &below_prime)
        .expect("encode largest canonical material");
    public_key_case(
        corpus,
        "public-key-material-field-prime-minus-one",
        format!("{canonical}\n").as_bytes(),
        Ok(below_prime),
    );

    let rejected: [(&str, [u8; x25519::PUBLIC_KEY_SIZE], &str); 5] = [
        (
            "public-key-material-all-zero",
            [0u8; x25519::PUBLIC_KEY_SIZE],
            "public_key_material_all_zero",
        ),
        (
            "public-key-material-field-prime",
            offset_from_prime(0),
            "public_key_material_not_canonical",
        ),
        (
            "public-key-material-field-prime-plus-one",
            offset_from_prime(1),
            "public_key_material_not_canonical",
        ),
        (
            "public-key-material-max-255-bit",
            max_255_bit,
            "public_key_material_not_canonical",
        ),
        (
            "public-key-material-high-bit-set",
            high_bit_set,
            "public_key_material_high_bit_not_masked",
        ),
    ];
    for (case_id, material, condition) in rejected {
        let text = encode_recipient_string_unchecked("x25519", &material)
            .expect("encode noncanonical material");
        public_key_case(
            corpus,
            case_id,
            format!("{text}\n").as_bytes(),
            Err((condition, "malformed_public_key")),
        );
    }

    // X25519 material is exactly 32 bytes; a shorter payload passes the
    // grammar and checksum and fails on the material rule.
    let short = encode_recipient_string_unchecked("x25519", &[9u8; 31])
        .expect("encode undersized material");
    public_key_case(
        corpus,
        "public-key-material-wrong-length",
        format!("{short}\n").as_bytes(),
        Err(("public_key_material_not_32_bytes", "malformed_public_key")),
    );
}

/// `private.key` extension, pair-consistency, and cap evidence (`FORMAT.md`
/// §8 and §12.3). Every case here is replayed through the unlock rather than
/// the structural validator, which applies neither the caller's resource
/// policy nor the AEAD: the extension and pair cases need the unwrap, and the
/// cap cases are refused before it.
fn write_private_key_ext_and_pair_cases(corpus: &mut Corpus, keys: &CorpusKeys, canonical: &[u8]) {
    use crate::crypto::tlv::tlv_bytes;
    use crate::key::private::{KDF_PARAMS_OFFSET, seal_private_key_unchecked_tlv};

    let opened = x25519::open_x25519_key_file(
        &corpus.root.join(&keys.private_a),
        &corpus_passphrase(),
        None,
        crate::KeyReadLimits::default(),
        &|_| {},
    )
    .expect("open corpus private key");
    let seal = |case_id: &str, ext_bytes: &[u8], public_material: &[u8]| {
        let _scope = case_scope(case_id);
        seal_private_key_unchecked_tlv(
            opened.secret.as_slice(),
            "x25519",
            public_material,
            ext_bytes,
            &corpus_passphrase(),
            &KdfParams::test_fast_default(),
        )
        .expect("seal private key")
    };

    // An ignorable tag is authenticated as associated data, skipped, and the
    // key still opens (`FORMAT.md` §6).
    private_key_open_case(
        corpus,
        "private-key-ext-ignorable",
        &seal(
            "private-key-ext-ignorable",
            &tlv_bytes(0x0001, b"ignorable"),
            &opened.public,
        ),
        "private-key-a",
        Ok(opened.public),
    );
    let critical_ref = corpus.write_ref(
        "artifacts/private-key/private-key-ext-unknown-critical.private.key",
        &seal(
            "private-key-ext-unknown-critical",
            &tlv_bytes(0x8001, b"critical"),
            &opened.public,
        ),
    );
    corpus.push_case(
        CaseRow::new(
            "private-key-ext-unknown-critical",
            "private_key_open",
            &critical_ref,
        )
        .fabricated()
        .credential("private-key-a")
        .capability("private_key_tlv:0x8001")
        .reject(
            "private_key_ext_unknown_critical_tag",
            "unknown_critical_tlv",
        ),
    );
    // A value length that runs past the region end.
    let mut malformed = tlv_bytes(0x0001, b"value");
    malformed.truncate(malformed.len() - 2);
    private_key_open_case(
        corpus,
        "private-key-ext-malformed",
        &seal("private-key-ext-malformed", &malformed, &opened.public),
        "private-key-a",
        Err(("private_key_ext_value_runs_past_region", "malformed_tlv")),
    );

    // `FORMAT.md` §8: a reader recomputes `X25519(secret_material, basepoint)`
    // and refuses a file whose stored public material is a different key, even
    // though the AEAD authenticated both halves.
    let other = decode_public_key_file(&keys.public_b)
        .to_x25519_bytes()
        .expect("decode the other corpus public key");
    private_key_open_case(
        corpus,
        "private-key-public-secret-mismatch",
        &seal("private-key-public-secret-mismatch", b"", &other),
        "private-key-a",
        Err((
            "private_key_public_material_not_derived_from_secret",
            "malformed_private_key",
        )),
    );

    // The wrapped-secret cap is a reader policy, and the writer refuses to
    // seal past it, so the artifact declares an oversized length directly.
    use crate::key::private::{
        EXT_LEN_OFFSET, PRIVATE_KEY_HEADER_FIXED_SIZE, PUBLIC_LEN_OFFSET, TYPE_NAME_LEN_OFFSET,
        WRAPPED_SECRET_LEN_OFFSET,
    };
    let over_cap_len = crate::KeyReadLimits::PRIVATE_KEY_WRAPPED_SECRET_LEN_DEFAULT + 1;
    let mut over_cap = canonical.to_vec();
    let u16_at = |bytes: &[u8], at: usize| -> usize {
        usize::from(u16::from_be_bytes(
            bytes[at..at + 2].try_into().expect("two bytes"),
        ))
    };
    let u32_at = |bytes: &[u8], at: usize| -> usize {
        u32::from_be_bytes(bytes[at..at + 4].try_into().expect("four bytes")) as usize
    };
    // The declared bytes must be present, so the cap is what rejects the file
    // rather than a short read. Every variable-length field counts.
    let declared = PRIVATE_KEY_HEADER_FIXED_SIZE
        + u16_at(&over_cap, TYPE_NAME_LEN_OFFSET)
        + u32_at(&over_cap, PUBLIC_LEN_OFFSET)
        + u32_at(&over_cap, EXT_LEN_OFFSET)
        + over_cap_len as usize;
    over_cap[WRAPPED_SECRET_LEN_OFFSET..WRAPPED_SECRET_LEN_OFFSET + 4]
        .copy_from_slice(&over_cap_len.to_be_bytes());
    over_cap.resize(declared, 0);
    private_key_open_case(
        corpus,
        "private-key-wrapped-secret-over-default-cap",
        &over_cap,
        "private-key-a",
        Err((
            "private_key_wrapped_secret_over_local_cap",
            "resource_cap_exceeded",
        )),
    );

    // The unlock applies the same KDF resource policy a `.fcr` recipient body
    // gets. One KiB over the memory cap at the cheapest time cost keeps the
    // work product far below its own cap, so only memory can reject the file,
    // and the cap is checked before Argon2id runs.
    let mut over_memory_cap = canonical.to_vec();
    over_memory_cap[KDF_PARAMS_OFFSET..KDF_PARAMS_OFFSET + KDF_PARAMS_SIZE].copy_from_slice(
        &KdfParams {
            mem_cost: KdfLimit::MEM_COST_KIB_DEFAULT + 1,
            time_cost: 1,
            lanes: 1,
        }
        .to_bytes(),
    );
    private_key_open_case(
        corpus,
        "private-key-kdf-memory-over-default-cap",
        &over_memory_cap,
        "private-key-a",
        Err((
            "private_key_argon2id_memory_above_default_local_cap",
            "resource_cap_exceeded",
        )),
    );

    // The other reachable KDF cap on this artifact: memory exactly on its cap
    // and a time cost that carries the product past the work cap, so the two
    // caps are evidenced apart here as they are on an `argon2id` body.
    let mut over_work_cap = canonical.to_vec();
    over_work_cap[KDF_PARAMS_OFFSET..KDF_PARAMS_OFFSET + KDF_PARAMS_SIZE].copy_from_slice(
        &KdfParams {
            mem_cost: KdfLimit::MEM_COST_KIB_DEFAULT,
            time_cost: 5,
            lanes: 1,
        }
        .to_bytes(),
    );
    private_key_open_case(
        corpus,
        "private-key-kdf-work-over-default-cap",
        &over_work_cap,
        "private-key-a",
        Err((
            "private_key_argon2id_work_above_default_local_cap",
            "resource_cap_exceeded",
        )),
    );
}

/// One rejection case built by editing bytes: the identifier, the edit that
/// produces it, the condition it isolates, and its diagnostic class.
type ByteMutationCase = (
    &'static str,
    Box<dyn Fn(&mut Vec<u8>)>,
    &'static str,
    &'static str,
);

/// Commits a `private.key` case. Every case here is a rejection, checked
/// through the structural validator, which needs no credential.
fn private_key_case(
    corpus: &mut Corpus,
    case_id: &str,
    bytes: &[u8],
    condition_id: &str,
    diagnostic_class: &str,
) {
    let artifact_ref = corpus.write_ref(
        &format!("artifacts/private-key/{case_id}.private.key"),
        bytes,
    );
    corpus.push_case(
        CaseRow::new(case_id, "private_key_validate", &artifact_ref)
            .fabricated()
            .credential("none")
            .reject(condition_id, diagnostic_class),
    );
}

fn write_private_key_cases(corpus: &mut Corpus, keys: &CorpusKeys) {
    use crate::key::private::{
        KDF_PARAMS_OFFSET, KIND_OFFSET, PRIVATE_KEY_HEADER_FIXED_SIZE, TYPE_NAME_LEN_OFFSET,
        VERSION_OFFSET,
    };

    let canonical = fs::read(corpus.root.join(&keys.private_a)).expect("read private key");

    // §8 fixed header: magic(4) || version(1) || kind(1) || key_flags(2) || …
    let mutations: [ByteMutationCase; 7] = [
        (
            "private-key-bad-magic",
            Box::new(|b: &mut Vec<u8>| b[0] ^= 0xFF),
            "private_key_magic_mismatch",
            "not_a_key_file",
        ),
        (
            "private-key-version-zero",
            Box::new(|b: &mut Vec<u8>| b[VERSION_OFFSET] = 0x00),
            "private_key_version_reserved_zero",
            "malformed_private_key",
        ),
        (
            "private-key-wrong-kind",
            Box::new(|b: &mut Vec<u8>| b[KIND_OFFSET] = 0x45),
            "private_key_kind_not_private_key",
            "wrong_kind",
        ),
        (
            "private-key-key-flags-nonzero",
            Box::new(|b: &mut Vec<u8>| b[7] = 0x01),
            "private_key_flags_nonzero",
            "malformed_private_key",
        ),
        (
            "private-key-truncated",
            Box::new(|b: &mut Vec<u8>| {
                b.truncate(40);
            }),
            "private_key_ends_before_declared_fields",
            "malformed_private_key",
        ),
        (
            "private-key-trailing-data",
            Box::new(|b: &mut Vec<u8>| b.extend_from_slice(&[0xAA; 8])),
            "private_key_bytes_follow_declared_fields",
            "malformed_private_key",
        ),
        // `private.key` stores its own `kdf_params`, held to the same §2.2
        // bounds as an `argon2id` recipient body. The check runs while the
        // cleartext header is parsed, so it precedes the unlock and needs no
        // passphrase.
        (
            "private-key-kdf-memory-above-max",
            Box::new(|b: &mut Vec<u8>| {
                b[KDF_PARAMS_OFFSET..KDF_PARAMS_OFFSET + size_of::<u32>()]
                    .copy_from_slice(&(KdfLimit::MEM_COST_KIB_STRUCTURAL_MAX + 1).to_be_bytes());
            }),
            "private_key_argon2id_memory_cost_above_structural_maximum",
            "invalid_kdf_parameters",
        ),
    ];
    for (case_id, mutate, condition, class) in mutations {
        let mut bytes = canonical.clone();
        mutate(&mut bytes);
        assert_ne!(bytes, canonical, "{case_id}: mutation changed nothing");
        private_key_case(corpus, case_id, &bytes, condition, class);
    }

    // A newer private-key encoding version is capability-relative.
    let mut newer = canonical.clone();
    newer[VERSION_OFFSET] = 0x02;
    let artifact_ref = corpus.write_ref(
        "artifacts/private-key/private-key-newer-version.private.key",
        &newer,
    );
    corpus.push_case(
        CaseRow::new(
            "private-key-newer-version",
            "private_key_validate",
            &artifact_ref,
        )
        .fabricated()
        .credential("none")
        .capability("private_key_version:0x02")
        .reject(
            "private_key_version_unsupported",
            "unsupported_private_key_version",
        ),
    );

    // A `public.key` handed to the private-key reader is a recognized key
    // artifact of the wrong form (§12.1 `wrong_key_file_type`).
    let public = keys.public_a.clone();
    private_key_case(
        corpus,
        "private-key-given-public-key-file",
        &public,
        "private_key_reader_given_public_key_file",
        "wrong_key_file_type",
    );

    write_private_key_ext_and_pair_cases(corpus, keys, &canonical);

    // Opening the key decodes its public half, which is the byte-exact record
    // §12.3 requires of an accepted key case. `FORMAT.md` §8 makes a reader
    // reject a file whose stored public material is not the one the secret
    // derives, so this value is evidence about the pair, not only the file.
    let material = decode_public_key_file(&keys.public_a)
        .to_x25519_bytes()
        .expect("decode paired public key");
    private_key_open_case(
        corpus,
        "private-key-open-canonical",
        &canonical,
        "private-key-a",
        Ok(material),
    );
    private_key_open_case(
        corpus,
        "private-key-wrong-passphrase",
        &canonical,
        "private-key-a-wrong-unlock",
        Err((
            "private_key_wrong_unlock_passphrase",
            "private_key_unlock_failed",
        )),
    );

    // The cleartext fields are bound as AEAD associated data and the wrapped
    // secret by the tag, so a change to either fails the same way a wrong
    // passphrase does — the AEAD cannot tell them apart (`FORMAT.md` §8).
    // The byte comes from `public_material`, which is neither a KDF input nor
    // the nonce, so only the associated-data binding can reject it: a reader
    // that bound no cleartext would open the file and fail the §8 derivation
    // check instead, which is a different verdict.
    let mut aad_tampered = canonical.clone();
    let public_material_at = PRIVATE_KEY_HEADER_FIXED_SIZE
        + usize::from(u16::from_be_bytes(
            canonical[TYPE_NAME_LEN_OFFSET..TYPE_NAME_LEN_OFFSET + 2]
                .try_into()
                .expect("type_name_len"),
        ));
    aad_tampered[public_material_at] ^= 0x01;
    private_key_open_case(
        corpus,
        "private-key-cleartext-aad-tampered",
        &aad_tampered,
        "private-key-a",
        Err((
            "private_key_cleartext_aad_modified",
            "private_key_unlock_failed",
        )),
    );
    let mut secret_tampered = canonical.clone();
    let last = secret_tampered.len() - 1;
    secret_tampered[last] ^= 0x01;
    private_key_open_case(
        corpus,
        "private-key-wrapped-secret-tampered",
        &secret_tampered,
        "private-key-a",
        Err((
            "private_key_wrapped_secret_modified",
            "private_key_unlock_failed",
        )),
    );
}

// ─── FCA payload construction ──────────────────────────────────────────────

/// One entry in a crafted FCA manifest. `content` is empty for a directory.
struct FcaEntry {
    kind: u8,
    mode: u16,
    path: String,
    entry_ext: Vec<u8>,
    content: Vec<u8>,
}

impl FcaEntry {
    fn file(path: &str, content: &[u8]) -> Self {
        Self {
            kind: crate::archive::format::KIND_FILE,
            mode: SOURCE_FILE_MODE,
            path: path.to_string(),
            entry_ext: Vec::new(),
            content: content.to_vec(),
        }
    }

    fn dir(path: &str) -> Self {
        Self {
            kind: crate::archive::format::KIND_DIR,
            mode: SOURCE_DIR_MODE,
            path: path.to_string(),
            entry_ext: Vec::new(),
            content: Vec::new(),
        }
    }

    fn with_entry_ext(mut self, ext: &[u8]) -> Self {
        self.entry_ext = ext.to_vec();
        self
    }

    /// Wire length of this entry's manifest record: the fixed part plus its
    /// path bytes and extension region.
    fn wire_len(&self) -> usize {
        crate::archive::format::FCA_ENTRY_FIXED_SIZE + self.path.len() + self.entry_ext.len()
    }
}

/// The extraction listing `FORMAT.md` §12.3 defines as the expected result of
/// an accepted directory root: one line per object, ordered by path depth and
/// then by path bytes, holding kind, size, content digest, and path. Modes are
/// left out because not every supported platform reproduces them.
fn extraction_listing(entries: &[FcaEntry]) -> Vec<u8> {
    let mut ordered: Vec<&FcaEntry> = entries.iter().collect();
    ordered.sort_by(|a, b| {
        let depth = |e: &FcaEntry| e.path.split('/').count();
        depth(a).cmp(&depth(b)).then_with(|| a.path.cmp(&b.path))
    });
    let mut out = String::new();
    for entry in ordered {
        if entry.kind == crate::archive::format::KIND_DIR {
            out.push_str(&format!("d - - {}\n", entry.path));
        } else {
            out.push_str(&format!(
                "f {} {} {}\n",
                entry.content.len(),
                sha3_hex(&entry.content),
                entry.path
            ));
        }
    }
    out.into_bytes()
}

/// Serializes a complete FCA payload: header, archive extension region,
/// manifest, then file content in manifest order.
/// FCA fixed-header field offsets (`FORMAT.md` §9.2). Only the fields the
/// cases below reach for are named; the check in the last initializer covers
/// the whole header, and lives there because the oldest supported compiler
/// does not count a use inside a free-standing `const _` assertion.
const FCA_OFF_VERSION: usize = 4;
const FCA_OFF_FLAGS: usize = FCA_OFF_VERSION + 1;
const FCA_OFF_ENTRY_COUNT: usize = {
    let at = FCA_OFF_FLAGS + 2;
    // entry_count(4) || archive_ext_len(4) || manifest_len(4) || total_file_bytes(8)
    assert!(at + 4 + 4 + 4 + 8 == crate::archive::format::FCA_HEADER_SIZE);
    at
};

fn build_fca(entries: &[FcaEntry], archive_ext: &[u8]) -> Vec<u8> {
    let manifest_len: usize = entries.iter().map(FcaEntry::wire_len).sum();
    let total_file_bytes: u64 = entries.iter().map(|e| e.content.len() as u64).sum();
    let mut out = Vec::new();
    out.extend_from_slice(b"FCA\0");
    out.push(0x01);
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    out.extend_from_slice(&(archive_ext.len() as u32).to_be_bytes());
    out.extend_from_slice(&(manifest_len as u32).to_be_bytes());
    out.extend_from_slice(&total_file_bytes.to_be_bytes());
    assert_eq!(out.len(), crate::archive::format::FCA_HEADER_SIZE);
    out.extend_from_slice(archive_ext);
    for entry in entries {
        out.push(entry.kind);
        out.push(0); // entry_flags
        out.extend_from_slice(&entry.mode.to_be_bytes());
        out.extend_from_slice(&(entry.path.len() as u16).to_be_bytes());
        out.extend_from_slice(&(entry.entry_ext.len() as u32).to_be_bytes());
        out.extend_from_slice(&(entry.content.len() as u64).to_be_bytes());
        out.extend_from_slice(entry.path.as_bytes());
        out.extend_from_slice(&entry.entry_ext);
    }
    for entry in entries {
        out.extend_from_slice(&entry.content);
    }
    out
}

/// Commits a `.fcr` whose payload region is a caller-crafted FCA image,
/// sealed under a real passphrase recipient with a valid header MAC, so the
/// case isolates the archive rule rather than tripping authentication first.
fn fca_case(
    corpus: &mut Corpus,
    case_id: &str,
    fca: &[u8],
    outcome: Result<Vec<u8>, (&str, &str)>,
) {
    fca_case_with_capability(corpus, case_id, fca, None, outcome);
}

/// Rejected FCA case whose outcome follows from the reader's feature set, so
/// the row names the one capability that would stop the rejection
/// (`FORMAT.md` §12.1).
fn fca_capability_case(
    corpus: &mut Corpus,
    case_id: &str,
    fca: &[u8],
    capability_id: &str,
    condition_id: &str,
    diagnostic_class: &str,
) {
    fca_case_with_capability(
        corpus,
        case_id,
        fca,
        Some(capability_id),
        Err((condition_id, diagnostic_class)),
    );
}

/// Wraps `fca` in a passphrase `.fcr` and commits the case, its origin, and —
/// for an accepted case — the extraction the reader must produce.
fn fca_case_with_capability(
    corpus: &mut Corpus,
    case_id: &str,
    fca: &[u8],
    capability_id: Option<&str>,
    outcome: Result<Vec<u8>, (&str, &str)>,
) {
    let scope = case_scope(case_id);
    let file_key = FileKey::generate().expect("file key");
    let entries = [argon2id_entry(&file_key)];
    let (built, stream_nonce_hex, payload_key_digest) = craft_header(&file_key, &entries, b"");
    let payload = encode_payload(&built.payload_key, &built.stream_nonce, fca, false);
    let bytes = assemble_fcr(&built, &payload);
    let artifact_ref = corpus.write_ref(&format!("artifacts/fcr/{case_id}.fcr"), &bytes);
    let origin_id = format!("origin-{case_id}");
    corpus.push_origin(OriginRow {
        origin_id: origin_id.clone(),
        origin_kind: "fcr_payload",
        anchor_case_id: case_id.to_string(),
        payload_key_ref: "-".to_string(),
        payload_key_sha3_256: payload_key_digest,
        stream_nonce_hex,
    });
    drop(scope);
    let row = CaseRow::fcr(case_id, &artifact_ref)
        .origin(&origin_id)
        .fabricated()
        .credential("passphrase-main");
    let row = match capability_id {
        Some(capability) => row.capability(capability),
        None => row,
    };
    let row = match outcome {
        Ok(expected) => {
            let expected_ref =
                corpus.write_ref(&format!("expected/plaintext/{case_id}.bin"), &expected);
            row.accept(&expected_ref)
        }
        Err((condition, class)) => row.reject(condition, class),
    };
    corpus.push_case(row);
}

/// Builds the entries for a file at the end of a chain of directories, one
/// entry per level, so a deep or long path still satisfies the `FORMAT.md`
/// §9.8 rule that every parent is present as a directory.
fn nested_chain(components: &[String], content: &[u8]) -> Vec<FcaEntry> {
    let mut entries = Vec::with_capacity(components.len());
    let mut path = String::new();
    for (index, component) in components.iter().enumerate() {
        if index > 0 {
            path.push('/');
        }
        path.push_str(component);
        if index + 1 == components.len() {
            entries.push(FcaEntry::file(&path, content));
        } else {
            entries.push(FcaEntry::dir(&path));
        }
    }
    entries
}

/// Commits an accepted `.fcr` case built from caller-supplied recipient
/// entries. The at-cap cases are assembled by hand like the over-cap twins
/// they pair with, rather than produced through the public writer.
fn fabricated_accept_fcr_case(
    corpus: &mut Corpus,
    case_id: &str,
    credential_id: &str,
    source: &Path,
    built: BuiltFcr,
) {
    let artifact_ref = corpus.write_ref(&format!("artifacts/fcr/{case_id}.fcr"), &built.bytes);
    let expected_ref = corpus.write_ref(
        &format!("expected/plaintext/{case_id}.bin"),
        &fs::read(source).expect("read source for expected plaintext"),
    );
    let origin_id = format!("origin-{case_id}");
    corpus.push_origin(OriginRow {
        origin_id: origin_id.clone(),
        origin_kind: "fcr_payload",
        anchor_case_id: case_id.to_string(),
        payload_key_ref: "-".to_string(),
        payload_key_sha3_256: built.payload_key_sha3_256,
        stream_nonce_hex: built.stream_nonce_hex,
    });
    corpus.push_case(
        CaseRow::fcr(case_id, &artifact_ref)
            .origin(&origin_id)
            .fabricated()
            .credential(credential_id)
            .accept(&expected_ref),
    );
}

/// Rejected FCA case built by mutating the bytes of a valid image.
fn fca_mutated_case(
    corpus: &mut Corpus,
    case_id: &str,
    condition_id: &str,
    diagnostic_class: &str,
    mutate: impl FnOnce(&mut Vec<u8>),
) {
    let mut fca = build_fca(&[FcaEntry::file("p.txt", b"fca payload")], b"");
    mutate(&mut fca);
    fca_case(corpus, case_id, &fca, Err((condition_id, diagnostic_class)));
}

// ─── FCA fixed header, manifest, tree, paths, extensions, content ───────────

fn write_fca_cases(corpus: &mut Corpus) {
    use crate::crypto::tlv::tlv_bytes;

    // A valid single-file root, accepted with its content as the expected
    // result.
    fca_case(
        corpus,
        "fca-file-root-valid",
        &build_fca(&[FcaEntry::file("p.txt", b"fca payload")], b""),
        Ok(b"fca payload".to_vec()),
    );

    // A valid directory root with a nested child, then the same tree with its
    // manifest in a permitted noncanonical order (`FORMAT.md` §9.8: the reader
    // resolves parents by lookup, so order does not change what is extracted).
    // Both are accepted against the same extraction listing.
    let tree = || {
        [
            FcaEntry::dir("root"),
            FcaEntry::file("root/a.txt", b"first"),
            FcaEntry::dir("root/sub"),
            FcaEntry::file("root/sub/deep.txt", b"nested content"),
        ]
    };
    let canonical = tree();
    fca_case(
        corpus,
        "fca-directory-root-valid",
        &build_fca(&canonical, b""),
        Ok(extraction_listing(&canonical)),
    );
    let [root, a, sub, deep] = tree();
    let noncanonical = [root, sub, deep, a];
    fca_case(
        corpus,
        "fca-manifest-noncanonical-order-valid",
        &build_fca(&noncanonical, b""),
        Ok(extraction_listing(&noncanonical)),
    );

    // Fixed-header rules (`FORMAT.md` §9.2).
    let header_cases: [ByteMutationCase; 6] = [
        (
            "fca-bad-magic",
            Box::new(|b: &mut Vec<u8>| b[0] ^= 0xFF),
            "fca_magic_mismatch",
            "malformed_archive",
        ),
        (
            "fca-version-zero",
            Box::new(|b: &mut Vec<u8>| b[FCA_OFF_VERSION] = 0x00),
            "fca_version_reserved_zero",
            "malformed_archive",
        ),
        (
            "fca-flags-nonzero",
            Box::new(|b: &mut Vec<u8>| b[FCA_OFF_FLAGS + 1] = 0x01),
            "fca_flags_nonzero",
            "malformed_archive",
        ),
        (
            "fca-entry-count-zero",
            Box::new(|b: &mut Vec<u8>| {
                b[FCA_OFF_ENTRY_COUNT..FCA_OFF_ENTRY_COUNT + 4].copy_from_slice(&0u32.to_be_bytes())
            }),
            "fca_entry_count_zero",
            "malformed_archive",
        ),
        (
            "fca-manifest-len-zero",
            Box::new(|b: &mut Vec<u8>| b[15..19].copy_from_slice(&0u32.to_be_bytes())),
            "fca_manifest_len_zero",
            "malformed_archive",
        ),
        (
            "fca-total-bytes-disagree",
            Box::new(|b: &mut Vec<u8>| b[19..27].copy_from_slice(&999u64.to_be_bytes())),
            "fca_total_file_bytes_disagrees_with_entries",
            "malformed_archive",
        ),
    ];
    for (case_id, mutate, condition, class) in header_cases {
        fca_mutated_case(corpus, case_id, condition, class, mutate);
    }

    // A newer FCA archive version is capability-relative.
    let mut newer = build_fca(&[FcaEntry::file("p.txt", b"fca payload")], b"");
    newer[crate::archive::format::FCA_MAGIC.len()] = 0x02;
    fca_capability_case(
        corpus,
        "fca-newer-version",
        &newer,
        "fca_version:0x02",
        "fca_version_unsupported",
        "unsupported_fca_version",
    );

    // Manifest and tree rules (`FORMAT.md` §9.7 / §9.8).
    let tree_cases: [(&str, Vec<FcaEntry>, &str, &str); 5] = [
        (
            "fca-duplicate-paths",
            vec![
                FcaEntry::dir("root"),
                FcaEntry::file("root/a.txt", b"one"),
                FcaEntry::file("root/a.txt", b"two"),
            ],
            "fca_duplicate_entry_path",
            "invalid_archive_tree",
        ),
        (
            "fca-ascii-case-collision",
            vec![
                FcaEntry::dir("root"),
                FcaEntry::file("root/a.txt", b"one"),
                FcaEntry::file("root/A.txt", b"two"),
            ],
            "fca_paths_collide_ignoring_ascii_case",
            "invalid_archive_tree",
        ),
        (
            "fca-missing-parent",
            vec![
                FcaEntry::dir("root"),
                FcaEntry::file("root/sub/a.txt", b"x"),
            ],
            "fca_entry_parent_absent",
            "invalid_archive_tree",
        ),
        (
            "fca-child-under-file",
            vec![
                FcaEntry::dir("root"),
                FcaEntry::file("root/a.txt", b"x"),
                FcaEntry::file("root/a.txt/b.txt", b"y"),
            ],
            "fca_child_under_file_path",
            "invalid_archive_tree",
        ),
        (
            "fca-multiple-roots",
            vec![FcaEntry::dir("one"), FcaEntry::dir("two")],
            "fca_more_than_one_top_level_root",
            "invalid_archive_tree",
        ),
    ];
    for (case_id, entries, condition, class) in tree_cases {
        fca_case(
            corpus,
            case_id,
            &build_fca(&entries, b""),
            Err((condition, class)),
        );
    }

    // Path grammar (`FORMAT.md` §9.6).
    let path_cases: [(&str, &str, &str); 15] = [
        ("fca-path-absolute", "/abs.txt", "fca_path_is_absolute"),
        (
            "fca-path-parent-component",
            "a/../b.txt",
            "fca_path_has_parent_component",
        ),
        (
            "fca-path-current-component",
            "a/./b.txt",
            "fca_path_has_current_component",
        ),
        (
            "fca-path-trailing-slash",
            "a.txt/",
            "fca_path_has_trailing_separator",
        ),
        (
            "fca-path-repeated-slash",
            "a//b.txt",
            "fca_path_has_repeated_separator",
        ),
        ("fca-path-backslash", "a\\b.txt", "fca_path_has_backslash"),
        (
            "fca-path-windows-reserved-name",
            "CON.txt",
            "fca_path_uses_windows_device_name",
        ),
        (
            "fca-path-trailing-dot",
            "name.",
            "fca_path_component_ends_with_dot",
        ),
        (
            "fca-path-trailing-space",
            "name ",
            "fca_path_component_ends_with_space",
        ),
        (
            "fca-path-windows-reserved-char",
            "a:b.txt",
            "fca_path_uses_windows_reserved_character",
        ),
        (
            "fca-path-ascii-control",
            "a\u{1}b.txt",
            "fca_path_contains_ascii_control",
        ),
        (
            "fca-path-delete-byte",
            "a\u{7f}b.txt",
            "fca_path_contains_delete",
        ),
        (
            "fca-path-c1-control",
            "a\u{85}b.txt",
            "fca_path_contains_c1_control",
        ),
        (
            "fca-path-bidi-override",
            "a\u{202e}b.txt",
            "fca_path_contains_bidi_control",
        ),
        (
            "fca-path-line-separator",
            "a\u{2028}b.txt",
            "fca_path_contains_line_separator",
        ),
    ];
    for (case_id, path, condition) in path_cases {
        fca_case(
            corpus,
            case_id,
            &build_fca(&[FcaEntry::file(path, b"x")], b""),
            Err((condition, "unsafe_archive_path")),
        );
    }
    // One byte past the per-component maximum, which leaves room for the
    // `.incomplete` staging suffix under the 255-byte filesystem name limit.
    let over_long = "c".repeat(crate::archive::path::FCA_COMPONENT_MAX_BYTES + 1);
    fca_case(
        corpus,
        "fca-path-component-over-max",
        &build_fca(&[FcaEntry::file(&over_long, b"x")], b""),
        Err(("fca_path_component_over_max_bytes", "unsafe_archive_path")),
    );

    // Non-ASCII text that breaks none of the grammar rules is accepted, so the
    // rules above read as targeted rather than as a ban on non-ASCII names.
    let unicode = build_fca(
        &[FcaEntry::file("naïve-Ω-日本.txt", b"unicode content")],
        b"",
    );
    fca_case(
        corpus,
        "fca-path-valid-unicode",
        &unicode,
        Ok(b"unicode content".to_vec()),
    );

    // Entry mode and size rules (`FORMAT.md` §9.4).
    fca_mutated_case(
        corpus,
        "fca-entry-mode-above-permission-bits",
        "fca_entry_mode_outside_permission_bits",
        "malformed_archive",
        |b| {
            let mode_at = crate::archive::format::FCA_HEADER_SIZE + 2;
            b[mode_at..mode_at + 2].copy_from_slice(&0o1777u16.to_be_bytes());
        },
    );
    fca_case(
        corpus,
        "fca-directory-entry-nonzero-size",
        &build_fca(
            &[FcaEntry::dir("root"), {
                let mut entry = FcaEntry::dir("root/sub");
                entry.content = b"unreachable".to_vec();
                entry
            }],
            b"",
        ),
        Err(("fca_directory_entry_declares_content", "malformed_archive")),
    );

    // A NUL byte cannot go through `FcaEntry::file`'s `&str`, so this one is
    // written straight into the manifest's path region.
    fca_mutated_case(
        corpus,
        "fca-path-nul-byte",
        "fca_path_contains_nul",
        "unsafe_archive_path",
        |b| {
            let path_at = crate::archive::format::FCA_HEADER_SIZE
                + crate::archive::format::FCA_ENTRY_FIXED_SIZE;
            b[path_at] = 0x00;
        },
    );

    // Extension regions (`FORMAT.md` §9.3 / §9.5). Each rule is driven in both
    // namespaces, because the archive-level and per-entry regions carry
    // separate tag spaces and are validated at different points of §9.11. An
    // ignorable tag is authenticated and skipped, a critical one is
    // capability-relative, and a truncated or reserved tag is invariant.
    let entry_ext = |ext: &[u8]| {
        build_fca(
            &[FcaEntry::file("p.txt", b"fca payload").with_entry_ext(ext)],
            b"",
        )
    };
    let archive_ext = |ext: &[u8]| build_fca(&[FcaEntry::file("p.txt", b"fca payload")], ext);

    fca_case(
        corpus,
        "fca-archive-ext-ignorable",
        &archive_ext(&tlv_bytes(0x0001, b"archive")),
        Ok(b"fca payload".to_vec()),
    );
    fca_case(
        corpus,
        "fca-entry-ext-ignorable",
        &entry_ext(&tlv_bytes(0x0001, b"entry")),
        Ok(b"fca payload".to_vec()),
    );
    fca_capability_case(
        corpus,
        "fca-archive-ext-critical",
        &archive_ext(&tlv_bytes(0x8001, b"archive")),
        "fca_archive_tlv:0x8001",
        "fca_archive_ext_unknown_critical_tag",
        "unknown_critical_tlv",
    );
    fca_capability_case(
        corpus,
        "fca-entry-ext-critical",
        &entry_ext(&tlv_bytes(0x8001, b"entry")),
        "fca_entry_tlv:0x8001",
        "fca_entry_ext_unknown_critical_tag",
        "unknown_critical_tlv",
    );
    // Three bytes where a TLV entry header needs six, so the region ends
    // inside the header of its only entry.
    fca_case(
        corpus,
        "fca-archive-ext-malformed",
        &archive_ext(&[0x00, 0x01, 0x00]),
        Err(("fca_archive_ext_entry_header_truncated", "malformed_tlv")),
    );
    fca_case(
        corpus,
        "fca-entry-ext-malformed",
        &entry_ext(&[0x00, 0x01, 0x00]),
        Err(("fca_entry_ext_entry_header_truncated", "malformed_tlv")),
    );
    fca_case(
        corpus,
        "fca-archive-ext-reserved-tag",
        &archive_ext(&tlv_bytes(0x0000, b"r")),
        Err(("fca_archive_ext_tag_reserved", "malformed_tlv")),
    );
    fca_case(
        corpus,
        "fca-entry-ext-reserved-tag",
        &entry_ext(&tlv_bytes(0x0000, b"r")),
        Err(("fca_entry_ext_tag_reserved", "malformed_tlv")),
    );

    // Content region (`FORMAT.md` §9.9): the declared size is exact.
    fca_mutated_case(
        corpus,
        "fca-content-short",
        "fca_content_region_ends_before_declared_size",
        "malformed_archive",
        |b| {
            b.pop();
        },
    );
    fca_mutated_case(
        corpus,
        "fca-content-trailing",
        "fca_content_region_has_trailing_bytes",
        "malformed_archive",
        |b| b.extend_from_slice(b"extra"),
    );
    fca_case(
        corpus,
        "fca-entry-kind-invalid",
        &build_fca(
            &[{
                let mut e = FcaEntry::file("p.txt", b"x");
                e.kind = 0x07;
                e
            }],
            b"",
        ),
        Err(("fca_entry_kind_unknown", "malformed_archive")),
    );
}

// ─── Resource policy ───────────────────────────────────────────────────────

/// Cases where structurally valid data exceeds a configurable local cap. The
/// rejection depends on the reader's configuration rather than on the format,
/// so each names the default this corpus is replayed under.
fn write_resource_policy_cases(corpus: &mut Corpus, keys: &CorpusKeys) {
    use crate::crypto::tlv::tlv_bytes;

    // Every cap is driven from both sides: one artifact a byte past it, which
    // must be refused, and one sitting exactly on it, which must be accepted.
    // Without the accepting half, a reader that placed a limit one unit low
    // would satisfy every refusing case while rejecting valid input.
    let staging = tempfile::tempdir().expect("source dir");
    let source = write_source(staging.path(), "p", 32);

    // FCA path caps: depth and total byte length. Components stay inside the
    // §9.6 per-component limit so only the whole-path cap can reject.
    let depth_cap = ArchiveLimits::PATH_DEPTH_DEFAULT as usize;
    let deep: String = std::iter::repeat_n("d", depth_cap + 1)
        .collect::<Vec<_>>()
        .join("/");
    fca_case(
        corpus,
        "fca-path-depth-over-default-cap",
        &build_fca(&[FcaEntry::file(&deep, b"x")], b""),
        Err(("fca_path_depth_above_default_cap", "resource_cap_exceeded")),
    );
    let at_depth = nested_chain(&vec!["d".to_string(); depth_cap], b"x");
    fca_case(
        corpus,
        "fca-path-depth-at-default-cap",
        &build_fca(&at_depth, b""),
        Ok(extraction_listing(&at_depth)),
    );

    let bytes_cap = ArchiveLimits::PATH_BYTES_DEFAULT as usize;
    let component = "c".repeat(200);
    let components = bytes_cap / (component.len() + 1) + 1;
    let long: String = std::iter::repeat_n(component.as_str(), components)
        .collect::<Vec<_>>()
        .join("/");
    assert!(
        long.len() > bytes_cap && components <= depth_cap,
        "the path must exceed the byte cap while staying inside the depth cap"
    );
    fca_case(
        corpus,
        "fca-path-bytes-over-default-cap",
        &build_fca(&[FcaEntry::file(&long, b"x")], b""),
        Err(("fca_path_bytes_above_default_cap", "resource_cap_exceeded")),
    );
    // The byte cap has no accepting twin: at 4096 bytes the path alone
    // exceeds what a host can address once an output directory is prefixed
    // (`PATH_MAX` is 1024 on macOS), so no artifact can both sit on the cap
    // and be extracted.

    // FCA extension caps, archive-level and per-entry. The TLV tag and length
    // count towards the region, so the value is the cap less that header.
    let region_cap = ArchiveLimits::ARCHIVE_EXT_BYTES_DEFAULT as usize;
    assert_eq!(
        region_cap,
        ArchiveLimits::ENTRY_EXT_BYTES_DEFAULT as usize,
        "one oversized region serves both caps only while they agree"
    );
    let oversized = vec![0x41u8; region_cap + 1 - crate::crypto::tlv::ENTRY_HEADER_SIZE];
    let at_cap = vec![0x41u8; region_cap - crate::crypto::tlv::ENTRY_HEADER_SIZE];
    fca_case(
        corpus,
        "fca-archive-ext-over-default-cap",
        &build_fca(
            &[FcaEntry::file("p.txt", b"x")],
            &tlv_bytes(0x0001, &oversized),
        ),
        Err((
            "fca_archive_ext_bytes_above_default_cap",
            "resource_cap_exceeded",
        )),
    );
    fca_case(
        corpus,
        "fca-archive-ext-at-default-cap",
        &build_fca(
            &[FcaEntry::file("p.txt", b"fca payload")],
            &tlv_bytes(0x0001, &at_cap),
        ),
        Ok(b"fca payload".to_vec()),
    );
    fca_case(
        corpus,
        "fca-entry-ext-over-default-cap",
        &build_fca(
            &[FcaEntry::file("p.txt", b"x").with_entry_ext(&tlv_bytes(0x0001, &oversized))],
            b"",
        ),
        Err((
            "fca_entry_ext_bytes_above_default_cap",
            "resource_cap_exceeded",
        )),
    );
    fca_case(
        corpus,
        "fca-entry-ext-at-default-cap",
        &build_fca(
            &[FcaEntry::file("p.txt", b"fca payload").with_entry_ext(&tlv_bytes(0x0001, &at_cap))],
            b"",
        ),
        Ok(b"fca payload".to_vec()),
    );

    // Header caps: the supported-recipient count and the per-recipient body
    // length, each driven one entry and one byte past its cap and then exactly
    // on it.
    let count_cap = crate::HeaderReadLimits::RECIPIENT_COUNT_DEFAULT;
    let scope = case_scope("header-recipient-count-over-default-cap");
    let file_key = FileKey::generate().expect("file key");
    let many: Vec<RecipientEntry> = (0..count_cap + 1)
        .map(|_| x25519_entry(&keys.public_a, &file_key))
        .collect();
    let built = build_fcr_with_entries(&source, &file_key, &many, b"");
    drop(scope);
    let artifact_ref = corpus.write_ref(
        "artifacts/fcr/header-recipient-count-over-default-cap.fcr",
        &built.bytes,
    );
    corpus.push_origin(OriginRow {
        origin_id: "origin-header-recipient-count-over-default-cap".to_string(),
        origin_kind: "fcr_payload",
        anchor_case_id: "header-recipient-count-over-default-cap".to_string(),
        payload_key_ref: "-".to_string(),
        payload_key_sha3_256: built.payload_key_sha3_256,
        stream_nonce_hex: built.stream_nonce_hex,
    });
    corpus.push_case(
        CaseRow::fcr("header-recipient-count-over-default-cap", &artifact_ref)
            .origin("origin-header-recipient-count-over-default-cap")
            .fabricated()
            .credential("private-key-a")
            .reject("recipient_count_above_default_cap", "resource_cap_exceeded"),
    );

    // Exactly the cap, with the decrypting key in the last slot so a reader
    // that stopped one entry early would fail to open it.
    let scope = case_scope("header-recipient-count-at-default-cap");
    let file_key = FileKey::generate().expect("file key");
    let mut at_count: Vec<RecipientEntry> = (0..count_cap - 1)
        .map(|_| x25519_entry(&keys.public_b, &file_key))
        .collect();
    at_count.push(x25519_entry(&keys.public_a, &file_key));
    assert_eq!(at_count.len(), count_cap as usize, "exactly the count cap");
    let built = build_fcr_with_entries(&source, &file_key, &at_count, b"");
    drop(scope);
    fabricated_accept_fcr_case(
        corpus,
        "header-recipient-count-at-default-cap",
        "private-key-a",
        &source,
        built,
    );

    let body_cap = crate::HeaderReadLimits::RECIPIENT_BODY_LEN_DEFAULT as usize;
    let scope = case_scope("recipient-body-over-default-cap");
    let file_key = FileKey::generate().expect("file key");
    let mut big_body = unknown_entry(false);
    big_body.body = vec![0xAA; body_cap + 1];
    let entries = [big_body, argon2id_entry(&file_key)];
    let built = build_fcr_with_entries(&source, &file_key, &entries, b"");
    drop(scope);
    let artifact_ref = corpus.write_ref(
        "artifacts/fcr/recipient-body-over-default-cap.fcr",
        &built.bytes,
    );
    corpus.push_origin(OriginRow {
        origin_id: "origin-recipient-body-over-default-cap".to_string(),
        origin_kind: "fcr_payload",
        anchor_case_id: "recipient-body-over-default-cap".to_string(),
        payload_key_ref: "-".to_string(),
        payload_key_sha3_256: built.payload_key_sha3_256,
        stream_nonce_hex: built.stream_nonce_hex,
    });
    corpus.push_case(
        CaseRow::fcr("recipient-body-over-default-cap", &artifact_ref)
            .origin("origin-recipient-body-over-default-cap")
            .fabricated()
            .credential("passphrase-main")
            .reject(
                "recipient_body_len_above_default_cap",
                "resource_cap_exceeded",
            ),
    );

    // Exactly the cap on an unknown non-critical entry, which the reader must
    // carry past and then open the supported slot behind it. The companion is
    // `x25519`, because §4.1 forbids `argon2id` beside any other entry.
    let scope = case_scope("recipient-body-at-default-cap");
    let file_key = FileKey::generate().expect("file key");
    let mut at_body = unknown_entry(false);
    at_body.body = vec![0xAA; body_cap];
    let entries = [at_body, x25519_entry(&keys.public_a, &file_key)];
    let built = build_fcr_with_entries(&source, &file_key, &entries, b"");
    drop(scope);
    fabricated_accept_fcr_case(
        corpus,
        "recipient-body-at-default-cap",
        "private-key-a",
        &source,
        built,
    );
}

// ─── Payload STREAM known-answer tests ─────────────────────────────────────

/// Emits the manifest rows for the STREAM known-answer cases.
///
/// The bytes themselves are **not** produced here. `FORMAT.md` §12.3 requires
/// the expected ciphertext to come from an implementation independent of
/// FerroCrypt's, because agreement between this crate's writer and its reader
/// is not transcript evidence. `tools/stream_kat_oracle.py` generates
/// `kat/stream/` from libsodium through PyNaCl; this function reads what the
/// oracle committed and records it in the manifests.
///
/// The first, third, and fourth identifiers are the minimum transcripts §12.3
/// names. The other two extend the same rules to a short final chunk and to a
/// multi-chunk transcript.
fn write_stream_kat_cases(corpus: &mut Corpus) {
    const KAT_CASES: [&str; 5] = [
        "stream-empty",
        "stream-one-byte",
        "stream-exact-65536",
        "stream-two-chunk-65537",
        "stream-multi-chunk",
    ];
    for case_id in KAT_CASES {
        let read = |suffix: &str| -> Vec<u8> {
            let reference = format!("kat/stream/{case_id}.{suffix}.bin");
            fs::read(corpus.root.join(&reference)).unwrap_or_else(|e| {
                panic!("{reference}: {e}. Run tools/stream_kat_oracle.py first.")
            })
        };
        let key = read("payload-key");
        corpus.push_origin(OriginRow {
            origin_id: format!("origin-{case_id}"),
            origin_kind: "stream_kat",
            anchor_case_id: case_id.to_string(),
            payload_key_ref: format!("kat/stream/{case_id}.payload-key.bin"),
            payload_key_sha3_256: sha3_hex(&key),
            stream_nonce_hex: hex(&oracle_nonce_prefix(case_id)),
        });

        corpus.push_case(
            CaseRow::new(
                case_id,
                "stream_encrypt_kat",
                &format!("kat/stream/{case_id}.input.bin"),
            )
            .fabricated()
            .credential("none")
            .transcript_equal(&format!("kat/stream/{case_id}.ciphertext.bin")),
        );
    }
}

/// The 19-byte nonce prefix `tools/stream_kat_oracle.py` fixes for each case.
/// Kept beside the case list so the two cannot drift; the oracle refuses to
/// emit two cases sharing a prefix, and the corpus validator refuses to accept
/// them.
fn oracle_nonce_prefix(case_id: &str) -> [u8; STREAM_NONCE_SIZE] {
    let byte = match case_id {
        "stream-empty" => 0x50,
        "stream-one-byte" => 0x51,
        "stream-exact-65536" => 0x52,
        "stream-two-chunk-65537" => 0x53,
        "stream-multi-chunk" => 0x54,
        other => panic!("no nonce prefix recorded for {other}"),
    };
    [byte; STREAM_NONCE_SIZE]
}

/// Replays the committed STREAM known-answer cases through the production
/// payload pipeline, in both directions.
///
/// `FORMAT.md` §12.3 requires crate-internal replay to encrypt and decrypt the
/// committed KATs. The expected bytes come from the independent PyNaCl oracle
/// in `tools/`, so agreement here is cross-implementation evidence rather than
/// FerroCrypt agreeing with itself: `payload_encryptor` must reproduce
/// libsodium's transcript byte for byte, and `payload_decryptor` must recover
/// the committed plaintext from it.
///
/// This half of the replay lives in the library because the payload pipeline is
/// crate-internal; every other case type is replayed through the public API by
/// `tests/wire_corpus.rs`.
#[test]
fn replay_stream_kats() {
    if !wire_corpus_present() {
        return;
    }
    let root = wire_dir();
    let cases = read_manifest(&root, "cases.tsv");
    let origins = read_manifest(&root, "origins.tsv");

    let mut replayed = 0usize;
    for case in cases
        .iter()
        .filter(|c| c["case_type"] == "stream_encrypt_kat")
    {
        let case_id = &case["case_id"];
        assert_eq!(case["outcome"], "transcript_equal", "{case_id}: outcome");

        let origin = origins
            .iter()
            .find(|o| &o["anchor_case_id"] == case_id)
            .unwrap_or_else(|| panic!("{case_id}: no origin anchored to this case"));
        assert_eq!(
            origin["origin_kind"], "stream_kat",
            "{case_id}: origin kind"
        );

        let key_bytes: [u8; 32] = fs::read(root.join(&origin["payload_key_ref"]))
            .expect("read payload key")
            .try_into()
            .expect("payload key is 32 bytes");
        assert_eq!(
            sha3_hex(&key_bytes),
            origin["payload_key_sha3_256"],
            "{case_id}: payload key does not match its committed digest"
        );
        let nonce = decode_hex_array::<STREAM_NONCE_SIZE>(&origin["stream_nonce_hex"]);

        let plaintext = fs::read(root.join(&case["artifact_ref"])).expect("read KAT input");
        let expected = fs::read(root.join(&case["expected_ref"])).expect("read KAT ciphertext");
        let payload_key = crate::crypto::keys::PayloadKey::from_bytes_for_tests(key_bytes);

        let mut produced = Vec::new();
        {
            let mut writer =
                crate::crypto::stream::payload_encryptor(&payload_key, &nonce, &mut produced);
            writer.write_all(&plaintext).expect("write KAT plaintext");
            writer.finish().expect("finish KAT transcript");
        }
        assert_eq!(
            produced, expected,
            "{case_id}: transcript differs from the independent oracle"
        );

        let mut recovered = Vec::new();
        crate::crypto::stream::payload_decryptor(&payload_key, &nonce, expected.as_slice())
            .read_to_end(&mut recovered)
            .expect("decrypt KAT transcript");
        assert_eq!(
            recovered, plaintext,
            "{case_id}: decrypted plaintext differs from the committed input"
        );
        replayed += 1;
    }
    assert!(
        replayed > 0,
        "the corpus declares no STREAM known-answer cases"
    );
}

/// Derives the payload key for every `.fcr` payload origin the corpus
/// credentials can reach, and checks it against the committed commitment
/// (`FORMAT.md` §12.3). This is crate-internal because the derivation stops at
/// the recipient unwrap: most anchors are files the public decryptor refuses
/// for a reason that lies past the recipient list — an unknown critical TLV
/// tag, a capped KDF parameter — yet whose payload was genuinely encrypted and
/// whose provenance row must still be evidenced.
///
/// The same pass checks origin and nonce hygiene: every anchor's stored
/// `stream_nonce_hex` is the nonce its header actually carries, and no two
/// origins share one.
#[test]
fn replay_fcr_payload_origins() {
    if !wire_corpus_present() {
        return;
    }
    let root = wire_dir();
    let cases: BTreeMap<String, BTreeMap<String, String>> = read_manifest(&root, "cases.tsv")
        .into_iter()
        .map(|row| (row["case_id"].clone(), row))
        .collect();

    let mut nonces = BTreeMap::new();
    let mut derived = 0usize;
    let mut unreachable = Vec::new();
    for origin in read_manifest(&root, "origins.tsv")
        .iter()
        .filter(|o| o["origin_kind"] == "fcr_payload")
    {
        let origin_id = &origin["origin_id"];
        assert_eq!(
            origin["payload_key_ref"], "-",
            "{origin_id}: an .fcr payload origin commits to its key without naming a file"
        );
        // Two origins sharing a nonce prefix would mean one payload key and
        // nonce pair encrypted two different plaintexts.
        if let Some(first) = nonces.insert(origin["stream_nonce_hex"].clone(), origin_id.clone()) {
            panic!("{origin_id}: nonce prefix repeats {first}");
        }

        let anchor = cases
            .get(&origin["anchor_case_id"])
            .unwrap_or_else(|| panic!("{origin_id}: anchor case is not declared"));
        let bytes = fs::read(root.join(&anchor["artifact_ref"])).expect("read anchor artifact");

        let Ok(header) = crate::container::read_encrypted_header(
            &mut bytes.as_slice(),
            // The structural maxima rather than the defaults: an anchor whose
            // stored outcome is a local resource cap still encrypted a genuine
            // payload, and its provenance row needs the same evidence.
            crate::HeaderReadLimits::default()
                .max_header_len(crate::format::HEADER_LEN_MAX)
                .max_recipient_count(crate::format::RECIPIENT_COUNT_MAX)
                .max_recipient_body_len(crate::format::BODY_LEN_MAX)
                .max_header_mac_work_bytes(u64::MAX),
        ) else {
            // A structurally malformed anchor never reaches its recipients.
            unreachable.push(origin_id.clone());
            continue;
        };
        assert_eq!(
            hex(&header.fixed.stream_nonce),
            origin["stream_nonce_hex"],
            "{origin_id}: stored nonce is not the one the anchor header carries"
        );

        let Some(file_key) =
            unwrap_any_slot(&root, &header.recipient_entries, &anchor["credential_id"])
        else {
            assert_ne!(
                anchor["outcome"], "accept",
                "{origin_id}: an accepted anchor must open with its own credential"
            );
            unreachable.push(origin_id.clone());
            continue;
        };
        let DerivedSubkeys { payload_key, .. } =
            derive_subkeys(&file_key, &header.fixed.stream_nonce).expect("derive subkeys");
        assert_eq!(
            sha3_hex(payload_key.expose()),
            origin["payload_key_sha3_256"],
            "{origin_id}: derived payload key does not match its committed commitment"
        );
        derived += 1;
    }

    assert!(
        derived > 0,
        "no .fcr payload origin was reachable, so no commitment was evidenced"
    );
    // A corpus whose anchors stopped opening would still pass the assertions
    // above; the floor keeps a silent collapse from reading as success.
    assert!(
        derived > unreachable.len(),
        "only {derived} of {} .fcr payload origins were reachable: {unreachable:?}",
        derived + unreachable.len()
    );
}

/// The `credentials.tsv` row for one credential. Read from the manifest so the
/// replay follows the same references an outside implementation would.
fn credential_row(root: &Path, credential_id: &str) -> BTreeMap<String, String> {
    read_manifest(root, "credentials.tsv")
        .into_iter()
        .find(|row| row["credential_id"] == credential_id)
        .unwrap_or_else(|| panic!("{credential_id}: not declared in credentials.tsv"))
}

/// Reads a passphrase the corpus stores as a credential file. The file holds
/// the passphrase bytes alone, with no terminator.
fn credential_passphrase(root: &Path, reference: &str) -> Passphrase {
    Passphrase::new(
        fs::read_to_string(root.join(reference)).unwrap_or_else(|e| panic!("{reference}: {e}")),
    )
}

/// Tries every recipient slot with one corpus credential, returning the first
/// `file_key` that unwraps. Mirrors the slot loop of `FORMAT.md` §3.7 without
/// its header-MAC acceptance step, which several anchors deliberately fail.
///
/// Dispatches on the `kind` column of `credentials.tsv` and reads the material
/// each row references, so an origin anchored to any declared credential
/// resolves without this function naming it.
fn unwrap_any_slot(
    root: &Path,
    entries: &[RecipientEntry],
    credential_id: &str,
) -> Option<FileKey> {
    let credential = credential_row(root, credential_id);
    let (passphrase, private_key) = match credential["kind"].as_str() {
        // No credential opens no slot.
        "none" => return None,
        "passphrase" => (
            Some(credential_passphrase(root, &credential["primary_ref"])),
            None,
        ),
        "private_key" => {
            // `secret_ref` is the passphrase that unlocks the key file. A row
            // pairing a key with a passphrase that does not unlock it opens no
            // slot, which is the same answer as a key that unwraps nothing.
            let secret_ref = &credential["secret_ref"];
            assert_ne!(
                secret_ref, "-",
                "{credential_id}: a private_key credential names its unlock passphrase"
            );
            let unlock = credential_passphrase(root, secret_ref);
            match x25519::open_x25519_key_file(
                &root.join(&credential["primary_ref"]),
                &unlock,
                None,
                crate::KeyReadLimits::default(),
                &|_| {},
            ) {
                Ok(opened) => (None, Some(opened.secret)),
                Err(_) => return None,
            }
        }
        other => panic!("{credential_id}: unsupported credential kind {other}"),
    };

    entries.iter().find_map(
        |entry| match (entry.type_name.as_str(), &passphrase, &private_key) {
            (argon2id::TYPE_NAME, Some(passphrase), _) => {
                let body = entry.body.as_slice().try_into().ok()?;
                argon2id::unwrap(body, passphrase, None, &|_| {}).ok()
            }
            (x25519::TYPE_NAME, _, Some(secret)) => {
                let body = entry.body.as_slice().try_into().ok()?;
                x25519::unwrap(body, secret).ok()
            }
            _ => None,
        },
    )
}

/// Parses a manifest table into column-keyed rows. Positional indexing would
/// silently read the wrong column if a later `SCHEMA-VERSION` adds one.
fn read_manifest(root: &Path, name: &str) -> Vec<BTreeMap<String, String>> {
    let text = fs::read_to_string(root.join(name))
        .unwrap_or_else(|e| panic!("{name}: {e}. The corpus must be committed."));
    let mut columns: Option<Vec<String>> = None;
    let mut rows = Vec::new();
    for line in text.lines() {
        if let Some(header) = line.strip_prefix('#') {
            if columns.is_none() {
                columns = Some(header.trim().split('\t').map(str::to_string).collect());
            }
            continue;
        }
        let columns = columns
            .as_ref()
            .unwrap_or_else(|| panic!("{name}: no column header"));
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), columns.len(), "{name}: row width");
        rows.push(
            columns
                .iter()
                .cloned()
                .zip(fields.iter().map(|f| f.to_string()))
                .collect(),
        );
    }
    rows
}

/// Decodes exactly `N` bytes of lowercase hexadecimal.
fn decode_hex_array<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2, "expected {N} bytes of hexadecimal");
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hexadecimal");
    }
    out
}
