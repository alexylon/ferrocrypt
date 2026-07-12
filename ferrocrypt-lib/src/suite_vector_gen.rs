//! Generator for the committed `testvectors/suite/` edge-case corpus.
//!
//! The suite corpus is the public set of must-reject (and a few
//! must-accept) fixtures required by `FORMAT.md` §12. Every fixture is
//! committed as real bytes plus a `manifest.tsv` row naming the decrypt
//! attempt and the exact expected outcome, so an independent reader
//! implementation can consume the corpus without running this crate's
//! test code. The `tests/testvector_suite.rs` integration test replays
//! the manifest through the public API on every `cargo test` run.
//!
//! Generation needs crate internals — `container::build_encrypted_header`
//! writes headers with extension bytes, crafted recipient lists, and
//! out-of-range KDF parameters that the public `Encryptor` refuses to
//! produce — so the generator lives in the library crate as an ignored
//! unit test. Regenerate with:
//!
//! ```bash
//! cargo test --package ferrocrypt --lib suite_vector_gen \
//!     -- --ignored --test-threads=1
//! ```
//!
//! Regeneration replaces `cases/`, `keys/`, `plaintext.txt`,
//! `manifest.tsv`, and `SUITE-VERSION` under `testvectors/suite/`, and
//! the engineer commits the result by hand. Generation runs under a fixed
//! deterministic RNG seed ([`SUITE_SEED`]) via
//! [`crate::crypto::keys::with_deterministic_rng`], so regenerating without
//! changing the generator produces byte-identical output and an empty diff.
//! Adding or editing a fixture therefore shows only that fixture's bytes in
//! the diff, not a re-randomization of the whole corpus. The committed files
//! are what independent readers must keep accepting or rejecting.

use std::fs;
use std::path::{Path, PathBuf};

use secrecy::SecretString;

use crate::crypto::kdf::{ARGON2_SALT_SIZE, KDF_PARAMS_SIZE, KdfParams};
use crate::crypto::keys::{DerivedSubkeys, FileKey, derive_subkeys, random_bytes};
use crate::crypto::stream::STREAM_NONCE_SIZE;
use crate::crypto::tlv::tlv_bytes;
use crate::error::sanitize_for_display;
use crate::format::{HEADER_FIXED_SIZE, HEADER_LEN_MAX, HEADER_MAC_SIZE, PREFIX_SIZE};
use crate::recipient::RecipientEntry;
use crate::recipient::entry::{ENTRY_HEADER_SIZE, RECIPIENT_FLAG_CRITICAL};
use crate::recipient::native::{argon2id, x25519};
use crate::{ArchiveLimits, CryptoError, Encryptor, KeyPairGenerator, PublicKey};

/// Passphrase for every argon2id fixture and both private keys.
/// Fixture-only; anyone with the repository can decrypt these files.
const SUITE_PASSPHRASE: &str = "suite-passphrase-not-secret-do-not-reuse";

/// Deliberately wrong passphrase used by the wrong-credential manifest row.
const WRONG_PASSPHRASE: &str = "wrong-passphrase";

/// Content of `plaintext.txt` — the source file every valid fixture
/// encrypts and every `ok` manifest row must decrypt back to.
const PLAINTEXT: &str = "FerroCrypt v1 test-vector suite plaintext.\n";

/// Fixed Unix mode pinned on `plaintext.txt` before it is archived. The
/// archiver records the source file's permission bits in every fixture's
/// manifest, so without a fixed mode the umask that created `plaintext.txt`
/// would leak into the encrypted bytes and break byte-identical
/// regeneration. `0o644` matches the archiver's non-Unix default mode, so the
/// corpus stays reproducible on every platform.
#[cfg(unix)]
const PLAINTEXT_FILE_MODE: u32 = 0o644;

/// Grammar-valid but unknown recipient `type_name` used by the
/// unknown-recipient fixtures.
const UNKNOWN_TYPE_NAME: &str = "mlkem768";

// `.fcr` prefix field offsets per `FORMAT.md` §3.1. The layout is frozen
// for v1, so the generator pins the byte positions directly.
const PREFIX_MAGIC_OFFSET: usize = 0;
const PREFIX_VERSION_OFFSET: usize = 4;
const PREFIX_KIND_OFFSET: usize = 5;
const PREFIX_FLAGS_OFFSET: usize = 6;
const PREFIX_HEADER_LEN_OFFSET: usize = 8;

/// One `manifest.tsv` row: which file to attempt, how, and what must
/// happen. `error_class` and `error_message` are `-` for `ok` rows.
struct Case {
    file: String,
    action: &'static str,
    credential: String,
    expect: &'static str,
    error_class: String,
    error_message: String,
}

impl Case {
    fn ok(file: &str, credential: &str) -> Self {
        Self {
            file: file.to_string(),
            action: "decrypt",
            credential: credential.to_string(),
            expect: "ok",
            error_class: "-".to_string(),
            error_message: "-".to_string(),
        }
    }

    fn err(file: &str, credential: &str, class: &str, message: &str) -> Self {
        Self {
            file: file.to_string(),
            action: "decrypt",
            credential: credential.to_string(),
            expect: "error",
            error_class: class.to_string(),
            error_message: message.to_string(),
        }
    }

    fn key_err(file: &str, class: &str, message: &str) -> Self {
        Self {
            action: "read-public-key",
            credential: "-".to_string(),
            ..Self::err(file, "-", class, message)
        }
    }

    fn private_key_err(file: &str, class: &str, message: &str) -> Self {
        Self {
            action: "validate-private-key",
            credential: "-".to_string(),
            ..Self::err(file, "-", class, message)
        }
    }
}

fn suite_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testvectors/suite")
}

fn suite_passphrase() -> SecretString {
    SecretString::from(SUITE_PASSPHRASE.to_string())
}

fn passphrase_credential(literal: &str) -> String {
    format!("passphrase:{literal}")
}

fn private_key_credential(key: &str) -> String {
    format!("private-key:keys/{key},unlock={SUITE_PASSPHRASE}")
}

/// Copies `base`, applies `mutate` to the raw bytes, and writes the
/// result as `cases/<name>`.
fn mutated_copy(cases: &Path, base: &str, name: &str, mutate: impl FnOnce(&mut Vec<u8>)) {
    let mut bytes = fs::read(cases.join(base)).expect("read base fixture");
    mutate(&mut bytes);
    fs::write(cases.join(name), bytes).expect("write mutated fixture");
}

/// Offset of the first payload byte: prefix, then the header region of
/// the length declared in the prefix, then the header MAC tag.
fn payload_offset(bytes: &[u8]) -> usize {
    let header_len = u32::from_be_bytes(
        bytes[PREFIX_HEADER_LEN_OFFSET..PREFIX_HEADER_LEN_OFFSET + 4]
            .try_into()
            .expect("prefix header_len slice"),
    ) as usize;
    PREFIX_SIZE + header_len + HEADER_MAC_SIZE
}

/// Draws a fresh stream nonce, derives the subkeys, and assembles the
/// encrypted header for `entries` and `ext_bytes`. Shared by the two
/// crafted-`.fcr` builders below, which differ only in how they attach the
/// payload after the header.
fn craft_encrypted_header(
    file_key: &FileKey,
    entries: &[RecipientEntry],
    ext_bytes: &[u8],
) -> Result<crate::container::BuiltEncryptedHeader, CryptoError> {
    let stream_nonce = random_bytes::<STREAM_NONCE_SIZE>()?;
    let DerivedSubkeys {
        payload_key,
        header_key,
    } = derive_subkeys(file_key, &stream_nonce)?;
    crate::container::build_encrypted_header(
        entries,
        ext_bytes,
        stream_nonce,
        payload_key,
        &header_key,
    )
}

/// Builds a `.fcr` from caller-supplied recipient entries and extension
/// bytes, with a real encrypted payload of `plaintext`. The caller
/// passes the `file_key` its entries wrap, so the header MAC and the
/// payload stream belong to the same key. This is the internals-only
/// path: the public `Encryptor` cannot emit extension bytes, unknown
/// recipient entries, mixed recipient lists, or out-of-range KDF
/// parameters.
fn build_crafted_fcr(
    plaintext: &Path,
    cases: &Path,
    name: &str,
    file_key: &FileKey,
    entries: &[RecipientEntry],
    ext_bytes: &[u8],
) -> Result<(), CryptoError> {
    let built = craft_encrypted_header(file_key, entries, ext_bytes)?;
    crate::container::write_encrypted_file(
        plaintext,
        cases,
        Some(&cases.join(name)),
        "suite",
        &built,
        ArchiveLimits::default(),
    )?;
    Ok(())
}

/// Wraps the suite `file_key` for the passphrase recipient with the
/// fast test parameters and returns the entry.
fn argon2id_entry(file_key: &FileKey) -> RecipientEntry {
    let body = argon2id::wrap(
        file_key,
        &suite_passphrase(),
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

/// Wraps the suite `file_key` for the X25519 recipient whose public key
/// is committed at `keys/<key>` and returns the entry.
fn x25519_entry(keys: &Path, key: &str, file_key: &FileKey) -> RecipientEntry {
    let public = PublicKey::from_key_file(keys.join(key))
        .to_bytes()
        .expect("resolve suite public key");
    let body = x25519::wrap(file_key, &public).expect("wrap x25519 recipient");
    RecipientEntry {
        type_name: x25519::TYPE_NAME.to_string(),
        recipient_flags: 0,
        body: body.to_vec(),
    }
}

/// Unknown-recipient entry with a grammar-valid `type_name` this build
/// does not implement. The body is opaque filler: a reader must decide
/// from the `type_name` and the critical flag alone.
fn unknown_entry(critical: bool) -> RecipientEntry {
    RecipientEntry {
        type_name: UNKNOWN_TYPE_NAME.to_string(),
        recipient_flags: if critical { RECIPIENT_FLAG_CRITICAL } else { 0 },
        body: vec![0xAA; 64],
    }
}

/// Variant of [`build_crafted_fcr`] for a single argon2id recipient
/// whose KDF parameter field is replaced with `bad_params` before the
/// header MAC is computed. The MAC is valid, so the fixture isolates
/// exactly one defect: parameters outside the v1 structural bounds.
fn build_bad_kdf_fcr(
    plaintext: &Path,
    cases: &Path,
    name: &str,
    bad_params: KdfParams,
) -> Result<(), CryptoError> {
    let file_key = FileKey::generate()?;
    let mut entry = argon2id_entry(&file_key);
    entry.body[ARGON2_SALT_SIZE..ARGON2_SALT_SIZE + KDF_PARAMS_SIZE]
        .copy_from_slice(&bad_params.to_bytes());
    build_crafted_fcr(
        plaintext,
        cases,
        name,
        &file_key,
        std::slice::from_ref(&entry),
        b"",
    )
}

/// Generates one key pair with the fast test parameters into `keys/`,
/// renaming the fixed `public.key` / `private.key` output names to the
/// per-recipient fixture names.
fn generate_key_pair(keys: &Path, label: &str) {
    let staging = tempfile::tempdir().expect("keygen staging dir");
    KeyPairGenerator::with_passphrase(suite_passphrase())
        .kdf_params(KdfParams::test_fast_default())
        .write(staging.path(), |_| {})
        .expect("generate suite key pair");
    fs::rename(
        staging.path().join("public.key"),
        keys.join(format!("recipient-{label}.public.key")),
    )
    .expect("move public key");
    fs::rename(
        staging.path().join("private.key"),
        keys.join(format!("recipient-{label}.private.key")),
    )
    .expect("move private key");
}

/// Writes the corrupted `public.key` text fixtures derived from
/// recipient A's committed key file. Returns the three manifest rows.
fn write_public_key_cases(suite: &Path, cases: &Path) -> Vec<Case> {
    let valid = fs::read_to_string(suite.join("keys/recipient-a.public.key"))
        .expect("read recipient A public key");
    let recipient = valid.strip_suffix('\n').unwrap_or(&valid);

    // Uppercase input: rejected before Bech32 decoding.
    fs::write(
        cases.join("public-key-uppercase.key"),
        format!("{}\n", recipient.to_uppercase()),
    )
    .expect("write uppercase public key fixture");

    // One data character replaced: the Bech32 checksum no longer matches.
    let flip_at = recipient.len() - 10;
    let flipped_char = if recipient.as_bytes()[flip_at] == b'q' {
        'p'
    } else {
        'q'
    };
    let mut bad_bech32: String = recipient.to_string();
    bad_bech32.replace_range(flip_at..=flip_at, &flipped_char.to_string());
    assert_ne!(
        bad_bech32, recipient,
        "character flip must change the string"
    );
    fs::write(
        cases.join("public-key-bad-bech32.key"),
        format!("{bad_bech32}\n"),
    )
    .expect("write bad-bech32 public key fixture");

    // Valid Bech32 around a payload whose internal SHA3-256 checksum is
    // wrong: flip the last payload byte (inside the checksum field) and
    // re-encode so only the inner check can catch it.
    let (hrp, mut data) = bech32::decode(recipient).expect("decode suite recipient string");
    *data.last_mut().expect("payload is non-empty") ^= 0x01;
    let bad_checksum =
        bech32::encode::<bech32::Bech32>(hrp, &data).expect("re-encode tampered payload");
    fs::write(
        cases.join("public-key-bad-checksum.key"),
        format!("{bad_checksum}\n"),
    )
    .expect("write bad-checksum public key fixture");

    vec![
        Case::key_err(
            "cases/public-key-uppercase.key",
            "InvalidInput",
            "Recipient string must be lowercase",
        ),
        Case::key_err(
            "cases/public-key-bad-bech32.key",
            "InvalidInput",
            &format!(
                "Invalid recipient string: {}",
                sanitize_for_display(&bad_bech32)
            ),
        ),
        Case::key_err(
            "cases/public-key-bad-checksum.key",
            "InvalidFormat(MalformedPublicKey)",
            "Public key is malformed",
        ),
    ]
}

/// Builds a `.fcr` whose decrypted payload is exactly `raw_payload` — crafted,
/// possibly-malformed FerroCrypt-archive bytes — instead of a real archive of a
/// file. The outer container is valid (the passphrase recipient unwraps and the
/// header MAC verifies), so decryption reaches the inner archive parser, which
/// is what these fixtures exercise.
fn build_crafted_payload_fcr(
    cases: &Path,
    name: &str,
    file_key: &FileKey,
    entries: &[RecipientEntry],
    raw_payload: &[u8],
) -> Result<(), CryptoError> {
    use std::io::Write;
    let built = craft_encrypted_header(file_key, entries, b"")?;
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&built.prefix_bytes);
    out.extend_from_slice(&built.header_bytes);
    out.extend_from_slice(&built.header_mac);
    let mut writer =
        crate::crypto::stream::payload_encryptor(&built.payload_key, &built.stream_nonce, out);
    writer
        .write_all(raw_payload)
        .map_err(|_| CryptoError::InternalInvariant("crafted payload write"))?;
    let out = writer.finish()?;
    fs::write(cases.join(name), out).expect("write crafted-payload fixture");
    Ok(())
}

/// Crafted FerroCrypt-archive payloads, each carrying exactly one defect the
/// inner archive parser must reject. Returns `(fixture-name, raw-fca-bytes)`.
fn crafted_fca_payloads() -> Vec<(&'static str, Vec<u8>)> {
    // A 27-byte FCA header is enough for the header-level rejects; the parser
    // stops at the first bad field. magic(4) version(1) flags(2) entry_count(4)
    // archive_ext_len(4) manifest_len(4) total_file_bytes(8).
    let header = |version: u8, flags: u16, entry_count: u32, manifest_len: u32| -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"FCA\0");
        b.push(version);
        b.extend_from_slice(&flags.to_be_bytes());
        b.extend_from_slice(&entry_count.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes()); // archive_ext_len
        b.extend_from_slice(&manifest_len.to_be_bytes());
        b.extend_from_slice(&0u64.to_be_bytes()); // total_file_bytes
        b
    };

    let mut bad_magic = header(0x01, 0, 1, 10);
    bad_magic[0] = b'X';

    vec![
        ("fca-bad-magic.fcr", bad_magic),
        ("fca-unsupported-version.fcr", header(0x02, 0, 1, 10)),
        ("fca-nonzero-flags.fcr", header(0x01, 1, 1, 10)),
        ("fca-zero-entry-count.fcr", header(0x01, 0, 0, 10)),
        ("fca-zero-manifest-len.fcr", header(0x01, 0, 1, 0)),
    ]
}

/// Writes the header-fixed / recipient-entry structural and per-field-tamper
/// reject fixtures by mutating the valid argon2id base at frozen v1 offsets,
/// and returns their manifest rows. Covers `FORMAT.md` §3.2 (`header_flags`),
/// §3.4 (reserved and native-critical flag bits), §3.3 (entry framing), and
/// §4.1 (each authenticated recipient-body field detected independently).
/// argon2id byte offsets: header_flags 12; entry at 43 (type_name_len 43,
/// recipient_flags 45, body_len 47, type_name 51, body 59 — salt 59,
/// wrapped_file_key 127).
fn write_header_entry_reject_cases(cases: &Path) -> Vec<Case> {
    let right = passphrase_credential(SUITE_PASSPHRASE);
    let base = "argon2id-valid.fcr";
    mutated_copy(cases, base, "header-flags-nonzero.fcr", |b| b[12] = 0x01);
    mutated_copy(cases, base, "entry-reserved-flag.fcr", |b| b[46] = 0x02);
    mutated_copy(cases, base, "entry-critical-flag.fcr", |b| b[46] = 0x01);
    mutated_copy(cases, base, "entry-typename-len-zero.fcr", |b| {
        b[43] = 0;
        b[44] = 0;
    });
    mutated_copy(cases, base, "argon2id-salt-tamper.fcr", |b| b[59] ^= 0xFF);
    mutated_copy(cases, base, "argon2id-wrappedkey-tamper.fcr", |b| {
        b[127] ^= 0xFF
    });

    // x25519 per-field tamper (FORMAT.md §4.2). x25519 entry body starts at
    // offset 57: ephemeral_public_key 57, wrap_nonce 89, wrapped_file_key 113.
    let key_a = private_key_credential("recipient-a.private.key");
    mutated_copy(
        cases,
        "x25519-valid.fcr",
        "x25519-ephemeral-tamper.fcr",
        |b| b[57] ^= 0xFF,
    );
    mutated_copy(
        cases,
        "x25519-valid.fcr",
        "x25519-wrappedkey-tamper.fcr",
        |b| b[113] ^= 0xFF,
    );

    vec![
        Case::err(
            "cases/header-flags-nonzero.fcr",
            &right,
            "InvalidFormat(MalformedHeader)",
            "File header is malformed",
        ),
        Case::err(
            "cases/entry-reserved-flag.fcr",
            &right,
            "InvalidFormat(RecipientFlagsReserved)",
            "Recipient entry uses reserved flag bits",
        ),
        Case::err(
            "cases/entry-critical-flag.fcr",
            &right,
            "InvalidFormat(MalformedRecipientEntry)",
            "Recipient entry is malformed",
        ),
        Case::err(
            "cases/entry-typename-len-zero.fcr",
            &right,
            "InvalidFormat(MalformedRecipientEntry)",
            "Recipient entry is malformed",
        ),
        Case::err(
            "cases/argon2id-salt-tamper.fcr",
            &right,
            "RecipientUnwrapFailed(argon2id)",
            "Decryption failed: wrong passphrase or modified file",
        ),
        Case::err(
            "cases/argon2id-wrappedkey-tamper.fcr",
            &right,
            "RecipientUnwrapFailed(argon2id)",
            "Decryption failed: wrong passphrase or modified file",
        ),
        Case::err(
            "cases/x25519-ephemeral-tamper.fcr",
            &key_a,
            "RecipientUnwrapFailed(x25519)",
            "Decryption failed: no matching recipient or modified file",
        ),
        Case::err(
            "cases/x25519-wrappedkey-tamper.fcr",
            &key_a,
            "RecipientUnwrapFailed(x25519)",
            "Decryption failed: no matching recipient or modified file",
        ),
    ]
}

/// Writes the crafted FerroCrypt-archive reject fixtures (a valid outer
/// container around malformed inner-archive bytes) and returns their manifest
/// rows. Each decrypts through the outer layer and must fail in the inner
/// archive parser with the listed class and message.
fn write_fca_reject_cases(cases: &Path) -> Vec<Case> {
    let right = passphrase_credential(SUITE_PASSPHRASE);
    // Kept in the same order as `crafted_fca_payloads`.
    let specs: [(&str, &str, &str); 5] = [
        (
            "fca-bad-magic.fcr",
            "MalformedArchive",
            "Malformed archive: bad magic",
        ),
        (
            "fca-unsupported-version.fcr",
            "InvalidFormat(UnsupportedArchiveVersion)",
            "Unsupported archive version (v2). Upgrade FerroCrypt.",
        ),
        (
            "fca-nonzero-flags.fcr",
            "MalformedArchive",
            "Malformed archive: header has non-zero flags",
        ),
        (
            "fca-zero-entry-count.fcr",
            "MalformedArchive",
            "Malformed archive: no entries declared",
        ),
        (
            "fca-zero-manifest-len.fcr",
            "MalformedArchive",
            "Malformed archive: manifest bytes do not match the declared layout",
        ),
    ];

    let mut rows = Vec::new();
    for ((name, raw), (spec_name, class, message)) in
        crafted_fca_payloads().iter().zip(specs.iter())
    {
        assert_eq!(name, spec_name, "payload and spec order must match");
        let file_key = FileKey::generate().expect("suite file key");
        let entry = argon2id_entry(&file_key);
        build_crafted_payload_fcr(cases, name, &file_key, std::slice::from_ref(&entry), raw)
            .expect("build FCA reject fixture");
        rows.push(Case::err(&format!("cases/{name}"), &right, class, message));
    }
    rows
}

/// Writes the `private.key` reject fixtures and returns their manifest rows.
/// Structural rejects are validated directly through `validate_private_key_file`
/// (the `validate-private-key` action); the unlock reject is structurally valid
/// but has a modified wrapped secret, so it is exercised as a decrypt
/// credential against `x25519-valid.fcr` and surfaces as an AEAD failure.
/// Offsets follow the `FORMAT.md` §8 fixed header (magic 0..4, version 4,
/// kind 5, key_flags 6..8).
fn write_private_key_reject_cases(keys: &Path, cases: &Path) -> Vec<Case> {
    let valid =
        fs::read(keys.join("recipient-a.private.key")).expect("read recipient A private key");
    let write_mutated = |name: &str, mutate: &dyn Fn(&mut Vec<u8>)| {
        let mut bytes = valid.clone();
        mutate(&mut bytes);
        fs::write(cases.join(name), &bytes).expect("write private-key reject fixture");
    };

    write_mutated("privatekey-bad-magic.private.key", &|b| b[0] ^= 0xFF);
    write_mutated("privatekey-newer-version.private.key", &|b| b[4] = 0x02);
    write_mutated("privatekey-wrong-kind.private.key", &|b| b[5] = 0x45);
    write_mutated("privatekey-nonzero-flags.private.key", &|b| b[6] = 0x01);
    write_mutated("privatekey-truncated.private.key", &|b| {
        b.truncate(b.len() - 20);
    });
    write_mutated("privatekey-trailing-byte.private.key", &|b| b.push(0xAA));

    // Structurally valid, but one byte of the wrapped secret is flipped, so
    // AEAD authentication fails at unlock. Lives in keys/ because it is used
    // as a decrypt credential rather than validated on its own.
    let mut secret_tamper = valid.clone();
    let last = secret_tamper.len() - 1;
    secret_tamper[last] ^= 0x01;
    fs::write(
        keys.join("recipient-a-tampered.private.key"),
        &secret_tamper,
    )
    .expect("write tampered private key");

    vec![
        Case::private_key_err(
            "cases/privatekey-bad-magic.private.key",
            "InvalidFormat(NotAKeyFile)",
            "Not a FerroCrypt key file",
        ),
        Case::private_key_err(
            "cases/privatekey-newer-version.private.key",
            "UnsupportedVersion(NewerKey)",
            "Newer key format (v2). Upgrade FerroCrypt.",
        ),
        Case::private_key_err(
            "cases/privatekey-wrong-kind.private.key",
            "InvalidFormat(WrongKeyFileType)",
            "Wrong key file kind (public vs private)",
        ),
        Case::private_key_err(
            "cases/privatekey-nonzero-flags.private.key",
            "InvalidFormat(MalformedPrivateKey)",
            "Private key is malformed",
        ),
        Case::private_key_err(
            "cases/privatekey-truncated.private.key",
            "InvalidFormat(MalformedPrivateKey)",
            "Private key is malformed",
        ),
        Case::private_key_err(
            "cases/privatekey-trailing-byte.private.key",
            "InvalidFormat(MalformedPrivateKey)",
            "Private key is malformed",
        ),
        Case::err(
            "cases/x25519-valid.fcr",
            &private_key_credential("recipient-a-tampered.private.key"),
            "KeyFileUnlockFailed",
            "Private key unlock failed: wrong passphrase or modified key file",
        ),
    ]
}

fn write_manifest(suite: &Path, rows: &[Case]) {
    let mut out = String::new();
    out.push_str("# FerroCrypt v1 edge-case test-vector manifest.\n");
    out.push_str("# Columns (tab-separated): file, action, credential, expect, error_class, error_message.\n");
    out.push_str("# action: decrypt (open the .fcr and decrypt with the credential),\n");
    out.push_str("# read-public-key (parse the public.key text file), or validate-private-key\n");
    out.push_str("# (structurally validate the private.key file).\n");
    out.push_str(
        "# credential: passphrase:<literal>, private-key:<path>,unlock=<literal>, or -.\n",
    );
    out.push_str(
        "# expect ok: decryption must succeed and reproduce plaintext.txt byte-for-byte.\n",
    );
    out.push_str(
        "# expect error: the attempt must fail; error_class names the typed CryptoError\n",
    );
    out.push_str("# variant and error_message is the exact user-facing message.\n");
    for row in rows {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            row.file, row.action, row.credential, row.expect, row.error_class, row.error_message
        ));
    }
    fs::write(suite.join("manifest.tsv"), out).expect("write manifest.tsv");
}

/// Fixed seed for the deterministic RNG the generator runs under, so
/// regenerating the corpus produces byte-identical output every time and a
/// re-run is a clean (empty) diff. Changing it re-randomizes every fixture.
const SUITE_SEED: u64 = 0xFECC_0000_5EED_0001;

/// Regenerates the committed suite corpus. Ignored in normal test runs;
/// see the module docs for the invocation and the commit workflow.
#[test]
#[ignore]
fn regenerate_suite_vectors() {
    crate::crypto::keys::with_deterministic_rng(SUITE_SEED, regenerate_suite_vectors_inner);
}

fn regenerate_suite_vectors_inner() {
    let suite = suite_dir();
    let cases = suite.join("cases");
    let keys = suite.join("keys");
    for dir in [&cases, &keys] {
        if dir.exists() {
            fs::remove_dir_all(dir).expect("clean suite subdirectory");
        }
        fs::create_dir_all(dir).expect("create suite subdirectory");
    }

    let plaintext = suite.join("plaintext.txt");
    fs::write(&plaintext, PLAINTEXT).expect("write plaintext.txt");
    // Pin the mode so the file permission bits the archiver records in every
    // fixture do not depend on the umask that created plaintext.txt (see
    // PLAINTEXT_FILE_MODE).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&plaintext, fs::Permissions::from_mode(PLAINTEXT_FILE_MODE))
            .expect("pin plaintext.txt mode");
    }
    fs::write(suite.join("SUITE-VERSION"), "1\n").expect("write SUITE-VERSION");

    generate_key_pair(&keys, "a");
    generate_key_pair(&keys, "b");

    let right = passphrase_credential(SUITE_PASSPHRASE);
    let wrong = passphrase_credential(WRONG_PASSPHRASE);
    let key_a = private_key_credential("recipient-a.private.key");
    let key_b = private_key_credential("recipient-b.private.key");
    let mut rows: Vec<Case> = Vec::new();

    // ── Valid bases, written through the public API ────────────────────
    Encryptor::with_passphrase(suite_passphrase())
        .kdf_params(KdfParams::test_fast_default())
        .save_as(cases.join("argon2id-valid.fcr"))
        .write(&plaintext, &cases, |_| {})
        .expect("encrypt argon2id base");
    Encryptor::with_public_key(PublicKey::from_key_file(
        keys.join("recipient-a.public.key"),
    ))
    .save_as(cases.join("x25519-valid.fcr"))
    .write(&plaintext, &cases, |_| {})
    .expect("encrypt x25519 base");
    Encryptor::with_public_keys([
        PublicKey::from_key_file(keys.join("recipient-a.public.key")),
        PublicKey::from_key_file(keys.join("recipient-b.public.key")),
    ])
    .expect("two-recipient encryptor")
    .save_as(cases.join("x25519-multi-valid.fcr"))
    .write(&plaintext, &cases, |_| {})
    .expect("encrypt two-recipient base");

    rows.push(Case::ok("cases/argon2id-valid.fcr", &right));
    rows.push(Case::ok("cases/x25519-valid.fcr", &key_a));
    rows.push(Case::ok("cases/x25519-multi-valid.fcr", &key_a));
    rows.push(Case::ok("cases/x25519-multi-valid.fcr", &key_b));
    rows.push(Case::err(
        "cases/argon2id-valid.fcr",
        &wrong,
        "RecipientUnwrapFailed(argon2id)",
        "Decryption failed: wrong passphrase or modified file",
    ));
    rows.push(Case::err(
        "cases/x25519-valid.fcr",
        &key_b,
        "RecipientUnwrapFailed(x25519)",
        "Decryption failed: no matching recipient or modified file",
    ));

    // ── Corrupted prefix and truncated header ──────────────────────────
    mutated_copy(&cases, "argon2id-valid.fcr", "prefix-bad-magic.fcr", |b| {
        b[PREFIX_MAGIC_OFFSET] ^= 0xFF;
    });
    mutated_copy(
        &cases,
        "argon2id-valid.fcr",
        "prefix-newer-version.fcr",
        |b| b[PREFIX_VERSION_OFFSET] = 0x02,
    );
    mutated_copy(&cases, "argon2id-valid.fcr", "prefix-wrong-kind.fcr", |b| {
        b[PREFIX_KIND_OFFSET] = b'K';
    });
    mutated_copy(
        &cases,
        "argon2id-valid.fcr",
        "prefix-nonzero-flags.fcr",
        |b| b[PREFIX_FLAGS_OFFSET] = 0x01,
    );
    mutated_copy(
        &cases,
        "argon2id-valid.fcr",
        "prefix-oversized-header-len.fcr",
        |b| {
            b[PREFIX_HEADER_LEN_OFFSET..PREFIX_HEADER_LEN_OFFSET + 4]
                .copy_from_slice(&(HEADER_LEN_MAX + 1).to_be_bytes());
        },
    );
    mutated_copy(&cases, "argon2id-valid.fcr", "header-truncated.fcr", |b| {
        b.truncate(PREFIX_SIZE + 10);
    });
    rows.push(Case::err(
        "cases/prefix-bad-magic.fcr",
        "-",
        "InvalidFormat(BadMagic)",
        "Not a FerroCrypt file",
    ));
    rows.push(Case::err(
        "cases/prefix-newer-version.fcr",
        "-",
        "UnsupportedVersion(NewerFile)",
        "Newer file format (v2). Upgrade FerroCrypt.",
    ));
    rows.push(Case::err(
        "cases/prefix-wrong-kind.fcr",
        "-",
        "InvalidFormat(WrongKind)",
        "Wrong file kind: 0x4B",
    ));
    rows.push(Case::err(
        "cases/prefix-nonzero-flags.fcr",
        "-",
        "InvalidFormat(MalformedHeader)",
        "File header is malformed",
    ));
    rows.push(Case::err(
        "cases/prefix-oversized-header-len.fcr",
        "-",
        "InvalidFormat(OversizedHeader)",
        &format!("File header is too large ({} bytes)", HEADER_LEN_MAX + 1),
    ));
    rows.push(Case::err(
        "cases/header-truncated.fcr",
        "-",
        "InvalidFormat(Truncated)",
        "File is truncated or corrupted",
    ));

    // ── Header MAC tamper: flip a stream_nonce byte after writing ──────
    let nonce_tail = PREFIX_SIZE + HEADER_FIXED_SIZE - 1;
    mutated_copy(
        &cases,
        "argon2id-valid.fcr",
        "header-mac-tampered-passphrase.fcr",
        |b| b[nonce_tail] ^= 0x01,
    );
    mutated_copy(
        &cases,
        "x25519-multi-valid.fcr",
        "header-mac-tampered-x25519.fcr",
        |b| b[nonce_tail] ^= 0x01,
    );
    rows.push(Case::err(
        "cases/header-mac-tampered-passphrase.fcr",
        &right,
        "HeaderTampered",
        "Decryption failed: file header was modified or corrupted",
    ));
    rows.push(Case::err(
        "cases/header-mac-tampered-x25519.fcr",
        &key_a,
        "HeaderMacFailedAfterUnwrap(x25519)",
        "Decryption failed: file header was modified or corrupted",
    ));

    // ── Payload truncation, tamper, and trailing data ───────────────────
    // A valid stream always ends with a final-flag chunk, so a payload
    // with zero bytes is provably truncated. A partial cut inside a
    // chunk is deliberately NOT this class: STREAM cannot tell a
    // shortened chunk from a modified one, so it reports tampering —
    // that shape is covered by `payload-tampered.fcr`.
    mutated_copy(&cases, "argon2id-valid.fcr", "payload-truncated.fcr", |b| {
        let cut = payload_offset(b);
        assert!(cut < b.len(), "base fixture has no payload to remove");
        b.truncate(cut);
    });
    mutated_copy(&cases, "argon2id-valid.fcr", "payload-tampered.fcr", |b| {
        let target = payload_offset(b) + 3;
        assert!(target < b.len(), "payload too short to tamper");
        b[target] ^= 0x01;
    });
    mutated_copy(
        &cases,
        "argon2id-valid.fcr",
        "payload-trailing-data.fcr",
        |b| b.extend_from_slice(&[0xA5; 16]),
    );
    rows.push(Case::err(
        "cases/payload-truncated.fcr",
        &right,
        "PayloadTruncated",
        "Encrypted file is truncated",
    ));
    rows.push(Case::err(
        "cases/payload-tampered.fcr",
        &right,
        "PayloadTampered",
        "Decryption failed: file data was modified or corrupted",
    ));
    // A file-level append shifts the final-chunk boundary, so STREAM's
    // per-chunk nonce binding reports it as payload tampering. The
    // distinct trailing-data class exists for readers whose input
    // signals end-of-stream at the chunk boundary and then yields more
    // bytes, which a committed file cannot express.
    rows.push(Case::err(
        "cases/payload-trailing-data.fcr",
        &right,
        "PayloadTampered",
        "Decryption failed: file data was modified or corrupted",
    ));

    // ── All-zero X25519 ephemeral: file-fatal on any credential ────────
    mutated_copy(
        &cases,
        "x25519-valid.fcr",
        "x25519-zero-ephemeral.fcr",
        |b| {
            let body =
                PREFIX_SIZE + HEADER_FIXED_SIZE + ENTRY_HEADER_SIZE + x25519::TYPE_NAME.len();
            b[body..body + x25519::PUBLIC_KEY_SIZE].fill(0);
        },
    );
    rows.push(Case::err(
        "cases/x25519-zero-ephemeral.fcr",
        &key_a,
        "InvalidFormat(MalformedRecipientEntry)",
        "Recipient entry is malformed",
    ));

    // ── Extension-region TLV cases (valid MAC, crafted ext bytes) ──────
    let tlv_fcr = |name: &str, ext: Vec<u8>| {
        let file_key = FileKey::generate().expect("suite file key");
        let entry = argon2id_entry(&file_key);
        build_crafted_fcr(
            &plaintext,
            &cases,
            name,
            &file_key,
            std::slice::from_ref(&entry),
            &ext,
        )
        .expect("build TLV fixture");
    };

    let mut descending = tlv_bytes(0x0002, &[0xAA]);
    descending.extend_from_slice(&tlv_bytes(0x0001, &[0xBB]));
    tlv_fcr("tlv-bad-order.fcr", descending);

    let mut duplicate = tlv_bytes(0x0001, &[0xAA]);
    duplicate.extend_from_slice(&tlv_bytes(0x0001, &[0xBB]));
    tlv_fcr("tlv-duplicate-tag.fcr", duplicate);

    // tag 0x0001 declaring 100 value bytes with only 3 present.
    let mut len_past_end = Vec::new();
    len_past_end.extend_from_slice(&0x0001u16.to_be_bytes());
    len_past_end.extend_from_slice(&100u32.to_be_bytes());
    len_past_end.extend_from_slice(&[0xAA; 3]);
    tlv_fcr("tlv-len-past-end.fcr", len_past_end);

    tlv_fcr(
        "tlv-unknown-ignorable.fcr",
        tlv_bytes(0x0042, b"suite-metadata"),
    );
    tlv_fcr("tlv-unknown-critical.fcr", tlv_bytes(0x8001, &[0xAA; 4]));

    for (name, class, message) in [
        ("tlv-bad-order.fcr", "InvalidFormat(MalformedTlv)", None),
        ("tlv-duplicate-tag.fcr", "InvalidFormat(MalformedTlv)", None),
        ("tlv-len-past-end.fcr", "InvalidFormat(MalformedTlv)", None),
        (
            "tlv-unknown-critical.fcr",
            "InvalidFormat(UnknownCriticalTag)",
            Some("Unknown required file feature (tag 0x8001). Upgrade FerroCrypt."),
        ),
    ] {
        rows.push(Case::err(
            &format!("cases/{name}"),
            &right,
            class,
            message.unwrap_or("Extension region is malformed"),
        ));
    }
    rows.push(Case::ok("cases/tlv-unknown-ignorable.fcr", &right));

    // ── Out-of-range KDF parameters under a valid header MAC ───────────
    let fast = KdfParams::test_fast_default();
    build_bad_kdf_fcr(
        &plaintext,
        &cases,
        "kdf-mem-over-max.fcr",
        KdfParams {
            mem_cost: KdfParams::MAX_MEM_COST + 1,
            ..fast
        },
    )
    .expect("build kdf-mem fixture");
    build_bad_kdf_fcr(
        &plaintext,
        &cases,
        "kdf-lanes-zero.fcr",
        KdfParams { lanes: 0, ..fast },
    )
    .expect("build kdf-lanes fixture");
    build_bad_kdf_fcr(
        &plaintext,
        &cases,
        "kdf-time-over-max.fcr",
        KdfParams {
            time_cost: 13,
            ..fast
        },
    )
    .expect("build kdf-time fixture");
    rows.push(Case::err(
        "cases/kdf-mem-over-max.fcr",
        &right,
        "InvalidKdfParams(MemoryCost)",
        &format!(
            "File has invalid KDF settings ({} KiB memory)",
            KdfParams::MAX_MEM_COST + 1
        ),
    ));
    rows.push(Case::err(
        "cases/kdf-lanes-zero.fcr",
        &right,
        "InvalidKdfParams(Parallelism)",
        "File has invalid KDF settings (parallelism 0)",
    ));
    rows.push(Case::err(
        "cases/kdf-time-over-max.fcr",
        &right,
        "InvalidKdfParams(TimeCost)",
        "File has invalid KDF settings (time cost 13)",
    ));

    // ── Recipient-list cases ────────────────────────────────────────────
    {
        let file_key = FileKey::generate().expect("suite file key");
        build_crafted_fcr(
            &plaintext,
            &cases,
            "recipient-unknown-critical.fcr",
            &file_key,
            &[
                x25519_entry(&keys, "recipient-a.public.key", &file_key),
                unknown_entry(true),
            ],
            b"",
        )
        .expect("build unknown-critical fixture");
    }
    {
        let file_key = FileKey::generate().expect("suite file key");
        build_crafted_fcr(
            &plaintext,
            &cases,
            "recipient-unknown-only.fcr",
            &file_key,
            &[unknown_entry(false)],
            b"",
        )
        .expect("build unknown-only fixture");
    }
    {
        let file_key = FileKey::generate().expect("suite file key");
        build_crafted_fcr(
            &plaintext,
            &cases,
            "recipient-mixed-exclusive.fcr",
            &file_key,
            &[
                argon2id_entry(&file_key),
                x25519_entry(&keys, "recipient-a.public.key", &file_key),
            ],
            b"",
        )
        .expect("build mixed-recipient fixture");
    }
    {
        let file_key = FileKey::generate().expect("suite file key");
        build_crafted_fcr(
            &plaintext,
            &cases,
            "recipient-unknown-skipped.fcr",
            &file_key,
            &[
                unknown_entry(false),
                x25519_entry(&keys, "recipient-a.public.key", &file_key),
            ],
            b"",
        )
        .expect("build unknown-skipped fixture");
    }
    rows.push(Case::err(
        "cases/recipient-unknown-critical.fcr",
        "-",
        "UnknownCriticalRecipient(mlkem768)",
        "Unsupported recipient `mlkem768`. Upgrade FerroCrypt.",
    ));
    rows.push(Case::err(
        "cases/recipient-unknown-only.fcr",
        "-",
        "NoSupportedRecipient",
        "Decryption failed: no supported recipient",
    ));
    rows.push(Case::err(
        "cases/recipient-mixed-exclusive.fcr",
        "-",
        "IncompatibleRecipients(argon2id)",
        "Recipient `argon2id` mixed with another recipient",
    ));
    rows.push(Case::ok("cases/recipient-unknown-skipped.fcr", &key_a));

    // ── Malformed public.key text files ─────────────────────────────────
    rows.extend(write_public_key_cases(&suite, &cases));

    // ── Malformed / tampered private.key files ──────────────────────────
    rows.extend(write_private_key_reject_cases(&keys, &cases));

    // ── Crafted malformed inner-archive (FCA) payloads ──────────────────
    rows.extend(write_fca_reject_cases(&cases));

    // ── Header-fixed / entry structural rejects + per-field tamper ──────
    rows.extend(write_header_entry_reject_cases(&cases));

    write_manifest(&suite, &rows);
}
