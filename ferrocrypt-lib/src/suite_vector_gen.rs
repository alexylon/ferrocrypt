//! Generator for the committed `testvectors/suite/` edge-case corpus.
//!
//! The suite corpus is the public set of must-reject (and a few
//! must-accept) fixtures required by `FORMAT.md` §12. Every fixture is
//! committed as real bytes plus a `manifest.tsv` row naming the public-API
//! action, the credential, and whether the case must be accepted or
//! rejected. An independent implementation can replay those four columns
//! without running this crate's test code. The remaining two columns,
//! `error_class` and `error_message`, hold Rust variant spellings and
//! English display text, which `FORMAT.md` §12.1 keeps out of the
//! cross-language contract; they are FerroCrypt regression detail. The
//! frozen `testvectors/wire/` corpus (§12.3) is what carries per-case
//! diagnostics across implementations. The `tests/testvector_suite.rs`
//! integration test replays the manifest through the public API on every
//! `cargo test` run.
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

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{KeyInit as AeadKeyInit, stream},
};
use secrecy::SecretString;

use crate::crypto::kdf::{ARGON2_SALT_SIZE, KDF_PARAMS_SIZE, KdfLimit, KdfParams};
use crate::crypto::keys::{DerivedSubkeys, FileKey, derive_subkeys, random_bytes};
use crate::crypto::stream::{BUFFER_SIZE, STREAM_NONCE_SIZE};
use crate::crypto::tlv::tlv_bytes;
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

/// Content of `plaintext.txt` — the source file every valid `.fcr` fixture
/// encrypts and every `ok` decrypt row must reproduce.
const PLAINTEXT: &str = "FerroCrypt v1 test-vector suite plaintext.\n";

/// Fixed Unix mode pinned on `plaintext.txt` before it is archived. The
/// archiver records the source file's permission bits in every fixture's
/// manifest, so without a fixed mode the umask that created `plaintext.txt`
/// would leak into the encrypted bytes and break byte-identical
/// regeneration. `0o644` matches the archiver's non-Unix default mode, so the
/// corpus stays reproducible on every platform.
const PLAINTEXT_FILE_MODE: u32 = 0o644;

/// Grammar-valid but unknown recipient `type_name` used by the
/// unknown-recipient fixtures. Plugin-namespaced on purpose: `FORMAT.md`
/// §3.3.1 gives every name containing `/` to external implementations,
/// so FerroCrypt can never define this one and the fixtures cannot be
/// invalidated by a future native recipient type.
const UNKNOWN_TYPE_NAME: &str = "test/unknown";

// u-coordinate of a known small-order Curve25519 point (`FORMAT.md`
// §4.2): canonical and nonzero, so it passes the credential-independent
// preflight, while X25519 with any clamped scalar yields the prohibited
// all-zero shared secret.
const SMALL_ORDER_EPHEMERAL: [u8; 32] = [
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
    0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
];

// `.fcr` prefix field offsets per `FORMAT.md` §3.1. The layout is frozen
// at version `0x01`, so the generator pins the byte positions directly.
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

    fn key_ok(file: &str) -> Self {
        Self {
            action: "read-public-key",
            credential: "-".to_string(),
            ..Self::ok(file, "-")
        }
    }

    fn private_key_err(file: &str, class: &str, message: &str) -> Self {
        Self {
            action: "validate-private-key",
            credential: "-".to_string(),
            ..Self::err(file, "-", class, message)
        }
    }

    fn private_key_ok(file: &str) -> Self {
        Self {
            action: "validate-private-key",
            credential: "-".to_string(),
            ..Self::ok(file, "-")
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
    let prepared = crate::archive::prepare_archive(plaintext, ArchiveLimits::default())?;
    crate::container::write_encrypted_file(
        prepared,
        cases,
        Some(&cases.join(name)),
        "suite",
        &built,
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
/// whose KDF parameter field is replaced before the header MAC is
/// computed. The replacement may be structurally invalid or merely
/// above a local resource cap; in either case the MAC remains valid so
/// the fixture isolates the KDF policy outcome.
fn build_rewritten_kdf_fcr(
    plaintext: &Path,
    cases: &Path,
    name: &str,
    replacement_params: KdfParams,
) -> Result<(), CryptoError> {
    let file_key = FileKey::generate()?;
    let mut entry = argon2id_entry(&file_key);
    entry.body[ARGON2_SALT_SIZE..ARGON2_SALT_SIZE + KDF_PARAMS_SIZE]
        .copy_from_slice(&replacement_params.to_bytes());
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
            "InvalidFormat(MalformedPublicKey)",
            "Public key is malformed",
        ),
        Case::key_err(
            "cases/public-key-bad-bech32.key",
            "InvalidFormat(MalformedPublicKey)",
            "Public key is malformed",
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

/// Builds a valid outer container and valid one-chunk FCA plaintext, then
/// seals that plaintext as a non-final chunk followed by an authenticated
/// empty final chunk. `FORMAT.md` §5 requires the full plaintext chunk itself
/// to carry the final flag, so this fixture isolates the reader-side
/// canonicality rejection without introducing an archive or authentication
/// defect.
fn build_empty_final_chunk_fcr(
    cases: &Path,
    name: &str,
    file_key: &FileKey,
    entries: &[RecipientEntry],
) -> Result<(), CryptoError> {
    const ROOT_NAME: &str = "payload.bin";
    let archive_overhead = crate::archive::format::FCA_HEADER_SIZE
        + crate::archive::format::FCA_ENTRY_FIXED_SIZE
        + ROOT_NAME.len();
    let content_len =
        BUFFER_SIZE
            .checked_sub(archive_overhead)
            .ok_or(CryptoError::InternalInvariant(
                "suite archive overhead exceeds one payload chunk",
            ))?;

    let staging = tempfile::tempdir()?;
    let source = staging.path().join(ROOT_NAME);
    fs::write(&source, vec![0x5A; content_len])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&source, fs::Permissions::from_mode(PLAINTEXT_FILE_MODE))?;
    }
    let raw_payload =
        crate::archive::encode::archive(&source, Vec::new(), ArchiveLimits::default())?;
    if raw_payload.len() != BUFFER_SIZE {
        return Err(CryptoError::InternalInvariant(
            "suite FCA payload is not exactly one stream chunk",
        ));
    }

    let built = craft_encrypted_header(file_key, entries, b"")?;
    let cipher = XChaCha20Poly1305::new(built.payload_key.expose().into());
    let mut encryptor = stream::EncryptorBE32::from_aead(cipher, (&built.stream_nonce).into());
    let mut encrypted_payload = raw_payload;
    encryptor
        .encrypt_next_in_place(b"", &mut encrypted_payload)
        .map_err(|_| {
            CryptoError::InternalCryptoFailure("suite non-final payload encryption failed")
        })?;
    let mut empty_final = Vec::new();
    encryptor
        .encrypt_last_in_place(b"", &mut empty_final)
        .map_err(|_| CryptoError::InternalCryptoFailure("suite empty-final encryption failed"))?;

    let mut out = Vec::new();
    out.extend_from_slice(&built.prefix_bytes);
    out.extend_from_slice(&built.header_bytes);
    out.extend_from_slice(&built.header_mac);
    out.extend_from_slice(&encrypted_payload);
    out.extend_from_slice(&empty_final);
    fs::write(cases.join(name), out)?;
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
/// reject fixtures by mutating the valid argon2id base at frozen byte offsets,
/// and returns their manifest rows. Covers `FORMAT.md` §3.2 (`header_flags`),
/// §3.4 (reserved and native-critical flag bits), §3.3 (entry framing), and
/// representative §4.1/§4.2 recipient-body tampering. The completion cases
/// below add the remaining independently authenticated body fields.
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
            "Unsupported FCA archive version byte 0x02. Upgrade FerroCrypt.",
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
    // An encrypted-file `E` byte in the private-key `kind` field is a
    // binary artifact mismatch, not a public/private key-file crossing.
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
            "Unsupported private-key version byte 0x02. Upgrade FerroCrypt.",
        ),
        Case::private_key_err(
            "cases/privatekey-wrong-kind.private.key",
            "InvalidFormat(WrongKind)",
            "Wrong file kind: 0x45",
        ),
        // Suite revision 5 pins both genuine public/private crossings so
        // `WrongKeyFileType` cannot drift back into generic kind-byte use.
        Case::private_key_err(
            "keys/recipient-a.public.key",
            "InvalidFormat(WrongKeyFileType)",
            "Wrong key file kind (public vs private)",
        ),
        Case::key_err(
            "keys/recipient-a.private.key",
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

/// Builds a complete one-file FCA payload with caller-supplied archive- and
/// entry-level extension regions. This deliberately writes the small frozen
/// wire layout directly: valid extension bytes exercise the accept path, while
/// malformed or critical bytes must survive into the authenticated archive so
/// the reader, rather than the fixture writer, rejects them.
fn single_file_fca_payload(archive_ext: &[u8], entry_ext: &[u8]) -> Vec<u8> {
    const PATH: &str = "plaintext.txt";

    let manifest_len = crate::archive::format::checked_entry_wire_len(PATH.len(), entry_ext.len())
        .expect("suite FCA manifest length");
    let mut out = crate::archive::format::write_fca_header(
        Vec::new(),
        1,
        u32::try_from(archive_ext.len()).expect("suite archive_ext length"),
        u32::try_from(manifest_len).expect("suite manifest length"),
        PLAINTEXT.len() as u64,
    )
    .expect("write suite FCA header");
    out.extend_from_slice(archive_ext);

    out.push(crate::archive::format::KIND_FILE);
    out.push(0); // entry_flags
    out.extend_from_slice(
        &u16::try_from(PLAINTEXT_FILE_MODE)
            .expect("suite file mode")
            .to_be_bytes(),
    );
    out.extend_from_slice(
        &u16::try_from(PATH.len())
            .expect("suite path length")
            .to_be_bytes(),
    );
    out.extend_from_slice(
        &u32::try_from(entry_ext.len())
            .expect("suite entry_ext length")
            .to_be_bytes(),
    );
    out.extend_from_slice(&(PLAINTEXT.len() as u64).to_be_bytes());
    out.extend_from_slice(PATH.as_bytes());
    out.extend_from_slice(entry_ext);
    out.extend_from_slice(PLAINTEXT.as_bytes());
    out
}

/// Encrypts one crafted FCA extension payload under a valid passphrase
/// recipient and header MAC.
fn write_fca_extension_fixture(cases: &Path, name: &str, archive_ext: &[u8], entry_ext: &[u8]) {
    let file_key = FileKey::generate().expect("suite file key");
    let entry = argon2id_entry(&file_key);
    let raw_payload = single_file_fca_payload(archive_ext, entry_ext);
    build_crafted_payload_fcr(
        cases,
        name,
        &file_key,
        std::slice::from_ref(&entry),
        &raw_payload,
    )
    .expect("build FCA extension fixture");
}

/// Appends the conformance cases added in suite revision 3. This function is
/// called only after every revision-2 RNG draw, preserving all previously
/// committed fixture bytes while completing the `FORMAT.md` §§4 and 12
/// matrices.
fn write_conformance_completion_cases(plaintext: &Path, cases: &Path, keys: &Path) -> Vec<Case> {
    let right = passphrase_credential(SUITE_PASSPHRASE);
    let key_a = private_key_credential("recipient-a.private.key");

    // Positive key-file rows let the manifest express successful parse and
    // validation actions, and make every committed key an exercised fixture.
    let mut rows = vec![
        Case::key_ok("keys/recipient-a.public.key"),
        Case::key_ok("keys/recipient-b.public.key"),
        Case::private_key_ok("keys/recipient-a.private.key"),
        Case::private_key_ok("keys/recipient-b.private.key"),
    ];

    // Complete independent recipient-body field tamper coverage. These are
    // byte mutations of the frozen valid bases and consume no RNG.
    let argon2id_body_offset =
        PREFIX_SIZE + HEADER_FIXED_SIZE + ENTRY_HEADER_SIZE + argon2id::TYPE_NAME.len();
    let argon2id_kdf_time_low_byte = argon2id_body_offset + ARGON2_SALT_SIZE + 7;
    let argon2id_wrap_nonce_offset = argon2id_body_offset + ARGON2_SALT_SIZE + KDF_PARAMS_SIZE;
    mutated_copy(
        cases,
        "argon2id-valid.fcr",
        "argon2id-kdf-tamper.fcr",
        |bytes| bytes[argon2id_kdf_time_low_byte] ^= 0x02,
    );
    mutated_copy(
        cases,
        "argon2id-valid.fcr",
        "argon2id-wrap-nonce-tamper.fcr",
        |bytes| bytes[argon2id_wrap_nonce_offset] ^= 0x01,
    );

    let x25519_body_offset =
        PREFIX_SIZE + HEADER_FIXED_SIZE + ENTRY_HEADER_SIZE + x25519::TYPE_NAME.len();
    let x25519_wrap_nonce_offset = x25519_body_offset + x25519::PUBLIC_KEY_SIZE;
    mutated_copy(
        cases,
        "x25519-valid.fcr",
        "x25519-wrap-nonce-tamper.fcr",
        |bytes| bytes[x25519_wrap_nonce_offset] ^= 0x01,
    );

    for file in [
        "cases/argon2id-kdf-tamper.fcr",
        "cases/argon2id-wrap-nonce-tamper.fcr",
    ] {
        rows.push(Case::err(
            file,
            &right,
            "RecipientUnwrapFailed(argon2id)",
            "Decryption failed: wrong passphrase or modified file",
        ));
    }
    rows.push(Case::err(
        "cases/x25519-wrap-nonce-tamper.fcr",
        &key_a,
        "RecipientUnwrapFailed(x25519)",
        "Decryption failed: no matching recipient or modified file",
    ));

    // Structurally valid KDF parameters one KiB above the default local
    // policy cap. The recipient was wrapped with fast parameters and the
    // field is replaced before MAC construction, so no large Argon2id run is
    // needed to exercise the reader's pre-KDF cap rejection.
    let default_kdf_limit = KdfLimit::default();
    let over_cap_mem = default_kdf_limit.max_mem_cost_kib + 1;
    build_rewritten_kdf_fcr(
        plaintext,
        cases,
        "kdf-mem-over-local-cap.fcr",
        KdfParams {
            mem_cost: over_cap_mem,
            ..KdfParams::test_fast_default()
        },
    )
    .expect("build KDF resource-cap fixture");
    rows.push(Case::err(
        "cases/kdf-mem-over-local-cap.fcr",
        &right,
        "KdfResourceCapExceeded",
        &format!(
            "Passphrase memory over limit ({over_cap_mem} KiB, limit {})",
            default_kdf_limit.max_mem_cost_kib
        ),
    ));

    // Native body-length and X25519 native-flag rejects carry a valid header
    // MAC, isolating the recipient-specific shape checks.
    {
        let file_key = FileKey::generate().expect("suite file key");
        let mut short = argon2id_entry(&file_key);
        assert_eq!(short.body.len(), argon2id::BODY_LENGTH);
        short.body.pop();
        build_crafted_fcr(
            plaintext,
            cases,
            "argon2id-invalid-length.fcr",
            &file_key,
            std::slice::from_ref(&short),
            b"",
        )
        .expect("build argon2id invalid-length fixture");
    }
    {
        let file_key = FileKey::generate().expect("suite file key");
        let valid = x25519_entry(keys, "recipient-a.public.key", &file_key);

        let mut short = valid.clone();
        assert_eq!(short.body.len(), x25519::BODY_LENGTH);
        short.body.pop();
        build_crafted_fcr(
            plaintext,
            cases,
            "x25519-invalid-length.fcr",
            &file_key,
            std::slice::from_ref(&short),
            b"",
        )
        .expect("build x25519 invalid-length fixture");

        let mut flagged = valid;
        flagged.recipient_flags = RECIPIENT_FLAG_CRITICAL;
        build_crafted_fcr(
            plaintext,
            cases,
            "x25519-invalid-flag.fcr",
            &file_key,
            std::slice::from_ref(&flagged),
            b"",
        )
        .expect("build x25519 invalid-flag fixture");
    }
    rows.push(Case::err(
        "cases/argon2id-invalid-length.fcr",
        &right,
        "InvalidFormat(MalformedRecipientEntry)",
        "Recipient entry is malformed",
    ));
    for file in [
        "cases/x25519-invalid-length.fcr",
        "cases/x25519-invalid-flag.fcr",
    ] {
        rows.push(Case::err(
            file,
            &key_a,
            "InvalidFormat(MalformedRecipientEntry)",
            "Recipient entry is malformed",
        ));
    }

    // Each FCA extension namespace gets an ignorable success case plus
    // malformed and unknown-critical rejections.
    let archive_ignorable = tlv_bytes(0x0042, b"archive-metadata");
    let entry_ignorable = tlv_bytes(0x0042, b"entry-metadata");
    let critical = tlv_bytes(0x8001, b"required");
    let mut malformed = tlv_bytes(0x0001, b"");
    malformed.pop();

    write_fca_extension_fixture(
        cases,
        "fca-archive-ext-ignorable.fcr",
        &archive_ignorable,
        b"",
    );
    write_fca_extension_fixture(cases, "fca-archive-ext-malformed.fcr", &malformed, b"");
    write_fca_extension_fixture(cases, "fca-archive-ext-critical.fcr", &critical, b"");
    write_fca_extension_fixture(cases, "fca-entry-ext-ignorable.fcr", b"", &entry_ignorable);
    write_fca_extension_fixture(cases, "fca-entry-ext-malformed.fcr", b"", &malformed);
    write_fca_extension_fixture(cases, "fca-entry-ext-critical.fcr", b"", &critical);

    rows.push(Case::ok("cases/fca-archive-ext-ignorable.fcr", &right));
    rows.push(Case::err(
        "cases/fca-archive-ext-malformed.fcr",
        &right,
        "InvalidFormat(MalformedTlv)",
        "Extension region is malformed",
    ));
    rows.push(Case::err(
        "cases/fca-archive-ext-critical.fcr",
        &right,
        "InvalidFormat(UnknownCriticalTag)",
        "Unknown required file feature (tag 0x8001). Upgrade FerroCrypt.",
    ));
    rows.push(Case::ok("cases/fca-entry-ext-ignorable.fcr", &right));
    rows.push(Case::err(
        "cases/fca-entry-ext-malformed.fcr",
        &right,
        "InvalidFormat(MalformedTlv)",
        "Extension region is malformed",
    ));
    rows.push(Case::err(
        "cases/fca-entry-ext-critical.fcr",
        &right,
        "InvalidFormat(UnknownCriticalTag)",
        "Unknown required file feature (tag 0x8001). Upgrade FerroCrypt.",
    ));

    rows
}

/// Appends the key-file conformance cases added in suite revision 4:
/// the `public.key` rejects independent implementations are most likely
/// to get wrong, plus a `private.key` with out-of-range `kdf_params`.
/// Every fixture is a deterministic re-encode or byte edit of committed
/// key material — no RNG draw — so all earlier fixture bytes stay
/// frozen.
fn write_key_file_completion_cases(suite: &Path, cases: &Path) -> Vec<Case> {
    use bech32::Fe32;
    use bech32::primitives::iter::{ByteIterExt, Fe32IterExt};

    let valid = fs::read_to_string(suite.join("keys/recipient-a.public.key"))
        .expect("read recipient A public key");
    let recipient = valid.strip_suffix('\n').unwrap_or(&valid);

    // Non-canonical 5-to-8 padding (`FORMAT.md` §7): set the lowest
    // padding bit of the final data character and recompute the BIP 173
    // checksum. Neither checksum covers the dropped padding bits, so
    // only the reader's canonical re-encode check can reject this.
    let (hrp, payload) = bech32::decode(recipient).expect("decode suite recipient string");
    assert!(
        (payload.len() * 8) % 5 != 0,
        "payload length leaves no padding bits; vary key_material length"
    );
    let mut fes: Vec<Fe32> = payload.iter().copied().bytes_to_fes().collect();
    let last = fes.pop().expect("payload is non-empty");
    let tweaked = Fe32::try_from(last.to_u8() | 0x01).expect("still a 5-bit value");
    assert_ne!(last, tweaked, "lowest padding bit must start unset");
    fes.push(tweaked);
    let non_canonical: String = fes
        .iter()
        .copied()
        .with_checksum::<bech32::Bech32>(&hrp)
        .chars()
        .collect();
    fs::write(
        cases.join("public-key-noncanonical-padding.key"),
        format!("{non_canonical}\n"),
    )
    .expect("write non-canonical padding fixture");

    // Newer public-key payload version: the version gate fires before
    // the internal checksum, so rewriting the leading payload byte is
    // enough.
    let mut newer_payload = payload;
    newer_payload[0] = 0x02;
    let newer = bech32::encode::<bech32::Bech32>(hrp, &newer_payload)
        .expect("re-encode newer-version payload");
    fs::write(
        cases.join("public-key-newer-version.key"),
        format!("{newer}\n"),
    )
    .expect("write newer-version fixture");

    // `FORMAT.md` §7.1 byte-exact grammar: CRLF and leading whitespace.
    fs::write(
        cases.join("public-key-crlf.key"),
        format!("{recipient}\r\n"),
    )
    .expect("write CRLF fixture");
    fs::write(
        cases.join("public-key-leading-space.key"),
        format!(" {recipient}\n"),
    )
    .expect("write leading-space fixture");

    // All-zero X25519 key material under a valid internal checksum, so
    // only the reader's zero-key ingress check can reject it.
    let zero = crate::key::public::encode_recipient_string_unchecked(x25519::TYPE_NAME, &[0u8; 32])
        .expect("encode all-zero recipient string");
    fs::write(
        cases.join("public-key-zero-material.key"),
        format!("{zero}\n"),
    )
    .expect("write all-zero fixture");

    // Cleartext `kdf_params` outside the structural bounds. Offsets
    // follow the `FORMAT.md` §8 fixed header (kdf_params 54..66,
    // mem_cost in the first four bytes).
    let over_max_mem = KdfParams::MAX_MEM_COST + 1;
    let mut bad_kdf =
        fs::read(suite.join("keys/recipient-a.private.key")).expect("read recipient A private key");
    bad_kdf[54..58].copy_from_slice(&over_max_mem.to_be_bytes());
    fs::write(cases.join("privatekey-bad-kdf.private.key"), &bad_kdf)
        .expect("write bad-kdf private-key fixture");

    vec![
        Case::key_err(
            "cases/public-key-noncanonical-padding.key",
            "InvalidFormat(MalformedPublicKey)",
            "Public key is malformed",
        ),
        Case::key_err(
            "cases/public-key-newer-version.key",
            "UnsupportedVersion(NewerPublicKey)",
            "Unsupported public-key version byte 0x02. Upgrade FerroCrypt.",
        ),
        Case::key_err(
            "cases/public-key-crlf.key",
            "InvalidFormat(MalformedPublicKey)",
            "Public key is malformed",
        ),
        Case::key_err(
            "cases/public-key-leading-space.key",
            "InvalidFormat(MalformedPublicKey)",
            "Public key is malformed",
        ),
        Case::key_err(
            "cases/public-key-zero-material.key",
            "InvalidFormat(MalformedPublicKey)",
            "Public key is malformed",
        ),
        Case::private_key_err(
            "cases/privatekey-bad-kdf.private.key",
            "InvalidKdfParams(MemoryCost)",
            &format!("File has invalid KDF settings ({over_max_mem} KiB memory)"),
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
    out.push_str("# expect ok: decrypt must reproduce plaintext.txt byte-for-byte; key-file\n");
    out.push_str("# actions must parse or validate successfully.\n");
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

/// Corpus revision written to `SUITE-VERSION`. Independent readers may pin
/// to a specific revision. Increment it whenever a fixture is added, removed,
/// or changed; different corpus contents must never share a revision.
/// Regeneration treats this constant as the source of truth and overwrites the
/// committed file.
const SUITE_VERSION: u32 = 11;

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
    fs::write(suite.join("SUITE-VERSION"), format!("{SUITE_VERSION}\n"))
        .expect("write SUITE-VERSION");

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
    // The `FORMAT.md` §3.7 undersized-header phase boundary: with no MAC
    // bytes the framing read fails first (truncated); with all 32 MAC
    // bytes present, the header too small to hold `header_fixed` is the
    // structural defect (malformed).
    mutated_copy(
        &cases,
        "argon2id-valid.fcr",
        "prefix-undersized-header-no-mac.fcr",
        |b| {
            b[PREFIX_HEADER_LEN_OFFSET..PREFIX_HEADER_LEN_OFFSET + 4]
                .copy_from_slice(&0u32.to_be_bytes());
            b.truncate(PREFIX_SIZE);
        },
    );
    mutated_copy(
        &cases,
        "argon2id-valid.fcr",
        "prefix-undersized-header-with-mac.fcr",
        |b| {
            b[PREFIX_HEADER_LEN_OFFSET..PREFIX_HEADER_LEN_OFFSET + 4]
                .copy_from_slice(&0u32.to_be_bytes());
            b.truncate(PREFIX_SIZE + HEADER_MAC_SIZE);
        },
    );
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
        "Unsupported .fcr version byte 0x02. Upgrade FerroCrypt.",
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
    rows.push(Case::err(
        "cases/prefix-undersized-header-no-mac.fcr",
        "-",
        "InvalidFormat(Truncated)",
        "File is truncated or corrupted",
    ));
    rows.push(Case::err(
        "cases/prefix-undersized-header-with-mac.fcr",
        "-",
        "InvalidFormat(MalformedHeader)",
        "File header is malformed",
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

    // ── Payload truncation, tamper, non-canonical final, and trailing data ──
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
    rows.push(Case::err(
        "cases/payload-empty-final-after-data.fcr",
        &right,
        "InvalidFormat(MalformedPayloadStream)",
        "Encrypted payload stream is malformed",
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

    // ── Small-order X25519 ephemeral: all-zero shared secret ───────────
    // The during-X25519 counterpart of the preflight case above: the
    // value passes the canonical/nonzero preflight, and the prohibited
    // all-zero shared secret then rejects the whole file (`FORMAT.md`
    // §4.2).
    mutated_copy(
        &cases,
        "x25519-valid.fcr",
        "x25519-small-order-ephemeral.fcr",
        |b| {
            let body =
                PREFIX_SIZE + HEADER_FIXED_SIZE + ENTRY_HEADER_SIZE + x25519::TYPE_NAME.len();
            b[body..body + x25519::PUBLIC_KEY_SIZE].copy_from_slice(&SMALL_ORDER_EPHEMERAL);
        },
    );
    rows.push(Case::err(
        "cases/x25519-small-order-ephemeral.fcr",
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
    build_rewritten_kdf_fcr(
        &plaintext,
        &cases,
        "kdf-mem-over-max.fcr",
        KdfParams {
            mem_cost: KdfParams::MAX_MEM_COST + 1,
            ..fast
        },
    )
    .expect("build kdf-mem fixture");
    build_rewritten_kdf_fcr(
        &plaintext,
        &cases,
        "kdf-lanes-zero.fcr",
        KdfParams { lanes: 0, ..fast },
    )
    .expect("build kdf-lanes fixture");
    build_rewritten_kdf_fcr(
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
        &format!("UnknownCriticalRecipient({UNKNOWN_TYPE_NAME})"),
        &format!("Unsupported recipient `{UNKNOWN_TYPE_NAME}`. Upgrade FerroCrypt."),
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

    // Generate this new RNG-consuming fixture after every pre-existing case so
    // extending the suite does not change the frozen bytes of older vectors.
    {
        let file_key = FileKey::generate().expect("suite file key");
        let entry = argon2id_entry(&file_key);
        build_empty_final_chunk_fcr(
            &cases,
            "payload-empty-final-after-data.fcr",
            &file_key,
            std::slice::from_ref(&entry),
        )
        .expect("build empty-final payload fixture");
    }

    // Revision-3 cases are deliberately last: every RNG draw used by the
    // revision-2 corpus above stays at the same position in the deterministic
    // stream, so all previously committed fixture bytes remain frozen.
    rows.extend(write_conformance_completion_cases(
        &plaintext, &cases, &keys,
    ));

    // Revision-4 cases draw no RNG at all, so their position cannot
    // disturb the frozen bytes of any earlier fixture.
    rows.extend(write_key_file_completion_cases(&suite, &cases));

    // Revision-6 case is deliberately last so every earlier fixture keeps
    // its frozen bytes. A wrong-length supported entry behind a well-shaped
    // entry must reject during the recipient preflight (`FORMAT.md` §3.7
    // step 8), before any credential is consulted.
    {
        let file_key = FileKey::generate().expect("suite file key");
        let valid = x25519_entry(&keys, "recipient-a.public.key", &file_key);
        let mut short = valid.clone();
        short.body.pop();
        build_crafted_fcr(
            &plaintext,
            &cases,
            "x25519-invalid-length-second-slot.fcr",
            &file_key,
            &[valid, short],
            b"",
        )
        .expect("build second-slot invalid-length fixture");
    }
    rows.push(Case::err(
        "cases/x25519-invalid-length-second-slot.fcr",
        "-",
        "InvalidFormat(MalformedRecipientEntry)",
        "Recipient entry is malformed",
    ));

    // Revision-7 cases follow the same append-only rule. A non-canonical
    // ephemeral public key in an `x25519` body is a credential-independent
    // structural defect (`FORMAT.md` §4.2), rejected during the recipient
    // preflight before any credential is consulted.
    {
        let file_key = FileKey::generate().expect("suite file key");
        let mut entry = x25519_entry(&keys, "recipient-a.public.key", &file_key);
        // Set the high bit of the ephemeral public key's last byte: an
        // RFC 7748 alias the canonical-encoding check must reject.
        entry.body[x25519::PUBLIC_KEY_SIZE - 1] |= 0x80;
        build_crafted_fcr(
            &plaintext,
            &cases,
            "x25519-noncanonical-ephemeral.fcr",
            &file_key,
            std::slice::from_ref(&entry),
            b"",
        )
        .expect("build non-canonical ephemeral fixture");
    }
    rows.push(Case::err(
        "cases/x25519-noncanonical-ephemeral.fcr",
        "-",
        "InvalidFormat(MalformedRecipientEntry)",
        "Recipient entry is malformed",
    ));

    // Non-canonical `public.key` material (`FORMAT.md` §2.4 / §7): a
    // high-bit alias of a valid key, the field-prime boundary values,
    // and wrong-length material. Each carries a valid internal
    // checksum, so only the canonical-encoding and length ingress
    // checks can reject them.
    rows.extend(write_noncanonical_public_key_cases(&suite, &cases));

    write_manifest(&suite, &rows);
}

/// Little-endian encoding of `2^255 - 19 + delta`, used to build the
/// `FORMAT.md` §7 field-boundary public-key vectors. `delta` is small,
/// so only the low bytes change and no borrow reaches byte 31.
fn field_prime_plus(delta: i16) -> [u8; x25519::PUBLIC_KEY_SIZE] {
    let mut bytes = x25519::FIELD_PRIME_LE;
    let low = u16::from_le_bytes([bytes[0], bytes[1]]) as i32 + delta as i32;
    let low = u16::try_from(low).expect("delta keeps the low half in range");
    bytes[0..2].copy_from_slice(&low.to_le_bytes());
    bytes
}

/// Writes the `FORMAT.md` §7 non-canonical and wrong-length `public.key`
/// fixtures: a high-bit alias of recipient A's key; the field-boundary
/// values `2^255 - 19`, `2^255 - 18`, and `2^255 - 1`; and 33-byte
/// material. Each rejects at ingress as
/// [`FormatDefect::MalformedPublicKey`]. Draws no RNG.
fn write_noncanonical_public_key_cases(suite: &Path, cases: &Path) -> Vec<Case> {
    let valid = fs::read_to_string(suite.join("keys/recipient-a.public.key"))
        .expect("read recipient A public key");
    let recipient = valid.strip_suffix('\n').unwrap_or(&valid);
    // Recipient A's key is canonical, so the reader decodes it; flipping
    // the high bit then produces the alias the fixture needs.
    let mut alias_material = crate::key::public::decode_x25519_recipient(recipient)
        .expect("recipient A key decodes as canonical X25519 material");
    alias_material[x25519::PUBLIC_KEY_SIZE - 1] |= 0x80;

    // 2^255 - 1: high bit of byte 31 clear, but the integer is still
    // above the field prime, so it exercises the value comparison
    // rather than the high-bit fast path.
    let mut max_255 = [0xFFu8; x25519::PUBLIC_KEY_SIZE];
    max_255[x25519::PUBLIC_KEY_SIZE - 1] = 0x7F;

    let fixtures: [(&str, &[u8]); 5] = [
        ("public-key-high-bit-alias.key", &alias_material),
        ("public-key-field-prime.key", &x25519::FIELD_PRIME_LE),
        ("public-key-field-prime-plus-one.key", &field_prime_plus(1)),
        ("public-key-field-max.key", &max_255),
        // 33 bytes: a valid X25519 point cannot have this length.
        (
            "public-key-wrong-length.key",
            &[0x11u8; x25519::PUBLIC_KEY_SIZE + 1],
        ),
    ];

    fixtures
        .iter()
        .map(|(name, material)| {
            let encoded =
                crate::key::public::encode_recipient_string_unchecked(x25519::TYPE_NAME, material)
                    .expect("encode non-canonical recipient string");
            fs::write(cases.join(name), format!("{encoded}\n"))
                .expect("write non-canonical public-key fixture");
            Case::key_err(
                &format!("cases/{name}"),
                "InvalidFormat(MalformedPublicKey)",
                "Public key is malformed",
            )
        })
        .collect()
}
