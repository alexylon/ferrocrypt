# ferrocrypt-lib Code Structure

**Status:** Canonical structural reference  
**Scope:** `ferrocrypt-lib/src/` public API, module layout, security boundaries, and ownership of format, cryptographic, archive, key, and filesystem responsibilities.

---

## Table of contents

1. [Architecture overview](#1-architecture-overview)
2. [Source layout](#2-source-layout)
3. [Top-level modules](#3-top-level-modules)
   - [3.1 `lib.rs`](#31-librs)
   - [3.2 `api.rs`](#32-apirs)
   - [3.3 `protocol.rs`](#33-protocolrs)
   - [3.4 `format.rs`](#34-formatrs)
   - [3.5 `container.rs`](#35-containerrs)
   - [3.6 `error.rs`](#36-errorrs)
   - [3.7 `passphrase.rs`](#37-passphrasers)
   - [3.8 `fuzz_exports.rs`](#38-fuzz_exportsrs)
   - [3.9 `suite_vector_gen.rs`](#39-suite_vector_genrs)
4. [`crypto/`](#4-crypto)
   - [4.1 `crypto/keys.rs`](#41-cryptokeysrs)
   - [4.2 `crypto/kdf.rs`](#42-cryptokdfrs)
   - [4.3 `crypto/hkdf.rs`](#43-cryptohkdfrs)
   - [4.4 `crypto/mac.rs`](#44-cryptomacrs)
   - [4.5 `crypto/aead.rs`](#45-cryptoaeadrs)
   - [4.6 `crypto/stream.rs`](#46-cryptostreamrs)
   - [4.7 `crypto/tlv.rs`](#47-cryptotlvrs)
5. [`recipient/`](#5-recipient)
   - [5.1 `recipient/entry.rs`](#51-recipiententryrs)
   - [5.2 `recipient/name.rs`](#52-recipientnamers)
   - [5.3 `recipient/policy.rs`](#53-recipientpolicyrs)
   - [5.4 `recipient/native/argon2id.rs`](#54-recipientnativeargon2idrs)
   - [5.5 `recipient/native/x25519.rs`](#55-recipientnativex25519rs)
6. [`key/`](#6-key)
   - [6.1 `key/public.rs`](#61-keypublicrs)
   - [6.2 `key/private.rs`](#62-keyprivaters)
   - [6.3 `key/files.rs`](#63-keyfilesrs)
7. [`archive/`](#7-archive)
   - [7.1 `archive/format.rs`](#71-archiveformatrs)
   - [7.2 `archive/model.rs`](#72-archivemodelrs)
   - [7.3 `archive/limits.rs`](#73-archivelimitsrs)
   - [7.4 `archive/path.rs`](#74-archivepathrs)
   - [7.5 `archive/tree.rs`](#75-archivetreers)
   - [7.6 `archive/encode.rs`](#76-archiveencoders)
   - [7.7 `archive/decode.rs`](#77-archivedecoders)
   - [7.8 `archive/platform.rs`](#78-archiveplatformrs)
   - [7.9 `archive/fd_limit.rs`](#79-archivefd_limitrs)
8. [`fs/`](#8-fs)
   - [8.1 `fs/atomic.rs`](#81-fsatomicrs)
   - [8.2 `fs/paths.rs`](#82-fspathsrs)
9. [Public API shape](#9-public-api-shape)
   - [9.1 Encryption](#91-encryption)
   - [Centralized cap enforcement](#centralized-cap-enforcement)
   - [9.2 Decryption](#92-decryption)
   - [9.3 Keys and identities](#93-keys-and-identities)
   - [9.4 Key generation](#94-key-generation)
   - [9.5 Recipient-mode probe](#95-recipient-mode-probe)
10. [Single sources of truth](#10-single-sources-of-truth)
11. [Dependency direction](#11-dependency-direction)
12. [Decryption security ordering](#12-decryption-security-ordering)
13. [Public error wording](#13-public-error-wording)
14. [Extension and non-goal boundaries](#14-extension-and-non-goal-boundaries)
15. [Architectural invariants](#15-architectural-invariants)

---

## 1. Architecture overview

FerroCrypt is organized around a single file-encryption protocol pipeline. The file model is:

```text
one random file_key
one encrypted payload
one or more typed recipient entries that wrap the same file_key
```

The library is therefore recipient-oriented rather than mode-oriented. Passphrase encryption and public-key encryption are different recipient schemes over the same protocol pipeline, not separate encrypted-file formats or independent orchestration paths.

The architecture has these primary layers:

```text
public API
   ↓
protocol pipeline
   ↓
container + recipient schemes + key formats + archive + filesystem staging
   ↓
format constants + cryptographic primitives
```

The core structural rules are:

1. **There is one encrypt/decrypt orchestration path.**
   `protocol.rs` owns the high-level operation flow for both passphrase and public-key encryption.

2. **Recipient schemes are first-class components.**
   Passphrase Argon2id and X25519 public-key support are implemented as native recipient schemes under `recipient/native/`.

3. **The encrypted file container is separate from cryptographic algorithms.**
   `container.rs` owns the `.fcr` container layout around the encrypted header, header MAC, and encrypted payload. It does not implement scheme-specific cryptography.

4. **Cryptographic primitives have explicit owners.**
   Reusable key types, KDF validation, HKDF, HMAC, AEAD, payload streaming, and TLV parsing live under `crypto/`.

5. **Archive handling is isolated from encryption logic.**
   FerroCrypt Archive (FCA) wire format, manifest serialization, path-grammar validation, tree-shape validation, archive limits, encode / decode, and platform-specific extraction hardening live under `archive/`.

6. **Filesystem mechanics are separate from archive semantics.**
   Atomic output, staging, and general path helpers live under `fs/`.

7. **Unknown recipient entries remain structurally parseable and authenticated.**
   The file format supports external recipient names. The parser preserves and authenticates unknown non-critical recipient entries as opaque data, while public third-party crypto extension traits remain outside the stable API surface.

---

## 2. Source layout

```text
ferrocrypt-lib/src/
├── lib.rs
├── api.rs
├── protocol.rs
├── error.rs
├── format.rs
├── container.rs
│
├── crypto/
│   ├── mod.rs
│   ├── keys.rs
│   ├── kdf.rs
│   ├── hkdf.rs
│   ├── mac.rs
│   ├── aead.rs
│   ├── stream.rs
│   └── tlv.rs
│
├── recipient/
│   ├── mod.rs
│   ├── entry.rs
│   ├── name.rs
│   ├── policy.rs
│   └── native/
│       ├── mod.rs
│       ├── argon2id.rs
│       └── x25519.rs
│
├── key/
│   ├── mod.rs
│   ├── public.rs
│   ├── private.rs
│   └── files.rs
│
├── archive/
│   ├── mod.rs
│   ├── format.rs
│   ├── model.rs
│   ├── limits.rs
│   ├── path.rs
│   ├── tree.rs
│   ├── encode.rs
│   ├── decode.rs
│   ├── platform.rs
│   ├── reasons.rs
│   └── fd_limit.rs   (test-only)
│
├── fs/
│   ├── mod.rs
│   ├── atomic.rs
│   └── paths.rs
│
├── passphrase.rs
├── fuzz_exports.rs
└── suite_vector_gen.rs   (test-only)
```

Each file represents a stable responsibility boundary. File size is not the organizing principle; ownership, auditability, and prevention of duplicated security logic are the organizing principles.

---

## 3. Top-level modules

### 3.1 `lib.rs`

`lib.rs` is the crate façade.

It contains:

- crate-level documentation;
- public re-exports;
- feature gates;
- public constants re-exported from their owning modules;
- the definitions of the shared public vocabulary types — `UnauthenticatedRecipientMode`, the sealed `AuthenticatedRecipientMode` and its kind enum, `ProgressEvent`, and the outcome structs. These live in the crate root because lower layers (`recipient/policy.rs`, `protocol.rs`) reference them; defining them in `api.rs` would invert the §11 dependency direction, so the crate root is the only cycle-free home shared by the façade and the layers below it.

It does not contain:

- cryptographic operations;
- format parsing;
- recipient parsing;
- archive encoding or extraction;
- direct filesystem writes;
- end-to-end encryption or decryption orchestration.

Normal public operations enter through `api.rs` and are executed through `protocol.rs`.

### 3.2 `api.rs`

`api.rs` owns public ergonomic wrappers and compatibility-facing API functions.

It contains:

- public `Encryptor` and `Decryptor` constructors or re-exports;
- `generate_key_pair`;
- `probe_recipient_mode` (cheap structural probe; **not** a security claim);
- `default_encrypted_filename`;
- `validate_public_key_file`;
- `validate_private_key_file`;
- compatibility shims retained by the public API.

`api.rs` translates stable public value types into internal protocol inputs. It does not derive keys, compute MACs, parse recipient bodies, extract archives, or emit low-level protocol progress events directly.

### 3.3 `protocol.rs`

`protocol.rs` owns the high-level FerroCrypt operation flow. It is the only module that coordinates all security-sensitive stages of one encryption or decryption operation.

During encryption, `protocol.rs` coordinates:

1. writer-side cap and KDF preflight (`preflight_header_write_limits` plus
   each recipient's `validate_for_write`), before any filesystem, archive,
   or key work;
2. file-key generation;
3. stream nonce generation;
4. recipient-scheme file-key wrapping;
5. authenticated-header construction;
6. archive encoding;
7. payload stream encryption;
8. staged output finalization;
9. progress event emission.

During decryption, `protocol.rs` coordinates:

1. container prefix and encrypted-header reading;
2. structural recipient parsing;
3. recipient mixing-rule enforcement;
4. local resource-cap enforcement;
5. recipient-scheme file-key unwrapping;
6. header MAC verification with each candidate `FileKey`;
7. authenticated TLV validation;
8. payload key derivation;
9. payload stream decryption;
10. archive decoding and safe extraction;
11. staged output finalization;
12. progress event emission.

Decryption stages 1–4 are represented by the crate-internal `DecryptSession`, which contains one opened input file, its parsed header, and its classified recipient mode. Later stages consume the session and continue reading from the same file. `PrivateKeyDecryptor::decrypt` creates the session before unlocking `private.key`, so replacing the input path during the unlock cannot change the file being decrypted.

`protocol.rs` defines the internal recipient-scheme abstraction boundary:

```rust
pub(crate) trait RecipientScheme {
    const TYPE_NAME: &'static str;
    const MIXING_RULE: NativeMixingRule;

    fn validate_for_write(&self) -> Result<(), CryptoError>;

    fn wrap_file_key(
        &self,
        file_key: &FileKey,
        on_event: &dyn Fn(&ProgressEvent),
    ) -> Result<RecipientBody, CryptoError>;
}

pub(crate) trait DecryptionCredential {
    const TYPE_NAME: &'static str;
    const EXPECTED_MODE: UnauthenticatedRecipientMode;

    fn unwrap_file_key(
        &self,
        body: &[u8],
        on_event: &dyn Fn(&ProgressEvent),
    ) -> Result<Option<FileKey>, CryptoError>;
}
```

Rules:

- These traits are `pub(crate)`.
- They are an internal deduplication and dispatch boundary, not a stable public plugin API.
- Scheme implementations return or accept recipient body bytes; they do not construct full headers.
- Recipient schemes do not compute or verify header MACs.
- `RecipientScheme::validate_for_write` is the writer-side preflight for scheme-carried parameters: `argon2id` validates its `KdfParams` against the same structural bounds, production floor, and `KdfLimit` policy the reader applies; `x25519` carries no such parameters and accepts. `protocol::encrypt` runs it on every recipient, so no in-crate caller can emit a recipient body the same-configured reader rejects. The method is required, not defaulted, so a future scheme must decide explicitly.
- A recipient unwrap is successful only after the candidate `FileKey` verifies the authenticated header MAC.
- The orchestrator threads a single `&dyn Fn(&ProgressEvent)` callback into each scheme. Schemes whose KDF step is expensive (Argon2id) emit `ProgressEvent::DerivingPassphraseWrapKey` from inside `wrap` / `unwrap` immediately before the KDF call — that is, **after** structural validation and resource-cap checks have passed. Schemes whose wrap / unwrap is sub-millisecond (X25519) MUST ignore the callback so cheap operations never lie about a long pause. The `private.key` Argon2id boundary is owned separately by `key::private::open_private_key`, which emits `ProgressEvent::UnlockingPrivateKey` at its own work boundary; `protocol::decrypt` does NOT emit a `DerivingKey`-style event from the orchestrator.

### 3.4 `format.rs`

`format.rs` owns byte-level wire constants and fixed structures.

It contains:

- magic bytes;
- the `.fcr` outer file version bytes (`FCR_FILE_VERSION`, writer-current;
  `FCR_FILE_V1_VERSION`, pinned first revision) and the reader's support
  gate `check_version`, the single source of truth for which container
  revisions this release accepts. Its arms are keyed to the pinned
  per-revision constants, not to `FCR_FILE_VERSION`, so advancing the
  writer's byte adds an arm instead of dropping read support that
  `FORMAT.md` §11.5 requires be kept;
- the `KeypairSuite` enum and the single shared support gate
  (`keypair_suite_is_supported`), both `pub(crate)` — internal compatibility
  machinery whose shape may change across releases. External observers
  depend on the stable version constants (`FCR_FILE_VERSION`,
  `PUBLIC_KEY_VERSION`, `PRIVATE_KEY_VERSION`, `*_V1_VERSION`) and the
  typed `UnsupportedVersion` diagnostics. The forward direction
  (suite → wire byte) is defined here on `KeypairSuite::public_key_version` /
  `KeypairSuite::private_key_version`, both compile-forced exhaustive
  matches; the reverse direction (wire byte → suite) is also centralised
  here as `keypair_suite_from_public_key_version` and
  `keypair_suite_from_private_key_version` (both `pub(crate)`), backed by
  the parameterised inner helper `keypair_suite_from_wire_version_with`
  so adding a new suite is a single match arm covering both artefact
  domains. The two reverse mappers return a small crate-internal
  `KeypairVersionRejection` (`Reserved` / `Older` / `Newer`) that the
  consumers in `key/public.rs` and `key/private.rs` translate into their
  domain-specific `CryptoError` variants — encryption-time recipient
  acceptance and decryption-time private-key acceptance are therefore
  decided by one predicate and one mapping table and cannot drift
  (`FORMAT.md` §11);
- the writer's logical suite (`WRITER_KEYPAIR_SUITE`);
- kind bytes;
- field sizes;
- maximum structural sizes;
- fixed prefix and header parsing;
- fixed prefix and header serialization;
- header MAC input definition.

`format.rs` does not contain:

- file I/O;
- archive logic;
- recipient-specific body parsing;
- cryptographic key derivation;
- end-to-end operation flow.

`format.rs` is the closest Rust representation of the FerroCrypt file format specification. It remains deterministic, small, and directly comparable to the binary format definition.

### 3.5 `container.rs`

`container.rs` owns the `.fcr` encrypted file container around the encrypted header and encrypted payload.

It contains:

- `HeaderReadLimits` (public, `#[non_exhaustive]`, builder methods clamp at the structural maxima);
- parsed encrypted-header structures;
- `build_encrypted_header`;
- `read_encrypted_header`;
- authenticated-header assembly;
- structural container validation;
- top-level `prefix || header || header_mac || payload` reading and writing.

`container.rs` owns container assembly and parsing. Header MAC computation and verification go through the typed wrappers in `format.rs`; `container.rs` does not implement HMAC directly. It does not own Argon2id behavior, X25519 behavior, payload-stream cryptography, archive semantics, public key file formats, or private key file formats.

### 3.6 `error.rs`

`error.rs` owns the library error taxonomy.

Errors remain centralized because they form a coherent diagnostic namespace. Public errors must be precise, stable, and careful not to overstate what cryptographic verification can prove.

Error variants that carry data carry typed structured data, such as `FormatDefect` (including authenticated payload-stream grammar defects), `UnsupportedVersion`, `InvalidKdfParams`, the `MixingPolicy` diagnostic projection (with a structured `Custom { compatibility_class }` payload for non-shorthand classes), named integer fields for resource caps, and owned `type_name` strings for per-recipient diagnostics. Inner-archive (FCA) failures keep the same distinctions: archive structure, path, and tree defects surface as `MalformedArchive` / `UnsafeArchivePath` / `InvalidArchiveTree` with a static `reason`; the archive count, size, path, and extension-region caps have dedicated `Archive*CapExceeded` variants with named integer fields; and TLV grammar failures use the shared `InvalidFormat(FormatDefect)` taxonomy. In particular, a TLV value above `ArchiveLimits::max_tlv_value_bytes` is `InvalidFormat(FormatDefect::MalformedTlv)`, not an `Archive*CapExceeded` error. Consumers can pattern-match on error shapes without substring comparisons.

Untrusted text embedded in an error message — archive entry paths, source-tree file names, and caller-supplied input paths — is sanitized before it is stored or rendered: ASCII control bytes and all non-ASCII characters (including direction-override and zero-width code points) become backslash escapes, and long input is truncated. Caller-supplied input paths get the same treatment as archive-internal names because they often come from shell glob expansion or a file-picker dialog, where an attacker with write access to a browsed directory chooses the name — including intermediate directory names. The "already exists" conflict messages keep the parent directory readable and untruncated (it is the caller's trust boundary, and the operator must be able to locate the conflict), escaping only control and bidirectional-formatting characters in it, while the final component — which can be attacker-influenced (an input-derived file stem, an archive-chosen root name) — goes through the stricter, truncating sanitizer. Terminal-bound error text can therefore never carry terminal escape sequences or bidirectional-formatting characters from any path component; printable Unicode in the trusted parent remains visible by design. `error.rs::sanitize_for_display` is the single strict implementation; `sanitize_path_for_display` is its `Path` shorthand, `sanitize_prefix_for_display` renders the trusted parent prefix, and `fs::paths::already_exists_error` is the single constructor for the conflict messages.

`error.rs` also owns the display policy. Complete library-owned diagnostics use
sentence case, begin with a capital letter, and have no terminal punctuation.
Static reason and marker fragments begin lowercase unless their first word is
an acronym or proper name, and likewise have no terminal punctuation; their
owning prefix supplies the capitalized start of the complete message. Stable
messages whose width is wholly controlled by the library must fit the desktop
status line's 64-character display allowance. Documented exceptions are
messages that necessarily append an unbounded caller path or operating-system
text, plus `ArchiveTotalEntryExtCapExceeded`, whose public `u64` limit can
render wider than the line at extreme values. The desktop performs its own
final elision for those messages.

Crate-owned internal markers must be constructed with
`internal_invariant!` or `internal_crypto_failure!`. Those macros enforce at
compile time that a marker is non-empty printable ASCII, has no terminal
punctuation, and fits after the longer `Internal crypto error: ` prefix.
`display_fragment_text_is_valid` is the shared ASCII and punctuation primitive
behind every fragment validator, and `display_fragment_is_valid` adds a width
bound for the fragments whose complete message has one.
`DisplayableMarker` separately bounds hand-constructed public error variants.
Every crate-owned archive reason is kept in one registry, grouped by the
variant that renders it: a `MalformedArchive` reason is width-bounded because
the library owns the whole message, while an `UnsafeArchivePath` or
`InvalidArchiveTree` reason is not, because those messages append an entry path
and no fragment bound would bring them inside the line. The error budget test
iterates each group in full rather than treating one current longest reason as
a proxy for the set.

Upgrade advice follows ownership, not guesswork. A stored version newer than
the one implemented here, or an unknown critical TLV tag defined by a later
compatible FerroCrypt specification, says that newer FerroCrypt is needed.
Unknown recipient and key type names stay neutral because their namespace also
admits external implementations that a FerroCrypt upgrade may never support.

Diagnostic rules:

- A passphrase recipient open failure means “wrong passphrase or recipient entry tampered,” not definitely “incorrect passphrase”.
- A private-key unlock failure means “wrong passphrase or private key file tampered,” not definitely one or the other.
- An X25519 recipient failure means “no matching credential, wrong key, or recipient entry tampered,” unless a later authenticated step proves a more specific class.
- A header MAC failure after recovering a candidate `FileKey` means the recovered key did not authenticate the header. It does not by itself prove whether the credential, recipient body, or header bytes were modified.

Public error names may be compatibility-oriented, but their display text must preserve this ambiguity.

### 3.7 `passphrase.rs`

`passphrase.rs` owns the public `Passphrase` type: the owned credential every passphrase-based operation consumes.

It wraps the passphrase text in a zeroizing buffer, prints redacted `Debug` output, and exposes the text only crate-internally. It contains no validation, parsing, or cryptography; the passphrase length rule is enforced by the operations that use the value.

### 3.8 `fuzz_exports.rs`

`fuzz_exports.rs` exposes internal parser and validation entry points needed by fuzz targets.

It is not part of the stable public API. It must not become an alternate implementation path for parsing, validation, cryptography, or archive handling.

### 3.9 `suite_vector_gen.rs`

`suite_vector_gen.rs` is a `#[cfg(test)]`-only module holding the ignored generator test for the committed `testvectors/suite/` edge-case corpus. It needs crate internals (`container::build_encrypted_header`, recipient `wrap` helpers, TLV byte building) to craft fixtures the public writer refuses to produce; the corpus itself is verified through the public API by `tests/testvector_suite.rs` on every test run.

It is compiled only for tests and must not grow non-generation logic.

---

## 4. `crypto/`

`crypto/` owns reusable cryptographic building blocks and typed secrets. It contains primitives and key types that are shared by the protocol, recipient schemes, key formats, and payload stream handling.

`crypto/` does not depend on `protocol.rs`, `archive/`, or `fs/`.

### 4.1 `crypto/keys.rs`

`crypto/keys.rs` owns typed encryption keys and file-key derivation.

It contains:

- `FileKey`;
- `PayloadKey`;
- `HeaderKey`;
- file-key generation;
- payload subkey derivation;
- header subkey derivation;
- zeroization boundaries.

Rules:

- `FileKey`, `PayloadKey`, and `HeaderKey` are strong newtypes.
- Constructors are private or `pub(crate)`.
- Callers borrow key bytes only through narrow methods such as `expose()`.
- Header MAC code accepts `HeaderKey`, not raw bytes.
- Payload stream code accepts `PayloadKey`, not raw bytes.
- It must be impossible to pass a payload key to header-MAC code without an explicit type error.

### 4.2 `crypto/kdf.rs`

`crypto/kdf.rs` owns KDF parameter types and validation.

It contains:

- `KdfParams`;
- `KdfLimit`;
- Argon2id parameter validation;
- local resource-cap checks.

Argon2id parameter parsing and validation have exactly one source of truth. Argon2id execution for passphrase-recipient wrapping may call through this module or through `recipient/native/argon2id.rs`, but resource-cap checks and parameter-validation logic are not duplicated.

### 4.3 `crypto/hkdf.rs`

`crypto/hkdf.rs` owns HKDF-SHA3-256 adapters.

It contains:

- HKDF-SHA3-256 expansion helpers;
- the single place that fixes the HKDF hash family and output length.

Recipient-specific HKDF info strings live with their recipient scheme. Header, payload, and private-key derivation labels live with the modules that own those derivations.

### 4.4 `crypto/mac.rs`

`crypto/mac.rs` owns HMAC-SHA3-256 helpers.

It contains:

- generic HMAC-SHA3-256 computation helpers;
- generic HMAC-SHA3-256 verification helpers;
- constant-time MAC comparison where applicable.

The primitives in `crypto/mac.rs` accept raw byte keys so they remain reusable. Header MAC type safety is enforced by the typed `compute_header_mac` and `verify_header_mac` wrappers in `format.rs`, which accept `&HeaderKey` and call these generic primitives.

### 4.5 `crypto/aead.rs`

`crypto/aead.rs` owns XChaCha20-Poly1305 helpers and the shared nonce and tag sizes.

It contains:

- AEAD seal helpers;
- AEAD open helpers;
- the wrap-nonce and Poly1305 tag size constants.

Common AEAD behavior is not duplicated in Argon2id recipients, X25519 recipients, private-key handling, or payload-stream code.

### 4.6 `crypto/stream.rs`

`crypto/stream.rs` owns STREAM-BE32 payload encryption and decryption.

It contains:

- payload chunk-size rules;
- counter rules;
- final-flag behavior;
- payload encryptor reader/writer adapters;
- payload decryptor reader/writer adapters;
- trailing-data detection;
- rejection of an authenticated empty final chunk after any non-final chunk;
- truncation detection;
- terminal error handling: after either adapter returns an error, it drops its
  cipher state and every later operation returns `StateExhausted`. The adapter
  never resumes a rejected stream (`FORMAT.md` §5).

Payload streaming uses `PayloadKey`. It does not know about recipient schemes, key files, archive paths, or output finalization.

### 4.7 `crypto/tlv.rs`

`crypto/tlv.rs` owns the shared TLV grammar for every FerroCrypt extension region: `.fcr` header `ext_bytes`, `private.key` `ext_bytes`, FCA `archive_ext`, and FCA per-entry `entry_ext`.

The module exposes:

- `scan_tlv_region(bytes, max_region_len, max_value_len) -> Vec<RawTlv>` — the parsing primitive. Validates structural framing (each entry header fits, declared `len` fits in the region and `<= max_value_len`), strict ascending tag order, reserved-tag rejection. Returns parsed entries with cached `TlvClass`. Does not enforce a critical-tag policy.
- `reject_unknown_critical(tlvs) -> Result<()>` — the current policy wrapper. Rejects any `TlvClass::Critical` entry as `UnknownCriticalTag` because the current specification defines no known critical tags in any region. A later specification that defines known criticals will iterate the scanned TLVs against a registry instead.
- `validate_no_known_critical(bytes, max_region_len, max_value_len) -> Result<()>` — the single-call helper. Combines `scan_tlv_region` and `reject_unknown_critical` for callers that don't need the parsed entries. Used by every current caller (FCR header, `private.key`, FCA `archive_ext`, FCA `entry_ext`).
- `classify_tlv_tag(tag) -> Result<TlvClass>` — pure tag classification, rejects the two reserved values.
- `validate_tlv(ext_bytes)` — public convenience function. Calls `validate_no_known_critical` with `EXT_LEN_MAX` for both region and value caps. Used by the `.fcr` header only; every other region has its own wrapper carrying the caps its containing format defines (`key::private::validate_private_key_ext_tlv`, `archive::format::validate_archive_ext_tlv`, `archive::format::validate_entry_ext_tlv`).

Rules:

- Each containing region (FCR header, private-key, FCA archive-level, FCA per-entry) has its own tag namespace; the structural rules are shared.
- TLV validation occurs only after the appropriate authentication succeeds (header MAC for `.fcr`, AEAD-AAD for `private.key`, outer `.fcr` payload AEAD for FCA).
- Unknown critical TLVs reject after authentication.
- Code must not act on unauthenticated TLV metadata.

---

## 5. `recipient/`

`recipient/` owns generic recipient-entry handling, recipient type-name validation, recipient mixing policy, and native recipient-scheme implementations.

Recipient entries are authenticated header data. Unsupported recipient entries remain opaque unless and until a supported scheme claims and parses their body.

### 5.1 `recipient/entry.rs`

`recipient/entry.rs` owns the generic recipient entry framing:

```text
type_name_len:u16
recipient_flags:u16
body_len:u32
type_name
body
```

It contains:

- `RecipientEntry` for parsed entries;
- `RecipientBody` for scheme body bytes plus type name;
- canonical recipient-entry serialization. `RecipientEntry::checked_wire_len` applies the writer-side rules that correspond to `parse_one` (`validate_type_name_grammar`, reserved flag bits, and `body.len() <= BODY_LEN_MAX`) and returns the exact encoded length. `container::build_encrypted_header` uses these lengths to enforce `HEADER_LEN_MAX` before allocating the combined recipient buffer, then serializes each entry through `RecipientEntry::to_bytes_checked`. The test-only `to_bytes` remains available for tests that intentionally create invalid bytes.
- strict framing parsing;
- unknown-body opacity.

Rules:

- Recipient schemes produce `RecipientBody`, not full header entries.
- Only `recipient/entry.rs` constructs or serializes `RecipientEntry` framing.
- Generic recipient-entry code never parses, normalizes, or interprets unsupported recipient bodies.

### 5.2 `recipient/name.rs`

`recipient/name.rs` owns recipient type-name validation. The §3.3 byte-level grammar and the §3.3.1 namespace policy are exposed as **two distinct validators** so that wire-format parsing stays forward-compatible while plugin-supplied names are held to the stricter policy:

- `validate_type_name_grammar(name)` — the §3.3 byte-level grammar (1..=255 bytes, lowercase ASCII, allowed character set, no leading/trailing punctuation, no `..`/`//`). All in-tree wire-format readers and writers (`recipient/entry.rs`, `key/public.rs`, `key/private.rs`) call this and only this. The grammar deliberately accepts unknown short native names so a future FerroCrypt version can introduce a new native recipient type without breaking forward-compatible parsing in older readers.
- `is_reserved_native_name(name)` — internal building block: returns `true` when `name` has the shape of a reserved FerroCrypt native type (no `/`, plus a reserved native prefix in `["mlkem", "pq", "hpke", "tag", "xwing", "kem"]` or the reserved `tag` suffix per `FORMAT.md` §3.3.1).
- `validate_external_type_name(name)` — runs the grammar check, then enforces the §3.3.1 namespace policy: the name MUST contain `/` and MUST NOT impersonate a reserved native shape. No public plugin / third-party recipient registration surface ships today, so this validator currently has no in-tree caller; it exists so the §3.3.1 policy is enforceable the moment such a surface is added.

`is_reserved_native_name` and `validate_external_type_name` are `pub(crate)` until a plugin-facing API needs them; only `validate_type_name_grammar` and `TYPE_NAME_MAX_LEN` are re-exported through `recipient::mod`.

### 5.3 `recipient/policy.rs`

`recipient/policy.rs` owns recipient mixing-rule enforcement, the public diagnostic projection, and native-scheme classification.

It contains two layers — an internal enforcement type and a public diagnostic projection:

```rust
// Internal enforcement representation. `pub(crate)`; never appears on
// the wire and is not part of the stable public API. The two variants
// are structurally distinct so cardinality and class-equality
// enforcement modes are mutually exclusive at the type level — a
// `SingleEntry` rule has no class field, so two single-entry rules
// cannot accidentally compare as compatible.
pub(crate) enum NativeMixingRule {
    SingleEntry,
    Class { name: &'static str },
}

// Public diagnostic projection of `NativeMixingRule`, surfaced via
// `CryptoError::IncompatibleRecipients`. New compatibility classes
// surface through `Custom` without adding fixed enum variants.
#[non_exhaustive]
pub enum MixingPolicy {
    Exclusive,
    PublicKeyMixable,
    Custom { compatibility_class: &'static str },
}
```

The `#[non_exhaustive]` attribute on `MixingPolicy` lets future variants be added without a breaking change. New native compatibility classes surface as `MixingPolicy::Custom { compatibility_class: "<class>" }` and do not require new fixed variants.

Responsibilities:

- defining the internal `NativeMixingRule` type and its named constructors (`exclusive`, `public_key_mixable`, `post_quantum`);
- defining the public `MixingPolicy` diagnostic projection;
- rejecting native entries with non-zero flags or a wrong body length, for every entry, before mixing runs (the `FORMAT.md` §3.7 step 8 preflight);
- enforcing mixing rules before expensive operations (cardinality bit + compatibility-class equality, both before any KDF or private-key work);
- mapping type names to supported native scheme metadata;
- declaring each native type's `UnauthenticatedRecipientMode` via `NativeRecipientType::recipient_mode` so `classify_recipient_mode` is registry-driven (no hard-coded `argon2id` / `x25519` switches in the classifier);
- classifying parsed headers as passphrase, public-key, unsupported, or mixed;
- preserving unknown non-critical entries as opaque authenticated data.

Rules:

- `argon2id` is `NativeMixingRule::SingleEntry` (must appear alone; no compatibility class — cardinality is the only constraint).
- `x25519` is `NativeMixingRule::Class { name: PUBLIC_KEY_CLASS }` (no cardinality constraint, mixes only with other entries declaring the same class).
- Native PQ recipients (e.g. the upcoming `x25519-mlkem768`) declare `NativeMixingRule::Class { name: POST_QUANTUM_CLASS }` and project to `MixingPolicy::Custom { compatibility_class: "postquantum" }`.
- Unknown non-critical recipients are ignored for class comparison but still count wherever the format says they count, including exclusive passphrase recipient checks.
- Mixing rules are enforced before expensive KDF or private-key operations.
- Native-scheme classification and mixing enforcement are kept together because every native scheme addition requires coordinated changes to both (`mixing_rule` + `recipient_mode` arms on `NativeRecipientType`).

A separate recipient registry module is introduced only when a reviewed public plugin-registration API exists.

### 5.4 `recipient/native/argon2id.rs`

`recipient/native/argon2id.rs` owns the native passphrase recipient scheme.

It contains:

- Argon2id recipient body layout;
- Argon2id recipient body length validation;
- KDF invocation for passphrase recipient wrapping and opening;
- wrap-key derivation;
- file-key seal/open logic;
- scheme-specific validation;
- emission of `ProgressEvent::DerivingPassphraseWrapKey` at the actual Argon2id call boundary (after structural validation and `KdfLimit` resource-cap checks have passed, immediately before `derive_passphrase_wrap_key`);
- `RecipientScheme` implementation;
- `DecryptionCredential` implementation for a passphrase credential;
- tests and vectors for the native passphrase scheme.

It does not:

- build full `.fcr` headers;
- compute header MACs;
- parse TLVs;
- write files;
- emit any other progress event (no `Encrypting` / `Decrypting` / `UnlockingPrivateKey` / `GeneratingKeyPair` from this module);
- perform archive encoding or extraction.

### 5.5 `recipient/native/x25519.rs`

`recipient/native/x25519.rs` owns the native X25519 public-key scheme.

It contains:

- X25519 recipient body layout;
- X25519 recipient body length validation;
- canonical public-key encoding check (`is_canonical_public_key_encoding`, `FORMAT.md` §2.4): every public-value ingress rejects a non-canonical RFC 7748 alias rather than normalizing it, so one curve point cannot acquire two fingerprints or recipient strings. The recipient-string encoder and the fingerprint helpers apply the same rules, so a writer cannot produce material a reader would refuse (`FORMAT.md` §7, §7.2);
- the `x25519` body preflight (`validate_body_preflight`): an all-zero or non-canonical ephemeral public key rejects during `classify_recipient_mode` (`FORMAT.md` §3.7 step 8) and again inside `unwrap`, before any private-key unlock or key agreement. The `argon2id` module carries the matching hook under the same name: `kdf_params` outside the `FORMAT.md` §2.2 structural bounds rejects at step 8, before a passphrase is collected. Both are reached through `NativeRecipientType::validate_body`, so a native type without a body preflight is a missing match arm rather than a silent gap. Only structural bounds belong in these hooks — the caller's `KdfLimit` arrives after classification and stays enforced inside `unwrap`;
- ephemeral key handling;
- all-zero shared-secret rejection (file-fatal `InvalidFormat(MalformedRecipientEntry)` on the decrypt side per `FORMAT.md` §2.4 / §4.2; the credential adapter propagates it instead of collapsing to the slot-skip channel reserved for AEAD failures);
- wrap-key derivation;
- file-key seal/open logic;
- X25519 key-pair generation logic;
- public-key recipient conversion for X25519;
- private-key unlock glue for X25519 (`open_x25519_private_key`), which threads `&dyn Fn(&ProgressEvent)` into `key::private::open_private_key` so the `UnlockingPrivateKey` event fires at the actual Argon2id boundary, not at this wrapper;
- `RecipientScheme` implementation (ignores the progress callback — X25519 wrap is sub-millisecond);
- `DecryptionCredential` implementation (ignores the progress callback — X25519 unwrap is sub-millisecond, and the expensive `private.key` Argon2id ran before the slot loop in `open_x25519_private_key`);
- tests and vectors for the native X25519 scheme.

It does not own the generic `private.key` binary layout. Generic private-key file structure belongs to `key/private.rs`.

---

## 6. `key/`

`key/` owns public and private key file formats and filesystem-level key helpers.

The canonical public value types are:

```rust
pub struct PublicKey  { /* opaque typed public key */ }
pub struct PrivateKey { /* opaque typed private key */ }
```

These names follow Rust cryptographic convention.

### 6.1 `key/public.rs`

`key/public.rs` owns the public recipient key text format. `key/limits.rs` owns `KeyReadLimits` (public, `#[non_exhaustive]`, builder methods clamp at the structural maxima), the caller-facing caps both key readers apply.

It contains:

- Bech32 recipient string encoding;
- Bech32 recipient string decoding;
- HRP validation;
- public-key wire-version-byte (`PUBLIC_KEY_VERSION`, `PUBLIC_KEY_V1_VERSION`) and the public-flavoured wire-version-to-suite translation, which is now a thin `map_err` wrapper over the centralised `keypair_suite_from_public_key_version` in `format.rs` — this layer picks the public-key error variants (`MalformedPublicKey`, `OlderPublicKey`, `NewerPublicKey`) and routes the suite through the shared support gate in `format.rs` (`FORMAT.md` §7);
- the writer's current logical version (`PUBLIC_KEY_VERSION`, derived from `WRITER_KEYPAIR_SUITE`);
- internal SHA3-256 checksum handling;
- canonical lowercase enforcement;
- one rejection class for grammar failures: non-ASCII input, uppercase text, a failed BIP 173 checksum, a wrong HRP, non-canonical padding, and a malformed typed payload all surface as `MalformedPublicKey` (the `FORMAT.md` §12.1 `malformed_public_key` class), except that an invalid payload type name reports `MalformedTypeName`;
- public recipient fingerprinting;
- `public.key` text validation;
- construction and serialization support for `PublicKey`.

`PublicKey` supports:

- loading from a key file;
- parsing from a recipient string;
- construction from bytes where supported by the public API;
- fingerprint generation;
- canonical recipient string output.

Every `PublicKey` ingress path stores or recovers the [`KeypairSuite`] (crate-internal) the key belongs to:

- `from_key_file` and `from_recipient_string` recover the suite from the wire-version byte during decode and store it on the value;
- `from_x25519_bytes` carries no suite marker on its input and tags the value with `WRITER_KEYPAIR_SUITE`, so raw bytes cannot resurrect a public key from a non-writer suite.

`PublicKey::to_recipient_string` re-encodes using the suite the value was constructed with, not the current writer suite, so a recipient string round-trips byte-identically as long as its suite is still supported by this build.

### 6.2 `key/private.rs`

`key/private.rs` owns the private key file format.

It contains:

- `private.key` binary layout;
- the private-key wire-version constants (`PRIVATE_KEY_VERSION` derived from `WRITER_KEYPAIR_SUITE`; `PRIVATE_KEY_V1_VERSION` derived from `KeypairSuite::V1`) and the private-flavoured wire-version-to-suite translation, which is now a thin `map_err` wrapper over the centralised `keypair_suite_from_private_key_version` in `format.rs` — this layer picks the private-key error variants (`MalformedPrivateKey`, `OlderKey`, `NewerKey`) and routes the suite through the shared support gate in `format.rs` (`FORMAT.md` §8);
- cleartext private-key header parsing;
- passphrase-wrapped secret encryption;
- passphrase-wrapped secret decryption;
- writer-side and reader-side `ext_bytes` TLV validation. `seal_private_key` runs `validate_private_key_ext_tlv` on `ext_bytes` after the structural length cap and before AEAD work, so a sealed `private.key` is one the matching reader will accept. `open_private_key` runs the same check after `open_with_aad` succeeds, so the validator always operates on authenticated bytes. Recipient-specific adapters (e.g. `recipient/native/x25519`) no longer re-validate;
- generic typed secret material returned to recipient schemes;
- construction and loading support for `PrivateKey`, which binds its unlock passphrase at construction;
- emission of `ProgressEvent::UnlockingPrivateKey` at the actual Argon2id call boundary inside `open_private_key` (after structural header parsing, the caller's `KdfLimit` resource-cap check, the wrapped-secret-length cap, the total-length check, and type-name grammar validation have all passed). A structurally malformed key file or one that exceeds either cap is rejected with no event emitted. `seal_private_key` is silent: keygen owns its own outer `GeneratingKeyPair` event.

It does not contain X25519-specific recipient policy. The X25519 recipient module verifies that decrypted secret material corresponds to X25519 public material.

### 6.3 `key/files.rs`

`key/files.rs` owns filesystem-level key helpers.

It contains:

- default filenames `public.key` and `private.key`;
- key-file classification (`KeyFileKind`).

Key-file reads go through `fs/paths.rs::read_file_capped` (`public.key`) and `fs/paths.rs::read_file_staged` (`private.key`, via `key/private.rs::read_private_key_file`), called directly by the readers in `key/public.rs` and `recipient/native/x25519.rs`. Write staging for generated key files is owned by `protocol.rs` key generation through the atomic-output helpers in `fs/atomic.rs`; nothing duplicates that behavior.

---

## 7. `archive/`

`archive/` owns the FerroCrypt Archive (FCA) wire format and directory/file payload semantics. The byte-level FCA spec lives in `ferrocrypt-lib/FORMAT.md` §9.

Archive handling is security-critical. Wire-format constants, model types, resource limits, path-grammar validation, tree-shape validation, encoding, decoding, and platform-specific extraction hardening are separated so each review surface is explicit.

`archive/reasons.rs` is the single registry of crate-owned reason fragments for
`MalformedArchive`, `UnsafeArchivePath`, and `InvalidArchiveTree`, used across
those modules. Each registered constant is compile-time validated against
`error.rs`'s display policy for its group, and the error-message budget test
iterates every group. `COMPONENT_TOO_LONG` embeds `FCA_COMPONENT_MAX_BYTES`, so
a unit test in `archive/path.rs` pins the number to that constant.

### 7.1 `archive/format.rs`

`archive/format.rs` owns the FCA wire format.

It contains:

- wire-format constants (`FCA_MAGIC = b"FCA\0"`, `FCA_VERSION = 0x01`, `FCA_HEADER_SIZE = 27` (includes the `archive_ext_len` field), `FCA_ENTRY_FIXED_SIZE = 18` (includes the per-entry `entry_ext_len` field), `KIND_FILE = 0x01`, `KIND_DIR = 0x02`, `PERMISSION_BITS_MASK = 0o777`);
- big-endian integer helpers used by both header and manifest serialization;
- header parse/build (`parse_fca_header` / `write_fca_header`);
- manifest serialize/parse (`checked_manifest_len` / `serialize_manifest` / `parse_manifest_bytes`);
- `copy_exact_n`, the shared exact-size byte copier used by both encode (source file → encrypted stream) and decode (encrypted stream → output file). Its buffer carries cleartext in both directions, so it is heap-held in `Zeroizing`, sized to at most the entry it copies, and wiped on every return path;
- `read_exact_fca`, which reads declared FCA regions exactly. If authenticated FCA data ends before a region is complete, it returns `MalformedArchive` and names the region. Payload-stream errors and filesystem I/O errors retain their existing classifications. `parse_fca_header` uses it for the fixed header, and `archive/decode.rs` uses it for the `archive_ext` and manifest regions.

`checked_manifest_len` runs BEFORE allocation: an over-cap manifest is rejected without growing a `Vec` first. `parse_manifest_bytes` calls `validate_fca_path` and `validate_manifest_tree` so a successfully-parsed `Manifest` is fully validated.

`serialize_manifest` runs the writer-side `validate_manifest_for_write` gate before emitting any bytes — `validate_fca_path` per entry, the `Directory` entries have `size == 0` invariant, the `manifest.total_file_bytes` equals `checked_add` sum of `File` entry sizes invariant (mirroring the reader's "Archive total-bytes mismatch" rejection), and the same `validate_manifest_tree` the reader runs. A `Manifest` the matching reader would reject cannot leak out as bytes. Adversarial reader-side tests use the test-only `serialize_manifest_unchecked` to construct synthetic FCA bytes (multi-root, missing parent, etc.).

### 7.2 `archive/model.rs`

`archive/model.rs` owns the FCA model types.

It contains:

- `FcaHeader` — parsed header summary (`entry_count`, `archive_ext_len`, `manifest_len`, `total_file_bytes`);
- `ArchiveEntryKind` — `File` / `Directory` enum;
- `ArchiveEntry` — `path_utf8`, `mode`, `size`, opaque `entry_ext: Vec<u8>` carrying the per-entry TLV region (empty for current writers, populated by the parser for files from a later compatible specification), plus the writer-only `source_path: Option<PathBuf>` set by the metadata pass so the content pass can reopen no-follow and `source_id: Option<(u64, u64)>`, the `(dev, ino)` pair that pass records on Unix so the content pass can tell the reopened file from one substituted at the same name;
- `Manifest` — `entries`, `total_file_bytes`, `root_name`, `root_is_file`, `root_mode`.

Readers leave `source_path` as `None`; writers set it.

### 7.3 `archive/limits.rs`

`archive/limits.rs` owns `ArchiveLimits` and archive resource-cap helpers.

`ArchiveLimits` covers:

- maximum entry count;
- maximum total regular-file content (logical sum);
- maximum path depth;
- maximum per-path UTF-8 byte length (capped by `u16::MAX` because the on-disk `path_len` field is `u16`);
- maximum serialized manifest byte length (includes per-entry TLV regions);
- maximum `archive_ext` byte length (default 64 KiB);
- maximum `entry_ext` byte length per entry (default 64 KiB);
- maximum cumulative per-entry TLV bytes (default 64 MiB);
- maximum single TLV value byte length (default 16 MiB).

`ArchiveLimits` follows the same public shape as `HeaderReadLimits` (`container.rs`) and `KeyReadLimits` (`key/limits.rs`): `pub(crate)` fields, one consuming builder method per cap named after the cap it sets, and a published `*_DEFAULT` constant per cap so a caller can adjust one cap relative to the defaults without copying a number out of `FORMAT.md` §9.12. `PATH_BYTES_STRUCTURAL_MAX` is the only structural ceiling the format imposes — the on-disk `path_len` field is a `u16` — and `max_path_bytes` clamps at it, so safe downstream code cannot construct a cap the wire format cannot express. The remaining caps are resource policy alone and accept any value their type holds. A module-level `const _: () = assert!(…)` pins `PATH_BYTES_DEFAULT` inside the structural ceiling at compile time. The type therefore needs no runtime `validate` step for public inputs: every value constructible through its safe public API is usable. Because the fields are `pub(crate)`, in-crate code must preserve the same invariant and must not assign an above-structural `max_path_bytes` directly.

The wrapper helpers `enforce_per_entry_caps` and `enforce_total_bytes_cap` are used only by the encrypt-side preflight; the decode side runs the same underlying per-cap helpers directly during manifest parsing and tree validation, so each cap rule has exactly one owner. Encrypt-side preflight and decrypt-side enforcement must agree: the encrypt side must not produce archives that the decrypt side rejects under default limits.

### 7.4 `archive/path.rs`

`archive/path.rs` owns the FCA path grammar — the **single shared writer/reader validator** (the spec §9.6/§9.10 symmetry guarantee).

It rejects:

- empty path;
- absolute path / leading `/`;
- trailing `/`;
- repeated `/`;
- NUL byte;
- backslash;
- `.` and `..` components, and any host `Component` that is not `Normal`;
- components longer than 244 bytes (`FCA_COMPONENT_MAX_BYTES` — the 255-byte filesystem name limit minus the `.incomplete` staging suffix);
- ASCII control bytes (`0x00..=0x1F`);
- Windows-reserved characters (`<`, `>`, `:`, `"`, `|`, `?`, `*`);
- trailing dot or trailing space in any component;
- Windows-reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `CLOCK$`, `CONIN$`, `CONOUT$`, `COM0..9`, `COM¹`/`COM²`/`COM³`, `LPT0..9`, `LPT¹`/`LPT²`/`LPT³`), including in extension stems (`CON.txt`, `LPT9.bin`), under ASCII-case-insensitive comparison (the superscript forms are matched on exact UTF-8 bytes);
- byte-length cap exceeded;
- depth cap exceeded.

`ascii_case_collision_key` lowercases ASCII A–Z (not locale-sensitive) and `unicode_form_collision_key` applies that key to the path's NFC form (equating precomposed and combining-mark spellings; non-ASCII letter case is not folded). Both serve tree-side duplicate detection in `tree.rs`.

This is one of the most security-sensitive modules. It must be heavily tested, including adversarial path cases.

### 7.5 `archive/tree.rs`

`archive/tree.rs` owns FCA manifest tree-shape validation.

`validate_manifest_tree` enforces:

- non-empty entry list;
- single top-level root;
- if root is a file, exactly one entry;
- if root is a directory, the root entry MUST be present and every non-root entry's parent MUST be present as a directory entry;
- no entry under a file path;
- no exact-duplicate paths;
- no ASCII-case-insensitive duplicate paths;
- no Unicode-form (NFC) duplicate paths;
- declared `total_file_bytes` within `max_total_plaintext_bytes`.

Order-independent (HashMap-based parent lookup), so non-canonical manifest orders satisfying the tree shape are accepted per spec §9.8.

### 7.6 `archive/encode.rs`

`archive/encode.rs` owns the FCA writer: source-tree traversal (metadata pass) and content-streaming pass.

The writer has two crate-internal phases. `prepare_archive` performs input validation, source-tree traversal, manifest serialization — which runs the tree validation as its own gate — and all writer-side limit checks. It returns a `PreparedArchive` containing the manifest, its serialized bytes, and the retained source file or directory handle. `PreparedArchive::write_to` writes the FCA header, manifest, and file contents. The orchestrator MUST call `prepare_archive` before cipher work and before creating the ciphertext staging file, so output placed inside the input tree cannot be included as source content. Entries created after preparation are not part of the archive. The one-call `archive` helper is compiled only for tests and the `unstable-fuzzing` feature.

It rejects:

- input symlinks (live or dangling);
- inputs that are not regular files or directories;
- symlinks, FIFOs, sockets, devices, Windows reparse points encountered during directory traversal;
- paths violating the FCA grammar (`validate_fca_path`);
- trees that exceed `ArchiveLimits` caps;
- source files whose size, type, or identity changes between the metadata pass and the content pass.

The writer is two-pass:

1. **Metadata pass** — opens the source root once. A single-file root is opened with a no-follow, non-blocking open and the handle is kept for the content pass; on Unix a `(dev, ino)` re-check against the lstat pre-check rejects a regular file swapped in behind that pre-check, whether at the leaf or through a replaced ancestor (`O_NOFOLLOW` guards the final component only). On non-Unix targets there is no comparable check: `std` exposes the Windows file identity only behind the unstable `windows_by_handle` feature, so the Windows open relies on its pre-open and post-open reparse-point and regular-file checks. A directory root is opened directly on Unix via `platform::open_anchor` and verified with the same `(dev, ino)` re-check, which rejects any directory swapped in behind the pre-check; on Windows, where no stable directory inode exists to re-check, it is opened through its parent via `platform::open_child_dir_nofollow` with the reparse-point post-check. The walk is iterative over `cap_std::fs::Dir::entries`, driven by a heap-backed stack of pending directories with deferred child opens (live handles track the depth of the tree, not its width, and deep nesting cannot overflow the process stack). Builds a `Manifest` with FCA-canonical paths, modes, sizes, and source paths, and on Unix records each file's `(dev, ino)` in `source_id` from the stat this pass already performs, so recording it costs no extra call; a filesystem reporting inode 0 supplies none and records `None`. Caps (entry count, total bytes, depth, path-bytes, manifest-size) apply while the tree is walked, so an over-cap tree is rejected without first holding every scanned entry in memory. The result is sorted by `(component_count, path_utf8)` per spec §9.8 for deterministic output.
2. **Content pass** — for each file entry in canonical manifest order, refreshes metadata from an open handle, requires the source is still a regular file with `len() == manifest size`, and streams exactly the declared size via `copy_exact_n`. Single-file roots stream from the handle held since the metadata pass, so no component of the user-supplied path is resolved a second time. Directory descendants re-anchor through the directory capability held since the metadata pass (per-component no-follow walk, then a no-follow non-blocking leaf open), and on Unix `require_same_source_file` compares the reopened leaf against the recorded `source_id` before the length check, because a regular file of the same length substituted at that name passes every other check and its content would be archived under the recorded path and mode. Off Unix nothing is recorded to compare: a directory listing there carries no volume serial number or file index, and reading them would mean opening every file in the metadata pass, so those targets keep the no-follow, reparse-point, type, and length checks alone — the omission `FORMAT.md` §9.10 permits a platform that exposes no stable file identity. Source mutation between passes is handled per spec §9.10.

Hardlinks are archived as independent regular-file contents (no link identity is stored). Setuid/setgid/sticky bits are stripped on write via `PERMISSION_BITS_MASK`.

Targets that are neither Unix nor Windows are rejected at compile time: the walker's repeat-directory detection (Unix `(dev, ino)` set, which refuses both a loop and the same directory reached at two places) and reparse-point rejection (Windows) have no equivalent there, so the build fails instead of walking a cyclic source tree until a resource cap fires. A Unix filesystem that reports inode 0 supplies no identity to compare, so those directories are excluded from the set and bounded by the entry-count, depth, and total-bytes caps alone.

### 7.7 `archive/decode.rs`

`archive/decode.rs` owns the FCA reader: header + manifest parse with full validation, then content extraction via the hardened cap-std platform backend.

The reader pipeline matches `FORMAT.md` §9.11, and the step numbers below are FORMAT.md's — they are cross-referenced from code comments and the audit trail, so the two documents must not drift. Steps 1–8 MUST complete before any filesystem output. The `output_dir` capability handle is opened between steps 8 and 9 and held through step 17, so staged writes, failure-path cleanup, the final mode application, and the closing identity checks all anchor to the same directory identity — as does the promotion itself on Linux and macOS (handle-relative via `archive/platform.rs::rename_at_no_clobber`). The Windows promotion is path-based in `fs/atomic.rs`.

1. parse and validate the FCA fixed header;
2. read exactly `archive_ext_len` bytes;
3. validate the archive-level TLV region;
4. read exactly `manifest_len` bytes;
5. parse the manifest, including each per-entry extension region;
6. validate every per-entry TLV region;
7. validate the complete manifest (entry count, total bytes, paths, duplicates, tree shape, parents present, resource caps, critical extension support);
8. pre-check the final output name with `symlink_metadata` (so a dangling symlink at the final name counts as occupied);
9. reject pre-existing `.incomplete` output at first create;
10. create `{root}.incomplete` (file or directory), hold a second handle for it, and pre-create its descendant directories. The handle is what steps 16 and 17 compare against and what failure cleanup destroys the staged plaintext through, so a run that cannot obtain it returns `CryptoError::Io` here rather than commit an output whose identity it could not confirm — the refusal precedes any plaintext, and the empty staged entry falls to the caller's [`IncompleteOutputPolicy`]. On Windows a directory root's second handle is opened by name with delete sharing (`archive/platform.rs::retain_staged_dir`), because a duplicate of the creating handle would refuse the promotion rename; it is confirmed by identity to be the directory just created before it is recorded (`decode::retain_staged_directory`), and a mismatch refuses the run here as a replacement;
11. stream file contents in manifest order via `copy_exact_n`, applying the per-file part of the platform durability sequence before the handle is dropped. Steps 11, 12, and 14 reach each entry through `archive/platform.rs::walk_to_parent` or `open_dir_at_rel`, both of which open existing directories only: step 10 created every directory the validated manifest declares, so a gap means another process changed the staged tree and the run fails rather than re-creating it;
12. apply descendant file modes by handle, interleaved per file with step 11 as §9.11 permits (the root entry's mode is deferred to step 16);
13. verify archive EOF (no trailing bytes);
14. apply descendant directory modes deepest-first;
15. promote `{root}.incomplete` to `{root}` via no-clobber rename;
16. apply the root entry's stored mode AFTER promotion. For directory roots this is macOS compatibility (a non-search-permitted root mode would block the rename); for regular-file roots this prevents a permissive manifest mode (e.g. `0o644`) from being briefly visible at the staged or final name while the file still holds plaintext. The reopened root is compared against the staged root's identity (`decode::require_staged_identity`) and the mode is applied through that same handle, so a substituted entry can neither receive the archive-chosen mode nor be swapped in after the comparison — a mode applies to an object rather than to a name, and a hard link would otherwise carry it to an object outside `output_dir`. A confirmed comparison also ratifies the commit: the extractor clears its staged-root record (`decode::PromotedIdentity`), so the step-17 checks can still fail the run but failure-path cleanup can no longer reach the committed output. An identity that was expected but could not be read (`decode::StagedIdentity::Unreadable`) skips the mode application instead of applying the mode to an unconfirmed entry; the output keeps the staged mode. Step 15 is the commit point, so this step is best-effort: a chmod failure here must not fail the extraction (a `DeleteOnError` caller would be told nothing was written while a complete output sits at the final name, beyond the reach of `.incomplete` cleanup), and the output then keeps the staged mode, which grants group and other nothing the manifest mode would have granted them and can leave the owner more access than the manifest asked for;
17. confirm the final name still denotes the object staged in step 10 (`archive/platform.rs::ObjectId`), and that the ambient `output_dir` still denotes the anchor the output was committed through; either mismatch fails the run rather than reporting an entry it did not write. Where step 16 ratified the commit, a mismatch here is report-only; without that ratification the staged record is still live, and `DeleteOnError` destroys the never-committed staged plaintext through it. The comparison follows the mode application, so a substitution made at any point up to it is caught; it shares `decode::require_staged_identity` with step 16, which reports the same mismatch but only refuses the chmod. A final name that no longer exists counts as a mismatch: step 15 committed an entry there, so its absence says the name no longer denotes the output. Any other failure to read that final entry does not, because it is not evidence about which object the name denotes. A failure to read the staged side is the same class of environment fault and skips the comparison on the same terms — `decode::StagedIdentity` keeps that state apart from a record without a handle, which no extraction produces, so the two cannot be confused for one another. Both sides of it are read AFTER the promotion — the retained staged handle against the final name — never recorded at creation and compared later: some filesystems derive a file's identity from the position of its directory entry, which the rename moves (measured on macOS `smbfs`, where both file and directory identities change across a rename while handle and name still agree). The retained handle also stays open until the last of these comparisons: a filesystem may give an object a new identifier once its last handle closes (measured on a Windows userspace filesystem reporting exFAT, where a run that closed the handle at ratification reported its own complete output as replaced), so ratification moves the `StagedRoot` record out of the cleanup slot without closing it, and it is dropped only after the destination-directory comparison. The destination-directory comparison is narrower: `EMFILE`, `ENFILE`, and `ENOMEM` — on Windows `ERROR_TOO_MANY_OPEN_FILES`, `ERROR_NOT_ENOUGH_MEMORY`, `ERROR_OUTOFMEMORY`, and `ERROR_NO_SYSTEM_RESOURCES` — skip it as unavailable resource checks, while permission denial and every other ordinary open or identity-read failure propagate; a path that no longer leads to a directory (missing, a non-directory, or a link cycle — `ELOOP`, on Windows `ERROR_CANT_RESOLVE_FILENAME`) reports as changed. Step 16 has already ratified the commit before that comparison, so an error cannot send `DeleteOnError` at the committed output. Every committed file root whose staging name was removed goes through `decode::require_single_linked_file` before step 16, which reads `nlink` through the retained staged-file handle and requires exactly one link — reading it after the mode was applied would hand the holder of a second name the access the deferred mode exists to withhold, so a wrong count skips step 16 entirely and the output keeps the owner-only staged mode: the staged plaintext is created under a name any local writer with access to `output_dir` can link to, and that link survives the promotion, so the route that committed the final name does not decide whether the count is read. A file-root hard-link fallback carries a distinct `PromotionOutcome` because it needs the count for a second reason — a moved staging link or an unlinked replacement must not be mistaken for cleanup — and the path-based file promotion used off Linux and macOS carries the same outcome on Unix targets, because `tempfile` can commit it by a hard link whose unlink result it does not report. The count covers the root entry: a descendant file inside a directory root has no handle retained to this point. An unlink failure, unreadable link count, or count other than one becomes an explicit post-commit error; the run never withdraws the final name after delayed or ambiguous cleanup, and `DeleteOnError` cannot reach the committed inode because the record left the cleanup slot before the error. The identity checks run on every platform (§7.8, `ObjectId`); a filesystem that reports no distinct identifiers makes them detect nothing rather than fail, and the hard-link count still fails closed;
18. return the final output path.

Before step 15, directory extraction completes that durability sequence with `archive/platform.rs::sync_extraction_barrier`. On macOS, every staged file first receives plain `fsync(2)` and every staged directory has the same best-effort sync attempted (for descendants, after the stored directory mode is applied, so the flush covers that mode); then one `F_FULLFSYNC` on the completed staged root asks the drive to commit all buffered data to persistent storage. The barrier is handle-relative and reports genuine failures before the commit point. This preserves the strongest-available pre-promotion durability while reducing full-device barriers from one per extracted file to one per directory decrypt. Single-file roots retain one strongest-available file flush. Linux needs no extra barrier because its per-file `fsync` is the same operation `sync_all` used; Windows retains `FlushFileBuffers` per extracted file.

`unarchive` accepts an [`IncompleteOutputPolicy`] from the caller. The default ([`IncompleteOutputPolicy::DeleteOnError`]) best-effort removes the `.incomplete` working tree while the current run still treats it as staged; [`IncompleteOutputPolicy::RetainOnError`] preserves it. Once step 16 ratifies a promoted root, later final-name, destination-directory, retained-temporary-name, or extra-link errors preserve the confirmed output and do not run staged cleanup. Cleanup tracks only the root THIS run created — `mkdir_strict` / `create_file_at` record a `StagedRoot` only when they actually created the working name, so an `.incomplete` this run did not create — a prior failed run's leftover, or a concurrent run's staging — rejects with `Incomplete output already exists` and is preserved. `StagedRoot::remove` chooses the removal from what the run created rather than from what currently occupies the working name, which is what a local writer with access to `output_dir` can change: a staged file is emptied through the handle `create_file_at` returned and then unlinked, never removed recursively, and a staged directory is removed through the handle `mkdir_strict` returned (`cap_std::fs::Dir::remove_open_dir_all`), whose contents go through that descriptor and whose own entry is found by identity in its parent. Unix has no portable unlink by descriptor, so the file arm's `set_len(0)` is what makes the two kinds agree when the staged root has been moved aside: the plaintext is destroyed under whatever name the entry now has. Neither arm is ever handle-less: a run that could not hold one failed at step 10, before any plaintext was staged, and the handle stays open across promotion on every platform. Windows has no recursive removal through a descriptor — `remove_open_dir_all` resolves the handle back to an absolute path, and the by-name removal resolves the name again for the same delete — so it removes by name against the SAME `cap_std::fs::Dir` opened for extraction, and only while the entry at the working name is still the directory behind the staged handle, so a directory substituted before that check is left in place; a directory put there in the instant between the check and the removal is what the removal then reaches, and a staged tree that was moved aside is not found by name and survives — the bounds `SECURITY.md` records for that target. Anchoring to the capability handle rather than re-resolving `output_dir` by path means a path swap of `output_dir` between failed extraction and cleanup cannot redirect `remove_*` to a different directory. All I/O errors are swallowed so the original `CryptoError` is the value the caller sees.

Steps 16 and 17 and this cleanup are pinned generatively by `decode::tests::post_commit_and_cleanup_invariants_hold_across_every_case`, which enumerates root kind × policy × payload completeness × local-writer interference × stored root mode and asserts invariants taken from `FORMAT.md` §9.11 rather than from this module, so a change that still satisfies the code's own reasoning but breaks the specification still fails. Three invariants it cannot reach are named on the test: removal or replacement of the output after promotion, because the reader is its only injection point and `unarchive` stops reading before it promotes (covered end to end through the dedicated step-16/17 seam by `a_post_ratification_replacement_preserves_the_committed_output`); failure of the resources the checks themselves need, which requires an fd-limit harness; and a staged descendant directory renamed out of the staged root, which cleanup can no longer reach through the handle that created that root, so plaintext already written inside it stays where it was put. The same seam covers a hard-link cleanup that nominally succeeded while another name still denotes the committed inode (`extraction_rejects_a_hidden_link_after_nominal_staging_cleanup`).

### 7.8 `archive/platform.rs`

`archive/platform.rs` owns the unified capability-based extraction backend used on every supported OS (Linux / macOS / Windows). Built on `cap-std` plus `cap-fs-ext`.

Invariant:

> Any symlink — or, on Windows, any NTFS reparse point including junctions and mount points — in an extraction path is an extraction error.

It contains:

- `open_anchor` — bootstraps the trusted `cap_std::fs::Dir` for the user-supplied `output_dir` and, on Unix, for the writer's source root (verified afterwards by the `(dev, ino)` re-check); the caller's chosen path IS the trust boundary so no no-follow check applies to it;
- `mkdir_strict`, `walk_to_parent`, `open_dir_at_rel`, `open_child_dir_nofollow` (the shared single-step open, also used by the writer's Windows source-root open) — every directory open routed through `cap_fs_ext::DirExt::open_dir_nofollow`. `mkdir_strict` is the only one that creates; `walk_to_parent` serves both sides, naming its own diagnostic through the label it is given;
- `finalize_dir_open` — Windows-only `FILE_ATTRIBUTE_REPARSE_POINT` post-check called after every successful directory open, so junctions / mount points fail closed (cap-fs-ext alone refuses entries where `is_symlink()` is true, but `is_symlink()` returns `false` for junctions — the bitmask post-check is what catches them);
- `create_file_at` — `OpenOptions::create_new(true)` plus `OpenOptionsFollowExt::follow(FollowSymlinks::No)` for atomic O_EXCL-style create that refuses every leaf symlink, dangling or live;
- `open_file_nofollow` + `finalize_file_open` — reopens the promoted root file without following symlinks and verifies that the opened object is a regular file (`decode::apply_root_file_mode`, `FORMAT.md` §9.11 step 16). On Unix the open is non-blocking, so a substituted FIFO cannot wait for a writer. The Windows reparse-point check also applies;
- `chmod_file_handle`, `chmod_dir_handle` — handle-based permission application; never path-based, so a substituted symlink between extract and chmod cannot redirect the operation. Special bits are stripped via `super::PERMISSION_BITS_MASK`. `chmod_dir_handle_durable` wraps the directory case for staged descendants: it opens the handle to flush while the directory still has the permissive staging mode, then applies the mode, then flushes that handle. The flush therefore covers the new mode; an open attempted afterwards would fail for a stored mode without read permission;
- `rename_at_no_clobber` (Linux/macOS) — handle-relative `renameat(dir, …, dir, …, RENAME_NOREPLACE)` via `rustix`, used by the decrypt promotion (`FORMAT.md` §9.11 step 15) so the `{root}.incomplete` → final-name commit is anchored to the same `output_dir` handle as extraction; a swap of the `output_dir` path mid-run cannot redirect it. On a filesystem whose driver refuses the no-replace flag outright (`fs/atomic.rs::no_replace_rename_unsupported`; the macOS exFAT driver among them) it dispatches to `rename_at_no_clobber_via_claim`. A file root takes `link_no_clobber` first: `cap_std::fs::Dir::hard_link` refuses an existing target atomically, so the staged file reaches the final name with no placeholder for a concurrent writer to replace, and the staged name is then unlinked. `PromotionOutcome::LinkedFile` keeps that route visible after a nominally successful or missing-name unlink, and `decode::require_single_linked_file` requires `nlink == 1` through the retained staged handle; moving the staging link or planting an unlinkable replacement therefore cannot produce success. If the unlink fails, the count cannot be read, or another link remains, the final name is not withdrawn: delayed cleanup gives a concurrent writer time to replace the entry, and no portable conditional unlink can remove only the link this run created. The decrypt completes the identity checks and returns an explicit post-commit error while preserving the complete commit and any additional link. Directory roots, and any filesystem without hard links, fall through to the claim: it atomically claims the final name through the same handle (`create_file_at` for a file root, owner-only `mkdir` for a directory root) and renames the staged root over its own claim — no-clobber against pre-existing entries stays unconditional, and both steps stay handle-relative. Between those two steps the claim is an ordinary entry, so an entry another process plants in its place is replaced by the rename; `SECURITY.md` states that bound. Windows and other-target promotion stays path-based in `fs/atomic.rs`, because a handle-relative no-replace rename on Windows needs an `unsafe` Win32 call the crate forbids;
- `ObjectId` + `metadata_object_id` / `dir_object_id` / `file_object_id` — the identity of a filesystem object, read from an open handle so a later step can tell whether a name still denotes the object this run created (`FORMAT.md` §9.11 steps 16 and 17). It is the `(dev, ino)` pair on Unix and the volume serial number and file index on Windows, both read through `fs/atomic.rs::file_identity` (§8.1), which a rename leaves unchanged; a filesystem reporting no distinct identifiers compares equal, so those steps keep the no-follow opens and the reparse-point checks as their guard;
- `retain_staged_dir` — the second handle to a staged directory root that the extractor holds across promotion. On Unix a duplicate of the creating handle; on Windows a fresh open of the entry by name with delete sharing, as a read handle with backup semantics that does not follow a reparse point, wrapped as a `Dir` for the identity read only — a cap-std directory handle has no delete sharing and would refuse the promotion rename. Because it resolves the name, `decode::retain_staged_directory` confirms its identity against the creating handle before recording it;
- `INITIAL_FILE_CREATE_MODE` — restrictive `0o600` initial mode applied at create time on Unix. Descendant files are chmod'd to the manifest mode after the payload is written (inside the 0o700 staged root). Single-file roots stay at `0o600` throughout staging and across the rename, with the manifest mode applied post-rename via `decode::apply_root_file_mode` so a wider final mode is never briefly visible. Effective on Unix only; ignored on Windows.
- `DIRECTORY_PROMOTION_SUPPORTED` — single source of truth for the set of targets with a safe no-clobber directory-promotion backend (Linux, macOS, Windows). A directory-root extraction cannot be committed elsewhere, so both the extractor (`decode::reject_unsupported_directory_root`) and the writer (`encode::validate_encrypt_input`) refuse a directory root on any other target — the writer refusing whatever the reader refuses keeps encrypt/decrypt symmetric. A `cfg!` value, not a `#[cfg]` gate, so both call sites type-check on every target. Single-file roots promote through `tempfile` everywhere and are unaffected.

Path validation and filesystem writes remain separate so race-hardening logic is auditable.

The backend uses `cap-std` and `cap-fs-ext` from the Bytecode Alliance — the same crates that back wasmtime's WASI sandbox. ferrocrypt itself contains no `unsafe`; all direct syscall surface lives in those audited dependencies. cap-std layers on `rustix` (Linux/macOS) and `windows-sys` (Windows) internally.

### 7.9 `archive/fd_limit.rs`

Test-only (`cfg(test)`, Linux and macOS): open-file-limit control for tests that need the archive code to run out of descriptors. `NofileLimit` sets the soft `RLIMIT_NOFILE` through the safe `rustix` `setrlimit` — never above the hard limit — and restores the saved value on drop; `HeldDescriptors` holds descriptors open so the code under test runs with a known number free, escalating its ceiling toward the hard limit on hosts whose soft limit starts low. The limit is process-wide while a guard is alive, so every test using this module relies on the workspace convention of running with `--test-threads=1`.

---

## 8. `fs/`

`fs/` owns local filesystem mechanics unrelated to archive-payload semantics.

Archive-specific path rules live in `archive/path.rs`; general output-path and staging mechanics live in `fs/`.

### 8.1 `fs/atomic.rs`

`fs/atomic.rs` owns atomic output behavior.

It contains:

- no-clobber finalization:
  - **encryption output and key generation** (file roots, every
    platform) go through `tempfile::*::persist_noclobber` — atomic
    no-replace on every supported platform, Windows included. On a
    Unix filesystem whose driver refuses the no-replace rename
    (`no_replace_rename_unsupported`; the macOS exFAT driver among
    them), `finalize_file` falls back to
    `finalize_file_via_link_or_claim`, which mirrors the archive
    promotion: it opens the destination directory as an `OutputDir` and
    links first (`cap_std::fs::Dir::hard_link`), because a link refuses
    an existing target atomically and so reaches the final name with no
    placeholder a concurrent writer could replace. `tempfile` does not
    retry the unsupported-operation error that leads here — its own
    link fallback answers only a no-replace flag reported as unknown or
    invalid, and discards that fallback's unlink result — so a
    filesystem with links but without a no-replace rename (SMB) is
    committed here without a claim
    window. Only a filesystem without hard links (exFAT) falls through
    to `finalize_file_via_claim`: exclusive-create the final name, then
    rename the temp file over that claim. No-clobber against
    pre-existing entries stays unconditional either way; between the
    claim and the rename the placeholder is an ordinary entry, so an
    entry another process plants in its place is replaced by the
    rename, the same bound `SECURITY.md` states for the archive claim;
    if that rename fails instead, the claim is withdrawn only while the
    entry is still the placeholder — the claim handle is retained and
    the removal is identity-checked — so such a planted entry is left
    in place.
    The link, the claim, the step-2 rename, and every removal resolve
    through one `OutputDir` handle — opened at entry, or threaded in by
    key generation so its commits share the anchor its rollbacks and
    flushes act on — and the staged temp file is an entry of the same
    directory, which the route confirms by identity before its first
    commit step; a staged entry that is missing or is another object —
    a temp staged elsewhere, or a local writer's deletion or
    replacement — refuses as a filesystem condition, not an internal
    error. A swap of the output path mid-commit therefore cannot
    redirect any step. If removing the staged
    name after a successful link fails, `finalize_file` returns a marked
    post-commit error and preserves both complete links; it never withdraws
    the final name after a delayed failure. A successful or missing-name unlink
    is followed by an `nlink == 1` check through the reopened committed handle,
    so moving the staged link or removing a planted replacement also fails the
    operation. The committed file handle remains live through that check and a
    final identity comparison — device and inode number on Unix, volume
    serial number and file index on Windows, read through the same handle
    on every platform — with the path the caller is about to report, so
    neither a hidden extra link nor a parent-directory/final-entry
    replacement can produce success; a final name that no longer exists
    counts as replaced, the step-17 rule the decrypt side applies.
    The one-step persist arm — on every platform — and the claim arm
    end with the same two confirmations through their retained handles:
    `tempfile`'s persist can itself have committed by hard link on Unix,
    so its `Ok` alone does not prove the staged name is gone, and a link
    planted against the staged temporary before the commit survives it
    anywhere.
    Opening the anchor needs a readable output
    directory (`SECURITY.md`);
  - **decrypt promotion on Windows and other non-Linux/macOS targets**:
    single-file roots through `promote_single_file_no_clobber` (the same
    `tempfile` atomic no-replace, Windows `MoveFileExW` included; on
    Unix targets the outcome is `PromotionOutcome::LinkedFile`, because
    `tempfile`'s primitive can commit by hard link there, so the decrypt
    still requires one link through its retained staged handle),
    directory roots through `rename_no_clobber` — best-effort
    `symlink_metadata` + `std::fs::rename` on Windows because no safe
    atomic no-replace directory rename is available there under
    `#![forbid(unsafe_code)]`;
  - **decrypt promotion on Linux and macOS** does NOT pass through this
    module: it is handle-relative and owned by
    `archive/platform.rs::rename_at_no_clobber`, anchored to the
    extraction `output_dir` handle so a path swap mid-run cannot
    redirect the commit;
- pre-promotion file durability: `sync_file_durable` flushes a staged
  `std::fs::File` with `sync_all` and falls back to plain `fsync(2)`
  where the filesystem reports the full flush as unsupported
  (`errno_not_supported`; macOS smbfs among them). Used where one flush
  covers a whole operation: the encrypted output and each generated key
  file. A single-file archive extraction similarly uses
  `archive/platform.rs::sync_single_file_durable`. Directory extraction
  instead applies `sync_file_standard` (plain `fsync(2)` on Linux and
  macOS) to each staged file, then calls `sync_extraction_barrier` once
  on the completed staged root before promotion. On macOS that final
  handle-relative call issues `F_FULLFSYNC`, reducing full-device
  barriers from one per file to one per operation without relying on
  plain `fsync` for operating-system-crash durability; a filesystem that
  rejects the full flush falls back to standard `fsync`, matching the
  strongest behavior it supported before. Linux already uses `fsync`
  for `sync_all`, and Windows retains `FlushFileBuffers` per file.
  Direct `rustix` `fsync` calls reach the syscall through
  `fsync_uninterrupted`, the single source of truth for EINTR handling,
  because `rustix` reports a signal-interrupted call as `EINTR` while
  `File::sync_all` retries internally;
- required directory-entry flushing: `sync_dir_durable` opens and flushes a directory, returning genuine failures to the caller. Unix uses an `O_DIRECTORY | O_NONBLOCK` read handle; Windows uses a backup-semantics write handle because `FlushFileBuffers` requires write access. Filesystems that cannot flush directories are treated as unsupported, which limits the caller's guarantee to process interruption. Key generation uses this helper after each key-file commit. `sync_parent_dir` remains the best-effort helper for path-based recoverable-output commits; on Unix and Windows alike it routes through the same `sync_dir_durable` primitive with the result dropped, so the parent is always opened as a directory and a path replaced by a FIFO or a device node after publication is refused rather than opened — a read-only open of such an object waits for a writer, and a best-effort helper has no error to swallow while the open itself is blocked. The Unix link/claim writer fallbacks instead flush through the exact `OutputDir` handle used for their commit on Linux and macOS, so a renamed destination path cannot redirect the barrier to a replacement directory; other Unix targets retain the path-based best effort. Staged descendant directories during extraction are flushed on Linux and macOS only (`archive/platform.rs::chmod_dir_handle_durable` for descendants, `sync_dir_handle` for the staged root): Windows needs a write handle for `FlushFileBuffers`, and the extraction directory handles are opened read-only; a capability-relative write reopen of `.` could close the gap but is not implemented or verified on Windows;
- anchored failure cleanup: `OutputDir` retains a `cap_std::fs::Dir` handle on the directory an operation publishes into, and `remove_published` resolves a removal inside that handle rather than through the entry's own path. A rollback runs after a commit is already visible on disk, which is exactly when a renamed or symlink-substituted output path would send the removal into a different directory and unlink a same-named file the operation never created. Key generation opens the handle before its first commit, threads it into both fallback commit routes (`finalize_file_with_anchor`), and undoes both key files through it, so commit, rollback, and barrier share one anchor; each rollback (`remove_published_if_retained`) also confirms through the retained committed handle that the entry it removes is still the file this run committed, so a key file moved aside and replaced during the failure window is left in place, and it returns a `RollbackOutcome` that `with_rollback_report` appends to the error being returned whenever the file is not confirmed gone — replaced, unreadable, or removed while it still had other names. The removal itself is `remove_retained`: on Unix an unlink of the name inside the anchored directory, on Windows a delete-on-close reopen of the retained committed handle (`cap_fs_ext::Reopen`), so a replacement made after the identity check is never removed there. The `finalize_file_via_claim` fallback uses the handle for the claim and, when its rename fails, for the identity-checked withdrawal of that claim (`remove_if_retained`, the same core as the key-file rollback, given the retained placeholder handle), so an entry planted in the placeholder's place is left alone; no bare-name removal remains in the module. The handle does not make the chosen directory trustworthy — the caller's choice of output directory is the trust boundary — it removes the mismatch between the directory an operation wrote to and the one it later cleans up in;
- keeping a staged file on disk after a refused promotion, so a rejected commit leaves the caller something to inspect.

Temporary output names, same-directory staging, and cleanup on encryption failure are the callers' concern: `container.rs` and `protocol.rs` build the names and stage into the destination directory, and `NamedTempFile`'s destructor removes a staged file that was never committed. `.incomplete` behavior on decryption failure belongs to `archive/decode.rs`, which owns the `StagedRoot` record of what the run created, its removal, and the `IncompleteOutputPolicy` dispatch.

Atomic output is a library guarantee. It is not a CLI-only concern.

### 8.2 `fs/paths.rs`

`fs/paths.rs` owns general path helpers.

It contains:

- output base-name derivation (`encryption_base_name`) — the file stem for a regular-file input, the full directory name for a directory input; the `.fcr` name itself is composed by the callers (`container.rs::resolve_encrypted_output_path`, `api.rs::default_encrypted_filename`);
- input leaf-name resolution (`input_leaf_name`) — the single source of truth for naming a user-supplied input. `.` and `..` carry no final component, so only those resolve against the current directory before the name is taken; every other path keeps the name as typed. Shared by `encryption_base_name`, which names the encrypted output, and `archive::encode::build_manifest`, which names the archive root, so one input cannot be named two ways;
- user-path error mapping;
- occupied-path / dangling-symlink rejection (`path_occupied`, `reject_occupied`) — `lstat`-based "is anything here?" preflight used by encrypt and keygen output prechecks so a stale symlink rejects in milliseconds instead of after Argon2id;
- special-file-safe input opening (`open_input_file`) — read-only open that refuses FIFOs, sockets, and device nodes; on Unix the open uses `O_NONBLOCK` so a FIFO cannot block the process inside `open(2)`, and the type check runs on the open handle (no check-to-use window). A missing path maps to the typed `InputPath` via `map_user_path_io_error`, so a vanished input reports identically across `Decryptor::open`, the probe, the decrypt open, and the key-file reads. Used by `api::probe_recipient_mode_with_limits`, `protocol::decrypt`, and `read_file_capped` — the decrypt-side counterpart of the encrypt-side `archive::encode::validate_encrypt_input` rejection;
- bounded file reads (`read_file_capped`) — opens via `open_input_file`, then `Read::take(cap + 1)` with over-cap rejection, used by `key/public.rs::read_public_key` to refuse multi-gigabyte attacker-controlled key files before any allocation;
- staged file reads (`read_file_staged`) — the same bounded open, but the fixed header is read first and the caller derives the remaining length from it, so a `private.key` is read at the size its own header declares rather than at the structural maximum of every field. Used through `key/private.rs::read_private_key_file` by `recipient/native/x25519.rs::open_x25519_private_key` and `api::validate_private_key_file`; a head that does not parse falls back to the structural cap, and a declared length above the cap is clamped to it.

It does not enforce FCA archive path rules. Archive path rules belong only to `archive/path.rs`.

---

## 9. Public API shape

The public API is value-oriented. Callers construct typed encryptors, decryptors, keys, and identities rather than selecting independent mode-specific orchestration functions.

### 9.1 Encryption

```rust
pub struct Encryptor { /* opaque */ }

impl Encryptor {
    pub fn with_passphrase(passphrase: Passphrase) -> Self;

    pub fn with_public_key(recipient: PublicKey) -> Self;

    pub fn with_public_keys(
        recipients: impl IntoIterator<Item = PublicKey>,
    ) -> Result<Self, CryptoError>;

    pub fn save_as(self, path: impl AsRef<Path>) -> Self;

    pub fn archive_limits(self, limits: ArchiveLimits) -> Self;

    pub fn header_read_limits(self, limits: HeaderReadLimits) -> Self;

    pub fn kdf_params(self, params: KdfParams) -> Self;

    pub fn kdf_limit(self, limit: KdfLimit) -> Self;

    pub fn write(
        self,
        input: impl AsRef<Path>,
        output_dir: impl AsRef<Path>,
        on_event: impl Fn(&ProgressEvent),
    ) -> Result<EncryptOutcome, CryptoError>;
}
```

Rules:

- `with_passphrase` creates exactly one `argon2id` recipient.
- `with_public_key` is a convenience wrapper around `with_public_keys` for one public recipient.
- `with_public_keys` supports the multi-recipient file format directly. It consumes the supplied iterator only up to one item past `HeaderReadLimits::RECIPIENT_COUNT_STRUCTURAL_MAX` and rejects there with `RecipientCountCapExceeded`, because no configuration can raise that ceiling and a longer list could never produce a writable file. The caller-configurable recipient-count cap is a separate check at `write`, since `header_read_limits` can still change it after construction.
- Recipient mixing is checked during construction.
- Empty recipient lists reject immediately.
- The API remains path-based because FerroCrypt security guarantees depend on archive preflight, streaming encryption, staging, and atomic finalization.
- **Writer caps mirror reader defaults.** A default-configured `Encryptor` produces `.fcr` files a default-configured `Decryptor` can read. The authoritative gates live in `protocol::encrypt` / `protocol::generate_key_pair`, so no in-crate caller can skip them; `Encryptor::write` / `KeyPairGenerator::write` run the same checks earlier so a misconfiguration fails before recipient key files are read (single source of truth per rule — see "Centralized cap enforcement" below):
  - `protocol::preflight_header_write_limits` checks all four axes of `HeaderReadLimits` against the exact header the writer will emit: `recipient_count`, per-entry `body_len` (canonical native value from `NativeRecipientType::body_len()`), the computed `header_len` — including the extension region, which the caller passes as the bytes themselves (`protocol::WRITE_EXT_BYTES`, empty today) so the checked length cannot drift from what `build_encrypted_header` seals — and the aggregate header-MAC work those imply. Tightening any axis below the writer's natural output rejects with the corresponding typed `*CapExceeded` variant. `protocol::encrypt` re-enforces the header-length and header-MAC-work caps against the assembled header bytes after the build, as the drift backstop.
  - For the passphrase path, `KdfParams::validate_for_write` (reached through `RecipientScheme::validate_for_write` in `protocol::encrypt`, and directly in `protocol::generate_key_pair`) runs the same `validate_structural` the reader runs (`lanes`, `time_cost`, `mem_cost` against the absolute bounds + the Argon2 `mem_cost ≥ ARGON2_MIN_MEM_COST_PER_LANE × lanes` floor), then the production memory floor `enforce_write_floor` (`mem_cost ≥ MIN_WRITE_MEM_COST`, 19 MiB), and finally `enforce_limit` against `KdfLimit`, which checks memory, time cost, lanes, and then the combined `mem_cost * time_cost` work. Above-structural params reject with `InvalidKdfParams::*`; below-floor `mem_cost` rejects with `KdfBelowWriteFloor`; above-resource-cap reject with `KdfResourceCapExceeded` / `KdfTimeCostCapExceeded` / `KdfLanesCapExceeded` / `KdfWorkCapExceeded`. Work is checked last so a header that also breaks a single dimension keeps reporting that dimension. The floor is hard and writer-only: the reader path never applies it, so a file written before the floor existed still decrypts.
  - The X25519 path never runs Argon2id during encrypt, so `kdf_limit` has no effect on `with_public_key` / `with_public_keys` flows.
  - To go above any default, the caller raises both sides explicitly: `Encryptor::header_read_limits` / `Encryptor::kdf_limit` / `KeyPairGenerator::kdf_limit` on the writer; `Decryptor::open_with_limits` plus `*::header_read_limits` / `*::kdf_limit` on the reader.
  - All checks fire after `validate_passphrase` and before any filesystem syscall or Argon2id work, so misconfiguration surfaces fast.

### Centralized cap enforcement

Every per-cap `if value > cap { return Err(...) }` lives in **one** method on the type that owns the cap. Both reader and writer call the same helper, so a cap value, its diagnostic, and its check semantics cannot drift.

| Cap / rule | Source of truth (constant) | Enforcement helper | Reader call site | Writer call site |
|---|---|---|---|---|
| `prefix.header_len` (resource cap) | `HeaderReadLimits::HEADER_LEN_DEFAULT` (= `format::HEADER_LEN_LOCAL_CAP_DEFAULT`) | `HeaderReadLimits::enforce_header_len` | `container::read_encrypted_header` | `protocol::preflight_header_write_limits` (called from `protocol::encrypt`; run early by `Encryptor::write`) — checks the exact `header_len` the writer will emit against the cap |
| `header_fixed.recipient_count` (resource cap) | `HeaderReadLimits::RECIPIENT_COUNT_DEFAULT` | `HeaderReadLimits::enforce_recipient_count` | `container::read_encrypted_header` | `protocol::preflight_header_write_limits` |
| Per-entry `body_len` (resource cap) | `HeaderReadLimits::RECIPIENT_BODY_LEN_DEFAULT` | `HeaderReadLimits::enforce_recipient_body_len` (writer); inline check in `RecipientEntry::parse_one` (reader; `recipient/entry.rs` sits below `container.rs` in the dep graph, so the helper can't be called from there without a cycle — same comparison, same `RecipientBodyCapExceeded` variant) | `RecipientEntry::parse_one` | `protocol::preflight_header_write_limits` (called against canonical `NativeRecipientType::body_len()`) |
| Aggregate header-MAC input (resource cap) — `supported_recipient_count × (PREFIX_SIZE + header_len)`, the product the three per-dimension caps above leave unbounded | `HeaderReadLimits::HEADER_MAC_WORK_BYTES_DEFAULT` (= `format::HEADER_MAC_WORK_LOCAL_CAP_DEFAULT`, itself the product of the recipient-count and header-length defaults) | `HeaderReadLimits::enforce_header_mac_work` | `protocol::classify_recipients_within_limits`, the one reader preflight both `protocol::DecryptSession::open` and `api::probe_recipient_mode_with_limits` call, so the file is refused before any private-key unlock, KDF, or header MAC — and so a probe cannot classify a file the decrypt path would refuse | `protocol::preflight_header_write_limits` (counts every entry, since the reader cannot know which will unwrap until after that work) |
| `header_fixed` structural rules (`header_flags == 0`, `1 <= recipient_count <= MAX`, `ext_len <= MAX`, `entries_len + ext_len + HEADER_FIXED_SIZE == header_len`) | `format::check_*` private helpers + `format::EXT_LEN_MAX` / `RECIPIENT_COUNT_MAX` | `HeaderFixed::validate_structural` | `HeaderFixed::parse` (after wire-byte parse) | `container::build_encrypted_header` (after constructing the `HeaderFixed` value from typed inputs) |
| Argon2id structural rules (`lanes ∈ [1, MAX_LANES]`, `time_cost ∈ [1, MAX_TIME_COST]`, `mem_cost ∈ [ARGON2_MIN_MEM_COST_PER_LANE × lanes, MAX_MEM_COST]`) | `KdfParams::MAX_*` constants + `crypto::kdf::ARGON2_MIN_MEM_COST_PER_LANE` | `KdfParams::validate_structural` | `KdfParams::from_bytes_structural` (after wire-byte parse) | `KdfParams::validate_for_write` (called from `protocol::encrypt` via `RecipientScheme::validate_for_write`, and from `protocol::generate_key_pair`; run early by `Encryptor::write` / `KeyPairGenerator::write`) |
| Argon2id `mem_cost` (resource cap, on top of structural) | `KdfLimit::MEM_COST_KIB_DEFAULT` (= `KdfParams::DEFAULT_MEM_COST`) / `KdfLimit::default()` | `KdfParams::enforce_limit` | `KdfParams::from_bytes` (calls `enforce_limit` after structural parse) | `KdfParams::validate_for_write` (calls `enforce_limit` after `validate_structural`) |
| Argon2id write floor (`mem_cost ≥ MIN_WRITE_MEM_COST`, 19 MiB; hard writer-only security policy) | `KdfParams::MIN_WRITE_MEM_COST` | `KdfParams::enforce_write_floor` | — (read path accepts below-floor files so existing data decrypts) | `KdfParams::validate_for_write` (calls `enforce_write_floor` on every write; from `protocol::encrypt` / `protocol::generate_key_pair`, run early by `Encryptor::write` / `KeyPairGenerator::write`) |
| Recipient-string length (resource cap) | `KeyReadLimits::RECIPIENT_STRING_CHARS_DEFAULT` (= `key::public::RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT`) | inline check in `key::public::decode_recipient_string` (the only site that sees the string) | `decode_recipient_string`, reached from `PublicKey::from_key_file` / `from_recipient_string` and their `*_with_limits` variants | — (writers emit a canonical string whose length follows from the key material) |
| `private.key` `wrapped_secret_len` (resource cap) | `KeyReadLimits::PRIVATE_KEY_WRAPPED_SECRET_LEN_DEFAULT` (= `key::private::PRIVATE_KEY_WRAPPED_SECRET_LOCAL_CAP_DEFAULT`) | inline check in `key::private::open_private_key` against the caller-supplied cap | `open_private_key`, reached from `open_x25519_private_key` with `PrivateKeyDecryptor::key_read_limits` | `key::private::seal_private_key_inner` (mirrors the default so a sealed file always opens under the default configuration) |
| Archive `max_entry_count`, `max_total_plaintext_bytes`, `max_path_depth` | `archive::limits::ArchiveLimits` defaults | `archive::limits::enforce_per_entry_caps`, `archive::limits::enforce_total_bytes_cap` | `archive::decode::extract_entries` (unified) | `archive::encode::archive` (iterative walker) |

Adding a new cap or wire-format rule = add the field/constant on the source-of-truth type, add one method (`enforce_*` for caps, `validate_*` for grouped structural rules), call it from both reader and writer sites. The compiler can't let you forget either side because the call sites are by name.

### 9.2 Decryption

```rust
#[non_exhaustive]
pub enum Decryptor {
    Passphrase(PassphraseDecryptor),
    PrivateKey(PrivateKeyDecryptor),
}

impl Decryptor {
    pub fn open(input: impl AsRef<Path>) -> Result<Self, CryptoError>;
}

pub struct PassphraseDecryptor { /* opaque */ }

impl PassphraseDecryptor {
    pub fn kdf_limit(self, limit: KdfLimit) -> Self;

    pub fn archive_limits(self, limits: ArchiveLimits) -> Self;

    pub fn header_read_limits(self, limits: HeaderReadLimits) -> Self;

    pub fn incomplete_output_policy(self, policy: IncompleteOutputPolicy) -> Self;

    pub fn decrypt(
        self,
        passphrase: Passphrase,
        output_dir: impl AsRef<Path>,
        on_event: impl Fn(&ProgressEvent),
    ) -> Result<DecryptOutcome, CryptoError>;
}

pub struct PrivateKeyDecryptor { /* opaque */ }

impl PrivateKeyDecryptor {
    pub fn kdf_limit(self, limit: KdfLimit) -> Self;

    pub fn key_read_limits(self, limits: KeyReadLimits) -> Self;

    pub fn archive_limits(self, limits: ArchiveLimits) -> Self;

    pub fn header_read_limits(self, limits: HeaderReadLimits) -> Self;

    pub fn incomplete_output_policy(self, policy: IncompleteOutputPolicy) -> Self;

    pub fn decrypt(
        self,
        private_key: PrivateKey,
        output_dir: impl AsRef<Path>,
        on_event: impl Fn(&ProgressEvent),
    ) -> Result<DecryptOutcome, CryptoError>;
}
```

`archive_limits` on the decrypt side mirrors `Encryptor::archive_limits` on the encrypt side. Both default to [`ArchiveLimits::default`] when unset; symmetry between encrypt-side preflight and decrypt-side extraction is the caller's responsibility — a `.fcr` produced under elevated encrypt caps can only be round-tripped by passing the same elevated value to the corresponding decryptor.

`incomplete_output_policy` defaults to [`IncompleteOutputPolicy::DeleteOnError`]: a failure best-effort removes this run's `.incomplete` plaintext while the output is still treated as staged, so authenticated-but-incomplete output does not linger under `output_dir`. It does not remove an output that was confirmed as complete before a later filesystem namespace error. [`IncompleteOutputPolicy::RetainOnError`] preserves the staged tree for backup-recovery / forensic flows; callers that opt in MUST treat retained partials as a potentially attacker-chosen prefix (FerroCrypt's STREAM-BE32 payload only detects truncation when the final chunk arrives, so an attacker can choose any chunk-aligned prefix that the recovered plaintext represents).

Preferred public concepts are `Passphrase` and `Recipient`. Internals are not organized around `Symmetric` and `Hybrid` because those names describe historical modes rather than the recipient-entry model.

### 9.3 Keys and identities

`PublicKey` supports:

- `from_key_file`;
- `from_recipient_string`;
- `from_x25519_bytes` where supported;
- `fingerprint`;
- canonical `to_recipient_string()` output.

Every constructor resolves its source to suite-plus-key-material immediately and the value stores that result, so a `PublicKey` never reads its source twice. This is a security requirement, not an optimisation: `fingerprint` and encryption MUST describe the same key material, otherwise an identity check made against a displayed fingerprint says nothing about the key an operation later uses. A construction failure is therefore reported at construction, and there is no separate "validate this value" operation — a `PublicKey` that exists is a valid one. `validate_public_key_file` remains the way to check a file without keeping the key.

`PrivateKey` supports:

- `from_key_file(path, Passphrase)`, which binds the passphrase that unlocks the file;
- validated private-key loading;
- typed dispatch to its native recipient scheme after passphrase unlock.

Because it holds the passphrase, `PrivateKey` is not `Clone`; build one value per decrypt.

### 9.4 Key generation

```rust
pub fn generate_key_pair(
    output_dir: impl AsRef<Path>,
    passphrase: Passphrase,
    on_event: impl Fn(&ProgressEvent),
) -> Result<KeyGenOutcome, CryptoError>;

pub struct KeyPairGenerator { /* opaque */ }

impl KeyPairGenerator {
    pub fn with_passphrase(passphrase: Passphrase) -> Self;

    pub fn kdf_params(self, params: KdfParams) -> Self;

    pub fn kdf_limit(self, limit: KdfLimit) -> Self;

    pub fn write(
        self,
        output_dir: impl AsRef<Path>,
        on_event: impl Fn(&ProgressEvent),
    ) -> Result<KeyGenOutcome, CryptoError>;
}
```

Ownership split:

- X25519 key generation lives in `recipient/native/x25519.rs`.
- Key serialization lives in `key/`.
- Key-file staging lives in `protocol.rs` key generation and uses the atomic-output helpers in `fs/`. Both files are staged and synced before either is committed. `private.key` is committed first, and the output directory is flushed after each commit — on Linux and macOS through the retained `fs/atomic.rs::OutputDir` handle (`OutputDir::flush_durable`, which reopens `.` through the handle because cap-std may hold it as `O_PATH`), elsewhere through the path-based `fs/atomic.rs::sync_dir_durable`. A failed final directory flush removes `public.key` but keeps `private.key`, because removing both without a working directory flush could leave only `public.key` behind after power loss. Every one of those removals goes through the same `OutputDir` handle opened before the first commit, so an output directory renamed or replaced between the two commits can neither turn a rollback into the deletion of an unrelated key file of the same name nor (on Linux and macOS) leave the durability barrier flushing a directory the entries were never committed to. Filesystems that cannot flush directories retain protection against process interruption but cannot provide the same power-loss guarantee.

`KeyPairGenerator` mirrors `Encryptor`'s reader-aligned cap rule for the passphrase that seals `private.key`: the whole of `KdfLimit` — `mem_cost` (default 1 GiB), `time_cost`, `lanes`, and the combined `mem_cost * time_cost` work (default the writer's own budget) — is enforced at `write` time before Argon2id runs. Above-default `mem_cost` rejects with `CryptoError::KdfResourceCapExceeded` and above-budget work with `CryptoError::KdfWorkCapExceeded`; the unlocking [`PrivateKeyDecryptor`] must be configured via [`PrivateKeyDecryptor::kdf_limit`] with a matching [`KdfLimit`].

### 9.5 Recipient-mode probe

```rust
pub fn probe_recipient_mode(
    path: impl AsRef<Path>,
) -> Result<Option<UnauthenticatedRecipientMode>, CryptoError>;
```

The canonical concepts are:

```rust
#[non_exhaustive]
pub enum UnauthenticatedRecipientMode {
    Passphrase,
    PublicKey,
}

pub struct AuthenticatedRecipientMode { /* sealed */ }

#[non_exhaustive]
pub enum AuthenticatedRecipientModeKind {
    Passphrase,
    PublicKey,
}
```

`probe_recipient_mode` performs a single bounded header parse on one file handle (no path reopen between magic check and header read). It runs no KDF, no private-key operation, no header-MAC verification, and no payload decryption. Its output is **not** a security claim; it is suitable only for UI / routing hints.

`AuthenticatedRecipientMode` is the post-decrypt counterpart: it is constructed only inside the decrypt path after a recipient unwraps and the header MAC verifies, and surfaces on `DecryptOutcome::recipient_mode`. The wrapping struct's field is private and there is no `From<UnauthenticatedRecipientMode>` impl, so external callers cannot fabricate a value that claims authentication. Callers switch on the variant via `kind()` (or the `is_passphrase` / `is_public_key` accessors).

Compatibility names may exist in the public API, but internal structure and documentation use passphrase and public-key (recipient) terminology.

---

## 10. Single sources of truth

Each security-sensitive concern has exactly one owner.

| Concern | Owner |
|---|---|
| Wire constants and fixed structs | `format.rs` |
| Keypair compatibility suite (`KeypairSuite`, `WRITER_KEYPAIR_SUITE`, `keypair_suite_is_supported`) — single shared support gate for both `public.key` and `private.key` parsers | `format.rs` |
| Keypair wire-version reverse mapping (`keypair_suite_from_public_key_version`, `keypair_suite_from_private_key_version`, returning `KeypairVersionRejection`) — single source of truth for `0x00` reserved-byte rejection and writer-relative older/newer classification across both artefact domains; consumers in `key/public.rs` and `key/private.rs` translate the rejection into their domain-specific error variants | `format.rs` |
| `.fcr` header/container assembly | `container.rs` |
| File-key generation | `crypto/keys.rs` |
| Payload/header subkey derivation | `crypto/keys.rs` |
| Header MAC computation, verification, and input definition | Typed wrappers in `format.rs`, backed by generic primitives in `crypto/mac.rs`, called by `container.rs` and `protocol.rs` |
| STREAM-BE32 payload rules | `crypto/stream.rs` |
| Argon2id parameter validation | `crypto/kdf.rs` |
| Recipient-entry framing | `recipient/entry.rs` |
| Recipient type-name grammar | `recipient/name.rs` |
| Mixing policy and native-scheme classification | `recipient/policy.rs` |
| Argon2id recipient body semantics | `recipient/native/argon2id.rs` |
| X25519 recipient body semantics | `recipient/native/x25519.rs` |
| Public recipient string format | `key/public.rs` |
| Private key binary format | `key/private.rs` |
| Key-file filesystem helpers | `key/files.rs` |
| Safe archive path validation | `archive/path.rs` |
| Archive resource limits | `archive/limits.rs` |
| Archive encoding | `archive/encode.rs` |
| Archive decoding | `archive/decode.rs` |
| Platform extraction hardening | `archive/platform.rs` |
| Atomic output (encryption and key-file finalize; Windows/other-target decrypt promotion) | `fs/atomic.rs` |
| Handle-relative decrypt promotion (Linux/macOS) | `archive/platform.rs` |
| General filesystem path helpers | `fs/paths.rs` |
| Public API translation | `api.rs` |
| End-to-end operation flow | `protocol.rs` |

No second implementation of these concerns may exist.

---

## 11. Dependency direction

The intended dependency graph is:

```text
lib.rs
  ↓
api.rs
  ↓
protocol.rs
  ├── container.rs → format.rs + archive/*
  ├── recipient/* → crypto/*
  │   └── recipient/native/x25519.rs → key/private.rs
  ├── key/* → crypto/* + recipient/name.rs
  │   └── key/public.rs → recipient/native/x25519.rs
  ├── archive/*
  └── fs/*
```

Dependency rules:

- `format.rs` depends only on `error.rs` and the `crypto/` primitive layer (`crypto/mac` and `crypto/keys` for the typed `compute_header_mac` / `verify_header_mac` wrappers, plus the `STREAM_NONCE_SIZE` constant from `crypto/stream`); it does not depend on any higher-layer module.
- `passphrase.rs` is a leaf: it depends on no other module in the crate, so any layer may consume it. `api.rs`, `protocol.rs`, `crypto/keys.rs`, `key/private.rs`, and `recipient/native/*` do.
- `crypto/*` does not depend on `protocol.rs`, `archive/*`, or `fs/*`.
- `recipient/native/*` does not call `container.rs` or `archive/*`.
- `archive/*` does not know about recipients, keys, or encrypted-header structure.
- `archive/*` and `recipient/native/*` may depend on `fs/*` for filesystem helpers; `fs/*` must not depend on archives, recipients, or cryptographic keys.
- `key/private.rs` does not know about archive handling or output paths.
- `key/public.rs` and `key/private.rs` do not perform end-to-end encryption or decryption.
- `fs/*` does not know about recipient schemes or cryptographic keys.
- `lib.rs` does not call low-level cryptographic functions directly.

---

## 12. Decryption security ordering

Decryption must preserve this order:

1. Read prefix.
2. Reject bad magic, version, kind, flags, or header length.
3. Read header and header MAC.
4. Structurally parse header and recipient entries.
5. Reject unknown critical recipients for every entry, then malformed flags and
   wrong native body lengths for every entry, then illegal mixing. Each pass
   covers the whole recipient list before the next one starts.
6. Apply local resource caps, including the aggregate header-MAC bound on the
   supported recipient count multiplied by the header size.
7. Attempt supported recipient entries. No private-key unlock, KDF, or key
   agreement may run before step 6 completes.
8. Verify header MAC with each candidate `FileKey`.
9. Validate authenticated TLV bytes only after successful header MAC verification.
10. Derive the payload key.
11. Decrypt the payload stream.
12. Decode the archive with path and resource checks before filesystem writes.
13. Promote staged output only after successful authenticated decryption and extraction.

No refactor may move TLV interpretation, archive writes, or payload plaintext release before the relevant authentication step.

The credential is also disposed of on a schedule. The passphrase that unlocks a `private.key` is dropped as soon as the unlock returns, and the decrypt credential — a passphrase or an unwrapped private scalar — is taken by value and dropped when step 8 ends. Steps 9 to 13 run on attacker-supplied bytes and need only the derived payload key, so no reusable long-term secret stays resident while an attacker-chosen archive is extracted. A refactor must not extend a credential's lifetime past the recipient slot loop, for example by borrowing it from a caller that outlives extraction.

The same rule governs the two writing paths, where the work after the credential's last use is bounded by the caller rather than an attacker but is still unbounded in principle. `protocol::encrypt` takes its recipient list by value and drops it once every body is wrapped, so an `argon2id` passphrase does not survive the payload stream; `PassphraseRecipient` owns its `Passphrase` for exactly this reason, and a scheme that borrowed one instead would defeat the drop. The credential is still live across `prepare_archive`, which runs first on purpose so an unusable source tree is rejected before an expensive KDF; that pass reads metadata only, while the streaming it precedes reads every byte. `protocol::generate_key_pair` takes its passphrase by value and drops it once `private.key` is sealed, before either key file is staged, flushed, or committed. `protocol::tests::recipients_are_dropped_before_the_payload_phase` and `credential_is_dropped_before_the_payload_phase` pin both orderings against the matching `ProgressEvent`.

---

## 13. Public error wording

Public errors must be precise without claiming certainty that cryptographic verification cannot provide.

Use wording such as:

- “wrong passphrase or modified file”;
- “no matching recipient or modified file”;
- “no supported recipient”;
- “file header was modified or corrupted”.

Do not use names or display messages that imply FerroCrypt can distinguish wrong credentials from tampering when the AEAD or HMAC result cannot prove that distinction.

---

## 14. Extension and non-goal boundaries

The file format supports external recipient names, and the implementation preserves unknown recipient entries as authenticated opaque data where permitted by policy.

The stable public API does not expose a third-party crypto plugin trait. Public plugin registration requires a separate security design, conformance tests, documentation, and review.

The stable public API also does not expose:

1. **Arbitrary caller-owned `Read`/`Write` streaming encryption.**
   FerroCrypt guarantees depend on path preflight, archive caps, staging, and atomic finalization.

2. **A simple in-memory whole-file API.**
   Whole-file plaintext or ciphertext buffers do not match FerroCrypt’s file-encryption and streaming-payload design.

3. **Async I/O.**
   Async support would expand the security-sensitive surface and is not part of the canonical structure.

4. **Localization in the library.**
   The library returns typed errors. CLI and desktop layers own localization of user-facing strings.

---

## 15. Architectural invariants

The following invariants define the long-term structure of the library:

- FerroCrypt is file encryption, not generic message encryption.
- Payloads are streamed; callers do not need whole plaintext or ciphertext buffers.
- Headers are authenticated before authenticated metadata is interpreted.
- Plaintext is not released before the relevant authentication checks succeed.
- Recipients are typed entries in one protocol, not separate protocol modes.
- Passphrase and X25519 support are native recipient schemes.
- Unknown non-critical recipient entries remain opaque authenticated data.
- Strong Rust newtypes protect file keys, payload keys, and header keys from misuse.
- Archive path validation is isolated and heavily tested.
- Filesystem finalization is staged and atomic.
- Error messages preserve cryptographic ambiguity.
- Public extension surfaces are added only after explicit security review.
- Each security-sensitive concern has a single owner and no duplicate implementation.
