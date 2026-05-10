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
   - [3.7 `fuzz_exports.rs`](#37-fuzz_exportsrs)
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

FerroCrypt is organized around a single file-encryption protocol pipeline. The v1 file model is:

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
│   └── platform.rs
│
├── fs/
│   ├── mod.rs
│   ├── atomic.rs
│   └── paths.rs
│
└── fuzz_exports.rs
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
- public constants re-exported from their owning modules.

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

1. file-key generation;
2. stream nonce generation;
3. recipient-scheme file-key wrapping;
4. authenticated-header construction;
5. archive encoding;
6. payload stream encryption;
7. staged output finalization;
8. progress event emission.

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

`protocol.rs` defines the internal recipient-scheme abstraction boundary:

```rust
pub(crate) trait RecipientScheme {
    const TYPE_NAME: &'static str;
    const MIXING_RULE: NativeMixingRule;

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
- A recipient unwrap is successful only after the candidate `FileKey` verifies the authenticated header MAC.
- The orchestrator threads a single `&dyn Fn(&ProgressEvent)` callback into each scheme. Schemes whose KDF step is expensive (Argon2id) emit `ProgressEvent::DerivingPassphraseWrapKey` from inside `wrap` / `unwrap` immediately before the KDF call — that is, **after** structural validation and resource-cap checks have passed. Schemes whose wrap / unwrap is sub-millisecond (X25519) MUST ignore the callback so cheap operations never lie about a long pause. The `private.key` Argon2id boundary is owned separately by `key::private::open_private_key`, which emits `ProgressEvent::UnlockingPrivateKey` at its own work boundary; `protocol::decrypt` does NOT emit a `DerivingKey`-style event from the orchestrator.

### 3.4 `format.rs`

`format.rs` owns byte-level wire constants and fixed structures.

It contains:

- magic bytes;
- the `.fcr` outer file version byte (`FCR_FILE_VERSION`);
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

- `HeaderReadLimits` (public, `#[non_exhaustive]`, builder methods clamp at the v1 structural maxima);
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

Error variants that carry data carry typed structured data, such as `FormatDefect`, `UnsupportedVersion`, `InvalidKdfParams`, the `MixingPolicy` diagnostic projection (with a structured `Custom { compatibility_class }` payload for non-shorthand classes), named integer fields for resource caps, and owned `type_name` strings for per-recipient diagnostics. Consumers can pattern-match on error shapes without substring comparisons.

Diagnostic rules:

- A passphrase recipient open failure means “wrong passphrase or recipient entry tampered,” not definitely “incorrect passphrase”.
- A private-key unlock failure means “wrong passphrase or private key file tampered,” not definitely one or the other.
- An X25519 recipient failure means “no matching credential, wrong key, or recipient entry tampered,” unless a later authenticated step proves a more specific class.
- A header MAC failure after recovering a candidate `FileKey` means the recovered key did not authenticate the header. It does not by itself prove whether the credential, recipient body, or header bytes were modified.

Public error names may be compatibility-oriented, but their display text must preserve this ambiguity.

### 3.7 `fuzz_exports.rs`

`fuzz_exports.rs` exposes internal parser and validation entry points needed by fuzz targets.

It is not part of the stable public API. It must not become an alternate implementation path for parsing, validation, cryptography, or archive handling.

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

`crypto/hkdf.rs` owns HKDF-SHA3-256 adapters and non-scheme-specific domain separation.

It contains:

- HKDF-SHA3-256 helper functions;
- shared HKDF wrappers;
- domain-separated labels that are not specific to a recipient scheme.

Recipient-specific HKDF info strings live with their recipient scheme. Header, payload, and private-key derivation labels live with the modules that own those derivations.

### 4.4 `crypto/mac.rs`

`crypto/mac.rs` owns HMAC-SHA3-256 helpers.

It contains:

- generic HMAC-SHA3-256 computation helpers;
- generic HMAC-SHA3-256 verification helpers;
- constant-time MAC comparison where applicable.

The primitives in `crypto/mac.rs` accept raw byte keys so they remain reusable. Header MAC type safety is enforced by the typed `compute_header_mac` and `verify_header_mac` wrappers in `format.rs`, which accept `&HeaderKey` and call these generic primitives.

### 4.5 `crypto/aead.rs`

`crypto/aead.rs` owns XChaCha20-Poly1305 helpers and nonce utilities.

It contains:

- AEAD seal helpers;
- AEAD open helpers;
- nonce generation utilities;
- nonce parsing and validation helpers where applicable.

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
- truncation detection.

Payload streaming uses `PayloadKey`. It does not know about recipient schemes, key files, archive paths, or output finalization.

### 4.7 `crypto/tlv.rs`

`crypto/tlv.rs` owns the shared TLV grammar for every FerroCrypt extension region: `.fcr` header `ext_bytes`, `private.key` `ext_bytes`, FCA `archive_ext`, and FCA per-entry `entry_ext`.

The module exposes:

- `scan_tlv_region(bytes, max_region_len, max_value_len) -> Vec<RawTlv>` — the parsing primitive. Validates structural framing (each entry header fits, declared `len` fits in the region and `<= max_value_len`), strict ascending tag order, reserved-tag rejection. Returns parsed entries with cached `TlvClass`. Does not enforce a critical-tag policy.
- `reject_unknown_critical(tlvs) -> Result<()>` — the v1.0 policy wrapper. Rejects any `TlvClass::Critical` entry as `UnknownCriticalTag` because v1.0 defines no known critical tags in any region. Future versions that define known criticals will iterate the scanned TLVs against a registry instead.
- `validate_no_known_critical(bytes, max_region_len, max_value_len) -> Result<()>` — the v1.0 single-call helper. Combines `scan_tlv_region` and `reject_unknown_critical` for callers that don't need the parsed entries. Used by every v1.0 caller (FCR header, `private.key`, FCA `archive_ext`, FCA `entry_ext`).
- `classify_tlv_tag(tag) -> Result<TlvClass>` — pure tag classification, rejects the two reserved values.
- `validate_tlv(ext_bytes)` — public convenience function. Calls `validate_no_known_critical` with `EXT_LEN_MAX` for both region and value caps. Used by `.fcr` header and `private.key` callers.

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

`recipient/entry.rs` owns the generic v1 recipient entry framing:

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
- canonical recipient-entry serialization;
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
- `validate_external_type_name(name)` — runs the grammar check, then enforces the §3.3.1 namespace policy: the name MUST contain `/` and MUST NOT impersonate a reserved native shape. v1 ships no public plugin / third-party recipient registration surface, so this validator currently has no in-tree caller; it exists so the §3.3.1 policy is enforceable the moment such a surface is added.

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

`key/public.rs` owns the public recipient key text format.

It contains:

- Bech32 recipient string encoding;
- Bech32 recipient string decoding;
- HRP validation;
- public-key wire-version-byte (`PUBLIC_KEY_VERSION`, `PUBLIC_KEY_V1_VERSION`) and the public-flavoured wire-version-to-suite translation, which is now a thin `map_err` wrapper over the centralised `keypair_suite_from_public_key_version` in `format.rs` — this layer picks the public-key error variants (`MalformedPublicKey`, `OlderPublicKey`, `NewerPublicKey`) and routes the suite through the shared support gate in `format.rs` (`FORMAT.md` §7);
- the writer's current logical version (`PUBLIC_KEY_VERSION`, derived from `WRITER_KEYPAIR_SUITE`);
- internal SHA3-256 checksum handling;
- canonical lowercase enforcement;
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
- `from_bytes` carries no suite marker on its input and tags the value with `WRITER_KEYPAIR_SUITE`, so raw bytes cannot resurrect a public key from a non-writer suite.

`PublicKey::to_recipient_string` re-encodes using the suite the value was constructed with, not the current writer suite, so a recipient string round-trips byte-identically as long as its suite is still supported by this build.

### 6.2 `key/private.rs`

`key/private.rs` owns the private key file format.

It contains:

- `private.key` binary layout;
- the private-key wire-version constants (`PRIVATE_KEY_VERSION` derived from `WRITER_KEYPAIR_SUITE`; `PRIVATE_KEY_V1_VERSION` derived from `KeypairSuite::V1`) and the private-flavoured wire-version-to-suite translation, which is now a thin `map_err` wrapper over the centralised `keypair_suite_from_private_key_version` in `format.rs` — this layer picks the private-key error variants (`MalformedPrivateKey`, `OlderKey`, `NewerKey`) and routes the suite through the shared support gate in `format.rs` (`FORMAT.md` §8);
- cleartext private-key header parsing;
- passphrase-wrapped secret encryption;
- passphrase-wrapped secret decryption;
- private-key TLV validation after authentication;
- generic typed secret material returned to recipient schemes;
- construction and loading support for `PrivateKey`;
- emission of `ProgressEvent::UnlockingPrivateKey` at the actual Argon2id call boundary inside `open_private_key` (after structural header parsing, the caller's `KdfLimit` resource-cap check, the wrapped-secret-length cap, the total-length check, and type-name grammar validation have all passed). A structurally malformed key file or one that exceeds either cap is rejected with no event emitted. `seal_private_key` is silent: keygen owns its own outer `GeneratingKeyPair` event.

It does not contain X25519-specific recipient policy. The X25519 recipient module verifies that decrypted secret material corresponds to X25519 public material.

### 6.3 `key/files.rs`

`key/files.rs` owns filesystem-level key helpers.

It contains:

- default filenames `public.key` and `private.key`;
- key-file classification;
- key-file read wrappers;
- key-file write wrappers;
- staging for generated key files.

Key-file staging uses filesystem helpers from `fs/` and does not duplicate atomic-output behavior.

---

## 7. `archive/`

`archive/` owns the FerroCrypt Archive (FCA) v1 wire format and directory/file payload semantics. The byte-level FCA spec lives in `ferrocrypt-lib/FORMAT.md` §9.

Archive handling is security-critical. Wire-format constants, model types, resource limits, path-grammar validation, tree-shape validation, encoding, decoding, and platform-specific extraction hardening are separated so each review surface is explicit.

### 7.1 `archive/format.rs`

`archive/format.rs` owns the FCA wire format.

It contains:

- wire-format constants (`FCA_MAGIC = b"FCA\0"`, `FCA_VERSION = 0x01`, `FCA_HEADER_SIZE = 27` (includes the `archive_ext_len` field), `FCA_ENTRY_FIXED_SIZE = 18` (includes the per-entry `entry_ext_len` field), `KIND_FILE = 0x01`, `KIND_DIR = 0x02`, `PERMISSION_BITS_MASK = 0o777`);
- big-endian integer helpers used by both header and manifest serialization;
- header parse/build (`parse_fca_header` / `write_fca_header`);
- manifest serialize/parse (`checked_manifest_len` / `serialize_manifest` / `parse_manifest_bytes`);
- `copy_exact_n`, the shared exact-size byte copier used by both encode (source file → encrypted stream) and decode (encrypted stream → output file).

`checked_manifest_len` runs BEFORE allocation: an over-cap manifest is rejected without growing a `Vec` first. `parse_manifest_bytes` calls `validate_fca_path` and `validate_manifest_tree` so a successfully-parsed `Manifest` is fully validated.

### 7.2 `archive/model.rs`

`archive/model.rs` owns the FCA model types.

It contains:

- `FcaHeader` — parsed header summary (`entry_count`, `archive_ext_len`, `manifest_len`, `total_file_bytes`);
- `ArchiveEntryKind` — `File` / `Directory` enum;
- `ArchiveEntry` — `path_utf8`, `mode`, `size`, opaque `entry_ext: Vec<u8>` carrying the per-entry TLV region (empty for v1 writers, populated by the parser for v1.x readers), plus a writer-only `source_path: Option<PathBuf>` set by the metadata pass so the content pass can reopen no-follow;
- `Manifest` — `entries`, `total_file_bytes`, `root_name`, `root_is_file`.

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

Cap helpers (`enforce_per_entry_caps`, `enforce_total_bytes_cap`) are shared by encrypt-side preflight and decrypt-side enforcement. Encrypt-side preflight and decrypt-side enforcement must agree: the encrypt side must not produce archives that the decrypt side rejects under default limits.

### 7.4 `archive/path.rs`

`archive/path.rs` owns the FCA path grammar — the **single shared writer/reader validator** (the spec §19.3 symmetry guarantee).

It rejects:

- empty path;
- absolute path / leading `/`;
- trailing `/`;
- repeated `/`;
- NUL byte;
- backslash;
- `.` and `..` components, and any host `Component` that is not `Normal`;
- ASCII control bytes (`0x00..=0x1F`);
- Windows-reserved characters (`<`, `>`, `:`, `"`, `|`, `?`, `*`);
- trailing dot or trailing space in any component;
- Windows-reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `CLOCK$`, `COM1..9`, `LPT1..9`), including in extension stems (`CON.txt`, `LPT9.bin`), under ASCII-case-insensitive comparison;
- byte-length cap exceeded;
- depth cap exceeded.

`ascii_case_collision_key` lowercases ASCII A–Z (not locale-sensitive) for tree-side duplicate detection in `tree.rs`.

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
- declared `total_file_bytes` within `max_total_plaintext_bytes`.

Order-independent (HashMap-based parent lookup), so non-canonical manifest orders satisfying the tree shape are accepted per spec §10.

### 7.6 `archive/encode.rs`

`archive/encode.rs` owns the FCA writer: source-tree traversal (metadata pass) and content-streaming pass.

It rejects:

- input symlinks (live or dangling);
- inputs that are not regular files or directories;
- symlinks, FIFOs, sockets, devices, Windows reparse points encountered during directory traversal;
- paths violating the FCA grammar (`validate_fca_path`);
- trees that exceed `ArchiveLimits` caps;
- source files whose size or type changes between the metadata pass and the content pass.

The writer is two-pass:

1. **Metadata pass** — recursive `fs::read_dir` walk that builds a `Manifest` with FCA-canonical paths, modes, sizes, and source paths. Caps (entry count, total bytes, depth, path-bytes, manifest-size) apply progressively. The result is sorted by `(component_count, path_utf8)` per spec §10 for deterministic output.
2. **Content pass** — for each file entry in canonical manifest order, reopens the source file with `O_NOFOLLOW` (Unix) or `symlink_metadata` + `File::open` (non-Unix), refreshes metadata from the open handle, requires the source is still a regular file with `len() == manifest size`, and streams exactly the declared size via `copy_exact_n`. Source mutation between passes is handled per spec §15.5.

Hardlinks are archived as independent regular-file contents (no link identity is stored). Setuid/setgid/sticky bits are stripped on write via `PERMISSION_BITS_MASK`.

### 7.7 `archive/decode.rs`

`archive/decode.rs` owns the FCA reader: header + manifest parse with full validation, then content extraction via the hardened cap-std platform backend.

The reader pipeline matches spec §16.1 (steps 1–5 MUST complete before any filesystem output):

1. parse and validate the header;
2. read exactly `manifest_len` bytes;
3. parse the manifest with full per-entry shape + path-grammar validation;
4. validate the manifest tree shape (single root, parents present, duplicates rejected, total bytes match);
5. pre-check the final output name with `symlink_metadata` (so a dangling symlink at the final name counts as occupied);
6. open `output_dir` as a `cap-std` directory handle;
7. create `{root}.incomplete` (file or directory);
8. pre-create all descendant directories under `.incomplete` (parent-before-child);
9. stream file contents in manifest order via `copy_exact_n`;
10. verify archive EOF (no trailing bytes);
11. apply descendant directory modes deepest-first;
12. promote `{root}.incomplete` to `{root}` via no-clobber rename;
13. apply the root entry's stored mode AFTER promotion. For directory roots this is macOS compatibility (a non-search-permitted root mode would block the rename); for regular-file roots this prevents a permissive manifest mode (e.g. `0o644`) from being briefly visible at the staged or final name while the file still holds plaintext.

`unarchive` accepts an [`IncompleteOutputPolicy`] from the caller. The default ([`IncompleteOutputPolicy::DeleteOnError`]) best-effort removes the staged `.incomplete` working tree on any decrypt failure; [`IncompleteOutputPolicy::RetainOnError`] preserves it. Cleanup tracks only roots THIS run created — `mkdir_strict` / `create_file_at` push `created_incomplete_roots` only when they actually created the working name, so a pre-existing `.incomplete` from a prior failed run rejects with `Previous .incomplete exists` and is preserved across the retry. Cleanup helper `cleanup_incomplete_path` routes by `symlink_metadata` (symlinks removed as symlinks; directories via `remove_dir_all`, which since Rust 1.71 is TOCTOU-hardened on Unix and does not follow descendant symlinks) and swallows all I/O errors so the original `CryptoError` is the value the caller sees.

### 7.8 `archive/platform.rs`

`archive/platform.rs` owns the unified capability-based extraction backend used on every supported OS (Linux / macOS / Windows). Built on `cap-std` plus `cap-fs-ext`.

Invariant:

> Any symlink — or, on Windows, any NTFS reparse point including junctions and mount points — in an extraction path is an extraction error.

It contains:

- `open_anchor` — bootstraps the trusted `cap_std::fs::Dir` for the user-supplied `output_dir`; the caller's chosen path IS the trust boundary so no no-follow check applies to it;
- `ensure_dir`, `mkdir_strict`, `walk_to_parent`, `open_dir_at_rel` — every directory open routed through `cap_fs_ext::DirExt::open_dir_nofollow`;
- `finalize_dir_open` — Windows-only `FILE_ATTRIBUTE_REPARSE_POINT` post-check called after every successful directory open, so junctions / mount points fail closed (cap-fs-ext alone refuses entries where `is_symlink()` is true, but `is_symlink()` returns `false` for junctions — the bitmask post-check is what catches them);
- `create_file_at` — `OpenOptions::create_new(true)` plus `OpenOptionsFollowExt::follow(FollowSymlinks::No)` for atomic O_EXCL-style create that refuses every leaf symlink, dangling or live;
- `chmod_file_handle`, `chmod_dir_handle` — handle-based permission application; never path-based, so a substituted symlink between extract and chmod cannot redirect the operation. Special bits are stripped via `super::PERMISSION_BITS_MASK`;
- `INITIAL_FILE_CREATE_MODE` — restrictive `0o600` initial mode applied at create time on Unix. Descendant files are chmod'd to the manifest mode after the payload is written (inside the 0o700 staged root). Single-file roots stay at `0o600` throughout staging and across the rename, with the manifest mode applied post-rename via `decode::apply_root_file_mode` so a wider final mode is never briefly visible. Effective on Unix only; ignored on Windows.

Path validation and filesystem writes remain separate so race-hardening logic is auditable.

The backend uses `cap-std` and `cap-fs-ext` from the Bytecode Alliance — the same crates that back wasmtime's WASI sandbox. ferrocrypt itself contains no `unsafe`; all direct syscall surface lives in those audited dependencies. cap-std layers on `rustix` (Linux/macOS) and `windows-sys` (Windows) internally.

---

## 8. `fs/`

`fs/` owns local filesystem mechanics unrelated to archive-payload semantics.

Archive-specific path rules live in `archive/path.rs`; general output-path and staging mechanics live in `fs/`.

### 8.1 `fs/atomic.rs`

`fs/atomic.rs` owns atomic output behavior.

It contains:

- temporary output name generation;
- no-clobber finalization;
- same-directory staging;
- cleanup on encryption failure;
- `.incomplete` behavior on decryption failure.

Atomic output is a library guarantee. It is not a CLI-only concern.

### 8.2 `fs/paths.rs`

`fs/paths.rs` owns general path helpers.

It contains:

- encrypted filename derivation;
- base-name extraction;
- user-path error mapping;
- occupied-path / dangling-symlink rejection (`path_occupied`, `reject_occupied`) — `lstat`-based "is anything here?" preflight used by encrypt and keygen output prechecks so a stale symlink rejects in milliseconds instead of after Argon2id;
- bounded file reads (`read_file_capped`) — `Read::take(cap + 1)` then over-cap rejection, used by `key/public.rs::read_public_key`, `recipient/native/x25519.rs::open_x25519_private_key`, and `api::validate_private_key_file` to refuse multi-gigabyte attacker-controlled key files before any allocation;
- general path normalization required outside archive semantics.

It does not enforce FCA archive path rules. Archive path rules belong only to `archive/path.rs`.

---

## 9. Public API shape

The public API is value-oriented. Callers construct typed encryptors, decryptors, keys, and identities rather than selecting independent mode-specific orchestration functions.

### 9.1 Encryption

```rust
pub struct Encryptor { /* opaque */ }

impl Encryptor {
    pub fn with_passphrase(passphrase: SecretString) -> Self;

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
- `with_public_keys` supports the multi-recipient file format directly.
- Recipient mixing is checked during construction.
- Empty recipient lists reject immediately.
- The API remains path-based because FerroCrypt security guarantees depend on archive preflight, streaming encryption, staging, and atomic finalization.
- **Writer caps mirror reader defaults.** A default-configured `Encryptor` produces `.fcr` files a default-configured `Decryptor` can read. `write` enforces this via the same helpers the reader uses (single source of truth per rule — see "Centralized cap enforcement" below):
  - `api::preflight_header_write_limits` checks all three axes of `HeaderReadLimits` against the exact header the writer will emit: `recipient_count`, per-entry `body_len` (canonical native value from `NativeRecipientType::body_len()`), and the computed `header_len`. Tightening any axis below the writer's natural output rejects with the corresponding typed `*CapExceeded` variant.
  - For the passphrase path, `KdfParams::validate_for_write` runs the same `validate_structural` the reader runs (`lanes`, `time_cost`, `mem_cost` against v1 absolute bounds + the Argon2 `mem_cost ≥ ARGON2_MIN_MEM_COST_PER_LANE × lanes` floor) and then `enforce_limit` against `KdfLimit`. Above-structural params reject with `InvalidKdfParams::*`; above-resource-cap reject with `KdfResourceCapExceeded`. The same rule chain applies to `KeyPairGenerator::write` for the passphrase that seals `private.key`.
  - The X25519 path never runs Argon2id during encrypt, so `kdf_limit` has no effect on `with_public_key` / `with_public_keys` flows.
  - To go above any default, the caller raises both sides explicitly: `Encryptor::header_read_limits` / `Encryptor::kdf_limit` / `KeyPairGenerator::kdf_limit` on the writer; `Decryptor::open_with_limits` plus `*::header_read_limits` / `*::kdf_limit` on the reader.
  - All checks fire after `validate_passphrase` and before any filesystem syscall or Argon2id work, so misconfiguration surfaces fast.

### Centralized cap enforcement

Every per-cap `if value > cap { return Err(...) }` lives in **one** method on the type that owns the cap. Both reader and writer call the same helper, so a cap value, its diagnostic, and its check semantics cannot drift.

| Cap / rule | Source of truth (constant) | Enforcement helper | Reader call site | Writer call site |
|---|---|---|---|---|
| `prefix.header_len` (resource cap) | `HeaderReadLimits::HEADER_LEN_DEFAULT` (= `format::HEADER_LEN_LOCAL_CAP_DEFAULT`) | `HeaderReadLimits::enforce_header_len` | `container::read_encrypted_header` | `api::preflight_header_write_limits` (called from `Encryptor::write`) — checks the exact `header_len` the writer will emit against the cap |
| `header_fixed.recipient_count` (resource cap) | `HeaderReadLimits::RECIPIENT_COUNT_DEFAULT` | `HeaderReadLimits::enforce_recipient_count` | `container::read_encrypted_header` | `api::preflight_header_write_limits` |
| Per-entry `body_len` (resource cap) | `HeaderReadLimits::RECIPIENT_BODY_LEN_DEFAULT` | `HeaderReadLimits::enforce_recipient_body_len` (writer); inline check in `RecipientEntry::parse_one` (reader; `recipient/entry.rs` sits below `container.rs` in the dep graph, so the helper can't be called from there without a cycle — same comparison, same `RecipientBodyCapExceeded` variant) | `RecipientEntry::parse_one` | `api::preflight_header_write_limits` (called against canonical `NativeRecipientType::body_len()`) |
| `header_fixed` structural rules (`header_flags == 0`, `1 <= recipient_count <= MAX`, `ext_len <= MAX`, `entries_len + ext_len + HEADER_FIXED_SIZE == header_len`) | `format::check_*` private helpers + `format::EXT_LEN_MAX` / `RECIPIENT_COUNT_MAX` | `HeaderFixed::validate_structural` | `HeaderFixed::parse` (after wire-byte parse) | `container::build_encrypted_header` (after constructing the `HeaderFixed` value from typed inputs) |
| Argon2id structural rules (`lanes ∈ [1, MAX_LANES]`, `time_cost ∈ [1, MAX_TIME_COST]`, `mem_cost ∈ [ARGON2_MIN_MEM_COST_PER_LANE × lanes, MAX_MEM_COST]`) | `KdfParams::MAX_*` constants + `crypto::kdf::ARGON2_MIN_MEM_COST_PER_LANE` | `KdfParams::validate_structural` | `KdfParams::from_bytes_structural` (after wire-byte parse) | `KdfParams::validate_for_write` (called from `Encryptor::write` and `KeyPairGenerator::write`) |
| Argon2id `mem_cost` (resource cap, on top of structural) | `KdfParams::DEFAULT_MEM_COST` / `KdfLimit::default()` | `KdfParams::enforce_limit` | `KdfParams::from_bytes` (calls `enforce_limit` after structural parse) | `KdfParams::validate_for_write` (calls `enforce_limit` after `validate_structural`) |
| Archive `max_entry_count`, `max_total_plaintext_bytes`, `max_path_depth` | `archive::limits::ArchiveLimits` defaults | `archive::limits::enforce_per_entry_caps`, `archive::limits::enforce_total_bytes_cap` | `archive::decode::extract_entries` (unified) | `archive::encode::archive` (recursive walker) |

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
        passphrase: SecretString,
        output_dir: impl AsRef<Path>,
        on_event: impl Fn(&ProgressEvent),
    ) -> Result<DecryptOutcome, CryptoError>;
}

pub struct PrivateKeyDecryptor { /* opaque */ }

impl PrivateKeyDecryptor {
    pub fn kdf_limit(self, limit: KdfLimit) -> Self;

    pub fn archive_limits(self, limits: ArchiveLimits) -> Self;

    pub fn header_read_limits(self, limits: HeaderReadLimits) -> Self;

    pub fn incomplete_output_policy(self, policy: IncompleteOutputPolicy) -> Self;

    pub fn decrypt(
        self,
        private_key: PrivateKey,
        private_key_passphrase: SecretString,
        output_dir: impl AsRef<Path>,
        on_event: impl Fn(&ProgressEvent),
    ) -> Result<DecryptOutcome, CryptoError>;
}
```

`archive_limits` on the decrypt side mirrors `Encryptor::archive_limits` on the encrypt side. Both default to [`ArchiveLimits::default`] when unset; symmetry between encrypt-side preflight and decrypt-side extraction is the caller's responsibility — a `.fcr` produced under elevated encrypt caps can only be round-tripped by passing the same elevated value to the corresponding decryptor.

`incomplete_output_policy` defaults to [`IncompleteOutputPolicy::DeleteOnError`]: a failed decrypt removes the staged `.incomplete` plaintext so no authenticated-but-incomplete output lingers under `output_dir`. [`IncompleteOutputPolicy::RetainOnError`] preserves the staged tree for backup-recovery / forensic flows; callers that opt in MUST treat retained partials as a potentially attacker-chosen prefix (FerroCrypt's STREAM-BE32 payload only detects truncation when the final chunk arrives, so an attacker can choose any chunk-aligned prefix that the recovered plaintext represents).

Preferred public concepts are `Passphrase` and `Recipient`. Internals are not organized around `Symmetric` and `Hybrid` because those names describe historical modes rather than the recipient-entry model.

### 9.3 Keys and identities

`PublicKey` supports:

- `from_key_file`;
- `from_recipient_string`;
- `from_bytes` where supported;
- `fingerprint`;
- canonical `to_recipient_string()` output.

`PrivateKey` supports:

- `from_key_file`;
- validated private-key loading;
- typed dispatch to its native recipient scheme after passphrase unlock.

### 9.4 Key generation

```rust
pub fn generate_key_pair(
    output_dir: impl AsRef<Path>,
    passphrase: SecretString,
    on_event: impl Fn(&ProgressEvent),
) -> Result<KeyGenOutcome, CryptoError>;

pub struct KeyPairGenerator { /* opaque */ }

impl KeyPairGenerator {
    pub fn with_passphrase(passphrase: SecretString) -> Self;

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
- Key-file staging lives in `key/files.rs` and `fs/`.

`KeyPairGenerator` mirrors `Encryptor`'s reader-aligned cap rule for the passphrase that seals `private.key`: `kdf_params.mem_cost <= kdf_limit.max_mem_cost_kib` (default 1 GiB) is enforced at `write` time before Argon2id runs. Above-default `mem_cost` rejects with `CryptoError::KdfResourceCapExceeded`; the unlocking [`PrivateKeyDecryptor`] must be configured via [`PrivateKeyDecryptor::kdf_limit`] with a matching [`KdfLimit`].

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
| Atomic output | `fs/atomic.rs` |
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
  ├── container.rs → format.rs
  ├── recipient/* → crypto/*
  ├── key/* → crypto/* + recipient/name.rs
  ├── archive/*
  └── fs/*
```

Dependency rules:

- `format.rs` depends on no FerroCrypt-specific modules except errors.
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
5. Reject malformed flags, unknown critical recipients, and illegal mixing.
6. Apply local resource caps.
7. Attempt supported recipient entries.
8. Verify header MAC with each candidate `FileKey`.
9. Validate authenticated TLV bytes only after successful header MAC verification.
10. Derive the payload key.
11. Decrypt the payload stream.
12. Decode the archive with path and resource checks before filesystem writes.
13. Promote staged output only after successful authenticated decryption and extraction.

No refactor may move TLV interpretation, archive writes, or payload plaintext release before the relevant authentication step.

---

## 13. Public error wording

Public errors must be precise without claiming certainty that cryptographic verification cannot provide.

Use wording such as:

- “wrong passphrase or tampered recipient entry”;
- “private key passphrase is wrong or the private key file was tampered with”;
- “no matching credential or recipient entry was modified”;
- “header authenticated by a recovered file key failed verification”.

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
