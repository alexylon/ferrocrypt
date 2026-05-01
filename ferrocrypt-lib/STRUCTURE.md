# ferrocrypt-lib Code Structure

**Status:** Canonical structural reference  
**Scope:** `ferrocrypt-lib/src/` public API, module layout, security boundaries, and ownership of format, cryptographic, archive, key, and filesystem responsibilities.

---

## 1. Architecture overview

FerroCrypt is organized around a single file-encryption protocol pipeline. The v1 file model is:

```text
one random file_key
one encrypted payload
one or more typed recipient entries that wrap the same file_key
```

The library is therefore recipient-oriented rather than mode-oriented. Passphrase encryption and public-recipient encryption are different recipient schemes over the same protocol pipeline, not separate encrypted-file formats or independent orchestration paths.

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
   `protocol.rs` owns the high-level operation flow for both passphrase and public-recipient encryption.

2. **Recipient schemes are first-class components.**
   Passphrase Argon2id and X25519 public-recipient support are implemented as native recipient schemes under `recipient/native/`.

3. **The encrypted file container is separate from cryptographic algorithms.**
   `container.rs` owns the `.fcr` container layout around the encrypted header, header MAC, and encrypted payload. It does not implement scheme-specific cryptography.

4. **Cryptographic primitives have explicit owners.**
   Reusable key types, KDF validation, HKDF, HMAC, AEAD, payload streaming, and TLV parsing live under `crypto/`.

5. **Archive handling is isolated from encryption logic.**
   TAR encoding, TAR decoding, archive limits, path validation, and platform-specific extraction hardening live under `archive/`.

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
│   ├── limits.rs
│   ├── path.rs
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
- `detect_encryption_mode`;
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
3. recipient mixing-policy enforcement;
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
    const MIXING_POLICY: MixingPolicy;

    fn wrap_file_key(&self, file_key: &FileKey) -> Result<RecipientBody, CryptoError>;
}

pub(crate) trait IdentityScheme {
    const TYPE_NAME: &'static str;

    fn unwrap_file_key(
        &self,
        body: &RecipientBody,
    ) -> Result<Option<FileKey>, CryptoError>;
}
```

Rules:

- These traits are `pub(crate)`.
- They are an internal deduplication and dispatch boundary, not a stable public plugin API.
- Scheme implementations return or accept recipient body bytes; they do not construct full headers.
- Recipient schemes do not compute or verify header MACs.
- A recipient unwrap is successful only after the candidate `FileKey` verifies the authenticated header MAC.

### 3.4 `format.rs`

`format.rs` owns byte-level wire constants and fixed structures.

It contains:

- magic bytes;
- version byte;
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

- `HeaderReadLimits`;
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

Error variants that carry data carry typed structured data, such as `FormatDefect`, `UnsupportedVersion`, `InvalidKdfParams`, `MixingPolicy`, named integer fields for resource caps, and owned `type_name` strings for per-recipient diagnostics. Consumers can pattern-match on error shapes without substring comparisons.

Diagnostic rules:

- A passphrase recipient open failure means “wrong passphrase or recipient entry tampered,” not definitely “incorrect passphrase”.
- A private-key unlock failure means “wrong passphrase or private key file tampered,” not definitely one or the other.
- An X25519 recipient failure means “no matching identity, wrong key, or recipient entry tampered,” unless a later authenticated step proves a more specific class.
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

`crypto/tlv.rs` owns authenticated TLV parsing and validation.

Rules:

- Encrypted-file TLV namespaces and private-key TLV namespaces are distinct at the caller level.
- TLV validation occurs only after the appropriate authentication succeeds.
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

`recipient/name.rs` owns recipient type-name validation and namespace rules.

It enforces:

- native names contain no `/`;
- external names contain `/`;
- allowed lowercase ASCII grammar;
- reserved native prefixes and suffixes.

All recipient type-name validation goes through this module.

### 5.3 `recipient/policy.rs`

`recipient/policy.rs` owns recipient mixing policy, enforcement, and native-scheme classification.

It contains:

```rust
#[non_exhaustive]
pub enum MixingPolicy {
    Exclusive,
    PublicKeyMixable,
}
```

The `#[non_exhaustive]` attribute lets future variants — same-type-only, unrestricted, custom, plugin-specific policies — be added without a breaking change.

Responsibilities:

- defining mixing-policy types;
- enforcing mixing policy before expensive operations;
- mapping type names to supported native scheme metadata;
- classifying parsed headers as passphrase, public-recipient, unsupported, or mixed;
- preserving unknown non-critical entries as opaque authenticated data.

Rules:

- `argon2id` is exclusive.
- `x25519` is public-key-mixable.
- Unknown non-critical recipients are ignored for scheme-specific opening but still count wherever the format says they count, including exclusive passphrase recipient checks.
- Mixing policy is enforced before expensive KDF or private-key operations.
- Native-scheme classification and mixing-policy enforcement are kept together because every native scheme addition requires coordinated changes to both.

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
- `RecipientScheme` implementation;
- `IdentityScheme` implementation for a passphrase identity;
- tests and vectors for the native passphrase scheme.

It does not:

- build full `.fcr` headers;
- compute header MACs;
- parse TLVs;
- write files;
- own progress events;
- perform archive encoding or extraction.

### 5.5 `recipient/native/x25519.rs`

`recipient/native/x25519.rs` owns the native X25519 public-recipient scheme.

It contains:

- X25519 recipient body layout;
- X25519 recipient body length validation;
- ephemeral key handling;
- all-zero shared-secret rejection;
- wrap-key derivation;
- file-key seal/open logic;
- X25519 key-pair generation logic;
- public-recipient conversion for X25519;
- identity/private-key unlock glue for X25519;
- `RecipientScheme` implementation;
- `IdentityScheme` implementation;
- tests and vectors for the native X25519 scheme.

It does not own the generic `private.key` binary layout. Generic private-key file structure belongs to `key/private.rs`.

---

## 6. `key/`

`key/` owns public and private key file formats and filesystem-level key helpers.

The canonical public value types are:

```rust
pub struct PublicKey  { /* opaque typed public recipient */ }
pub struct PrivateKey { /* opaque typed private identity source */ }
```

These names follow Rust cryptographic convention. In FerroCrypt documentation and method names, `PublicKey` represents a public recipient key and `PrivateKey` represents a private identity source.

Format-oriented aliases are available for callers that prefer recipient/identity terminology:

```rust
pub type RecipientKey = PublicKey;
pub type IdentityKey  = PrivateKey;
```

### 6.1 `key/public.rs`

`key/public.rs` owns the public recipient key text format.

It contains:

- Bech32 recipient string encoding;
- Bech32 recipient string decoding;
- HRP validation;
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

### 6.2 `key/private.rs`

`key/private.rs` owns the private key file format.

It contains:

- `private.key` binary layout;
- cleartext private-key header parsing;
- passphrase-wrapped secret encryption;
- passphrase-wrapped secret decryption;
- private-key TLV validation after authentication;
- generic typed secret material returned to recipient schemes;
- construction and loading support for `PrivateKey`.

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

`archive/` owns the safe TAR subset and directory/file payload semantics.

Archive handling is security-critical. Path validation, resource limits, encoding, decoding, and platform-specific extraction hardening are separated so each review surface is explicit.

### 7.1 `archive/limits.rs`

`archive/limits.rs` owns `ArchiveLimits` and archive resource-cap checks.

It contains limits for:

- maximum entry count;
- maximum total file content;
- maximum archive depth;
- writer-side preflight;
- reader-side enforcement.

Encrypt-side preflight and decrypt-side enforcement must agree. The encrypt side must not produce archives that the decrypt side rejects under default limits.

### 7.2 `archive/path.rs`

`archive/path.rs` owns per-path canonicalization and rejection.

It rejects:

- absolute paths;
- `.` components;
- `..` components;
- repeated separators;
- backslashes;
- non-UTF-8 paths;
- malformed directory trailing-slash usage.

This is one of the most security-sensitive modules. It must be heavily tested, including adversarial path cases.

### 7.3 `archive/encode.rs`

`archive/encode.rs` owns plaintext file and directory traversal and safe TAR writing.

It rejects:

- symlinks;
- device nodes;
- sockets;
- FIFOs;
- unsupported metadata;
- paths not representable in the v1 safe ustar subset.

Archive encoding performs all required preflight checks before producing encrypted output.

### 7.4 `archive/decode.rs`

`archive/decode.rs` owns TAR reading and output reconstruction.

Rules:

- Every archive path is validated through `archive/path.rs` before any filesystem write.
- Duplicate paths are detected on canonical archive paths before extraction.
- Single-top-level-root enforcement rejects an archive with multiple distinct roots before the second root's output is written.
- Trailing zero padding after the TAR end-of-archive marker is verified.
- Resource limits are enforced while reading.
- Extraction preserves the order: validate first, then create or write.
- Decode logic does not bypass platform extraction hardening.

### 7.5 `archive/platform.rs`

`archive/platform.rs` owns platform-specific extraction hardening.

It contains:

- Linux and macOS `openat`/`mkdirat`/`O_NOFOLLOW` behavior where available;
- Windows fallback behavior;
- Unix permission filtering;
- no-follow race resistance.

Path validation and filesystem writes remain separate so race-hardening logic is auditable.

---

## 8. `fs/`

`fs/` owns local filesystem mechanics unrelated to TAR semantics.

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
- general path normalization required outside archive semantics.

It does not enforce TAR archive path rules. Archive path rules belong only to `archive/path.rs`.

---

## 9. Public API shape

The public API is value-oriented. Callers construct typed encryptors, decryptors, keys, and identities rather than selecting independent mode-specific orchestration functions.

### 9.1 Encryption

```rust
pub struct Encryptor { /* opaque */ }

impl Encryptor {
    pub fn with_passphrase(passphrase: SecretString) -> Self;

    pub fn with_recipient(recipient: PublicKey) -> Self;

    pub fn with_recipients(
        recipients: impl IntoIterator<Item = PublicKey>,
    ) -> Result<Self, CryptoError>;

    pub fn save_as(self, path: impl AsRef<Path>) -> Self;

    pub fn archive_limits(self, limits: ArchiveLimits) -> Self;

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
- `with_recipient` is a convenience wrapper around `with_recipients` for one public recipient.
- `with_recipients` supports the multi-recipient file format directly.
- Recipient mixing is checked during construction.
- Empty recipient lists reject immediately.
- The API remains path-based because FerroCrypt security guarantees depend on archive preflight, streaming encryption, staging, and atomic finalization.

### 9.2 Decryption

```rust
#[non_exhaustive]
pub enum Decryptor {
    Passphrase(PassphraseDecryptor),
    Recipient(RecipientDecryptor),
}

impl Decryptor {
    pub fn open(input: impl AsRef<Path>) -> Result<Self, CryptoError>;
}

pub struct PassphraseDecryptor { /* opaque */ }

impl PassphraseDecryptor {
    pub fn kdf_limit(self, limit: KdfLimit) -> Self;

    pub fn archive_limits(self, limits: ArchiveLimits) -> Self;

    pub fn decrypt(
        self,
        passphrase: SecretString,
        output_dir: impl AsRef<Path>,
        on_event: impl Fn(&ProgressEvent),
    ) -> Result<DecryptOutcome, CryptoError>;
}

pub struct RecipientDecryptor { /* opaque */ }

impl RecipientDecryptor {
    pub fn kdf_limit(self, limit: KdfLimit) -> Self;

    pub fn archive_limits(self, limits: ArchiveLimits) -> Self;

    pub fn decrypt(
        self,
        identity: PrivateKey,
        identity_passphrase: SecretString,
        output_dir: impl AsRef<Path>,
        on_event: impl Fn(&ProgressEvent),
    ) -> Result<DecryptOutcome, CryptoError>;
}
```

`archive_limits` on the decrypt side mirrors `Encryptor::archive_limits` on the encrypt side. Both default to [`ArchiveLimits::default`] when unset; symmetry between encrypt-side preflight and decrypt-side extraction is the caller's responsibility — a `.fcr` produced under elevated encrypt caps can only be round-tripped by passing the same elevated value to the corresponding decryptor.

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
```

Ownership split:

- X25519 key generation lives in `recipient/native/x25519.rs`.
- Key serialization lives in `key/`.
- Key-file staging lives in `key/files.rs` and `fs/`.

### 9.5 Mode detection

```rust
pub fn detect_encryption_mode(
    path: impl AsRef<Path>,
) -> Result<Option<EncryptionMode>, CryptoError>;
```

The canonical concepts are:

```rust
#[non_exhaustive]
pub enum EncryptionMode {
    Passphrase,
    Recipient,
}
```

Compatibility names may exist in the public API, but internal structure and documentation use passphrase and recipient terminology.

---

## 10. Single sources of truth

Each security-sensitive concern has exactly one owner.

| Concern | Owner |
|---|---|
| Wire constants and fixed structs | `format.rs` |
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
- “no matching identity or recipient entry was modified”;
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
