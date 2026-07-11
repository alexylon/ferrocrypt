# FerroCrypt Format v1

> **Status:** Canonical v1 specification.
>
> This document is the source of truth for the FerroCrypt v1 specification. The
> encrypted `.fcr` outer file version is `0x01`.
>
> Key-pair compatibility is a separate domain. v1 key pairs use canonical
> `private.key` version `0x01`; matching `public.key` recipient payloads carry
> public-key version `0x01` and map to the same v1 key-pair suite.
>
> This v1 specification uses the v1 key-pair suite and defines an explicit,
> modular, namespaced, independently specified, and independently tested
> recipient/plugin model.

---

## Table of contents

1. [Scope and notation](#1-scope-and-notation)
2. [Cryptographic primitives](#2-cryptographic-primitives)
   - [2.1 Randomness](#21-randomness)
   - [2.2 Argon2id](#22-argon2id)
   - [2.3 HKDF domain separation](#23-hkdf-domain-separation)
   - [2.4 X25519](#24-x25519)
3. [Encrypted file format (`.fcr`)](#3-encrypted-file-format-fcr)
   - [3.1 Prefix](#31-prefix)
   - [3.2 Header](#32-header)
   - [3.3 Recipient entry framing](#33-recipient-entry-framing)
     - [3.3.1 Recipient type-name registry](#331-recipient-type-name-registry)
   - [3.4 Recipient flags](#34-recipient-flags)
   - [3.5 Recipient model](#35-recipient-model)
   - [3.6 Header MAC](#36-header-mac)
   - [3.7 Decryption order](#37-decryption-order)
4. [Native recipient types](#4-native-recipient-types)
   - [4.1 `argon2id`](#41-argon2id)
   - [4.2 `x25519`](#42-x25519)
   - [4.3 Future recipient types](#43-future-recipient-types)
5. [Payload stream](#5-payload-stream)
6. [TLV extension regions](#6-tlv-extension-regions)
7. [Public-key recipients](#7-public-key-recipients)
   - [7.1 `public.key` file form](#71-publickey-file-form)
   - [7.2 Fingerprint](#72-fingerprint)
8. [Private key format (`private.key`)](#8-private-key-format-privatekey)
9. [Archive payload — FerroCrypt Archive (FCA) v1](#9-archive-payload--ferrocrypt-archive-fca-v1)
   - [9.1 Layout](#91-layout)
   - [9.2 FCA fixed header](#92-fca-fixed-header)
   - [9.3 Archive extension region](#93-archive-extension-region)
   - [9.4 Manifest](#94-manifest)
   - [9.5 Per-entry extension regions](#95-per-entry-extension-regions)
   - [9.6 Path grammar](#96-path-grammar)
   - [9.7 Duplicate and collision policy](#97-duplicate-and-collision-policy)
   - [9.8 Tree shape and entry ordering](#98-tree-shape-and-entry-ordering)
   - [9.9 File-content region](#99-file-content-region)
   - [9.10 Writer obligations](#910-writer-obligations)
   - [9.11 Reader and extractor obligations](#911-reader-and-extractor-obligations)
   - [9.12 Resource caps](#912-resource-caps)
   - [9.13 Platform metadata and preservation](#913-platform-metadata-and-preservation)
   - [9.14 FCA extensibility rules](#914-fca-extensibility-rules)
   - [9.15 Design rationale and benefits](#915-design-rationale-and-benefits)
10. [ASCII armor](#10-ascii-armor)
11. [Versioning and compatibility](#11-versioning-and-compatibility)
12. [Diagnostics and conformance](#12-diagnostics-and-conformance)
13. [Quick reference](#13-quick-reference)
    - [13.1 Encrypted-file prefix](#131-encrypted-file-prefix)
    - [13.2 Header fixed section](#132-header-fixed-section)
    - [13.3 Recipient entry](#133-recipient-entry)
    - [13.4 Recipient namespace summary](#134-recipient-namespace-summary)
    - [13.5 Native recipient types](#135-native-recipient-types)
    - [13.6 FCA v1 payload](#136-fca-v1-payload)

---

## 1. Scope and notation

This specification defines:

- encrypted `.fcr` files;
- typed recipient entries;
- native `argon2id` and `x25519` recipients;
- future and plugin recipient rules;
- recipient mixing policies;
- recipient-specific conformance requirements;
- payload stream encryption;
- public recipient keys;
- passphrase-wrapped private keys;
- optional ASCII armor (deferred in v1.0; see §10);
- the required safe FCA archive payload format.

FerroCrypt v1 is built around one central abstraction:

```text
A file has one random file_key.
The payload is encrypted once with that file_key.
Each recipient entry independently wraps that same file_key.
```

Passphrase encryption, X25519 public-key encryption, future KEMs,
post-quantum recipients, hardware-token recipients, and plugin recipients are
all represented by the same top-level mechanism: a typed recipient entry.

The core `.fcr` format is responsible for framing, authentication, and payload
encryption. Recipient types are responsible for their own body layouts,
cryptographic procedures, validation rules, privacy properties, mixing policy,
and test vectors.

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
normative.

Conventions:

- All multi-byte integers are unsigned and big-endian.
- `u8`, `u16`, `u32`, and `u64` mean 1-, 2-, 4-, and 8-byte unsigned integers.
- `||` means byte-string concatenation.
- Byte offsets are zero-based.
- Length fields are byte lengths unless stated otherwise.
- Readers MUST perform all length arithmetic with overflow checking and MUST
  reject inputs whose computed offsets or total lengths overflow the
  implementation's integer types.
- Literal strings used for domain separation are ASCII byte strings.
- `first_N_bytes(x)` means the first `N` bytes of byte string `x`.

---

## 2. Cryptographic primitives

| Role | Primitive |
|---|---|
| Payload encryption | XChaCha20-Poly1305 STREAM-BE32 |
| Native file-key wrapping | XChaCha20-Poly1305 |
| Private-key encryption | XChaCha20-Poly1305 |
| Passphrase KDF | Argon2id |
| Key derivation | HKDF-SHA3-256 |
| Header authentication | HMAC-SHA3-256 |
| Native public-key agreement | X25519 |
| Public recipient text encoding | Bech32, HRP `fcr` |
| Fingerprint | SHA3-256 |

### 2.1 Randomness

Writers MUST use a cryptographically secure random number generator.

Fresh randomness requirements:

| Value | Size | Requirement |
|---|---:|---|
| `file_key` | 32 bytes | Fresh per encrypted file |
| `stream_nonce` | 19 bytes | Fresh per encrypted file |
| native recipient `wrap_nonce` | 24 bytes | Fresh per recipient entry |
| Argon2id salt | 32 bytes | Fresh per passphrase recipient or private-key file |
| X25519 private key material | 32 bytes | Fresh per generated key pair |
| X25519 ephemeral secret | 32 bytes | Fresh per X25519 recipient entry |

Future KEM, post-quantum, hardware-token, and plugin recipient specifications
MUST define their own randomness requirements, including KEM secrets, ephemeral
keys, AEAD nonces, retry behavior, and rejection-sampling behavior where
relevant.

AEAD nonces MUST be unique for a given key. Writers MUST generate each native
recipient `wrap_nonce` independently. Writers MUST NOT reuse a nonce with the
same wrapping key.

### 2.2 Argon2id

Argon2id parameters are stored as:

```text
kdf_params = mem_kib:u32 || time:u32 || lanes:u32
```

Settings:

- Algorithm: Argon2id.
- Argon2 version: `0x13` only. The version is not encoded in `kdf_params`.
  Readers and writers MUST use Argon2id version `0x13` and MUST NOT use version
  `0x10` or any other Argon2 version.
- Password input: exact UTF-8 bytes supplied by the caller.
- No Unicode normalization is performed by the format.
- Salt: the stored 32-byte salt.
- Secret input: empty.
- Associated-data input: empty.
- Output length: 32 bytes.

Structural bounds:

```text
1 <= lanes <= 8
1 <= time  <= 12
8 * lanes <= mem_kib <= 2,097,152
```

Readers MUST reject out-of-range parameters before running Argon2id.

Recommended writer default for desktop-class v1 encryption:

```text
mem_kib = 1,048,576
time    = 4
lanes   = 4
```

Implementations MAY impose lower local resource caps for untrusted input. Local
caps are resource policy, not format incompatibility. Implementations SHOULD make
such caps configurable and report a distinct resource-cap error.

### 2.3 HKDF domain separation

Native v1.x HKDF derivations use HKDF-SHA3-256 and produce 32 bytes unless a
future recipient specification says otherwise.

| Purpose | HKDF `info` |
|---|---|
| Passphrase recipient wrap key | `ferrocrypt/v1/recipient/argon2id/wrap` |
| X25519 recipient wrap key | `ferrocrypt/v1/recipient/x25519/wrap` |
| Private-key wrap key | `ferrocrypt/v1/private-key/wrap` |
| Payload key | `ferrocrypt/v1/payload` |
| Header HMAC key | `ferrocrypt/v1/header` |

Where this document says `salt = empty`, HKDF-Extract uses no application salt,
equivalent to the RFC 5869 default salt of HashLen zero bytes.

### 2.4 X25519

FerroCrypt native X25519 uses RFC 7748 X25519.

`private_key_material` is the original 32-byte X25519 scalar input. Writers
generate it as 32 random bytes. The X25519 operation applies RFC 7748 clamping
when computing public keys or shared secrets.

```text
recipient_public_key_bytes = X25519(private_key_material, basepoint)
shared                     = X25519(private_or_ephemeral_scalar, peer_public_key)
```

X25519 recipient creation and opening MUST reject an all-zero `shared` value.

---

## 3. Encrypted file format (`.fcr`)

A `.fcr` file is:

```text
prefix || header || header_mac || payload
```

A fresh random 32-byte `file_key` is generated for each encrypted file. Every
recipient entry independently wraps that same `file_key`.

### 3.1 Prefix

The prefix is exactly 12 bytes at file offset 0:

| Offset | Size | Field | Value |
|---:|---:|---|---|
| 0 | 4 | `magic` | `46 43 52 00` (`FCR\0`) |
| 4 | 1 | `version` | `0x01` (`.fcr` outer file version) |
| 5 | 1 | `kind` | `0x45` (`E`) |
| 6 | 2 | `prefix_flags` | `u16`; MUST be zero |
| 8 | 4 | `header_len` | `u32`; length of `header`; MUST be `<= 16,777,216` |

The prefix is authenticated as part of the header MAC input (§3.6). The
`version` field is the encrypted `.fcr` file version only; it is independent of
key-pair compatibility (§11).

Readers MUST reject:

- input shorter than 12 bytes;
- magic bytes other than `FCR\0`;
- unsupported version values (anything other than `0x01`);
- `kind != 0x45` for an encrypted `.fcr` file;
- non-zero `prefix_flags`;
- `header_len > 16,777,216`.

Any of these failures surface as a structural rejection before any cryptographic
operation runs.

### 3.2 Header

```text
header = header_fixed || recipient_entries || ext_bytes
```

`header_fixed` is 31 bytes:

| Offset | Size | Field | Meaning |
|---:|---:|---|---|
| 0 | 2 | `header_flags` | `u16`; MUST be zero |
| 2 | 2 | `recipient_count` | `u16`; number of recipient entries |
| 4 | 4 | `recipient_entries_len` | `u32`; total byte length of recipient entries |
| 8 | 4 | `ext_len` | `u32`; byte length of `ext_bytes` |
| 12 | 19 | `stream_nonce` | payload stream base nonce |

Structural limits:

```text
header_len >= 31
header_flags == 0
1 <= recipient_count <= 4096
recipient_entries_len <= header_len - 31
ext_len <= 65,536
31 + recipient_entries_len + ext_len == header_len
```

Readers MUST reject malformed headers before trying any recipient.

Recommended local caps for untrusted input:

```text
header_len <= 1,048,576
recipient_count <= 64
per-recipient body_len <= 8,192
```

Callers MAY raise local caps for specific use cases. Local caps are resource
policy, not format incompatibility.

Recipient type specifications MAY define smaller structural body limits than the
global `body_len` limit. Implementations SHOULD apply recipient-specific local
caps before invoking plugin code or expensive cryptographic operations.

For plugin recipients, implementations SHOULD allow callers to configure local
caps separately from the structural format maximum. Exceeding a local cap SHOULD
produce a distinct resource-cap error rather than a generic malformed-file error.

`recipient_count` MUST equal the number of parsed recipient entries.
Recipient entries MUST consume exactly `recipient_entries_len` bytes.

`stream_nonce` MUST be freshly generated for each encrypted file.

### 3.3 Recipient entry framing

Each recipient entry is independently length-prefixed:

```text
recipient_entry = type_name_len:u16
                  recipient_flags:u16
                  body_len:u32
                  type_name:type_name_len bytes
                  body:body_len bytes
```

Rules:

- `type_name_len` MUST be in `1..=255`.
- `body_len` MUST be `<= 16,777,216`.
- `type_name` MUST be lowercase ASCII.
- `type_name` MUST contain only `a-z`, `0-9`, `.`, `_`, `+`, `-`, and `/`.
- `type_name` MUST NOT start or end with `.`, `_`, `+`, `-`, or `/`.
- `type_name` MUST NOT contain `..` or `//`.
- The entry MUST fit inside `recipient_entries_len`.
- Duplicate recipient entries are allowed unless a recipient specification
  forbids them.
- The generic parser treats `body` as opaque bytes.
- The generic parser MUST NOT inspect the body of an unsupported recipient type.
- For a supported recipient type, the generic parser MUST pass the exact body
  bytes to that recipient implementation after generic framing and flag
  validation.
- Recipient-specific validation MUST be performed by the implementation of that
  recipient type.

Native FerroCrypt type names are short names without `/`, such as `argon2id` and
`x25519`. Names without `/` are reserved for FerroCrypt-defined native recipient
types. Plugin and third-party recipient types MUST use a `/`-containing name.
The portion before the first `/` SHOULD be a DNS name, reversed DNS name, or
other globally controlled namespace owned by the plugin author, such as
`example.com/enigma`, `example.org/hardware-token`, or `com.example/foo`.
Plugin authors MUST NOT use short native-looking names such as `foo`, `kem`,
`pq`, `xwing`, or `hardware` unless those names are assigned by the FerroCrypt
specification.

### 3.3.1 Recipient type-name registry

Recipient type names are divided into two namespaces:

| Namespace | Form | Owner |
|---|---|---|
| Native | no `/` character | FerroCrypt specification |
| Plugin/external | contains at least one `/` character | external implementation or organization |

The native-name prefixes `mlkem`, `pq`, `hpke`, `tag`, `xwing`, and `kem`, as well as
native names ending in `tag`, are reserved for future FerroCrypt-defined
recipient types. Future FerroCrypt specifications MAY define additional native
names or reserved prefixes.

### 3.4 Recipient flags

`recipient_flags` is a `u16` bit field:

| Bit | Meaning |
|---:|---|
| 0 | `critical`; unknown readers MUST reject instead of skipping |
| 1..15 | reserved; MUST be zero |

Readers MUST reject entries with reserved flag bits set.

Unknown recipient entries with `critical = 0` MUST be skipped. Unknown recipient
entries with `critical = 1` MUST cause rejection.

Native `argon2id` and `x25519` entries MUST have `recipient_flags = 0`.

### 3.5 Recipient model

A recipient entry is an independently framed method for recovering the same
per-file `file_key`. The core `.fcr` format defines only the generic recipient
container from §3.3.

The core parser is responsible for validating recipient-entry framing,
`type_name` syntax, `recipient_flags`, structural and local size limits, unknown
critical/non-critical behavior, and inclusion of exact recipient-entry bytes in
the header MAC input. The core parser MUST treat an unknown recipient `body` as
opaque bytes and MUST NOT parse, normalize, rewrite, or partially interpret it.
For known recipient types, the exact body bytes are passed to the recipient
implementation.

Each recipient type specification is responsible for defining the exact
`type_name`, allowed flags, body layout, public/private key material if any, key
wrapping/opening procedures, randomness requirements, validation rules, mixing
policy, privacy considerations, and required test vectors.

Mixing policies are enforced for supported recipient types. Unknown non-critical
recipient entries are ignored for mixing-policy purposes unless a supported
recipient type's own policy defines exclusivity over all recipient entries.

A recipient unwrap MUST NOT be considered successful until the candidate
`file_key` has successfully verified the file header MAC.

### 3.6 Header MAC

After recovering a candidate `file_key`, derive:

```text
header_key = HKDF-SHA3-256(
    salt = empty,
    ikm  = file_key,
    info = "ferrocrypt/v1/header",
    L    = 32,
)
```

The header MAC input is:

```text
prefix || header
```

The MAC is:

```text
header_mac = HMAC-SHA3-256(header_key, prefix || header)
```

`header_mac` is 32 bytes and immediately follows `header`.

The MAC covers the 12-byte prefix, header flags, recipient entries, recipient
order, `stream_nonce`, and `ext_bytes`.

### 3.7 Decryption order

Readers MUST process `.fcr` files in this order:

1. Read the 12-byte prefix.
2. Reject bad magic, unsupported version, wrong kind, non-zero prefix flags, or
   `header_len > 16,777,216`.
3. Read exactly `header_len` bytes of `header` and exactly 32 bytes of
   `header_mac`; reject if either read reaches EOF early.
4. Structurally parse `header_fixed`, reject non-zero `header_flags`, and parse
   recipient entries.
5. Reject any recipient entry with reserved recipient flag bits set.
6. Reject unknown recipient entries with `critical = 1`.
7. Skip unknown recipient entries with `critical = 0`; their bodies remain
   opaque, and their entries remain available for policy checks that
   consider all recipient entries.
8. For supported recipient types, validate recipient-specific flags, body
   lengths, and pre-cryptographic structural requirements.
9. Enforce all recipient mixing rules before running expensive KDFs or private
   key operations.
10. Try supported recipient entries until one produces a candidate `file_key`.
11. Verify `header_mac` with that candidate `file_key`.
12. A recipient unwrap MUST NOT be considered successful unless `header_mac`
    verifies.
13. If HMAC verification fails, continue trying other candidate recipients.
14. After HMAC success, validate `ext_bytes`.
15. Derive the payload key and decrypt the payload stream.

A recipient unwrap is not successful until the header MAC verifies.

Readers SHOULD either attempt unwrap of all supported recipient entries before
returning success or randomize recipient iteration order to reduce timing leakage
about which recipient matched.

---

## 4. Native recipient types

Native recipient bodies use XChaCha20-Poly1305 with empty AAD to wrap the 32-byte
`file_key`:

```text
wrapped_file_key = ciphertext(32 bytes) || tag(16 bytes)
```

The recipient entry and its position are authenticated by the header MAC. Native
recipient entries MUST have `recipient_flags = 0`.

### 4.1 `argon2id`

Type name:

```text
argon2id
```

Status and purpose: `argon2id` is a native FerroCrypt passphrase recipient. It
derives a wrapping key from the caller-supplied passphrase and wraps the file's
random `file_key`.

Body length: exactly 116 bytes.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 32 | `argon2_salt` |
| 32 | 12 | `kdf_params` |
| 44 | 24 | `wrap_nonce` |
| 68 | 48 | `wrapped_file_key` |

Wrapping:

```text
ikm = Argon2id(passphrase, argon2_salt, kdf_params)

wrap_key = HKDF-SHA3-256(
    salt = argon2_salt,
    ikm  = ikm,
    info = "ferrocrypt/v1/recipient/argon2id/wrap",
    L    = 32,
)

wrapped_file_key = XChaCha20-Poly1305-Seal(
    key       = wrap_key,
    nonce     = wrap_nonce,
    plaintext = file_key,
    AAD       = empty,
)
```

Opening: readers derive the same `wrap_key` from the supplied passphrase, stored
salt, and stored KDF parameters, then attempt to open `wrapped_file_key`. The
resulting candidate `file_key` is not accepted until the header MAC verifies.

Mixing policy: `argon2id` is exclusive. A file containing an `argon2id` recipient
MUST contain exactly one recipient entry. Unknown non-critical entries also count
toward this total and MUST cause rejection. Writers MUST NOT mix `argon2id` with
any other recipient. Readers MUST reject such mixes before running Argon2id.

Reason: passphrase encryption normally implies to users that the passphrase is
the only way to decrypt the file. Silently mixing a passphrase recipient with
public-key recipients would violate that expectation.

Privacy: an `argon2id` recipient does not identify a public-key recipient. It
exposes the KDF parameters and salt, which are not secret.

Readers MUST reject an `argon2id` entry if:

- `recipient_flags != 0`;
- body length is not exactly 116 bytes;
- KDF parameters are outside the structural bounds in §2.2;
- local KDF resource caps are exceeded and the caller has not opted in;
- the file violates the `argon2id` mixing policy.

The `argon2id` recipient test suite MUST include valid, wrong-passphrase,
malformed-KDF, resource-cap, tamper covering each authenticated field
independently, illegal-mixing, invalid-flag, invalid-length, and
header-MAC-failure vectors.

### 4.2 `x25519`

Type name:

```text
x25519
```

Status and purpose: `x25519` is a native FerroCrypt public-key recipient. It
wraps the file key using an ephemeral X25519 agreement with the recipient's
static X25519 public key.

Body length: exactly 104 bytes.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 32 | `ephemeral_public_key_bytes` |
| 32 | 24 | `wrap_nonce` |
| 56 | 48 | `wrapped_file_key` |

Wrapping:

```text
ephemeral_secret = random 32-byte X25519 scalar input
ephemeral_public_key_bytes = X25519(ephemeral_secret, basepoint)
shared           = X25519(ephemeral_secret, recipient_public_key_bytes)
```

If `shared` is all zero bytes, writers MUST reject and retry or fail.

```text
wrap_key = HKDF-SHA3-256(
    salt = ephemeral_public_key_bytes || recipient_public_key_bytes,
    ikm  = shared,
    info = "ferrocrypt/v1/recipient/x25519/wrap",
    L    = 32,
)

wrapped_file_key = XChaCha20-Poly1305-Seal(
    key       = wrap_key,
    nonce     = wrap_nonce,
    plaintext = file_key,
    AAD       = empty,
)
```

Opening:

```text
shared = X25519(private_key_bytes, ephemeral_public_key_bytes)
```

Readers MUST reject this recipient if `shared` is all zero bytes. Readers derive
the same `wrap_key` using the public key corresponding to `private_key_bytes`:

```text
recipient_public_key_bytes = X25519(private_key_bytes, basepoint)

wrap_key = HKDF-SHA3-256(
    salt = ephemeral_public_key_bytes || recipient_public_key_bytes,
    ikm  = shared,
    info = "ferrocrypt/v1/recipient/x25519/wrap",
    L    = 32,
)
```

Readers then attempt to open `wrapped_file_key`. The resulting candidate
`file_key` is not accepted until the header MAC verifies.

Mixing policy: `x25519` is public-key-mixable. It MAY appear with other
public-key or KEM recipient types whose specifications also permit mixing. It
MUST NOT appear with an exclusive recipient type such as `argon2id`.

Privacy: the native `x25519` recipient body contains an ephemeral public key but
no stable recipient identifier. A file with only anonymous `x25519` recipients
does not explicitly identify which recipient public keys can decrypt it.

Readers MUST reject an `x25519` entry if:

- `recipient_flags != 0`;
- body length is not exactly 104 bytes;
- the X25519 shared secret is all zero;
- the file violates the `x25519` mixing policy.

The `x25519` recipient test suite MUST include valid single-recipient,
valid multi-recipient, unknown-non-critical, wrong-key, all-zero-shared-secret,
tamper covering each authenticated field independently, invalid-flag,
invalid-length, illegal-mixing, and header-MAC-failure vectors.

### 4.3 Future recipient types

**Future types.** Future v1.x recipient types can be added without changing the
top-level file format if they obey §3.3 and §3.4.

**Recipient specifications.** Every native or plugin recipient type MUST have a
complete recipient specification defining: exact `type_name`, namespace, status,
purpose, allowed flags, body layout and length limits, public/private key
material formats if any, file-key wrapping/opening procedures, cryptographic
parameters, randomness requirements, malformed-input rejection rules, failure
behavior, mixing policy, privacy/security considerations, and positive,
wrong-key, malformed, and tamper vectors.

**Parser compatibility.** A recipient type specification MUST NOT require changes
to the generic `.fcr` recipient-entry parser unless it is defining a new
incompatible file version.

**Mixing policy.** Every recipient type MUST define a mixing policy: exclusive,
same-type-only, public-key-mixable, unrestricted, or custom. If any recipient
entry in a file has an exclusive or incompatible mixing policy, readers MUST
reject the file before running expensive KDFs or private-key operations.
Passphrase-like recipient types SHOULD normally be exclusive.

**Plugin recipients.** Plugin recipients MUST use fully qualified names
containing `/`. The generic parser MUST pass exact recipient body bytes to plugin
implementations without normalization or rewriting. Plugin implementations MUST
NOT assume they are the only recipient in a file unless their recipient
specification defines an exclusive or custom mixing rule and the host enforces
it.

**Host invocation.** Hosts SHOULD invoke plugin recipients only after generic
header framing, recipient type-name syntax, recipient flags, local resource caps,
unknown critical recipients, and recipient mixing rules have been checked.

**Privacy.** A recipient specification that stores recipient identifiers, key
IDs, tags, truncated hashes, hints, routing information, or hardware-token
identifiers MUST state whether files using the recipient type are anonymous,
recipient-linkable, linkable across files, or distinguishable by third parties.
Recipient types SHOULD avoid exposing stable recipient identifiers unless doing
so is required for usability, hardware-token routing, or performance.

**Reserved names.** The registry reservations in §3.3.1 apply to all future and
plugin recipient types.

**Specification structure.** A recipient specification SHOULD use this structure:
status, type name, purpose, public/private key format if applicable, body layout,
encryption procedure, decryption procedure, validation rules, mixing policy,
privacy considerations, security considerations, and test vectors.

---

## 5. Payload stream

After header MAC verification, derive:

```text
payload_key = HKDF-SHA3-256(
    salt = stream_nonce,
    ikm  = file_key,
    info = "ferrocrypt/v1/payload",
    L    = 32,
)
```

Payload encryption uses XChaCha20-Poly1305 STREAM-BE32.

| Parameter | Value |
|---|---:|
| Plaintext chunk size | 65,536 bytes |
| Tag size | 16 bytes |
| Stored base nonce | 19-byte `stream_nonce` |
| Counter size | 32-bit unsigned integer |

Each encrypted chunk is stored as:

```text
ciphertext_chunk = AEAD_ciphertext || tag
```

For a non-final chunk, the stored ciphertext chunk is exactly 65,536 + 16 bytes.
For a final non-empty chunk, the stored ciphertext chunk is between 17 and 65,552
bytes inclusive. Empty plaintext is encoded as one final chunk containing only
the 16-byte AEAD tag.

Per-chunk nonce:

```text
chunk_nonce = stream_nonce || counter_u32_be || last_flag_u8
```

Rules:

- `counter` starts at `0` and increments by `1` per chunk.
- `last_flag = 0x00` for non-final chunks.
- `last_flag = 0x01` for the final chunk.
- Non-final plaintext chunks MUST be exactly 65,536 bytes.
- The final plaintext chunk MAY be shorter than 65,536 bytes.
- The final plaintext chunk MUST NOT be empty unless the entire plaintext is
  empty.
- Empty plaintext is encoded as one empty final chunk.
- Non-empty plaintext whose length is a multiple of 65,536 bytes ends with a
  full-size final chunk using `last_flag = 0x01`.
- Writers MUST NOT append an extra empty final chunk after non-empty plaintext.
- Writers MUST NOT emit more than `2^32` chunks.
- The final chunk MUST use a counter value in `0..=2^32-1`. If counter
  `2^32 - 1` is used, that chunk MUST be final.
- Readers MUST reject streams that exceed `2^32` chunks, fail authentication,
  reach EOF before a valid final chunk, or contain bytes after the final chunk.

The payload is chunk-seekable. When seeking relative to the end, readers MUST
locate and authenticate the final chunk before returning earlier plaintext.

---

## 6. TLV extension regions

FerroCrypt uses one TLV grammar for encrypted-file header `ext_bytes`,
private-key `ext_bytes`, FCA archive extension regions, and FCA per-entry
extension regions. Each context has its own tag namespace and its own containing
length field, but the structural TLV grammar and canonicality rules are shared.

For encrypted `.fcr` file headers, `ext_bytes` is authenticated by the header
MAC. For `private.key`, `ext_bytes` is authenticated by the private-key AEAD AAD
and tag. For FCA, extension bytes are authenticated by the outer `.fcr` payload
stream.

```text
ext_bytes = *tlv
tlv       = tag:u16 || len:u32 || value:len bytes
```

The encrypted-file header `ext_len` MUST be `<= 65,536`. Other TLV-containing
regions use the caps defined by their containing format section.

Tag classes:

| Tag range | Class |
|---:|---|
| `0x0001..=0x7FFF` | Ignorable |
| `0x8001..=0xFFFF` | Critical |
| `0x0000` | Reserved; reject |
| `0x8000` | Reserved; reject |

Rules after the relevant containing authentication step:

1. Tags MUST be strictly ascending.
2. Duplicate tags MUST be rejected.
3. TLV entries MUST NOT run past their containing TLV region.
4. Truncated TLV headers MUST be rejected.
5. Zero-length values are allowed.
6. Unknown ignorable tags MUST be skipped.
7. Unknown critical tags MUST cause rejection.
8. Reserved tags MUST be rejected.

The encrypted-file header namespace defines no v1 global TLV tags. v1 writers
MUST emit `ext_len = 0` unless implementing a tag defined by a later v1.x
revision.

---

## 7. Public-key recipients

A public recipient is a lowercase Bech32 string with HRP `fcr`.

Public-recipient payload versions identify key-pair compatibility suites, not
`.fcr` file versions. Decoders MUST read the payload version at offset 0, map it
to the shared key-pair suite for `public.key` and `private.key`, and reject
unsupported suites before a public recipient is used for encryption. A release
MUST NOT accept a public key for encryption unless the same key-pair suite
remains supported for private-key decryption.

Public-recipient payloads are always versioned:

```text
recipient_payload = public_key_version:u8
                    type_name_len:u16
                    key_material_len:u32
                    type_name:type_name_len bytes
                    key_material:key_material_len bytes
                    checksum:16 bytes
```

`public_key_version` MUST be in `0x01..=0xFF`. `0x00` is reserved and MUST be
rejected. v1 public-key recipient payloads use `public_key_version = 0x01` and map to
key-pair suite v1.

All public-key recipient payloads use the same checksum scheme, with the version byte
mixed into the hash input:

```text
checksum = first_16_bytes(SHA3-256(
    "ferrocrypt/v1/public-key/checksum"
 || public_key_version
 || type_name
 || 0x00
 || key_material
))
```

The `v1` in the checksum domain string names the checksum scheme defined by this
specification, not a specific key-pair suite. A future v2, v3, … key-pair suite
uses the same domain string with its own `public_key_version` byte mixed in. Only
a checksum scheme change would require a new domain string.

Rules:

- Current v1 writers MUST emit `public_key_version = 0x01`.
- Readers MUST reject any other public-key version byte and MUST map
  `public_key_version = 0x01` to key-pair suite v1 before deciding support.
- `type_name` follows §3.3 and §3.3.1.
- `key_material_len` MUST be `<= 12,215` unless a recipient spec defines a
  smaller bound. This worst-case cap is derived so that a maximum-length
  255-byte `type_name`, the 7-byte typed-payload header, and the 16-byte
  internal checksum still fit alongside `key_material` under the
  20,000-character recipient-string ceiling, letting implementations
  enforce the cap structurally without a separate post-encode
  length check.
- The full Bech32 string MUST be `<= 20,000` ASCII characters.
- The Bech32 checksum algorithm is the original BIP 173 Bech32 algorithm, not
  Bech32m. FerroCrypt does not use BIP 173's 90-character length limit.
- Encoders convert 8-to-5 with padding enabled.
- Decoders convert 5-to-8 with padding disabled and reject non-canonical padding.
- Mixed-case and uppercase encodings MUST be rejected.
- The internal checksum MUST verify.
- Generic public-key recipient decoders MAY decode unsupported type names after the
  key-pair suite itself is supported. A public recipient MUST be supported by the
  implementation or by an available plugin before use as an encryption
  recipient.

Native X25519 public recipients:

```text
type_name        = "x25519"
key_material_len = 32
key_material     = recipient_public_key_bytes
```

Readers MUST reject X25519 public recipients whose key material length is not
exactly 32 bytes.

### 7.1 `public.key` file form

A `public.key` file is UTF-8 text containing exactly:

```text
canonical_lowercase_fcr_bech32_string [optional single LF]
```

Writers MUST write the lowercase recipient string followed by one LF.

Readers MUST reject leading whitespace, trailing whitespace other than one final
LF, CRLF, blank lines, comments, non-canonical Bech32, invalid checksum, invalid
padding, strings longer than 20,000 ASCII characters, unsupported key-pair
suites, and unsupported type names when loading a public recipient for
encryption. Readers MUST treat `public.key` as byte-exact ASCII after UTF-8
validation and MUST NOT apply Unicode normalization, case folding, or whitespace
normalization before Bech32 validation.

### 7.2 Fingerprint

```text
fingerprint = SHA3-256(type_name || 0x00 || key_material)
```

The canonical fingerprint is 64 lowercase hexadecimal characters. A short display
form MAY use the first 16 lowercase hexadecimal characters. For voice or
out-of-band verification, implementations MAY display four-character lowercase
hex groups separated by `:`. The unspaced 64-character form remains canonical.

---

## 8. Private key format (`private.key`)

A `private.key` file stores one passphrase-wrapped private key for one recipient
type. The `version` byte is the private-key wire version. It belongs to the
key-pair compatibility domain, not to encrypted `.fcr` file versioning.

| Offset | Size | Field | Value / meaning |
|---:|---:|---|---|
| 0 | 4 | `magic` | `46 43 52 00` (`FCR\0`) |
| 4 | 1 | `version` | `0x01` (canonical v1 private-key version) |
| 5 | 1 | `kind` | `0x4B` (`K`) |
| 6 | 2 | `key_flags` | `u16`; MUST be zero |
| 8 | 2 | `type_name_len` | `u16`; 1..255 |
| 10 | 4 | `public_len` | `u32`; may be zero |
| 14 | 4 | `ext_len` | `u32`; MUST be `<= 65,536` |
| 18 | 4 | `wrapped_secret_len` | `u32`; 16..16,777,216 |
| 22 | 32 | `argon2_salt` | fresh random |
| 54 | 12 | `kdf_params` | `mem_kib:u32 || time:u32 || lanes:u32` |
| 66 | 24 | `wrap_nonce` | fresh random |
| 90 | `type_name_len` | `type_name` | recipient type name |
| ... | `public_len` | `public_material` | optional public material |
| ... | `ext_len` | `ext_bytes` | TLV extension region |
| ... | `wrapped_secret_len` | `wrapped_secret` | ciphertext plus tag |

Writers MUST emit private-key version `0x01`. Readers MUST reject any other
private-key version byte and MUST map `0x01` to key-pair suite v1 before
deciding support.

Total size:

```text
90 + type_name_len + public_len + ext_len + wrapped_secret_len
```

Structural limits:

```text
1 <= type_name_len <= 255
public_len <= 12,288
ext_len <= 65,536
16 <= wrapped_secret_len <= 16,777,216
```

For native X25519:

```text
type_name          = "x25519"
public_len         = 32
wrapped_secret_len = 48
plaintext secret   = 32-byte X25519 scalar input
```

For native X25519 private keys, after decrypting `secret_material`, readers MUST
compute `X25519(secret_material, basepoint)` and reject the private key unless
the result exactly equals `public_material`.

Let `secret_material` be the recipient-type-specific private key material to be
wrapped.

Wrapping:

```text
ikm = Argon2id(passphrase, argon2_salt, kdf_params)

wrap_key = HKDF-SHA3-256(
    salt = argon2_salt,
    ikm  = ikm,
    info = "ferrocrypt/v1/private-key/wrap",
    L    = 32,
)

wrapped_secret = XChaCha20-Poly1305-Seal(
    key       = wrap_key,
    nonce     = wrap_nonce,
    plaintext = secret_material,
    AAD       = bytes[0 .. start_of_wrapped_secret),
)
```

There is no separate HMAC for `private.key`. The AEAD tag authenticates every
cleartext byte before `wrapped_secret` through AAD, including magic, version,
kind, flags, type name, public material, and `ext_bytes`.

Private-key `ext_bytes` use the TLV grammar and canonicality rules from §6, but
their tag namespace is separate from encrypted-file header TLV tags. Readers MAY
structurally parse private-key `ext_bytes` before authentication, but MUST NOT
act on them or reject unknown critical private-key TLVs until `wrapped_secret`
has been successfully authenticated. Unknown critical private-key TLVs MUST cause
rejection after successful authentication.

Readers MUST validate magic, private-key version and key-pair suite support,
kind, flags, type name, lengths, total file size, KDF parameters, local resource
caps, AEAD authentication, TLV rules, and recipient-type-specific secret/public
material constraints.

Unknown private-key type names MUST be rejected unless supported by a plugin or
local implementation.

---

## 9. Archive payload — FerroCrypt Archive (FCA) v1

The decrypted payload of an encrypted `.fcr` file is a **FerroCrypt Archive
(FCA)** stream. The `.fcr` format defined here carries an FCA archive as its
payload; FCA has its own inner magic and version at the start of the
authenticated payload plaintext.

Readers MUST dispatch on the FCA magic and version after payload decryption has
made those bytes available. Unsupported FCA versions MUST be reported as
unsupported archive versions, not as generic malformed payload bytes.

The `.fcr` outer file version controls the outer cryptographic container. The
FCA version controls the inner archive grammar. `FORMAT.md` describes the `.fcr`
payload as an FCA archive and does not bind the outer `.fcr` container to a
single immutable FCA archive grammar. Therefore, adding or supporting inner FCA
version dispatch for future FCA versions does not by itself require an outer
`.fcr` version bump. An outer `.fcr` version bump is required only for
incompatible changes to the outer cryptographic container, recipient framing,
header authentication, payload stream, or other generic `.fcr` rules.

FCA v1 is a small native archive format with a manifest-first design and
length-delimited extension regions. It represents the archive features
FerroCrypt intentionally preserves by default: regular files, directories, one
top-level output root, relative UTF-8 `/` paths, portable path safety rules,
Unix-style `0o000..0o777` permission bits, declared regular-file sizes, and
regular-file bytes concatenated in manifest order.

FCA v1 provides archive-level and per-entry TLV extension regions so later
specifications can add optional metadata without changing the fixed FCA v1
framing. Unknown ignorable metadata can be skipped. Unknown critical metadata
causes rejection before any filesystem output is created. New filesystem object
kinds remain strict and fail closed.

FCA v1 intentionally does **not** define native preservation for symlinks,
hardlink entries, device files, FIFOs, sockets, sparse-file holes, owners or
groups, timestamps, ACLs, extended attributes, Windows alternate data streams,
Windows reparse points, macOS resource forks, compression,
TAR/PAX/GNU/ZIP/CPIO/libarchive extension records, or generic archive-tool
compatibility. Unsupported object semantics are unrepresentable unless a later
specification defines an explicit entry kind or critical extension for them.

### 9.1 Layout

An FCA v1 payload is exactly:

```text
fca_payload = fca_header || archive_ext || manifest || file_contents
```

There is no padding, no archive-level checksum, and no compression.

- `archive_ext` is exactly `archive_ext_len` bytes.
- `manifest` is exactly `manifest_len` bytes.
- `file_contents` follows immediately after the manifest.

Integrity and authenticity are provided by the outer FerroCrypt encrypted
payload stream (§5). FCA by itself is an inner plaintext archive format, not a
standalone authenticated container.

### 9.2 FCA fixed header

The FCA header is exactly 27 bytes:

```text
fca_header:
  magic              4 bytes   b"FCA\0"
  version            u8        0x01
  flags              u16       MUST be 0
  entry_count        u32       number of manifest entries
  archive_ext_len    u32       byte length of archive_ext
  manifest_len       u32       byte length of manifest
  total_file_bytes   u64       logical sum of all regular-file sizes
```

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | `magic` | MUST equal `46 43 41 00`, ASCII `FCA\0` |
| 4 | 1 | `version` | MUST equal `0x01` |
| 5 | 2 | `flags` | MUST be zero |
| 7 | 4 | `entry_count` | MUST be `1..=limits.max_entry_count` |
| 11 | 4 | `archive_ext_len` | MUST be `<= limits.max_archive_ext_bytes` and fit in `usize` |
| 15 | 4 | `manifest_len` | MUST be `1..=limits.max_manifest_bytes` and fit in `usize` |
| 19 | 8 | `total_file_bytes` | logical bytes; MUST be `<= limits.max_total_plaintext_bytes` |

All multi-byte integers are unsigned big-endian.

Readers MUST reject short headers, bad magic, unsupported FCA header versions,
non-zero header flags, zero `entry_count`, `entry_count` above the configured
cap, `archive_ext_len` above the configured cap, `archive_ext_len` values not
representable as `usize`, `manifest_len == 0`, `manifest_len` above the
configured cap, `manifest_len` values not representable as `usize`, and declared
`total_file_bytes` above the configured cap.

After parsing the manifest, readers MUST recompute the actual entry count and
actual logical regular-file byte count and require exact equality with the
header fields. `total_file_bytes` is the logical sum. Readers MUST compute the
encoded file-content byte count separately from the validated manifest as
`sum(encoded_content_bytes_for_entry(entry))` and use that encoded sum, not
`total_file_bytes`, for file-content stream length validation when any supported
critical extension changes encoded content consumption.

### 9.3 Archive extension region

`archive_ext` is an FCA archive-level TLV extension region. It uses the TLV
grammar and canonicality rules from §6. Its tag namespace is separate from the
`.fcr` header TLV namespace and from the per-entry FCA TLV namespace.

This specification defines no FCA archive-level TLV tags. v1 writers MUST emit
`archive_ext_len = 0` unless implementing a tag defined by a later v1.x
specification.

Readers MUST validate the complete archive-level TLV region before parsing it as
metadata and before creating filesystem output. Unknown ignorable archive TLVs
MUST be skipped. Unknown critical archive TLVs MUST cause rejection before any
filesystem output is created.

### 9.4 Manifest

The manifest is exactly `manifest_len` bytes and contains exactly `entry_count`
entries. Each entry has an 18-byte fixed prefix followed by its path bytes and
per-entry extension bytes:

```text
manifest_entry:
  kind          u8        0x01 = file, 0x02 = directory
  entry_flags   u8        MUST be 0
  mode          u16       Unix rwx bits only, 0o000..0o777
  path_len      u16       byte length of path
  entry_ext_len u32       byte length of entry_ext
  size          u64       logical file size, or 0 for directories
  path          path_len bytes
  entry_ext     entry_ext_len bytes
```

| Relative offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 1 | `kind` | `0x01` file, `0x02` directory |
| 1 | 1 | `entry_flags` | MUST be zero |
| 2 | 2 | `mode` | MUST be `0o000..=0o777` |
| 4 | 2 | `path_len` | MUST be `1..=limits.max_path_bytes` |
| 6 | 4 | `entry_ext_len` | MUST be `<= limits.max_entry_ext_bytes` |
| 10 | 8 | `size` | logical file size; MUST be zero for directories |
| 18 | `path_len` | `path` | UTF-8 FCA path |
| ... | `entry_ext_len` | `entry_ext` | per-entry TLV region |

Directory entries have `size == 0` and consume no bytes in the file-content
region. File entries MAY have `size == 0`. The `entry_flags` field is reserved
for future incompatible archive formats and MUST be zero in FCA v1.

Readers MUST reject truncated fixed entry headers, `path_len == 0`, paths above
`limits.max_path_bytes`, path bytes running past `manifest_len`, `entry_ext_len`
above `limits.max_entry_ext_bytes`, entry extension bytes running past
`manifest_len`, total entry extension bytes above
`limits.max_total_entry_ext_bytes`, trailing bytes after exactly `entry_count`
entries, unknown `kind` values, non-zero `entry_flags`, `mode > 0o777`,
directory entries with non-zero size, checked-add overflow while summing logical
file sizes, recomputed entry-count mismatch, recomputed logical total-file-byte
mismatch, and total logical file bytes above the configured cap.

### 9.5 Per-entry extension regions

Each `entry_ext` is a per-entry TLV extension region. It uses the TLV grammar and
canonicality rules from §6. Its tag namespace is separate from the `.fcr` header
TLV namespace and from the FCA archive-level TLV namespace.

This specification defines no FCA per-entry TLV tags. v1 writers MUST emit
`entry_ext_len = 0` for every entry unless implementing a tag defined by a later
v1.x specification.

Readers MUST validate every per-entry TLV region before creating filesystem
output. Unknown ignorable per-entry TLVs MUST be skipped. Unknown critical
per-entry TLVs MUST cause rejection before any filesystem output is created.
Known TLVs with malformed values MUST be rejected even if their tag number is in
the ignorable range.

A later specification MUST NOT encode a new filesystem object type as an old
object type plus an ignorable per-entry TLV. Object types are represented by
`kind` values and unknown kinds fail closed.

### 9.6 Path grammar

FCA paths are UTF-8 byte strings using `/` as the only separator. They are more
restrictive than generic host paths so a path accepted on one supported platform
has predictable behavior on Linux, macOS, and Windows.

A valid FCA path MUST satisfy all whole-path rules:

- not empty;
- valid UTF-8;
- relative only;
- no leading `/`;
- no trailing `/`;
- no repeated `/`;
- no NUL byte;
- no backslash byte (`\`);
- byte length `<= limits.max_path_bytes`;
- component count `<= limits.max_path_depth`;
- after conversion to a host `Path`, no `RootDir`, `Prefix`, `CurDir`, or
  `ParentDir` component.

Directory paths do not carry a trailing slash. Files and directories share one
canonical path namespace. Any extension value that stores an FCA path, such as a
future hardlink target path, MUST use this same FCA path grammar.

Each path component MUST satisfy all component rules:

- not empty;
- not `.`;
- not `..`;
- at most 244 bytes long;
- does not contain `/`, `\`, or NUL;
- does not contain ASCII control bytes `0x00..=0x1F`;
- does not contain any Windows-reserved character: `<`, `>`, `:`, `"`, `|`,
  `?`, `*`;
- does not end with a space;
- does not end with a dot;
- is not a Windows reserved device name, ASCII-case-insensitive: `CON`, `PRN`,
  `AUX`, `NUL`, `CLOCK$`, `CONIN$`, `CONOUT$`, `COM0` through `COM9`, `COM¹`,
  `COM²`, `COM³`, `LPT0` through `LPT9`, `LPT¹`, `LPT²`, or `LPT³`;
- does not have a Windows reserved device stem before an extension, also
  ASCII-case-insensitive, such as `CON.txt`, `AUX.backup`, `COM1.log`, or
  `LPT9.bin`.

The 244-byte component cap is the 255-byte filename limit shared by ext4, XFS,
APFS, and NTFS, minus the 11-byte `.incomplete` staging suffix that extraction
appends to the root component (§9.11). Without this reserve, a component near
the filesystem limit would be archivable but not extractable.

The reserved-device check is ASCII-case-insensitive only. Implementations MUST
NOT use locale-sensitive case conversion. The reserved stem is the component
bytes before the first `.` with trailing spaces removed, matching Windows
device-name resolution, so a component such as `AUX .txt` resolves to the `AUX`
device and MUST be rejected. The superscript names (`COM¹` through `COM³`,
`LPT¹` through `LPT³`) are matched on their exact UTF-8 bytes; the superscript
digits have no ASCII case.

### 9.7 Duplicate and collision policy

Readers MUST reject exact duplicate paths before creating any output.

Readers MUST also reject simple ASCII-case-insensitive duplicate paths before
creating output. The collision key maps ASCII `A` through `Z` to `a` through `z`
and leaves every other byte unchanged. This prevents common collisions on
case-insensitive filesystems, including default-config NTFS and common macOS
volumes, before extraction reaches `create_new(true)`.

This collision rule intentionally does not implement full Unicode case folding or
filesystem Unicode normalization. Filesystem-specific collisions not caught by
this rule MUST fail closed during extraction through exclusive file creation or
no-clobber final promotion under `.incomplete`.

### 9.8 Tree shape and entry ordering

FCA preserves FerroCrypt's one-output-root behavior:

1. Every path has a first component called the top-level root.
2. All entries MUST have the same top-level root.
3. If the top-level root is a file, the archive MUST contain exactly one entry.
4. If the top-level root is a directory:
   - the root directory entry MUST be present;
   - every non-root entry's parent directory MUST be present as a directory
     entry;
   - no child may appear under a file path;
   - no entry may collide with another entry's path.

The manifest order defines the order of file contents in the content region.
Readers MUST NOT require lexicographic ordering. Readers MUST accept any order
that satisfies the manifest and tree-shape rules.

Writers SHOULD emit deterministic order:

1. root directory first for directory archives;
2. directories before their descendants;
3. entries sorted by canonical path bytes where parent-before-child allows;
4. files and directories sorted together by canonical path bytes once parent
   ordering is satisfied.

A practical deterministic ordering is `sort by (component_count,
path_utf8_bytes)`.

A later hardlink specification that stores hardlink target paths MUST require the
hardlink entry to appear after the regular-file entry it targets in manifest
order. This preserves one-pass manifest validation and avoids topological
sorting.

### 9.9 File-content region

Immediately after the manifest, the file-content region contains the encoded
content bytes of entries in manifest order. For FCA v1 as defined here, regular
files are encoded densely and directories consume zero bytes:

```text
for entry in manifest.entries:
    if entry.kind == file:
        read exactly entry.size bytes
    if entry.kind == directory:
        read zero bytes
```

For any later critical per-entry extension that changes file-content
consumption, the extension specification MUST define
`encoded_content_bytes_for_entry(entry)`. Readers MUST validate the complete
manifest and every such extension before consuming file contents.

The archive ends exactly after the final encoded file-content byte. Readers MUST
walk the validated manifest, compute
`sum(encoded_content_bytes_for_entry(entry))`, and require the file-content
region to contain exactly that many bytes. Readers MUST NOT use
`total_file_bytes` for this encoded stream length check when critical sparse or
other content-encoding extensions are present.

Readers MUST reject file content shorter than declared and any trailing byte
after the final encoded content byte. Readers MUST NOT use unbounded `io::copy`
from the archive reader for file contents; they MUST copy exactly the encoded
content size for each content-bearing entry.

When an underlying `io::Error` carries a FerroCrypt stream marker, such as
payload truncation, authentication failure, or encrypted-stream extra data, the
reader MUST preserve the typed FerroCrypt error instead of converting it into a
generic archive error.

### 9.10 Writer obligations

Writers MUST apply the same path grammar, duplicate policy, tree-shape rules, TLV
canonicality rules, extension caps, and resource caps as readers before emitting
the archive. Encryption MUST fail before the encrypted output is finalized if a
source path or source tree cannot be represented by FCA v1. FerroCrypt MUST NOT
write archives its own default reader will reject.

Writers MUST emit deterministic FCA plaintext for identical input and identical
metadata policy. Manifest entries SHOULD use the deterministic order from §9.8.
TLV tags MUST be serialized in strictly ascending order. Empty extension regions
MUST be serialized as zero lengths.

Writers MUST reject:

- missing input;
- input root symlink;
- dangling input root symlink;
- input root Windows reparse point;
- input root that is neither a regular file nor a directory;
- symlinks inside the tree;
- dangling symlinks inside the tree;
- Windows reparse points, junctions, and mount points inside the tree;
- FIFOs, sockets, devices, and any other non-regular, non-directory entries
  inside the tree.

On Unix, regular-file opens SHOULD use `O_NOFOLLOW`. On Windows, the writer MUST
check `FILE_ATTRIBUTE_REPARSE_POINT` for the input root, every traversed
directory, and every file to be opened. Windows file opens SHOULD use a
reparse-safe open mode such as `FILE_FLAG_OPEN_REPARSE_POINT` followed by
post-open metadata validation.

The writer MUST build a metadata-only manifest before emitting the FCA header.
The metadata pass records entry kind, canonical FCA path string, source path or
equivalent reopen information, mode, logical regular-file size, and entry
extension bytes. The metadata pass MUST apply path validation, duplicate
detection, ASCII-case collision detection, entry-count cap, logical
total-file-byte cap, path-depth cap, path-byte cap, archive-extension cap,
per-entry-extension cap, total-entry-extension cap, manifest-size cap, and
tree-shape validation.

Writers MUST NOT store setuid, setgid, sticky, or platform-specific mode bits.
On Unix, the stored mode is `metadata.permissions().mode() & 0o777`. On non-Unix
platforms, regular-file entries use `0o644` and directory entries use `0o755`.

A source tree may change between the metadata pass and the content-streaming
pass. When streaming each file, the writer MUST either stream from a handle held
open since the metadata pass or reopen the source no-follow/reparse-safe where
supported. In both cases the writer MUST fetch fresh metadata from the open
handle, require that the object is still a regular file, require that its current
length equals the manifest size, and copy exactly the manifest size. Shrink,
type change, pre-copy growth, or inaccessibility MUST fail. If a source file
grows after the fresh metadata check but during the copy, the writer still copies
exactly the declared size, keeping the archive self-consistent.

Filesystem hardlinks MAY be archived as independent regular-file contents.
Hardlink identity MUST NOT be stored unless a later critical hardlink extension
specification is implemented.

### 9.11 Reader and extractor obligations

Readers MUST process FCA archives in this order:

1. read and validate the FCA header;
2. allocate and read exactly `archive_ext_len` bytes;
3. validate the archive-level TLV region;
4. allocate and read exactly `manifest_len` bytes;
5. parse manifest entries, including each `entry_ext` region;
6. validate every per-entry TLV region;
7. validate the complete manifest before creating output:
   - entry count;
   - logical total file bytes;
   - encoded content byte count;
   - path grammar;
   - exact duplicate paths;
   - ASCII-case-insensitive duplicate paths;
   - one top-level root;
   - root file vs root directory shape;
   - parent directories present;
   - no child under file path;
   - resource caps;
   - critical extension support;
8. pre-check the final output name with `symlink_metadata`, so dangling symlinks
   count as occupied;
9. reject pre-existing `.incomplete` output at first create;
10. create the staged root and directories under `{root}.incomplete` with the
    hardened filesystem backend;
11. stream file bytes using exact-size copying;
12. apply descendant file modes by handle where supported (the root entry's
    mode is deferred to step 16);
13. verify archive EOF immediately after the last encoded content byte;
14. apply deferred directory modes deepest-first, except the root directory;
15. promote `{root}.incomplete` to the final output name with no-clobber
    semantics;
16. apply the root entry's mode after promotion. For directory roots this is a
    macOS-compatibility requirement; for regular-file roots this prevents the
    staged file from being briefly visible at a wider mode under either the
    `.incomplete` name or the final name while it still holds plaintext.
    A failure to apply the root mode MUST NOT fail the extraction: the output
    is already complete at its final name, where `DeleteOnError` cleanup
    cannot remove it, and it remains at its restrictive initial mode;
17. return the final output path.

Steps 1 through 8 MUST complete before any filesystem output is created.

Steps 11 and 12 MAY be interleaved per entry: applying a file's mode to its
open handle immediately after its content is written is equivalent to a
separate pass, because every descendant file sits inside the restrictive
staged root until promotion.

Readers SHOULD sync staged file contents to stable storage before step 15.
After promotion the output exists under its final name with no `.incomplete`
marker, so content that was never flushed could otherwise surface truncated
after a crash while appearing complete.

For a directory root, readers SHOULD also sync each staged directory — the
descendant subdirectories and the staged root — before step 15. Flushing a file
does not by itself make the containing directory entry durable; without a
directory sync, a crash can leave the final output present while nested entries
are missing or empty.

On platforms where FerroCrypt has a safe handle-relative no-clobber rename
backend (Linux and macOS), step 15 MUST resolve both the staged source name and
the final target name through the same trusted destination directory handle used
for extraction. A rename or replacement of the ambient `output_dir` path during
the run then cannot redirect the commit.

The step-15 commit SHOULD be a single atomic no-replace rename. On a filesystem
whose driver cannot perform one (the macOS exFAT driver among them), readers
MAY commit in two steps: atomically claim the final name — exclusive-create for
a file root, `mkdir` for a directory root — then rename the staged root over
the claim, because the exclusive claim preserves the no-clobber guarantee (an
entry that predates the commit is never replaced) and the rename lands content
at the final name whole. Both steps MUST resolve through the same trusted
directory handle where the platform backend is handle-relative. A crash between
the two steps leaves an empty claimed entry alongside the staged
`.incomplete` root.

On Windows, the zero-unsafe implementation keeps the documented path-based
final rename: single-file roots use a kernel atomic no-replace move, while
directory roots use the best-effort check-then-rename sequence described in
`SECURITY.md`.

Extraction uses staged output:

```text
output_dir/root.incomplete -> output_dir/root
```

The final output path MUST NOT exist before extraction. If `{root}.incomplete`
already exists, extraction MUST reject rather than reuse or delete it.

On extraction failure, `DeleteOnError` removes only `.incomplete` roots created
by the current run, best-effort. `RetainOnError` leaves staged plaintext for
inspection or recovery. Process termination, power loss, or `SIGKILL` can leave
`.incomplete` output regardless of policy.

A conforming reader MUST keep FerroCrypt's hardened extraction invariants:
output operations rooted in a trusted destination directory handle,
component-by-component traversal, no-follow directory opens, no-follow file
creation where supported, `create_new(true)` / exclusive file creation for file
leaves, Windows `FILE_ATTRIBUTE_REPARSE_POINT` rejection for symlinks,
junctions, mount points, and other reparse points, restrictive initial modes for
new files and directories, handle-based chmod where supported, deferred
directory permissions, `.incomplete` staging, and final no-clobber promotion.

FCA simplifies the archive parser. It MUST NOT simplify filesystem extraction.
The acceptable architecture is:

```text
small FCA parser + hardened capability-based filesystem backend
```

The following is not acceptable:

```text
small FCA parser + output_dir.join(path) + ordinary path-based extraction
```

### 9.12 Resource caps

`ArchiveLimits` covers all FCA resource caps. The default limits are:

| Limit | Default | Meaning |
|---|---:|---|
| `max_entry_count` | `250_000` | maximum manifest entries |
| `max_total_plaintext_bytes` | `64 GiB` | maximum cumulative logical regular-file bytes |
| `max_path_depth` | `64` | maximum component count for any path |
| `max_path_bytes` | `4096` | maximum UTF-8 byte length of any path |
| `max_manifest_bytes` | `64 MiB` | maximum raw manifest byte length, including per-entry extensions |
| `max_archive_ext_bytes` | `65,536` | maximum archive-level TLV bytes |
| `max_entry_ext_bytes` | `65,536` | maximum TLV bytes for one entry |
| `max_total_entry_ext_bytes` | `64 MiB` | maximum sum of all per-entry TLV bytes |
| `max_tlv_value_bytes` | `16 MiB` | maximum value length for one FCA TLV |

`max_path_bytes` MUST be `<= u16::MAX` because the on-disk `path_len` field is a
`u16`.

Readers MUST apply caps before allocation or content copying:

- `max_entry_count` before allocating per-entry state beyond the declared cap;
- `max_archive_ext_bytes` before allocating the archive extension buffer;
- `max_manifest_bytes` before allocating the manifest buffer;
- `max_entry_ext_bytes` before allocating or slicing per-entry extension bytes;
- `max_total_entry_ext_bytes` while parsing the manifest;
- `max_tlv_value_bytes` while validating FCA TLV regions;
- `max_path_bytes` before allocating or converting an entry path;
- `max_path_depth` before filesystem traversal;
- `max_total_plaintext_bytes` before file-content copying.

Writers MUST apply the same caps before emitting the archive. Writers MUST
pre-compute the serialized archive extension length, serialized manifest length,
total entry extension length, logical file byte count, and encoded content byte
count with checked arithmetic before allocating or serializing output, and MUST
reject inputs whose computed lengths exceed configured caps.

`max_manifest_bytes` is not a complete process memory budget. Parsed entries,
path strings, source paths, hash sets, extension views, and sort buffers also
consume memory.

FCA v1 defines no metadata TLV tags, so this section lists no metadata-specific
caps. Future metadata tag specifications (e.g. xattr counts, ACL entries, sparse
extents) MUST define their own resource caps and apply them with the same
before-allocation discipline.

### 9.13 Platform metadata and preservation

FCA v1 preserves file contents, directory structure, and Unix-style
`0o000..0o777` permission bits. It does not preserve ownership, timestamps,
ACLs, extended attributes, hardlink identity, symlink relationships, devices,
FIFOs, sockets, sparse-file metadata, Windows alternate data streams, Windows
reparse points, macOS resource forks, compression, or platform-specific mode
bits unless a later specification defines an explicit extension and the writer
and reader opt into that extension.

The default writer emits no FCA metadata TLVs. A later metadata-preservation
feature MUST be explicit policy, not silent default behavior. Where security and
convenience trade off, the default profile is safe and restrictive. Symlinks,
security-sensitive xattrs, ACL restoration, absolute link targets, and other
filesystem semantics with extraction risk MUST require explicit opt-in and MUST
fail closed when required support is absent.

On Unix, implementations SHOULD restore regular-file modes by handle where
supported and SHOULD apply directory modes after child creation. Directory modes
are applied deepest-first. The root entry's mode is applied after final
promotion: for directory roots this preserves behavior when the root mode lacks
search permission, and for regular-file roots this prevents the staged file
from being briefly visible at a wider mode while it still holds plaintext.

On Windows, Unix permission restoration is a no-op or best-effort compatibility
operation. Windows implementations MUST preserve the path and reparse-point
safety rules in this section even though they do not restore Unix permissions in
the same way as Unix implementations.

### 9.14 FCA extensibility rules

FCA v1 extension regions use the shared TLV grammar from §6. Implementations
SHOULD share one TLV scanner and canonicality validator across `.fcr`,
`private.key`, and FCA extension regions, with separate tag registries per
namespace.

FCA extension bytes are authenticated by the outer `.fcr` payload stream. FCA
MUST NOT define a nested checksum, MAC, or integrity tag for normal FerroCrypt
extraction. A standalone FCA parser may exist for tests, fuzzing, diagnostics,
or transformations, but raw FCA bytes are not a standalone security boundary.

Object kinds are strict. Unknown `kind` values MUST reject. Optional metadata is
extensible through TLVs. A future feature that changes object type, encoded
content consumption, security policy, or required preservation semantics MUST use
a critical tag or a new entry kind and MUST reject on unsupported readers.

Compression is deliberately out of scope for FCA v1. Compression MUST NOT be
introduced through an ignorable TLV. Any future compression profile requires its
own explicit security analysis and compatibility specification.

Manifest-first validation is a hard FCA rule. Readers MUST validate the complete
header, archive-level TLVs, manifest, per-entry TLVs, paths, tree shape,
duplicate policy, resource caps, and critical feature support before creating
filesystem output.

### 9.15 Design rationale and benefits

FCA replaces the previous restricted ustar archive payload with a native format
because FerroCrypt needs a safe encrypted directory payload, not a general
interchange archive. The main benefits are structural.

**Unsupported archive semantics are unrepresentable or fail closed.** TAR was
designed for a different problem and accumulated many extension mechanisms: PAX
records, GNU long names and long links, sparse files, multi-volume records,
dumpdir, volume headers, legacy long-name records, Solaris records, and binary
size encodings. A restricted-TAR reader must continually prove that all of those
cases are rejected or neutralized. FCA has no wire fields for unsupported object
semantics unless a later specification explicitly defines them. Unknown object
kinds and unknown critical metadata reject before output.

**The parser is smaller and more direct.** FCA uses fixed-width big-endian
integers, explicit lengths, checked arithmetic, and one bounded manifest
allocation. It does not require an archive-format crate and does not inherit that
crate's compatibility behavior, such as transparently merging extension records
into later entries.

**Manifest-first validation matches the security model.** The full manifest is
validated before any filesystem output is created. Entry counts, logical and
encoded byte counts, path grammar, duplicate and collision checks, tree shape,
parent presence, extension support, and resource caps are known before
extraction starts. A per-entry TAR stream cannot provide the same preflight
property without buffering or re-parsing the archive.

**File contents still stream.** FCA buffers only the bounded manifest and
extension metadata. Regular file contents, which dominate real payload size, are
copied in fixed-size chunks and exactly by declared encoded length. This keeps
memory use bounded without giving up pre-write manifest validation.

**Path handling is portable and more useful than ustar.** POSIX ustar stores
paths as a `prefix(155) + '/' + name(100)` split; a path is representable only if
a slash falls in the right position. FCA stores each path as one UTF-8 string
with a `u16` length and a configurable cap. Long real-world paths with flat
components can be represented without enabling GNU long-name or PAX extensions.

**The filesystem security boundary is preserved.** FCA changes the archive
syntax, not the extraction trust boundary. The extractor still uses rooted,
component-wise, no-follow filesystem operations, exclusive creation,
`.incomplete` staging, deferred modes, and no-clobber final promotion. A small
parser paired with ordinary path-based extraction would be a security regression.

**Writer and reader invariants are symmetric.** Writers apply the same path,
tree, duplicate, collision, TLV, and resource rules as readers before emitting
bytes. Writers also reject symlinks, dangling symlinks, Windows reparse points,
junctions, mount points, devices, FIFOs, sockets, and source mutation that would
make the manifest false. The intended result is that FerroCrypt never writes an
archive its own default reader rejects.

**Exact sizes and EOF checks close ambiguity.** Every regular-file logical size
is declared in the manifest, the header declares the total logical regular-file
byte count, encoded file content is consumed in manifest order, and the archive
must end immediately after the final encoded byte. Short content, surplus bytes,
arithmetic overflow, logical total-byte mismatches, and encoded-byte mismatches
are all format errors.

**Resource limits are explicit.** Entry count, manifest bytes, archive extension
bytes, per-entry extension bytes, TLV value bytes, path bytes, path depth, and
total plaintext bytes are first-class limits. Readers apply them before
allocation or copying; writers apply them before emitting the archive. This makes
denial-of-service policy visible and testable.

**Fuzzing and conformance are simpler.** Header parsing, TLV validation,
manifest parsing, path validation, tree validation, and exact-size content
copying are separate, deterministic surfaces. Fuzz targets can assert strong
invariants after any successful manifest parse.

**No intended archive-tool interoperability is lost.** FCA is an inner plaintext
payload consumed by FerroCrypt after outer payload authentication. It is not
meant to be passed to `tar -xf` or third-party archive tools. Keeping TAR solely
for tool familiarity would retain the old extension and compatibility audit
surface without providing a supported user-facing interchange format.

**The trade-off is explicit ownership.** FCA is FerroCrypt's format to maintain;
there is no external archive implementation to act as a compatibility oracle.
The compensating design choice is to keep the grammar small, fixed-width,
bounded, extensible through shared TLV rules, and covered by dedicated tests and
fuzzing.

> **Parked snapshot.** The pre-FCA restricted-ustar implementation that motivated
> this migration is preserved under `experiments/archive/` as a reference
> snapshot. It does not ship and is not mounted by `lib.rs`; the active archive
> code lives at `ferrocrypt-lib/src/archive/` and implements FCA v1 only.

---

## 10. ASCII armor

> **Status:** deferred to a future release. The armor encoder/decoder is not
> shipped in this version of `ferrocrypt-lib`. A reference implementation is
> parked under `experiments/armor/` and may be reintroduced in a later version.
> The specification below remains authoritative for that future revival; no
> wire-format change is implied.

ASCII armor is an optional transport encoding around a complete binary `.fcr`
file. It does not change the binary wire format and is not an authenticity
mechanism.

Label:

```text
FERROCRYPT ENCRYPTED FILE
```

Canonical form:

```text
-----BEGIN FERROCRYPT ENCRYPTED FILE-----
<base64 of complete binary .fcr file, 64 characters per line except final line>
-----END FERROCRYPT ENCRYPTED FILE-----
```

Rules:

- Base64 is standard RFC 4648 Base64 with padding.
- Writers MUST wrap Base64 at 64 characters per line except the final line.
- Writers MUST use LF line endings.
- Writers MUST NOT emit PEM headers, attributes, comments, blank lines, leading
  text, trailing text, leading whitespace, trailing whitespace, or whitespace
  inside Base64 lines.
- Readers MAY accept LF or CRLF inside the armor block.
- Readers MUST reject wrong labels, data before BEGIN, data after END except one
  final line ending, blank lines, whitespace inside Base64 lines, non-Base64
  characters, non-canonical Base64 padding, or Base64 body lines that are not 64
  characters long except for the final Base64 line, which MUST contain 1 to 64
  characters.
- After decoding, readers parse the bytes as a binary FerroCrypt v1-compatible
  `.fcr` file.

Conventional armored extensions are `.fcr.asc` and `.fcr.pem`. Detection is by
BEGIN line, not extension.

---

## 11. Versioning and compatibility

FerroCrypt has four independent version domains. Each is bumped on its own
schedule:

- Encrypted `.fcr` outer file version byte = `0x01`.
- FCA inner archive version byte = `0x01`.
- `private.key` header version byte = `0x01` (canonical v1 private-key
  encoding).
- `public.key` recipient payload version byte = `0x01`.

Key-pair compatibility is a separate domain from `.fcr` file compatibility.
`private.key` header versions and `public.key` recipient payload version bytes
are wire-level encodings that MUST map to a shared key-pair suite before support
is decided. v1 `public.key` recipient payloads carry `public_key_version = 0x01`
and map to key-pair suite v1. `public_key_version = 0x00` is reserved and MUST
be rejected.

Readers MUST reject unsupported outer file versions, unsupported inner FCA
archive versions, unsupported private-key versions, and unsupported public-key
payload versions.

The `.fcr` outer file version is independent from key-pair compatibility. A
change to the FCA archive payload does not change key-pair compatibility. A
release MUST NOT accept a public key for encryption unless the same key-pair
suite remains supported for private-key decryption.

Safe v1.x evolution can occur through:

- new recipient type names;
- new public/private key type names;
- authenticated TLV tags in the encrypted-file header namespace;
- authenticated FCA archive-level or per-entry TLV tags;
- plugin recipient type names;
- recipient-specific specifications that do not change the generic `.fcr`
  recipient-entry parser.

Sender authentication is intentionally out of scope. Future v1.x
sender-authentication mechanisms MAY be defined as critical TLV extensions;
such extensions MUST specify a canonical signed transcript and MUST NOT change
the generic `.fcr` container.

A new outer `.fcr` file version is required for incompatible changes to the
prefix layout, header layout, generic recipient-entry framing, header MAC input,
payload stream, encrypted-file TLV canonicality, or other generic `.fcr`
container rules. This includes future recipient mechanisms that require
changing those generic container rules.

A new key-pair suite is required for incompatible changes to public-key
recipient payload interpretation or private-key fixed-header semantics.
Key-pair suite bumps do not by themselves require a new outer `.fcr` file
version. When the next incompatible key-pair change occurs, public and private
wire encodings MUST map to the same new key-pair suite, and support MUST be
decided through one shared suite gate. Implementations MUST either keep both old
public and private encodings supported, or reject both.

A new FCA archive version is required for incompatible changes to FCA fixed
header framing, manifest-entry fixed framing, path grammar, object-kind
semantics, file-content ordering, or any archive behavior that an FCA v1 reader
cannot safely skip or reject through the v1 TLV and `kind` rules. A future FCA
archive version carried inside an otherwise unchanged `.fcr` payload does not
by itself require a new outer `.fcr` file version.

The next incompatible outer `.fcr` file version SHOULD use `version = 0x02` and
SHOULD preserve the initial `FCR\0` magic and version byte long enough for
current readers to report an unsupported version rather than unrecognized data.
The next incompatible `private.key` format SHOULD use private-key version
`0x02`. The next incompatible `public.key` recipient payload SHOULD use
`public_key_version = 0x02`. The three "next" numbers coincide at `0x02` only
because none of the four domains has been bumped before; future bumps in any
domain are independent and will diverge.

---

## 12. Diagnostics and conformance

Implementations SHOULD preserve distinct failure classes for the following
conditions. These classes need not be mutually exclusive; implementations MAY
expose specific subclasses for clearer diagnostics:

- bad magic, unsupported outer file version, unsupported inner FCA archive
  version, unsupported key-pair suite, wrong kind, malformed prefix;
- oversized or malformed header;
- local header, recipient, body, or KDF resource-cap exceeded;
- malformed recipient entry, invalid recipient type name, unknown critical
  recipient, no supported recipient;
- illegal recipient mixing;
- recipient unwrap failure, invalid KDF parameters, wrong passphrase/key;
- plugin recipient failure;
- recipient candidate key failed header MAC verification;
- passphrase recipient mixed with any other recipient;
- all-zero X25519 shared secret;
- header MAC failure;
- malformed TLV, unknown critical TLV;
- archive extension, manifest, entry extension, path, or plaintext resource-cap
  exceeded;
- payload truncation, authentication failure, or trailing data;
- malformed public key or private key;
- unsupported public-key or private-key version;
- private-key unlock failure;
- unsafe or unsupported archive entry;
- critical archive feature disabled by local extraction policy.

Implementations MAY claim conformance at one of these levels:

| Level | Requirement |
|---|---|
| Core parser | Parses `.fcr` structure, recipient entries, TLV, and payload framing, but need not decrypt |
| Native reader | Core parser plus native `argon2id` and `x25519` recipient opening |
| Native writer | Native reader plus canonical native recipient writing |
| Plugin-capable reader | Core parser plus external recipient implementations through the generic recipient-entry API |
| Full implementation | Native reading/writing, plugin API, public/private keys, archive semantics, and all vectors |

An implementation MUST NOT claim support for a recipient type unless it passes
that recipient type's required test vectors.

A conforming FerroCrypt v1 release MUST ship committed test vectors and publish
frozen wire vectors at a stable HTTPS URL. Vectors MUST cover valid and invalid
`.fcr`, `public.key`, `private.key`, payload-stream, recipient, TLV, KDF,
prefix, and archive cases, including FCA archive-level and per-entry extension
regions. Armor vectors are required only for releases that ship the optional
armor transport (deferred in v1.0; see §10).

Each recipient type specification MUST publish positive, wrong-key, malformed,
and tamper vectors, including unknown-non-critical, illegal-mixing, and
header-MAC-failure cases where applicable. Recipient vectors SHOULD be reusable
by independent implementations without requiring access to implementation-
specific code.

Frozen vectors MUST NOT be regenerated in a patch or minor release. If a change
breaks a frozen v1.x fixture, that change is breaking and requires a new format
version.

---

## 13. Quick reference

```text
.fcr = prefix(12) || header(header_len) || header_mac(32) || payload
```

### 13.1 Encrypted-file prefix

| Field | Size | Value |
|---|---:|---|
| `magic` | 4 | `FCR\0` |
| `version` | 1 | `0x01` |
| `kind` | 1 | `0x45` (`E`) |
| `prefix_flags` | 2 | zero |
| `header_len` | 4 | `<= 16,777,216` |

### 13.2 Header fixed section

| Field | Size |
|---|---:|
| `header_flags` | 2 |
| `recipient_count` | 2 |
| `recipient_entries_len` | 4 |
| `ext_len` | 4 |
| `stream_nonce` | 19 |

### 13.3 Recipient entry

| Field | Size |
|---|---:|
| `type_name_len` | 2 |
| `recipient_flags` | 2 |
| `body_len` | 4 |
| `type_name` | `type_name_len` |
| `body` | `body_len` |

### 13.4 Recipient namespace summary

| Name form | Meaning |
|---|---|
| no `/` | FerroCrypt native recipient name |
| contains `/` | plugin/external recipient name |

### 13.5 Native recipient types

| Type | Body length | Mixing policy | Meaning |
|---|---:|---|---|
| `argon2id` | 116 | Exclusive | passphrase recipient |
| `x25519` | 104 | Public-key-mixable | X25519 public-key recipient |

HKDF info strings:

```text
ferrocrypt/v1/recipient/argon2id/wrap
ferrocrypt/v1/recipient/x25519/wrap
ferrocrypt/v1/private-key/wrap
ferrocrypt/v1/payload
ferrocrypt/v1/header
```

Core v1 recipient design rule:

```text
Keep the .fcr container stable and simple.
Put recipient-specific cryptography in independently specified recipient types.
Require every recipient type to be namespaced, validated, documented, and tested.
```

### 13.6 FCA v1 payload

```text
fca_payload = fca_header(27) || archive_ext || manifest || file_contents
```

FCA fixed header:

| Field | Size | Value / meaning |
|---|---:|---|
| `magic` | 4 | `FCA\0` |
| `version` | 1 | `0x01` |
| `flags` | 2 | zero |
| `entry_count` | 4 | manifest entry count |
| `archive_ext_len` | 4 | archive-level TLV bytes |
| `manifest_len` | 4 | manifest bytes |
| `total_file_bytes` | 8 | logical regular-file bytes |

FCA manifest entry fixed prefix:

| Field | Size |
|---|---:|
| `kind` | 1 |
| `entry_flags` | 1 |
| `mode` | 2 |
| `path_len` | 2 |
| `entry_ext_len` | 4 |
| `size` | 8 |
| `path` | `path_len` |
| `entry_ext` | `entry_ext_len` |

FCA v1 object kinds:

| Kind | Meaning |
|---:|---|
| `0x01` | regular file |
| `0x02` | directory |

FCA v1 extension rule:

```text
Use shared TLV grammar.
Unknown ignorable tags are skipped.
Unknown critical tags reject before filesystem output.
Unknown object kinds reject.
Validate the complete manifest and every TLV before extraction.
```
