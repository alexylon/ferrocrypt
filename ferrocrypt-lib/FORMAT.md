# FerroCrypt Format v1

> **Status:** Canonical v1 specification.
>
> This document is the source of truth for the FerroCrypt v1 specification. The
> wire-version byte for both `.fcr` and `private.key` is `0x01`.
>
> This v1 specification uses the v1 binary wire format and defines an explicit,
> modular, namespaced, independently specified, and independently tested
> recipient/plugin model.

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
- the required safe archive payload subset.

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
recipient_pubkey = X25519(private_key_material, basepoint)
shared           = X25519(private_or_ephemeral_scalar, peer_public_key)
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
| 4 | 1 | `version` | `0x01` |
| 5 | 1 | `kind` | `0x45` (`E`) |
| 6 | 2 | `prefix_flags` | `u16`; MUST be zero |
| 8 | 4 | `header_len` | `u32`; length of `header`; MUST be `<= 16,777,216` |

The prefix is authenticated as part of the header MAC input (§3.6).

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
| 0 | 32 | `ephemeral_pubkey` |
| 32 | 24 | `wrap_nonce` |
| 56 | 48 | `wrapped_file_key` |

Wrapping:

```text
ephemeral_secret = random 32-byte X25519 scalar input
ephemeral_pubkey = X25519(ephemeral_secret, basepoint)
shared           = X25519(ephemeral_secret, recipient_pubkey)
```

If `shared` is all zero bytes, writers MUST reject and retry or fail.

```text
wrap_key = HKDF-SHA3-256(
    salt = ephemeral_pubkey || recipient_pubkey,
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
shared = X25519(recipient_secret, ephemeral_pubkey)
```

Readers MUST reject this recipient if `shared` is all zero bytes. Readers derive
the same `wrap_key` using the public key corresponding to `recipient_secret`:

```text
recipient_pubkey = X25519(recipient_secret, basepoint)

wrap_key = HKDF-SHA3-256(
    salt = ephemeral_pubkey || recipient_pubkey,
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

**Update.** A recipient type's mixing policy MAY equivalently be expressed as a
set of **mixing labels** — short identifying strings such that two recipient
entries are compatible in the same file iff their declared label sets are
exactly equal. The fixed names above are convenient shorthands within this
model: `public-key-mixable` corresponds to the empty set, `same-type-only` to a
singleton matching the type's name, and `exclusive` to any singleton not
declared by another type. Mixing labels are a per-type compile-time property
and never appear on the wire. Implementations MAY use either representation
internally; files are byte-identical and the reader-side rejection requirement
above is unchanged.

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

## 6. TLV extension region

`ext_bytes` is authenticated by the header MAC.

```text
ext_bytes = *tlv
tlv       = tag:u16 || len:u32 || value:len bytes
```

`ext_len` MUST be `<= 65,536`.

Tag classes:

| Tag range | Class |
|---:|---|
| `0x0001..0x7FFF` | Ignorable |
| `0x8001..0xFFFF` | Critical |
| `0x0000` | Reserved; reject |
| `0x8000` | Reserved; reject |

Rules after header MAC verification:

1. Tags MUST be strictly ascending.
2. Duplicate tags MUST be rejected.
3. TLV entries MUST NOT run past `ext_bytes`.
4. Truncated TLV headers MUST be rejected.
5. Zero-length values are allowed.
6. Unknown ignorable tags MUST be skipped.
7. Unknown critical tags MUST cause rejection.
8. Reserved tags MUST be rejected.

v1 defines no global TLV tags. v1 writers MUST emit `ext_len = 0` unless
implementing a tag defined by a later v1.x revision.

---

## 7. Public recipient keys

A public recipient is a lowercase Bech32 string with HRP `fcr`.

Logical payload:

```text
recipient_payload = type_name_len:u16
                    key_material_len:u32
                    type_name:type_name_len bytes
                    key_material:key_material_len bytes
                    checksum:16 bytes
```

```text
checksum = first_16_bytes(SHA3-256(
    "ferrocrypt/v1/public-key/checksum" || type_name || 0x00 || key_material
))
```

Rules:

- `type_name` follows §3.3 and §3.3.1.
- `key_material_len` MUST be `<= 12,288` unless a recipient spec defines a
  smaller bound.
- The full Bech32 string MUST be `<= 20,000` ASCII characters.
- The Bech32 checksum algorithm is the original BIP 173 Bech32 algorithm, not
  Bech32m. FerroCrypt does not use BIP 173's 90-character length limit.
- Encoders convert 8-to-5 with padding enabled.
- Decoders convert 5-to-8 with padding disabled and reject non-canonical padding.
- Mixed-case and uppercase encodings MUST be rejected.
- The internal checksum MUST verify.
- Generic public-recipient decoders MAY decode unsupported type names. A public
  recipient MUST be supported by the implementation or by an available plugin
  before use as an encryption recipient.

Native X25519 public recipients:

```text
type_name        = "x25519"
key_material_len = 32
key_material     = recipient_pubkey
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
padding, strings longer than 20,000 ASCII characters, and unsupported type names
when loading a public recipient for encryption. Readers MUST treat `public.key`
as byte-exact ASCII after UTF-8 validation and MUST NOT apply Unicode
normalization, case folding, or whitespace normalization before Bech32
validation.

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
type.

| Offset | Size | Field | Value / meaning |
|---:|---:|---|---|
| 0 | 4 | `magic` | `46 43 52 00` (`FCR\0`) |
| 4 | 1 | `version` | `0x01` |
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

Readers MUST validate magic, version, kind, flags, type name, lengths, total file
size, KDF parameters, local resource caps, AEAD authentication, TLV rules, and
recipient-type-specific secret/public material constraints.

Unknown private-key type names MUST be rejected unless supported by a plugin or
local implementation.

---

## 9. Archive payload

The decrypted payload is a TAR stream using a safe POSIX ustar subset.

Writers MUST emit only:

- relative UTF-8 paths;
- `/` separators;
- regular-file entries;
- directory entries;
- POSIX ustar headers.

Writers MUST NOT emit absolute paths, `..` components, symlinks, hardlinks,
devices, FIFOs, sockets, sparse files, pax headers, GNU headers, GNU long-name or
long-link records, or other special entry types.

Archive paths MUST be canonical relative UTF-8 paths. Readers MUST reject empty
paths, absolute paths, paths containing `.` or `..` components, repeated `/`
separators, `\` bytes, NUL bytes, or invalid UTF-8. File entry paths MUST NOT end
with `/`. Directory entry paths MUST end with `/`. Duplicate detection is
performed after removing exactly one trailing `/` from directory entry paths.

If source paths cannot be represented in the ustar subset, writers MUST reject
the input. Filesystem hardlinks MAY be archived as independent regular files;
hardlink TAR entries MUST NOT be emitted.

Readers MUST reject unsafe paths, unsupported entry types, duplicate output
paths, entries that collide with existing top-level output paths, and archives
with more than one top-level root. The top-level root is the first path component
after directory trailing-slash canonicalization; all entries in an archive MUST
have the same top-level root.

Writers MUST terminate the TAR stream with the standard two 512-byte zero blocks.
Readers MUST reject malformed ustar headers, invalid header checksums, file data
that runs past the archive, and non-zero data after the end-of-archive marker.

Readers MUST treat TAR metadata outside path, entry type, size, and file contents
as non-authoritative. Readers MUST NOT restore ownership and MUST NOT apply
setuid, setgid, sticky, device, or special-file semantics. Implementations SHOULD
extract with conservative platform-appropriate permissions.

v1 preserves file contents and directory structure. It does not guarantee
cross-implementation preservation of ownership, timestamps, platform-specific
permission bits, ACLs, extended attributes, hardlink identity, or symlink
relationships.

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

- `.fcr` and `private.key` files use version byte `0x01`.
- `public.key` has no binary version byte; its compatibility surface is the HRP,
  Bech32 grammar, payload grammar, and type names.
- Readers MUST reject unsupported versions.

Safe v1.x evolution can occur through:

- new recipient type names;
- new public/private key type names;
- authenticated TLV tags;
- plugin recipient type names;
- recipient-specific specifications that do not change the generic `.fcr`
  recipient-entry parser.

Sender authentication is intentionally out of scope. Future v1.x
sender-authentication mechanisms MAY be defined as critical TLV extensions;
such extensions MUST specify a canonical signed transcript and MUST NOT change
the generic `.fcr` container.

A new file version is required for incompatible changes to the prefix layout,
header layout, generic recipient-entry framing, header MAC input, payload
stream, private-key fixed header, TLV canonicality, or public-key
interpretation. This includes future recipient mechanisms that require changing
those generic container rules.

The next incompatible version SHOULD use `version = 0x02` and SHOULD preserve the
initial `FCR\0` magic and version byte long enough for v1 readers to report
unsupported version rather than garbage.

---

## 12. Diagnostics and conformance

Implementations SHOULD preserve distinct failure classes for the following
conditions. These classes need not be mutually exclusive; implementations MAY
expose specific subclasses for clearer diagnostics:

- bad magic, unsupported version, wrong kind, malformed prefix;
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
- payload truncation, authentication failure, or trailing data;
- malformed public key or private key;
- private-key unlock failure;
- unsafe or unsupported archive entry.

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
prefix, and archive cases. Armor vectors are required only for releases that
ship the optional armor transport (deferred in v1.0; see §10).

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
