# FerroCrypt Wire-Format Specification

> **Status:** Canonical specification.
>
> This document is the source of truth for FerroCrypt's stored formats. It is a
> living specification for independently versioned `.fcr`, FCA, public-key, and
> private-key encodings; it does not have one umbrella wire-format version.
>
> FerroCrypt release `0.3.0` establishes the initial compatibility baseline.
> The four initial stored version bytes are all `0x01`, but they are independent
> fields and may diverge. Public-key encoding version `0x01` and private-key
> encoding version `0x01` both map to the byte-less logical key-pair suite
> `KPS-1`.

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
9. [Archive payload — FerroCrypt Archive (FCA)](#9-archive-payload--ferrocrypt-archive-fca)
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
    - [11.1 Software releases and stored version domains](#111-software-releases-and-stored-version-domains)
    - [11.2 Key-pair suites](#112-key-pair-suites)
    - [11.3 Frozen cryptographic labels](#113-frozen-cryptographic-labels)
    - [11.4 Compatibility baselines](#114-compatibility-baselines)
    - [11.5 Version-change rules](#115-version-change-rules)
12. [Diagnostics and conformance](#12-diagnostics-and-conformance)
    - [12.1 Stable diagnostic taxonomy](#121-stable-diagnostic-taxonomy)
    - [12.2 Invariant and capability-relative expectations](#122-invariant-and-capability-relative-expectations)
    - [12.3 Frozen public conformance corpus](#123-frozen-public-conformance-corpus)
    - [12.4 Conformance claims](#124-conformance-claims)
13. [Quick reference](#13-quick-reference)
    - [13.1 Encrypted-file prefix](#131-encrypted-file-prefix)
    - [13.2 Header fixed section](#132-header-fixed-section)
    - [13.3 Recipient entry](#133-recipient-entry)
    - [13.4 Recipient namespace summary](#134-recipient-namespace-summary)
    - [13.5 Native recipient types](#135-native-recipient-types)
    - [13.6 FCA archive version `0x01` payload](#136-fca-archive-version-0x01-payload)

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
- optional ASCII armor (not shipped by FerroCrypt release `0.3.0`; see §10);
- the required safe FCA archive payload format.

`.fcr` outer-container version `0x01` is built around one central abstraction:

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
- Password byte length: 1 to 4,096 bytes, inclusive.
- No Unicode normalization is performed by the format.
- Salt: the stored 32-byte salt.
- Secret input: empty.
- Associated-data input: empty.
- Output length: 32 bytes.

Structural KDF-parameter bounds:

```text
1 <= lanes <= 8
1 <= time  <= 12
8 * lanes <= mem_kib <= 2,097,152
```

Readers MUST reject out-of-range parameters before running Argon2id.

The passphrase byte-length bound is a fixed credential rule for the `argon2id`
recipient defined under `.fcr` outer-container version `0x01` and for
private-key encoding version `0x01`; it is not a configurable local KDF
resource cap. It applies identically when creating or opening either artifact.
Readers and writers MUST reject a passphrase outside this bound before running
Argon2id. Implementations MUST count the exact UTF-8 bytes supplied by the
caller and MUST NOT normalize, trim, case-fold, truncate, or treat an embedded
NUL as a terminator.

Recommended writer default for desktop-class encryption:

```text
mem_kib = 1,048,576
time    = 4
lanes   = 4
```

Writers MAY refuse to emit a `mem_kib` below a local minimum above the
structural floor, because a passphrase-protected artifact written with too
little memory is weak for its whole lifetime. FerroCrypt refuses `mem_kib`
below 19,456 when creating either artifact. Such a minimum is writer policy
only: readers MUST accept every structurally valid value, so an artifact
written before or below a writer minimum stays readable.

Implementations MAY impose lower local KDF work caps on Argon2id parameters read
from untrusted input. Local KDF caps are resource policy, not format
incompatibility or passphrase-length bounds. Implementations SHOULD make such
caps configurable and report a distinct resource-cap error.

Such a cap MAY bound the product `mem_kib * time`, because that product is the
Argon2id work factor, whereas a cap on `time` alone would refuse parameter sets
cheaper than the writer default a reader must already accept. A product cap
does not replace a `mem_kib` cap: the two bound different resources, since
`mem_kib` alone determines the allocation a reader holds while deriving.

### 2.3 HKDF domain separation

The native HKDF derivations defined here use HKDF-SHA3-256 and produce 32 bytes
unless a future recipient specification says otherwise.

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

Every native X25519 public value serialized by FerroCrypt MUST use the canonical
RFC 7748 output encoding. This includes static `recipient_public_key_bytes`,
X25519 `public_material` in `private.key`, and `ephemeral_public_key_bytes` in an
`x25519` recipient body. The canonical encoding is exactly 32 bytes and, when
decoded as an unsigned little-endian integer `u`, satisfies:

```text
0 <= u < 2^255 - 19
```

Equivalently, the most significant bit of byte 31 is zero and the remaining
255-bit integer is strictly less than the Curve25519 field prime. Writers MUST
emit this encoding. Readers MUST reject any other encoding and MUST NOT make it
acceptable by clearing the high bit or reducing the integer modulo the field
prime.

This is a FerroCrypt serialization rule, not a change to the X25519 primitive.
RFC 7748 requires the primitive itself to mask the high bit of received X25519
coordinates and accept non-canonical field encodings. FerroCrypt rejects those
aliases at the format boundary because the serialized public bytes are also
bound into HKDF salts, checksums, and fingerprints; accepting aliases would give
one X25519 point multiple FerroCrypt identities and transcripts.

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
| 4 | 1 | `version` | `0x01` (`.fcr` outer-container version) |
| 5 | 1 | `kind` | `0x45` (`E`) |
| 6 | 2 | `prefix_flags` | `u16`; MUST be zero |
| 8 | 4 | `header_len` | `u32`; length of `header`; MUST be `<= 16,777,216` |

The prefix is authenticated as part of the header MAC input (§3.6). The byte at
file offset 4 is the `.fcr` outer-container version; magic `FCR\0` at offsets
0..3 and kind `0x45` (`E`) at offset 5 establish that domain. It is independent
of key-pair compatibility (§11). Version byte `0x00` is reserved and
structurally malformed. Version bytes `0x02..=0xFF` are unsupported by a reader
that implements only `.fcr` outer-container version `0x01`.

Readers MUST reject, in this order:

- input shorter than 12 bytes;
- magic bytes other than `FCR\0`;
- `kind != 0x45` for an encrypted `.fcr` file;
- `.fcr` outer-container version byte `0x00` with diagnostic class
  `malformed_header` (§12.1);
- unsupported `.fcr` outer-container version bytes `0x02..=0xFF` with
  diagnostic class `unsupported_outer_version` (§12.1);
- non-zero `prefix_flags`;
- `header_len > 16,777,216`.

`kind` precedes `version` because §11.1 makes the kind byte the selector for the
version byte's domain: a file declaring another kind is `wrong_kind` (§12.1)
whatever byte sits at offset 4.

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
supported_recipient_count * (12 + header_len) <= 67,109,632
```

Callers MAY raise local caps for specific use cases. Local caps are resource
policy, not format incompatibility.

The fourth cap bounds aggregate header-MAC input, because §3.6 has every
candidate recipient authenticate the whole `prefix || header`: a file's
verification cost is the product of its recipient count and its header size, not
the sum, so the first three caps bound each factor without bounding the work.
Its recommended value is the product of the first two, and it therefore rejects
nothing they accept on their own. Readers SHOULD evaluate it after §3.7 step 9
and before step 10, so a file over the cap is refused before any private key is
unlocked and before any recipient KDF or header MAC runs. Writers SHOULD apply
it to the entry list they are about to seal, counting every supported entry,
since a reader cannot know which entries will unwrap until after that work.

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

When one entry violates more than one rule, readers MUST check in this order
and report the first failure, so two conforming readers report the same
diagnostic class (§12.1) for the same bytes:

1. The region holds fewer than the 8 entry-header bytes —
   `malformed_recipient_entry`.
2. `type_name_len` outside `1..=255` — `malformed_recipient_entry`.
3. `body_len > 16,777,216` — `malformed_recipient_entry`.
4. A reserved `recipient_flags` bit is set (§3.4) — `recipient_flags_reserved`.
5. The entry runs past `recipient_entries_len` — `malformed_recipient_entry`.
6. `body_len` above the reader's local cap (§3.2) — `resource_cap_exceeded`.
   The cap is checked after the fit check because fitting the region is a
   structural rule; an entry that runs past its region is malformed, not
   merely over a configured limit.
7. `type_name` is not valid UTF-8 or violates the grammar above —
   `malformed_type_name`.

Entries are validated one at a time in declared order, each fully through the
list above before the next entry is read, so when two entries are both invalid
the earlier entry determines the diagnostic.

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
2. Reject bad magic; reject `.fcr` outer-container version byte `0x00` as
   structurally malformed; reject an unsupported nonzero outer-container
   version, wrong kind, non-zero prefix flags, or
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

The step 5 rejection is applied entry-by-entry during the step 4 parse, at its
position in the §3.3 check order. Steps 6 through 9 are one file-wide
preflight, and each step MUST complete over every recipient entry before the
next step begins, so a rejected file yields one diagnostic class determined by
its content rather than by the order its entries appear in (§12.3). If a file
has both an unknown critical entry and a recipient-specific structural defect,
the step 6 rejection takes precedence.
Readers MUST complete the recipient-specific step 8 checks for every supported
entry before starting the mixing checks in step 9. Step 9 MUST NOT begin unless
every step 8 check has succeeded; if a file has both a recipient-specific
structural defect and an illegal recipient mix, the step 8 structural rejection
takes precedence. The step 8 checks include the exact 116-byte `argon2id` body
length, its `kdf_params` against the §2.2 bounds, and the exact 104-byte
`x25519` body length. Local KDF resource caps are not part of step 8, because a
reader MAY take that policy from its caller after classification; a reader MUST
still apply them before Argon2id runs. A reader MUST NOT unlock a
supplied private key (including running its unlock KDF), perform X25519 or
another KEM operation, or run a recipient KDF until this preflight succeeds.

Between step 9 and step 10, readers SHOULD reject a file whose supported
recipient count multiplied by `12 + header_len` exceeds the aggregate
header-MAC cap from §3.2. Step 11 authenticates the whole `prefix || header`
once per candidate, so that product — not `header_len` alone — is the work a
file can demand, and the check belongs where nothing expensive has run yet.

A recipient unwrap is not successful until the header MAC verifies.

Readers SHOULD either attempt unwrap of all supported recipient entries before
returning success or randomize recipient iteration order to reduce timing leakage
about which recipient matched.

Readers SHOULD keep one opened file for all steps above instead of resolving the
path again between structural parsing and payload decryption. Resolving the path
again could select a replacement file that did not pass the earlier checks.

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

The first three are §3.7 step 8 checks and MUST be reported ahead of the mixing
violation, because a malformed entry is a property of the entry itself while a
mixing violation is a property of the list. The resource cap is not a step 8
check: it is caller policy that a reader MAY receive after classification, and
MUST apply before Argon2id runs.

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

Before this operation, writers MUST validate that
`recipient_public_key_bytes` uses the canonical encoding from §2.4. Writers
MUST reject a non-canonical recipient public key rather than normalize it.
`ephemeral_public_key_bytes` is the canonical X25519 output encoding from §2.4.

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
- `ephemeral_public_key_bytes` is the all-zero byte string;
- `ephemeral_public_key_bytes` is not the canonical encoding from §2.4;
- the X25519 shared secret is all zero;
- the file violates the `x25519` mixing policy.

The explicit all-zero and canonical-encoding checks on
`ephemeral_public_key_bytes` are credential-independent step 8 checks and MUST
run before any private-key unlock. The all-zero-shared-secret check remains
mandatory during X25519 for every other preflight-valid ephemeral public key.

The `x25519` recipient test suite MUST include valid single-recipient,
valid multi-recipient, unknown-non-critical, wrong-key, all-zero-shared-secret,
non-canonical-ephemeral-key, tamper covering each authenticated field
independently, invalid-flag, invalid-length, illegal-mixing, and
header-MAC-failure vectors.

### 4.3 Future recipient types

**Future types.** Future recipient types can be added without changing `.fcr`
outer-container version `0x01` if they obey §3.3 and §3.4.

**Recipient specifications.** Every native or plugin recipient type MUST have a
complete recipient specification defining: exact `type_name`, namespace, status,
purpose, allowed flags, body layout and length limits, public/private key
material formats if any, file-key wrapping/opening procedures, cryptographic
parameters, randomness requirements, malformed-input rejection rules, failure
behavior, mixing policy, privacy/security considerations, and positive,
wrong-key, malformed, and tamper vectors.

**Parser compatibility.** A recipient type specification MUST NOT require
changes to the generic `.fcr` recipient-entry parser unless it is defining a
new incompatible `.fcr` outer-container version.

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
| Associated data (AAD) | empty byte string |

The XChaCha20-Poly1305 associated-data input for every payload chunk MUST be
the empty byte string.

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
- Readers MUST reject an empty final chunk that follows any non-final chunk.
- Writers MUST NOT emit more than `2^32` chunks.
- The final chunk MUST use a counter value in `0..=2^32-1`. If counter
  `2^32 - 1` is used, that chunk MUST be final.
- Readers MUST reject streams that exceed `2^32` chunks, fail authentication,
  reach EOF before a valid final chunk, or contain bytes after the final chunk.
- Any rejection is terminal for the stream. After a chunk fails, readers MUST
  NOT decrypt or release later chunks. Each chunk authenticates independently,
  so later ciphertext could otherwise form a valid sequence at the unchanged
  stream position.

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

The `.fcr` header namespace for outer-container version `0x01` defines no TLV
tags. Writers of that version MUST emit `ext_len = 0` unless implementing a tag
defined by a later compatible specification.

---

## 7. Public-key recipients

A public recipient is a lowercase Bech32 string with HRP `fcr`.

The public-key encoding version is the first byte at offset 0 of the decoded
Bech32 payload. It is not an offset in the UTF-8 `public.key` text file and is
independent of the `.fcr` outer-container version. The `1` visible in a string
beginning `fcr1...` is Bech32's separator between the HRP `fcr` and the encoded
data; it is not a version field.

Decoders MUST map the public-key encoding version to a logical key-pair suite
shared with the corresponding private-key encoding before deciding support. An
implementation MUST NOT accept a public key for encryption unless it also
supports private-key decryption through at least one private-key encoding that
maps to the same key-pair suite.

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
rejected with diagnostic class `malformed_public_key` (§12.1). Public-key
encoding version `0x01` maps to key-pair suite `KPS-1`.

All public-key recipient payloads use the same checksum scheme, with the
public-key encoding version byte mixed into the hash input:

```text
checksum = first_16_bytes(SHA3-256(
    "ferrocrypt/v1/public-key/checksum"
 || public_key_version
 || type_name
 || 0x00
 || key_material
))
```

The substring `v1` in the checksum domain string is an opaque, frozen part of
that ASCII byte string. It does not name a software release, stored version, or
key-pair suite. A future key-pair suite continues to use the same domain string
with its own `public_key_version` byte mixed in unless a future specification
explicitly defines a different checksum scheme and label. A version-byte or
key-pair-suite change does not alter the label automatically.

Rules:

- Writers conforming to public-key encoding version `0x01` MUST emit
  `public_key_version = 0x01`.
- Readers that support only public-key encoding version `0x01` MUST map
  `public_key_version = 0x01` to `KPS-1` before deciding support and MUST
  reject `0x02..=0xFF` with diagnostic class
  `unsupported_public_key_version` (§12.1).
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

Implementations MAY apply a smaller local cap on recipient-string length for
untrusted input and SHOULD let callers raise it up to the structural ceiling,
because a future key type with larger key material needs a longer string. Such
a cap is resource policy, not format incompatibility, and exceeding it SHOULD
produce a distinct resource-cap error.

Native X25519 public recipients:

```text
type_name        = "x25519"
key_material_len = 32
key_material     = recipient_public_key_bytes
```

Native X25519 `key_material` MUST use the canonical encoding from §2.4 and MUST
NOT be the all-zero byte string. Readers MUST reject an X25519 public recipient
whose key material is not exactly 32 bytes, is not canonical, or is all zero.
Writers MUST apply the same checks before serializing, fingerprinting, or using
the key for encryption.

Implementations MUST enforce these rules at every native X25519 public-key
ingress, including raw-byte APIs, recipient strings, and `public.key` files.
After checksum verification, readers MUST reject a non-canonical encoding
rather than normalize it. This ensures that equivalent RFC 7748 input encodings
cannot acquire distinct FerroCrypt recipient strings or fingerprints, and that
encryption and decryption bind the same `recipient_public_key_bytes` into the
X25519 wrap-key salt.

The native X25519 public-recipient test suite MUST include a generated canonical
key; the same key with the most significant bit of byte 31 set; encodings of
`u = 2^255 - 19`, `u = 2^255 - 18`, and `u = 2^255 - 1`; the all-zero value; and
wrong-length material. Only the generated canonical key is a valid native
X25519 public recipient.

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
For native X25519, `key_material` MUST already have passed the canonical-encoding
checks above; an RFC 7748 alias MUST NOT be fingerprinted as a separate key.

---

## 8. Private key format (`private.key`)

A `private.key` file stores one passphrase-wrapped private key for one recipient
type. The byte at file offset 4 is the private-key encoding version. Its domain
is established by magic `FCR\0` at offsets 0..3 and kind `0x4B` (`K`) at offset
5. It is independent of the `.fcr` outer-container version stored at the same
offset under kind `0x45` (`E`).

| Offset | Size | Field | Value / meaning |
|---:|---:|---|---|
| 0 | 4 | `magic` | `46 43 52 00` (`FCR\0`) |
| 4 | 1 | `version` | `0x01` (private-key encoding version) |
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

Writers conforming to private-key encoding version `0x01` MUST emit `0x01` at
offset 4. Private-key encoding version byte `0x00` is reserved and MUST be
rejected with diagnostic class `malformed_private_key` (§12.1). Readers that
support only private-key encoding version `0x01` MUST map `0x01` to `KPS-1`
before deciding support and MUST reject `0x02..=0xFF` with diagnostic class
`unsupported_private_key_version` (§12.1).

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
public_material    = recipient_public_key_bytes (canonical per §2.4)
plaintext secret   = 32-byte X25519 scalar input
```

For native X25519 private keys, writers MUST store the canonical X25519 output
for `public_material`. After decrypting `secret_material`, readers MUST compute
`X25519(secret_material, basepoint)` and reject the private key unless the result
exactly equals `public_material`. Readers MUST NOT normalize `public_material`
before this comparison.

Let `secret_material` be the recipient-type-specific private key material to be
wrapped.

Passphrases used to create or open `private.key` use the exact input encoding and
fixed byte-length bound from §2.2.

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

Readers MUST validate magic, kind, private-key encoding version and
key-pair-suite support, flags, type name, lengths, total file size, KDF
parameters, local resource caps, AEAD authentication, TLV rules, and
recipient-type-specific secret/public material constraints.
`kind` precedes the version byte because §11.1 makes the kind byte the selector
for that byte's domain: a file declaring another kind is `wrong_kind` (§12.1)
whatever byte sits at offset 4.

A local cap on `wrapped_secret_len` follows the same rule as the recipient-string
cap in §7: implementations MAY set one below the structural maximum and SHOULD
let callers raise it, because a future key type wraps more secret material.

Unknown private-key type names MUST be rejected unless supported by a plugin or
local implementation.

---

## 9. Archive payload — FerroCrypt Archive (FCA)

The decrypted payload of an encrypted `.fcr` file is a **FerroCrypt Archive
(FCA)** stream. The `.fcr` format defined here carries an FCA archive as its
payload; FCA has its own inner magic and FCA archive version at the start of
the authenticated payload plaintext.

Readers MUST dispatch on the FCA magic and archive version after payload
decryption has made those bytes available. Unsupported FCA archive versions
MUST be reported as such, not as generic malformed payload bytes.

The `.fcr` outer-container version controls the outer cryptographic container.
The FCA archive version controls the inner archive grammar. `FORMAT.md`
describes the `.fcr` payload as an FCA archive and does not bind the outer
container to a single immutable FCA grammar. Therefore, adding or supporting a
future FCA archive version does not by itself require a new `.fcr`
outer-container version. A new `.fcr` outer-container version is required only
for incompatible changes to the outer cryptographic container, recipient
framing, header authentication, payload stream, or other generic `.fcr` rules.

FCA archive version `0x01` is a small native archive format with a
manifest-first design and length-delimited extension regions. It represents the
archive features FerroCrypt intentionally preserves by default: regular files,
directories, one top-level output root, relative UTF-8 `/` paths, portable path
safety rules, Unix-style `0o000..0o777` permission bits, declared regular-file
sizes, and regular-file bytes concatenated in manifest order.

FCA archive version `0x01` provides archive-level and per-entry TLV extension
regions so later compatible specifications can add optional metadata without
changing its fixed framing. Unknown ignorable metadata can be skipped. Unknown
critical metadata causes rejection before any filesystem output is created.
New filesystem object kinds remain strict and fail closed.

FCA archive version `0x01` intentionally does **not** define native preservation
for symlinks, hardlink entries, device files, FIFOs, sockets, sparse-file holes,
owners or groups, timestamps, ACLs, extended attributes, Windows alternate data
streams, Windows reparse points, macOS resource forks, compression,
TAR/PAX/GNU/ZIP/CPIO/libarchive extension records, or generic archive-tool
compatibility. Unsupported object semantics are unrepresentable unless a later
specification defines an explicit entry kind or critical extension for them.

### 9.1 Layout

An FCA archive version `0x01` payload is exactly:

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

FCA archive version byte `0x00` is reserved and MUST be rejected with diagnostic
class `malformed_archive` (§12.1). A reader that implements only FCA archive
version `0x01` MUST reject `0x02..=0xFF` with diagnostic class
`unsupported_fca_version` (§12.1).

Readers MUST reject short headers, bad magic, the reserved zero FCA archive
version, unsupported nonzero FCA archive versions, non-zero header flags, zero
`entry_count`, `entry_count` above the configured cap, `archive_ext_len` above
the configured cap, `archive_ext_len` values not representable as `usize`,
`manifest_len == 0`, `manifest_len` above the configured cap, `manifest_len`
values not representable as `usize`, and declared `total_file_bytes` above the
configured cap.

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

FCA archive version `0x01` defines no archive-level TLV tags. Writers of that
version MUST emit `archive_ext_len = 0` unless implementing a tag defined by a
later compatible specification.

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
for future incompatible FCA archive versions and MUST be zero in FCA archive
version `0x01`.

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

FCA archive version `0x01` defines no per-entry TLV tags. Writers of that
version MUST emit `entry_ext_len = 0` for every entry unless implementing a tag
defined by a later compatible specification.

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
creating output. The ASCII collision key maps ASCII `A` through `Z` to `a`
through `z` and leaves every other byte unchanged. This prevents common
collisions on case-insensitive filesystems, including default-config NTFS and
common macOS volumes, before extraction reaches `create_new(true)`.

Readers MUST also reject paths that have the same NFC collision key. To
construct this key, normalize the complete FCA path to Unicode Normalization
Form C (NFC), then apply the ASCII `A` through `Z` mapping defined above. For
example, a path containing precomposed `é` collides with the corresponding path
containing `e` followed by `U+0301 COMBINING ACUTE ACCENT`, including when the
paths also differ in ASCII case. NFC is applied only when constructing the
collision key; the manifest retains the original path bytes, and extraction
uses the original path rather than the key.

For case comparison, the ASCII and NFC collision keys fold ASCII letters only.
Case-equivalence rules beyond ASCII vary by filesystem and volume and are
outside this portable preflight. Filesystem-specific collisions not caught by
these keys MUST fail closed during extraction through exclusive file creation
or no-clobber final promotion under `.incomplete`.

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
content bytes of entries in manifest order. For FCA archive version `0x01` as
defined here, regular files are encoded densely and directories consume zero
bytes:

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
source path or source tree cannot be represented by FCA archive version `0x01`.
FerroCrypt MUST NOT write archives its own default reader will reject.

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

Where the platform exposes a stable file identity, the writer SHOULD confirm
after opening the source root that the opened object is the one its pre-open
classification examined, because the open resolves the path a second time and
no-follow guards only the final component.

The writer MUST build a metadata-only manifest before emitting the FCA header.
If the output location can appear within the source tree, the metadata pass MUST
finish before the writer creates any output there. Otherwise, the output could
be recorded as source content and the archive would no longer represent the
captured source tree.
The metadata pass records entry kind, canonical FCA path string, source path or
equivalent reopen information, mode, logical regular-file size, and entry
extension bytes. The metadata pass MUST apply path validation, exact duplicate
detection, duplicate detection under the ASCII collision key, duplicate
detection under the NFC collision key, entry-count cap, logical
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
   - duplicate paths under the ASCII collision key;
   - duplicate paths under the NFC collision key;
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
    hardened filesystem backend. Where the confirmations in steps 16 and 17
    need a handle retained from this step, the reader MUST obtain it here and
    MUST fail the extraction if it cannot, because a reader that continues
    without one commits an output whose identity it can no longer confirm, and
    failing at this point precedes any plaintext;
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
    Where the platform exposes a stable file identity, the reader MUST confirm
    that the reopened root denotes the object staged in step 10 and MUST apply
    the mode through that same handle, because a mode applies to an object
    rather than to a name: an entry substituted at the final name would
    otherwise receive the archive-chosen mode, and a hard link carries that to
    an object outside the destination directory.
    A failure to apply the root mode MUST NOT fail the extraction: the output
    is already complete at its final name, where `DeleteOnError` cleanup
    cannot remove it, and it remains at its restrictive initial mode;
17. where the platform exposes a stable file identity, confirm that the final
    output name still denotes the object staged in step 10, and that the
    destination directory path still denotes the directory the output was
    committed in. Both MUST run after step 16 and MUST fail the extraction on
    a mismatch, because step 15 resolves the staged entry by name and a local
    writer with access to the destination directory can put another object
    under either name. A final output name that no longer exists MUST count
    as a mismatch, because step 15 committed an entry there and its absence
    is evidence that the name no longer denotes the output. Any other failure
    to read that final entry MUST NOT count as a mismatch, because it reports
    the environment rather than the entry. When reopening the destination
    directory or reading either directory identity, only `EMFILE`, `ENFILE`,
    and `ENOMEM` MAY skip the comparison as unavailable resource checks; every
    other failure MUST fail the extraction without removing an output already
    ratified in step 16. If a file-root hard-link fallback created the final
    name, a staging-name unlink that reports success or `NotFound` MUST be
    followed by a link-count check through the retained staged-file handle, and
    the reader MUST NOT return success unless that committed inode has exactly
    one link. The unlink result alone is insufficient: a local writer can move
    the staging link so it appears missing, or replace it so the unlink removes
    another entry. If the unlink reports failure, the link count cannot be
    established, or the count is not one, the reader MUST NOT withdraw the
    final name after that delayed or ambiguous cleanup; after these identity
    checks it MUST fail while preserving the complete commit and any additional
    link;
18. return the final output path.

Steps 1 through 8 MUST complete before any filesystem output is created.

Where the platform exposes no stable identity, the corresponding confirmation
in step 16 or step 17 is skipped. A failure to read the staged-root or final-name
identity is likewise not evidence of a substitution and skips that comparison.
This exception does not apply to the hard-link link-count post-condition: a
failure to read that count MUST fail the extraction after commit. The
destination-directory check follows the narrower resource rule in step 17;
permission denial and other ordinary I/O failures propagate. None of these
rules license continuing without the staged handle: step 10 requires the reader
to fail before any plaintext where that handle cannot be obtained. The reader
MUST keep that handle open until the last comparison of steps 16 and 17 is
made, because a filesystem may assign an object a new identifier once its last
handle closes, and MUST read the staged identity from it after step 15, because
a filesystem may assign one from the position of the directory entry the
promotion moves.

Steps 11 and 12 MAY be interleaved per entry: applying a file's mode to its
open handle immediately after its content is written is equivalent to a
separate pass, because every descendant file sits inside the restrictive
staged root until promotion.

When step 16 reopens the promoted root, the reader MUST NOT follow symlinks. It
MUST also verify that a file root is a regular file and a directory root is a
directory. The open MUST NOT wait on a substituted special file; for example,
opening a FIFO for reading can wait indefinitely for a writer. These checks
protect the interval in which another local process can replace the final name
between steps 15 and 16.

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
whose driver cannot perform one (the macOS exFAT driver among them), a file
root SHOULD instead be linked to the final name and the staged name unlinked,
because creating a link refuses an existing target atomically and reaches the
final name without a placeholder any other process could replace. The reader
MUST retain a handle to that inode until the step-17 link-count post-condition
has completed.

Where neither is available — a directory root, or a filesystem without hard
links — readers MAY commit in two steps: atomically claim the final name —
exclusive-create for a file root, `mkdir` for a directory root — then rename
the staged root over the claim, because the exclusive claim preserves the
no-clobber guarantee (an entry that predates the commit is never replaced) and
the rename lands content at the final name whole. Between the two steps the
claim is an ordinary entry, so an entry another process puts in its place is
replaced by the rename. Both steps MUST resolve through the same trusted
directory handle where the platform backend is handle-relative. A crash between
the two steps leaves an empty claimed entry alongside the staged `.incomplete`
root.

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

On extraction failure while the current run still treats its root as staged,
`DeleteOnError` removes only the root created by that run, best-effort. The
removal MUST be chosen from what the run staged, not from what currently
occupies the working name, because a local writer with access to the destination
directory can put an object of another type there; a staged regular file MUST
NOT be removed recursively.

Once step 16 confirms and ratifies the promoted root, the reader MUST stop
treating that object as staged. A later final-name or destination-directory
error, a post-commit failure to remove a hard-link staging name, or a failure to
prove that the linked inode has exactly one remaining link MUST NOT invoke
`DeleteOnError` against the confirmed output. Such an error can therefore return
after complete plaintext was committed.

That writer can also move the staged root aside, leaving the working name to
denote something else. A removal resolved only through that name then misses
the staged plaintext, so a reader SHOULD destroy the staged content through the
handle it created the root with: emptying a staged file, and removing a staged
directory through its own descriptor. Where the platform offers no way to do so
— a handle that cannot be removed through without resolving it back to a path —
the staged root is left in place, which
`RetainOnError` callers already expect and which never removes an object the
run did not create.

`RetainOnError` leaves staged plaintext for inspection or recovery. Process
termination, power loss, or `SIGKILL` can leave `.incomplete` output regardless
of policy.

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

FCA archive version `0x01` defines no metadata TLV tags, so this section lists
no metadata-specific caps. Future metadata tag specifications (e.g. xattr
counts, ACL entries, sparse extents) MUST define their own resource caps and
apply them with the same before-allocation discipline.

### 9.13 Platform metadata and preservation

FCA archive version `0x01` preserves file contents, directory structure, and
Unix-style `0o000..0o777` permission bits. It does not preserve ownership,
timestamps, ACLs, extended attributes, hardlink identity, symlink
relationships, devices, FIFOs, sockets, sparse-file metadata, Windows alternate
data streams, Windows reparse points, macOS resource forks, compression, or
platform-specific mode bits unless a later specification defines an explicit
extension and the writer and reader opt into that extension.

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

FCA archive version `0x01` extension regions use the shared TLV grammar from
§6. Implementations SHOULD share one TLV scanner and canonicality validator
across `.fcr`, `private.key`, and FCA extension regions, with separate tag
registries per namespace.

FCA extension bytes are authenticated by the outer `.fcr` payload stream. FCA
MUST NOT define a nested checksum, MAC, or integrity tag for normal FerroCrypt
extraction. A standalone FCA parser may exist for tests, fuzzing, diagnostics,
or transformations, but raw FCA bytes are not a standalone security boundary.

Object kinds are strict. Unknown `kind` values MUST reject. Optional metadata is
extensible through TLVs. A future feature that changes object type, encoded
content consumption, security policy, or required preservation semantics MUST use
a critical tag or a new entry kind and MUST reject on unsupported readers.

Compression is deliberately out of scope for FCA archive version `0x01`.
Compression MUST NOT be introduced through an ignorable TLV. Any future
compression profile requires its own explicit security analysis and
compatibility specification.

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
> code lives at `ferrocrypt-lib/src/archive/` and implements FCA archive version
> `0x01` only.

---

## 10. ASCII armor

> **Status:** deferred. The armor encoder/decoder is not shipped by FerroCrypt
> release `0.3.0`. A reference implementation is parked under
> `experiments/armor/` and may be reintroduced by a later release. The
> specification below remains authoritative for that future revival;
> introducing armor does not change any stored version domain.

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
- After decoding, readers parse the bytes as a binary `.fcr` file and dispatch
  on its outer-container version.

Conventional armored extensions are `.fcr.asc` and `.fcr.pem`. Detection is by
BEGIN line, not extension.

---

## 11. Versioning and compatibility

### 11.1 Software releases and stored version domains

FerroCrypt software releases use dotted semantic versions such as `0.3.0`,
`0.4.0`, and `1.0.0`. A release number is not stored in an artifact and has no
automatic effect on any stored byte.

The specification has four independently stored version domains. A version
byte is meaningful only within its exact artifact context:

| Canonical name | Artifact context | Version location | Discriminating context | Initial value |
|---|---|---|---|---|
| `.fcr` outer-container version | Binary encrypted `.fcr` file | File offset 4 | Offsets 0..3 are `FCR\0`; offset 5 is kind `0x45` (`E`) | `0x01` |
| FCA archive version | Plaintext recovered from the authenticated payload stream | Recovered-payload offset 4 | Recovered-payload offsets 0..3 are `FCA\0`; there is no kind byte, and flags begin at offsets 5..6 | `0x01` |
| Public-key encoding version | Decoded Bech32 recipient payload | Decoded-payload offset 0 | Bech32 HRP is `fcr`; `type_name` follows in the decoded payload | `0x01` |
| Private-key encoding version | Binary `private.key` file | File offset 4 | Offsets 0..3 are `FCR\0`; offset 5 is kind `0x4B` (`K`) | `0x01` |

The byte at file offset 4 under magic `FCR\0` is not self-describing. The kind
byte selects its domain:

```text
FCR\0 || 0x01 || 0x45  => .fcr outer-container version 0x01
FCR\0 || 0x01 || 0x4B  => private-key encoding version 0x01
```

For `public.key`, offset 0 always means offset 0 of the decoded Bech32 payload,
not byte 0 of the UTF-8 text file. The `1` in `fcr1...` is the Bech32 separator,
not the public-key encoding version.

All four initial values happen to be `0x01`. They are not a shared field, need
not change together, and may diverge. Normative prose and user-facing
diagnostics MUST identify the affected domain and render the stored byte in
two-digit hexadecimal form, such as `0x01` or `0xFF`.

### 11.2 Key-pair suites

`KPS-1` means **key-pair suite 1**. It is a logical compatibility identifier,
not a stored byte:

```text
public-key encoding version 0x01  ─┐
                                   ├── KPS-1
private-key encoding version 0x01 ─┘
```

Readers MUST map a supported public- or private-key encoding version to a
key-pair suite before deciding whether the key is usable. The mapping may be
many-to-one. A representation-only change may map a new encoding version to an
existing suite when logical key material and recipient compatibility are
unchanged. Conversely, future public- and private-key encoding version numbers
that map to the same new suite need not be numerically equal.

For example, a future mapping could be:

```text
public-key encoding version 0x02  ─┐
                                   ├── KPS-2
private-key encoding version 0x03 ─┘
```

An implementation MUST NOT accept a public-key encoding for encryption unless
it also supports private-key decryption through at least one private-key
encoding that maps to the same `KPS-N`.

### 11.3 Frozen cryptographic labels

The following values are literal ASCII byte strings used as cryptographic
inputs:

```text
ferrocrypt/v1/recipient/argon2id/wrap
ferrocrypt/v1/recipient/x25519/wrap
ferrocrypt/v1/private-key/wrap
ferrocrypt/v1/public-key/checksum
ferrocrypt/v1/payload
ferrocrypt/v1/header
```

The substring `v1` is an opaque, frozen part of each byte sequence. It is not a
software release, a directory, a stored version field, a key-pair suite, or an
instruction to substitute the current version. These labels MUST remain
byte-for-byte unchanged for every artifact that currently uses them. A future
specification may define a different cryptographic label only explicitly; a
stored version change does not replace `/v1/` automatically.

The string `ferrocrypt/v1/test`, where it appears in test-only material, is not
a production protocol label and carries no stored-version meaning.

### 11.4 Compatibility baselines

A compatibility baseline is a release-anchored promise, not a stored field. The
initial baseline is **the `0.3.0` compatibility baseline**, consisting of:

```text
.fcr outer-container version 0x01
FCA archive version 0x01
public-key encoding version 0x01 -> KPS-1
private-key encoding version 0x01 -> KPS-1
the native recipients and all normative semantics defined for those versions
```

FerroCrypt release `0.3.0` establishes this baseline. Every later FerroCrypt
release MUST continue to read every valid artifact covered by it and MUST
preserve its structural, canonicality, authentication, and security rejection
rules.

Baselines are immutable and cumulative. A later stable baseline contains every
earlier baseline plus any newly promised formats or semantics:

```text
0.3.0 baseline = initial supported formats and semantics
0.4.0 baseline = 0.3.0 baseline + formats or semantics first promised by 0.4.0
```

A later release MUST NOT redefine the `0.3.0` compatibility baseline. An older
reader is not required to understand a future incompatible version; the promise
is one-way from later readers to earlier stable artifacts. A rejection caused
only by an unknown feature is capability-relative: a later implementation may
accept the same feature after implementing its specification, as defined in
§12.2.

Artifacts produced by `0.3.0-alpha.N`, `0.3.0-beta.N`, `0.3.0-rc.N`, or
untagged development revisions such as `main` are outside the cross-release
promise until stable FerroCrypt release `0.3.0` is tagged.

### 11.5 Version-change rules

Changing the FerroCrypt software release does not by itself change any stored
version. A later release may continue to write all four initial `0x01`
encodings.

The affected stored version remains unchanged when the existing specification
provides a safe extension mechanism and older readers can follow the assigned
skip-or-reject rule. Compatible changes include:

- a new recipient type using the existing recipient-entry framing;
- an authenticated ignorable TLV tag;
- an authenticated critical TLV tag with explicitly specified opt-in support
  and rejection by unsupported readers;
- a new public- or private-key type under the existing encoding grammar; and
- implementation, API, CLI, UI, or performance changes that do not alter
  serialized semantics.

Sender authentication remains out of scope. A future sender-authentication
mechanism MAY use a critical TLV extension without changing the affected stored
version only if it defines a canonical signed transcript and preserves the
existing generic framing.

A new `.fcr` outer-container version is required for an incompatible change to:

- prefix, fixed-header, variable-header, or generic recipient-entry framing;
- header-MAC key derivation or authenticated transcript;
- payload-key derivation;
- the STREAM algorithm, chunk grammar, nonce, counter, final-flag construction,
  or payload AAD;
- `.fcr` TLV canonicality; or
- another generic outer-container rule that an existing reader cannot safely
  skip or reject.

The next such version SHOULD use `0x02` and SHOULD preserve the `FCR\0` magic
where practical. Later releases MUST retain read support for `.fcr`
outer-container version `0x01` (§11.4).

A new FCA archive version is required for an incompatible change to:

- FCA fixed-header or manifest-entry framing;
- path grammar;
- object-kind or archive-tree semantics;
- file-content ordering; or
- another archive rule that an FCA archive version `0x01` reader cannot safely
  skip or reject.

An FCA archive version `0x02` payload MAY remain inside `.fcr`
outer-container version `0x01` when the outer cryptographic container is
unchanged.

An incompatible public recipient-payload representation requires a new
public-key encoding version. An incompatible `private.key` representation
requires a new private-key encoding version. Only the affected domain changes,
and every new encoding version MUST map to its appropriate `KPS-N`.

A new key-pair suite is required only when public key material, private key
material, algorithm interpretation, or recipient compatibility changes so that
the existing logical pairing is insufficient. A new `KPS-N` does not by itself
require a new `.fcr` outer-container version or FCA archive version.

---

## 12. Diagnostics and conformance

### 12.1 Stable diagnostic taxonomy

The public conformance contract uses specification-level diagnostic class
identifiers. It does not use Rust type or variant names, English display text,
CLI formatting, or implementation-only subclasses.

Every rejected conformance case MUST carry both:

- a nonempty `condition_id` naming the exact rule exercised; and
- one diagnostic class from the following registry.

| Diagnostic class | Meaning | FerroCrypt mapping |
|---|---|---|
| `truncated` | Top-level `.fcr` framing ended before the prefix, declared header, or header MAC was complete | `InvalidFormat(Truncated)` |
| `bad_magic` | The top-level `FCR\0` magic does not match | `InvalidFormat(BadMagic)` |
| `not_a_key_file` | The input is not a recognized FerroCrypt key artifact | `InvalidFormat(NotAKeyFile)` |
| `wrong_kind` | An `FCR\0` artifact has the wrong kind for the requested operation | `InvalidFormat(WrongKind)` |
| `wrong_key_file_type` | A recognized key artifact is not the requested public/private key form | `InvalidFormat(WrongKeyFileType)` |
| `unsupported_outer_version` | A nonzero `.fcr` outer-container version is unsupported | `UnsupportedVersion(OlderFile)` or `UnsupportedVersion(NewerFile)` |
| `unsupported_fca_version` | A nonzero FCA archive version is unsupported | `InvalidFormat(UnsupportedArchiveVersion)` |
| `unsupported_public_key_version` | A nonzero public-key encoding version is unsupported | `UnsupportedVersion(OlderPublicKey)` or `UnsupportedVersion(NewerPublicKey)` |
| `unsupported_private_key_version` | A nonzero private-key encoding version is unsupported | `UnsupportedVersion(OlderKey)` or `UnsupportedVersion(NewerKey)` |
| `oversized_header` | The declared `.fcr` header exceeds the structural maximum | `InvalidFormat(OversizedHeader)` |
| `malformed_header` | The `.fcr` prefix or header violates a structural grammar or accounting rule assigned to this class | `InvalidFormat(MalformedHeader)` |
| `extension_region_too_large` | The declared `.fcr` header extension region exceeds its structural maximum | `InvalidFormat(ExtTooLarge)` |
| `malformed_tlv` | A TLV region violates framing or canonicality rules | `InvalidFormat(MalformedTlv)` |
| `unknown_critical_tlv` | A well-formed critical TLV is unsupported | `InvalidFormat(UnknownCriticalTag)` |
| `recipient_count_out_of_range` | The recipient count violates structural bounds | `InvalidFormat(RecipientCountOutOfRange)` |
| `malformed_type_name` | A recipient type name violates §3.3 | `InvalidFormat(MalformedTypeName)` |
| `malformed_recipient_entry` | Recipient framing or recipient-specific structural validation failed | `InvalidFormat(MalformedRecipientEntry)` |
| `recipient_flags_reserved` | A reserved recipient flag bit is nonzero | `InvalidFormat(RecipientFlagsReserved)` |
| `unknown_critical_recipient` | A well-formed critical recipient type is unsupported | `UnknownCriticalRecipient` |
| `no_supported_recipient` | No supported recipient type is present | `NoSupportedRecipient` |
| `incompatible_recipients` | The recipient set violates a mixing policy | `IncompatibleRecipients` |
| `recipient_unwrap_failed` | No supported recipient accepted the supplied credential | `RecipientUnwrapFailed` |
| `header_authentication_failed` | A candidate file key failed header-MAC verification | `HeaderTampered` or `HeaderMacFailedAfterUnwrap` |
| `invalid_kdf_parameters` | Stored KDF parameters violate structural rules | Any `InvalidKdfParams` variant |
| `resource_cap_exceeded` | Structurally valid data exceeds configured local resource policy | Relevant header, recipient, KDF, key, or archive `*CapExceeded` variant |
| `payload_authentication_failed` | Payload-chunk authentication failed | `PayloadTampered` |
| `payload_truncated` | The encrypted payload ended before a valid final chunk | `PayloadTruncated` |
| `malformed_payload_stream` | The payload STREAM transcript violates structural rules | `InvalidFormat(MalformedPayloadStream)` |
| `extra_data_after_payload` | Bytes follow the authenticated final payload chunk | `ExtraDataAfterPayload` |
| `payload_chunk_count_exceeded` | The payload exceeds the permitted counter/chunk range | `PayloadChunkCountExceeded` |
| `malformed_archive` | The authenticated FCA payload violates header, manifest, or content-region grammar | `MalformedArchive` |
| `unsafe_archive_path` | An FCA path violates the portable path-safety grammar | `UnsafeArchivePath` |
| `invalid_archive_tree` | The FCA manifest violates tree-shape or collision rules | `InvalidArchiveTree` |
| `malformed_public_key` | A public-key artifact violates its encoding or canonicality rules | `InvalidFormat(MalformedPublicKey)` |
| `unsupported_key_type` | A well-formed key type is unsupported | `UnsupportedKeyType` |
| `malformed_private_key` | A private-key artifact violates its encoding or post-unlock consistency rules | `InvalidFormat(MalformedPrivateKey)` |
| `private_key_unlock_failed` | Private-key authentication failed for the supplied passphrase or modified file | `KeyFileUnlockFailed` |

Conformance case rows store only the diagnostic-class identifier. The final
column documents FerroCrypt's structured-error mapping for replay; it does not
make a Rust type name part of the cross-language corpus schema or authorize
renaming a public FerroCrypt error variant.

Different exact conditions may intentionally map to one class. For example, the
credential-independent all-zero X25519 ephemeral value and a canonical nonzero
small-order value that produces an all-zero shared secret have distinct
`condition_id` values but both map to `malformed_recipient_entry`. The latter
condition uses `condition_id = x25519_all_zero_shared_secret`.

Validation phase is observable where it changes the class. In particular, an
undersized declared `header_len` is not rejected during prefix parsing merely
for being below 31. A reader first reads exactly the declared header and the
32-byte header MAC. If the MAC bytes are incomplete, the class is `truncated`;
if the complete framing is present and `header_fixed` cannot fit, the class is
`malformed_header`.

The initial corpus pins this boundary with:

```text
header_len = 0, no header-MAC bytes       -> truncated
header_len = 0, all 32 header-MAC bytes   -> malformed_header
```

Implementations MAY expose more specific local subclasses, but their corpus
replay layer MUST map structured errors to the stable class registry without
parsing English text. Existing class identifiers and meanings MUST NOT be
renamed or repurposed. New stable classes MAY be appended when a future
normative distinction or shipping implementation requires one.

FerroCrypt's stable English display strings use sentence case without terminal
punctuation and state only what the error class proves. A newer-version class
may say that newer FerroCrypt is needed. An unknown recipient or key type MUST
NOT prescribe an upgrade because it may belong to an external implementation.
An unknown critical TLV tag denotes a required feature from a later compatible
FerroCrypt specification (§6), so it MUST use this exact form, substituting the
tag as four uppercase hexadecimal digits:

```text
Newer FerroCrypt is needed for file feature tag 0xNNNN
```

Unsupported encoding versions MUST use these exact forms, substituting the raw
byte as two uppercase hexadecimal digits:

```text
Newer FerroCrypt is needed for .fcr version byte 0xNN
Newer FerroCrypt is needed for FCA archive version byte 0xNN
Newer FerroCrypt is needed for public-key version byte 0xNN
Newer FerroCrypt is needed for private-key version byte 0xNN
```

For FerroCrypt's retained older-version error variants, the English display
strings MUST use these exact forms:

```text
Unsupported older .fcr version byte 0xNN
Unsupported older public-key version byte 0xNN
Unsupported older private-key version byte 0xNN
```

The display forms use compact domain names because the full message has to fit
FerroCrypt's status-line width. The §11.1 canonical names remain the normative
prose vocabulary; the four compact prefixes stay mutually distinct.

For the encodings defined here, zero is reserved and structurally malformed in
all four stored version domains: `.fcr`, FCA, public-key, and private-key. Every
defined nonzero encoding version is supported. An older-version diagnostic is
therefore unreachable for current valid artifacts. If a later implementation
rejects a valid artifact covered by an earlier compatibility baseline, that is
a compatibility defect, not a reason to install an older release or regenerate
a key.

English wording is not part of the cross-language conformance contract; callers
MUST use structured errors rather than parse display strings. The raw `u8`
version value MUST remain available in the structured version error.

### 12.2 Invariant and capability-relative expectations

Structural, canonicality, authentication, and security requirements are
invariant. A later implementation MUST NOT reclassify malformed framing,
reserved bits, bad authentication tags, unsafe archive paths, or prohibited
X25519 shared secrets as valid.

An outcome caused only by the implementation's current feature set is
capability-relative. Examples include an unsupported future stored version, an
unknown critical recipient or TLV, and a grammar-valid but unsupported key
type.

The frozen corpus identifies such features with these capability-ID forms:

```text
outer_version:0xNN
fca_version:0xNN
public_key_version:0xNN
private_key_version:0xNN
recipient_type:<type_name>
outer_tlv:0xNNNN
private_key_tlv:0xNNNN
fca_archive_tlv:0xNNNN
fca_entry_tlv:0xNNNN
key_type:<type_name>
```

In these forms, `NN` and `NNNN` denote exactly two and four uppercase
hexadecimal digits, respectively. `<type_name>` is the exact grammar-valid type
name from §3.3.

The reserved `0x00` value in any stored version domain MUST NOT be represented
as a capability ID. Reserved-zero cases are invariant.

An invariant case MUST use `capability_id = -`. A capability-relative case MUST
name exactly one relevant capability ID.

Every replay implementation MUST declare its supported capability-ID set before
evaluating cases. It MUST assert an invariant case unconditionally. It MUST
assert a capability-relative case's stored outcome when the named capability is
absent, and MUST omit only that outcome assertion when the capability is
present. Even when the outcome assertion is omitted, the case row, bytes,
digest, schema, and provenance remain subject to validation.

Equivalently:

```text
assert_stored_outcome =
    expectation_scope == invariant
    OR capability_id NOT IN declared_capabilities
```

When a capability becomes supported, its behavior MUST be covered by new cases
appended in a later corpus revision. The earlier capability-relative case
remains immutable evidence of the earlier baseline; it is not edited or
reinterpreted.

### 12.3 Frozen public conformance corpus

**Identity and schema.** The frozen public corpus is stored at:

```text
ferrocrypt-lib/testvectors/wire/
```

It is distinct from the mutable development suite at `testvectors/suite/`,
internal regression fixtures at `tests/fixtures/`, the valid-only compatibility
net at `tests/fixtures/frozen/v0.3.0/`, and primitive known-answer material at
`testvectors/kat/`.

For the initial stable publication:

```text
SCHEMA-VERSION  = 1
CORPUS-REVISION = 1
baseline_id     = 0.3.0
```

`SCHEMA-VERSION` identifies the manifest grammar, `CORPUS-REVISION` identifies
append-only corpus content, and `baseline_id` identifies the compatibility
promise first evidenced by a case. This publication is **the `0.3.0` frozen
conformance corpus**.

Revision 1 uses this repository layout:

```text
testvectors/wire/
├── README.md
├── SCHEMA-VERSION
├── CORPUS-REVISION
├── baselines.tsv
├── diagnostic-classes.tsv
├── credentials.tsv
├── origins.tsv
├── cases.tsv
├── errata.tsv
├── artifacts/
│   ├── fcr/
│   ├── public-key/
│   └── private-key/
├── expected/
│   ├── plaintext/
│   ├── public-key/
│   └── private-key/
├── kat/
│   └── stream/
└── tools/
```

The manifest tables use these exact columns:

- `baselines.tsv`: `baseline_id`, `established_by_release`,
  `parent_baseline_id`, `introduced_in_corpus_revision`;
- `diagnostic-classes.tsv`: `class_id`, `description_ref`,
  `description_sha3_256`, `introduced_in_corpus_revision`;
- `credentials.tsv`: `credential_id`, `kind`, `primary_ref`,
  `primary_sha3_256`, `secret_ref`, `secret_sha3_256`,
  `introduced_in_release`, `introduced_in_corpus_revision`;
- `origins.tsv`: `origin_id`, `origin_kind`, `anchor_case_id`,
  `payload_key_ref`, `payload_key_sha3_256`, `stream_nonce_hex`,
  `introduced_in_release`, `introduced_in_corpus_revision`;
- `cases.tsv`: `case_id`, `case_type`, `artifact_ref`,
  `artifact_sha3_256`, `first_required_by_baseline`,
  `introduced_in_release`, `introduced_in_corpus_revision`, `construction`,
  `parent_case_id`, `payload_transcript_kind`, `payload_origin_ids`,
  `credential_id`, `outcome`, `expectation_scope`, `capability_id`,
  `condition_id`, `diagnostic_class`, `expected_ref`,
  `expected_sha3_256`;
- `errata.tsv`: `erratum_id`, `affected_case_id`,
  `effective_corpus_revision`, `rationale_ref`, `rationale_sha3_256`,
  `replacement_case_id`, `introduced_in_release`.

All tables MUST be UTF-8 with LF line endings, one header comment naming the
columns, and tab-separated fields. `#` begins only a whole-line comment; `-`
represents an inapplicable scalar; and comma-separated IDs represent a list.
List elements MUST be separated by one comma with no surrounding whitespace.
Fields MUST NOT contain tabs, CR, LF, `..`, absolute paths, or backslashes.
Baseline, class, credential, origin, case, erratum, and condition IDs MUST
match `[a-z0-9][a-z0-9._-]*`. Capability IDs instead use the structured forms
defined in §12.2. A non-`-` digest field MUST contain exactly 64 lowercase
hexadecimal characters. Except for the payload-key commitment defined below,
each non-`-` `*_sha3_256` field MUST equal the SHA3-256 digest of the exact
bytes named by its corresponding non-`-` `*_ref` field. References MUST use
POSIX separators and be relative to `testvectors/wire/`.

Each `diagnostic-classes.tsv` `description_ref` MUST identify stable explanatory
text for the class.

The corpus `README.md` MUST name the authoritative generation and reproduction
commands and record tool provenance. Corpus-generation code is test tooling,
not part of FerroCrypt's public library API.

The initial schema permits these exact enumerated values:

```text
credentials.tsv kind:              passphrase | private_key | none
origins.tsv origin_kind:            fcr_payload | stream_kat
cases.tsv case_type:                fcr_decrypt | public_key_decode
                                    | private_key_open | private_key_validate
                                    | stream_encrypt_kat
cases.tsv construction:             original | mutation | fabricated
cases.tsv payload_transcript_kind:  origins | none | not_applicable
cases.tsv outcome:                  accept | reject | transcript_equal
cases.tsv expectation_scope:        invariant | capability_relative
```

For `payload_transcript_kind = origins`, `payload_origin_ids` MUST be a
nonempty, duplicate-free list of existing origins in order of first
contribution. An ordinary `.fcr` case lists one origin; a ciphertext splice
lists every contributing origin. `none` means a `.fcr`-shaped structural case
has no genuine encrypted payload transcript. `not_applicable` is required for
artifacts that do not contain a `.fcr` payload stream. Every
`case_type = fcr_decrypt` row MUST therefore use `origins` or `none`; every
other case type MUST use `not_applicable`. `payload_origin_ids` MUST be `-` for
`none` and `not_applicable`. `parent_case_id` is required exactly for
mutations and MUST be `-` for other construction types. Construction lineage
and cryptographic provenance are independent.

Every rejected case MUST provide a nonempty `condition_id` and
`diagnostic_class` and MUST NOT contain an English-message expectation. Every
accepted or transcript-equality case MUST provide a byte-exact semantic result
through `expected_ref` and `expected_sha3_256`. For `.fcr` acceptance this is
the expected plaintext; for key acceptance it is a byte-exact record of decoded
fields or key material; for transcript equality it is expected ciphertext.
Validation success alone is not sufficient evidence. `credential_id` is
required whenever the case action requires a credential. Non-reject outcomes
MUST use `diagnostic_class = -`.

The initial `baselines.tsv` row is:

```text
0.3.0    0.3.0    -    1
```

A later baseline names its immediate parent and MUST be a superset of every
ancestor. For a passphrase credential, `primary_ref` identifies the byte-exact
passphrase and `secret_ref` is `-`. For a private-key credential, `primary_ref`
identifies `private.key` and `secret_ref` identifies its byte-exact unlock
passphrase. A `none` credential denotes an action that needs no credential
material. All credentials are public test material; their filenames and the
corpus `README.md` MUST make that status explicit and warn against operational
reuse.

**Publication and contract boundary.** The stable `v0.3.0` Git tag permanently
addresses the initial publication at:

```text
https://github.com/alexylon/ferrocrypt/tree/v0.3.0/ferrocrypt-lib/testvectors/wire
```

The compatibility baseline and frozen corpus are distinct. The baseline is the
normative read-compatibility promise; the corpus is committed evidence that
implementations honor it.

The frozen contract comprises the manifest rows, referenced artifact and
expected-result bytes, their digests, and their semantic expectations. It does
not include English error prose or Rust type names. The manifests also record
each case's credential, construction lineage, first required baseline,
expectation scope, and capability ID where applicable.

**Revision and provenance policy.** Existing manifest rows, referenced artifact
bytes, expected results, digests, class meanings, credentials, and provenance
records MUST NOT be edited, removed, reordered, or regenerated.

`CORPUS-REVISION` increments whenever a case, origin, credential, diagnostic
class, baseline, or erratum is appended. Corrections use append-only errata
and, where needed, a new replacement case; an erratum MUST NOT conceal an
implementation regression, and tagged history remains unchanged. Its rationale
MUST state whether the error concerns generation, metadata, specification, or
classification.
Current-revision replay excludes an affected case only at or after the
erratum's `effective_corpus_revision`; a replacement is a new case with its own
bytes, digest, and provenance. `replacement_case_id` MAY be `-` when no
replacement is appropriate. An incompatible manifest-grammar change increments
`SCHEMA-VERSION`; consumers MUST still be able to read the earlier schema at the
stable tag that published it. A corpus revision does not by itself change any
of the four stored version domains; one changes only when its serialized
semantics change incompatibly.

Provenance is recorded per actual payload STREAM encryption operation, not per
case or per accept/reject outcome. When copied, mutated, fabricated, or spliced
containers include genuine payload ciphertext, they reference its contributing
encryption origins in order of first contribution. Each origin is counted once
regardless of how many cases reference it. Every origin has an immutable anchor
case. `stream_nonce_hex` MUST be exactly 38 lowercase hexadecimal characters
representing a 19-byte prefix. Independent origins MUST use distinct nonce
prefixes and SHOULD use distinct payload keys. A STREAM KAT origin MUST
reference its fixed payload key through `payload_key_ref`; a `.fcr` payload
origin normally uses `payload_key_ref = -` and records only the
`payload_key_sha3_256 = SHA3-256(payload_key)` commitment. The replay derives
and verifies that commitment wherever credentials permit. All committed
credentials, fixed keys, and nonces are public test material and MUST NOT be
reused operationally.

**Minimum revision-1 evidence.** Corpus revision 1 MUST cover at least:

| Area | Required evidence |
|---|---|
| Valid `.fcr` files | Native `argon2id`; native X25519; multiple X25519 recipients; empty, 1-byte, exact-65,536-byte, 65,537-byte, and multi-chunk payloads |
| Prefix and framing | Bad magic; an invariant `.fcr` outer-container version `0x00` case classified as `malformed_header`; a `.fcr` outer-container version `0x02` capability case classified as `unsupported_outer_version`; wrong kind; nonzero flags; the structural maximum; truncation at each framing boundary; and both undersized-header precedence outcomes |
| Header | Fixed-field accounting, recipient count and range, extension length, header-MAC tamper after successful unwrap, and exact authenticated scope |
| Recipient framing | Truncated entry headers and bodies, invalid lengths, malformed type names, reserved flags, unknown critical and ignorable recipients, no supported recipient, and illegal mixing |
| `argon2id` recipient | Valid, wrong passphrase, every body field tampered, invalid body length, invalid and locally capped KDF parameters, and recipient flags |
| X25519 recipient | Valid, multiple recipients, wrong private key, every body field tampered, invalid length and flags, noncanonical and all-zero ephemeral preflight, and a canonical nonzero small-order ephemeral value that produces an all-zero shared secret |
| `.fcr` TLV | Empty region, valid unknown ignorable, unknown critical, reserved tag, duplicate and out-of-order tags, truncated header and value, and oversized region and value |
| Payload STREAM | Independent byte-exact known-answer tests, authentication failure, truncation, forbidden empty final chunk after data, trailing data, exact-boundary finalization, and chunk-count-boundary evidence |
| `public.key` | Canonical file; optional LF; checksum, padding, case, whitespace, and length failures; an invariant public-key encoding version `0x00` case classified as `malformed_public_key`; a public-key encoding version `0x02` capability case classified as `unsupported_public_key_version`; unsupported type; canonical X25519 material; aliases; field-prime boundaries; all zero; and wrong lengths |
| `private.key` | Canonical valid and openable file; wrong passphrase; cleartext-AAD and wrapped-secret tamper; malformed, truncated, and trailing data; wrong kind or key-file type; an invariant private-key encoding version `0x00` case classified as `malformed_private_key`; a private-key encoding version `0x02` capability case classified as `unsupported_private_key_version`; caps; TLVs; and public/secret consistency |
| FCA fixed header | Valid file and directory roots; bad magic; an invariant FCA archive version `0x00` case classified as `malformed_archive`; an FCA archive version `0x02` capability case classified as `unsupported_fca_version`; flags; counts; archive-extension length; manifest length; total-byte accounting; and truncation |
| FCA manifest and tree | File and directory entries, acceptance of canonical and permitted noncanonical order, duplicate and ASCII-case-colliding paths, missing parents, child under file, multiple roots, invalid kinds, modes, sizes, and totals |
| FCA paths | Absolute, parent, and current components; separators; NUL, control, and reserved characters; trailing dot and space; Windows device names; depth, component, and total-length limits; valid Unicode |
| FCA extensions | Archive-level and per-entry TLV namespaces: ignorable, critical, malformed, and reserved tags; per-region, per-value, and aggregate entry-extension caps |
| FCA content and extraction | Exact file contents, short content, trailing content, unsafe or unsupported entries, and representative extraction rejection classes without unsafe final output |
| Resource policy | Structural maxima and configurable local caps for headers, recipients, KDFs, key files, manifests, paths, plaintext totals, and extension regions |

The X25519 during-operation all-zero-shared-secret case MUST use this canonical,
nonzero small-order ephemeral public value:

```text
e0 eb 7a 7c 3b 41 b8 ae 16 56 e3 fa f1 9f c4 6a
da 09 8d eb 9c 32 b1 fd 86 62 05 16 5f 49 b8 00
```

It MUST pass the credential-independent canonical/nonzero preflight, reach the
X25519 operation, produce the prohibited all-zero shared secret, and reject
with `condition_id = x25519_all_zero_shared_secret` and diagnostic class
`malformed_recipient_entry`.

**Independent STREAM transcripts.** The corpus MUST include independent,
byte-exact payload STREAM known-answer tests (KATs) with these minimum
transcripts:

| Case ID | Plaintext bytes | Chunk transcript | Ciphertext bytes |
|---|---:|---|---:|
| `stream-empty` | 0 | counter 0, final flag `0x01` | 16 |
| `stream-exact-65536` | 65,536 | counter 0, final flag `0x01` | 65,552 |
| `stream-two-chunk-65537` | 65,537 | counter 0, flag `0x00`; counter 1, flag `0x01` | 65,569 |

The plaintext inputs MUST be deterministic and byte-exact; their committed
bytes and SHA3-256 digests are authoritative.

Each KAT MUST use its own fixed payload key and 19-byte nonce prefix. The
expected ciphertext MUST be generated by an independent XChaCha20-Poly1305
implementation using empty AAD and:

```text
full_nonce = stream_nonce(19) || counter:u32_be || final_flag:u8
```

The corpus validator MUST reject duplicate KAT payload keys, duplicate KAT
nonce prefixes, duplicate effective `(payload_key, full_nonce)` pairs among KAT
chunks, and duplicate nonce prefixes across independent corpus origins.
Mutated and spliced cases reference existing origins and do not represent new
encryption operations.

The initial expected bytes MUST be produced by a committed PyNaCl/libsodium
oracle that is independent of FerroCrypt's production implementation. The
oracle MUST emit all fixed inputs and expected outputs deterministically, MUST
import no FerroCrypt production code, MUST record the PyNaCl and libsodium
versions used for initial generation, and MUST remain a generation and
reproduction tool rather than a runtime dependency. It MUST be committed in the
corpus with the KATs. Continuous integration compares FerroCrypt output with the
committed bytes and does not install or run PyNaCl. Round-trip agreement between
FerroCrypt's own writer and reader is not sufficient transcript evidence.

**Replay requirements.** Normal conformance replay MUST parse every manifest
table strictly; verify every referenced digest; reject duplicate IDs, invalid
paths and list forms, and dangling references; apply effective errata without
deleting history; exercise `.fcr`, public-key, and private-key cases through
public interfaces where possible; apply §12.2's capability rule; compare
successful results with their exact expected bytes or decoded fields; and map
structured errors to the stable diagnostic taxonomy without comparing display
text.

Crate-internal replay additionally MUST encrypt and decrypt the committed
STREAM KATs, derive payload keys for accessible `.fcr` origin anchors, verify
their commitments and origin/nonce hygiene, and prove that the canonical
small-order X25519 vector reaches the during-X25519 all-zero-shared-secret check
rather than the zero-ephemeral preflight.

### 12.4 Conformance claims

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

A conforming implementation that claims the `0.3.0` compatibility baseline MUST
pass every applicable invariant case and every asserted capability-relative
case in corpus revision 1. A conforming FerroCrypt release MUST ship committed
vectors and publish its frozen corpus at a stable HTTPS URL. Vectors MUST cover
valid and invalid `.fcr`, `public.key`, `private.key`, payload STREAM,
recipient, TLV, KDF, prefix, and FCA cases, including archive-level and
per-entry extension regions. Armor vectors are required only for a release that
ships the optional armor transport described in §10.

Each recipient type specification MUST publish positive, wrong-key, malformed,
and tamper vectors, including unknown-non-critical, illegal-mixing, and
header-MAC-failure cases where applicable. Recipient vectors SHOULD be reusable
by independent implementations without requiring access to implementation-
specific code.

A release MUST NOT satisfy conformance by regenerating a frozen artifact around
changed behavior. If an implementation change breaks an invariant frozen case,
the implementation or specification has regressed; the case is not rewritten.

---

## 13. Quick reference

```text
.fcr = prefix(12) || header(header_len) || header_mac(32) || payload
```

### 13.1 Encrypted-file prefix

| Field | Size | Value |
|---|---:|---|
| `magic` | 4 | `FCR\0` |
| `version` | 1 | `0x01` (`.fcr` outer-container version) |
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

Passphrases are exact UTF-8 byte strings of 1 to 4,096 bytes. Every serialized
native X25519 public value is a canonical 32-byte little-endian field encoding
strictly below `2^255 - 19`; readers reject aliases rather than normalize them.

HKDF info strings:

```text
ferrocrypt/v1/recipient/argon2id/wrap
ferrocrypt/v1/recipient/x25519/wrap
ferrocrypt/v1/private-key/wrap
ferrocrypt/v1/payload
ferrocrypt/v1/header
```

Core recipient design rule for `.fcr` outer-container version `0x01`:

```text
Keep the .fcr container stable and simple.
Put recipient-specific cryptography in independently specified recipient types.
Require every recipient type to be namespaced, validated, documented, and tested.
```

### 13.6 FCA archive version `0x01` payload

```text
fca_payload = fca_header(27) || archive_ext || manifest || file_contents
```

FCA fixed header:

| Field | Size | Value / meaning |
|---|---:|---|
| `magic` | 4 | `FCA\0` |
| `version` | 1 | `0x01` (FCA archive version) |
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

FCA archive version `0x01` object kinds:

| Kind | Meaning |
|---:|---|
| `0x01` | regular file |
| `0x02` | directory |

FCA archive version `0x01` extension rule:

```text
Use shared TLV grammar.
Unknown ignorable tags are skipped.
Unknown critical tags reject before filesystem output.
Unknown object kinds reject.
Validate the complete manifest and every TLV before extraction.
```
