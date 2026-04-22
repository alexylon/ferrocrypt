# FerroCrypt Format Specification

This document specifies the current on-disk formats used by `ferrocrypt-lib`:

- encrypted payload files: `*.fcr`
- hybrid public key files: `public.key`
- hybrid private key files: `private.key`

It covers:

- file format layout
- key file layout
- compatibility guarantees
- minor/major versioning rules
- what is and is not authenticated
- archive semantics

This specification describes the **current format family** implemented by the library on this branch. The v3/v4 family is a breaking change that has not yet shipped in a published crate release — see `CHANGELOG.md [Unreleased]`. The crate version and the on-disk format version are separate.

This document is meant to be concrete rather than cryptic: the current field order, byte sizes, and compatibility rules are described explicitly below.

---

## 1. Terminology

- **Encoded** means a current `.fcr` header field stored using FerroCrypt's triple-replication format.
- **Decoded** means the original logical bytes recovered after majority-vote decoding.
- **Header** means all bytes before the encrypted payload ciphertext begins.
- **Payload** means the encrypted TAR stream after the header.

---

## 2. Triple-replication encoding

In the current encrypted-file format family (**symmetric `v3.0`, hybrid `v4.0`**), **all defined encrypted-file header fields** are stored using a simple triple-replication scheme for error correction.

### Wire format

For an input byte string `data`:

```text
[pad, pad, pad, copy_0, copy_1, copy_2]
```

Where:

- `pad` is `0` if the input length is even
- `pad` is `1` if the input length is odd
- odd-length inputs are zero-padded to even length before replication
- the three `pad` bytes are themselves replicated so a single corrupted pad byte can be corrected
- each output byte position is recovered by majority vote across the three copies

### Encoded size

For an original logical size `N`:

```text
padded = N if N is even, else N + 1
encoded_size = 3 + 3 * padded
```

Examples:

| Logical size | Encoded size |
|---|---:|
| 8 | 27 |
| 12 | 39 |
| 19 | 63 |
| 24 | 75 |
| 32 | 99 |
| 136 | 411 |

### Scope

For the current encrypted-file format family, every defined `.fcr` header field is triple-replicated.

This does **not** apply to:

- `public.key`
- `private.key`

It also does **not** imply that a future optional trailing minor-version field must use triple replication, although the current defined header does.

---

## 3. Encrypted file format (`.fcr`)

Every encrypted FerroCrypt file consists of:

```text
[header][ciphertext payload]
```

The header identifies the mode, version, and decryption parameters. The payload is a streamed XChaCha20-Poly1305 encryption of a TAR archive.

### 3.1 Shared encrypted-file prefix

Every `.fcr` file begins with a logical 8-byte prefix, stored in encoded form.

#### Logical prefix layout

| Offset | Size | Field | Meaning |
|---|---:|---|---|
| 0 | 1 | Magic | `0xFC` |
| 1 | 1 | Type | `0x53` = symmetric, `0x48` = hybrid |
| 2 | 1 | Major version | breaking format changes |
| 3 | 1 | Minor version | backward-compatible additions |
| 4..=5 | 2 | Flags | big-endian `u16`, currently must be `0` |
| 6..=7 | 2 | Extension length | big-endian `u16`, logical size of the authenticated `ext_bytes` region (0 when no extensions) |

#### Stored size

- logical size: `8`
- encoded size: `27`

#### Current values

- symmetric encrypted-file major version: `3`
- hybrid encrypted-file major version: `4`
- encrypted-file minor version: `0`

Symmetric and hybrid major versions increment independently based on per-mode format changes. They are not required to match each other or the crate version, and the current asymmetry (`3` / `4`) reflects the independent development history of each mode.

---

## 4. Symmetric `.fcr` layout

Symmetric mode uses:

- Argon2id for password-based key derivation
- HKDF-SHA3-256 for subkey separation
- XChaCha20-Poly1305 stream encryption for the payload
- HMAC-SHA3-256 for header authentication

### 4.1 Header fields and order

In the current `v3.0` symmetric format, every defined header field listed below is stored in encoded form and appears in this order:

1. file prefix (`8` logical bytes, stored encoded)
2. Argon2 salt (`32` logical bytes, stored encoded)
3. HKDF salt (`32` logical bytes, stored encoded)
4. KDF params (`12` logical bytes, stored encoded)
5. stream nonce (`19` logical bytes, stored encoded)
6. `ext_bytes` — authenticated extension region (`ext_len` logical bytes, stored encoded; `ext_len = 0` in `v3.0`)
7. HMAC tag (`32` logical bytes, stored encoded)
8. ciphertext payload

### 4.2 KDF params layout

KDF params are stored as three big-endian `u32` values:

| Offset | Size | Field |
|---|---:|---|
| 0..=3 | 4 | `mem_cost` (KiB) |
| 4..=7 | 4 | `time_cost` |
| 8..=11 | 4 | `lanes` |

Current default values used for newly encrypted files are:

- `mem_cost = 1_048_576` KiB (1 GiB)
- `time_cost = 4`
- `lanes = 4`

Current readers additionally enforce safety bounds on header-supplied KDF params:

- `8 * lanes <= mem_cost <= 2 * 1024 * 1024` KiB (2 GiB)
- `1 <= time_cost <= 12`
- `1 <= lanes <= 8`

The `mem_cost` lower bound of `8 * lanes` is an Argon2 requirement (memory must be at least 8 × parallelism).

Files outside those bounds are rejected by current readers.

Library callers additionally get a **default** `KdfLimit` of `1_048_576` KiB (1 GiB), matching the writer's own default. Files whose header `mem_cost` exceeds this ceiling are rejected with `ExcessiveWork` unless the caller opts into a higher limit. The 2 GiB bound above is the hard structural maximum enforced regardless of caller choice.

### 4.3 Key derivation pipeline

Symmetric mode derives keys as follows:

```text
passphrase + Argon2 salt + KDF params
    -> Argon2id -> 32-byte IKM
IKM + HKDF salt
    -> HKDF-SHA3-256
    -> 32-byte encryption key
    -> 32-byte header HMAC key
```

### 4.4 Stored sizes (v3.0 symmetric, `ext_len = 0`)

| Field | Logical size | Stored size |
|---|---:|---:|
| Prefix | 8 | 27 |
| Argon2 salt | 32 | 99 |
| HKDF salt | 32 | 99 |
| KDF params | 12 | 39 |
| Stream nonce | 19 | 63 |
| `ext_bytes` | 0 | 3 |
| HMAC tag | 32 | 99 |
| **Total header size** | — | **429 bytes** |

So a current symmetric `v3.0` file (with no extensions) is laid out as:

```text
0..27    encoded prefix
27..126  encoded Argon2 salt
126..225 encoded HKDF salt
225..264 encoded KDF params
264..327 encoded stream nonce
327..330 encoded ext_bytes (empty)
330..429 encoded HMAC tag
429..end ciphertext payload
```

The `hmac_key` and `encryption_key` are derived from the same passphrase + Argon2 salt + KDF params + HKDF salt, so a wrong passphrase or a tampered key-derivation field produces a wrong `hmac_key` and HMAC verification fails before any ciphertext is read. No separate key-verification hash is required; both "wrong passphrase" and "header tampered" surface as a single `HeaderAuthenticationFailed` error.

A future minor version that ships `ext_len = L` logical bytes of authenticated
extension data adds exactly `encoded_size(L) - encoded_size(0)` bytes before the
HMAC tag; all other offsets shift accordingly.

---

## 5. Hybrid `.fcr` layout

Hybrid mode uses:

- ephemeral X25519 ECDH key agreement with the recipient's static public key
- HKDF-SHA256 to derive an envelope wrapping key from the shared secret
- XChaCha20-Poly1305 envelope encryption for per-file random keys
- XChaCha20-Poly1305 stream encryption for the payload
- HMAC-SHA3-256 for the outer header

The envelope transports two per-file random keys:

- payload encryption key (`32` bytes)
- outer HMAC key (`32` bytes)

### 5.1 Header fields and order

In the current `v4.0` hybrid format, every defined header field listed below is stored in encoded form and appears in this order:

1. file prefix (`8` logical bytes, stored encoded)
2. sealed envelope (`136` logical bytes, stored encoded)
3. stream nonce (`19` logical bytes, stored encoded)
4. `ext_bytes` — authenticated extension region (`ext_len` logical bytes, stored encoded; `ext_len = 0` in `v4.0`)
5. HMAC tag (`32` logical bytes, stored encoded)
6. ciphertext payload

### 5.2 Envelope layout

The decoded envelope is:

| Offset | Size | Field |
|---|---:|---|
| 0..=31 | 32 | ephemeral X25519 public key |
| 32..=55 | 24 | XChaCha20-Poly1305 envelope nonce |
| 56..=135 | 80 | envelope ciphertext |

Envelope ciphertext is the encrypted form of:

```text
[payload_encryption_key (32) | header_hmac_key (32)]
```

So the envelope plaintext is `64` bytes and the ciphertext is `64 + 16 = 80` bytes.

### 5.3 Envelope key derivation

The envelope wrapping key is derived via HKDF-SHA256:

- **IKM:** X25519 shared secret (`ephemeral_secret.diffie_hellman(recipient_public)`)
- **Salt:** `ephemeral_public (32) || recipient_public (32)` (64 bytes)
- **Info:** `b"ferrocrypt hybrid envelope key v4"`
- **Output:** 32-byte wrapping key for XChaCha20-Poly1305

All-zero shared secrets (indicating a small-order public key) are rejected before key derivation.

### 5.4 Stored sizes (v4.0 hybrid, `ext_len = 0`)

| Field | Logical size | Stored size |
|---|---:|---:|
| Prefix | 8 | 27 |
| Envelope | 136 | 411 |
| Stream nonce | 19 | 63 |
| `ext_bytes` | 0 | 3 |
| HMAC tag | 32 | 99 |
| **Total header size** | — | **603 bytes** |

So a current hybrid `v4.0` file (with no extensions) is laid out as:

```text
0..27    encoded prefix
27..438  encoded envelope
438..501 encoded stream nonce
501..504 encoded ext_bytes (empty)
504..603 encoded HMAC tag
603..end ciphertext payload
```

---

## 6. Payload format

After the header, both symmetric and hybrid modes store the encrypted payload.

### 6.1 What the payload is

The payload is a **TAR archive** encrypted as a streaming XChaCha20-Poly1305 AEAD stream.

### 6.2 Streaming behavior

Plaintext TAR bytes are processed in chunks of:

- plaintext chunk size: `65536` bytes (64 KiB)
- authentication tag per chunk: `16` bytes

Non-final chunks carry `65536` plaintext bytes plus a `16`-byte tag.
The stream ends with one final AEAD chunk, which may be shorter and may be
only a tag if the plaintext length is an exact multiple of `65536` bytes.

### 6.3 Maximum stream size

The streaming AEAD construction uses a 32-bit big-endian chunk counter
(`chacha20poly1305::stream::EncryptorBE32` / `DecryptorBE32`). With 64 KiB
plaintext chunks, a single encrypted stream can therefore carry at most
`2^32 × 65_536 = 2^48` bytes of plaintext (≈ **256 TiB**) before the counter
is exhausted. The archive layer produces a TAR stream, so this is a limit
on the total size of the *archived* payload, not on any individual file
inside it.

Current implementations do not enforce this bound explicitly because no
realistic input reaches it. Behavior at the boundary is defined by the
underlying `chacha20poly1305` crate's counter-overflow handling.

### 6.4 What is inside the TAR stream

- If the input was a file, the TAR contains one top-level file entry with the original file name.
- If the input was a directory, the TAR contains one top-level directory entry with the directory name, then its accepted descendants.

Extraction enforces the same single-root invariant (see §11.3), so a crafted archive carrying a second top-level root is rejected.

The encrypted payload does **not** expose plaintext file contents.

The header also does **not** expose filenames or timestamps.

---

## 7. Key file formats

FerroCrypt hybrid mode uses two key files:

- `public.key`
- `private.key`

Key files use a separate, non-replicated 8-byte header.

### 7.1 Shared key-file header

| Offset | Size | Field | Meaning |
|---|---:|---|---|
| 0 | 1 | Magic | `0xFC` |
| 1 | 1 | Type | `0x50` = public, `0x53` = private |
| 2 | 1 | Version | per-key-type (public = `3`, private = `4`) |
| 3 | 1 | Algorithm | `0x01` = X25519 |
| 4..=5 | 2 | Data length | big-endian `u16`, number of body bytes after the header |
| 6..=7 | 2 | Flags | big-endian `u16`, currently must be `0` |

The version byte is version-per-key-type, not a single family version: `public.key` is at version `3` and `private.key` is at version `4`. They can evolve independently. See §9.2 for why the starting numbers aren't `1`.

### 7.2 `public.key` layout

A public key file is:

```text
[key header][32-byte raw X25519 public key]
```

#### Sizes

- header: `8` bytes
- body: `32` bytes
- total file size: `40` bytes

### 7.3 `private.key` layout

A private key file is:

```text
[key header]
[KDF params]
[Argon2 salt]
[XChaCha20-Poly1305 nonce]
[ext_len:u16 BE]
[ext_bytes]
[encrypted private-key blob]
```

#### Body layout

| Offset | Size | Field |
|---|---:|---|
| 0..=11 | 12 | KDF params |
| 12..=43 | 32 | Argon2 salt |
| 44..=67 | 24 | XChaCha20-Poly1305 nonce |
| 68..=69 | 2 | `ext_len` (big-endian `u16`) |
| 70..=(70 + ext_len − 1) | `ext_len` | `ext_bytes` (authenticated extension region) |
| 70 + `ext_len`..=(70 + `ext_len` + 47) | 48 | encrypted private-key blob |

The encrypted private-key blob is:

- plaintext private key: `32` bytes
- AEAD tag: `16` bytes
- ciphertext+tag total: `48` bytes

#### Sizes

- header: `8` bytes
- fixed-minimum body (excluding `ext_bytes`): `118` bytes
- body: `118 + ext_len` bytes
- total file size: `126 + ext_len` bytes

Current releases emit `ext_len = 0` (total 126 bytes on disk). Future
`v4.x` minors may populate `ext_bytes` with authenticated TLV
metadata; readers that don't recognize a tag must still authenticate
the full region via AEAD and then skip it.

### 7.4 Private-key encryption

Private keys are encrypted at rest using:

- Argon2id with the stored KDF params and salt
- the resulting 32-byte Argon2id output directly as the XChaCha20-Poly1305 key
- the stored 24-byte nonce for AEAD encryption/decryption
- the 8-byte cleartext key-file header, the KDF params, the Argon2
  salt, the nonce, the big-endian `ext_len`, and the `ext_bytes`
  payload as **AEAD associated data (AAD)**

Binding the cleartext header and body fields as AAD means every byte
on disk — including fields that wouldn't otherwise affect key
derivation (header, flags, `ext_len`, `ext_bytes`) — is
cryptographically authenticated by the AEAD tag. This is
defense-in-depth rather than a distinct user-facing error signal:
the AEAD primitive returns a single undifferentiated failure for
both "wrong passphrase" and "tampered cleartext", and both surface
as the same `KeyFileUnlockFailed` error. Its Display wording
reflects both causes.

Unlike `.fcr` headers, key files do **not** use replicated fields and
do **not** use a separate header HMAC.

---

## 8. Authentication boundaries

This section defines what current readers authenticate and what they do not.

## 8.1 Symmetric `.fcr`

In symmetric mode, the header HMAC authenticates the **decoded** values of:

- file prefix (including `ext_len`)
- Argon2 salt
- HKDF salt
- KDF params
- stream nonce
- `ext_bytes` (any authenticated extension data)

The outer HMAC tag itself is then stored in replicated form immediately after
`ext_bytes`.

The payload ciphertext is authenticated per stream chunk by XChaCha20-Poly1305.

### Minor-version extensions are authenticated

A future minor version adding data does so by shipping non-empty `ext_bytes` and
setting `ext_len` accordingly. Older readers:

- read `ext_len` from the prefix
- read the encoded extension region, decode it, and include the decoded `ext_bytes` in HMAC verification
- then discard the extension contents before proceeding

Because the HMAC covers `ext_bytes`, an attacker cannot tamper with the
extension without breaking HMAC verification. Minor-version additions must
still be:

- optional (older readers can decrypt without interpreting them)
- non-security-critical (older readers will not act on their contents)
- ignorable (older readers produce correct output regardless of what they contain)

A change that violates any of these requirements is a **major** version bump,
not a minor one.

## 8.2 Hybrid `.fcr`

In hybrid mode, the outer HMAC authenticates the **decoded** values of:

- file prefix (including `ext_len`)
- envelope
- stream nonce
- `ext_bytes` (any authenticated extension data)

The payload ciphertext is authenticated per stream chunk by XChaCha20-Poly1305.

The envelope itself is also an AEAD ciphertext (XChaCha20-Poly1305 with an HKDF-derived wrapping key).

### What hybrid mode does not authenticate

Hybrid mode does **not** bind the ciphertext to a long-term sender identity.

It provides confidentiality and integrity for the recipient, but it is not a substitute for digital signatures or persistent sender authentication.

### Minor-version extensions are authenticated

The same authenticated-extension rule applies here: a future `v4.x` minor
version extends the header via `ext_bytes`, and the HMAC binds those bytes to
the file. Older readers read the encoded extension region, decode it, include
the decoded `ext_bytes` in HMAC verification, and ignore the contents.

## 8.3 `public.key`

A public key file is structurally validated:

- magic
- type
- version
- algorithm
- data length
- exact total size

There is **no cryptographic authentication tag** on `public.key` itself.

Out-of-band verification is expected to use the public-key fingerprint.

## 8.4 `private.key`

A private key file is structurally validated:

- magic
- type
- version
- algorithm
- `data_len` lower-bounded by the fixed-minimum body size
- total on-disk size matches `8 + data_len`
- internal consistency between `data_len` and the parsed `ext_len`
- unknown nonzero flags rejected
- KDF parameter bounds

The encrypted private-key blob is authenticated by
XChaCha20-Poly1305 during decryption, and that AEAD binds the
following cleartext fields as **associated data**:

- the 8-byte key-file header (magic, type, version, algorithm,
  `data_len`, flags)
- the stored KDF params
- the Argon2 salt
- the AEAD nonce
- the big-endian `ext_len`
- the `ext_bytes` payload

Tamper on any of those bytes causes the decrypt-side AEAD to fail
authentication. Unlike the `.fcr` header, `private.key` has **no**
separate HMAC layer and **no** replicated fields — authentication
comes entirely from the AEAD tag over the AAD + ciphertext.

### Minor-version extensions are authenticated

A future `v4.x` minor private-key version may populate `ext_bytes`
with TLV metadata. Readers of any `v4.x` minor:

- read `ext_len` from the body
- read `ext_bytes`
- include both in the AEAD AAD during decryption
- interpret tags they recognize; authenticate-and-ignore tags they don't

The same optional / non-security-critical / ignorable requirements
apply to private-key extensions as to `.fcr` extensions (see 8.1).

---

## 9. Compatibility guarantees

## 9.1 Encrypted files (`.fcr`)

Current reader behavior is:

- **Symmetric:** accept major version `3`, allow compatible future minor versions within major `3`
- **Hybrid:** accept major version `4`, allow compatible future minor versions within major `4`
- reject older or newer major versions for the respective mode
- reject unknown nonzero header flags

Files produced before the current magic-byte-based format family are not supported by current readers.

## 9.2 Key files

Current reader behavior is:

- accept `public.key` version `3` only
- accept `private.key` version `4` only
- reject any other key-file version (older or newer) for the respective file
- reject unknown nonzero key-file flags
- reject unknown key algorithms
- for `private.key`, reject bodies where `data_len` disagrees with the parsed `ext_len`
- for `private.key v4.x` minors, authenticate-and-ignore any `ext_bytes` TLV tags the reader does not recognize

0.3.0 is the first FerroCrypt release to define versioned `.fcr` and key-file formats. The numbers `symmetric .fcr v3.0` / `hybrid .fcr v4.0` / `public.key v3` / `private.key v4` start above 1 because the formats went through a few iterations during 0.3.0 pre-release development; none of those earlier shapes ever appeared in a published release.

## 9.3 KDF parameter compatibility

For both symmetric file headers and private-key files, current readers only accept KDF params within the current safety bounds.

That means a file can be structurally well-formed yet still be rejected if it carries out-of-policy KDF parameters.

---

## 10. Versioning rules

## 10.1 Encrypted-file major version

Increment the encrypted-file **major** version when a reader from the previous major cannot safely decrypt the new file.

Examples of major-version changes:

- changing the payload cipher or stream construction
- changing the meaning or required interpretation of existing fields
- adding a required field that older readers must understand to decrypt safely
- changing authentication semantics in a way older readers must know about

## 10.2 Encrypted-file minor version

Increment the encrypted-file **minor** version only for backward-compatible additions that older readers of the same major can safely ignore.

Minor-version additions must be placed inside the authenticated `ext_bytes`
region and the writer must set `ext_len` in the prefix to match. Older readers
of the same major:

- read `ext_len` from the prefix,
- read the encoded extension region,
- decode it and include the decoded `ext_bytes` in HMAC verification (binding the extension to the file),
- and then discard the contents.

Minor versions must **not** introduce:

- required cipher changes
- required KDF changes
- required authentication changes
- fields that older readers must interpret to decrypt correctly

If the new field must be understood to decrypt safely, it is **not** a minor change.

## 10.3 Key-file versioning

Key files use a single version byte per key type, not a separate major/minor pair.

`public.key` and `private.key` are versioned independently:

- the two files can evolve at different rates (the current release keeps `public.key` at `v3` while bumping `private.key` to `v4`)
- a new `public.key` layout bumps the public-key version only; a new `private.key` layout bumps the private-key version only
- `private.key` follows a `v<major>.<x>` style implicitly: `ext_bytes` provides the same authenticated-extension forward-compat mechanism that `.fcr` minors use, so a `v4.1` `private.key` that adds an optional field via TLV stays readable by `v4.0` readers

Any incompatible or structurally distinct key-file revision that cannot be expressed as an authenticated `ext_bytes` addition must use a new top-level key-file version and be handled by explicit version dispatch in the reader.

---

## 11. Archive semantics

The encrypted payload is a TAR stream produced and consumed with the following policy.

## 11.1 Input acceptance during archiving

### Accepted

- regular files
- directories containing only regular files and subdirectories

### Rejected

- symlink inputs
- directories containing symlinks
- sockets
- FIFOs
- device files
- other special filesystem entries

On Unix, regular files are opened with `O_NOFOLLOW` so the open itself refuses symlinks atomically.

## 11.2 Directory traversal safety on extraction

Extraction rejects archive paths that contain:

- `..`
- absolute roots
- Windows/host-specific path prefixes

This prevents path traversal outside the selected output directory.

## 11.3 Archive root cardinality on extraction

FerroCrypt's archiver always produces exactly one top-level root (see §6.4).

Extraction enforces the same invariant: an archive that contains entries under more than one distinct top-level root is rejected before any output is finalized. This keeps the decryption function's single returned output path faithful to what extraction actually creates on disk.

## 11.4 Output collision policy

During extraction, the top-level root created by the archive must not already exist in the chosen output directory.

If the top-level root already exists, extraction fails before writing into it.

## 11.5 Unsupported TAR entry types on extraction

Extraction accepts only:

- directory entries
- regular file entries

Other TAR entry types are rejected, including symlink entries.

## 11.6 Partial extraction behavior

Decryption/extraction is intentionally **non-transactional**.

If extraction fails after some output has already been written, the top-level root is renamed with a `.incomplete` suffix.

This preserves partially recovered plaintext for inspection or salvage.

## 11.7 Metadata preservation

FerroCrypt preserves:

- file contents
- directory structure

The current implementation also attempts to preserve regular-file and directory
permission bits on Unix, with setuid, setgid, and sticky bits stripped on both
archive creation and extraction. That is current behavior, not a guaranteed
cross-platform compatibility contract.

FerroCrypt does **not** preserve as part of its compatibility contract:

- ownership
- timestamps
- permission preservation across all platforms and implementations
- hardlink identity
- symlink relationships
- special filesystem entries

Hardlinks are archived as ordinary file contents rather than preserved as links.

The archive semantics are intended for safe consumer file encryption, not for faithful filesystem backup/restore.

---

## 12. Current format identifiers summary

### Encrypted files

- magic byte: `0xFC`
- symmetric type: `0x53` (`'S'`)
- hybrid type: `0x48` (`'H'`)
- current symmetric version: `3.0`
- current hybrid version: `4.0`
- extension: `.fcr`

### Key files

- magic byte: `0xFC`
- public key type: `0x50` (`'P'`)
- private key type: `0x53` (`'S'`)
- current `public.key` version: `3`
- current `private.key` version: `4`
- accepted `public.key` versions: `3`
- accepted `private.key` versions: `4`
- algorithm id: `0x01` (`X25519`)

---

## 13. Practical scope of this specification

This document defines the current byte-level contract and behavior that callers can rely on.

It does **not** imply:

- backward compatibility with anything produced before FerroCrypt 0.3.0 (which is the first release to define these versioned formats)
- support for arbitrary future key-file versions
- preservation of full filesystem metadata
- suitability for high-assurance or regulated environments
