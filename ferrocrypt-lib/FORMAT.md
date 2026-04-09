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

This specification describes the **current released format family** implemented by the library. The crate version and the on-disk format version are separate.

This document is meant to be concrete rather than cryptic: the current field order, byte sizes, and compatibility rules are described explicitly below.

---

## 1. Terminology

- **Encoded** means a current `.fcr` header field stored using FerroCrypt's triple-replication format.
- **Decoded** means the original logical bytes recovered after majority-vote decoding.
- **Header** means all bytes before the encrypted payload ciphertext begins.
- **Payload** means the encrypted TAR stream after the header.

---

## 2. Triple-replication encoding

In the current `v3.0` `.fcr` format, **all defined encrypted-file header fields** are stored using a simple triple-replication scheme for error correction.

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

For the current `v3.0` encrypted-file format, every defined `.fcr` header field is triple-replicated.

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
| 4..=5 | 2 | Header length | big-endian `u16`, total bytes from file start to first ciphertext byte |
| 6..=7 | 2 | Flags | big-endian `u16`, currently must be `0` |

#### Stored size

- logical size: `8`
- encoded size: `27`

#### Current values

- encrypted-file major version: `3`
- encrypted-file minor version: `0`

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
6. key verification hash (`32` logical bytes, stored encoded)
7. HMAC tag (`32` logical bytes, stored encoded)
8. optional future minor-version trailing bytes, if any
9. ciphertext payload

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

- `1 <= mem_cost <= 2 * 1024 * 1024` KiB (2 GiB)
- `1 <= time_cost <= 12`
- `1 <= lanes <= 8`

Files outside those bounds are rejected by current readers.

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

### 4.4 Key verification hash

The key verification hash is:

```text
SHA3-256(encryption_key)
```

It is used to help distinguish:

- wrong password / wrong derived key
- vs. generic header authentication failure

It is part of the authenticated symmetric header.

### 4.5 Stored sizes (v3.0 symmetric)

| Field | Logical size | Stored size |
|---|---:|---:|
| Prefix | 8 | 27 |
| Argon2 salt | 32 | 99 |
| HKDF salt | 32 | 99 |
| KDF params | 12 | 39 |
| Stream nonce | 19 | 63 |
| Key verification hash | 32 | 99 |
| HMAC tag | 32 | 99 |
| **Total header size** | — | **525 bytes** |

So a current symmetric `v3.0` file is laid out as:

```text
0..27    encoded prefix
27..126  encoded Argon2 salt
126..225 encoded HKDF salt
225..264 encoded KDF params
264..327 encoded stream nonce
327..426 encoded key verification hash
426..525 encoded HMAC tag
525..end ciphertext payload
```

---

## 5. Hybrid `.fcr` layout

Hybrid mode uses:

- an ephemeral sender secret and the recipient public key to seal a per-file envelope
- XChaCha20-Poly1305 stream encryption for the payload
- HMAC-SHA3-256 for the outer header

The envelope transports two per-file random keys:

- payload encryption key (`32` bytes)
- outer HMAC key (`32` bytes)

### 5.1 Header fields and order

In the current `v3.0` hybrid format, every defined header field listed below is stored in encoded form and appears in this order:

1. file prefix (`8` logical bytes, stored encoded)
2. sealed envelope (`136` logical bytes, stored encoded)
3. stream nonce (`19` logical bytes, stored encoded)
4. HMAC tag (`32` logical bytes, stored encoded)
5. optional future minor-version trailing bytes, if any
6. ciphertext payload

### 5.2 Envelope layout

The decoded envelope is:

| Offset | Size | Field |
|---|---:|---|
| 0..=31 | 32 | ephemeral public key |
| 32..=55 | 24 | envelope nonce |
| 56..=135 | 80 | envelope ciphertext |

Envelope ciphertext is the encrypted form of:

```text
[payload_encryption_key (32) | header_hmac_key (32)]
```

So the envelope plaintext is `64` bytes and the ciphertext is `64 + 16 = 80` bytes.

### 5.3 Stored sizes (v3.0 hybrid)

| Field | Logical size | Stored size |
|---|---:|---:|
| Prefix | 8 | 27 |
| Envelope | 136 | 411 |
| Stream nonce | 19 | 63 |
| HMAC tag | 32 | 99 |
| **Total header size** | — | **600 bytes** |

So a current hybrid `v3.0` file is laid out as:

```text
0..27    encoded prefix
27..438  encoded envelope
438..501 encoded stream nonce
501..600 encoded HMAC tag
600..end ciphertext payload
```

---

## 6. Payload format

After the header, both symmetric and hybrid modes store the encrypted payload.

### 6.1 What the payload is

The payload is a **TAR archive** encrypted as a streaming XChaCha20-Poly1305 AEAD stream.

### 6.2 Streaming behavior

Plaintext TAR bytes are processed in chunks of:

- plaintext chunk size: `65536` bytes
- authentication tag per chunk: `16` bytes

Non-final chunks use `encrypt_next`; the final chunk uses `encrypt_last`.

### 6.3 What is inside the TAR stream

- If the input was a file, the TAR contains one top-level file entry with the original file name.
- If the input was a directory, the TAR contains one top-level directory entry with the directory name, then its accepted descendants.

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
| 1 | 1 | Type | `0x50` = public, `0x53` = secret/private |
| 2 | 1 | Version | current key-file version |
| 3 | 1 | Algorithm | `0x01` = X25519 |
| 4..=5 | 2 | Data length | big-endian `u16`, number of body bytes after the header |
| 6..=7 | 2 | Flags | big-endian `u16`, currently must be `0` |

Current key-file version: `2`

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
[key header][KDF params][Argon2 salt][XChaCha20-Poly1305 nonce][encrypted secret key blob]
```

#### Body layout

| Offset | Size | Field |
|---|---:|---|
| 0..=11 | 12 | KDF params |
| 12..=43 | 32 | Argon2 salt |
| 44..=67 | 24 | XChaCha20-Poly1305 nonce |
| 68..=115 | 48 | encrypted secret key blob |

The encrypted secret key blob is:

- plaintext secret key: `32` bytes
- AEAD tag: `16` bytes
- ciphertext+tag total: `48` bytes

#### Sizes

- header: `8` bytes
- body: `116` bytes
- total file size: `124` bytes

### 7.4 Private-key encryption

Private keys are encrypted at rest using:

- Argon2id with the stored KDF params and salt
- the resulting 32-byte Argon2id output directly as the XChaCha20-Poly1305 key
- the stored 24-byte nonce for AEAD encryption/decryption

Unlike `.fcr` headers, key files do **not** use replicated fields and do **not** use a separate header HMAC.

---

## 8. Authentication boundaries

This section defines what current readers authenticate and what they do not.

## 8.1 Symmetric `.fcr`

In symmetric mode, the header HMAC authenticates the **decoded** values of:

- file prefix
- Argon2 salt
- HKDF salt
- KDF params
- stream nonce
- key verification hash

The outer HMAC tag itself is then stored in replicated form.

The payload ciphertext is authenticated per stream chunk by XChaCha20-Poly1305.

### Not authenticated by older readers

If a future minor version appends bytes **after** the stored HMAC tag, older readers will:

- verify the HMAC over the fields they know
- skip the trailing bytes using `header_len`
- continue decrypting

Therefore, trailing minor-version bytes are **not authenticated by older readers** and must be:

- optional
- non-security-critical
- ignorable without affecting correct decryption

## 8.2 Hybrid `.fcr`

In hybrid mode, the outer HMAC authenticates the **decoded** values of:

- file prefix
- envelope
- stream nonce

The payload ciphertext is authenticated per stream chunk by XChaCha20-Poly1305.

The envelope itself is also an AEAD ciphertext produced by `ChaChaBox`.

### What hybrid mode does not authenticate

Hybrid mode does **not** bind the ciphertext to a long-term sender identity.

It provides confidentiality and integrity for the recipient, but it is not a substitute for digital signatures or persistent sender authentication.

### Not authenticated by older readers

The same minor-version rule applies here: trailing bytes added after the stored HMAC tag are not authenticated by older readers and must be optional and ignorable.

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
- data length
- exact total size
- KDF parameter bounds

The encrypted secret-key blob is authenticated by XChaCha20-Poly1305 during decryption.

However, the key-file header and its KDF metadata are **not** covered by a separate header MAC like `.fcr` files are.

In practice, tampering with the stored KDF params, salt, nonce, or ciphertext should result in decryption failure or validation failure, but the format does not define an additional independent key-file header authentication layer.

---

## 9. Compatibility guarantees

## 9.1 Encrypted files (`.fcr`)

Current reader behavior is:

- accept current major version `3`
- allow compatible future **minor** versions within major `3`
- reject older or newer **major** versions
- reject unknown nonzero header flags

Files produced before the current magic-byte-based format family are not supported by current readers.

Future major versions are intended to retain readers for previously released major versions (e.g. a v4 reader would still accept v3 encrypted files), so that upgrading FerroCrypt does not orphan existing encrypted data.

## 9.2 Key files

Current reader behavior is:

- accept key-file version `2`
- reject older or newer key-file versions
- reject unknown nonzero key-file flags
- reject unknown key algorithms

So current key-file compatibility is **exact-version**, not major/minor compatible.

Future key-file versions are intended to retain readers for previously released versions.

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

Minor-version additions must be placed:

- **after the stored HMAC tag**
- **before the ciphertext payload**

Older readers rely on `header_len` to skip such bytes.

Minor versions must **not** introduce:

- required cipher changes
- required KDF changes
- required authentication changes
- fields that older readers must interpret to decrypt correctly

If the new field must be understood to decrypt safely, it is **not** a minor change.

## 10.3 Key-file versioning

Key files currently use a single version byte, not a separate major/minor pair.

Any incompatible or structurally distinct key-file revision must use a new key-file version and be handled by explicit version dispatch in the reader.

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

## 11.3 Output collision policy

During extraction, each top-level root created by the archive must not already exist in the chosen output directory.

If a top-level root already exists, extraction fails before writing into it.

## 11.4 Unsupported TAR entry types on extraction

Extraction accepts only:

- directory entries
- regular file entries

Other TAR entry types are rejected, including symlink entries.

## 11.5 Partial extraction behavior

Decryption/extraction is intentionally **non-transactional**.

If extraction fails after some output has already been written, each created top-level root is renamed with a `.incomplete` suffix.

This preserves partially recovered plaintext for inspection or salvage.

## 11.6 Metadata preservation

FerroCrypt preserves:

- file contents
- directory structure

FerroCrypt does **not** preserve as part of its compatibility contract:

- ownership
- timestamps
- permissions
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
- current encrypted-file version: `3.0`
- extension: `.fcr`

### Key files

- magic byte: `0xFC`
- public key type: `0x50` (`'P'`)
- secret/private key type: `0x53` (`'S'`)
- current key-file version: `2`
- algorithm id: `0x01` (`X25519`)

---

## 13. Practical scope of this specification

This document defines the current byte-level contract and behavior that callers can rely on.

It does **not** imply:

- backward compatibility with pre-v3 encrypted files
- backward compatibility with pre-v2 key files
- support for arbitrary future key-file versions
- preservation of full filesystem metadata
- suitability for high-assurance or regulated environments
