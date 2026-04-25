# FerroCrypt on-disk format — v1 specification

Authoritative byte-level contract for the FerroCrypt v1 on-disk format.

Covers:

- encrypted payload files: `*.fcr`
- public recipient: `public.key` (UTF-8 text file carrying a Bech32 `fcr1…` string)
- passphrase-wrapped private key: `private.key`
- TLV extension region grammar
- compatibility & versioning policy
- what is and is not authenticated
- archive semantics

This is the **final** v1 format. It resets the pre-release v3/v4 draft
numbering to a single clean `v1` across every artefact, unifies on
SHA-3, introduces a per-file `file_key` abstraction (borrowed from
age), and collapses the full-header triple replication into a single
replicated prefix that preserves only the diagnostic UX it was
designed for.

---

## 1. Design principles

These are load-bearing; later sections cite them.

1. **Authenticate everything the reader acts on.** Prefix, envelope,
   stream nonce, TLV region — all covered by HMAC-SHA3-256 or
   AEAD-AAD. No unauthenticated dispatch.
2. **On-disk bytes = authenticated bytes.** Triple replication is
   enforced canonically *before* HMAC verification (§5.1), so a
   tampered replica surfaces as a specific diagnostic error rather
   than as silently corrected input with a passing HMAC.
3. **Minimum mechanism.** The grammar is the smallest one that lets
   v1 decrypt correctly and lets v1.x extend authenticably.
4. **One hash family.** SHA-3 throughout: HMAC, HKDF, fingerprint.
5. **Per-version domain separation.** Every HKDF info string begins
   `ferrocrypt/v1/…`. A future v2 uses `ferrocrypt/v2/…` and cannot
   collide.
6. **Diagnostic quality is a product promise.** Prefix replication
   and specific error variants exist to serve that promise.
7. **Canonical recipient is `fcr1…`.** `public.key` is a text file
   containing that string. No binary public-key blob.
8. **v2 safety belt.** A future `version = 2` MUST change either the
   magic bytes or the prefix length so a v1 parser cannot silently
   misinterpret a v2 file (§10).

---

## 2. Cryptographic primitives

| Role | Primitive |
|---|---|
| Payload AEAD (`.fcr`) | XChaCha20-Poly1305, STREAM-BE32 |
| Envelope AEAD (`.fcr`) | XChaCha20-Poly1305 (single-shot) |
| `private.key` AEAD | XChaCha20-Poly1305 (single-shot) |
| Passphrase KDF | Argon2id |
| Key derivation / expansion | HKDF-SHA3-256 |
| Header MAC | HMAC-SHA3-256 |
| Key agreement | X25519 |
| Public-key fingerprint | SHA3-256 (of `algorithm \|\| key_material`) |
| Recipient string | Bech32 (BIP 173) with HRP `"fcr"` |

### 2.1 Argon2id parameter bounds (normative)

- `8 * lanes <= mem_kib <= 2 * 1024 * 1024`
- `1 <= time <= 12`
- `1 <= lanes <= 8`

Readers MUST reject out-of-range values with
`InvalidKdfParams::{Parallelism | MemoryCost | TimeCost}`. A
caller-supplied `KdfLimit` MAY further cap accepted `mem_kib` from
untrusted input; the default cap matches the writer's default cost
(~1 GiB), not the structural maximum.

---

## 3. Canonical encoding rules (normative)

1. All fixed-layout integer fields are big-endian.
2. Reserved bytes / reserved bits MUST be zero on write; readers MUST
   reject any nonzero reserved value.
3. `ext_len` in both `.fcr` and `private.key` MUST be `<= 32768`.
4. The only replicated bytes in v1 are the 27 on-disk bytes of the
   `.fcr` prefix (§5.1). Everything else is stored raw.
5. The TLV extension region (§6) is canonical: each entry's `len` MUST
   equal its actual value size; entries MUST NOT extend past the end
   of the region.

Readers MUST reject non-canonical fixed-field values **before any
cryptographic operation**. Non-canonical TLV structure is rejected
**after** the extension region has been authenticated (HMAC for
`.fcr`, AEAD-AAD for `private.key`).

---

## 4. `.fcr` encrypted file — v1 layout

Every `.fcr` file is:

```text
[ replicated_prefix (27 bytes) ]
[ mode_envelope (116 B symmetric | 104 B hybrid) ]
[ stream_nonce (19 bytes) ]
[ ext_bytes (ext_len bytes) ]
[ hmac_tag (32 bytes) ]
[ payload ]
```

Total header with `ext_len = 0`: **194 bytes** (symmetric) or
**182 bytes** (hybrid).

### 4.1 Replicated prefix

The logical prefix is 8 bytes:

| Offset | Size | Field | Value / meaning |
|---:|---:|---|---|
| 0–3 | 4 | `magic` | `"FCR\0"` = `0x46 0x43 0x52 0x00` |
| 4 | 1 | `version` | `0x01` |
| 5 | 1 | `type` | `0x53 'S'` symmetric · `0x48 'H'` hybrid |
| 6–7 | 2 | `ext_len` | `u16 BE`; byte length of `ext_bytes` |

The on-disk encoding is always 27 bytes:

```text
pad0 || pad1 || pad2 || copy1 || copy2 || copy3
```

- each `pad` byte MUST be `0x00`
- `copy1`, `copy2`, `copy3` are the same 8-byte logical prefix

**Writer rule.** Writers MUST emit the canonical form only: all pads
zero, three byte-identical copies.

**Reader rule.** Readers MUST:

1. read 27 bytes;
2. recover a best-effort logical 8-byte prefix by majority vote per
   byte position;
3. re-encode that logical prefix canonically;
4. compare the on-disk 27 bytes to the canonical re-encoding.

If any byte position has no majority, or if the on-disk bytes are not
the canonical encoding, the file MUST be rejected as a **corrupted
prefix** (`FormatDefect::CorruptedPrefix { decoded_view }`). The
decoded view carries the majority-voted logical prefix so callers can
surface upgrade messaging ("file says v2, upgrade FerroCrypt") even
on a bit-rotten file.

**Rationale.** Decoding still runs on a corrupted prefix — but only
to produce a useful error. Acceptance requires canonical on-disk
bytes, so writer and reader always HMAC the same bytes and on-disk ≡
authenticated.

**Scope of replication.** Only the 8-byte prefix. Everything after it
(salts, nonces, envelopes, ext_bytes, HMAC tag, ciphertext) is raw
— each is either random, cryptographically authenticated by the AEAD
primitive or the HMAC, or both.

### 4.2 Symmetric envelope

116 raw bytes, written immediately after the replicated prefix.

| Offset | Size | Field |
|---:|---:|---|
| 0–31 | 32 | `argon2_salt` |
| 32–43 | 12 | `kdf_params` = `mem_kib u32 \|\| time u32 \|\| lanes u32` |
| 44–67 | 24 | `wrap_nonce` |
| 68–115 | 48 | `wrapped_file_key` (32 B ciphertext + 16 B Poly1305 tag) |

Per-file derivation:

```text
file_key = random 32 bytes (CSPRNG)
ikm      = Argon2id(passphrase, argon2_salt, kdf_params)
wrap_key = HKDF-SHA3-256(
    salt = argon2_salt,
    ikm  = ikm,
    info = "ferrocrypt/v1/sym/wrap",
    L    = 32)
wrapped_file_key = XChaCha20-Poly1305-Seal(wrap_key, wrap_nonce, file_key, AAD = empty)
```

Reusing `argon2_salt` as the HKDF salt is safe; it saves storing two
distinct salts on disk.

### 4.3 Hybrid envelope

104 raw bytes, written immediately after the replicated prefix.

| Offset | Size | Field |
|---:|---:|---|
| 0–31 | 32 | `ephemeral_pubkey` (X25519) |
| 32–55 | 24 | `wrap_nonce` |
| 56–103 | 48 | `wrapped_file_key` |

Per-file derivation:

```text
file_key         = random 32 bytes (CSPRNG)
ephemeral_secret = random X25519 private key (CSPRNG)
ephemeral_public = X25519_basepoint_mult(ephemeral_secret)
shared           = X25519(ephemeral_secret, recipient_pubkey)
  -- MUST reject if `shared` is all zero (small-order public key defence)
wrap_key         = HKDF-SHA3-256(
    salt = ephemeral_public || recipient_pubkey,
    ikm  = shared,
    info = "ferrocrypt/v1/hyb/wrap",
    L    = 32)
wrapped_file_key = XChaCha20-Poly1305-Seal(wrap_key, wrap_nonce, file_key, AAD = empty)
```

Binding the salt to both public keys means a single ECDH session
produces a single wrap key bound to that specific exchange.

### 4.4 Header tail

After the mode envelope, both modes store:

| Size | Field |
|---:|---|
| 19 | `stream_nonce` (XChaCha20-Poly1305 STREAM-BE32 base nonce) |
| `ext_len` | `ext_bytes` (TLV region, §6) |
| 32 | `hmac_tag` (HMAC-SHA3-256 over everything above) |

### 4.5 Post-unwrap subkeys

```text
payload_key = HKDF-SHA3-256(
    salt = stream_nonce,
    ikm  = file_key,
    info = "ferrocrypt/v1/payload",
    L    = 32)
header_key  = HKDF-SHA3-256(
    salt = empty,
    ikm  = file_key,
    info = "ferrocrypt/v1/header",
    L    = 32)
```

### 4.6 HMAC input

```text
hmac_input =
    on_disk_prefix     (27 bytes, canonical)
 || envelope_bytes     (116 B symmetric | 104 B hybrid)
 || stream_nonce       (19 bytes)
 || ext_bytes          (ext_len bytes)

hmac_tag = HMAC-SHA3-256(header_key, hmac_input)
```

`header_key` is derived from `file_key`, so readers MUST unwrap the
envelope **before** verifying the header MAC. Consequences:

- wrong passphrase / wrong private key / envelope tamper → fails at
  envelope unwrap (`SymmetricEnvelopeUnlockFailed` or
  `HybridEnvelopeUnlockFailed`) before HMAC is ever reached;
- right passphrase / right key but tampered rest-of-header → fails at
  HMAC verification (`HeaderTampered`) — a distinct, more actionable
  error than a collapsed "authentication failed".

### 4.7 AEAD AAD for mode envelopes

All `.fcr` AEAD operations (wrap, unwrap) use `AAD = empty`.
Envelope-internal fields participate in `wrap_key` derivation or are
the AEAD's own nonce input, so tampering any of them changes derived
values and the AEAD primitive rejects on its own. Outside-envelope
fields (prefix, stream_nonce, ext_bytes) are covered by the header
HMAC. `private.key` (§7) is different: it has no separate HMAC, so
every cleartext byte is bound as AEAD-AAD.

### 4.8 Decryption processing order (normative)

Readers MUST process `.fcr` files in this order:

1. read and validate the replicated prefix (bad magic, unsupported
   version, unknown type, oversized `ext_len`, corrupted prefix are
   all rejected here);
2. read the rest of the fixed header;
3. validate KDF parameter bounds if `type = Symmetric`;
4. unwrap `file_key` from the envelope;
5. derive `header_key` and `payload_key` from `file_key`;
6. verify `hmac_tag`;
7. parse `ext_bytes` under the TLV rules in §6;
8. decrypt the payload stream.

Wrong passphrase / wrong recipient key / envelope tamper fails at
step 4; header tamper outside the envelope fails at step 6;
malformed or unrecognised-critical TLV fails at step 7; payload
truncation / trailing data / payload tamper fails at step 8.

### 4.9 Payload stream

The payload is a TAR stream encrypted with XChaCha20-Poly1305
STREAM-BE32.

- **Chunk size:** 65 536 bytes plaintext, 16-byte Poly1305 tag per
  chunk.
- **Stored base nonce:** the 19-byte `stream_nonce` from the header.
- **Per-chunk nonce:** `stream_nonce (19) || chunk_counter_u32_be (4)
  || last_flag_u8 (1)` — exactly the scheme implemented by
  `chacha20poly1305::stream::EncryptorBE32` / `DecryptorBE32`.
- **Counter:** starts at `0` and increments by `1` per chunk.
- **Last flag:** `0x00` on every non-final chunk, `0x01` on the
  final chunk.

Normative behaviour:

- the final chunk MAY be shorter than 65 536 bytes;
- the final chunk MUST NOT be empty unless the whole plaintext is
  empty, in which case the payload consists of a single empty-plaintext
  chunk with `last_flag = 0x01`;
- decryptors MUST raise `PayloadTruncated` if EOF is reached without
  successfully decrypting a final-flag chunk;
- decryptors MUST reject bytes appended after the authenticated payload.
  STREAM-BE32's per-chunk nonce binding rejects ordinary appends as
  `PayloadTampered` (a naive append cannot produce a valid final chunk);
  pathological readers that signal EOF at a chunk boundary and then
  yield more bytes are caught by an explicit post-`decrypt_last`
  trailing-data probe and surface as `ExtraDataAfterPayload`;
- any chunk AEAD failure is `PayloadTampered`.

Writers SHOULD refuse payloads larger than `2^32` chunks of 65 536
bytes (~256 TiB); real inputs never reach this bound.

---

## 5. Payload format (TAR archive inside STREAM AEAD)

The decrypted payload is a TAR archive with these normative semantics:

- if the input was a file, the TAR contains one top-level file entry
  with the original file name;
- if the input was a directory, the TAR contains one top-level
  directory entry and its accepted descendants;
- only regular files and directories are valid entry kinds;
- symlinks, devices, FIFOs, sockets, and other special entries MUST
  be rejected by conforming writers and readers;
- extraction MUST reject absolute paths, `..`, host-specific path
  prefixes, and archives with more than one top-level root;
- extraction MUST reject collisions with an already-existing
  top-level output path.

What v1 preserves as part of the format contract:

- file contents;
- directory structure.

What v1 does **not** guarantee across implementations:

- ownership;
- timestamps;
- full permission fidelity on every platform;
- hardlink identity;
- symlink relationships.

---

## 6. TLV extension region (`ext_bytes`)

Authenticated extension region used by both `.fcr` and `private.key`.

```text
ext_bytes = *tlv
tlv       = tag (u16 BE) || len (u16 BE) || value (len bytes)
```

### 6.1 Tag classes

- `0x0001..=0x7FFF` — **ignorable** tags
- `0x8001..=0xFFFF` — **critical** tags
- `0x0000` and `0x8000` are reserved and MUST NOT be emitted

### 6.2 Normative rules

This is the complete TLV specification.

1. **Tags MUST appear in strictly ascending numeric order.**
2. **Duplicate tags MUST be rejected.**
3. **`len` is authoritative.** `len` MUST equal the actual byte
   length of `value`. Readers MUST reject if `tag || len || value`
   would extend past the end of `ext_bytes`.
4. **Zero-length values are permitted.** A `tag || 0x0000` entry is
   well-formed; its meaning is tag-specific.
5. **Unknown ignorable tags are skipped after authentication.**
   Readers that do not recognise a tag in `0x0001..=0x7FFF` MUST
   authenticate it (it is covered by HMAC or AEAD-AAD) and skip its
   value.
6. **Unknown critical tags are rejected after authentication.**
   Readers that do not recognise a tag in `0x8001..=0xFFFF` MUST reject
   the file with `FormatDefect::UnknownCriticalTag { tag }`. v1.0
   defines none, so any critical tag today is an upgrade-required
   signal.
7. **v1.0 writers emit `ext_len = 0`** unless using a tag defined in
   a later v1.x revision.
8. **`ext_len` is capped at 32 KiB.** Readers MUST reject larger
   values with `FormatDefect::ExtTooLarge`.

If a change is "so critical that old readers must reject files that
use it," that change is a `version = 2` bump, not a TLV tag.

### 6.3 How future features ship

When a future release adds a TLV tag, the PR that adds it:

1. Picks the next available `u16` value.
2. Documents the tag number, semantics, value format, and any size
   constraints in this specification.
3. Adds test vectors under `testvectors/suite/`.

No pre-allocation, no separate registry, no governance process.

---

## 7. `public.key` — text form, canonical `fcr1…`

`public.key` is a **UTF-8 text file** containing exactly one line: the
canonical lowercase Bech32 recipient string, optionally followed by a
single trailing line feed.

Example:

```
fcr1qqpjkm5g7wk60xptrc30ah3ks55z0a9dyrvprm8jyutswmgkp4lqqjuvzyg
```

No binary header, no separate integrity tag. The Bech32 checksum
(BIP 173, 6 characters) provides copy-paste error detection. Identity
("is this really Alice's key?") is verified out-of-band via the
fingerprint.

### 7.1 `fcr1…` payload

```text
HRP  = "fcr"
DATA = algorithm (1 byte) || public_key_material
```

Defined algorithms in v1:

- `0x01` — X25519; `public_key_material` length = 32 bytes.

Future algorithms use new `algorithm` values. The original BIP 173
90-character length cap is explicitly lifted; the checksum is still
verified.

Readers MUST:

- verify the BIP 173 checksum;
- reject non-canonical encodings, including any uppercase or mixed-case
  string;
- reject unknown `algorithm` bytes (`FormatDefect::UnknownAlgorithm`);
- reject key material whose length does not match the algorithm
  (`FormatDefect::UnexpectedKeyLength`).

Readers SHOULD strip leading and trailing ASCII whitespace (spaces,
tabs, CR, LF) before parsing so that files saved with differing
line endings, a missing trailing LF, or an editor-inserted trailing
newline all parse identically. Internal whitespace inside the
`fcr1…` string is rejected by the Bech32 checksum; no dedicated
error is needed.

### 7.2 Fingerprint

```text
fingerprint = SHA3-256(algorithm || public_key_material)
```

Displayed as the first 16 hex characters (short) or all 64 hex
characters (full). Hashing `algorithm || key_material` avoids
cross-algorithm fingerprint collisions when future public-key
algorithms are added.

---

## 8. `private.key` — binary, passphrase-wrapped

`private.key` is the only binary on-disk artefact other than `.fcr`.
There is no separate HMAC; the AEAD tag is the sole integrity
mechanism, so every cleartext byte is bound as AEAD-AAD.

### 8.1 Layout

Total 125 bytes when `ext_len = 0`.

| Offset | Size | Field |
|---:|---:|---|
| 0–3 | 4 | `magic` = `"FCR\0"` |
| 4 | 1 | `version` = `0x01` |
| 5 | 1 | `type` = `0x4B` (`'K'`) |
| 6 | 1 | `algorithm` = `0x01` (X25519) |
| 7–8 | 2 | `ext_len` (u16 BE) |
| 9–40 | 32 | `argon2_salt` |
| 41–52 | 12 | `kdf_params` |
| 53–76 | 24 | `wrap_nonce` |
| 77… | `ext_len` | `ext_bytes` |
| next | 48 | `wrapped_privkey` (32 B ciphertext + 16 B tag) |

The `type` byte is `0x4B` rather than `0x53` so `file(1)`-style
matchers can disambiguate a `private.key` file from a symmetric
`.fcr` file by a single byte.

### 8.2 Key wrapping

```text
ikm         = Argon2id(passphrase, argon2_salt, kdf_params)
wrap_key    = HKDF-SHA3-256(
    salt = argon2_salt,
    ikm  = ikm,
    info = "ferrocrypt/v1/private-key/wrap",
    L    = 32)

aad         = bytes[0 .. start_of_wrapped_privkey)   -- every cleartext byte
wrapped     = XChaCha20-Poly1305-Seal(wrap_key, wrap_nonce, private_key_material, aad)
```

Tampering any cleartext byte — header, KDF params, salt, nonce,
`ext_len`, `ext_bytes` — causes the AEAD decrypt to fail with
`CryptoError::KeyFileUnlockFailed`. That error is intentionally
indistinguishable from "wrong passphrase" at the AEAD layer; a local
attacker with read access gains nothing from the distinction.

### 8.3 Reader rules

Readers MUST:

1. reject bad `magic`, unsupported `version`, wrong `type`, unknown
   `algorithm`, or oversized `ext_len`;
2. check total file size against the parsed structure;
3. validate KDF parameter bounds **before** attempting Argon2id;
4. authenticate and decrypt `wrapped_privkey` using the full
   cleartext prefix as AAD;
5. parse `ext_bytes` under the TLV rules in §6 after the AEAD tag
   authenticates.

---

## 9. HKDF info-string convention

Every HKDF info string is literal ASCII of the form
`ferrocrypt/v1/<part>`. Pinned exactly:

| Info string | Purpose |
|---|---|
| `ferrocrypt/v1/sym/wrap` | Symmetric-envelope wrap key |
| `ferrocrypt/v1/hyb/wrap` | Hybrid-envelope wrap key |
| `ferrocrypt/v1/private-key/wrap` | `private.key` wrap key |
| `ferrocrypt/v1/payload` | Payload AEAD key (from `file_key`) |
| `ferrocrypt/v1/header` | Header HMAC key (from `file_key`) |

A future v2 uses `ferrocrypt/v2/…`; non-colliding by construction.

Fingerprints (§7.2) are a plain SHA3-256 hash and deliberately do
**not** use an HKDF info string.

---

## 10. Versioning and the v2 safety belt

### 10.1 Versioning policy

- `.fcr` uses a single `version` byte, starting at `0x01`.
- `private.key` uses a single `version` byte, starting at `0x01`.
- `public.key` has no binary version byte; its compatibility surface
  is the Bech32 grammar plus `algorithm` IDs.

There is no separate major/minor split in v1.

### 10.2 Backward-compatible evolution

Backward-compatible evolution within v1 happens through:

- ignorable TLV tags in `ext_bytes`;
- new public-key `algorithm` IDs;
- new `.fcr` `type` values (e.g. a future PQ-hybrid mode).

Unknown ignorable TLV tags are skipped after authentication. Unknown
critical TLV tags are rejected after authentication. Unknown `type`
or `algorithm` values are rejected immediately with a specific error.

### 10.3 What requires `version = 0x02`

A new `.fcr` or `private.key` version is required for any change that
breaks a v1 reader's ability to parse or safely act on the file,
including:

- changing the logical `.fcr` prefix layout;
- changing the replication rule for that prefix;
- changing the meaning of existing fixed fields;
- changing the payload-stream construction;
- changing the `private.key` fixed header layout;
- swapping a cryptographic primitive for an existing `type` in a way
  v1 readers cannot safely ignore.

### 10.4 v2 safety belt

A future `version = 0x02` MUST change either:

- the magic bytes, or
- the logical `.fcr` prefix length.

This ensures a v1 parser cannot silently misinterpret a v2 file under
any reader bug.

### 10.5 Compatibility boundary

v1 intentionally does **not** preserve compatibility with older
pre-v1 FerroCrypt draft formats (the v3/v4 numbering iterated during
0.3.0 pre-release development and never shipped publicly). The reset
is worth doing once, before the format ships as a stable long-term
contract.

---

## 11. Authentication coverage (summary)

| Asset | Authenticated by | Scope |
|---|---|---|
| `.fcr` prefix | canonicity check + HMAC-SHA3-256 | all 27 on-disk bytes |
| `.fcr` envelope | AEAD primitive + HMAC | self-integrity via `wrap_key`; bytes also in HMAC scope |
| `.fcr` stream_nonce | HMAC | 19 bytes |
| `.fcr` ext_bytes | HMAC | full region |
| `.fcr` payload | AEAD per chunk + final-flag semantics | every chunk, every byte |
| `private.key` cleartext | AEAD-AAD | every cleartext byte |
| `private.key` body | AEAD tag | 32 B key material |
| `public.key` / `fcr1…` | BIP 173 checksum | copy-paste integrity only |
| public-key identity | out-of-band fingerprint comparison | SHA3-256 of `algorithm \|\| key_material` |

---

## 12. Diagnostic error surface

FerroCrypt distinguishes the following failure classes; the exact
enum names are implementation-specific, but the distinction itself
is part of the product promise.

- `InvalidFormat::BadMagic` — not a FerroCrypt file
- `InvalidFormat::UnknownType { type_byte }` — unknown `.fcr` type
- `UnsupportedVersion { version }` — unknown major version
- `InvalidFormat::CorruptedPrefix { decoded_view }` — replicated
  prefix failed canonicity (carries the decoded view so diagnostics
  can still surface the declared version)
- `InvalidFormat::ExtTooLarge { len }` — `ext_len` over 32 KiB
- `InvalidFormat::MalformedTlv` — TLV ordering / duplicate / length
  violation
- `InvalidFormat::UnknownCriticalTag { tag }` — critical TLV tag
  the reader doesn't understand
- `InvalidKdfParams` — KDF params outside structural bounds
- `ExcessiveWork { required_kib, max_kib }` — KDF memory exceeds
  caller's `KdfLimit`
- `SymmetricEnvelopeUnlockFailed` — wrong passphrase or tampered
  symmetric envelope
- `HybridEnvelopeUnlockFailed` — wrong private key or tampered
  hybrid envelope (also fires on all-zero X25519 shared secret)
- `HeaderTampered` — HMAC mismatch after successful envelope unwrap
  (the right key opened the envelope, but `stream_nonce` or
  `ext_bytes` were tampered with)
- `PayloadTampered` — per-chunk AEAD failed; ordinary appended bytes
  on a regular file fail here because STREAM-BE32's per-chunk nonce
  rejects a naive append
- `PayloadTruncated` — EOF before the final-flag chunk
- `ExtraDataAfterPayload` — defense-in-depth trailing-data probe fired
  after a successful final-chunk decrypt; catches pathological readers
  that signal EOF at the chunk boundary and then yield more bytes
- `KeyFileUnlockFailed` — `private.key` AEAD failed (wrong passphrase
  **or** tampered cleartext; the two are indistinguishable by design)

---

## 13. Test vectors and conformance

v1 ships with committed test vectors split into two directories:

- **`testvectors/wire/`** — frozen v1 examples referenced directly
  by this specification. Not regenerated once v1 ships.
- **`testvectors/suite/`** — extensible edge-case corpus for
  malformed inputs; versioned separately via a `SUITE-VERSION` file.

Minimum coverage:

- empty, one-byte, and multi-chunk `.fcr` files for both modes;
- one valid `public.key` / `private.key` pair;
- corrupted replicated prefix;
- malformed TLV (ordering, duplicates, len-past-end);
- unknown critical and unknown ignorable TLV tags;
- out-of-range KDF parameters;
- truncated payload;
- trailing data after final payload chunk;
- wrong-passphrase / wrong-recipient envelope failures;
- header MAC failure after successful unwrap.

Equivalent cases are exercised by the in-tree unit tests
(`src/symmetric.rs::tests`, `src/hybrid.rs::tests`,
`src/format.rs::tests`, `src/common.rs::tests`); the `testvectors/`
corpus extends this coverage to independent reader implementations.

---

## 14. Format identifiers summary

### `.fcr`

- magic: `"FCR\0"` = `0x46 0x43 0x52 0x00`
- version: `0x01`
- symmetric type: `0x53` (`'S'`)
- hybrid type: `0x48` (`'H'`)
- extension: `.fcr`
- prefix length (logical / on-disk): 8 / 27 bytes

### `private.key`

- magic: `"FCR\0"`
- version: `0x01`
- type: `0x4B` (`'K'`)
- algorithm: `0x01` (X25519)
- fixed total (with `ext_len = 0`): 125 bytes

### `public.key`

- text file, single `fcr1…` line + optional trailing LF
- HRP: `"fcr"`
- payload: `algorithm(1) || key_material`
- for X25519 (the only v1 algorithm): ~64 bytes on disk

---

## 15. Practical scope

This document defines the byte-level contract that callers can rely
on. It does **not** imply:

- backward compatibility with anything produced before FerroCrypt
  0.3.0 (which is the first release to define versioned v1 formats);
- support for arbitrary future `type` or `algorithm` values;
- preservation of full filesystem metadata;
- suitability for high-assurance or regulated environments.

Independent reader implementations MUST implement §1–§11 as
normative; §12–§15 are informative descriptions of the FerroCrypt
reference implementation's behaviour.
