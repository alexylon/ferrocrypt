# `testvectors/suite/` — edge-case corpus (versioned)

**Status:** populated. `SUITE-VERSION` tracks the corpus revision so
readers can pin to a specific one. Unlike `testvectors/wire/` (frozen
forever once it ships at 1.0), fixtures here **may** be added,
corrected, or extended in any release; each such change bumps
`SUITE-VERSION`.

Like `testvectors/wire/`, this directory serves independent reader
implementations — a different role from `tests/fixtures/`, which is an
internal regeneratable regression net for this codebase.

## Layout

```
testvectors/suite/
├── README.md          ← this file
├── SUITE-VERSION      ← corpus revision, bumped on any fixture change
├── plaintext.txt      ← source file every valid fixture encrypts
├── manifest.tsv       ← one row per attempt: file, action, credential,
│                        expected outcome
├── keys/              ← two X25519 key pairs plus a tampered private key
└── cases/             ← malformed/edge-case `.fcr` and key-file bytes
```

Every fixture is real bytes produced by this crate's writer and then —
for the must-reject cases — either surgically corrupted or built
through internal writer paths the public API refuses to expose
(extension bytes, unknown recipient entries, mixed recipient lists,
out-of-range KDF parameters). Each corrupted fixture isolates one
defect. Structural and policy cases that must survive header authentication
(out-of-range or over-cap KDF parameters and TLV extension bytes) are written
**before** the header MAC is computed, so the MAC is valid and only the defect
itself can trigger the rejection. Recipient-body tamper cases are surgical
mutations of valid files; their per-recipient unwrap fails before a candidate
key could reach the header-MAC gate.

## Manifest

`manifest.tsv` is tab-separated with `#` comment lines. Columns:

| Column | Meaning |
|---|---|
| `file` | Fixture path relative to this directory |
| `action` | `decrypt` (open and decrypt a `.fcr`), `read-public-key` (parse a `public.key`), or `validate-private-key` (structurally validate a `private.key`) |
| `credential` | `passphrase:<literal>`, `private-key:<path>,unlock=<literal>`, or `-` when rejection happens before any credential is used |
| `expect` | `ok` or `error` |
| `error_class` | Typed `CryptoError` variant the attempt must produce (`-` for `ok` rows) |
| `error_message` | Exact user-facing message (`-` for `ok` rows) |

An `ok` decrypt row must reproduce `plaintext.txt` byte-for-byte; an
`ok` key-file row must parse or validate successfully. A row's
`error_message` is this library's `Display` output; independent
implementations should match the `error_class` failure semantics and MAY
word messages differently.

All argon2id fixtures and both private keys use the passphrase
`suite-passphrase-not-secret-do-not-reuse`. Keys and passphrase are
fixture-only — never reuse them for real data.

## Covered classes (FORMAT.md §12)

- Corrupted prefix: magic, version, kind, `prefix_flags`, oversized
  `header_len`; plus a header-region truncation.
- Outer `.fcr` TLV extension region: descending tags, duplicate tag, `len`
  past the region end, unknown critical tag (reject), and unknown ignorable
  tag (must decrypt).
- FCA archive-level and per-entry TLV regions: each has an unknown ignorable
  success case plus malformed and unknown-critical rejection cases.
- Out-of-range KDF parameters under a **valid** header MAC:
  `mem_cost > 2 GiB`, `lanes = 0`, `time_cost = 13`.
- Structurally valid KDF parameters above the default local memory cap,
  rejected before Argon2id runs.
- Payload: missing final chunk (`PayloadTruncated`), flipped byte and
  appended bytes (both `PayloadTampered`), and an empty final chunk
  after a full data chunk (`InvalidFormat(MalformedPayloadStream)`).
  These classifications are explained below.
- Wrong credential: wrong passphrase, and an X25519 file decrypted with
  a non-recipient key (both `RecipientUnwrapFailed`).
- Header MAC failure after a successful unwrap: `HeaderTampered` on a
  passphrase file, `HeaderMacFailedAfterUnwrap` on a multi-recipient
  X25519 file.
- Recipient lists: unknown critical entry (reject before any unwrap),
  only-unknown entries (`NoSupportedRecipient`), `argon2id` mixed with
  another entry (`IncompatibleRecipients`), and an unknown non-critical
  entry that must be skipped (file decrypts).
- Native recipient body coverage: every Argon2id and X25519 body field is
  independently tampered; both native body lengths reject when short, and a
  non-zero X25519 native flag rejects. The existing Argon2id critical-flag
  case supplies the matching Argon2id flag coverage.
- All-zero X25519 ephemeral key (file-fatal
  `MalformedRecipientEntry`).
- Key files: valid `public.key` and `private.key` artifacts, plus uppercase
  public-key text, corrupted Bech32 and internal SHA3-256 checksums,
  non-canonical Bech32 padding, a newer public-key payload version, CRLF and
  leading-whitespace content, all-zero X25519 key material under a valid
  checksum, private structural defects, both public/private key-file
  crossings, out-of-range private-key KDF parameters, and private-key unlock
  authentication failure.

Four cases need further explanation because their classifications may
be unexpected:

- **Truncation vs tamper.** STREAM cannot distinguish a chunk that was
  shortened from a chunk that was modified — both fail AEAD
  authentication and report `PayloadTampered`. Only a payload whose
  final chunk is missing entirely is provably truncated, so that is
  what `payload-truncated.fcr` ships.
- **Trailing data.** Appending bytes to a file shifts the final-chunk
  boundary, so the appended tail is authenticated as part of the last
  chunk and fails as `PayloadTampered`. The distinct
  `ExtraDataAfterPayload` class exists for stream readers that signal
  end-of-input at the chunk boundary and later yield more bytes — a
  shape a committed file cannot express.
- **Empty final chunk after data.** A stream can encode all plaintext in
  non-final chunks and then close with an authenticated empty final
  chunk. This produces the same plaintext as the canonical encoding and
  would pass a reader that checks authentication alone. FORMAT.md §5
  forbids writers from emitting this shape and requires readers to
  reject it, preserving a single ciphertext encoding for each plaintext
  under a fixed key and nonce. Creating this fixture requires the
  payload key, so the rule enforces canonical encoding rather than
  protecting against unauthenticated modification.
  `payload-empty-final-after-data.fcr` contains this shape.
- **Wrong binary kind vs key-file crossing.**
  `privatekey-wrong-kind.private.key` carries the encrypted-file kind byte
  `0x45` where the private-key kind `0x4B` belongs, so it reports
  `WrongKind { kind: 0x45 }`. Supplying a valid `public.key` to the private-key
  validator, or a valid `private.key` to the public-key reader, instead reports
  `WrongKeyFileType`; that diagnostic is reserved for those concrete
  public/private crossings.

## Regenerating

```bash
cargo test --package ferrocrypt --lib suite_vector_gen \
    -- --ignored --test-threads=1
```

The generator (`ferrocrypt-lib/src/suite_vector_gen.rs`) rewrites
`cases/`, `keys/`, `plaintext.txt`, `manifest.tsv`, and
`SUITE-VERSION`; commit the regenerated files manually. Its fixed RNG
seed makes an unchanged generator reproduce the corpus byte-for-byte,
leaving an empty diff. Existing fixture bytes also remain stable when
new RNG-consuming fixtures are appended without changing the earlier
draw order.

Increment `SUITE_VERSION` whenever a fixture is added, removed, or
changed. The constant is the source of truth: regeneration writes its
value to `SUITE-VERSION`, so do not edit the committed file directly.

`tests/testvector_suite.rs` replays the full manifest through the
public API on every `cargo test` run, so a drift between the committed
corpus and reader behaviour fails CI.
