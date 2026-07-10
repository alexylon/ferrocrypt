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
├── keys/              ← two X25519 key pairs (recipient A and B)
└── cases/             ← the fixture bytes (`.fcr` and `public.key` files)
```

Every fixture is real bytes produced by this crate's writer and then —
for the must-reject cases — either surgically corrupted or built
through internal writer paths the public API refuses to expose
(extension bytes, unknown recipient entries, mixed recipient lists,
out-of-range KDF parameters). Each corrupted fixture isolates one
defect; where a defect must survive header authentication (KDF
parameters, TLV extension bytes), it is written **before** the header
MAC is computed, so the MAC is valid and only the defect itself can
trigger the rejection.

## Manifest

`manifest.tsv` is tab-separated with `#` comment lines. Columns:

| Column | Meaning |
|---|---|
| `file` | Fixture path relative to this directory |
| `action` | `decrypt` (open the `.fcr`, decrypt with the credential) or `read-public-key` (parse the text file as a `public.key`) |
| `credential` | `passphrase:<literal>`, `private-key:<path>,unlock=<literal>`, or `-` when rejection happens before any credential is used |
| `expect` | `ok` or `error` |
| `error_class` | Typed `CryptoError` variant the attempt must produce (`-` for `ok` rows) |
| `error_message` | Exact user-facing message (`-` for `ok` rows) |

An `ok` row must decrypt to `plaintext.txt` byte-for-byte. A row's
`error_message` is this library's `Display` output; independent
implementations should match the `error_class` failure semantics and
MAY word messages differently.

All argon2id fixtures and both private keys use the passphrase
`suite-passphrase-not-secret-do-not-reuse`. Keys and passphrase are
fixture-only — never reuse them for real data.

## Covered classes (FORMAT.md §12)

- Corrupted prefix: magic, version, kind, `prefix_flags`, oversized
  `header_len`; plus a header-region truncation.
- TLV extension region: descending tags, duplicate tag, `len` past the
  region end, unknown critical tag (reject) and unknown ignorable tag
  (must decrypt).
- Out-of-range KDF parameters under a **valid** header MAC:
  `mem_cost > 2 GiB`, `lanes = 0`, `time_cost = 13`.
- Payload: missing final chunk (`PayloadTruncated`), flipped byte and
  appended bytes (both `PayloadTampered` — see below).
- Wrong credential: wrong passphrase, and an X25519 file decrypted with
  a non-recipient key (both `RecipientUnwrapFailed`).
- Header MAC failure after a successful unwrap: `HeaderTampered` on a
  passphrase file, `HeaderMacFailedAfterUnwrap` on a multi-recipient
  X25519 file.
- Recipient lists: unknown critical entry (reject before any unwrap),
  only-unknown entries (`NoSupportedRecipient`), `argon2id` mixed with
  another entry (`IncompatibleRecipients`), and an unknown non-critical
  entry that must be skipped (file decrypts).
- All-zero X25519 ephemeral key (file-fatal
  `MalformedRecipientEntry`).
- `public.key` text grammar: uppercase input, corrupted Bech32
  checksum, valid Bech32 around a corrupted internal SHA3-256 checksum.

Two classes deserve a note because the naive expectation is wrong:

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

## Regenerating

```bash
cargo test --package ferrocrypt --lib suite_vector_gen \
    -- --ignored --test-threads=1
```

The generator (`ferrocrypt-lib/src/suite_vector_gen.rs`) replaces
`cases/`, `keys/`, `plaintext.txt`, `manifest.tsv`, and
`SUITE-VERSION`; commit the result by hand and bump `SUITE-VERSION`
when fixtures changed. Generation uses the OS CSPRNG, so bytes are not
reproducible — the committed files are the contract.

`tests/testvector_suite.rs` replays the full manifest through the
public API on every `cargo test` run, so a drift between the committed
corpus and reader behaviour fails CI.
