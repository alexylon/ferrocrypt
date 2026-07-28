# Fuzz testing

Coverage-guided fuzz targets for ferrocrypt using
[cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) (libfuzzer).

## Prerequisites

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Targets

Two layers: cheap **parser-surface** targets that iterate millions of
times per second, and slower **integration** targets that drive the
full decrypt pipeline.

### Parser-surface (primary)

These targets import internals via the `ferrocrypt/fuzzing` cargo
feature and hit the lowest useful parser layer directly. They do not
run Argon2id, so the iteration rate is orders of magnitude higher than
the integration targets.

| Target | What it exercises |
|---|---|
| `fuzz_header_prefix` | v1 12-byte prefix + `header_fixed` + recipient-entry framing via `read_encrypted_header` |
| `fuzz_private_key_header` | v1 90-byte `private.key` cleartext header and total-size shape checks |
| `fuzz_tlv` | `validate_tlv` extension-region grammar: canonical ordering, reserved tags, critical-tag rejection |
| `fuzz_kdf_params` | `KdfParams::from_bytes` structural and local-resource bounds |
| `fuzz_archive_path` | `validate_fca_path` — the FCA archive path-grammar gate (writer/reader symmetric, takes UTF-8 `&str`); asserts every FORMAT.md §9.6 grammar promise on accepted paths, with the reserved-device list restated independently so an accept-direction regression crashes instead of passing |
| `fuzz_fca_header` | `parse_fca_header` — 27-byte FCA fixed header parser; asserts returned values are inside the default `ArchiveLimits` on success |
| `fuzz_fca_manifest` | Full FCA manifest pipeline: header → manifest bytes → `parse_manifest_bytes` → tree-shape validation; asserts spec §20 manifest invariants on success, then re-serializes through the writer gate and asserts byte-identity (writer/reader symmetry) |
| `fuzz_fca_full_pipeline` | `archive::unarchive` end-to-end on arbitrary bytes against a fresh tempdir per iteration (header, `archive_ext` TLV, manifest, tree, content streaming, promotion, cleanup); asserts the `DeleteOnError` contract — no `.incomplete` residue on error, output present and no residue on success |
| `fuzz_stream_decrypt` | STREAM-BE32 `DecryptReader` on raw ciphertext under a fixed key/nonce: chunk refill, exact-chunk one-byte peek, and classification of truncation, tampering, trailing data, and an empty final chunk after data; when an input decrypts, asserts deterministic re-encryption is byte-identical |
| `fuzz_recipient_string_decode` | Generic typed-payload recipient-string decoder (two-argument form with a fuzzed length cap): arbitrary type names and key-material lengths, plus the canonical-padding re-encode check |
| `fuzz_recipient_decode` | Bech32 `fcr1…` recipient string parser and internal SHA3-256 checksum |
| `fuzz_public_key_file` | Complete `public.key` content grammar: key-kind routing, UTF-8, the optional trailing `LF`, other ASCII whitespace, and the X25519 type and length; accepted content must re-encode byte-for-byte through the public recipient-string API |
| `fuzz_probe_mode` | `probe_recipient_mode` top-level parser entry, end-to-end via a real temp file |

### Integration (secondary)

These feed arbitrary bytes to the full decrypt pipeline. Iteration is
slower because each run includes a full Argon2id derivation, but they
catch interaction bugs the parser-surface targets cannot see.

| Target | What it exercises |
|---|---|
| `fuzz_symmetric_decrypt` | Drives arbitrary bytes through `Decryptor::open` and `PassphraseDecryptor::decrypt` (passphrase recipient mode); Argon2id capped at 8 MiB via `kdf_limit` so a crafted header cannot stall iterations |
| `fuzz_hybrid_decrypt` | Drives arbitrary bytes through `Decryptor::open` and `PrivateKeyDecryptor::decrypt` (X25519 recipient mode), using a one-time keypair sealed at the 19 MiB writer floor with a matching `kdf_limit`, so the per-iteration `private.key` unlock stays cheap |

## Seed corpora

`seeds/<target>/` holds small checked-in inputs that reach important
parser states on the first iteration: valid artifacts that sit behind a
checksum or a structured encoding, plus selected rejection boundaries.
`corpus/` is gitignored, so it starts empty on CI and fresh checkouts.
Regenerate after any wire-format change:

```bash
cargo run --example gen_seeds
```

Every seed is checked through the production reader during generation,
so format drift fails regeneration instead of silently leaving stale
seeds. Valid seeds produced by the writer, including supported forms
patched from writer output, must be accepted. Deliberately malformed
seeds for shapes the writer cannot emit must fail with the expected
error. CI passes `seeds/<target>` as an extra corpus directory; locally,
`gen_seeds` also copies each seed into `corpus/<target>` so a plain
`cargo fuzz run <target>` picks it up.

## Running

```bash
cd ferrocrypt-lib/fuzz

# List all targets
cargo +nightly fuzz list

# Run indefinitely (Ctrl-C to stop)
cargo +nightly fuzz run fuzz_header_prefix

# Time-limited run (seconds)
cargo +nightly fuzz run fuzz_kdf_params -- -max_total_time=60
```

## CI

The `fuzz` job is a reusable workflow at `.github/workflows/fuzz.yml`,
called from both `rust.yml` (every push and pull request) and
`release.yml` (every tag push, as a release-gate — `build` declares
`needs: fuzz`). It installs the nightly toolchain + `cargo-fuzz`,
builds **every** target (catches API drift when a library refactor
breaks a fuzz target), and then runs each parser-surface target for
60 seconds. The two integration-level targets (`fuzz_symmetric_decrypt`,
`fuzz_hybrid_decrypt`) are built but skipped from the per-run loop
because each iteration runs a full Argon2id derivation. Crashes
surface as a failing CI run, and a tag push cannot publish artifacts
unless fuzz passes.

Corpus files and crash artifacts are saved under `fuzz/corpus/` and
`fuzz/artifacts/` respectively (both gitignored).
