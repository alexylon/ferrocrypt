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
| `fuzz_header_prefix` | `read_header_from_reader` — 27-byte triple-replicated prefix, magic byte, type check |
| `fuzz_key_file_header` | `parse_key_file_header` + `validate_key_layout` — both public and private key-file variants |
| `fuzz_kdf_params` | `KdfParams::from_bytes` — 12-byte KDF parameter bounds |
| `fuzz_replication_decode` | `replication::decode` and `decode_exact` — majority-vote decoder |
| `fuzz_archive_path` | `validate_archive_path` — tar-entry path guard |
| `fuzz_recipient_decode` | `decode_recipient` — Bech32 `fcr1…` recipient string parser |
| `fuzz_detect_mode` | `detect_encryption_mode` — public top-level parser entry, end-to-end via a real temp file |

### Integration (secondary)

These feed arbitrary bytes to the full decrypt pipeline. Iteration is
slower because each run includes a full Argon2id derivation, but they
catch interaction bugs the parser-surface targets cannot see.

| Target | What it exercises |
|---|---|
| `fuzz_symmetric_decrypt` | Feeds arbitrary bytes as a `.fcr` file into `symmetric_decrypt` |
| `fuzz_hybrid_decrypt` | Same for `hybrid_decrypt`, with a one-time X25519 keypair |

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

The `fuzz` job in `.github/workflows/rust.yml` runs on every push and
pull request. It installs the nightly toolchain + `cargo-fuzz`, builds
**every** target (catches API drift when a library refactor breaks a
fuzz target), and then runs each parser-surface target for 10 seconds
as a smoke check. Crashes surface as a failing CI run.

Corpus files and crash artifacts are saved under `fuzz/corpus/` and
`fuzz/artifacts/` respectively (both gitignored).
