# Fuzz testing

Coverage-guided fuzz targets for ferrocrypt using
[cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) (libfuzzer).

## Prerequisites

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Targets

| Target | What it exercises |
|---|---|
| `fuzz_symmetric_decrypt` | Feeds arbitrary bytes as a `.fcr` file into `symmetric_decrypt` |
| `fuzz_hybrid_decrypt` | Same for `hybrid_decrypt`, with a one-time X25519 keypair |
| `fuzz_symmetric_encrypt` | Feeds arbitrary bytes as file content into `symmetric_encrypt` |
| `fuzz_hybrid_encrypt` | Same for `hybrid_encrypt`, with a one-time X25519 keypair |

Decrypt targets test robustness against malformed/malicious input.
Encrypt targets test the archiver, header construction, and streaming pipeline.

## Running

```bash
cd ferrocrypt-lib

# Run indefinitely (Ctrl-C to stop)
cargo +nightly fuzz run fuzz_symmetric_decrypt
cargo +nightly fuzz run fuzz_hybrid_decrypt
cargo +nightly fuzz run fuzz_symmetric_encrypt
cargo +nightly fuzz run fuzz_hybrid_encrypt

# Time-limited run (seconds)
cargo +nightly fuzz run fuzz_symmetric_decrypt -- -max_total_time=60

# List available targets
cargo +nightly fuzz list
```

Corpus files and crash artifacts are saved under `fuzz/corpus/` and
`fuzz/artifacts/` respectively (both gitignored).
