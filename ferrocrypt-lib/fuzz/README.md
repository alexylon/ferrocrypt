# Fuzz testing

Coverage-guided fuzz targets for ferrocrypt decryption paths using
[cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) (libfuzzer).

## Prerequisites

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Targets

| Target | What it exercises |
|---|---|
| `fuzz_symmetric_decrypt` | Feeds arbitrary bytes as a `.fcr` file into `symmetric_encryption` (decrypt path) |
| `fuzz_hybrid_decrypt` | Same for `hybrid_encryption`, with a one-time 2048-bit RSA keypair |

## Running

```bash
cd ferrocrypt-lib

# Run indefinitely (Ctrl-C to stop)
cargo +nightly fuzz run fuzz_symmetric_decrypt
cargo +nightly fuzz run fuzz_hybrid_decrypt

# Time-limited run (seconds)
cargo +nightly fuzz run fuzz_symmetric_decrypt -- -max_total_time=60

# List available targets
cargo +nightly fuzz list
```

Corpus files and crash artifacts are saved under `fuzz/corpus/` and
`fuzz/artifacts/` respectively (both gitignored).
