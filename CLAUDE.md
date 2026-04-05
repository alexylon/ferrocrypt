# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Workspace (lib + CLI)
cargo build                    # build workspace members
cargo test -- --test-threads=1 # run all tests (integration tests need sequential execution)

# Desktop app (excluded from workspace, must cd or specify path)
cd ferrocrypt-desktop && cargo build
cd ferrocrypt-desktop && cargo run    # launch GUI

# Run specific tests
cargo test test_name -- --test-threads=1     # single test by name
cargo test "output_file" -- --test-threads=1 # filter by substring

# Format
./fmt.sh   # formats all crates including desktop and experiments
```

## Architecture

Three crates, one shared library:

- **ferrocrypt-lib** (`ferrocrypt` on crates.io) — core encryption library. All crypto logic lives here.
- **ferrocrypt-cli** — CLI binary (`ferrocrypt`). Thin wrapper calling library functions.
- **ferrocrypt-desktop** — Slint GUI app. Excluded from the Cargo workspace; built separately.

### Library Module Roles

| Module | Role |
|---|---|
| `lib.rs` | Public API, encrypt/decrypt routing (magic-byte detection), temp workspace management |
| `symmetric.rs` | Argon2id → HKDF-SHA3-256 → XChaCha20-Poly1305 streaming encrypt/decrypt |
| `hybrid.rs` | RSA-4096 OAEP envelope + XChaCha20-Poly1305 streaming encrypt/decrypt |
| `archiver.rs` | ZIP archive/unarchive (lossless store, preserves directory structure) |
| `format.rs` | File format constants, header parsing, forward-compatibility skip for minor versions |
| `replication.rs` | Triple replication with majority-vote decoding for header error correction |
| `common.rs` | Shared: streaming I/O (64KB chunks), HMAC-SHA3-256, path normalization |
| `error.rs` | `CryptoError` enum |

### Encryption Pipeline

```
Input file/dir → archiver::archive → ZIP in temp dir
  → derive keys (Argon2id+HKDF for symmetric, random+RSA for hybrid)
  → build header (magic bytes + triple-replicated fields + HMAC)
  → XChaCha20-Poly1305 stream encrypt → output .fcr file
  → cleanup temp dir
```

Decryption reverses: read header → derive/decrypt keys → verify HMAC → stream decrypt → unarchive. (Keys are derived first because the HMAC key comes from Argon2id+HKDF in symmetric, or from the RSA-decrypted envelope in hybrid.)

### Desktop App Structure

- `ui/app.slint` — UI layout and state in Slint DSL. Defines `AppWindow` with 2 top-level tabs (Symmetric, Hybrid) and 5 internal modes (SE=0, SD=1, HE=2, HD=3, GK=4). Key generation (GK=4) is inline within the Hybrid tab via a sub-selector.
- `src/main.rs` — Rust backend: file dialog callbacks, mode auto-detection via magic bytes, threaded crypto operations with progress updates via `slint::invoke_from_event_loop`.
- `src/password_scorer.rs` — Password strength scoring (0–4 scale) with character-class analysis, sequence/repetition penalties, and common-password detection.
- macOS uses native `NSOpenPanel` (via objc2) for combined file+folder picker; other platforms use `rfd`.

### File Format (v1.0)

8-byte prefix: `[0xFC, type, major, minor, header_len_be16, flags_be16]`
- Type `0x53` ('S') = symmetric, `0x48` ('H') = hybrid
- All header fields triple-replicated for error correction
- HMAC-SHA3-256 authenticates the header (prefix + all fields except the HMAC tag itself)
- Forward compatibility: a minor-version bump may append fields **after** the HMAC tag; older readers use `header_len` to skip them (`skip_unknown_header_bytes`)

## Key Conventions

- The `_with_progress` function variants accept `output_file: Option<&str>` to override the default `{stem}.fcr` output path (ignored during decryption).
- The non-progress API (`symmetric_encryption`, `hybrid_encryption`) keeps a stable signature — passes `None` internally.
- Encrypt vs decrypt is routed by reading magic bytes, not file extension.
- Integration tests use `tests/workspace/` as a temp directory, cleaned up by a `#[ctor::dtor]` hook.
- `ENCRYPTED_EXTENSION` ("fcr") and `ENCRYPTED_DOT_EXTENSION` (".fcr") constants live in `format.rs`.

## Code Guidelines

- Do not add self-explanatory comments; only add comments where the logic is non-obvious
- Avoid magic strings and numbers — use named constants
- Keep code DRY — extract shared logic into helpers
- Handle unwraps — prefer returning errors or using safe alternatives
- Tests should be self-contained and only cover important behavior
- After each new feature, update README.md and CHANGELOG.md (under `[Unreleased]`)
- After each session, double-check all changes against these guidelines before finishing
