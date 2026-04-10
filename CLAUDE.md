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
| `lib.rs` | Public API: explicit `symmetric_encrypt`/`decrypt`, `hybrid_encrypt`/`decrypt`, auto-routing wrappers (`symmetric_auto`/`hybrid_auto`), `GeneratedKeyPair`, `detect_encryption_mode`, path validation, key fingerprint |
| `symmetric.rs` | Argon2id → HKDF-SHA3-256 → XChaCha20-Poly1305 streaming encrypt/decrypt |
| `hybrid.rs` | X25519 + XChaCha20-Poly1305 envelope + XChaCha20-Poly1305 streaming encrypt/decrypt |
| `archiver.rs` | TAR archive/unarchive (streaming, preserves directory structure). Manual recursive walk rejects symlinks and special entries at archive time; hardlinks archived as regular files. Failed extractions rename partial output with `.incomplete` suffix. |
| `format.rs` | File format constants, header/key-file parsing, version-dispatch helpers, forward-compatibility skip for minor versions |
| `replication.rs` | Triple replication with majority-vote decoding for header error correction |
| `common.rs` | Shared: `EncryptWriter`/`DecryptReader` streaming adapters (64KB chunks), HMAC-SHA3-256, `KdfParams` (serialized to headers/key files), shared crypto constants |
| `error.rs` | `CryptoError` enum: `Io`, `Cipher`, `KeyDerivation`, `SliceConversion`, `AuthenticationFailed`, `InvalidFormat`, `UnsupportedVersion`, `InvalidKdfParams`, `InternalError`, `InputPath`, `InvalidInput` |

### Encryption Pipeline

```
Input file/dir
  → derive keys (Argon2id+HKDF for symmetric, random+X25519/ChaChaBox for hybrid)
  → build header (magic bytes + triple-replicated fields + HMAC)
  → write header to output .fcr file
  → tar::Builder<EncryptWriter<File>> streams TAR data through XChaCha20-Poly1305 directly to disk
```

No plaintext intermediate files touch disk. The TAR archive is never materialized — it streams directly through the encryption layer.

Decryption reverses: read header → derive/decrypt keys → verify HMAC → DecryptReader streams ciphertext through XChaCha20-Poly1305 → tar::Archive unpacks directly. (Keys are derived first because the HMAC key comes from Argon2id+HKDF in symmetric, or from the X25519-decrypted envelope in hybrid.)

### Desktop App Structure

- `ui/app.slint` — UI layout and state in Slint DSL. Defines `AppWindow` with 2 top-level tabs (Symmetric, Hybrid) and 5 internal modes (SE=0, SD=1, HE=2, HD=3, GK=4). Key generation (GK=4) is inline within the Hybrid tab via a sub-selector.
- `src/main.rs` — Rust backend: file dialog callbacks, mode auto-detection via magic bytes, threaded crypto operations with progress updates via `slint::invoke_from_event_loop`.
- `src/password_scorer.rs` — Password strength scoring (0–4 scale) with character-class analysis, sequence/repetition penalties, and common-password detection.
- macOS uses native `NSOpenPanel` (via objc2) for combined file+folder picker; other platforms use `rfd`.

### File Format (v3.0)

8-byte logical prefix: `[0xFC, type, major, minor, header_len_be16, flags_be16]`
- Type `0x53` ('S') = symmetric, `0x48` ('H') = hybrid
- The entire header — including the prefix — is triple-replicated for error correction
- HMAC-SHA3-256 authenticates the header (prefix + decoded canonical field values, excluding the HMAC tag itself). The HMAC is computed over majority-vote-decoded values so that single-copy replication corruption is correctable without failing HMAC verification.
- Forward compatibility: a minor-version bump may append fields **after** the HMAC tag; older readers use `header_len` to skip them (`skip_unknown_header_bytes`)

## Key Conventions

- Primary API: `symmetric_encrypt`/`symmetric_decrypt`, `hybrid_encrypt`/`hybrid_decrypt` — explicit, return `PathBuf`.
- Auto-routing: `symmetric_auto`/`hybrid_auto` — detect encrypt vs decrypt by magic bytes, used by CLI/desktop.
- `generate_key_pair` returns `GeneratedKeyPair` with paths and fingerprint.
- Encrypt functions accept `save_as: Option<&Path>` to override the default `{stem}.fcr` output path.
- Integration tests use `tests/workspace/` as a temp directory, cleaned up by a `#[ctor::dtor]` hook.
- `ENCRYPTED_EXTENSION` ("fcr") constant lives in `format.rs`.

## Non-Negotiable Rules

- Use idiomatic Rust and repository naming conventions.
- Keep code DRY and focused.
- Avoid magic strings and numbers.
- Do not add self-explanatory comments.
- Do not leave `unwrap()` or `expect()` in normal code paths.
- Never invent cryptography.
- Use standard, reviewed crypto crates and constructions only.
- Treat all external input as adversarial.
- Never leak secrets through logs, errors, debug output, or UI.
- Prefer authenticated encryption.
- Fail closed on malformed, truncated, ambiguous, or unsupported input.
- Use strong types where possible.
- Keep errors and messages up to 64 characters to fit the desktop field.
- Keep parsing, validation, crypto, and I/O separated.
- Add or update important tests and keep them self-contained.
- Add regression tests for security-sensitive and format bugs.
- After each important change, update if needed:
    - `README.md`
    - `CHANGELOG.md` under `[Unreleased]`
    - `ferrocrypt-lib/FORMAT.md`
    - `ferrocrypt-lib/fuzz/fuzz_targets`
    - `stress_test.sh`
- Run:
    - `cargo fmt --all`
    - `cargo clippy --all-targets -- -D warnings`
    - `cargo test --all`
- Before finishing, review the change with adversarial thinking and future-proofing in mind.
