# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Workspace (ferrocrypt-lib + ferrocrypt-cli)
cargo build                              # build workspace members
cargo test -- --test-threads=1           # run all workspace tests sequentially
cargo clippy --workspace --all-targets -- -D warnings

# Desktop app (excluded from workspace; run separately)
cd ferrocrypt-desktop && cargo build
cd ferrocrypt-desktop && cargo run       # launch GUI
cd ferrocrypt-desktop && cargo clippy --all-targets -- -D warnings

# Run specific tests
cargo test test_name -- --test-threads=1     # single test by name
cargo test "output_file" -- --test-threads=1 # filter by substring

# Format
./fmt.sh   # formats all crates including desktop and experiments
```

Notes:
- For **doc-only changes**, do not run code tests/builds unless the change affects rustdoc rendering or examples.
- The desktop crate is excluded from the workspace, so root-level `cargo test` / `cargo clippy` do not cover it.

## Architecture

Repository layout:

- **ferrocrypt-lib** (`ferrocrypt` on crates.io) — core encryption library. All crypto logic lives here.
- **ferrocrypt-cli** — CLI binary (`ferrocrypt`). Thin wrapper calling library functions.
- **ferrocrypt-desktop** — Slint GUI app. Excluded from the Cargo workspace; built separately.

### Library Module Roles

| Module | Role |
|---|---|
| `lib.rs` | Public API: explicit `symmetric_encrypt`/`decrypt`, `hybrid_encrypt`/`decrypt`, auto-routing wrappers (`symmetric_auto`/`hybrid_auto`), `GeneratedKeyPair`, `detect_encryption_mode`, path validation, key fingerprint |
| `symmetric.rs` | Argon2id → HKDF-SHA3-256 → XChaCha20-Poly1305 streaming encrypt/decrypt |
| `hybrid.rs` | X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305 envelope + XChaCha20-Poly1305 streaming encrypt/decrypt |
| `archiver.rs` | TAR archive/unarchive (streaming, preserves directory structure). Manual recursive walk rejects symlinks and special entries at archive time; hardlinks archived as regular files. Failed extractions rename partial output with `.incomplete` suffix. |
| `format.rs` | File format constants, header/key-file parsing, version-dispatch helpers, forward-compatibility skip for minor versions |
| `replication.rs` | Triple replication with majority-vote decoding for header error correction |
| `common.rs` | Shared: `EncryptWriter`/`DecryptReader` streaming adapters (**64 KiB** chunks), HMAC-SHA3-256, `KdfParams` (serialized to headers/key files), shared crypto constants |
| `error.rs` | `CryptoError` enum: `Io`, `Cipher`, `KeyDerivation`, `SliceConversion`, `AuthenticationFailed`, `InvalidFormat`, `UnsupportedVersion`, `InvalidKdfParams`, `ExcessiveWork`, `InternalError`, `InputPath`, `InvalidInput` |

### Encryption Pipeline

```
Input file/dir
  → derive keys (Argon2id+HKDF for symmetric, random+X25519 ECDH+HKDF-SHA256 for hybrid)
  → build header (magic bytes + triple-replicated fields + HMAC)
  → write header to output .fcr file
  → tar::Builder<EncryptWriter<File>> streams TAR data through XChaCha20-Poly1305 directly to disk
```

No plaintext intermediate files touch disk. The TAR archive is never materialized — it streams directly through the encryption layer.

Decryption reverses: read header → derive/decrypt keys → verify HMAC → DecryptReader streams ciphertext through XChaCha20-Poly1305 → tar::Archive unpacks directly. (Keys are derived first because the HMAC key comes from Argon2id+HKDF in symmetric, or from the X25519-decrypted envelope in hybrid.)

### Desktop App Structure

- `ui/app.slint` — UI layout and state in Slint DSL. Defines `AppWindow` with 2 top-level tabs (Symmetric, Hybrid) and 5 internal modes (SE=0, SD=1, HE=2, HD=3, GK=4). Key generation (GK=4) is inline within the Hybrid tab via a sub-selector.
- `src/main.rs` — Rust backend: file dialog callbacks, mode auto-detection via magic bytes, threaded crypto operations with progress updates via `slint::invoke_from_event_loop`.
- `src/password_scorer.rs` — Password strength scoring (0–4 scale) adapted from Proton Pass.
- macOS uses native `NSOpenPanel` (via objc2) for combined file+folder picker; other platforms use `rfd`.

### File Format (symmetric v3.0, hybrid v4.0)

8-byte logical prefix: `[0xFC, type, major, minor, flags_be16, ext_len_be16]`
- Type `0x53` ('S') = symmetric (major 3), `0x48` ('H') = hybrid (major 4)
- The entire encrypted-file header — including the prefix — is triple-replicated for error correction
- HMAC-SHA3-256 authenticates the header: `prefix || fixed_core_fields || ext_bytes` (all in decoded form, excluding the HMAC tag itself). Single-copy replication corruption is corrected by majority vote before HMAC verification.
- Forward compatibility: a minor-version bump puts new data inside the authenticated `ext_bytes` region (sized by `ext_len` in the prefix). Older readers decode the region, include the decoded `ext_bytes` in HMAC verification, and ignore the contents.

## Key Conventions

- Primary API: `symmetric_encrypt`/`symmetric_decrypt`, `hybrid_encrypt`/`hybrid_decrypt` — explicit, return `PathBuf`.
- Auto-routing: `symmetric_auto`/`hybrid_auto` — detect encrypt vs decrypt by magic bytes, used by CLI/desktop.
- `generate_key_pair` returns `GeneratedKeyPair` with paths and fingerprint.
- `encode_recipient`/`decode_recipient` — Bech32 `fcr1...` strings for human-readable public key exchange. `hybrid_encrypt_from_recipient` encrypts from raw bytes without a key file.
- `symmetric_auto` caveats:
  - if `input_path` is already a FerroCrypt file, it decrypts and ignores `save_as`
  - otherwise it encrypts; `output_dir` is the destination directory unless `save_as` is provided
- `hybrid_auto` caveats:
  - decrypt path: `key_file` must be the private key; `passphrase` is required; `save_as` is ignored
  - encrypt path: `key_file` must be the public key; `passphrase` and `kdf_limit` are ignored
- CLI `hybrid --recipient / -r` accepts a `fcr1...` string directly for encryption. `recipient` (alias `rc`) subcommand prints the string from a key file.
- CLI never accepts passphrases as command-line arguments. Passphrases are prompted interactively via `rpassword` (hidden TTY input) with confirmation on encrypt/keygen. For non-interactive use (tests, scripts), set the `FERROCRYPT_PASSPHRASE` environment variable.
- Encrypt functions accept `save_as: Option<&Path>` to override the default `{stem}.fcr` output path.
- Integration tests use `tests/workspace/` as a temp directory, cleaned up by a `#[ctor::dtor]` hook. CLI integration tests use `FERROCRYPT_PASSPHRASE` env var to supply passphrases non-interactively.
- `ENCRYPTED_EXTENSION` (`"fcr"`) is re-exported from `format.rs`.

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
- Prefer concise user-facing messages; desktop UI space is limited.
- Keep parsing, validation, crypto, and I/O separated.
- Add or update important tests and keep them self-contained.
- Add regression tests for security-sensitive and format bugs.
- After each important change, update if relevant:
    - `README.md`
    - `CHANGELOG.md` under `[Unreleased]`
    - `ferrocrypt-lib/FORMAT.md`
    - `ferrocrypt-lib/fuzz/fuzz_targets`
    - `stress_test.sh`
- When touching code, run the relevant checks:
    - `./fmt.sh`
    - workspace: `cargo clippy --workspace --all-targets -- -D warnings`
    - workspace: `cargo test -- --test-threads=1`
    - desktop (if touched): `cd ferrocrypt-desktop && cargo clippy --all-targets -- -D warnings`
- Before finishing, review the change with adversarial thinking and future-proofing in mind.
