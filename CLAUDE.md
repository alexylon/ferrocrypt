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

# Windows cross-check (for `cfg(target_os = "windows")` / `cfg(not(unix))`
# arms such as the Windows fallback path in `atomic_output.rs`). Requires
# `rustup target add x86_64-pc-windows-gnu`, which is already installed on
# this machine.
cargo check  --package ferrocrypt --target x86_64-pc-windows-gnu
cargo clippy --package ferrocrypt --target x86_64-pc-windows-gnu --all-targets
```

Notes:
- For **doc-only changes**, do not run code tests/builds unless the change affects rustdoc rendering or examples.
- The desktop crate is excluded from the workspace, so root-level `cargo test` / `cargo clippy` do not cover it locally. **CI does cover it** via a separate `desktop` job that runs clippy + build + tests on Ubuntu / macOS / Windows on every PR.
- The Windows cross-check only type-checks (no linker), so it is sufficient for verifying `cfg(target_os = "windows")` / `cfg(not(unix))` arms compile. Use it whenever you touch `atomic_output` or any other branch that varies by platform.

## Architecture

Repository layout:

- **ferrocrypt-lib** (`ferrocrypt` on crates.io) — core encryption library. All crypto logic lives here.
- **ferrocrypt-cli** — CLI binary (`ferrocrypt`). Thin wrapper calling library functions.
- **ferrocrypt-desktop** — Slint GUI app. Excluded from the Cargo workspace; built separately.

### Library Module Roles

| Module | Role |
|---|---|
| `lib.rs` | Public API: config-struct operation surface (`symmetric_encrypt` / `symmetric_decrypt` / `hybrid_encrypt` / `hybrid_decrypt` / `generate_key_pair`) plus their `*Config` / `*Outcome` types, the `PublicKey` / `PrivateKey` / `ProgressEvent` abstractions, `detect_encryption_mode`, path validation |
| `symmetric.rs` | Argon2id → HKDF-SHA3-256 → XChaCha20-Poly1305 streaming encrypt/decrypt |
| `hybrid.rs` | X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305 envelope + XChaCha20-Poly1305 streaming encrypt/decrypt |
| `archiver.rs` | TAR archive/unarchive (streaming, preserves directory structure). Manual recursive walk rejects symlinks and special entries at archive time; hardlinks archived as regular files. Decryption writes under an `.incomplete` working name throughout and renames to the final name on success; failure leaves the `.incomplete` on disk for inspection. On Linux and macOS, extraction is anchored at a directory file descriptor and uses `openat`/`mkdirat` with `O_NOFOLLOW` to defeat local symlink/component-race attacks. |
| `format.rs` | File format constants, header/key-file parsing, version-dispatch helpers, forward-compatibility skip for minor versions |
| `replication.rs` | Triple replication with majority-vote decoding for header error correction |
| `common.rs` | Shared: `EncryptWriter`/`DecryptReader` streaming adapters (**64 KiB** chunks), HMAC-SHA3-256, `KdfParams` (serialized to headers/key files), shared crypto constants |
| `error.rs` | `CryptoError` enum, grouped by concern: filesystem/input (`Io`, `InputPath`, `InvalidInput`), format/version (`InvalidFormat`, `UnsupportedVersion`), KDF/work (`KeyDerivation`, `InvalidKdfParams`, `ExcessiveWork`), authentication (`KeyFileUnlockFailed`, `HeaderAuthenticationFailed`, `PayloadAuthenticationFailed`, `TruncatedStream`), primitives (`SliceConversion`), internal invariants (`InternalInvariant`, `InternalCryptoFailure`). Also defines the crate-private `StreamError` marker used to thread decrypt-path failures from `DecryptReader`/`EncryptWriter` through `io::Error` back into typed `CryptoError` variants via a manual `From<io::Error>` impl. |

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
- File and folder pickers go through `rfd::FileDialog` on every platform. On macOS the desktop crate calls `pick_file_or_folder()` (rfd's combined picker, which internally wraps `NSOpenPanel`); on other platforms it falls back to `pick_file()` / `pick_folder()` because rfd does not expose a combined picker outside macOS.

### File Format (symmetric v3.0, hybrid v4.0)

8-byte logical prefix: `[0xFC, type, major, minor, flags_be16, ext_len_be16]`
- Type `0x53` ('S') = symmetric (major 3), `0x48` ('H') = hybrid (major 4)
- The entire encrypted-file header — including the prefix — is triple-replicated for error correction
- HMAC-SHA3-256 authenticates the header: `prefix || fixed_core_fields || ext_bytes` (all in decoded form, excluding the HMAC tag itself). Single-copy replication corruption is corrected by majority vote before HMAC verification.
- Forward compatibility: a minor-version bump puts new data inside the authenticated `ext_bytes` region (sized by `ext_len` in the prefix). Older readers decode the region, include the decoded `ext_bytes` in HMAC verification, and ignore the contents.

### Key File Format (public.key v3, private.key v4)

8-byte key-file header: `[0xFC, type, version, algorithm, data_len_be16, flags_be16]`
- `public.key` (type `0x50` 'P', version `3`): header + 32-byte raw X25519 public key = 40 bytes total. No AEAD, no MAC — authenticity comes from out-of-band fingerprint verification.
- `private.key` (type `0x53` 'S', version `4`): header + body with layout `[kdf(12)][salt(32)][nonce(24)][ext_len_be16][ext_bytes][ciphertext+tag(48)]`. Today `ext_len = 0`, total file size 126 bytes.
- `private.key v4` binds the entire cleartext (header + kdf + salt + nonce + ext_len + ext_bytes) as AEAD **associated data**, so every byte on disk is cryptographically authenticated. The AEAD primitive can't distinguish "wrong passphrase" from "tampered cleartext" — both surface as `CryptoError::KeyFileUnlockFailed`, whose Display wording (`"Private key unlock failed: wrong passphrase or tampered file"`) reflects both causes.
- Forward compatibility: future `v4.x` minors can populate `ext_bytes` with TLV metadata. Older `v4` readers authenticate the bytes via the AEAD tag and ignore unrecognized tags.
- 0.3.0 is the first release to define versioned key-file formats. Starting numbers (`public.key v3` / `private.key v4`) are above `1` because the formats went through iterations during pre-release development; no earlier shape ever shipped. `public.key` stayed at its pre-release value because it's 40 bytes and carries no secret — redesigning it buys nothing.

## Key Conventions

- Operation API: each public operation function takes a config struct by value plus a `Fn(&ProgressEvent)` callback and returns a `*Outcome` struct. The 5 operations are `symmetric_encrypt` / `symmetric_decrypt` / `hybrid_encrypt` / `hybrid_decrypt` / `generate_key_pair`. All config and outcome types are `#[non_exhaustive]` so fields and enum variants can grow without breaking downstream callers.
- Config construction: `SymmetricEncryptConfig::new(input, output_dir, passphrase)` sets required fields; `.save_as(path)` / `.kdf_limit(limit)` builder methods set optional fields. Configs are `Clone` so a template can be reused across multiple operations.
- Key-source abstractions: `hybrid_encrypt` consumes a `PublicKey` in its config; `hybrid_decrypt` consumes a `PrivateKey`. `PublicKey` has constructors `from_key_file(path)`, `from_bytes([u8; 32])`, `from_recipient_string("fcr1…")` (plus `FromStr`), and methods `fingerprint()`, `to_recipient_string()`, `to_bytes()`, `validate()`. `PrivateKey` has `from_key_file(path)` today. Both wrappers are `#[non_exhaustive]` structs over a private inner enum so new sources (in-memory secret material, hardware-backed keys) can be added as constructors without breaking the config shape. There is no separate `Recipient` type — the domain role is captured by the field name (`HybridEncryptConfig::public_key`) mirroring the decrypt side's `HybridDecryptConfig::private_key`.
- Progress signalling: `ProgressEvent` is a `#[non_exhaustive]` enum with 4 current variants (`DerivingKey`, `Encrypting`, `Decrypting`, `GeneratingKeyPair`). It implements `Display` with wording that is locked in by a unit test; CLI and desktop render `{event}` directly. New progress phases are added as new variants — match arms in caller code need a `_` wildcard.
- **In-repo direction routing:** ferrocrypt-cli and ferrocrypt-desktop call `detect_encryption_mode` (CLI) or read `mode` from UI state (desktop) first, then build the appropriate explicit config. The library no longer exposes auto-routing convenience wrappers — direction detection is a caller concern.
- Bech32 `fcr1…` recipient strings are the human-readable public-key exchange format. The typed entry point is `PublicKey::from_recipient_string(&str)` or `"fcr1…".parse::<PublicKey>()` (see the key-source abstractions bullet above); `decode_recipient(&str) -> [u8; 32]` is kept as the low-level primitive for the `fuzz_recipient_decode` fuzz target and callers that specifically want raw bytes.
- CLI `hybrid --recipient / -r` accepts a `fcr1...` string directly for encryption. `recipient` (alias `rc`) subcommand prints the string from a key file.
- CLI never accepts passphrases as command-line arguments. Passphrases are prompted interactively via `rpassword` (hidden TTY input) with confirmation on encrypt/keygen. For non-interactive use (tests, scripts), set the `FERROCRYPT_PASSPHRASE` environment variable.
- Integration tests use `tests/workspace/` as a temp directory, cleaned up by a `#[ctor::dtor]` hook. CLI integration tests use `FERROCRYPT_PASSPHRASE` env var to supply passphrases non-interactively. Both integration and compatibility test binaries pull `symmetric_auto` / `hybrid_auto` / `generate_key_pair` shims from a shared `tests/common/mod.rs` module — these preserve the pre-0.3.0 positional-arg call shape around the new config API so the ~140 existing call sites don't churn.
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
- After each important change, but only when we are ready to commit, update if relevant:
    - `README.md`
    - `CHANGELOG.md` under `[Unreleased]` — user-relevant changes only (functionality, security behavior, public API, supported platforms, major technical decisions). Keep CI/build/tooling entries to one-liners; skip entirely if not user-visible.
    - `ferrocrypt-lib/FORMAT.md`
    - `ferrocrypt-lib/fuzz/fuzz_targets`
    - `stress_test.sh`
- When touching code, run the relevant checks:
    - `./fmt.sh`
    - workspace: `cargo clippy --workspace --all-targets -- -D warnings`
    - workspace: `cargo test -- --test-threads=1`
    - desktop (if touched): `cd ferrocrypt-desktop && cargo clippy --all-targets -- -D warnings`
    - supply chain (if `Cargo.toml` / `Cargo.lock` changed): `cargo vet` — mirrors the `vet` job in `.github/workflows/rust.yml` so local runs catch failures before GitHub CI does. Requires `cargo install --locked cargo-vet` once.
- Before finishing, review the change with adversarial thinking and future-proofing in mind.
- Never commit or stage changes with Git.
