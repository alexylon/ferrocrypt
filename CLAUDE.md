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
| `symmetric.rs` | Passphrase → Argon2id → HKDF-SHA3-256 → `wrap_key`; wraps a per-file random `file_key` via XChaCha20-Poly1305; derives `payload_key` + `header_key` from `file_key` via HKDF-SHA3-256; streaming encrypt/decrypt. |
| `hybrid.rs` | X25519 ECDH → HKDF-SHA3-256 → `wrap_key`; same file-key indirection + post-unwrap subkey derivation as symmetric. Also owns the `private.key` (passphrase-wrapped, binary) and `public.key` (UTF-8 text file carrying `fcr1…`) handling, plus Bech32 recipient-string encode/decode. |
| `archiver.rs` | TAR archive/unarchive (streaming, preserves directory structure). Owns `validate_encrypt_input`, the per-entry rule set (reject symlinks and non-regular/non-directory inputs); the encrypt entry points in `lib.rs` call this up-front so Argon2id never fires for a symlink, and `archive` re-runs it as defense-in-depth. Hardlinks are archived as regular files. Decryption writes under an `.incomplete` working name throughout and renames to the final name on success; failure leaves the `.incomplete` on disk for inspection. On Linux and macOS, extraction is anchored at a directory file descriptor and uses `openat`/`mkdirat` with `O_NOFOLLOW` to defeat local symlink/component-race attacks. |
| `format.rs` | v1 format constants, 8-byte prefix layout, `private.key` cleartext header, replicated-prefix encode/decode with canonicity check (`decode_and_canonicalize_prefix`), `build_encoded_header_prefix` helper. |
| `replication.rs` | Triple-replication `encode` / `decode` / `decode_exact` primitives used only for the 8-byte `.fcr` prefix. Body fields are stored raw in v1. |
| `common.rs` | Shared: `EncryptWriter`/`DecryptReader` streaming adapters (**64 KiB** chunks), HMAC-SHA3-256 helpers, `KdfParams`, `KdfLimit`, HKDF-SHA3-256 expansion helper, file-key derivation (`generate_file_key`, `seal_file_key`, `open_file_key`, `derive_subkeys`, `derive_passphrase_wrap_key`), canonical TLV validator (`validate_tlv`), pinned HKDF info-string constants (`HKDF_INFO_SYM_WRAP`, `HKDF_INFO_HYB_WRAP`, `HKDF_INFO_PRIVATE_KEY_WRAP`, `HKDF_INFO_PAYLOAD`, `HKDF_INFO_HEADER`), random-bytes helpers (`random_bytes`, `random_secret`). |
| `error.rs` | `CryptoError` enum, grouped by concern: filesystem/input (`Io`, `InputPath`, `InvalidInput`), format/version (`InvalidFormat`, `UnsupportedVersion`), KDF/work (`KeyDerivation`, `InvalidKdfParams`, `ExcessiveWork`), authentication (`KeyFileUnlockFailed`, `SymmetricEnvelopeUnlockFailed`, `HybridEnvelopeUnlockFailed`, `HeaderTampered`, `PayloadTampered`, `PayloadTruncated`, `ExtraDataAfterPayload`), primitives (`SliceConversion`), internal invariants (`InternalInvariant`, `InternalCryptoFailure`). Also defines the crate-private `StreamError` marker used to thread decrypt-path failures from `DecryptReader`/`EncryptWriter` through `io::Error` back into typed `CryptoError` variants via a manual `From<io::Error>` impl. |

### Encryption Pipeline (v1)

```
Input file/dir
  → derive wrap_key (passphrase → Argon2id → HKDF-SHA3-256 for symmetric;
                     X25519 ECDH → HKDF-SHA3-256 for hybrid)
  → generate random 32-byte file_key
  → seal file_key with wrap_key (XChaCha20-Poly1305) → wrapped_file_key
  → derive payload_key + header_key from file_key (HKDF-SHA3-256)
  → build header (replicated prefix + mode envelope + stream_nonce + ext_bytes + HMAC)
  → write header to output .fcr file
  → tar::Builder<EncryptWriter<File>> streams TAR data through XChaCha20-Poly1305
    directly to disk, keyed by payload_key
```

No plaintext intermediate files touch disk. The TAR archive is never materialized — it streams directly through the encryption layer.

Decryption reverses (FORMAT.md §4.8 eight-step order): read + canonicity-check prefix → read fixed header → validate KDF params → unwrap file_key via envelope AEAD (wrong passphrase / wrong key → `*EnvelopeUnlockFailed`) → derive header_key + payload_key → verify HMAC (tamper outside envelope → `HeaderTampered`) → validate TLV after authentication → DecryptReader streams ciphertext through XChaCha20-Poly1305 → tar::Archive unpacks directly.

### Desktop App Structure

- `ui/app.slint` — UI layout and state in Slint DSL. Defines `AppWindow` with 2 top-level tabs (Symmetric, Hybrid) and 5 internal modes (SE=0, SD=1, HE=2, HD=3, GK=4). Key generation (GK=4) is inline within the Hybrid tab via a sub-selector.
- `src/main.rs` — Rust backend: file dialog callbacks, mode auto-detection via magic bytes, threaded crypto operations with progress updates via `slint::invoke_from_event_loop`.
- `src/password_scorer.rs` — Password strength scoring (0–4 scale) adapted from Proton Pass.
- File and folder pickers go through `rfd::FileDialog` on every platform. On macOS the desktop crate calls `pick_file_or_folder()` (rfd's combined picker, which internally wraps `NSOpenPanel`); on other platforms it falls back to `pick_file()` / `pick_folder()` because rfd does not expose a combined picker outside macOS.

### File Format (v1 — every artefact)

See `ferrocrypt-lib/FORMAT.md` for the full byte-level spec. Summary:

**`.fcr` 8-byte logical prefix (27 bytes on disk, triple-replicated):**
`[magic(4) "FCR\0"][version(1)=0x01][type(1)][ext_len_be16]`

- Type `0x53` ('S') = symmetric, `0x48` ('H') = hybrid
- Replication scope is **only** the prefix. Body fields (envelope, stream_nonce, ext_bytes, HMAC tag, ciphertext) are stored raw.
- Canonicity is enforced before HMAC: readers majority-decode the logical prefix, re-encode canonically, and reject `CorruptedPrefix` if on-disk ≠ canonical. The decoded view is returned in the error so upgrade diagnostics still surface on a bit-rotten file.
- HMAC-SHA3-256 authenticates: `on_disk_prefix(27) || envelope(104/116) || stream_nonce(19) || ext_bytes`.
- Forward compatibility: ignorable TLV tags in `ext_bytes` are authenticated + skipped; critical tags (`0x8001..=0xFFFF`) are rejected as `UnknownCriticalTag`. See FORMAT.md §6.

**Mode envelopes (raw, not replicated):**
- Symmetric (116 B): `argon2_salt(32) || kdf_params(12) || wrap_nonce(24) || wrapped_file_key(48)`
- Hybrid (104 B): `ephemeral_pubkey(32) || wrap_nonce(24) || wrapped_file_key(48)`

**File-key indirection:** both modes wrap a random per-file 32-byte `file_key`. `payload_key` and `header_key` are derived from `file_key` via HKDF-SHA3-256 (`info = "ferrocrypt/v1/payload"` with salt = `stream_nonce`; `info = "ferrocrypt/v1/header"` with empty salt). Identical post-unwrap shape across modes; future PQ hybrids plug in as new `type` bytes without touching anything downstream.

### Key File Format (v1)

**`public.key`** is a **UTF-8 text file** containing exactly one line: the canonical `fcr1…` Bech32 recipient string, optionally followed by a single trailing LF. No binary header. Copy-paste integrity via BIP 173 checksum (6 characters); identity verification is out-of-band via the fingerprint. Bech32 payload: `algorithm(1) || public_key_material(32)` = 33 bytes for X25519. Total file size ~64 bytes.

**`private.key`** v1 (125 bytes when `ext_len = 0`):
- Cleartext header (9 B): `[magic(4) "FCR\0"][version(1)=0x01][type(1)=0x4B 'K'][algorithm(1)=0x01][ext_len_be16]`
- Fixed body (68 B): `argon2_salt(32) || kdf_params(12) || wrap_nonce(24)`
- Variable: `ext_bytes(ext_len)`
- Wrapped private key (48 B): 32-byte ciphertext + 16-byte Poly1305 tag
- Every cleartext byte before `wrapped_privkey` is bound as AEAD **associated data**, so tampering any cleartext field fails authentication. AEAD cannot distinguish "wrong passphrase" from "tampered cleartext" — both surface as `CryptoError::KeyFileUnlockFailed` with wording `"Private key unlock failed: wrong passphrase or tampered file"`.
- Wrap-key derivation: `HKDF-SHA3-256(salt=argon2_salt, ikm=Argon2id(passphrase, argon2_salt, kdf_params), info="ferrocrypt/v1/private-key/wrap", L=32)`.
- Type byte is `0x4B` ('K'), not `0x53` — `file(1)`-style matchers can disambiguate `private.key` from symmetric `.fcr` by a single byte.
- Forward compatibility: TLV tags in `ext_bytes` authenticated via AEAD-AAD. Validated after successful AEAD unwrap.

## Key Conventions

- Operation API: each public operation function takes a config struct by value plus a `Fn(&ProgressEvent)` callback and returns a `*Outcome` struct. The 5 operations are `symmetric_encrypt` / `symmetric_decrypt` / `hybrid_encrypt` / `hybrid_decrypt` / `generate_key_pair`. All config and outcome types are `#[non_exhaustive]` so fields and enum variants can grow without breaking downstream callers.
- Config construction: `SymmetricEncryptConfig::new(input, output_dir, passphrase)` sets required fields; `.save_as(path)` / `.kdf_limit(limit)` builder methods set optional fields. Configs are `Clone` so a template can be reused across multiple operations.
- Key-source abstractions: `hybrid_encrypt` consumes a `PublicKey` in its config; `hybrid_decrypt` consumes a `PrivateKey`. `PublicKey` has constructors `from_key_file(path)`, `from_bytes([u8; 32])`, `from_recipient_string("fcr1…")` (plus `FromStr`), and methods `fingerprint()`, `to_recipient_string()`, `to_bytes()`, `validate()`. `PrivateKey` has `from_key_file(path)` today. Both wrappers are `#[non_exhaustive]` structs over a private inner enum so new sources (in-memory secret material, hardware-backed keys) can be added as constructors without breaking the config shape. There is no separate `Recipient` type — the domain role is captured by the field name (`HybridEncryptConfig::public_key`) mirroring the decrypt side's `HybridDecryptConfig::private_key`.
- Progress signalling: `ProgressEvent` is a `#[non_exhaustive]` enum with 4 current variants (`DerivingKey`, `Encrypting`, `Decrypting`, `GeneratingKeyPair`). It implements `Display` with wording that is locked in by a unit test; CLI and desktop render `{event}` directly. New progress phases are added as new variants — match arms in caller code need a `_` wildcard.
- **In-repo direction routing:** ferrocrypt-cli and ferrocrypt-desktop call `detect_encryption_mode` (CLI) or read `mode` from UI state (desktop) first, then build the appropriate explicit config. The library no longer exposes auto-routing convenience wrappers — direction detection is a caller concern.
- Bech32 `fcr1…` recipient strings are the human-readable public-key exchange format. The typed entry point is `PublicKey::from_recipient_string(&str)` or `"fcr1…".parse::<PublicKey>()` (see the key-source abstractions bullet above); `decode_recipient(&str) -> [u8; 32]` is kept as the low-level primitive for the `fuzz_recipient_decode` fuzz target and callers that specifically want raw bytes.
- CLI `hybrid --recipient / -r` accepts a `fcr1...` string directly for encryption. `recipient` (alias `rc`) subcommand prints the string from a key file.
- CLI never accepts passphrases as command-line arguments. Passphrases are prompted interactively via `rpassword` (hidden TTY input) with confirmation on encrypt/keygen. For non-interactive use (tests, scripts), set the `FERROCRYPT_PASSPHRASE` environment variable.
- Integration tests use `tests/workspace/` as a temp directory, cleaned up by a `#[ctor::dtor]` hook. CLI integration tests use `FERROCRYPT_PASSPHRASE` env var to supply passphrases non-interactively. Integration tests pull `symmetric_auto` / `hybrid_auto` / `generate_key_pair` shims from a shared `tests/common/mod.rs` module — these preserve a stable positional-arg call shape around the config API so existing test call sites don't churn. Low-level format mechanics (prefix encoding, header parsing, envelope unwrap, version/algorithm rejection, recipient decoding) are exercised by in-module unit tests (`src/symmetric.rs::tests`, `src/hybrid.rs::tests`, `src/format.rs::tests`, `src/common.rs::tests`).
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
