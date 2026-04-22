# Changelog

All notable changes to FerroCrypt are documented in this file.

## [Unreleased]

### Added
- **Bech32 recipient strings (`fcr1...`)** for human-readable public key exchange. Checksummed and validated on decode. Library: build a `PublicKey` via `PublicKey::from_recipient_string("fcr1…")` (or `"fcr1…".parse::<PublicKey>()`) and render one back out with `PublicKey::to_recipient_string()`; `decode_recipient` is kept as the low-level Bech32 primitive. CLI: new `recipient` subcommand (alias `rc`) and `hybrid --recipient` / `-r` flag to encrypt directly with a recipient string instead of a key file.
- **Public key fingerprints (SHA3-256)** for out-of-band verification. CLI: new `fingerprint` subcommand (alias `fp`); `keygen` and `hybrid` encrypt now print the relevant fingerprint (falling back to the key file path if the key cannot be read). Desktop app shows the fingerprint with a copy-to-clipboard button.
- **`--max-kdf-memory <MiB>`** flag on `symmetric` and `hybrid` to cap accepted KDF memory cost during decryption. Library: attach a `KdfLimit` to `SymmetricDecryptConfig` / `HybridDecryptConfig` via the `.kdf_limit(limit)` builder; out-of-budget files fail with `CryptoError::ExcessiveWork`. `KdfLimit` is `#[non_exhaustive]` so future limit dimensions (time cost, parallelism) can be added without a breaking change — construct via `KdfLimit::new` or `KdfLimit::from_mib`. Default ceiling is **1 GiB**, matching the writer's own default; callers who encrypt with higher `mem_cost` must opt into a wider limit explicitly.
- **`--save-as` / `-s`** flag to choose the encrypted output filename. `--output-path` is optional when `--save-as` is given.
- **Early conflict detection** for `encrypt` and `keygen` — fails before overwriting an existing `.fcr` file or key pair.
- **Subcommand help** with descriptions, aliases, and usage examples. Aliases: `sym` for `symmetric`, `hyb` for `hybrid`, `gen` for `keygen`, `rc` for `recipient`, `fp` for `fingerprint`.
- **Slint-based desktop app** (`ferrocrypt-desktop`) with Symmetric and Hybrid tabs. Key generation is inline within the Hybrid tab; after generation the app auto-transitions to Hybrid Encrypt with the public key pre-filled. Includes "Save As" dialog, magic-byte mode detection, conflict warnings, key file validation on selection, and a password strength indicator (scoring adapted from Proton Pass).
- Progress messages (`Deriving key…`, `Encrypting…`, etc.) printed to stderr.
- `cargo-audit` dependency vulnerability scanning in GitHub Actions.
- `cargo-vet` supply-chain attestation enforced in GitHub Actions.
- **Desktop crate in CI.** A new `desktop` matrix job in `.github/workflows/rust.yml` runs on `ubuntu-latest`, `macos-latest`, and `windows-latest` on every push and pull request. On Ubuntu it installs the Slint system dependencies (`libfontconfig-dev`, `libfreetype-dev`, `libxcb-shape0-dev`, `libxcb-xfixes0-dev`, `libxkbcommon-dev`, `libwayland-dev`, `libssl-dev`), then runs `cargo clippy --all-targets -- -D warnings`, `cargo build`, and `cargo test -- --test-threads=1` inside `ferrocrypt-desktop/`. Previously the desktop crate was excluded from the workspace and never checked in CI, so a library refactor could silently break the GUI until someone ran the build locally. The audit for this job also caught that `README.md`'s Linux install instructions were missing `libwayland-dev` — `rfd 0.17` defaults to the Wayland + XDG-Portal backend and transitively runs a `pkg_config::probe("wayland-client")` at build time, which needs the dev headers. The package was added to both `README.md` and the Fedora install list (as `wayland-devel`).
- **Fuzz-target rewrite around parser surfaces, plus CI wiring.** Seven new parser-surface targets exercise the lowest-useful parsing layers directly, skipping the Argon2id derivation that dominates the integration targets: `fuzz_header_prefix` (27-byte triple-replicated prefix + magic/type), `fuzz_key_file_header` (public and private key-file header + layout validation), `fuzz_kdf_params` (12-byte KDF parameter bounds), `fuzz_replication_decode` (majority-vote decoder), `fuzz_archive_path` (tar-entry path guard), `fuzz_recipient_decode` (Bech32 `fcr1…`), and `fuzz_detect_mode` (top-level encryption-mode detection). The two slower integration targets (`fuzz_symmetric_decrypt`, `fuzz_hybrid_decrypt`) are kept for end-to-end coverage; the two encrypt-side targets are dropped because they did not exercise any parser. A new `fuzz` job in GitHub Actions installs the nightly toolchain and `cargo-fuzz`, runs clippy on the fuzz crate, builds every target on every push/PR (catching API drift), smoke-fuzzes every parser-surface target for ten seconds, and uploads crash reproducers as a workflow artifact on failure. Internals are re-exported through a new `ferrocrypt/fuzzing` cargo feature that is off by default and not part of the stable API.
- Library: `PUBLIC_KEY_FILENAME` and `PRIVATE_KEY_FILENAME` constants exported.

### Changed
- **Breaking:** Hybrid encryption migrated from RSA-4096 (OpenSSL) to **X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305** envelope encryption. Removes the OpenSSL C dependency — the project is now pure Rust. All-zero shared secrets are rejected as a small-order key defense. Pre-`0.3.0` hybrid files cannot be decrypted; old key pairs must be regenerated.
- **Breaking:** New `.fcr` file format family (symmetric `v3.0`, hybrid `v4.0`, single `.fcr` extension replacing `.fcs` / `.fch`).
- **Breaking:** `.fcr` headers are now **triple-replicated** for error correction and **authenticated by HMAC-SHA3-256** before any payload decryption begins, so attacker-controlled changes to salts, nonces, KDF parameters, or authenticated extension bytes are rejected before they affect decryption state.
- **Breaking:** `.fcr` payloads are now a streaming **XChaCha20-Poly1305** AEAD over a TAR archive, encrypted directly to the output file — no plaintext intermediate files touch disk. Each **64 KiB** plaintext chunk has its own Poly1305 authentication tag, and the reader verifies each chunk before yielding that chunk’s plaintext. Bytes from a failing chunk are never returned, though earlier verified plaintext may already have been written or extracted before a later failure. Future minor versions can append optional metadata to a single authenticated extension region; older readers authenticate those bytes via HMAC and then ignore the contents. Files from earlier releases cannot be decrypted.
- **Breaking:** Key file formats are introduced. `public.key` (version `3`) holds the raw 32-byte X25519 public key; `private.key` (version `4`) is passphrase-protected via Argon2id + XChaCha20-Poly1305 and written with `0o600` on POSIX. `private.key` binds the cleartext key-file header, the KDF parameters, the Argon2 salt, the AEAD nonce, the big-endian `ext_len`, and the `ext_bytes` payload as **AEAD associated data**, so every byte on disk is cryptographically authenticated. The AEAD primitive returns a single undifferentiated failure for both wrong-passphrase and tampered-cleartext, so both surface as the same `KeyFileUnlockFailed` error; its Display wording has been updated to `"Private key unlock failed: wrong passphrase or tampered file"` to reflect both causes. The format also reserves a forward-compatible authenticated `ext_bytes` extension region (empty today, `ext_len = 0`) that future `v4.x` minors can populate with TLV metadata — older readers authenticate those bytes via the AEAD tag and then ignore the contents. 0.3.0 is the first release to define versioned key-file formats; the starting numbers (`3` / `4`) are above `1` because the formats went through a few iterations during pre-release development. Keys generated before 0.3.0 are not compatible and must be regenerated.
- **Breaking:** Symmetric password-based key derivation pipeline: **Argon2id** (1 GiB memory / time cost 4 / parallelism 4) → **HKDF-SHA3-256** with domain separation → independent encryption and HMAC subkeys. A compromise of one subkey does not reveal the other. KDF parameters are stored in the header so decryption always uses the exact values from encryption time.
- **Breaking (CLI):** Removed `-p` / `--passphrase` flag. Passphrases are prompted interactively with hidden input and confirmation on encrypt and keygen; passphrase confirmation uses constant-time comparison. For non-interactive use (scripts, CI) set the `FERROCRYPT_PASSPHRASE` environment variable. Empty passphrases are rejected.
- **Breaking (CLI):** Removed `--bit-size` / `-b` and `--large` / `-l` flags (RSA-only).
- **Breaking (library API):** Each operation function now takes a config struct plus an `impl Fn(&ProgressEvent)` callback and returns a typed outcome struct. The five public operations are `symmetric_encrypt` / `symmetric_decrypt` / `hybrid_encrypt` / `hybrid_decrypt` / `generate_key_pair`, paired with `SymmetricEncryptConfig` / `SymmetricDecryptConfig` / `HybridEncryptConfig` / `HybridDecryptConfig` / `KeyGenConfig` inputs and `EncryptOutcome` / `DecryptOutcome` / `KeyGenOutcome` outputs. Every config and outcome type is `#[non_exhaustive]` and `Clone`; configs are built with `::new(required fields)` plus `.save_as(path)` / `.kdf_limit(limit)` builders, so adding new optional fields or outcome fields in later releases is non-breaking. `ProgressEvent` is a `#[non_exhaustive]` enum whose `Display` wording is locked in by a unit test; consumers that rendered the previous `&str` callback via `eprintln!("{msg}")` can keep doing the same with `eprintln!("{ev}")`. Public-key material is carried by a new `PublicKey` type (constructors `from_key_file(path)`, `from_bytes([u8; 32])`, `from_recipient_string("fcr1…")`, plus `FromStr`) with methods `fingerprint()`, `to_recipient_string()`, `to_bytes()`, and `validate()`. Private-key material is carried by `PrivateKey` (constructor `from_key_file(path)`). Both wrappers are `#[non_exhaustive]` so additional key sources (in-memory, hardware-backed) can be added without breaking the config shape. The auto-routing wrappers (`symmetric_auto` / `hybrid_auto`), the separate `hybrid_encrypt_from_recipient` entry point, and the free functions `public_key_fingerprint` / `encode_recipient` / `encode_recipient_from_bytes` are removed — direction detection is now a caller concern via `detect_encryption_mode`, and the public-key operations moved to methods on `PublicKey`. `decode_recipient` remains as the low-level Bech32 primitive.
- **Encrypt vs. decrypt routing uses magic-byte detection only** — file extension no longer forces a path. Files that start with the FerroCrypt magic bytes but have a corrupted header now fail closed with `InvalidFormat` instead of being silently re-encrypted.
- **Atomic output handling.** Encrypted files and generated key files are staged under temporary names and promoted to their final path only on success, which keeps ordinary single-writer use from silently replacing an existing file. Directory decryption continues to use an `.incomplete` working directory that is moved into place once extraction finishes; on failure the `.incomplete` copy remains on disk for inspection. Linux and macOS keep the stronger directory-finalization path. Windows keeps a narrower best-effort directory-finalization step in exchange for the zero-unsafe design. Encrypted output is flushed to disk before being promoted, and the parent directory is synced on Unix on a best-effort basis after finalization. The library contains no unsafe code.
- **File and directory permissions are preserved** through encrypt/decrypt round-trips on Unix. Setuid, setgid, and sticky bits are stripped on both archiving and extraction. Decrypted regular files are no longer marked executable. On non-Unix platforms, permission handling is platform-limited.
- Tauri and Dioxus GUI experiments moved to `experiments/`; replaced by the new Slint desktop app.

### Fixed
- **Decryption errors are now distinct and user-readable.** Previously a failed decryption surfaced as a wrapped internal error such as `Io(Custom { ..., error: "aead::Error" })` on the CLI, with no way for a user to tell whether the password was wrong, the header was tampered with, the payload was corrupted mid-stream, or the file was simply truncated. Five distinct error conditions are now reported, each with a short plain-language message:
    - **Private key unlock failed: wrong passphrase or tampered file** — the hybrid private key file failed AEAD authentication. Either the passphrase does not decrypt it or one of its cleartext fields has been tampered with since the file was written; the AEAD primitive cannot distinguish the two cases.
    - **Decryption failed: wrong passphrase or tampered file** — (symmetric) the passphrase does not unlock the file, or the header has been modified.
    - **Decryption failed: wrong private key or tampered file** — (hybrid) the supplied private key does not match the key pair the file was encrypted for, or the header has been modified.
    - **Payload authentication failed: data tampered or corrupted** — a ciphertext chunk failed its authentication tag after the header authenticated successfully.
    - **Encrypted file is truncated** — the encrypted stream ends before its final authenticated chunk.

  Encryption and streaming internals no longer leak low-level crate error names into user-visible messages. The CLI prints errors using `Display` instead of the default `Debug` format, so users see the library's short messages directly. The desktop app already used `Display`. The library's error type groups variants by area of concern (filesystem/input, format/version, KDF/work limits, authentication, primitives, internal invariants) and the variants are identity-only — no per-operation context is baked into the error type. Variants that do carry data now carry *typed* data instead of heap-allocated strings: `InvalidFormat(FormatDefect)`, `UnsupportedVersion(UnsupportedVersion)`, `InvalidKdfParams(InvalidKdfParams)`, and `InternalInvariant(&'static str)` / `InternalCryptoFailure(&'static str)`. `FormatDefect`, `UnsupportedVersion`, and `InvalidKdfParams` are re-exported from the crate root so library consumers can pattern-match on structural failure shapes without substring comparisons. The former catch-all `InternalError` variant is split into `InternalInvariant` (state-machine misuse or impossible-size checks that indicate a library bug) and `InternalCryptoFailure` (a crypto primitive rejected well-formed input — practically unreachable, left typed so it cannot be silently reclassified as generic I/O). `CryptoError::InputPath` is now a bare unit variant (was `InputPath(String)`) — the path the caller passed in is information the caller already has, so it does not belong inside the error. The remaining `String`-carrying variant is `InvalidInput(String)`, kept as the designated heterogeneous-caller-input bucket because the tar-archive layer needs to identify *which* archive entry triggered a fail-closed rejection — see the type-level docs on `CryptoError` for the full rationale and the `age` crate parallel.
- **Security: Windows no longer silently overwrites existing output.** Earlier versions on Windows could replace an existing `.fcr` file or key file at the output path without asking. Encryption and key generation now avoid silently replacing existing final files on the supported desktop targets, and directory decryption follows the same intent with a stronger path on Linux/macOS and a narrower best-effort step on Windows.
- **Security: duplicate entries inside a decrypted archive no longer overwrite each other.** A maliciously crafted encrypted archive that contained two entries for the same path previously had the second entry quietly replace the first during extraction. Extraction now fails closed on the duplicate.
- **Security: extraction rejects archives with multiple top-level roots.** FerroCrypt's archiver always produces exactly one top-level root — a single file entry, or one directory entry with descendants (documented in `FORMAT.md §6.4`). Earlier extraction code tolerated hand-crafted or tampered `.fcr` payloads that contained entries under multiple distinct top-level roots: it would silently create every root under an `.incomplete` working name and rename each into place, while the public decryption return value only reported the first root. A crafted payload could therefore produce more output than the API advertised. Extraction now refuses any second distinct top-level root with an `InvalidInput` error before that root's output is written, so the single `PathBuf` return value is always faithful to what extraction created on disk. See `FORMAT.md §11.3` for the enforced invariant.
- **Security: key generation writes the public key before the private key.** If generation is interrupted partway, the private key never appears on disk — only an orphan public key remains, which is harmless.
- **Security: directory encryption no longer follows symlinks.** Symlink inputs and symlink entries inside directories are rejected. Encrypt entry points reject symlink and non-regular inputs up-front, before any Argon2id work runs; the archiver re-applies the same per-entry rules during the TAR walk as defense-in-depth. File opens use `O_NOFOLLOW` on Unix with post-open regular-file validation, hardening against symlink and special-file TOCTOU races. Hardlinks are archived as regular file contents. Extraction rejects unsupported TAR entry types instead of silently dropping them.
- **Security: extraction is hardened against local symlink/directory-component races on Linux and macOS.** Every filesystem operation inside the `.incomplete` working tree is now anchored at a directory file descriptor rooted in the user's output directory. Intermediate components are resolved via `openat`/`mkdirat` with `O_NOFOLLOW | O_NONBLOCK`, each resulting fd is `fstat`-verified to be a directory, and the final regular file is created with `O_CREAT | O_EXCL | O_NOFOLLOW`. A concurrent local attacker who swaps a directory component for a symlink no longer redirects writes outside the destination tree: the walker aborts with `ELOOP` or a typed "symlink in extraction path" error. Deferred directory permissions are now applied via `fchmod` on the still-open fd instead of path-based `set_permissions`. Windows and non-Linux/non-macOS Unix targets keep the existing path-based extraction path.
- **Security: KDF parameters from untrusted headers are bounded in every dimension** (`mem_cost`, `time_cost`, `lanes`, plus rejection of zero values), preventing denial-of-service via crafted encrypted files or key files.
- **Security: per-chunk plaintext buffers in the streaming AEAD adapters are zeroized** between chunks, on `finish()`, and on `Drop` — preventing plaintext from lingering on the heap after error or normal completion. Decrypted key material (envelope combined key, raw X25519 private key bytes before they enter `StaticSecret`) lives in `Zeroizing` wrappers that clear automatically on drop, covering success, error, and unwinding paths.
- **Desktop: worker thread panics no longer freeze the UI.** Previously, a panic in the encrypt/decrypt/keygen worker (e.g. Argon2id OOM on a constrained host) left the UI permanently disabled with the "working…" state stuck. The worker body is now wrapped in `std::panic::catch_unwind`, resetting `is_working` and surfacing a clear error on panic so the app stays recoverable without a force-quit.
- **Hybrid decrypt progress phases.** `hybrid_decrypt` now emits `DerivingKey` before the private-key Argon2id runs and `Decrypting` only after the envelope opens — matching the symmetric path. Previously it emitted `Decrypting` immediately and never emitted `DerivingKey`, so a UI would mislabel the multi-second KDF window as "decrypting".
- Crash on truncated, corrupted, or maliciously crafted `.fcr` files replaced with structured `InvalidFormat` errors.
- Default encrypted output naming for directories with dots (e.g. `photos.v1/`) preserves the full directory name (`photos.v1.fcr` instead of `photos.fcr`).
- Nonexistent input paths no longer silently produce empty encrypted files.
- `keygen` creates missing output directories. Key pair generation is atomic: both files are written to temp names, `fsync`'d to disk, and renamed into place; partial state is cleaned up on failure.
- Directory archiver no longer silently skips inaccessible files or path errors.

### Removed
- `openssl`, `reed-solomon-simd`, `bincode`, and `serde` dependencies.

## [0.2.5] - 2025-12-18

### Added
- Examples for documented library items

## [0.2.4] - 2025-12-16

### Fixed
- Usage of the library in the documentation

## [0.2.3] - 2025-12-16

### Added
- Documentation for the library's public API
- Renamed CLI binary from `fcr` to `ferrocrypt`

## [0.2.2] - 2025-12-14

### Changed
- Bumped version for crates.io metadata fixes

## [0.2.1] - 2025-12-14

### Added
- Crates.io install options, badges, and table of contents in README
- Package `include` directives for crates.io publishing

## [0.2.0] - 2025-12-14

### Added
- Published `ferrocrypt` and `ferrocrypt-cli` to crates.io
- Crates.io metadata (description, keywords, categories, repository, homepage)

### Changed
- Migrated error correction from `reed-solomon-erasure` to `reed-solomon-simd`
- Implemented secure secret handling with `secrecy` crate
- All path parameters now use `impl AsRef<Path>`
- Implemented subcommand and REPL CLI modes (keygen, hybrid, symmetric)
- Refactored and cleaned up library internals

## [0.1.0] - 2023-07-04

### Added
- Symmetric encryption with XChaCha20-Poly1305 + Argon2id key derivation
- Hybrid encryption with RSA-4096 + XChaCha20-Poly1305 (envelope encryption)
- RSA key pair generation with passphrase-protected private keys
- Reed-Solomon error correction on cryptographic headers (salt, nonce, key hash)
- Stream encryption mode for large files (EncryptorBE32/DecryptorBE32)
- Automatic file/directory archiving (ZIP) before encryption
- Constant-time key hash comparison to prevent timing attacks
- Key zeroization after use
- CLI with subcommands: `keygen`, `hybrid`, `symmetric`
- Tauri desktop GUI application
- `.fcr` file format for both symmetric and hybrid encryption
- GitHub Actions CI workflow

---

**Versioning:** This project follows [Semantic Versioning](https://semver.org/).
