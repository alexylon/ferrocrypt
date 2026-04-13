# Changelog

All notable changes to FerroCrypt are documented in this file.

## [Unreleased]

### Added
- **Bech32 recipient strings (`fcr1...`)** for human-readable public key exchange. Checksummed and validated on decode. Library: `encode_recipient` / `decode_recipient` / `encode_recipient_from_bytes` / `hybrid_encrypt_from_recipient`. CLI: new `recipient` subcommand (alias `rc`) and `hybrid --recipient` / `-r` flag to encrypt directly with a recipient string instead of a key file.
- **Public key fingerprints (SHA3-256)** for out-of-band verification. CLI: new `fingerprint` subcommand (alias `fp`); `keygen` and `hybrid` encrypt now print the relevant fingerprint. Desktop app shows the fingerprint with a copy-to-clipboard button.
- **`--max-kdf-memory <MiB>`** flag on `symmetric` and `hybrid` to cap accepted KDF memory cost during decryption. Library: `KdfLimit` struct accepted by all decrypt functions; out-of-budget files fail with `CryptoError::ExcessiveWork`.
- **`--save-as` / `-s`** flag to choose the encrypted output filename. `--output-path` is optional when `--save-as` is given.
- **Early conflict detection** for `encrypt` and `keygen` — fails before overwriting an existing `.fcr` file or key pair.
- **Subcommand help** with descriptions, aliases, and usage examples. Aliases: `sym` for `symmetric`, `hyb` for `hybrid`, `gen` for `keygen`, `rc` for `recipient`, `fp` for `fingerprint`.
- **Slint-based desktop app** (`ferrocrypt-desktop`) with Symmetric and Hybrid tabs. Key generation is inline within the Hybrid tab; after generation the app auto-transitions to Hybrid Encrypt with the public key pre-filled. Includes "Save As" dialog, magic-byte mode detection, conflict warnings, key file validation on selection, and a password strength indicator (scoring adapted from Proton Pass).
- Progress messages (`Deriving key…`, `Encrypting…`, etc.) printed to stderr.
- `cargo-audit` dependency vulnerability scanning in GitHub Actions.
- Library: `PUBLIC_KEY_FILENAME` and `PRIVATE_KEY_FILENAME` constants exported.

### Changed
- **Breaking:** Hybrid encryption migrated from RSA-4096 (OpenSSL) to **X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305** envelope encryption. Removes the OpenSSL C dependency — the project is now pure Rust. All-zero shared secrets are rejected as a small-order key defense. Pre-`0.3.0` hybrid files cannot be decrypted; old key pairs must be regenerated.
- **Breaking:** New `.fcr` file format family (symmetric `v3.0`, hybrid `v4.0`, single `.fcr` extension replacing `.fcs` / `.fch`).
- **Breaking:** `.fcr` headers are now **triple-replicated** for error correction and **authenticated by HMAC-SHA3-256** before any payload decryption begins, so attacker-controlled changes to salts, nonces, KDF parameters, key-verification hashes, or authenticated extension bytes are rejected before they affect decryption state.
- **Breaking:** `.fcr` payloads are now a streaming **XChaCha20-Poly1305** AEAD over a TAR archive, encrypted directly to the output file — no plaintext intermediate files touch disk. Each **64 KiB** plaintext chunk has its own Poly1305 authentication tag, and the reader verifies each chunk before yielding that chunk’s plaintext. Bytes from a failing chunk are never returned, though earlier verified plaintext may already have been written or extracted before a later failure. Future minor versions can append optional metadata to a single authenticated extension region; older readers authenticate those bytes via HMAC and then ignore the contents. Files from earlier releases cannot be decrypted.
- **Breaking:** New key file format. `private.key` is passphrase-protected via Argon2id + XChaCha20-Poly1305 and written with `0o600` on POSIX; `public.key` holds the raw 32-byte X25519 public key. Pre-`0.3.0` key pairs are not supported.
- **Breaking:** Symmetric password-based key derivation pipeline: **Argon2id** (1 GiB memory / time cost 4 / parallelism 4) → **HKDF-SHA3-256** with domain separation → independent encryption and HMAC subkeys. A compromise of one subkey does not reveal the other. KDF parameters are stored in the header so decryption always uses the exact values from encryption time.
- **Breaking (CLI):** Removed `-p` / `--passphrase` flag. Passphrases are prompted interactively with hidden input and confirmation on encrypt and keygen; passphrase confirmation uses constant-time comparison. For non-interactive use (scripts, CI) set the `FERROCRYPT_PASSPHRASE` environment variable. Empty passphrases are rejected.
- **Breaking (CLI):** Removed `--bit-size` / `-b` and `--large` / `-l` flags (RSA-only).
- **Breaking (library API):** Explicit `symmetric_encrypt` / `symmetric_decrypt` / `hybrid_encrypt` / `hybrid_decrypt` functions; auto-routing wrappers renamed to `symmetric_auto` / `hybrid_auto`. Encrypt/decrypt return `Result<PathBuf, CryptoError>`. `generate_key_pair` returns `GeneratedKeyPair` with paths and fingerprint. `detect_encryption_mode` returns `Result<Option<EncryptionMode>, CryptoError>`. All public path parameters use `impl AsRef<Path>`. Several `CryptoError` variants and function signatures changed.
- **Encrypt vs. decrypt routing uses magic-byte detection only** — file extension no longer forces a path. Files that start with the FerroCrypt magic bytes but have a corrupted header now fail closed with `InvalidFormat` instead of being silently re-encrypted by the auto-routing helpers.
- **Atomic output handling.** Both encryption and decryption write under an `.incomplete` working name and rename to the final name only on success, using platform-native non-overwriting rename (`renameat2` on Linux, `renamex_np` on macOS). Failed encryptions delete the working file; failed decryptions leave it on disk for inspection. A second attempt fails if an `.incomplete` already exists. Encrypted output is `fsync`'d before success is reported.
- **File and directory permissions are preserved** through encrypt/decrypt round-trips on Unix. Setuid, setgid, and sticky bits are stripped on both archiving and extraction. Decrypted regular files are no longer marked executable. On non-Unix platforms, permission handling is platform-limited.
- Tauri and Dioxus GUI experiments moved to `experiments/`; replaced by the new Slint desktop app.

### Fixed
- **Security: directory encryption no longer follows symlinks.** Symlink inputs and symlink entries inside directories are rejected at archive time. File opens use `O_NOFOLLOW` on Unix with post-open regular-file validation, hardening against symlink and special-file TOCTOU races. Hardlinks are archived as regular file contents. Extraction rejects unsupported TAR entry types instead of silently dropping them.
- **Security: KDF parameters from untrusted headers are bounded in every dimension** (`mem_cost`, `time_cost`, `lanes`, plus rejection of zero values), preventing denial-of-service via crafted encrypted files or key files.
- **Security: per-chunk plaintext buffers in the streaming AEAD adapters are zeroized** between chunks, on `finish()`, and on `Drop` — preventing plaintext from lingering on the heap after error or normal completion. Decrypted key material is also zeroized on every error path.
- Symmetric decryption distinguishes wrong-password from header tampering: HMAC is verified before the key-hash check. The user-facing message for the ambiguous case is "Password incorrect or file header corrupted".
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
