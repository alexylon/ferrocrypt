# Changelog

All notable changes to FerroCrypt are documented in this file.

## [Unreleased]

### Added
- **CLI:** `fingerprint` subcommand (alias `fp`) to print a public key's SHA3-256 fingerprint for out-of-band verification
- **CLI:** `keygen` now prints the public key fingerprint after generation
- **CLI:** `hybrid` encrypt now prints the recipient's key fingerprint before encryption
- **CLI:** Progress messages (`Deriving key…`, `Encrypting…`, etc.) now printed to stderr
- **CLI:** Private key file validated before hybrid decryption
- **CLI:** `--save-as` / `-s` flag on `symmetric` and `hybrid` subcommands
- **CLI:** Interactive mode aliases: `sym` for `symmetric`, `hyb` for `hybrid`, `gen` for `keygen`
- **Desktop app:** Slint-based desktop GUI (`ferrocrypt-desktop`) with two tabs: Symmetric and Hybrid. Key generation is inline within the Hybrid tab. After generating a key pair, the app auto-transitions to Hybrid Encrypt with the public key pre-filled. Includes "Save As" dialog, auto-detection of encryption mode from file headers, and conflict warnings.
- **Desktop app:** Public key fingerprint display with copy-to-clipboard button in hybrid encrypt mode
- **Desktop app:** Key file validation on selection — invalid key files show an error and disable the action button
- **Desktop app:** Password strength indicator (visible in Symmetric Encrypt and Key Gen modes). Scoring adapted from Proton Pass.
- HKDF-SHA3-256 subkey derivation with domain separation (`ferrocrypt-enc`, `ferrocrypt-hmac`)
- HMAC-SHA3-256 header authentication — tampering is detected before decryption begins
- Versioned file format with magic bytes (`0xFC` + type), major/minor version, and header length field. Forward-compatible: future minor versions can append fields without breaking older parsers.

### Changed
- **Breaking:** Replaced RSA-4096 OAEP (OpenSSL) with X25519 + XChaCha20-Poly1305 (`crypto_box` crate, `ChaChaBox`) for hybrid envelope encryption. Removes the OpenSSL C dependency — the project is now pure Rust.
- **Breaking:** Streaming TAR encryption pipeline — input is archived and encrypted directly to the output file in a single pass. No plaintext intermediate files touch disk. Replaces the previous ZIP-based approach.
- **Breaking:** Format version bumped to 3.0 — files from older versions cannot be decrypted. Unified file extension from `.fcs`/`.fch` to single `.fcr`.
- **Breaking:** Argon2id parameters raised to 1 GiB memory / t=4 / p=4 for stronger brute-force resistance
- **Breaking (library API):** Renamed `generate_asymmetric_key_pair` to `generate_key_pair`, removed `bit_size` parameter. Renamed `rsa_key_pem` to `key_file` in `hybrid_encryption`.
- **Breaking (library API):** Renamed `CryptoError` variants: `EncryptionDecryptionError` → `CryptoOperation`, `Message` → `InvalidInput`, `ChaCha20Poly1305Error` → `Cipher`, `Argon2Error` → `KeyDerivation`, `TryFromSliceError` → `SliceConversion`
- **Breaking (library API):** Removed `OpensslError`, `WalkDirError`, `ZipError`, `BinCodeEncodeError`, `BinCodeDecodeError`, and `ReedSolomonError` variants from `CryptoError` enum
- **Breaking (library API):** Collapsed `_with_progress` variants into base functions — `symmetric_encryption`, `hybrid_encryption`, and `generate_key_pair` now accept `save_as` and `on_progress` directly
- **Breaking (library API):** Removed `serde::Serialize` implementation from `CryptoError`
- **Breaking (CLI):** Removed `--bit-size` / `-b` flag from `keygen` and `--large` / `-l` flag from encryption
- Key files use `private.key` (passphrase-protected via Argon2id + XChaCha20-Poly1305) and `public.key` (raw 32 bytes)
- Encrypt vs decrypt determined by reading file header magic bytes, not file extension
- Replaced `reed-solomon-simd` with simple triple replication (RS with 1 original shard was producing identical copies)
- Replaced bincode header serialization with raw byte layout for long-term format stability
- Stream encryption buffer increased from 500 bytes to 64 KiB
- Empty passphrases rejected for symmetric encryption
- Moved Tauri and Dioxus GUIs to `experiments/`

### Fixed
- **Stream truncation vulnerability:** symmetric decryption had a code path that skipped `decrypt_last()`, allowing truncation at chunk boundaries without detection
- Symmetric decryption now verifies the HMAC before the key-hash check, so header tampering is reported as an authentication failure rather than "wrong password"
- HMAC covers decoded (canonical) field values — single-copy replication corruption recovered by majority vote no longer causes HMAC verification failure
- Private key files written with `0o600` (owner-only) on POSIX systems
- Key material zeroized on all error paths (decrypted envelope keys, combined key buffer, HMAC failure early returns)
- Hybrid plaintext buffers zeroized on drop
- Length validation on decrypted envelope key material
- Crash on truncated, corrupted, or maliciously crafted `.fcr` files
- Crash on unexpected replicated decoding output length
- Nonexistent input paths silently producing empty encrypted files
- `keygen` now creates missing output directories
- Temporary directory cleanup masking the original crypto error
- Temporary directory race condition with concurrent encryptions to the same output directory
- Directory archiver silently skipping inaccessible files and path errors

### Removed
- `openssl`, `reed-solomon-simd`, `bincode`, and `serde` dependencies
- `--large` / `-l` CLI flag (streaming is now the only mode)

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
