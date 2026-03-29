# Changelog

All notable changes to FerroCrypt are documented in this file.

## [Unreleased]

### Added
- HMAC-SHA3-256 header authentication: detects tampering with file headers (salt, nonce, flags) before decryption

### Changed
- **Breaking:** New file format — existing `.fcs` and `.fch` files from older versions cannot be decrypted
- Argon2id memory cost raised from 1 MiB to 64 MiB for stronger brute-force resistance
- RSA padding switched from PKCS#1 v1.5 to OAEP (current NIST standard)
- Stream encryption buffer increased from 500 bytes to 64 KiB for better performance
- Argon2id time cost lowered from 8 to 2 (offset by the much higher memory)

### Fixed
- Crash (panic) when decrypting truncated or corrupted `.fcs` and `.fch` files
- Nonexistent input paths silently producing empty encrypted files
- Key material not zeroized on error paths in symmetric and hybrid encryption
- Temporary directory cleanup masking the original crypto error on failure
- Directory archiver silently skipping inaccessible files and path errors

### Improved
- Rewrote archiver unit tests to be self-contained (replaced fixture-dependent stubs)
- Expanded Reed-Solomon tests: odd-length data, shard corruption, error paths
- Added integration tests: binary content, truncated files, wrong key pair, large mode edge cases, empty password, RSA-4096 round-trip

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
- `.fcs` file format for symmetric encryption
- `.fch` file format for hybrid encryption
- GitHub Actions CI workflow

---

**Versioning:** This project follows [Semantic Versioning](https://semver.org/).
