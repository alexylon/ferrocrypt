# Changelog

All notable changes to FerroCrypt are documented in this file.

## [Unreleased]

### Added
- **Library:** `output_file` parameter on `symmetric_encryption_with_progress` and `hybrid_encryption_with_progress` — when `Some`, writes the encrypted output to the exact path instead of deriving `<stem>.fcr` inside the output directory
- **Library:** `default_encrypted_filename()` helper and `ENCRYPTED_EXTENSION` constant for callers that need to predict or filter the output filename
- **Slint GUI:** "Save As" dialog for encryption — the output field shows the full file path and lets the user rename the encrypted file before saving. Decryption and key generation keep the directory picker.

- HKDF-SHA3-256 subkey derivation: Argon2id now produces 32 bytes of input keying material, expanded via HKDF into separate encryption and HMAC subkeys with domain separation (`ferrocrypt-enc`, `ferrocrypt-hmac`). A separate 32-byte HKDF salt is stored in the header.
- HMAC-SHA3-256 header authentication: detects tampering with file headers (salt, nonce, flags) before decryption
- Versioned file format with magic bytes (`0xFC` + type), major/minor version, and header length field (see `format.rs` for the full specification). Files from older versions and non-FerroCrypt files are now detected with clear error messages instead of misleading crypto errors. The header length field enables forward compatibility — future minor versions can add fields without breaking older parsers.
- `detect_encryption_mode()` public API for determining whether an `.fcr` file uses symmetric or hybrid encryption

### Changed
- **Breaking:** New file format — existing encrypted files from older versions cannot be decrypted. Unified file extension from `.fcs`/`.fch` to single `.fcr`. Both symmetric and hybrid modes now use the STREAM construction (EncryptorBE32/DecryptorBE32) for streaming encrypt/decrypt, eliminating the need to load entire files into memory. Hybrid nonce changed from 24 to 19 bytes to match the STREAM format. Symmetric header now includes an HKDF salt field.
- **Breaking (library API):** Removed `BinCodeEncodeError`/`BinCodeDecodeError` and `ReedSolomonError` from `CryptoError` enum
- **Breaking (CLI):** Removed `--large` flag — all encryption now uses streaming mode unconditionally
- **Breaking:** Argon2id parameters raised to 1 GiB memory / t=4 / p=4 for stronger brute-force resistance
- **Breaking:** RSA OAEP hash upgraded from SHA-1 to SHA-256 (both OAEP hash and MGF1 hash)
- Empty passphrases are now rejected for symmetric encryption
- Encrypt vs decrypt is now determined by reading the file header (magic bytes) instead of relying solely on the `.fcr` extension, so FerroCrypt files are recognized regardless of their filename
- Replaced `reed-solomon-simd` dependency with simple triple replication — the RS encoder with 1 original shard was producing identical copies, so the dependency provided no benefit over direct replication. Header integrity is guaranteed by HMAC.
- Stream encryption buffer increased from 500 bytes to 64 KiB
- Replaced bincode header serialization with raw byte layout for long-term format stability

### Fixed
- **Stream truncation vulnerability:** symmetric decryption had a code path that skipped the required `decrypt_last()` call, allowing an attacker to truncate ciphertext at chunk boundaries without detection. Now all final chunks go through `decrypt_last`, which verifies the STREAM terminator.
- Hybrid plaintext buffers (both pre-encryption and post-decryption) are now zeroized on drop
- Added length validation on RSA-decrypted key material to prevent silent corruption
- Crash (panic) when decrypting truncated, corrupted, or maliciously crafted `.fcr` files
- Crash when replicated decoding produces unexpected output length (validated before indexing)
- Nonexistent input paths silently producing empty encrypted files
- Key material not zeroized on all error paths: RSA-decrypted keys, combined key buffer, private key PEM content, and HMAC failure early returns now all zeroize correctly
- Temporary directory cleanup masking the original crypto error on failure
- Temporary directory race condition when multiple processes encrypt to the same output directory
- Directory archiver silently skipping inaccessible files and path errors
- Removed bincode dependency for header serialization (bincode wire format is not stable across major versions)

### Removed
- `reed-solomon-simd` dependency
- `--large` / `-l` CLI flag (streaming is now the only mode)

### Improved
- File archiver now streams file content instead of loading entire files into memory
- Rewrote archiver unit tests to be self-contained (replaced fixture-dependent stubs)

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
