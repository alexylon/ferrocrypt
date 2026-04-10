# Changelog

All notable changes to FerroCrypt are documented in this file.

## [Unreleased]

### Added
- **Library API:** `KdfLimit` struct for caller-controlled KDF memory cost ceiling on decrypt. Decrypt functions (`symmetric_decrypt`, `hybrid_decrypt`, `symmetric_auto`, `hybrid_auto`) accept an optional `KdfLimit` parameter. When a file's KDF memory cost exceeds the limit, decryption fails with `CryptoError::ExcessiveWork` instead of a generic error.
- **CLI:** `--max-kdf-memory <MiB>` flag on `symmetric` and `hybrid` subcommands to cap accepted KDF memory cost during decryption
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
- **CI:** `cargo-audit` dependency vulnerability scanning in GitHub Actions
- Versioned file format with magic bytes (`0xFC` + type), major/minor version, and header length field. Forward-compatible within a major version: future minor versions may append optional trailing fields that older readers can skip via the header length. Minor versions must not change required decryption or authentication semantics.

### Changed
- `detect_encryption_mode` now fails closed on malformed headers: files that start with the FerroCrypt magic byte pattern but have a corrupted, truncated, or unrecognized header return `Err(InvalidFormat)` instead of `Ok(None)`. This prevents corrupted `.fcr` files from being silently re-encrypted by the auto-routing helpers.
- Decryption now writes output under an `.incomplete` working name and only renames to the final name on success using platform-native non-overwriting rename (`renameat2` on Linux, `renamex_np` on macOS). Plaintext never appears under the final output name during streaming decryption. On failure, the `.incomplete` output stays on disk for inspection. A subsequent attempt errors if the `.incomplete` output already exists, requiring the user to clean up first.
- Key generation now calls `sync_all()` on key files before the atomic rename, ensuring key data is durable on disk before the final filenames become visible.
- **Library API:** Renamed public functions and types for idiomatic Rust naming (see API docs for updated names)
- Migrated Argon2id implementation from `rust-argon2` to RustCrypto `argon2` crate for better maintenance and ecosystem alignment. KDF output is now stack-allocated (`[u8; 32]`) instead of heap-allocated (`Vec<u8>`), improving zeroization guarantees. No format change — existing encrypted files and key files remain fully compatible.
- Tightened KDF parameter validation: `mem_cost` minimum now enforces Argon2's requirement (`>= 8 × lanes`) instead of allowing any nonzero value. Rejects maliciously crafted headers with clearer errors.
- Version-dispatch architecture: decrypt and key-reading paths now dispatch by file/key format version, enabling future reader compatibility for the current format line (encrypted files v3+, key files v2+). Golden fixture tests guard against regressions.
- **Breaking:** Encrypted-file format bumped to 3.0 — files from older versions cannot be decrypted. Unified file extension from `.fcs`/`.fch` to single `.fcr`.
- **Breaking:** Key-file format bumped to 2.0 — public/private key files from the older RSA/OpenSSL line are not supported by the current release.
- **Breaking:** Replaced RSA-4096 OAEP (OpenSSL) with X25519 + XChaCha20-Poly1305 (`crypto_box` crate, `ChaChaBox`) for hybrid envelope encryption. Removes the OpenSSL C dependency — the project is now pure Rust.
- **Breaking:** Streaming TAR encryption pipeline — input is archived and encrypted directly to the output file in a single pass. No plaintext intermediate files touch disk. Replaces the previous ZIP-based approach.
- **Breaking:** Entire header (including prefix and padding indicator) is now triple-replicated for uniform error correction
- **Breaking:** Argon2id parameters raised to 1 GiB memory / t=4 / p=4 for stronger brute-force resistance. KDF parameters are now stored in the symmetric file header and private key file, so decryption always uses the exact parameters that were used during encryption.
- **Breaking (library API):** Explicit `symmetric_encrypt` / `symmetric_decrypt` / `hybrid_encrypt` / `hybrid_decrypt` functions replace the auto-routing `symmetric_encryption` / `hybrid_encryption`. Auto-routing wrappers renamed to `symmetric_auto` / `hybrid_auto`. All encrypt/decrypt functions now return `Result<PathBuf, CryptoError>` instead of `Result<String, CryptoError>`. `generate_key_pair` returns `KeyPairInfo` struct with paths and fingerprint. `detect_encryption_mode` returns `Result<Option<EncryptionMode>, CryptoError>` instead of `Option`. `hybrid_encrypt` no longer requires a passphrase argument.
- **Breaking (library API):** Renamed functions (`generate_asymmetric_key_pair` → `generate_key_pair`), parameters (`rsa_key_pem` → `key_file`), and `CryptoError` variants. Removed `bit_size` parameter, `_with_progress` function variants, `serde::Serialize` on `CryptoError`, and error variants tied to removed dependencies. All public path parameters now use `impl AsRef<Path>` instead of `&str`; `save_as` changed from `Option<&str>` to `Option<&Path>`.
- **Breaking (CLI):** Removed `--bit-size` / `-b` and `--large` / `-l` flags
- Key files use `private.key` (passphrase-protected via Argon2id + XChaCha20-Poly1305) and `public.key` (raw 32 bytes)
- Encrypt vs decrypt determined by reading file header magic bytes, not file extension
- Replaced `reed-solomon-simd` with simple triple replication (RS with 1 original shard was producing identical copies)
- Replaced bincode header serialization with raw byte layout for long-term format stability
- Stream encryption buffer increased from 500 bytes to 64 KiB
- Empty passphrases rejected for symmetric encryption
- Moved Tauri and Dioxus GUIs to `experiments/`

### Fixed
- **Security:** `EncryptWriter` and `DecryptReader` now zeroize plaintext buffers on drop, preventing cleartext from lingering on the heap after errors or normal completion
- Archived files now use `0o644` permissions instead of `0o755` — decrypted files are no longer marked executable
- Encrypted output files are now `fsync`'d to disk before reporting success, preventing data loss if the system crashes before the OS flushes write buffers
- Encrypt/decrypt routing now uses magic-byte detection only — `.fcr` extension no longer forces the decrypt path, so non-FerroCrypt files named `.fcr` can be encrypted
- Default encrypted output naming for directories with dots (e.g. `photos.v1/`) now preserves the full directory name (`photos.v1.fcr` instead of `photos.fcr`)
- Directory archiver replaced with a manual recursive walk: symlinks and special entries (sockets, FIFOs, devices) are rejected at encryption time; hardlinks are archived as regular file contents. File opens use `O_NOFOLLOW` on Unix, with post-open regular-file validation, to harden against symlink and special-file TOCTOU races during archiving. Extraction also rejects unsupported entry types instead of silently dropping them.
- **Security:** KDF parameters from untrusted file headers are now fully bounded — `time_cost`, `lanes`, and zero values are rejected in addition to the existing `mem_cost` cap, preventing denial-of-service via crafted encrypted files or key files
- Symmetric decryption error message for wrong password is now "Password incorrect or file header corrupted" to account for ambiguous corruption cases
- **Stream truncation vulnerability:** symmetric decryption had a code path that skipped `decrypt_last()`, allowing truncation at chunk boundaries without detection
- **Security:** Directory encryption no longer follows symlinks — prevents unintended inclusion of files outside the selected directory tree. Symlink inputs are now explicitly rejected.
- Symmetric decryption now verifies the HMAC before the key-hash check, so header tampering is reported as an authentication failure rather than "wrong password"
- HMAC covers decoded (canonical) field values — single-copy replication corruption recovered by majority vote no longer causes HMAC verification failure
- Private key files written with `0o600` (owner-only) on POSIX systems
- Key material zeroized on all error paths (decrypted envelope keys, combined key buffer, hybrid plaintext buffers, HMAC failure early returns)
- Compile-time size assertion on `crypto_box::SecretKey` to guard unsafe zeroization against upstream layout changes
- Length validation on decrypted envelope key material
- Crash on truncated, corrupted, maliciously crafted `.fcr` files, or unexpected replicated decoding output length
- Nonexistent input paths silently producing empty encrypted files
- `keygen` now creates missing output directories
- Temporary directory cleanup masking the original crypto error and race condition with concurrent encryptions
- Directory archiver silently skipping inaccessible files and path errors
- Failed encryptions clean up partial `.fcr` output files; failed decryptions rename partial output with `.incomplete` suffix
- Key pair generation is now atomic — both files are written to temp names and renamed into place; partial state is cleaned up on failure

### Removed
- `openssl`, `reed-solomon-simd`, `bincode`, and `serde` dependencies
- `normalize_paths` helper and `ENCRYPTED_DOT_EXTENSION` constant (replaced by `Path` operations)

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
