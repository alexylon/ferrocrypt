# Changelog

All notable changes to FerroCrypt are documented in this file.

## [Unreleased]

### Added
- **New `Encryptor` / `Decryptor` value-type API.** Pick the recipient kind at construction (`Encryptor::with_passphrase(pass)` / `with_recipient(public_key)` / `with_recipients(iter)`); optional `.save_as(path)` / `.archive_limits(limits)` / `.kdf_limit(limit)` / `.header_read_limits(limits)` builders; finalize with `.write(input, output_dir, on_event)`. `Decryptor::open(input)` probes the file's recipient list with no crypto and returns a typed `Decryptor::Passphrase` or `Decryptor::Recipient` variant, so passing the wrong credential is a compile error rather than a runtime failure. Multi-recipient encrypt is supported: `with_recipients([alice, bob])` produces a single `.fcr` either recipient can decrypt with their own private key. New `PublicKey` and `PrivateKey` types replace raw byte arrays in the public API.
- **Bech32 recipient strings (`fcr1...`)** for human-readable public-key exchange. Build a `PublicKey` via `PublicKey::from_recipient_string("fcr1…")` and render with `to_recipient_string()`. Copy-paste corruption is detected at decode. CLI: `encrypt --recipient` / `-r` takes an `fcr1…` string directly (repeatable, mixable with `--public-key` / `-k`); the `public.key` file is itself a single-line UTF-8 recipient string, so `cat public.key` is enough.
- **SHA3-256 public-key fingerprints** for out-of-band verification, domain-separated by recipient type so future native types (post-quantum, hybrid KEMs) cannot collide with X25519 fingerprints. CLI: new `fingerprint` subcommand (alias `fp`); `keygen` and `encrypt` print the relevant fingerprint. Desktop app shows the fingerprint with a copy-to-clipboard button.
- **`ArchiveLimits` and archive resource caps**, applied symmetrically on encrypt and decrypt. Defaults: at most 250,000 entries, 64 GiB total file content, 64 path segments. Decrypt caps fire before any allocation to bound DoS exposure; the encrypt-side preflight refuses trees the default-config decrypt would refuse, preventing the "encrypt fine but cannot decrypt your own file" footgun. Override via `Encryptor::archive_limits(limits)` and the decryptor variants. A `.fcr` written under elevated caps must be decrypted under matching caps.
- **`HeaderReadLimits` exposed publicly** so callers can opt into elevated header / recipient-count / recipient-body caps when files legitimately exceed the conservative defaults. New `Decryptor::open_with_limits` and `detect_encryption_mode_with_limits` propagate the limits; either decryptor variant also exposes `.header_read_limits(limits)`.
- **`--max-kdf-memory <MiB>` flag on `decrypt`** to cap accepted KDF memory cost. Library: attach a `KdfLimit` via `.kdf_limit(limit)`; out-of-budget files fail with `KdfResourceCapExceeded`. Default ceiling 1 GiB.
- **`--save-as` / `-s` flag on `encrypt`** to choose the encrypted output filename. `--output-dir` is optional when `--save-as` is given.
- **`--allow-double-encrypt` flag on `encrypt`.** Inputs whose first 4 bytes match the FerroCrypt magic warn and refuse by default; an interactive shell prompts y/N (default N), a non-interactive shell exits 1.
- **Early conflict detection** for `encrypt` and `keygen` — fails before overwriting an existing `.fcr` file or key pair.
- **Subcommand help, descriptions, and aliases.** `enc` for `encrypt`, `dec` for `decrypt`, `gen` for `keygen`, `fp` for `fingerprint`.
- **Slint-based desktop app** (`ferrocrypt-desktop`) with Symmetric and Hybrid tabs. Inline key generation in the Hybrid tab; auto-transition to Hybrid Encrypt with the public key pre-filled. "Save As" dialog, magic-byte mode detection, conflict warnings, key file validation on selection, password strength indicator (scoring adapted from Proton Pass).
- **`MixingPolicy::Custom { compatibility_class }`** variant on `CryptoError::IncompatibleRecipients`, reserved for future native compatibility classes (starting with the upcoming post-quantum `x25519-mlkem768` recipient). The two existing variants (`Exclusive`, `PublicKeyMixable`) keep their shape.
- Progress messages (`Deriving key…`, `Encrypting…`, etc.) printed to stderr.

### Changed
- **Breaking:** New on-disk **format v1** across every artefact. Single `.fcr` extension replaces `.fcs` / `.fch`. v1 `.fcr` is a single container with a typed **recipient list**, not a per-mode envelope: the symmetric-vs-hybrid distinction is derived from the list, not encoded in the header. v1.0 ships two native recipient types: `argon2id` (passphrase, exclusive — must appear alone) and `x25519` (public-key, mixable — multiple slots in one file are supported and the decrypt loop iterates). Mixed lists (e.g. `argon2id` plus `x25519`) reject before any KDF runs. See `ferrocrypt-lib/FORMAT.md` for the full byte-level spec.
- **Breaking:** Hybrid encryption migrated from RSA-4096 (OpenSSL) to **X25519 ECDH + HKDF-SHA3-256 + XChaCha20-Poly1305** envelope encryption. Removes the OpenSSL C dependency — the project is now pure Rust. All-zero shared secrets are rejected as a small-order key defence. Pre-`0.3.0` hybrid files cannot be decrypted; old key pairs must be regenerated.
- **Breaking:** Both modes use a per-file random **32-byte `file_key`** indirection (age-inspired). The recipient body seals the random `file_key`; the payload AEAD key and the header MAC key are derived separately from `file_key`, so a compromise of one subkey does not reveal the other. Argon2id parameters: 1 GiB memory, time cost 4, parallelism 4. Payload is XChaCha20-Poly1305 STREAM-BE32 over 64 KiB chunks. The header MAC is verified after a recipient successfully unwraps a candidate `file_key`; MAC verification is the final acceptance gate. Multi-recipient MAC failures surface as `HeaderMacFailedAfterUnwrap { type_name }` and the loop continues; single-recipient MAC failures surface as `HeaderTampered`.
- **Breaking:** `public.key` is a **UTF-8 text file** containing the canonical Bech32 `fcr1…` recipient string optionally followed by a single trailing LF (no other surrounding whitespace).
- **Breaking:** `private.key` v1 is passphrase-protected via **Argon2id + HKDF-SHA3-256 + XChaCha20-Poly1305** with permissions `0o600` on POSIX. The cleartext header is bound to authentication, so tampering any field fails the unlock. Wrong passphrase and tampered file are indistinguishable at the AEAD layer; both surface as `KeyFileUnlockFailed` with wording `"Private key unlock failed: wrong passphrase or tampered file"`. The public/private halves are cross-checked at unlock; mismatch surfaces as `MalformedPrivateKey`, catching structurally valid files whose halves were sealed inconsistently.
- **Breaking:** Forward-compatible authenticated **TLV extension region** is present in both `.fcr` and `private.key` (empty in v1.0). Reserved-tag and critical-tag rules let future format additions reject older readers safely. Cap: 64 KiB.
- **Breaking:** SHA-3 unified across the spec — HMAC-SHA3-256 for the header MAC, HKDF-SHA3-256 for every key derivation, SHA3-256 for fingerprints and the internal Bech32 checksum.
- **Breaking (CLI):** Operation-oriented subcommand surface. `symmetric` / `sym` and `hybrid` / `hyb` are removed; everything goes through `encrypt` (alias `enc`) and `decrypt` (alias `dec`). `keygen` (alias `gen`) and `fingerprint` (alias `fp`) keep their names. Mode is decided by what the user supplies: `encrypt` runs in passphrase mode by default and switches to public-recipient mode when `--recipient` / `-r` or `--public-key` / `-k` is given; `decrypt` reads the file's recipient list and routes itself. The `recipient` / `rc` subcommand is removed because `public.key` is itself a single-line `fcr1...` text file. Long-flag renames: `--input-path` → `--input`, `--output-path` → `--output-dir`, `--key` → `--public-key` (encrypt) / `--private-key` (decrypt). Short-flag case split: `-k` is the shareable public key, `-K` is the secret private key. Removed flags: `--bit-size` / `-b`, `--large` / `-l` (RSA-only).
- **Breaking (CLI):** Passphrases are no longer accepted as CLI argument values. They are prompted interactively with hidden input and confirmation on encrypt and keygen. For non-interactive use (scripts, CI) set the `FERROCRYPT_PASSPHRASE` environment variable. Empty passphrases are rejected.
- **Breaking (library API):** `PublicKey::from_bytes` now returns `Result<PublicKey, CryptoError>` and structurally rejects the all-zero X25519 public key at construction. The same reject runs at every ingress that loads a public key. Callers that previously chained `PublicKey::from_bytes(b).validate()?` should now write `PublicKey::from_bytes(b)?.validate()?`.
- **Breaking (library API):** Renamed `EncryptionMode::Symmetric` → `Passphrase` and `EncryptionMode::Hybrid` → `Recipient` to match the recipient-oriented vocabulary. Desktop tab names are unchanged.
- **Breaking (library API):** Folded `CryptoError::PassphraseRecipientMixed` and the previous `CryptoError::IncompatibleRecipients { policy }` into `CryptoError::IncompatibleRecipients { type_name: String, policy: MixingPolicy }`. Encrypt-side and decrypt-side mixing rejections both surface the same variant. Existing `match err { CryptoError::PassphraseRecipientMixed => ... }` arms must be rewritten; arms that destructured `policy` only must add a `type_name` binding (or `..`).
- **Encrypt vs. decrypt routing uses magic-byte detection only** — file extension no longer forces a path. Files that start with the FerroCrypt magic but have a corrupted header now fail closed with a typed format error instead of being silently re-encrypted.
- **Atomic output handling.** Encrypted files and generated key files are staged under temporary names and promoted to their final path only on success; ordinary single-writer use no longer silently replaces an existing file. Directory decryption uses an `.incomplete` working directory that is moved into place once extraction finishes; on failure the `.incomplete` copy remains on disk for inspection. Linux and macOS use a stronger directory-finalization path; Windows keeps a narrower best-effort step. The library contains no unsafe code.
- **File and directory permissions are preserved** through encrypt/decrypt round-trips on Unix. Setuid, setgid, and sticky bits are stripped on both archiving and extraction. Decrypted regular files are no longer marked executable. On non-Unix platforms, permission handling is platform-limited.

### Removed
- **Breaking (library API):** Removed the legacy `symmetric_encrypt` / `symmetric_decrypt` / `hybrid_encrypt` / `hybrid_decrypt` free functions and their `*Config` structs, the auto-routing wrappers (`symmetric_auto` / `hybrid_auto`), and the free functions `public_key_fingerprint` / `encode_recipient` / `encode_recipient_from_bytes`. Use `Encryptor` / `Decryptor`, `generate_key_pair(output_dir, passphrase, on_event)`, `detect_encryption_mode`, and `PublicKey` methods. `decode_recipient` remains as the low-level Bech32 primitive.
- `openssl`, `reed-solomon-simd`, `bincode`, and `serde` dependencies.

### Fixed
- **Decryption errors are now distinct and user-readable.** Previously a failed decryption surfaced as a wrapped internal error with no way to tell whether the password was wrong, the header was tampered, the payload was corrupted, or the file was truncated. The library now exposes a typed taxonomy:
    - `KeyFileUnlockFailed` — `private.key` failed to unlock (wrong passphrase or tampered file; the AEAD primitive cannot distinguish the two).
    - `RecipientUnwrapFailed { type_name }` — recipient body failed to unwrap (wrong credential or tampered body).
    - `HeaderMacFailedAfterUnwrap { type_name }` — multi-recipient: a candidate slot unwrapped but MAC verification failed; the loop continues to the next supported slot.
    - `HeaderTampered` — single-recipient: unwrap succeeded but MAC verification failed.
    - `NoSupportedRecipient` — no entry in the recipient list yielded a verifying credential.
    - `IncompatibleRecipients { type_name, policy }` — the file declares an exclusive recipient (today only `argon2id`) alongside any other entry; rejected before any KDF runs.
    - `UnknownCriticalRecipient { type_name }` — the file declares a recipient with the critical bit whose `type_name` is unknown to this implementation.
    - `PayloadTampered` — a ciphertext chunk failed authentication.
    - `PayloadTruncated` — the encrypted stream ends before its final-flag chunk.
    - `ExtraDataAfterPayload` — bytes remain after the final-flag chunk.
    - `KdfResourceCapExceeded { mem_cost_kib, local_cap_kib }` — KDF parameters request more memory than the configured limit allows.
    - `DecryptorModeMismatch { expected, found }` — wrong decryptor variant for the file's recipient list.

  Variants carry typed structured data so callers can pattern-match without parsing messages. Header-read I/O errors are more precise: a non-EOF `io::Error` (`PermissionDenied`, `BrokenPipe`, etc.) raised mid-header now surfaces as a real I/O error instead of being collapsed to a corrupt-file diagnostic — a failing disk no longer masquerades as a corrupted file. The CLI prints errors using `Display` instead of the default `Debug` format, so users see the library's short messages directly.
- **Security: Windows no longer silently overwrites existing output.** Earlier versions on Windows could replace an existing `.fcr` file or key file at the output path without asking. Encryption and key generation now avoid silently replacing existing final files, and directory decryption follows the same intent.
- **Security: archive payload conforms to a strict POSIX ustar subset** (`FORMAT.md` §9). Hostile or malformed archive entries are rejected per a tight whitelist (entry types, paths, UTF-8, trailing-slash convention, canonical-path duplicates, end-of-archive zero padding) before any filesystem write.
- **Security: an `x25519` recipient slot whose ECDH shared secret is all zero now causes file-fatal rejection in every code path** (`FORMAT.md` §2.4 / §4.2). Practical impact today is bounded — FerroCrypt's own writer cannot produce such files — but a structurally valid file from any source is now refused as required, regardless of recipient slot ordering.
- **Security: PAX `'x'` extended headers that override the size attribute now reject at archive validation.** FerroCrypt's own writer never emits PAX records.
- **Security: extraction rejects archives with multiple top-level roots.** FerroCrypt's archiver always produces exactly one. Earlier extraction silently created every root in a tampered payload while the public return value only reported the first; now any second distinct top-level root is refused before its output is written.
- **Security: key generation writes the public key before the private key.** If generation is interrupted partway, the private key never appears on disk — only an orphan public key remains, which is harmless.
- **Security: directory encryption no longer follows symlinks.** Symlink inputs and symlink entries inside directories are rejected before any Argon2id work runs. Hardlinks are archived as regular file contents. Extraction rejects unsupported TAR entry types instead of silently dropping them.
- **Security: extraction is hardened against local symlink/directory-component races on Linux and macOS.** A concurrent local attacker who swaps a directory component for a symlink can no longer redirect writes outside the destination tree. Windows and other Unix targets keep the existing path-based extraction.
- **Security: KDF parameters from untrusted headers are bounded** in every dimension (memory, time cost, parallelism), preventing denial-of-service via crafted encrypted files or key files. Over-budget headers surface as `KdfResourceCapExceeded` before Argon2id runs.
- **Security: native recipient entries with the critical bit set now reject before any expensive KDF work.** End behaviour is unchanged (the file is still rejected); the rejection happens earlier so an adversarial file cannot force compute on a CPU/RAM-bounded reader. FerroCrypt's own writers cannot produce such entries, so files written by any FerroCrypt release are unaffected.
- **Security: plaintext and key material are zeroized after use** — per-chunk plaintext buffers between chunks and on drop, decrypted key material in zeroizing wrappers, covering success, error, and unwinding paths.
- **Desktop: worker thread panics no longer freeze the UI.** Previously, a panic in the encrypt/decrypt/keygen worker (e.g. Argon2id OOM on a constrained host) left the UI permanently disabled with the "working…" state stuck. The app now stays recoverable on panic.
- **Recipient-decrypt progress phases.** The recipient (X25519) decrypt path now emits `DerivingKey` before the private-key Argon2id runs and `Decrypting` only after the recipient body unwraps — matching the passphrase path. Previously a UI mislabelled the multi-second KDF window as "decrypting".
- **Pub/priv key file mix-ups now report `WrongKeyFileType`.** Previously, reading a binary `private.key` as a public key surfaced a cryptic UTF-8 error, and reading a text `public.key` as a private key surfaced a generic format defect.
- **`public.key` enforces strict canonical whitespace.** The file MUST be the lowercase `fcr1…` recipient string optionally followed by exactly one trailing `\n`. Other surrounding whitespace (CRLF line endings, leading blanks, trailing spaces, blank lines) is rejected as `MalformedPublicKey` rather than silently trimmed.
- **Missing key-file paths** surface as a typed input-path error instead of leaking a raw OS error string.
- **`InvalidKdfParams` Display wording.** "File has invalid decrypt settings" → "File has invalid KDF settings": neutral across the encrypt/decrypt split.
- Output-conflict wording unified to "Output already exists: `path`". Symlink-race wording unified to "Input is a symlink: `path`".
- Crash on truncated, corrupted, or maliciously crafted `.fcr` files replaced with structured format errors.
- Default encrypted output naming for directories with dots (e.g. `photos.v1/`) preserves the full directory name (`photos.v1.fcr` instead of `photos.fcr`).
- Nonexistent input paths no longer silently produce empty encrypted files.
- `keygen` creates missing output directories. Key pair generation is atomic: both files are written to temp names, `fsync`'d, and renamed into place; partial state is cleaned up on failure.
- Directory archiver no longer silently skips inaccessible files or path errors.

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
