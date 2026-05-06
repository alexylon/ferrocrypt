# Changelog

All notable changes to FerroCrypt are documented in this file.

## [Unreleased]

### Security
- **Hardened extraction unified across Linux, macOS, and Windows.** Replaced the previous platform split (rustix-based hardened path on Linux/macOS plus a path-based fallback elsewhere) with a single capability-based extractor built on `cap-std` + `cap-fs-ext`. Every directory open routes through `cap_fs_ext::DirExt::open_dir_nofollow`, so a symlink at any component of an extraction path is rejected on every supported OS. On Windows, directory opens additionally fail closed on any NTFS reparse point — including junctions and mount points — via an explicit `FILE_ATTRIBUTE_REPARSE_POINT` post-check. File creation uses `OpenOptions::create_new(true)` plus `OpenOptionsFollowExt::follow(FollowSymlinks::No)`. Permissions are always set on an open handle, never via a re-resolved path. The previous Windows path-based fallback's documented symlink-race exposure is closed.

### Added
- **`Encryptor::kdf_params(KdfParams)` and `KeyPairGenerator` builder.** The encrypt-side passphrase path and the new key-pair generator both accept an explicit `KdfParams` override, replacing the previous all-or-nothing reliance on `KdfParams::default()`. The free function `generate_key_pair(...)` is preserved as a thin wrapper around `KeyPairGenerator::with_passphrase(...).write(...)` for backwards compatibility. `KdfParams` is now publicly re-exported from `ferrocrypt`.
- **New `Encryptor` / `Decryptor` value-type API.** Pick the recipient kind at construction (`Encryptor::with_passphrase(pass)` / `with_recipient(public_key)` / `with_recipients(iter)`); optional `.save_as(path)` / `.archive_limits(limits)` / `.kdf_limit(limit)` / `.header_read_limits(limits)` / `.kdf_params(params)` builders; finalize with `.write(input, output_dir, on_event)`. `Decryptor::open(input)` probes the file's recipient list with no crypto and returns a typed `Decryptor::Passphrase` or `Decryptor::Recipient` variant, so passing the wrong credential is a compile error rather than a runtime failure. Multi-recipient encrypt is supported: `with_recipients([alice, bob])` produces a single `.fcr` either recipient can decrypt with their own private key. New `PublicKey` and `PrivateKey` types replace raw byte arrays in the public API.
- **Bech32 recipient strings (`fcr1...`)** for human-readable public-key exchange. Build a `PublicKey` via `PublicKey::from_recipient_string("fcr1…")` and render with `to_recipient_string()`. Copy-paste corruption is detected at decode. CLI: `encrypt --recipient` / `-r` takes an `fcr1…` string directly (repeatable, mixable with `--public-key` / `-k`); the `public.key` file is itself a single-line UTF-8 recipient string, so `cat public.key` is enough.
- **SHA3-256 public-key fingerprints** for out-of-band verification, domain-separated by recipient type so future native types (post-quantum, hybrid KEMs) cannot collide with X25519 fingerprints. CLI: new `fingerprint` subcommand (alias `fp`); `keygen` and `encrypt` print the relevant fingerprint. Desktop app shows the fingerprint with a copy-to-clipboard button.
- **`ArchiveLimits` and archive resource caps**, applied symmetrically on encrypt and decrypt. Defaults: at most 250,000 entries, 64 GiB total file content, 64 path segments. Decrypt caps fire before any allocation to bound DoS exposure; the encrypt-side preflight refuses trees the default-config decrypt would refuse, preventing the "encrypt fine but cannot decrypt your own file" footgun. Override via `Encryptor::archive_limits(limits)` and the decryptor variants. A `.fcr` written under elevated caps must be decrypted under matching caps.
- **`HeaderReadLimits` exposed publicly** so callers can opt into elevated header / recipient-count / recipient-body caps when files legitimately exceed the conservative defaults. New `Decryptor::open_with_limits` and `detect_encryption_mode_with_limits` propagate the limits; either decryptor variant also exposes `.header_read_limits(limits)`.
- **`--max-kdf-memory <MiB>` flag on `decrypt`** to cap accepted KDF memory cost. Library: attach a `KdfLimit` via `.kdf_limit(limit)`; out-of-budget files fail with `KdfResourceCapExceeded`. Default ceiling 1 GiB.
- **`--keep-partial` flag on `decrypt`** for backup-recovery and forensic flows: keep the staged `.incomplete` plaintext when a decrypt fails mid-stream so the caller can inspect or recover authenticated chunks already written. Library: opt in via `.incomplete_output_policy(IncompleteOutputPolicy::RetainOnError)` on either decryptor variant. Without the flag the default is `DeleteOnError` — see "Default cleanup-on-error" under **Changed**.
- **`--save-as` / `-s` flag on `encrypt`** to choose the encrypted output filename. `--output-dir` is optional when `--save-as` is given.
- **`--allow-double-encrypt` flag on `encrypt`.** Inputs whose first 4 bytes match the FerroCrypt magic warn and refuse by default; an interactive shell prompts y/N (default N), a non-interactive shell exits 1.
- **Early conflict detection** for `encrypt` and `keygen` — fails before overwriting an existing `.fcr` file or key pair.
- **Subcommand help, descriptions, and aliases.** `enc` for `encrypt`, `dec` for `decrypt`, `gen` for `keygen`, `fp` for `fingerprint`.
- **Slint-based desktop app** (`ferrocrypt-desktop`) with **Password** and **Key pair** tabs. Inline key generation in the Key pair tab; auto-transition to Key pair Encrypt with the public key pre-filled. "Save As" dialog, magic-byte mode detection, conflict warnings, key file validation on selection, password strength indicator (scoring adapted from Proton Pass).
- **`MixingPolicy::Custom { compatibility_class }`** variant on `CryptoError::IncompatibleRecipients`, reserved for future native compatibility classes (starting with the upcoming post-quantum `x25519-mlkem768` recipient). The two existing variants (`Exclusive`, `PublicKeyMixable`) keep their shape.
- Progress messages (`Deriving passphrase key…`, `Unlocking private key…`, `Encrypting…`, etc.) printed to stderr.

### Changed
- **Breaking:** New on-disk **format v1** across every artefact. Single `.fcr` extension replaces `.fcs` / `.fch`. v1 `.fcr` is a single container with a typed **recipient list**, not a per-mode envelope: the symmetric-vs-hybrid distinction is derived from the list, not encoded in the header. v1 defines two native recipient types: `argon2id` (passphrase, exclusive — must appear alone) and `x25519` (public-key, mixable — multiple slots in one file are supported and the decrypt loop iterates). Mixed lists (e.g. `argon2id` plus `x25519`) reject before any KDF runs. See `ferrocrypt-lib/FORMAT.md` for the full byte-level spec.
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
- **Breaking (library API): writer caps mirror reader defaults.** A default-configured `Encryptor` now rejects configurations that would produce a `.fcr` file a default-configured `Decryptor::open` refuses, instead of silently producing them. Specifically: `Encryptor::with_recipients(...)` followed by `.write(...)` rejects `recipients.len() > 64` (the default `RECIPIENT_COUNT_LOCAL_CAP_DEFAULT`) with `RecipientCountCapExceeded` before any X25519 ECDH runs; `Encryptor::with_passphrase(...).kdf_params(P)` rejects `P.mem_cost > 1 GiB` (the default `KdfLimit`) with `KdfResourceCapExceeded` before Argon2id runs. The writer-side preflight also checks the per-entry `body_len` and the exact `header_len` it will emit against the same `HeaderReadLimits`, so all three header axes — recipient count, body length, header length — refuse to produce above-cap output unless the caller raises that axis explicitly. To produce a file with more recipients or any other axis above default, the caller MUST opt in via the new `Encryptor::header_read_limits(HeaderReadLimits)` and `Encryptor::kdf_limit(KdfLimit)` builders, AND the receiving decryptor MUST be configured with matching limits (`Decryptor::open_with_limits` and `*::kdf_limit`). `KeyPairGenerator::kdf_params` follows the same rule for the passphrase that seals `private.key`; the new `KeyPairGenerator::kdf_limit` is the matching opt-in. Pre-existing files are unaffected — only the encrypt/keygen surfaces tighten.
- **Breaking (library API): writer-side structural KDF validation.** `Encryptor::with_passphrase(...).kdf_params(P)` and `KeyPairGenerator::kdf_params(P)` now reject structurally invalid Argon2id parameters (`lanes` outside `1..=8`, `time_cost` outside `1..=12`, `mem_cost` outside `[8 × lanes, 2 GiB]`) with `CryptoError::InvalidKdfParams(...)` at `write` time, mirroring the reader's `KdfParams::from_bytes_structural`. Previously these would have flowed through to argon2's runtime check and produced an artefact no FerroCrypt reader could open. Both encrypt and decrypt now route every Argon2id-parameter validation through the same `KdfParams::validate_structural` helper.
- **Breaking (library API):** `FormatDefect::ExtTooLarge { len }` is now emitted on both sides when `ext_len > EXT_LEN_MAX`. Previously the writer emitted `ExtTooLarge` and the reader emitted the generic `MalformedHeader` for the same wire-format violation. Existing `match` arms on `MalformedHeader` for the specific `ext_len > EXT_LEN_MAX` case must be updated to `ExtTooLarge { len }`. Other reader-side `MalformedHeader` cases (truncation, malformed flags, length-field inconsistency) are unchanged.
- **Encrypt vs. decrypt routing uses magic-byte detection only** — file extension no longer forces a path. Files that start with the FerroCrypt magic but have a corrupted header now fail closed with a typed format error instead of being silently re-encrypted.
- **Atomic output handling.** Encrypted files and generated key files are staged under temporary names and promoted to their final path only on success; ordinary single-writer use no longer silently replaces an existing file. Directory decryption uses an `.incomplete` working directory that is moved into place once extraction finishes; on failure the staged tree is removed by default (see "Default cleanup-on-error" below) or retained when the caller opts in via `IncompleteOutputPolicy::RetainOnError`. Directory extraction uses the unified capability-based backend described above before promotion. The library contains no unsafe code.
- **Default cleanup-on-error for failed decrypts.** When a decrypt fails mid-stream — payload AEAD on a later chunk, archive structural reject after some entries were written, trailing zero-block reject, final-rename collision — the staged `.incomplete` plaintext is now best-effort removed before the typed `CryptoError` returns. Earlier revisions left the staged tree on disk, which surprised callers who expected "decrypt failed" to mean "no plaintext written" and could expose authenticated-but-incomplete plaintext to downstream automation. The retain-for-inspection behaviour is still available as `IncompleteOutputPolicy::RetainOnError` (CLI `--keep-partial`); callers who opt in MUST treat retained partials as a potentially attacker-chosen prefix because FerroCrypt's STREAM-BE32 payload only detects truncation when the final chunk arrives. Cleanup tracks only roots THIS run created, so a pre-existing `.incomplete` from a prior failed run is preserved across a retry that fails with `Previous .incomplete exists`.
- **File and directory permissions are preserved** through encrypt/decrypt round-trips on Unix. Setuid, setgid, and sticky bits are stripped on both archiving and extraction. Decrypted regular files are no longer marked executable. On non-Unix platforms, permission handling is platform-limited.
- **Breaking (library API): `ProgressEvent` split for accurate UI signalling.** The single legacy `DerivingKey` variant (which fired both for "Argon2id is about to run" and speculatively from the orchestrator before the file was even parsed) is replaced by two specific variants emitted at the actual KDF call boundary: `DerivingPassphraseWrapKey` (Display: `"Deriving passphrase key…"`) for the passphrase recipient encrypt + decrypt, and `UnlockingPrivateKey` (Display: `"Unlocking private key…"`) for `private.key` Argon2id unlock. Pure-X25519 encrypt and structurally-malformed file rejects fire **zero** KDF events. The orchestrator no longer emits a speculative event before parsing; UIs that previously showed "Deriving key…" briefly during X25519 wrapping or for the few microseconds before a malformed-file rejection no longer do. `match`/`matches!` on `ProgressEvent::DerivingKey` must be replaced with the specific variants. The orchestrator calls `wrap_file_key` / `unwrap_file_key` once per supported slot, so `DerivingPassphraseWrapKey` fires exactly once on a successful passphrase encrypt or decrypt and zero times when no passphrase slot is reached.

### Removed
- **Breaking: removed the public `fast-kdf` Cargo feature.** Earlier revisions exposed a Cargo feature that lowered `KdfParams::default()` to test-speed Argon2id parameters when any consumer in the dependency graph activated it. `KdfParams::default()` now always returns production parameters (1 GiB memory, time_cost 4, parallelism 4). Callers that genuinely need different parameters construct `KdfParams` explicitly and pass it via the new `Encryptor::kdf_params(...)` / `KeyPairGenerator::kdf_params(...)` builders.
- **Breaking (library API):** Removed the legacy `symmetric_encrypt` / `symmetric_decrypt` / `hybrid_encrypt` / `hybrid_decrypt` free functions and their `*Config` structs, the auto-routing wrappers (`symmetric_auto` / `hybrid_auto`), and the free functions `public_key_fingerprint` / `encode_recipient` / `encode_recipient_from_bytes`. Use `Encryptor` / `Decryptor`, `generate_key_pair(output_dir, passphrase, on_event)`, `detect_encryption_mode`, and `PublicKey` methods. `decode_recipient` remains as the low-level Bech32 primitive.
- `openssl`, `reed-solomon-simd`, `bincode`, and `serde` dependencies.
- **`xattr` transitive dependency.** `tar` is now pulled with `default-features = false`; FerroCrypt's wire format does not preserve extended attributes, so the `tar` `xattr` feature was unused supply-chain surface. No user-visible behavior change.

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
- **Security: every PAX and GNU TAR extension record now rejects at archive validation.** Decryption iterates archive entries with `tar::Entries::raw(true)`, so PAX (`'x'` per-entry, `'g'` global) and GNU (`'L'`/`'K'` long-name/long-link, `'S'` sparse, `'M'` multi-volume, `'D'` dumpdir, `'V'` volume-header, `'N'` legacy long-name) and Solaris (`'X'`) extension records surface as their own entries with the wire typeflag intact and reject explicitly, instead of being silently merged into the next entry's metadata by the `tar` crate. Earlier revisions caught only PAX records that overrode the path or size attribute (the only attributes whose merge left a detectable signature); PAX overrides of mtime, uid/gid, or mode could slip past undetected. FerroCrypt's own writer has never emitted PAX or GNU records, so files written by any FerroCrypt release are unaffected.
- **Encrypt and decrypt agree on a single per-file size ceiling.** The largest value the standard ustar `size` field can carry is `8_589_934_591` bytes (one byte short of 8 GiB). Encrypt rejects larger single-file inputs with a clear error before any KDF or cipher work runs. Decrypt rejects any header whose `size` field uses the GNU binary numeric encoding (the underlying `tar` crate's silent fallback for `size ≥ 2^33`), so an attacker cannot smuggle a multi-gigabyte regular-file declaration past the validator.
- **Security: extraction rejects archives with multiple top-level roots.** FerroCrypt's archiver always produces exactly one. Earlier extraction silently created every root in a tampered payload while the public return value only reported the first; now any second distinct top-level root is refused before its output is written.
- **Security: key generation writes the public key before the private key.** If generation is interrupted partway, the private key never appears on disk — only an orphan public key remains, which is harmless.
- **Security: directory encryption no longer follows symlinks.** Symlink inputs and symlink entries inside directories are rejected before any Argon2id work runs. Hardlinks are archived as regular file contents. Extraction rejects unsupported TAR entry types instead of silently dropping them.
- **Security: extraction is hardened against local symlink/directory-component races across Linux, macOS, and Windows.** A concurrent local attacker who swaps a directory component for a symlink can no longer redirect writes outside the destination tree; on Windows, NTFS reparse points such as junctions and mount points are rejected too. The old path-based extraction fallback is removed.
- **Security: KDF parameters from untrusted headers are bounded** in every dimension (memory, time cost, parallelism), preventing denial-of-service via crafted encrypted files or key files. Over-budget headers surface as `KdfResourceCapExceeded` before Argon2id runs.
- **Security: native recipient entries with the critical bit set now reject before any expensive KDF work.** End behaviour is unchanged (the file is still rejected); the rejection happens earlier so an adversarial file cannot force compute on a CPU/RAM-bounded reader. FerroCrypt's own writers cannot produce such entries, so files written by any FerroCrypt release are unaffected.
- **Security: plaintext and key material are zeroized after use** — per-chunk plaintext buffers between chunks and on drop, decrypted key material in zeroizing wrappers, covering success, error, and unwinding paths.
- **Desktop: worker thread panics no longer freeze the UI.** Previously, a panic in the encrypt/decrypt/keygen worker (e.g. Argon2id OOM on a constrained host) left the UI permanently disabled with the "working…" state stuck. The app now stays recoverable on panic.
- **Recipient-decrypt progress phases.** The recipient (X25519) decrypt path now emits `UnlockingPrivateKey` before the private-key Argon2id runs and `Decrypting` only after the recipient body unwraps — matching the passphrase path's `DerivingPassphraseWrapKey` → `Decrypting` ordering. Previously a UI mislabelled the multi-second KDF window as "decrypting".
- **Pub/priv key file mix-ups now report `WrongKeyFileType`.** Previously, reading a binary `private.key` as a public key surfaced a cryptic UTF-8 error, and reading a text `public.key` as a private key surfaced a generic format defect.
- **`public.key` enforces strict canonical whitespace.** The file MUST be the lowercase `fcr1…` recipient string optionally followed by exactly one trailing `\n`. Other surrounding whitespace (CRLF line endings, leading blanks, trailing spaces, blank lines) is rejected as `MalformedPublicKey` rather than silently trimmed.
- **Missing key-file paths** surface as a typed input-path error instead of leaking a raw OS error string.
- **`InvalidKdfParams` Display wording.** "File has invalid decrypt settings" → "File has invalid KDF settings": neutral across the encrypt/decrypt split.
- Output-conflict wording unified to "Output already exists: `path`". Symlink-race wording unified to "Input is a symlink: `path`".
- **Re-running encrypt against an existing output now fails immediately**, before any Argon2id derivation runs. Previously a populated destination cost a multi-second KDF in passphrase mode before the conflict surfaced. The atomic no-clobber rename remains the load-bearing race-proof guarantee. The same preflight catches dangling symlinks at the destination — earlier versions used `Path::exists()`, which follows the link and returned `false` for a missing target, letting the KDF run before the rename eventually refused to overwrite.
- **Recipient strings with non-ASCII characters now reject with a clear `InvalidInput("Recipient string must be ASCII Bech32")`** instead of misclassifying as a length-cap exceedance. Bech32 (BIP 173) is an ASCII-only grammar.
- **Strict TAR end-of-archive enforcement.** `FORMAT.md` §9 requires the archive payload to end with two 512-byte zero blocks. The previous reader accepted archives missing one or both end blocks because the underlying `tar` crate's raw iterator stops on the first all-zero header it sees — the post-iterator drain only checked that *remaining* bytes were zero, which was vacuously true for missing markers. Decrypt now requires both blocks and rejects archives missing either with `"Missing TAR end-of-archive zero block"`. FerroCrypt's own writer has always emitted both blocks via `tar::Builder::finish`, so files written by any FerroCrypt release are unaffected.
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
