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
# arms such as the Windows fallback path in `fs/atomic.rs`). Requires
# `rustup target add x86_64-pc-windows-gnu`, which is already installed on
# this machine.
cargo check  --package ferrocrypt --target x86_64-pc-windows-gnu
cargo clippy --package ferrocrypt --target x86_64-pc-windows-gnu --all-targets
```

Notes:
- For **doc-only changes**, do not run code tests/builds unless the change affects rustdoc rendering or examples.
- The desktop crate is excluded from the workspace, so root-level `cargo test` / `cargo clippy` do not cover it locally. **CI does cover it** via a separate `desktop` job that runs clippy + build + tests on Ubuntu / macOS / Windows on every PR.
- The Windows cross-check only type-checks (no linker), so it is sufficient for verifying `cfg(target_os = "windows")` / `cfg(not(unix))` arms compile. Use it whenever you touch `fs::atomic` or any other branch that varies by platform.

## `notes/` directory

Gitignored scratchpad for helper files the user asks to be created there — typically markdown (current proposal/plan files, side references during a refactor, etc.). Safe to read for context; nothing in `notes/` ships with the repo.

## Architecture

Repository layout:

- **ferrocrypt-lib** (`ferrocrypt` on crates.io) — core encryption library. All crypto logic lives here.
- **ferrocrypt-cli** — CLI binary (`ferrocrypt`). Thin wrapper calling library functions.
- **ferrocrypt-desktop** — Slint GUI app. Excluded from the Cargo workspace; built separately.

### Library Module Roles

| Module | Role |
|---|---|
| `lib.rs` | Public re-exports + module wiring: surfaces the `Encryptor` / `Decryptor` value-type API and `generate_key_pair` / `detect_encryption_mode` / `default_encrypted_filename` / `validate_*_key_file` from `api.rs`; re-exports `PublicKey` / `PrivateKey` (plus `RecipientKey` / `IdentityKey` aliases), `ProgressEvent`, `EncryptionMode` (variants `Passphrase` / `Recipient`), `MixingPolicy`, `ArchiveLimits`. |
| `api.rs` | Public façade. `Encryptor` (`with_passphrase` / `with_recipient` / `with_recipients` / `save_as` / `archive_limits` / `write`), the typed `Decryptor` enum (`Passphrase(PassphraseDecryptor)` / `Recipient(RecipientDecryptor)`) opened via `Decryptor::open`, key generation (`generate_key_pair(output_dir, passphrase, on_event)`), mode detection (`detect_encryption_mode`), key-file validation. Translates stable public types into internal protocol calls; owns no crypto, MAC, or header bytes. |
| `protocol.rs` | Single source of truth for encrypt / decrypt orchestration plus key-pair generation (writes `private.key` + `public.key` files). Defines `pub(crate) trait RecipientScheme` (encrypt-side) and `pub(crate) trait IdentityScheme` (decrypt-side). `encrypt` takes a `&[R]` recipient slice (1 element for passphrase, N for X25519) plus an `ArchiveLimits` value; rejects empty lists with `EmptyRecipientList` and multi-`Exclusive` lists with `IncompatibleRecipients` before any KDF runs. The timing-safe slot loop on decrypt covers both single-candidate (passphrase) and multi-candidate (X25519) cases. Recipient schemes return `RecipientBody`; protocol owns the header MAC verification (final acceptance gate per FORMAT.md §3.7). |
| `key/files.rs` | `KeyFileKind::classify` (cheap pub/priv heuristic), `PUBLIC_KEY_FILENAME`, `PRIVATE_KEY_FILENAME`. |
| `recipient/native/x25519.rs` | X25519 body layout, wrap/unwrap, HKDF info string, X25519 keypair generation (`generate_keypair`), `open_x25519_private_key` (binary key-file unlock with FORMAT.md §8 derivation check), `validate_private_key_shape` (re-exported via `fuzz_exports`). |
| `recipient/entry.rs` | `RecipientEntry` framing (`type_name_len(2) || recipient_flags(2) || body_len(4) || type_name || body`), `parse_recipient_entries`, `ENTRY_HEADER_SIZE`, `RECIPIENT_FLAG_CRITICAL`, `RECIPIENT_FLAGS_RESERVED_MASK`. |
| `recipient/name.rs` | `validate_type_name` (`FORMAT.md` §3.3 grammar), `TYPE_NAME_MAX_LEN`. |
| `recipient/policy.rs` | `NativeRecipientType` (Argon2id / X25519) registry, `MixingPolicy` (Exclusive / PublicKeyMixable), `enforce_recipient_mixing_policy`, `classify_encryption_mode`. |
| `recipient/native/argon2id.rs` | Argon2id body layout, wrap/unwrap, HKDF info string. Adding a new native recipient is a new submodule plus a `NativeRecipientType` variant. |
| `container.rs` | Single source of truth for `.fcr` header build/parse: `HeaderReadLimits`, `ParsedEncryptedHeader`, `BuiltEncryptedHeader`, `read_encrypted_header`, `build_encrypted_header`. Header MAC is computed/verified by `format::compute_header_mac` / `verify_header_mac`; this module includes the MAC tag in the on-disk byte stream and the parsed result, but the caller is responsible for verifying it after a successful recipient unwrap. |
| `key/private.rs` | v1 `private.key` byte layout (`PrivateKeyHeader`, `PRIVATE_KEY_HEADER_FIXED_SIZE = 90`), `seal_private_key`, `open_private_key`, `OpenedPrivateKey`. Cleartext fields are bound as AEAD AAD; AEAD cannot distinguish wrong-passphrase from tampered-cleartext, both surface as `KeyFileUnlockFailed`. |
| `key/public.rs` | v1 `public.key` Bech32 grammar (`encode_recipient_string`, `decode_recipient_string`, `DecodedRecipient`, `RECIPIENT_STRING_LEN_LOCAL_CAP_DEFAULT`), internal SHA3-256 typed-payload checksum domain-separated from the BIP 173 checksum, fingerprint helper (`fingerprint_hex` over `type_name \|\| key_material`). |
| `archive/limits.rs` | `ArchiveLimits` (DoS-bounding caps on entry count, total plaintext bytes, and path depth) plus the shared `enforce_per_entry_caps` / `enforce_total_bytes_cap` helpers — applied symmetrically on encrypt (writer-side preflight) and decrypt (extraction-time gate) so a tree the default-config decrypt would refuse cannot be encrypted in the first place. |
| `archive/path.rs` | `validate_archive_path` (path-traversal guard, re-exported via `fuzz_exports`), the POSIX `ustar` wire-format constants (`MAGIC`, `VERSION`, `TYPEFLAG_*`, `PATH_REPRESENTABLE_MAX`), and the `UstarEntryKind` classification shared by writer and reader. |
| `archive/encode.rs` | TAR archive construction (streaming, preserves directory structure). Owns `validate_encrypt_input`, the per-entry rule set (reject symlinks and non-regular/non-directory inputs); the encrypt entry points in `api.rs` call this up-front so Argon2id never fires for a symlink, and `archive` re-runs it as defense-in-depth. Hardlinks are archived as regular files. Owns `ArchiveCounters`, `ustar_archive_path_string`, `build_ustar_header`, the `*_mode` helpers, the `cfg(unix)` / `cfg(not(unix))` `open_no_follow` symlink guard, and the encrypt-side default mode constants. |
| `archive/decode.rs` | TAR extraction. Owns `unarchive`, both `extract_entries` arms (Linux/macOS hardened path + path-based fallback), `validate_ustar_entry`, `NormalizedEntry`, `ExtractCounters`, `drain_and_verify_zero_padding`, `extract_and_register_root`, `incomplete_working_name`, `incomplete_entry_path` (fallback only), and `restore_permissions_from_mode` (Unix non-Linux/non-macOS + non-Unix). Decryption writes under an `.incomplete` working name throughout and renames to the final name on success; failure leaves the `.incomplete` on disk for inspection. |
| `archive/platform.rs` | Linux/macOS-only directory-fd-anchored extraction primitives (`open_anchor`, `mkdirat_strict`, `ensure_dir`, `walk_to_parent`, `open_dir_at_rel`, `create_file_at`, `fchmod`) using `openat`/`mkdirat` with `O_NOFOLLOW` to defeat local symlink/component-race attacks. Owns `DIR_CREATE_MODE` and the `mode_from` rustix-mode coercion helper. Gated to Linux/macOS because rustix is only pulled in there; the other-platform extraction path keeps the existing path-based approach in `decode.rs`. |
| `format.rs` | v1 format constants and primitives: `MAGIC`, `VERSION`, `Kind` (`KIND_ENCRYPTED = 0x45 'E'`, `KIND_PRIVATE_KEY = 0x4B 'K'`), `PREFIX_SIZE = 12`, `HEADER_FIXED_SIZE = 31`, `HEADER_MAC_SIZE = 32`, structural caps (`HEADER_LEN_MAX`, `RECIPIENT_COUNT_MAX`, `BODY_LEN_MAX`, `EXT_LEN_MAX`) and matching `*_LOCAL_CAP_DEFAULT` resource caps, `Prefix` / `HeaderFixed` parse+build, `compute_header_mac` / `verify_header_mac`. |
| `crypto/keys.rs` | Typed key newtypes (`FileKey`, `PayloadKey`, `HeaderKey`) with `pub(crate)` constructors and narrow `expose()` accessors so the type system enforces "MAC uses HeaderKey, payload uses PayloadKey". File-key generation (`FileKey::generate`), payload/header subkey derivation (`derive_subkeys`, `DerivedSubkeys`), passphrase wrap-key derivation (`derive_passphrase_wrap_key`), `random_bytes` / `random_secret`, key-size constants (`ENCRYPTION_KEY_SIZE`, `FILE_KEY_SIZE`), and the pinned `HKDF_INFO_PAYLOAD` / `HKDF_INFO_HEADER` info strings. |
| `crypto/kdf.rs` | `KdfParams`, `KdfLimit`, Argon2id parameter validation (structural and policy caps), `ARGON2_SALT_SIZE`, `KDF_PARAMS_SIZE`. |
| `crypto/hkdf.rs` | HKDF-SHA3-256 expansion helper (`hkdf_expand_sha3_256`). |
| `crypto/mac.rs` | HMAC-SHA3-256 helpers (`hmac_sha3_256_parts`, `hmac_sha3_256_parts_verify`), constant-time 32-byte compare (`ct_eq_32`), `HMAC_KEY_SIZE`, `HMAC_TAG_SIZE`. |
| `crypto/aead.rs` | XChaCha20-Poly1305 single-shot seal/open helpers (`seal_file_key`, `open_file_key`), `WRAP_NONCE_SIZE`, `TAG_SIZE`, `WRAPPED_FILE_KEY_SIZE`. |
| `crypto/stream.rs` | `EncryptWriter`/`DecryptReader` streaming adapters (**64 KiB** chunks; FORMAT.md §5 deferred-last-chunk rule for writers, one-byte peek-ahead for readers), `payload_encryptor` / `payload_decryptor` factories, `BUFFER_SIZE`, `STREAM_NONCE_SIZE`. |
| `crypto/tlv.rs` | Canonical TLV validator (`validate_tlv`) for both `.fcr` `ext_bytes` and `private.key` `ext_bytes`; runs only on authenticated bytes. |
| `fs/atomic.rs` | Temporary-output-name staging, no-clobber finalization, `.incomplete` cleanup on decrypt failure, parent-dir `sync_all` on Unix. |
| `fs/paths.rs` | General path helpers: `encryption_base_name`, `file_stem`, `parent_or_cwd`, `INCOMPLETE_SUFFIX`, `map_user_path_io_error`. |
| `error.rs` | `CryptoError` enum, grouped by concern: filesystem/input (`Io`, `InputPath`, `InvalidInput`), format/version (`InvalidFormat(FormatDefect)`, `UnsupportedVersion`), KDF/resource caps (`KeyDerivation`, `InvalidKdfParams`, `KdfResourceCapExceeded`, `HeaderLenCapExceeded`, `RecipientCountCapExceeded`, `RecipientBodyCapExceeded`, `RecipientStringCapExceeded`), authentication (`KeyFileUnlockFailed`, `RecipientUnwrapFailed { type_name }`, `HeaderTampered`, `HeaderMacFailedAfterUnwrap { type_name }`, `UnknownCriticalRecipient { type_name }`, `NoSupportedRecipient`, `PassphraseRecipientMixed`, `PayloadTampered`, `PayloadTruncated`, `ExtraDataAfterPayload`), internal invariants (`InternalInvariant`, `InternalCryptoFailure`). `FormatDefect` is the structural-defect taxonomy (`BadMagic`, `Truncated`, `ExtTooLarge { len: u32 }`, `MalformedTlv`, `UnknownCriticalTag`, `NotAKeyFile`, `WrongKeyFileType`, `MalformedPublicKey`, `WrongKind { kind }`, `MalformedHeader`, `OversizedHeader { header_len }`, `RecipientCountOutOfRange`, `MalformedTypeName`, `MalformedRecipientEntry`, `RecipientFlagsReserved`, `MalformedPrivateKey`). Also defines the crate-private `StreamError` marker used to thread decrypt-path failures from `DecryptReader`/`EncryptWriter` through `io::Error` back into typed `CryptoError` variants via a manual `From<io::Error>` impl. |

### Encryption Pipeline (v1)

```
Input file/dir
  → generate random 32-byte file_key + 19-byte stream_nonce
  → derive payload_key + header_key from file_key (HKDF-SHA3-256)
  → for each recipient: wrap file_key into a recipient body
       argon2id: passphrase → Argon2id → HKDF → wrap_key → seal file_key
       x25519:   ECDH(ephemeral, recipient_pubkey) → HKDF → wrap_key → seal file_key
  → build header (prefix(12) || header_fixed(31) || recipient_entries(N) || ext_bytes)
  → HMAC-SHA3-256 over (prefix || header_fixed || recipient_entries || ext_bytes)
    with header_key → header_mac(32)
  → write prefix || header || header_mac to output .fcr file
  → tar::Builder<EncryptWriter<File>> streams TAR data through
    XChaCha20-Poly1305 STREAM-BE32 directly to disk, keyed by payload_key
```

No plaintext intermediate files touch disk. The TAR archive is never materialized — it streams directly through the encryption layer. The `EncryptWriter` defers committing a full chunk until either more plaintext arrives (then `encrypt_next`) or `finish()` is called (then `encrypt_last`), so a non-empty plaintext whose length is an exact multiple of 65,536 ends with a full-size FINAL chunk, not a stray empty trailer (`FORMAT.md` §5).

Decryption reverses (`FORMAT.md` §3.7 acceptance order):

1. read + structurally validate the header (`container::read_encrypted_header`); local caps enforced before any allocation.
2. `recipient::classify_encryption_mode` — reject unknown-critical entries, enforce `argon2id` exclusivity (before any KDF).
3. iterate supported recipient slots in declared order:
   - flags-zero / body-len shape check;
   - per-recipient `unwrap` (Argon2id for `argon2id`, ECDH for `x25519`);
   - on success, derive `payload_key + header_key` from the candidate `file_key`;
   - `format::verify_header_mac` is the FINAL acceptance gate (per-candidate failure → `HeaderMacFailedAfterUnwrap { type_name }`, loop continues).
4. validate TLV `ext_bytes` (`common::validate_tlv`) AFTER MAC verify, so the validator operates on authenticated bytes.
5. `DecryptReader` streams ciphertext through XChaCha20-Poly1305 STREAM-BE32, peek-ahead resolves "exact-N final chunk" vs "exact-N then more data"; `tar::Archive` unpacks the result.

A single-recipient MAC failure surfaces as `HeaderTampered` (the loop has no further candidates); list-exhaustion without success surfaces as `NoSupportedRecipient`.

### Desktop App Structure

- `ui/app.slint` — UI layout and state in Slint DSL. Defines `AppWindow` with 2 top-level tabs (Symmetric, Hybrid) and 5 internal modes (SE=0, SD=1, HE=2, HD=3, GK=4). Key generation (GK=4) is inline within the Hybrid tab via a sub-selector.
- `src/main.rs` — Rust backend: file dialog callbacks, mode auto-detection via magic bytes, threaded crypto operations with progress updates via `slint::invoke_from_event_loop`.
- `src/password_scorer.rs` — Password strength scoring (0–4 scale) adapted from Proton Pass.
- File and folder pickers go through `rfd::FileDialog` on every platform. On macOS the desktop crate calls `pick_file_or_folder()` (rfd's combined picker, which internally wraps `NSOpenPanel`); on other platforms it falls back to `pick_file()` / `pick_folder()` because rfd does not expose a combined picker outside macOS.

### File Format (v1 — every artefact)

See `ferrocrypt-lib/FORMAT.md` for the full byte-level spec. Summary:

**`.fcr` 12-byte plain prefix at offset 0:**
`magic(4) "FCR\0" || version(1)=0x01 || kind(1)=0x45 'E' || prefix_flags(2) || header_len(4)`

- `kind = 0x45 'E'` for any encrypted file. The symmetric-vs-hybrid distinction is **not** in the prefix; it's derived from the recipient list (one `argon2id` entry → Symmetric; one or more supported `x25519` entries → Hybrid).
- `prefix_flags` MUST be zero in v1; non-zero rejects as `MalformedHeader`.
- `header_len <= HEADER_LEN_MAX` (16 MiB structural). Local resource cap (`HEADER_LEN_LOCAL_CAP_DEFAULT`, 1 MiB) rejects oversized declarations as `HeaderLenCapExceeded` before allocation.

**Header layout (right after the prefix):**

```
header_fixed(31) || recipient_entries(recipient_entries_len bytes)
                || ext_bytes(ext_len bytes) || header_mac(32)
```

`header_fixed = header_flags(2) || recipient_count(2) || recipient_entries_len(4) || ext_len(4) || stream_nonce(19)`. HMAC-SHA3-256 with `header_key` authenticates `prefix(12) || header_fixed || recipient_entries || ext_bytes` (32-byte tag = `header_mac`). Forward compatibility: ignorable TLV tags in `ext_bytes` are authenticated + skipped; critical tags (`0x8001..=0xFFFF`) are rejected as `UnknownCriticalTag`. See `FORMAT.md` §6.

**Recipient entry framing** (`FORMAT.md` §3.5):

```
recipient_entry = type_name_len(2) || recipient_flags(2) || body_len(4)
                  || type_name (UTF-8, validated against §3.3 grammar)
                  || body (opaque to framing; per-recipient module parses it)
```

`recipient_flags` defines bit 0 as `critical`; all other bits MUST be zero in v1.

**Native recipient bodies** (v1 ships two native types):

- `argon2id` (116 B): `argon2_salt(32) || kdf_params(12) || wrap_nonce(24) || wrapped_file_key(48)`. `MixingPolicy::Exclusive` — must appear alone.
- `x25519` (104 B): `ephemeral_pubkey(32) || wrap_nonce(24) || wrapped_file_key(48)`. `MixingPolicy::PublicKeyMixable` — multiple `x25519` slots allowed in one file (decrypt iterates).

**File-key indirection:** every recipient body seals the same per-file random 32-byte `file_key`. After unwrap, `payload_key` and `header_key` are derived from `file_key` via HKDF-SHA3-256 (`info = "ferrocrypt/v1/payload"` with salt = `stream_nonce`; `info = "ferrocrypt/v1/header"` with empty salt). Identical post-unwrap shape across recipient types; future native types (post-quantum, hybrid KEMs) plug in as new `RecipientEntry` `type_name`s without touching the header-MAC scope or the payload pipeline.

**Payload (`FORMAT.md` §5):** XChaCha20-Poly1305 STREAM-BE32 over 64 KiB plaintext chunks. Writers MUST NOT emit an empty trailing chunk after non-empty plaintext that ends on a 65,536-byte boundary; the final non-empty chunk uses `last_flag = 1`. Empty plaintext is encoded as a single tag-only `last` chunk.

### Key File Format (v1)

**`public.key`** is a **UTF-8 text file** containing exactly one line: the canonical lowercase `fcr1…` Bech32 recipient string, optionally followed by a single trailing LF (any other surrounding whitespace rejects as `MalformedPublicKey`). The Bech32 payload carries a typed body `type_name_len(2) || key_material_len(4) || type_name || key_material` plus an internal SHA3-256 checksum (in addition to the BIP 173 checksum), domain-separated so cross-algorithm collisions are impossible. For X25519 the file is ~107 bytes on disk. Identity verification is out-of-band via the SHA3-256 fingerprint of `type_name || key_material`.

**`private.key`** v1 (176 bytes for X25519 with `ext_len = 0`):
- Cleartext fixed header (90 B): `magic(4) || version(1) || kind(1)=0x4B 'K' || key_flags(2) || type_name_len(2) || public_len(4) || ext_len(4) || wrapped_secret_len(4) || argon2_salt(32) || kdf_params(12) || wrap_nonce(24)`
- Variable fields (right after the fixed header): `type_name(type_name_len) || public_material(public_len) || ext_bytes(ext_len)`
- Wrapped secret (`wrapped_secret_len` bytes): `secret_material(secret_len) || Poly1305_tag(16)`
- Every cleartext byte before `wrapped_secret` is bound as AEAD **associated data**, so tampering any cleartext field fails authentication. AEAD cannot distinguish "wrong passphrase" from "tampered cleartext" — both surface as `CryptoError::KeyFileUnlockFailed` with wording `"Private key unlock failed: wrong passphrase or tampered file"`.
- Wrap-key derivation: `HKDF-SHA3-256(salt=argon2_salt, ikm=Argon2id(passphrase, argon2_salt, kdf_params), info="ferrocrypt/v1/private-key/wrap", L=32)`.
- `kind = 0x4B` ('K') is deliberately distinct from the encrypted-file `kind = 0x45` ('E') so `file(1)`-style matchers and the in-tree `KeyFileKind::classify` heuristic can disambiguate `private.key` from `.fcr` on a single byte.
- The `type_name` field is the recipient discriminator (no separate algorithm byte). v1 ships `"x25519"`; future native key kinds (post-quantum, hybrid KEMs) extend the `type_name` set without touching the header layout.
- Forward compatibility: TLV tags in `ext_bytes` are authenticated via AEAD-AAD. Validated after successful AEAD unwrap.

## Key Conventions

- Operation API: the public surface is `Encryptor` / `Decryptor` value types in `api.rs`, plus the free function `generate_key_pair(output_dir, passphrase, on_event)`. Encrypt is built via `Encryptor::with_passphrase(SecretString)` / `with_recipient(PublicKey)` / `with_recipients(IntoIterator<Item = PublicKey>)`, optionally chained with `.save_as(path)` / `.archive_limits(limits)`, and finalized with `.write(input, output_dir, on_event)`. Decrypt opens via `Decryptor::open(input)` which classifies the file's recipient list (no crypto, no KDF) and returns the matching `Decryptor::Passphrase(PassphraseDecryptor)` or `Decryptor::Recipient(RecipientDecryptor)`; each variant takes `.kdf_limit(KdfLimit)` and `.decrypt(credentials, output_dir, on_event)`. Multi-recipient encrypt is part of the public API: `Encryptor::with_recipients([alice, bob])` produces a single `.fcr` either recipient can decrypt. `EncryptionMode` (`Passphrase` / `Recipient`) is the cheap mode-probe enum returned by `detect_encryption_mode` for callers that want to pre-classify a file without going through `Decryptor::open`. All public types are `#[non_exhaustive]`.
- Key-source abstractions: `Encryptor::with_recipient(s)` consumes `PublicKey`; `RecipientDecryptor::decrypt` consumes `PrivateKey`. `PublicKey` has constructors `from_key_file(path)`, `from_bytes([u8; 32])`, `from_recipient_string("fcr1…")` (plus `FromStr`), and methods `fingerprint()`, `to_recipient_string()`, `to_bytes()`, `validate()`. `PrivateKey` has `from_key_file(path)` today. Both wrappers are `#[non_exhaustive]` structs over a private inner enum so new sources (in-memory secret material, hardware-backed keys) can be added as constructors without breaking the API. `pub type RecipientKey = PublicKey;` and `pub type IdentityKey = PrivateKey;` are alternative names re-exported from `lib.rs` for callers who prefer the FORMAT.md vocabulary; the canonical names follow the universal Rust crypto idiom.
- Progress signalling: `ProgressEvent` is a `#[non_exhaustive]` enum with 4 current variants (`DerivingKey`, `Encrypting`, `Decrypting`, `GeneratingKeyPair`). It implements `Display` with wording that is locked in by a unit test; CLI and desktop render `{event}` directly. New progress phases are added as new variants — match arms in caller code need a `_` wildcard.
- **In-repo direction routing:** ferrocrypt-cli and ferrocrypt-desktop call `detect_encryption_mode` (CLI) or read `mode` from UI state (desktop) first, then build the appropriate explicit config. The library no longer exposes auto-routing convenience wrappers — direction detection is a caller concern.
- Bech32 `fcr1…` recipient strings are the human-readable public-key exchange format. The typed entry point is `PublicKey::from_recipient_string(&str)` or `"fcr1…".parse::<PublicKey>()` (see the key-source abstractions bullet above); `decode_recipient(&str) -> [u8; 32]` is kept as the low-level primitive for the `fuzz_recipient_decode` fuzz target and callers that specifically want raw bytes.
- CLI `hybrid --recipient / -r` accepts a `fcr1...` string directly for encryption. `recipient` (alias `rc`) subcommand prints the string from a key file.
- CLI never accepts passphrases as command-line arguments. Passphrases are prompted interactively via `rpassword` (hidden TTY input) with confirmation on encrypt/keygen. For non-interactive use (tests, scripts), set the `FERROCRYPT_PASSPHRASE` environment variable.
- Integration tests use `tests/workspace/` (and `tests/workspace_fixture_stability/`, `tests/workspace_api/`) as temp directories, cleaned up by `#[ctor::dtor]` hooks. CLI integration tests use `FERROCRYPT_PASSPHRASE` env var to supply passphrases non-interactively. The `tests/common/mod.rs` shim exposes `symmetric_auto` / `hybrid_auto` / `generate_key_pair` over the new `Encryptor` / `Decryptor` API so existing test call sites don't churn. New-API-specific coverage lives in `tests/api_tests.rs` (round trips, multi-recipient, `EmptyRecipientList`, `Decryptor::open` directory / non-FCR / missing-input rejections). Low-level format mechanics (prefix parsing, `header_fixed` parsing, recipient-entry framing, recipient unwrap, version / kind rejection, TLV grammar, public-key Bech32 + internal SHA3-256 checksum, `private.key` shape) are exercised by in-module unit tests (`src/format.rs::tests`, `src/container.rs::tests`, `src/recipient/entry.rs::tests`, `src/recipient/name.rs::tests`, `src/recipient/policy.rs::tests`, `src/recipient/native/argon2id.rs::tests`, `src/recipient/native/x25519.rs::tests`, `src/key/private.rs::tests`, `src/key/public.rs::tests`, `src/crypto/keys.rs::tests`, `src/crypto/kdf.rs::tests`, `src/crypto/hkdf.rs::tests`, `src/crypto/mac.rs::tests`, `src/crypto/stream.rs::tests`, `src/crypto/tlv.rs::tests`, `src/fs/paths.rs::tests`, `src/protocol.rs::tests`). The forward-compat multi-recipient cases (FORMAT.md §3.4 / §3.5) live in `src/protocol.rs::tests::multi_*`, which build hand-crafted multi-entry `.fcr` bytes via `container::build_encrypted_header`. Round-trip and basic tampering coverage lives in `tests/integration_tests.rs` and `tests/fixture_stability.rs`.
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
- Keep explanations concise and written for humans: plain language, short, clear, no needless jargon. Use analogies when they help, skip ceremony, do not pad with restated context.
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
- Never manually bump `version` in any `Cargo.toml`. Versioning is automated; see `RELEASE.md`.
