<div align="center"><img src="ferrocrypt-desktop/assets/app_icon.png" style="width: 85px;" alt="FerroCrypt"></div>

<h1 align="center"><code>FerroCrypt</code></h1>

![](https://github.com/alexylon/ferrocrypt/actions/workflows/rust.yml/badge.svg)
&nbsp;
[![crate: ferrocrypt](https://img.shields.io/crates/v/ferrocrypt.svg?label=crate%3A%20ferrocrypt&color=blue)](https://crates.io/crates/ferrocrypt)
&nbsp;
[![docs.rs](https://img.shields.io/docsrs/ferrocrypt/latest?color=2e7d32)](https://docs.rs/ferrocrypt/latest)
&nbsp;
![MSRV](https://img.shields.io/badge/MSRV-1.87-blue)
&nbsp;
[![crate: ferrocrypt-cli](https://img.shields.io/crates/v/ferrocrypt-cli.svg?label=crate%3A%20ferrocrypt-cli&color=blue)](https://crates.io/crates/ferrocrypt-cli)

Recipient-oriented file encryption for files and directories, with a Rust library,
command-line tool, and desktop app.

<div align="center">
  <img src="/assets/screenshot-1.png" width="400" alt="FerroCrypt">&nbsp;&nbsp;
</div>

<div align="center">
  <img src="/assets/screenshot-2.png" width="400" alt="FerroCrypt">&nbsp;&nbsp;
</div>

<div align="center">
  <img src="/assets/screenshot-3.png" width="400" alt="FerroCrypt">
</div>

## About

FerroCrypt encrypts files and directories into `.fcr` files. It supports two
user-facing encryption paths:

- **Symmetric** — password-based encryption. The file contains exactly one
  native `argon2id` recipient. The passphrase is processed with Argon2id and
  HKDF-SHA3-256 to unwrap the per-file key during decryption.
- **Hybrid** — public/private-key encryption. The file contains one or more
  native `x25519` recipients. Each recipient entry wraps the same per-file key
  for a recipient public key. Decryption requires a matching `private.key` file
  and that key file's passphrase.

Both paths use the same v1 `.fcr` container: one random 32-byte `file_key`, one
STREAM-BE32 encrypted payload, and one or more typed recipient entries that
independently wrap the same `file_key`. Mode is derived from the authenticated
recipient list, not from the filename or a per-mode magic byte.

The current implementation ships two native recipient types:

- `argon2id` — passphrase recipient, exclusive; it must appear alone.
- `x25519` — public-key recipient, public-key-mixable; multiple X25519
  recipients may share a file.

The v1 format reserves space for future recipient types and authenticated TLV
extensions, but the stable public library API does not currently expose a
third-party crypto plugin interface.

### Crates and applications

| Crate | Purpose |
|---|---|
| [`ferrocrypt-lib`](https://crates.io/crates/ferrocrypt) (crate `ferrocrypt`) | Core Rust library: file format handling, encryption/decryption orchestration, key files, archive handling, typed errors, and the `Encryptor` / `Decryptor` API. |
| [`ferrocrypt-cli`](https://crates.io/crates/ferrocrypt-cli) | Command-line interface that installs the `ferrocrypt` binary. It exposes `symmetric`, `hybrid`, `keygen`, `fingerprint`, and `recipient` subcommands. |
| `ferrocrypt-desktop` | Slint-based desktop app using the library. It provides symmetric and hybrid workflows, key generation, key-file validation, conflict warnings, and fingerprint display. |

Canonical reference documents live in `ferrocrypt-lib/`:

- [**`FORMAT.md`**](ferrocrypt-lib/FORMAT.md) — byte-level v1 wire format:
  `.fcr`, `private.key`, `public.key`, recipient entries, payload stream, TLV
  extensions, and archive subset.
- [**`STRUCTURE.md`**](ferrocrypt-lib/STRUCTURE.md) — library architecture:
  module ownership, single sources of truth, public API shape, dependency
  direction, and decryption ordering.

### Main features

- **Pure Rust cryptographic stack:** XChaCha20-Poly1305, Argon2id,
  HKDF-SHA3-256, HMAC-SHA3-256, SHA3-256, and X25519.
- **Unified `.fcr` format:** one encrypted-file container for passphrase and
  public-key recipients.
- **HMAC-SHA3-256 header authentication:** the prefix, fixed header fields,
  recipient list, and extension region are authenticated by a 32-byte tag. A
  recipient unwrap is not accepted until the candidate file key verifies the
  header MAC, so tampering is detected before any payload byte is decrypted.
- **Streaming encryption:** plaintext is streamed directly through
  XChaCha20-Poly1305 STREAM-BE32 in 64 KiB chunks. The TAR archive of a
  directory payload is never materialized as a plaintext temp file.
- **Typed library API:** `Encryptor` and `Decryptor` route callers to passphrase
  or recipient decryption based on the file's recipient list.
- **Multi-recipient public-key encryption:**
  `Encryptor::with_recipients([alice, bob])` writes one `.fcr` file that either
  listed recipient can decrypt with their own private key.
- **Bech32 public recipient strings:** public keys can be shared as lowercase
  `fcr1…` strings with both the BIP 173 checksum and an internal SHA3-256
  checksum over the typed payload.
- **SHA3-256 fingerprints:** public-recipient fingerprints are 64 lowercase hex
  characters over `type_name || 0x00 || key_material`.
- **Safe archive subset:** directory payloads use a restricted POSIX ustar subset
  and reject symlinks, hardlink entries, device files, FIFOs, sockets, unsafe
  paths, duplicate output paths, and archives with more than one top-level root.
- **Hardened extraction on Linux and macOS:** every write inside the
  `.incomplete` working tree is anchored to a directory file descriptor and
  resolves intermediate components with `openat`/`mkdirat` and `O_NOFOLLOW`,
  so a local attacker who swaps a path component for a symlink cannot redirect
  plaintext writes outside the destination tree. Other platforms use a
  path-based extraction path that is less strict against in-tree races.
- **Atomic output:** encrypted files and generated key files are staged and
  promoted only after success. Failed decryptions leave an `.incomplete` working
  directory rather than a final output path.
- **Typed errors:** structural format failures, KDF resource-cap failures,
  private-key unlock failures, recipient unwrap failures, header MAC failures,
  payload authentication failures, truncation, and trailing data have distinct
  public error variants.

Decryption is based on the `FCR\0` magic bytes and v1 header structure, not on
the file extension. Renaming a file does not change how FerroCrypt interprets
it.

### What's new in 0.3.0

FerroCrypt 0.3.0 is a ground-up rewrite of the library, CLI, desktop app, and
on-disk format. The main changes are:

- **Unified format v1:** one `.fcr` container for passphrase and public-key
  encryption, with mode derived from the recipient list.
- **Pure Rust hybrid encryption:** X25519 + HKDF-SHA3-256 replaces the previous
  RSA/OpenSSL-based hybrid path. Older hybrid files and key pairs must be
  decrypted with an older release and regenerated.
- **New library API:** `Encryptor` / `Decryptor` replace the legacy per-mode
  config structs and free functions.
- **Multi-recipient public-key encryption:** one `.fcr` file can be encrypted to
  multiple X25519 recipients.
- **Bech32 recipient strings and fingerprints:** public keys can be shared as
  lowercase `fcr1…` strings and verified with SHA3-256 fingerprints.
- **New key formats:** `public.key` is canonical Bech32 text; `private.key` is a
  passphrase-wrapped v1 binary key file.
- **Resource caps and safer archives:** KDF memory limits and archive caps are
  enforced before expensive work, and directory payloads use a strict safe ustar
  subset.
- **Atomic output and clearer errors:** output files are staged before finalizing,
  and decryption failures surface as typed, user-readable errors.
- **Slint desktop app:** the desktop UI was rewritten with mode detection,
  key-file validation, conflict warnings, fingerprint display, and inline key
  generation.

### Security and limitations

- Sender authentication is not part of the v1 format. Hybrid encryption controls
  which private keys can decrypt; it does not prove who encrypted the file.
- Directory encryption is a safe-file-transfer convenience, not a full backup
  format. FerroCrypt preserves file contents and directory structure. It does
  not guarantee preservation of ownership, timestamps, ACLs, extended
  attributes, symlink relationships, hardlink identity, or platform-specific
  metadata.
- Symlinks and special filesystem entries are rejected during encryption.
  Filesystem hardlinks may be archived as independent regular files.
- Archive resource caps are enforced on both encrypt and decrypt: by default,
  at most 250,000 entries, 64 GiB total regular-file content, and 64 path
  components per entry.
- Encrypted files and generated key files are staged under temporary names and
  promoted only after success. Failed decryptions may leave a sibling
  `.incomplete` working directory.
- The current v1 format is not backward-compatible with pre-v1 FerroCrypt files
  or key pairs. Decrypt older data with the release that created it, then
  re-encrypt with the current release.
- This project has not undergone an independent third-party security audit.

### What's stored in an encrypted file

Every `.fcr` file starts with a plain 12-byte prefix, followed by an
authenticated header, a 32-byte header MAC, and the encrypted payload. The
header contains the metadata needed to attempt decryption: fixed header fields,
the typed recipient list, the stream nonce, and optional authenticated extension
bytes. Payload filenames and file contents are inside the encrypted archive
payload, not in the header.

| File | Contents |
|---|---|
| **Symmetric `.fcr`** | 12-byte prefix (`FCR\0` magic, version, kind `'E'`, prefix flags, header length), `header_fixed`, one `argon2id` recipient entry, extension region, header HMAC tag, encrypted payload |
| **Hybrid `.fcr`** | 12-byte prefix (`FCR\0` magic, version, kind `'E'`, prefix flags, header length), `header_fixed`, one or more `x25519` recipient entries, extension region, header HMAC tag, encrypted payload |
| **`private.key`** | Binary v1 key file: cleartext fixed header and variable cleartext fields authenticated as AEAD associated data, followed by a passphrase-wrapped X25519 secret |
| **`public.key`** | UTF-8 text file containing the canonical lowercase Bech32 `fcr1…` recipient string, written with one trailing newline; readers also accept the same string without the final newline |

## Installation

Pre-built packages are available on the [GitHub Releases](https://github.com/alexylon/ferrocrypt/releases) page: CLI binaries for macOS, Linux, and Windows, plus desktop app packages (`.app` for macOS, `.deb` for Debian/Ubuntu, `.rpm` for Fedora/RHEL, `.msi` for Windows).

### CLI

From crates.io:

```bash
cargo install ferrocrypt-cli
```

Or build from source:

```bash
cargo build --release
```

Binary output: `target/release/ferrocrypt` (macOS/Linux) or `target\release\ferrocrypt.exe` (Windows).

### Desktop App

Build from source — requires [Rust](https://www.rust-lang.org/tools/install) and [cargo-bundle](https://github.com/nickelc/cargo-bundle):

```bash
cd ferrocrypt-desktop
cargo bundle --release # produces .app (macOS) / .deb + .AppImage (Linux) / .msi (Windows)
```

**Linux only** — install system dependencies first:

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install libfontconfig-dev libfreetype-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libwayland-dev libssl-dev

# Fedora
sudo dnf install fontconfig-devel freetype-devel libxcb-devel libxkbcommon-devel wayland-devel openssl-devel
```

The AppImage output additionally needs `mksquashfs`. Skip this if you only want the `.deb`:

```bash
# Debian/Ubuntu
sudo apt install squashfs-tools

# Fedora
sudo dnf install squashfs-tools
```

### Library

```bash
cargo add ferrocrypt
```

## Rust version support

The `ferrocrypt` library crate currently targets **MSRV 1.87**.

This minimum supported Rust version is checked in CI for `ferrocrypt-lib`.
It may be increased in future releases if required by dependencies or language improvements.

## CLI Usage

### Subcommands

| Subcommand | Alias | Purpose |
|---|---|---|
| `symmetric` | `sym` | Encrypt/decrypt with a password |
| `hybrid` | `hyb` | Encrypt/decrypt with public/private keys |
| `keygen` | `gen` | Generate a key pair |
| `fingerprint` | `fp` | Print a public key's SHA3-256 fingerprint |
| `recipient` | `rc` | Print a public key as a Bech32 `fcr1…` string |

Run without arguments to start an interactive REPL. Aliases are available in interactive mode.

Passphrases are never passed on the command line. The CLI prompts interactively with hidden input when a passphrase is needed (with confirmation on encrypt/keygen). For non-interactive use (scripts, CI), set the `FERROCRYPT_PASSPHRASE` environment variable.

### Symmetric

```bash
# Encrypt (prompts for passphrase with confirmation)
ferrocrypt symmetric -i secret.txt -o ./encrypted

# Decrypt (prompts for passphrase)
ferrocrypt symmetric -i ./encrypted/secret.fcr -o ./decrypted

# Encrypt with custom output path (--output-path not needed)
ferrocrypt symmetric -i secret.txt -s ./backup.fcr
```

### Hybrid

```bash
# Generate keys (prompts for passphrase with confirmation)
ferrocrypt keygen -o ./keys

# Print recipient string (for sharing)
ferrocrypt recipient ./keys/public.key

# Verify a public key's fingerprint
ferrocrypt fingerprint ./keys/public.key

# Encrypt with recipient string (no passphrase needed)
ferrocrypt hybrid -i secret.txt -o ./encrypted -r fcr1...

# Encrypt with custom output path (--output-path not needed)
ferrocrypt hybrid -i secret.txt -s ./secret.fcr -r fcr1...

# Encrypt with public key file (no passphrase needed)
ferrocrypt hybrid -i secret.txt -o ./encrypted -k ./keys/public.key

# Decrypt with private key (prompts for passphrase)
ferrocrypt hybrid -i ./encrypted/secret.fcr -o ./decrypted -k ./keys/private.key
```

### Interactive Mode

```text
$ ferrocrypt
FerroCrypt interactive mode
Commands: symmetric (sym), hybrid (hyb), keygen (gen), fingerprint (fp), recipient (rc), quit

ferrocrypt> sym -i secret.txt -o out
Passphrase:
Confirm passphrase:
ferrocrypt> quit
```

The REPL exits on `quit`, `exit` (case-insensitive), or Ctrl-D (EOF). Ctrl-C cancels the current line without exiting.

### Flag Reference

#### `symmetric`

| Flag | Description |
|---|---|
| `-i, --input-path` | Input file or directory |
| `-o, --output-path` | Output directory (optional with `--save-as`) |
| `-s, --save-as` | Custom output file path (encrypt only) |
| `--max-kdf-memory` | Maximum KDF memory cost to accept in MiB (decrypt only) |

#### `hybrid`

| Flag | Description |
|---|---|
| `-i, --input-path` | Input file or directory |
| `-o, --output-path` | Output directory (optional with `--save-as`) |
| `-k, --key` | Key file path: public key for encrypt, private key for decrypt |
| `-r, --recipient` | Bech32 recipient string for encryption (`fcr1...`) |
| `-s, --save-as` | Custom output file path (encrypt only) |
| `--max-kdf-memory` | Maximum KDF memory cost to accept in MiB (decrypt only) |

#### `keygen`

| Flag | Description |
|---|---|
| `-o, --output-path` | Output directory for the key pair |

#### `fingerprint`

| Argument | Description |
|---|---|
| `<key_file>` | Path to a public key file |

#### `recipient`

| Argument | Description |
|---|---|
| `<key_file>` | Path to a public key file |

## Desktop App Usage

Select a file or folder, then choose the encryption mode. The app auto-detects encrypted files by reading the file header, regardless of extension.

- **Symmetric** — Enter a password. The output path is auto-filled as `{name}.fcr` and can be changed with Save As. Decryption uses a directory picker.
- **Hybrid** — Use an existing public key to encrypt, or create a new key pair inline. After key generation, the app switches to encryption with the new public key pre-filled. The recipient's public key fingerprint is shown with a copy button for out-of-band verification. Key files are validated on selection and invalid files show an error before the operation starts. Decryption requires a private key and its passphrase.

A password strength indicator (based on [Proton Pass](https://github.com/protonpass/proton-pass-common) implementation) is shown during encryption and key generation.

## Decryption errors

FerroCrypt distinguishes several distinct decryption-failure stages so that a failed decrypt tells you what actually went wrong:

- **Private key unlock failed: wrong passphrase or tampered file** — The hybrid private key file failed AEAD authentication. Either the passphrase does not decrypt it, or one of the file's cleartext fields (header, KDF params, salt, nonce, public material, or extension region) has been tampered with since the file was written. The AEAD primitive cannot distinguish the two cases. Retry with the correct passphrase first; if that still fails, regenerate the key pair and re-encrypt.
- **Decryption failed: recipient `argon2id` unwrap failed** (symmetric) — The passphrase does not unwrap the file key, or the recipient body has been modified. No plaintext has been produced.
- **Decryption failed: recipient `x25519` unwrap failed** (hybrid) — The supplied private key does not match the key pair the file was encrypted for, or the recipient body has been modified. No plaintext has been produced.
- **Decryption failed: no recipient could unlock the file** — The recipient list was iterated to exhaustion without any supported entry yielding a `file_key` that verified the header MAC. In single-recipient files this overlaps with the per-recipient unwrap failure above; in multi-recipient files it is the final error after every supported slot has been tried.
- **Decryption failed: header tampered after unlock** — A recipient entry produced a candidate file key, but that key did not verify the header HMAC. This does not prove which input was wrong or modified; the credential, recipient body, or bytes inside the MAC scope may be the cause.
- **Payload authentication failed: data tampered or corrupted** — The header authenticated successfully, but a later ciphertext chunk failed its authentication tag. This usually means the file has been corrupted or truncated partway through, an attacker has modified bytes after the header, or extra bytes were appended after the authenticated payload. During streaming decryption, earlier chunks that authenticated successfully may already have been written to disk under an `.incomplete` working directory before the failing chunk was reached.
- **Encrypted file is truncated** — The encrypted stream ends before its final authenticated chunk, usually because of a partial download or an interrupted copy.
- **Encrypted file has unexpected trailing data** — Bytes remain after the final authenticated chunk was decrypted successfully. Ordinary appended-bytes cases on a local file are already caught as a payload authentication failure (above), because the per-chunk AEAD's final-flag binding rejects a naive append. This dedicated variant is the defense-in-depth path for pathological input readers — non-blocking sockets, `Take`-style wrappers, or similar — that signal end-of-file at the chunk boundary and then yield additional bytes; FerroCrypt refuses to return success on such a stream.
- **KDF resource cap exceeded** — The encrypted file's stored Argon2id memory cost exceeds the `--max-kdf-memory` cap (or the built-in 1 GiB ceiling, when the flag isn't set). The error reports both the file's required `mem_cost` and the configured cap. Re-run with a higher cap if you trust the source of the file.

None of these failures produce a file at the final output path. Partial plaintext may have been written under a sibling `.incomplete` working directory (FerroCrypt leaves it there on purpose, because when ciphertext is damaged it may hold the only recoverable data). A retry starts fresh once that `.incomplete` directory is removed.

## Acknowledgments

The desktop app is built with [Slint](https://slint.dev/).

Password strength scoring is adapted from [Proton Pass](https://github.com/protonpass/proton-pass-common) (GPLv3).

[![forthebadge](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com)
