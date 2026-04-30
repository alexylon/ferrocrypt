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

Cross-platform file encryption tool with CLI and desktop interfaces. Written in Rust.

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

FerroCrypt 0.3.0 is a ground-up rewrite of the library, CLI, and desktop app. The internal organization, the public API, and the on-disk file format have all been redesigned together so each layer reflects the same recipient-oriented model: each `.fcr` file holds one random `file_key`, one streamed authenticated payload, and one or more typed recipient entries that independently wrap the same `file_key`. Passphrase encryption and X25519 public-key encryption are recipient schemes over a single protocol pipeline rather than separate code paths, so future native or plugin recipient types — post-quantum KEMs, hybrid KEMs, hardware tokens — plug in without changing the container layout or the payload pipeline.

What 0.3.0 brings:

- **Pure-Rust hybrid stack.** X25519 ECDH + HKDF-SHA3-256 + XChaCha20-Poly1305 replaces the previous RSA-4096 / OpenSSL pipeline. No C dependency.
- **Unified `.fcr` container.** One file extension across both modes; mode is derived from the recipient list, not the file name or a per-mode magic byte. SHA-3 is used uniformly across header MAC, every key derivation, fingerprints, and the internal Bech32 checksum.
- **Typed public API.** `Encryptor` and `Decryptor` value types in `ferrocrypt-lib` replace the previous per-mode config structs. Wrong-credential mismatches (passphrase used against a public-key file, or vice versa) fail at compile time instead of surfacing as runtime "no supported recipient" errors. Multi-recipient encryption (`Encryptor::with_recipients([alice, bob])`) produces a single file decryptable by any listed recipient.
- **Bech32 recipient strings and SHA3-256 fingerprints.** Public keys are exchanged as `fcr1…` Bech32 strings carrying both the BIP 173 outer checksum and an internal SHA3-256 typed-payload checksum, so transcription errors are caught before any cryptographic step runs. Public-key fingerprints are 64-char lowercase hex of `SHA3-256(type_name || 0x00 || key_material)`, domain-separated so future native types cannot collide with X25519.
- **Hardened extraction and atomic output.** Linux/macOS extraction anchors every filesystem write to a directory file descriptor and resolves intermediate components via `openat`/`mkdirat` with `O_NOFOLLOW`, so a local attacker who swaps a path component for a symlink cannot redirect plaintext writes outside the destination tree. Encrypted files and key files are staged under temporary names and only promoted to the final name on success. Archive resource caps gate writer and reader symmetrically — a tree the default decrypt would refuse cannot be encrypted in the first place.
- **Typed, user-readable errors.** Decryption failures are named and distinct (wrong passphrase or tampered file, header MAC mismatch, payload truncation, trailing data, KDF cap exceeded, …) rather than wrapped internal AEAD strings. Library consumers can pattern-match on typed `FormatDefect`, `UnsupportedVersion`, and `InvalidKdfParams` shapes without substring comparisons.
- **Canonical specifications.** Two reference documents ship with the library: `ferrocrypt-lib/FORMAT.md` (byte-level wire format) and `ferrocrypt-lib/STRUCTURE.md` (code architecture, single sources of truth, dependency direction, public API shape, decryption security ordering).
- **Slint-based desktop app.** Rewritten from scratch using [Slint](https://slint.dev/), with magic-byte mode auto-detection, conflict warnings, key-file validation on selection, recipient-fingerprint display with a copy button, and a password strength indicator.

FerroCrypt encrypts and decrypts files and directories in two modes:

- **Symmetric** — Password-based. Uses XChaCha20-Poly1305 with Argon2id passphrase derivation and HKDF-SHA3-256 subkey expansion. Each file gets a unique random file key, wrapped by the passphrase-derived key; the same password encrypts and decrypts.
- **Hybrid** — Public/private-key based. Combines X25519 key agreement with XChaCha20-Poly1305 data encryption. Each file gets a unique random file key sealed for the recipient's public key. Decryption requires the matching private key and its passphrase. Hybrid mode provides confidentiality and integrity for the recipient, but it does not authenticate the sender; it is not a substitute for digital signatures.

Both modes produce `.fcr` files. Decryption is based on the 4-byte `FCR\0` magic in the file header, not the file extension — renaming a file does not change how FerroCrypt interprets it.

For the byte-level on-disk format, see `ferrocrypt-lib/FORMAT.md` in the repository.

### What's stored in an encrypted file

Every `.fcr` file starts with a header followed by the encrypted payload. The header contains only the metadata needed to begin decryption — no filenames, timestamps, or plaintext content is exposed. A plain 12-byte prefix at file offset 0 (magic, version, kind, prefix flags, header length) carries enough information to identify the file and locate the rest of the header; the entire header — prefix, fixed fields, recipient list, and extension region — is authenticated by HMAC-SHA3-256 before any payload byte is decrypted.

| File | Contents |
|---|---|
| **Symmetric `.fcr`** | 12-byte prefix (`FCR\0` magic, version, kind `'E'`, prefix flags, header length), header_fixed (header flags, recipient count, recipient-entries length, extension length, stream nonce), one `argon2id` recipient entry (Argon2id salt + KDF parameters + wrap nonce + wrapped file key), extension region, header HMAC tag, encrypted payload |
| **Hybrid `.fcr`** | 12-byte prefix (`FCR\0` magic, version, kind `'E'`, prefix flags, header length), header_fixed (header flags, recipient count, recipient-entries length, extension length, stream nonce), one `x25519` recipient entry (ephemeral X25519 public key + wrap nonce + wrapped file key), extension region, header HMAC tag, encrypted payload |
| **`private.key`** | Cleartext header (magic, version, kind `'K'`, key flags, type-name length, public-material length, extension length, wrapped-secret length, Argon2id salt, KDF parameters, AEAD nonce), variable region (recipient type name, public material, extension region), passphrase-encrypted X25519 private key (the raw key is never stored unencrypted; the entire cleartext is bound as AEAD associated data so tampering fails authentication) |
| **`public.key`** | UTF-8 text file containing the canonical lowercase Bech32 `fcr1…` recipient string followed by a newline. The Bech32 payload is a typed encoding of the recipient type name and public-key material, with an internal SHA3-256 checksum for early detection of malformed input. |

### Security

- **Symmetric encryption:** XChaCha20-Poly1305 via the [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) crate ([audited by NCC Group](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/)), with Argon2id passphrase derivation and HKDF-SHA3-256 subkey expansion; each file gets a random file key wrapped by the passphrase-derived key
- **Hybrid encryption:** X25519 ECDH key agreement via [`x25519-dalek`](https://crates.io/crates/x25519-dalek), HKDF-SHA3-256 wrap-key derivation, XChaCha20-Poly1305 envelope encryption; each file gets a random file key sealed for the recipient
- HMAC-SHA3-256 header authentication — tampering is detected before payload decryption begins; a recipient entry is opened first to recover the file key, and the header HMAC key is derived from it. The HMAC scope covers the full prefix, fixed header, recipient list, and extension region, so reordering or modifying any of those fields invalidates the tag.
- Streaming encryption — plaintext is streamed directly into the encryptor; no plaintext temporary archive is written to disk
- Passphrases are handled via the `secrecy` crate (hidden from `Debug`/`Display`, zeroized on drop)
- Bech32 recipient strings carry an internal SHA3-256 checksum in addition to the BIP 173 outer checksum, so transcription errors and truncation are caught with a clear error before any cryptographic step runs
- The current implementation preserves regular-file and directory permission bits through encrypt/decrypt round-trips on Unix. Setuid, setgid, and sticky bits are stripped on both archiving and extraction. This is current behavior rather than a cross-platform compatibility guarantee; on non-Unix platforms, permission metadata may be approximate
- Symlink inputs are rejected; directory encryption does not follow symlinks, preventing unintended inclusion of files outside the selected tree. Directories containing symlinks or other special entries (sockets, FIFOs, devices) are rejected at encryption time. Hardlinks are archived as regular file contents; hardlink relationships are not preserved.
- Directory extraction is hardened against local symlink and directory-component races on Linux and macOS. Every write inside the `.incomplete` working tree is rooted at a directory file descriptor and resolved via `openat`/`mkdirat` with `O_NOFOLLOW`, so a concurrent local attacker who swaps a path component for a symlink cannot redirect plaintext writes outside the destination tree. The extraction aborts with a typed error instead. Windows and non-Linux/non-macOS Unix targets use a path-based extraction path that is less strict against in-tree races. When extracting archives whose authenticity you do not trust on Windows, choose an output directory that is not writable by other local users.
- Archive operations enforce resource caps to bound DoS exposure on both encrypt and decrypt. Defaults: at most **250,000 files and folders** in one archive, **64 GiB total file content**, and **paths nested at most 64 levels deep** (counting each `/`-separated segment including the filename — e.g. `a/b/c/file.txt` is 4 levels). The same caps gate writer-side preflight, so a tree the default-config decrypt would refuse cannot be encrypted in the first place — preventing the "encrypt fine but cannot decrypt your own file" footgun. Pathological inputs (millions of empty entries, multi-TiB declared sizes, deeply nested trees) reject with `InvalidInput` before allocation or `io::copy` runs.
- Encrypted files and generated key files are staged under temporary names in the destination directory and only promoted to the final name on success. Decrypted output is staged under `.incomplete` working names and promoted at the end. Failed encryptions usually clean up their temp files; failed decryptions intentionally leave the `.incomplete` output behind because it may contain the only recoverable plaintext when ciphertext is damaged. On Linux and macOS, directory finalization uses a strict no-clobber path; on Windows, the directory step is a little more conservative and best-effort.
- Versioned file format with magic bytes — corrupted or incompatible files produce clear errors

### Limitations

- **File metadata is not fully preserved.** FerroCrypt always preserves file contents and directory structure. The current implementation also preserves regular-file and directory permission bits on Unix, with setuid, setgid, and sticky bits stripped, but that behavior is best-effort rather than a stable cross-platform format guarantee. FerroCrypt does not preserve timestamps or ownership. On non-Unix platforms, permission handling is platform-limited and archive metadata may be approximate. Hardlink relationships are not preserved (hardlinked files are archived as independent copies). Symlinks and special entries cause an error at encryption time. Directory encryption is a convenience feature, not a full backup/archive format. If you need faithful filesystem backup/restore semantics, use a dedicated archiving tool and encrypt its output with FerroCrypt.
- **No backward compatibility with older format versions.** v0.3.0 introduced a unified on-disk format v1 across `.fcr` files, `public.key`, and `private.key`. Files and keys produced by earlier versions (v0.1.x / v0.2.x) cannot be decrypted or used by v0.3.0 or later. Those releases use a different format family; in hybrid mode and key files they also use a different crypto stack (RSA/OpenSSL). If you still have data encrypted with an older version, install that older version (still available on crates.io as a pinned dependency), decrypt with it, then re-encrypt with the current release. The full list of changes is in `CHANGELOG.md`.

### Project Structure

| Crate | Description |
|---|---|
| `ferrocrypt-lib` | Core encryption library ([crates.io](https://crates.io/crates/ferrocrypt)) |
| `ferrocrypt-cli` | CLI binary ([crates.io](https://crates.io/crates/ferrocrypt-cli)) |
| `ferrocrypt-desktop` | Desktop app built with [Slint](https://slint.dev/) |

Two canonical specification documents live in `ferrocrypt-lib/`:

- **`FORMAT.md`** — wire format specification: `.fcr` byte layout, `private.key` / `public.key` file formats, recipient entry framing, payload stream rules, TLV extension grammar.
- **`STRUCTURE.md`** — code architecture specification: module layout, single sources of truth for security-sensitive concerns, dependency direction, public API shape, and decryption security ordering.

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
- **Decryption failed: header tampered after unlock** — A recipient entry unwrapped successfully, but the header HMAC does not match. Header bytes inside the MAC scope — the prefix, fixed header, recipient list, or extension region — have been tampered with or corrupted since writing.
- **Payload authentication failed: data tampered or corrupted** — The header authenticated successfully, but a later ciphertext chunk failed its authentication tag. This usually means the file has been corrupted or truncated partway through, an attacker has modified bytes after the header, or extra bytes were appended after the authenticated payload. During streaming decryption, earlier chunks that authenticated successfully may already have been written to disk under an `.incomplete` working directory before the failing chunk was reached.
- **Encrypted file is truncated** — The encrypted stream ends before its final authenticated chunk, usually because of a partial download or an interrupted copy.
- **Encrypted file has unexpected trailing data** — Bytes remain after the final authenticated chunk was decrypted successfully. Ordinary appended-bytes cases on a local file are already caught as a payload authentication failure (above), because the per-chunk AEAD's final-flag binding rejects a naive append. This dedicated variant is the defense-in-depth path for pathological input readers — non-blocking sockets, `Take`-style wrappers, or similar — that signal end-of-file at the chunk boundary and then yield additional bytes; FerroCrypt refuses to return success on such a stream.
- **KDF resource cap exceeded** — The encrypted file's stored Argon2id memory cost exceeds the `--max-kdf-memory` cap (or the built-in 1 GiB ceiling, when the flag isn't set). The error reports both the file's required `mem_cost` and the configured cap. Re-run with a higher cap if you trust the source of the file.

None of these failures produce a file at the final output path. Partial plaintext may have been written under a sibling `.incomplete` working directory (FerroCrypt leaves it there on purpose, because when ciphertext is damaged it may hold the only recoverable data). A retry starts fresh once that `.incomplete` directory is removed.

## Acknowledgments

The desktop app is built with [Slint](https://slint.dev/).

Password strength scoring is adapted from [Proton Pass](https://github.com/protonpass/proton-pass-common) (GPLv3).

[![forthebadge](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com)
