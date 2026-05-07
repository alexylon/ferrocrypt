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

FerroCrypt is a pure Rust library, CLI, and desktop application for encrypting and decrypting files and directories using password-based or key-pair-based encryption.

<div align="center">
  <img src="/assets/screenshot-1.png" width="400" alt="FerroCrypt">&nbsp;&nbsp;
</div>

<div align="center">
  <img src="/assets/screenshot-2.png" width="400" alt="FerroCrypt">&nbsp;&nbsp;
</div>

<div align="center">
  <img src="/assets/screenshot-3.png" width="400" alt="FerroCrypt">
</div>

> **Status:** `main` is the in-development branch for the upcoming **v0.3.0** release.
> The crates published on crates.io (`0.2.5`) use the previous on-disk format and
> CLI; everything below describes the v0.3.0 line. Until v0.3.0 ships, files
> produced by `main` are not interchangeable with `0.2.5`, **further breaking
> changes (wire format, public API, CLI) may land before the final v0.3.0 cut**,
> and any pre-release `main` artefact should be treated as unstable. See the
> [`[Unreleased]` section of `CHANGELOG.md`](CHANGELOG.md#unreleased) for the
> full list of breaking changes so far.

## Overview

FerroCrypt encrypts a file or directory into a single `.fcr` file. Each file carries one or more typed recipients — any one of them can unlock the same encrypted payload:

- **Passphrase recipient (`argon2id`)** — encryption and decryption use the same passphrase. Typical use is encrypting data that only the user needs to read again.
- **Public-key recipient (`x25519`)** — encryption uses one or more recipient public keys; decryption uses the matching password-protected private key. Typical use is sending encrypted data to someone else, or to several recipients in a single file.

The recipient list is part of authenticated metadata inside the file, not the filename or extension. Renaming an encrypted file does not change how FerroCrypt interprets it.

Directory encryption is intended for safe transfer and storage of file contents. It preserves directory structure and regular file data, but it is not a full system-backup format.

## Installation

Pre-built CLI binaries and desktop packages are published on the [GitHub Releases](https://github.com/alexylon/ferrocrypt/releases) page.

Available release artifacts include:

- CLI binaries for macOS, Linux, and Windows
- Desktop packages for macOS, Debian/Ubuntu, Fedora/RHEL, and Windows

### Rust library

```bash
cargo add ferrocrypt
```

API documentation is available on [docs.rs](https://docs.rs/ferrocrypt/latest/ferrocrypt/).

### Command-line interface

Install from crates.io:

```bash
cargo install ferrocrypt-cli
```

Or build from source:

```bash
cargo build --release
```

The compiled binary is written to `target/release/ferrocrypt` on macOS and Linux, or `target\release\ferrocrypt.exe` on Windows.

### Desktop application

Building the desktop application from source requires Rust and `cargo-bundle`:

```bash
cd ferrocrypt-desktop
cargo bundle --release
```

The bundle command produces platform-specific packages, such as `.app`, `.deb`, `.AppImage`, or `.msi`, depending on the host platform and installed tooling.

Linux builds also require these system packages:

```bash
# Debian/Ubuntu
sudo apt install libfontconfig-dev libfreetype-dev libxcb-shape0-dev \
                 libxcb-xfixes0-dev libxkbcommon-dev libwayland-dev libssl-dev

# Fedora
sudo dnf install fontconfig-devel freetype-devel libxcb-devel \
                 libxkbcommon-devel wayland-devel openssl-devel
```

AppImage output also requires `mksquashfs`, provided by the `squashfs-tools` package.

## Command-line usage

The CLI exposes four subcommands — `encrypt`, `decrypt`, `keygen`, `fingerprint` — and starts an interactive prompt when invoked without arguments. The encryption mode (passphrase or public-key) is chosen by the credentials supplied to `encrypt`; `decrypt` reads the file's recipient list and routes itself.

### Password-based encryption

```bash
# Encrypt a file or directory with a passphrase
ferrocrypt encrypt -i secret.txt -o ./encrypted

# Decrypt the resulting .fcr file
ferrocrypt decrypt -i ./encrypted/secret.fcr -o ./decrypted

# Write the encrypted file to an explicit path
ferrocrypt encrypt -i secret.txt -s ./secret.fcr
```

When neither `--public-key` nor `--recipient` is given, `encrypt` runs in passphrase mode. `--passphrase` (`-p`) makes the choice explicit.

### Public-key encryption

```bash
# Generate a key pair
ferrocrypt keygen -o ./keys

# Encrypt with a public key file
ferrocrypt encrypt -i secret.txt -o ./encrypted -k ./keys/public.key

# Decrypt with the matching private key
ferrocrypt decrypt -i ./encrypted/secret.fcr -o ./decrypted -K ./keys/private.key
```

`-k` (lowercase) selects the shareable public key; `-K` (uppercase) selects the secret private key. Each flag has exactly one meaning.

Multiple recipients can be combined into one `.fcr`: pass `-k` and `-r` repeatedly and any matching private key will decrypt the file.

```bash
# Encrypt to two public-key recipients in a single file
ferrocrypt encrypt -i secret.txt -o ./encrypted \
  -k ./alice/public.key \
  -k ./bob/public.key
```

Public keys can also be represented as `fcr1...` recipient strings. The contents of `public.key` is already such a string, so a separate command to extract it is not needed:

```bash
# Print the recipient string stored in a public key file
cat ./keys/public.key

# Print the public key fingerprint for independent verification
ferrocrypt fingerprint ./keys/public.key

# Encrypt directly to a recipient string
ferrocrypt encrypt -i secret.txt -o ./encrypted -r fcr1...
```

The shorter aliases `enc`, `dec`, `gen`, and `fp` may be used in place of the full subcommand names.

Passphrases are not accepted as command-line arguments. The CLI prompts for them with hidden input. For scripts and CI environments, the `FERROCRYPT_PASSPHRASE` environment variable may be used.

If `encrypt` is given an input that already begins with the FerroCrypt magic bytes, it warns and prompts for confirmation on an interactive shell, refuses with exit code 1 on a non-interactive shell, or proceeds when `--allow-double-encrypt` is set.

### Interactive mode

```text
$ ferrocrypt
FerroCrypt interactive mode
Commands: encrypt (enc), decrypt (dec), keygen (gen), fingerprint (fp), quit

ferrocrypt> encrypt -i secret.txt -o out
Passphrase:
Confirm passphrase:
ferrocrypt> quit
```

The interactive prompt exits on `quit`, `exit`, or Ctrl-D. Ctrl-C cancels the current line without exiting the prompt.

### Subcommands

| Subcommand | Alias | Purpose |
|---|---|---|
| `encrypt` | `enc` | Encrypt a file or directory |
| `decrypt` | `dec` | Decrypt a `.fcr` file |
| `keygen` | `gen` | Generate a public/private key pair |
| `fingerprint` | `fp` | Print a public key fingerprint |

`fingerprint` takes a public key file path directly: `ferrocrypt fingerprint ./keys/public.key`.

### Common options

| Option | Applies to | Description |
|---|---|---|
| `-i, --input` | `encrypt`, `decrypt` | Input file or directory |
| `-o, --output-dir` | `encrypt`, `decrypt`, `keygen` | Output directory |
| `-s, --save-as` | `encrypt` | Explicit encrypted output file path |
| `-p, --passphrase` | `encrypt` | Encrypt with a passphrase (default when no recipient is given) |
| `-r, --recipient` | `encrypt` | Public recipient string (`fcr1...`); repeatable |
| `-k, --public-key` | `encrypt` | Public key file; repeatable |
| `-K, --private-key` | `decrypt` | Private key file (required for public-recipient files) |
| `--allow-double-encrypt` | `encrypt` | Permit encrypting an input that already looks like a `.fcr` file |
| `--max-kdf-memory` | `decrypt` | Maximum Argon2id memory cost accepted during decryption |

## Desktop application

The desktop application provides the same encryption workflows through a graphical interface. It accepts files and directories as input and detects encrypted files by reading their file headers.

- **Password** tab — passphrase-based encryption.
- **Key pair** tab — public/private-key encryption. Key pairs can be generated from inside the application. Public key fingerprints are displayed for independent verification.

Encrypted output is named automatically and can be changed with Save As. Key files are validated on selection, and invalid inputs or output conflicts are reported before encryption or decryption begins. A password-strength indicator is shown when a password is entered.

## Main properties

- **Single encrypted-file format.** Password-based and public-key encryption both produce `.fcr` files.
- **Mode detection from file contents.** Encrypted files are recognized from their internal header, not from the file extension.
- **Authenticated metadata.** File headers are authenticated before any plaintext is produced.
- **Streaming encryption.** File data is processed in chunks, so large inputs do not need to be held entirely in memory.
- **Directory support.** Directories are stored as a restricted internal archive and encrypted as part of the payload.
- **Public recipient strings.** Public keys can be shared as lowercase `fcr1...` recipient strings.
- **Public key fingerprints.** SHA3-256 fingerprints provide a stable ID for independent public-key verification.
- **Atomic output.** Encrypted files and generated key files are staged before being moved into their final location.
- **Hardened extraction on Linux, macOS, and Windows.** Every directory step is anchored to a capability handle that refuses symlinks at any path component, and on Windows additionally rejects NTFS reparse points (junctions and mount points). Extraction writes cannot be redirected outside the chosen output directory.
- **Typed library errors.** The Rust API distinguishes wrong credentials, unsupported data, authentication failures, truncation, and resource-limit failures.
- **Pure Rust implementation.** The cryptographic implementation does not depend on OpenSSL. The library forbids `unsafe` code.

Multi-recipient public-key encryption is supported by the library API. A single `.fcr` file can be encrypted for several X25519 public keys, allowing any matching private key to decrypt it.

## Security and limitations

FerroCrypt is an encryption tool, not an authentication or identity system. Public-key encryption controls which private keys can decrypt a file, but it does not prove who created the encrypted file. Sender authentication requires a separate signing mechanism.

The project has not undergone an independent third-party security audit. The [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) AEAD crate it uses for data encryption was [audited by NCC Group](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/).

Limitations:

- Pre-v1 FerroCrypt files and key pairs are not compatible with the current v1 format. Older data must be decrypted with the release that created it and then re-encrypted with the current release.
- Directory encryption preserves file contents, directory structure, and Unix file permissions. It does not preserve ownership, timestamps, ACLs, extended attributes, hardlink identity, setuid/setgid/sticky bits, or platform-specific metadata.
- Symlinks, hardlink archive entries, device files, FIFOs, sockets, unsafe paths, duplicate output paths, archives with more than one top-level root, and any PAX or GNU TAR extension record are rejected during archive processing.
- Filesystem hardlinks encountered during encryption are stored as independent regular files.
- Single files inside an encrypted folder are limited to about 8 GiB (the largest value the standard ustar size field can carry, exactly 8,589,934,591 bytes); larger inputs are rejected up front. Archives can hold many such files up to the total-bytes cap below.
- Default archive limits are enforced during encryption and decryption: at most 250,000 entries, 64 GiB of total regular-file content, and 64 path components per entry.
- Failed decryptions do not write to the final output path. By default the staged `.incomplete` working copy is removed before the error returns, so a failed decrypt leaves no plaintext residue under the output directory. Pass `decrypt --keep-partial` (CLI) or `IncompleteOutputPolicy::RetainOnError` (library) to keep the staged copy for backup-recovery or forensic inspection; retained partials may represent an attacker-chosen prefix of the original because the per-chunk authentication only detects truncation when the final chunk arrives.
- Hardened extraction is unified across Linux, macOS, and Windows: every directory open uses `cap-std` plus `cap-fs-ext` no-follow primitives, with an additional `FILE_ATTRIBUTE_REPARSE_POINT` rejection on Windows so junctions and mount points are refused alongside symlinks. The same code path applies on every supported OS.

## Decryption errors

FerroCrypt reports decryption failures according to the stage that failed. This helps distinguish common causes without treating all failures as a generic wrong-password error.

Common failure categories include:

- **Private key unlock failed: wrong passphrase or tampered file** — the private key passphrase is wrong, or the encrypted private key file has been modified.
- **Decryption failed: recipient `argon2id` unwrap failed** — the supplied passphrase does not unlock the file, or the recipient metadata has been modified.
- **Decryption failed: recipient `x25519` unwrap failed** — the supplied private key does not unlock the file, or the recipient metadata has been modified.
- **Decryption failed: recipient `x25519` MAC mismatch** (multi-recipient) — a recipient unwrapped a candidate file key, but the authenticated header did not verify. Decryption continues with the next recipient in the file.
- **Decryption failed: no recipient could unlock the file** — none of the supported recipients in the file could unlock the file key.
- **Decryption failed: header tampered after unlock** — a candidate file key was found, but the authenticated header did not verify.
- **Payload authentication failed: data tampered or corrupted** — the header verified, but the encrypted payload was corrupted or modified.
- **Encrypted file is truncated** — the encrypted stream ended before its final authenticated chunk.
- **Encrypted file has unexpected trailing data** — extra data was found after the authenticated encrypted stream.
- **KDF resource cap exceeded** — the file requests more Argon2id memory than the configured limit permits. The default cap is 1 GiB; raise it with `--max-kdf-memory` if the source is trusted.
- **Unknown critical recipient: `<type>`. Upgrade FerroCrypt.** — the file uses a recipient type marked as required that this release does not support.

No failed decryption produces a completed output at the requested final path. The default behavior removes any staged `.incomplete` working copy before the error returns; `--keep-partial` keeps it for inspection. A leftover `.incomplete` from a previous failed run is preserved across a retry that fails with `Previous .incomplete exists`, so the prior partial is not silently overwritten.

## Technical reference

The canonical technical references are:

- [**`FORMAT.md`**](ferrocrypt-lib/FORMAT.md) — `.fcr`, `private.key`, `public.key`, recipient entries, payload stream, extension data, and archive rules.
- [**`STRUCTURE.md`**](ferrocrypt-lib/STRUCTURE.md) — library organization, API boundaries, dependency direction, and decryption flow.

The cryptographic implementation uses:

| Role | Primitive |
|---|---|
| Payload encryption | XChaCha20-Poly1305 STREAM-BE32 |
| Passphrase KDF | Argon2id |
| Public-key agreement | X25519 |
| Key derivation | HKDF-SHA3-256 |
| Header authentication | HMAC-SHA3-256 |
| Public-key fingerprint | SHA3-256 |
| Recipient string encoding | Bech32, HRP `fcr` |

## Rust version support

The `ferrocrypt` library crate currently targets **MSRV 1.87**. This minimum supported Rust version is checked in CI and may be raised in future releases if required by dependencies or language changes.

## Acknowledgments

The desktop application is built with [Slint](https://slint.dev/).

Password strength scoring is adapted from [Proton Pass](https://github.com/protonpass/proton-pass-common) (GPLv3).

[![forthebadge](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com)
