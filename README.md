<div align="center"><img src="ferrocrypt-desktop/assets/app_icon.png" style="width: 85px;" alt="FerroCrypt"></div>

<h1 align="center"><code>FerroCrypt</code></h1>

![](https://github.com/alexylon/ferrocrypt/actions/workflows/rust.yml/badge.svg)
&nbsp;
[![crate: ferrocrypt](https://img.shields.io/crates/v/ferrocrypt.svg?label=crate%3A%20ferrocrypt&color=blue)](https://crates.io/crates/ferrocrypt)
&nbsp;
[![docs.rs](https://img.shields.io/docsrs/ferrocrypt/latest?color=2e7d32)](https://docs.rs/ferrocrypt/latest)
&nbsp;
[![crate: ferrocrypt-cli](https://img.shields.io/crates/v/ferrocrypt-cli.svg?label=crate%3A%20ferrocrypt-cli&color=blue)](https://crates.io/crates/ferrocrypt-cli)

Multiplatform file encryption tool with CLI and desktop interfaces. Written in Rust.

<div align="center">
  <img src="/assets/screenshot-1.png" width="295" alt="FerroCrypt">&nbsp;&nbsp;
  <img src="/assets/screenshot-2.png" width="295" alt="FerroCrypt">&nbsp;&nbsp;
  <img src="/assets/screenshot-3.png" width="295" alt="FerroCrypt">
</div>

## About

FerroCrypt encrypts and decrypts files and directories. It supports two modes:

- **Symmetric** — Password-based. Uses XChaCha20-Poly1305 with Argon2id key derivation and HKDF-SHA3-256 subkey expansion. Same password encrypts and decrypts.
- **Hybrid** — Public/private key based. Combines X25519 key agreement with XChaCha20-Poly1305 (data encryption). Each file gets a unique random key sealed with the recipient's public key. Decryption requires the private key and its passphrase.

Both modes produce `.fcr` files. Decryption is based on magic bytes in the file header, not the file extension — renaming a file won't break anything.

### Security

- **Symmetric encryption:** XChaCha20-Poly1305 via the [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) crate ([audited by NCC Group](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/)), with Argon2id key derivation and HKDF-SHA3-256 subkey expansion
- **Hybrid encryption:** X25519 key agreement + XChaCha20-Poly1305 envelope via the [`crypto_box`](https://crates.io/crates/crypto_box) crate ([audited by Cure53](https://cure53.de/pentest-report_rust-libs.pdf))
- HMAC-SHA3-256 header authentication — tampering is detected before decryption begins
- Passphrases handled via the `secrecy` crate (zeroized on drop, hidden from Debug/Display)
- Triple-replicated headers with majority-vote decoding for error correction. The header is the most critical part of an encrypted file — it holds the salts, nonces, and key material needed to begin decryption. Unlike the ciphertext, which is protected per-chunk by Poly1305 tags, a single corrupted header byte would make the entire file unrecoverable. Triple replication ensures that up to 33% of the stored header bytes can be corrupted and still be automatically corrected without data loss. Triple replication was chosen over Reed-Solomon because each header field must be decoded independently, making RS degenerate to identical copies (k=1) with added Galois field overhead and no correction advantage.
- Versioned file format with magic bytes — corrupted or incompatible files produce clear errors

### Project Structure

| Crate | Description |
|---|---|
| `ferrocrypt-lib` | Core encryption library ([crates.io](https://crates.io/crates/ferrocrypt)) |
| `ferrocrypt-cli` | CLI binary ([crates.io](https://crates.io/crates/ferrocrypt-cli)) |
| `ferrocrypt-desktop` | Desktop app built with [Slint](https://slint.dev/) |

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
cargo bundle --release # produces .app (macOS) / .deb (Linux) / .msi (Windows)
```

**Linux only** — install system dependencies first:

```bash
# Debian/Ubuntu
sudo apt install libfontconfig-dev libfreetype-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev

# Fedora
sudo dnf install fontconfig-devel freetype-devel libxcb-devel libxkbcommon-devel openssl-devel
```

### Library

```bash
cargo add ferrocrypt
```

## CLI Usage

### Subcommands

| Subcommand | Alias | Purpose |
|---|---|---|
| `symmetric` | `sym` | Encrypt/decrypt with a password |
| `hybrid` | `hyb` | Encrypt/decrypt with public/private keys |
| `keygen` | `gen` | Generate a key pair |
| `fingerprint` | `fp` | Print a public key's SHA3-256 fingerprint |

Run without arguments to start an interactive REPL. Aliases are available in interactive mode.

### Symmetric

```bash
# Encrypt
ferrocrypt symmetric -i secret.txt -o ./encrypted -p "my password"

# Decrypt
ferrocrypt symmetric -i ./encrypted/secret.fcr -o ./decrypted -p "my password"

# Encrypt with custom output filename
ferrocrypt symmetric -i secret.txt -o ./encrypted -p "my password" -s ./encrypted/backup.fcr
```

### Hybrid

```bash
# Generate keys (prints fingerprint)
ferrocrypt keygen -o ./keys -p "key password"

# Verify a public key's fingerprint
ferrocrypt fingerprint ./keys/public.key

# Encrypt with public key (prints recipient fingerprint)
ferrocrypt hybrid -i secret.txt -o ./encrypted -k ./keys/public.key

# Decrypt with private key
ferrocrypt hybrid -i ./encrypted/secret.fcr -o ./decrypted -k ./keys/private.key -p "key password"
```

### Interactive Mode

```text
$ ferrocrypt
FerroCrypt interactive mode
Commands: symmetric (sym), hybrid (hyb), keygen (gen), fingerprint (fp), quit

ferrocrypt> sym -i secret.txt -o out -p "my password"
ferrocrypt> quit
```

### Flag Reference

#### `symmetric`

| Flag | Description |
|---|---|
| `-i, --inpath` | Input file or directory |
| `-o, --outpath` | Output directory |
| `-p, --passphrase` | Password for encryption/decryption |
| `-s, --save-as` | Custom output file path (encrypt only, optional) |

#### `hybrid`

| Flag | Description |
|---|---|
| `-i, --inpath` | Input file or directory |
| `-o, --outpath` | Output directory |
| `-k, --key` | Public key (encrypt) or private key (decrypt) |
| `-p, --passphrase` | Private key passphrase (decrypt only) |
| `-s, --save-as` | Custom output file path (encrypt only, optional) |

#### `keygen`

| Flag | Description |
|---|---|
| `-o, --outpath` | Output directory for the key pair |
| `-p, --passphrase` | Passphrase to encrypt the private key |

#### `fingerprint`

| Argument | Description |
|---|---|
| `<key_file>` | Path to a public key file |

## Desktop App Usage

Select a file or folder, then choose the encryption mode. The app auto-detects encrypted files by reading the file header, regardless of extension.

- **Symmetric** — Enter a password. The output path is auto-filled as `{name}.fcr` and can be changed with "Save As". Decryption uses a directory picker.
- **Hybrid** — Use an existing public key to encrypt, or create a new key pair inline. After key generation, the app switches to encryption with the new public key pre-filled. The recipient's public key fingerprint is shown for out-of-band verification. Key files are validated on selection — invalid files show an error and disable the action button. Decryption requires a private key + passphrase.

A password strength indicator (based on [Proton Pass](https://github.com/protonpass/proton-pass-common) implementation) is shown during encryption and key generation.

## Acknowledgments

The desktop app is built with [Slint](https://slint.dev/).

Password strength scoring is adapted from [Proton Pass](https://github.com/protonpass/proton-pass-common) (GPLv3).

[![forthebadge](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com)
