<div align="center"><img src="ferrocrypt-desktop/assets/app_icon.png" style="width: 85px;" alt="clavirio"></div>

<h1 align="center"><code>FerroCrypt</code></h1>

![](https://github.com/alexylon/ferrocrypt/actions/workflows/rust.yml/badge.svg)
&nbsp;
[![crate: ferrocrypt](https://img.shields.io/crates/v/ferrocrypt.svg?label=crate%3A%20ferrocrypt&color=blue)](https://crates.io/crates/ferrocrypt)
&nbsp;
[![docs.rs](https://img.shields.io/docsrs/ferrocrypt/latest?color=2e7d32)](https://docs.rs/ferrocrypt/latest)
&nbsp;
[![crate: ferrocrypt-cli](https://img.shields.io/crates/v/ferrocrypt-cli.svg?label=crate%3A%20ferrocrypt-cli&color=blue)](https://crates.io/crates/ferrocrypt-cli)

Multiplatform file encryption tool with CLI and desktop interfaces. Written in Rust.

<div align="center"><img src="/assets/screenshot.png" width="400" alt="FerroCrypt"></div>

## About

FerroCrypt encrypts and decrypts files and directories. It supports two modes:

- **Symmetric** — Password-based. Uses XChaCha20-Poly1305 with Argon2id key derivation and HKDF-SHA3-256 subkey expansion. Same password encrypts and decrypts.
- **Hybrid** — Public/private key based. Combines RSA-4096 (key encryption) with XChaCha20-Poly1305 (data encryption). Each file gets a unique random key sealed with the recipient's public key. Decryption requires the private key and its passphrase.

Both modes produce `.fcr` files. The file header identifies the mode automatically — no need to remember which mode was used.

### Security

- XChaCha20-Poly1305 via the audited `chacha20poly1305` crate
- HMAC-SHA3-256 header authentication — tampering is detected before decryption begins
- Passphrases handled via the `secrecy` crate (zeroized on drop, hidden from Debug/Display)
- Triple-replicated headers with majority-vote decoding for error correction
- Versioned file format with magic bytes — corrupted or incompatible files produce clear errors

### Project Structure

| Crate | Description |
|---|---|
| `ferrocrypt-lib` | Core encryption library ([crates.io](https://crates.io/crates/ferrocrypt)) |
| `ferrocrypt-cli` | CLI binary ([crates.io](https://crates.io/crates/ferrocrypt-cli)) |
| `ferrocrypt-desktop` | Desktop app built with [Slint](https://slint.dev/) |

## Installation

### CLI

```bash
cargo install ferrocrypt-cli
```

Or build from source:

```bash
cargo build --release
```

Binary output: `target/release/ferrocrypt` (macOS/Linux) or `target\release\ferrocrypt.exe` (Windows).

### Library

```bash
cargo add ferrocrypt
```

## CLI Usage

### Subcommands

| Subcommand | Purpose |
|---|---|
| `symmetric` | Encrypt/decrypt with a password |
| `hybrid` | Encrypt/decrypt with RSA keys |
| `keygen` | Generate an RSA key pair |

Run without arguments to start an interactive REPL.

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
# Generate keys
ferrocrypt keygen -o ./keys -p "key password"

# Encrypt with public key (no passphrase needed)
ferrocrypt hybrid -i secret.txt -o ./encrypted -k ./keys/rsa-4096-pub-key.pem

# Decrypt with private key
ferrocrypt hybrid -i ./encrypted/secret.fcr -o ./decrypted -k ./keys/rsa-4096-priv-key.pem -p "key password"
```

### Interactive Mode

```text
$ ferrocrypt
FerroCrypt interactive mode
Type `keygen`, `hybrid`, or `symmetric` with flags, or `quit` to exit.

ferrocrypt> symmetric -i secret.txt -o out -p "my password"
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
| `-b, --bit-size` | RSA key size in bits (default: `4096`) |

## Desktop App

### Build

Requires [Rust](https://www.rust-lang.org/tools/install). Navigate to the `ferrocrypt-desktop` directory.

**Linux only** — install rendering dependencies:

```bash
# Debian/Ubuntu
sudo apt install libfontconfig1-dev libfreetype-dev

# Fedora
sudo dnf install fontconfig-devel freetype-devel
```

macOS and Windows need no extra dependencies.

```bash
cargo run              # dev build
cargo build --release  # release build
```

Binary output: `target/release/ferrocrypt-desktop` (macOS/Linux) or `target\release\ferrocrypt-desktop.exe` (Windows).

### Usage

Select a file or folder, then choose the encryption mode. The app auto-detects the mode when opening `.fcr` files.

- **Symmetric** — Enter a password. The output path is auto-filled as `{name}.fcr` and can be changed with "Save As". Decryption uses a directory picker.
- **Hybrid** — Select a public key to encrypt, or a private key + passphrase to decrypt. Same "Save As" option for custom output names.
- **Key Gen** — Enter a passphrase, choose an output folder, and generate RSA-4096 keys.

A password strength indicator (based on [Proton Pass](https://github.com/protonpass/proton-pass-common) implementation) is shown during encryption and key generation.

## Acknowledgments

The desktop app is built with [Slint](https://slint.dev/).

Password strength scoring is adapted from [Proton Pass](https://github.com/protonpass/proton-pass-common) (GPLv3).

[![forthebadge](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com)
