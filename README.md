# FerroCrypt

![](https://github.com/alexylon/Ferrocrypt/actions/workflows/rust.yml/badge.svg)
&nbsp; 
[![crate: ferrocrypt](https://img.shields.io/crates/v/ferrocrypt.svg?label=crate%3A%20ferrocrypt&color=blue)](https://crates.io/crates/ferrocrypt)
&nbsp;
[![docs.rs](https://img.shields.io/docsrs/ferrocrypt/latest?color=2e7d32)](https://docs.rs/ferrocrypt/latest)
&nbsp;
[![crate: ferrocrypt-cli](https://img.shields.io/crates/v/ferrocrypt-cli.svg?label=crate%3A%20ferrocrypt-cli&color=blue)](https://crates.io/crates/ferrocrypt-cli)

Tiny, easy-to-use, and highly secure multiplatform encryption tool with CLI and GUI interfaces.
Written entirely in Rust.

<br/>

<div align="center"><img align="center" src="/assets/ferrocrypt_screenshot.png" width="400" alt="Ferrocrypt"></div>

<br/>

## Table of Contents

- [Ferrocrypt](#ferrocrypt)
    - [ABOUT](#about)
    - [INSTALLATION](#installation)
    - [USING the CLI app](#using-the-cli-app)
        - [1. Direct subcommand usage](#1-direct-subcommand-usage)
            - [Symmetric encryption (password-based key derivation)](#symmetric-encryption-password-based-key-derivation)
            - [Hybrid encryption](#hybrid-encryption)
                - [Generate a private/public key pair and set a passphrase for encrypting the private key](#generate-a-privatepublic-key-pair-and-set-a-passphrase-for-encrypting-the-private-key)
                - [Encrypt file or directory (using a public key)](#encrypt-file-or-directory-using-a-public-key)
                - [Decrypt file (using a private key)](#decrypt-file-using-a-private-key)
        - [2. Interactive command mode (REPL)](#2-interactive-command-mode-repl)
    - [SUBCOMMANDS AND OPTIONS](#subcommands-and-options)
        - [Global options](#global-options)
        - [`symmetric` subcommand](#symmetric-subcommand)
        - [`hybrid` subcommand](#hybrid-subcommand)
        - [`keygen` subcommand](#keygen-subcommand)
    - [BUILD the desktop app](#build-the-desktop-app)
        - [Run a dev build:](#run-a-dev-build)
        - [Build a release binary:](#build-a-release-binary)
    - [USING the GUI App](#using-the-gui-app)
        - [Symmetric Encryption Mode](#symmetric-encryption-mode)
        - [Hybrid Encryption Mode](#hybrid-encryption-mode)
        - [Key Pair Creation](#key-pair-creation)

## ABOUT

Ferrocrypt is a simple encryption tool leveraging Rust's memory safety guarantees and performance benefits.
The name comes from Latin: "ferrum" (iron) and "ferrugo" (rust).

**Encryption Modes:**

1. **Symmetric** - Uses XChaCha20-Poly1305 encryption with Argon2id password-based key derivation and HKDF-SHA3-256 subkey expansion for domain-separated encryption and HMAC keys. Ideal for personal use where the same password encrypts and decrypts data.

2. **Hybrid** - Combines XChaCha20-Poly1305 (data encryption) with RSA-4096 (key encryption). Each file/folder gets a unique random key, encrypted with your public key. Requires both the private key AND password for decryption, providing dual-layer security.

Both modes produce `.fcr` vault files. The format is self-identifying — the file header distinguishes symmetric from hybrid internally.

**Security Features:**

- **Audited encryption**: Uses the `chacha20poly1305` crate, which has undergone successful security audits
- **Tamper detection**: HMAC-SHA3-256 authenticates every file header — any modification to the salt, nonce, or flags is detected before decryption begins
- **Secure secret handling**: Passphrases are protected using the `secrecy` crate, preventing accidental exposure through Debug/Display traits and ensuring automatic memory zeroization when dropped
- **Error correction**: Triple-replicated cryptographic headers with majority-vote decoding protect against bit rot and data transfer errors
- **Versioned file format**: Files start with a magic-byte header that identifies the format, version, and structure. Corrupted, misnamed, or incompatible files produce clear error messages instead of misleading crypto failures

The code is separated into the library `ferrocrypt-lib`, a CLI client `ferrocrypt-cli`, and a [**Slint**](https://slint.dev/) desktop app `ferrocrypt-desktop`.

<br/>

## INSTALLATION

### CLI Installation

**Install from crates.io:**

```bash
# Installs the 'ferrocrypt' binary
cargo install ferrocrypt-cli
```

**Or build from source:**

```bash
cargo build --release
```

The binary executable file will be generated in `target/release/ferrocrypt` (macOS and Linux)
or `target\release\ferrocrypt.exe` (Windows).

### Library Installation

```bash
cargo add ferrocrypt
```

Or add to your `Cargo.toml`:

```toml
ferrocrypt = "0.2"
```

<br/>

## USING the CLI app

The CLI supports two usage modes:

1. **Direct subcommands** (recommended for scripts and automation)
2. **Interactive command mode** (REPL), entered when you run `./ferrocrypt` with no arguments

Commands shown are for macOS/Linux (use `ferrocrypt` instead of `./ferrocrypt` on Windows).  
Flags can be used in any order.

Available subcommands:

- `keygen`    – Generate a hybrid (asymmetric) key pair
- `hybrid`    – Hybrid encryption/decryption using public/private keys
- `symmetric` – Symmetric encryption/decryption using a passphrase

---

## 1. Direct subcommand usage

### Symmetric encryption (password-based key derivation)

- Encrypt file or directory | decrypt file

`./ferrocrypt symmetric --inpath <SRC_PATH> --outpath <DEST_DIR_PATH> --passphrase <PASSPHRASE>`

or

`./ferrocrypt symmetric -i <SRC_PATH> -o <DEST_DIR_PATH> -p <PASSPHRASE>`

<br/>

### Hybrid encryption

#### Generate a private/public key pair and set a passphrase for encrypting the private key

`./ferrocrypt keygen --bit-size <BIT_SIZE> --passphrase <PASSPHRASE> --outpath <DEST_DIR_PATH>`

or

`./ferrocrypt keygen -b <BIT_SIZE> -p <PASSPHRASE> -o <DEST_DIR_PATH>`

If `--bit-size` is omitted, the default is `4096`.

#### Encrypt file or directory (using a public key)

`./ferrocrypt hybrid --inpath <SRC_PATH> --outpath <DEST_DIR_PATH> --key <PUBLIC_PEM_KEY>`

or

`./ferrocrypt hybrid -i <SRC_PATH> -o <DEST_DIR_PATH> -k <PUBLIC_PEM_KEY>`

#### Decrypt file (using a private key)

`./ferrocrypt hybrid --inpath <SRC_FILE_PATH> --outpath <DEST_DIR_PATH> --key <PRIVATE_PEM_KEY> --passphrase <PASSPHRASE>`

or

`./ferrocrypt hybrid -i <SRC_FILE_PATH> -o <DEST_DIR_PATH> -k <PRIVATE_PEM_KEY> -p <PASSPHRASE>`

---

## 2. Interactive command mode (REPL)

Running `./ferrocrypt` **without any arguments** starts an interactive shell:

```text
$ ./ferrocrypt
Ferrocrypt interactive mode
Type `keygen`, `hybrid`, or `symmetric` with flags, or `quit` to exit.

ferrocrypt> keygen -o keys -p "my secret"
ferrocrypt> hybrid -i secret.txt -o out -k public.pem
ferrocrypt> symmetric -i secret.txt -o out -p "my secret"
ferrocrypt> quit
```

This mode is convenient for exploratory or repeated use.  
Under the hood, it uses the same subcommands and flags as the direct CLI.

---

## SUBCOMMANDS AND OPTIONS

### Global options

```markdown
| Flag             | Description    |
|------------------|----------------|
| `-h, --help`     | Print help     |
| `-V, --version`  | Print version  |
```

<br/>

### `symmetric` subcommand

```markdown
| Flag                             | Description                                                                                                  |
|----------------------------------|--------------------------------------------------------------------------------------------------------------|
| `-i, --inpath <SRC_PATH>`        | File or directory path that needs to be encrypted, or the file path that needs to be decrypted              |
| `-o, --outpath <DEST_DIR>`       | Destination directory path                                                                                   |
| `-p, --passphrase <PASSWORD>`    | Password to derive the symmetric key for encryption and decryption                                          |
```

<br/>

### `hybrid` subcommand

```markdown
| Flag                             | Description                                                                                                  |
|----------------------------------|--------------------------------------------------------------------------------------------------------------|
| `-i, --inpath <SRC_PATH>`        | File or directory path that needs to be encrypted, or the file path that needs to be decrypted              |
| `-o, --outpath <DEST_DIR>`       | Destination directory path                                                                                   |
| `-k, --key <KEY_PATH>`           | Path to the public key for encryption, or the path to the private key for decryption                        |
| `-p, --passphrase <PASSWORD>`    | Password to decrypt the private key (only required when using a private key)                                |
```

<br/>

### `keygen` subcommand

```markdown
| Flag                             | Description                                                                                                  |
|----------------------------------|--------------------------------------------------------------------------------------------------------------|
| `-o, --outpath <DEST_DIR>`       | Destination directory path where the generated key pair will be written                                     |
| `-p, --passphrase <PASSWORD>`    | Passphrase to encrypt the generated private key                                                              |
| `-b, --bit-size <BIT_SIZE>`      | Length of the key in bits for the key pair generation (default: `4096`)                                     |
```

<br/>

## BUILD the desktop app

After [installing Rust](https://www.rust-lang.org/tools/install), navigate to the `ferrocrypt-desktop` directory.

**Prerequisites (Linux only):** Slint requires a few system libraries for rendering. On Debian/Ubuntu:

```bash
sudo apt install libfontconfig1-dev libfreetype-dev
```

On Fedora:

```bash
sudo dnf install fontconfig-devel freetype-devel
```

macOS and Windows need no extra dependencies.

### Run a dev build:

```bash
cargo run
```

### Build a release binary:

```bash
cargo build --release
```

The binary will be generated in `target/release/ferrocrypt-desktop` (macOS/Linux) or `target\release\ferrocrypt-desktop.exe` (Windows).

<br/>

## USING the GUI App

Select a file or folder, then choose the encryption mode. When decrypting, the app auto-detects the mode from the file header.

### Symmetric Encryption Mode

Encrypt/decrypt using the same password. Choose a password and click "Encrypt". When encrypting, the output file path is auto-filled (e.g. `secrets.fcr`) and can be changed via the "Save As" button. When decrypting, select a destination folder.

### Hybrid Encryption Mode

Ideal for secure data exchange. Encrypt using a _public_ RSA key (PEM format), decrypt using the corresponding _private_ key and password. Like symmetric mode, the "Save As" dialog lets you choose the encrypted file name and location.

### Key Pair Creation

Select "Create key pair", enter a password to protect the private key, choose output folder, and generate RSA-4096 keys.


<br/>


## Acknowledgments

The desktop app is built with [Slint](https://slint.dev/).

[![forthebadge](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com)
