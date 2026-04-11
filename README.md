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

FerroCrypt encrypts and decrypts files and directories. It supports two modes:

- **Symmetric** — Password-based. Uses XChaCha20-Poly1305 with Argon2id key derivation and HKDF-SHA3-256 subkey expansion. Same password encrypts and decrypts.
- **Hybrid** — Public/private key based. Combines X25519 key agreement with XChaCha20-Poly1305 (data encryption). Each file gets a unique random key sealed with the recipient's public key. Decryption requires the private key and its passphrase. Hybrid mode provides confidentiality and integrity for the recipient, but does not authenticate the sender — it is not a substitute for digital signatures.

Both modes produce `.fcr` files. Decryption is based on magic bytes in the file header, not the file extension — renaming a file won't break anything.

A standalone format specification is available at [`ferrocrypt-lib/FORMAT.md`](ferrocrypt-lib/FORMAT.md).

### What's stored in an encrypted file

Every `.fcr` file starts with a header followed by the encrypted payload. The header contains only the metadata needed to begin decryption — no filenames, timestamps, or plaintext content is exposed. All header fields are triple-replicated for error correction.

| File | Contents |
|---|---|
| **Symmetric `.fcr`** | Format identifier, version, Argon2id salt, HKDF salt, KDF parameters (memory cost, iterations, parallelism), stream nonce, key verification hash, HMAC authentication tag |
| **Hybrid `.fcr`** | Format identifier, version, sealed key envelope (ephemeral public key + encrypted random key), stream nonce, HMAC authentication tag |
| **`private.key`** | KDF parameters, Argon2id salt, nonce, passphrase-encrypted secret key (the raw key is never stored unencrypted) |
| **`public.key`** | Raw 32-byte X25519 public key (not secret). Can also be shared as a Bech32 `fcr1…` recipient string via the library API. |

### Security

- **Symmetric encryption:** XChaCha20-Poly1305 via the [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) crate ([audited by NCC Group](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/)), with Argon2id key derivation and HKDF-SHA3-256 subkey expansion
- **Hybrid encryption:** X25519 ECDH key agreement via [`x25519-dalek`](https://crates.io/crates/x25519-dalek), HKDF-SHA256 envelope key derivation, XChaCha20-Poly1305 envelope encryption
- HMAC-SHA3-256 header authentication — tampering is detected before payload decryption begins; in hybrid mode the envelope is opened first to recover the HMAC key
- Streaming encryption — plaintext never touches disk as an intermediate file
- Passphrases handled via the `secrecy` crate (zeroized on drop, hidden from Debug/Display)
- Triple-replicated headers with majority-vote decoding for error correction (see [Why triple replication?](#why-triple-replication) below)
- Symlink inputs are rejected; directory encryption does not follow symlinks — prevents unintended inclusion of files outside the selected tree. Directories containing symlinks or other special entries (sockets, FIFOs, devices) are rejected at encryption time with a clear error. Hardlinks are archived as regular file contents; hardlink relationships are not preserved.
- Both encryption and decryption write output under an `.incomplete` working name (e.g. `myfile.fcr.incomplete`, `myfile.txt.incomplete`, `myfolder.incomplete`) and only rename to the final name on success. Output never appears under the final name during streaming. Failed encryptions clean up the `.incomplete` file (ciphertext only); failed decryptions leave it on disk intentionally — it may be the only recoverable data when the original ciphertext is damaged
- Versioned file format with magic bytes — corrupted or incompatible files produce clear errors

### Limitations

- **File metadata is not fully preserved.** FerroCrypt preserves file contents and directory structure. It does not preserve permissions, timestamps, or ownership. Hardlink relationships are not preserved (hardlinked files are archived as independent copies). Symlinks and special entries cause an error at encryption time. If you need faithful filesystem backup/restore semantics, use a dedicated backup tool and encrypt its output with FerroCrypt.
- **No backward compatibility with older format versions.** The current release uses symmetric encrypted-file format v3.0, hybrid encrypted-file format v4.0, and key-file format v3. Files and keys produced by earlier versions (v0.1.x / v0.2.x) cannot be decrypted or used — those versions relied on a different crypto stack (RSA/OpenSSL). If you have data encrypted with an older version, decrypt it with that version first (available on crates.io), then re-encrypt with the current release.

### Why triple replication?

The file header holds the salts, nonces, and KDF parameters needed to begin decryption. If the header can't be parsed, the tool can't distinguish a wrong password from a corrupted file from an unsupported format — every failure looks the same. The encrypted payload is much larger and far more likely to be damaged on unreliable storage, so header replication usually does not save the file. What it saves is the **diagnostic**: by correcting single-copy header corruption, the user still gets a specific error message:

- "Unsupported file version" — instead of failing to identify the format at all
- "Unrecognized encryption type: 0xNN" — instead of treating the file as plaintext
- "Invalid KDF memory cost" / "File requires N KiB, limit is M KiB" — instead of silently allocating unbounded memory
- "Authentication failed: wrong password, wrong key, or tampered data" — instead of not knowing whether the password is wrong or the file is damaged
- "Encrypted stream truncated" / per-chunk AEAD failure — instead of not reaching decryption at all

Without a readable header, all of these collapse into a single generic "invalid format" error.

The mechanism is deliberately simple: store three identical copies of each header field and pick the majority value per byte. If two out of three copies agree, the correct value is recovered. This gives 33% corruption tolerance across the stored header bytes — one copy can be completely destroyed and the header still parses correctly.

**Why not Reed-Solomon?** Header fields are decoded independently (each field is its own unit), which forces RS to operate at k=1 (one data symbol per codeword). At k=1, RS degenerates to the same correction capability as triple replication — one-symbol correction — but adds Galois field arithmetic, polynomial evaluation, and a substantially larger implementation surface. For small pieces of data such as the file header, triple replication achieves the same result with plain byte comparison: no arithmetic, no lookup tables, no side-channel concerns.

For a security tool, implementation simplicity is a feature. The entire replication decoder is ~30 lines of majority-vote logic with no integer overflow risk, no GF(256) operations, and no subtle correctness edge cases. This keeps the auditing surface minimal and the attack surface close to zero — properties that matter more than the theoretical elegance of a more complex code.

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

- **Symmetric** — Enter a password. The output path is auto-filled as `{name}.fcr` and can be changed with "Save As". Decryption uses a directory picker.
- **Hybrid** — Use an existing public key to encrypt, or create a new key pair inline. After key generation, the app switches to encryption with the new public key pre-filled. The recipient's public key fingerprint is shown for out-of-band verification. Key files are validated on selection — invalid files show an error and disable the action button. Decryption requires a private key + passphrase.

A password strength indicator (based on [Proton Pass](https://github.com/protonpass/proton-pass-common) implementation) is shown during encryption and key generation.

## Acknowledgments

The desktop app is built with [Slint](https://slint.dev/).

Password strength scoring is adapted from [Proton Pass](https://github.com/protonpass/proton-pass-common) (GPLv3).

[![forthebadge](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com)
