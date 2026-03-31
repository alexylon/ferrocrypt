# Ferrocrypt Dioxus GUI

A desktop GUI for Ferrocrypt built with Dioxus 0.7.

## Features

This application provides the same functionality as ferrocrypt-desktop-tauri (Tauri version):

- **Symmetric Encryption/Decryption**: Password-based encryption using ChaCha20-Poly1305
- **Hybrid Encryption/Decryption**: RSA + ChaCha20 encryption
- **Key Generation**: Generate RSA key pairs (4096-bit)
- **Large File Support**: Low RAM usage mode for large files
- **Auto-detection**: Automatically detects encrypted files from the `.fcr` extension

## Building

### Development Build
```bash
cargo build
```

### Release Build
```bash
cargo build --release
```

The binary will be located at `target/release/ferrocrypt-desktop-dioxus`.

## Running

### Development Mode
```bash
cargo run
```

### Release Mode
```bash
./target/release/ferrocrypt-desktop-dioxus
```

## Usage

1. **Select Input File**: Click "Select" button next to the input field to choose a file or folder to encrypt/decrypt
2. **Choose Mode**:
   - **Symmetric**: Password-based encryption (AES-256)
   - **Hybrid**: RSA + symmetric encryption
   - **Create key pair**: Generate a new RSA key pair
3. **Enter Password**: Required for most operations
4. **Select Key** (Hybrid mode only): Choose public key for encryption or private key for decryption
5. **Large Files Option** (Symmetric encryption only): Check this for better memory efficiency with large files
6. **Select Output Directory**: Choose where to save the result
7. **Click Encrypt/Decrypt/Create**: Start the operation

## Dependencies

- **Dioxus 0.7**: Cross-platform GUI framework
- **rfd**: Native file dialogs
- **ferrocrypt-lib**: Core encryption library

## Technical Details

- Built with Rust and Dioxus 0.7
- Native desktop application
- Uses the same ferrocrypt-lib as the CLI and Tauri versions
- Supports macOS, Linux, and Windows

## Comparison with Tauri Version

| Feature | Dioxus | Tauri |
|---------|---------|-------|
| Language | Pure Rust | Rust + TypeScript |
| Size | Smaller binary | Larger (includes web engine) |
| Startup | Faster | Slightly slower |
| UI Framework | Dioxus | React |
| Encryption Features | All features | All features |
| File Selection | Button only | Button + Drag-and-drop |

**Note:** Drag-and-drop is not supported in the Dioxus version. Use the "Select" button instead.

## License

Same as the main Ferrocrypt project.
