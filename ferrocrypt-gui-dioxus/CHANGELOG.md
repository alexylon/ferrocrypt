# Changelog

## [0.1.0] - 2025-11-24

### Added
- Initial implementation of Ferrocrypt GUI using Dioxus 0.7
- Window size: 450px × 750px (non-resizable)
- Symmetric encryption/decryption with password protection
- Hybrid encryption/decryption with RSA keys
- RSA key pair generation (4096-bit)
- Large file support option (low RAM usage)
- Auto-detection of encrypted files (.fcr)
- Password visibility toggle with proper icons
- Password match indicator with visual feedback
- File and folder selection via native dialogs
- Same UI styling as Tauri version

### Known Limitations
- Drag-and-drop not supported (use Select button instead)

### Technical Details
- Built with Dioxus 0.7 desktop
- Uses ferrocrypt-lib for all encryption operations
- Native file dialogs via rfd crate
- Asset management via manganis
