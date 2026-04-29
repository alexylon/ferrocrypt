//! Reusable cryptographic building blocks and typed secrets.
//!
//! Owns:
//!
//! - [`keys`] — file-key generation, payload/header subkey derivation,
//!   passphrase wrap-key derivation, and shared key-size constants.
//! - [`kdf`] — Argon2id parameter validation ([`kdf::KdfParams`]) and
//!   resource-cap policy ([`kdf::KdfLimit`]).
//! - [`hkdf`] — HKDF-SHA3-256 expansion helper.
//! - [`mac`] — HMAC-SHA3-256 helpers and constant-time 32-byte
//!   comparison.
//! - [`aead`] — XChaCha20-Poly1305 single-shot seal/open helpers used to
//!   wrap the per-file `file_key`.
//! - [`stream`] — STREAM-BE32 payload encryptor/decryptor adapters and
//!   chunk-size constants.
//! - [`tlv`] — authenticated TLV grammar validator (FORMAT.md §6).
//!
//! Recipient-specific HKDF info strings live with their recipient
//! schemes; header/payload labels live in [`keys`]; the private-key
//! wrap label lives with [`crate::key::private`].

pub(crate) mod aead;
pub(crate) mod hkdf;
pub(crate) mod kdf;
pub(crate) mod keys;
pub(crate) mod mac;
pub(crate) mod stream;
pub(crate) mod tlv;
