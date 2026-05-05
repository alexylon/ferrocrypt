//! Public and private key file formats.
//!
//! Owns:
//!
//! - [`public`] — Bech32 recipient string encoding/decoding, HRP
//!   validation, internal SHA3-256 checksum, canonical lowercase
//!   enforcement, public recipient fingerprinting, `public.key` text
//!   validation, and the [`PublicKey`] wrapper that abstracts over
//!   the source of public-key material.
//! - [`private`] — `private.key` binary layout, cleartext header
//!   parsing, passphrase-wrapped secret encryption/decryption,
//!   private-key TLV validation after authentication, and the
//!   [`PrivateKey`] wrapper for the recipient decrypt path.
//! - [`files`] — filesystem-level key helpers: the canonical
//!   `public.key` / `private.key` default filenames and the
//!   `KeyFileKind` heuristic that classifies a path as a public or
//!   private key file from a cheap byte sniff.
//!
//! [`PublicKey`]: crate::PublicKey
//! [`PrivateKey`]: crate::PrivateKey

pub(crate) mod files;
pub(crate) mod private;
pub(crate) mod public;
