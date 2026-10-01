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
//!   parsing, the `private.key` signature check, passphrase-wrapped
//!   secret encryption/decryption, private-key TLV validation after
//!   authentication, and the [`PrivateKey`] wrapper for the public-key
//!   decrypt path.
//! - [`files`] — filesystem-level key helpers: the canonical
//!   `public.key` / `private.key` default filenames, the cheap check that
//!   recognizes a `public.key` by its first bytes, and the read both
//!   private-key readers start with.
//! - [`limits`] — [`KeyReadLimits`], the caller-facing local caps on
//!   recipient-string length and `private.key` wrapped-secret length.
//!
//! [`PublicKey`]: crate::PublicKey
//! [`PrivateKey`]: crate::PrivateKey
//! [`KeyReadLimits`]: crate::KeyReadLimits

pub(crate) mod files;
pub(crate) mod limits;
pub(crate) mod private;
pub(crate) mod public;
