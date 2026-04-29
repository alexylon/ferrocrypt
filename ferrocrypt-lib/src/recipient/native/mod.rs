//! Native v1 recipient schemes.
//!
//! - [`argon2id`] — passphrase recipient (`FORMAT.md` §4.1). Exclusive
//!   mixing policy: must appear alone.
//! - [`x25519`] — X25519 public-key recipient (`FORMAT.md` §4.2).
//!   Public-key-mixable: multiple `x25519` slots allowed in one file.
//!
//! Each scheme owns its body layout, body length, KDF/ECDH wrap-key
//! derivation, file-key seal/open, and scheme-specific validation.
//! Generic recipient framing (the `type_name_len || flags || body_len ||
//! type_name || body` envelope) lives in [`crate::recipient::entry`];
//! mixing-policy enforcement and classification live in
//! [`crate::recipient::policy`].

pub mod argon2id;
pub mod x25519;
