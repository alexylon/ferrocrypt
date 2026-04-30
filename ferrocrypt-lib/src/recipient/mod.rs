//! FerroCrypt v1 recipient layer.
//!
//! Per `FORMAT.md` §3.3, a recipient entry is an independently framed
//! method for recovering the per-file `file_key`. Two native v1
//! recipient types are defined:
//!
//! - [`native::argon2id`] — passphrase-based, exclusive (must be the
//!   only entry in a file per `FORMAT.md` §4.1 mixing rule).
//! - [`native::x25519`] — X25519 public-key, public-key-mixable.
//!
//! ## Module layout
//!
//! - [`entry`] — generic recipient framing (`type_name_len:u16 ||
//!   recipient_flags:u16 || body_len:u32 || type_name || body`),
//!   `RecipientEntry`, framing parser.
//! - [`name`] — `validate_type_name` and `TYPE_NAME_MAX_LEN` per
//!   `FORMAT.md` §3.3 grammar.
//! - [`policy`] — `NativeRecipientType` registry, `MixingPolicy`,
//!   `enforce_recipient_mixing_policy`, `classify_encryption_mode`.
//! - [`native`] — per-algorithm scheme implementations:
//!   [`native::argon2id`] and [`native::x25519`].
//!
//! ## Type-name namespace
//!
//! Per `FORMAT.md` §3.3.1, native recipient type names are short names
//! without `/`. Plugin and third-party types MUST use a fully qualified
//! name containing `/` (e.g. `example.com/enigma`). Native-name
//! prefixes `mlkem`, `pq`, `hpke`, `tag`, `xwing`, `kem` and any name
//! ending in `tag` are reserved for future FerroCrypt-defined recipient
//! types. The stable public API does not expose a third-party recipient plugin
//! registration surface.

pub mod entry;
pub mod name;
pub mod native;
pub mod policy;

pub use entry::{RecipientEntry, parse_recipient_entries};
pub use name::{TYPE_NAME_MAX_LEN, validate_type_name};
pub use native::{argon2id, x25519};
pub use policy::classify_encryption_mode;
