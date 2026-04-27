//! FerroCrypt v1 recipient layer.
//!
//! Per `FORMAT.md` §3.5, a recipient entry is an independently framed
//! method for recovering the per-file `file_key`. Two native v1
//! recipient types are defined:
//!
//! - [`argon2id`] — passphrase-based, exclusive (must be the only entry
//!   in a file per `FORMAT.md` §4.1 mixing rule).
//! - [`x25519`] — X25519 public-key, public-key-mixable.
//!
//! The generic recipient framing (length-prefixed entries with the
//! type-name grammar in `FORMAT.md` §3.3) lives in this module — see
//! [`RecipientEntry`] and [`parse_recipient_entries`]. The cryptographic
//! body of each native recipient type lives in its own submodule.
//! Callers dispatch on [`NativeRecipientType`] after the header parser
//! has matched a `type_name` against the registry.
//!
//! ## Type-name namespace
//!
//! Per `FORMAT.md` §3.3.1, native recipient type names are short names
//! without `/`. Plugin and third-party types MUST use a fully qualified
//! name containing `/` (e.g. `example.com/enigma`). Native-name
//! prefixes `mlkem`, `pq`, `hpke`, `tag`, `xwing`, `kem` and any name
//! ending in `tag` are reserved for future FerroCrypt-defined recipient
//! types. Plugin registries MUST reject such names.
//!
//! ## Recipient-entry framing
//!
//! Each entry on the wire is
//! `type_name_len:u16 || recipient_flags:u16 || body_len:u32 ||
//! type_name:N || body:M` (`FORMAT.md` §3.5). The framing layer here
//! owns: 8-byte header parsing, structural bounds, reserved-flag-bit
//! enforcement, type-name grammar validation, and the local body-size
//! resource cap. The body itself is opaque to this layer; per-recipient
//! modules ([`argon2id`], [`x25519`]) parse and operate on body bytes.

pub mod argon2id;
pub mod x25519;

use crate::CryptoError;
use crate::error::FormatDefect;
use crate::format::BODY_LEN_MAX;

/// Registered native v1 recipient types. Adding a variant here is a
/// deliberate breaking change inside the crate: every `match` on
/// [`NativeRecipientType`] becomes a compile error until the new variant
/// is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeRecipientType {
    /// Passphrase recipient. See [`argon2id`].
    Argon2id,
    /// X25519 public-key recipient. See [`x25519`].
    X25519,
}

impl NativeRecipientType {
    /// Looks up a `type_name` against the v1 native recipient registry.
    /// Returns `None` for unrecognised names. Per `FORMAT.md` §3.4
    /// non-critical unknown recipients are skipped by callers; critical
    /// unknown recipients cause file rejection.
    pub fn from_type_name(name: &str) -> Option<Self> {
        match name {
            argon2id::TYPE_NAME => Some(Self::Argon2id),
            x25519::TYPE_NAME => Some(Self::X25519),
            _ => None,
        }
    }

    /// Wire-format type name for this variant.
    pub const fn type_name(self) -> &'static str {
        match self {
            Self::Argon2id => argon2id::TYPE_NAME,
            Self::X25519 => x25519::TYPE_NAME,
        }
    }

    /// Recipient body length (in bytes) for this variant.
    pub const fn body_len(self) -> usize {
        match self {
            Self::Argon2id => argon2id::BODY_LENGTH,
            Self::X25519 => x25519::BODY_LENGTH,
        }
    }

    /// Recipient-mixing rule for this native type, per `FORMAT.md` §3.4.
    /// Used by [`enforce_recipient_mixing_policy`] before any
    /// recipient unwrap or KDF runs.
    pub const fn mixing_policy(self) -> MixingPolicy {
        match self {
            // argon2id is exclusive: a passphrase recipient cannot be
            // mixed with anything else, not even another argon2id slot
            // or an unknown non-critical entry.
            Self::Argon2id => MixingPolicy::Exclusive,
            // x25519 admits multiple x25519 slots in the same file.
            Self::X25519 => MixingPolicy::PublicKeyMixable,
        }
    }
}

/// Mixing rule for a native recipient type, per `FORMAT.md` §3.4.
///
/// Applied before recipient unwrap so a hostile mixed file cannot
/// trick the reader into running an expensive KDF unnecessarily.
///
/// Only the variants required by v1 native types are defined.
/// Future native types whose policy doesn't fit either variant
/// will extend this enum (it is `#[non_exhaustive]`); v1 readers
/// will then need to handle the new variant explicitly via
/// [`enforce_recipient_mixing_policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MixingPolicy {
    /// This recipient must appear alone — not mixed with any other
    /// entry, including unknown non-critical ones. Currently:
    /// `argon2id`.
    Exclusive,
    /// Standard public-key mixability: multiple recipients of this
    /// type are permitted, alongside other public-key recipients.
    /// Currently: `x25519`.
    PublicKeyMixable,
}

/// Maximum byte length of a recipient `type_name`
/// (`FORMAT.md` §3.3, `type_name_len:u16` constrained to `1..=255`).
pub const TYPE_NAME_MAX_LEN: usize = 255;

/// Validates a recipient `type_name` against the grammar in
/// `FORMAT.md` §3.3:
///
/// - 1..=255 bytes;
/// - lowercase ASCII;
/// - allowed characters: `a-z 0-9 . _ + - /`;
/// - no leading or trailing `.`, `_`, `+`, `-`, `/`;
/// - no `..` or `//`.
///
/// On failure surfaces [`crate::error::FormatDefect::MalformedTypeName`].
pub fn validate_type_name(name: &str) -> Result<(), CryptoError> {
    let malformed = || CryptoError::InvalidFormat(FormatDefect::MalformedTypeName);
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > TYPE_NAME_MAX_LEN {
        return Err(malformed());
    }
    for &b in bytes {
        let allowed = matches!(
            b,
            b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'+' | b'-' | b'/'
        );
        if !allowed {
            return Err(malformed());
        }
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    for &edge in &[first, last] {
        if matches!(edge, b'.' | b'_' | b'+' | b'-' | b'/') {
            return Err(malformed());
        }
    }
    for window in bytes.windows(2) {
        if window == b".." || window == b"//" {
            return Err(malformed());
        }
    }
    Ok(())
}

/// On-wire size of a recipient-entry header (`type_name_len:u16 ||
/// recipient_flags:u16 || body_len:u32`), per `FORMAT.md` §3.5.
pub const ENTRY_HEADER_SIZE: usize = 8;

/// Bit 0 of `recipient_flags`. When set, an unknown recipient type
/// MUST cause file rejection (`FORMAT.md` §3.4); when clear, an unknown
/// recipient is skipped.
pub const RECIPIENT_FLAG_CRITICAL: u16 = 1 << 0;

/// Mask of all `recipient_flags` bits other than
/// [`RECIPIENT_FLAG_CRITICAL`]. Per `FORMAT.md` §3.5, these MUST be
/// zero on the wire; readers reject any entry with a reserved bit set.
pub const RECIPIENT_FLAGS_RESERVED_MASK: u16 = !RECIPIENT_FLAG_CRITICAL;

/// A parsed recipient entry per `FORMAT.md` §3.5. Owns its
/// `type_name` (validated against the §3.3 grammar) and `body` (opaque
/// to the framing layer; per-recipient modules parse the body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientEntry {
    /// Canonical recipient `type_name`, e.g. `"argon2id"` or `"x25519"`.
    pub type_name: String,
    /// `recipient_flags` field as stored on the wire. The only defined
    /// bit in v1 is [`RECIPIENT_FLAG_CRITICAL`]; reserved bits are
    /// rejected at parse time.
    pub recipient_flags: u16,
    /// Recipient body bytes. Length matches the on-wire `body_len`
    /// field; structural bounds and the local resource cap are checked
    /// at parse time.
    pub body: Vec<u8>,
}

impl RecipientEntry {
    /// Constructs a `RecipientEntry` for a native v1 recipient type
    /// from a body produced by the corresponding per-recipient `wrap`
    /// helper (e.g. [`argon2id::wrap`] or [`x25519::wrap`]).
    ///
    /// The `type_name` is taken from the `NativeRecipientType` so
    /// callers cannot accidentally construct an entry with a typo'd
    /// or off-spec name. The body length is checked against the
    /// type's expected `body_len()`. Native entries default to
    /// `recipient_flags = 0` (non-critical); critical bit is reserved
    /// for plugin / opt-in semantics that v1 native types do not use.
    pub fn native(ty: NativeRecipientType, body: Vec<u8>) -> Result<Self, CryptoError> {
        if body.len() != ty.body_len() {
            return Err(CryptoError::InvalidFormat(
                FormatDefect::MalformedRecipientEntry,
            ));
        }
        Ok(Self {
            type_name: ty.type_name().to_owned(),
            recipient_flags: 0,
            body,
        })
    }

    /// Returns `true` if [`RECIPIENT_FLAG_CRITICAL`] is set. Per
    /// `FORMAT.md` §3.4, unknown critical entries MUST cause file
    /// rejection; unknown non-critical entries are skipped.
    pub const fn is_critical(&self) -> bool {
        (self.recipient_flags & RECIPIENT_FLAG_CRITICAL) != 0
    }

    /// Serialises this entry as `type_name_len(2) || recipient_flags(2)
    /// || body_len(4) || type_name || body`. Casts assume the entry was
    /// constructed from a valid native call site (`type_name.len() <=
    /// TYPE_NAME_MAX_LEN`, `body.len() <= BODY_LEN_MAX as usize`),
    /// which holds for every native call path in this crate.
    pub fn to_bytes(&self) -> Vec<u8> {
        let type_name_len = self.type_name.len();
        let body_len = self.body.len();
        let mut out = Vec::with_capacity(ENTRY_HEADER_SIZE + type_name_len + body_len);
        out.extend_from_slice(&(type_name_len as u16).to_be_bytes());
        out.extend_from_slice(&self.recipient_flags.to_be_bytes());
        out.extend_from_slice(&(body_len as u32).to_be_bytes());
        out.extend_from_slice(self.type_name.as_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    /// Parses one recipient entry from the start of `bytes`. Returns
    /// the parsed entry and the number of bytes consumed
    /// (`ENTRY_HEADER_SIZE + type_name_len + body_len`).
    ///
    /// Validates per `FORMAT.md` §3.5 in cheap-to-expensive order:
    /// header is large enough, length fields are in range, reserved
    /// flag bits are zero, body is within the local resource cap, the
    /// declared total fits in `bytes`, and the `type_name` satisfies
    /// the §3.3 grammar.
    pub fn parse_one(bytes: &[u8], local_body_cap: u32) -> Result<(Self, usize), CryptoError> {
        let malformed = || CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry);
        if bytes.len() < ENTRY_HEADER_SIZE {
            return Err(malformed());
        }
        let type_name_len = u16::from_be_bytes([bytes[0], bytes[1]]);
        let recipient_flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        let body_len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        if type_name_len == 0 || type_name_len as usize > TYPE_NAME_MAX_LEN {
            return Err(malformed());
        }
        if body_len > BODY_LEN_MAX {
            return Err(malformed());
        }
        if (recipient_flags & RECIPIENT_FLAGS_RESERVED_MASK) != 0 {
            return Err(CryptoError::InvalidFormat(
                FormatDefect::RecipientFlagsReserved,
            ));
        }
        if body_len > local_body_cap {
            return Err(CryptoError::RecipientBodyCapExceeded {
                body_len,
                local_cap: local_body_cap,
            });
        }

        let type_name_end = ENTRY_HEADER_SIZE
            .checked_add(type_name_len as usize)
            .ok_or_else(malformed)?;
        let total = type_name_end
            .checked_add(body_len as usize)
            .ok_or_else(malformed)?;
        if bytes.len() < total {
            return Err(malformed());
        }

        let type_name_bytes = &bytes[ENTRY_HEADER_SIZE..type_name_end];
        let type_name = std::str::from_utf8(type_name_bytes)
            .map_err(|_| CryptoError::InvalidFormat(FormatDefect::MalformedTypeName))?;
        validate_type_name(type_name)?;

        let body = bytes[type_name_end..total].to_vec();

        Ok((
            Self {
                type_name: type_name.to_owned(),
                recipient_flags,
                body,
            },
            total,
        ))
    }
}

/// Parses a contiguous `recipient_entries` region containing exactly
/// `expected_count` entries. The region length MUST equal the sum of
/// per-entry sizes — trailing or unaccounted bytes surface as
/// [`FormatDefect::MalformedRecipientEntry`].
///
/// `local_body_cap` is forwarded to each [`RecipientEntry::parse_one`]
/// call. Per `FORMAT.md` §3.5, the local cap applies to every entry,
/// including unknown entries that will later be skipped, so an
/// attacker-supplied unknown entry cannot DoS a reader that "skips" it.
pub fn parse_recipient_entries(
    region: &[u8],
    expected_count: u16,
    local_body_cap: u32,
) -> Result<Vec<RecipientEntry>, CryptoError> {
    let mut entries = Vec::with_capacity(expected_count as usize);
    let mut offset = 0usize;
    for _ in 0..expected_count {
        let (entry, consumed) = RecipientEntry::parse_one(&region[offset..], local_body_cap)?;
        entries.push(entry);
        offset += consumed;
    }
    if offset != region.len() {
        return Err(CryptoError::InvalidFormat(
            FormatDefect::MalformedRecipientEntry,
        ));
    }
    Ok(entries)
}

/// Enforces the v1 recipient-mixing policy across a parsed entry list,
/// per `FORMAT.md` §3.4. Returns immediately if the rule is satisfied;
/// otherwise returns a typed error.
///
/// This MUST be called BEFORE running any recipient unwrap (especially
/// the Argon2id KDF on `argon2id`), so a hostile mixed-recipient file
/// cannot force expensive cryptographic work that the policy would
/// have rejected anyway.
///
/// Rule: `argon2id` is [`MixingPolicy::Exclusive`]. If any entry is
/// `argon2id` AND the list has more than one entry — *including a
/// second `argon2id` entry, an `x25519` entry, or any unknown non-
/// critical entry* — fail with
/// [`CryptoError::PassphraseRecipientMixed`].
///
/// All other combinations are allowed at this layer; finer
/// classification (no supported recipient, only-unknown-non-critical,
/// etc.) is the job of [`classify_encryption_mode`].
///
/// Unknown critical entries are NOT rejected here. They are rejected
/// inside [`classify_encryption_mode`] before classification commits.
pub fn enforce_recipient_mixing_policy(entries: &[RecipientEntry]) -> Result<(), CryptoError> {
    // The policy table on `NativeRecipientType` is the single source of
    // truth: every native type declares its mixing rule via
    // `mixing_policy()`, and adding a new native variant forces this
    // function to handle it (the `MixingPolicy` enum is
    // `#[non_exhaustive]`, so a new variant produces a compile error
    // here until the new arm is wired in).
    for entry in entries {
        let Some(ty) = NativeRecipientType::from_type_name(&entry.type_name) else {
            continue;
        };
        match ty.mixing_policy() {
            MixingPolicy::Exclusive => {
                if entries.len() != 1 {
                    return Err(CryptoError::PassphraseRecipientMixed);
                }
            }
            MixingPolicy::PublicKeyMixable => {}
        }
    }
    Ok(())
}

/// Classifies a parsed recipient list as either `Symmetric` (one
/// `argon2id` recipient, alone) or `Hybrid` (one or more supported
/// `x25519` recipients with no `argon2id`). Returns an error for any
/// list that does not fit into one of those two modes.
///
/// Per `FORMAT.md` §3.4 / §3.5, this scans the **entire** list rather
/// than only the first entry — future valid files may place unknown
/// non-critical recipients before a supported native recipient, and a
/// classifier that looked at only the first entry would misclassify
/// those.
///
/// Order of checks:
/// 1. Reject any unknown **critical** entry with
///    [`CryptoError::UnknownCriticalRecipient`].
/// 2. Run [`enforce_recipient_mixing_policy`] (`argon2id` is exclusive).
/// 3. Exactly one `argon2id` (alone) → [`crate::EncryptionMode::Symmetric`].
/// 4. One or more supported `x25519` (and no `argon2id`) →
///    [`crate::EncryptionMode::Hybrid`].
/// 5. Otherwise (no supported native recipient and no unknown
///    critical) → [`CryptoError::NoSupportedRecipient`].
///
/// This is structural classification only. The caller still has to
/// run the appropriate per-recipient unwrap and the header MAC verify
/// before accepting any candidate `file_key`.
pub fn classify_encryption_mode(
    entries: &[RecipientEntry],
) -> Result<crate::EncryptionMode, CryptoError> {
    // Step 1: reject unknown critical entries up front. A reader MUST
    // refuse to process a file that declares it cannot be skipped.
    for entry in entries {
        if NativeRecipientType::from_type_name(&entry.type_name).is_none() && entry.is_critical() {
            return Err(CryptoError::UnknownCriticalRecipient {
                type_name: entry.type_name.clone(),
            });
        }
    }

    // Step 2: enforce mixing policy before any KDF/unwrap could run.
    enforce_recipient_mixing_policy(entries)?;

    // Step 3 / 4: native classification.
    let has_argon2id = entries.iter().any(|e| e.type_name == argon2id::TYPE_NAME);
    let has_supported_x25519 = entries.iter().any(|e| e.type_name == x25519::TYPE_NAME);

    if has_argon2id {
        // `enforce_recipient_mixing_policy` already guaranteed the
        // list is exactly `[argon2id]`.
        return Ok(crate::EncryptionMode::Symmetric);
    }
    if has_supported_x25519 {
        return Ok(crate::EncryptionMode::Hybrid);
    }

    // Step 5: no supported native recipient. Unknown non-critical
    // entries cannot decrypt the file on their own.
    Err(CryptoError::NoSupportedRecipient)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_recipient_type_round_trips_through_type_name() {
        assert_eq!(
            NativeRecipientType::from_type_name(argon2id::TYPE_NAME),
            Some(NativeRecipientType::Argon2id)
        );
        assert_eq!(
            NativeRecipientType::from_type_name(x25519::TYPE_NAME),
            Some(NativeRecipientType::X25519)
        );
        assert_eq!(
            NativeRecipientType::Argon2id.type_name(),
            argon2id::TYPE_NAME
        );
        assert_eq!(NativeRecipientType::X25519.type_name(), x25519::TYPE_NAME);
    }

    #[test]
    fn known_recipient_type_returns_none_for_unknown_names() {
        assert_eq!(NativeRecipientType::from_type_name("scrypt"), None);
        assert_eq!(NativeRecipientType::from_type_name("foo"), None);
        assert_eq!(NativeRecipientType::from_type_name(""), None);
        assert_eq!(NativeRecipientType::from_type_name("argon2"), None); // close but not exact
    }

    #[test]
    fn body_length_matches_per_type() {
        assert_eq!(
            NativeRecipientType::Argon2id.body_len(),
            argon2id::BODY_LENGTH
        );
        assert_eq!(NativeRecipientType::X25519.body_len(), x25519::BODY_LENGTH);
    }

    #[test]
    fn mixing_policy_per_native_type() {
        // argon2id MUST be Exclusive — passphrase recipients cannot
        // mix with anything per FORMAT.md §3.4.
        assert_eq!(
            NativeRecipientType::Argon2id.mixing_policy(),
            MixingPolicy::Exclusive
        );
        // x25519 admits multiple x25519 slots in the same file.
        assert_eq!(
            NativeRecipientType::X25519.mixing_policy(),
            MixingPolicy::PublicKeyMixable
        );
    }

    fn argon2id_entry() -> RecipientEntry {
        RecipientEntry::native(
            NativeRecipientType::Argon2id,
            vec![0u8; argon2id::BODY_LENGTH],
        )
        .unwrap()
    }

    fn x25519_entry() -> RecipientEntry {
        RecipientEntry::native(NativeRecipientType::X25519, vec![0u8; x25519::BODY_LENGTH]).unwrap()
    }

    fn unknown_entry(name: &str, critical: bool) -> RecipientEntry {
        RecipientEntry {
            type_name: name.to_string(),
            recipient_flags: if critical { RECIPIENT_FLAG_CRITICAL } else { 0 },
            body: vec![0u8; 8],
        }
    }

    #[test]
    fn native_constructor_rejects_wrong_body_length() {
        let err =
            RecipientEntry::native(NativeRecipientType::Argon2id, vec![0u8; 100]).unwrap_err();
        match err {
            CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry) => {}
            other => panic!("expected MalformedRecipientEntry, got {other:?}"),
        }
    }

    #[test]
    fn native_constructor_sets_canonical_type_name_and_zero_flags() {
        let entry = argon2id_entry();
        assert_eq!(entry.type_name, argon2id::TYPE_NAME);
        assert_eq!(entry.recipient_flags, 0);
        assert!(!entry.is_critical());
    }

    #[test]
    fn enforce_mixing_accepts_lone_argon2id() {
        enforce_recipient_mixing_policy(&[argon2id_entry()]).unwrap();
    }

    #[test]
    fn enforce_mixing_accepts_multiple_x25519() {
        enforce_recipient_mixing_policy(&[x25519_entry(), x25519_entry()]).unwrap();
    }

    #[test]
    fn enforce_mixing_rejects_argon2id_plus_x25519() {
        let err = enforce_recipient_mixing_policy(&[argon2id_entry(), x25519_entry()]).unwrap_err();
        assert!(matches!(err, CryptoError::PassphraseRecipientMixed));
    }

    #[test]
    fn enforce_mixing_rejects_two_argon2ids() {
        // argon2id is Exclusive — even another argon2id is a violation.
        // Without this case the "exactly one" guarantee is implicit; the
        // test makes it explicit.
        let err =
            enforce_recipient_mixing_policy(&[argon2id_entry(), argon2id_entry()]).unwrap_err();
        assert!(matches!(err, CryptoError::PassphraseRecipientMixed));
    }

    #[test]
    fn classify_rejects_two_argon2ids() {
        let err = classify_encryption_mode(&[argon2id_entry(), argon2id_entry()]).unwrap_err();
        assert!(matches!(err, CryptoError::PassphraseRecipientMixed));
    }

    #[test]
    fn enforce_mixing_rejects_argon2id_plus_unknown_non_critical() {
        // Per FORMAT.md §3.4 (and the plan), even an unknown
        // non-critical entry alongside argon2id is a mixing violation.
        let err = enforce_recipient_mixing_policy(&[
            argon2id_entry(),
            unknown_entry("future-thing", false),
        ])
        .unwrap_err();
        assert!(matches!(err, CryptoError::PassphraseRecipientMixed));
    }

    #[test]
    fn classify_returns_symmetric_for_lone_argon2id() {
        let mode = classify_encryption_mode(&[argon2id_entry()]).unwrap();
        assert_eq!(mode, crate::EncryptionMode::Symmetric);
    }

    #[test]
    fn classify_returns_hybrid_for_x25519() {
        let mode = classify_encryption_mode(&[x25519_entry()]).unwrap();
        assert_eq!(mode, crate::EncryptionMode::Hybrid);
    }

    #[test]
    fn classify_returns_hybrid_for_multiple_x25519() {
        let mode = classify_encryption_mode(&[x25519_entry(), x25519_entry()]).unwrap();
        assert_eq!(mode, crate::EncryptionMode::Hybrid);
    }

    #[test]
    fn classify_skips_unknown_non_critical_in_front_of_x25519() {
        // Forward-compat: a future file may put unknown non-critical
        // entries before a supported native entry. Classification must
        // not look only at the first slot.
        let mode =
            classify_encryption_mode(&[unknown_entry("future-thing", false), x25519_entry()])
                .unwrap();
        assert_eq!(mode, crate::EncryptionMode::Hybrid);
    }

    #[test]
    fn classify_rejects_unknown_critical() {
        let err =
            classify_encryption_mode(&[unknown_entry("must-handle-me", true), x25519_entry()])
                .unwrap_err();
        match err {
            CryptoError::UnknownCriticalRecipient { type_name } => {
                assert_eq!(type_name, "must-handle-me");
            }
            other => panic!("expected UnknownCriticalRecipient, got {other:?}"),
        }
    }

    #[test]
    fn classify_rejects_argon2id_mixed_via_passphrase_recipient_mixed() {
        let err = classify_encryption_mode(&[argon2id_entry(), x25519_entry()]).unwrap_err();
        assert!(matches!(err, CryptoError::PassphraseRecipientMixed));
    }

    #[test]
    fn classify_rejects_only_unknown_non_critical_with_no_supported_recipient() {
        let err = classify_encryption_mode(&[unknown_entry("future-thing", false)]).unwrap_err();
        assert!(matches!(err, CryptoError::NoSupportedRecipient));
    }

    #[test]
    fn classify_rejects_empty_entry_list_with_no_supported_recipient() {
        // A zero-recipient header is structurally rejected upstream
        // (HeaderFixed validates recipient_count >= 1), but the
        // classifier must still answer something sensible if called
        // with an empty slice. NoSupportedRecipient is the right class.
        let err = classify_encryption_mode(&[]).unwrap_err();
        assert!(matches!(err, CryptoError::NoSupportedRecipient));
    }

    #[test]
    fn validate_type_name_accepts_canonical_natives() {
        validate_type_name(argon2id::TYPE_NAME).unwrap();
        validate_type_name(x25519::TYPE_NAME).unwrap();
    }

    #[test]
    fn validate_type_name_accepts_fqn_plugin_names() {
        validate_type_name("example.com/enigma").unwrap();
        validate_type_name("com.example/foo").unwrap();
        validate_type_name("a.b.c/d").unwrap();
    }

    #[test]
    fn validate_type_name_rejects_empty() {
        match validate_type_name("") {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for empty, got {other:?}"),
        }
    }

    #[test]
    fn validate_type_name_rejects_overlong() {
        let long = "a".repeat(256);
        match validate_type_name(&long) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for 256-byte name, got {other:?}"),
        }
    }

    #[test]
    fn validate_type_name_accepts_max_length() {
        let max = "a".repeat(255);
        validate_type_name(&max).unwrap();
    }

    #[test]
    fn validate_type_name_rejects_uppercase() {
        match validate_type_name("Argon2id") {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for uppercase, got {other:?}"),
        }
    }

    #[test]
    fn validate_type_name_rejects_invalid_characters() {
        for bad in &["foo bar", "foo!", "foo:bar", "foo*", "foo\nbar"] {
            match validate_type_name(bad) {
                Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
                other => panic!("expected MalformedTypeName for `{bad}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_type_name_rejects_edge_punctuation() {
        for bad in &[
            ".foo", "_foo", "+foo", "-foo", "/foo", "foo.", "foo_", "foo+", "foo-", "foo/",
        ] {
            match validate_type_name(bad) {
                Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
                other => panic!("expected MalformedTypeName for `{bad}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_type_name_rejects_consecutive_punctuation() {
        for bad in &["foo..bar", "foo//bar", "a.b..c", "a/b//c"] {
            match validate_type_name(bad) {
                Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
                other => panic!("expected MalformedTypeName for `{bad}`, got {other:?}"),
            }
        }
    }

    // ─── Recipient-entry framing ───────────────────────────────────────────

    use crate::format::BODY_LEN_LOCAL_CAP_DEFAULT;

    /// Builds a raw 8-byte entry header so tests can inject arbitrary
    /// out-of-spec values without going through `RecipientEntry::to_bytes`.
    fn entry_header(type_name_len: u16, recipient_flags: u16, body_len: u32) -> [u8; 8] {
        let mut hdr = [0u8; ENTRY_HEADER_SIZE];
        hdr[0..2].copy_from_slice(&type_name_len.to_be_bytes());
        hdr[2..4].copy_from_slice(&recipient_flags.to_be_bytes());
        hdr[4..8].copy_from_slice(&body_len.to_be_bytes());
        hdr
    }

    #[test]
    fn recipient_entry_round_trips_minimal_x25519() {
        let entry = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_owned(),
            recipient_flags: 0,
            body: vec![0xAB; x25519::BODY_LENGTH],
        };
        let bytes = entry.to_bytes();
        let (parsed, consumed) =
            RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed, entry);
        assert!(!parsed.is_critical());
    }

    #[test]
    fn recipient_entry_round_trips_with_critical_flag() {
        let entry = RecipientEntry {
            type_name: argon2id::TYPE_NAME.to_owned(),
            recipient_flags: RECIPIENT_FLAG_CRITICAL,
            body: vec![0u8; argon2id::BODY_LENGTH],
        };
        let bytes = entry.to_bytes();
        let (parsed, _) = RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(parsed, entry);
        assert!(parsed.is_critical());
    }

    #[test]
    fn recipient_entry_to_bytes_layout_matches_spec() {
        let entry = RecipientEntry {
            type_name: "x25519".to_owned(),
            recipient_flags: RECIPIENT_FLAG_CRITICAL,
            body: vec![0xCD, 0xEF],
        };
        let bytes = entry.to_bytes();
        // type_name_len = 6
        assert_eq!(&bytes[0..2], &6u16.to_be_bytes());
        // recipient_flags = 1
        assert_eq!(&bytes[2..4], &1u16.to_be_bytes());
        // body_len = 2
        assert_eq!(&bytes[4..8], &2u32.to_be_bytes());
        // type_name bytes
        assert_eq!(&bytes[8..14], b"x25519");
        // body bytes
        assert_eq!(&bytes[14..16], &[0xCD, 0xEF]);
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn parse_one_rejects_truncated_header() {
        let bytes = [0u8; ENTRY_HEADER_SIZE - 1];
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => panic!("expected MalformedRecipientEntry for short header, got {other:?}"),
        }
    }

    #[test]
    fn parse_one_rejects_zero_type_name_len() {
        let bytes = entry_header(0, 0, 0);
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => {
                panic!("expected MalformedRecipientEntry for zero type_name_len, got {other:?}")
            }
        }
    }

    #[test]
    fn parse_one_rejects_overlong_type_name_len() {
        let bytes = entry_header((TYPE_NAME_MAX_LEN as u16) + 1, 0, 0);
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => {
                panic!("expected MalformedRecipientEntry for type_name_len=256, got {other:?}")
            }
        }
    }

    #[test]
    fn parse_one_rejects_body_above_structural_max() {
        // body_len = BODY_LEN_MAX + 1 must reject before any allocation
        // — local_body_cap = u32::MAX so the cap check cannot fire.
        let bytes = entry_header(6, 0, BODY_LEN_MAX + 1);
        match RecipientEntry::parse_one(&bytes, u32::MAX) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => panic!(
                "expected MalformedRecipientEntry for body_len > BODY_LEN_MAX, got {other:?}"
            ),
        }
    }

    #[test]
    fn parse_one_rejects_body_above_local_cap() {
        let oversized = BODY_LEN_LOCAL_CAP_DEFAULT + 1;
        let bytes = entry_header(6, 0, oversized);
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::RecipientBodyCapExceeded {
                body_len,
                local_cap,
            }) => {
                assert_eq!(body_len, oversized);
                assert_eq!(local_cap, BODY_LEN_LOCAL_CAP_DEFAULT);
            }
            other => panic!("expected RecipientBodyCapExceeded, got {other:?}"),
        }
    }

    #[test]
    fn parse_one_rejects_reserved_flag_bits() {
        // Bit 1 is reserved per FORMAT.md §3.5.
        let bytes = entry_header(6, 1u16 << 1, 0);
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::RecipientFlagsReserved)) => {}
            other => panic!("expected RecipientFlagsReserved, got {other:?}"),
        }
    }

    #[test]
    fn parse_one_rejects_each_reserved_bit() {
        // Every non-critical bit (1..=15) must be rejected individually.
        for bit in 1..16 {
            let bytes = entry_header(6, 1u16 << bit, 0);
            match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
                Err(CryptoError::InvalidFormat(FormatDefect::RecipientFlagsReserved)) => {}
                other => panic!("expected RecipientFlagsReserved for bit {bit}, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_one_rejects_entry_exceeding_remaining_bytes() {
        // Header claims 6-byte type_name + 100-byte body, but only the
        // header is provided.
        let bytes = entry_header(6, 0, 100);
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => panic!("expected MalformedRecipientEntry for entry > bytes, got {other:?}"),
        }
    }

    #[test]
    fn parse_one_rejects_malformed_type_name_grammar() {
        // Uppercase type_name violates the §3.3 grammar.
        let mut bytes = entry_header(6, 0, 0).to_vec();
        bytes.extend_from_slice(b"X25519");
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for uppercase, got {other:?}"),
        }
    }

    #[test]
    fn parse_one_rejects_non_utf8_type_name() {
        let mut bytes = entry_header(6, 0, 0).to_vec();
        bytes.extend_from_slice(&[0xFF; 6]);
        match RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedTypeName)) => {}
            other => panic!("expected MalformedTypeName for non-UTF8, got {other:?}"),
        }
    }

    #[test]
    fn parse_one_accepts_zero_body_len() {
        // Body length zero is structurally valid at the framing layer;
        // recipient modules enforce their own body-size invariants.
        let mut bytes = entry_header(6, 0, 0).to_vec();
        bytes.extend_from_slice(b"x25519");
        let (parsed, consumed) =
            RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.type_name, "x25519");
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn parse_one_consumes_only_declared_extent() {
        // When extra trailing bytes exist after the declared entry, the
        // parser returns the consumed length; trailing data is the
        // multi-entry parser's concern.
        let entry = RecipientEntry {
            type_name: "x25519".to_owned(),
            recipient_flags: 0,
            body: vec![0xAA, 0xBB],
        };
        let mut bytes = entry.to_bytes();
        let original_len = bytes.len();
        bytes.extend_from_slice(b"trailing");
        let (parsed, consumed) =
            RecipientEntry::parse_one(&bytes, BODY_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(consumed, original_len);
        assert_eq!(parsed, entry);
    }

    #[test]
    fn parse_recipient_entries_handles_zero_count_empty_region() {
        let parsed = parse_recipient_entries(&[], 0, BODY_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_recipient_entries_rejects_zero_count_with_trailing_bytes() {
        let bytes = [0u8; 4];
        match parse_recipient_entries(&bytes, 0, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => panic!("expected MalformedRecipientEntry, got {other:?}"),
        }
    }

    #[test]
    fn parse_recipient_entries_handles_single() {
        let entry = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_owned(),
            recipient_flags: 0,
            body: vec![0xCD; x25519::BODY_LENGTH],
        };
        let bytes = entry.to_bytes();
        let parsed = parse_recipient_entries(&bytes, 1, BODY_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(parsed, vec![entry]);
    }

    #[test]
    fn parse_recipient_entries_handles_multiple() {
        let e1 = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_owned(),
            recipient_flags: 0,
            body: vec![0xAB; x25519::BODY_LENGTH],
        };
        let e2 = RecipientEntry {
            type_name: argon2id::TYPE_NAME.to_owned(),
            recipient_flags: RECIPIENT_FLAG_CRITICAL,
            body: vec![0xCD; argon2id::BODY_LENGTH],
        };
        let mut bytes = e1.to_bytes();
        bytes.extend(e2.to_bytes());
        let parsed = parse_recipient_entries(&bytes, 2, BODY_LEN_LOCAL_CAP_DEFAULT).unwrap();
        assert_eq!(parsed, vec![e1, e2]);
    }

    #[test]
    fn parse_recipient_entries_rejects_count_below_actual_entries() {
        // Region contains 2 entries' worth of bytes, but caller claims 1.
        let e1 = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_owned(),
            recipient_flags: 0,
            body: vec![0xAB; x25519::BODY_LENGTH],
        };
        let e2 = RecipientEntry {
            type_name: argon2id::TYPE_NAME.to_owned(),
            recipient_flags: 0,
            body: vec![0xCD; argon2id::BODY_LENGTH],
        };
        let mut bytes = e1.to_bytes();
        bytes.extend(e2.to_bytes());
        match parse_recipient_entries(&bytes, 1, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => {
                panic!("expected MalformedRecipientEntry for trailing entry bytes, got {other:?}")
            }
        }
    }

    #[test]
    fn parse_recipient_entries_rejects_count_above_actual_entries() {
        // Region contains 1 entry but caller claims 2.
        let entry = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_owned(),
            recipient_flags: 0,
            body: vec![0xAB; x25519::BODY_LENGTH],
        };
        let bytes = entry.to_bytes();
        match parse_recipient_entries(&bytes, 2, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {}
            other => panic!("expected MalformedRecipientEntry for missing entries, got {other:?}"),
        }
    }

    #[test]
    fn parse_recipient_entries_propagates_per_entry_resource_cap() {
        // The cap applies to every entry, even ones the multi-entry
        // parser would otherwise skip past.
        let oversized = BODY_LEN_LOCAL_CAP_DEFAULT + 1;
        let mut bytes = entry_header(6, 0, oversized).to_vec();
        bytes.extend_from_slice(b"x25519");
        bytes.extend(std::iter::repeat_n(0u8, oversized as usize));
        match parse_recipient_entries(&bytes, 1, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::RecipientBodyCapExceeded { .. }) => {}
            other => panic!("expected RecipientBodyCapExceeded, got {other:?}"),
        }
    }

    #[test]
    fn parse_recipient_entries_handles_body_at_local_cap_boundary() {
        // body_len = local_cap is allowed (cap is inclusive).
        let cap = BODY_LEN_LOCAL_CAP_DEFAULT;
        let mut bytes = entry_header(6, 0, cap).to_vec();
        bytes.extend_from_slice(b"x25519");
        bytes.extend(std::iter::repeat_n(0xAAu8, cap as usize));
        let parsed = parse_recipient_entries(&bytes, 1, cap).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].body.len(), cap as usize);
    }

    #[test]
    fn parse_recipient_entries_propagates_structural_error_from_inner_entry() {
        // First entry parses cleanly; second has a reserved flag bit set.
        // The multi-entry parser MUST surface the inner error rather than
        // silently masking it as MalformedRecipientEntry.
        let e1 = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_owned(),
            recipient_flags: 0,
            body: vec![0xAB; x25519::BODY_LENGTH],
        };
        let mut bad_entry = entry_header(6, 1u16 << 1, 0).to_vec();
        bad_entry.extend_from_slice(b"x25519");
        let mut bytes = e1.to_bytes();
        bytes.extend(bad_entry);
        match parse_recipient_entries(&bytes, 2, BODY_LEN_LOCAL_CAP_DEFAULT) {
            Err(CryptoError::InvalidFormat(FormatDefect::RecipientFlagsReserved)) => {}
            other => panic!("expected RecipientFlagsReserved propagation, got {other:?}"),
        }
    }
}
