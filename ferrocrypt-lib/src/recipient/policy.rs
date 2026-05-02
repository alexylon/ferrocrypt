//! Mixing-rule enforcement, native-scheme classification, and the
//! `NativeRecipientType` registry.
//!
//! Native classification and mixing enforcement are kept together because
//! adding a native recipient type requires coordinated updates to both.
//!
//! ## Two layers
//!
//! - `NativeMixingRule` (`pub(crate)`) is the **internal enforcement
//!   representation**. Each native recipient type declares one as a
//!   compile-time constant. The enum has two structurally-distinct
//!   shapes: `SingleEntry` (the type must appear alone, no class) and
//!   `Class { name }` (multiple entries of the same class may coexist).
//!   By construction, a single-entry rule has no class to compare, so
//!   the cardinality and class-equality enforcement modes are mutually
//!   exclusive at the type level.
//! - [`MixingPolicy`] (`pub`) is the **public diagnostic projection** of
//!   the rule, surfaced via [`CryptoError::IncompatibleRecipients`] so
//!   callers can pattern-match on the cause without parsing the message.
//!   New compatibility classes show up as
//!   [`MixingPolicy::Custom { compatibility_class }`](MixingPolicy::Custom)
//!   and do not require a new public enum variant.

use crate::CryptoError;
use crate::error::FormatDefect;
use crate::recipient::entry::RecipientEntry;
use crate::recipient::native::{argon2id, x25519};

/// Registered native recipient types supported by this implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeRecipientType {
    /// Passphrase recipient. See [`crate::recipient::native::argon2id`].
    Argon2id,
    /// X25519 public-key recipient. See [`crate::recipient::native::x25519`].
    X25519,
}

impl NativeRecipientType {
    /// Looks up a recipient `type_name` in the native registry.
    ///
    /// Returns `None` for unrecognised names. Per `FORMAT.md` §3.4,
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

    /// Recipient-mixing rule for this native type, per `FORMAT.md` §3.5.
    /// Used by [`enforce_recipient_mixing_policy`] before any recipient
    /// unwrap or KDF runs. Adding a new native type means adding one arm
    /// here — the rest of the mixing-enforcement machinery is registry-
    /// driven and does not need editing.
    pub(crate) const fn mixing_rule(self) -> NativeMixingRule {
        match self {
            Self::Argon2id => NativeMixingRule::exclusive(),
            Self::X25519 => NativeMixingRule::public_key_mixable(),
        }
    }

    /// Native [`crate::EncryptionMode`] for this type. Used by
    /// [`classify_encryption_mode`] to pick the file's mode without a
    /// second closed list of `has_*` booleans. Adding a new native type
    /// means adding one arm here.
    pub(crate) const fn encryption_mode(self) -> crate::EncryptionMode {
        match self {
            Self::Argon2id => crate::EncryptionMode::Passphrase,
            Self::X25519 => crate::EncryptionMode::Recipient,
        }
    }
}

/// Public diagnostic category for a recipient mixing rule, surfaced
/// through [`CryptoError::IncompatibleRecipients`].
///
/// This is intentionally not the full internal enforcement representation
/// — that is the crate-private `NativeMixingRule` type, which can express
/// new native compatibility classes without adding public enum variants.
/// [`MixingPolicy::Custom`] is the catch-all for compatibility classes
/// that do not match the two fixed shorthand variants below; the
/// associated `compatibility_class` string preserves which class the
/// offending rule declared, so programmatic diagnostics can distinguish
/// (for example) a post-quantum class clash from any future custom class.
///
/// The enum is `#[non_exhaustive]` so future native rules can be added
/// without a breaking API change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MixingPolicy {
    /// This recipient must appear alone — not mixed with any other
    /// entry, including unknown non-critical ones. Currently:
    /// `argon2id`.
    Exclusive,
    /// Standard public-key mixability: multiple recipients of this
    /// type are permitted, alongside other public-key recipients in
    /// the same compatibility class. Currently: `x25519`.
    PublicKeyMixable,
    /// A recipient-specific compatibility class not represented by the
    /// fixed shorthand variants above. The `compatibility_class` field
    /// carries the class identifier the offending rule declared so a
    /// caller can distinguish — for example — a post-quantum class
    /// clash (`"postquantum"`) from a future custom class.
    Custom {
        /// Class identifier as declared by the recipient type's
        /// crate-private mixing rule. Stable per native type within a
        /// release; not part of the wire format and never appears on
        /// disk.
        compatibility_class: &'static str,
    },
}

/// Internal native-recipient mixing rule, per `FORMAT.md` §3.5.
///
/// The enum has two structurally-distinct shapes — a single-entry rule
/// has no compatibility class at all, so a class comparison cannot
/// accidentally treat two single-entry rules as compatible. Cardinality
/// (single-entry) and class equality are mutually exclusive enforcement
/// modes by construction.
///
/// `NativeMixingRule` is `pub(crate)` because it is the enforcement plane;
/// public diagnostics surface as [`MixingPolicy`] (the projection
/// returned by [`Self::diagnostic_policy`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeMixingRule {
    /// The recipient type must be the only entry in the file (counting
    /// unknown non-critical entries too, per `FORMAT.md` §4.1). There
    /// is no compatibility class because a single-entry rule by
    /// definition cannot coexist with anything. Currently: `argon2id`.
    SingleEntry,
    /// The recipient type may coexist with other entries declaring the
    /// same compatibility class. Two `Class` rules are compatible iff
    /// their `name` fields are exactly equal. Currently: `x25519`
    /// declares `Class { name: PUBLIC_KEY_CLASS }`; the upcoming
    /// `x25519-mlkem768` would declare
    /// `Class { name: POST_QUANTUM_CLASS }`.
    Class {
        /// Compatibility-class identifier, fixed per native recipient
        /// type and never appearing on the wire.
        name: &'static str,
    },
}

impl NativeMixingRule {
    /// Class for ordinary public-key recipients that share an
    /// unconstrained compatibility group.
    pub(crate) const PUBLIC_KEY_CLASS: &'static str = "public-key";

    /// Class for native post-quantum or hybrid-PQ recipients (reserved
    /// for the upcoming `x25519-mlkem768` recipient type and any future
    /// native PQ recipient sharing the same compatibility class).
    #[allow(dead_code)] // referenced by the upcoming PQ recipient PR
    pub(crate) const POST_QUANTUM_CLASS: &'static str = "postquantum";

    /// `argon2id`-style rule: the type must be the only entry in the
    /// file. Diagnostic projection is [`MixingPolicy::Exclusive`].
    pub(crate) const fn exclusive() -> Self {
        Self::SingleEntry
    }

    /// `x25519`-style rule: ordinary public-key compatibility class,
    /// no cardinality constraint. Diagnostic projection is
    /// [`MixingPolicy::PublicKeyMixable`].
    pub(crate) const fn public_key_mixable() -> Self {
        Self::Class {
            name: Self::PUBLIC_KEY_CLASS,
        }
    }

    /// Future native PQ / hybrid-PQ rule: post-quantum compatibility
    /// class, no cardinality constraint. Diagnostic projection is
    /// [`MixingPolicy::Custom { compatibility_class: "postquantum" }`].
    #[allow(dead_code)] // referenced by the upcoming PQ recipient PR
    pub(crate) const fn post_quantum() -> Self {
        Self::Class {
            name: Self::POST_QUANTUM_CLASS,
        }
    }

    /// `true` iff this rule requires the recipient to be the only
    /// entry in the file.
    pub(crate) const fn requires_single_entry(self) -> bool {
        matches!(self, Self::SingleEntry)
    }

    /// Public-API diagnostic projection of this rule. Used by
    /// [`CryptoError::IncompatibleRecipients`] so callers can pattern-
    /// match on the cause without inspecting the internal enum.
    pub(crate) fn diagnostic_policy(self) -> MixingPolicy {
        match self {
            Self::SingleEntry => MixingPolicy::Exclusive,
            Self::Class { name } if name == Self::PUBLIC_KEY_CLASS => {
                MixingPolicy::PublicKeyMixable
            }
            Self::Class { name } => MixingPolicy::Custom {
                compatibility_class: name,
            },
        }
    }
}

/// Enforces recipient-mixing rules across a parsed entry list, per
/// `FORMAT.md` §3.5.
///
/// Returns `Ok(())` if the list satisfies every supported native mixing
/// rule; otherwise returns a typed [`CryptoError::IncompatibleRecipients`]
/// carrying the offending `type_name` and the rule's diagnostic
/// [`MixingPolicy`] projection.
///
/// This must run before any recipient unwrap, especially before the
/// Argon2id KDF for `argon2id`, so an invalid mixed-recipient file
/// cannot force work that policy would reject.
///
/// Rules:
///
/// 1. Cardinality. Any entry whose native rule is
///    [`NativeMixingRule::SingleEntry`] (today only `argon2id`) MUST
///    appear as the only entry in the file — counting unknown
///    non-critical entries too, per `FORMAT.md` §4.1. A second
///    same-type entry, a different native entry, or any unknown
///    non-critical entry alongside it is a violation.
///
/// 2. Compatibility class. Two supported [`NativeMixingRule::Class`]
///    rules are compatible iff their `name` fields are exactly equal.
///    Unknown non-critical entries are skipped for the class
///    comparison (they are forward-compatibility filler, not
///    enforcement subjects). Unknown critical entries are rejected
///    upstream by [`classify_encryption_mode`] before this function
///    can matter.
///
/// On a class clash the reported `(type_name, policy)` favours the
/// stricter / non-`PublicKeyMixable` side so the diagnostic identifies
/// the recipient with the more specific compatibility class. The error
/// shape carries one `type_name`, not both sides; the
/// [`MixingPolicy::Custom`] variant additionally carries the offending
/// rule's compatibility-class string so programmatic consumers can
/// distinguish, for example, post-quantum from any future custom class.
pub fn enforce_recipient_mixing_policy(entries: &[RecipientEntry]) -> Result<(), CryptoError> {
    // The mixing-rule table on `NativeRecipientType::mixing_rule` is the
    // single source of truth. Adding a new native type means adding one
    // arm there; this function does not need to be edited.
    let mut control: Option<(&RecipientEntry, NativeMixingRule)> = None;
    for entry in entries {
        let Some(ty) = NativeRecipientType::from_type_name(&entry.type_name) else {
            // Unknown non-critical entries are skipped here. Critical
            // unknowns were rejected by `classify_encryption_mode`
            // before this function ran.
            continue;
        };
        let rule = ty.mixing_rule();

        if rule.requires_single_entry() && entries.len() != 1 {
            return Err(CryptoError::IncompatibleRecipients {
                type_name: entry.type_name.clone(),
                policy: rule.diagnostic_policy(),
            });
        }

        match control {
            None => control = Some((entry, rule)),
            Some((first_entry, first_rule)) => match (first_rule, rule) {
                // Same compatibility class: compatible. Control stays
                // on the first entry so a third clashing entry is
                // still reported against the original.
                (NativeMixingRule::Class { name: a }, NativeMixingRule::Class { name: b })
                    if a == b => {}
                // Class clash: prefer the stricter / non-PublicKeyMixable
                // side for the diagnostic so the reported `type_name`
                // identifies the recipient with the more specific
                // compatibility class.
                (NativeMixingRule::Class { .. }, NativeMixingRule::Class { .. }) => {
                    let (reported_entry, reported_rule) =
                        if rule.diagnostic_policy() != MixingPolicy::PublicKeyMixable {
                            (entry, rule)
                        } else {
                            (first_entry, first_rule)
                        };
                    return Err(CryptoError::IncompatibleRecipients {
                        type_name: reported_entry.type_name.clone(),
                        policy: reported_rule.diagnostic_policy(),
                    });
                }
                // A `SingleEntry` rule on either side cannot reach this
                // arm: the cardinality check at the start of each
                // iteration rejects any single-entry rule whenever
                // `entries.len() != 1`, and we only enter the
                // class-comparison arm when a previous entry has
                // already been processed (so `entries.len() >= 2`).
                // Fail closed if the invariant ever breaks instead of
                // accepting silently.
                (NativeMixingRule::SingleEntry, _) | (_, NativeMixingRule::SingleEntry) => {
                    return Err(CryptoError::InternalInvariant(
                        "single-entry rule reached class comparison",
                    ));
                }
            },
        }
    }
    Ok(())
}

/// Classifies a parsed recipient list into the file's
/// [`crate::EncryptionMode`]. Returns an error for any list that does
/// not yield a unique mode.
///
/// This scans the **entire** list rather than only the first entry —
/// future valid files may place unknown non-critical recipients before
/// a supported native recipient, and a classifier that looked at only
/// the first entry would misclassify those.
///
/// Order of checks:
/// 1. For each entry, reject either a known native entry whose
///    `recipient_flags != 0` (per `FORMAT.md` §3.4: "Native `argon2id`
///    and `x25519` entries MUST have `recipient_flags = 0`") with
///    [`CryptoError::InvalidFormat`] /
///    [`FormatDefect::MalformedRecipientEntry`], or an unknown critical
///    entry with [`CryptoError::UnknownCriticalRecipient`]. Reserved
///    bits 1..=15 are already rejected at parse time
///    (`RECIPIENT_FLAGS_RESERVED_MASK`), so by the time this runs only
///    bit 0 (critical) can be set among the flags.
/// 2. Run [`enforce_recipient_mixing_policy`] (cardinality + class).
/// 3. For each supported native entry, look up
///    [`NativeRecipientType::encryption_mode`]; the file's mode is the
///    common value across all supported entries.
/// 4. If two supported native entries declare different modes the file
///    is rejected (currently unreachable — the cardinality check on
///    `argon2id` already forbids cross-mode mixes — but the branch is
///    kept fail-closed in case a future native type breaks the
///    one-class-implies-one-mode assumption).
/// 5. If no supported native entry is present (only unknown non-critical
///    entries) → [`CryptoError::NoSupportedRecipient`].
///
/// This is structural classification only. The caller still has to
/// run the appropriate per-recipient unwrap and the header MAC verify
/// before accepting any candidate `file_key`.
pub fn classify_encryption_mode(
    entries: &[RecipientEntry],
) -> Result<crate::EncryptionMode, CryptoError> {
    // Step 1: per-entry flag rejection. A reader MUST refuse to process
    // a file that either declares an unknown entry it cannot skip, or
    // tags a known native entry with a non-zero flag. Both checks ride
    // the same iteration so the rejection fires before any KDF.
    for entry in entries {
        match NativeRecipientType::from_type_name(&entry.type_name) {
            Some(_native) => {
                if entry.recipient_flags != 0 {
                    return Err(CryptoError::InvalidFormat(
                        FormatDefect::MalformedRecipientEntry,
                    ));
                }
            }
            None => {
                if entry.is_critical() {
                    return Err(CryptoError::UnknownCriticalRecipient {
                        type_name: entry.type_name.clone(),
                    });
                }
            }
        }
    }

    // Step 2: enforce mixing rules before any KDF/unwrap could run.
    enforce_recipient_mixing_policy(entries)?;

    // Step 3 / 4: registry-driven mode classification. Walk the entry
    // list once, look up `encryption_mode()` per supported native type,
    // and confirm every supported entry agrees on a single mode.
    let mut mode: Option<crate::EncryptionMode> = None;
    for entry in entries {
        let Some(ty) = NativeRecipientType::from_type_name(&entry.type_name) else {
            continue;
        };
        let entry_mode = ty.encryption_mode();
        match mode {
            None => mode = Some(entry_mode),
            Some(existing) if existing == entry_mode => {}
            Some(_) => {
                // Cross-mode native mix slipped past
                // `enforce_recipient_mixing_policy`. Currently
                // unreachable (argon2id's cardinality forbids it); kept
                // fail-closed as defense-in-depth for future native
                // types whose class might span modes.
                return Err(CryptoError::IncompatibleRecipients {
                    type_name: entry.type_name.clone(),
                    policy: ty.mixing_rule().diagnostic_policy(),
                });
            }
        }
    }

    // Step 5: no supported native recipient. Unknown non-critical
    // entries cannot decrypt the file on their own.
    mode.ok_or(CryptoError::NoSupportedRecipient)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FormatDefect;
    use crate::recipient::entry::RECIPIENT_FLAG_CRITICAL;

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
    fn mixing_rule_per_native_type() {
        // argon2id: SingleEntry — diagnostic projection `Exclusive`.
        // The variant carries no class field, so two argon2id rules
        // cannot have a "matching class" by accident.
        let argon = NativeRecipientType::Argon2id.mixing_rule();
        assert_eq!(argon, NativeMixingRule::SingleEntry);
        assert!(argon.requires_single_entry());
        assert_eq!(argon.diagnostic_policy(), MixingPolicy::Exclusive);

        // x25519: Class { name: PUBLIC_KEY_CLASS }, no cardinality,
        // diagnostic projection `PublicKeyMixable`.
        let x = NativeRecipientType::X25519.mixing_rule();
        assert_eq!(
            x,
            NativeMixingRule::Class {
                name: NativeMixingRule::PUBLIC_KEY_CLASS,
            }
        );
        assert!(!x.requires_single_entry());
        assert_eq!(x.diagnostic_policy(), MixingPolicy::PublicKeyMixable);
    }

    /// Confirm the [`NativeMixingRule::post_quantum`] / [`NativeMixingRule::POST_QUANTUM_CLASS`]
    /// constants project to the documented public diagnostic shape.
    /// Locks in the `Custom { compatibility_class: "postquantum" }`
    /// wording so the upcoming `x25519-mlkem768` recipient PR does not
    /// silently drift the class identifier.
    #[test]
    fn post_quantum_rule_projects_to_custom_diagnostic() {
        let rule = NativeMixingRule::post_quantum();
        assert_eq!(
            rule,
            NativeMixingRule::Class {
                name: NativeMixingRule::POST_QUANTUM_CLASS,
            }
        );
        assert!(!rule.requires_single_entry());
        assert_eq!(
            rule.diagnostic_policy(),
            MixingPolicy::Custom {
                compatibility_class: NativeMixingRule::POST_QUANTUM_CLASS,
            }
        );
    }

    /// Native registry's [`NativeRecipientType::encryption_mode`]
    /// must agree with what `classify_encryption_mode` emits for
    /// single-recipient lists. Locks in the registry as the single
    /// source of truth for mode classification (the classifier no
    /// longer hard-codes `argon2id` / `x25519` type-name strings).
    #[test]
    fn encryption_mode_per_native_type() {
        assert_eq!(
            NativeRecipientType::Argon2id.encryption_mode(),
            crate::EncryptionMode::Passphrase
        );
        assert_eq!(
            NativeRecipientType::X25519.encryption_mode(),
            crate::EncryptionMode::Recipient
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

    /// Helper: assert `err` is the `IncompatibleRecipients` variant
    /// naming `argon2id` with the `Exclusive` policy.
    fn assert_argon2id_mixing_violation(err: CryptoError) {
        match err {
            CryptoError::IncompatibleRecipients { type_name, policy } => {
                assert_eq!(type_name, argon2id::TYPE_NAME);
                assert_eq!(policy, MixingPolicy::Exclusive);
            }
            other => panic!("expected IncompatibleRecipients(argon2id, Exclusive), got {other:?}"),
        }
    }

    #[test]
    fn enforce_mixing_rejects_argon2id_plus_x25519() {
        let err = enforce_recipient_mixing_policy(&[argon2id_entry(), x25519_entry()]).unwrap_err();
        assert_argon2id_mixing_violation(err);
    }

    /// Reverse-order companion of
    /// [`enforce_mixing_rejects_argon2id_plus_x25519`]: place the
    /// `x25519` entry first so the cardinality check fires on the
    /// SECOND iteration. The error must still name `argon2id`
    /// (not `x25519`) — the cardinality check on the single-entry
    /// rule is what trips, regardless of iteration position.
    #[test]
    fn enforce_mixing_rejects_x25519_plus_argon2id() {
        let err = enforce_recipient_mixing_policy(&[x25519_entry(), argon2id_entry()]).unwrap_err();
        assert_argon2id_mixing_violation(err);
    }

    #[test]
    fn enforce_mixing_rejects_two_argon2ids() {
        // argon2id is Exclusive — even another argon2id is a violation.
        // Without this case the "exactly one" guarantee is implicit; the
        // test makes it explicit.
        let err =
            enforce_recipient_mixing_policy(&[argon2id_entry(), argon2id_entry()]).unwrap_err();
        assert_argon2id_mixing_violation(err);
    }

    #[test]
    fn classify_rejects_two_argon2ids() {
        let err = classify_encryption_mode(&[argon2id_entry(), argon2id_entry()]).unwrap_err();
        assert_argon2id_mixing_violation(err);
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
        assert_argon2id_mixing_violation(err);
    }

    #[test]
    fn classify_returns_symmetric_for_lone_argon2id() {
        let mode = classify_encryption_mode(&[argon2id_entry()]).unwrap();
        assert_eq!(mode, crate::EncryptionMode::Passphrase);
    }

    #[test]
    fn classify_returns_hybrid_for_x25519() {
        let mode = classify_encryption_mode(&[x25519_entry()]).unwrap();
        assert_eq!(mode, crate::EncryptionMode::Recipient);
    }

    #[test]
    fn classify_returns_hybrid_for_multiple_x25519() {
        let mode = classify_encryption_mode(&[x25519_entry(), x25519_entry()]).unwrap();
        assert_eq!(mode, crate::EncryptionMode::Recipient);
    }

    #[test]
    fn classify_skips_unknown_non_critical_in_front_of_x25519() {
        // Forward-compat: a future file may put unknown non-critical
        // entries before a supported native entry. Classification must
        // not look only at the first slot.
        let mode =
            classify_encryption_mode(&[unknown_entry("future-thing", false), x25519_entry()])
                .unwrap();
        assert_eq!(mode, crate::EncryptionMode::Recipient);
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
    fn classify_rejects_argon2id_mixed_via_incompatible_recipients() {
        let err = classify_encryption_mode(&[argon2id_entry(), x25519_entry()]).unwrap_err();
        assert_argon2id_mixing_violation(err);
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

    /// FORMAT.md §3.4 mandates `recipient_flags = 0` on native
    /// `argon2id` and `x25519` entries. A native entry with the
    /// critical bit set is structurally malformed and must be rejected
    /// at classify time — not just inside `protocol::decrypt`'s slot
    /// loop — so `detect_encryption_mode` and the cross-mode mismatch
    /// path both surface the typed `MalformedRecipientEntry` rather
    /// than misroute the file.
    #[test]
    fn classify_rejects_native_argon2id_with_critical_bit() {
        let bad = RecipientEntry {
            type_name: argon2id::TYPE_NAME.to_owned(),
            recipient_flags: RECIPIENT_FLAG_CRITICAL,
            body: vec![0u8; argon2id::BODY_LENGTH],
        };
        let err = classify_encryption_mode(&[bad]).unwrap_err();
        match err {
            CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry) => {}
            other => {
                panic!(
                    "expected MalformedRecipientEntry for native argon2id+critical, got {other:?}"
                )
            }
        }
    }

    /// Companion of [`classify_rejects_native_argon2id_with_critical_bit`]
    /// for the `x25519` native type — same `FORMAT.md` §3.4 rule.
    #[test]
    fn classify_rejects_native_x25519_with_critical_bit() {
        let bad = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_owned(),
            recipient_flags: RECIPIENT_FLAG_CRITICAL,
            body: vec![0u8; x25519::BODY_LENGTH],
        };
        let err = classify_encryption_mode(&[bad]).unwrap_err();
        match err {
            CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry) => {}
            other => {
                panic!("expected MalformedRecipientEntry for native x25519+critical, got {other:?}")
            }
        }
    }

    /// When BOTH a native-flags violation AND an unknown-critical entry
    /// are present, the file is rejected. Either rejection is correct
    /// per `FORMAT.md` §3.4; the test asserts only the rejection, not
    /// which diagnostic surfaces first, so a future refactor of the
    /// per-entry walk is not constrained by a non-spec ordering
    /// invariant. The single-violation cases above pin the precise
    /// diagnostic per case.
    #[test]
    fn classify_rejects_when_native_critical_and_unknown_critical_both_present() {
        let bad_native = RecipientEntry {
            type_name: x25519::TYPE_NAME.to_owned(),
            recipient_flags: RECIPIENT_FLAG_CRITICAL,
            body: vec![0u8; x25519::BODY_LENGTH],
        };
        let unknown_crit = unknown_entry("future-critical", true);
        let err = classify_encryption_mode(&[bad_native, unknown_crit]).unwrap_err();
        match err {
            CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)
            | CryptoError::UnknownCriticalRecipient { .. } => {}
            other => panic!(
                "expected MalformedRecipientEntry or UnknownCriticalRecipient when both violations present, got {other:?}"
            ),
        }
    }
}
