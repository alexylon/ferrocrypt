//! Mixing-policy enforcement, native-scheme classification, and the
//! `NativeRecipientType` registry.
//!
//! Native classification and mixing policy always change together —
//! every new `NativeRecipientType` variant requires a coordinated edit
//! to its mixing policy and the classifier — so they live in one file
//! per `notes/STRUCTURE_PROPOSAL.md` §3.7.

use crate::CryptoError;
use crate::error::FormatDefect;
use crate::recipient::entry::RecipientEntry;
use crate::recipient::native::{argon2id, x25519};

/// Registered native v1 recipient types. Adding a variant here is a
/// deliberate breaking change inside the crate: every `match` on
/// [`NativeRecipientType`] becomes a compile error until the new variant
/// is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeRecipientType {
    /// Passphrase recipient. See [`crate::recipient::native::argon2id`].
    Argon2id,
    /// X25519 public-key recipient. See [`crate::recipient::native::x25519`].
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
/// will then need to handle the new variant explicitly when
/// enforcing the mixing policy across a parsed recipient list.
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

/// Classifies a parsed recipient list as either `Passphrase` (one
/// `argon2id` recipient, alone) or `Recipient` (one or more supported
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
/// 1. For each entry, reject either a known native entry whose
///    `recipient_flags != 0` (per `FORMAT.md` §3.4: "Native `argon2id`
///    and `x25519` entries MUST have `recipient_flags = 0`") with
///    [`CryptoError::InvalidFormat`] /
///    [`FormatDefect::MalformedRecipientEntry`], or an unknown critical
///    entry with [`CryptoError::UnknownCriticalRecipient`]. Reserved
///    bits 1..=15 are already rejected at parse time
///    (`RECIPIENT_FLAGS_RESERVED_MASK`), so by the time this runs only
///    bit 0 (critical) can be set among the flags.
/// 2. Run [`enforce_recipient_mixing_policy`] (`argon2id` is exclusive).
/// 3. Exactly one `argon2id` (alone) → [`crate::EncryptionMode::Passphrase`].
/// 4. One or more supported `x25519` (and no `argon2id`) →
///    [`crate::EncryptionMode::Recipient`].
/// 5. Otherwise (no supported native recipient and no unknown
///    critical) → [`CryptoError::NoSupportedRecipient`].
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

    // Step 2: enforce mixing policy before any KDF/unwrap could run.
    enforce_recipient_mixing_policy(entries)?;

    // Step 3 / 4: native classification.
    let has_argon2id = entries.iter().any(|e| e.type_name == argon2id::TYPE_NAME);
    let has_supported_x25519 = entries.iter().any(|e| e.type_name == x25519::TYPE_NAME);

    if has_argon2id {
        // `enforce_recipient_mixing_policy` already guaranteed the
        // list is exactly `[argon2id]`.
        return Ok(crate::EncryptionMode::Passphrase);
    }
    if has_supported_x25519 {
        return Ok(crate::EncryptionMode::Recipient);
    }

    // Step 5: no supported native recipient. Unknown non-critical
    // entries cannot decrypt the file on their own.
    Err(CryptoError::NoSupportedRecipient)
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
