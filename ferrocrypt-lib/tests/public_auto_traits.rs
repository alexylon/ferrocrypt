//! Compile-time pin: every exported type stays `Send + Sync`.
//!
//! The compiler grants and withdraws these auto-traits silently from a
//! type's contents, and callers (the desktop app among them) move
//! operations onto worker threads, so thread portability is part of the
//! public contract. Several exported types wrap private enums that are
//! documented to grow — a future variant holding a thread-bound value
//! (for example a hardware-key handle) would strip `Send`/`Sync` from
//! the wrapper without any library test failing. This file is an
//! external-style consumer: if an exported type loses either trait, the
//! test suite stops compiling and the loss becomes a deliberate
//! decision. Thread-bound sources belong behind a separate API type.
//!
//! A hand-written list would cover only the types someone remembered to
//! add, so `pinned_list_matches_the_crate_exports` reads `src/lib.rs` and
//! compares it against the list below. A newly exported type fails that
//! test by name instead of going silently unpinned.

use std::collections::BTreeSet;

fn assert_send_sync<T: Send + Sync>() {}

/// Names each exported type once. The macro emits both the `Send + Sync`
/// assertion and the string used to compare the list against `lib.rs`,
/// so the two can never fall out of step with each other.
macro_rules! pinned_types {
    ($($name:ident),+ $(,)?) => {
        const PINNED: &[&str] = &[$(stringify!($name)),+];

        #[test]
        fn public_api_is_send_and_sync() {
            $(assert_send_sync::<ferrocrypt::$name>();)+
        }
    };
}

pinned_types![
    Encryptor,
    Decryptor,
    PassphraseDecryptor,
    PrivateKeyDecryptor,
    KeyPairGenerator,
    PublicKey,
    PrivateKey,
    Passphrase,
    CryptoError,
    FormatDefect,
    UnsupportedVersion,
    InvalidKdfParams,
    EncryptOutcome,
    DecryptOutcome,
    KeyGenOutcome,
    ProgressEvent,
    UnauthenticatedRecipientMode,
    AuthenticatedRecipientMode,
    AuthenticatedRecipientModeKind,
    KdfParams,
    KdfLimit,
    ArchiveLimits,
    HeaderReadLimits,
    KeyReadLimits,
    MixingPolicy,
    IncompleteOutputPolicy,
];

/// Exported types that are deliberately not `Send + Sync`. Adding a name
/// here is the record of that decision and needs a reason beside it.
const EXEMPT: &[&str] = &[];

#[test]
fn pinned_list_matches_the_crate_exports() {
    let source = include_str!("../src/lib.rs");
    let exported = exported_type_names(source);

    // A glob re-export would hide types from the scan, and the hidden ones
    // would go unpinned without any comparison below failing. A private
    // `use super::*;` inside a test module is not a re-export and is fine.
    let globs: Vec<&str> = source
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("pub use ") && line.contains('*'))
        .collect();
    assert!(
        globs.is_empty(),
        "lib.rs gained a glob re-export ({globs:?}); the scan cannot see the \
         names it brings in, so list them explicitly instead"
    );

    let unpinned: Vec<&str> = exported
        .iter()
        .map(String::as_str)
        .filter(|name| !PINNED.contains(name) && !EXEMPT.contains(name))
        .collect();
    assert!(
        unpinned.is_empty(),
        "exported but not pinned Send + Sync: {unpinned:?} — add each to \
         `pinned_types!`, or to `EXEMPT` with the reason it is thread-bound"
    );

    let stale: Vec<&&str> = PINNED
        .iter()
        .filter(|name| !exported.contains(**name))
        .collect();
    assert!(
        stale.is_empty(),
        "pinned but no longer exported: {stale:?} — drop each from \
         `pinned_types!`"
    );
}

/// Positive control for the scan: pins that it reads every shape `lib.rs`
/// uses. A scan that stopped matching would be caught either way — every
/// pinned name would then read as no longer exported — but this says which
/// shape broke.
#[test]
fn the_scan_reads_every_re_export_shape() {
    let sample = "\
pub use crate::a::{Alpha, Beta};
pub use crate::b::Gamma;
pub use crate::c::Delta as Epsilon;
pub use crate::d::{
    Zeta,
    LOUD_CONSTANT,
    lowercase_function,
};
pub const NOT_A_TYPE: u8 = 0;
pub fn also_not_a_type() {}
pub mod nor_this;
pub struct Eta {
pub enum Theta {
";
    let expected: BTreeSet<String> = ["Alpha", "Beta", "Gamma", "Epsilon", "Zeta", "Eta", "Theta"]
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    assert_eq!(exported_type_names(sample), expected);
}

/// Collects the type names the crate root exports, by scanning `lib.rs`
/// for `pub use` re-exports and for `pub struct` / `pub enum` items
/// defined there. Functions and modules start lowercase and constants are
/// upper case throughout; neither carries auto traits, so both are
/// skipped.
fn exported_type_names(source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut inside_braced_use = false;

    for line in source.lines() {
        let line = line.trim();

        if inside_braced_use {
            let (items, ends) = match line.find('}') {
                Some(end) => (&line[..end], true),
                None => (line, false),
            };
            items.split(',').for_each(|item| collect(item, &mut names));
            inside_braced_use = !ends;
        } else if let Some(rest) = line.strip_prefix("pub use ") {
            match (rest.find('{'), rest.rfind('}')) {
                (Some(open), Some(close)) => rest[open + 1..close]
                    .split(',')
                    .for_each(|item| collect(item, &mut names)),
                (Some(open), None) => {
                    rest[open + 1..]
                        .split(',')
                        .for_each(|item| collect(item, &mut names));
                    inside_braced_use = true;
                }
                _ => collect(
                    rest.trim_end_matches(';').rsplit("::").next().unwrap_or(""),
                    &mut names,
                ),
            }
        } else if let Some(rest) = line
            .strip_prefix("pub struct ")
            .or_else(|| line.strip_prefix("pub enum "))
        {
            collect(rest, &mut names);
        }
    }

    names
}

/// Takes the identifier `raw` exports and keeps it only if it names a
/// type: an upper-case first letter with at least one lower-case letter
/// after it, which excludes `SCREAMING_CASE` constants. For a renaming
/// re-export the exported name is the one after `as`.
fn collect(raw: &str, out: &mut BTreeSet<String>) {
    let raw = raw.trim();
    let raw = raw.rsplit(" as ").next().unwrap_or(raw);
    let name: String = raw
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    let starts_upper = name.starts_with(|c: char| c.is_ascii_uppercase());
    if starts_upper && name.contains(|c: char| c.is_ascii_lowercase()) {
        out.insert(name);
    }
}
