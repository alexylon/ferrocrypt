//! The `.fcr` check list of the §12.3 order row: the checks of `FORMAT.md`
//! §3.1 to §3.3, those of §3.7 up to the first recipient attempt, the
//! aggregate header-MAC cap, and the checks a credential decides, which the
//! claim covers only against the cap.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ferrocrypt_test_support::wire_manifest::{
    CAP_COLUMN_PREFIX, FCA_ARCHIVE_TLV_DOMAIN, FCA_ENTRY_TLV_DOMAIN, FCA_VERSION_DOMAIN,
    KEY_TYPE_DOMAIN, OUTER_TLV_DOMAIN, OUTER_VERSION_DOMAIN, PRIVATE_KEY_TLV_DOMAIN,
    PRIVATE_KEY_VERSION_DOMAIN, PUBLIC_KEY_VERSION_DOMAIN, RECIPIENT_TYPE_DOMAIN, capability_parts,
    field, limit_value, subject_version, table_columns,
};
use zeroize::Zeroizing;

use super::{
    CheckList, Direction, Evidence, Reach, Row, Span, corpus_root, limit_profiles, open_among,
    open_pairs, rejected_cases, stray_losses,
};
use crate::crypto::kdf::{KDF_PARAMS_SIZE, KdfLimit, KdfParams};
use crate::crypto::keys::{FILE_KEY_SIZE, FileKey, derive_subkeys};
use crate::crypto::stream::STREAM_NONCE_SIZE;
use crate::format::{
    BODY_LEN_MAX, EXT_LEN_MAX, FCR_FILE_V1_VERSION, HEADER_FIXED_EXT_LEN_OFFSET,
    HEADER_FIXED_FLAGS_OFFSET, HEADER_FIXED_RECIPIENT_COUNT_OFFSET,
    HEADER_FIXED_RECIPIENT_ENTRIES_LEN_OFFSET, HEADER_FIXED_SIZE, HEADER_FIXED_STREAM_NONCE_OFFSET,
    HEADER_LEN_MAX, HEADER_MAC_SIZE, KIND_ENCRYPTED, MAGIC, PREFIX_FLAGS_OFFSET,
    PREFIX_HEADER_LEN_OFFSET, PREFIX_KIND_OFFSET, PREFIX_SIZE, PREFIX_VERSION_OFFSET,
    RECIPIENT_COUNT_MAX, read_u16_be, read_u32_be, verify_header_mac,
};
use crate::key::files::read_private_key_bytes;
use crate::key::private::PrivateKeyHeader;
use crate::passphrase::Passphrase;
use crate::recipient::entry::{
    ENTRY_BODY_LEN_OFFSET, ENTRY_HEADER_SIZE, ENTRY_RECIPIENT_FLAGS_OFFSET,
    ENTRY_TYPE_NAME_LEN_OFFSET, RECIPIENT_FLAG_CRITICAL, RecipientEntry,
};
use crate::recipient::name::{TYPE_NAME_MAX_LEN, validate_type_name_grammar};
use crate::recipient::native::{argon2id, x25519};
use crate::recipient::policy::{NativeRecipientType, enforce_recipient_mixing_policy};
use crate::wire_vector_gen::{CorpusCredential, WALK_ORDER_CASE_PREFIX, read_credential};
use crate::{CryptoError, FormatDefect, HeaderReadLimits, KeyReadLimits};

/// One check of the `.fcr` list, in the order the specification fixes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Fcr {
    /// §3.1: the input is shorter than the 12-byte prefix.
    PrefixShort,
    /// §3.1: the magic is not `FCR\0`.
    Magic,
    /// §3.1: the kind is not the encrypted-file kind.
    Kind,
    /// §3.1: the outer-container version byte is `0x00`.
    VersionZero,
    /// §3.1: a nonzero outer-container version the reader does not support.
    VersionUnsupported,
    /// §3.1: `prefix_flags` is nonzero.
    PrefixFlags,
    /// §3.1: `header_len` is above the structural maximum.
    HeaderLenMax,
    /// §3.2 step 1: `header_len` is above the local cap.
    HeaderLenCap,
    /// §3.2 step 2: the declared header or the header MAC ends early.
    HeaderTruncated,
    /// §3.2 step 3: `header_len` cannot hold `header_fixed`.
    HeaderFixedShort,
    /// §3.2 step 4: `header_flags` is nonzero.
    HeaderFlags,
    /// §3.2 step 5: `recipient_count` is outside its range.
    RecipientCountRange,
    /// §3.2 step 6: `ext_len` is above its maximum.
    ExtLenMax,
    /// §3.2 step 7: the region lengths do not sum to `header_len`.
    LengthsSum,
    /// §3.2 step 8: `recipient_count` is above the local cap.
    RecipientCountCap,
    /// §3.3: the region ends inside an entry header.
    EntryHeaderShort,
    /// §3.3: `type_name_len` is outside `1..=255`.
    TypeNameLen,
    /// §3.3: `body_len` is above the structural maximum.
    BodyLenMax,
    /// §3.4, applied during the §3.3 parse: a reserved flag bit is set.
    FlagsReserved,
    /// §3.3: the entry runs past the region.
    EntryFit,
    /// §3.3: `body_len` is above the local cap.
    BodyLenCap,
    /// §3.3: the type name breaks the grammar.
    TypeNameGrammar,
    /// §3.3: bytes are left in the region after the last entry.
    TrailingBytes,
    /// §3.7 step 6: an unknown recipient type is critical.
    UnknownCritical,
    /// §3.7 step 8, framing pass: a native entry's flags are nonzero.
    NativeFlags,
    /// §3.7 step 8, framing pass: a native body has the wrong length.
    NativeLength,
    /// §3.7 step 8, content pass: `argon2id` KDF parameters are out of bounds.
    Argon2idContent,
    /// §3.7 step 8, content pass: an `x25519` ephemeral key is refused.
    X25519Content,
    /// §3.7 step 9: the recipient mix is illegal.
    Mixing,
    /// §3.7, between steps 9 and 10: the aggregate header-MAC work is above
    /// the local cap.
    HeaderMacWorkCap,
    /// §3.7 step 10: the file holds no supported recipient.
    NoSupportedRecipient,
    /// A local KDF cap on an `argon2id` recipient, applied right before its
    /// KDF.
    KdfCap,
    /// The supplied private key does not unlock.
    KeyUnlock,
    /// An `x25519` key agreement yields the all-zero shared secret.
    KeyAgreement,
    /// No `argon2id` recipient opens with the supplied passphrase.
    PassphraseUnwrap,
    /// No `x25519` recipient opens with the supplied private key.
    KeyUnwrap,
    /// Every recipient that opens fails the header MAC.
    HeaderMac,
}

use Fcr::*;

/// The checks a credential decides. The claim covers them only against the
/// cap, which must precede them all.
const TRYING: [Fcr; 6] = [
    KdfCap,
    KeyUnlock,
    KeyAgreement,
    PassphraseUnwrap,
    KeyUnwrap,
    HeaderMac,
];

/// The §3.7 checks made once per recipient entry.
const PER_ENTRY_STEPS: [Fcr; 5] = [
    UnknownCritical,
    NativeFlags,
    NativeLength,
    Argon2idContent,
    X25519Content,
];

/// The recipient-entry framing checks of §3.3, which §3.3 makes on each entry
/// before it reads the next.
const FRAMING: [Fcr; 7] = [
    EntryHeaderShort,
    TypeNameLen,
    BodyLenMax,
    FlagsReserved,
    EntryFit,
    BodyLenCap,
    TypeNameGrammar,
];

/// The direction group of the §3.3 checks.
const FRAMING_GROUP: usize = 0;

/// A pass of §3.3 and §3.7 over the recipient entries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Pass {
    /// §3.3: each entry through every framing check before the next.
    Framing,
    /// §3.7 step 6.
    UnknownCritical,
    /// §3.7 step 8, the framing checks.
    NativeFraming,
    /// §3.7 step 8, the content checks of one native type: §3.7 orders them
    /// by registry index whatever the order of the entries.
    Content(NativeRecipientType),
}

/// The pass a per-entry check belongs to, or none for a check made once per
/// file.
fn pass(check: Fcr) -> Option<Pass> {
    match check {
        _ if FRAMING.contains(&check) => Some(Pass::Framing),
        UnknownCritical => Some(Pass::UnknownCritical),
        NativeFlags | NativeLength => Some(Pass::NativeFraming),
        Argon2idContent => Some(Pass::Content(NativeRecipientType::Argon2id)),
        X25519Content => Some(Pass::Content(NativeRecipientType::X25519)),
        _ => None,
    }
}

/// Every native recipient type, in registry order.
const NATIVE_TYPES: [NativeRecipientType; 2] = {
    // A new type stops the build here until it is listed.
    match NativeRecipientType::Argon2id {
        NativeRecipientType::Argon2id | NativeRecipientType::X25519 => {}
    }
    [NativeRecipientType::Argon2id, NativeRecipientType::X25519]
};

/// The step-8 content check of a native type.
fn content_check(native: NativeRecipientType) -> Fcr {
    match native {
        NativeRecipientType::Argon2id => Argon2idContent,
        NativeRecipientType::X25519 => X25519Content,
    }
}

/// Whether one entry can break both per-entry checks, alone or with others,
/// under some reading.
fn one_entry_breaks_both(a: Fcr, b: Fcr) -> bool {
    let pair = |x: Fcr, y: Fcr| (a == x && b == y) || (a == y && b == x);
    let across = |xs: &[Fcr], ys: &[Fcr]| xs.iter().any(|&x| ys.iter().any(|&y| pair(x, y)));
    let native = [NativeFlags, NativeLength, Argon2idContent, X25519Content];
    let content = [Argon2idContent, X25519Content];
    // A native name has a legal length and grammar and a known type, a body's
    // content is read only at its type's length, and an entry has one type.
    !(across(&[TypeNameLen, TypeNameGrammar, UnknownCritical], &native)
        || across(&[BodyLenMax, NativeLength], &content)
        || pair(Argon2idContent, X25519Content))
}

/// Whether no file breaks both checks under any one reading.
fn exclusive(a: Fcr, b: Fcr) -> bool {
    let pair = |x: Fcr, y: Fcr| (a == x && b == y) || (a == y && b == x);
    let either = |one: Fcr| a == one || b == one;
    let other = |one: Fcr| if a == one { b } else { a };
    // The version is one byte, and a header above the structural maximum
    // holds `header_fixed`.
    if pair(VersionZero, VersionUnsupported) || pair(HeaderLenMax, HeaderFixedShort) {
        return true;
    }
    // An input shorter than the prefix has only prefix fields to break.
    if either(PrefixShort) {
        return ![Magic, Kind, VersionZero, VersionUnsupported, PrefixFlags]
            .contains(&other(PrefixShort));
    }
    // A file with no supported recipient has no native entry and none to
    // count.
    if either(NoSupportedRecipient) {
        return [
            NativeFlags,
            NativeLength,
            Argon2idContent,
            X25519Content,
            Mixing,
            HeaderMacWorkCap,
        ]
        .contains(&other(NoSupportedRecipient));
    }
    false
}

struct FcrList;

impl CheckList for FcrList {
    type Check = Fcr;

    fn order() -> &'static [Fcr] {
        &[
            PrefixShort,
            Magic,
            Kind,
            VersionZero,
            VersionUnsupported,
            PrefixFlags,
            HeaderLenMax,
            HeaderLenCap,
            HeaderTruncated,
            HeaderFixedShort,
            HeaderFlags,
            RecipientCountRange,
            ExtLenMax,
            LengthsSum,
            RecipientCountCap,
            EntryHeaderShort,
            TypeNameLen,
            BodyLenMax,
            FlagsReserved,
            EntryFit,
            BodyLenCap,
            TypeNameGrammar,
            TrailingBytes,
            UnknownCritical,
            NativeFlags,
            NativeLength,
            Argon2idContent,
            X25519Content,
            Mixing,
            HeaderMacWorkCap,
            NoSupportedRecipient,
            KdfCap,
            KeyUnlock,
            KeyAgreement,
            PassphraseUnwrap,
            KeyUnwrap,
            HeaderMac,
        ]
    }

    fn class(check: Fcr) -> &'static str {
        match check {
            PrefixShort | HeaderTruncated => "truncated",
            Magic => "bad_magic",
            Kind => "wrong_kind",
            VersionZero | PrefixFlags | HeaderFixedShort | HeaderFlags | LengthsSum => {
                "malformed_header"
            }
            VersionUnsupported => "unsupported_outer_version",
            HeaderLenMax => "oversized_header",
            HeaderLenCap | RecipientCountCap | BodyLenCap | HeaderMacWorkCap | KdfCap => {
                "resource_cap_exceeded"
            }
            RecipientCountRange => "recipient_count_out_of_range",
            ExtLenMax => "extension_region_too_large",
            EntryHeaderShort | TypeNameLen | BodyLenMax | EntryFit | TrailingBytes
            | NativeFlags | NativeLength | X25519Content | KeyAgreement => {
                "malformed_recipient_entry"
            }
            FlagsReserved => "recipient_flags_reserved",
            TypeNameGrammar => "malformed_type_name",
            UnknownCritical => "unknown_critical_recipient",
            Argon2idContent => "invalid_kdf_parameters",
            Mixing => "incompatible_recipients",
            NoSupportedRecipient => "no_supported_recipient",
            KeyUnlock => "private_key_unlock_failed",
            PassphraseUnwrap | KeyUnwrap => "recipient_unwrap_failed",
            HeaderMac => "header_authentication_failed",
        }
    }

    fn claimed(earlier: Fcr, later: Fcr) -> bool {
        if exclusive(earlier, later) {
            return false;
        }
        // After the preflight only the cap's place is claimed.
        !TRYING.contains(&later) || earlier == HeaderMacWorkCap
    }

    /// The §3.3 checks share a group, as §3.3 takes each entry through all of
    /// them before the next; every §3.7 per-entry check has a group of its own.
    const DIRECTION_GROUPS: usize = 1 + PER_ENTRY_STEPS.len();

    fn direction_group(check: Fcr) -> usize {
        PER_ENTRY_STEPS
            .iter()
            .position(|&step| step == check)
            .map_or(FRAMING_GROUP, |index| index + 1)
    }

    /// §3.3 finds each entry by reading the one before it, so its checks meet
    /// the entries front to back.
    fn directions(group: usize) -> &'static [Direction] {
        if group == FRAMING_GROUP {
            &[Direction::FrontToBack]
        } else {
            &Direction::BOTH
        }
    }

    /// The specification takes the checks of each per-entry pass one entry at
    /// a time, front to back, and makes every other check once.
    fn specification_report(broken: &[Break]) -> Option<&'static str> {
        for stage in Self::order().chunk_by(|a, b| pass(*a).is_some() && pass(*a) == pass(*b)) {
            let entries: BTreeSet<Option<usize>> = broken
                .iter()
                .filter(|(check, _)| stage.contains(check))
                .map(|(_, entry)| *entry)
                .collect();
            for entry in entries {
                if let Some(&check) = stage
                    .iter()
                    .find(|&&check| broken.contains(&(check, entry)))
                {
                    return Some(Self::class(check));
                }
            }
        }
        None
    }
}

/// What a reader declaring a capability supports beyond the native set.
#[derive(Default)]
struct Capabilities {
    outer_versions: BTreeSet<u8>,
    recipient_types: BTreeSet<String>,
}

impl Capabilities {
    /// The capabilities a reader declaring every capability of `run` has, and
    /// the checks of this list they change. A capability no check here reads,
    /// such as an FCA archive version inside the payload, changes none.
    fn declaring(run: &[String]) -> (Self, BTreeSet<Fcr>) {
        let mut capabilities = Self::default();
        let mut changed = BTreeSet::new();
        for capability_id in run {
            let (domain, subject) = capability_parts(capability_id)
                .unwrap_or_else(|| panic!("{capability_id}: not a capability ID"));
            match domain {
                OUTER_VERSION_DOMAIN => {
                    let version = subject_version(subject)
                        .unwrap_or_else(|| panic!("{capability_id}: not a version"));
                    capabilities.outer_versions.insert(version);
                    changed.insert(VersionUnsupported);
                }
                // A reader that supports a type also mixes and tries its
                // entries.
                RECIPIENT_TYPE_DOMAIN => {
                    capabilities.recipient_types.insert(subject.to_string());
                    changed.extend(
                        [
                            UnknownCritical,
                            NoSupportedRecipient,
                            Mixing,
                            HeaderMacWorkCap,
                        ]
                        .into_iter()
                        .chain(TRYING),
                    );
                }
                FCA_VERSION_DOMAIN
                | PUBLIC_KEY_VERSION_DOMAIN
                | PRIVATE_KEY_VERSION_DOMAIN
                | OUTER_TLV_DOMAIN
                | PRIVATE_KEY_TLV_DOMAIN
                | FCA_ARCHIVE_TLV_DOMAIN
                | FCA_ENTRY_TLV_DOMAIN
                | KEY_TYPE_DOMAIN => {}
                other => panic!("{capability_id}: unknown capability domain {other}"),
            }
        }
        (capabilities, changed)
    }

    fn supports(&self, type_name: &[u8]) -> bool {
        native_type(type_name).is_some()
            || std::str::from_utf8(type_name).is_ok_and(|name| self.recipient_types.contains(name))
    }
}

/// The native type `type_name` names, if any.
fn native_type(type_name: &[u8]) -> Option<NativeRecipientType> {
    std::str::from_utf8(type_name)
        .ok()
        .and_then(NativeRecipientType::from_type_name)
}

/// A check an artifact breaks, with the recipient entry it breaks on when the
/// check is made once per entry.
type Break = (Fcr, Option<usize>);

/// The checks an artifact breaks.
#[derive(Clone, Default)]
struct Breaks {
    /// Broken for every reader that makes the check first.
    certain: BTreeSet<Break>,
    /// Broken for some such readers only.
    uncertain: BTreeSet<Break>,
    /// Where readers that make a check on the entries met so far first meet
    /// it.
    reach: BTreeMap<Fcr, Reach>,
    /// The checks a credential breaks on whichever entry a reader tries
    /// first.
    first_try: BTreeSet<Fcr>,
}

impl Breaks {
    /// One artifact under several readings: a check every reading breaks for
    /// certain stays certain, and any other check a reading breaks is
    /// uncertain. For a check made on the entries met so far, the earliest
    /// stop is the earliest over the readings and the latest stop the latest
    /// over them, or none when some reading never meets the check.
    fn merge(readings: impl IntoIterator<Item = Breaks>) -> Breaks {
        let readings: Vec<Breaks> = readings.into_iter().collect();
        let certain = in_every(readings.iter().map(|reading| reading.certain.clone()));
        let uncertain = readings
            .iter()
            .flat_map(|reading| reading.certain.iter().chain(&reading.uncertain))
            .filter(|broken| !certain.contains(broken))
            .copied()
            .collect();
        let reached: BTreeSet<Fcr> = readings
            .iter()
            .flat_map(|reading| reading.reach.keys().copied())
            .collect();
        let reach = reached
            .into_iter()
            .map(|check| {
                let span = |direction: Direction| {
                    let spans: Vec<Option<Span>> = readings
                        .iter()
                        .map(|reading| reading.reach.get(&check).map(|r| r.toward(direction)))
                        .collect();
                    let earlier = |a, b| if direction.meets_before(b, a) { b } else { a };
                    let later = |a, b| if direction.meets_before(a, b) { b } else { a };
                    Span {
                        first: spans
                            .iter()
                            .flatten()
                            .map(|span| span.first)
                            .reduce(earlier)
                            .expect("a reading reaches the check"),
                        last: spans
                            .iter()
                            .map(|span| span.and_then(|span| span.last))
                            .collect::<Option<Vec<usize>>>()
                            .and_then(|lasts| lasts.into_iter().reduce(later)),
                    }
                };
                let reach = Reach {
                    front_to_back: span(Direction::FrontToBack),
                    back_to_front: span(Direction::BackToFront),
                };
                (check, reach)
            })
            .collect();
        let first_try = in_every(readings.iter().map(|reading| reading.first_try.clone()));
        Breaks {
            certain,
            uncertain,
            reach,
            first_try,
        }
    }

    /// The checks a case that stores `class` counts: every certain one, and
    /// an uncertain one only when it reports `class`.
    fn counted(&self, class: &str) -> Vec<Break> {
        self.certain
            .iter()
            .chain(
                self.uncertain
                    .iter()
                    .filter(|(check, _)| FcrList::class(*check) == class),
            )
            .copied()
            .collect()
    }
}

/// The members every one of `sets` holds.
fn in_every<T: Ord + Copy>(sets: impl Iterator<Item = BTreeSet<T>>) -> BTreeSet<T> {
    sets.reduce(|a, b| a.intersection(&b).copied().collect())
        .unwrap_or_default()
}

/// Where a reader takes the recipient-entry region to end. The declared
/// lengths can disagree, so a reader may take the end from any of them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RegionEnd {
    /// After `recipient_entries_len` bytes.
    Declared,
    /// After `recipient_entries_len` bytes or at the end of the declared
    /// header, whichever comes first.
    DeclaredInHeader,
    /// At the end of the declared header, whatever the region lengths say.
    Header,
    /// Where the declared header leaves `ext_len` bytes for `ext_bytes`.
    BeforeExtensions,
    /// After `recipient_entries_len` bytes or where `ext_bytes` start,
    /// whichever comes first.
    DeclaredBeforeExtensions,
}

/// Where a reader stops reading an entry's fields, type name, and body.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryEnd {
    Region,
    Header,
    File,
}

/// How far a reader that makes a check first reads. Such a reader may read
/// past a declared end before the check that guards that end, so each end is
/// kept or ignored.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Reading {
    /// Whether `header_fixed` ends with the declared header.
    fixed_in_header: bool,
    region_end: RegionEnd,
    entry_end: EntryEnd,
}

impl Reading {
    /// The reading of the reader the specification describes, whose checks
    /// guard every end before it reads past it.
    const SPECIFICATION: Reading = Reading {
        fixed_in_header: true,
        region_end: RegionEnd::Declared,
        entry_end: EntryEnd::Region,
    };

    /// Every reading.
    fn all() -> impl Iterator<Item = Reading> {
        let region_ends = [
            RegionEnd::Declared,
            RegionEnd::DeclaredInHeader,
            RegionEnd::Header,
            RegionEnd::BeforeExtensions,
            RegionEnd::DeclaredBeforeExtensions,
        ];
        let entry_ends = [EntryEnd::Region, EntryEnd::Header, EntryEnd::File];
        [true, false].into_iter().flat_map(move |fixed_in_header| {
            region_ends.into_iter().flat_map(move |region_end| {
                entry_ends.into_iter().map(move |entry_end| Reading {
                    fixed_in_header,
                    region_end,
                    entry_end,
                })
            })
        })
    }
}

/// One recipient entry as a reading reached it.
struct Entry {
    /// The type name, when the reading holds all of it.
    type_name: Option<Vec<u8>>,
    flags: u16,
    body_len: u32,
    /// As much of the body as the reading holds.
    body: Vec<u8>,
}

impl Entry {
    /// The body, when the reading holds all of it.
    fn whole_body(&self) -> Option<&[u8]> {
        (self.body.len() == self.body_len as usize).then_some(self.body.as_slice())
    }
}

/// The recipient entries one reading walks.
#[derive(Default)]
struct Walk {
    entries: Vec<Entry>,
    /// Whether the walk reached the type name of every declared entry, so a
    /// check over the whole list can be judged.
    complete: bool,
}

/// Every check of the list `bytes` breaks before any recipient is tried, each
/// evaluated on its own under one reading, plus the entries that reading
/// walks.
fn structural_breaks(
    bytes: &[u8],
    profile: &Row,
    capabilities: &Capabilities,
    reading: Reading,
) -> (Breaks, Walk) {
    let mut certain = BTreeSet::new();
    let mut uncertain = BTreeSet::new();
    let n = bytes.len();
    if n < PREFIX_SIZE {
        certain.insert((PrefixShort, None));
    }
    // A file shorter than the magic breaks it only for a reader that compares
    // the magic byte by byte as it reads it.
    let magic_held = n.min(MAGIC.len());
    if bytes[..magic_held] != MAGIC[..magic_held] {
        if magic_held == MAGIC.len() {
            certain.insert((Magic, None));
        } else {
            uncertain.insert((Magic, None));
        }
    }
    if bytes
        .get(PREFIX_KIND_OFFSET)
        .is_some_and(|&kind| kind != KIND_ENCRYPTED)
    {
        certain.insert((Kind, None));
    }
    match bytes.get(PREFIX_VERSION_OFFSET).copied() {
        Some(0) => {
            certain.insert((VersionZero, None));
        }
        Some(version)
            if version != FCR_FILE_V1_VERSION
                && !capabilities.outer_versions.contains(&version) =>
        {
            certain.insert((VersionUnsupported, None));
        }
        _ => {}
    }
    if read_u16_be(bytes, PREFIX_FLAGS_OFFSET).is_ok_and(|flags| flags != 0) {
        certain.insert((PrefixFlags, None));
    }
    let no_entries = |certain, uncertain| {
        let breaks = Breaks {
            certain,
            uncertain,
            ..Breaks::default()
        };
        (breaks, Walk::default())
    };
    let Ok(header_len) = read_u32_be(bytes, PREFIX_HEADER_LEN_OFFSET) else {
        return no_entries(certain, uncertain);
    };
    let header_len = header_len as usize;
    if header_len > HEADER_LEN_MAX as usize {
        certain.insert((HeaderLenMax, None));
    }
    let caps = ProfileCaps::new(profile).header();
    if header_len > caps.max_header_len as usize {
        certain.insert((HeaderLenCap, None));
    }
    if n < PREFIX_SIZE + header_len + HEADER_MAC_SIZE {
        certain.insert((HeaderTruncated, None));
    }
    if header_len < HEADER_FIXED_SIZE {
        certain.insert((HeaderFixedShort, None));
    }
    let fixed_end = if reading.fixed_in_header {
        n.min(PREFIX_SIZE + header_len)
    } else {
        n
    };
    let header = &bytes[PREFIX_SIZE..fixed_end];
    let flags = read_u16_be(header, HEADER_FIXED_FLAGS_OFFSET).ok();
    let count = read_u16_be(header, HEADER_FIXED_RECIPIENT_COUNT_OFFSET).ok();
    let entries_len = read_u32_be(header, HEADER_FIXED_RECIPIENT_ENTRIES_LEN_OFFSET).ok();
    let ext_len = read_u32_be(header, HEADER_FIXED_EXT_LEN_OFFSET).ok();
    if flags.is_some_and(|flags| flags != 0) {
        certain.insert((HeaderFlags, None));
    }
    if count.is_some_and(|count| count == 0 || count > RECIPIENT_COUNT_MAX) {
        certain.insert((RecipientCountRange, None));
    }
    if ext_len.is_some_and(|ext_len| ext_len > EXT_LEN_MAX) {
        certain.insert((ExtLenMax, None));
    }
    if let (Some(entries_len), Some(ext_len)) = (entries_len, ext_len) {
        let sum = HEADER_FIXED_SIZE as u64 + u64::from(entries_len) + u64::from(ext_len);
        if sum != header_len as u64 {
            certain.insert((LengthsSum, None));
        }
    }
    if count.is_some_and(|count| count > caps.max_recipient_count) {
        certain.insert((RecipientCountCap, None));
    }
    let (Some(count), Some(entries_len)) = (count, entries_len) else {
        return no_entries(certain, uncertain);
    };
    let entries_len = entries_len as usize;
    let header_room = header_len.saturating_sub(HEADER_FIXED_SIZE);
    let before_extensions = ext_len.map(|ext_len| header_room.saturating_sub(ext_len as usize));
    let region_len = match reading.region_end {
        RegionEnd::Declared => Some(entries_len),
        RegionEnd::DeclaredInHeader => Some(entries_len.min(header_room)),
        RegionEnd::Header => Some(header_room),
        RegionEnd::BeforeExtensions => before_extensions,
        RegionEnd::DeclaredBeforeExtensions => before_extensions.map(|end| entries_len.min(end)),
    };
    let Some(region_len) = region_len else {
        return no_entries(certain, uncertain);
    };
    let region_start = PREFIX_SIZE + HEADER_FIXED_SIZE;
    let held_end = match reading.entry_end {
        EntryEnd::Region => region_start + region_len,
        EntryEnd::Header => PREFIX_SIZE + header_len,
        EntryEnd::File => n,
    };
    let held = bytes.get(region_start..n.min(held_end)).unwrap_or_default();
    let walk = walk_region(
        held,
        region_len,
        count,
        caps.max_recipient_body_len,
        &mut certain,
        &mut uncertain,
    );

    for (index, entry) in walk.entries.iter().enumerate() {
        let Some(type_name) = entry.type_name.as_deref() else {
            continue;
        };
        let Some(native) = native_type(type_name) else {
            if entry.flags & RECIPIENT_FLAG_CRITICAL != 0 && !capabilities.supports(type_name) {
                certain.insert((UnknownCritical, Some(index)));
            }
            continue;
        };
        if entry.flags != 0 {
            certain.insert((NativeFlags, Some(index)));
        }
        if entry.body_len as usize != native.body_len() {
            certain.insert((NativeLength, Some(index)));
        }
        if let Some(body) = entry
            .whole_body()
            .filter(|body| body.len() == native.body_len())
        {
            if native.validate_body(body).is_err() {
                certain.insert((content_check(native), Some(index)));
            }
        }
    }

    // A reader that makes the mixing check or the work cap first, on a list
    // it could not read to the end, may or may not judge it on the entries
    // read. No reader can judge a list it did not read to the end to hold no
    // supported recipient: an entry it did not read may be one.
    let list_wide = if walk.complete {
        &mut certain
    } else {
        &mut uncertain
    };
    let listed: Vec<RecipientEntry> = walk
        .entries
        .iter()
        .map(|entry| RecipientEntry {
            type_name: entry
                .type_name
                .as_deref()
                .map(|name| String::from_utf8_lossy(name).into_owned())
                .unwrap_or_default(),
            recipient_flags: entry.flags,
            body: Vec::new(),
        })
        .collect();
    let mixing_refuses = |met: &[usize], counted: bool| {
        let entries = met.iter().map(|&index| listed[index].clone()).collect();
        mixing_refused(entries, counted.then_some(usize::from(count)))
    };
    let every_entry: Vec<usize> = (0..listed.len()).collect();
    if mixing_refuses(&every_entry, true) {
        list_wide.insert((Mixing, None));
    }
    let supported: Vec<bool> = walk
        .entries
        .iter()
        .map(|entry| {
            entry
                .type_name
                .as_deref()
                .is_some_and(|name| capabilities.supports(name))
        })
        .collect();
    let over_work_cap = |met: &[usize]| {
        let counted = met.iter().filter(|&&index| supported[index]).count() as u64;
        counted * (PREFIX_SIZE + header_len) as u64 > caps.max_header_mac_work_bytes
    };
    if over_work_cap(&every_entry) {
        list_wide.insert((HeaderMacWorkCap, None));
    }
    if walk.complete && !supported.contains(&true) {
        certain.insert((NoSupportedRecipient, None));
    }
    let mut reach = BTreeMap::new();
    let mixing = reach_of(
        listed.len(),
        |met| mixing_refuses(met, true),
        |met| mixing_refuses(met, false),
    );
    let work_cap = reach_of(listed.len(), over_work_cap, over_work_cap);
    for (check, found) in [(Mixing, mixing), (HeaderMacWorkCap, work_cap)] {
        if let Some(found) = found {
            reach.insert(check, found);
        }
    }
    let breaks = Breaks {
        certain,
        uncertain,
        reach,
        first_try: BTreeSet::new(),
    };
    (breaks, walk)
}

/// Whether the mixing rules refuse `met`, the entries met so far. A reader that
/// counts the `declared` entries the header holds can apply the rules before
/// it meets them all, with entries of no supported type standing in for the
/// rest.
fn mixing_refused(mut met: Vec<RecipientEntry>, declared: Option<usize>) -> bool {
    if let Some(declared) = declared {
        met.resize(met.len().max(declared), entry_of_type(""));
    }
    match enforce_recipient_mixing_policy(&met) {
        Ok(()) => false,
        Err(CryptoError::IncompatibleRecipients { .. }) => true,
        Err(other) => panic!("the mixing rules refuse a list for another reason: {other:?}"),
    }
}

/// An entry of `type_name` with no flags and no body, as the mixing rules see
/// one: they judge a supported type and count every entry.
fn entry_of_type(type_name: &str) -> RecipientEntry {
    RecipientEntry {
        type_name: type_name.to_string(),
        recipient_flags: 0,
        body: Vec::new(),
    }
}

/// Where readers that judge a rule on the entries met so far first find it
/// broken, walking `len` entries each way: the earliest of them judges by
/// `earliest`, and the latest by `latest`, which never finds the rule broken
/// sooner. None when even `earliest` does not find it broken. A rule judged
/// this way stays broken as more entries are met, which lets the search
/// bisect: the work cap counts supported entries, which only grow, and
/// [`the_mixing_rules_stay_broken_as_more_entries_are_met`] holds the mixing
/// rules to it.
fn reach_of(
    len: usize,
    earliest: impl Fn(&[usize]) -> bool,
    latest: impl Fn(&[usize]) -> bool,
) -> Option<Reach> {
    let span = |direction: Direction| {
        let order: Vec<usize> = match direction {
            Direction::FrontToBack => (0..len).collect(),
            Direction::BackToFront => (0..len).rev().collect(),
        };
        let found = |broken: &dyn Fn(&[usize]) -> bool| {
            let met = (1..=len).collect::<Vec<usize>>();
            let first = met.partition_point(|&count| !broken(&order[..count]));
            met.get(first).map(|&count| order[count - 1])
        };
        Some(Span {
            first: found(&earliest)?,
            last: found(&latest),
        })
    };
    Some(Reach {
        front_to_back: span(Direction::FrontToBack)?,
        back_to_front: span(Direction::BackToFront)?,
    })
}

/// Walks a recipient-entry region `region_len` bytes long, reading its entries
/// from `held`: the bytes this reading holds from the start of the region,
/// which may stop before the region's end or run past it. Adds the §3.3 checks
/// each entry breaks to `certain`, or to `uncertain` where readers can
/// disagree. The walk stops at the first entry that runs past the region,
/// since no later entry lies in it.
fn walk_region(
    held: &[u8],
    region_len: usize,
    count: u16,
    body_cap: u32,
    certain: &mut BTreeSet<Break>,
    uncertain: &mut BTreeSet<Break>,
) -> Walk {
    let count = usize::from(count);
    let mut entries = Vec::new();
    let finish = |entries: Vec<Entry>| Walk {
        complete: entries.len() == count && entries.iter().all(|entry| entry.type_name.is_some()),
        entries,
    };
    let mut offset = 0;
    for index in 0..count {
        let room = region_len - offset;
        let type_name_len = read_u16_be(held, offset + ENTRY_TYPE_NAME_LEN_OFFSET).ok();
        let flags = read_u16_be(held, offset + ENTRY_RECIPIENT_FLAGS_OFFSET).ok();
        let body_len = read_u32_be(held, offset + ENTRY_BODY_LEN_OFFSET).ok();
        if room < ENTRY_HEADER_SIZE {
            certain.insert((EntryHeaderShort, Some(index)));
        }
        if type_name_len.is_some_and(|len| len == 0 || usize::from(len) > TYPE_NAME_MAX_LEN) {
            certain.insert((TypeNameLen, Some(index)));
        }
        if body_len.is_some_and(|len| len > BODY_LEN_MAX) {
            certain.insert((BodyLenMax, Some(index)));
        }
        if flags.is_some_and(|flags| flags & !RECIPIENT_FLAG_CRITICAL != 0) {
            certain.insert((FlagsReserved, Some(index)));
        }
        let (Some(type_name_len), Some(flags), Some(body_len)) = (type_name_len, flags, body_len)
        else {
            return finish(entries);
        };
        let size = ENTRY_HEADER_SIZE as u64 + u64::from(type_name_len) + u64::from(body_len);
        let fits = size <= room as u64;
        if !fits {
            certain.insert((EntryFit, Some(index)));
        }
        if body_len > body_cap {
            certain.insert((BodyLenCap, Some(index)));
        }
        let name_start = offset + ENTRY_HEADER_SIZE;
        let name_end = name_start + usize::from(type_name_len);
        let type_name = held.get(name_start..name_end).map(<[u8]>::to_vec);
        let ungrammatical = |name: &[u8]| {
            !std::str::from_utf8(name).is_ok_and(|name| validate_type_name_grammar(name).is_ok())
        };
        if type_name.as_deref().is_some_and(ungrammatical) {
            // Outside 1..=255 bytes, a name breaks the grammar for a reader
            // whose grammar check repeats the length rule; its characters are
            // not judged apart.
            if (1..=TYPE_NAME_MAX_LEN).contains(&usize::from(type_name_len)) {
                certain.insert((TypeNameGrammar, Some(index)));
            } else {
                uncertain.insert((TypeNameGrammar, Some(index)));
            }
        }
        let body_end = name_end.saturating_add(body_len as usize);
        let body = held
            .get(name_end.min(held.len())..body_end.min(held.len()))
            .unwrap_or_default()
            .to_vec();
        entries.push(Entry {
            type_name,
            flags,
            body_len,
            body,
        });
        if !fits {
            return finish(entries);
        }
        offset += size as usize;
    }
    if offset != region_len {
        certain.insert((TrailingBytes, None));
    }
    finish(entries)
}

/// A file key kept for later cases, wiped on drop.
type KeptFileKey = Zeroizing<[u8; FILE_KEY_SIZE]>;

/// The corpus credentials, opened once per test run, and what trying a body
/// with one gives.
struct Credentials {
    root: PathBuf,
    /// Each credential as a reader holds it, by credential and by the two
    /// key-read caps a profile sets: the unlock applies the recipient-string
    /// cap to a `public.key` handed to it.
    opened: BTreeMap<(String, usize, u32), Opened>,
    /// What trying a body with a credential gives, by credential and body.
    tried: BTreeMap<(String, Vec<u8>), Tried>,
}

/// A credential as a reader holds it before it tries any recipient.
enum Opened {
    None,
    Passphrase(Passphrase),
    PrivateKey {
        /// The KDF parameters the key stores, which the unlock's KDF caps
        /// bound.
        kdf_params: KdfParams,
        /// The X25519 secret, or none when the unlock passphrase is wrong.
        secret: Option<Zeroizing<[u8; x25519::PRIVATE_KEY_SIZE]>>,
    },
    /// A private key the reader refuses for a reason other than a wrong
    /// passphrase.
    RefusedKey(String),
}

/// What a credential decides about a file under one reading.
enum Decided {
    /// The checks of this list the credential breaks.
    Breaks(Breaks),
    /// The reader refuses the supplied private key, for the stated reason, by
    /// a check this list does not hold.
    KeyRefused(String),
}

/// What trying one body with a credential gives.
enum Tried {
    /// The file key the body opens.
    Opened(KeptFileKey),
    Refused,
    /// An `x25519` key agreement with the all-zero shared secret.
    ZeroSharedSecret,
}

/// Whether KDF parameters are above a profile's KDF caps, judged on the
/// numbers alone, as a reader that applies the caps before the §2.2 bounds
/// would.
fn over_kdf_cap(params: KdfParams, kdf_limit: &KdfLimit) -> bool {
    match params.enforce_limit(Some(kdf_limit)) {
        Ok(_) => false,
        Err(
            CryptoError::KdfResourceCapExceeded { .. }
            | CryptoError::KdfTimeCostCapExceeded { .. }
            | CryptoError::KdfLanesCapExceeded { .. }
            | CryptoError::KdfWorkCapExceeded { .. },
        ) => true,
        Err(other) => panic!("the KDF caps refuse parameters for another reason: {other:?}"),
    }
}

/// The KDF parameters the bytes of an `argon2id` body store, read without the
/// §2.2 bounds, or none when the bytes stop before them.
fn stored_kdf_params(body: &[u8]) -> Option<KdfParams> {
    body.get(argon2id::KDF_PARAMS_OFFSET..argon2id::KDF_PARAMS_OFFSET + KDF_PARAMS_SIZE)
        .and_then(|field| field.try_into().ok())
        .and_then(|field| KdfParams::from_bytes_unvalidated(field).ok())
}

/// Opens one corpus credential under a profile's key-read caps, reading a
/// private key from its file as the unlock does. A private key is unlocked
/// whatever its KDF cost, which [`credential_breaks`] checks against each
/// profile apart.
fn open_credential(root: &Path, credential_id: &str, profile: &Row) -> Opened {
    match read_credential(root, credential_id) {
        CorpusCredential::None => Opened::None,
        CorpusCredential::Passphrase(passphrase) => Opened::Passphrase(passphrase),
        CorpusCredential::PrivateKey { key, unlock } => {
            let key_read = ProfileCaps::new(profile).key_read();
            let bytes = read_private_key_bytes(&key, key_read.private_key_wrapped_secret_len())
                .expect("read a corpus private key");
            let kdf_params = match PrivateKeyHeader::from_file_bytes(&bytes) {
                Ok(header) => header.kdf_params,
                Err(refusal) => return Opened::RefusedKey(format!("{refusal:?}")),
            };
            let any_cost = KdfLimit::new(u32::MAX)
                .max_time_cost(u32::MAX)
                .max_lanes(u32::MAX)
                .max_work(u64::MAX);
            let secret = match x25519::open_x25519_private_key(
                &key,
                &unlock,
                Some(&any_cost),
                key_read,
                &|_| {},
            ) {
                Ok(secret) => Some(secret),
                Err(CryptoError::KeyFileUnlockFailed) => None,
                Err(refusal) => return Opened::RefusedKey(format!("{refusal:?}")),
            };
            Opened::PrivateKey { kdf_params, secret }
        }
    }
}

/// Tries one body with an opened credential of its type.
fn try_body(opened: &Opened, body: &[u8], kdf_limit: &KdfLimit) -> Tried {
    let unwrapped = match opened {
        Opened::Passphrase(passphrase) => {
            let body = body.try_into().expect("a body of the native length");
            argon2id::unwrap(body, passphrase, Some(kdf_limit), &|_| {})
        }
        Opened::PrivateKey {
            secret: Some(secret),
            ..
        } => {
            let body = body.try_into().expect("a body of the native length");
            x25519::unwrap(body, secret)
        }
        Opened::None | Opened::PrivateKey { secret: None, .. } | Opened::RefusedKey(_) => {
            panic!("only an opened credential tries a body")
        }
    };
    match unwrapped {
        Ok(file_key) => Tried::Opened(Zeroizing::new(*file_key.expose())),
        Err(CryptoError::RecipientUnwrapFailed { .. }) => Tried::Refused,
        Err(CryptoError::InvalidFormat(FormatDefect::MalformedRecipientEntry)) => {
            Tried::ZeroSharedSecret
        }
        Err(other) => panic!("trying a body: {other:?}"),
    }
}

/// The checks a credential decides that `bytes` breaks under one reading, each
/// evaluated as a reader that made it first would, over the entries of the
/// credential's type. A body of another length, one the reading cuts off, or
/// one the preflight refuses is not tried, as no single outcome holds for every
/// reader, but a reader may still apply the KDF caps to the parameters such an
/// `argon2id` body holds, or make a key agreement on the key such an `x25519`
/// body holds. A cap those parameters break is therefore uncertain, and so is
/// that key agreement when it yields the all-zero shared secret or the
/// preflight refuses the key, on which readers differ. The other `argon2id`
/// bodies are checked against the KDF caps, and the bodies within them are
/// tried. A KDF cap or key agreement an entry breaks is also uncertain when a
/// reader may never reach that entry: one that makes the step-8 framing checks
/// first skips an entry with nonzero flags, and one may stop at a candidate
/// whose header MAC verifies. `PassphraseUnwrap`, `KeyUnwrap`, and `HeaderMac`
/// report classes no other check reports, and the claim covers them only
/// against the cap, so they are judged only when `cap_broken`, and only when
/// every entry could be tried. An `argon2id` body, whose try costs a KDF run,
/// is tried only when one of these judgments needs its outcome.
fn credential_breaks(
    credentials: &mut Credentials,
    credential_id: &str,
    profile: &Row,
    bytes: &[u8],
    walk: &Walk,
    cap_broken: bool,
) -> Decided {
    let Credentials {
        root,
        opened,
        tried,
    } = credentials;
    let profile_caps = ProfileCaps::new(profile);
    let key_read = profile_caps.key_read();
    let opened = opened
        .entry((
            credential_id.to_string(),
            key_read.recipient_string_chars(),
            key_read.private_key_wrapped_secret_len(),
        ))
        .or_insert_with(|| open_credential(root, credential_id, profile));
    let kdf_limit = profile_caps.kdf();
    // Every entry is of the credential's type and one a reader tries, so it
    // meets what the credential breaks on whichever entry it tries first.
    let every_entry_tried_first = |native: NativeRecipientType| {
        walk.complete
            && !walk.entries.is_empty()
            && walk.entries.iter().all(|entry| {
                entry.type_name.as_deref() == Some(native.type_name().as_bytes())
                    && entry.flags == 0
                    && triable(native, entry).is_some()
            })
    };
    let mut broken = Breaks::default();
    let (native, unwrap_check) = match opened {
        Opened::None => return Decided::Breaks(broken),
        Opened::Passphrase(_) => (NativeRecipientType::Argon2id, PassphraseUnwrap),
        Opened::RefusedKey(refusal) => return Decided::KeyRefused(refusal.clone()),
        Opened::PrivateKey { kdf_params, .. } if over_kdf_cap(*kdf_params, &kdf_limit) => {
            return Decided::KeyRefused(format!(
                "its KDF parameters are above the caps of {}",
                field(profile, "limit_profile_id")
            ));
        }
        Opened::PrivateKey { secret: None, .. } => {
            // A reader may wait to unlock the key until it has an entry to
            // try with it; one with nonzero flags it may skip.
            let must_try = walk.entries.iter().any(|entry| {
                entry.type_name.as_deref() == Some(x25519::TYPE_NAME.as_bytes())
                    && entry.flags == 0
                    && triable(NativeRecipientType::X25519, entry).is_some()
            });
            if must_try {
                broken.certain.insert((KeyUnlock, None));
            } else {
                broken.uncertain.insert((KeyUnlock, None));
            }
            if every_entry_tried_first(NativeRecipientType::X25519) {
                broken.first_try.insert(KeyUnlock);
            }
            return Decided::Breaks(broken);
        }
        Opened::PrivateKey { .. } => (NativeRecipientType::X25519, KeyUnwrap),
    };
    let of_type: Vec<&Entry> = walk
        .entries
        .iter()
        .filter(|entry| entry.type_name.as_deref() == Some(native.type_name().as_bytes()))
        .collect();
    // With no entry of the credential's type there is nothing to try, and
    // readers differ on what they report.
    let mut every_entry_tried = !of_type.is_empty();
    // The KDF caps and key agreements an entry breaks, each with whether a
    // reader may skip that entry: one that makes the step-8 framing checks
    // before it tries an entry skips one with nonzero flags.
    let mut met: Vec<(Fcr, bool)> = Vec::new();
    let mut within_caps: Vec<(&[u8], bool)> = Vec::new();
    let ephemeral_key = x25519::EPHEMERAL_PUBLIC_KEY_OFFSET
        ..x25519::EPHEMERAL_PUBLIC_KEY_OFFSET + x25519::PUBLIC_KEY_SIZE;
    for entry in of_type {
        let skippable = entry.flags != 0;
        let Some(body) = triable(native, entry) else {
            every_entry_tried = false;
            let doubtful = match native {
                NativeRecipientType::Argon2id => stored_kdf_params(&entry.body)
                    .is_some_and(|params| over_kdf_cap(params, &kdf_limit))
                    .then_some(KdfCap),
                NativeRecipientType::X25519 => entry
                    .body
                    .get(ephemeral_key.clone())
                    .is_some_and(|key| {
                        // The agreement on the key the body holds, in an
                        // otherwise empty body. Readers differ on a key the
                        // preflight refuses, so such a key may yield the
                        // all-zero secret for some of them.
                        let mut padded = vec![0; native.body_len()];
                        padded[ephemeral_key.clone()].copy_from_slice(key);
                        native.validate_body(&padded).is_err()
                            || matches!(
                                tried
                                    .entry((credential_id.to_string(), padded.clone()))
                                    .or_insert_with(|| try_body(opened, &padded, &kdf_limit)),
                                Tried::ZeroSharedSecret
                            )
                    })
                    .then_some(KeyAgreement),
            };
            broken.uncertain.extend(doubtful.map(|check| (check, None)));
            continue;
        };
        if skippable {
            every_entry_tried = false;
        }
        let over_cap = native == NativeRecipientType::Argon2id
            && stored_kdf_params(body).is_some_and(|params| over_kdf_cap(params, &kdf_limit));
        if over_cap {
            met.push((KdfCap, skippable));
            every_entry_tried = false;
            continue;
        }
        within_caps.push((body, skippable));
    }
    let mut candidates = Vec::new();
    let mut zero_on_every_try = true;
    if native == NativeRecipientType::X25519 || cap_broken || !met.is_empty() {
        for (body, skippable) in within_caps {
            let outcome = tried
                .entry((credential_id.to_string(), body.to_vec()))
                .or_insert_with(|| try_body(opened, body, &kdf_limit));
            zero_on_every_try &= matches!(outcome, Tried::ZeroSharedSecret);
            match outcome {
                Tried::Opened(file_key) => {
                    candidates.push(FileKey::from_bytes_for_tests(**file_key))
                }
                Tried::Refused => {}
                Tried::ZeroSharedSecret => met.push((KeyAgreement, skippable)),
            }
        }
    }
    // A reader may stop at the first candidate whose header MAC verifies, and
    // so never reach an entry that breaks a KDF cap or a key agreement.
    let mac = header_mac_verifies(bytes, &candidates);
    let verified = mac == Some(true);
    for (check, skippable) in met {
        if skippable || verified {
            broken.uncertain.insert((check, None));
        } else {
            broken.certain.insert((check, None));
        }
    }
    if cap_broken && every_entry_tried {
        if candidates.is_empty() {
            broken.certain.insert((unwrap_check, None));
        } else if mac == Some(false) {
            broken.certain.insert((HeaderMac, None));
        }
    }
    if native == NativeRecipientType::X25519 && zero_on_every_try && every_entry_tried_first(native)
    {
        broken.first_try.insert(KeyAgreement);
    }
    Decided::Breaks(broken)
}

/// The body of `entry` a reader tries with a credential for `native`: all of
/// it held, of the native length, and passing the preflight.
fn triable(native: NativeRecipientType, entry: &Entry) -> Option<&[u8]> {
    entry
        .whole_body()
        .filter(|body| body.len() == native.body_len() && native.validate_body(body).is_ok())
}

/// Whether the header MAC verifies under one of `candidates`, or none when
/// the file does not hold the whole header and tag.
fn header_mac_verifies(bytes: &[u8], candidates: &[FileKey]) -> Option<bool> {
    let header_end = PREFIX_SIZE + read_u32_be(bytes, PREFIX_HEADER_LEN_OFFSET).ok()? as usize;
    let prefix: &[u8; PREFIX_SIZE] = bytes.get(..PREFIX_SIZE)?.try_into().ok()?;
    let header = bytes.get(PREFIX_SIZE..header_end)?;
    let tag: &[u8; HEADER_MAC_SIZE] = bytes
        .get(header_end..header_end + HEADER_MAC_SIZE)?
        .try_into()
        .ok()?;
    let stream_nonce: &[u8; STREAM_NONCE_SIZE] = header
        .get(HEADER_FIXED_STREAM_NONCE_OFFSET..HEADER_FIXED_SIZE)?
        .try_into()
        .ok()?;
    Some(candidates.iter().any(|file_key| {
        let subkeys = derive_subkeys(file_key, stream_nonce).expect("derive subkeys");
        verify_header_mac(prefix, header, &subkeys.header_key, tag).is_ok()
    }))
}

/// The caps of a limit profile, read through the builders that clamp a
/// reader's caps. Every cap column read is recorded, so a test can tell which
/// columns this list reads.
struct ProfileCaps<'a> {
    profile: &'a Row,
    read: RefCell<BTreeSet<String>>,
}

impl<'a> ProfileCaps<'a> {
    fn new(profile: &'a Row) -> Self {
        Self {
            profile,
            read: RefCell::new(BTreeSet::new()),
        }
    }

    fn cap(&self, column: &str) -> u64 {
        self.read.borrow_mut().insert(column.to_string());
        limit_value(self.profile, column)
    }

    fn narrow<T: TryFrom<u64>>(&self, column: &str) -> T {
        T::try_from(self.cap(column))
            .unwrap_or_else(|_| panic!("{column}: the cap does not fit its type"))
    }

    fn header(&self) -> HeaderReadLimits {
        HeaderReadLimits::default()
            .max_header_len(self.narrow("max_header_len"))
            .max_recipient_count(self.narrow("max_recipient_count"))
            .max_recipient_body_len(self.narrow("max_recipient_body_len"))
            .max_header_mac_work_bytes(self.cap("max_header_mac_work_bytes"))
    }

    fn kdf(&self) -> KdfLimit {
        KdfLimit::new(self.narrow("max_kdf_mem_kib"))
            .max_time_cost(self.narrow("max_kdf_time"))
            .max_lanes(self.narrow("max_kdf_lanes"))
            .max_work(self.cap("max_kdf_work"))
    }

    fn key_read(&self) -> KeyReadLimits {
        KeyReadLimits::default()
            .max_recipient_string_chars(self.narrow("max_recipient_string_chars"))
            .max_private_key_wrapped_secret_len(self.narrow("max_private_key_wrapped_secret_len"))
    }
}

/// The cap columns of a limit profile this list leaves alone: the archive
/// caps, which only the payload meets.
const CAP_COLUMNS_UNREAD: [&str; 9] = [
    "max_entry_count",
    "max_total_plaintext_bytes",
    "max_path_depth",
    "max_path_bytes",
    "max_manifest_bytes",
    "max_archive_ext_bytes",
    "max_entry_ext_bytes",
    "max_total_entry_ext_bytes",
    "max_tlv_value_bytes",
];

/// The checks this list can still judge on a file of a newer outer-container
/// version that a reader supports: the magic and the kind keep their places,
/// while the prefix length and all the file holds past its kind may differ.
/// Such a file therefore fixes no order of the other checks for that reader.
/// A pair that rests on it alone is not fixed for that reader, though no check
/// of the pair is one its capability changes, so the capability runs report
/// it as a loss.
const KEPT_BY_NEWER_VERSIONS: [Fcr; 2] = [Magic, Kind];

/// Every check a case's artifact breaks for a reader with `capabilities`,
/// merged over every reading, and the type names of the entries some reading
/// walks. Also asserts that the specification's reader reports the stored
/// class, or breaks nothing on a header the library itself accepts.
fn case_breaks(
    credentials: &mut Credentials,
    row: &Row,
    bytes: &[u8],
    profile: &Row,
    capabilities: &Capabilities,
) -> (Breaks, BTreeSet<Vec<u8>>) {
    let newer_version = bytes
        .get(PREFIX_VERSION_OFFSET)
        .is_some_and(|version| capabilities.outer_versions.contains(version));
    let mut walked = BTreeSet::new();
    let breaks = Breaks::merge(Reading::all().map(|reading| {
        let (mut breaks, walk) = structural_breaks(bytes, profile, capabilities, reading);
        walked.extend(
            walk.entries
                .iter()
                .filter_map(|entry| entry.type_name.clone()),
        );
        assert!(
            walk.entries.iter().all(|entry| {
                entry
                    .type_name
                    .as_deref()
                    .is_none_or(|name| native_type(name).is_some() || !capabilities.supports(name))
            }),
            "{}: a reader that declares a recipient type tries entries of that type, \
             which this check list cannot evaluate",
            field(row, "case_id")
        );
        let cap_broken = breaks.certain.contains(&(HeaderMacWorkCap, None));
        let key_refusal = match credential_breaks(
            credentials,
            field(row, "credential_id"),
            profile,
            bytes,
            &walk,
            cap_broken,
        ) {
            Decided::Breaks(credential) => {
                breaks.certain.extend(credential.certain);
                breaks.uncertain.extend(credential.uncertain);
                breaks.first_try.extend(credential.first_try);
                None
            }
            Decided::KeyRefused(refusal) => Some(refusal),
        };
        if newer_version {
            let (known, unknown) = std::mem::take(&mut breaks.certain)
                .into_iter()
                .partition(|(check, _)| KEPT_BY_NEWER_VERSIONS.contains(check));
            breaks.certain = known;
            breaks.uncertain.extend(unknown);
            breaks.reach.clear();
            breaks.first_try.clear();
        }
        // §3.7 leaves the checks §8 makes on a supplied private key before its
        // unlock unordered against the `.fcr` checks, and this list holds none
        // of the checks made after it, so a refusal must decide the case alone.
        if let Some(refusal) = &key_refusal {
            assert!(
                breaks.certain.is_empty() && breaks.uncertain.is_empty(),
                "{}: the reader refuses the key ({refusal}), and some reader breaks a check \
                 of the file that refusal is not ordered against",
                field(row, "case_id")
            );
        }
        if reading == Reading::SPECIFICATION {
            let certain: Vec<Break> = breaks.certain.iter().copied().collect();
            let report = FcrList::specification_report(&certain);
            let class = field(row, "diagnostic_class");
            // A case that breaks no check of this list takes its class from
            // a check made later, so its header must pass the reader's own
            // structural checks.
            assert!(
                report == Some(class)
                    || (report.is_none()
                        && (newer_version || library_accepts_header(bytes, profile))),
                "{}: the specification's reader reports {report:?}",
                field(row, "case_id")
            );
        }
        breaks
    }));
    (breaks, walked)
}

/// Whether the library reads the header of `bytes` and classifies its
/// recipients without error under `profile`'s caps: the structural checks of
/// this list, made by the reader itself.
fn library_accepts_header(bytes: &[u8], profile: &Row) -> bool {
    let limits = ProfileCaps::new(profile).header();
    let mut reader = bytes;
    crate::container::read_encrypted_header(&mut reader, limits)
        .and_then(|parsed| crate::protocol::classify_recipients_within_limits(&parsed, limits))
        .is_ok()
}

/// A rejected `.fcr` case, with the checks its artifact breaks for a reader
/// that declares each run of capabilities, the empty run included, that does
/// not hold the capability the case rests on.
struct LoadedCase {
    row: Row,
    breaks: BTreeMap<Vec<String>, Breaks>,
}

/// Every rejected `.fcr` case of the committed corpus, evaluated once per test
/// run.
fn loaded_cases() -> &'static [LoadedCase] {
    static CASES: OnceLock<Vec<LoadedCase>> = OnceLock::new();
    CASES.get_or_init(|| {
        let root = corpus_root().expect("the corpus is on disk");
        let profiles = limit_profiles(&root);
        let cases = rejected_cases(&root, "fcr_decrypt");
        let runs = capability_runs(cases.iter().map(|(row, _)| row));
        let mut credentials = Credentials {
            root,
            opened: BTreeMap::new(),
            tried: BTreeMap::new(),
        };
        let mut loaded = Vec::new();
        for (row, bytes) in cases {
            let profile = &profiles[field(&row, "limit_profile_id")];
            let (base, walked) = case_breaks(
                &mut credentials,
                &row,
                &bytes,
                profile,
                &Capabilities::default(),
            );
            let mut breaks = BTreeMap::new();
            for run in &runs {
                if run
                    .iter()
                    .any(|capability| capability == field(&row, "capability_id"))
                {
                    continue;
                }
                let (capabilities, changed) = Capabilities::declaring(run);
                // A reader declaring capabilities sees what a reader declaring
                // none sees, unless they change a check of this list and the
                // file holds what they add: its version byte, or an entry of a
                // type they add.
                let touched = !changed.is_empty()
                    && (capabilities
                        .outer_versions
                        .iter()
                        .any(|version| bytes.get(PREFIX_VERSION_OFFSET) == Some(version))
                        || capabilities
                            .recipient_types
                            .iter()
                            .any(|type_name| walked.contains(type_name.as_bytes())));
                let run_breaks = if touched {
                    case_breaks(&mut credentials, &row, &bytes, profile, &capabilities).0
                } else {
                    base.clone()
                };
                breaks.insert(run.clone(), run_breaks);
            }
            loaded.push(LoadedCase { row, breaks });
        }
        loaded
    })
}

/// The runs of capabilities the cases are evaluated under, each in sorted
/// order: the empty run, then each combination of the capabilities `rows`
/// rest on that change a check of this list, joined by every capability they
/// rest on that changes none. Such a capability only leaves out the cases that
/// rest on it, and leaving out more cases can only lose more, so each
/// combination is checked where it can lose the most.
fn capability_runs<'r>(rows: impl Iterator<Item = &'r Row>) -> Vec<Vec<String>> {
    let declared: BTreeSet<String> = rows
        .map(|row| field(row, "capability_id").to_string())
        .filter(|capability| capability != "-")
        .collect();
    let (changing, inert): (Vec<String>, Vec<String>) =
        declared.into_iter().partition(|capability| {
            !Capabilities::declaring(std::slice::from_ref(capability))
                .1
                .is_empty()
        });
    let mut runs = vec![Vec::new()];
    for members in 0..1usize << changing.len() {
        let mut run: Vec<String> = changing
            .iter()
            .enumerate()
            .filter(|(index, _)| members & (1 << index) != 0)
            .map(|(_, capability)| capability.clone())
            .chain(inert.iter().cloned())
            .collect();
        run.sort();
        if !run.is_empty() {
            runs.push(run);
        }
    }
    runs
}

/// The capability runs every loaded case is evaluated under.
fn loaded_runs() -> Vec<Vec<String>> {
    capability_runs(loaded_cases().iter().map(|case| &case.row))
}

/// The `.fcr` evidence the corpus holds for a reader that declares every
/// capability of `run`, leaving out the cases that rest on one of them.
fn evidence(run: &[String]) -> Vec<Evidence<Fcr>> {
    loaded_cases()
        .iter()
        .filter_map(|case| {
            let breaks = case.breaks.get(run)?;
            let class = field(&case.row, "diagnostic_class");
            let broken = breaks.counted(class);
            (!broken.is_empty()).then(|| Evidence {
                case_id: field(&case.row, "case_id").to_string(),
                broken,
                reach: breaks.reach.clone(),
                class: class.to_string(),
            })
        })
        .collect()
}

/// Every cap a limit profile sets is one this list reads or one only the
/// payload meets, so a cap the corpus adds cannot go unread unnoticed.
#[test]
fn every_profile_cap_is_read_or_left_to_the_payload() {
    let columns: Vec<&str> = table_columns("limit-profiles.tsv")
        .iter()
        .copied()
        .filter(|column| column.starts_with(CAP_COLUMN_PREFIX))
        .collect();
    let profile: Row = columns
        .iter()
        .map(|column| (column.to_string(), "1".to_string()))
        .collect();
    let caps = ProfileCaps::new(&profile);
    caps.header();
    caps.kdf();
    caps.key_read();
    let read = caps.read.into_inner();
    let unread: BTreeSet<String> = CAP_COLUMNS_UNREAD.iter().map(|c| c.to_string()).collect();
    assert!(read.is_disjoint(&unread));
    let known: BTreeSet<String> = read.union(&unread).cloned().collect();
    assert_eq!(
        known,
        columns
            .iter()
            .map(|c| c.to_string())
            .collect::<BTreeSet<_>>()
    );
}

/// The §12.3 `.fcr` check-order row holds: the cases fix every claimed pair,
/// and a reader that declares capabilities loses only pairs with a check they
/// change.
#[test]
fn the_corpus_fixes_every_claimed_fcr_check_order() {
    if corpus_root().is_none() {
        return;
    }
    for run in loaded_runs() {
        let (_, changed) = Capabilities::declaring(&run);
        let lost = open_pairs::<FcrList>(&evidence(&run));
        let changed: Vec<Fcr> = changed.into_iter().collect();
        let stray = stray_losses(&lost, &changed);
        assert!(
            stray.is_empty(),
            "a reader that declares {run:?} finds these `.fcr` check pairs open: {stray:?}"
        );
    }
}

/// The checker finds open pairs: the cases named for each pair are the only
/// ones that fix it, so leaving them out reopens it. The list names the
/// witnesses of every check the §12.3 row says the cap precedes. If a later
/// case fixes one of these pairs too, name it as well.
#[test]
fn leaving_out_the_witnesses_reopens_their_pair() {
    if corpus_root().is_none() {
        return;
    }
    let base = evidence(&[]);
    let witnessed: [(&[&str], (Fcr, Fcr)); 12] = [
        (&["prefix-order-length-before-magic"], (PrefixShort, Magic)),
        (
            &["entry-order-entry-header-before-flags"],
            (EntryHeaderShort, FlagsReserved),
        ),
        // A reader may meet the entries of the §3.7 steps in either order, so
        // each order has its own witness.
        (
            &["recipient-order-unknown-critical-before-native-flags-x25519-first"],
            (UnknownCritical, NativeFlags),
        ),
        (
            &["recipient-order-unknown-critical-before-native-flags-unknown-first"],
            (UnknownCritical, NativeFlags),
        ),
        (
            &["recipient-order-unknown-critical-before-native-length-x25519-first"],
            (UnknownCritical, NativeLength),
        ),
        (
            &["recipient-order-unknown-critical-before-native-length-unknown-first"],
            (UnknownCritical, NativeLength),
        ),
        (
            &["header-mac-work-order-mixing-before-cap"],
            (Mixing, HeaderMacWorkCap),
        ),
        (
            &["header-mac-work-order-cap-before-passphrase-unwrap"],
            (HeaderMacWorkCap, PassphraseUnwrap),
        ),
        (
            &["header-mac-work-order-cap-before-private-key-unlock"],
            (HeaderMacWorkCap, KeyUnlock),
        ),
        (
            &["header-mac-work-order-cap-before-x25519-shared-secret"],
            (HeaderMacWorkCap, KeyAgreement),
        ),
        // The key agreement fails on every entry the key would open, so the
        // shared-secret case leaves that key no entry to open as well.
        (
            &[
                "header-mac-work-order-cap-before-x25519-unwrap",
                "header-mac-work-order-cap-before-x25519-shared-secret",
            ],
            (HeaderMacWorkCap, KeyUnwrap),
        ),
        (
            &["header-mac-work-order-cap-before-header-mac"],
            (HeaderMacWorkCap, HeaderMac),
        ),
    ];
    for (witnesses, pair) in witnessed {
        let rest: Vec<Evidence<Fcr>> = base
            .iter()
            .filter(|evidence| !witnesses.contains(&evidence.case_id.as_str()))
            .cloned()
            .collect();
        assert_eq!(
            rest.len() + witnesses.len(),
            base.len(),
            "{witnesses:?} are cases of the corpus"
        );
        assert!(
            !open_among::<FcrList>(&rest, &[pair]).is_empty(),
            "without {witnesses:?}, {pair:?} should be open"
        );
    }
}

/// The checks a reader may make on the entries it has met so far instead of
/// once over the whole list.
const MADE_SO_FAR: [Fcr; 2] = [Mixing, HeaderMacWorkCap];

/// The checks a credential decides that a reader applying the work cap to the
/// entries as it tries them can meet while the entries met so far are within
/// the cap: the private-key unlock, made before the first entry is tried, and
/// the key agreement, made on an entry as it is tried. The KDF caps belong here
/// too, but report the work cap's own class, so no file shows their order
/// against it.
const MET_ON_ONE_TRY: [Fcr; 2] = [KeyUnlock, KeyAgreement];

/// §3.7 makes the mixing rules and the work cap once over the whole list, but
/// a reader may make them on the entries it has met so far, in a pass over the
/// entries. The cases rule out every such reader that meets one of them before
/// a check §3.7 orders first: for each claimed pair, and each direction a pass
/// making the earlier check may take, some case shows that order. A reader
/// that declares capabilities may lose only the pairs with a check they change.
#[test]
fn the_corpus_fixes_the_checks_made_on_the_entries_met_so_far() {
    if corpus_root().is_none() {
        return;
    }
    for run in loaded_runs() {
        let (_, changed) = Capabilities::declaring(&run);
        let stray: Vec<(Fcr, Fcr, Direction)> = unshown_walk_orders(&run, |_| true)
            .into_iter()
            .filter(|(earlier, later, _)| !changed.contains(earlier) && !changed.contains(later))
            .collect();
        assert!(
            stray.is_empty(),
            "for a reader that declares {run:?}, no case rules out meeting the later check \
             first: {stray:?}"
        );
    }
    // Without the walk-order cases such readers remain, so the check can find
    // them.
    let walk_order =
        |case: &LoadedCase| field(&case.row, "case_id").starts_with(WALK_ORDER_CASE_PREFIX);
    assert!(!unshown_walk_orders(&[], |case| !walk_order(case)).is_empty());
}

/// The claimed pairs whose later check is made on the entries met so far, each
/// with a direction a pass making the earlier check may take, that no case of
/// `run` kept by `kept` shows that order for.
fn unshown_walk_orders(
    run: &[String],
    kept: impl Fn(&LoadedCase) -> bool,
) -> Vec<(Fcr, Fcr, Direction)> {
    let cases: Vec<(&LoadedCase, &Breaks)> = loaded_cases()
        .iter()
        .filter(|case| kept(case))
        .filter_map(|case| Some((case, case.breaks.get(run)?)))
        .collect();
    let mut unshown = Vec::new();
    for (earlier, later) in super::claimed_pairs::<FcrList>() {
        if !MADE_SO_FAR.contains(&later) {
            continue;
        }
        for &direction in walk_directions(earlier) {
            let shown = cases
                .iter()
                .any(|(case, breaks)| shows_walk_order(case, breaks, earlier, later, direction));
            if !shown {
                unshown.push((earlier, later, direction));
            }
        }
    }
    unshown
}

/// The directions in which a pass over the entries may make `check`: those of
/// its group for a check made once per entry, front to back for the trailing
/// bytes the §3.3 walk finds at its end, either for a check made on the entries
/// met so far, and none for a check made once.
fn walk_directions(check: Fcr) -> &'static [Direction] {
    if MADE_SO_FAR.contains(&check) {
        &Direction::BOTH
    } else if pass(check).is_some() {
        FcrList::directions(FcrList::direction_group(check))
    } else if check == TrailingBytes {
        &[Direction::FrontToBack]
    } else {
        &[]
    }
}

/// Whether `case` rules out every reader that makes `later` on the entries met
/// so far, in a pass walking `direction`, and meets it before `earlier`: the
/// case stores the class of `earlier` and breaks it for certain, every such
/// reader meets `later`, and it meets `later` before any check it could report
/// that class by instead. That check must be `earlier` itself, unless
/// `earlier` is a check of the §3.3 walk: no pass precedes that walk, so then
/// any check a reader meets on an entry past where it meets `later`
/// qualifies, whichever pass makes it.
fn shows_walk_order(
    case: &LoadedCase,
    breaks: &Breaks,
    earlier: Fcr,
    later: Fcr,
    direction: Direction,
) -> bool {
    let class = FcrList::class(earlier);
    if field(&case.row, "diagnostic_class") != class
        || !breaks.certain.iter().any(|(check, _)| *check == earlier)
    {
        return false;
    }
    let Some(met) = breaks
        .reach
        .get(&later)
        .and_then(|reach| reach.toward(direction).last)
    else {
        return false;
    };
    let of_class: Vec<Break> = breaks
        .certain
        .iter()
        .chain(&breaks.uncertain)
        .copied()
        .filter(|(check, _)| FcrList::class(*check) == class)
        .collect();
    // Whether a reader walking `direction` can meet `check` only past `met`.
    let met_after = |check: Fcr| {
        if check == TrailingBytes {
            return direction == Direction::FrontToBack;
        }
        let first = match breaks.reach.get(&check) {
            Some(reach) => Some(reach.toward(direction).first),
            None => {
                let entries = of_class
                    .iter()
                    .filter(|(broken, _)| *broken == check)
                    .filter_map(|(_, entry)| *entry);
                match direction {
                    Direction::FrontToBack => entries.min(),
                    Direction::BackToFront => entries.max(),
                }
            }
        };
        first.is_some_and(|first| direction.meets_before(met, first))
    };
    let in_walk = pass(earlier) == Some(Pass::Framing) || earlier == TrailingBytes;
    of_class
        .iter()
        .all(|&(check, _)| (check == earlier || in_walk) && met_after(check))
}

/// §3.7 applies the work cap before any entry is tried, but a reader may apply
/// it to the entries as it tries them, in any order. For each check of
/// [`MET_ON_ONE_TRY`], which the claim puts after the cap, some case rules out
/// every such reader that meets the check before the cap: the case breaks the
/// check on whichever entry a reader tries first, one entry alone is within
/// the cap, and no other check reports the cap's class. A reader that declares
/// capabilities may lose only a check they change.
#[test]
fn the_corpus_fixes_the_work_cap_before_the_entry_tried_first() {
    if corpus_root().is_none() {
        return;
    }
    let claimed = super::claimed_pairs::<FcrList>();
    for later in MET_ON_ONE_TRY {
        assert!(claimed.contains(&(HeaderMacWorkCap, later)));
    }
    for run in loaded_runs() {
        let (_, changed) = Capabilities::declaring(&run);
        let over_cap: Vec<&Breaks> = loaded_cases()
            .iter()
            .filter(|case| field(&case.row, "diagnostic_class") == FcrList::class(HeaderMacWorkCap))
            .filter_map(|case| case.breaks.get(&run))
            .collect();
        for later in MET_ON_ONE_TRY {
            if changed.contains(&HeaderMacWorkCap) || changed.contains(&later) {
                continue;
            }
            assert!(
                over_cap
                    .iter()
                    .any(|breaks| shows_cap_before_first_try(breaks, later)),
                "for a reader that declares {run:?}, no case rules out meeting {later:?} on the \
                 entry tried first before the work cap"
            );
        }
    }
}

/// Whether `breaks` shows the work cap before `later`, a check a reader meets
/// on the entry it tries first, for a reader that applies the cap to the
/// entries as it tries them: see
/// [`the_corpus_fixes_the_work_cap_before_the_entry_tried_first`].
fn shows_cap_before_first_try(breaks: &Breaks, later: Fcr) -> bool {
    let class = FcrList::class(HeaderMacWorkCap);
    // Every entry is one a reader tries, so a reader walking front to back
    // passes the first entry within the cap.
    let first_within = breaks
        .reach
        .get(&HeaderMacWorkCap)
        .is_some_and(|reach| reach.front_to_back.first > 0);
    breaks.certain.contains(&(HeaderMacWorkCap, None))
        && breaks.first_try.contains(&later)
        && first_within
        && breaks
            .certain
            .iter()
            .chain(&breaks.uncertain)
            .all(|(check, _)| *check == HeaderMacWorkCap || FcrList::class(*check) != class)
}

/// [`reach_of`] bisects, which holds only for a rule that stays broken as more
/// entries are met. The mixing rules must: over every list of up to four
/// entries of the native types and of no supported type, with or without a
/// declared count, a list they refuse stays refused as entries are added.
#[test]
fn the_mixing_rules_stay_broken_as_more_entries_are_met() {
    const LONGEST: usize = 4;
    let kinds: Vec<RecipientEntry> = NATIVE_TYPES
        .iter()
        .map(|native| native.type_name())
        .chain([""])
        .map(entry_of_type)
        .collect();
    let mut lists = vec![Vec::new()];
    for _ in 0..LONGEST {
        lists = lists
            .iter()
            .flat_map(|list: &Vec<RecipientEntry>| {
                kinds
                    .iter()
                    .map(move |kind| [list.clone(), vec![kind.clone()]].concat())
            })
            .collect();
    }
    assert!(lists.iter().any(|list| mixing_refused(list.clone(), None)));
    for list in &lists {
        for declared in [None].into_iter().chain((1..=2 * LONGEST).map(Some)) {
            for met in 1..LONGEST {
                let refused = |count: usize| mixing_refused(list[..count].to_vec(), declared);
                assert!(
                    !refused(met) || refused(met + 1),
                    "the mixing rules refuse {:?} but not one more entry",
                    &list[..met]
                );
            }
        }
    }
}

/// A reader may arrange the per-entry checks of §3.3 and §3.7 into passes over
/// the entries, merged or reordered, each pass read in a direction every check
/// in it allows; the §3.3 framing checks stay together, as §3.3 makes them all
/// on one entry before it reads the next, in a pass front to back. Every such
/// reader that reports the stored class for every case the per-entry checks
/// decide must also report the specification's class for every small file: one
/// that breaks one check, two that one entry can break together, or one on each
/// of two entries. A reader that disagrees with the specification on a larger
/// file disagrees on the small file that keeps only the two checks they report,
/// so the cases fix the per-entry order too. A reader that declares
/// capabilities may disagree only on a file with a check they change.
#[test]
fn the_corpus_fixes_the_fcr_per_entry_passes() {
    if corpus_root().is_none() {
        return;
    }
    let units = units();
    let spec = specification_reader(&units);
    let files = small_files(&units);
    let readers = readers(&units);
    // Without the cases, some reader disagrees, so the search can find a gap.
    assert!(readers.iter().any(|reader| {
        files
            .iter()
            .any(|file| report(reader, &units, file) != report(&spec, &units, file))
    }));
    let base = per_entry_cases(&[]);
    for run in loaded_runs() {
        let cases = per_entry_cases(&run);
        // A run with the cases of the base run has its result.
        if !run.is_empty() && cases == base {
            continue;
        }
        let passes_every_case = |reader: &PassReader| {
            cases
                .iter()
                .all(|(instance, class)| report(reader, &units, instance) == Some(class.as_str()))
        };
        assert!(
            passes_every_case(&spec),
            "the specification's reader reports every stored class"
        );
        let (_, changed) = Capabilities::declaring(&run);
        let mut gaps = BTreeMap::new();
        for reader in readers.iter().filter(|reader| passes_every_case(reader)) {
            for file in &files {
                let lost = file.iter().any(|(check, _)| changed.contains(check));
                if !lost && report(reader, &units, file) != report(&spec, &units, file) {
                    gaps.entry(file.iter().copied().collect::<Vec<_>>())
                        .or_insert_with(|| reader.clone());
                }
            }
        }
        assert!(
            gaps.is_empty(),
            "for a reader that declares {run:?}, readers that pass every case disagree on: \
             {gaps:?}"
        );
    }
}

/// The cases of `run` that the per-entry checks decide, those whose other
/// checks all follow every per-entry check, each as the per-entry checks its
/// artifact breaks, with the class it stores.
fn per_entry_cases(run: &[String]) -> Vec<(BTreeSet<(Fcr, usize)>, String)> {
    let position = |check: Fcr| {
        FcrList::order()
            .iter()
            .position(|c| *c == check)
            .expect("every check is in the order")
    };
    let last_per_entry = FcrList::order()
        .iter()
        .rposition(|check| pass(*check).is_some())
        .expect("a per-entry check");
    evidence(run)
        .into_iter()
        .filter(|evidence| {
            evidence
                .broken
                .iter()
                .all(|(check, entry)| entry.is_some() || position(*check) > last_per_entry)
        })
        .map(|evidence| {
            let instance: BTreeSet<(Fcr, usize)> = evidence
                .broken
                .iter()
                .filter_map(|(check, entry)| entry.map(|entry| (*check, entry)))
                .collect();
            (instance, evidence.class)
        })
        .filter(|(instance, _)| !instance.is_empty())
        .collect()
}

/// The per-entry checks in the specification order, in the units a reader of
/// the pass test moves: the §3.3 framing checks together, and every other
/// per-entry check on its own.
fn units() -> Vec<Vec<Fcr>> {
    let per_entry = FcrList::order()
        .iter()
        .copied()
        .filter(|check| pass(*check).is_some());
    let mut units: Vec<Vec<Fcr>> = Vec::new();
    for check in per_entry {
        match units.last_mut() {
            Some(unit) if FRAMING.contains(&check) && unit.iter().all(|c| FRAMING.contains(c)) => {
                unit.push(check)
            }
            _ => units.push(vec![check]),
        }
    }
    units
}

/// A reader of the per-entry checks: passes over the entries, each an ordered
/// list of units, given by index, and the direction it reads the entries in.
#[derive(Clone, Debug)]
struct PassReader {
    passes: Vec<(Vec<usize>, Direction)>,
}

/// The reader the specification describes: the units of each of its passes
/// together, the passes in order, each front to back.
fn specification_reader(units: &[Vec<Fcr>]) -> PassReader {
    let indices: Vec<usize> = (0..units.len()).collect();
    PassReader {
        passes: indices
            .chunk_by(|&a, &b| pass(units[a][0]) == pass(units[b][0]))
            .map(|members| (members.to_vec(), Direction::FrontToBack))
            .collect(),
    }
}

/// The class `reader` reports for a file that breaks `instance`, or none.
fn report(
    reader: &PassReader,
    units: &[Vec<Fcr>],
    instance: &BTreeSet<(Fcr, usize)>,
) -> Option<&'static str> {
    let entries: BTreeSet<usize> = instance.iter().map(|(_, entry)| *entry).collect();
    for (members, direction) in &reader.passes {
        let order: Vec<usize> = match direction {
            Direction::FrontToBack => entries.iter().copied().collect(),
            Direction::BackToFront => entries.iter().rev().copied().collect(),
        };
        for entry in order {
            for &member in members {
                for &check in &units[member] {
                    if instance.contains(&(check, entry)) {
                        return Some(FcrList::class(check));
                    }
                }
            }
        }
    }
    None
}

/// Every reader of `units`: each ordered partition of the units into passes,
/// the units of a pass in any order, each pass read in either direction its
/// units allow.
fn readers(units: &[Vec<Fcr>]) -> Vec<PassReader> {
    fn partitions(items: &[usize]) -> Vec<Vec<Vec<usize>>> {
        let Some((&first, rest)) = items.split_first() else {
            return vec![Vec::new()];
        };
        let mut out = Vec::new();
        for partition in partitions(rest) {
            for block in 0..partition.len() {
                for position in 0..=partition[block].len() {
                    let mut next = partition.clone();
                    next[block].insert(position, first);
                    out.push(next);
                }
            }
            for block in 0..=partition.len() {
                let mut next = partition.clone();
                next.insert(block, vec![first]);
                out.push(next);
            }
        }
        out
    }
    let allows = |members: &[usize], direction: Direction| {
        members.iter().all(|&member| {
            FcrList::directions(FcrList::direction_group(units[member][0])).contains(&direction)
        })
    };
    let indices: Vec<usize> = (0..units.len()).collect();
    let mut readers = Vec::new();
    for partition in partitions(&indices) {
        for directions in 0..1u32 << partition.len() {
            let passes: Vec<(Vec<usize>, Direction)> = partition
                .iter()
                .enumerate()
                .map(|(index, members)| {
                    let direction = if directions & (1 << index) == 0 {
                        Direction::FrontToBack
                    } else {
                        Direction::BackToFront
                    };
                    (members.clone(), direction)
                })
                .collect();
            if passes
                .iter()
                .all(|(members, direction)| allows(members, *direction))
            {
                readers.push(PassReader { passes });
            }
        }
    }
    readers
}

/// Every small file: one broken check, two broken on one entry where one entry
/// can break both, and one on each of two entries where the first entry fits
/// its region, so the walk reaches the second.
fn small_files(units: &[Vec<Fcr>]) -> Vec<BTreeSet<(Fcr, usize)>> {
    let per_entry: Vec<Fcr> = units.iter().flatten().copied().collect();
    // A body over its structural maximum, which equals the header's, runs past
    // the region of any header within its own maximum.
    let stops_the_walk = [EntryHeaderShort, BodyLenMax, EntryFit];
    let mut files = Vec::new();
    for &a in &per_entry {
        files.push(BTreeSet::from([(a, 0)]));
        for &b in &per_entry {
            if a < b && one_entry_breaks_both(a, b) {
                files.push(BTreeSet::from([(a, 0), (b, 0)]));
            }
            if !stops_the_walk.contains(&a) {
                files.push(BTreeSet::from([(a, 0), (b, 1)]));
            }
        }
    }
    files
}
