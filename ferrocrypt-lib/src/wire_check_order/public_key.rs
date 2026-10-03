//! The `public.key` check list of the §12.3 order row: the file checks of
//! `FORMAT.md` §7.1, then the recipient-string checks of §7.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Checksum, Fe32};
use ferrocrypt_test_support::wire_manifest::{
    FCA_ARCHIVE_TLV_DOMAIN, FCA_ENTRY_TLV_DOMAIN, FCA_VERSION_DOMAIN, KEY_TYPE_DOMAIN,
    OUTER_TLV_DOMAIN, OUTER_VERSION_DOMAIN, PRIVATE_KEY_TLV_DOMAIN, PRIVATE_KEY_VERSION_DOMAIN,
    PUBLIC_KEY_VERSION_DOMAIN, RECIPIENT_TYPE_DOMAIN, capability_parts, field, subject_version,
};

use super::{
    Breaks, CheckList, Direction, LoadedReadings, ProfileCaps, ReaderCapabilities, Row, across,
    assert_specification_report, corpus_root, evidence, length_rule_breaks, limit_profiles,
    load_readings, rejected_cases, reopens, stray_open_pairs, type_name_breaks,
};
use crate::format::{read_u16_be, read_u32_be};
use crate::key::private::has_private_key_signature;
use crate::key::public::{
    KEY_MATERIAL_LEN_MAX, PAYLOAD_HEADER_SIZE, PAYLOAD_KEY_MATERIAL_LEN_OFFSET,
    PAYLOAD_TYPE_NAME_LEN_OFFSET, PAYLOAD_VERSION_OFFSET, PUBLIC_KEY_CHECKSUM_SIZE,
    PUBLIC_KEY_FILE_READ_CAP_BYTES, PUBLIC_KEY_VERSION, RECIPIENT_HRP, RECIPIENT_STRING_LEN_MAX,
    compute_checksum,
};
use crate::recipient::name::TYPE_NAME_MAX_LEN;
use crate::recipient::native::x25519;

/// One check of the `public.key` list, in the order the specification fixes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Pk {
    /// §7.1 step 1: the file is longer than 20,001 bytes.
    FileTooLong,
    /// §7.1 step 2: the file opens with the `private.key` signature.
    PrivateKeySignature,
    /// §7.1 step 3: the file is not valid UTF-8.
    NotUtf8,
    /// §7 step 1: the recipient string is not ASCII.
    NotAscii,
    /// §7 step 2: the string is longer than 20,000 characters.
    StringTooLong,
    /// §7 step 3: the string is longer than the local cap.
    StringCap,
    /// §7 step 4: the string is not lowercase Bech32 with the human-readable
    /// part `fcr`.
    NotBech32,
    /// §7 step 5: the payload is shorter than its fixed fields.
    PayloadShort,
    /// §7 step 6: the padding is not canonical.
    Padding,
    /// §7 step 7: `public_key_version` is `0x00`.
    VersionZero,
    /// §7 step 7: a nonzero `public_key_version` the reader does not support.
    VersionUnsupported,
    /// §7 step 8: a length field is outside its limit.
    Lengths,
    /// §7 step 9: the payload length differs from what its fields declare.
    PayloadLength,
    /// §7 step 10: the type name is not valid UTF-8 or breaks the grammar.
    TypeName,
    /// §7 step 11: the internal checksum does not verify.
    Checksum,
    /// §7 step 12: the key type is not supported.
    TypeSupport,
    /// §7 step 13: the key material breaks the rules of its type.
    TypeRules,
}

use Pk::*;

/// The checks a reader can make only on a payload it has decoded.
const PAYLOAD: [Pk; 10] = [
    PayloadShort,
    Padding,
    VersionZero,
    VersionUnsupported,
    Lengths,
    PayloadLength,
    TypeName,
    Checksum,
    TypeSupport,
    TypeRules,
];

/// The checks whose break leaves no string that §7 step 4 accepts, so a
/// reader that decodes only such strings never reaches a payload.
const UNDECODABLE: [Pk; 4] = [PrivateKeySignature, NotUtf8, NotAscii, NotBech32];

/// Whether no file breaks both checks under any reading.
fn exclusive(a: Pk, b: Pk) -> bool {
    // The version is one byte, and only a supported type has rules of its
    // own, under a name of the grammar.
    across(a, b, &[VersionZero], &[VersionUnsupported])
        || across(a, b, &[TypeSupport, TypeName], &[TypeRules])
}

/// The checks of another class than `PayloadShort` that a payload too short
/// for its fixed fields can break only once it holds the type name they read,
/// and then it declares more than it holds: as this build's version lays out
/// the payload, every file that breaks both also breaks `PayloadLength`, of
/// `PayloadShort`'s class, between them. `case_breaks` asserts that premise on
/// every case.
const SHADOWED_BY_PAYLOAD_LENGTH: [Pk; 2] = [TypeName, TypeSupport];

/// Whether every file that breaks both checks also breaks a check of the
/// earlier one's class between them, so that the pair of that check and the
/// later one counts instead (§12.3). On a newer version's file, whose layout
/// this list does not know, no check past those the version keeps fixes an
/// order at all, so the premise needs only this build's layout.
fn shadowed(earlier: Pk, later: Pk) -> bool {
    earlier == PayloadShort && SHADOWED_BY_PAYLOAD_LENGTH.contains(&later)
}

/// Whether one file can break both checks for a reader of `reading`: one that
/// decodes only the strings §7 step 4 accepts never reaches the payload of
/// another, and one that judges support only on a name of the grammar never
/// breaks type support together with the type-name check.
fn both_breakable(reading: Reading, a: Pk, b: Pk) -> bool {
    (reading.lenient || !across(a, b, &UNDECODABLE, &PAYLOAD))
        && (reading.support_of_any_name || !across(a, b, &[TypeName], &[TypeSupport]))
}

struct PublicKeyList;

impl CheckList for PublicKeyList {
    type Check = Pk;

    fn order() -> &'static [Pk] {
        &[
            FileTooLong,
            PrivateKeySignature,
            NotUtf8,
            NotAscii,
            StringTooLong,
            StringCap,
            NotBech32,
            PayloadShort,
            Padding,
            VersionZero,
            VersionUnsupported,
            Lengths,
            PayloadLength,
            TypeName,
            Checksum,
            TypeSupport,
            TypeRules,
        ]
    }

    fn class(check: Pk) -> &'static str {
        match check {
            PrivateKeySignature => "wrong_key_file_type",
            NotUtf8 => "not_a_key_file",
            StringCap => "resource_cap_exceeded",
            VersionUnsupported => "unsupported_public_key_version",
            TypeName => "malformed_type_name",
            TypeSupport => "unsupported_key_type",
            FileTooLong | NotAscii | StringTooLong | NotBech32 | PayloadShort | Padding
            | VersionZero | Lengths | PayloadLength | Checksum | TypeRules => {
                "malformed_public_key"
            }
        }
    }

    fn claimed(earlier: Pk, later: Pk) -> bool {
        !exclusive(earlier, later) && !shadowed(earlier, later)
    }

    // A key file holds no recipient entries, so one direction stands for both.
    fn directions(_group: usize) -> &'static [Direction] {
        &[Direction::FrontToBack]
    }
}

/// What a reader declaring a capability supports beyond this build.
#[derive(Default)]
struct Capabilities {
    versions: BTreeSet<u8>,
    key_types: BTreeSet<String>,
}

impl ReaderCapabilities for Capabilities {
    type Check = Pk;

    fn declaring(run: &[String]) -> (Self, BTreeSet<Pk>) {
        let mut capabilities = Self::default();
        let mut changed = BTreeSet::new();
        for capability_id in run {
            let (domain, subject) = capability_parts(capability_id)
                .unwrap_or_else(|| panic!("{capability_id}: not a capability ID"));
            match domain {
                PUBLIC_KEY_VERSION_DOMAIN => {
                    let version = subject_version(subject)
                        .unwrap_or_else(|| panic!("{capability_id}: not a version"));
                    capabilities.versions.insert(version);
                    changed.insert(VersionUnsupported);
                }
                KEY_TYPE_DOMAIN => {
                    capabilities.key_types.insert(subject.to_string());
                    changed.extend([TypeSupport, TypeRules]);
                }
                OUTER_VERSION_DOMAIN
                | RECIPIENT_TYPE_DOMAIN
                | FCA_VERSION_DOMAIN
                | PRIVATE_KEY_VERSION_DOMAIN
                | OUTER_TLV_DOMAIN
                | PRIVATE_KEY_TLV_DOMAIN
                | FCA_ARCHIVE_TLV_DOMAIN
                | FCA_ENTRY_TLV_DOMAIN => {}
                other => panic!("{capability_id}: unknown capability domain {other}"),
            }
        }
        (capabilities, changed)
    }
}

impl Capabilities {
    fn supports_version(&self, version: u8) -> bool {
        version == PUBLIC_KEY_VERSION || self.versions.contains(&version)
    }
}

/// Where a reader takes the key material and the internal checksum from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tail {
    /// The material as long as the payload declares, and the checksum right
    /// after it.
    Declared,
    /// The material as long as the payload declares, and the checksum from
    /// the end of the payload.
    ChecksumAtEnd,
    /// The checksum from the end of the payload, and the material as every
    /// byte between the type name and that checksum.
    MaterialToChecksum,
}

/// How a reader that makes a check first reads a `public.key`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Reading {
    /// Whether it decodes the data part of a string that §7 step 4 refuses,
    /// whatever its case, human-readable part, and BIP 173 checksum.
    lenient: bool,
    tail: Tail,
    /// Whether it reads a file only as far as one byte past the 20,001-byte
    /// ceiling.
    capped: bool,
    /// Whether it judges the support of a type name that breaks the grammar.
    support_of_any_name: bool,
}

impl Reading {
    /// The reading of the reader the specification describes.
    const SPECIFICATION: Reading = Reading {
        lenient: false,
        tail: Tail::Declared,
        capped: false,
        support_of_any_name: false,
    };

    /// Every reading.
    fn all() -> Vec<Reading> {
        let mut readings = Vec::new();
        for lenient in [false, true] {
            for tail in [
                Tail::Declared,
                Tail::ChecksumAtEnd,
                Tail::MaterialToChecksum,
            ] {
                for capped in [false, true] {
                    for support_of_any_name in [false, true] {
                        readings.push(Reading {
                            lenient,
                            tail,
                            capped,
                            support_of_any_name,
                        });
                    }
                }
            }
        }
        readings
    }
}

/// BIP 173 Bech32 with no limit on length, so a check a reader makes first
/// sees whether a string past the 20,000-character ceiling decodes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AnyLengthBech32 {}

impl Checksum for AnyLengthBech32 {
    type MidstateRepr = <bech32::Bech32 as Checksum>::MidstateRepr;
    const CHECKSUM_LENGTH: usize = <bech32::Bech32 as Checksum>::CHECKSUM_LENGTH;
    const CODE_LENGTH: usize = usize::MAX;
    const GENERATOR_SH: [Self::MidstateRepr; 5] = <bech32::Bech32 as Checksum>::GENERATOR_SH;
    const TARGET_RESIDUE: Self::MidstateRepr = <bech32::Bech32 as Checksum>::TARGET_RESIDUE;
}

/// Whether `string` meets §7 step 4: lowercase Bech32 under the BIP 173
/// checksum, with the human-readable part `fcr`.
fn is_recipient_bech32(string: &[u8]) -> bool {
    std::str::from_utf8(string).is_ok_and(|text| {
        !text.bytes().any(|byte| byte.is_ascii_uppercase())
            && CheckedHrpstring::new::<AnyLengthBech32>(text)
                .is_ok_and(|checked| checked.hrp() == RECIPIENT_HRP)
    })
}

/// The 5-bit groups of the data part of `string`, read whatever its case and
/// its human-readable part, without the BIP 173 checksum, or none when it has
/// no separator or holds a character outside the Bech32 alphabet.
fn data_groups(string: &[u8]) -> Option<Vec<u8>> {
    let separator = string.iter().rposition(|&byte| byte == b'1')?;
    let data = &string[separator + 1..];
    let checksum_length = <bech32::Bech32 as Checksum>::CHECKSUM_LENGTH;
    data.get(..data.len().checked_sub(checksum_length)?)?
        .iter()
        .map(|&byte| {
            Fe32::from_char(char::from(byte.to_ascii_lowercase()))
                .ok()
                .map(Fe32::to_u8)
        })
        .collect()
}

/// The bytes `groups` carry, and whether their padding is canonical (§7 step
/// 6): fewer than five bits left over, all zero.
fn groups_to_bytes(groups: &[u8]) -> (Vec<u8>, bool) {
    const GROUP_BITS: u32 = 5;
    let mut bytes = Vec::new();
    let mut held = 0u32;
    let mut bits = 0u32;
    for &group in groups {
        held = (held << GROUP_BITS) | u32::from(group);
        bits += GROUP_BITS;
        if bits >= u8::BITS {
            bits -= u8::BITS;
            bytes.push((held >> bits) as u8);
            held &= (1 << bits) - 1;
        }
    }
    (bytes, bits < GROUP_BITS && held == 0)
}

/// Whether readers that count `string` in bytes and those that count it in
/// characters find it longer than `limit`: by both, by one, or by neither.
fn longer_than(string: &[u8], limit: usize) -> Option<bool> {
    let by_bytes = string.len() > limit;
    let by_chars = String::from_utf8_lossy(string).chars().count() > limit;
    match (by_bytes, by_chars) {
        (true, true) => Some(true),
        (false, false) => None,
        _ => Some(false),
    }
}

/// What a reader of one reading finds in a `public.key`.
struct Decoded {
    /// Every check of the list the file breaks for that reader.
    breaks: Breaks<Pk>,
    /// The `public_key_version` byte of the payload it decodes, if any.
    version: Option<u8>,
    /// The type name that payload holds, if any.
    type_name: Option<Vec<u8>>,
}

/// What a reader of `reading` with `capabilities` finds in the file `bytes`,
/// each check evaluated on its own, as a reader that made it first would see
/// it: once, or twice when the reader stops short of the end on a line feed,
/// which it may strip as the final one or keep. The variant that strips it
/// comes first; the other decodes no payload, as a line feed is outside the
/// Bech32 alphabet.
fn reading_breaks(
    bytes: &[u8],
    profile: &Row,
    capabilities: &Capabilities,
    reading: Reading,
) -> Vec<Decoded> {
    let mut breaks = Breaks::default();
    let read = if reading.capped {
        &bytes[..bytes.len().min(PUBLIC_KEY_FILE_READ_CAP_BYTES + 1)]
    } else {
        bytes
    };
    if read.len() > PUBLIC_KEY_FILE_READ_CAP_BYTES {
        breaks.add(FileTooLong, true);
    }
    if has_private_key_signature(read) {
        breaks.add(PrivateKeySignature, true);
    }
    if std::str::from_utf8(read).is_err() {
        breaks.add(NotUtf8, true);
    }
    let stripped = read.strip_suffix(b"\n").unwrap_or(read);
    let mut variants = vec![string_breaks(
        breaks.clone(),
        stripped,
        profile,
        capabilities,
        reading,
    )];
    if read.len() < bytes.len() && stripped.len() < read.len() {
        variants.push(string_breaks(breaks, read, profile, capabilities, reading));
    }
    variants
}

/// What a reader of `reading` with `capabilities` finds in the recipient
/// string `string`, recorded with `breaks`, the checks its file breaks.
fn string_breaks(
    mut breaks: Breaks<Pk>,
    string: &[u8],
    profile: &Row,
    capabilities: &Capabilities,
    reading: Reading,
) -> Decoded {
    if !string.is_ascii() {
        breaks.add(NotAscii, true);
    }
    if let Some(certain) = longer_than(string, RECIPIENT_STRING_LEN_MAX) {
        breaks.add(StringTooLong, certain);
    }
    let cap = ProfileCaps::new(profile)
        .key_read()
        .recipient_string_chars();
    if let Some(certain) = longer_than(string, cap) {
        breaks.add(StringCap, certain);
    }
    let bech32 = is_recipient_bech32(string);
    if !bech32 {
        breaks.add(NotBech32, true);
    }
    let decoded = (bech32 || reading.lenient)
        .then(|| data_groups(string))
        .flatten()
        .map(|groups| groups_to_bytes(&groups));
    let Some((payload, canonical)) = decoded else {
        return Decoded {
            breaks,
            version: None,
            type_name: None,
        };
    };
    if payload.len() < PAYLOAD_HEADER_SIZE + PUBLIC_KEY_CHECKSUM_SIZE {
        breaks.add(PayloadShort, true);
    }
    if !canonical {
        breaks.add(Padding, true);
    }
    let version = payload.get(PAYLOAD_VERSION_OFFSET).copied();
    match version {
        Some(0) => breaks.add(VersionZero, true),
        Some(version) if !capabilities.supports_version(version) => {
            breaks.add(VersionUnsupported, true)
        }
        _ => {}
    }
    let type_name_len = read_u16_be(&payload, PAYLOAD_TYPE_NAME_LEN_OFFSET)
        .ok()
        .map(usize::from);
    let material_len = read_u32_be(&payload, PAYLOAD_KEY_MATERIAL_LEN_OFFSET)
        .ok()
        .map(|len| len as usize);
    let name_len_wrong = type_name_len.is_some_and(|len| !(1..=TYPE_NAME_MAX_LEN).contains(&len));
    let material_len_wrong = material_len.is_some_and(|len| len > KEY_MATERIAL_LEN_MAX as usize);
    if name_len_wrong || material_len_wrong {
        breaks.add(Lengths, true);
    }
    let (Some(type_name_len), Some(material_len)) = (type_name_len, material_len) else {
        return Decoded {
            breaks,
            version,
            type_name: None,
        };
    };
    let fields = PAYLOAD_HEADER_SIZE + type_name_len + material_len;
    if payload.len() != fields + PUBLIC_KEY_CHECKSUM_SIZE {
        breaks.add(PayloadLength, true);
    }
    let name_end = PAYLOAD_HEADER_SIZE + type_name_len;
    let Some(type_name) = payload.get(PAYLOAD_HEADER_SIZE..name_end) else {
        return Decoded {
            breaks,
            version,
            type_name: None,
        };
    };
    let native = type_name == x25519::TYPE_NAME.as_bytes();
    let added =
        std::str::from_utf8(type_name).is_ok_and(|name| capabilities.key_types.contains(name));
    let named = type_name_breaks(type_name, native || added, reading.support_of_any_name);
    if let Some(certain) = named.grammar {
        breaks.add(TypeName, certain);
    }
    let checksum_from_end = payload.len().checked_sub(PUBLIC_KEY_CHECKSUM_SIZE);
    let (material, stored) = match reading.tail {
        Tail::Declared => (
            payload.get(name_end..fields),
            payload.get(fields..fields + PUBLIC_KEY_CHECKSUM_SIZE),
        ),
        Tail::ChecksumAtEnd => (
            payload.get(name_end..fields),
            checksum_from_end.and_then(|start| payload.get(start..)),
        ),
        Tail::MaterialToChecksum => (
            checksum_from_end.and_then(|end| payload.get(name_end..end)),
            checksum_from_end.and_then(|start| payload.get(start..)),
        ),
    };
    if let (Some(version), Some(material), Some(stored)) = (version, material, stored) {
        if stored != compute_checksum(version, type_name, material) {
            breaks.add(Checksum, true);
        }
    }
    if let Some(certain) = named.support {
        breaks.add(TypeSupport, certain);
    }
    if native {
        let declared_wrong = material_len != x25519::PUBLIC_KEY_SIZE;
        // A reader that takes the material up to the checksum may judge its
        // length by those bytes or by the declared field.
        let length_rule = match reading.tail {
            Tail::MaterialToChecksum => length_rule_breaks(
                declared_wrong,
                material.map(|material| material.len() != x25519::PUBLIC_KEY_SIZE),
            ),
            Tail::Declared | Tail::ChecksumAtEnd => declared_wrong.then_some(true),
        };
        if let Some(certain) = length_rule {
            breaks.add(TypeRules, certain);
        }
        let key_rule = material
            .and_then(|material| <&[u8; x25519::PUBLIC_KEY_SIZE]>::try_from(material).ok())
            .is_some_and(|key| {
                x25519::is_zero_public_key(key) || !x25519::is_canonical_public_key_encoding(key)
            });
        if key_rule {
            breaks.add(TypeRules, true);
        }
    }
    Decoded {
        breaks,
        version,
        type_name: Some(type_name.to_vec()),
    }
}

/// The checks a file of a public-key encoding version that a reader supports,
/// other than this build's, still breaks for that reader: those on the file
/// and the string, the padding of its data part, and the size of the payload's
/// fixed fields, which §7 makes the same whatever the version, so that they
/// read nothing a newer version may lay out differently (see
/// [`Breaks::as_newer_version`]). Such a file fixes no order of the other
/// checks for that reader, so a pair that rests on it alone is reported as a
/// loss.
const KEPT_BY_NEWER_VERSIONS: [Pk; 9] = [
    FileTooLong,
    PrivateKeySignature,
    NotUtf8,
    NotAscii,
    StringTooLong,
    StringCap,
    NotBech32,
    PayloadShort,
    Padding,
];

/// Every check a case's artifact breaks for a reader of `reading` with
/// `capabilities`. Also asserts the premise of [`shadowed`], that the
/// specification's reader reports the stored class, and that no payload names
/// a key type a capability adds, whose rules this list does not know.
fn case_breaks(
    row: &Row,
    bytes: &[u8],
    profile: &Row,
    capabilities: &Capabilities,
    reading: Reading,
) -> Breaks<Pk> {
    let variants = reading_breaks(bytes, profile, capabilities, reading);
    for Decoded { breaks, .. } in &variants {
        assert!(
            !breaks.is_broken(PayloadShort)
                || !SHADOWED_BY_PAYLOAD_LENGTH
                    .into_iter()
                    .any(|check| breaks.is_broken(check))
                || breaks.certain.contains(&(PayloadLength, None)),
            "{} under {reading:?}: a payload too short for its fixed fields holds its type \
             name but declares no more than it holds",
            field(row, "case_id")
        );
    }
    let mut variants = variants.into_iter();
    let Decoded {
        breaks,
        version,
        type_name,
    } = variants.next().expect("a reading has a variant");
    let mut breaks =
        Breaks::merge(std::iter::once(breaks).chain(variants.map(|variant| variant.breaks)));
    assert!(
        !type_name.is_some_and(|name| {
            std::str::from_utf8(&name).is_ok_and(|name| capabilities.key_types.contains(name))
        }),
        "{}: a reader that declares a key type applies rules this list does not know",
        field(row, "case_id")
    );
    if version.is_some_and(|version| {
        version != PUBLIC_KEY_VERSION && capabilities.supports_version(version)
    }) {
        breaks.as_newer_version(&KEPT_BY_NEWER_VERSIONS);
    }
    if reading == Reading::SPECIFICATION {
        assert_specification_report::<PublicKeyList>(row, &breaks);
    }
    breaks
}

/// Every rejected `public.key` case of the committed corpus, evaluated once
/// per test run for each reading.
fn loaded_cases() -> &'static LoadedReadings<Pk, Reading> {
    static CASES: OnceLock<LoadedReadings<Pk, Reading>> = OnceLock::new();
    CASES.get_or_init(|| {
        let root = corpus_root().expect("the corpus is on disk");
        let profiles = limit_profiles(&root);
        let cases = rejected_cases(&root, "public_key_decode");
        load_readings::<Capabilities, _>(&cases, &Reading::all(), |row, bytes, run, reading| {
            let (capabilities, _) = Capabilities::declaring(run);
            let profile = &profiles[field(row, "limit_profile_id")];
            case_breaks(row, bytes, profile, &capabilities, reading)
        })
    })
}

/// The §12.3 `public.key` check-order row holds: for the readers of each
/// reading, the cases fix every claimed pair that such a reader can break
/// together, and a reader that declares capabilities loses only pairs with a
/// check they change.
#[test]
fn the_corpus_fixes_every_claimed_public_key_check_order() {
    if corpus_root().is_none() {
        return;
    }
    let open = stray_open_pairs::<PublicKeyList, Capabilities, _>(loaded_cases(), both_breakable);
    assert!(
        open.is_empty(),
        "the corpus leaves these `public.key` check pairs open: {open:#?}"
    );
}

/// The order of a pair `shadowed` leaves out shows through the payload-length
/// check, whose own pair with the later check the claim covers.
#[test]
fn a_shadowed_pair_shows_through_a_claimed_pair() {
    let position = |check: Pk| {
        PublicKeyList::order()
            .iter()
            .position(|&other| other == check)
            .expect("a check of the list")
    };
    for later in SHADOWED_BY_PAYLOAD_LENGTH {
        assert!(position(PayloadShort) < position(PayloadLength));
        assert!(position(PayloadLength) < position(later));
        assert_eq!(
            PublicKeyList::class(PayloadLength),
            PublicKeyList::class(PayloadShort)
        );
        assert_ne!(
            PublicKeyList::class(PayloadLength),
            PublicKeyList::class(later)
        );
        assert!(PublicKeyList::claimed(PayloadLength, later));
    }
}

/// The checker finds open pairs: the case named for each pair is the only one
/// that fixes it for the readers of the stated reading, so leaving it out
/// reopens the pair. If a later case fixes one of these pairs too, the pair
/// needs another witness.
#[test]
fn leaving_out_the_witnesses_reopens_their_pair() {
    if corpus_root().is_none() {
        return;
    }
    let lenient = Reading {
        lenient: true,
        ..Reading::SPECIFICATION
    };
    let specification: &[(&str, (Pk, Pk))] = &[
        ("public-key-order-ascii-before-cap", (NotAscii, StringCap)),
        (
            "public-key-order-cap-before-payload-size",
            (StringCap, PayloadShort),
        ),
        (
            "public-key-order-padding-before-version",
            (Padding, VersionUnsupported),
        ),
        (
            "public-key-order-type-name-before-internal-checksum",
            (TypeName, Checksum),
        ),
        (
            "public-key-order-internal-checksum-before-type-support",
            (Checksum, TypeSupport),
        ),
        (
            "public-key-order-version-before-type-rules",
            (VersionUnsupported, TypeRules),
        ),
    ];
    // Only a reader that decodes a string §7 step 4 refuses reaches its
    // version.
    let lenient_only: &[(&str, (Pk, Pk))] = &[(
        "public-key-order-bech32-before-version",
        (NotBech32, VersionUnsupported),
    )];
    let witnessed = [
        (Reading::SPECIFICATION, specification),
        (lenient, lenient_only),
    ];
    for (reading, witnesses) in witnessed {
        let (_, cases) = loaded_cases()
            .readings
            .iter()
            .find(|(loaded, _)| *loaded == reading)
            .expect("every reading is loaded");
        let base = evidence::<PublicKeyList>(cases, &[]);
        for &(witness, pair) in witnesses {
            assert!(
                reopens::<PublicKeyList>(&base, &[witness], pair),
                "without {witness}, {pair:?} should be open for a reader of {reading:?}"
            );
        }
    }
}
