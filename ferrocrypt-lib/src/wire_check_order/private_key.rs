//! The `private.key` check lists of the §12.3 order row: the checks of
//! `FORMAT.md` §8, through each reader that makes them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use ferrocrypt_test_support::wire_manifest::{
    FCA_ARCHIVE_TLV_DOMAIN, FCA_ENTRY_TLV_DOMAIN, FCA_VERSION_DOMAIN, KEY_TYPE_DOMAIN,
    OUTER_TLV_DOMAIN, OUTER_VERSION_DOMAIN, PRIVATE_KEY_TLV_DOMAIN, PRIVATE_KEY_VERSION_DOMAIN,
    PUBLIC_KEY_VERSION_DOMAIN, RECIPIENT_TYPE_DOMAIN, capability_parts, field, subject_tag,
    subject_version,
};
use zeroize::Zeroizing;

use super::{
    Breaks, CheckList, Direction, LoadedReadings, ProfileCaps, ReaderCapabilities, Row, across,
    assert_specification_report, corpus_root, evidence, length_rule_breaks, limit_profiles,
    load_readings, over_kdf_cap, rejected_cases, reopens, stray_open_pairs, type_name_breaks,
};
use crate::crypto::aead::{WRAP_NONCE_SIZE, open_with_aad};
use crate::crypto::kdf::{ARGON2_SALT_SIZE, KDF_PARAMS_SIZE, KdfParams};
use crate::crypto::keys::{ENCRYPTION_KEY_SIZE, derive_passphrase_wrap_key};
use crate::crypto::tlv::{ENTRY_HEADER_SIZE, TlvClass, classify_tlv_tag, scan_tlv_region};
use crate::error::FormatDefect;
use crate::format::{
    KIND_PRIVATE_KEY, MAGIC, MAGIC_SIZE, RECIPIENT_STRING_PREFIX, read_u16_be, read_u32_be,
};
use crate::key::files::read_private_key_bytes;
use crate::key::private::{
    ARGON2_SALT_OFFSET, EXT_LEN_OFFSET, HKDF_INFO_PRIVATE_KEY_WRAP, KDF_PARAMS_OFFSET,
    KEY_FLAGS_OFFSET, KIND_OFFSET, PRIVATE_KEY_EXT_LEN_MAX, PRIVATE_KEY_FILE_READ_CAP_BYTES,
    PRIVATE_KEY_HEADER_FIXED_SIZE, PRIVATE_KEY_PUBLIC_LEN_MAX, PRIVATE_KEY_VERSION,
    PRIVATE_KEY_WRAPPED_SECRET_LEN_MAX, PRIVATE_KEY_WRAPPED_SECRET_LEN_MIN, PUBLIC_LEN_OFFSET,
    PrivateKeyHeader, TYPE_NAME_LEN_OFFSET, VERSION_OFFSET, WRAP_NONCE_OFFSET,
    WRAPPED_SECRET_LEN_OFFSET,
};
use crate::passphrase::Passphrase;
use crate::recipient::name::TYPE_NAME_MAX_LEN;
use crate::recipient::native::x25519;
use crate::wire_vector_gen::{CorpusCredential, read_credential};
use crate::{CryptoError, KeyReadLimits};

/// One check of `FORMAT.md` §8, in the order the specification fixes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Sk {
    /// Step 0: the file opens with `fcr1`, the start of every recipient
    /// string.
    PublicKeyPrefix,
    /// Step 1: the file is shorter than the 90-byte fixed header.
    HeaderShort,
    /// Step 2: `magic` is not `FCR\0`.
    Magic,
    /// Step 3: `kind` is not `0x4B`.
    Kind,
    /// Step 4: `version` is `0x00`.
    VersionZero,
    /// Step 4: a nonzero `version` the reader does not support.
    VersionUnsupported,
    /// Step 5: `key_flags` is not zero.
    KeyFlags,
    /// Step 6: a length field is outside its structural limit.
    Lengths,
    /// Step 7: `kdf_params` is outside the §2.2 bounds.
    KdfBounds,
    /// Step 8: `kdf_params` exceeds a local KDF cap.
    KdfCap,
    /// Step 9: `wrapped_secret_len` exceeds the local cap.
    WrappedSecretCap,
    /// Step 10: the file length differs from the total its fields declare.
    FileLength,
    /// Step 11: `type_name` is not valid UTF-8 or breaks the §3.3 grammar.
    TypeName,
    /// Step 12: AEAD authentication fails.
    Unlock,
    /// Step 13: `ext_bytes` breaks a §6 rule other than rule 7.
    TlvMalformed,
    /// Step 13: `ext_bytes` holds an unknown critical tag.
    TlvUnknownCritical,
    /// Step 14: the key type is not supported.
    TypeSupport,
    /// Step 15: the key breaks the rules of its type.
    TypeRules,
}

use Sk::*;

/// The diagnostic class each check reports (`FORMAT.md` §12.1).
fn class(check: Sk) -> &'static str {
    match check {
        PublicKeyPrefix => "wrong_key_file_type",
        Magic => "not_a_key_file",
        Kind => "wrong_kind",
        VersionUnsupported => "unsupported_private_key_version",
        KdfBounds => "invalid_kdf_parameters",
        KdfCap | WrappedSecretCap => "resource_cap_exceeded",
        TypeName => "malformed_type_name",
        Unlock => "private_key_unlock_failed",
        TlvMalformed => "malformed_tlv",
        TlvUnknownCritical => "unknown_critical_tlv",
        TypeSupport => "unsupported_key_type",
        HeaderShort | VersionZero | KeyFlags | Lengths | FileLength | TypeRules => {
            "malformed_private_key"
        }
    }
}

/// The checks that read past the fixed header, which a file shorter than it
/// cannot break.
const PAST_FIXED_HEADER: [Sk; 6] = [
    TypeName,
    Unlock,
    TlvMalformed,
    TlvUnknownCritical,
    TypeSupport,
    TypeRules,
];

/// Whether no file breaks both checks under any reading.
fn exclusive(a: Sk, b: Sk) -> bool {
    // The version is one byte, only a supported type has rules of its own,
    // under a name of the grammar, and a file shorter than the fixed header
    // holds nothing past it.
    across(a, b, &[VersionZero], &[VersionUnsupported])
        || across(a, b, &[TypeSupport, TypeName], &[TypeRules])
        || across(a, b, &[HeaderShort], &PAST_FIXED_HEADER)
}

/// The checks of steps 0 to 7: those the header parse of this build makes, on
/// whose break its staged read stops after the fixed header.
const FIXED_HEADER_CHECKS: [Sk; 9] = [
    PublicKeyPrefix,
    HeaderShort,
    Magic,
    Kind,
    VersionZero,
    VersionUnsupported,
    KeyFlags,
    Lengths,
    KdfBounds,
];

/// The local caps of the unlock, steps 8 and 9, which read the fixed header
/// alone.
const CAP_CHECKS: [Sk; 2] = [KdfCap, WrappedSecretCap];

/// Whether one file can break both checks for a reader of `reading`: one that
/// judges support only on a name of the grammar never breaks type support
/// together with the type-name check, and one that stops after the fixed
/// header on a check holds no type name long enough to have rules of its own
/// when that check breaks.
fn both_breakable(reading: Reading, a: Sk, b: Sk) -> bool {
    let stopped = |x: Sk, y: Sk| x == TypeRules && reading.extent.stops_on(y);
    (reading.support_of_any_name || !across(a, b, &[TypeName], &[TypeSupport]))
        && !stopped(a, b)
        && !stopped(b, a)
}

/// The list of a `private.key` reader: the unlock, which makes every step of
/// §8, when `UNLOCKS`, and otherwise validation, which applies no local cap
/// and does not unlock: it skips steps 8, 9, 12, and 13, and at step 15
/// applies only the rules that need no secret.
struct PrivateKeyList<const UNLOCKS: bool>;

/// The unlock's list.
type OpenList = PrivateKeyList<true>;

/// Validation's list.
type ValidateList = PrivateKeyList<false>;

const OPEN_ORDER: [Sk; 18] = [
    PublicKeyPrefix,
    HeaderShort,
    Magic,
    Kind,
    VersionZero,
    VersionUnsupported,
    KeyFlags,
    Lengths,
    KdfBounds,
    KdfCap,
    WrappedSecretCap,
    FileLength,
    TypeName,
    Unlock,
    TlvMalformed,
    TlvUnknownCritical,
    TypeSupport,
    TypeRules,
];

const VALIDATE_ORDER: [Sk; 13] = [
    PublicKeyPrefix,
    HeaderShort,
    Magic,
    Kind,
    VersionZero,
    VersionUnsupported,
    KeyFlags,
    Lengths,
    KdfBounds,
    FileLength,
    TypeName,
    TypeSupport,
    TypeRules,
];

impl<const UNLOCKS: bool> CheckList for PrivateKeyList<UNLOCKS> {
    type Check = Sk;

    fn order() -> &'static [Sk] {
        if UNLOCKS {
            &OPEN_ORDER
        } else {
            &VALIDATE_ORDER
        }
    }

    fn class(check: Sk) -> &'static str {
        class(check)
    }

    fn claimed(earlier: Sk, later: Sk) -> bool {
        !exclusive(earlier, later)
    }

    // A key file holds no recipient entries, so one direction stands for both.
    fn directions(_group: usize) -> &'static [Direction] {
        &[Direction::FrontToBack]
    }
}

/// The two `private.key` readers of the corpus.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reader {
    Validate,
    Open,
}

impl Reader {
    /// The case type the corpus replays through this reader.
    fn case_type(self) -> &'static str {
        match self {
            Reader::Validate => "private_key_validate",
            Reader::Open => "private_key_open",
        }
    }
}

/// What a reader declaring a capability supports beyond this build.
#[derive(Default)]
struct Capabilities {
    versions: BTreeSet<u8>,
    key_types: BTreeSet<String>,
    tlv_tags: BTreeSet<u16>,
}

impl ReaderCapabilities for Capabilities {
    type Check = Sk;

    fn declaring(run: &[String]) -> (Self, BTreeSet<Sk>) {
        let mut capabilities = Self::default();
        let mut changed = BTreeSet::new();
        for capability_id in run {
            let (domain, subject) = capability_parts(capability_id)
                .unwrap_or_else(|| panic!("{capability_id}: not a capability ID"));
            match domain {
                PRIVATE_KEY_VERSION_DOMAIN => {
                    let version = subject_version(subject)
                        .unwrap_or_else(|| panic!("{capability_id}: not a version"));
                    capabilities.versions.insert(version);
                    changed.insert(VersionUnsupported);
                }
                KEY_TYPE_DOMAIN => {
                    capabilities.key_types.insert(subject.to_string());
                    changed.extend([TypeSupport, TypeRules]);
                }
                PRIVATE_KEY_TLV_DOMAIN => {
                    let tag = subject_tag(subject)
                        .unwrap_or_else(|| panic!("{capability_id}: not a tag"));
                    capabilities.tlv_tags.insert(tag);
                    changed.insert(TlvUnknownCritical);
                }
                OUTER_VERSION_DOMAIN
                | RECIPIENT_TYPE_DOMAIN
                | FCA_VERSION_DOMAIN
                | PUBLIC_KEY_VERSION_DOMAIN
                | OUTER_TLV_DOMAIN
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
        version == PRIVATE_KEY_VERSION || self.versions.contains(&version)
    }
}

/// How far a reader reads a `private.key`. A file shorter than the fixed
/// header is read whole whatever the extent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Extent {
    /// The whole file.
    Whole,
    /// As far as the lengths the fixed header declares and one byte more,
    /// with the wrapped secret clamped at its cap and the whole at one byte
    /// past the most a `private.key` can hold.
    Declared,
    /// As [`Extent::Declared`] when the fixed header passes steps 0 to 7, and
    /// otherwise the fixed header and one byte more, as the staged read of
    /// this build does.
    HeadFirst,
    /// As [`Extent::HeadFirst`], stopping also when the fixed header breaks a
    /// local cap of the unlock.
    HeadFirstWithCaps,
}

impl Extent {
    /// Whether a reader reading to this extent stops after the fixed header
    /// and one byte when the fixed header breaks `check`.
    fn stops_on(self, check: Sk) -> bool {
        match self {
            Extent::Whole | Extent::Declared => false,
            Extent::HeadFirst => FIXED_HEADER_CHECKS.contains(&check),
            Extent::HeadFirstWithCaps => {
                FIXED_HEADER_CHECKS.contains(&check) || CAP_CHECKS.contains(&check)
            }
        }
    }

    /// Whether a reader reading to this extent stops after the fixed header
    /// and one byte, for a fixed header that breaks the checks of `breaks`.
    fn stops_after_header(self, breaks: &Breaks<Sk>) -> bool {
        OPEN_ORDER
            .into_iter()
            .any(|check| self.stops_on(check) && breaks.is_broken(check))
    }
}

/// How a reader that makes a check first reads a `private.key`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Reading {
    extent: Extent,
    /// Whether it takes every byte it holds after `ext_bytes` as the wrapped
    /// secret rather than the `wrapped_secret_len` bytes the header declares.
    secret_to_end: bool,
    /// Whether it judges the support of a type name that breaks the grammar.
    support_of_any_name: bool,
}

impl Reading {
    /// The reading of the reader the specification describes.
    const SPECIFICATION: Reading = Reading {
        extent: Extent::Whole,
        secret_to_end: false,
        support_of_any_name: false,
    };

    /// Every reading of `reader`. Validation applies no local cap, so it never
    /// stops on one.
    fn all(reader: Reader) -> Vec<Reading> {
        let extents: &[Extent] = match reader {
            Reader::Validate => &[Extent::Whole, Extent::Declared, Extent::HeadFirst],
            Reader::Open => &[
                Extent::Whole,
                Extent::Declared,
                Extent::HeadFirst,
                Extent::HeadFirstWithCaps,
            ],
        };
        let mut readings = Vec::new();
        for &extent in extents {
            for secret_to_end in [false, true] {
                for support_of_any_name in [false, true] {
                    readings.push(Reading {
                        extent,
                        secret_to_end,
                        support_of_any_name,
                    });
                }
            }
        }
        readings
    }
}

/// The bytes of the file `bytes` that a reader reading to `extent` holds, with
/// the wrapped secret clamped at `wrapped_secret_cap`. `stops_after_header`
/// says whether such a reader stops after the fixed header and one byte.
fn read_extent(
    bytes: &[u8],
    wrapped_secret_cap: u32,
    extent: Extent,
    stops_after_header: bool,
) -> &[u8] {
    if extent == Extent::Whole || bytes.len() < PRIVATE_KEY_HEADER_FIXED_SIZE {
        return bytes;
    }
    let past_fixed_header = if stops_after_header {
        0
    } else {
        let lengths = DeclaredLengths::read(bytes).expect("the fixed header is held");
        let declared = lengths.type_name
            + lengths.public
            + lengths.ext
            + lengths.wrapped_secret.min(u64::from(wrapped_secret_cap));
        declared.min((PRIVATE_KEY_FILE_READ_CAP_BYTES - PRIVATE_KEY_HEADER_FIXED_SIZE) as u64)
    };
    let end = PRIVATE_KEY_HEADER_FIXED_SIZE as u64 + past_fixed_header + 1;
    &bytes[..bytes.len().min(usize::try_from(end).unwrap_or(usize::MAX))]
}

/// The four length fields of the fixed header, read without their limits.
struct DeclaredLengths {
    type_name: u64,
    public: u64,
    ext: u64,
    wrapped_secret: u64,
}

impl DeclaredLengths {
    /// The fields `bytes` holds, or none when it stops before any of them.
    fn read(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            type_name: read_u16_be(bytes, TYPE_NAME_LEN_OFFSET).ok()?.into(),
            public: read_u32_be(bytes, PUBLIC_LEN_OFFSET).ok()?.into(),
            ext: read_u32_be(bytes, EXT_LEN_OFFSET).ok()?.into(),
            wrapped_secret: read_u32_be(bytes, WRAPPED_SECRET_LEN_OFFSET).ok()?.into(),
        })
    }

    fn type_name_end(&self) -> u64 {
        PRIVATE_KEY_HEADER_FIXED_SIZE as u64 + self.type_name
    }

    fn public_end(&self) -> u64 {
        self.type_name_end() + self.public
    }

    fn ext_end(&self) -> u64 {
        self.public_end() + self.ext
    }

    fn total(&self) -> u64 {
        self.ext_end() + self.wrapped_secret
    }
}

/// The bytes `read` holds from offset `start` up to `end`, or none when it
/// stops before `end`.
fn held(read: &[u8], start: u64, end: u64) -> Option<&[u8]> {
    read.get(usize::try_from(start).ok()?..usize::try_from(end).ok()?)
}

/// The KDF parameters the fixed header stores, read without the §2.2 bounds,
/// or none when the file stops before them.
fn stored_kdf_params(read: &[u8]) -> Option<([u8; KDF_PARAMS_SIZE], KdfParams)> {
    let stored: [u8; KDF_PARAMS_SIZE] = read
        .get(KDF_PARAMS_OFFSET..KDF_PARAMS_OFFSET + KDF_PARAMS_SIZE)?
        .try_into()
        .ok()?;
    let params = KdfParams::from_bytes_unvalidated(&stored).ok()?;
    Some((stored, params))
}

/// The most Argon2id work, in KiB times passes as `KdfLimit::max_work` counts
/// it, that this module spends on one unlock: well above the work the corpus
/// keys are sealed with, and far below the parameters its cap cases store. An
/// unlock that needs more is not tried.
const UNLOCK_WORK_BUDGET: u64 = 64 * 1024;

/// What the unlock reads besides the file: the caps of the case's limit
/// profile and the passphrase of its credential.
struct UnlockInputs<'a> {
    caps: ProfileCaps<'a>,
    credential_id: &'a str,
    passphrase: &'a Passphrase,
}

/// What authenticating the wrapped secret gives.
enum Unlocked {
    /// The secret material.
    Opened(Zeroizing<Vec<u8>>),
    /// Authentication fails.
    Refused,
    /// Not tried: the KDF parameters are outside the §2.2 bounds, where
    /// readers differ on what an unlock does, or need more work than
    /// [`UNLOCK_WORK_BUDGET`].
    NotTried,
}

/// What one wrap key derives from: the credential, the salt, and the KDF
/// parameters as stored.
type WrapKeyInputs = (String, [u8; ARGON2_SALT_SIZE], [u8; KDF_PARAMS_SIZE]);

/// The wrap keys derived so far, so that each Argon2id run happens once per
/// test run.
#[derive(Default)]
struct WrapKeys(BTreeMap<WrapKeyInputs, Zeroizing<[u8; ENCRYPTION_KEY_SIZE]>>);

impl WrapKeys {
    /// Authenticates `wrapped` with `aad` under the passphrase of `unlock` and
    /// the salt, KDF parameters, and nonce of the fixed header `read` holds.
    fn unlock(
        &mut self,
        unlock: &UnlockInputs,
        read: &[u8],
        aad: &[u8],
        wrapped: &[u8],
    ) -> Unlocked {
        let fixed = |offset: usize, len: usize| &read[offset..offset + len];
        let (stored, params) = stored_kdf_params(read).expect("the fixed header is held");
        let work = u64::from(params.mem_cost) * u64::from(params.time_cost);
        if params.validate_structural().is_err() || work > UNLOCK_WORK_BUDGET {
            return Unlocked::NotTried;
        }
        let salt: [u8; ARGON2_SALT_SIZE] = fixed(ARGON2_SALT_OFFSET, ARGON2_SALT_SIZE)
            .try_into()
            .expect("the salt is held");
        let nonce: [u8; WRAP_NONCE_SIZE] = fixed(WRAP_NONCE_OFFSET, WRAP_NONCE_SIZE)
            .try_into()
            .expect("the nonce is held");
        let key = self
            .0
            .entry((unlock.credential_id.to_string(), salt, stored))
            .or_insert_with(|| {
                derive_passphrase_wrap_key(
                    unlock.passphrase,
                    &salt,
                    &params,
                    HKDF_INFO_PRIVATE_KEY_WRAP,
                )
                .expect("derive a wrap key within the §2.2 bounds")
            });
        match open_with_aad(key, &nonce, wrapped, aad, || {
            CryptoError::KeyFileUnlockFailed
        }) {
            Ok(secret) => Unlocked::Opened(secret),
            Err(_) => Unlocked::Refused,
        }
    }
}

/// Whether readers that check `region` against the §6 rules other than rule 7
/// find it malformed: all of them, or only those that apply the cap
/// `private.key` sets on the region and on each value, which the length check
/// already applies to the region. None when it breaks none of those rules.
fn malformed_tlv(region: &[u8]) -> Option<bool> {
    match scan_tlv_region(region, u32::MAX, u32::MAX) {
        Err(CryptoError::InvalidFormat(FormatDefect::MalformedTlv)) => Some(true),
        Err(other) => panic!("scanning a TLV region: {other:?}"),
        Ok(_) => scan_tlv_region(region, PRIVATE_KEY_EXT_LEN_MAX, PRIVATE_KEY_EXT_LEN_MAX)
            .is_err()
            .then_some(false),
    }
}

/// Whether readers that look for an unknown critical tag in `region` before
/// checking the other §6 rules find one: all of them when it sits in an entry
/// before any entry that breaks another rule, and only some of them when it
/// sits in that entry, or past it in an entry they can still frame. None when
/// no such reader finds one. A tag `known` holds is one a capability adds,
/// whose rules these lists do not know, and is refused.
fn unknown_critical_tag(region: &[u8], known: &BTreeSet<u16>) -> Option<bool> {
    let mut found = None;
    let mut cursor = 0;
    let mut previous: Option<u16> = None;
    let mut clean_so_far = true;
    while let Ok(tag) = read_u16_be(region, cursor) {
        let value_start = cursor + ENTRY_HEADER_SIZE;
        let len = read_u32_be(region, cursor + size_of::<u16>())
            .ok()
            .and_then(|len| usize::try_from(len).ok());
        let fits = len.is_some_and(|len| {
            value_start
                .checked_add(len)
                .is_some_and(|end| end <= region.len())
        });
        let class = classify_tlv_tag(tag);
        let kept = fits
            && len.is_some_and(|len| len <= PRIVATE_KEY_EXT_LEN_MAX as usize)
            && class.is_ok()
            && previous.is_none_or(|previous| tag > previous);
        if matches!(class, Ok(TlvClass::Critical)) {
            assert!(
                !known.contains(&tag),
                "a reader that declares TLV tag {tag:#06X} applies rules this list does not know"
            );
            found = Some(found.unwrap_or(false) || (clean_so_far && kept));
        }
        clean_so_far &= kept;
        let (true, Some(len)) = (fits, len) else {
            break;
        };
        previous = Some(tag);
        cursor = value_start + len;
    }
    found
}

/// Every check `bytes` breaks for a reader of `reading` with `capabilities`,
/// each evaluated on its own, as a reader that made it first would see it, and
/// the type name the file holds, if any. `unlock` is given for the unlock and
/// is none for validation, which skips the checks that need it.
fn reading_breaks(
    bytes: &[u8],
    unlock: Option<&UnlockInputs>,
    wrap_keys: &mut WrapKeys,
    capabilities: &Capabilities,
    reading: Reading,
) -> (Breaks<Sk>, Option<Vec<u8>>) {
    let mut breaks = fixed_header_breaks(bytes, unlock, capabilities);
    let caps = unlock.map(|unlock| &unlock.caps);
    let read = read_extent(
        bytes,
        wrapped_secret_cap(caps),
        reading.extent,
        reading.extent.stops_after_header(&breaks),
    );
    let Some(lengths) = DeclaredLengths::read(read) else {
        return (breaks, None);
    };
    if read.len() as u64 != lengths.total() {
        breaks.add(FileLength, true);
    }
    let type_name = held(
        read,
        PRIVATE_KEY_HEADER_FIXED_SIZE as u64,
        lengths.type_name_end(),
    );
    let native = type_name == Some(x25519::TYPE_NAME.as_bytes());
    let named = type_name.map(|name| {
        let added =
            std::str::from_utf8(name).is_ok_and(|name| capabilities.key_types.contains(name));
        type_name_breaks(name, native || added, reading.support_of_any_name)
    });
    if let Some(certain) = named.as_ref().and_then(|named| named.grammar) {
        breaks.add(TypeName, certain);
    }
    let mut unlocked = None;
    if let Some(unlock) = unlock {
        let aad = held(read, 0, lengths.ext_end());
        let wrapped = if reading.secret_to_end {
            held(read, lengths.ext_end(), read.len() as u64)
        } else {
            held(read, lengths.ext_end(), lengths.total())
        };
        if let (Some(aad), Some(wrapped)) = (aad, wrapped) {
            let outcome = wrap_keys.unlock(unlock, read, aad, wrapped);
            match outcome {
                Unlocked::Opened(_) => {}
                Unlocked::Refused => breaks.add(Unlock, true),
                Unlocked::NotTried => breaks.add(Unlock, false),
            }
            unlocked = Some(outcome);
        }
        if let Some(region) = held(read, lengths.public_end(), lengths.ext_end()) {
            if let Some(certain) = malformed_tlv(region) {
                breaks.add(TlvMalformed, certain);
            }
            if let Some(certain) = unknown_critical_tag(region, &capabilities.tlv_tags) {
                breaks.add(TlvUnknownCritical, certain);
            }
        }
    }
    if let Some(certain) = named.and_then(|named| named.support) {
        breaks.add(TypeSupport, certain);
    }
    if native {
        let public = held(read, lengths.type_name_end(), lengths.public_end())
            .and_then(|public| <[u8; x25519::PUBLIC_KEY_SIZE]>::try_from(public).ok());
        if lengths.public != x25519::PUBLIC_KEY_SIZE as u64 {
            breaks.add(TypeRules, true);
        }
        let secret_declared_wrong = lengths.wrapped_secret != x25519::WRAPPED_SECRET_LEN as u64;
        // A reader that takes every byte after `ext_bytes` as the wrapped
        // secret may judge its length by those bytes or by the declared field.
        let secret_length_rule = if reading.secret_to_end {
            length_rule_breaks(
                secret_declared_wrong,
                held(read, lengths.ext_end(), read.len() as u64)
                    .map(|secret| secret.len() != x25519::WRAPPED_SECRET_LEN),
            )
        } else {
            secret_declared_wrong.then_some(true)
        };
        if let Some(certain) = secret_length_rule {
            breaks.add(TypeRules, certain);
        }
        match unlocked {
            Some(Unlocked::Opened(secret)) => {
                let derived = <[u8; x25519::PRIVATE_KEY_SIZE]>::try_from(secret.as_slice())
                    .ok()
                    .map(|secret| {
                        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret))
                            .to_bytes()
                    });
                if derived.is_none() || derived != public {
                    breaks.add(TypeRules, true);
                }
            }
            Some(Unlocked::NotTried) => breaks.add(TypeRules, false),
            // Without the secret, a reader may still refuse public material no
            // X25519 secret can produce: all zero or not canonical.
            Some(Unlocked::Refused) | None => {
                let underivable = public.is_some_and(|public| {
                    x25519::is_zero_public_key(&public)
                        || !x25519::is_canonical_public_key_encoding(&public)
                });
                if underivable {
                    breaks.add(TypeRules, false);
                }
            }
        }
    }
    (breaks, type_name.map(<[u8]>::to_vec))
}

/// The cap a reader applies to the wrapped secret: the local cap of `caps` for
/// the unlock, and the structural maximum for validation, which applies none.
fn wrapped_secret_cap(caps: Option<&ProfileCaps>) -> u32 {
    caps.map_or(
        KeyReadLimits::PRIVATE_KEY_WRAPPED_SECRET_LEN_STRUCTURAL_MAX,
        |caps| caps.key_read().private_key_wrapped_secret_len(),
    )
}

/// The checks of the list that read the fixed header alone, which see the
/// same bytes under every extent: steps 0 to 7, and the unlock's local caps.
fn fixed_header_breaks(
    bytes: &[u8],
    unlock: Option<&UnlockInputs>,
    capabilities: &Capabilities,
) -> Breaks<Sk> {
    let mut breaks = Breaks::default();
    if bytes.starts_with(RECIPIENT_STRING_PREFIX) {
        breaks.add(PublicKeyPrefix, true);
    }
    if bytes.len() < PRIVATE_KEY_HEADER_FIXED_SIZE {
        breaks.add(HeaderShort, true);
    }
    // A file shorter than the magic breaks it only for a reader that compares
    // the magic byte by byte as it reads it.
    let magic_held = bytes.len().min(MAGIC_SIZE);
    if bytes[..magic_held] != MAGIC[..magic_held] {
        breaks.add(Magic, magic_held == MAGIC_SIZE);
    }
    if bytes
        .get(KIND_OFFSET)
        .is_some_and(|&kind| kind != KIND_PRIVATE_KEY)
    {
        breaks.add(Kind, true);
    }
    match bytes.get(VERSION_OFFSET) {
        Some(0) => breaks.add(VersionZero, true),
        Some(&version) if !capabilities.supports_version(version) => {
            breaks.add(VersionUnsupported, true)
        }
        _ => {}
    }
    if read_u16_be(bytes, KEY_FLAGS_OFFSET).is_ok_and(|flags| flags != 0) {
        breaks.add(KeyFlags, true);
    }
    let wrapped_secret_range =
        PRIVATE_KEY_WRAPPED_SECRET_LEN_MIN..=PRIVATE_KEY_WRAPPED_SECRET_LEN_MAX;
    if read_u16_be(bytes, TYPE_NAME_LEN_OFFSET)
        .is_ok_and(|len| !(1..=TYPE_NAME_MAX_LEN).contains(&usize::from(len)))
        || read_u32_be(bytes, PUBLIC_LEN_OFFSET).is_ok_and(|len| len > PRIVATE_KEY_PUBLIC_LEN_MAX)
        || read_u32_be(bytes, EXT_LEN_OFFSET).is_ok_and(|len| len > PRIVATE_KEY_EXT_LEN_MAX)
        || read_u32_be(bytes, WRAPPED_SECRET_LEN_OFFSET)
            .is_ok_and(|len| !wrapped_secret_range.contains(&len))
    {
        breaks.add(Lengths, true);
    }
    let kdf_params = stored_kdf_params(bytes).map(|(_, params)| params);
    if kdf_params.is_some_and(|params| params.validate_structural().is_err()) {
        breaks.add(KdfBounds, true);
    }
    if let Some(unlock) = unlock {
        if kdf_params.is_some_and(|params| over_kdf_cap(params, &unlock.caps.kdf())) {
            breaks.add(KdfCap, true);
        }
        if read_u32_be(bytes, WRAPPED_SECRET_LEN_OFFSET)
            .is_ok_and(|len| len > wrapped_secret_cap(Some(&unlock.caps)))
        {
            breaks.add(WrappedSecretCap, true);
        }
    }
    breaks
}

/// The checks a file of a private-key encoding version that a reader supports,
/// other than this build's, still breaks for that reader: the `fcr1` prefix,
/// the magic, the kind, and the size of the fixed header, which §8 makes the
/// same whatever the version, so that they read nothing a newer version may
/// lay out differently (see [`Breaks::as_newer_version`]). Such a file fixes no
/// order of the other checks for that reader, so a pair that rests on it alone
/// is reported as a loss.
const KEPT_BY_NEWER_VERSIONS: [Sk; 4] = [PublicKeyPrefix, HeaderShort, Magic, Kind];

/// Every check a case's artifact breaks for `reader` of `reading` with
/// `capabilities`. Also asserts that the specification's reader reports the
/// stored class, and that no file names a key type a capability adds, whose
/// rules these lists do not know.
fn case_breaks(
    reader: Reader,
    row: &Row,
    bytes: &[u8],
    unlock: Option<&UnlockInputs>,
    wrap_keys: &mut WrapKeys,
    capabilities: &Capabilities,
    reading: Reading,
) -> Breaks<Sk> {
    let (mut breaks, type_name) = reading_breaks(bytes, unlock, wrap_keys, capabilities, reading);
    assert!(
        !type_name.is_some_and(|name| {
            std::str::from_utf8(&name).is_ok_and(|name| capabilities.key_types.contains(name))
        }),
        "{}: a reader that declares a key type applies rules this list does not know",
        field(row, "case_id")
    );
    let newer_version = bytes.get(VERSION_OFFSET).is_some_and(|&version| {
        version != PRIVATE_KEY_VERSION && capabilities.supports_version(version)
    });
    if newer_version {
        breaks.as_newer_version(&KEPT_BY_NEWER_VERSIONS);
    }
    if reading == Reading::SPECIFICATION {
        match reader {
            Reader::Validate => assert_specification_report::<ValidateList>(row, &breaks),
            Reader::Open => assert_specification_report::<OpenList>(row, &breaks),
        }
    }
    breaks
}

/// Every rejected case of `reader` in the committed corpus, evaluated once per
/// test run for each reading.
fn loaded_cases(reader: Reader) -> &'static LoadedReadings<Sk, Reading> {
    static VALIDATE: OnceLock<LoadedReadings<Sk, Reading>> = OnceLock::new();
    static OPEN: OnceLock<LoadedReadings<Sk, Reading>> = OnceLock::new();
    let cases = match reader {
        Reader::Validate => &VALIDATE,
        Reader::Open => &OPEN,
    };
    cases.get_or_init(|| load(reader))
}

/// Reads the rejected cases of `reader` and evaluates each under every reading
/// and every run of capabilities that does not hold the capability it rests
/// on.
fn load(reader: Reader) -> LoadedReadings<Sk, Reading> {
    let root = corpus_root().expect("the corpus is on disk");
    let profiles = limit_profiles(&root);
    let cases = rejected_cases(&root, reader.case_type());
    let passphrases: BTreeMap<&str, Passphrase> = match reader {
        Reader::Validate => BTreeMap::new(),
        Reader::Open => cases
            .iter()
            .map(|(row, _)| field(row, "credential_id"))
            .collect::<BTreeSet<&str>>()
            .into_iter()
            .map(
                |credential_id| match read_credential(&root, credential_id) {
                    CorpusCredential::PrivateKey { unlock, .. } => (credential_id, unlock),
                    _ => panic!("{credential_id}: the unlock needs a private-key credential"),
                },
            )
            .collect(),
    };
    let mut wrap_keys = WrapKeys::default();
    load_readings::<Capabilities, _>(&cases, &Reading::all(reader), |row, bytes, run, reading| {
        let unlock = (reader == Reader::Open).then(|| UnlockInputs {
            caps: ProfileCaps::new(&profiles[field(row, "limit_profile_id")]),
            credential_id: field(row, "credential_id"),
            passphrase: &passphrases[field(row, "credential_id")],
        });
        let (capabilities, _) = Capabilities::declaring(run);
        case_breaks(
            reader,
            row,
            bytes,
            unlock.as_ref(),
            &mut wrap_keys,
            &capabilities,
            reading,
        )
    })
}

/// What the cases of `reader` leave open through the list `L`, described.
fn open_pairs_through<L: CheckList<Check = Sk>>(reader: Reader) -> Vec<String> {
    stray_open_pairs::<L, Capabilities, _>(loaded_cases(reader), both_breakable)
}

/// The §12.3 `private.key` check-order row holds: through each reader, for
/// the readers of each reading, the cases fix every claimed pair that such a
/// reader can break together, and a reader that declares capabilities loses
/// only pairs with a check they change.
#[test]
fn the_corpus_fixes_every_claimed_private_key_check_order() {
    if corpus_root().is_none() {
        return;
    }
    let validate = open_pairs_through::<ValidateList>(Reader::Validate);
    let open = open_pairs_through::<OpenList>(Reader::Open);
    assert!(
        validate.is_empty() && open.is_empty(),
        "the corpus leaves these `private.key` check pairs open, through validation: \
         {validate:#?}, through the unlock: {open:#?}"
    );
}

/// The checker finds open pairs: the case named for each pair is the only one
/// that fixes it, through its reader and for readers that read as the
/// specification describes, so leaving it out reopens the pair. If a later
/// case fixes one of these pairs too, the pair needs another witness.
#[test]
fn leaving_out_the_witnesses_reopens_their_pair() {
    if corpus_root().is_none() {
        return;
    }
    let validate: &[(&str, (Sk, Sk))] = &[
        (
            "private-key-given-recipient-string-prefix-alone",
            (PublicKeyPrefix, HeaderShort),
        ),
        ("private-key-order-size-before-magic", (HeaderShort, Magic)),
        (
            "private-key-order-kind-before-version",
            (Kind, VersionUnsupported),
        ),
        (
            "private-key-order-version-before-flags",
            (VersionUnsupported, KeyFlags),
        ),
        (
            "private-key-order-file-length-before-type-support",
            (FileLength, TypeSupport),
        ),
        (
            "private-key-order-kdf-parameters-before-type-rules",
            (KdfBounds, TypeRules),
        ),
    ];
    let open: &[(&str, (Sk, Sk))] = &[
        (
            "private-key-open-order-kdf-parameters-before-wrapped-secret-cap",
            (KdfBounds, WrappedSecretCap),
        ),
        (
            "private-key-open-order-kdf-cap-before-file-length",
            (KdfCap, FileLength),
        ),
        (
            "private-key-open-order-wrapped-secret-cap-before-file-length",
            (WrappedSecretCap, FileLength),
        ),
        (
            "private-key-open-order-authentication-before-ext",
            (Unlock, TlvMalformed),
        ),
        (
            "private-key-open-order-ext-structure-before-critical-tag",
            (TlvMalformed, TlvUnknownCritical),
        ),
        (
            "private-key-open-order-critical-ext-before-type-support",
            (TlvUnknownCritical, TypeSupport),
        ),
        (
            "private-key-open-order-critical-ext-before-type-rules",
            (TlvUnknownCritical, TypeRules),
        ),
    ];
    assert_witnesses::<ValidateList>(Reader::Validate, validate);
    assert_witnesses::<OpenList>(Reader::Open, open);
}

/// Asserts that leaving each case of `witnessed` out of the cases of `reader`
/// reopens its pair for readers that read as the specification describes.
fn assert_witnesses<L: CheckList<Check = Sk>>(reader: Reader, witnessed: &[(&str, (Sk, Sk))]) {
    let (_, cases) = loaded_cases(reader)
        .readings
        .iter()
        .find(|(reading, _)| *reading == Reading::SPECIFICATION)
        .expect("every reading is loaded");
    let base = evidence::<L>(cases, &[]);
    for &(witness, pair) in witnessed {
        assert!(
            reopens::<L>(&base, &[witness], pair),
            "without {witness}, {pair:?} should be open through {reader:?}"
        );
    }
}

/// The head-first extent holds exactly what the staged read of this build
/// reads, through each reader and for every rejected `private.key` case, and
/// the fixed header breaks a check of steps 0 to 7 exactly when the header
/// parse of this build refuses it.
#[test]
fn the_head_first_extent_is_the_staged_read_of_this_build() {
    let Some(root) = corpus_root() else {
        return;
    };
    let profiles = limit_profiles(&root);
    for reader in [Reader::Validate, Reader::Open] {
        for (row, bytes) in rejected_cases(&root, reader.case_type()) {
            let case_id = field(&row, "case_id");
            let caps = (reader == Reader::Open)
                .then(|| ProfileCaps::new(&profiles[field(&row, "limit_profile_id")]));
            let cap = wrapped_secret_cap(caps.as_ref());
            let refused = Extent::HeadFirst.stops_after_header(&fixed_header_breaks(
                &bytes,
                None,
                &Capabilities::default(),
            ));
            assert_eq!(
                refused,
                PrivateKeyHeader::from_file_bytes(&bytes).is_err(),
                "{case_id}: steps 0 to 7 disagree with the header parse"
            );
            let staged = read_private_key_bytes(&root.join(field(&row, "artifact_ref")), cap)
                .expect("read a corpus artifact");
            assert_eq!(
                read_extent(&bytes, cap, Extent::HeadFirst, refused),
                staged.as_slice(),
                "{case_id}: the head-first extent differs from the staged read"
            );
        }
    }
}
