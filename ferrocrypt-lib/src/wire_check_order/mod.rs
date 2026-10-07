//! Checks the wire corpus's validation-order claims (`FORMAT.md` §12.3).
//!
//! The claims cover `.fcr` parsing through the pre-recipient checks, the
//! `public.key` reader, and both `private.key` readers. A claimed pair consists
//! of two checks that report different diagnostic classes and can both fail
//! for one artifact. Their order must be able to affect the reported class.
//! If every artifact that fails both checks also fails an intervening check
//! of the earlier check's class, §12.3 counts that intervening check and the
//! later check instead: no artifact distinguishes the original pair's order
//! once the intervening check precedes the later one.
//!
//! ## Evidence model
//!
//! Each rejected case constrains the possible check orders: at least one
//! failing check of the expected class must precede every failing check of
//! another class. A pair is fixed only if no order satisfying all case
//! constraints reverses it. The specified reader must also produce every
//! case's stored class.
//!
//! Per-recipient checks are grouped by parsing pass. Each group has one
//! allowed traversal direction, forward or reverse, for a given reader
//! family. Families refuted by the cases are excluded; every remaining family
//! must fix every claimed pair. Checks over entries seen so far are evaluated
//! at the first entry where they fail in each direction. The model does not
//! cover readers that change traversal direction within a group; checks share
//! a group only where the specification places them in one pass.
//!
//! ## Evaluating artifacts
//!
//! Each check is evaluated independently, as though it ran first. Missing
//! bytes do not establish a failure. Credential-dependent checks use the
//! corpus credentials rather than manually annotated failures. The lists also
//! model alternative ways to read lengths and declared boundaries.
//!
//! A failure shared by all modeled readings is certain. An uncertain failure
//! contributes evidence only when it reports the case's expected class;
//! otherwise it could incorrectly constrain a reader that passes that check.
//! The `.fcr` list merges alternative readings. The key lists evaluate each
//! reading separately and claim only pairs that can fail together under that
//! reading. Unlocks skipped because their KDF parameters are invalid or exceed
//! this checker's work budget are treated as uncertain too.
//!
//! ## Capability coverage
//!
//! The base run declares no capabilities and asserts every applicable case
//! (§12.2). Additional runs cover combinations of capabilities that change
//! checks, omitting cases conditional on those capabilities being absent.
//! Each run also declares all capabilities that change no check: these only
//! remove evidence, so this is the most restrictive case for that combination.
//! Any pair whose coverage is lost must involve a check changed by the run's
//! capabilities.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::path::Path;

use ferrocrypt_test_support::wire_manifest::{
    CAP_COLUMN_PREFIX, Row, cases_withdrawn_by_errata, corpus_revision, field, limit_value,
    read_committed, read_table, table_columns,
};

use crate::crypto::kdf::{KdfLimit, KdfParams};
use crate::recipient::name::{TYPE_NAME_MAX_LEN, validate_type_name_grammar};
use crate::{CryptoError, HeaderReadLimits, KeyReadLimits};

mod fcr;
mod private_key;
mod public_key;

/// The order in which a reader meets the recipient entries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Direction {
    FrontToBack,
    BackToFront,
}

impl Direction {
    const BOTH: [Direction; 2] = [Direction::FrontToBack, Direction::BackToFront];

    /// Whether a reader walking this way meets entry `a` before entry `b`.
    fn meets_before(self, a: usize, b: usize) -> bool {
        match self {
            Direction::FrontToBack => a < b,
            Direction::BackToFront => a > b,
        }
    }
}

/// Where readers walking the entries one way first meet a check they make on
/// the entries met so far. Such readers may judge those entries in different
/// ways, so they can stop at different entries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Span {
    /// The entry at which the earliest of them meets the check.
    first: usize,
    /// The entry at which the latest of them meets the check, or none when
    /// one of them can finish the walk without meeting it.
    last: Option<usize>,
}

/// Where readers that make a check on the entries met so far first meet it,
/// walking front to back and back to front.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Reach {
    front_to_back: Span,
    back_to_front: Span,
}

impl Reach {
    /// The span of the readers walking `direction`.
    fn toward(self, direction: Direction) -> Span {
        match direction {
            Direction::FrontToBack => self.front_to_back,
            Direction::BackToFront => self.back_to_front,
        }
    }
}

/// The checks an artifact breaks, each with the recipient entry it breaks on
/// when the check is made once per entry.
#[derive(Clone)]
struct Breaks<C> {
    /// Broken for every reader that makes the check first.
    certain: BTreeSet<(C, Option<usize>)>,
    /// Broken for some such readers only.
    uncertain: BTreeSet<(C, Option<usize>)>,
    /// Where readers that make a check on the entries met so far first meet
    /// it.
    reach: BTreeMap<C, Reach>,
    /// The checks a credential breaks on whichever recipient entry a reader
    /// tries first.
    first_try: BTreeSet<C>,
}

impl<C> Default for Breaks<C> {
    fn default() -> Self {
        Self {
            certain: BTreeSet::new(),
            uncertain: BTreeSet::new(),
            reach: BTreeMap::new(),
            first_try: BTreeSet::new(),
        }
    }
}

impl<C: Copy + Ord> Breaks<C> {
    /// One artifact under several readings: a check every reading breaks for
    /// certain stays certain, and any other check a reading breaks is
    /// uncertain. For a check made on the entries met so far, the earliest
    /// stop is the earliest over the readings and the latest stop the latest
    /// over them, or none when some reading never meets the check.
    fn merge(readings: impl IntoIterator<Item = Breaks<C>>) -> Breaks<C> {
        let readings: Vec<Breaks<C>> = readings.into_iter().collect();
        let certain = in_every(readings.iter().map(|reading| reading.certain.clone()));
        let uncertain = readings
            .iter()
            .flat_map(|reading| reading.certain.iter().chain(&reading.uncertain))
            .filter(|broken| !certain.contains(broken))
            .copied()
            .collect();
        let reached: BTreeSet<C> = readings
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

    /// Records that the artifact breaks `check`, a check not made once per
    /// recipient entry: for every reader that makes it first when `certain`,
    /// and for some of them otherwise. A check broken for every reader is not
    /// also recorded as broken for some.
    fn add(&mut self, check: C, certain: bool) {
        let broken = (check, None);
        if certain {
            self.uncertain.remove(&broken);
            self.certain.insert(broken);
        } else if !self.certain.contains(&broken) {
            self.uncertain.insert(broken);
        }
    }

    /// Whether some reader that makes `check` first finds it broken, for a
    /// check not made once per recipient entry.
    fn is_broken(&self, check: C) -> bool {
        self.certain.contains(&(check, None)) || self.uncertain.contains(&(check, None))
    }

    /// What a reader that supports a newer stored version than this build's
    /// finds in a file of that version: only the checks of `kept`, which read
    /// nothing the newer version may lay out differently (§11.5), stay
    /// certain. Where readers meet a check and what the first try breaks come
    /// from such bytes, so both are dropped.
    fn as_newer_version(&mut self, kept: &[C]) {
        let (known, unknown) = std::mem::take(&mut self.certain)
            .into_iter()
            .partition(|(check, _)| kept.contains(check));
        self.certain = known;
        self.uncertain.extend(unknown);
        self.reach.clear();
        self.first_try.clear();
    }

    /// The checks a case that stores `class` counts: every certain one, and
    /// an uncertain one only when it reports `class`.
    fn counted<L: CheckList<Check = C>>(&self, class: &str) -> Vec<(C, Option<usize>)> {
        self.certain
            .iter()
            .chain(
                self.uncertain
                    .iter()
                    .filter(|(check, _)| L::class(*check) == class),
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

/// A rejected case, with the checks its artifact breaks for a reader that
/// declares each run of capabilities, the empty run included, that does not
/// hold the capability the case rests on.
struct LoadedCase<C> {
    row: Row,
    breaks: BTreeMap<Vec<String>, Breaks<C>>,
}

/// The evidence `cases` hold for a reader that declares every capability of
/// `run`, leaving out the cases that rest on one of them.
fn evidence<L: CheckList>(
    cases: &[LoadedCase<L::Check>],
    run: &[String],
) -> Vec<Evidence<L::Check>> {
    cases
        .iter()
        .filter_map(|case| {
            let breaks = case.breaks.get(run)?;
            let class = field(&case.row, "diagnostic_class");
            let broken = breaks.counted::<L>(class);
            (!broken.is_empty()).then(|| Evidence {
                case_id: field(&case.row, "case_id").to_string(),
                broken,
                reach: breaks.reach.clone(),
                class: class.to_string(),
            })
        })
        .collect()
}

/// The cases of a check list evaluated apart under each of its readings.
struct LoadedReadings<C, R> {
    /// The runs of capabilities the cases are evaluated under.
    runs: Vec<Vec<String>>,
    /// Each reading, with every case as its readers find it.
    readings: Vec<(R, Vec<LoadedCase<C>>)>,
}

/// Every case of `cases`, as `evaluate` finds it under each of `readings` and
/// each run of capabilities `Cap` names that does not hold the capability the
/// case rests on.
fn load_readings<Cap: ReaderCapabilities, R: Copy>(
    cases: &[(Row, Vec<u8>)],
    readings: &[R],
    mut evaluate: impl FnMut(&Row, &[u8], &[String], R) -> Breaks<Cap::Check>,
) -> LoadedReadings<Cap::Check, R> {
    let runs = Cap::runs(cases.iter().map(|(row, _)| row));
    let readings = readings
        .iter()
        .map(|&reading| {
            let loaded = cases
                .iter()
                .map(|(row, bytes)| {
                    let breaks = runs
                        .iter()
                        .filter(|run| {
                            !run.iter()
                                .any(|capability| capability == field(row, "capability_id"))
                        })
                        .map(|run| (run.clone(), evaluate(row, bytes, run, reading)))
                        .collect();
                    LoadedCase {
                        row: row.clone(),
                        breaks,
                    }
                })
                .collect();
            (reading, loaded)
        })
        .collect();
    LoadedReadings { runs, readings }
}

/// What the cases of `loaded` leave open, described: for a reader of each
/// reading that declares each run of capabilities, the claimed pairs of `L`
/// open for it, other than pairs with a check the run changes. A pair counts
/// for a reading only when `breakable` says a reader of it can break both
/// checks. A reading and run whose readers the cases rule out entirely are
/// reported too, as the checker cannot tell a corpus that refutes every such
/// reader from a mistake in evaluating the reading.
fn stray_open_pairs<L, Cap, R>(
    loaded: &LoadedReadings<L::Check, R>,
    breakable: impl Fn(R, L::Check, L::Check) -> bool,
) -> Vec<String>
where
    L: CheckList,
    Cap: ReaderCapabilities<Check = L::Check>,
    R: Copy + Debug,
{
    let mut found = Vec::new();
    for (reading, cases) in &loaded.readings {
        let pairs: Vec<(L::Check, L::Check)> = claimed_pairs::<L>()
            .into_iter()
            .filter(|&(earlier, later)| breakable(*reading, earlier, later))
            .collect();
        for run in &loaded.runs {
            let Findings { open, refuted } =
                open_and_refuted::<L>(&evidence::<L>(cases, run), &pairs);
            if refuted.len() == families::<L>().len() {
                found.push(format!(
                    "the cases rule out every reader of {reading:?} declaring {run:?}"
                ));
                continue;
            }
            let changed: Vec<L::Check> = Cap::declaring(run).1.into_iter().collect();
            let stray = stray_losses(&open, &changed);
            if !stray.is_empty() {
                found.push(format!("{reading:?} declaring {run:?}: {stray:?}"));
            }
        }
    }
    found
}

/// Whether leaving `witnesses` out of `base`, the evidence of a reader that
/// declares no capability, leaves `pair` open.
fn reopens<L: CheckList>(
    base: &[Evidence<L::Check>],
    witnesses: &[&str],
    pair: (L::Check, L::Check),
) -> bool {
    let rest: Vec<Evidence<L::Check>> = base
        .iter()
        .filter(|evidence| !witnesses.contains(&evidence.case_id.as_str()))
        .cloned()
        .collect();
    assert_eq!(
        rest.len() + witnesses.len(),
        base.len(),
        "{witnesses:?} are cases of the corpus"
    );
    !open_among::<L>(&rest, &[pair]).is_empty()
}

/// Asserts that the reader the specification describes reports the class `row`
/// stores for an artifact that breaks the certain checks of `breaks`.
fn assert_specification_report<L: CheckList>(row: &Row, breaks: &Breaks<L::Check>) {
    let certain: Vec<(L::Check, Option<usize>)> = breaks.certain.iter().copied().collect();
    assert_eq!(
        L::specification_report(&certain),
        Some(field(row, "diagnostic_class")),
        "{}: the specification's reader does not report the stored class",
        field(row, "case_id")
    );
}

/// What a reader that declares capabilities supports beyond this build, as one
/// check list reads it.
trait ReaderCapabilities: Sized {
    /// A check of the list.
    type Check: Ord;

    /// The capabilities a reader declaring every capability of `run` has, and
    /// the checks of the list they change. A capability no check of the list
    /// reads changes none.
    fn declaring(run: &[String]) -> (Self, BTreeSet<Self::Check>);

    /// Whether `capability` changes a check of the list.
    fn changes_a_check(capability: &str) -> bool {
        !Self::declaring(std::slice::from_ref(&capability.to_string()))
            .1
            .is_empty()
    }

    /// The runs of capabilities the cases of `rows` are evaluated under (see
    /// [`capability_runs`]).
    fn runs<'r>(rows: impl Iterator<Item = &'r Row>) -> Vec<Vec<String>> {
        capability_runs(rows, Self::changes_a_check)
    }
}

/// The runs of capabilities cases are evaluated under, each in sorted order:
/// the empty run, then each combination of the capabilities `rows` rest on
/// that `changes` a check of a list, joined by every capability they rest on
/// that changes none. Such a capability only leaves out the cases that rest
/// on it, and leaving out more cases can only lose more, so each combination
/// is checked where it can lose the most.
fn capability_runs<'r>(
    rows: impl Iterator<Item = &'r Row>,
    changes: impl Fn(&str) -> bool,
) -> Vec<Vec<String>> {
    let declared: BTreeSet<String> = rows
        .map(|row| field(row, "capability_id").to_string())
        .filter(|capability| capability != "-")
        .collect();
    let (changing, inert): (Vec<String>, Vec<String>) = declared
        .into_iter()
        .partition(|capability| changes(capability));
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

/// Whether one of `a` and `b` is among `xs` and the other among `ys`.
fn across<C: PartialEq>(a: C, b: C, xs: &[C], ys: &[C]) -> bool {
    (xs.contains(&a) && ys.contains(&b)) || (xs.contains(&b) && ys.contains(&a))
}

/// Whether a length rule breaks for the readers that make it first, when a
/// reader may judge it on a declared length or on the bytes it takes in that
/// length's place: for every such reader when both are wrong (`Some(true)`),
/// for some when one is or when the taken bytes are not held and the declared
/// length is wrong (`Some(false)`), and for none otherwise.
fn length_rule_breaks(declared_wrong: bool, taken_wrong: Option<bool>) -> Option<bool> {
    match (declared_wrong, taken_wrong) {
        (true, Some(true)) => Some(true),
        (false, Some(false) | None) => None,
        _ => Some(false),
    }
}

/// Whether `name` breaks the §3.3 type-name check, which it does when it is
/// not valid UTF-8 or breaks the grammar: for every reader that makes the
/// check first (`Some(true)`), or for some of them (`Some(false)`). Outside
/// 1..=255 bytes, a name breaks the grammar for a reader whose grammar check
/// repeats the length rule, which the length check before it applies; its
/// characters are not judged apart, so such a name counts as broken for some
/// readers only.
fn type_name_grammar_breaks(name: &[u8]) -> Option<bool> {
    let grammatical =
        std::str::from_utf8(name).is_ok_and(|name| validate_type_name_grammar(name).is_ok());
    (!grammatical).then_some((1..=TYPE_NAME_MAX_LEN).contains(&name.len()))
}

/// Whether the type-name and type-support checks of a key file break, each
/// for every reader that makes it first (`Some(true)`), for some of them
/// (`Some(false)`), or for none.
struct TypeNameBreaks {
    /// The type name is not valid UTF-8 or breaks the §3.3 grammar.
    grammar: Option<bool>,
    /// The key type is not supported.
    support: Option<bool>,
}

/// What the readers that make them first find for the type-name and
/// type-support checks of a key file that stores the type name `name`, as
/// [`type_name_grammar_breaks`] judges the grammar. `supported` says whether
/// the reader supports that type, and a reader judges the support of a name
/// that breaks the grammar only when `support_of_any_name`. A reader whose
/// grammar check leaves out the length rule may find a name outside 1..=255
/// bytes grammatical, so the support of such a name otherwise counts as broken
/// for some readers only.
fn type_name_breaks(name: &[u8], supported: bool, support_of_any_name: bool) -> TypeNameBreaks {
    let grammar = type_name_grammar_breaks(name);
    let support = match (supported, grammar) {
        (true, _) => None,
        (false, None) => Some(true),
        (false, Some(true)) => support_of_any_name.then_some(true),
        (false, Some(false)) => Some(support_of_any_name),
    };
    TypeNameBreaks { grammar, support }
}

/// The caps of a limit profile, read through the builders that clamp a
/// reader's caps. Every cap column read is recorded, so a test can tell which
/// columns the lists read.
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

/// The cap columns of a limit profile the lists leave alone: the archive
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

/// Every cap a limit profile sets is one the lists read or one only the
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

/// At least one check of `group` comes before `later`.
#[derive(Clone, Debug)]
struct Constraint<C> {
    group: BTreeSet<C>,
    later: C,
}

/// A rejected case seen through a check list: the checks its artifact breaks,
/// each with the recipient entry it breaks on when the check is made once per
/// entry, where readers meet the checks a reader may make on the entries met
/// so far, and the class the case stores.
#[derive(Clone)]
struct Evidence<C> {
    case_id: String,
    broken: Vec<(C, Option<usize>)>,
    reach: BTreeMap<C, Reach>,
    class: String,
}

/// A check list as the evidence model reads it.
trait CheckList {
    /// One check of the list.
    type Check: Copy + Ord + Debug + 'static;

    /// Every check, in the order the specification fixes.
    fn order() -> &'static [Self::Check];

    /// The diagnostic class the check reports (`FORMAT.md` §12.1).
    fn class(check: Self::Check) -> &'static str;

    /// Whether the claim covers `earlier` before `later`, two checks in the
    /// specification order that report different classes. A list leaves out a
    /// pair no artifact can break together, a pair whose order decides no
    /// report, and a pair outside the scope its row states.
    fn claimed(earlier: Self::Check, later: Self::Check) -> bool;

    /// How many groups the checks made once per recipient entry form. A reader
    /// meets the entries in one direction for every check of a group, and
    /// makes checks it meets in different directions in different passes. The
    /// default is one group.
    const DIRECTION_GROUPS: usize = 1;

    /// The group, below [`Self::DIRECTION_GROUPS`], of a check made once per
    /// recipient entry.
    fn direction_group(_check: Self::Check) -> usize {
        0
    }

    /// The directions in which a reader may meet the entries for the checks
    /// of `group`. The default is both.
    fn directions(_group: usize) -> &'static [Direction] {
        &Direction::BOTH
    }

    /// The class the reader the specification describes reports for an
    /// artifact that breaks `broken`, or none when it breaks nothing. The
    /// default reports the first broken check in the specification order.
    fn specification_report(broken: &[(Self::Check, Option<usize>)]) -> Option<&'static str> {
        Self::order()
            .iter()
            .find(|&&check| broken.iter().any(|&(other, _)| other == check))
            .map(|&check| Self::class(check))
    }
}

/// The constraints one case yields for readers that meet the entries of each
/// direction group in the direction `family` gives it: each broken check of
/// another class follows some broken check of the expected class. A reader
/// that makes two checks in one pass meets them one entry at a time, so when
/// it can meet a check of the expected class at an entry before the one at
/// which it meets another check, it can meet that check first whatever the
/// order of the two checks, and the case fixes nothing about the other one.
fn constraints<L: CheckList>(
    evidence: &Evidence<L::Check>,
    family: &[Direction],
) -> Vec<Constraint<L::Check>> {
    let mut broken: BTreeSet<L::Check> = BTreeSet::new();
    let mut entries_of: BTreeMap<L::Check, BTreeSet<usize>> = BTreeMap::new();
    for &(check, entry) in &evidence.broken {
        broken.insert(check);
        if let Some(entry) = entry {
            entries_of.entry(check).or_default().insert(entry);
        }
    }
    let expected: BTreeSet<L::Check> = broken
        .iter()
        .copied()
        .filter(|check| L::class(*check) == evidence.class)
        .collect();
    // Where a reader walking `direction` meets `check`: anywhere in its span
    // for a check made on the entries met so far, which a pass of either
    // direction can make, and at its first entry that way for a check made
    // once per entry, which only a pass of its group's direction makes.
    let meets = |check: L::Check, direction: Direction| {
        if let Some(reach) = evidence.reach.get(&check) {
            return Some(reach.toward(direction));
        }
        let entries = entries_of.get(&check)?;
        if family[L::direction_group(check)] != direction {
            return None;
        }
        let at = match direction {
            Direction::FrontToBack => entries.first(),
            Direction::BackToFront => entries.last(),
        };
        at.map(|&at| Span {
            first: at,
            last: Some(at),
        })
    };
    // Checks met in different directions are made in different passes.
    let met_first_by_entry = |first: L::Check, later: L::Check| {
        Direction::BOTH.into_iter().any(|direction| {
            let (Some(first), Some(later)) = (meets(first, direction), meets(later, direction))
            else {
                return false;
            };
            later
                .last
                .is_none_or(|last| direction.meets_before(first.first, last))
        })
    };
    broken
        .iter()
        .copied()
        .filter(|later| L::class(*later) != evidence.class)
        .filter(|&later| {
            !expected
                .iter()
                .any(|&first| met_first_by_entry(first, later))
        })
        .map(|later| Constraint {
            group: expected.clone(),
            later,
        })
        .collect()
}

/// The groups of `constraints`, by the check each group must precede.
fn groups_before<C: Copy + Ord>(constraints: &[Constraint<C>]) -> BTreeMap<C, Vec<&BTreeSet<C>>> {
    let mut groups: BTreeMap<C, Vec<&BTreeSet<C>>> = BTreeMap::new();
    for constraint in constraints {
        groups
            .entry(constraint.later)
            .or_default()
            .push(&constraint.group);
    }
    groups
}

/// Whether some order of `checks` puts, for every group, one of its checks
/// before the check it must precede, and, when `swapped` is `(a, b)`, `b`
/// before `a`. Placing a check never stops another from being placed, so
/// placing any placeable check first finds such an order whenever one exists.
fn feasible<C: Copy + Ord>(
    checks: &[C],
    groups_before: &BTreeMap<C, Vec<&BTreeSet<C>>>,
    swapped: Option<(C, C)>,
) -> bool {
    let mut placed = BTreeSet::new();
    loop {
        let before = placed.len();
        for &check in checks {
            let groups_met = groups_before.get(&check).is_none_or(|groups| {
                groups
                    .iter()
                    .all(|group| group.iter().any(|g| placed.contains(g)))
            });
            let swap_met =
                swapped.is_none_or(|(earlier, later)| check != earlier || placed.contains(&later));
            if groups_met && swap_met {
                placed.insert(check);
            }
        }
        if placed.len() == before {
            return placed.len() == checks.len();
        }
    }
}

/// The claimed pairs that `evidence` leaves open, as [`open_among`] decides.
fn open_pairs<L: CheckList>(evidence: &[Evidence<L::Check>]) -> Vec<(L::Check, L::Check)> {
    open_among::<L>(evidence, &claimed_pairs::<L>())
}

/// The pairs of `pairs` that `evidence` leaves open: those some order of the
/// checks reverses for a family of readers the cases do not refute. Also
/// asserts that the specification's reader reports every stored class, which
/// the constraints rest on.
fn open_among<L: CheckList>(
    evidence: &[Evidence<L::Check>],
    pairs: &[(L::Check, L::Check)],
) -> Vec<(L::Check, L::Check)> {
    for case in evidence {
        assert_eq!(
            L::specification_report(&case.broken),
            Some(case.class.as_str()),
            "{}: the specification's reader does not report the stored class for {:?}",
            case.case_id,
            case.broken
        );
    }
    let Findings { open, refuted } = open_and_refuted::<L>(evidence, pairs);
    // The specification's own family cannot be refuted, since its reader
    // reports every stored class.
    assert!(
        refuted
            .iter()
            .all(|family| family.contains(&Direction::BackToFront)),
        "no order of the checks satisfies every case for readers that meet every entry front \
         to back"
    );
    open
}

/// What some cases leave open, and which readers they rule out.
struct Findings<C> {
    /// The pairs some order of the checks reverses for a family of readers
    /// the cases do not refute.
    open: Vec<(C, C)>,
    /// The families of readers the cases refute.
    refuted: Vec<Vec<Direction>>,
}

/// What the cases of `evidence` find for the pairs of `pairs`.
fn open_and_refuted<L: CheckList>(
    evidence: &[Evidence<L::Check>],
    pairs: &[(L::Check, L::Check)],
) -> Findings<L::Check> {
    let mut open = BTreeSet::new();
    let mut refuted = Vec::new();
    for family in families::<L>() {
        let known: Vec<_> = evidence
            .iter()
            .flat_map(|case| constraints::<L>(case, &family))
            .collect();
        let groups = groups_before(&known);
        if !feasible(L::order(), &groups, None) {
            refuted.push(family);
            continue;
        }
        for &pair in pairs {
            if feasible(L::order(), &groups, Some(pair)) {
                open.insert(pair);
            }
        }
    }
    let open = pairs
        .iter()
        .copied()
        .filter(|pair| open.contains(pair))
        .collect();
    Findings { open, refuted }
}

/// Every way of giving each direction group a direction its list allows.
fn families<L: CheckList>() -> Vec<Vec<Direction>> {
    (0..L::DIRECTION_GROUPS).fold(vec![Vec::new()], |families, group| {
        families
            .iter()
            .flat_map(|family| {
                L::directions(group).iter().map(|&direction| {
                    let mut family = family.clone();
                    family.push(direction);
                    family
                })
            })
            .collect()
    })
}

/// Every pair the claim covers, in the specification order.
fn claimed_pairs<L: CheckList>() -> Vec<(L::Check, L::Check)> {
    let checks = L::order();
    let mut pairs = Vec::new();
    for (index, &earlier) in checks.iter().enumerate() {
        for &later in &checks[index + 1..] {
            if L::class(earlier) != L::class(later) && L::claimed(earlier, later) {
                pairs.push((earlier, later));
            }
        }
    }
    pairs
}

/// The corpus root, or `None` where the crate is built without it (the
/// published crate omits the corpus).
fn corpus_root() -> Option<std::path::PathBuf> {
    crate::wire_vector_gen::wire_corpus_present().then(crate::wire_vector_gen::wire_dir)
}

/// The rejected cases of `case_type` no erratum withdraws, with the artifact
/// bytes each names, read after their digests are checked.
fn rejected_cases(root: &Path, case_type: &str) -> Vec<(Row, Vec<u8>)> {
    let withdrawn = cases_withdrawn_by_errata(root, corpus_revision(root));
    read_table(root, "cases.tsv")
        .into_iter()
        .filter(|row| field(row, "case_type") == case_type && field(row, "outcome") == "reject")
        .filter(|row| !withdrawn.contains(field(row, "case_id")))
        .map(|row| {
            let bytes = read_committed(root, &row, "artifact_ref", "artifact_sha3_256");
            (row, bytes)
        })
        .collect()
}

/// The `limit-profiles.tsv` rows, keyed by profile ID.
fn limit_profiles(root: &Path) -> BTreeMap<String, Row> {
    read_table(root, "limit-profiles.tsv")
        .into_iter()
        .map(|row| (field(&row, "limit_profile_id").to_string(), row))
        .collect()
}

/// The pairs `lost` holds that involve none of `changed`, the checks some
/// capabilities change: those a reader declaring them must not lose.
fn stray_losses<C: Copy + Ord + Debug>(lost: &[(C, C)], changed: &[C]) -> Vec<(C, C)> {
    lost.iter()
        .copied()
        .filter(|(earlier, later)| !changed.contains(earlier) && !changed.contains(later))
        .collect()
}

mod engine_tests {
    use super::*;

    /// A toy list of three checks, `a` and `b` of one class and `c` of
    /// another, every pair claimed.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
    enum Toy {
        A,
        B,
        C,
    }

    struct ToyList;

    impl CheckList for ToyList {
        type Check = Toy;
        fn order() -> &'static [Toy] {
            &[Toy::A, Toy::B, Toy::C]
        }
        fn class(check: Toy) -> &'static str {
            match check {
                Toy::A | Toy::B => "first",
                Toy::C => "second",
            }
        }
        fn claimed(_: Toy, _: Toy) -> bool {
            true
        }
    }

    fn case(broken: &[Toy], class: &str) -> Evidence<Toy> {
        Evidence {
            case_id: format!("{broken:?}"),
            broken: broken.iter().map(|check| (*check, None)).collect(),
            reach: BTreeMap::new(),
            class: class.to_string(),
        }
    }

    /// A case of the class of `a` and `b` that breaks each check on an entry.
    fn on_entries(broken: &[(Toy, usize)]) -> Evidence<Toy> {
        Evidence {
            case_id: format!("{broken:?}"),
            broken: broken
                .iter()
                .map(|(check, entry)| (*check, Some(*entry)))
                .collect(),
            reach: BTreeMap::new(),
            class: "first".to_string(),
        }
    }

    /// One case per claimed pair fixes it; without one the pair stays open.
    #[test]
    fn a_case_that_breaks_both_checks_fixes_their_order() {
        assert_eq!(
            open_pairs::<ToyList>(&[]),
            vec![(Toy::A, Toy::C), (Toy::B, Toy::C)]
        );
        assert_eq!(
            open_pairs::<ToyList>(&[case(&[Toy::A, Toy::C], "first")]),
            vec![(Toy::B, Toy::C)]
        );
        assert!(
            open_pairs::<ToyList>(&[
                case(&[Toy::A, Toy::C], "first"),
                case(&[Toy::B, Toy::C], "first"),
            ])
            .is_empty()
        );
    }

    /// A case that breaks two checks of the expected class fixes only that one
    /// of them comes first.
    #[test]
    fn a_case_with_two_checks_of_its_class_fixes_neither_alone() {
        assert_eq!(
            open_pairs::<ToyList>(&[case(&[Toy::A, Toy::B, Toy::C], "first")]),
            vec![(Toy::A, Toy::C), (Toy::B, Toy::C)]
        );
    }

    /// A check of the expected class on an entry a reader meets before every
    /// entry the other check breaks on fixes nothing about that check, so a
    /// pair broken on two entries is fixed only by cases in both entry orders.
    #[test]
    fn a_pair_on_two_entries_needs_both_entry_orders() {
        let both = vec![(Toy::A, Toy::C), (Toy::B, Toy::C)];
        let a_first = on_entries(&[(Toy::A, 0), (Toy::C, 1)]);
        let c_first = on_entries(&[(Toy::A, 1), (Toy::C, 0)]);
        assert_eq!(open_pairs::<ToyList>(std::slice::from_ref(&a_first)), both);
        assert_eq!(open_pairs::<ToyList>(std::slice::from_ref(&c_first)), both);
        assert_eq!(
            open_pairs::<ToyList>(&[a_first, c_first]),
            vec![(Toy::B, Toy::C)]
        );
        // A second check of the expected class on the far side fixes nothing.
        assert_eq!(
            open_pairs::<ToyList>(&[
                on_entries(&[(Toy::A, 0), (Toy::B, 2), (Toy::C, 1)]),
                on_entries(&[(Toy::A, 2), (Toy::B, 0), (Toy::C, 1)]),
            ]),
            both
        );
        // On one entry, the order of the checks decides.
        assert_eq!(
            open_pairs::<ToyList>(&[on_entries(&[(Toy::A, 0), (Toy::C, 0)])]),
            vec![(Toy::B, Toy::C)]
        );
    }

    /// The toy list, with its entries met front to back only.
    struct ForwardList;

    impl CheckList for ForwardList {
        type Check = Toy;
        fn order() -> &'static [Toy] {
            ToyList::order()
        }
        fn class(check: Toy) -> &'static str {
            ToyList::class(check)
        }
        fn claimed(earlier: Toy, later: Toy) -> bool {
            ToyList::claimed(earlier, later)
        }
        fn directions(_group: usize) -> &'static [Direction] {
            &[Direction::FrontToBack]
        }
    }

    /// When the entries of a group are met front to back only, one entry order
    /// suffices: the one in which such a reader meets the other check first.
    #[test]
    fn a_group_met_one_way_needs_one_entry_order() {
        let c_first = on_entries(&[(Toy::A, 1), (Toy::C, 0)]);
        assert_eq!(
            open_pairs::<ForwardList>(&[c_first]),
            vec![(Toy::B, Toy::C)]
        );
    }

    /// A check made on the entries met so far is met where those entries first
    /// break it, so a case puts it after a check of the expected class only
    /// when every reader, walking either way, meets it before the entry that
    /// check breaks on.
    #[test]
    fn a_check_made_on_the_entries_met_so_far_is_fixed_only_where_it_is_met_first() {
        let so_far = |a: usize, front_to_back: Option<usize>, back_to_front: Option<usize>| {
            // `c` is never the expected check here, so only where the latest
            // reader meets it matters.
            let span = |last| Span { first: 0, last };
            Evidence {
                case_id: format!("{a}"),
                broken: vec![(Toy::A, Some(a)), (Toy::C, None)],
                reach: BTreeMap::from([(
                    Toy::C,
                    Reach {
                        front_to_back: span(front_to_back),
                        back_to_front: span(back_to_front),
                    },
                )]),
                class: "first".to_string(),
            }
        };
        let pair = [(Toy::A, Toy::C)];
        assert!(open_among::<ToyList>(&[so_far(1, Some(0), Some(2))], &pair).is_empty());
        // A reader walking front to back meets `a` first.
        assert_eq!(
            open_among::<ToyList>(&[so_far(1, Some(2), Some(2))], &pair),
            pair
        );
        // So does one that can walk past every entry without meeting `c`.
        assert_eq!(
            open_among::<ToyList>(&[so_far(1, Some(0), None)], &pair),
            pair
        );
    }

    /// A toy list of four checks of four classes in two direction groups:
    /// the specification takes `q` and `p` together, one entry at a time
    /// front to back, and then `r` and `s` each over every entry.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
    enum Grouped {
        Q,
        P,
        R,
        S,
    }

    struct GroupedList;

    impl CheckList for GroupedList {
        type Check = Grouped;
        const DIRECTION_GROUPS: usize = 2;
        fn order() -> &'static [Grouped] {
            &[Grouped::Q, Grouped::P, Grouped::R, Grouped::S]
        }
        fn class(check: Grouped) -> &'static str {
            match check {
                Grouped::Q => "q",
                Grouped::P => "p",
                Grouped::R => "r",
                Grouped::S => "s",
            }
        }
        fn claimed(_: Grouped, _: Grouped) -> bool {
            true
        }
        fn direction_group(check: Grouped) -> usize {
            usize::from(matches!(check, Grouped::R | Grouped::S))
        }
        fn specification_report(broken: &[(Grouped, Option<usize>)]) -> Option<&'static str> {
            let stage = |check: Grouped| match check {
                Grouped::Q | Grouped::P => 0,
                Grouped::R => 1,
                Grouped::S => 2,
            };
            broken
                .iter()
                .min_by_key(|(check, entry)| (stage(*check), *entry, *check))
                .map(|(check, _)| Self::class(*check))
        }
    }

    /// Cases that refute every reader meeting the first group back to front
    /// leave the readers that meet only the second group that way, so a pair
    /// of the second group broken on two entries still needs both entry
    /// orders.
    #[test]
    fn a_refuted_family_leaves_the_others_to_be_fixed() {
        let case = |broken: &[(Grouped, usize)], class: &str| Evidence {
            case_id: format!("{broken:?}"),
            broken: broken
                .iter()
                .map(|(check, entry)| (*check, Some(*entry)))
                .collect(),
            reach: BTreeMap::new(),
            class: class.to_string(),
        };
        let first_group_forward = [
            case(&[(Grouped::Q, 0), (Grouped::P, 0)], "q"),
            case(&[(Grouped::P, 0), (Grouped::Q, 1)], "p"),
        ];
        let r_later = case(&[(Grouped::R, 1), (Grouped::S, 0)], "r");
        let r_earlier = case(&[(Grouped::R, 0), (Grouped::S, 1)], "r");
        let pair = (Grouped::R, Grouped::S);
        let mut cases = first_group_forward.to_vec();
        cases.push(r_later);
        assert!(open_pairs::<GroupedList>(&cases).contains(&pair));
        cases.push(r_earlier);
        assert!(!open_pairs::<GroupedList>(&cases).contains(&pair));
    }

    /// A stored class the specification order cannot produce is refused.
    #[test]
    #[should_panic(expected = "the specification's reader does not report the stored class")]
    fn a_case_against_the_specification_order_is_refused() {
        open_pairs::<ToyList>(&[case(&[Toy::A, Toy::C], "second")]);
    }

    /// A case none of whose broken checks reports its class is refused.
    #[test]
    #[should_panic(expected = "the specification's reader does not report the stored class")]
    fn a_case_with_no_check_of_its_class_is_refused() {
        open_pairs::<ToyList>(&[case(&[Toy::C], "first")]);
    }

    /// A reader declaring no capability, for the toy list.
    struct NoCapabilities;

    impl ReaderCapabilities for NoCapabilities {
        type Check = Toy;

        fn declaring(_run: &[String]) -> (Self, BTreeSet<Toy>) {
            (NoCapabilities, BTreeSet::new())
        }
    }

    /// A reading whose readers the cases rule out entirely is reported, not
    /// passed over as one that leaves nothing open.
    #[test]
    fn a_reading_the_cases_rule_out_is_reported() {
        let loaded_case = |broken: &[Toy], class: &str| LoadedCase {
            row: Row::from([
                ("case_id".to_string(), format!("{broken:?} {class}")),
                ("diagnostic_class".to_string(), class.to_string()),
            ]),
            breaks: BTreeMap::from([(
                Vec::new(),
                Breaks {
                    certain: broken.iter().map(|&check| (check, None)).collect(),
                    ..Breaks::default()
                },
            )]),
        };
        let fixing = || {
            vec![
                loaded_case(&[Toy::A, Toy::C], "first"),
                loaded_case(&[Toy::B, Toy::C], "first"),
            ]
        };
        let mut contradicted = fixing();
        contradicted.push(loaded_case(&[Toy::A, Toy::C], "second"));
        let loaded = LoadedReadings {
            runs: vec![Vec::new()],
            readings: vec![("consistent", fixing()), ("contradicted", contradicted)],
        };
        assert_eq!(
            stray_open_pairs::<ToyList, NoCapabilities, _>(&loaded, |_, _, _| true),
            vec![r#"the cases rule out every reader of "contradicted" declaring []"#.to_string()]
        );
    }

    /// A length rule a reader may judge on a declared length or on the bytes
    /// it takes breaks for every reader only when both are wrong.
    #[test]
    fn a_length_rule_on_two_lengths_is_certain_only_when_both_are_wrong() {
        assert_eq!(length_rule_breaks(true, Some(true)), Some(true));
        assert_eq!(length_rule_breaks(true, Some(false)), Some(false));
        assert_eq!(length_rule_breaks(false, Some(true)), Some(false));
        assert_eq!(length_rule_breaks(true, None), Some(false));
        assert_eq!(length_rule_breaks(false, Some(false)), None);
        assert_eq!(length_rule_breaks(false, None), None);
    }

    /// A stored type name breaks the grammar for every reader inside 1..=255
    /// bytes and for some outside, and its support breaks for a reader that
    /// judges it.
    #[test]
    fn a_stored_type_name_is_judged_by_its_grammar_and_support() {
        let judge = |name: &[u8], supported: bool, support_of_any_name: bool| {
            let judged = type_name_breaks(name, supported, support_of_any_name);
            (judged.grammar, judged.support)
        };
        assert_eq!(judge(b"x25519", true, false), (None, None));
        assert_eq!(judge(b"test/unsupported", false, false), (None, Some(true)));
        assert_eq!(judge(b"X25519", false, false), (Some(true), None));
        assert_eq!(judge(b"X25519", false, true), (Some(true), Some(true)));
        let long = vec![b'a'; TYPE_NAME_MAX_LEN + 1];
        assert_eq!(judge(&long, false, false), (Some(false), Some(false)));
        assert_eq!(judge(&long, false, true), (Some(false), Some(true)));
        assert_eq!(judge(b"", false, false), (Some(false), Some(false)));
    }
}
