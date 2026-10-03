//! Order coverage of the frozen wire corpus (`FORMAT.md` §12.3).
//!
//! Three rows of the §12.3 evidence table claim more than the presence of
//! cases: that the corpus fixes the order of every two checks of a check list
//! that report different classes and that one artifact can break together.
//! The rows cover the `.fcr` checks of §3.1 to §3.3 and of §3.7 up to the first
//! recipient attempt, the `public.key` checks of §7.1 and §7, and the
//! `private.key` checks of §8. This module checks the `.fcr` claim against the
//! committed corpus, so it stays true as the corpus grows.
//!
//! **The evidence model.** A reader is modelled as an order over the checks of
//! a list. A rejected case states the class the reader reports for its
//! artifact, so of the checks the artifact breaks, one of that class comes
//! first: every broken check of another class follows some broken check of the
//! expected class. Each case thus yields constraints, and a pair of checks is
//! fixed when no order that satisfies every constraint puts the later check
//! first. A reader may make checks made once per recipient entry in one pass,
//! one entry at a time, front to back or back to front. A list sorts those
//! checks into groups whose entries a reader meets in one direction, and each
//! way of giving every group a direction its list allows is a family of
//! readers. A family the cases rule out entirely is refuted; every other family
//! must fix every claimed pair. A reader that meets the entries in different
//! directions for checks of one group is outside this model, so a list puts
//! checks in one group only where the specification makes them in one pass. A
//! reader may also make a check that the specification makes once over the
//! whole recipient list on the entries it has met so far, in a pass of either
//! direction, and so meet it at the first entry where those entries break it;
//! a case records where such readers, walking each way, first meet it. The
//! reader the specification describes must report every stored class.
//!
//! Each artifact is evaluated check by check, as a reader that made that check
//! first would see it: a check that reads bytes the file does not hold is not
//! broken. Checks a credential decides, such as unlocking a `private.key` or
//! unwrapping a recipient, are evaluated with the corpus credentials, so no
//! case states by hand which checks it breaks. Where such readers can disagree
//! on whether a check breaks, because they read past a declared end or judge a
//! list they could not read to its end, the case counts that check only if it
//! reports the case's class: a reader may report it, but a check of another
//! class that some readers pass fixes nothing.
//!
//! The base run asserts every case, as a reader that declares no capability
//! does (§12.2). Each combination of the capabilities the cases rest on that
//! change a check of the list then has a run of its own, which also declares
//! every capability the cases rest on that changes none: the cases that rest
//! on any of them are left out, as a reader that declares them leaves them
//! out, the checks they change are evaluated as such a reader would, and the
//! pairs that run loses must all involve one of those checks. A capability
//! that changes no check only leaves out more cases, so each run also stands
//! for the same combination without it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::path::Path;

use ferrocrypt_test_support::wire_manifest::{
    Row, cases_withdrawn_by_errata, corpus_revision, field, read_committed, read_table,
};

mod fcr;

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
    /// pair no artifact can break together, and a pair outside the scope its
    /// row states.
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
    let mut open = BTreeSet::new();
    for family in families::<L>() {
        let known: Vec<_> = evidence
            .iter()
            .flat_map(|case| constraints::<L>(case, &family))
            .collect();
        let groups = groups_before(&known);
        if !feasible(L::order(), &groups, None) {
            // The cases refute every reader of this family. The
            // specification's own family cannot be refuted, since its reader
            // reports every stored class.
            assert!(
                family.contains(&Direction::BackToFront),
                "no order of the checks satisfies every case for readers that meet every \
                 entry front to back"
            );
            continue;
        }
        for &pair in pairs {
            if feasible(L::order(), &groups, Some(pair)) {
                open.insert(pair);
            }
        }
    }
    pairs
        .iter()
        .copied()
        .filter(|pair| open.contains(pair))
        .collect()
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
}
