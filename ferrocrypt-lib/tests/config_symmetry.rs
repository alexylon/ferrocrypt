//! Writer/reader configuration symmetry.
//!
//! The repository's first rule is that FerroCrypt never writes a file
//! the same-configured reader would refuse. Each cap below is therefore
//! measured from both sides: the lowest value at which the writer
//! accepts a fixture, and the lowest value at which the reader accepts
//! the file that writer produced. The two must be the same number.
//!
//! Thresholds are searched rather than written down, so a test cannot
//! disagree with the implementation about how an entry, a component, or
//! a header byte is counted — only about whether the two sides agree.
//!
//! Scope: the caps a writer can actually exercise. Reader-only caps
//! ([`ferrocrypt::KeyReadLimits`]) and caps no current writer can reach
//! (the extension regions, which every writer emits empty) have no
//! writer half to compare against, so they are reader boundaries rather
//! than symmetry pairs and are not measured here.

use std::fs;
use std::path::{Path, PathBuf};

use ferrocrypt::{
    ArchiveLimits, CryptoError, Decryptor, Encryptor, HeaderReadLimits, KdfLimit, KdfParams,
    KeyGenOutcome, KeyPairGenerator, Passphrase, PrivateKey, PublicKey,
};
use ferrocrypt_test_support::{TEST_FAST_KDF_MEM_COST, fast_keypair_generator};

const PASSPHRASE: &str = "config-symmetry-passphrase";
const TEST_WORKSPACE: &str = "tests/workspace_config_symmetry";

#[ctor::dtor]
fn cleanup() {
    ferrocrypt_test_support::remove_per_process_workspace(TEST_WORKSPACE);
}

fn fresh_workspace(name: &str) -> PathBuf {
    // Per-process subtree, so a concurrent `cargo test` invocation of
    // this binary cannot delete files this run is using.
    let dir = ferrocrypt_test_support::per_process_workspace(TEST_WORKSPACE).join(name);
    reset_dir(&dir);
    dir
}

fn reset_dir(dir: &Path) {
    if dir.exists() {
        fs::remove_dir_all(dir).expect("clear directory");
    }
    fs::create_dir_all(dir).expect("create directory");
}

fn pass() -> Passphrase {
    Passphrase::new(PASSPHRASE)
}

/// Source tree the caps are measured against: nested enough to give
/// entry count, path depth, and path length distinct thresholds, and
/// small enough that a search over a cap's whole range stays quick.
fn build_source_tree(root: &Path) {
    reset_dir(root);
    fs::create_dir_all(root.join("sub/deep")).expect("create nested directories");
    fs::write(root.join("alpha.txt"), b"alpha").expect("write alpha");
    fs::write(root.join("sub/bravo.txt"), b"bravo").expect("write bravo");
    fs::write(root.join("sub/deep/charlie.txt"), b"charlie").expect("write charlie");
}

/// Confirms an extracted tree holds what [`build_source_tree`] wrote.
fn assert_tree_restored(root: &Path) {
    assert_eq!(
        fs::read(root.join("alpha.txt")).expect("read alpha"),
        b"alpha"
    );
    assert_eq!(
        fs::read(root.join("sub/bravo.txt")).expect("read bravo"),
        b"bravo"
    );
    assert_eq!(
        fs::read(root.join("sub/deep/charlie.txt")).expect("read charlie"),
        b"charlie"
    );
}

/// A cap with both a writer and a reader half.
///
/// The first five belong to [`ArchiveLimits`] and gate the archive
/// inside the encrypted file; the last four belong to
/// [`HeaderReadLimits`] and gate the `.fcr` header around it.
#[derive(Clone, Copy, Debug)]
enum Axis {
    EntryCount,
    TotalPlaintextBytes,
    PathDepth,
    PathBytes,
    ManifestBytes,
    RecipientCount,
    RecipientBodyLen,
    HeaderLen,
    HeaderMacWorkBytes,
}

/// Every axis, so adding one to this suite is a single edit.
const AXES: [Axis; 9] = [
    Axis::EntryCount,
    Axis::TotalPlaintextBytes,
    Axis::PathDepth,
    Axis::PathBytes,
    Axis::ManifestBytes,
    Axis::RecipientCount,
    Axis::RecipientBodyLen,
    Axis::HeaderLen,
    Axis::HeaderMacWorkBytes,
];

impl Axis {
    /// The published default for this cap, which is also the top of the
    /// search range: every fixture here sits well inside the defaults,
    /// so the default is known to accept.
    fn ceiling(self) -> u64 {
        match self {
            Self::EntryCount => ArchiveLimits::ENTRY_COUNT_DEFAULT as u64,
            Self::TotalPlaintextBytes => ArchiveLimits::TOTAL_PLAINTEXT_BYTES_DEFAULT,
            Self::PathDepth => ArchiveLimits::PATH_DEPTH_DEFAULT as u64,
            Self::PathBytes => ArchiveLimits::PATH_BYTES_DEFAULT as u64,
            Self::ManifestBytes => ArchiveLimits::MANIFEST_BYTES_DEFAULT as u64,
            Self::RecipientCount => HeaderReadLimits::RECIPIENT_COUNT_DEFAULT as u64,
            Self::RecipientBodyLen => HeaderReadLimits::RECIPIENT_BODY_LEN_DEFAULT as u64,
            Self::HeaderLen => HeaderReadLimits::HEADER_LEN_DEFAULT as u64,
            Self::HeaderMacWorkBytes => HeaderReadLimits::HEADER_MAC_WORK_BYTES_DEFAULT,
        }
    }

    /// Archive caps set to `value` on this axis, defaults elsewhere. An
    /// axis from the other family leaves the whole struct at its
    /// defaults, so both families run through one code path.
    fn archive_limits(self, value: u64) -> ArchiveLimits {
        let limits = ArchiveLimits::default();
        match self {
            Self::EntryCount => limits.max_entry_count(as_u32(value)),
            Self::TotalPlaintextBytes => limits.max_total_plaintext_bytes(value),
            Self::PathDepth => limits.max_path_depth(as_u32(value)),
            Self::PathBytes => limits.max_path_bytes(as_u32(value)),
            Self::ManifestBytes => limits.max_manifest_bytes(as_u32(value)),
            _ => limits,
        }
    }

    /// Header caps set to `value` on this axis, defaults elsewhere.
    fn header_limits(self, value: u64) -> HeaderReadLimits {
        let limits = HeaderReadLimits::default();
        match self {
            Self::RecipientCount => limits.max_recipient_count(as_u16(value)),
            Self::RecipientBodyLen => limits.max_recipient_body_len(as_u32(value)),
            Self::HeaderLen => limits.max_header_len(as_u32(value)),
            Self::HeaderMacWorkBytes => limits.max_header_mac_work_bytes(value),
            _ => limits,
        }
    }

    /// The rejection both sides must report below the threshold.
    fn rejects_with(self, error: &CryptoError) -> bool {
        match self {
            Self::EntryCount => {
                matches!(error, CryptoError::ArchiveEntryCountCapExceeded { .. })
            }
            Self::TotalPlaintextBytes => {
                matches!(error, CryptoError::ArchiveTotalBytesCapExceeded { .. })
            }
            Self::PathDepth => matches!(error, CryptoError::ArchivePathDepthCapExceeded { .. }),
            Self::PathBytes => matches!(error, CryptoError::ArchivePathBytesCapExceeded { .. }),
            Self::ManifestBytes => {
                matches!(error, CryptoError::ArchiveManifestLenCapExceeded { .. })
            }
            Self::RecipientCount => matches!(error, CryptoError::RecipientCountCapExceeded { .. }),
            Self::RecipientBodyLen => matches!(error, CryptoError::RecipientBodyCapExceeded { .. }),
            Self::HeaderLen => matches!(error, CryptoError::HeaderLenCapExceeded { .. }),
            Self::HeaderMacWorkBytes => {
                matches!(error, CryptoError::HeaderMacWorkCapExceeded { .. })
            }
        }
    }
}

fn as_u32(value: u64) -> u32 {
    u32::try_from(value).expect("axis value fits its cap type")
}

fn as_u16(value: u64) -> u16 {
    u16::try_from(value).expect("axis value fits its cap type")
}

/// Encrypts `source` with `axis` capped at `value`, into a cleared
/// `out_dir`. Both limit families are applied on every call, so the
/// writer configuration is built exactly as the reader's is below.
fn write_at(
    axis: Axis,
    value: u64,
    source: &Path,
    out_dir: &Path,
    public_key_path: &Path,
) -> Result<PathBuf, CryptoError> {
    reset_dir(out_dir);
    let public_key = PublicKey::from_key_file(public_key_path).expect("read public key");
    Encryptor::with_public_key(public_key)
        .archive_limits(axis.archive_limits(value))
        .header_read_limits(axis.header_limits(value))
        .write(source, out_dir, |_| {})
        .map(|outcome| outcome.output_path)
}

/// Decrypts `encrypted` with `axis` capped at `value`, into a cleared
/// `out_dir`. The caps are applied at both reader gates: the structural
/// open, and the operation that follows it.
fn read_at(
    axis: Axis,
    value: u64,
    encrypted: &Path,
    out_dir: &Path,
    private_key_path: &Path,
) -> Result<PathBuf, CryptoError> {
    reset_dir(out_dir);
    let decryptor = Decryptor::open_with_limits(encrypted, axis.header_limits(value))?;
    let Decryptor::PrivateKey(decryptor) = decryptor else {
        panic!("a public-key file must open as a private-key decryptor");
    };
    let private_key = PrivateKey::from_key_file(private_key_path, pass());
    decryptor
        .archive_limits(axis.archive_limits(value))
        .header_read_limits(axis.header_limits(value))
        .decrypt(private_key, out_dir, |_| {})
        .map(|outcome| outcome.output_path)
}

/// Lowest value in `0..=ceiling` at which `accepts` succeeds.
///
/// Raising a cap never turns an accepted operation into a refused one,
/// so acceptance is monotone and a search finds the one value where it
/// changes. The probe doubles from 1 before narrowing, so a threshold
/// near the bottom of a cap's range — which every fixture here has —
/// costs a handful of operations rather than a search over the whole
/// published range.
///
/// # Panics
///
/// Panics if the ceiling itself refuses, which would mean there is no
/// threshold in range to find.
fn lowest_accepting(ceiling: u64, accepts: impl Fn(u64) -> bool) -> u64 {
    // Everything below `low` is known to refuse; `high` is the first
    // value known to accept.
    let (mut low, mut high) = (0u64, 1u64);
    loop {
        if high >= ceiling {
            high = ceiling;
            assert!(
                accepts(high),
                "the search ceiling must accept, or the fixture does not fit the published default"
            );
            break;
        }
        if accepts(high) {
            break;
        }
        low = high + 1;
        high = high.saturating_mul(2);
    }
    while low < high {
        let middle = low + (high - low) / 2;
        if accepts(middle) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    low
}

/// Confirms nothing was left behind by a refused write. The rule the
/// writer preflights exist for is that a refusal costs the caller
/// nothing, so a refused encrypt must not leave a partial `.fcr`.
fn assert_no_output(out_dir: &Path) {
    let entries: Vec<PathBuf> = fs::read_dir(out_dir)
        .expect("read output directory")
        .map(|entry| entry.expect("read entry").path())
        .collect();
    assert!(
        entries.is_empty(),
        "a refused write must leave the output directory empty, found {entries:?}"
    );
}

/// Every writer/reader cap pair agrees on where it refuses.
///
/// For each axis: find the lowest cap the writer accepts, then require
/// the reader to accept the file that writer produced at that same cap
/// and to refuse it one below, with the axis's own error on both
/// sides. Under the monotonicity the threshold search itself assumes,
/// those two probes pin the reader's threshold to the writer's number
/// without a second search, and the axis-error checks keep a shared
/// threshold from being satisfied by two caps that reject for
/// unrelated reasons.
///
/// Fails if a cap gains a writer half that refuses later than its
/// reader half (a file FerroCrypt writes but cannot read back), or
/// earlier (a file it refuses to write but would accept).
#[test]
fn every_writer_cap_refuses_exactly_where_its_reader_half_does() {
    let work = fresh_workspace("thresholds");
    let source = work.join("tree");
    build_source_tree(&source);

    let keys = work.join("keys");
    fs::create_dir_all(&keys).expect("create key directory");
    let keypair = fast_keypair_generator(pass())
        .write(&keys, |_| {})
        .expect("generate key pair");

    // Three directories, because a write probe clears the one it writes
    // into: `out_dir` takes the throwaway attempts, `kept_dir` holds the
    // one artefact each axis is then measured against.
    let out_dir = work.join("out");
    let kept_dir = work.join("kept");
    let restore_dir = work.join("restored");

    for axis in AXES {
        let writer_threshold = lowest_accepting(axis.ceiling(), |value| {
            write_at(axis, value, &source, &out_dir, &keypair.public_key_path).is_ok()
        });
        assert!(
            writer_threshold > 0,
            "{axis:?}: a cap of zero was accepted, so the writer does not enforce it"
        );

        // Written once at the threshold, then read back at descending
        // caps: the reader is measured against the file the writer
        // actually produced at its own limit.
        let encrypted = write_at(
            axis,
            writer_threshold,
            &source,
            &kept_dir,
            &keypair.public_key_path,
        )
        .unwrap_or_else(|e| panic!("{axis:?}: writing at its own threshold must succeed: {e}"));

        // No second search for the reader: succeeding here and being
        // refused one below (checked at the end of the loop) pins the
        // reader's threshold to the writer's number, under the same
        // monotonicity the search itself assumes.
        let restored = read_at(
            axis,
            writer_threshold,
            &encrypted,
            &restore_dir,
            &keypair.private_key_path,
        )
        .unwrap_or_else(|e| panic!("{axis:?}: reading at the shared threshold must succeed: {e}"));
        assert_tree_restored(&restored);

        let below = writer_threshold - 1;
        let write_error = write_at(axis, below, &source, &out_dir, &keypair.public_key_path)
            .expect_err("a cap below the threshold must refuse the write");
        assert!(
            axis.rejects_with(&write_error),
            "{axis:?}: the writer must refuse with this axis's own error, got {write_error}"
        );
        assert_no_output(&out_dir);

        let read_error = read_at(
            axis,
            below,
            &encrypted,
            &restore_dir,
            &keypair.private_key_path,
        )
        .expect_err("a cap below the threshold must refuse the read");
        assert!(
            axis.rejects_with(&read_error),
            "{axis:?}: the reader must refuse with this axis's own error, got {read_error}"
        );
    }
}

/// `max_path_bytes` is the one archive cap the format itself bounds, so
/// the published structural maximum must be a value both sides accept
/// rather than one the builder silently reduces to something smaller.
#[test]
fn the_path_length_cap_accepts_its_structural_maximum_on_both_sides() {
    let work = fresh_workspace("structural_max");
    let source = work.join("tree");
    build_source_tree(&source);

    let keys = work.join("keys");
    fs::create_dir_all(&keys).expect("create key directory");
    let keypair = fast_keypair_generator(pass())
        .write(&keys, |_| {})
        .expect("generate key pair");

    let at_max = u64::from(ArchiveLimits::PATH_BYTES_STRUCTURAL_MAX);
    let encrypted = write_at(
        Axis::PathBytes,
        at_max,
        &source,
        &work.join("out"),
        &keypair.public_key_path,
    )
    .expect("the structural maximum must be accepted for writing");

    let restored = read_at(
        Axis::PathBytes,
        at_max,
        &encrypted,
        &work.join("restored"),
        &keypair.private_key_path,
    )
    .expect("the structural maximum must be accepted for reading");
    assert_tree_restored(&restored);
}

/// Recipient counts across the default cap, decrypted from the last
/// slot rather than the first.
///
/// Each list is padded with a stranger's public key and ends with the
/// key under test, so every count above one walks past slots that
/// cannot unwrap before reaching the one that can. A count above the
/// default is refused by the writer unless the caller raises the cap,
/// and the same raise on the reader must accept the file — the
/// recipient-count half of the symmetry rule, stated over a real list
/// rather than a preflight.
#[test]
fn recipient_counts_across_the_default_cap_stay_symmetric() {
    let work = fresh_workspace("recipient_counts");
    let input = work.join("payload.txt");
    fs::write(&input, b"multi-recipient payload").expect("write payload");

    let stranger_keys = work.join("stranger");
    let holder_keys = work.join("holder");
    fs::create_dir_all(&stranger_keys).expect("create stranger key directory");
    fs::create_dir_all(&holder_keys).expect("create holder key directory");
    let stranger = fast_keypair_generator(pass())
        .write(&stranger_keys, |_| {})
        .expect("generate stranger key pair");
    let holder = fast_keypair_generator(pass())
        .write(&holder_keys, |_| {})
        .expect("generate holder key pair");

    let default_cap = HeaderReadLimits::RECIPIENT_COUNT_DEFAULT;
    for count in [1u16, 2, default_cap, default_cap + 1] {
        let above_default = count > default_cap;
        let limits = HeaderReadLimits::default().max_recipient_count(count);
        let out_dir = work.join(format!("out-{count}"));
        reset_dir(&out_dir);

        // Slots before the last belong to the stranger; the last is the
        // holder's, so every count above one makes the decrypt below
        // walk past a slot it cannot open.
        let mut recipients: Vec<PublicKey> = (1..count)
            .map(|_| PublicKey::from_key_file(&stranger.public_key_path).expect("read stranger"))
            .collect();
        recipients.push(PublicKey::from_key_file(&holder.public_key_path).expect("read holder"));

        let at_default = Encryptor::with_public_keys(recipients.clone())
            .expect("collect recipients")
            .write(&input, &out_dir, |_| {});
        if above_default {
            let error = at_default.expect_err("a count above the default cap must be refused");
            assert!(
                matches!(error, CryptoError::RecipientCountCapExceeded { .. }),
                "expected the recipient-count cap, got {error}"
            );
            assert_no_output(&out_dir);
        } else {
            at_default.unwrap_or_else(|e| panic!("{count} recipients must be accepted: {e}"));
            reset_dir(&out_dir);
        }

        let encrypted = Encryptor::with_public_keys(recipients)
            .expect("collect recipients")
            .header_read_limits(limits)
            .write(&input, &out_dir, |_| {})
            .unwrap_or_else(|e| panic!("{count} recipients under a matching cap must write: {e}"))
            .output_path;

        if above_default {
            let error = Decryptor::open(&encrypted)
                .expect_err("the default reader cap must refuse a file above it");
            assert!(
                matches!(error, CryptoError::RecipientCountCapExceeded { .. }),
                "expected the recipient-count cap, got {error}"
            );
        }

        let restore_dir = work.join(format!("restored-{count}"));
        reset_dir(&restore_dir);
        let Decryptor::PrivateKey(decryptor) =
            Decryptor::open_with_limits(&encrypted, limits).expect("open under a matching cap")
        else {
            panic!("a public-key file must open as a private-key decryptor");
        };
        let private_key = PrivateKey::from_key_file(&holder.private_key_path, pass());
        let restored = decryptor
            .header_read_limits(limits)
            .decrypt(private_key, &restore_dir, |_| {})
            .unwrap_or_else(|e| panic!("{count} recipients must decrypt: {e}"))
            .output_path;
        assert_eq!(
            fs::read(&restored).expect("read restored payload"),
            b"multi-recipient payload"
        );
    }
}

// -- Key-derivation caps ---------------------------------------------------

/// Argon2id time cost the fixtures below are written with. Above one, so
/// the axis has a value beneath its threshold for both sides to refuse.
const FIXTURE_TIME_COST: u32 = 2;

/// Argon2id lane count the fixtures below are written with, above one
/// for the same reason as [`FIXTURE_TIME_COST`].
const FIXTURE_LANES: u32 = 2;

/// The parameters every key-derivation fixture here is written with.
///
/// Memory sits at the writer's floor — the lowest value it will emit —
/// so the memory axis measures the limit rather than the floor. The two
/// deliberate asymmetries are kept apart that way: this suite measures
/// where the caps agree, and
/// [`the_memory_floor_is_a_writer_only_boundary`] measures the floor.
fn fixture_kdf_params() -> KdfParams {
    KdfParams {
        mem_cost: TEST_FAST_KDF_MEM_COST,
        time_cost: FIXTURE_TIME_COST,
        lanes: FIXTURE_LANES,
    }
}

/// A key-derivation cap with both a writer and a reader half.
///
/// Each is set on [`KdfLimit`], which the writer applies to the
/// parameters it is about to store and the reader applies to the
/// parameters it finds stored — in a `.fcr` recipient body for a
/// passphrase file, or in a `private.key` cleartext header.
#[derive(Clone, Copy, Debug)]
enum KdfAxis {
    MemCost,
    TimeCost,
    Lanes,
    Work,
}

/// Every key-derivation axis, so adding one is a single edit.
const KDF_AXES: [KdfAxis; 4] = [
    KdfAxis::MemCost,
    KdfAxis::TimeCost,
    KdfAxis::Lanes,
    KdfAxis::Work,
];

impl KdfAxis {
    /// The value [`KdfLimit::default`] carries for this cap, and the top
    /// of the search range. Memory and work default to the writer's own
    /// budget; time cost and lanes default to the format's maxima.
    fn ceiling(self) -> u64 {
        match self {
            Self::MemCost => KdfLimit::MEM_COST_KIB_DEFAULT as u64,
            Self::TimeCost => KdfLimit::TIME_COST_STRUCTURAL_MAX as u64,
            Self::Lanes => KdfLimit::LANES_STRUCTURAL_MAX as u64,
            Self::Work => KdfLimit::WORK_DEFAULT,
        }
    }

    /// This cap set to `value`, every other dimension at its default.
    fn limit(self, value: u64) -> KdfLimit {
        match self {
            Self::MemCost => KdfLimit::new(as_u32(value)),
            Self::TimeCost => KdfLimit::default().max_time_cost(as_u32(value)),
            Self::Lanes => KdfLimit::default().max_lanes(as_u32(value)),
            Self::Work => KdfLimit::default().max_work(value),
        }
    }

    /// The rejection both sides must report below the threshold.
    fn rejects_with(self, error: &CryptoError) -> bool {
        match self {
            Self::MemCost => matches!(error, CryptoError::KdfResourceCapExceeded { .. }),
            Self::TimeCost => matches!(error, CryptoError::KdfTimeCostCapExceeded { .. }),
            Self::Lanes => matches!(error, CryptoError::KdfLanesCapExceeded { .. }),
            Self::Work => matches!(error, CryptoError::KdfWorkCapExceeded { .. }),
        }
    }
}

/// Encrypts `input` with a passphrase, `axis` capped at `value`, into a
/// cleared `out_dir`.
fn write_passphrase_at(
    axis: KdfAxis,
    value: u64,
    input: &Path,
    out_dir: &Path,
) -> Result<PathBuf, CryptoError> {
    reset_dir(out_dir);
    Encryptor::with_passphrase(pass())
        .kdf_params(fixture_kdf_params())
        .kdf_limit(axis.limit(value))
        .write(input, out_dir, |_| {})
        .map(|outcome| outcome.output_path)
}

/// Decrypts a passphrase file with `axis` capped at `value`, into a
/// cleared `out_dir`.
fn read_passphrase_at(
    axis: KdfAxis,
    value: u64,
    encrypted: &Path,
    out_dir: &Path,
) -> Result<PathBuf, CryptoError> {
    reset_dir(out_dir);
    let Decryptor::Passphrase(decryptor) = Decryptor::open(encrypted)? else {
        panic!("a passphrase file must open as a passphrase decryptor");
    };
    decryptor
        .kdf_limit(axis.limit(value))
        .decrypt(pass(), out_dir, |_| {})
        .map(|outcome| outcome.output_path)
}

/// Generates a key pair with `axis` capped at `value`, into a cleared
/// `keys_dir`.
fn generate_at(axis: KdfAxis, value: u64, keys_dir: &Path) -> Result<KeyGenOutcome, CryptoError> {
    reset_dir(keys_dir);
    KeyPairGenerator::with_passphrase(pass())
        .kdf_params(fixture_kdf_params())
        .kdf_limit(axis.limit(value))
        .write(keys_dir, |_| {})
}

/// Decrypts a public-key file with `axis` capped at `value`, into a
/// cleared `out_dir`. The only key derivation on this path is the
/// `private.key` unlock, so the cap under test is the unlock's.
fn unlock_at(
    axis: KdfAxis,
    value: u64,
    encrypted: &Path,
    out_dir: &Path,
    private_key_path: &Path,
) -> Result<PathBuf, CryptoError> {
    reset_dir(out_dir);
    let Decryptor::PrivateKey(decryptor) = Decryptor::open(encrypted)? else {
        panic!("a public-key file must open as a private-key decryptor");
    };
    decryptor
        .kdf_limit(axis.limit(value))
        .decrypt(
            PrivateKey::from_key_file(private_key_path, pass()),
            out_dir,
            |_| {},
        )
        .map(|outcome| outcome.output_path)
}

/// Runs the threshold comparison for one key-derivation axis.
///
/// Written as one helper because the passphrase path and the key-file
/// path make the same claim about the same four caps, and a second copy
/// of the protocol would be free to drift from the first.
fn assert_kdf_axis_symmetric<Artefact>(
    axis: KdfAxis,
    write_at: impl Fn(u64) -> Result<PathBuf, CryptoError>,
    keep_at: impl Fn(u64) -> Artefact,
    read_at: impl Fn(u64, &Artefact) -> Result<PathBuf, CryptoError>,
    refused_write_dir: &Path,
    expected_plaintext: &[u8],
) {
    let writer_threshold = lowest_accepting(axis.ceiling(), |value| write_at(value).is_ok());
    assert!(
        writer_threshold > 0,
        "{axis:?}: a cap of zero was accepted, so the writer does not enforce it"
    );

    // What the reader is measured against: for a passphrase file the
    // `.fcr` alone, for key generation the generated key pair plus a
    // file encrypted to it.
    let kept = keep_at(writer_threshold);

    let reader_threshold = lowest_accepting(axis.ceiling(), |value| read_at(value, &kept).is_ok());
    assert_eq!(
        writer_threshold, reader_threshold,
        "{axis:?}: the writer and the reader must refuse at the same cap"
    );

    let restored = read_at(reader_threshold, &kept)
        .unwrap_or_else(|e| panic!("{axis:?}: reading at the shared threshold must succeed: {e}"));
    assert_eq!(
        fs::read(&restored).expect("read restored payload"),
        expected_plaintext
    );

    let below = writer_threshold - 1;
    let write_error = write_at(below).expect_err("a cap below the threshold must refuse the write");
    assert!(
        axis.rejects_with(&write_error),
        "{axis:?}: the writer must refuse with this axis's own error, got {write_error}"
    );
    assert_no_output(refused_write_dir);

    let read_error =
        read_at(below, &kept).expect_err("a cap below the threshold must refuse the read");
    assert!(
        axis.rejects_with(&read_error),
        "{axis:?}: the reader must refuse with this axis's own error, got {read_error}"
    );
}

/// Every passphrase key-derivation cap agrees on where it refuses.
///
/// This is the one encryption path where the key-derivation caps have a
/// write side at all: public-key encryption runs no Argon2id, so its
/// `kdf_params` and `kdf_limit` are documented no-ops.
#[test]
fn every_passphrase_kdf_cap_refuses_exactly_where_its_reader_half_does() {
    let work = fresh_workspace("passphrase_kdf");
    let input = work.join("payload.txt");
    let plaintext = b"passphrase key-derivation payload";
    fs::write(&input, plaintext).expect("write payload");

    let out_dir = work.join("out");
    let kept_dir = work.join("kept");
    let restore_dir = work.join("restored");

    for axis in KDF_AXES {
        assert_kdf_axis_symmetric(
            axis,
            |value| write_passphrase_at(axis, value, &input, &out_dir),
            |value| {
                write_passphrase_at(axis, value, &input, &kept_dir).unwrap_or_else(|e| {
                    panic!("{axis:?}: writing at its own threshold must succeed: {e}")
                })
            },
            |value, encrypted| read_passphrase_at(axis, value, encrypted, &restore_dir),
            &out_dir,
            plaintext,
        );
    }
}

/// Every key-generation cap agrees with the `private.key` unlock.
///
/// Key generation is a writer whose reader is the unlock, so the same
/// rule applies to it: a key pair FerroCrypt generates under a given
/// budget must be one it can unlock under that budget. The unlock is
/// driven through a public-key decrypt, because that is where the
/// library performs it — and the X25519 path itself runs no key
/// derivation, so the cap measured is the unlock's alone.
#[test]
fn every_key_generation_kdf_cap_refuses_exactly_where_the_unlock_does() {
    let work = fresh_workspace("keygen_kdf");
    let input = work.join("payload.txt");
    let plaintext = b"key-file unlock payload";
    fs::write(&input, plaintext).expect("write payload");

    let probe_keys = work.join("probe-keys");
    let kept_keys = work.join("kept-keys");
    let encrypted_dir = work.join("encrypted");
    let restore_dir = work.join("restored");

    for axis in KDF_AXES {
        assert_kdf_axis_symmetric(
            axis,
            |value| generate_at(axis, value, &probe_keys).map(|kg| kg.private_key_path),
            |value| {
                // The kept pair is encrypted to once, so every unlock
                // probe reads the same file and differs only in its cap.
                let generated = generate_at(axis, value, &kept_keys).unwrap_or_else(|e| {
                    panic!("{axis:?}: generating at its own threshold must succeed: {e}")
                });
                reset_dir(&encrypted_dir);
                let public_key =
                    PublicKey::from_key_file(&generated.public_key_path).expect("read public key");
                let encrypted = Encryptor::with_public_key(public_key)
                    .write(&input, &encrypted_dir, |_| {})
                    .expect("encrypt to the generated key")
                    .output_path;
                (encrypted, generated.private_key_path)
            },
            |value, (encrypted, private_key_path)| {
                unlock_at(axis, value, encrypted, &restore_dir, private_key_path)
            },
            &probe_keys,
            plaintext,
        );
    }
}

/// The memory floor is a boundary the writers apply alone, rather than
/// an offset from one.
///
/// Both writers refuse to emit Argon2id parameters below it and both
/// accept it exactly: the value is a minimum strength, not a resource
/// ceiling, so there is nothing for a reader to mirror. The reader
/// deliberately has no floor, which keeps files written by older
/// releases readable — proven on every run by the frozen sub-floor
/// fixture that `frozen_fixture_compat.rs` decrypts under default
/// limits, and not reproducible here because no current writer can
/// produce one. That this is the *only* such cap is what the threshold
/// tests above establish, by finding every other one symmetric.
#[test]
fn the_memory_floor_is_a_writer_only_boundary() {
    let work = fresh_workspace("write_floor");
    let input = work.join("payload.txt");
    fs::write(&input, b"floor payload").expect("write payload");
    let out_dir = work.join("out");
    let keys_dir = work.join("keys");

    let at_floor = KdfParams {
        mem_cost: TEST_FAST_KDF_MEM_COST,
        time_cost: FIXTURE_TIME_COST,
        lanes: FIXTURE_LANES,
    };
    let below_floor = KdfParams {
        mem_cost: at_floor.mem_cost - 1,
        ..at_floor
    };

    reset_dir(&out_dir);
    Encryptor::with_passphrase(pass())
        .kdf_params(at_floor)
        .write(&input, &out_dir, |_| {})
        .expect("the floor itself must be accepted for writing");

    reset_dir(&out_dir);
    let encrypt_error = Encryptor::with_passphrase(pass())
        .kdf_params(below_floor)
        .write(&input, &out_dir, |_| {})
        .expect_err("memory below the floor must be refused");
    assert!(
        matches!(encrypt_error, CryptoError::KdfBelowWriteFloor { .. }),
        "expected the write floor, got {encrypt_error}"
    );
    assert_no_output(&out_dir);

    reset_dir(&keys_dir);
    let keygen_error = KeyPairGenerator::with_passphrase(pass())
        .kdf_params(below_floor)
        .write(&keys_dir, |_| {})
        .expect_err("memory below the floor must be refused for key generation too");
    assert!(
        matches!(keygen_error, CryptoError::KdfBelowWriteFloor { .. }),
        "expected the write floor, got {keygen_error}"
    );
    assert_no_output(&keys_dir);
}
