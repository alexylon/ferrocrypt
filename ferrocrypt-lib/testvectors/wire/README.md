# `testvectors/wire/` — frozen conformance corpus

The public, cross-language conformance contract for FerroCrypt. An independent
implementer — someone writing a reader in another language, or a separate Rust
crate with no access to this codebase — can fetch this directory and prove their
implementation conformant by replaying every case and comparing against the
committed expectations.

`FORMAT.md` §12.3 defines the identity, layout, manifest schema, provenance
rules, and freeze policy this corpus follows. Where this document and
`FORMAT.md` disagree, `FORMAT.md` governs.

```text
SCHEMA-VERSION  = 1     manifest grammar
CORPUS-REVISION = 1     append-only content revision
baseline_id     = 0.3.0 the compatibility promise these cases evidence
```

## Status

Populated and replaying. **Not yet frozen**: until stable release `0.3.0` is
tagged, the corpus may be regenerated freely, because `FORMAT.md` §11.4 places
artifacts from pre-release and untagged revisions outside the cross-release
promise. From the `v0.3.0` tag, manifest rows, artifact bytes, expected results,
digests, and class meanings are append-only and immutable; corrections use the
errata mechanism in §12.3 rather than edits.

## What is here

| Path | Contents |
|---|---|
| `baselines.tsv` | Compatibility baselines and their lineage |
| `diagnostic-classes.tsv` | The stable rejection classes this corpus uses |
| `diagnostic-classes/` | One file per class holding its stable explanatory text |
| `credentials.tsv` | Credential material each case is replayed with |
| `credentials/` | Passphrase bytes the credential table references |
| `limit-profiles.tsv` | The local resource limits each case is evaluated under |
| `origins.tsv` | Provenance of every payload encryption |
| `cases.tsv` | One row per case: artifact, outcome, and expectation |
| `errata.tsv` | Corrections to frozen rows; empty in revision 1 |
| `artifacts/` | The bytes under test, by artifact kind |
| `expected/` | Byte-exact expected results for accepted cases |
| `kat/stream/` | Payload STREAM known-answer material |
| `tools/` | Corpus tooling; see below |

## Credentials are public test material

Every passphrase and private key in this corpus is committed in the clear and
readable by anyone who fetches it. The filenames say so
(`credentials/passphrase-main.txt`, `credentials/passphrase-wrong.txt`), and so
does this sentence: **never reuse any of this material to protect real data.**
It exists only so a replay can open the accepted artifacts.

## Replaying the corpus

Read `cases.tsv`, and for each row perform the action its `case_type` names on
the bytes at `artifact_ref`, using the credential its `credential_id` names and
the limit profile its `limit_profile_id` names:

| `case_type` | Action | An accepted case must produce |
|---|---|---|
| `fcr_decrypt` | Decrypt the `.fcr` | the plaintext at `expected_ref` for a file root, and the extraction listing at `expected_ref` for a directory root |
| `public_key_decode` | Decode the `public.key` | the key material at `expected_ref` |
| `private_key_open` | Unlock the `private.key` | its public material at `expected_ref` |
| `private_key_validate` | Validate the `private.key` structurally | — |
| `stream_encrypt_kat` | Encrypt the input under the origin's key and nonce | the ciphertext at `expected_ref` |

The extraction listing is one LF-terminated line per extracted object, ordered
by path depth and then by path bytes: `kind SP size SP content_sha3_256 SP path`,
with `d` and two `-` fields for a directory. §12.3 defines it, and the extracted
root kind selects the comparison — not the case row.

A row with `outcome = reject` must be refused, and the refusal must map to the
`diagnostic_class` the row names. Match on structured errors: `FORMAT.md` §12.1
keeps English message text out of this contract, and `condition_id` distinguishes
exact conditions that share a class.

A row with `expectation_scope = capability_relative` names one capability in
`capability_id`. Assert its stored outcome only while your implementation does
not support that capability (`FORMAT.md` §12.2). An outcome that rests on an
unknown recipient or key type, or on an unknown extension tag, uses a test
value wherever it can: a type name beginning with `test/`, or tag `0x0001` or
`0x8001`. §3.3.1 and §6 set these aside as values no implementation
implements, so every case built on them is invariant. The one-letter native
type name `t`, which a type name at its minimum length needs, is not one, and
its cases are capability-relative. A second tag that a case needs only for its
structure, such as `0x0002` beside `0x0001`, cannot change the outcome,
because §6 checks the structure of a region before it refuses an unknown
critical tag or interprets the value of a tag it implements.

**Every case is evaluated under committed limits.** Local resource caps are
configuration rather than format, so a stored outcome can depend on them. Each
`limit-profiles.tsv` row gives every local cap a value, and each case names one
profile; set all of them before evaluating the case, whether it is accepted or
refused, and never choose them from the expected result — a cap can refuse
with a class other than `resource_cap_exceeded`. The values are frozen with the
corpus and do not follow FerroCrypt's defaults, which may change between
releases. Most cases name `default-0.3.0`, the defaults of FerroCrypt
`0.3.0`. A case that has to sit on a limit those defaults keep out of reach
names a profile that changes only what it needs: `header-structural-maxima`
raises the header-length, recipient-count, and recipient-body caps to the
structural maxima of `FORMAT.md` §3.1 to §3.3, `small-artifact-caps` sets
every cap to exactly what the one-byte passphrase file and the key pair of
the corpus need, each `lowered-*` profile lowers one cap, and
`recipient-string-structural-maximum` raises the recipient-string cap to the
§7 ceiling, so a string carrying key material on or past its maximum reaches
the payload checks. One profile serves the check order instead of a limit:
`zero-recipient-string-cap` sets that cap to zero, so a string too short to
hold a payload is over it.
`private_key_validate` and `stream_encrypt_kat` apply no local cap and name
`-`. An implementation that cannot set its caps to a profile's values cannot
assert the cases that name it.

**`first_required_by_baseline` names the promise a case evidences.** It is the
earliest compatibility baseline whose rules require the stored outcome.
Baselines are cumulative, so a replay claiming a baseline asserts every case
first required by that baseline or by one of its ancestors. It is not the
revision a case arrived in: `introduced_in_corpus_revision` records that.

### Verifying the corpus as data

`tools/verify_manifests.py` checks the corpus without decrypting anything and
without needing FerroCrypt: the table columns, the identifier and reference
grammar, every committed digest against the bytes it names, referential
integrity between the tables, the enumerated values, and the per-outcome column
rules of §12.3. Python 3 standard library only.

```bash
python3 tools/verify_manifests.py
```

It exits 0 when the corpus is well formed, and 1 with one line per problem
otherwise. Run it first: a corpus that fails here cannot be replayed meaningfully.
A reference's spelling is validated before the file it names is read: a
manifest holding a reference the grammar refuses is refused before any
referenced file is opened or examined.

`tools/test_verify_manifests.py` checks the checker: the committed corpus
passes, and a reference the grammar refuses is reported without any file being
reached through it.

```bash
python3 tools/test_verify_manifests.py
```

## Generation and reproduction

The corpus is generated by an ignored test in the FerroCrypt library crate and
committed by hand:

```bash
cargo test --package ferrocrypt --lib wire_vector_gen -- --ignored --test-threads=1
```

Generation runs under a fixed deterministic seed, so regenerating without
changing the generator reproduces the corpus byte for byte and leaves an empty
diff. Adding a case therefore shows only that case in the diff.

**Tool provenance.** The generator is
`ferrocrypt-lib/src/wire_vector_gen.rs`. It builds artifacts through the
library's own writer paths, including internal ones the public API does not
expose — crafted recipient lists, extension regions, out-of-range key-derivation
parameters, and payload transcripts that violate §5. Corpus-generation code is
test tooling, not part of FerroCrypt's public library API, and carries no
stability promise.

**FerroCrypt's own replay is split across two test binaries**, because raw
payload STREAM encryption is crate-internal and unreachable from an integration
test:

```bash
cargo test --package ferrocrypt --test wire_corpus          # every public-API case type
cargo test --package ferrocrypt --lib replay_stream_kats    # the STREAM known-answer cases
```

Each half asserts it covered its share of `cases.tsv` — the first that it
replayed every row it did not defer, the second that it replayed every row the
first deferred — so a case that stops being exercised fails the suite instead
of passing unnoticed. Both print the counts they covered. The first also
checks that each cap a limit profile lowers above zero is exactly what one of
that profile's accepted cases needs: lowered by one more, it must refuse that
case with the class a reader reports for that cap. Each cap a profile raises
above its default must be needed by one of that profile's cases: restored to
the default, it must refuse that case with the same class. Each cap a profile
other than `small-artifact-caps` lowers to zero must be needed by one of its
cases: that case is refused with the class of the cap, and with the default
restored it is still refused, with another class.

This split is an artifact of FerroCrypt's own module boundaries. An outside
implementation has no such constraint: `origins.tsv` names the payload key file
and the base nonce, and `cases.tsv` names the input and the expected ciphertext.

## Diagnostic classes that are narrower than they sound

Two classes in the §12.1 registry describe conditions a file-backed reader
almost never reaches. Cases here are recorded against what actually happens, not
against the class whose name reads closest.

**Appended bytes are `payload_authentication_failed`, not
`extra_data_after_payload`.** A reader fills a whole chunk before decrypting, so
appended bytes either extend the final frame or turn it into a non-final one;
either way the AEAD refuses first. `extra_data_after_payload` is reserved for an
inner reader that signals end of file and then produces more bytes, which no
file-backed reader does.

**A cut payload is `payload_authentication_failed` unless the payload region is
empty.** Only a stream carrying no chunk at all reaches `payload_truncated`; a
cut that leaves any byte behind leaves a frame that fails authentication, and a
reader cannot tell that from a tampered tail. `payload-region-empty` and
`payload-cut-at-chunk-boundary` pin both sides of that boundary.

## Coverage of revision 1

Every item the §12.3 minimum-evidence table names is present. The table itself
excludes the payload chunk-count ceiling: a genuine 2^32-chunk artifact is
about 256 TiB, and the known-answer schema cannot stand in for it, because
`origins.tsv` has no field for a starting counter, so no row can say "this
transcript begins at counter 2^32 - 1". Evidencing it would need a schema
change.

Every local cap is evidenced from both sides: an artifact one unit past it is
refused and one sitting exactly on it is accepted. Under the default profile
many of these halves cannot exist. An artifact sitting on a default cap would
often be too large to commit or too costly to replay, no supported key reaches
the default key-file caps, and no common host can extract an archive path as
long as the default path cap allows. Some caps never refuse anything under the
defaults: the total entry-extension and TLV value caps sit behind the
manifest-length and per-region caps, the Argon2id time-cost and lane caps equal
their structural maxima, and the header-MAC work cap equals the most work a
header within the recipient-count and header-length caps can demand. Those
halves are evidenced under profiles that lower the caps instead:
`small-artifact-caps` sets every cap to exactly what the one-byte passphrase
file and the key pair of the corpus need, and each `lowered-*` profile lowers
one cap.

Where a default cap would refuse an artifact before it reaches a structural
limit, the case runs under a profile that raises that cap to its structural
maximum: `header-structural-maxima` for the header length, recipient count,
and recipient body length, and `recipient-string-structural-maximum` for the
recipient string, whose key-material cases include the longest well-formed
string of 19,999 characters. Such a profile evidences the structural limit,
not the cap it raises.

The `.fcr` and key-file cases also fix the whole check order of §3.1 to §3.3, of
§3.7 before any recipient is tried, and of §7.1, §7, and §8. A case that breaks
two checks, and none before them, fixes the order of the two, and such cases
chain: one check before a second and the second before a third put the first
before the third. A case that also breaks a later check of the class it expects
fixes the order only together with the cases that put that later check after the
others. A reader may meet the entries of a §3.7 step in either order, so where
two such checks break on different recipient entries, a case fixes their order
only together with a case in the other entry order; the §3.3 checks meet the
entries in declared order, as a reader finds each entry only by reading the one
before it. A reader may also apply the mixing rules and the header-MAC work cap
to the entries it has met so far instead of once to the whole list. Under
`lowered-header-mac-work-cap`, `walk-order-mixed-entries` holds five `argon2id`
entries, whose first two already break both, and so do its last two. Each other
`walk-order-` case damages its middle entry so that it breaks a check of §3.3 or
of §3.7 steps 6 to 8, or adds a defect that §3.3 finds past its last entry, so a
reader walking the entries either way meets the mixing rules and the cap first
and must still report the defect's check. A body over the default cap reports
the class of the work cap, so `walk-order-body-cap-before-mixing` runs under the
default caps, where it breaks the mixing rules alone. Together the cases fix the
order of every two checks that report different classes, that one file can break
together, and whose order can decide a report (`FORMAT.md` §12.3), with a step
whose outcomes differ in class, such as the version, counted as one check per
class. FerroCrypt's own tests check this claim against the committed corpus. For
the `.fcr` checks they also check it for a reader that, before the check that
guards the end it passes, reads `header_fixed` past the declared header, takes
the recipient-entry region from any length the header declares or from the
declared header alone, or reads an entry past that region. For the key files
they check it through each `private.key` reader, and also for a reader that
decodes a recipient string §7 step 4 refuses, takes the internal checksum from
the end of the payload with the key material it declares or with every byte
before that checksum, reads no further than one byte past the longest valid
file, past the lengths a `private.key` header declares, or past a fixed header
that breaks a check of §8 steps 0 to 7, or of steps 0 to 9, takes every byte
after `ext_bytes` as the wrapped secret, or judges the support of a type name
that breaks the grammar. Only a pair with a check that a capability changes
rests on a capability-relative case, so a reader that declares capabilities, one
or several, loses only such pairs. The unknown recipient type and the extension
tags the order cases use are test values (`FORMAT.md` §3.3.1, §6), which no
reader implements, so the only capabilities that touch the order cases are newer
stored versions. The header-MAC work cap follows every check of `FORMAT.md` §3.7
steps 1 to 9 and comes before the private-key unlock and before any recipient is
tried. `header-mac-work-order-mixing-before-cap` puts it after the mixing rules
with an `argon2id` entry between two `x25519` entries, either of which alone
crosses the cap, and so, through the order the step-8 cases already fix, after
every recipient check. `header-mac-work-order-cap-before-passphrase-unwrap`,
`header-mac-work-order-cap-before-private-key-unlock`,
`header-mac-work-order-cap-before-x25519-shared-secret`,
`header-mac-work-order-cap-before-x25519-unwrap`, and
`header-mac-work-order-cap-before-header-mac` put it before the unlock and every
check made while a recipient is tried: a wrong passphrase, a wrong private-key
passphrase, a key agreement that yields the all-zero shared secret, a private
key that opens no entry, and a modified header MAC. Their `x25519` file holds
two entries that cross the cap only together, and a wrong private-key
passphrase, or an ephemeral key in each entry that yields the all-zero shared
secret, fails on whichever entry a reader tries first, so a reader that applies
the cap to the entries as it tries them, in any order, must report the cap too.
Two `.fcr` rules order entries rather than checks, so each has its own cases.
§3.3 takes each entry through every check before it reads the next:
`entry-order-whole-entry-before-next-entry` has a malformed first type name and
a second entry the region holds no bytes for. §3.7 finishes each step over every
entry before the next step begins: the
`recipient-order-unknown-critical-before-native-` cases put an unknown critical
entry before and after an `x25519` entry one byte short, and before and after
one with its critical flag set. Every `private-key-order-` case also runs
through the unlock, as a `private-key-open-order-` case, because the unlock
makes both of its checks too; a `private-key-open-order-` case with no such twin
orders steps validation skips. Only a string too short to hold a payload's fixed
fields can break the recipient-string cap and the payload size together, so that
case runs under `zero-recipient-string-cap`, which sets the cap to zero.

The length fields of both key files and of a recipient entry also have cases on
their lower bounds, the type-name length through `t`, the shortest name the §3.3
grammar allows. The file length, the type name, the key type, the lengths §8
fixes for an `x25519` key (each one byte short and one byte long), and a
`public.key` handed to the reader have cases through both `private.key` readers,
structural validation and the unlock, because an implementation's unlock need
not share validation's code. The `public.key` cases include the two classes §7.1
gives a file that is not a recipient string at all, and text over the cap with a
space in it, which the cap refuses before any Bech32 rule sees the space. An
encrypted file and a `private.key` of a newer version, also given to the
`public.key` reader, show that the `private.key` signature is the magic with
the kind byte, whatever the version byte says.

The §8 check for a `public.key` reads the first four bytes only, and its cases
go through both `private.key` readers: a key of a newer version, one with a
damaged checksum, the `fcr1` prefix alone, which is shorter than the fixed
header, and the prefix followed by bytes that are not UTF-8 are all
`wrong_key_file_type`, while a key with a leading space does not open with the
prefix and is `not_a_key_file`. A key longer than the default recipient-string
cap is `wrong_key_file_type` through the unlock under the default profile,
because the check applies no cap.

Two areas are covered in a shape worth stating: a directory root's expected
result is the extraction listing §12.3 defines rather than a single plaintext
file, and stored permission modes are evidenced by rejection cases only,
because §9.13 makes Unix permission restoration best-effort on Windows.
