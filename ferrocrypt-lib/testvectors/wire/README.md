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
not support that capability (`FORMAT.md` §12.2).

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
the corpus need, and each `lowered-*` profile lowers one cap.
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
case with the class a reader reports for that cap.

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

Two areas are covered in a shape worth stating: a directory root's expected
result is the extraction listing §12.3 defines rather than a single plaintext
file, and stored permission modes are evidenced by rejection cases only,
because §9.13 makes Unix permission restoration best-effort on Windows.
