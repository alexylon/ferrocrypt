# `testvectors/wire/` — frozen conformance corpus

**Status:** currently empty. The corpus is populated and published with
stable FerroCrypt release 0.3.0. `FORMAT.md` §12.3 defines its identity,
directory layout, manifest schema, provenance rules, and freeze policy.

## Purpose vs `tests/fixtures/`

This directory is the public, cross-language conformance contract. An
independent implementer — someone writing a reader in another language
or a separate Rust crate with no access to this codebase — should be
able to fetch it and prove their implementation spec-compliant by
replaying every case and comparing against the committed expectations.

This is a different role from `tests/fixtures/`. That directory is an
internal regression net for *this* codebase that the team regenerates
when the wire format intentionally changes. `testvectors/wire/` is a
one-way commitment to the outside world: once the stable release tag
ships, committed rows and bytes are append-only and immutable;
corrections use the errata mechanism from `FORMAT.md` §12.3.

When the corpus lands, this README is replaced by the full document
required by `FORMAT.md` §12.3, including the authoritative generation
and reproduction commands.

## Note for whoever authors the corpus

`FORMAT.md` §12.3 requires payload-stream evidence covering trailing
data. Record those cases as `payload_authentication_failed`, with a
`condition_id` naming the appended-bytes condition — not as
`extra_data_after_payload`.

Appending bytes to a valid `.fcr` never reaches the
`extra_data_after_payload` class in FerroCrypt. The reader fills a full
chunk before decrypting, so appended bytes either extend the final
frame or turn it into a non-final one; either way the AEAD rejects
first. `extra_data_after_payload` is reserved for an inner reader that
signals end of file and then produces more bytes, which no file-backed
reader does. A case recorded under the wrong class would fail replay
against this implementation, and the corpus is immutable once the
stable release is tagged.
