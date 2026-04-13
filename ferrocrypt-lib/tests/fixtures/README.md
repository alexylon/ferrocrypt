# Fixture layout

This directory contains committed binary fixtures for the format regression
tests in `tests/compatibility_tests.rs`. Every CI run decrypts them and
compares against known plaintext, catching unintended byte-level changes to
the on-disk format.

## Version buckets

- `v3/symmetric/`
  - symmetric encrypted-file fixtures for symmetric `v3.0`
- `v4/hybrid/`
  - hybrid encrypted-file fixtures for hybrid `v4.0`
  - uses X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305 envelope
  - key files in this directory are written as key-file format `v3`

Directory names reflect the on-disk major version number of the files inside,
not the crate or release version.

## Current status: pre-release format fixtures

The symmetric `v3.0` / hybrid `v4.0` format family described here is a
breaking change on the current branch and has **not yet shipped in any
published crate release** — `CHANGELOG.md` still has it under `[Unreleased]`.
These fixtures represent the current branch's definition of v3.0 / v4.0,
not files that any user of a released version of FerroCrypt has on disk.
They exist to catch accidental format drift during pre-release development
of the new format family.

A format-affecting change on this branch may therefore deliberately
regenerate these fixtures, as part of a reviewed PR that also updates
`FORMAT.md` and `CHANGELOG.md [Unreleased]`. Regeneration uses the
`#[ignore]`-gated `generate_*_fixtures` tests.

## After the first release that ships this format family

Once a crate release (expected `0.3.0`) ships the v3/v4 format family, the
then-current fixtures become **historical compatibility fixtures** — they
will represent bytes real users have on disk. From that point on:

- Do not regenerate or replace committed fixtures. Any change is a
  wire-format break.
- Any intentional format change must bump the major version number, add a
  new version bucket alongside the existing one, and keep the old fixtures
  and the old reader path intact for backward compatibility.
- Document every such change in `CHANGELOG.md` and `FORMAT.md`.
