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

## Current status: pre-release regression fixtures

FerroCrypt has not yet cut a stable release. These fixtures represent the
**current branch's** definition of v3.0 / v4.0, not files that any external
user has on disk. They exist to catch accidental format drift during
pre-release development.

A format-affecting change on the pre-release branch may therefore deliberately
regenerate these fixtures, as part of a reviewed PR that also updates
`FORMAT.md` and `CHANGELOG.md [Unreleased]`. Regeneration uses the
`#[ignore]`-gated `generate_*_fixtures` tests.

## After the first stable release

At the first stable release, the then-current fixtures become **historical
compatibility fixtures** — they will represent bytes real users have on disk.
From that point on:

- Do not regenerate or replace committed fixtures. Any change is a
  wire-format break.
- Any intentional format change must bump the major version number, add a
  new version bucket alongside the existing one, and keep the old fixtures
  and the old reader path intact for backward compatibility.
- Document every such change in `CHANGELOG.md` and `FORMAT.md`.
