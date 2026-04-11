# Fixture layout

This directory contains committed golden fixtures for compatibility tests.

## Version buckets

- `v3/symmetric/`
  - symmetric encrypted-file fixtures for the released symmetric `v3.0` format

- `v3/hybrid/`
  - legacy hybrid release-directory fixtures
  - the key files in this directory are **key-file format v2**
  - they remain under `v3/hybrid/` because that was the historical release bucket

- `v4/hybrid/`
  - hybrid encrypted-file fixtures for the current hybrid `v4.0` format
  - these use the new X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305 envelope
  - new key files written by the current code are **key-file format v3**

## Important compatibility notes

- Symmetric encrypted files remain on format `v3.0`.
- Hybrid encrypted files moved from `v3.0` to `v4.0`.
- Key-file formats `v2` and `v3` have the same byte layout.
- The current reader accepts both key-file versions `2` and `3`.

## Fixture discipline

- These fixtures are golden compatibility artifacts.
- Do not regenerate or replace committed fixtures casually.
- If fixtures must change, update the changelog and compatibility tests together.
