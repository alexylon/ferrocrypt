# `testvectors/wire/` — frozen v1 wire-format fixtures

**Status:** pre-1.0, currently empty. At the 1.0 release tag, the
fixtures listed below MUST be populated (see `FORMAT.md` §12). Once
shipped, they are frozen forever — any change to their bytes is a
breaking change requiring a `version = 2` bump.

## Purpose vs `tests/fixtures/`

These are the public conformance contract for FerroCrypt v1. An
independent implementer — someone writing a reader in another language
or a separate Rust crate with no access to this codebase — should be
able to fetch this directory and prove their implementation is
spec-compliant by decrypting each fixture and comparing against the
expected plaintext.

This is a different role from `tests/fixtures/`. That directory is an
internal regression net for *this* codebase that the team regenerates
when the wire format intentionally changes. `testvectors/wire/` is a
one-way commitment to the outside world: once v1.0 ships, the bytes
never change.

## Intended contents

Each fixture is the raw bytes of a `.fcr` file or key file produced by
the v1 writer. Accompanying `.plaintext` files contain the expected
decryption result (where deterministic).

| Fixture | Purpose |
|---|---|
| `symmetric-empty.fcr` | Symmetric `.fcr` with 0-byte plaintext |
| `symmetric-1byte.fcr` | Symmetric `.fcr` with 1-byte plaintext |
| `symmetric-multichunk.fcr` | Symmetric `.fcr` spanning > 1 STREAM chunk |
| `hybrid-empty.fcr` | Hybrid `.fcr` with 0-byte plaintext |
| `hybrid-1byte.fcr` | Hybrid `.fcr` with 1-byte plaintext |
| `hybrid-multichunk.fcr` | Hybrid `.fcr` spanning > 1 STREAM chunk |
| `public.key` | Canonical v1 public key (text file, `fcr1…\n`) |
| `private.key` | Matching v1 private key (binary, passphrase `test`) |
| `passphrase.txt` | Passphrase used to wrap `private.key` and encrypt symmetric fixtures |

## Policy

- Fixtures are generated once and committed as binary files.
- The v1 library MUST decrypt every fixture in this directory.
- If a future change breaks any fixture, that change is breaking and
  requires a `version = 2` bump.
- Fixture generation uses real OS-CSPRNG, so envelope nonces, salts,
  and ephemeral keys are not reproducible — but the fixtures
  themselves remain bit-for-bit stable.

## Generation

Fixtures may be regenerated **only** during the initial v1 freeze. The
generation code should live in a `cargo run --bin generate-wire-vectors`
binary or similar so the procedure is explicit and reviewable. It is
not part of the library's public API.

Both the generator and the populated fixtures are 1.0-release
deliverables, not deferred follow-up work. Until they land, this
README documents the intended layout; individual fixtures land when
the generator does.
