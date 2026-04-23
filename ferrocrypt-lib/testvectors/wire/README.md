# `testvectors/wire/` — frozen v1 wire-format fixtures

**Status:** frozen on the v1 release. **Do not regenerate** these fixtures
in a patch or minor release — they are the on-disk contract that
independent implementers build against.

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

Until that tool ships, this directory documents the intended layout;
individual fixtures are added in subsequent commits as generation is
implemented.
