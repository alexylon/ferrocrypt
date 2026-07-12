# `tests/fixtures/frozen/` — cross-version backward-read net

Each `v<version>/` subdirectory holds encrypted `.fcr` artefacts, the key
pair that opens them, and their expected plaintext, captured from a specific
released version and **never regenerated**.

Unlike `tests/fixtures/` (which `regenerate_fixtures` rewrites with fresh
random bytes on demand), these bytes are frozen at the version they were
captured from. `tests/frozen_fixture_compat.rs` decrypts each one with the
current reader and asserts it still reproduces the original plaintext, so a
future change that stops reading bytes an older release wrote fails the test.
This is the "never strand a recipient" guarantee, enforced across versions.

## Freezing a new version

At release time, after `regenerate_fixtures` has produced the current
`encrypted/`, `keys/`, and `source/`:

```bash
cp -R tests/fixtures/encrypted tests/fixtures/keys tests/fixtures/source \
    tests/fixtures/frozen/v<version>/
```

Then add `"v<version>"` to `FROZEN_VERSIONS` in
`tests/frozen_fixture_compat.rs` and commit. Never edit or delete an existing
frozen corpus — that would defeat the guarantee. All frozen fixtures use the
passphrase `fixture-passphrase-not-secret-do-not-reuse` (not a secret).
