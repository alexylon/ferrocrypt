# Wire-format stability fixtures

These artefacts pin FerroCrypt's decrypt behaviour to known bytes. The
`fixture_stability.rs` integration test decrypts each `.fcr` here and
asserts that the recovered plaintext matches the matching file under
`source/`. Failure means decrypt behaviour drifted — investigate before
merging.

The single per-step acceptance check from `notes/RESTRUCTURE_PLAN.md`
("Core invariant: pure refactor → Verifying the invariant at every
step") relies on these fixtures.

## Layout

```
tests/fixtures/
├── README.md                              ← this file
├── source/
│   ├── small_file.txt                    ← single small file
│   └── small_dir/                        ← directory tree
│       ├── alpha.txt
│       ├── beta.txt
│       └── nested/gamma.txt
├── keys/
│   ├── public.key                        ← test recipient public key
│   └── private.key                       ← test recipient private key
│                                            (encrypted with fixture passphrase)
└── encrypted/
    ├── small_file.passphrase.fcr        ← small_file.txt + passphrase
    ├── small_dir.passphrase.fcr         ← small_dir + passphrase
    ├── small_file.recipient.fcr         ← small_file.txt + recipient
    └── small_dir.recipient.fcr          ← small_dir + recipient
```

## Test passphrase

`fixture-passphrase-not-secret-do-not-reuse`

This passphrase, the test public key, and the test private key are
**fixture-only**. Do not reuse them for real data. Anyone with read access
to this repository can decrypt anything encrypted to this key pair.

## Regenerating the fixtures

Run only after a deliberate, reviewed wire-format change has merged. Pure
refactors must *never* require regeneration — the whole point of these
fixtures is to catch unintended format drift.

```bash
cargo test --package ferrocrypt --test fixture_stability \
    regenerate -- --ignored --test-threads=1
```

That deletes `encrypted/` and `keys/`, regenerates the test key pair, and
re-encrypts the source files. Commit the resulting files by hand.

## What "drift" looks like

If `cargo test --package ferrocrypt --test fixture_stability` fails, one
of the following happened:

1. **Decrypt path changed** — header parsing, recipient unwrap, payload
   stream, archive extraction, or atomic finalize behaves differently
   than when the fixture was generated.
2. **Source file content changed** — someone edited a `source/` file
   without regenerating the corresponding `.fcr`.
3. **Test logic changed** — the assertions in `fixture_stability.rs`
   compare paths or bytes that no longer match.

Cases 1 and 2 are the load-bearing ones. Case 1 is the regression
indicator the fixtures exist to catch. Case 2 is a maintenance error.
