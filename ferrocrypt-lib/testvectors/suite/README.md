# `testvectors/suite/` — edge-case corpus (versioned)

**Status:** pre-1.0, currently empty. The cases listed below are the
edge-case corpus required by `FORMAT.md` §12 and must be populated as
binary fixtures before the 1.0 release.

Unlike `testvectors/wire/`, fixtures here **may** be added, corrected,
or extended in any patch release. The `SUITE-VERSION` file tracks the
corpus version so readers can pin to a specific revision.

Like `testvectors/wire/`, this directory serves independent reader
implementations — a different role from `tests/fixtures/`, which is an
internal regeneratable regression net for this codebase.

## Required coverage (FORMAT.md §12)

- Corrupted replicated prefix: single-byte flip and no-majority case
- TLV: malformed ordering, duplicate tag, `len`-past-end
- TLV: unknown ignorable tag (must decrypt OK) and unknown critical
  tag (must reject)
- Out-of-range KDF parameters (mem_cost > 2 GiB; lanes = 0; time = 13)
- Truncated payload (cut mid-final-chunk)
- Trailing data after valid final payload chunk
- Wrong-passphrase `.fcr` → `SymmetricEnvelopeUnlockFailed`
- Wrong-recipient `.fcr` (encrypt to A, decrypt with B)
- Header MAC failure after successful unwrap (flip a byte in
  `stream_nonce` post-HMAC)
- Mixed-case `fcr1…`; `fcr1…` with tampered checksum

Most of this coverage currently lives in the in-tree unit tests
(`src/symmetric.rs::tests`, `src/hybrid.rs::tests`, `src/format.rs::tests`,
`src/common.rs::tests`). Committing the same cases as binary fixtures
is a regression gate for independent reader implementations.
