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

- Corrupted prefix: single-byte flip in `magic`, `version`, `kind`,
  `prefix_flags`, or `header_len`
- TLV: malformed ordering, duplicate tag, `len`-past-end
- TLV: unknown ignorable tag (must decrypt OK) and unknown critical
  tag (must reject)
- Out-of-range KDF parameters (`mem_cost > 2 GiB`; `lanes = 0`;
  `time_cost = 13`)
- Truncated payload (cut mid-final-chunk) →
  `PayloadTruncated`
- Trailing data after the valid final payload chunk →
  `ExtraDataAfterPayload`
- Wrong-passphrase `argon2id` `.fcr` →
  `RecipientUnwrapFailed { type_name: "argon2id" }`
- Wrong-recipient `x25519` `.fcr` (encrypt to A, decrypt with B) →
  `NoSupportedRecipient`
- Header MAC failure after successful unwrap (flip a byte in
  `stream_nonce` post-MAC) → `HeaderTampered` (single-recipient file)
  or `HeaderMacFailedAfterUnwrap { type_name }` (multi-recipient file)
- Unknown critical recipient `type_name` →
  `UnknownCriticalRecipient { type_name }`
- Incompatible recipient mixing (`argon2id` plus any other entry) →
  `IncompatibleRecipients { type_name, policy }`
- Mixed-case `fcr1…`; `fcr1…` with tampered Bech32 or internal SHA3-256
  checksum

Most of this coverage currently lives in the in-tree unit tests under
`ferrocrypt-lib/src/` — notably `format.rs::tests`,
`container.rs::tests`, `protocol.rs::tests`,
`recipient/native/argon2id.rs::tests`,
`recipient/native/x25519.rs::tests`, `crypto/tlv.rs::tests`,
`crypto/kdf.rs::tests`, `key/private.rs::tests`, and
`key/public.rs::tests`. Committing the same cases as binary fixtures
is a regression gate for independent reader implementations.
