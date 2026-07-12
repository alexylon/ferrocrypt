# `testvectors/kat/` — primitive known-answer vectors

**Status:** active. These pin FerroCrypt's key-derivation and header-MAC
**wiring** against an independent reference.

## Why this exists

Every committed `.fcr` and key fixture in `testvectors/suite/` and
`tests/fixtures/` is produced by FerroCrypt's own writer, which shares
`crypto/`, `format.rs`, and `container.rs` with the reader that validates
it. That makes the round-trip and replay tests a closed loop: a symmetric
day-one mistake — swapped HKDF `info` strings, a swapped salt/ikm
argument, an HMAC input missing the prefix, wrong domain separation —
would encrypt and decrypt consistently and pass every fixture, only
failing when an independent implementation tried to interoperate.

`hkdf_hmac_oracle.py` recomputes the derivation and header-MAC
intermediate values using only the Python standard library
(`hashlib.sha3_256` + `hmac`) — a different implementation lineage from
the Rust build (RustCrypto's `sha3` / `hmac` / `hkdf` crates). The Rust
unit tests assert those exact bytes, so agreement is a genuine
cross-implementation check, not two copies of the same code agreeing.

## What it covers

| Oracle output | Rust test | FORMAT.md |
|---|---|---|
| `HKDF_RAW` | `crypto/hkdf.rs :: hkdf_expand_sha3_256_matches_independent_oracle` | §2.3 |
| `PAYLOAD` / `HEADER` | `crypto/keys.rs :: derive_subkeys_matches_independent_oracle` | §3.6, §5 |
| `HMAC` | `crypto/mac.rs :: hmac_sha3_256_parts_matches_independent_oracle` | §3.6 |

The X25519 shared-secret, XChaCha20-Poly1305, and Argon2id primitives are
supplied by separately known-answer-tested crates (`x25519-dalek`,
`chacha20poly1305`, `argon2`); the FerroCrypt-specific risk in those
paths is the HKDF wrap-key derivation, which shares the
`hkdf_expand_sha3_256` helper pinned here.

## Reproducing

```
python3 testvectors/kat/hkdf_hmac_oracle.py
```

If the printed bytes change, either an input constant in the script
drifted from its Rust test, or a FerroCrypt derivation changed — the
latter is a wire-breaking event requiring a format-version bump.
