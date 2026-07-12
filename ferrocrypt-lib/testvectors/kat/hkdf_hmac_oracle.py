#!/usr/bin/env python3
"""Independent known-answer oracle for FerroCrypt's HKDF/HMAC wiring.

This script recomputes the key-derivation and header-MAC intermediate
values that FerroCrypt's Rust code produces, using ONLY the Python
standard library (``hashlib.sha3_256`` + ``hmac``). That is a different
implementation lineage from the Rust build (RustCrypto's ``sha3`` /
``hmac`` / ``hkdf`` crates), so when the Rust unit tests assert these
exact bytes and pass, the agreement proves FerroCrypt wires the
primitives the way ``FORMAT.md`` specifies — it is not two copies of the
same code agreeing with each other.

Why this exists: every committed ``.fcr`` / key fixture in the repository
is produced by FerroCrypt's own writer, which shares ``crypto/`` with the
reader under test. A symmetric day-one mistake — swapped HKDF ``info``
strings, a swapped salt/ikm argument, an HMAC input missing the prefix —
would round-trip cleanly and pass every fixture, surfacing only when an
independent implementation tried to conform. These primitive-level KATs
close that gap for the derivation and header-MAC wiring.

The printed values are asserted byte-for-byte by:
  - crypto/hkdf.rs :: hkdf_expand_sha3_256_matches_independent_oracle
  - crypto/keys.rs :: derive_subkeys_matches_independent_oracle
  - crypto/mac.rs  :: hmac_sha3_256_parts_matches_independent_oracle

Run ``python3 hkdf_hmac_oracle.py`` to regenerate; if the printed bytes
ever change, either an input constant here drifted from the Rust test or
FerroCrypt's derivation changed (a wire-breaking event).

References: RFC 5869 (HKDF), FIPS 198-1 (HMAC), FIPS 202 (SHA-3),
FORMAT.md sections 2.3, 3.6, and 5.
"""

import hashlib
import hmac

HASHLEN = 32  # SHA3-256 output length in bytes.


def hmac_sha3_256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha3_256).digest()


def hkdf_sha3_256(salt, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF (Extract-then-Expand) over HMAC-SHA3-256.

    ``salt=None`` uses HashLen zero bytes as the extract salt, matching
    FORMAT.md 2.3 ("HKDF-Extract uses no application salt, equivalent to
    the RFC 5869 default salt of HashLen zero bytes") and the ``hkdf``
    crate's ``Hkdf::new(None, ikm)`` behaviour.
    """
    if length > 255 * HASHLEN:
        # RFC 5869 caps Expand output at 255 HashLen-sized blocks; past that
        # the block counter would exceed a single byte.
        raise ValueError("length must be at most 255*HashLen per RFC 5869")
    if salt is None:
        salt = b"\x00" * HASHLEN
    prk = hmac_sha3_256(salt, ikm)  # Extract.
    okm = b""
    block = b""
    counter = 0
    while len(okm) < length:  # Expand.
        counter += 1
        block = hmac_sha3_256(prk, block + info + bytes([counter]))
        okm += block
    return okm[:length]


def rust_array(b: bytes) -> str:
    return "[" + ", ".join("0x%02x" % x for x in b) + "]"


def main() -> None:
    # 1. Raw HKDF-SHA3-256 expand (crypto/hkdf.rs).
    #    salt = [0x22; 16], ikm = [0x11; 32], info = "ferrocrypt/v1/test".
    print("HKDF_RAW =", rust_array(
        hkdf_sha3_256(b"\x22" * 16, b"\x11" * 32, b"ferrocrypt/v1/test")))

    # 2. derive_subkeys (crypto/keys.rs).
    #    file_key = [0x11; 32], stream_nonce = [0x22; 19].
    file_key = b"\x11" * 32
    stream_nonce = b"\x22" * 19
    print("PAYLOAD  =", rust_array(
        hkdf_sha3_256(stream_nonce, file_key, b"ferrocrypt/v1/payload")))
    print("HEADER   =", rust_array(
        hkdf_sha3_256(None, file_key, b"ferrocrypt/v1/header")))

    # 3. HMAC-SHA3-256 over parts fed in order (crypto/mac.rs).
    #    key = [0x0b; 32], parts = ["ferrocrypt-prefix",
    #    "ferrocrypt-header-bytes"] — MAC of the concatenation.
    key = b"\x0b" * 32
    parts = b"ferrocrypt-prefix" + b"ferrocrypt-header-bytes"
    print("HMAC     =", rust_array(hmac_sha3_256(key, parts)))


if __name__ == "__main__":
    main()
