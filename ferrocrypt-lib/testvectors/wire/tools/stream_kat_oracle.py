#!/usr/bin/env python3
"""Generates the payload STREAM known-answer vectors from libsodium, via PyNaCl.

`FORMAT.md` §12.3 requires the expected STREAM ciphertexts to come from an
implementation independent of FerroCrypt's own, because agreement between
FerroCrypt's writer and its reader is not transcript evidence: a shared
chunking or final-flag error would cancel out. This oracle is that
implementation. It imports no FerroCrypt code, reads nothing FerroCrypt wrote,
and derives every byte from the §5 rules alone.

It is a generation and reproduction tool, never a runtime dependency.
Continuous integration compares FerroCrypt's output against the committed
bytes and neither installs nor runs PyNaCl.

    pip install pynacl
    python3 tools/stream_kat_oracle.py            # rewrite kat/stream/
    python3 tools/stream_kat_oracle.py --check    # verify without writing

Provenance of the committed bytes, per §12.3:

    PyNaCl    1.6.2
    libsodium bundled in that PyNaCl wheel; PyNaCl 1.6.2 exposes no
              `sodium_version_string`, so the wheel version identifies the
              libsodium build.

`FORMAT.md` §5 defines the transcript this reproduces:

    chunk size  65,536 plaintext bytes
    AAD         empty
    full_nonce  stream_nonce(19) || counter:u32_be || final_flag:u8

A non-final chunk is exactly 65,536 plaintext bytes with `final_flag = 0x00`.
The final chunk carries `final_flag = 0x01` and may be shorter, but must not be
empty unless the whole plaintext is empty — so a plaintext that is an exact
multiple of the chunk size ends with a full-size final chunk, never an empty
trailer.
"""

import argparse
import struct
import sys
from pathlib import Path

try:
    import nacl
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt as seal
except ImportError:  # pragma: no cover - the tool is useless without it
    print("this oracle needs PyNaCl: pip install pynacl", file=sys.stderr)
    raise SystemExit(2)

CHUNK = 65_536
NONCE_PREFIX_LEN = 19

# Each case fixes its own payload key and nonce prefix, as section 12.3
# requires. The three cases section 12.3 names by identifier are the minimum;
# the other two extend the same rules to a short final chunk and to a
# multi-chunk transcript.
CASES = [
    # (case id, plaintext length, payload key byte, nonce prefix byte)
    ("stream-empty", 0, 0x40, 0x50),
    ("stream-one-byte", 1, 0x41, 0x51),
    ("stream-exact-65536", CHUNK, 0x42, 0x52),
    ("stream-two-chunk-65537", CHUNK + 1, 0x43, 0x53),
    ("stream-multi-chunk", CHUNK * 2 + 4321, 0x44, 0x54),
]


def plaintext_bytes(length):
    """Deterministic, byte-exact input; its committed bytes are authoritative."""
    return bytes((i * 31 + 7) % 256 for i in range(length))


def chunks(plaintext):
    """Splits plaintext into (bytes, counter, final_flag) per FORMAT.md section 5."""
    if not plaintext:
        yield b"", 0, 1
        return
    counter, offset = 0, 0
    while offset < len(plaintext):
        piece = plaintext[offset : offset + CHUNK]
        offset += len(piece)
        yield piece, counter, 1 if offset == len(plaintext) else 0
        counter += 1


def transcript(key, nonce_prefix, plaintext):
    out = bytearray()
    for piece, counter, final_flag in chunks(plaintext):
        full_nonce = nonce_prefix + struct.pack(">I", counter) + bytes([final_flag])
        out += seal(bytes(piece), b"", full_nonce, key)
    return bytes(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify without writing")
    parser.add_argument("corpus", nargs="?", help="corpus root (default: the one this tool lives in)")
    args = parser.parse_args()

    root = Path(args.corpus) if args.corpus else Path(__file__).resolve().parent.parent
    out_dir = root / "kat" / "stream"
    out_dir.mkdir(parents=True, exist_ok=True)

    seen_keys, seen_prefixes, seen_pairs = set(), set(), set()
    mismatches = 0
    for case_id, length, key_byte, prefix_byte in CASES:
        key = bytes([key_byte]) * 32
        nonce_prefix = bytes([prefix_byte]) * NONCE_PREFIX_LEN
        plaintext = plaintext_bytes(length)

        # Section 12.3 forbids duplicate KAT keys, duplicate nonce prefixes, and
        # duplicate effective (payload_key, full_nonce) pairs.
        assert key not in seen_keys, f"{case_id}: duplicate payload key"
        assert nonce_prefix not in seen_prefixes, f"{case_id}: duplicate nonce prefix"
        seen_keys.add(key)
        seen_prefixes.add(nonce_prefix)
        for _, counter, final_flag in chunks(plaintext):
            pair = (key, nonce_prefix + struct.pack(">I", counter) + bytes([final_flag]))
            assert pair not in seen_pairs, f"{case_id}: duplicate (key, nonce) pair"
            seen_pairs.add(pair)

        ciphertext = transcript(key, nonce_prefix, plaintext)
        files = {
            f"{case_id}.input.bin": plaintext,
            f"{case_id}.payload-key.bin": key,
            f"{case_id}.ciphertext.bin": ciphertext,
        }
        for name, data in files.items():
            path = out_dir / name
            if args.check:
                if not path.is_file() or path.read_bytes() != data:
                    print(f"{name}: differs from the oracle", file=sys.stderr)
                    mismatches += 1
            else:
                path.write_bytes(data)
        print(f"{case_id:<24} plaintext={length:<7} ciphertext={len(ciphertext)}")

    print(f"PyNaCl {nacl.__version__}; {len(CASES)} STREAM known-answer cases")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
