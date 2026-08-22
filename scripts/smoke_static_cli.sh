#!/bin/sh
# Exercises a CLI binary end to end on the machine it is handed to.
#
# The static Linux builds exist so that one file runs on a machine with no
# matching C library installed. The release workflow therefore runs this
# inside an Alpine container, where the only C library present is musl and
# no build tooling exists at all. That is why this is POSIX sh rather than
# bash: Alpine ships busybox.
#
# The script covers both recipient kinds — a passphrase round trip over a
# small directory tree and a public-key round trip over a single file —
# because they reach different code: only the passphrase path derives a key
# from a passphrase, and only the directory path builds and extracts an
# archive.
#
# Usage: ./scripts/smoke_static_cli.sh /path/to/ferrocrypt

set -eu

binary="${1:-}"
if [ -z "$binary" ]; then
    echo "usage: $0 <ferrocrypt-binary>" >&2
    exit 2
fi
if [ ! -x "$binary" ]; then
    echo "Not an executable file: $binary" >&2
    exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The CLI never takes a passphrase on the command line; this is the
# documented way to supply one without a terminal.
FERROCRYPT_PASSPHRASE='smoke test passphrase'
export FERROCRYPT_PASSPHRASE

echo "== version =="
"$binary" --version

echo "== building the source tree =="
mkdir -p "$work/source/nested"
printf 'ferrocrypt static binary smoke test\n' > "$work/source/greeting.txt"
# Larger than three payload chunks, so the round trip covers the streaming
# path rather than a single-chunk special case.
head -c 200000 /dev/urandom > "$work/source/nested/random.bin"

echo "== passphrase round trip (directory) =="
"$binary" encrypt --passphrase --input "$work/source" --save-as "$work/passphrase.fcr"
mkdir -p "$work/from-passphrase"
"$binary" decrypt --input "$work/passphrase.fcr" --output-dir "$work/from-passphrase"
diff -r "$work/source" "$work/from-passphrase/source"

echo "== public-key round trip (single file) =="
mkdir -p "$work/keys"
"$binary" keygen --output-dir "$work/keys"
"$binary" fingerprint "$work/keys/public.key" > /dev/null
"$binary" encrypt \
    --input "$work/source/greeting.txt" \
    --save-as "$work/recipient.fcr" \
    --public-key "$work/keys/public.key"
mkdir -p "$work/from-recipient"
"$binary" decrypt \
    --input "$work/recipient.fcr" \
    --output-dir "$work/from-recipient" \
    --private-key "$work/keys/private.key"
diff "$work/source/greeting.txt" "$work/from-recipient/greeting.txt"

echo "== a wrong passphrase is refused =="
mkdir -p "$work/refused"
if FERROCRYPT_PASSPHRASE='not the passphrase' \
    "$binary" decrypt --input "$work/passphrase.fcr" --output-dir "$work/refused"
then
    echo "Decryption with a wrong passphrase succeeded." >&2
    exit 1
fi
if [ -n "$(ls -A "$work/refused")" ]; then
    echo "A refused decryption left output behind:" >&2
    ls -lA "$work/refused" >&2
    exit 1
fi

echo "OK: $binary passed the smoke test."
