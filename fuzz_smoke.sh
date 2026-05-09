#!/usr/bin/env bash
# Smoke-run every fuzz target for 10s. Mirrors the CI `fuzz` job in
# .github/workflows/rust.yml.
set -euo pipefail

cd "$(dirname "$0")/ferrocrypt-lib/fuzz"

# Capture into a variable so `set -e` trips if `fuzz list` fails — command
# substitution in `for ... in $(...)` is not subject to fail-fast.
targets=$(cargo +nightly fuzz list)
if [[ -z "$targets" ]]; then
    echo "error: cargo fuzz list returned no targets" >&2
    exit 1
fi

for t in $targets; do
    echo "=== $t ==="
    cargo +nightly fuzz run "$t" -- -max_total_time=10
done
