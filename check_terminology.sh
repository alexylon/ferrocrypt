#!/usr/bin/env bash
# Rejects ambiguous bare version wording (v1, v2, v1.x, v1.0, "at 1.0")
# in live documentation and source comments. The canonical vocabulary is
# defined in ferrocrypt-lib/FORMAT.md §11: stored versions are named by
# their domain and hexadecimal byte, and software releases use dotted
# release numbers.
#
# Allowed token contexts are blanked out of each matched line before the
# line is tested again, so an allowed token never hides a bare one on
# the same line:
# - path-shaped `/v1/` text: the frozen cryptographic labels
#   `ferrocrypt/v1/...` and prose quoting them (FORMAT.md §11.3);
# - `fcr1` Bech32 text (the `1` is the Bech32 separator, not a version);
# - FORMAT.md's own sentences about "the substring `v1`" being frozen;
# - the byte-frozen suite fixture plaintext and the generated manifest
#   header line in `suite_vector_gen.rs`;
# - `photos.v1`, an example dotted directory name in `fs/paths.rs`.
#
# Not scanned: CHANGELOG.md (history), notes/ (local scratchpad),
# experiments/ (parked snapshots), and test-vector data files (only
# `.rs` and `.md` files are scanned). A scan error fails the check.

set -u

pattern='\bv1\b|\bv2\b|\bv1\.x\b|\bv1\.0\b|\bv0\.x\b|\bat 1\.0\b'

raw=$(grep -rnE "$pattern" \
    README.md SECURITY.md AGENTS.md CLAUDE.md RELEASE.md \
    ferrocrypt-lib/FORMAT.md ferrocrypt-lib/STRUCTURE.md \
    ferrocrypt-lib/src ferrocrypt-lib/tests ferrocrypt-lib/fuzz/fuzz_targets \
    ferrocrypt-lib/testvectors \
    ferrocrypt-cli/src ferrocrypt-cli/tests \
    ferrocrypt-desktop/src \
    --include='*.rs' --include='*.md')
status=$?
if [ "$status" -ge 2 ]; then
    echo "check_terminology.sh: scan failed (grep exit $status)" >&2
    exit 2
fi
if [ "$status" -eq 1 ]; then
    echo "Terminology check passed."
    exit 0
fi

hits=$(printf '%s\n' "$raw" | sed \
    -e 's|/v1/| |g' \
    -e 's|fcr1| |g' \
    -e 's|substring `v1`| |g' \
    -e 's|photos\.v1| |g' \
    -e 's|FerroCrypt v1 test-vector suite plaintext| |g' \
    -e 's|FerroCrypt v1 edge-case test-vector manifest| |g' \
    | grep -E "$pattern")
status=$?
if [ "$status" -ge 2 ]; then
    echo "check_terminology.sh: filter failed (grep exit $status)" >&2
    exit 2
fi
if [ "$status" -eq 0 ]; then
    echo "Ambiguous version wording found; use the FORMAT.md §11 vocabulary" >&2
    echo "(domain + hexadecimal byte, or a dotted release number):" >&2
    echo "$hits" >&2
    exit 1
fi

echo "Terminology check passed."
