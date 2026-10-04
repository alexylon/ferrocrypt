#!/usr/bin/env bash
# The pre-release hook set in ferrocrypt-lib/release.toml. cargo-release runs it
# once per release, after it has set the new versions and before its commit, and
# a failure stops the release before anything is committed, tagged, or pushed.
#
# 1. Records the new versions in the lock files of the desktop app and the fuzz
#    targets, which are outside the workspace, the way cargo-release records
#    them in the workspace's. Fails if any of the three lock files then records
#    other dependency versions than the last commit: no test or review has seen
#    them.
# 2. Runs the workspace tests with the skip list of the `build` job in
#    .github/workflows/rust.yml, whose comment names every copy of that list.
#    `--locked` refuses a Cargo.lock that does not match the new versions.
# 3. Runs the >4 GiB round trip, which CI runs only for a tag, in the
#    `large-file` job of .github/workflows/release.yml. Here it fails before a
#    tag exists. It needs about 8 GiB of free disk.
# 4. Fails if the tests changed a tracked file: the release commit takes every
#    tracked file as this script leaves it.
#
# A dry run of cargo-release does none of this. Run on its own, the script does
# all of it.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "${DRY_RUN:-false}" == true ]]; then
    echo "Dry run: the lock files and the tests are left to the real release."
    exit 0
fi

for manifest in ferrocrypt-desktop/Cargo.toml ferrocrypt-lib/fuzz/Cargo.toml; do
    cargo metadata --format-version 1 --manifest-path "$manifest" > /dev/null
done

# The registry and git packages a lock file records, one per line. This
# repository's own packages have no source, so their versions are left out.
# Fields are read only inside `[[package]]` tables.
locked_sources() {
    awk '/^\[/ {
             if (in_package && source != "") print name, version, source
             in_package = ($0 == "[[package]]"); name = version = source = ""
         }
         in_package && /^name = /    { name = $3 }
         in_package && /^version = / { version = $3 }
         in_package && /^source = /  { source = $3 }
         END { if (in_package && source != "") print name, version, source }' | sort
}
for lock in Cargo.lock ferrocrypt-desktop/Cargo.lock ferrocrypt-lib/fuzz/Cargo.lock; do
    if [[ "$(git show "HEAD:$lock" | locked_sources)" != "$(locked_sources < "$lock")" ]]; then
        echo "error: $lock records other dependency versions than the last commit; bring it up to date in a commit of its own first." >&2
        exit 1
    fi
done

tracked_changes() {
    git diff --binary --no-color --no-ext-diff --no-textconv HEAD
}
before="$(tracked_changes)"

cargo test --locked -- --test-threads=1 --include-ignored \
    --skip regenerate_fixtures --skip regenerate_suite_vectors \
    --skip regenerate_wire_corpus \
    --skip round_trip_file_larger_than_4gib

# The round trip must cross 4 GiB, whatever size the shell asks for.
unset FERROCRYPT_LARGE_FILE_BYTES
cargo test --locked --release -p ferrocrypt --test large_file -- \
    --ignored --test-threads=1

if [[ "$(tracked_changes)" != "$before" ]]; then
    echo "error: the tests changed a tracked file, which the release commit would include:" >&2
    git status --short >&2
    exit 1
fi
