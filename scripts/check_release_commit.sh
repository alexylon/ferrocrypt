#!/usr/bin/env bash
# The check the release workflow makes before it publishes to crates.io and
# again before it creates the GitHub release: the tag must still name the
# commit the run built, and that commit must be on main. A re-run of an older
# run, after the tag was moved to a fix, must not publish or release the
# commit the tag named before; and releases come from main only. Both the tag
# and main are read from GitHub at the time of the check.
#
# Usage: scripts/check_release_commit.sh <tag> <commit>
set -euo pipefail

tag="$1"
commit="$2"

# ls-remote also lists refs that merely end in the pattern, such as
# refs/tags/x/refs/tags/<tag>, so only the exact names count. An annotated
# tag's commit is on its `^{}` line, which follows the tag's own line; a
# lightweight tag has only its own line.
tagged="$(git ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}" \
    | awk -v ref="refs/tags/$tag" '$2 == ref || $2 == ref "^{}" { last = $1 } END { print last }')"
if [[ "$tagged" != "$commit" ]]; then
    echo "::error::$tag names ${tagged:-no commit} now, not $commit. Use the run the latest push of the tag started."
    exit 1
fi

git fetch --quiet --no-tags origin main
if ! git merge-base --is-ancestor "$commit" origin/main; then
    echo "::error::$commit is not on main, and only a commit on main is released."
    exit 1
fi
