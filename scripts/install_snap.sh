#!/usr/bin/env bash
# Installs a snap for the release workflow, and tries again when the install
# fails. The Snap Store sometimes refuses or drops connections for a few
# minutes, which would otherwise fail a snap build or upload before it starts.
#
# Usage: scripts/install_snap.sh <snap> [snap install options]
set -euo pipefail

ATTEMPTS=5
# The wait before each retry grows by this much: 1, 2, 3, then 4 minutes.
WAIT_STEP_SECONDS=60

if (( $# < 1 )); then
    echo "Usage: scripts/install_snap.sh <snap> [snap install options]" >&2
    exit 2
fi
snap="$1"
for attempt in $(seq "$ATTEMPTS"); do
    if sudo snap install "$@"; then
        exit 0
    fi
    if (( attempt < ATTEMPTS )); then
        wait_seconds=$(( attempt * WAIT_STEP_SECONDS ))
        echo "::warning::Installing $snap failed (attempt $attempt of $ATTEMPTS). Trying again in $wait_seconds seconds."
        sleep "$wait_seconds"
    fi
done
echo "::error::Installing $snap failed $ATTEMPTS times."
exit 1
