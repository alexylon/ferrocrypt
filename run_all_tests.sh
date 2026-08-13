#!/usr/bin/env bash
# Runs every FerroCrypt test suite locally, except stress_test.sh (long;
# run it separately). macOS and Linux; Windows uses run_all_tests.ps1.
#
# Lanes (each reported PASS / FAIL / SKIP, summary at the end):
#   1. workspace          — full workspace suite, CI build-job mirror
#                           (--include-ignored, generators skipped)
#   2. testvector-cycle   — committed corpus replayed, generator run,
#                           fresh output validated, committed corpus
#                           restored and re-validated
#   3. fixture-cycle      — run the fixture generator, validate its fresh
#                           output, restore the committed fixtures,
#                           re-validate
#   4. desktop            — ferrocrypt-desktop suite (own target dir)
#   5. release-cli        — release-profile CLI tests with full-strength
#                           Argon2id (1 GiB sequential; needs >= 4 GiB RAM)
#   6. fuzz-smoke         — ./fuzz_smoke.sh (needs nightly + cargo-fuzz)
#   7. fs-matrix lanes    — archive tests on non-default filesystems:
#                           macOS: case-sensitive APFS, exFAT, FAT32
#                                  (hdiutil images, no root needed)
#                           Linux: btrfs, exFAT (loop mounts; opt in with
#                                  FERROCRYPT_GAUNTLET_ROOT_LANES=1, uses sudo)
#   8. smb                — macOS loopback SMB share (opt in with
#                           FERROCRYPT_GAUNTLET_SMB=1; python3 + network
#                           access for "pip install impacket")
#   9. msrv               — lib on 1.87.0, CLI on 1.89.0 (skipped unless
#                           those toolchains are installed via rustup)
#
# Not covered here:
#   - stress_test.sh — excluded on purpose.
#   - NFS — needs interactive sudo for nfsd and mount. Manual recipe:
#       echo "<short-dir> -alldirs -mapall=$(id -u) localhost" | sudo tee -a /etc/exports
#       sudo nfsd restart && sudo nfsd checkexports
#       sudo mount -t nfs -o resvport,nolocks localhost:<short-dir> <mnt>
#       FERROCRYPT_FS_MATRIX_DIR=<mnt> cargo test -p ferrocrypt \
#           --test archive_fs_matrix -- --ignored --test-threads=1
#       then remove the exports line, "sudo nfsd stop", unmount.
#   - Static checks (fmt, clippy, rustdoc, cargo vet/audit) — see AGENTS.md;
#     CI runs them on every push.

set -u
cd "$(dirname "$0")"

# Keep in sync with the msrv / msrv-cli jobs in .github/workflows/rust.yml.
MSRV_LIB=1.87.0
MSRV_CLI=1.89.0

PASS=()
FAIL=()
SKIP=()

TEST_WORKSPACE_ROOTS=(
    ferrocrypt-lib/tests/workspace
    ferrocrypt-lib/tests/workspace_api
    ferrocrypt-lib/tests/workspace_config_symmetry
    ferrocrypt-lib/tests/workspace_fixture_stability
    ferrocrypt-lib/tests/workspace_testvector_suite
    ferrocrypt-lib/tests/workspace_concurrency
    ferrocrypt-lib/tests/workspace_memory_bounds
    ferrocrypt-lib/tests/workspace_roundtrip_randomized
    ferrocrypt-lib/tests/workspace_large_file
    ferrocrypt-cli/tests/cli_workspace
)

cleanup_stale_test_workspaces() {
    local root run_dir run_name run_pid
    for root in "${TEST_WORKSPACE_ROOTS[@]}"; do
        [ -d "$root" ] || continue
        for run_dir in "$root"/run-*; do
            [ -d "$run_dir" ] || continue
            run_name=${run_dir##*/}
            run_pid=${run_name#run-}
            case "$run_pid" in
                ''|*[!0-9]*) continue ;;
            esac
            if kill -0 "$run_pid" 2>/dev/null ||
                ps -p "$run_pid" -o pid= 2>/dev/null | grep -q '[0-9]'; then
                continue
            fi
            rm -rf -- "$run_dir"
            if [ -e "$run_dir" ]; then
                printf 'warning: could not remove stale test workspace: %s\n' "$run_dir" >&2
            fi
        done
        rmdir "$root" 2>/dev/null || true
    done
}

note() { printf '\n=== %s\n' "$*"; }

record() { # record <lane> <status 0|nonzero>
    if [ "$2" -eq 0 ]; then PASS+=("$1"); else FAIL+=("$1"); fi
}

skip() { # skip <lane> <reason>
    note "$1 — SKIP: $2"
    SKIP+=("$1 ($2)")
}

ram_mib() {
    if [ "$(uname)" = Darwin ]; then
        echo $(($(sysctl -n hw.memsize) / 1048576))
    else
        awk '/MemTotal/{print int($2/1024)}' /proc/meminfo
    fi
}

fs_matrix_run() { # fs_matrix_run <mounted-dir>
    FERROCRYPT_FS_MATRIX_DIR="$1" cargo test -p ferrocrypt \
        --test archive_fs_matrix -- --ignored --test-threads=1
}

# Remove abandoned per-process directories from interrupted earlier runs.
# A directory whose PID still exists is never touched. The EXIT trap also
# catches directories left behind when a test destructor cannot delete them.
cleanup_stale_test_workspaces
trap cleanup_stale_test_workspaces EXIT

# ── 1. workspace ─────────────────────────────────────────────────────
# The regeneration lanes below restore committed state afterwards, so
# refuse them when those paths are dirty before we start — a restore
# would silently discard local edits.
TESTVECTORS_DIRTY=$(git status --porcelain ferrocrypt-lib/testvectors | wc -l | tr -d ' ')
FIXTURES_DIRTY=$(git status --porcelain ferrocrypt-lib/tests/fixtures | wc -l | tr -d ' ')

note "workspace"
cargo test -- --test-threads=1 --include-ignored \
    --skip regenerate_fixtures --skip regenerate_suite_vectors \
    --skip round_trip_file_larger_than_4gib
record workspace $?

# ── 2. test-vector corpus: replay committed, then a generator cycle ──
# First replay the committed corpus (the release-relevant check), then
# run the generator, replay its fresh output, and restore the
# committed files.
if [ "$TESTVECTORS_DIRTY" -eq 0 ]; then
    note "testvector-cycle"
    cargo test -p ferrocrypt --test testvector_suite -- --test-threads=1 &&
        cargo test -p ferrocrypt --lib -- --ignored --exact suite_vector_gen::regenerate_suite_vectors --test-threads=1 &&
        cargo test -p ferrocrypt --test testvector_suite -- --test-threads=1 &&
        git restore ferrocrypt-lib/testvectors &&
        cargo test -p ferrocrypt --test testvector_suite -- --test-threads=1
    record testvector-cycle $?
else
    skip testvector-cycle "ferrocrypt-lib/testvectors has local changes; not restoring over them"
fi

# ── 3. fixture regeneration cycle ────────────────────────────────────
if [ "$FIXTURES_DIRTY" -eq 0 ]; then
    note "fixture-cycle"
    cargo test -p ferrocrypt --test fixture_stability -- --ignored --exact regenerate_fixtures --test-threads=1 &&
        cargo test -p ferrocrypt --test fixture_stability -- --test-threads=1 &&
        git restore ferrocrypt-lib/tests/fixtures &&
        cargo test -p ferrocrypt --test fixture_stability -- --test-threads=1
    record fixture-cycle $?
else
    skip fixture-cycle "ferrocrypt-lib/tests/fixtures has local changes; not restoring over them"
fi

# ── 4. desktop ───────────────────────────────────────────────────────
note "desktop"
(cd ferrocrypt-desktop && cargo test -- --test-threads=1)
record desktop $?

# ── 5. release-profile CLI, full-strength Argon2id ───────────────────
if [ "$(ram_mib)" -ge 4096 ]; then
    note "release-cli"
    cargo test --release --package ferrocrypt-cli --test cli_tests -- --ignored --test-threads=1
    record release-cli $?
else
    skip release-cli "less than 4 GiB RAM for sequential 1 GiB Argon2id runs"
fi

# ── large-file: >4 GiB round trip (opt in) ───────────────────────────
# Excluded from lane 1 because it streams >4 GiB through real I/O to catch a
# u32 truncation in the size/progress accounting. Opt in explicitly; needs a
# few GiB of free disk. Release profile so the payload is not debug-slow.
if [ "${FERROCRYPT_GAUNTLET_LARGE_FILE:-0}" = 1 ]; then
    note "large-file"
    cargo test --release -p ferrocrypt --test large_file -- --ignored --test-threads=1
    record large-file $?
else
    skip large-file "opt in with FERROCRYPT_GAUNTLET_LARGE_FILE=1 (>4 GiB I/O, needs spare disk)"
fi

# ── 6. fuzz smoke ────────────────────────────────────────────────────
if rustup toolchain list 2>/dev/null | grep -q nightly && cargo fuzz --version >/dev/null 2>&1; then
    note "fuzz-smoke"
    ./fuzz_smoke.sh
    record fuzz-smoke $?
else
    skip fuzz-smoke "needs a nightly toolchain and cargo-fuzz"
fi

# ── 7. fs-matrix on non-default filesystems ──────────────────────────
if [ "$(uname)" = Darwin ]; then
    IMG_DIR=$(mktemp -d)
    # <lane name> <hdiutil -fs value> <volume name>
    # Volume names MUST stay at 11 characters or fewer: FAT-family
    # labels are capped there, and macOS silently drops a longer label
    # and mounts the volume at "/Volumes/NO NAME" instead. The mount
    # point is parsed from the attach output rather than assumed, so a
    # label surprise fails the lane loudly instead of testing the
    # wrong directory and leaving the image attached.
    while IFS='|' read -r lane fs vol; do
        note "fs-matrix-$lane"
        img="$IMG_DIR/$lane.dmg"
        mnt=""
        status=1
        if hdiutil create -size 200m -fs "$fs" -volname "$vol" "$img" -quiet; then
            mnt=$(hdiutil attach "$img" | sed -n 's|.*\(/Volumes/.*[^[:space:]]\)[[:space:]]*$|\1|p' | tail -1)
            if [ -n "$mnt" ]; then
                fs_matrix_run "$mnt"
                status=$?
            else
                echo "fs-matrix-$lane: could not determine the mount point"
            fi
        fi
        [ -n "$mnt" ] && hdiutil detach "$mnt" -quiet 2>/dev/null
        rm -f "$img"
        record "fs-matrix-$lane" $status
    done <<'LANES'
apfs-cs|Case-sensitive APFS|FCRTESTCS
exfat|ExFAT|FCRTESTEXF
fat32|MS-DOS FAT32|FCRTESTF32
LANES
    rmdir "$IMG_DIR" 2>/dev/null
elif [ "${FERROCRYPT_GAUNTLET_ROOT_LANES:-0}" = 1 ]; then
    # Mirrors the linux-btrfs / linux-exfat CI lanes; needs sudo.
    for lane in btrfs exfat; do
        mkfs="mkfs.$lane"
        if ! command -v "$mkfs" >/dev/null 2>&1; then
            skip "fs-matrix-$lane" "$mkfs not installed"
            continue
        fi
        note "fs-matrix-$lane"
        img=$(mktemp /tmp/fcr-fsmatrix-XXXXXX.img)
        mnt=$(mktemp -d)
        dd if=/dev/zero of="$img" bs=1M count=200 status=none &&
            "$mkfs" "$img" >/dev/null &&
            sudo mount -o loop "$img" "$mnt" &&
            sudo chown "$(id -u)" "$mnt" &&
            fs_matrix_run "$mnt"
        status=$?
        sudo umount "$mnt" 2>/dev/null
        rm -f "$img"
        rmdir "$mnt" 2>/dev/null
        record "fs-matrix-$lane" $status
    done
else
    skip fs-matrix "Linux loop-mount lanes need FERROCRYPT_GAUNTLET_ROOT_LANES=1 (uses sudo)"
fi

# ── 8. loopback SMB share (macOS, opt in) ────────────────────────────
if [ "$(uname)" = Darwin ] && [ "${FERROCRYPT_GAUNTLET_SMB:-0}" = 1 ]; then
    note "smb"
    SMB_DIR=$(mktemp -d)
    mkdir -p "$SMB_DIR/share" "$SMB_DIR/mnt"
    if python3 -m venv "$SMB_DIR/venv" &&
        "$SMB_DIR/venv/bin/pip" install --quiet impacket; then
        "$SMB_DIR/venv/bin/smbserver.py" -smb2support -port 1445 \
            -username fcr -password fcrtest FCRSMB "$SMB_DIR/share" \
            >"$SMB_DIR/server.log" 2>&1 &
        SMB_PID=$!
        sleep 2
        mount_smbfs "//fcr:fcrtest@127.0.0.1:1445/FCRSMB" "$SMB_DIR/mnt" &&
            fs_matrix_run "$SMB_DIR/mnt"
        status=$?
        umount "$SMB_DIR/mnt" 2>/dev/null
        kill "$SMB_PID" 2>/dev/null
    else
        echo "smb: could not set up the impacket virtual environment"
        status=1
    fi
    rm -rf "$SMB_DIR"
    record smb $status
elif [ "$(uname)" = Darwin ]; then
    skip smb "opt in with FERROCRYPT_GAUNTLET_SMB=1 (installs impacket into a temp venv)"
else
    skip smb "loopback SMB lane is macOS-only in this script"
fi

# ── 9. MSRV toolchains ───────────────────────────────────────────────
for pair in "$MSRV_LIB ferrocrypt" "$MSRV_CLI ferrocrypt-cli"; do
    ver=${pair%% *}
    pkg=${pair#* }
    if rustup toolchain list 2>/dev/null | grep -q "^$ver"; then
        note "msrv-$pkg"
        cargo "+$ver" test -p "$pkg" -- --test-threads=1
        record "msrv-$pkg" $?
    else
        skip "msrv-$pkg" "toolchain $ver not installed (rustup toolchain install $ver)"
    fi
done

# ── summary ──────────────────────────────────────────────────────────
printf '\n════════ SUMMARY ════════\n'
for l in ${PASS+"${PASS[@]}"}; do printf 'PASS  %s\n' "$l"; done
for l in ${SKIP+"${SKIP[@]}"}; do printf 'SKIP  %s\n' "$l"; done
for l in ${FAIL+"${FAIL[@]}"}; do printf 'FAIL  %s\n' "$l"; done
if [ ${#FAIL[@]} -gt 0 ]; then
    printf '\n%d lane(s) failed.\n' ${#FAIL[@]}
    exit 1
fi
printf '\nAll executed lanes passed.\n'
