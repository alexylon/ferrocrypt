# Runs every FerroCrypt test suite locally on Windows, except
# stress_test.sh (bash-only; run it separately under WSL or Git Bash).
# macOS and Linux use run_all_tests.sh.
#
# Lanes (each reported PASS / FAIL / SKIP, summary at the end):
#   1. workspace          - full workspace suite, CI build-job mirror
#                           (--include-ignored, generators skipped).
#                           This script defaults
#                           FERROCRYPT_REQUIRE_WINDOWS_SYMLINK_TESTS=1 so
#                           a green gauntlet is trustworthy: the
#                           symlink/junction extraction tests fail closed
#                           when the privilege is missing, matching CI.
#                           Set that variable to 0 before running to opt
#                           out on a machine without the privilege and
#                           without Developer Mode.
#   2. testvector-cycle   - committed corpus replayed, generator run,
#                           fresh output validated, committed corpus
#                           restored and re-validated
#   3. fixture-cycle      - fixture generator, fresh output validated,
#                           committed fixtures restored and re-validated
#   4. desktop            - ferrocrypt-desktop suite (own target dir)
#   5. release-cli        - release-profile CLI tests with full-strength
#                           Argon2id (1 GiB sequential; needs >= 4 GiB RAM)
#   6. fs-matrix-exfat    - archive tests on an exFAT VHD (mirrors the CI
#                           windows-exfat lane; needs elevation + Hyper-V
#                           cmdlets; opt in with FERROCRYPT_GAUNTLET_EXFAT=1)
#   7. msrv               - lib on 1.87.0, CLI on 1.89.0 (skipped unless
#                           those toolchains are installed via rustup)
#
# Not covered here: fuzz smoke (fuzz_smoke.sh is bash; nightly libFuzzer
# on Windows is unsupported in this repository's setup) and the SMB/NFS
# loopback lanes (macOS-specific client drivers; see run_all_tests.sh).
# NTFS itself is covered by lane 1 - the default filesystem run.

$ErrorActionPreference = "Continue"
Set-Location -Path $PSScriptRoot

# Keep in sync with the msrv / msrv-cli jobs in .github/workflows/rust.yml.
$MsrvLib = "1.87.0"
$MsrvCli = "1.89.0"

$Pass = @()
$Fail = @()
$Skip = @()

$TestWorkspaceRoots = @(
    (Join-Path $PSScriptRoot "ferrocrypt-lib\tests\workspace"),
    (Join-Path $PSScriptRoot "ferrocrypt-lib\tests\workspace_api"),
    (Join-Path $PSScriptRoot "ferrocrypt-lib\tests\workspace_config_symmetry"),
    (Join-Path $PSScriptRoot "ferrocrypt-lib\tests\workspace_fixture_stability"),
    (Join-Path $PSScriptRoot "ferrocrypt-lib\tests\workspace_testvector_suite"),
    (Join-Path $PSScriptRoot "ferrocrypt-lib\tests\workspace_concurrency"),
    (Join-Path $PSScriptRoot "ferrocrypt-lib\tests\workspace_memory_bounds"),
    (Join-Path $PSScriptRoot "ferrocrypt-lib\tests\workspace_roundtrip_randomized"),
    (Join-Path $PSScriptRoot "ferrocrypt-lib\tests\workspace_large_file"),
    (Join-Path $PSScriptRoot "ferrocrypt-cli\tests\cli_workspace")
)

function Remove-StaleTestWorkspaces {
    foreach ($root in $TestWorkspaceRoots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }

        foreach ($runDir in Get-ChildItem -LiteralPath $root -Directory -Filter "run-*" -ErrorAction SilentlyContinue) {
            if ($runDir.Name -notmatch '^run-(\d+)$') { continue }
            $runProcessId = [long]$Matches[1]
            if (Get-Process -Id $runProcessId -ErrorAction SilentlyContinue) { continue }

            Remove-Item -LiteralPath $runDir.FullName -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $runDir.FullName) {
                Write-Warning "Could not remove stale test workspace: $($runDir.FullName)"
            }
        }

        # Remove the now-empty root only when it is actually empty. A bare
        # `Remove-Item` on a non-empty directory (a live run-<pid> that
        # survived pruning) prompts "item has children" — an interactive
        # run blocks, and confirming would recurse into a live workspace.
        # This mirrors bash's `rmdir`, which fails silently on non-empty.
        if (-not (Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue)) {
            Remove-Item -LiteralPath $root -ErrorAction SilentlyContinue
        }
    }
}

function Note([string]$Msg) { Write-Host "`n=== $Msg" }

function Record([string]$Lane, [bool]$Ok) {
    if ($Ok) { $script:Pass += $Lane } else { $script:Fail += $Lane }
}

function SkipLane([string]$Lane, [string]$Reason) {
    Note "$Lane - SKIP: $Reason"
    $script:Skip += "$Lane ($Reason)"
}

function Run-FsMatrix([string]$Dir) {
    $env:FERROCRYPT_FS_MATRIX_DIR = $Dir
    # Pipe cargo's stdout to the host, not the pipeline. A native
    # command's output inside a function joins the function's return
    # stream, so without this the caller's `$ok = Run-FsMatrix ...` would
    # receive every cargo line plus the boolean as an array — and binding
    # a multi-element array to `Record`'s `[bool]$Ok` coerces to $true,
    # recording PASS even when the tests fail. Out-Host keeps only $ok
    # on the pipeline and shows cargo output live.
    cargo test -p ferrocrypt --test archive_fs_matrix -- --ignored --test-threads=1 --nocapture | Out-Host
    $ok = ($LASTEXITCODE -eq 0)
    Remove-Item Env:FERROCRYPT_FS_MATRIX_DIR -ErrorAction SilentlyContinue
    return $ok
}

# Remove abandoned per-process directories from interrupted earlier runs.
# A directory whose PID still exists is never touched.
Remove-StaleTestWorkspaces

# The regeneration lanes restore committed state afterwards, so refuse
# them when those paths are dirty before we start - a restore would
# silently discard local edits.
$TestvectorsDirty = (git status --porcelain ferrocrypt-lib/testvectors | Measure-Object).Count
$FixturesDirty = (git status --porcelain ferrocrypt-lib/tests/fixtures | Measure-Object).Count

# -- 1. workspace ------------------------------------------------------
# Fail closed on a missing Windows symlink privilege (matching CI's
# build job) unless the caller already chose a value, so a green local
# gauntlet means the same as a green CI run. Set the variable to 0 to
# opt out. This applies to the whole run; only the archive/platform
# symlink and junction tests read it, and those run in this lane.
if (-not (Test-Path Env:FERROCRYPT_REQUIRE_WINDOWS_SYMLINK_TESTS)) {
    $env:FERROCRYPT_REQUIRE_WINDOWS_SYMLINK_TESTS = "1"
}
Note "workspace"
cargo test -- --test-threads=1 --include-ignored --skip regenerate_fixtures --skip regenerate_suite_vectors --skip round_trip_file_larger_than_4gib
Record "workspace" ($LASTEXITCODE -eq 0)

# -- 2. test-vector corpus: committed replay and generator cycle -------
if ($TestvectorsDirty -eq 0) {
    Note "testvector-cycle"
    $ok = $true
    $generatorStarted = $false

    cargo test -p ferrocrypt --test testvector_suite -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { $ok = $false }

    if ($ok) {
        $generatorStarted = $true
        cargo test -p ferrocrypt --lib -- --ignored --exact suite_vector_gen::regenerate_suite_vectors --test-threads=1
        if ($LASTEXITCODE -ne 0) { $ok = $false }
    }
    if ($ok) {
        cargo test -p ferrocrypt --test testvector_suite -- --test-threads=1
        if ($LASTEXITCODE -ne 0) { $ok = $false }
    }

    if ($generatorStarted) {
        git restore ferrocrypt-lib/testvectors
        if ($LASTEXITCODE -ne 0) { $ok = $false }
    }
    if ($generatorStarted -and $ok) {
        cargo test -p ferrocrypt --test testvector_suite -- --test-threads=1
        if ($LASTEXITCODE -ne 0) { $ok = $false }
    }

    Record "testvector-cycle" $ok
} else {
    SkipLane "testvector-cycle" "ferrocrypt-lib/testvectors has local changes; not restoring over them"
}

# -- 3. fixture regeneration cycle --------------------------------------
if ($FixturesDirty -eq 0) {
    Note "fixture-cycle"
    $ok = $true
    cargo test -p ferrocrypt --test fixture_stability -- --ignored --exact regenerate_fixtures --test-threads=1
    if ($LASTEXITCODE -ne 0) { $ok = $false }
    if ($ok) {
        cargo test -p ferrocrypt --test fixture_stability -- --test-threads=1
        if ($LASTEXITCODE -ne 0) { $ok = $false }
    }
    if ($ok) {
        git restore ferrocrypt-lib/tests/fixtures
        if ($LASTEXITCODE -ne 0) { $ok = $false }
    }
    if ($ok) {
        cargo test -p ferrocrypt --test fixture_stability -- --test-threads=1
        if ($LASTEXITCODE -ne 0) { $ok = $false }
    }
    Record "fixture-cycle" $ok
} else {
    SkipLane "fixture-cycle" "ferrocrypt-lib/tests/fixtures has local changes; not restoring over them"
}

# -- 4. desktop ----------------------------------------------------------
Note "desktop"
Push-Location ferrocrypt-desktop
cargo test -- --test-threads=1
Record "desktop" ($LASTEXITCODE -eq 0)
Pop-Location

# -- 5. release-profile CLI, full-strength Argon2id -----------------------
$RamMib = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
if ($RamMib -ge 4096) {
    Note "release-cli"
    cargo test --release --package ferrocrypt-cli --test cli_tests -- --ignored --test-threads=1
    Record "release-cli" ($LASTEXITCODE -eq 0)
} else {
    SkipLane "release-cli" "less than 4 GiB RAM for sequential 1 GiB Argon2id runs"
}

# -- large-file: >4 GiB round trip (opt in) --------------------------------
# Excluded from lane 1 because it streams >4 GiB through real I/O to catch a
# u32 truncation in the size/progress accounting. Opt in explicitly; needs a
# few GiB of free disk.
if ($env:FERROCRYPT_GAUNTLET_LARGE_FILE -eq "1") {
    Note "large-file"
    cargo test --release -p ferrocrypt --test large_file -- --ignored --test-threads=1
    Record "large-file" ($LASTEXITCODE -eq 0)
} else {
    SkipLane "large-file" "opt in with FERROCRYPT_GAUNTLET_LARGE_FILE=1 (>4 GiB I/O, needs spare disk)"
}

# -- 6. exFAT VHD (mirrors the CI windows-exfat lane) ----------------------
$IsElevated = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$HasHyperV = $null -ne (Get-Command New-VHD -ErrorAction SilentlyContinue)

if ($env:FERROCRYPT_GAUNTLET_EXFAT -eq "1" -and $IsElevated -and $HasHyperV) {
    Note "fs-matrix-exfat"
    $VhdPath = Join-Path $env:TEMP "fcr-fsmatrix.vhd"
    $ok = $false
    try {
        New-VHD -Path $VhdPath -SizeBytes 200MB -Dynamic | Out-Null
        $vhd = Mount-VHD -Path $VhdPath -Passthru
        $disk = Get-Disk -Number $vhd.DiskNumber
        Initialize-Disk -Number $disk.Number -PartitionStyle MBR
        $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
        Format-Volume -DriveLetter $part.DriveLetter -FileSystem exFAT -Confirm:$false | Out-Null
        $ok = Run-FsMatrix "$($part.DriveLetter):\"
    } finally {
        Dismount-VHD -Path $VhdPath -ErrorAction SilentlyContinue
        Remove-Item $VhdPath -ErrorAction SilentlyContinue
    }
    Record "fs-matrix-exfat" $ok
} else {
    SkipLane "fs-matrix-exfat" "opt in with FERROCRYPT_GAUNTLET_EXFAT=1 in an elevated shell with Hyper-V cmdlets"
}

# -- 7. MSRV toolchains -----------------------------------------------------
$Toolchains = rustup toolchain list 2>$null
foreach ($pair in @(@($MsrvLib, "ferrocrypt"), @($MsrvCli, "ferrocrypt-cli"))) {
    $ver = $pair[0]
    $pkg = $pair[1]
    if ($Toolchains -match "^$([regex]::Escape($ver))") {
        Note "msrv-$pkg"
        cargo "+$ver" test -p $pkg
        Record "msrv-$pkg" ($LASTEXITCODE -eq 0)
    } else {
        SkipLane "msrv-$pkg" "toolchain $ver not installed (rustup toolchain install $ver)"
    }
}

# Remove any per-process directories whose test process has exited but
# whose best-effort destructor could not clean them.
Remove-StaleTestWorkspaces

# -- summary ------------------------------------------------------------------
Write-Host "`n======== SUMMARY ========"
foreach ($l in $Pass) { Write-Host "PASS  $l" }
foreach ($l in $Skip) { Write-Host "SKIP  $l" }
foreach ($l in $Fail) { Write-Host "FAIL  $l" }
if ($Fail.Count -gt 0) {
    Write-Host "`n$($Fail.Count) lane(s) failed."
    exit 1
}
Write-Host "`nAll executed lanes passed."
