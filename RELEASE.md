# Release Process Guide

This project uses **cargo-release** to automate the release workflow for both `ferrocrypt` (library) and `ferrocrypt-cli` crates simultaneously.

## Setup

Install cargo-release if not already installed:

```bash
cargo install cargo-release
```

The configuration is in `release.toml`. Both crates share the same version and are released together.

## Release Commands

### 1. Dry Run (Recommended First Step)
Preview what will happen without making changes:

```bash
cargo release patch
```

This shows:
- Version bump for both crates (e.g., 0.2.5 → 0.2.6)
- Files to be modified
- Git operations
- Publishing steps (lib first, then CLI)

### 2. Perform Release
Execute the full release workflow:

```bash
cargo release patch --execute
```

This automatically:
1. Bumps version in both `Cargo.toml` files
2. Updates the CLI's dependency version on the lib
3. Runs tests: `cargo test`
4. Updates `CHANGELOG.md`
5. Publishes `ferrocrypt` (lib) to crates.io
6. Publishes `ferrocrypt-cli` to crates.io
7. Creates release commit: `"Release vX.Y.Z"`
8. Creates Git tag: `vX.Y.Z`
9. Pushes commits and tags to remote

### 3. Release with Specific Version
Bump to a specific version (major, minor, patch):

```bash
# Patch release (0.2.5 → 0.2.6)
cargo release patch --execute

# Minor release (0.2.5 → 0.3.0)
cargo release minor --execute

# Major release (0.2.5 → 1.0.0)
cargo release major --execute
```

**Note:** Always pass either a version level (`patch` / `minor` / `major` / `alpha` / `beta` / `rc` / `release`) or an explicit version string (e.g., `0.3.0-beta.1`). Running `cargo release` without an argument will try to re-release the current version.

### 4. Pre-release (alpha / beta / rc)
For shipping a pre-release version (e.g., `0.3.0-beta.1`) before the final `0.3.0`:

```bash
# First pre-release — specify the exact version
cargo release 0.3.0-beta.1 --execute

# Subsequent pre-releases — bumps the suffix automatically
cargo release beta --execute     # 0.3.0-beta.1 → 0.3.0-beta.2

# Promote to final release — drops the pre-release suffix
cargo release release --execute  # 0.3.0-beta.N → 0.3.0
```

The same workflow applies with `alpha` or `rc` identifiers (`0.3.0-alpha.1`, `0.3.0-rc.1`).

**Notes:**
- The Git tag includes the suffix: `v0.3.0-beta.1`.
- Cargo does not auto-select pre-releases. Consumers must opt in by writing the exact version in their `Cargo.toml` (e.g., `ferrocrypt = "0.3.0-beta.1"`).
- Breaking changes are allowed between pre-releases and before the final release (semver treats pre-release versions as unstable by design).

### 5. Release Without Publishing to crates.io
If you want to skip publishing:

```bash
cargo release patch --execute --no-publish
```

### 6. Release Without Pushing to Git
For testing/staging:

```bash
cargo release patch --execute --no-push
```

## What Gets Updated

### Files Modified Automatically
- **ferrocrypt-lib/Cargo.toml**: Version number
- **ferrocrypt-cli/Cargo.toml**: Version number + dependency version
- **CHANGELOG.md**: New release section with date
- **ferrocrypt-desktop/Cargo.toml**: Version number (see "Desktop app version" below)
- **Git**: Creates commit and annotated tag

### Publish Order
1. `ferrocrypt` (library) — published first since CLI depends on it
2. `ferrocrypt-cli` — published after the lib is available on crates.io

### Desktop app version

`ferrocrypt-desktop` is excluded from the Cargo workspace, so cargo-release's
shared-version does not bump it automatically. Two things keep it correct:

- **Its `Cargo.toml` version** — used for the macOS / Linux / Windows installer
  metadata — is rewritten by a `[[pre-release-replacements]]` rule in
  `ferrocrypt-lib/release.toml`, which sets `prerelease = true` (without that,
  cargo-release silently skips the rewrite on `-beta` / `-rc` releases).
- **The version shown in the app window** is read from the library at runtime
  (`ferrocrypt::VERSION`), so it always matches the released version even if the
  manifest rewrite is somehow skipped.

As a backstop, the `desktop-version` job in `.github/workflows/release.yml` fails
the release if `ferrocrypt-desktop/Cargo.toml` does not match the pushed tag. If
that happens, bump `ferrocrypt-desktop/Cargo.toml` to the tag version, then
delete and re-push the tag.

## Before Release

Ensure:
1. All changes are committed: `git status`
2. Tests pass: `cargo test`
3. The large-file round trip passes (see below)
4. Code is formatted: `./fmt.sh`
5. You have push access to the remote repository
6. crates.io credentials are configured: `cargo login`

### Large-file round trip

`tests/large_file.rs` moves a payload just over 4 GiB through a full encrypt
and decrypt. It is the only coverage for size accounting above `u32::MAX`, and
it is `#[ignore]`d by design, so the CI test lane skips it. Run it by hand
against the candidate, on a machine with a few spare GiB of disk:

```bash
cargo test -p ferrocrypt --release --test large_file -- --ignored --test-threads=1
```

It takes under a minute. `FERROCRYPT_LARGE_FILE_BYTES` overrides the payload
size; a small value checks the harness quickly but does not cross the boundary,
so the release check must run at the default size.

## Rollback Release

If something goes wrong:

```bash
# Undo the last commit
git reset --soft HEAD~1

# Delete the tag locally
git tag -d vX.Y.Z

# Delete the tag remotely
git push origin :refs/tags/vX.Y.Z
```

## References

- [cargo-release documentation](https://rust-lang.github.io/cargo-release/)
- [Semantic Versioning](https://semver.org/)
