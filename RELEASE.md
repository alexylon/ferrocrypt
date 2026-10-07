# Releasing

cargo-release makes a release on your machine, and the release workflow checks,
builds, and publishes it. The settings are in `release.toml`,
`ferrocrypt-lib/release.toml`, and `.github/workflows/release.yml`. The order of
the steps on your machine was checked against the source of cargo-release
1.1.6, the version this installs; check it again before you upgrade.

```bash
cargo install --locked cargo-release@1.1.6
```

## Once, before the first release from the workflow

The workflow publishes to crates.io with a short-lived token that crates.io
gives it for each run, so no publishing token has to be stored, on GitHub or on
your machine. Before the first such release, make crates.io trust the workflow,
and limit on GitHub who can start it:

1. On crates.io, in the settings of `ferrocrypt` and then of `ferrocrypt-cli`,
   under Trusted Publishing, add GitHub with the owner `alexylon`, the
   repository `ferrocrypt`, the workflow `release.yml`, and the environment
   `release`.
2. On GitHub, in the repository's Settings, click Environments in the left
   sidebar and create the environment `release`. In its "Deployment branches"
   dropdown, choose "Selected branches and tags", and add a rule of the ref
   type Tag for `v*`. Then only a run that a release tag started can publish.
   If you also add yourself under "Required reviewers", each publish waits for
   your approval on the run's page.
3. On GitHub, in the repository's Settings, click Rulesets in the left sidebar
   and create a new tag ruleset that targets tags matching `v*`, with the rules
   "Restrict creations", "Restrict updates", "Restrict deletions", and "Block
   force pushes", and with Repository admin in its bypass list. Then only a
   repository admin can create, move, or delete a release tag, and so start a
   release.
4. After the first release that the workflow publishes, tick "Require trusted
   publishing for all new versions" in the settings of both crates on
   crates.io, and revoke the API token your machine used to publish, at
   <https://crates.io/settings/tokens>. Then only the workflow can publish
   them.

## Making a release

First, see what the release would do. Without `--execute`, nothing is changed
and the tests do not run:

```bash
cargo release rc
```

Then make the release:

```bash
cargo release rc --execute
```

That one command, in this order:

1. Sets the new version of `ferrocrypt`, `ferrocrypt-cli`, and
   `ferrocrypt-test-support` in their `Cargo.toml` files and in `Cargo.lock`,
   and the CLI's dependency on the library to match.
2. Moves everything under `## [Unreleased]` in `CHANGELOG.md` into a section
   for the new version, dated with today's date in UTC, and sets the same
   version in `ferrocrypt-desktop/Cargo.toml`. For a release without a
   pre-release suffix, it also sets that version in `README.md`, the crates.io
   page of both crates, in its links to the version and its install commands.
3. Runs `scripts/release_hook.sh`, which records the new versions in the lock
   files of the desktop app and the fuzz targets, runs the workspace tests as
   every push runs them in CI, then runs the >4 GiB round trip at its full
   size, whatever `FERROCRYPT_LARGE_FILE_BYTES` says. It stops the release if a
   lock file records other dependency versions than the last commit, if a test
   fails, or if a test changed a file that the commit would include.
4. Commits all of it as `Release X.Y.Z`.
5. Tags `vX.Y.Z`.
6. Pushes the commit and the tag together: both or neither.

It prints a `Publishing` line, but it packages and uploads nothing: the
workflow publishes.

The tag starts `.github/workflows/release.yml`, which:

1. Runs every check a push gets on the tagged commit, fuzzes every target for
   60 seconds, and runs the >4 GiB round trip. Checks that the tag names the
   version of every published crate and of the desktop app, that the CLI
   requires that version of the library, and that `PUBLISHED_CRATES` in the
   workflow names exactly the crates that can be published. Packages and
   builds those crates as crates.io will receive them.
2. Builds the CLI and the desktop app for Linux, macOS (Intel and Apple
   silicon), and Windows, and the static Linux CLI for x86-64 and arm64, which
   it also checks for shared libraries and runs on Alpine.
3. Checks that the tag still names its commit, that the commit is on `main`,
   and that it packages the crates exactly as step 1 built them. Then it
   publishes `ferrocrypt` to crates.io, then `ferrocrypt-cli`.
4. Checks the tag and `main` again, then creates a GitHub release with the
   archives, marked as a pre-release when the version has a suffix such as
   `-rc.5`.

Nothing reaches crates.io unless every check and build has passed.

A new crate to publish goes into `PUBLISHED_CRATES` in
`.github/workflows/release.yml`. Until it is there, or until its `Cargo.toml`
sets `publish = false`, the version check stops every release. crates.io
trusts a workflow only for a crate it already has, so publish the crate's
first version by hand, with an API token that you revoke afterwards, and add
its trusted publisher as in step 1 above. Until then, the workflow stops
before it uploads anything.

## Choosing the version

Pass `patch`, `minor`, or `major`; or `alpha`, `beta`, or `rc` for the next
pre-release of that kind, such as `0.3.0-rc.4` to `0.3.0-rc.5`; or an exact
version, such as `0.3.0-rc.5`. `cargo release release` drops the pre-release
suffix: `0.3.0-rc.5` becomes `0.3.0`. On its own, `cargo release` tries to
release the version already in `Cargo.toml`.

On a version without a suffix, `alpha`, `beta`, and `rc` move to the next
patch version: `0.3.0` becomes `0.3.1-rc.1`. For the first pre-release of a
new minor or major version, pass the exact version, such as `0.4.0-rc.1`.

The tag carries the suffix too, such as `v0.3.0-rc.5`. Cargo chooses a
pre-release only for a requirement that names one, such as
`ferrocrypt = "0.3.0-rc.5"`, and that requirement also accepts the later
pre-releases of `0.3.0`. Semantic Versioning allows incompatible changes
between pre-releases.

The `semver` job in `.github/workflows/rust.yml` freezes the library's public
API: on every push and on every release, it refuses any incompatible change
since the newest release tag before the commit. A version that changes the API
on purpose, such as `0.4.0` after `0.3.x`, needs that job's
`--release-type patch` changed to `--release-type major` first. For a `0.x`
version, cargo-semver-checks counts a change of the second number, such as
`0.3` to `0.4`, as major.

## Before you start

- On `main`, with everything committed and nothing untracked: `git status`.
  cargo-release refuses to start otherwise.
- Formatted: after `./scripts/fmt.sh`, `git status` still shows nothing. It
  also formats the desktop app and the fuzz targets, which CI does not check.
- Everything pushed, and the CI run of the last commit passed. The release
  runs all those checks again on the tagged commit, and a failure there means
  moving the tag.
- Anything worth reading about is under `## [Unreleased]` in `CHANGELOG.md`.
  The release does not write it.
- No confirmed release blocker remains under
  [`THREAT_MODEL.md` section 6](THREAT_MODEL.md#6-release-and-review-governance)
- About 8 GiB of free disk for the >4 GiB round trip
- For a release without a pre-release suffix: `README.md` no longer describes
  a pre-release, in its status note and beside its install commands. The
  release changes only the version numbers.
- For a pre-release: the rule for `README.md` in `ferrocrypt-lib/release.toml`
  sets `prerelease = true` only if the README describes a changed API or CLI,
  such as for `0.4.0-rc.1`. Without it, the README's install commands keep
  naming the last release without a suffix.

The tests need no run of their own: the release runs them. To run them alone,
for example before you start, use `./scripts/release_hook.sh`. If it changes
`ferrocrypt-desktop/Cargo.lock` or `ferrocrypt-lib/fuzz/Cargo.lock`, commit
them before you start.

## Committing and tagging without pushing

```bash
cargo release rc --execute --no-push
```

Push the commit and the tag later, both together:

```bash
git push --atomic origin HEAD vX.Y.Z
```

## The desktop app's version

`ferrocrypt-desktop` is excluded from the Cargo workspace, so the shared version
does not cover it. A rule in `ferrocrypt-lib/release.toml` sets its version in
its `Cargo.toml`, which the installers use; the rule sets `prerelease = true`,
without which cargo-release skips it for a pre-release. The version shown in
the app window comes from the library (`ferrocrypt::VERSION`), so it is right
even if the rule is skipped. The release workflow's version check stops the
release if the desktop app's `Cargo.toml` does not match the tag.

The release hook records the new versions in the `Cargo.lock` files of the
app and of the fuzz targets, which are outside the workspace too.

## If something fails

On your machine, before anything was pushed:

- There is no release commit, and files are left changed: the release
  stopped before its commit, usually in the hook. Put back the files the
  release changed:

  ```bash
  git checkout -- Cargo.lock CHANGELOG.md README.md ferrocrypt-lib/Cargo.toml \
      ferrocrypt-cli/Cargo.toml ferrocrypt-test-support/Cargo.toml \
      ferrocrypt-desktop/Cargo.toml ferrocrypt-desktop/Cargo.lock \
      ferrocrypt-lib/fuzz/Cargo.lock
  ```

  If the hook says that a test changed a file, `git status` shows which; find
  out why before you put it back. If it says that a lock file records other
  dependency versions than the last commit, a `Cargo.toml` changed without its
  lock file: put the release's files back, bring that lock file up to date in
  a commit of its own, push it, and start again.

- The last commit is `Release X.Y.Z`, but the push failed. Push again once the
  cause is fixed, with the command under "Committing and tagging without
  pushing". Or undo the tag and the commit:

  ```bash
  git tag -d vX.Y.Z
  git reset --hard HEAD~1
  ```

  Only when `git log -1 --oneline` shows the release commit, and nothing else
  is uncommitted: otherwise this throws away work of your own.

In the release workflow, after the push:

- A job failed because of a temporary problem, such as a download that timed
  out: open the run on the Actions page and choose to re-run the failed jobs.
- A check, the version check, the packaging, or a build failed for a real
  reason: nothing was published. Fix it in a new commit, push it, and move the
  tag to it. Pushing the moved tag starts the workflow again:

  ```bash
  git push origin HEAD
  git tag -f -a vX.Y.Z -m "Release X.Y.Z"
  git push -f origin vX.Y.Z
  ```

  From then on, use only the run that this push started. An older run builds
  the commit the tag named before, and its publishing stops because the tag
  no longer names that commit.
- Publishing failed because crates.io does not trust the workflow: check the
  settings under "Once, before the first release from the workflow", then
  re-run the failed jobs.
- Publishing stopped because the tagged commit is not on `main`: nothing was
  published. Delete the tag, here and on GitHub, and release from `main`:

  ```bash
  git tag -d vX.Y.Z
  git push origin --delete vX.Y.Z
  ```
- Publishing stopped after `ferrocrypt` and before `ferrocrypt-cli`: re-run the
  failed jobs. The workflow skips a crate whose package on crates.io is exactly
  the one this commit makes. If one at this version differs, it stops: yank
  that version as below, and release the next one.
- Publishing stopped because the packages differ from the ones the `package`
  job built: this attempt published nothing. Re-run all the jobs of the run,
  so that both jobs package the crates again with the same toolchain.
- crates.io keeps refusing `ferrocrypt-cli` after it accepted `ferrocrypt`:
  yank `ferrocrypt` as below, fix the cause, and release the next version.
- The crates are on crates.io but the GitHub release failed: re-run the failed
  jobs.
- After a release, the `vet` job fails with `ferrocrypt:X.Y.Z missing
  ["safe-to-deploy"]`: no wildcard audit in `supply-chain/audits.toml` covers
  the new version's publisher, which the job's output names. If it is
  `github:alexylon/ferrocrypt`, the audits for the release workflow have
  expired: renew them with `cargo vet renew ferrocrypt` and
  `cargo vet renew ferrocrypt-cli`. If it is another publisher, such as a
  renamed repository, certify that one with
  `cargo vet certify <crate> --wildcard <publisher>`, and add `renew = false`
  to the old publisher's entries so that they are never extended. Then run
  `cargo vet`, which also records the new publisher, and commit
  `supply-chain/`.

A version on crates.io cannot be replaced, and its number cannot be used
again. If a published version is wrong, yank it, for example with
`cargo yank --version X.Y.Z ferrocrypt`, and release the next version.
`cargo yank` needs a crates.io API token on your machine: create one that may
only yank, and revoke it afterwards.

## References

- [cargo-release 1.1.6 reference](https://github.com/crate-ci/cargo-release/blob/1263ad90fa0edfd3d645bb287b40d7292fd0b381/docs/reference.md)
- [Semantic Versioning](https://semver.org/)
