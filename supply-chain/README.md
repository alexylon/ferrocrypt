# Supply-Chain Auditing with cargo-vet

This directory is managed by [cargo-vet](https://mozilla.github.io/cargo-vet/), a supply-chain audit tool for Rust dependencies.

## What it does

cargo-vet tracks whether each dependency in `Cargo.lock` has been reviewed by someone you trust. It prevents unreviewed code from entering the build.

## Files

- `config.toml` — imports (organizations whose audits we trust), trusted publishers, and exemptions (crates not yet reviewed).
- `audits.toml` — your own audit certifications and trusted publisher entries. When you review a crate or trust a publisher, the record goes here.
- `imports.lock` — cached audits fetched from imported organizations.

## How exemptions work

`cargo vet init` exempted every dependency at its current version. This is the baseline: "we trust what we have today."

When a dependency version changes (upgrade, downgrade, or new addition), the exemption no longer matches. `cargo vet` fails until you either:

1. **Review and certify** the new version: `cargo vet certify <crate> <version>`
2. **Add an exemption** to skip review: `cargo vet add-exemption <crate> <version>`

Option 1 is the point of the tool. Option 2 is the escape hatch.

## Reducing exemptions over time

Exemptions are not a problem — they just mark crates that haven't been reviewed yet. The number goes down gradually through three mechanisms:

1. **Imported organizations review them for you.** If Mozilla or Zcash publishes an audit for a crate version you use, running `cargo vet prune` drops your exemption.
2. **Dependency bumps are small reviews.** When you bump a crate, `cargo vet diff <crate> <old> <new>` shows only what changed. Review the diff, then `cargo vet certify <crate> <new-version>`.
3. **Full crate reviews.** For small crates, `cargo vet inspect <crate> <version>` shows the full source. Review it and certify.

You do not need to push the count to zero. CI with exemptions still catches every *new* unreviewed dependency.

## Workflow: bumping a dependency

When you update a crate version in `Cargo.toml` and `cargo vet` fails:

```bash
cargo vet                              # see what failed
cargo vet diff <crate> <old> <new>     # read the diff
cargo vet certify <crate> <new>        # record your review
```

If you don't want to review it right now:

```bash
cargo vet add-exemption <crate> <new>  # skip review (escape hatch)
```

## Workflow: adding a new dependency

When you add a new crate to `Cargo.toml` and `cargo vet` fails:

```bash
cargo vet                              # see what failed
cargo vet inspect <crate> <version>    # read the full source
cargo vet certify <crate> <version>    # record your review
```

Or if covered by a trusted publisher or imported audit, just run `cargo vet prune`.

## Periodic maintenance

Run this occasionally (e.g. before a release) to pick up new audits published by imported organizations:

```bash
cargo vet prune     # drop exemptions now covered by imports or trust
cargo vet           # verify everything still passes
```

`prune` is safe — it only removes exemptions that are redundant because an import or publisher trust already covers the crate.

## Common commands

```bash
cargo vet                              # check all dependencies
cargo vet suggest                      # show which exemptions are easiest to clear
cargo vet inspect <crate> <version>    # view full source of a crate
cargo vet diff <crate> <old> <new>     # view diff between two versions
cargo vet certify <crate> <version>    # record that you reviewed a crate
cargo vet add-exemption <crate> <ver>  # trust without review (escape hatch)
cargo vet prune                        # drop redundant exemptions
cargo vet trust --all <publisher>      # trust all crates by a publisher
```

## Imported trust

We import published audit logs from 7 organizations in `config.toml`:

- **bytecode-alliance** (Wasmtime) — broad Rust ecosystem coverage
- **embark-studios** — game/systems crates
- **fermyon** (Spin) — WASI and core crates
- **google** — wide coverage of common dependencies
- **isrg** (divviup/libprio-rs) — crypto-adjacent crates
- **mozilla** — extensive Rust ecosystem audits
- **zcash** — RustCrypto and cryptographic crates

When one of these organizations reviews a crate version we depend on, their audit satisfies our requirement — no exemption or local review needed. This is how patch bumps on shared crates (RustCrypto, dalek, etc.) get covered without manual effort.

To add another organization's audits:

```bash
cargo vet import <url>
```

## Trusted publishers

We trust specific crates.io publishers — well-known maintainers whose code is already trusted by multiple imported organizations. When a publisher is trusted, any crate they publish (current and future versions) counts as audited.

Current trusted publishers:

- **kennykerr** (Kenny Kerr, Microsoft) — `windows-sys`, `windows-targets`, `windows_*`
- **dtolnay** (David Tolnay) — `syn`, `quote`, `proc-macro2`, `thiserror`, `semver`, `unicode-ident`
- **epage** (Ed Page) — `clap`, `clap_builder`, `clap_derive`, `clap_lex`, `anstream`, `anstyle*`, `colorchoice`
- **sunfishcode** (Dan Gohman) — `rustix`, `linux-raw-sys`, `fd-lock`, `wasi`
- **alexcrichton** (Alex Crichton) — `tar`, `filetime`, `libc`, `wasi`
- **BurntSushi** (Andrew Gallant) — `memchr`

To trust a new publisher:

```bash
cargo vet trust --all <publisher>                             # single-publisher crates
cargo vet trust --all <publisher> --allow-multiple-publishers  # includes shared crates
cargo vet prune                                                # clean up redundant exemptions
```

## Current status

As of initial setup: 79 dependencies fully audited (via imports + publisher trust), 56 still exempted. The remaining exemptions are mostly RustCrypto ecosystem crates (`chacha20poly1305`, `x25519-dalek`, `argon2`, `sha3`, `hkdf`, etc.) and CLI dependencies (`rustyline`, `rpassword`). These are fine as exemptions for now and can be cleared over time.

## CI integration

Add `cargo vet` to your CI pipeline. It exits non-zero when any dependency lacks an audit or exemption, blocking PRs that introduce unreviewed code.
