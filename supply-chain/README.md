# Supply-Chain Auditing with cargo-vet

This directory is managed by [cargo-vet](https://mozilla.github.io/cargo-vet/), a supply-chain audit tool for Rust dependencies.

## What it does

cargo-vet tracks whether each dependency in `Cargo.lock` has been reviewed by someone you trust. It prevents unreviewed code from entering the build.

## Files

- `config.toml` — exemptions and trust imports. Every dependency starts here as "exempted" (trusted without review). As you review crates or import trust from other organizations, exemptions shrink.
- `audits.toml` — your own audit certifications. When you review a crate, the record goes here.
- `imports.lock` — cached audits from organizations you import trust from.

## How exemptions work

`cargo vet init` exempted every dependency at its current version. This is the baseline: "we trust what we have today."

When a dependency version changes (upgrade, downgrade, or new addition), the exemption no longer matches. `cargo vet` fails until you either:

1. **Review and certify** the new version: `cargo vet certify <crate> <version>`
2. **Add an exemption** to skip review: `cargo vet add-exemption <crate> <version>`

Option 1 is the point of the tool. Option 2 is the escape hatch.

## Common commands

```bash
cargo vet                # check all dependencies (run in CI)
cargo vet suggest        # show which exemptions are easiest to clear
cargo vet certify <c> <v> # record that you reviewed crate c at version v
cargo vet diff <c> <old> <new>  # view the diff between two versions of a crate
cargo vet add-exemption <c> <v> # trust without review (escape hatch)
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

After adding imports, run `cargo vet prune` to drop exemptions that are now redundant.

To add another organization's audits:

```bash
cargo vet import <url>
```

## Trusted publishers

We also trust specific crates.io publishers — well-known maintainers whose code is already trusted by multiple imported organizations. When a publisher is trusted, any crate they publish (current and future versions) counts as audited.

Current trusted publishers:

- **kennykerr** (Kenny Kerr, Microsoft) — `windows-sys`, `windows-targets`, `windows_*`
- **dtolnay** (David Tolnay) — `syn`, `quote`, `proc-macro2`, `thiserror`, `semver`, `unicode-ident`
- **epage** (Ed Page) — `clap`, `clap_builder`, `clap_derive`, `clap_lex`, `anstream`, `anstyle*`, `colorchoice`
- **sunfishcode** (Dan Gohman) — `rustix`, `linux-raw-sys`, `fd-lock`, `wasi`
- **alexcrichton** (Alex Crichton) — `tar`, `filetime`, `libc`, `wasi`
- **BurntSushi** (Andrew Gallant) — `memchr`

To trust a new publisher:

```bash
cargo vet trust --all <publisher>                        # single-publisher crates
cargo vet trust --all <publisher> --allow-multiple-publishers  # includes shared crates
cargo vet prune                                           # clean up redundant exemptions
```

## Current status

As of initial setup: 79 dependencies fully audited (via imports + publisher trust), 56 still exempted. The remaining exemptions are mostly RustCrypto ecosystem crates (`chacha20poly1305`, `x25519-dalek`, `argon2`, `sha3`, `hkdf`, etc.) and CLI dependencies (`rustyline`, `rpassword`). These are fine as exemptions for now and can be cleared over time via manual review.

## CI integration

Add `cargo vet` to your CI pipeline. It exits non-zero when any dependency lacks an audit or exemption, blocking PRs that introduce unreviewed code.
