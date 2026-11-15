# Contributing

Thank you for contributing to FerroCrypt.

FerroCrypt is security-sensitive Rust software. Please optimize for correctness, clarity, maintainability, and misuse resistance. When in doubt, prefer the design that is easier to explain, review, and audit.

---

## Repository layout

- `ferrocrypt-lib` — core encryption library
- `ferrocrypt-cli` — CLI frontend
- `ferrocrypt-desktop` — Slint desktop app
- `ferrocrypt-test-support` — helpers the tests share, not published
- `ferrocrypt-lib/tests` and `ferrocrypt-cli/tests` — integration tests
- `ferrocrypt-lib/FORMAT.md` — encrypted-file and key-file format specification
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — security guarantees, their assumptions, and when a finding blocks a release

### Workspace note

The Cargo workspace currently includes:

- `ferrocrypt-lib`
- `ferrocrypt-cli`
- `ferrocrypt-test-support`

`ferrocrypt-desktop` is outside the workspace and must be built and checked separately when changed.

---

## Core principles

- Prefer correctness over cleverness.
- Prefer clarity over terseness.
- Prefer safe defaults over flexible but dangerous behavior.
- Prefer explicit design over accidental behavior.
- In security-sensitive code, favor misuse resistance over abstraction elegance.

If a design is hard to reason about, simplify it.

---

## Before you open a PR

Run the checks that match your change.

### Workspace changes (`ferrocrypt-lib`, `ferrocrypt-cli`)

```bash
./scripts/fmt.sh
./scripts/check_terminology.sh
cargo test -- --test-threads=1
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --package ferrocrypt --features unstable-fuzzing --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --package ferrocrypt-cli
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --exclude ferrocrypt-cli
```

If you changed the public API of `ferrocrypt-lib`, also run the API check CI
runs; [`RELEASE.md`](RELEASE.md) explains it. If you changed the format
corpus under `ferrocrypt-lib/testvectors/wire/`, run
`python3 ferrocrypt-lib/testvectors/wire/tools/verify_manifests.py`.

### Desktop changes (`ferrocrypt-desktop`)

```bash
./scripts/fmt.sh
(cd ferrocrypt-desktop && cargo build)
(cd ferrocrypt-desktop && cargo clippy --all-targets -- -D warnings)
(cd ferrocrypt-desktop && cargo clippy --all-targets --features mcp -- -D warnings)
(cd ferrocrypt-desktop && cargo test -- --test-threads=1)
```

If you changed desktop behavior, also manually verify the important user flows:

- encrypt and decrypt with a password (the Password tab)
- encrypt with a public key and decrypt with a private key (the Key pair tab)
- create a key pair
- key validation and fingerprint display
- the progress bar during a long operation
- the same flows with the keyboard alone, and with a screen reader

An agent or a script can drive these flows too: `scripts/desktop_mcp.py run` starts a development build with Slint's MCP server on, and `scripts/desktop_mcp.py` lists the commands that click, type, choose files, and take screenshots.

### Documentation-only changes

Doc-only changes need no build or tests, but run `./scripts/check_terminology.sh`:
CI checks the wording of the main docs.
If you changed rustdoc examples or documentation that depends on generated output, run the relevant checks for that surface.

### Dependency changes

Every new or updated dependency of the workspace must pass `cargo vet`, which
CI runs. Also check for known advisories, as CI does:

```bash
cargo vet
cargo audit
cargo audit --file ferrocrypt-desktop/Cargo.lock
```

---

## Rust guidelines

- Use idiomatic Rust naming and structure.
- Keep modules focused.
- Prefer explicit, readable control flow over clever shortcuts.
- Avoid magic strings and numbers where named constants or strong types improve clarity.
- Avoid boolean parameter traps; prefer enums or option structs when appropriate.
- Design public APIs intentionally; keep them small and hard to misuse.
- Make invalid states unrepresentable where practical.

### Error handling

- Use typed errors.
- Propagate errors with useful context.
- Do not introduce silent fallback behavior in security-sensitive code.
- Avoid panics in library code except for impossible internal invariants.
- Do not leave `unwrap()` or `expect()` in normal runtime paths.
- Errors must not leak secrets.

### Comments and documentation

- Do not add comments that merely restate the code.
- Add comments for invariants, security assumptions, wire-format details, and non-obvious logic.
- Keep documentation aligned with actual behavior.

---

## Cryptography and security rules

- Never invent cryptography.
- Use well-reviewed constructions and maintained crates.
- Prefer authenticated encryption.
- Treat all external input as adversarial.
- Fail closed: malformed, ambiguous, truncated, or unsupported input must error.
- Never log, print, or serialize secrets unintentionally.
- Do not expose secrets in errors, debug output, crash output, or telemetry.
- Minimize secret lifetime in memory.
- Use zeroization where practical for passwords, keys, and derived secrets.
- Use constant-time comparison for secret-dependent equality checks where relevant.
- Nonces, salts, and KDF parameters must follow the safety requirements of the chosen primitive.
- Do not silently weaken defaults, compatibility guarantees, or security properties.

### Format changes

Any change affecting encrypted-file format, key-file format, metadata layout, header semantics, or compatibility must update:

- `ferrocrypt-lib/FORMAT.md`
- `README.md` if user-visible behavior changed
- `CHANGELOG.md` under `[Unreleased]`

The public conformance corpus under `ferrocrypt-lib/testvectors/wire/` is frozen:
new cases go into a later corpus revision, and a frozen case is never edited or
regenerated around changed behavior (`FORMAT.md` §12).

---

## Area-specific guidance

### Library (`ferrocrypt-lib`)

- Keep parsing, validation, cryptographic operations, and I/O clearly separated.
- Prefer strong types for validated inputs and protocol-relevant values.
- Do not add public API surface casually.
- Keep the safest path the easiest path.

### CLI (`ferrocrypt-cli`)

- CLI behavior should be deterministic and script-friendly.
- Keep output clear and stable.
- Do not print secrets or sensitive derived values.
- Error messages should be useful without exposing sensitive internals.
- Destructive or overwriting behavior must require explicit user intent.

### Desktop (`ferrocrypt-desktop`)

- Keep the UI responsive.
- Move expensive crypto and file I/O off the UI thread when needed.
- Validate user-selected paths and file operations carefully.
- Do not keep secrets in long-lived UI state longer than necessary.
- Prevent accidental data loss in encrypt/decrypt/save/export flows.
- Ensure temporary files, logs, and platform storage do not leak secrets.

---

## Testing expectations

Tests should be:

- deterministic
- self-contained
- focused on important behavior

At minimum, cover relevant combinations of:

- successful encrypt/decrypt round trips
- wrong password or wrong key handling
- corrupted ciphertext handling
- corrupted header handling
- truncated input handling
- format version parsing / compatibility behavior
- empty input behavior
- boundary-sized inputs
- non-ASCII path behavior, if supported

Add regression tests for every security-sensitive bug and every format bug.
Prefer focused unit tests plus a smaller number of high-value integration tests.

---

## Documentation requirements

Update the docs that match your change:

- `README.md` — user-visible behavior, installation, usage, limitations
- `CHANGELOG.md` — add an entry under `[Unreleased]`
- `ferrocrypt-lib/FORMAT.md` — format or compatibility changes
- `ferrocrypt-lib/STRUCTURE.md` — module layout, public API shape, or architectural rules
- rustdoc / examples — public API changes
- [`THREAT_MODEL.md`](THREAT_MODEL.md) and `SECURITY.md` — security-relevant behavior; rule PR-01 in the threat model lists every document such a change must reconcile

Documentation should match actual behavior, defaults, limitations, and compatibility guarantees.

---

## Pull request checklist

Before opening or merging a PR, verify that:

- [ ] the change follows the principles above
- [ ] formatting has been run (`./scripts/fmt.sh`)
- [ ] relevant build/test/clippy checks were run
- [ ] no new panic paths were introduced in normal flows
- [ ] no secrets can leak through logs, errors, or debug output
- [ ] malformed input is handled safely
- [ ] tests cover the important behavior
- [ ] `CHANGELOG.md` was updated under `[Unreleased]` when appropriate
- [ ] `ferrocrypt-lib/FORMAT.md` was updated if format or compatibility changed
- [ ] `README.md` or API docs were updated if behavior changed
- [ ] `THREAT_MODEL.md`, `SECURITY.md`, and `STRUCTURE.md` were reconciled if security-relevant behavior changed (PR-01)

---

## Release notes

For release steps, see `RELEASE.md`.