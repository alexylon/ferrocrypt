# Contributing

Thank you for contributing to FerroCrypt.

FerroCrypt is security-sensitive Rust software. Please optimize for correctness, clarity, maintainability, and misuse resistance. When in doubt, prefer the design that is easier to explain, review, and audit.

---

## Repository layout

- `ferrocrypt-lib` — core encryption library
- `ferrocrypt-cli` — CLI frontend
- `ferrocrypt-desktop` — Slint desktop app
- `ferrocrypt-lib/tests` and `ferrocrypt-cli/tests` — integration tests
- `ferrocrypt-lib/FORMAT.md` — encrypted-file and key-file format specification

### Workspace note

The Cargo workspace currently includes:

- `ferrocrypt-lib`
- `ferrocrypt-cli`

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
./fmt.sh
cargo test -- --test-threads=1
cargo clippy --workspace --all-targets -- -D warnings
```

### Desktop changes (`ferrocrypt-desktop`)

```bash
./fmt.sh
(cd ferrocrypt-desktop && cargo build)
(cd ferrocrypt-desktop && cargo clippy --all-targets -- -D warnings)
```

If you changed desktop behavior, also manually verify the important user flows:

- symmetric encrypt
- symmetric decrypt
- hybrid encrypt
- hybrid decrypt
- key generation
- key validation / fingerprint display

### Documentation-only changes

In general, doc-only changes do not require code build/test steps.
If you changed rustdoc examples or documentation that depends on generated output, run the relevant checks for that surface.

### Dependency changes

If `cargo-audit` is installed locally, run:

```bash
cargo audit
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
- rustdoc / examples — public API changes

Documentation should match actual behavior, defaults, limitations, and compatibility guarantees.

---

## Pull request checklist

Before opening or merging a PR, verify that:

- [ ] the change follows the principles above
- [ ] formatting has been run (`./fmt.sh`)
- [ ] relevant build/test/clippy checks were run
- [ ] no new panic paths were introduced in normal flows
- [ ] no secrets can leak through logs, errors, or debug output
- [ ] malformed input is handled safely
- [ ] tests cover the important behavior
- [ ] `CHANGELOG.md` was updated under `[Unreleased]` when appropriate
- [ ] `ferrocrypt-lib/FORMAT.md` was updated if format or compatibility changed
- [ ] `README.md` or API docs were updated if behavior changed

---

## Release notes

For release steps, see `RELEASE.md`.