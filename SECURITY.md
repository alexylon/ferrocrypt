# Security Policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:

https://github.com/alexylon/ferrocrypt/security/advisories/new

Please include:

- the affected version (`ferrocrypt --version` for the CLI or desktop app, or
  the crate version if integrating the library);
- the host platform and architecture;
- a minimal reproducer (input bytes, command, or test case);
- the impact you observed.

## Supported versions

FerroCrypt is pre-1.0. Security fixes target the latest released minor
series.

| Version    | Security fixes                                        |
|------------|-------------------------------------------------------|
| 0.3.x      | Supported once 0.3.0 ships.                           |
| ≤ 0.2.x    | Best-effort migration guidance only; no patches.      |

When 0.4.x or later ships, the previous 0.x.y series will receive critical
fixes for one minor cycle and then transition to migration-only.

## Audit status

FerroCrypt has not undergone an independent third-party security audit.
The [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) AEAD
crate that handles payload encryption was [audited by NCC Group](https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/).

The current on-disk format is FerroCrypt v1 (wire-version byte `0x01`).
Public conformance test vectors are deferred to the v1.0 release. Until
then, the canonical references are
[`ferrocrypt-lib/FORMAT.md`](ferrocrypt-lib/FORMAT.md) and the in-tree
fixture suite under `ferrocrypt-lib/tests/fixtures/` (an internal
regression net, regenerated when the format intentionally changes).

## Known limitations

- **No sender authentication.** Public-key encryption controls who can
  decrypt a file, not who created it. Sender authentication requires a
  separate signing layer.
- **Not a backup or archive metadata format.** Directory encryption
  preserves file contents, directory structure, and Unix file
  permissions only. Ownership, timestamps, ACLs, extended attributes,
  hardlink identity, setuid/setgid/sticky bits, and platform-specific
  metadata are not preserved.
- **Partial plaintext on decrypt failure.** Authenticated chunks are
  released to disk as they verify. If a later chunk fails
  authentication, partial plaintext may remain in a sibling
  `.incomplete` working copy. The final output path is never written
  on a failed decrypt.
- **Hardened extraction is Linux- and macOS-only.** Linux and macOS use
  directory-fd-anchored `openat` / `mkdirat` with `O_NOFOLLOW` to
  resist local symlink and path-component-race attacks. On Windows,
  extraction is best-effort against local filesystem races; on shared
  Windows machines, choose an output directory writable only by the
  current user.
- **Pre-v1 files are not forward-compatible.** Older FerroCrypt files
  and key pairs use a different format family. Decrypt them with the
  release that produced them and re-encrypt with the current release.
