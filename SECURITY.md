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
- **Hardened extraction is unified across Linux, macOS, and Windows.**
  Every directory open is anchored to a `cap-std` directory handle and
  refuses any symlink at any component (via
  `cap_fs_ext::DirExt::open_dir_nofollow`). On Windows, directory opens
  additionally reject any NTFS reparse point — including junctions and
  mount points — via an explicit `FILE_ATTRIBUTE_REPARSE_POINT`
  post-check. File creation uses `OpenOptions::create_new(true)` plus
  an explicit `FollowSymlinks::No` flag. Permissions are always set on
  an open handle, never via a re-resolved path. The same code path
  applies on every supported OS.
- **Windows final-rename is atomic no-clobber for single-file
  decrypts; directory decrypts still have a tiny race window.** When
  decryption finishes, FerroCrypt renames the working `.incomplete`
  entry to its final name. On Linux and macOS, the operating system
  refuses this rename atomically if the final name is already taken —
  no window for another process to interfere. On Windows:
  **single-file** decrypts now route through the kernel's atomic
  no-replace move (`MoveFileExW` without the replace flag, via the
  `tempfile` crate), so the kernel performs the existence check and the
  rename together as a single operation and no race window exists.
  **Directory** decrypts on Windows still use the older "check, then
  rename" sequence: a process that creates the final directory name in
  the brief window between the check and the rename has its entry
  silently overwritten by ours. The decrypted
  contents still land where you asked — Windows renames don't follow
  symbolic links, so plaintext is never redirected somewhere
  unexpected — and the worst case for the directory path is that
  someone else's planted entry in your output folder is destroyed
  (integrity, not confidentiality). This matters only when an
  untrusted local process can write to your output folder; typical
  per-user folders are not reachable. Closing the directory window
  fully would require unsafe Windows API code, which the crate
  currently forbids (`#![forbid(unsafe_code)]`).
- **Pre-v1 files are not forward-compatible.** Older FerroCrypt files
  and key pairs use a different format family. Decrypt them with the
  release that produced them and re-encrypt with the current release.
