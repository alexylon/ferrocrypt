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

Dependency review is tracked with `cargo vet`. Several core crypto crates
are covered by imported audits or maintainer-approved exemptions rather than
first-party audits by this project, so a passing `cargo vet` run means the
configured supply-chain policy is satisfied; it is not an independent audit
of each cryptographic dependency by the FerroCrypt project.

The current stored formats are `.fcr` outer-container version `0x01`,
FCA archive version `0x01`, public-key encoding version `0x01`, and
private-key encoding version `0x01`.
Public conformance test vectors are published with stable FerroCrypt
release 0.3.0. The canonical references are
[`ferrocrypt-lib/FORMAT.md`](ferrocrypt-lib/FORMAT.md) and the in-tree
fixture suite under `ferrocrypt-lib/tests/fixtures/` (an internal
regression net, regenerated when the format intentionally changes).

## Known limitations

- **No sender authentication.** Public-key encryption controls who can
  decrypt a file, not who created it. Sender authentication requires a
  separate signing layer.
- **A recipient's public key is only as trustworthy as the fingerprint
  you checked.** FerroCrypt cannot tell whose key a `public.key` file
  holds. Compare the SHA3-256 fingerprint with the recipient over a
  channel an attacker cannot rewrite before you encrypt to that key. The
  fingerprint the command line prints and the one the desktop app shows
  describe the key material those operations then use, so a key file
  replaced afterwards cannot change the recipient behind your back. A
  library caller gets the same guarantee by keeping the `PublicKey` value
  it fingerprinted, rather than passing the path again.
- **A passphrase typed into the desktop app stays in memory until the
  app exits.** FerroCrypt wipes every passphrase it holds itself: the
  library clears one as soon as the operation stops needing it, and the
  command line keeps its prompt in memory that is wiped on every exit
  path, including when a confirmation does not match. The desktop app
  cannot do the same for the text in its password field. The
  user-interface toolkit it is built on stores that text in a string
  type that copies on every edit and wipes nothing when it releases a
  copy, so fragments of what you typed remain in released memory for as
  long as the app runs. Clearing the field does not remove them, and the
  toolkit offers no way to reach those buffers, so this cannot be fixed
  from FerroCrypt's side. Reading them requires access to the app's
  memory — a crash dump, a swap file, or a separate flaw that discloses
  memory. Where that exposure matters, use the command line, and quit
  the desktop app when you have finished rather than leaving it open.
- **A passphrase supplied through the environment is readable for as
  long as the command runs.** The command line never accepts a
  passphrase as an argument, but it does read one from
  `FERROCRYPT_PASSPHRASE` so that scripts and continuous integration can
  run unattended. FerroCrypt wipes the copy it takes from that variable;
  it cannot wipe the variable. The value stays in the process
  environment until the process exits, where another process running as
  the same user can read it, and if it was exported, everything else
  that shell starts inherits it. Depending on how it was set it may also
  reach shell history or a build log. Unlike the desktop field above,
  this one has a remedy: use the interactive prompt, which keeps the
  passphrase only in memory FerroCrypt wipes. Reserve the variable for
  runs where no terminal exists, and treat a passphrase passed that way
  as visible to anything running as you.
- **No freshness or replay protection.** FerroCrypt authenticates each
  file as written, but it does not know whether that file is the newest
  version. A captured valid `.fcr` can be restored or replayed later
  without detection. Use external versioning or a freshness check if
  rollback/replay matters.
- **Not fully metadata-hiding.** FerroCrypt encrypts file contents and,
  for directory inputs, the internal names, tree structure, and
  per-file sizes. It does not hide the total ciphertext length (an
  approximate plaintext-size signal), the recipient count, or the fact
  that the file is a FerroCrypt `.fcr` container.
- **Not a backup or archive metadata format.** Directory encryption
  preserves file contents, directory structure, and Unix file
  permissions only. Ownership, timestamps, ACLs, extended attributes,
  hardlink identity, setuid/setgid/sticky bits, and platform-specific
  metadata are not preserved.
- **Decryption can fail on a filesystem that ignores letter case in
  names beyond ASCII.** FerroCrypt refuses to create or decrypt an
  archive that contains two paths differing only in ASCII letter case
  (`Report.txt` and `REPORT.TXT`) or only in Unicode spelling — the
  same visible name written as one composed character or as a base
  letter plus a separate accent mark. What remains is letter case
  beyond ASCII: `Ärzte.txt` and `ärzte.txt` are visibly distinct
  names, so they stay archivable, but Windows and most Macs treat
  them as the same name, and which names a filesystem equates this
  way depends on its own per-volume rules, so no up-front check can
  cover them all. Such a pair can exist — and encrypt — only on a
  filesystem that keeps the names apart, typically on Linux.
  Decrypting the result on a filesystem that equates them stops with
  an error naming the colliding entry: creating the second name is
  refused, nothing already on disk is overwritten, and the final
  output path is never written. Decrypt on a filesystem that keeps
  the names apart, or rename one of the pair and re-encrypt.
- **Partial plaintext on decrypt failure.** Authenticated chunks are
  released to disk as they verify. If a later chunk fails
  authentication, partial plaintext may remain in a sibling
  `.incomplete` working copy. A failure before final promotion does not
  write the final output path. A later filesystem namespace check can
  still report an error after the complete output was committed; that
  post-commit error does not delete the confirmed output by name.
- **Hardened extraction is unified across Linux, macOS, and Windows.**
  Every directory open is anchored to a `cap-std` directory handle and
  refuses any symlink at any component (via
  `cap_fs_ext::DirExt::open_dir_nofollow`). On Windows, directory opens
  additionally reject any NTFS reparse point — including junctions and
  mount points — via an explicit `FILE_ATTRIBUTE_REPARSE_POINT`
  post-check. File creation uses `OpenOptions::create_new(true)` plus
  an explicit `FollowSymlinks::No` flag. Permissions are always set on
  an open handle, never via a re-resolved path. This symlink and
  reparse-point hardening is the same code path on every supported OS.
  On Linux and macOS the final rename that commits the staged output to
  its requested name is anchored to that same handle as well, so a swap
  of the output directory during the run cannot redirect the commit; on
  Windows that final rename is path-based (see the next item).
- **Windows final-rename is atomic no-clobber for single-file
  decrypts; directory decrypts still have a tiny race window.** When
  decryption finishes, FerroCrypt renames the working `.incomplete`
  entry to its final name. On Linux and macOS, the operating system
  refuses this rename atomically if the final name is already taken. On
  filesystems whose
  driver cannot do that in one step (Apple's exFAT driver, some network
  filesystems), any single **file** FerroCrypt commits — a decrypted
  file, an encrypted file, or a generated key file — is instead linked
  to its final name and the working name removed: creating a link
  refuses an existing entry atomically, so there is no replaceable
  placeholder at the final name. FerroCrypt does not trust the subsequent
  unlink alone: another directory writer could move the working link and
  make the unlink report it missing, or plant a replacement that the unlink
  removes instead. Before success, FerroCrypt reads the committed inode's
  link count through its retained handle and requires exactly one link.
  The same requirement applies when the commit is performed inside the
  platform file library, which on some mounts (Linux network and FUSE
  filesystems among them) falls back to a hard link of its own without
  reporting how its working-name removal went.
  If the working name cannot be removed, the link count cannot be read, or
  another link remains, the final name is already a complete commit.
  FerroCrypt does not withdraw it: the cleanup may have taken long enough
  for another writer to replace that entry, and removing it by name could
  delete the replacement. Instead the operation completes its identity
  checks and returns an explicit post-commit error. Complete content may
  remain under the final name and under a temporary or moved second name,
  which must be inspected manually. This applies to decrypted files,
  encrypted files, and generated key files. A decrypted **folder**
  cannot be linked, and neither can anything on a filesystem without
  hard links (exFAT again). Those cases claim the final name by creating
  it — creation refuses an existing entry atomically — and then rename
  the finished output over their own claim. An entry that existed before
  the commit is still never replaced. The remaining differences: a
  process killed between the two steps can leave an empty placeholder
  at the final name next to the `.incomplete` entry, and a local
  process with write access to your output folder that deletes the
  claim and plants its own entry inside that brief window has its
  planted entry replaced by ours — the same "someone else's planted
  entry may be destroyed" bound, and the same trust assumption, as the
  Windows directory case below. Both fallback commits anchor to your
  output folder: FerroCrypt opens the folder once and performs the link,
  the claim, the final rename, and its own cleanup through that one
  handle, so renaming the folder mid-commit cannot redirect any step.
  The folder must therefore be one FerroCrypt can read and not only
  write into: a write-only output folder on a filesystem without the
  one-step rename cannot be committed into at all. On Windows:
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
- **A freshly decrypted single file on Windows starts with its archive
  attribute cleared.** The atomic no-replace move described above clears
  the file's attributes as part of the operation. Nothing the format
  promises is lost — FerroCrypt's archive format does not carry Windows
  attributes, and the file's content, name, and access rights are
  unaffected — but incremental backup tools read a clear archive bit as
  "already backed up" and may skip the file until it changes again. Set
  the attribute yourself if your backup schedule depends on it.
- **An output folder another local process can change is a trust
  boundary.** FerroCrypt writes each output under a temporary name in
  the folder you chose and commits it there. Encryption and key generation
  retain the committed file handle and check immediately before return that
  each reported path still denotes that file; Linux and macOS decryption
  performs the matching directory and output identity checks. Before
  success, every file commit also requires, through that retained handle,
  that the committed file has exactly one name, so a hard-link fallback
  that left its working name, or a link another local process created
  against the temporary file before the commit, is reported rather than
  hidden. A swap detected there returns an error and leaves the entry currently at the
  reported path untouched. If the original file or folder was moved, the
  complete output remains under that new name. If it was removed without
  another name or hard link, the retained handle permits detection but does
  not make the output recoverable after the call returns. No path can remain
  stable against a namespace change made after the check or after the call
  returns. These checks compare the identifiers the filesystem itself
  assigns — inode numbers on Unix, the volume serial number and file index
  on Windows — between objects that both still exist when the comparison
  runs, so an identifier reused later cannot satisfy them. ReFS reports a 64-bit
  truncation of its wider identifier, and a filesystem that gives every
  object the same identifier, as some network redirectors do, makes the
  checks detect nothing there rather than fail. What such a swap cannot do is misdirect a cleanup: when key
  generation has to undo a key file it already wrote, it removes that file
  through a handle held on the folder the file actually went to, and only
  while the entry there is still the file it wrote, so a same-named file
  elsewhere is not deleted. On Windows that removal goes through the
  folder's current path, resolved from the handle immediately before, so
  only a swap made in that last instant is outside this protection. Choose
  an output folder that only you can modify.
- **Generated key pairs publish `private.key` before `public.key`.** Key
  generation writes and flushes both files before either receives its
  final name. It then commits `private.key`, flushes the output
  directory, commits `public.key`, and flushes the directory again.
  Process interruption therefore cannot leave a usable `public.key`
  without its matching `private.key`. On filesystems that support
  directory flushing, the same guarantee covers power loss. A flush
  failure stops key generation and removes any unsafe partial result;
  after a failure following the `public.key` commit, a lone
  `private.key` may remain and is safe to delete. If that removal cannot
  be confirmed — the key file was replaced during the operation, or it
  still had another name — the error says so. Filesystems that do
  not support directory flushing depend on their own ordering after
  power loss. Key generation opens your output folder for its rollback
  anchoring and its directory flushes, so it needs a folder it can read
  and not only write into.
- **Files from releases before 0.3.0 are not compatible.** Older
  FerroCrypt files and key pairs use a different format family. Decrypt
  them with the release that produced them and re-encrypt with the
  current release.
