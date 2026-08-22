# FerroCrypt threat model

**Initial compatibility baseline:** stable FerroCrypt 0.3.0

**Scope:** ferrocrypt-lib, ferrocrypt-cli, ferrocrypt-desktop, .fcr
containers, FCA archives, public.key, and private.key

This document is FerroCrypt's authoritative security boundary and release
classification standard. It defines what FerroCrypt protects, the conditions
under which those protections apply, what FerroCrypt does not promise, and
which confirmed violations block a release.

The terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative. A stable
release beginning with 0.3.0 MUST conform to every applicable requirement in
this document. This document does not certify an untagged development build,
alpha, beta, or release candidate; a non-conforming development revision is
classified under section 6 before a stable release can ship.

Related canonical documents have separate responsibilities:

- [FORMAT.md](ferrocrypt-lib/FORMAT.md) specifies stored bytes and format
  processing.
- [STRUCTURE.md](ferrocrypt-lib/STRUCTURE.md) specifies code architecture and
  implementation invariants.
- [SECURITY.md](SECURITY.md) explains vulnerability reporting, supported
  release lines, audit status, and user-facing limitations.

This document governs security scope and release classification. A
contradiction between canonical documents is a documentation defect under
PR-01; it is not permission to select the weaker statement.

## 1. Review use

A security review MUST classify each confirmed finding as follows:

1. Cite the exact TM identifier whose guarantee, assumption, or boundary is
   relevant.
2. State the attacker capability, deployment profile, platform, filesystem,
   timing, and configuration required for the demonstrated effect.
3. If those conditions are in scope, identify the violated MUST or MUST NOT
   and apply sections 5 and 6.
4. If a required condition is explicitly outside scope, classify the item as
   out of scope. It MAY be recorded separately as defence-in-depth hardening,
   but it is not a product defect under this model.
5. If neither result is possible, the model is incomplete. Extend it
   deliberately before assigning a severity.

A review MUST distinguish a confirmed vulnerability from a hypothetical gap.
It MUST also distinguish an implementation defect from documentation drift,
test-coverage work, compatibility-only behaviour, and optional hardening.

The following terms are used throughout:

| Term | Meaning |
|---|---|
| Attacker-controlled artefact | Any .fcr byte, authenticated FCA content, archive path or mode, recipient string, public.key, or private.key supplied by another party. Authentication does not make the sender trusted. |
| Local writer | A process that can create, rename, link, replace, or delete entries in a relevant directory while FerroCrypt is running. |
| Supported environment | One of the operating-system and filesystem combinations named by TM-15. |
| Compatibility-only environment | An environment in which FerroCrypt may operate but does not promise the full filesystem-security properties of the named supported set. |
| Staged output | Plaintext or ciphertext written under a temporary or .incomplete name before final publication. |
| Committed output | A complete output made visible at its requested final name. An error may still occur after this point. |
| Normal returned error | An error returned through the operation's documented result type, excluding process termination, abort, power loss, and an unwind that does not complete. |
| Fail closed | Stop without accepting unauthenticated data, crossing an in-scope containment boundary, overwriting a protected entry, or reporting an unverified result as success. |

## 2. Protected properties

### TM-01 — Content confidentiality

**FerroCrypt MUST keep plaintext, passphrases, private keys, file keys, and
derived keys from a party that lacks the required credential, subject to
TM-10 and TM-11.**

Ciphertext length, recipient count, and the fact that an artefact is a
FerroCrypt file are not confidential. Public-key encryption does not
authenticate the sender.

### TM-02 — Artefact integrity

**FerroCrypt MUST reject an altered, truncated, extended, structurally
ambiguous, or unauthenticated .fcr or private.key artefact before reporting it
as successfully authenticated.**

The header MAC is verified before authenticated header metadata is acted on.
Payload chunks are authenticated before their plaintext is released. FCA
metadata and content are protected by the outer authenticated payload stream.
A malicious sender who can create a valid recipient entry can still choose the
plaintext, archive names, modes, and tree.

### TM-03 — Public-key validity and recipient binding

**FerroCrypt MUST reject malformed or checksum-invalid public keys, and a
PublicKey value that it fingerprints MUST resolve to the same key material
later used for encryption.**

Public-key checksums detect accidental corruption; they do not detect a valid
key substituted by an attacker. FerroCrypt does not establish who owns a key.
The user or caller MUST verify the fingerprint through a channel an attacker
cannot rewrite.

### TM-04 — Adversarial parsing and resource gates

**FerroCrypt MUST treat every external length, count, path, flag, KDF
parameter, and extension as hostile, use checked arithmetic, and enforce the
configured structural and resource limits before the corresponding
allocation, expensive operation, or filesystem output.**

Per-operation limits do not bound aggregate service load. Service admission and
concurrency obligations are defined by TM-16 and TM-17.

### TM-05 — Archive containment and no-clobber

**Within the selected output-directory and supported-environment profiles,
FerroCrypt MUST keep extraction beneath the selected output directory, refuse
unsafe paths and unsupported object types, avoid following archive-provided
symlinks or reparse points, and refuse to overwrite an entry that existed
before the final commit began.**

FCA version 0x01 represents regular files, directories, portable relative
paths, file content, and Unix permission bits only.

### TM-06 — Outcome truth

**Within the selected profiles, a successful operation MUST report a path that
names its own complete output, and an error MUST NOT be described as proof that
nothing was written unless the applicable API contract provides that
guarantee.**

Post-commit errors are a first-class state. An error returned after complete
output became visible MUST identify that consequence clearly enough for a
caller to avoid discarding or overwriting the output. An explicit statement in
the returned error text that the output is complete satisfies this requirement;
TM-06 does not require a dedicated typed post-commit variant.

### TM-07 — Writer and reader symmetry

**Under the same configuration, FerroCrypt MUST NOT write an artefact that its
matching reader rejects.**

Writer-side path, grammar, structure, mixing, KDF, header, TLV, and resource
checks MUST mirror the reader. A writer-only KDF minimum MAY strengthen newly
created passphrase artefacts without making older structurally valid artefacts
unreadable.

### TM-08 — Stable-format compatibility

**Every release after stable 0.3.0 MUST continue to read every valid artefact
in the 0.3.0 compatibility baseline and MUST preserve its security rejection
rules.**

Alpha, beta, release-candidate, and untagged development artefacts are not part
of this cross-release promise.

### TM-09 — Source-tree consistency

**FerroCrypt MUST produce a self-consistent archive or fail when a source
object changes in a way that FORMAT.md section 9.10 requires it to detect, but
a caller requiring a point-in-time snapshot MUST prevent concurrent source
mutation or provide a snapshot filesystem.**

Where the platform and filesystem provide usable stable identity, FerroCrypt
checks it as specified. A platform whose directory listing exposes no usable
identity (Windows today), or a compatibility-only filesystem that supplies
none, omits the identity confirmation and relies on the no-follow,
reparse-safe, type, and length checks permitted by FORMAT.md section 9.10.

### TM-10 — Credential and cryptographic assumptions

**The caller MUST keep passphrases and private keys secret, verify recipient
fingerprints, choose adequate passphrases, and rely on a sound
operating-system random generator and sound implementations of the
cryptographic constructions specified by FORMAT.md.**

Breaking a primitive, compromising the random generator, substituting the
running binary or its dependencies, or obtaining a credential by another
channel is outside FerroCrypt's protection.

### TM-11 — Host integrity

**FerroCrypt MUST assume that its own process, kernel, and trusted hardware are
not already controlled by the attacker.**

A party that can read or alter process memory, trace the process, replace
system calls, or administer the host can read plaintext or credentials
directly. FerroCrypt SHOULD still minimise secret lifetime and wipe the secret
buffers it owns as defence in depth.

## 3. Trust and deployment assumptions

### TM-12 — Trusted output namespace

**The caller MUST choose an output directory and path ancestry that no
untrusted process can modify from the start of the operation until it
returns.**

Users MUST select a private per-user or per-operation directory. A shared,
attacker-writable directory or attacker-controlled mount does not satisfy this
assumption. A finding that requires an untrusted local writer to mutate only
that selected namespace is out of scope unless the effect crosses outside it
or harms an object that the writer could not otherwise reach.

This trust assumption does not relax archive containment, no-clobber protection
for pre-existing final entries, cleanup ownership, or outcome truth.

### TM-13 — Local-race defence in depth

**FerroCrypt MUST keep its existing reliable local-race protections, but a gap
that matters only when TM-12's trusted-directory assumption is broken MUST be
classified as non-blocking hardening.**

Reliable, bounded retained-handle, no-follow, exclusive-creation, identity,
link-count, anchored-cleanup, and final-verification protections remain useful
defence in depth. Any later removal or simplification MUST be a separate,
bounded change that proves it does not weaken an in-scope containment,
no-clobber, durability, cleanup-ownership, or outcome-truth guarantee.

### TM-14 — Failed-decrypt cleanup

**After a normal returned decrypt error in a supported environment,
DeleteOnError MUST overcome cleanup obstacles created by the current run,
including permissions it applied to its own staged tree; if an environmental
failure outside FerroCrypt's control prevents confirmed removal, the returned
error MUST state that plaintext may remain and identify the working path.**

An externally changed permission, an unmounted filesystem, a storage or I/O
failure, or an equivalent condition outside the operation's control is an
environmental failure. A restrictive mode that FerroCrypt applied to an object
it created is not.

RetainOnError intentionally leaves the staged tree for the caller. A completed
panic unwind receives best-effort cleanup; process abort, SIGKILL, power loss,
and an unwind that does not complete have no cleanup guarantee. A pre-existing
.incomplete entry MUST NOT be reused or deleted automatically and continues to
block a retry.

Failure cleanup MUST NOT remove an object that the current run did not create.
Once FerroCrypt has confirmed a root as committed output, a later post-commit
error MUST preserve that output rather than remove it by name and MUST report
the resulting state under TM-06.

### TM-15 — Supported filesystems and evidence availability

**FerroCrypt MUST provide its filesystem security guarantees on Linux with
ext4, macOS with APFS, and Windows with NTFS.**

Every other filesystem is compatibility-only. FerroCrypt MAY reject an
operation there, omit an identity check that the environment cannot support,
or provide weaker race-resistance, mode, and durability checks. Existing
fallback behaviour MAY continue without an up-front capability detector or a
new user-visible refusal. Compatibility-only status is never permission to
overwrite a pre-existing final entry: a name collision encountered during
exclusive creation or promotion MUST fail closed.

The cryptographic and wire-format guarantees remain independent of the
filesystem tier. The named supported set MAY be expanded only by an explicit
policy decision backed by qualification evidence.

**A filesystem check required by an in-scope guarantee in a supported
environment MUST fail the operation if it cannot produce meaningful evidence;
a defence-in-depth or compatibility-only check MAY be skipped, but absent,
unreadable, all-zero, truncated, or otherwise non-distinguishing evidence
MUST NOT be treated as confirmation.**

This availability rule classifies evidence a check actually returns; it does
not require an up-front filesystem detector. Case-folding or other
filesystem-specific name collisions not caught by portable preflight MUST fail
closed during exclusive creation. FerroCrypt does not promise to extract every
Unicode name on every volume.

### TM-16 — Process and resource profiles

**Interactive applications MUST use the trusted-conditions profile, while
unattended services MUST set explicit resource limits, bound concurrency,
isolate KDF work where necessary, and receive fail-closed operation results
within those budgets.**

In the trusted-conditions profile, the caller MUST provide adequate memory and
descriptors, avoid hostile same-user interference, and configure limits within
the resources available to the operation. Ordinary EMFILE, ENFILE, ENOMEM,
allocator failure, or caller-raised limits are operating failures rather than
vulnerabilities by themselves. They MUST NOT become false authentication,
unsafe cleanup, an in-scope containment failure, or false success. A required
filesystem check follows TM-15 when its resource is unavailable.

Concurrent operations targeting the same final name MUST preserve the
applicable no-clobber guarantee.

### TM-17 — Protected-user profiles

**FerroCrypt MUST define an interactive profile and a service profile that
both satisfy TM-12, and every security review MUST state which profile a
finding affects.**

The profiles differ in deployment and resource obligations, not in
output-namespace trust:

- The interactive profile covers an individual and same-authority automation
  using private input and output locations.
- The service profile accepts untrusted encrypted input only in isolated
  per-operation work areas, with explicit caps, bounded concurrency, isolated
  KDF work where necessary, and no greater filesystem authority than the
  submitting tenant.

A privileged helper decrypting into a shared attacker-writable namespace is
outside both profiles unless it provides stronger isolation independently.
Both profiles receive the same cryptographic, parsing, archive-containment,
and pre-existing-entry no-clobber guarantees.

### TM-18 — Attacker-controlled display text and FCA path grammar

**In addition to U+0000–U+001F, FCA path components MUST reject U+007F,
U+0080–U+009F, U+2028, U+2029, U+202A–U+202E, and U+2066–U+2069. The
direction marks U+061C, U+200E, and U+200F are accepted.**

Writers and readers MUST enforce this rule symmetrically. Ordinary Arabic,
Hebrew, and other right-to-left names remain valid; they do not require the
rejected span controls. The rule is a deliberate compromise between security
and fidelity, not a filesystem restriction: the supported filesystems accept
every listed code point. The span controls are rejected because an override
can reverse the displayed letters of a name. The marks are accepted because
word processors leave them in mixed-direction text, so refusing them refuses
legitimate names; a mark cannot reverse letters, but it can still move
punctuation or digits across a right-to-left run in a display FerroCrypt does
not control. Changing this rejection set after stable 0.3.0 requires the
compatibility and versioning analysis required by TM-08 and FORMAT.md.

The CLI and desktop app SHOULD escape or otherwise render
attacker-controlled paths without terminal control or misleading bidirectional
display, including the three accepted marks. A library path result remains
data rather than display text; an embedder that presents it to a user SHOULD
apply equivalent rendering. These presentation protections are defence in
depth in addition to the grammar, and the only protection against the marks.

### TM-19 — Authority and publication

**The top-level THREAT_MODEL.md MUST remain FerroCrypt's authoritative public
threat model and MUST be linked from SECURITY.md and the repository review
instructions.**

An internal review rule MUST NOT be used to dismiss a violation of a stronger
public promise.

## 4. Explicit non-goals and retained limitations

The following properties are not promised:

- **NG-01 — Sender authentication.** FerroCrypt does not prove who created an
  encrypted file. Signing is a separate layer.
- **NG-02 — Key ownership.** FerroCrypt does not prove whose key was loaded.
  The fingerprint MUST be verified out of band.
- **NG-03 — Freshness and replay.** A valid older .fcr file can be restored or
  replayed without detection.
- **NG-04 — Full metadata hiding.** Ciphertext length, recipient count, and the
  FerroCrypt container signature remain observable.
- **NG-05 — Complete archive metadata.** FCA version 0x01 does not preserve
  ownership, timestamps, ACLs, extended attributes, hardlink identity,
  symlinks, special files, sparse layout, or platform-specific metadata.
- **NG-06 — General archive interoperability.** Raw FCA is neither a
  standalone authenticated format nor a tar or ZIP replacement.
- **NG-07 — Compromised endpoints.** FerroCrypt does not protect secrets from
  a compromised process, kernel, administrator, debugger, crash-dump reader,
  or hardware platform.
- **NG-08 — Post-return namespace stability.** No file path remains stable
  against a rename, replacement, or deletion performed after FerroCrypt's last
  check or after the call returns.
- **NG-09 — Universal filename portability.** Non-ASCII case folding and
  other volume-specific name equivalences can still make extraction fail
  closed.
- **NG-10 — Pre-0.3.0 compatibility.** Earlier format families are not part of
  the stable 0.3.0 compatibility baseline.

These implementation and platform limitations also remain explicit:

- The desktop toolkit can retain copies of a typed passphrase until the
  application exits. Clearing the field cannot reliably wipe those copies.
- FERROCRYPT_PASSPHRASE remains in the process environment until process exit
  and can be read by other same-authority processes. Interactive input is the
  safer path.
- Under the safe-code-only implementation, Windows directory promotion uses
  a check-then-rename sequence, and the owner of a staged directory root is
  not confirmed there as it is on Linux and macOS. A race requiring an
  untrusted writer in the selected output directory is outside TM-12 and
  remains defence in depth under TM-13.
- A freshly decrypted single file on Windows may have its archive attribute
  cleared.
- Filesystems outside the named TM-15 set have compatibility-only identity,
  race-resistance, mode, and durability behaviour. Directory-entry durability
  after power loss depends on filesystem support.
- Key generation publishes private.key before public.key. Process-interruption
  ordering is protected; power-loss ordering requires a working directory
  flush.
- RetainOnError, process termination, power loss, and a reported environmental
  cleanup failure can leave partial or complete .incomplete plaintext. A
  post-commit error can leave complete output at its confirmed or moved name.
  TM-06 and TM-14 govern the required report.

These limitations do not weaken a stronger normative requirement elsewhere in
this document.

## 5. Severity

### 5.1 Required classification axes

Every confirmed finding MUST record these axes before receiving a severity:

| Axis | Required distinctions |
|---|---|
| Protected property | Plaintext or key confidentiality; authentication; authenticated-output or filesystem integrity; containment; availability; cleanup ownership; outcome truth; diagnostics or documentation only |
| Attacker capability | No attacker; artefact sender; local writer; same-user process; filesystem server; host or process control |
| Deployment | Default CLI or desktop; ordinary library call; explicit raised limits; service profile; privileged embedding |
| Reliability | Deterministic; repeatable with notification or scheduling; narrow race; dependent on an unusual driver or coincident fault |
| Environment | Named supported set; compatibility-only filesystem; explicitly unsupported |
| User effect | Silent or signalled; complete or partial; recoverable or irreversible; retry possible or permanently blocked |
| Promise status | Violates an applicable MUST; contradicts public documentation; matches an accepted limitation; defence in depth only |

Severity MUST describe demonstrated impact under realistic prerequisites, not
the most dramatic imaginable embedding. Scope is applied before severity. An
out-of-scope item receives no security severity, although it MAY be tracked as
hardening or compatibility work.

### 5.2 Severity scale

| Severity | Threshold |
|---|---|
| Critical | Practical compromise of keys or plaintext, arbitrary code execution, or broad destructive impact from an attacker-controlled artefact in the default supported profile, with little or no user action |
| High | Practical confidentiality or integrity failure in a default supported profile without host compromise or an explicitly excluded local-writer condition |
| Medium | Confidentiality, integrity, serious availability, or false-success failure requiring one additional in-scope condition, such as a local race, privileged embedding, or user-initiated decrypt; also a deterministic default failure that silently leaves protected plaintext or makes recovery materially unsafe |
| Low | Constrained, recoverable, or defence-in-depth impact requiring a compatibility-only filesystem, explicit raised limits, a narrow race, or another capability already close to the effect |
| Informational | Documentation, diagnostics, process, test coverage, or hardening with no demonstrated violation of an applicable security guarantee |

## 6. Release and review governance

### 6.1 Release-blocking threshold

**Every confirmed violation of an applicable MUST or MUST NOT in a supported
profile MUST block the release when it affects confidentiality,
authentication, integrity, containment, pre-existing-entry no-clobber, cleanup
ownership, or outcome truth. An availability violation blocks only when it is
deterministic in the default profile and not safely recoverable.**

After scope is applied:

- every Critical or High finding blocks;
- a Medium finding blocks when it affects the default profile or another
  applicable supported profile;
- a Low or Informational finding does not block when it is accurately
  documented and does not violate one of the blocking contracts above.

A documentation defect blocks only when it can cause a caller to expose
plaintext, destroy data, discard the only key, or mishandle a post-commit
error. Wording differences without that consequence remain finite
documentation work under PR-01.

### 6.2 Reclassifying intentional behaviour

**Documented intentional behaviour MAY be reclassified as a defect only when
new evidence changes a prerequisite, reliability, impact, recoverability, or
retry consequence; proves that the documentation was factually incomplete;
shows a conflict with a higher-priority requirement; or follows an explicit
owner policy change.**

A new description of the same known facts is not new evidence.

### 6.3 Documentation consistency

**PR-01 — A security-relevant behaviour change MUST reconcile THREAT_MODEL.md,
public rustdoc, SECURITY.md, FORMAT.md, STRUCTURE.md, README.md, and the
changelog wherever each document is authoritative, and stable behaviour SHOULD
be pinned by tests where practical.**

Documentation drift does not become in scope or out of scope through a threat
assumption. A review SHOULD report one contradiction set rather than
reinterpret the same drift as several security findings.

## 7. Classification examples

These examples show how to apply the selected rules. They do not describe a
separate threat model.

### 7.1 A run prevents its own cleanup

If FerroCrypt applies a restrictive mode to a staged directory it created and
that mode later prevents DeleteOnError from removing the tree, the behaviour
violates TM-14. The obstacle is self-created, no attacker or unusual
filesystem is required, and the cleanup contract makes the defect
release-blocking. If an external storage or permission failure prevents
cleanup instead, the operation conforms only when the returned error identifies
the working path and states that plaintext may remain.

### 7.2 A local writer substitutes an output entry

If exploitation requires another process to modify only the selected output
directory during the operation, the caller has violated TM-12. The item is out
of scope and is non-blocking defence in depth under TM-13. It becomes in scope
if the effect escapes the selected directory, harms an object the writer could
not otherwise reach, or independently violates an unqualified guarantee such
as pre-existing-entry no-clobber.

### 7.3 An FCA name contains bidirectional span controls

A writer or reader that accepts a code point prohibited by TM-18 violates the
path grammar. Before stable 0.3.0, the defect blocks the release
because TM-08 freezes the baseline's accepted artefacts and security rejection
rules once stable; the blocking reason is compatibility timing, not the
display issue's severity. Safe CLI and desktop rendering remains
defence-in-depth protection in addition to the grammar.

### 7.4 A filesystem identity carries no information

An absent, unreadable, all-zero, truncated, or otherwise non-distinguishing
identity is unavailable evidence, not a match. If an in-scope guarantee in a
named supported environment requires the check, TM-15 requires the operation
to fail. If the check is defence in depth or the filesystem is
compatibility-only, FerroCrypt may skip it, but it MUST NOT record the result
as confirmation.
