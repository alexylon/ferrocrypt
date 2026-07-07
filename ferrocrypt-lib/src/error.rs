use thiserror::Error;

use crate::UnauthenticatedRecipientMode;
use crate::recipient::argon2id;
use crate::recipient::policy::MixingPolicy;

/// Maximum number of rendered `chars` (counting an inserted ellipsis as one)
/// a `type_name` may occupy when interpolated into a user-facing error
/// message. Sized to keep the longest interpolating message
/// (`UnknownCriticalRecipient`, fixed wording = 51 chars) within the
/// 64-char desktop status-line budget enforced by
/// [`tests::user_facing_messages_fit_status_line_budget`].
const TYPE_NAME_DISPLAY_MAX: usize = 13;
const _: () = assert!(TYPE_NAME_DISPLAY_MAX >= 1);

/// Writes `s` to `f`, escaping each character via [`write_sanitized_char`] and
/// bounding the escaped output to `max` rendered chars, including a trailing
/// `…` when truncation occurs. The function never splits a UTF-8 code point or
/// a backslash escape sequence; if the next escaped character would not fit, it
/// emits `…` instead. Shared by [`DisplayableTypeName`] and
/// [`DisplayableMarker`].
fn write_truncated_sanitized(
    f: &mut std::fmt::Formatter<'_>,
    s: &str,
    max: usize,
) -> std::fmt::Result {
    let mut written = 0;
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        let mut escaped = String::new();
        write_sanitized_char(&mut escaped, ch)?;
        let escaped_len = escaped.chars().count();
        let ellipsis_reserve = usize::from(chars.peek().is_some());
        if written + escaped_len + ellipsis_reserve <= max {
            f.write_str(&escaped)?;
            written += escaped_len;
        } else {
            if written < max {
                f.write_str("…")?;
            }
            return Ok(());
        }
    }
    Ok(())
}

/// Wraps a `type_name` so its `Display` rendering escapes non-printable
/// characters and truncates the escaped output to [`TYPE_NAME_DISPLAY_MAX`]
/// chars, replacing the tail with `…` when truncation actually occurs. The
/// FORMAT.md §3.3 grammar already limits a parsed `type_name` to printable
/// lowercase ASCII, but a `CryptoError::*` variant can be hand-constructed
/// from any string, so the escape (shared with `sanitize_for_display` via
/// `write_sanitized_char`) stops a non-grammar name from smuggling a terminal
/// escape sequence into an error message.
struct DisplayableTypeName<'a>(&'a str);

impl std::fmt::Display for DisplayableTypeName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_truncated_sanitized(f, self.0, TYPE_NAME_DISPLAY_MAX)
    }
}

/// Largest number of display columns an internal-error marker may occupy after
/// its fixed prefix. Set to the 64-column status-line budget minus the longer
/// prefix `"Internal crypto error: "`, so both internal messages stay within
/// budget for any marker.
const INTERNAL_MARKER_DISPLAY_MAX: usize = 64 - "Internal crypto error: ".len();
const _: () = assert!(INTERNAL_MARKER_DISPLAY_MAX >= 1);

/// Wraps an internal-error marker so its `Display` escapes non-printable
/// characters and bounds the output to [`INTERNAL_MARKER_DISPLAY_MAX`] columns.
/// The markers are fixed `&'static str`s this crate controls, so the escape is
/// defense-in-depth; the bound keeps `Internal error: {marker}` and
/// `Internal crypto error: {marker}` within the status-line budget.
struct DisplayableMarker<'a>(&'a str);

impl std::fmt::Display for DisplayableMarker<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_truncated_sanitized(f, self.0, INTERNAL_MARKER_DISPLAY_MAX)
    }
}

/// User-facing message for [`CryptoError::RecipientUnwrapFailed`].
///
/// Passphrase recipients render the wrong-passphrase-or-modified-file
/// message. Public-key recipients render a message that says no recipient
/// matched, or the file was modified. The `type_name` stays in the variant
/// payload for inspection and is never shown, so the message carries no
/// attacker-chosen text.
fn recipient_unwrap_message(type_name: &str) -> &'static str {
    if type_name == argon2id::TYPE_NAME {
        "Decryption failed: wrong passphrase or modified file"
    } else {
        "Decryption failed: no matching recipient or modified file"
    }
}

/// Shared Display text for the two header-authentication failures —
/// [`CryptoError::HeaderTampered`] (passphrase mode) and
/// [`CryptoError::HeaderMacFailedAfterUnwrap`] (public-key mode). They are the
/// same condition and must read identically, so both render this one string.
const HEADER_CORRUPTED_MESSAGE: &str = "Decryption failed: file header was modified or corrupted";

/// Maximum number of `chars` of untrusted text [`sanitize_for_display`]
/// keeps before truncating with `…`. Long enough to locate an entry in
/// a large archive, short enough that one hostile path cannot flood a
/// terminal or log line.
const UNTRUSTED_TEXT_DISPLAY_MAX: usize = 64;

/// Appends `c` to `w`, passing printable ASCII (and the space character)
/// through unchanged and rendering every other character as a backslash
/// escape (`\n`, `\u{202e}`, …). The one definition of the per-character
/// escape rule, shared by `sanitize_for_display` and `DisplayableTypeName`
/// so neither can let a hostile character carry a terminal escape
/// sequence or visually reorder the surrounding text.
fn write_sanitized_char<W: std::fmt::Write>(w: &mut W, c: char) -> std::fmt::Result {
    if c.is_ascii_graphic() || c == ' ' {
        w.write_char(c)
    } else {
        write!(w, "{}", c.escape_default())
    }
}

/// Renders untrusted text for embedding in an error message.
///
/// Printable ASCII passes through unchanged; every other character —
/// ASCII control bytes, and all non-ASCII including direction-override
/// and zero-width code points — is rendered as a backslash escape
/// (`\n`, `\u{202e}`, …), so terminal-bound error text cannot carry
/// escape sequences and cannot be visually reordered or spoofed. Input
/// longer than [`UNTRUSTED_TEXT_DISPLAY_MAX`] chars is truncated with a
/// trailing `…`. Used wherever an error message embeds text an attacker
/// may have chosen: archive entry paths, source-tree file names, and
/// the recipient-string parser's input echo.
pub(crate) fn sanitize_for_display(text: &str) -> String {
    let mut out = String::new();
    for (i, c) in text.chars().enumerate() {
        if i >= UNTRUSTED_TEXT_DISPLAY_MAX {
            out.push('…');
            break;
        }
        let _ = write_sanitized_char(&mut out, c);
    }
    out
}

/// Renders a filesystem path for embedding in an error message:
/// [`sanitize_for_display`] over `Path::display`. Used for
/// caller-supplied input paths and other whole-path embeddings — such
/// paths often come from shell glob expansion or a file-picker dialog,
/// so every component, including intermediate directories, can be as
/// attacker-chosen as a name found inside an archive. The "already
/// exists" conflict messages instead route through
/// `fs::paths::already_exists_error`, which keeps the trusted parent
/// directory raw and escapes only the final component.
pub(crate) fn sanitize_path_for_display(path: &std::path::Path) -> String {
    sanitize_for_display(&path.display().to_string())
}

/// Renders `: {path}` when an optional sanitized path is present, and
/// nothing otherwise, so one `#[error]` string serves both the
/// "path known" and "path not yet parsed" construction sites of the
/// archive cap variants.
struct PathSuffix<'a>(&'a Option<String>);

impl std::fmt::Display for PathSuffix<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(path) => write!(f, ": {path}"),
            None => Ok(()),
        }
    }
}

/// Errors that can occur during key generation, encryption, or decryption.
///
/// All `Display` messages are short, user-facing, and free of internal
/// type names so that consumers can surface them directly without
/// additional mapping.
///
/// # Design: identity-only where possible
///
/// Most variants are **identity-only**: they carry no per-operation
/// context (no paths, no byte offsets, no wrapped error text), because
/// that context belongs at the *caller*, not inside the error. A CLI
/// frontend can prepend the file path if it wants to; a GUI can elide
/// it; a server can log structured fields. The library stays agnostic.
///
/// Variants that do carry data carry *typed structured data*, not
/// heap-allocated strings:
/// - [`CryptoError::InvalidFormat`] carries a [`FormatDefect`]
/// - [`CryptoError::UnsupportedVersion`] carries an [`UnsupportedVersion`]
/// - [`CryptoError::InvalidKdfParams`] carries an [`InvalidKdfParams`]
/// - [`CryptoError::InternalInvariant`] and [`CryptoError::InternalCryptoFailure`]
///   carry a `&'static str` marker (no heap allocation)
/// - The `*CapExceeded` variants ([`CryptoError::HeaderLenCapExceeded`],
///   [`CryptoError::RecipientCountCapExceeded`],
///   [`CryptoError::RecipientBodyCapExceeded`],
///   [`CryptoError::RecipientStringCapExceeded`],
///   [`CryptoError::KdfResourceCapExceeded`],
///   [`CryptoError::KdfTimeCostCapExceeded`],
///   [`CryptoError::KdfLanesCapExceeded`],
///   [`CryptoError::PrivateKeyWrappedSecretCapExceeded`], and the
///   `Archive*CapExceeded` family for the `FORMAT.md` §9.12 caps) each
///   carry the offending value plus the configured local cap as named
///   integer fields, matching the "distinct resource-cap error" classes
///   that `FORMAT.md` §3.2 / §12 enumerate
/// - The archive defect variants ([`CryptoError::MalformedArchive`],
///   [`CryptoError::UnsafeArchivePath`],
///   [`CryptoError::InvalidArchiveTree`]) carry a static `reason`
///   describing the violated rule; the path-carrying ones also carry
///   the offending entry path, sanitized for display (control and
///   non-ASCII characters escaped, long paths truncated), because an
///   attacker-crafted archive can hold thousands of entries and the
///   path is the only way to locate the bad one
/// - The multi-recipient diagnostics ([`CryptoError::RecipientUnwrapFailed`],
///   [`CryptoError::HeaderMacFailedAfterUnwrap`],
///   [`CryptoError::UnknownCriticalRecipient`],
///   [`CryptoError::IncompatibleRecipients`]) each carry the
///   `type_name` so callers can tell which recipient slot raised them
///
/// Consumers can pattern-match on these shapes without substring
/// comparisons.
///
/// # The one escape hatch: [`CryptoError::InvalidInput`]
///
/// One variant — [`CryptoError::InvalidInput`] — carries a free-form
/// `String`. It is the **designated heterogeneous caller-input
/// bucket** for fail-closed rejections whose only useful context is
/// a path or short token that has to be echoed back to the user.
/// Concretely it covers:
///
/// - **encrypt-side source-tree problems**: "Input is a symlink:
///   `path`", "Source is no longer a regular file: `name`",
///   "Unsupported file type: `path`". The source tree belongs to the
///   caller's environment, so these are caller-input rejections, not
///   format defects. Every embedded path or name — caller-supplied
///   top-level paths included — is sanitized via
///   `sanitize_for_display` / `sanitize_path_for_display` before
///   embedding.
/// - **Bech32 recipient parser**: reports the offending recipient
///   string ("Invalid recipient string: `fcr1…`", "Unexpected recipient
///   prefix…", "Recipient string must be lowercase"). Callers pass
///   recipient strings through as opaque values, so the parser has to
///   echo the input back (sanitized and truncated) for the user to
///   spot a typo.
/// - **Caller-invocation path conflicts and shape rejections**:
///   "Output already exists: `path`", "Key file already exists:
///   `path`", "Invalid recipient public key". These surface *which*
///   user-supplied path or value triggered the rejection so
///   operators can fix it without extra debugging. The conflict
///   messages render the parent directory raw (it is the caller's
///   trust boundary) and escape the final component, which can be
///   attacker-influenced.
/// - **Caller-supplied config values** outside the valid range:
///   "KDF memory limit overflow: `N` MiB", "Passphrase must not be
///   empty".
///
/// Rejections of a *parsed archive payload* — a hostile or corrupt
/// FCA inside the decrypted stream — are **not** `InvalidInput`: they
/// surface as [`CryptoError::MalformedArchive`],
/// [`CryptoError::UnsafeArchivePath`],
/// [`CryptoError::InvalidArchiveTree`], or the `Archive*CapExceeded`
/// family, because they describe the file, not the caller.
///
/// Library consumers treat `InvalidInput` as an opaque string and
/// surface it via `Display`; the CLI and desktop frontends do exactly
/// that.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CryptoError {
    // ─── Input & filesystem ──────────────────────────────────────────────
    /// Filesystem or stream I/O failure.
    #[error(transparent)]
    Io(std::io::Error),
    /// Input file or directory does not exist.
    #[error("Input file or folder missing")]
    InputPath,
    /// Invalid caller input with a human-readable explanation. See the
    /// type-level docs for the design rationale.
    #[error("{0}")]
    InvalidInput(String),

    // ─── File format & version ───────────────────────────────────────────
    /// Encrypted file or key-file structure is invalid, truncated, or
    /// corrupted at the format level (not a crypto authentication issue).
    #[error("{0}")]
    InvalidFormat(FormatDefect),
    /// Encrypted file or key-file version is outside the range this
    /// release can read.
    #[error("{0}")]
    UnsupportedVersion(UnsupportedVersion),

    // ─── Key derivation & work limits ────────────────────────────────────
    /// KDF parameters read from an untrusted header are outside safe
    /// structural bounds.
    #[error("{0}")]
    InvalidKdfParams(InvalidKdfParams),
    /// Argon2id memory cost from a header exceeds the caller-configured
    /// local resource cap. Per `FORMAT.md` §3.2, exceeding a local cap
    /// produces a distinct resource-cap error rather than a generic
    /// malformed-file error. Distinct from
    /// [`InvalidKdfParams`] (structurally invalid params): here the params
    /// are well-formed but cost more than the caller is willing to
    /// spend.
    #[error("Passphrase memory over limit ({mem_cost_kib} KiB, limit {local_cap_kib})")]
    KdfResourceCapExceeded {
        /// Memory cost requested by the untrusted header, in KiB.
        mem_cost_kib: u32,
        /// Maximum memory cost accepted by the caller's local policy, in KiB.
        local_cap_kib: u32,
    },
    /// Argon2id time cost (iteration count) from a header exceeds the
    /// caller-configured local cap. The time-dimension counterpart of
    /// [`Self::KdfResourceCapExceeded`]: the value is structurally valid
    /// (within the v1 maximum) but asks for more iterations than the policy
    /// allows. The default cap is the v1 maximum, so this variant is returned
    /// only when a caller tightens `KdfLimit` below that maximum.
    #[error("Passphrase time over limit ({time_cost}, limit {local_cap})")]
    KdfTimeCostCapExceeded {
        /// Time cost (iteration count) requested by the untrusted header.
        time_cost: u32,
        /// Maximum time cost accepted by the caller's local policy.
        local_cap: u32,
    },
    /// Argon2id lane count (parallelism) from a header exceeds the
    /// caller-configured local cap. The parallelism-dimension counterpart of
    /// [`Self::KdfResourceCapExceeded`]; like [`Self::KdfTimeCostCapExceeded`],
    /// the default cap is the v1 maximum, so this variant is returned only when
    /// a caller tightens `KdfLimit` below that maximum.
    #[error("Passphrase parallelism over limit ({lanes}, limit {local_cap})")]
    KdfLanesCapExceeded {
        /// Lane count (parallelism) requested by the untrusted header.
        lanes: u32,
        /// Maximum lane count accepted by the caller's local policy.
        local_cap: u32,
    },
    /// Writer-side Argon2id memory cost is below the production floor.
    /// Raised only when writing a `.fcr` or `private.key` (passphrase
    /// encryption / key sealing), so a caller cannot accidentally seal an
    /// artefact with weak Argon2id memory. The floor is a writer policy
    /// only: readers accept any structurally valid, within-cap parameters,
    /// so a file written before the floor existed always decrypts.
    #[error("Passphrase memory too low ({mem_cost_kib} KiB, needs {floor_kib} KiB)")]
    KdfBelowWriteFloor {
        /// Memory cost the caller requested, in KiB.
        mem_cost_kib: u32,
        /// Minimum memory cost the writer accepts, in KiB.
        floor_kib: u32,
    },
    /// `header_len` exceeds the caller-configured local cap. The
    /// structural max (`HEADER_LEN_MAX = 16 MiB` per `FORMAT.md` §3.1)
    /// is much higher; this fires when the header would exceed the
    /// caller's resource policy. Distinct from
    /// [`FormatDefect::OversizedHeader`] (above structural max) per
    /// `FORMAT.md` §3.2.
    #[error("Header too large ({header_len} bytes, limit {local_cap})")]
    HeaderLenCapExceeded {
        /// Header length declared by the `.fcr` prefix, in bytes.
        header_len: u32,
        /// Maximum header length accepted by local policy, in bytes.
        local_cap: u32,
    },
    /// `recipient_count` exceeds the caller-configured local cap. The
    /// structural range (`1..=4096` per `FORMAT.md` §3.2) is much
    /// wider; this fires when the count would exceed the caller's
    /// resource policy. Distinct from
    /// [`FormatDefect::RecipientCountOutOfRange`] (above structural
    /// max).
    #[error("Too many recipients ({count} entries, limit {local_cap})")]
    RecipientCountCapExceeded {
        /// Recipient count declared by the header or requested by the writer.
        count: u16,
        /// Maximum recipient count accepted by local policy.
        local_cap: u16,
    },
    /// A recipient entry's `body_len` exceeds the local resource cap.
    /// The structural max (`BODY_LEN_MAX = 16 MiB` per `FORMAT.md`
    /// §3.3) is much higher; this fires when the body would exceed the
    /// caller-configured local cap (`FORMAT.md` §3.2 recommends 8 KiB
    /// for untrusted input). Distinct from
    /// [`FormatDefect::MalformedRecipientEntry`]: the file is
    /// structurally valid; the reader's resource policy is the
    /// constraint, and callers MAY raise the cap for trusted input.
    #[error("Recipient data too large ({body_len} bytes, limit {local_cap})")]
    RecipientBodyCapExceeded {
        /// Recipient body length declared by the entry, in bytes.
        body_len: u32,
        /// Maximum per-recipient body length accepted by local policy, in bytes.
        local_cap: u32,
    },
    /// Bech32 recipient string exceeds the caller-configured local
    /// length cap.
    ///
    /// Distinct from malformed public-key input: the string may be
    /// structurally valid, but the reader's resource policy rejected it.
    /// The v1 structural ceiling is 20,000 ASCII characters (`FORMAT.md`
    /// §7); the recommended local default is smaller. For valid recipient
    /// strings, byte length and character count are the same because the
    /// encoding is ASCII.
    #[error("Recipient string too long ({input_chars} chars, limit {local_cap})")]
    RecipientStringCapExceeded {
        /// Number of characters in the supplied recipient string.
        input_chars: u32,
        /// Maximum recipient-string length accepted by local policy.
        local_cap: u32,
    },
    /// A `private.key` file's `wrapped_secret_len` exceeds the local
    /// resource cap. The structural max (16 MiB per `FORMAT.md` §8) is
    /// much higher; this fires when the wrapped secret would exceed the
    /// reader's resource policy (4 KiB by default — every v1 native key
    /// type needs only 48 bytes). Distinct from
    /// [`FormatDefect::MalformedPrivateKey`]: the file may be
    /// structurally valid for a future key type; the local policy is
    /// the constraint.
    #[error("Private key data too large ({wrapped_secret_len} bytes, limit {local_cap})")]
    PrivateKeyWrappedSecretCapExceeded {
        /// Wrapped-secret length declared by the `private.key` header, in bytes.
        wrapped_secret_len: u32,
        /// Maximum wrapped-secret length accepted by local policy, in bytes.
        local_cap: u32,
    },

    // ─── Authentication failures ─────────────────────────────────────────
    /// Unlocking the `private.key` file failed AEAD authentication. The
    /// key file is structurally valid, but either the supplied
    /// passphrase does not decrypt it, or its cleartext fields have
    /// been tampered with after the file was written. The AEAD
    /// primitive cannot distinguish the two cases — the associated-data
    /// binding introduced in the v1 `private.key` format catches tampering
    /// cryptographically, but both failure modes surface as the same
    /// error by design. The Display wording reflects both causes.
    #[error("Private key unlock failed: wrong passphrase or modified key file")]
    KeyFileUnlockFailed,
    /// The header MAC failed after the passphrase recipient unwrapped
    /// a candidate `file_key`.
    ///
    /// Per `FORMAT.md` §3.7, a recipient unwrap is not accepted until
    /// the candidate key verifies the header MAC. The failed MAC shows
    /// the MAC-covered bytes changed after the file was written, but
    /// cannot distinguish deliberate tampering from storage corruption.
    /// This variant is the passphrase-mode verdict; the public-key
    /// decrypt path reports the same condition as
    /// [`Self::HeaderMacFailedAfterUnwrap`], whatever the recipient
    /// count.
    #[error("{}", HEADER_CORRUPTED_MESSAGE)]
    HeaderTampered,
    /// In a public-key decrypt, a recipient slot unwrapped a
    /// `file_key`, but the resulting `header_key` did not verify the
    /// header MAC.
    ///
    /// The unwrap is not final until the MAC verifies. The decrypt loop
    /// still visits every supported slot; when at least one slot
    /// unwrapped and none verified, this variant is the final verdict —
    /// including for a single-recipient public-key file. The passphrase
    /// counterpart is [`Self::HeaderTampered`], and both render the same
    /// message. The `type_name` field records which recipient type produced
    /// the failed candidate; it is not shown in the message.
    #[error("{}", HEADER_CORRUPTED_MESSAGE)]
    HeaderMacFailedAfterUnwrap {
        /// Recipient type name whose candidate key failed header-MAC verification.
        type_name: String,
    },
    /// No supported recipient slot opened with the supplied credential.
    /// This means the credential is wrong or a recipient body was modified;
    /// the AEAD result cannot distinguish those cases. This is the
    /// `FORMAT.md` §12 wrong-passphrase/key class, separate from
    /// [`Self::NoSupportedRecipient`] (a file with no supported recipient
    /// type at all). An opened slot is not final until the header MAC verifies.
    ///
    /// The rendered message follows `type_name`: wrong passphrase for
    /// `argon2id`; for public-key recipients, no matching recipient or a
    /// modified file. The `type_name` is not shown.
    #[error("{}", recipient_unwrap_message(type_name))]
    RecipientUnwrapFailed {
        /// Recipient type name whose body failed to unwrap.
        type_name: String,
    },
    /// The recipient list contains a `recipient_flags.critical = 1`
    /// entry whose `type_name` is unknown to this implementation. Per
    /// `FORMAT.md` §3.4 unknown critical entries MUST cause file
    /// rejection (vs unknown non-critical, which are skipped).
    #[error(
        "Unsupported recipient `{}`. Upgrade FerroCrypt.",
        DisplayableTypeName(type_name)
    )]
    UnknownCriticalRecipient {
        /// Unknown recipient type name that carried the critical flag.
        type_name: String,
    },
    /// The file holds no recipient of a type this build can process — only
    /// unknown non-critical entries. Detected while classifying the recipient
    /// list, before any unwrap. A *supported* recipient whose unwrap fails is
    /// [`Self::RecipientUnwrapFailed`] instead; `FORMAT.md` §12 lists the two
    /// as separate failure classes.
    #[error("Decryption failed: no supported recipient")]
    NoSupportedRecipient,
    /// The decryptor variant the caller chose does not match the file's
    /// recipient mode (e.g. a passphrase decryptor invoked against a file
    /// sealed to public-key recipients, or vice versa).
    ///
    /// The public API routes through [`crate::Decryptor::open`], which
    /// inspects the file structurally and hands back the matching variant —
    /// so callers using the public surface cannot reach this error. It is
    /// reserved for internal callers and any future plugin-style API
    /// where a caller drives `protocol::decrypt` directly with a chosen
    /// credential scheme.
    ///
    /// `expected` is the mode the decryptor expected (its credential-scheme
    /// mode); `found` is the mode classified from the file's recipient
    /// list. Distinct from [`Self::NoSupportedRecipient`], which means
    /// "the file's recipient list contains no entry I can unlock,"
    /// not "I'm the wrong tool for this file."
    #[error("File is {found} encrypted; use {}", found.credential_name())]
    DecryptorModeMismatch {
        /// Decryptor mode selected by the caller.
        expected: UnauthenticatedRecipientMode,
        /// Recipient mode classified from the `.fcr` header.
        found: UnauthenticatedRecipientMode,
    },
    /// The caller provided no encryption recipients.
    ///
    /// `Encryptor::with_public_keys` requires at least one public recipient;
    /// otherwise there is no recipient entry to wrap the per-file `file_key`.
    #[error("Recipient list cannot be empty")]
    EmptyRecipientList,
    /// The recipient list contains an entry whose mixing rule forbids
    /// the company it is in. The most common v1 trigger is an
    /// [`MixingPolicy::Exclusive`] native type (today only `argon2id`)
    /// sharing a file with any other entry — per `FORMAT.md` §4.1 such
    /// types MUST appear alone, and readers MUST reject the mix
    /// structurally before running any KDF.
    ///
    /// `type_name` identifies which entry triggered the rejection;
    /// `policy` carries the [`MixingPolicy`] projection the offending
    /// rule declared, so callers can pattern-match without parsing the
    /// message. Future native types whose compatibility class differs
    /// from the two fixed shorthand classes surface as
    /// [`MixingPolicy::Custom { compatibility_class }`](MixingPolicy::Custom),
    /// with the class identifier preserved in the variant payload. The
    /// same variant surfaces from both the decrypt-side mixing
    /// enforcement (run before any KDF) and the encrypt-side preflight
    /// (run before any output bytes are written), with identical
    /// wording in both directions.
    #[error(
        "Recipient `{}` mixed with another recipient",
        DisplayableTypeName(type_name)
    )]
    IncompatibleRecipients {
        /// Recipient type name whose mixing policy rejected the list.
        type_name: String,
        /// Mixing policy associated with the offending recipient type.
        policy: MixingPolicy,
    },
    /// An encrypted payload chunk failed AEAD authentication during
    /// streaming decryption. The ciphertext was modified or corrupted
    /// after the header was authenticated.
    #[error("Decryption failed: file data was modified or corrupted")]
    PayloadTampered,
    /// The encrypted stream ends before the final-flag chunk.
    /// Usually caused by a truncated file or an aborted download.
    #[error("Encrypted file is truncated")]
    PayloadTruncated,
    /// Bytes remain after the final-flag chunk has been successfully
    /// decrypted. The file has unexpected trailing data.
    #[error("Encrypted file has unexpected trailing data")]
    ExtraDataAfterPayload,
    /// The encrypted payload exceeds the `2^32`-chunk cap mandated by
    /// `FORMAT.md` §5. Surfaces from the writer-side cap (refuses to
    /// emit the over-cap chunk) and the reader-side cap (refuses to
    /// consume one).
    #[error("Encrypted file exceeds supported data size")]
    PayloadChunkCountExceeded,

    // ─── Archive payload (FCA) ───────────────────────────────────────────
    /// Inner FCA archive header or manifest is structurally invalid:
    /// bad magic, reserved flags set, no entries declared, truncated or
    /// over-declared regions, a length-field overflow, trailing
    /// manifest or content bytes, an unknown entry kind, a directory
    /// entry declaring a size, an out-of-range mode word, a non-UTF-8
    /// or empty entry path, or a declared total that does not match the
    /// entry sizes. Fires inside the encrypted payload after the outer
    /// container is accepted, and from the writer gate when a caller
    /// hands the archive writer data it could never read back. The
    /// `reason` names the violated rule. Per `FORMAT.md` §9.
    #[error("Malformed archive: {reason}")]
    MalformedArchive {
        /// The specific `FORMAT.md` §9 rule the payload violated.
        reason: &'static str,
    },
    /// An archive entry path violates the `FORMAT.md` §9.6 grammar
    /// (absolute, traversal, separator abuse, control bytes,
    /// Windows-reserved names, …). Fires on read for a hostile or
    /// corrupt archive and on write for a source tree whose names FCA
    /// cannot represent.
    #[error("Unsafe archive path ({reason}): {path}")]
    UnsafeArchivePath {
        /// Offending entry path, sanitized for display (control and
        /// non-ASCII characters escaped, long input truncated).
        path: String,
        /// The specific `FORMAT.md` §9.6 rule the path violated.
        reason: &'static str,
    },
    /// The archive manifest violates the `FORMAT.md` §9.7/§9.8 tree
    /// rules: duplicate entries (exact or ASCII-case-insensitive),
    /// multiple top-level roots, a missing parent or root entry, or a
    /// child under a file path.
    #[error("Invalid archive tree ({reason}): {path}")]
    InvalidArchiveTree {
        /// Entry path that exposed the violation, sanitized for display.
        path: String,
        /// The specific tree rule the manifest violated.
        reason: &'static str,
    },
    /// Archive entry count exceeds the configured
    /// [`ArchiveLimits::max_entry_count`](crate::ArchiveLimits) cap
    /// (`FORMAT.md` §9.12). Like every `Archive*CapExceeded` variant,
    /// this is a resource-policy rejection, not a format defect, and is
    /// enforced identically on encrypt and decrypt.
    #[error("Too many archive entries ({entry_count}, limit {local_cap})")]
    ArchiveEntryCountCapExceeded {
        /// Entry count declared by the archive or discovered by the writer.
        entry_count: u32,
        /// Maximum entry count accepted by local policy.
        local_cap: u32,
    },
    /// Total plaintext bytes exceed the configured
    /// [`ArchiveLimits::max_total_plaintext_bytes`](crate::ArchiveLimits)
    /// cap (`FORMAT.md` §9.12).
    #[error("Archive is too large (limit {local_cap} bytes)")]
    ArchiveTotalBytesCapExceeded {
        /// Running plaintext total that crossed the cap, in bytes.
        total_bytes: u64,
        /// Maximum total plaintext accepted by local policy, in bytes.
        local_cap: u64,
    },
    /// Serialized manifest length exceeds the configured
    /// [`ArchiveLimits::max_manifest_bytes`](crate::ArchiveLimits) cap
    /// (`FORMAT.md` §9.12).
    #[error("Archive manifest is too large (limit {local_cap} bytes)")]
    ArchiveManifestLenCapExceeded {
        /// Manifest length declared by the archive header or computed
        /// by the writer, in bytes.
        manifest_len: u64,
        /// Maximum manifest length accepted by local policy, in bytes.
        local_cap: u32,
    },
    /// An entry path's UTF-8 byte length exceeds the configured
    /// [`ArchiveLimits::max_path_bytes`](crate::ArchiveLimits) cap
    /// (`FORMAT.md` §9.12). `path` is `None` when the cap fires on the
    /// declared length before the path bytes have been parsed.
    #[error(
        "Archive path too long ({path_bytes} bytes, limit {local_cap}){}",
        PathSuffix(path)
    )]
    ArchivePathBytesCapExceeded {
        /// Declared or measured path length, in bytes.
        path_bytes: u32,
        /// Maximum path length accepted by local policy, in bytes.
        local_cap: u32,
        /// Offending entry path, sanitized for display, when available.
        path: Option<String>,
    },
    /// An entry path's component depth exceeds the configured
    /// [`ArchiveLimits::max_path_depth`](crate::ArchiveLimits) cap
    /// (`FORMAT.md` §9.12).
    #[error("Archive path too deep ({depth} components, limit {local_cap}): {path}")]
    ArchivePathDepthCapExceeded {
        /// Component count of the offending path.
        depth: u32,
        /// Maximum path depth accepted by local policy.
        local_cap: u32,
        /// Offending entry path, sanitized for display.
        path: String,
    },
    /// The archive-level extension region exceeds the configured
    /// [`ArchiveLimits::max_archive_ext_bytes`](crate::ArchiveLimits)
    /// cap (`FORMAT.md` §9.12).
    #[error("Archive extension is too large (limit {local_cap} bytes)")]
    ArchiveExtLenCapExceeded {
        /// Declared archive-extension length, in bytes.
        ext_len: u64,
        /// Maximum archive-extension length accepted by local policy, in bytes.
        local_cap: u32,
    },
    /// A per-entry extension region exceeds the configured
    /// [`ArchiveLimits::max_entry_ext_bytes`](crate::ArchiveLimits) cap
    /// (`FORMAT.md` §9.12). `path` is `None` when the cap fires on the
    /// declared length before the entry's path has been parsed.
    #[error(
        "Archive entry extension is too large (limit {local_cap} bytes){}",
        PathSuffix(path)
    )]
    ArchiveEntryExtLenCapExceeded {
        /// Declared entry-extension length, in bytes.
        ext_len: u64,
        /// Maximum per-entry extension length accepted by local policy, in bytes.
        local_cap: u32,
        /// Offending entry path, sanitized for display, when available.
        path: Option<String>,
    },
    /// The summed per-entry extension regions exceed the configured
    /// [`ArchiveLimits::max_total_entry_ext_bytes`](crate::ArchiveLimits)
    /// cap (`FORMAT.md` §9.12).
    #[error("Archive entry extensions too large (limit {local_cap} bytes)")]
    ArchiveTotalEntryExtCapExceeded {
        /// Running entry-extension total that crossed the cap, in bytes.
        total_ext_bytes: u64,
        /// Maximum summed entry-extension bytes accepted by local policy.
        local_cap: u64,
    },

    // ─── Internal invariants ─────────────────────────────────────────────
    /// A non-cryptographic invariant that should hold by construction did
    /// not hold. Triggered by state-machine misuse (e.g. using a stream
    /// after it was finalized), impossible-size checks, or internal
    /// encoding failures. If this fires, it indicates a library bug.
    #[error("Internal error: {}", DisplayableMarker(.0))]
    InternalInvariant(&'static str),
    /// A cryptographic primitive (AEAD encryption, HKDF expansion) returned
    /// an error even though the inputs were well-formed. Unreachable in
    /// practice for valid data; indicates either a library bug or a very
    /// rare underlying-crate failure.
    #[error("Internal crypto error: {}", DisplayableMarker(.0))]
    InternalCryptoFailure(&'static str),
}

/// Structural defects detected while parsing a FerroCrypt encrypted file
/// or key file. Carried inside [`CryptoError::InvalidFormat`] so format
/// failures can be pattern-matched without substring comparisons and
/// without heap-allocated `String`s.
///
/// Each variant is the most granular structural class `FORMAT.md` §12
/// admits. Resource-cap exceedances are *not* `FormatDefect`s — they
/// are top-level [`CryptoError`] variants in the `*CapExceeded` family
/// (e.g. [`FormatDefect::OversizedHeader`] is the structural max
/// violation; the local-cap counterpart is
/// [`CryptoError::HeaderLenCapExceeded`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatDefect {
    /// Input ended before a complete field or header could be read.
    Truncated,
    /// Leading magic bytes do not match `"FCR\0"`.
    BadMagic,
    /// `ext_len` (in a `.fcr` header's fixed section or a `private.key`
    /// header) exceeds the reader's structural cap (`EXT_LEN_MAX`, 64 KiB).
    /// Carried as `u32` because the cap is `65_536`, which exceeds
    /// `u16::MAX`.
    ExtTooLarge {
        /// Declared extension-region length, in bytes.
        len: u32,
    },
    /// A TLV entry in the extension region is malformed: bad ordering,
    /// duplicate tag, or `len` extends past the end of the region.
    /// `FORMAT.md` §6.
    MalformedTlv,
    /// A TLV tag in the critical range (`0x8001..=0xFFFF`) is not
    /// recognised by this release. Per `FORMAT.md` §6, unknown
    /// critical TLV tags MUST cause file rejection.
    UnknownCriticalTag {
        /// Unknown critical TLV tag value.
        tag: u16,
    },
    /// Leading magic bytes do not match `"FCR\0"` — not a FerroCrypt
    /// key file. Key-file analogue of [`FormatDefect::BadMagic`].
    NotAKeyFile,
    /// Key file is the wrong kind for this operation (public vs private).
    WrongKeyFileType,
    /// `public.key` text file violates the canonical grammar
    /// (`FORMAT.md` §7.1): the file MUST contain the lowercase `fcr1…`
    /// recipient string optionally followed by exactly one trailing
    /// `\n`, OR the typed payload itself is structurally invalid.
    /// Leading/trailing whitespace other than a single final LF, CRLF
    /// line endings, extra blank lines, internal whitespace, header
    /// length-field violations, and internal-checksum mismatch all
    /// surface here.
    MalformedPublicKey,
    /// `.fcr` `kind` byte does not match the expected value for this
    /// operation (e.g. caller asked for `.fcr` but got a `private.key`,
    /// or vice versa). `FORMAT.md` §3.1.
    WrongKind {
        /// Raw `kind` byte from the file prefix.
        kind: u8,
    },
    /// Structural defect in the header_fixed layout (non-zero
    /// `header_flags`, `ext_len` over the structural cap, or length
    /// fields that don't sum to `header_len`). Distinct from
    /// [`Self::OversizedHeader`] (header_len > 16 MiB structural max) and
    /// [`Self::RecipientCountOutOfRange`] (recipient_count outside 1..=4096).
    /// `FORMAT.md` §3.2.
    MalformedHeader,
    /// `header_len` exceeds the structural maximum (`HEADER_LEN_MAX =
    /// 16 MiB` per `FORMAT.md` §3.1). Distinct from
    /// [`CryptoError::HeaderLenCapExceeded`] which fires on the
    /// caller-configured local cap (resource policy, not format
    /// violation).
    OversizedHeader {
        /// Header length declared by the `.fcr` prefix, in bytes.
        header_len: u32,
    },
    /// `recipient_count` is outside the structural range `1..=4096`
    /// (`FORMAT.md` §3.2). Distinct from
    /// [`CryptoError::RecipientCountCapExceeded`] which fires on the
    /// caller-configured local cap.
    RecipientCountOutOfRange {
        /// Recipient count declared by `header_fixed`.
        count: u16,
    },
    /// Recipient `type_name` does not satisfy the grammar in
    /// `FORMAT.md` §3.3 (lowercase ASCII, allowed character set, no
    /// leading/trailing punctuation, no `..` or `//`).
    MalformedTypeName,
    /// Recipient entry framing is structurally invalid: 8-byte header
    /// truncated, length fields out of range, declared entry size
    /// exceeds the bytes available, or the recipient region's per-entry
    /// total accounting doesn't add up to `recipient_entries_len`.
    /// `FORMAT.md` §3.3.
    MalformedRecipientEntry,
    /// Recipient entry has reserved bits set in `recipient_flags`. Per
    /// `FORMAT.md` §3.4, only bit 0 (the `critical` flag) is defined in
    /// v1; all other bits MUST be zero on the wire.
    RecipientFlagsReserved,
    /// `private.key` cleartext header is structurally invalid: bad
    /// magic-after-prefix-checks, non-zero `key_flags`, length fields
    /// out of structural range, declared variable fields exceed the
    /// file size, or trailing bytes after the wrapped secret. Per
    /// `FORMAT.md` §8.
    MalformedPrivateKey,
    /// Inner FCA archive `version` byte is not one this release can
    /// read. Distinct from the outer `.fcr` / `private.key` version
    /// rejection in [`UnsupportedVersion`]: this variant fires inside
    /// the encrypted payload after the outer container is accepted, so
    /// it is a structural defect of the inner archive grammar (FCA),
    /// not of the outer FerroCrypt file. Per `FORMAT.md` §9 / §12.
    UnsupportedArchiveVersion {
        /// FCA archive version byte from the encrypted payload.
        version: u8,
    },
}

impl std::fmt::Display for FormatDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("File is truncated or corrupted"),
            Self::BadMagic => f.write_str("Not a FerroCrypt file"),
            Self::ExtTooLarge { len } => {
                write!(f, "Extension region is too large ({len} bytes)")
            }
            Self::MalformedTlv => f.write_str("Extension region is malformed"),
            Self::UnknownCriticalTag { tag } => write!(
                f,
                "Unknown required file feature (tag 0x{tag:04X}). Upgrade FerroCrypt."
            ),
            Self::NotAKeyFile => f.write_str("Not a FerroCrypt key file"),
            Self::WrongKeyFileType => f.write_str("Wrong key file kind (public vs private)"),
            Self::MalformedPublicKey => f.write_str("Public key is malformed"),
            Self::WrongKind { kind } => {
                write!(f, "Wrong file kind: 0x{kind:02X}")
            }
            Self::MalformedHeader => f.write_str("File header is malformed"),
            Self::OversizedHeader { header_len } => {
                write!(f, "File header is too large ({header_len} bytes)")
            }
            Self::RecipientCountOutOfRange { count } => {
                write!(f, "Recipient count out of range ({count})")
            }
            Self::MalformedTypeName => f.write_str("Recipient type name is malformed"),
            Self::MalformedRecipientEntry => f.write_str("Recipient entry is malformed"),
            Self::RecipientFlagsReserved => f.write_str("Recipient entry uses reserved flag bits"),
            Self::MalformedPrivateKey => f.write_str("Private key is malformed"),
            Self::UnsupportedArchiveVersion { version } => {
                write!(
                    f,
                    "Unsupported archive version (v{version}). Upgrade FerroCrypt."
                )
            }
        }
    }
}

/// File-format or key-file version rejection. Carries the raw version
/// byte so callers can inspect it without parsing a formatted string.
///
/// The four variant pairs cover FerroCrypt's three independent on-disk
/// version domains:
///
/// - `OlderFile` / `NewerFile` — `.fcr` outer-file version (`FORMAT.md` §3.1);
/// - `OlderKey` / `NewerKey` — `private.key` wire-version byte
///   (`FORMAT.md` §8). "Key" rather than "PrivateKey" for backwards
///   compatibility with v0.x callers that pattern-match on the variant
///   names;
/// - `OlderPublicKey` / `NewerPublicKey` — `public.key` recipient-payload
///   version (`FORMAT.md` §7). Distinct from the `Key` pair because the
///   private-key wire encoding and the public-key payload encoding are
///   different on-disk shapes that may produce the same logical
///   keypair-suite v from different bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnsupportedVersion {
    /// Encrypted file version is older than the current release supports.
    OlderFile {
        /// Version byte read from the encrypted-file prefix.
        version: u8,
    },
    /// Encrypted file version is newer than the current release supports.
    NewerFile {
        /// Version byte read from the encrypted-file prefix.
        version: u8,
    },
    /// `private.key` wire version is older than the current release
    /// accepts.
    OlderKey {
        /// Wire-version byte read from the `private.key` fixed header.
        version: u8,
    },
    /// `private.key` wire version is newer than the current release
    /// accepts.
    NewerKey {
        /// Wire-version byte read from the `private.key` fixed header.
        version: u8,
    },
    /// `public.key` recipient-payload version is older than the current
    /// release accepts. Surfaced when a public recipient (Bech32 string
    /// or `public.key` file) is offered for encryption but its key-pair
    /// suite is no longer supported by this build. Per `FORMAT.md` §7
    /// and the symmetry rule in §11, a release MUST NOT accept a public
    /// key for encryption unless the same key-pair suite remains
    /// supported for private-key decryption.
    OlderPublicKey {
        /// Wire-version byte read from the recipient payload.
        version: u8,
    },
    /// `public.key` recipient-payload version is newer than the current
    /// release accepts. Carries the leading version byte read from the
    /// recipient payload's offset 0.
    NewerPublicKey {
        /// Wire-version byte from the recipient payload.
        version: u8,
    },
}

impl std::fmt::Display for UnsupportedVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OlderFile { version } => {
                write!(f, "Older file format (v{version}). Use a previous release.")
            }
            Self::NewerFile { version } => {
                write!(f, "Newer file format (v{version}). Upgrade FerroCrypt.")
            }
            Self::OlderKey { version } => {
                write!(f, "Older key format (v{version}). Use a previous release.")
            }
            Self::NewerKey { version } => {
                write!(f, "Newer key format (v{version}). Upgrade FerroCrypt.")
            }
            Self::OlderPublicKey { version } => {
                write!(
                    f,
                    "Older public-key format (v{version}). Generate a new key pair."
                )
            }
            Self::NewerPublicKey { version } => {
                write!(
                    f,
                    "Newer public-key format (v{version}). Upgrade FerroCrypt."
                )
            }
        }
    }
}

/// Which KDF parameter from an untrusted header failed its structural
/// bound check. Carries the raw value so callers can decide whether to
/// re-try with looser limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidKdfParams {
    /// `lanes` is zero or exceeds the library's maximum.
    Parallelism(u32),
    /// `mem_cost` is below the per-lane minimum or exceeds the library's
    /// maximum.
    MemoryCost(u32),
    /// `time_cost` is zero or exceeds the library's maximum.
    TimeCost(u32),
}

impl std::fmt::Display for InvalidKdfParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parallelism(n) => {
                write!(f, "File has invalid KDF settings (parallelism {n})")
            }
            Self::MemoryCost(n) => {
                write!(f, "File has invalid KDF settings ({n} KiB memory)")
            }
            Self::TimeCost(n) => write!(f, "File has invalid KDF settings (time cost {n})"),
        }
    }
}

/// Errors that `DecryptReader` and `EncryptWriter` surface via [`std::io::Error`]
/// through the [`std::io::Read`] / [`std::io::Write`] trait boundary. The
/// `From<io::Error> for CryptoError` impl below downcasts these back into
/// typed [`CryptoError`] variants at the boundary where `?` converts
/// `io::Result` into `Result<_, CryptoError>`.
#[derive(Debug)]
pub(crate) enum StreamError {
    /// Streaming AEAD decryption rejected a chunk's authentication tag.
    DecryptAead,
    /// Streaming AEAD encryption failed (unreachable in practice for valid inputs).
    EncryptAead,
    /// Encrypted stream ended before the final-flag chunk.
    Truncated,
    /// Bytes remain after the final-flag chunk was successfully
    /// decrypted. Raised by the post-`decrypt_last_in_place` probe
    /// in [`crate::crypto::stream::DecryptReader::fill_buffer`]. Ordinary
    /// appended-bytes cases on a plain `File` / `&[u8]` reader fail
    /// earlier via [`StreamError::DecryptAead`] (STREAM-BE32's
    /// per-chunk nonce binding rejects a naive append as an AEAD
    /// tamper); this variant is the defense-in-depth path for
    /// pathological readers that signal EOF at the chunk boundary
    /// and then yield more bytes (non-blocking sockets, buggy
    /// `Take`-style wrappers). Downcast to
    /// [`CryptoError::ExtraDataAfterPayload`] via `From<io::Error>`.
    ExtraData,
    /// Writer or reader state was already consumed (programmer bug).
    StateExhausted,
    /// `FORMAT.md` §5: writers MUST NOT emit more than `2^32` chunks
    /// and readers MUST reject streams that exceed that count. Surfaced
    /// when ferrocrypt's own counter trips before the upstream
    /// STREAM-BE32 primitive's counter overflow does.
    ChunkCountExceeded,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            StreamError::DecryptAead => "Payload authentication failed",
            StreamError::EncryptAead => "payload encryption failed",
            StreamError::Truncated => "Encrypted stream truncated",
            StreamError::ExtraData => "Encrypted stream has trailing data",
            StreamError::StateExhausted => "stream state already finalized",
            StreamError::ChunkCountExceeded => "Encrypted stream exceeds supported data size",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for StreamError {}

impl From<std::io::Error> for CryptoError {
    fn from(e: std::io::Error) -> Self {
        // If the io::Error carries one of our typed stream markers,
        // convert it back into the appropriate CryptoError variant
        // instead of wrapping it as an opaque Io. The `EncryptAead` and
        // `StateExhausted` branches pass the same bare marker as
        // `StreamError`'s Display text; the `InternalCryptoFailure` /
        // `InternalInvariant` Display adds the `Internal …:` prefix.
        if let Some(stream_err) = e
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<StreamError>())
        {
            return match stream_err {
                StreamError::DecryptAead => CryptoError::PayloadTampered,
                StreamError::Truncated => CryptoError::PayloadTruncated,
                StreamError::ExtraData => CryptoError::ExtraDataAfterPayload,
                StreamError::ChunkCountExceeded => CryptoError::PayloadChunkCountExceeded,
                StreamError::EncryptAead => {
                    CryptoError::InternalCryptoFailure("payload encryption failed")
                }
                StreamError::StateExhausted => {
                    CryptoError::InternalInvariant("stream state already finalized")
                }
            };
        }
        CryptoError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipient::policy::NativeMixingRule;

    /// Lock in the exact user-facing Display text for the bare `CryptoError`
    /// variants. The CLI and desktop app surface `Display` directly, so a
    /// silent wording change would be a visible UX regression. If a message
    /// genuinely needs to change, update this test in the same commit so
    /// the intent is reviewable.
    #[test]
    fn typed_decryption_errors_display_exact_strings() {
        assert_eq!(
            CryptoError::InputPath.to_string(),
            "Input file or folder missing"
        );
        assert_eq!(
            CryptoError::KeyFileUnlockFailed.to_string(),
            "Private key unlock failed: wrong passphrase or modified key file"
        );
        assert_eq!(
            CryptoError::HeaderTampered.to_string(),
            "Decryption failed: file header was modified or corrupted"
        );
        assert_eq!(
            CryptoError::HeaderMacFailedAfterUnwrap {
                type_name: "x25519".to_owned()
            }
            .to_string(),
            "Decryption failed: file header was modified or corrupted"
        );
        // `type_name` is intentionally over `TYPE_NAME_DISPLAY_MAX` to
        // exercise truncation: a 14-char input renders as 12 chars +
        // `…` (= 13 chars total), keeping the full message under the
        // 64-char desktop budget.
        assert_eq!(
            CryptoError::UnknownCriticalRecipient {
                type_name: "mlkem768x25519".to_owned()
            }
            .to_string(),
            "Unsupported recipient `mlkem768x255…`. Upgrade FerroCrypt."
        );
        assert_eq!(
            CryptoError::NoSupportedRecipient.to_string(),
            "Decryption failed: no supported recipient"
        );
        assert_eq!(
            CryptoError::DecryptorModeMismatch {
                expected: UnauthenticatedRecipientMode::Passphrase,
                found: UnauthenticatedRecipientMode::PublicKey,
            }
            .to_string(),
            "File is public-key encrypted; use a private key"
        );
        assert_eq!(
            CryptoError::DecryptorModeMismatch {
                expected: UnauthenticatedRecipientMode::PublicKey,
                found: UnauthenticatedRecipientMode::Passphrase,
            }
            .to_string(),
            "File is passphrase encrypted; use a passphrase"
        );
        assert_eq!(
            CryptoError::EmptyRecipientList.to_string(),
            "Recipient list cannot be empty"
        );
        assert_eq!(
            CryptoError::IncompatibleRecipients {
                type_name: "argon2id".to_owned(),
                policy: MixingPolicy::Exclusive,
            }
            .to_string(),
            "Recipient `argon2id` mixed with another recipient"
        );
        // Worst-case truncation: a 14-char `type_name` renders as
        // 12 chars + `…` = 13 chars total inside the message, holding
        // the rendered output under the 64-char desktop budget.
        assert_eq!(
            CryptoError::IncompatibleRecipients {
                type_name: "mlkem768x25519".to_owned(),
                policy: MixingPolicy::Exclusive,
            }
            .to_string(),
            "Recipient `mlkem768x255…` mixed with another recipient"
        );
        // The new Custom variant projects through Display the same way
        // — the `compatibility_class` payload is structured diagnostic
        // detail for programmatic consumers, not part of the
        // user-facing message. (15-char input renders as 12 chars + `…`.)
        assert_eq!(
            CryptoError::IncompatibleRecipients {
                type_name: "x25519-mlkem768".to_owned(),
                policy: MixingPolicy::Custom {
                    compatibility_class: NativeMixingRule::POST_QUANTUM_CLASS,
                },
            }
            .to_string(),
            "Recipient `x25519-mlkem…` mixed with another recipient"
        );
        assert_eq!(
            CryptoError::PayloadTampered.to_string(),
            "Decryption failed: file data was modified or corrupted"
        );
        assert_eq!(
            CryptoError::PayloadTruncated.to_string(),
            "Encrypted file is truncated"
        );
        assert_eq!(
            CryptoError::ExtraDataAfterPayload.to_string(),
            "Encrypted file has unexpected trailing data"
        );
        assert_eq!(
            CryptoError::PayloadChunkCountExceeded.to_string(),
            "Encrypted file exceeds supported data size"
        );
        // A public-key recipient keeps the no-match-or-modified-file
        // ambiguity; the passphrase recipient reports a wrong passphrase or
        // modified file. `type_name` is not shown.
        assert_eq!(
            CryptoError::RecipientUnwrapFailed {
                type_name: "x25519".to_owned()
            }
            .to_string(),
            "Decryption failed: no matching recipient or modified file"
        );
        assert_eq!(
            CryptoError::RecipientUnwrapFailed {
                type_name: "argon2id".to_owned()
            }
            .to_string(),
            "Decryption failed: wrong passphrase or modified file"
        );
        assert_eq!(
            CryptoError::RecipientBodyCapExceeded {
                body_len: 10_000,
                local_cap: 8_192
            }
            .to_string(),
            "Recipient data too large (10000 bytes, limit 8192)"
        );
        assert_eq!(
            CryptoError::RecipientStringCapExceeded {
                input_chars: 5_000,
                local_cap: 1_024,
            }
            .to_string(),
            "Recipient string too long (5000 chars, limit 1024)"
        );
        assert_eq!(
            CryptoError::HeaderLenCapExceeded {
                header_len: 2_000_000,
                local_cap: 1_048_576,
            }
            .to_string(),
            "Header too large (2000000 bytes, limit 1048576)"
        );
        assert_eq!(
            CryptoError::RecipientCountCapExceeded {
                count: 100,
                local_cap: 64,
            }
            .to_string(),
            "Too many recipients (100 entries, limit 64)"
        );
        assert_eq!(
            CryptoError::KdfResourceCapExceeded {
                mem_cost_kib: 1_048_576,
                local_cap_kib: 524_288,
            }
            .to_string(),
            "Passphrase memory over limit (1048576 KiB, limit 524288)"
        );
        assert_eq!(
            CryptoError::KdfTimeCostCapExceeded {
                time_cost: 8,
                local_cap: 6,
            }
            .to_string(),
            "Passphrase time over limit (8, limit 6)"
        );
        assert_eq!(
            CryptoError::KdfLanesCapExceeded {
                lanes: 4,
                local_cap: 2,
            }
            .to_string(),
            "Passphrase parallelism over limit (4, limit 2)"
        );
        assert_eq!(
            CryptoError::KdfBelowWriteFloor {
                mem_cost_kib: 8_192,
                floor_kib: 19_456,
            }
            .to_string(),
            "Passphrase memory too low (8192 KiB, needs 19456 KiB)"
        );
    }

    /// Lock in the Display text of the typed `FormatDefect`,
    /// `UnsupportedVersion`, and `InvalidKdfParams` variants so
    /// wording regressions are caught at test time.
    #[test]
    fn typed_format_variants_display_exact_strings() {
        assert_eq!(
            FormatDefect::Truncated.to_string(),
            "File is truncated or corrupted"
        );
        assert_eq!(FormatDefect::BadMagic.to_string(), "Not a FerroCrypt file");
        assert_eq!(
            FormatDefect::ExtTooLarge { len: 65_537 }.to_string(),
            "Extension region is too large (65537 bytes)"
        );
        assert_eq!(
            FormatDefect::MalformedTlv.to_string(),
            "Extension region is malformed"
        );
        assert_eq!(
            FormatDefect::UnknownCriticalTag { tag: 0x8001 }.to_string(),
            "Unknown required file feature (tag 0x8001). Upgrade FerroCrypt."
        );
        assert_eq!(
            FormatDefect::NotAKeyFile.to_string(),
            "Not a FerroCrypt key file"
        );
        assert_eq!(
            FormatDefect::WrongKeyFileType.to_string(),
            "Wrong key file kind (public vs private)"
        );
        assert_eq!(
            FormatDefect::MalformedPublicKey.to_string(),
            "Public key is malformed"
        );
        assert_eq!(
            FormatDefect::WrongKind { kind: 0x99 }.to_string(),
            "Wrong file kind: 0x99"
        );
        assert_eq!(
            FormatDefect::MalformedHeader.to_string(),
            "File header is malformed"
        );
        assert_eq!(
            FormatDefect::OversizedHeader {
                header_len: 16_777_217
            }
            .to_string(),
            "File header is too large (16777217 bytes)"
        );
        assert_eq!(
            FormatDefect::MalformedTypeName.to_string(),
            "Recipient type name is malformed"
        );
        assert_eq!(
            FormatDefect::MalformedRecipientEntry.to_string(),
            "Recipient entry is malformed"
        );
        assert_eq!(
            FormatDefect::RecipientFlagsReserved.to_string(),
            "Recipient entry uses reserved flag bits"
        );
        assert_eq!(
            FormatDefect::MalformedPrivateKey.to_string(),
            "Private key is malformed"
        );
        assert_eq!(
            FormatDefect::UnsupportedArchiveVersion { version: 0xFF }.to_string(),
            "Unsupported archive version (v255). Upgrade FerroCrypt."
        );
        assert_eq!(
            FormatDefect::RecipientCountOutOfRange { count: 5000 }.to_string(),
            "Recipient count out of range (5000)"
        );
        assert_eq!(
            UnsupportedVersion::NewerFile { version: 9 }.to_string(),
            "Newer file format (v9). Upgrade FerroCrypt."
        );
        assert_eq!(
            UnsupportedVersion::OlderFile { version: 1 }.to_string(),
            "Older file format (v1). Use a previous release."
        );
        assert_eq!(
            UnsupportedVersion::NewerKey { version: 9 }.to_string(),
            "Newer key format (v9). Upgrade FerroCrypt."
        );
        assert_eq!(
            UnsupportedVersion::OlderKey { version: 1 }.to_string(),
            "Older key format (v1). Use a previous release."
        );
        assert_eq!(
            UnsupportedVersion::OlderPublicKey { version: 1 }.to_string(),
            "Older public-key format (v1). Generate a new key pair."
        );
        assert_eq!(
            UnsupportedVersion::NewerPublicKey { version: 9 }.to_string(),
            "Newer public-key format (v9). Upgrade FerroCrypt."
        );
        assert_eq!(
            InvalidKdfParams::Parallelism(9999).to_string(),
            "File has invalid KDF settings (parallelism 9999)"
        );
        assert_eq!(
            InvalidKdfParams::MemoryCost(42).to_string(),
            "File has invalid KDF settings (42 KiB memory)"
        );
        assert_eq!(
            InvalidKdfParams::TimeCost(7).to_string(),
            "File has invalid KDF settings (time cost 7)"
        );

        // StreamError Display text. The four user-facing markers
        // (DecryptAead, Truncated, ExtraData, ChunkCountExceeded) start
        // capitalized like the rest of the error surface; the two
        // internal-bug markers (EncryptAead, StateExhausted) are
        // deliberately lowercase because they only ever render after an
        // "Internal ...:" prefix. This is the only place the user-facing
        // markers' wording is locked in — they downcast to typed
        // CryptoError variants that carry their own Display.
        assert_eq!(
            StreamError::DecryptAead.to_string(),
            "Payload authentication failed"
        );
        assert_eq!(
            StreamError::EncryptAead.to_string(),
            "payload encryption failed"
        );
        assert_eq!(
            StreamError::Truncated.to_string(),
            "Encrypted stream truncated"
        );
        assert_eq!(
            StreamError::ExtraData.to_string(),
            "Encrypted stream has trailing data"
        );
        assert_eq!(
            StreamError::StateExhausted.to_string(),
            "stream state already finalized"
        );
        assert_eq!(
            StreamError::ChunkCountExceeded.to_string(),
            "Encrypted stream exceeds supported data size"
        );
    }

    /// Lock in the Display text of the archive defect and cap variants.
    /// The path-carrying variants are deliberately not part of the
    /// 64-char status-line budget: they exist to locate one bad entry
    /// in a large archive, so the (sanitized, truncated) path is the
    /// payload.
    #[test]
    fn archive_errors_display_exact_strings() {
        assert_eq!(
            CryptoError::MalformedArchive {
                reason: "bad magic"
            }
            .to_string(),
            "Malformed archive: bad magic"
        );
        assert_eq!(
            CryptoError::UnsafeArchivePath {
                path: "../etc/passwd".to_owned(),
                reason: "forbidden component",
            }
            .to_string(),
            "Unsafe archive path (forbidden component): ../etc/passwd"
        );
        assert_eq!(
            CryptoError::InvalidArchiveTree {
                path: "root/a.txt".to_owned(),
                reason: "duplicate entry",
            }
            .to_string(),
            "Invalid archive tree (duplicate entry): root/a.txt"
        );
        assert_eq!(
            CryptoError::ArchiveEntryCountCapExceeded {
                entry_count: 250_001,
                local_cap: 250_000,
            }
            .to_string(),
            "Too many archive entries (250001, limit 250000)"
        );
        assert_eq!(
            CryptoError::ArchiveTotalBytesCapExceeded {
                total_bytes: 100,
                local_cap: 99,
            }
            .to_string(),
            "Archive is too large (limit 99 bytes)"
        );
        assert_eq!(
            CryptoError::ArchiveManifestLenCapExceeded {
                manifest_len: 100,
                local_cap: 99,
            }
            .to_string(),
            "Archive manifest is too large (limit 99 bytes)"
        );
        assert_eq!(
            CryptoError::ArchivePathBytesCapExceeded {
                path_bytes: 100,
                local_cap: 99,
                path: None,
            }
            .to_string(),
            "Archive path too long (100 bytes, limit 99)"
        );
        assert_eq!(
            CryptoError::ArchivePathBytesCapExceeded {
                path_bytes: 100,
                local_cap: 99,
                path: Some("root/long".to_owned()),
            }
            .to_string(),
            "Archive path too long (100 bytes, limit 99): root/long"
        );
        assert_eq!(
            CryptoError::ArchivePathDepthCapExceeded {
                depth: 65,
                local_cap: 64,
                path: "a/b".to_owned(),
            }
            .to_string(),
            "Archive path too deep (65 components, limit 64): a/b"
        );
        assert_eq!(
            CryptoError::ArchiveExtLenCapExceeded {
                ext_len: 100,
                local_cap: 99,
            }
            .to_string(),
            "Archive extension is too large (limit 99 bytes)"
        );
        assert_eq!(
            CryptoError::ArchiveEntryExtLenCapExceeded {
                ext_len: 100,
                local_cap: 99,
                path: None,
            }
            .to_string(),
            "Archive entry extension is too large (limit 99 bytes)"
        );
        assert_eq!(
            CryptoError::ArchiveTotalEntryExtCapExceeded {
                total_ext_bytes: 100,
                local_cap: 99,
            }
            .to_string(),
            "Archive entry extensions too large (limit 99 bytes)"
        );
        assert_eq!(
            CryptoError::PrivateKeyWrappedSecretCapExceeded {
                wrapped_secret_len: 5000,
                local_cap: 4096,
            }
            .to_string(),
            "Private key data too large (5000 bytes, limit 4096)"
        );
        // Internal errors prefix a bounded marker; the marker stays in the
        // variant payload for bug reports.
        assert_eq!(
            CryptoError::InternalInvariant("envelope ciphertext size mismatch").to_string(),
            "Internal error: envelope ciphertext size mismatch"
        );
        assert_eq!(
            CryptoError::InternalCryptoFailure("payload encryption failed").to_string(),
            "Internal crypto error: payload encryption failed"
        );
    }

    /// The display sanitizer passes printable ASCII through, escapes
    /// control bytes and every non-ASCII character (including
    /// direction-override code points), and truncates long input.
    #[test]
    fn sanitize_for_display_escapes_and_truncates() {
        assert_eq!(
            sanitize_for_display("plain path/file.txt"),
            "plain path/file.txt"
        );
        assert_eq!(
            sanitize_for_display("a\x1b]0;pwned\x07b"),
            "a\\u{1b}]0;pwned\\u{7}b"
        );
        assert_eq!(sanitize_for_display("nul\0byte"), "nul\\u{0}byte");
        assert_eq!(
            sanitize_for_display("bidi\u{202e}gpj.txt"),
            "bidi\\u{202e}gpj.txt"
        );
        assert_eq!(sanitize_for_display("caf\u{e9}"), "caf\\u{e9}");

        let long: String = "x".repeat(UNTRUSTED_TEXT_DISPLAY_MAX + 10);
        let rendered = sanitize_for_display(&long);
        assert_eq!(
            rendered.chars().count(),
            UNTRUSTED_TEXT_DISPLAY_MAX + 1,
            "64 kept chars plus the ellipsis"
        );
        assert!(rendered.ends_with('…'));

        let exact: String = "y".repeat(UNTRUSTED_TEXT_DISPLAY_MAX);
        assert_eq!(
            sanitize_for_display(&exact),
            exact,
            "at-cap input is untouched"
        );
    }

    /// The path wrapper applies the same escaping as
    /// [`sanitize_for_display`], so a caller-supplied path whose file
    /// name carries terminal-escape bytes renders escaped, never raw.
    #[test]
    fn sanitize_path_for_display_escapes_hostile_name() {
        let path = std::path::Path::new("dir/evil\u{1b}]0;pwned\u{7}.txt");
        let rendered = sanitize_path_for_display(path);
        assert!(
            !rendered.chars().any(char::is_control),
            "raw control character leaked: {rendered:?}"
        );
        assert_eq!(rendered, "dir/evil\\u{1b}]0;pwned\\u{7}.txt");
    }

    /// Defense-in-depth: a `type_name` carrying terminal-escape or
    /// direction-override bytes — only reachable via a hand-constructed
    /// `CryptoError`, since the FORMAT.md §3.3 grammar rejects such names —
    /// is escaped and bounded in the rendered message, never emitted raw.
    /// Guards the `write_sanitized_char` path through `DisplayableTypeName`,
    /// exercised here via a variant that still renders `type_name`.
    #[test]
    fn type_name_in_error_is_escaped_not_emitted_raw() {
        let msg = CryptoError::IncompatibleRecipients {
            type_name: "\u{1b}\u{202e}".to_owned(),
            policy: MixingPolicy::Exclusive,
        }
        .to_string();
        assert_eq!(msg, "Recipient `\\u{1b}…` mixed with another recipient");
        assert!(!msg.contains('\u{1b}'), "raw ESC must not appear: {msg:?}");
        assert!(msg.chars().count() <= 64, "message over budget: {msg}");
    }

    #[test]
    fn type_name_escape_truncation_keeps_status_budget() {
        let msg = CryptoError::UnknownCriticalRecipient {
            type_name: "\u{202e}".repeat(20),
        }
        .to_string();
        assert!(
            !msg.contains('\u{202e}'),
            "raw bidi char must not appear: {msg:?}"
        );
        assert!(msg.contains('…'), "hostile name should be truncated: {msg}");
        assert!(msg.chars().count() <= 64, "message over budget: {msg}");
    }

    /// Budget: every static user-facing `CryptoError` message — plus
    /// the worst-case formatted variants — must fit in the desktop
    /// status line's 64-char window.
    #[test]
    fn user_facing_messages_fit_status_line_budget() {
        const BUDGET: usize = 64;

        // Count `chars` (display columns for the ASCII-plus-ellipsis
        // alphabet we actually emit), not bytes: the budget is the
        // status-line column width, and a multi-byte glyph like the
        // truncation ellipsis (`…`, 3 bytes / 1 column) must count
        // for a single column.
        fn check(label: &str, msg: &str) {
            let chars = msg.chars().count();
            assert!(
                chars <= BUDGET,
                "message over {BUDGET}-char budget ({chars} chars) [{label}]: {msg}",
            );
        }

        // Fixed-payload CryptoError variants.
        check("InputPath", &CryptoError::InputPath.to_string());
        check(
            "KeyFileUnlockFailed",
            &CryptoError::KeyFileUnlockFailed.to_string(),
        );
        check("HeaderTampered", &CryptoError::HeaderTampered.to_string());
        check(
            "HeaderMacFailedAfterUnwrap",
            &CryptoError::HeaderMacFailedAfterUnwrap {
                type_name: "x25519".to_owned(),
            }
            .to_string(),
        );
        check(
            "NoSupportedRecipient",
            &CryptoError::NoSupportedRecipient.to_string(),
        );
        check(
            "DecryptorModeMismatch(passphrase, public-key)",
            &CryptoError::DecryptorModeMismatch {
                expected: UnauthenticatedRecipientMode::Passphrase,
                found: UnauthenticatedRecipientMode::PublicKey,
            }
            .to_string(),
        );
        check(
            "DecryptorModeMismatch(public-key, passphrase)",
            &CryptoError::DecryptorModeMismatch {
                expected: UnauthenticatedRecipientMode::PublicKey,
                found: UnauthenticatedRecipientMode::Passphrase,
            }
            .to_string(),
        );
        check(
            "EmptyRecipientList",
            &CryptoError::EmptyRecipientList.to_string(),
        );
        check(
            "IncompatibleRecipients(argon2id, Exclusive)",
            &CryptoError::IncompatibleRecipients {
                type_name: "argon2id".to_owned(),
                policy: MixingPolicy::Exclusive,
            }
            .to_string(),
        );
        // Truncated `type_name` upper bound: 14 chars in, 13 chars
        // out (`mlkem768x255…`), exercising the budget on the
        // longest plausibly-rendered Exclusive-policy native name.
        check(
            "IncompatibleRecipients(truncated, Exclusive)",
            &CryptoError::IncompatibleRecipients {
                type_name: "mlkem768x25519".to_owned(),
                policy: MixingPolicy::Exclusive,
            }
            .to_string(),
        );
        check(
            "IncompatibleRecipients(argon2id, PublicKeyMixable)",
            &CryptoError::IncompatibleRecipients {
                type_name: "argon2id".to_owned(),
                policy: MixingPolicy::PublicKeyMixable,
            }
            .to_string(),
        );
        // Same budget assertion against the Custom variant — the
        // structured `compatibility_class` payload doesn't widen the
        // user-facing message, but lock the worst-case `type_name`
        // truncation against a plausibly-rendered PQ class so a
        // future Display-impl change cannot regress the budget.
        check(
            "IncompatibleRecipients(truncated, Custom)",
            &CryptoError::IncompatibleRecipients {
                type_name: "x25519-mlkem768".to_owned(),
                policy: MixingPolicy::Custom {
                    compatibility_class: NativeMixingRule::POST_QUANTUM_CLASS,
                },
            }
            .to_string(),
        );
        check("PayloadTampered", &CryptoError::PayloadTampered.to_string());
        check(
            "RecipientUnwrapFailed(passphrase)",
            &CryptoError::RecipientUnwrapFailed {
                type_name: "argon2id".to_owned(),
            }
            .to_string(),
        );
        check(
            "RecipientUnwrapFailed(public-key)",
            &CryptoError::RecipientUnwrapFailed {
                type_name: "x25519".to_owned(),
            }
            .to_string(),
        );
        check(
            "PayloadTruncated",
            &CryptoError::PayloadTruncated.to_string(),
        );
        check(
            "ExtraDataAfterPayload",
            &CryptoError::ExtraDataAfterPayload.to_string(),
        );
        check(
            "PayloadChunkCountExceeded",
            &CryptoError::PayloadChunkCountExceeded.to_string(),
        );
        // Cap-exceeded variants at worst-case integer payloads — the
        // budget assertion has to hold even when both fields render at
        // their maximum width.
        check(
            "KdfResourceCapExceeded(max)",
            &CryptoError::KdfResourceCapExceeded {
                mem_cost_kib: u32::MAX,
                local_cap_kib: u32::MAX,
            }
            .to_string(),
        );
        check(
            "KdfBelowWriteFloor(max)",
            &CryptoError::KdfBelowWriteFloor {
                mem_cost_kib: u32::MAX,
                floor_kib: u32::MAX,
            }
            .to_string(),
        );
        check(
            "KdfTimeCostCapExceeded(max)",
            &CryptoError::KdfTimeCostCapExceeded {
                time_cost: u32::MAX,
                local_cap: u32::MAX,
            }
            .to_string(),
        );
        check(
            "KdfLanesCapExceeded(max)",
            &CryptoError::KdfLanesCapExceeded {
                lanes: u32::MAX,
                local_cap: u32::MAX,
            }
            .to_string(),
        );
        check(
            "HeaderLenCapExceeded(max)",
            &CryptoError::HeaderLenCapExceeded {
                header_len: u32::MAX,
                local_cap: u32::MAX,
            }
            .to_string(),
        );
        check(
            "RecipientCountCapExceeded(max)",
            &CryptoError::RecipientCountCapExceeded {
                count: u16::MAX,
                local_cap: u16::MAX,
            }
            .to_string(),
        );
        check(
            "RecipientBodyCapExceeded(max)",
            &CryptoError::RecipientBodyCapExceeded {
                body_len: u32::MAX,
                local_cap: u32::MAX,
            }
            .to_string(),
        );
        check(
            "RecipientStringCapExceeded(max)",
            &CryptoError::RecipientStringCapExceeded {
                input_chars: u32::MAX,
                local_cap: u32::MAX,
            }
            .to_string(),
        );

        // Archive limit messages at worst-case field widths. Two are not
        // budget-checked because their rendered length is variable text the
        // desktop elides: `ArchivePathDepthCapExceeded` always carries a
        // path, and `ArchiveTotalEntryExtCapExceeded` carries an unbounded
        // `u64` limit whose extreme values overrun the line. The other
        // path-bearing variants are checked without a path.
        check(
            "ArchiveEntryCountCapExceeded(max)",
            &CryptoError::ArchiveEntryCountCapExceeded {
                entry_count: u32::MAX,
                local_cap: u32::MAX,
            }
            .to_string(),
        );
        check(
            "ArchiveTotalBytesCapExceeded(max)",
            &CryptoError::ArchiveTotalBytesCapExceeded {
                total_bytes: u64::MAX,
                local_cap: u64::MAX,
            }
            .to_string(),
        );
        check(
            "ArchiveManifestLenCapExceeded(max)",
            &CryptoError::ArchiveManifestLenCapExceeded {
                manifest_len: u64::MAX,
                local_cap: u32::MAX,
            }
            .to_string(),
        );
        check(
            "ArchivePathBytesCapExceeded(max, no path)",
            &CryptoError::ArchivePathBytesCapExceeded {
                path_bytes: u32::MAX,
                local_cap: u32::MAX,
                path: None,
            }
            .to_string(),
        );
        check(
            "ArchiveExtLenCapExceeded(max)",
            &CryptoError::ArchiveExtLenCapExceeded {
                ext_len: u64::MAX,
                local_cap: u32::MAX,
            }
            .to_string(),
        );
        check(
            "ArchiveEntryExtLenCapExceeded(max, no path)",
            &CryptoError::ArchiveEntryExtLenCapExceeded {
                ext_len: u64::MAX,
                local_cap: u32::MAX,
                path: None,
            }
            .to_string(),
        );

        // `UnknownCriticalRecipient` still interpolates `type_name`; pin
        // that a worst-case 255-byte name (FORMAT.md §3.3 upper bound) stays
        // in budget after `DisplayableTypeName` truncates it. Recipient
        // unwrap and header-MAC failures no longer show `type_name`, and
        // `IncompatibleRecipients` is covered above.
        let max_name = "x".repeat(u8::MAX as usize);
        check(
            "UnknownCriticalRecipient(max-name)",
            &CryptoError::UnknownCriticalRecipient {
                type_name: max_name,
            }
            .to_string(),
        );

        // Internal markers are bounded by `INTERNAL_MARKER_DISPLAY_MAX`, so
        // even an over-long marker stays within budget after the prefix.
        check(
            "InternalInvariant(long marker)",
            &CryptoError::InternalInvariant(
                "Manifest entry missing source_path during content streaming",
            )
            .to_string(),
        );
        check(
            "InternalCryptoFailure(long marker)",
            &CryptoError::InternalCryptoFailure(
                "Argon2id key derivation failed inside an overlong internal marker",
            )
            .to_string(),
        );

        // FormatDefect — every variant at its worst-case payload.
        let defects: &[(&str, FormatDefect)] = &[
            ("Truncated", FormatDefect::Truncated),
            ("BadMagic", FormatDefect::BadMagic),
            ("ExtTooLarge", FormatDefect::ExtTooLarge { len: u32::MAX }),
            ("MalformedTlv", FormatDefect::MalformedTlv),
            (
                "UnknownCriticalTag",
                FormatDefect::UnknownCriticalTag { tag: u16::MAX },
            ),
            ("NotAKeyFile", FormatDefect::NotAKeyFile),
            ("WrongKeyFileType", FormatDefect::WrongKeyFileType),
            ("MalformedPublicKey", FormatDefect::MalformedPublicKey),
            ("WrongKind", FormatDefect::WrongKind { kind: u8::MAX }),
            ("MalformedHeader", FormatDefect::MalformedHeader),
            (
                "OversizedHeader(max)",
                FormatDefect::OversizedHeader {
                    header_len: u32::MAX,
                },
            ),
            (
                "RecipientCountOutOfRange(max)",
                FormatDefect::RecipientCountOutOfRange { count: u16::MAX },
            ),
            ("MalformedTypeName", FormatDefect::MalformedTypeName),
            (
                "MalformedRecipientEntry",
                FormatDefect::MalformedRecipientEntry,
            ),
            (
                "RecipientFlagsReserved",
                FormatDefect::RecipientFlagsReserved,
            ),
            ("MalformedPrivateKey", FormatDefect::MalformedPrivateKey),
            (
                "UnsupportedArchiveVersion(max)",
                FormatDefect::UnsupportedArchiveVersion { version: u8::MAX },
            ),
        ];
        for (label, d) in defects {
            check(label, &d.to_string());
        }

        // UnsupportedVersion at u8::MAX so the widest numeric render
        // still fits.
        let versions: &[(&str, UnsupportedVersion)] = &[
            (
                "OlderFile(max)",
                UnsupportedVersion::OlderFile { version: u8::MAX },
            ),
            (
                "NewerFile(max)",
                UnsupportedVersion::NewerFile { version: u8::MAX },
            ),
            (
                "OlderKey(max)",
                UnsupportedVersion::OlderKey { version: u8::MAX },
            ),
            (
                "NewerKey(max)",
                UnsupportedVersion::NewerKey { version: u8::MAX },
            ),
            (
                "OlderPublicKey(max)",
                UnsupportedVersion::OlderPublicKey { version: u8::MAX },
            ),
            (
                "NewerPublicKey(max)",
                UnsupportedVersion::NewerPublicKey { version: u8::MAX },
            ),
        ];
        for (label, v) in versions {
            check(label, &v.to_string());
        }

        // InvalidKdfParams at u32::MAX so 10-digit interpolation still
        // fits.
        let kdf: &[(&str, InvalidKdfParams)] = &[
            ("Parallelism(max)", InvalidKdfParams::Parallelism(u32::MAX)),
            ("MemoryCost(max)", InvalidKdfParams::MemoryCost(u32::MAX)),
            ("TimeCost(max)", InvalidKdfParams::TimeCost(u32::MAX)),
        ];
        for (label, p) in kdf {
            check(label, &p.to_string());
        }

        // StreamError (internal-error markers that surface via
        // `InternalCryptoFailure` / `InternalInvariant`).
        check(
            "StreamError::DecryptAead",
            &StreamError::DecryptAead.to_string(),
        );
        check(
            "StreamError::EncryptAead",
            &StreamError::EncryptAead.to_string(),
        );
        check(
            "StreamError::Truncated",
            &StreamError::Truncated.to_string(),
        );
        check(
            "StreamError::ExtraData",
            &StreamError::ExtraData.to_string(),
        );
        check(
            "StreamError::StateExhausted",
            &StreamError::StateExhausted.to_string(),
        );
        check(
            "StreamError::ChunkCountExceeded",
            &StreamError::ChunkCountExceeded.to_string(),
        );
    }

    /// `StreamError` markers must downcast back into their typed
    /// `CryptoError` variants. Guards against an io::Error path accidentally
    /// collapsing into the generic `Io` variant, pins the split between
    /// `InternalInvariant` and `InternalCryptoFailure`, and asserts the
    /// exact `&'static str` payload so the `From<io::Error>` impl cannot
    /// silently drift away from `StreamError::Display`.
    #[test]
    fn stream_error_markers_map_to_typed_variants() {
        fn from_marker(marker: StreamError) -> CryptoError {
            std::io::Error::other(marker).into()
        }
        assert!(matches!(
            from_marker(StreamError::DecryptAead),
            CryptoError::PayloadTampered
        ));
        assert!(matches!(
            from_marker(StreamError::Truncated),
            CryptoError::PayloadTruncated
        ));
        assert!(matches!(
            from_marker(StreamError::ExtraData),
            CryptoError::ExtraDataAfterPayload
        ));
        assert!(matches!(
            from_marker(StreamError::ChunkCountExceeded),
            CryptoError::PayloadChunkCountExceeded
        ));
        match from_marker(StreamError::EncryptAead) {
            CryptoError::InternalCryptoFailure(msg) => {
                assert_eq!(msg, "payload encryption failed");
                assert_eq!(msg, StreamError::EncryptAead.to_string());
            }
            other => panic!("expected InternalCryptoFailure, got {other:?}"),
        }
        match from_marker(StreamError::StateExhausted) {
            CryptoError::InternalInvariant(msg) => {
                assert_eq!(msg, "stream state already finalized");
                assert_eq!(msg, StreamError::StateExhausted.to_string());
            }
            other => panic!("expected InternalInvariant, got {other:?}"),
        }

        // A bare io::Error without a marker must still land in `Io`.
        let plain: CryptoError = std::io::Error::other("bare message").into();
        assert!(
            matches!(plain, CryptoError::Io(_)),
            "unmarked io::Error must map to CryptoError::Io, got {plain:?}"
        );
    }
}
