use thiserror::Error;

use crate::UnauthenticatedRecipientMode;
use crate::recipient::argon2id;
use crate::recipient::policy::MixingPolicy;

/// Maximum number of rendered `chars` (counting an inserted ellipsis as one)
/// a `type_name` may occupy when interpolated into a user-facing error
/// message. The longest interpolating message (`IncompatibleRecipients`)
/// has 41 chars of fixed wording, leaving 23 within the 64-char desktop
/// status-line budget enforced by
/// [`tests::user_facing_messages_fit_status_line_budget`]; 13 are used.
const TYPE_NAME_DISPLAY_MAX: usize = 13;
const _: () = assert!(TYPE_NAME_DISPLAY_MAX >= 1);

/// Escapes `s` into `w` and limits the result to `max` displayed
/// characters, including a trailing `…` when truncated. The function
/// never splits a code point or an escape sequence. `DisplayableTypeName`,
/// `DisplayableMarker`, and `sanitize_for_display` all use this rule.
fn write_truncated_sanitized<W: std::fmt::Write>(
    w: &mut W,
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
            w.write_str(&escaped)?;
            written += escaped_len;
        } else {
            if written < max {
                w.write_str("…")?;
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

/// Largest number of display columns a crate-owned malformed-archive reason
/// may occupy after its fixed prefix. The reasons are registered in
/// `archive::reasons` and validated at compile time.
const MALFORMED_ARCHIVE_REASON_DISPLAY_MAX: usize = 64 - "Malformed archive: ".len();
const _: () = assert!(MALFORMED_ARCHIVE_REASON_DISPLAY_MAX >= 1);

/// Shared text rules for crate-owned fragments appended to a fixed error
/// prefix: non-empty printable ASCII with no terminal punctuation. Width is
/// checked separately, because only some prefixes have a width target.
const fn display_fragment_text_is_valid(fragment: &str) -> bool {
    let bytes = fragment.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    if matches!(bytes[bytes.len() - 1], b'.' | b'!' | b'?') {
        return false;
    }

    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] < b' ' || bytes[index] > b'~' {
            return false;
        }
        index += 1;
    }
    true
}

/// Shared validator for crate-owned fragments whose complete message has a
/// width target: the text rules plus the caller's remaining display width.
/// Printable ASCII makes the byte length also the displayed width.
const fn display_fragment_is_valid(fragment: &str, max: usize) -> bool {
    fragment.len() <= max && display_fragment_text_is_valid(fragment)
}

/// Returns whether a crate-owned malformed-archive reason follows the display
/// policy: non-empty printable ASCII, no terminal punctuation, and short
/// enough to render without truncation after the fixed prefix. Reasons are
/// lowercase sentence fragments; the `Malformed archive: ` prefix supplies
/// the capitalized start of the complete message.
pub(crate) const fn malformed_archive_reason_is_valid(reason: &str) -> bool {
    display_fragment_is_valid(reason, MALFORMED_ARCHIVE_REASON_DISPLAY_MAX)
}

/// Returns whether a crate-owned reason for the two path-bearing archive
/// variants — [`CryptoError::UnsafeArchivePath`] and
/// [`CryptoError::InvalidArchiveTree`] — follows the display policy. Same
/// text rules as [`malformed_archive_reason_is_valid`], without a width
/// bound: those messages append an entry path of their own, so their width
/// is never within the status-line allowance and no bound on the fragment
/// would bring it back inside.
pub(crate) const fn archive_path_reason_is_valid(reason: &str) -> bool {
    display_fragment_text_is_valid(reason)
}

/// Largest number of display columns an internal-error marker may occupy after
/// its fixed prefix. Set to the 64-column status-line budget minus the longer
/// prefix `"Internal crypto error: "`, so both internal messages stay within
/// budget for any marker.
const INTERNAL_MARKER_DISPLAY_MAX: usize = 64 - "Internal crypto error: ".len();
const _: () = assert!(INTERNAL_MARKER_DISPLAY_MAX >= 1);

/// Returns whether a crate-owned internal marker follows the display policy:
/// non-empty printable ASCII, no terminal punctuation, and short enough to
/// render without truncation. Markers begin lowercase unless their first word
/// is a proper name or acronym. Their byte length is therefore also their
/// displayed width.
pub(crate) const fn internal_marker_is_valid(marker: &str) -> bool {
    display_fragment_is_valid(marker, INTERNAL_MARKER_DISPLAY_MAX)
}

macro_rules! internal_invariant {
    ($marker:literal) => {{
        const _: () = assert!($crate::error::internal_marker_is_valid($marker));
        $crate::error::CryptoError::InternalInvariant($marker)
    }};
}

macro_rules! internal_crypto_failure {
    ($marker:literal) => {{
        const _: () = assert!($crate::error::internal_marker_is_valid($marker));
        $crate::error::CryptoError::InternalCryptoFailure($marker)
    }};
}

pub(crate) use internal_crypto_failure;
pub(crate) use internal_invariant;

/// Wraps an internal-error marker so its `Display` escapes non-printable
/// characters and bounds the output to [`INTERNAL_MARKER_DISPLAY_MAX`] columns.
/// Crate-owned markers are fixed `&'static str`s, while variants constructed
/// outside the crate may carry arbitrary static text. Crate-owned markers use
/// `internal_invariant!` or `internal_crypto_failure!`, which reject literals
/// that violate the marker policy at compile time. The display bound keeps
/// `Internal error: {marker}` and `Internal crypto error: {marker}` within the
/// status-line budget.
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

/// Maximum displayed length returned by [`sanitize_for_display`], including
/// escape sequences and a trailing ellipsis. The limit prevents one untrusted
/// value from dominating a terminal or log line.
const UNTRUSTED_TEXT_DISPLAY_MAX: usize = 64;

/// Appends `c` to `w`, passing printable ASCII (and the space character)
/// through unchanged and rendering every other character as a backslash
/// escape (`\n`, `\u{202e}`, …). The one definition of the per-character
/// escape rule, shared by `sanitize_for_display` and `DisplayableTypeName`,
/// so neither can let a malicious character carry a terminal escape sequence
/// or visually reorder the surrounding text.
fn write_sanitized_char<W: std::fmt::Write>(w: &mut W, c: char) -> std::fmt::Result {
    if c.is_ascii_graphic() || c == ' ' {
        w.write_char(c)
    } else {
        write!(w, "{}", c.escape_default())
    }
}

/// Renders untrusted text for use in an error message.
///
/// Printable ASCII is preserved. Control characters and non-ASCII code points
/// use Rust-style escapes, which prevents terminal control sequences and
/// misleading text direction. The displayed result is limited to
/// [`UNTRUSTED_TEXT_DISPLAY_MAX`] characters.
///
/// Use this function for untrusted archive paths, source-tree names, and
/// recipient strings included in errors.
pub(crate) fn sanitize_for_display(text: &str) -> String {
    let mut out = String::new();
    // Writing into a `String` cannot fail.
    let _ = write_truncated_sanitized(&mut out, text, UNTRUSTED_TEXT_DISPLAY_MAX);
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
/// directory readable and untruncated — escaping only control and
/// bidirectional-formatting characters in it — and routes the final
/// component through this stricter, truncating sanitizer.
pub(crate) fn sanitize_path_for_display(path: &std::path::Path) -> String {
    sanitize_for_display(&path.display().to_string())
}

/// Returns whether `c` is a Unicode bidirectional-formatting control.
/// These characters (the "Trojan Source" set) can reorder how the
/// surrounding text is displayed, so they are escaped even inside
/// otherwise readable text such as a trusted directory prefix.
fn is_bidi_control(c: char) -> bool {
    // LRE/RLE/PDF/LRO/RLO, LRI/RLI/FSI/PDI, LRM/RLM, and ALM.
    matches!(
        c,
        '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{061C}'
    )
}

/// Renders a trusted path prefix — the parent directory of an
/// "already exists" conflict — for an error message. Printable
/// characters pass through unchanged, including readable non-ASCII such
/// as accented Latin or CJK, so the operator can still read and locate
/// the directory. Control and bidirectional-formatting characters are
/// escaped so the prefix cannot inject a terminal escape sequence or
/// visually reorder the message.
///
/// Unlike [`sanitize_for_display`], the result is not length-bounded:
/// the operator uses the parent to locate the conflict, so it is kept
/// whole. Only the final, possibly attacker-influenced component of a
/// path is routed through the stricter, truncating
/// [`sanitize_for_display`]; see `fs::paths::already_exists_error`.
pub(crate) fn sanitize_prefix_for_display(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() || is_bidi_control(c) {
            // Same escape style as `write_sanitized_char`.
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
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
/// additional mapping. Stable library-owned messages use sentence case
/// without terminal punctuation. Lowercase archive reasons and internal
/// markers are fragments rendered after a capitalized prefix. Transparent
/// operating-system errors and caller/path text may retain their own
/// punctuation.
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
///   [`CryptoError::HeaderMacWorkCapExceeded`],
///   [`CryptoError::RecipientStringCapExceeded`],
///   [`CryptoError::KdfResourceCapExceeded`],
///   [`CryptoError::KdfTimeCostCapExceeded`],
///   [`CryptoError::KdfLanesCapExceeded`],
///   [`CryptoError::KdfWorkCapExceeded`],
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
/// # Evolution
///
/// New failure classes arrive as new variants, which the enum-level
/// `#[non_exhaustive]` absorbs. The field set of every existing variant
/// is frozen: new information about an existing class also arrives as a
/// new variant, never as a new field, so downstream `match` patterns
/// keep compiling and externally constructed values stay possible.
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
/// - **Caller-invocation path conflicts and shape rejections**:
///   "Output already exists: `path`", "Key file already exists:
///   `path`", "Invalid recipient public key". These surface *which*
///   user-supplied path or value triggered the rejection so
///   operators can fix it without extra debugging. The conflict
///   messages keep the parent directory readable and untruncated (it
///   is the caller's trust boundary) while escaping control and bidi
///   characters in it, and escape the final component — which can be
///   attacker-influenced — more strictly.
/// - **Caller-supplied config values** outside the valid range:
///   "KDF memory limit overflow: `N` MiB", "Passphrase must not be
///   empty".
///
/// Rejections of a *parsed archive payload* — a malicious or corrupt
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
    #[error("Input file or directory not found")]
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
    /// (within the format maximum) but asks for more iterations than the policy
    /// allows. The default cap is the format maximum, so this variant is returned
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
    /// the default cap is the format maximum, so this variant is returned only when
    /// a caller tightens `KdfLimit` below that maximum.
    #[error("Passphrase parallelism over limit ({lanes}, limit {local_cap})")]
    KdfLanesCapExceeded {
        /// Lane count (parallelism) requested by the untrusted header.
        lanes: u32,
        /// Maximum lane count accepted by the caller's local policy.
        local_cap: u32,
    },
    /// Combined Argon2id work from a header — memory cost in KiB multiplied by
    /// time cost — exceeds the caller-configured local cap. Bounds how long one
    /// derivation runs, where [`Self::KdfResourceCapExceeded`] bounds how much
    /// memory it holds; neither implies the other, so a header within the
    /// memory cap can still be refused here. The default budget is the writer's
    /// own (1 GiB × 4 passes), so a file this library produced at its defaults
    /// always decrypts; raise it with `KdfLimit::max_work`.
    #[error("Passphrase work over limit ({work} KiB-passes, limit {local_cap})")]
    KdfWorkCapExceeded {
        /// Combined work requested by the untrusted header, in KiB-passes.
        work: u64,
        /// Maximum combined work accepted by the caller's local policy.
        local_cap: u64,
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
    ///
    /// That distinction is exact on the reader side, where a header declaring
    /// more than the structural max is a malformed file. On the writer side
    /// the structural max is simply the highest policy a caller can set, so a
    /// recipient list above it reports here — including from
    /// [`crate::Encryptor::with_public_keys`], which stops collecting there
    /// and so reports the count at which it stopped.
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
    /// constraint, and callers may raise the cap for trusted input.
    #[error("Recipient data too large ({body_len} bytes, limit {local_cap})")]
    RecipientBodyCapExceeded {
        /// Recipient body length declared by the entry, in bytes.
        body_len: u32,
        /// Maximum per-recipient body length accepted by local policy, in bytes.
        local_cap: u32,
    },
    /// Verifying every recipient in this file would hash more header
    /// bytes than the local resource cap allows.
    ///
    /// Each candidate recipient authenticates the whole `prefix ||
    /// header` (`FORMAT.md` §3.6), so the work is the recipient count
    /// times the header size. The per-dimension caps bound each factor
    /// on its own; this one bounds the product. Raise it with
    /// [`crate::HeaderReadLimits::max_header_mac_work_bytes`] for files
    /// from a known origin that legitimately combine many recipients
    /// with a large header. Readers report it before any private-key
    /// unlock, KDF, or MAC work, and writers before sealing, so neither
    /// side can be made to do that work by the file itself.
    #[error("Recipient verification work too large ({work_bytes} bytes, limit {local_cap})")]
    HeaderMacWorkCapExceeded {
        /// Total header bytes all candidate recipients would authenticate.
        work_bytes: u64,
        /// Maximum aggregate header-MAC input accepted by local policy, in bytes.
        local_cap: u64,
    },
    /// Bech32 recipient string exceeds the caller-configured local
    /// length cap.
    ///
    /// Distinct from malformed public-key input: the string may be
    /// structurally valid, but the reader's resource policy rejected it.
    /// The structural ceiling is 20,000 ASCII characters (`FORMAT.md`
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
    /// A `private.key` `wrapped_secret_len` exceeds the local resource
    /// cap. The structural max (16 MiB per `FORMAT.md` §8) is much
    /// higher; this fires when the wrapped secret would exceed the
    /// resource policy (4 KiB by default — every native key type
    /// needs only 48 bytes); the writer enforces the same cap before
    /// sealing. Distinct from
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
    /// binding in the `private.key` format catches tampering
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
    /// `FORMAT.md` §3.4 unknown critical entries must cause file
    /// rejection (vs unknown non-critical, which are skipped).
    #[error("Unsupported recipient `{}`", DisplayableTypeName(type_name))]
    UnknownCriticalRecipient {
        /// Unknown recipient type name that carried the critical flag.
        type_name: String,
    },
    /// A key file or recipient string carries a grammar-valid `type_name`
    /// this build does not support, in a supported key-pair suite. It may
    /// come from a newer FerroCrypt or an external implementation
    /// (`FORMAT.md` §11). Distinct from [`FormatDefect::WrongKeyFileType`],
    /// the genuine public/private mix-up.
    #[error("Unsupported key type `{}`", DisplayableTypeName(type_name))]
    UnsupportedKeyType {
        /// Grammar-valid key type name this build cannot use.
        type_name: String,
    },
    /// The file holds no recipient of a type this build can process — only
    /// unknown non-critical entries. Detected while classifying the recipient
    /// list, before any unwrap. A *supported* recipient whose unwrap fails is
    /// [`Self::RecipientUnwrapFailed`] instead; `FORMAT.md` §12 lists the two
    /// as separate failure classes. A newer release may support an unknown
    /// recipient, but the type may instead belong to a third-party
    /// implementation, so the message does not prescribe an upgrade.
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
    /// the combination. The most common trigger is an
    /// [`MixingPolicy::Exclusive`] native type (today only `argon2id`)
    /// sharing a file with any other entry — per `FORMAT.md` §4.1 such
    /// types must appear alone, and readers must reject the mix
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
    /// Windows-reserved names, and similar path-safety violations).
    /// Fires on read for a malicious or corrupt archive and on write for a
    /// source tree whose names FCA cannot represent.
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
    // Five archive size-cap variants carry `u64` offending values but omit
    // them from Display so worst-case messages stay concise. The typed fields
    // remain available to callers: total bytes, manifest length, archive
    // extension length, entry extension length, and total entry extensions.
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
    #[error("Archive entry extensions are too large (limit {local_cap} bytes)")]
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
    /// A cryptographic primitive (AEAD encryption, HKDF expansion)
    /// returned an error even though the inputs were well-formed, or the
    /// Argon2id working memory could not be allocated. The allocation
    /// case is reachable on a memory-tight host; the others indicate a
    /// library bug or a very rare underlying-crate failure.
    #[error("Internal crypto error: {}", DisplayableMarker(.0))]
    InternalCryptoFailure(&'static str),
}

/// Structural defects detected while parsing a FerroCrypt encrypted file
/// or key file. Carried inside [`CryptoError::InvalidFormat`] so format
/// failures can be pattern-matched without substring comparisons and
/// without heap-allocated `String`s. That promise is also what lets the
/// enum stay `Copy` while it remains `#[non_exhaustive]`.
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
    /// `ext_len` in a `.fcr` header's fixed section exceeds the reader's
    /// structural cap (`EXT_LEN_MAX`, 64 KiB). The shared TLV scanner
    /// re-checks its cap on every region it is handed, but the FCA and
    /// `private.key` regions are capped by their containing formats
    /// first (the latter as [`Self::MalformedPrivateKey`]), so only the
    /// `.fcr` fixed-section check is reachable from input. Carried as
    /// `u32` because the cap is `65_536`, which exceeds `u16::MAX`.
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
    /// critical TLV tags must cause file rejection.
    UnknownCriticalTag {
        /// Unknown critical TLV tag value.
        tag: u16,
    },
    /// Leading magic bytes do not match `"FCR\0"` — not a FerroCrypt
    /// key file. Key-file analogue of [`FormatDefect::BadMagic`].
    NotAKeyFile,
    /// A `public.key` was supplied to a private-key operation, or a
    /// `private.key` was supplied to a public-key operation. Reserved for
    /// this concrete cross-use; an unexpected binary artifact `kind` byte
    /// is [`FormatDefect::WrongKind`].
    WrongKeyFileType,
    /// `public.key` text file violates the canonical grammar
    /// (`FORMAT.md` §7.1): the file must contain the lowercase `fcr1…`
    /// recipient string optionally followed by exactly one trailing
    /// `\n`, OR the typed payload itself is structurally invalid.
    /// Leading/trailing whitespace other than a single final LF, CRLF
    /// line endings, extra blank lines, internal whitespace, header
    /// length-field violations, and internal-checksum mismatch all
    /// surface here.
    MalformedPublicKey,
    /// A binary FerroCrypt artifact's `kind` byte does not match the
    /// expected value for this operation (e.g. a caller asked for an
    /// encrypted `.fcr` but got a binary `private.key`, or vice versa).
    /// `FORMAT.md` §3.1 and §8.
    WrongKind {
        /// Raw `kind` byte from the binary artifact header.
        kind: u8,
    },
    /// Structural defect in the header_fixed layout (non-zero
    /// `header_flags`, `ext_len` over the structural cap, or length
    /// fields that don't sum to `header_len`). Distinct from
    /// [`Self::OversizedHeader`] (header_len > 16 MiB structural max) and
    /// [`Self::RecipientCountOutOfRange`] (recipient_count outside 1..=4096).
    /// `FORMAT.md` §3.2.
    MalformedHeader,
    /// The authenticated payload stream violates the canonical chunk grammar
    /// in `FORMAT.md` §5. Currently this means an empty final chunk following
    /// one or more non-final chunks; an empty final chunk is valid only when
    /// it is the stream's sole chunk and represents empty plaintext.
    MalformedPayloadStream,
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
    /// `FORMAT.md` §3.4, only bit 0 (the `critical` flag) is defined;
    /// all other bits must be zero on the wire.
    RecipientFlagsReserved,
    /// `private.key` cleartext header is structurally invalid: bad
    /// magic-after-prefix-checks, non-zero `key_flags`, length fields
    /// out of structural range, declared variable fields exceed the
    /// file size, or trailing bytes after the wrapped secret. Per
    /// `FORMAT.md` §8.
    MalformedPrivateKey,
    /// Inner FCA archive `version` byte is a nonzero value this release
    /// cannot read (zero is reserved and rejects as malformed). Distinct
    /// from the outer `.fcr` / `private.key` version
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
            Self::UnknownCriticalTag { tag } => {
                write!(
                    f,
                    "Newer FerroCrypt is needed for file feature tag 0x{tag:04X}"
                )
            }
            Self::NotAKeyFile => f.write_str("Not a FerroCrypt key file"),
            Self::WrongKeyFileType => f.write_str("Wrong key file kind (public vs private)"),
            Self::MalformedPublicKey => f.write_str("Public key is malformed"),
            Self::WrongKind { kind } => {
                write!(f, "Wrong file kind: 0x{kind:02X}")
            }
            Self::MalformedHeader => f.write_str("File header is malformed"),
            Self::MalformedPayloadStream => f.write_str("Encrypted payload stream is malformed"),
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
                    "Newer FerroCrypt is needed for FCA archive version byte 0x{version:02X}"
                )
            }
        }
    }
}

/// File-format or key-file version rejection. Carries the raw version
/// byte so callers can inspect it without parsing a formatted string.
///
/// The three variant pairs cover three of FerroCrypt's four independent
/// on-disk version domains (`FORMAT.md` §11); the fourth — the inner FCA
/// archive version — is a defect of the encrypted payload rather than the
/// outer file, so it surfaces as [`FormatDefect::UnsupportedArchiveVersion`]
/// instead:
///
/// - `OlderFile` / `NewerFile` — `.fcr` outer-container version
///   (`FORMAT.md` §3.1);
/// - `OlderKey` / `NewerKey` — private-key encoding version
///   (`FORMAT.md` §8). "Key" rather than "PrivateKey" for backwards
///   compatibility with earlier callers that pattern-match on the
///   variant names;
/// - `OlderPublicKey` / `NewerPublicKey` — public-key encoding version
///   (`FORMAT.md` §7). Distinct from the `Key` pair because the
///   private-key encoding and the public-key encoding are different
///   on-disk shapes that may map to the same logical key-pair suite
///   from different bytes.
///
/// Every variant carries one wire version byte and nothing else, which
/// is what lets the enum stay `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnsupportedVersion {
    /// `.fcr` outer-container version is older than the current release
    /// supports.
    OlderFile {
        /// Version byte read from the encrypted-file prefix.
        version: u8,
    },
    /// `.fcr` outer-container version is newer than the current release
    /// supports.
    NewerFile {
        /// Version byte read from the encrypted-file prefix.
        version: u8,
    },
    /// Private-key encoding version is older than the current release
    /// accepts.
    OlderKey {
        /// Version byte read from the `private.key` fixed header.
        version: u8,
    },
    /// Private-key encoding version is newer than the current release
    /// accepts.
    NewerKey {
        /// Version byte read from the `private.key` fixed header.
        version: u8,
    },
    /// Public-key encoding version is older than the current release
    /// accepts. Surfaced when a public recipient (Bech32 string or
    /// `public.key` file) is offered for encryption but its key-pair
    /// suite is no longer supported by this build. Per `FORMAT.md` §7
    /// and the symmetry rule in §11, a release must not accept a public
    /// key for encryption unless the same key-pair suite remains
    /// supported for private-key decryption.
    OlderPublicKey {
        /// Version byte read from the decoded recipient payload.
        version: u8,
    },
    /// Public-key encoding version is newer than the current release
    /// accepts. Carries the version byte read from offset 0 of the
    /// decoded recipient payload.
    NewerPublicKey {
        /// Version byte read from the decoded recipient payload.
        version: u8,
    },
}

impl std::fmt::Display for UnsupportedVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OlderFile { version } => {
                write!(f, "Unsupported older .fcr version byte 0x{version:02X}")
            }
            Self::NewerFile { version } => {
                write!(
                    f,
                    "Newer FerroCrypt is needed for .fcr version byte 0x{version:02X}"
                )
            }
            Self::OlderKey { version } => {
                write!(
                    f,
                    "Unsupported older private-key version byte 0x{version:02X}"
                )
            }
            Self::NewerKey { version } => {
                write!(
                    f,
                    "Newer FerroCrypt is needed for private-key version byte 0x{version:02X}"
                )
            }
            Self::OlderPublicKey { version } => {
                write!(
                    f,
                    "Unsupported older public-key version byte 0x{version:02X}"
                )
            }
            Self::NewerPublicKey { version } => {
                write!(
                    f,
                    "Newer FerroCrypt is needed for public-key version byte 0x{version:02X}"
                )
            }
        }
    }
}

/// Which KDF parameter from an untrusted header failed its structural
/// bound check. Carries the raw value so callers can decide whether to
/// re-try with looser limits. Every variant carries one number and
/// nothing else, which is what lets the enum stay `Copy`.
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
                write!(f, "File has invalid KDF settings (memory {n} KiB)")
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
    /// An authenticated empty final chunk following one or more non-final
    /// chunks. `FORMAT.md` §5 permits an empty final chunk only as the sole
    /// encoding of empty plaintext.
    EmptyFinalChunk,
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
    /// Writer or reader state is no longer available. This occurs after a
    /// writer finishes, after a writer returns a sink or AEAD error, or after
    /// a reader returns any terminal error. Later operations return this
    /// marker instead of resuming the stream.
    StateExhausted,
    /// `FORMAT.md` §5: writers must not emit more than `2^32` chunks
    /// and readers must reject streams that exceed that count. Surfaced
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
            StreamError::EmptyFinalChunk => "Encrypted stream has an invalid empty final chunk",
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
                StreamError::EmptyFinalChunk => {
                    CryptoError::InvalidFormat(FormatDefect::MalformedPayloadStream)
                }
                StreamError::ExtraData => CryptoError::ExtraDataAfterPayload,
                StreamError::ChunkCountExceeded => CryptoError::PayloadChunkCountExceeded,
                StreamError::EncryptAead => {
                    internal_crypto_failure!("payload encryption failed")
                }
                StreamError::StateExhausted => {
                    internal_invariant!("stream state already finalized")
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
            "Input file or directory not found"
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
            "Unsupported recipient `mlkem768x255…`"
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
            "Newer FerroCrypt is needed for file feature tag 0x8001"
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
            FormatDefect::MalformedPayloadStream.to_string(),
            "Encrypted payload stream is malformed"
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
            "Newer FerroCrypt is needed for FCA archive version byte 0xFF"
        );
        assert_eq!(
            FormatDefect::RecipientCountOutOfRange { count: 5000 }.to_string(),
            "Recipient count out of range (5000)"
        );
        assert_eq!(
            UnsupportedVersion::NewerFile { version: 9 }.to_string(),
            "Newer FerroCrypt is needed for .fcr version byte 0x09"
        );
        assert_eq!(
            UnsupportedVersion::OlderFile { version: 1 }.to_string(),
            "Unsupported older .fcr version byte 0x01"
        );
        assert_eq!(
            UnsupportedVersion::NewerKey { version: 9 }.to_string(),
            "Newer FerroCrypt is needed for private-key version byte 0x09"
        );
        assert_eq!(
            UnsupportedVersion::OlderKey { version: 1 }.to_string(),
            "Unsupported older private-key version byte 0x01"
        );
        assert_eq!(
            UnsupportedVersion::OlderPublicKey { version: 1 }.to_string(),
            "Unsupported older public-key version byte 0x01"
        );
        assert_eq!(
            UnsupportedVersion::NewerPublicKey { version: 9 }.to_string(),
            "Newer FerroCrypt is needed for public-key version byte 0x09"
        );
        assert_eq!(
            InvalidKdfParams::Parallelism(9999).to_string(),
            "File has invalid KDF settings (parallelism 9999)"
        );
        assert_eq!(
            InvalidKdfParams::MemoryCost(42).to_string(),
            "File has invalid KDF settings (memory 42 KiB)"
        );
        assert_eq!(
            InvalidKdfParams::TimeCost(7).to_string(),
            "File has invalid KDF settings (time cost 7)"
        );

        // StreamError Display text. The five user-facing markers
        // (DecryptAead, Truncated, EmptyFinalChunk, ExtraData,
        // ChunkCountExceeded) start capitalized; the two internal-bug markers
        // (EncryptAead, StateExhausted) are lowercase because they only render
        // after an "Internal ...:" prefix. This is the only place the user-facing
        // markers' text is pinned — they carry no CryptoError payload of
        // their own.
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
            StreamError::EmptyFinalChunk.to_string(),
            "Encrypted stream has an invalid empty final chunk"
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
            "Archive entry extensions are too large (limit 99 bytes)"
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

    /// Every crate-owned internal marker goes through a compile-time assertion
    /// that it follows the display policy. Pin the boundary and representative
    /// rejection cases used by that assertion.
    #[test]
    fn crate_internal_markers_follow_display_policy() {
        const BOUNDARY_MARKER: &str = "encrypt writer already finished or failed";
        assert_eq!(BOUNDARY_MARKER.len(), INTERNAL_MARKER_DISPLAY_MAX);
        assert!(internal_marker_is_valid(BOUNDARY_MARKER));
        assert!(!internal_marker_is_valid(""));
        assert!(!internal_marker_is_valid(
            "manifest entry missing source path after content streaming"
        ));
        assert!(!internal_marker_is_valid("non-ASCII marker: é"));
        assert!(!internal_marker_is_valid("payload encryption failed."));
        assert_eq!(
            internal_invariant!("encrypt writer already finished or failed").to_string(),
            "Internal error: encrypt writer already finished or failed"
        );
        assert_eq!(
            internal_crypto_failure!("payload encryption failed").to_string(),
            "Internal crypto error: payload encryption failed"
        );
    }

    /// Pin the malformed-archive fragment validator independently of the
    /// registry sweep, including its exact 45-character boundary.
    #[test]
    fn malformed_archive_reasons_follow_display_policy() {
        const BOUNDARY_REASON: &str = "declared total does not match the entry sizes";
        assert_eq!(BOUNDARY_REASON.len(), MALFORMED_ARCHIVE_REASON_DISPLAY_MAX);
        assert!(malformed_archive_reason_is_valid(BOUNDARY_REASON));
        assert_eq!(
            CryptoError::MalformedArchive {
                reason: BOUNDARY_REASON,
            }
            .to_string()
            .chars()
            .count(),
            64
        );

        assert!(!malformed_archive_reason_is_valid(""));
        let overlong = "x".repeat(MALFORMED_ARCHIVE_REASON_DISPLAY_MAX + 1);
        assert!(!malformed_archive_reason_is_valid(&overlong));
        assert!(!malformed_archive_reason_is_valid(
            "entry path is not valid UTF-\u{ff11}"
        ));
        assert!(!malformed_archive_reason_is_valid("entry path is empty."));
        assert!(!malformed_archive_reason_is_valid("entry path\nis empty"));
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
            UNTRUSTED_TEXT_DISPLAY_MAX,
            "63 kept chars plus the ellipsis fill the rendered budget"
        );
        assert!(rendered.ends_with('…'));

        let exact: String = "y".repeat(UNTRUSTED_TEXT_DISPLAY_MAX);
        assert_eq!(
            sanitize_for_display(&exact),
            exact,
            "at-cap input is untouched"
        );
    }

    /// Escaped input must remain within the rendered output budget.
    #[test]
    fn sanitize_for_display_bounds_rendered_chars_for_escaped_input() {
        let hostile: String = "\u{202e}".repeat(UNTRUSTED_TEXT_DISPLAY_MAX);
        let rendered = sanitize_for_display(&hostile);
        assert!(
            rendered.chars().count() <= UNTRUSTED_TEXT_DISPLAY_MAX,
            "rendered budget exceeded: {} chars",
            rendered.chars().count()
        );
        assert!(rendered.ends_with('…'));
        assert!(rendered.starts_with("\\u{202e}"));
        assert!(
            !rendered.contains('\u{202e}'),
            "raw bidi override leaked: {rendered:?}"
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

    /// Pins the `UnsupportedKeyType` user-facing wording: it names the key
    /// type, unlike the public/private mix-up message of
    /// `FormatDefect::WrongKeyFileType`.
    #[test]
    fn unsupported_key_type_message_names_type() {
        let msg = CryptoError::UnsupportedKeyType {
            type_name: "mlkem768".to_owned(),
        }
        .to_string();
        assert_eq!(msg, "Unsupported key type `mlkem768`");
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
        fn check_width(label: &str, msg: &str) {
            let chars = msg.chars().count();
            assert!(
                chars <= BUDGET,
                "message over {BUDGET}-char budget ({chars} chars) [{label}]: {msg}",
            );
        }

        fn check(label: &str, msg: &str) {
            assert!(
                msg.chars().next().is_some_and(|c| c.is_ascii_uppercase()),
                "message does not start with a capital [{label}]: {msg}",
            );
            assert!(
                !matches!(msg.chars().last(), Some('.' | '!' | '?')),
                "message has terminal punctuation [{label}]: {msg}",
            );
            check_width(label, msg);
        }

        // Fixed-payload CryptoError variants.
        check("InputPath", &CryptoError::InputPath.to_string());

        // Every crate-owned archive reason, swept from its registry. A
        // fragment starts lowercase unless its first word is a proper name;
        // `Windows-reserved device name` is the only such fragment today.
        const PROPER_NOUN_STARTS: &[&str] = &["Windows-"];
        let mut archive_reasons = std::collections::HashSet::new();
        let mut check_fragment = |reason: &'static str| {
            assert!(
                archive_reasons.insert(reason),
                "duplicate archive reason: {reason}"
            );
            assert!(
                reason.starts_with(|c: char| c.is_ascii_lowercase())
                    || PROPER_NOUN_STARTS.iter().any(|p| reason.starts_with(p)),
                "archive reason is not a lowercase fragment: {reason}",
            );
        };
        // `MalformedArchive` is wholly library-owned, so its complete message
        // is width-checked too.
        for &reason in crate::archive::reasons::MALFORMED_ALL {
            check_fragment(reason);
            let rendered = CryptoError::MalformedArchive { reason }.to_string();
            assert_eq!(
                rendered,
                format!("Malformed archive: {reason}"),
                "crate-owned malformed-archive reason was altered for display",
            );
            check(reason, &rendered);
        }
        // The two path-bearing variants append an entry path, so only the
        // fragment policy applies; the desktop elides the rendered width.
        for &reason in crate::archive::reasons::UNSAFE_PATH_ALL {
            check_fragment(reason);
            assert_eq!(
                CryptoError::UnsafeArchivePath {
                    path: "root/a.txt".to_owned(),
                    reason,
                }
                .to_string(),
                format!("Unsafe archive path ({reason}): root/a.txt"),
                "crate-owned unsafe-path reason was altered for display",
            );
        }
        for &reason in crate::archive::reasons::INVALID_TREE_ALL {
            check_fragment(reason);
            assert_eq!(
                CryptoError::InvalidArchiveTree {
                    path: "root/a.txt".to_owned(),
                    reason,
                }
                .to_string(),
                format!("Invalid archive tree ({reason}): root/a.txt"),
                "crate-owned invalid-tree reason was altered for display",
            );
        }
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

        // `UnknownCriticalRecipient` and `UnsupportedKeyType` still
        // interpolate `type_name`; pin that a worst-case 255-byte name
        // (FORMAT.md §3.3 upper bound) stays in budget after
        // `DisplayableTypeName` truncates it. Recipient unwrap and
        // header-MAC failures no longer show `type_name`, and
        // `IncompatibleRecipients` is covered above.
        let max_name = "x".repeat(u8::MAX as usize);
        check(
            "UnknownCriticalRecipient(max-name)",
            &CryptoError::UnknownCriticalRecipient {
                type_name: max_name.clone(),
            }
            .to_string(),
        );
        check(
            "UnsupportedKeyType(max-name)",
            &CryptoError::UnsupportedKeyType {
                type_name: max_name,
            }
            .to_string(),
        );

        // Variants constructed outside the crate are still bounded by
        // `INTERNAL_MARKER_DISPLAY_MAX`; crate-owned markers are additionally
        // checked at compile time by their construction macros.
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
                "MalformedPayloadStream",
                FormatDefect::MalformedPayloadStream,
            ),
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
        check_width(
            "StreamError::DecryptAead",
            &StreamError::DecryptAead.to_string(),
        );
        check_width(
            "StreamError::EncryptAead",
            &StreamError::EncryptAead.to_string(),
        );
        check_width(
            "StreamError::Truncated",
            &StreamError::Truncated.to_string(),
        );
        check_width(
            "StreamError::EmptyFinalChunk",
            &StreamError::EmptyFinalChunk.to_string(),
        );
        check_width(
            "StreamError::ExtraData",
            &StreamError::ExtraData.to_string(),
        );
        check_width(
            "StreamError::StateExhausted",
            &StreamError::StateExhausted.to_string(),
        );
        check_width(
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
            from_marker(StreamError::EmptyFinalChunk),
            CryptoError::InvalidFormat(FormatDefect::MalformedPayloadStream)
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
