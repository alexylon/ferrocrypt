use thiserror::Error;

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
///   [`CryptoError::KdfResourceCapExceeded`]) each carry the offending
///   value plus the configured local cap as named integer fields,
///   matching the "distinct resource-cap error" classes that
///   `FORMAT.md` §3.2 / §12 enumerate
/// - The multi-recipient diagnostics ([`CryptoError::RecipientUnwrapFailed`],
///   [`CryptoError::HeaderMacFailedAfterUnwrap`],
///   [`CryptoError::UnknownCriticalRecipient`]) each carry the
///   `type_name` so callers can tell which recipient slot raised them
///
/// Consumers can pattern-match on these shapes without substring
/// comparisons. Ferrocrypt's error type is closely modelled on the
/// `age` crate's `DecryptError`, which takes the same stance.
///
/// # The one escape hatch: [`CryptoError::InvalidInput`]
///
/// One variant — [`CryptoError::InvalidInput`] — carries a free-form
/// `String`. It is the **designated heterogeneous caller-input
/// bucket** for fail-closed rejections whose only useful context is
/// a path or short token that has to be echoed back to the user.
/// Concretely it covers:
///
/// - **tar-archive layer**: "symlink entry `foo/bar`", "unsafe path in
///   archive `../escape.txt`", "archive mixes file and directory at
///   root `mydir`", etc. A malformed or attacker-crafted `.fcr` can
///   hold thousands of entries; without the entry path embedded in the
///   error, a developer debugging a failing extraction would see only
///   "something in this archive is bad" and be unable to locate it.
/// - **Bech32 recipient parser**: reports the offending recipient
///   string ("Invalid recipient string: `fcr1…`", "Unexpected recipient
///   prefix…", "Recipient string must be lowercase"). Callers pass
///   recipient strings through as opaque values, so the parser has to
///   echo the input back for the user to spot a typo.
/// - **Caller-invocation path conflicts and shape rejections**:
///   "Output already exists: `path`", "Key file already exists:
///   `path`", "Input is a symlink: `path`", "Unsupported file type:
///   `path`", "Invalid recipient public key". These surface *which*
///   user-supplied path or value triggered the rejection so
///   operators can fix it without extra debugging.
/// - **Caller-supplied config values** outside the valid range:
///   "KDF memory limit overflow: `N` MiB", "Passphrase must not be
///   empty".
///
/// Typing these via structured variants would require dozens of new
/// variants each carrying a `PathBuf` or `String`, which reintroduces
/// the exact "library carries per-operation context" problem the rest
/// of the type deliberately avoids.
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
    /// Argon2 key-derivation failed.
    #[error(transparent)]
    KeyDerivation(#[from] argon2::Error),
    /// KDF parameters read from an untrusted header are outside safe
    /// structural bounds.
    #[error("{0}")]
    InvalidKdfParams(InvalidKdfParams),
    /// Argon2id memory cost from a header exceeds the caller-configured
    /// local resource cap. Per `FORMAT.md` §3.2, exceeding a local cap
    /// produces a distinct resource-cap error rather than a generic
    /// malformed-file error. Distinct from
    /// [`InvalidKdfParams`] (structurally invalid params) and
    /// [`KeyDerivation`] (Argon2id itself failed): here the params
    /// are well-formed but cost more than the caller is willing to
    /// spend.
    #[error("KDF resource cap exceeded ({mem_cost_kib} KiB, cap {local_cap_kib})")]
    KdfResourceCapExceeded {
        mem_cost_kib: u32,
        local_cap_kib: u32,
    },
    /// `header_len` exceeds the caller-configured local cap. The
    /// structural max (`HEADER_LEN_MAX = 16 MiB` per `FORMAT.md` §3.1)
    /// is much higher; this fires when the header would exceed the
    /// caller's resource policy. Distinct from
    /// [`FormatDefect::OversizedHeader`] (above structural max) per
    /// `FORMAT.md` §3.2.
    #[error("Header length cap exceeded ({header_len} bytes, cap {local_cap})")]
    HeaderLenCapExceeded { header_len: u32, local_cap: u32 },
    /// `recipient_count` exceeds the caller-configured local cap. The
    /// structural range (`1..=4096` per `FORMAT.md` §3.2) is much
    /// wider; this fires when the count would exceed the caller's
    /// resource policy. Distinct from
    /// [`FormatDefect::RecipientCountOutOfRange`] (above structural
    /// max).
    #[error("Recipient count cap exceeded ({count} entries, cap {local_cap})")]
    RecipientCountCapExceeded { count: u16, local_cap: u16 },
    /// A recipient entry's `body_len` exceeds the local resource cap.
    /// The structural max (`BODY_LEN_MAX = 16 MiB` per `FORMAT.md`
    /// §3.3) is much higher; this fires when the body would exceed the
    /// caller-configured local cap (`FORMAT.md` §3.2 recommends 8 KiB
    /// for untrusted input). Distinct from
    /// [`FormatDefect::MalformedRecipientEntry`]: the file is
    /// structurally valid; the reader's resource policy is the
    /// constraint, and callers MAY raise the cap for trusted input.
    #[error("Recipient body cap exceeded ({body_len} bytes, cap {local_cap})")]
    RecipientBodyCapExceeded { body_len: u32, local_cap: u32 },
    /// Bech32 recipient string exceeds the caller-configured local
    /// length cap. Distinct from any malformed-input error per
    /// `FORMAT.md` §3.2: the string may be perfectly valid; the
    /// reader's resource policy is what rejects it, and callers MAY
    /// raise the cap for trusted input. Spec ceiling is 20,000 chars
    /// (§7.1); the recommended local default is much smaller.
    /// Saturating casts: an input > `u32::MAX` chars (4 GiB+) reports
    /// `u32::MAX` for `input_chars`, but the cap rejection itself is
    /// still correct.
    #[error("Recipient string cap exceeded ({input_chars} chars, cap {local_cap})")]
    RecipientStringCapExceeded { input_chars: u32, local_cap: u32 },

    // ─── Authentication failures ─────────────────────────────────────────
    /// Unlocking the `private.key` file failed AEAD authentication. The
    /// key file is structurally valid, but either the supplied
    /// passphrase does not decrypt it, or its cleartext fields have
    /// been tampered with after the file was written. The AEAD
    /// primitive cannot distinguish the two cases — the associated-data
    /// binding introduced in the v1 `private.key` format catches tampering
    /// cryptographically, but both failure modes surface as the same
    /// error by design. The Display wording reflects both causes.
    #[error("Private key unlock failed: wrong passphrase or tampered file")]
    KeyFileUnlockFailed,
    /// The single-recipient header MAC failed after the recipient
    /// successfully unwrapped a candidate `file_key`. The caller has
    /// the right passphrase or private key, but bytes inside the
    /// MAC scope (prefix, header_fixed, recipient_entries, ext_bytes)
    /// were tampered with after the file was written. In a multi-
    /// recipient file the per-candidate MAC failure surfaces as
    /// [`HeaderMacFailedAfterUnwrap`] instead so the decrypt loop can
    /// continue iterating; this variant is the final error for the
    /// single-recipient case where there is no other slot to try.
    #[error("Decryption failed: header tampered after unlock")]
    HeaderTampered,
    /// In a multi-recipient decrypt loop, a recipient candidate
    /// unwrapped a `file_key`, but the resulting `header_key` did not
    /// verify the header MAC. Per `FORMAT.md` §3.7 the unwrap is not
    /// final until the MAC verifies; the loop catches this variant and
    /// continues to the next supported recipient entry. Distinct from
    /// [`HeaderTampered`] which is the final error when no further
    /// recipient slot remains. The `type_name` identifies which
    /// recipient slot produced the failed candidate.
    #[error("Decryption failed: recipient `{type_name}` MAC mismatch")]
    HeaderMacFailedAfterUnwrap { type_name: String },
    /// A native or plugin recipient entry's body failed to unwrap. The
    /// `type_name` distinguishes which recipient kind raised it (e.g.
    /// `"argon2id"`, `"x25519"`). Wrong passphrase, wrong key, and
    /// tampered envelope are indistinguishable at the AEAD layer; all
    /// three surface here. Per `FORMAT.md` §3.7, recipient unwrap is
    /// not considered final until the header MAC also verifies.
    #[error("Decryption failed: recipient `{type_name}` unwrap failed")]
    RecipientUnwrapFailed { type_name: String },
    /// The recipient list contains a `recipient_flags.critical = 1`
    /// entry whose `type_name` is unknown to this implementation. Per
    /// `FORMAT.md` §3.4 unknown critical entries MUST cause file
    /// rejection (vs unknown non-critical, which are skipped).
    #[error("Unknown critical recipient: `{type_name}`. Upgrade FerroCrypt.")]
    UnknownCriticalRecipient { type_name: String },
    /// The recipient list was iterated to exhaustion without any
    /// supported recipient yielding a `file_key` that verified the
    /// header MAC. Distinct from [`RecipientUnwrapFailed`] (which is
    /// per-candidate during iteration) and [`HeaderTampered`] (which is
    /// the final single-recipient error). Per `FORMAT.md` §12.
    #[error("Decryption failed: no recipient could unlock the file")]
    NoSupportedRecipient,
    /// The recipient list contains an `argon2id` entry alongside one or
    /// more other recipients. Per `FORMAT.md` §4.1 `argon2id` is
    /// exclusive: a file containing it MUST contain exactly that one
    /// entry. Readers MUST reject the mix structurally before running
    /// any Argon2id work.
    #[error("Passphrase recipient mixed with another recipient")]
    PassphraseRecipientMixed,
    /// An encrypted payload chunk failed AEAD authentication during
    /// streaming decryption. The ciphertext has been tampered with or
    /// corrupted after the header was authenticated.
    #[error("Payload authentication failed: data tampered or corrupted")]
    PayloadTampered,
    /// The encrypted stream ends before the final-flag chunk.
    /// Usually caused by a truncated file or an aborted download.
    #[error("Encrypted file is truncated")]
    PayloadTruncated,
    /// Bytes remain after the final-flag chunk has been successfully
    /// decrypted. The file has unexpected trailing data.
    #[error("Encrypted file has unexpected trailing data")]
    ExtraDataAfterPayload,

    // ─── Internal invariants ─────────────────────────────────────────────
    /// A non-cryptographic invariant that should hold by construction did
    /// not hold. Triggered by state-machine misuse (e.g. using a stream
    /// after it was finalized), impossible-size checks, or internal
    /// encoding failures. If this fires, it indicates a library bug.
    #[error("{0}")]
    InternalInvariant(&'static str),
    /// A cryptographic primitive (AEAD encryption, HKDF expansion) returned
    /// an error even though the inputs were well-formed. Unreachable in
    /// practice for valid data; indicates either a library bug or a very
    /// rare underlying-crate failure.
    #[error("{0}")]
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
    /// `ext_len` (in a `.fcr` prefix or `private.key` header)
    /// exceeds the reader's structural cap (`EXT_LEN_MAX`, 64 KiB).
    /// Carried as `u32` because the cap is `65_536`, which exceeds
    /// `u16::MAX`.
    ExtTooLarge { len: u32 },
    /// A TLV entry in the extension region is malformed: bad ordering,
    /// duplicate tag, or `len` extends past the end of the region.
    /// `FORMAT.md` §6.
    MalformedTlv,
    /// A TLV tag in the critical range (`0x8001..=0xFFFF`) is not
    /// recognised by this release. Per `FORMAT.md` §6, unknown
    /// critical TLV tags MUST cause file rejection.
    UnknownCriticalTag { tag: u16 },
    /// Leading magic bytes do not match `"FCR\0"` — not a FerroCrypt
    /// key file. Key-file analogue of [`FormatDefect::BadMagic`].
    NotAKeyFile,
    /// Key file is the wrong kind for this operation (public vs private).
    WrongKeyFileType,
    /// `public.key` text file violates the canonical grammar
    /// (`FORMAT.md` §7.4): the file MUST contain the lowercase `fcr1…`
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
    WrongKind { kind: u8 },
    /// Structural defect in the header_fixed layout (non-zero
    /// `header_flags`, `ext_len` over the structural cap, or length
    /// fields that don't sum to `header_len`). Distinct from
    /// [`OversizedHeader`] (header_len > 16 MiB structural max) and
    /// [`RecipientCountOutOfRange`] (recipient_count outside 1..=4096).
    /// `FORMAT.md` §3.2.
    MalformedHeader,
    /// `header_len` exceeds the structural maximum (`HEADER_LEN_MAX =
    /// 16 MiB` per `FORMAT.md` §3.1). Distinct from
    /// [`CryptoError::HeaderLenCapExceeded`] which fires on the
    /// caller-configured local cap (resource policy, not format
    /// violation).
    OversizedHeader { header_len: u32 },
    /// `recipient_count` is outside the structural range `1..=4096`
    /// (`FORMAT.md` §3.2). Distinct from
    /// [`CryptoError::RecipientCountCapExceeded`] which fires on the
    /// caller-configured local cap.
    RecipientCountOutOfRange { count: u16 },
    /// Recipient `type_name` does not satisfy the grammar in
    /// `FORMAT.md` §3.3 (lowercase ASCII, allowed character set, no
    /// leading/trailing punctuation, no `..` or `//`).
    MalformedTypeName,
    /// Recipient entry framing is structurally invalid: 8-byte header
    /// truncated, length fields out of range, declared entry size
    /// exceeds the bytes available, or the recipient region's per-entry
    /// total accounting doesn't add up to `recipient_entries_len`.
    /// `FORMAT.md` §3.5.
    MalformedRecipientEntry,
    /// Recipient entry has reserved bits set in `recipient_flags`. Per
    /// `FORMAT.md` §3.5, only bit 0 (the `critical` flag) is defined in
    /// v1; all other bits MUST be zero on the wire.
    RecipientFlagsReserved,
    /// `private.key` cleartext header is structurally invalid: bad
    /// magic-after-prefix-checks, non-zero `key_flags`, length fields
    /// out of structural range, declared variable fields exceed the
    /// file size, or trailing bytes after the wrapped secret. Per
    /// `FORMAT.md` §8.
    MalformedPrivateKey,
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
        }
    }
}

/// File-format or key-file version rejection. Carries the raw version
/// byte so callers can inspect it without parsing a formatted string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnsupportedVersion {
    /// Encrypted file version is older than the current release supports.
    OlderFile { version: u8 },
    /// Encrypted file version is newer than the current release supports.
    NewerFile { version: u8 },
    /// Key file version is older than the current release supports.
    OlderKey { version: u8 },
    /// Key file version is newer than the current release supports.
    NewerKey { version: u8 },
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
    /// in [`crate::common::DecryptReader::fill_buffer`]. Ordinary
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
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            StreamError::DecryptAead => "Payload authentication failed",
            StreamError::EncryptAead => "Internal error: payload encryption failed",
            StreamError::Truncated => "Encrypted stream truncated",
            StreamError::ExtraData => "Encrypted stream has trailing data",
            StreamError::StateExhausted => "Internal error: stream state already finalized",
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
        // `StateExhausted` branches pick static literals that match
        // `StreamError`'s Display text, so the user-facing wording is
        // still defined by this module.
        if let Some(stream_err) = e
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<StreamError>())
        {
            return match stream_err {
                StreamError::DecryptAead => CryptoError::PayloadTampered,
                StreamError::Truncated => CryptoError::PayloadTruncated,
                StreamError::ExtraData => CryptoError::ExtraDataAfterPayload,
                StreamError::EncryptAead => {
                    CryptoError::InternalCryptoFailure("Internal error: payload encryption failed")
                }
                StreamError::StateExhausted => {
                    CryptoError::InternalInvariant("Internal error: stream state already finalized")
                }
            };
        }
        CryptoError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "Private key unlock failed: wrong passphrase or tampered file"
        );
        assert_eq!(
            CryptoError::HeaderTampered.to_string(),
            "Decryption failed: header tampered after unlock"
        );
        assert_eq!(
            CryptoError::HeaderMacFailedAfterUnwrap {
                type_name: "x25519".to_owned()
            }
            .to_string(),
            "Decryption failed: recipient `x25519` MAC mismatch"
        );
        assert_eq!(
            CryptoError::UnknownCriticalRecipient {
                type_name: "mlkem768x25519".to_owned()
            }
            .to_string(),
            "Unknown critical recipient: `mlkem768x25519`. Upgrade FerroCrypt."
        );
        assert_eq!(
            CryptoError::NoSupportedRecipient.to_string(),
            "Decryption failed: no recipient could unlock the file"
        );
        assert_eq!(
            CryptoError::PassphraseRecipientMixed.to_string(),
            "Passphrase recipient mixed with another recipient"
        );
        assert_eq!(
            CryptoError::PayloadTampered.to_string(),
            "Payload authentication failed: data tampered or corrupted"
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
            CryptoError::RecipientUnwrapFailed {
                type_name: "x25519".to_owned()
            }
            .to_string(),
            "Decryption failed: recipient `x25519` unwrap failed"
        );
        assert_eq!(
            CryptoError::RecipientBodyCapExceeded {
                body_len: 10_000,
                local_cap: 8_192
            }
            .to_string(),
            "Recipient body cap exceeded (10000 bytes, cap 8192)"
        );
        assert_eq!(
            CryptoError::RecipientStringCapExceeded {
                input_chars: 5_000,
                local_cap: 1_024,
            }
            .to_string(),
            "Recipient string cap exceeded (5000 chars, cap 1024)"
        );
        assert_eq!(
            CryptoError::HeaderLenCapExceeded {
                header_len: 2_000_000,
                local_cap: 1_048_576,
            }
            .to_string(),
            "Header length cap exceeded (2000000 bytes, cap 1048576)"
        );
        assert_eq!(
            CryptoError::RecipientCountCapExceeded {
                count: 100,
                local_cap: 64,
            }
            .to_string(),
            "Recipient count cap exceeded (100 entries, cap 64)"
        );
        assert_eq!(
            CryptoError::KdfResourceCapExceeded {
                mem_cost_kib: 1_048_576,
                local_cap_kib: 524_288,
            }
            .to_string(),
            "KDF resource cap exceeded (1048576 KiB, cap 524288)"
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

        // StreamError — every variant stringifies to a capitalized
        // sentence start, matching the rest of the error surface. The
        // three non-internal markers (DecryptAead / Truncated /
        // ExtraData) have no CryptoError payload carrying their text
        // (they downcast to typed variants with their own Display),
        // so this is the only place their wording is locked in.
        assert_eq!(
            StreamError::DecryptAead.to_string(),
            "Payload authentication failed"
        );
        assert_eq!(
            StreamError::EncryptAead.to_string(),
            "Internal error: payload encryption failed"
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
            "Internal error: stream state already finalized"
        );
    }

    /// Budget: every static user-facing `CryptoError` message — plus
    /// the worst-case formatted variants — must fit in the desktop
    /// status line's 64-char window.
    #[test]
    fn user_facing_messages_fit_status_line_budget() {
        const BUDGET: usize = 64;

        fn check(label: &str, msg: &str) {
            assert!(
                msg.len() <= BUDGET,
                "message over {BUDGET}-char budget ({} chars) [{label}]: {msg}",
                msg.len()
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
            "NoSupportedRecipient",
            &CryptoError::NoSupportedRecipient.to_string(),
        );
        check(
            "PassphraseRecipientMixed",
            &CryptoError::PassphraseRecipientMixed.to_string(),
        );
        check("PayloadTampered", &CryptoError::PayloadTampered.to_string());
        check(
            "PayloadTruncated",
            &CryptoError::PayloadTruncated.to_string(),
        );
        check(
            "ExtraDataAfterPayload",
            &CryptoError::ExtraDataAfterPayload.to_string(),
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
        match from_marker(StreamError::EncryptAead) {
            CryptoError::InternalCryptoFailure(msg) => {
                assert_eq!(msg, "Internal error: payload encryption failed");
                assert_eq!(msg, StreamError::EncryptAead.to_string());
            }
            other => panic!("expected InternalCryptoFailure, got {other:?}"),
        }
        match from_marker(StreamError::StateExhausted) {
            CryptoError::InternalInvariant(msg) => {
                assert_eq!(msg, "Internal error: stream state already finalized");
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
