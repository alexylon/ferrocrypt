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
/// - [`CryptoError::ExcessiveWork`] has named `u32` fields
///
/// Consumers can pattern-match on these shapes without substring
/// comparisons. Ferrocrypt's error type is closely modelled on the
/// `age` crate's `DecryptError`, which takes the same stance.
///
/// # The one escape hatch: [`CryptoError::InvalidInput`]
///
/// One variant — [`CryptoError::InvalidInput`] — carries a free-form
/// `String`. It exists because the tar-archive layer inside the library
/// genuinely needs to surface *which archive entry* triggered a
/// fail-closed rejection ("symlink entry `foo/bar`", "unsafe path in
/// archive `../escape.txt`", "archive mixes file and directory at root
/// `mydir`", etc.). A malformed or attacker-crafted `.fcr` can hold
/// thousands of entries; without the entry path embedded in the error,
/// a developer debugging a failing extraction would see only "something
/// in this archive is bad" and be unable to locate it. Typing the
/// entry path via structured variants would require ~25 new variants
/// each carrying a `PathBuf`, which reintroduces the exact "library
/// carries per-operation context" problem the rest of the type
/// deliberately avoids.
///
/// `InvalidInput` is therefore the **designated heterogeneous
/// caller-input bucket**. It is *not* where paths from the user's
/// invocation live (those belong at the CLI/desktop boundary), and
/// it is *not* used for anything the other variants can express as
/// typed data. Library consumers treating it as an opaque string and
/// surfacing it via `Display` is the correct pattern.
///
/// # Examples
///
/// ```rust
/// use ferrocrypt::{
///     symmetric_encrypt, SymmetricEncryptConfig, CryptoError, secrecy::SecretString,
/// };
///
/// fn example() -> Result<(), CryptoError> {
///     let passphrase = SecretString::from("test".to_string());
///     let config = SymmetricEncryptConfig::new("./missing.txt", "./out", passphrase);
///     match symmetric_encrypt(config, |_| {}) {
///         Ok(outcome) => println!("Output: {}", outcome.output_path.display()),
///         Err(CryptoError::InputPath) => eprintln!("Input file or folder missing"),
///         Err(e) => eprintln!("{e}"),
///     }
///     Ok(())
/// }
/// ```
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CryptoError {
    // ─── Input & filesystem ──────────────────────────────────────────────
    /// Filesystem or stream I/O failure.
    #[error(transparent)]
    Io(std::io::Error),
    /// Input file or directory does not exist. Identity-only — the
    /// caller knows which path it passed in.
    #[error("Input file or folder missing")]
    InputPath,
    /// Invalid caller input with a human-readable explanation. See the
    /// type-level docs for the design rationale — this is the one
    /// `String`-carrying variant in the type, and it exists for
    /// archive-layer rejections that need to identify which entry
    /// triggered the failure.
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
    /// KDF memory cost exceeds the caller-supplied work limit.
    #[error("File needs {required_kib} KiB to unlock; limit is {max_kib} KiB")]
    ExcessiveWork { required_kib: u32, max_kib: u32 },

    // ─── Authentication failures ─────────────────────────────────────────
    /// Unlocking the private key file with the supplied passphrase
    /// failed. The key file is structurally valid; the passphrase does
    /// not decrypt it.
    #[error("Private key file unlock failed: wrong passphrase")]
    KeyFileUnlockFailed,
    /// The encrypted file's header failed authentication. Produced when
    /// the symmetric header HMAC does not verify, when the hybrid envelope
    /// AEAD refuses to unwrap, or when the derived X25519 shared secret
    /// is all zero. From the user's perspective: wrong password, wrong
    /// key, or the encrypted file has been tampered with.
    #[error("Wrong password/key or file was tampered with")]
    HeaderAuthenticationFailed,
    /// An encrypted payload chunk failed AEAD authentication during
    /// streaming decryption. The ciphertext has been tampered with or
    /// corrupted after the header was authenticated.
    #[error("Payload authentication failed: data tampered or corrupted")]
    PayloadAuthenticationFailed,
    /// The encrypted stream ends before the final authenticated chunk.
    /// Usually caused by a truncated file or an aborted download.
    #[error("Encrypted file is truncated")]
    TruncatedStream,

    // ─── Low-level primitives ────────────────────────────────────────────
    /// Fixed-size byte conversion failed due to an unexpected length.
    #[error(transparent)]
    SliceConversion(#[from] std::array::TryFromSliceError),

    // ─── Internal invariants ─────────────────────────────────────────────
    /// A non-cryptographic invariant that should hold by construction did
    /// not hold. Triggered by state-machine misuse (e.g. using a stream
    /// after it was finalized), impossible-size checks, or internal
    /// encoding failures. If this fires, it indicates a library bug. The
    /// payload is a `&'static str` marker chosen at the call site — no
    /// heap allocation, no dynamic context.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatDefect {
    /// Input ended before a complete field or header could be read.
    Truncated,
    /// Replication decoding failed, or a decoded field length doesn't
    /// match the expected structural layout.
    CorruptedHeader,
    /// Leading magic byte does not match `0xFC`. Either the input is
    /// not a FerroCrypt file, or it was created by a pre-v3 format
    /// family that this release no longer supports.
    BadMagic,
    /// Magic byte is valid but the format-type byte is not recognized.
    UnknownEncryptionType(u8),
    /// File is the wrong format family for the current operation
    /// (e.g. caller asked for symmetric but the file is hybrid).
    WrongEncryptedFileType,
    /// Header `flags` field has bits this release does not recognize.
    UnknownHeaderFlags(u16),
    /// Input looks structurally valid but is not a FerroCrypt key file.
    NotAKeyFile,
    /// Key file is the wrong kind for this operation (public vs
    /// private).
    WrongKeyFileType,
    /// Key file algorithm byte is not supported.
    UnsupportedKeyFileAlgorithm(u8),
    /// Key file has an unexpected total size or data-length field.
    BadKeyFileSize,
    /// Key file `flags` field has bits this release does not recognize.
    UnknownKeyFileFlags(u16),
    /// Key material or decrypted envelope has an unexpected byte length.
    UnexpectedKeyLength,
}

impl std::fmt::Display for FormatDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("File is truncated or corrupted"),
            Self::CorruptedHeader => f.write_str("File header is corrupted"),
            Self::BadMagic => f.write_str("Not a FerroCrypt file or unsupported old format"),
            Self::UnknownEncryptionType(b) => {
                write!(f, "Unknown encryption type in FerroCrypt file: 0x{b:02X}")
            }
            Self::WrongEncryptedFileType => {
                f.write_str("Wrong encrypted file type for this operation")
            }
            Self::UnknownHeaderFlags(flags) => {
                write!(
                    f,
                    "Unknown file features (0x{flags:04X}). Upgrade FerroCrypt."
                )
            }
            Self::NotAKeyFile => f.write_str("Not a FerroCrypt key file"),
            Self::WrongKeyFileType => f.write_str("Wrong key file kind (public vs private)"),
            Self::UnsupportedKeyFileAlgorithm(a) => {
                write!(f, "Unsupported key file algorithm: {a}")
            }
            Self::BadKeyFileSize => f.write_str("Key file has unexpected size or data length"),
            Self::UnknownKeyFileFlags(flags) => write!(
                f,
                "Unknown key file flags (0x{flags:04X}). Upgrade FerroCrypt."
            ),
            Self::UnexpectedKeyLength => f.write_str("Key data has an invalid length"),
        }
    }
}

/// File-format or key-file version rejection. Carries the raw version
/// bytes so callers can inspect them without parsing a formatted string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnsupportedVersion {
    /// Encrypted file version is older than the current release supports.
    OlderFile { major: u8, minor: u8 },
    /// Encrypted file version is newer than the current release supports.
    NewerFile { major: u8, minor: u8 },
    /// Key file version is older than the current release supports.
    OlderKey { version: u8 },
    /// Key file version is newer than the current release supports.
    NewerKey { version: u8 },
}

impl std::fmt::Display for UnsupportedVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OlderFile { major, minor } => write!(
                f,
                "Older file format (v{major}.{minor}). Use a previous release."
            ),
            Self::NewerFile { major, minor } => write!(
                f,
                "Newer file format (v{major}.{minor}). Upgrade FerroCrypt."
            ),
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
                write!(f, "File has invalid unlock settings (parallelism {n})")
            }
            Self::MemoryCost(n) => {
                write!(f, "File has invalid unlock settings ({n} KiB memory)")
            }
            Self::TimeCost(n) => write!(f, "File has invalid unlock settings (time cost {n})"),
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
    /// Encrypted stream ended before the final authenticated chunk.
    Truncated,
    /// Writer or reader state was already consumed (programmer bug).
    StateExhausted,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            StreamError::DecryptAead => "payload authentication failed",
            StreamError::EncryptAead => "internal error: payload encryption failed",
            StreamError::Truncated => "encrypted stream truncated",
            StreamError::StateExhausted => "internal error: stream state already finalized",
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
                StreamError::DecryptAead => CryptoError::PayloadAuthenticationFailed,
                StreamError::Truncated => CryptoError::TruncatedStream,
                StreamError::EncryptAead => {
                    CryptoError::InternalCryptoFailure("internal error: payload encryption failed")
                }
                StreamError::StateExhausted => {
                    CryptoError::InternalInvariant("internal error: stream state already finalized")
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
            "Private key file unlock failed: wrong passphrase"
        );
        assert_eq!(
            CryptoError::HeaderAuthenticationFailed.to_string(),
            "Wrong password/key or file was tampered with"
        );
        assert_eq!(
            CryptoError::PayloadAuthenticationFailed.to_string(),
            "Payload authentication failed: data tampered or corrupted"
        );
        assert_eq!(
            CryptoError::TruncatedStream.to_string(),
            "Encrypted file is truncated"
        );
    }

    /// Lock in the Display text of the typed `FormatDefect`,
    /// `UnsupportedVersion`, and `InvalidKdfParams` variants so
    /// wording regressions are caught at test time. Integration tests
    /// grep for several of these substrings.
    #[test]
    fn typed_format_variants_display_exact_strings() {
        assert_eq!(
            FormatDefect::Truncated.to_string(),
            "File is truncated or corrupted"
        );
        assert_eq!(
            FormatDefect::CorruptedHeader.to_string(),
            "File header is corrupted"
        );
        assert_eq!(
            FormatDefect::BadMagic.to_string(),
            "Not a FerroCrypt file or unsupported old format"
        );
        assert_eq!(
            FormatDefect::UnknownEncryptionType(0x41).to_string(),
            "Unknown encryption type in FerroCrypt file: 0x41"
        );
        assert_eq!(
            FormatDefect::WrongEncryptedFileType.to_string(),
            "Wrong encrypted file type for this operation"
        );
        assert_eq!(
            UnsupportedVersion::NewerFile { major: 9, minor: 0 }.to_string(),
            "Newer file format (v9.0). Upgrade FerroCrypt."
        );
        assert_eq!(
            UnsupportedVersion::OlderFile { major: 1, minor: 0 }.to_string(),
            "Older file format (v1.0). Use a previous release."
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
            "File has invalid unlock settings (parallelism 9999)"
        );
        assert_eq!(
            InvalidKdfParams::MemoryCost(42).to_string(),
            "File has invalid unlock settings (42 KiB memory)"
        );
        assert_eq!(
            InvalidKdfParams::TimeCost(7).to_string(),
            "File has invalid unlock settings (time cost 7)"
        );
    }

    /// Budget: every static user-facing `CryptoError` message — plus
    /// the worst-case formatted variants — must fit in the desktop
    /// status line's 64-char window. Dynamic `InvalidInput` messages
    /// are exempt because the desktop frontend runs them through path
    /// elision; this test covers the messages that have no path to
    /// elide.
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
        check(
            "HeaderAuthenticationFailed",
            &CryptoError::HeaderAuthenticationFailed.to_string(),
        );
        check(
            "PayloadAuthenticationFailed",
            &CryptoError::PayloadAuthenticationFailed.to_string(),
        );
        check("TruncatedStream", &CryptoError::TruncatedStream.to_string());
        // ExcessiveWork at both-u32-max so numeric interpolation cannot
        // blow the budget at runtime.
        check(
            "ExcessiveWork(max)",
            &CryptoError::ExcessiveWork {
                required_kib: u32::MAX,
                max_kib: u32::MAX,
            }
            .to_string(),
        );

        // FormatDefect — every variant at its worst-case payload.
        let defects: &[(&str, FormatDefect)] = &[
            ("Truncated", FormatDefect::Truncated),
            ("CorruptedHeader", FormatDefect::CorruptedHeader),
            ("BadMagic", FormatDefect::BadMagic),
            (
                "UnknownEncryptionType",
                FormatDefect::UnknownEncryptionType(u8::MAX),
            ),
            (
                "WrongEncryptedFileType",
                FormatDefect::WrongEncryptedFileType,
            ),
            (
                "UnknownHeaderFlags",
                FormatDefect::UnknownHeaderFlags(u16::MAX),
            ),
            ("NotAKeyFile", FormatDefect::NotAKeyFile),
            ("WrongKeyFileType", FormatDefect::WrongKeyFileType),
            (
                "UnsupportedKeyFileAlgorithm",
                FormatDefect::UnsupportedKeyFileAlgorithm(u8::MAX),
            ),
            ("BadKeyFileSize", FormatDefect::BadKeyFileSize),
            (
                "UnknownKeyFileFlags",
                FormatDefect::UnknownKeyFileFlags(u16::MAX),
            ),
            ("UnexpectedKeyLength", FormatDefect::UnexpectedKeyLength),
        ];
        for (label, d) in defects {
            check(label, &d.to_string());
        }

        // UnsupportedVersion at u8::MAX so the widest numeric render
        // still fits.
        let versions: &[(&str, UnsupportedVersion)] = &[
            (
                "OlderFile(max)",
                UnsupportedVersion::OlderFile {
                    major: u8::MAX,
                    minor: u8::MAX,
                },
            ),
            (
                "NewerFile(max)",
                UnsupportedVersion::NewerFile {
                    major: u8::MAX,
                    minor: u8::MAX,
                },
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
            CryptoError::PayloadAuthenticationFailed
        ));
        assert!(matches!(
            from_marker(StreamError::Truncated),
            CryptoError::TruncatedStream
        ));
        match from_marker(StreamError::EncryptAead) {
            CryptoError::InternalCryptoFailure(msg) => {
                assert_eq!(msg, "internal error: payload encryption failed");
                assert_eq!(msg, StreamError::EncryptAead.to_string());
            }
            other => panic!("expected InternalCryptoFailure, got {other:?}"),
        }
        match from_marker(StreamError::StateExhausted) {
            CryptoError::InternalInvariant(msg) => {
                assert_eq!(msg, "internal error: stream state already finalized");
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
