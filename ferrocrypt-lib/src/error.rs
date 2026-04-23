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
    /// KDF memory cost exceeds the caller-supplied work limit.
    #[error("Needs {required_kib} KiB to decrypt; limit is {max_kib} KiB")]
    ExcessiveWork { required_kib: u32, max_kib: u32 },

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
    /// A symmetric `.fcr` envelope failed to unlock. Either the
    /// passphrase does not derive the right wrap key, or the envelope
    /// ciphertext / wrap-derivation fields (argon2_salt, kdf_params,
    /// wrap_nonce) were tampered with. The AEAD primitive cannot
    /// distinguish the two cases, and the format deliberately collapses
    /// them into a single error.
    #[error("Decryption failed: wrong passphrase or tampered envelope")]
    SymmetricEnvelopeUnlockFailed,
    /// A hybrid `.fcr` envelope failed to unlock. Fires from the envelope
    /// AEAD-open (wrong private key or tampered envelope are
    /// indistinguishable there) and from the all-zero X25519
    /// shared-secret guard (small-order recipient public key).
    #[error("Decryption failed: wrong private key or tampered envelope")]
    HybridEnvelopeUnlockFailed,
    /// The envelope unwrapped successfully but the header HMAC failed.
    /// This means the caller has the right passphrase / private key, but
    /// header bytes outside the envelope (replicated prefix,
    /// `stream_nonce`, `ext_bytes`) were tampered with after the file
    /// was written.
    #[error("Decryption failed: header tampered after unlock")]
    HeaderTampered,
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

    // ─── Low-level primitives ────────────────────────────────────────────
    /// Fixed-size byte conversion failed due to an unexpected length.
    #[error(transparent)]
    SliceConversion(#[from] std::array::TryFromSliceError),

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatDefect {
    /// Input ended before a complete field or header could be read.
    Truncated,
    /// Replication decoding produced a logical length that does not
    /// match the expected structural layout.
    CorruptedHeader,
    /// The 27-byte on-disk replicated prefix is not the canonical
    /// encoding of its majority-voted 8-byte logical form. `decoded_view`
    /// carries the logical bytes so callers can still surface upgrade
    /// messages ("file says v2") even on a bit-rotten file.
    CorruptedPrefix { decoded_view: [u8; 8] },
    /// Leading magic bytes do not match `"FCR\0"`.
    BadMagic,
    /// `.fcr` type byte is not recognised.
    UnknownType { type_byte: u8 },
    /// File is the wrong format family for the current operation
    /// (e.g. caller asked for symmetric but the file is hybrid).
    WrongEncryptedFileType,
    /// `ext_len` (in a `.fcr` prefix or `private.key` header) exceeds
    /// the reader's structural cap of 32 KiB.
    ExtTooLarge { len: u16 },
    /// A TLV entry in the extension region is malformed: bad ordering,
    /// duplicate tag, or `len` extends past the end of the region.
    MalformedTlv,
    /// A TLV tag in the critical range (`0x8001..=0xFFFF`) is not
    /// recognised by this release.
    UnknownCriticalTag { tag: u16 },
    /// Input looks structurally valid but is not a FerroCrypt key file.
    NotAKeyFile,
    /// Key file is the wrong kind for this operation (public vs private).
    WrongKeyFileType,
    /// Key-file or `fcr1…` algorithm byte is not supported.
    UnknownAlgorithm { algorithm: u8 },
    /// Key file has an unexpected total size relative to its parsed
    /// layout.
    BadKeyFileSize,
    /// Key material or decrypted envelope has an unexpected byte length.
    UnexpectedKeyLength,
}

impl std::fmt::Display for FormatDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("File is truncated or corrupted"),
            Self::CorruptedHeader => f.write_str("File header is corrupted"),
            Self::CorruptedPrefix { decoded_view } => {
                write!(f, "File header corrupted (declared v{})", decoded_view[4])
            }
            Self::BadMagic => f.write_str("Not a FerroCrypt file"),
            Self::UnknownType { type_byte } => {
                write!(f, "Unknown encrypted file type: 0x{type_byte:02X}")
            }
            Self::WrongEncryptedFileType => {
                f.write_str("Wrong encrypted file type for this operation")
            }
            Self::ExtTooLarge { len } => {
                write!(f, "File extension region too large ({len} bytes)")
            }
            Self::MalformedTlv => f.write_str("File extension region malformed"),
            Self::UnknownCriticalTag { tag } => write!(
                f,
                "Unknown required file feature (tag 0x{tag:04X}). Upgrade FerroCrypt."
            ),
            Self::NotAKeyFile => f.write_str("Not a FerroCrypt key file"),
            Self::WrongKeyFileType => f.write_str("Wrong key file kind (public vs private)"),
            Self::UnknownAlgorithm { algorithm } => {
                write!(f, "Unsupported key algorithm: 0x{algorithm:02X}")
            }
            Self::BadKeyFileSize => f.write_str("Key file has unexpected size"),
            Self::UnexpectedKeyLength => f.write_str("Key data has an invalid length"),
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
                write!(f, "File has invalid decrypt settings (parallelism {n})")
            }
            Self::MemoryCost(n) => {
                write!(f, "File has invalid decrypt settings ({n} KiB memory)")
            }
            Self::TimeCost(n) => write!(f, "File has invalid decrypt settings (time cost {n})"),
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
    /// Bytes remain after the final-flag chunk. Reserved for future
    /// spec-compliant detection per FORMAT.md §3.7; trailing data
    /// currently surfaces via `DecryptAead` when the final-chunk AEAD
    /// fails on appended bytes. Wiring an explicit post-unarchive
    /// probe into the decrypt path is planned follow-up work.
    #[allow(dead_code)]
    ExtraData,
    /// Writer or reader state was already consumed (programmer bug).
    StateExhausted,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            StreamError::DecryptAead => "payload authentication failed",
            StreamError::EncryptAead => "internal error: payload encryption failed",
            StreamError::Truncated => "encrypted stream truncated",
            StreamError::ExtraData => "encrypted stream has trailing data",
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
                StreamError::DecryptAead => CryptoError::PayloadTampered,
                StreamError::Truncated => CryptoError::PayloadTruncated,
                StreamError::ExtraData => CryptoError::ExtraDataAfterPayload,
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
            "Private key unlock failed: wrong passphrase or tampered file"
        );
        assert_eq!(
            CryptoError::SymmetricEnvelopeUnlockFailed.to_string(),
            "Decryption failed: wrong passphrase or tampered envelope"
        );
        assert_eq!(
            CryptoError::HybridEnvelopeUnlockFailed.to_string(),
            "Decryption failed: wrong private key or tampered envelope"
        );
        assert_eq!(
            CryptoError::HeaderTampered.to_string(),
            "Decryption failed: header tampered after unlock"
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
        assert_eq!(
            FormatDefect::CorruptedHeader.to_string(),
            "File header is corrupted"
        );
        assert_eq!(
            FormatDefect::CorruptedPrefix {
                decoded_view: [b'F', b'C', b'R', 0, 2, 0x53, 0, 0]
            }
            .to_string(),
            "File header corrupted (declared v2)"
        );
        assert_eq!(FormatDefect::BadMagic.to_string(), "Not a FerroCrypt file");
        assert_eq!(
            FormatDefect::UnknownType { type_byte: 0x41 }.to_string(),
            "Unknown encrypted file type: 0x41"
        );
        assert_eq!(
            FormatDefect::WrongEncryptedFileType.to_string(),
            "Wrong encrypted file type for this operation"
        );
        assert_eq!(
            FormatDefect::ExtTooLarge { len: 65535 }.to_string(),
            "File extension region too large (65535 bytes)"
        );
        assert_eq!(
            FormatDefect::MalformedTlv.to_string(),
            "File extension region malformed"
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
            FormatDefect::UnknownAlgorithm { algorithm: 0xFF }.to_string(),
            "Unsupported key algorithm: 0xFF"
        );
        assert_eq!(
            FormatDefect::BadKeyFileSize.to_string(),
            "Key file has unexpected size"
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
            "File has invalid decrypt settings (parallelism 9999)"
        );
        assert_eq!(
            InvalidKdfParams::MemoryCost(42).to_string(),
            "File has invalid decrypt settings (42 KiB memory)"
        );
        assert_eq!(
            InvalidKdfParams::TimeCost(7).to_string(),
            "File has invalid decrypt settings (time cost 7)"
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
        check(
            "SymmetricEnvelopeUnlockFailed",
            &CryptoError::SymmetricEnvelopeUnlockFailed.to_string(),
        );
        check(
            "HybridEnvelopeUnlockFailed",
            &CryptoError::HybridEnvelopeUnlockFailed.to_string(),
        );
        check("HeaderTampered", &CryptoError::HeaderTampered.to_string());
        check("PayloadTampered", &CryptoError::PayloadTampered.to_string());
        check(
            "PayloadTruncated",
            &CryptoError::PayloadTruncated.to_string(),
        );
        check(
            "ExtraDataAfterPayload",
            &CryptoError::ExtraDataAfterPayload.to_string(),
        );
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
            (
                "CorruptedPrefix",
                FormatDefect::CorruptedPrefix {
                    decoded_view: [b'F', b'C', b'R', 0, u8::MAX, u8::MAX, u8::MAX, u8::MAX],
                },
            ),
            ("BadMagic", FormatDefect::BadMagic),
            (
                "UnknownType",
                FormatDefect::UnknownType { type_byte: u8::MAX },
            ),
            (
                "WrongEncryptedFileType",
                FormatDefect::WrongEncryptedFileType,
            ),
            ("ExtTooLarge", FormatDefect::ExtTooLarge { len: u16::MAX }),
            ("MalformedTlv", FormatDefect::MalformedTlv),
            (
                "UnknownCriticalTag",
                FormatDefect::UnknownCriticalTag { tag: u16::MAX },
            ),
            ("NotAKeyFile", FormatDefect::NotAKeyFile),
            ("WrongKeyFileType", FormatDefect::WrongKeyFileType),
            (
                "UnknownAlgorithm",
                FormatDefect::UnknownAlgorithm { algorithm: u8::MAX },
            ),
            ("BadKeyFileSize", FormatDefect::BadKeyFileSize),
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
