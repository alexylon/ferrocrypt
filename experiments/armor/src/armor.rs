//! ASCII armor for v1 `.fcr` files (`FORMAT.md` §10).
//!
//! Wraps a binary `.fcr` file in a printable Base64 envelope so it
//! can be pasted into email, chat, GitHub issues, or any other
//! text-only transport. Same security as binary; armor adds zero
//! crypto, only encoding.
//!
//! Canonical form:
//!
//! ```text
//! -----BEGIN FERROCRYPT ENCRYPTED FILE-----
//! <RFC 4648 standard Base64, wrapped at 64 chars except final line>
//! -----END FERROCRYPT ENCRYPTED FILE-----
//! ```
//!
//! ## Architecture
//!
//! Streaming, ported from `rage`'s sync `armor.rs` design (we skip
//! the `async` and `Seek` paths since neither is in our consumer
//! surface). Two public types:
//!
//! - [`ArmoredWriter`] wraps any `Write` and optionally applies armor
//!   based on the [`Format`] enum. The internal
//!   `Enabled { byte_buf, encoded_buf } | Disabled` shape lets the
//!   same struct drive both binary and armored output through one
//!   `Write` impl. The caller MUST call [`ArmoredWriter::finish`] —
//!   that flushes the trailing partial Base64 chunk and writes the
//!   END marker.
//! - [`ArmoredReader`] wraps a `Read` (internally a `BufReader`) and
//!   auto-detects on first read by consuming up to [`MIN_ARMOR_LEN`]
//!   bytes from the inner reader. If the prefix matches the BEGIN
//!   marker, the reader runs the strict line-by-line decoder;
//!   otherwise the consumed bytes are stashed in `binary_prefix` and
//!   replayed on subsequent reads, then the wrapper streams the
//!   original bytes through unchanged.
//!
//! ## Auto-detection vs strict decoding
//!
//! [`ArmoredReader`] is an *auto-detecting* adapter. It runs the
//! strict armor decoder only when the stream begins exactly with
//! this crate's [`BEGIN_MARKER`]. Non-matching prefixes — including
//! third-party armor labels (e.g. `-----BEGIN AGE…-----`) and
//! arbitrary leading garbage — are passed through verbatim as
//! binary, and rejection (if appropriate) is the downstream `.fcr`
//! parser's responsibility.
//!
//! Once armor mode is entered, the decoder fails closed per
//! `FORMAT.md` §10 on:
//!
//! - wrong END marker (incl. trailing/leading whitespace),
//! - bad BEGIN terminator (must be `\n` or `\r\n`),
//! - after END, anything other than at most one trailing line
//!   terminator (LF or CRLF) — stricter than rage's "any whitespace
//!   allowed",
//! - blank lines or whitespace inside Base64 lines,
//! - non-Base64 characters,
//! - non-canonical Base64 padding (final line length must be a
//!   multiple of 4),
//! - body lines other than the final one not at exactly 64 chars,
//! - body content after a final line (a line ending in `=` or
//!   shorter than 64 chars marks end-of-body — only the END marker
//!   may follow),
//! - bare `\r` (CR) inside a line.
//!
//! Each rejection class surfaces as a typed [`ArmorDefect`] inside
//! [`FormatDefect::MalformedArmor`].

use std::io::{self, BufRead, BufReader, Read, Write};

use base64::{Engine, prelude::BASE64_STANDARD};
use zeroize::Zeroizing;

use crate::error::ArmorDefect;

/// Number of Base64 characters per line in the armored body.
pub const ARMORED_COLUMNS_PER_LINE: usize = 64;

/// Number of plaintext bytes that encode to one full armored line
/// (`64 / 4 * 3`).
pub const ARMORED_BYTES_PER_LINE: usize = ARMORED_COLUMNS_PER_LINE / 4 * 3;

/// Internal Base64 chunking: encode this many plaintext bytes at a
/// time before emitting Base64 lines. Tuned so the encoded output is
/// a whole number of lines (`8 KiB / 4 * 3 = 6144`).
const BASE64_CHUNK_SIZE_COLUMNS: usize = 8 * 1024;
const BASE64_CHUNK_SIZE_BYTES: usize = BASE64_CHUNK_SIZE_COLUMNS / 4 * 3;

/// BEGIN marker (`FORMAT.md` §10).
pub const BEGIN_MARKER: &str = "-----BEGIN FERROCRYPT ENCRYPTED FILE-----";
/// END marker (`FORMAT.md` §10).
pub const END_MARKER: &str = "-----END FERROCRYPT ENCRYPTED FILE-----";

/// Bytes the armor detector consumes from the reader on first access
/// for prefix classification; replayed through `binary_prefix` when
/// the stream is not armored. The window is the BEGIN marker plus its
/// line terminator (`\n` or `\r\n`): 41 + 2 = 43 — same idea as
/// rage's `MIN_ARMOR_LEN`.
pub const MIN_ARMOR_LEN: usize = BEGIN_MARKER.len() + 2;

/// Hard cap on bytes appended to `line_buf` per raw `read_until`
/// call. Stops a malicious armored stream from claiming to be armor
/// and then streaming an unbounded line without an LF (memory DoS).
/// Per §10 the longest legal body line is 64 chars + CRLF = 66
/// bytes; 128 bytes gives slack so non-canonical-but-still-
/// rejectable lines can be parsed in full and surface the correct
/// `ArmorDefect` class instead of being truncated at a `\r` boundary
/// into `LineContainsCr`.
const MAX_LINE_BYTES: usize = 128;

/// Output format for [`ArmoredWriter`]. Picked at write time so a
/// single writer type drives both paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Binary `.fcr`. The writer is a transparent passthrough to the
    /// inner `Write`.
    Binary,
    /// Armored `.fcr`. The writer Base64-encodes, line-wraps, and
    /// emits the BEGIN/END markers around the body.
    AsciiArmor,
}

// ─── LineEndingWriter ───────────────────────────────────────────────────────

/// Inserts an LF after every [`ARMORED_COLUMNS_PER_LINE`] bytes
/// written, and emits the BEGIN marker on construction. Ported from
/// rage; the only state is the column index in the current line.
struct LineEndingWriter<W: Write> {
    inner: W,
    column: usize,
}

impl<W: Write> LineEndingWriter<W> {
    fn new(mut inner: W) -> io::Result<Self> {
        inner.write_all(BEGIN_MARKER.as_bytes())?;
        inner.write_all(b"\n")?;
        Ok(Self { inner, column: 0 })
    }

    /// Writes the END marker. If the current body line is partial,
    /// first terminates it with `\n`; full 64-character body lines
    /// were already terminated by `write` (which emits the LF as
    /// soon as the column hits the line width).
    fn finish(mut self) -> io::Result<W> {
        if self.column != 0 {
            self.inner.write_all(b"\n")?;
        }
        self.inner.write_all(END_MARKER.as_bytes())?;
        self.inner.write_all(b"\n")?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for LineEndingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0usize;
        let mut remaining = buf;
        while !remaining.is_empty() {
            let room = ARMORED_COLUMNS_PER_LINE - self.column;
            let take = room.min(remaining.len());
            self.inner.write_all(&remaining[..take])?;
            self.column += take;
            remaining = &remaining[take..];
            written += take;
            if self.column == ARMORED_COLUMNS_PER_LINE {
                self.inner.write_all(b"\n")?;
                self.column = 0;
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ─── ArmoredWriter ──────────────────────────────────────────────────────────

/// Writer that optionally applies the v1 ASCII armor format. The
/// caller picks [`Format::Binary`] or [`Format::AsciiArmor`] at
/// construction; the same `Write` impl drives both.
///
/// The caller **MUST** call [`ArmoredWriter::finish`] when done so
/// the trailing partial Base64 chunk is flushed and the END marker
/// is written. Failing to call `finish` produces a truncated armor
/// block that will not decode.
pub struct ArmoredWriter<W: Write> {
    state: ArmorState<W>,
    /// Once the inner writer returns an I/O error, retrying the same
    /// input would risk duplicate or malformed output because some
    /// bytes may already have reached the underlying writer. Poison
    /// the adapter after the first write error and make later calls
    /// fail without accepting more caller bytes.
    failed: bool,
}

enum ArmorState<W: Write> {
    Enabled {
        inner: LineEndingWriter<W>,
        byte_buf: Vec<u8>,
        encoded_buf: Box<[u8; BASE64_CHUNK_SIZE_COLUMNS]>,
    },
    Disabled {
        inner: W,
    },
}

impl<W: Write> ArmoredWriter<W> {
    /// Wraps `output` in an `ArmoredWriter` that applies `format`.
    pub fn wrap_output(output: W, format: Format) -> io::Result<Self> {
        let state = match format {
            Format::AsciiArmor => ArmorState::Enabled {
                inner: LineEndingWriter::new(output)?,
                byte_buf: Vec::with_capacity(BASE64_CHUNK_SIZE_BYTES),
                encoded_buf: Box::new([0u8; BASE64_CHUNK_SIZE_COLUMNS]),
            },
            Format::Binary => ArmorState::Disabled { inner: output },
        };
        Ok(Self {
            state,
            failed: false,
        })
    }

    /// Flushes the armor encoder's internal Base64 buffer and writes
    /// the END marker, then returns the underlying writer.
    ///
    /// This does **not** call `flush()` on the returned writer.
    /// Callers wrapping a buffered writer (`BufWriter`, `File` with
    /// OS-level buffering, etc.) should flush explicitly if they
    /// need delayed I/O errors to surface here rather than at drop
    /// time. FerroCrypt callers funnel through `fs::atomic`,
    /// which performs its own flush+sync before commit, so this
    /// adapter intentionally leaves the final flush to the caller.
    pub fn finish(self) -> io::Result<W> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "armored writer is poisoned after an earlier I/O error",
            ));
        }
        match self.state {
            ArmorState::Enabled {
                mut inner,
                byte_buf,
                mut encoded_buf,
            } => {
                // `byte_buf.len() <= BASE64_CHUNK_SIZE_BYTES` and
                // `encoded_buf.len() == BASE64_CHUNK_SIZE_COLUMNS`,
                // sized so any chunk encodes in-place. The only
                // possible encode_slice error (`OutputSliceTooSmall`)
                // is structurally unreachable.
                let encoded = BASE64_STANDARD
                    .encode_slice(&byte_buf, &mut encoded_buf[..])
                    .expect("encoded_buf sized to fit max chunk by construction");
                inner.write_all(&encoded_buf[..encoded])?;
                inner.finish()
            }
            ArmorState::Disabled { inner } => Ok(inner),
        }
    }
}

impl<W: Write> Write for ArmoredWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "armored writer is poisoned after an earlier I/O error",
            ));
        }

        let armored = matches!(&self.state, ArmorState::Enabled { .. });

        let result = match &mut self.state {
            ArmorState::Enabled {
                inner,
                byte_buf,
                encoded_buf,
            } => {
                if buf.is_empty() {
                    Ok(0)
                } else {
                    // If a previous call filled the chunk buffer, flush
                    // it before accepting bytes from this call. If the
                    // flush fails, this call consumes zero caller bytes,
                    // and the writer is poisoned below to reject retries.
                    let flush_result = if byte_buf.len() == BASE64_CHUNK_SIZE_BYTES {
                        let encoded = BASE64_STANDARD
                            .encode_slice(&byte_buf[..], &mut encoded_buf[..])
                            .expect("encoded_buf sized to fit max chunk by construction");
                        debug_assert_eq!(encoded, BASE64_CHUNK_SIZE_COLUMNS);
                        inner.write_all(&encoded_buf[..encoded])
                    } else {
                        Ok(())
                    };

                    match flush_result {
                        Ok(()) => {
                            if byte_buf.len() == BASE64_CHUNK_SIZE_BYTES {
                                byte_buf.clear();
                            }
                            let room = BASE64_CHUNK_SIZE_BYTES - byte_buf.len();
                            let take = room.min(buf.len());
                            byte_buf.extend_from_slice(&buf[..take]);
                            Ok(take)
                        }
                        Err(e) => Err(e),
                    }
                }
            }
            ArmorState::Disabled { inner } => inner.write(buf),
        };

        // Poison only when we're in armored mode AND the error isn't
        // `Interrupted`. Rationale: armored mode has stateful buffering
        // (`byte_buf`) that could produce duplicate or malformed output
        // on retry, so failing closed there is correct. `Interrupted`
        // is documented as retryable per the Read/Write trait
        // conventions, so poisoning on it would turn a harmless retry
        // into a permanent BrokenPipe. Disabled (binary) mode is a
        // transparent passthrough — it has no internal state to
        // protect, so leaving the user's retry semantics intact is
        // correct.
        if let Err(ref e) = result {
            if armored && e.kind() != io::ErrorKind::Interrupted {
                self.failed = true;
            }
        }
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "armored writer is poisoned after an earlier I/O error",
            ));
        }
        let armored = matches!(&self.state, ArmorState::Enabled { .. });
        let result = match &mut self.state {
            ArmorState::Enabled { inner, .. } => inner.flush(),
            ArmorState::Disabled { inner } => inner.flush(),
        };
        if let Err(ref e) = result {
            if armored && e.kind() != io::ErrorKind::Interrupted {
                self.failed = true;
            }
        }
        result
    }
}

// ─── ArmoredReader ──────────────────────────────────────────────────────────

/// Reader that auto-detects ASCII armor and transparently decodes
/// it, or passes the original bytes through unchanged for binary
/// input. Detection happens on the first read: the wrapper consumes
/// up to [`MIN_ARMOR_LEN`] bytes from the inner reader and matches
/// the prefix against the BEGIN marker. If the input is binary,
/// those consumed bytes are stashed in `binary_prefix` and replayed
/// on subsequent reads before the wrapper delegates to the inner
/// reader.
pub struct ArmoredReader<R: Read> {
    inner: BufReader<R>,
    is_armored: Option<bool>,
    line_buf: Zeroizing<Vec<u8>>,
    /// "Exposed" buffer — bytes ready to serve to the caller. Filled
    /// by promoting `pending_buf` once the line *after* the pending
    /// one has been parsed successfully. The lookahead-by-1
    /// confirmation prevents bytes from a body line at EOF (where no
    /// END marker can follow) from being exposed to the caller.
    byte_buf: Zeroizing<[u8; ARMORED_BYTES_PER_LINE]>,
    byte_start: usize,
    byte_end: usize,
    /// "Pending" buffer — bytes from the most recently decoded body
    /// line, NOT yet exposed. Promoted to `byte_buf` only when the
    /// next line is parsed successfully (another body line, or the
    /// END marker after `check_no_trailing_garbage` passes). On any
    /// parse failure or EOF before END, pending bytes are discarded.
    pending_buf: Zeroizing<[u8; ARMORED_BYTES_PER_LINE]>,
    pending_len: usize,
    /// `true` once a line that marks end-of-body has been parsed —
    /// either a short line (length < `ARMORED_COLUMNS_PER_LINE`) or a
    /// 64-char line containing Base64 padding (`=`). Both cases
    /// signal "no further body lines may appear; only the END marker
    /// may follow."
    found_final_body_line: bool,
    found_end: bool,
    /// Pre-detection peek bytes that turned out to be plain `.fcr`
    /// data; replayed before further reads from `inner`. Zeroized on
    /// drop for consistency with the other reader buffers — the peek
    /// straddles header_fixed and the first recipient-entry header.
    binary_prefix: Zeroizing<Vec<u8>>,
    binary_prefix_pos: usize,
    /// First armor defect seen by the reader. Once set, later reads
    /// return the same typed defect without reading or appending more
    /// bytes, preventing retry-after-error from growing `line_buf` or
    /// changing diagnostics.
    failed: Option<ArmorDefect>,
}

impl<R: Read> ArmoredReader<R> {
    /// Wraps `inner` in an `ArmoredReader` that auto-detects on
    /// first read.
    pub fn new(inner: R) -> Self {
        Self {
            inner: BufReader::new(inner),
            is_armored: None,
            // Capacity covers 1 leftover byte from `detect_armor` plus
            // a full `MAX_LINE_BYTES` read, so `line_buf` never
            // reallocates under normal operation. `Zeroizing<Vec<u8>>`
            // only zeroes on drop — a reallocation would leave the
            // old heap buffer unzeroized in the allocator.
            line_buf: Zeroizing::new(Vec::with_capacity(MAX_LINE_BYTES + 2)),
            byte_buf: Zeroizing::new([0u8; ARMORED_BYTES_PER_LINE]),
            byte_start: ARMORED_BYTES_PER_LINE,
            byte_end: ARMORED_BYTES_PER_LINE,
            pending_buf: Zeroizing::new([0u8; ARMORED_BYTES_PER_LINE]),
            pending_len: 0,
            found_final_body_line: false,
            found_end: false,
            binary_prefix: Zeroizing::new(Vec::new()),
            binary_prefix_pos: 0,
            failed: None,
        }
    }

    fn detect_armor(&mut self) -> io::Result<()> {
        debug_assert!(self.is_armored.is_none());

        let mut peek = [0u8; MIN_ARMOR_LEN];
        let read = read_up_to(&mut self.inner, &mut peek)?;

        // Match the BEGIN marker on its own (LF needs marker + 1
        // byte, CRLF needs marker + 2). We classify as armor as soon
        // as the marker bytes match, then validate the terminator
        // separately so that `BEGIN_MARKER\n` (truncated, 42 bytes)
        // and `BEGIN_MARKER\r\n` (43 bytes) are treated consistently
        // — both as armor that goes on to fail with the appropriate
        // typed defect, rather than the LF case escaping to binary.
        let marker_len = BEGIN_MARKER.len();
        let marker_matches = read >= marker_len && &peek[..marker_len] == BEGIN_MARKER.as_bytes();

        if !marker_matches {
            // Not armored: replay the peeked bytes on subsequent
            // reads, then fall back to direct passthrough.
            self.is_armored = Some(false);
            self.binary_prefix = Zeroizing::new(peek[..read].to_vec());
            return Ok(());
        }

        // Classify *before* any fallible inner validation, so a caller
        // that swallows the resulting error and re-enters `read` cannot
        // re-trigger detection on a half-consumed BufReader.
        self.is_armored = Some(true);

        // The byte at `peek[marker_len]` is the BEGIN line terminator
        // (or, on a truncated stream, missing). Bounds-check via
        // `peek[..read]` so we never read past what the inner reader
        // actually produced.
        let after_marker = &peek[marker_len..read];
        match after_marker {
            [b'\n', leftover @ ..] => {
                // LF terminator. Any bytes past the LF are first-body-
                // line leftovers. Keep them as raw bytes and validate
                // UTF-8 only once the complete line has been read, so
                // a multi-byte code point split at this detection
                // boundary does not produce a boundary-dependent
                // `InvalidUtf8` diagnostic.
                self.line_buf.extend_from_slice(leftover);
            }
            [b'\r', b'\n', ..] => {
                // CRLF terminator. With our 43-byte peek window the
                // CRLF consumes both available bytes after the marker,
                // so there is no in-window leftover.
            }
            // Marker without a complete terminator (truncated stream),
            // or a non-LF/non-CRLF byte after the marker: malformed.
            _ => return Err(self.fail(ArmorDefect::BadBeginMarker)),
        }
        Ok(())
    }

    fn fail(&mut self, defect: ArmorDefect) -> io::Error {
        self.failed = Some(defect);
        self.line_buf.clear();
        self.discard_buffered_bytes();
        armor_io_error(defect)
    }

    /// Validates `line_buf` against the §10 grammar. For body lines,
    /// Base64-decodes into a stack-local temp; on success, the
    /// previously pending line is promoted into the exposed
    /// `byte_buf`, and the just-decoded line becomes the new pending
    /// line. Returns `true` if the line was the END marker (caller
    /// then promotes pending and runs `check_no_trailing_garbage`).
    fn parse_armor_line(&mut self) -> io::Result<bool> {
        // Strip the line terminator. `BufRead::read_until` returns the
        // trailing `\n` (and any preceding `\r`); a missing newline
        // means we hit EOF on the final line.
        let line_bytes: Zeroizing<Vec<u8>> = if let Some(rest) = self.line_buf.strip_suffix(b"\r\n")
        {
            Zeroizing::new(rest.to_vec())
        } else if let Some(rest) = self.line_buf.strip_suffix(b"\n") {
            Zeroizing::new(rest.to_vec())
        } else {
            Zeroizing::new(self.line_buf.to_vec())
        };

        if line_bytes.as_slice() == END_MARKER.as_bytes() {
            self.found_end = true;
            self.line_buf.clear();
            return Ok(true);
        }

        // END-marker-shaped lines are marker errors, not body/Base64
        // errors. Do this before the generic bare-CR and UTF-8 checks
        // so `END_MARKER + "\r"` and mistyped END labels surface as
        // `BadEndMarker`.
        if bytes_contains(&line_bytes, END_MARKER.as_bytes()) || looks_like_end_marker(&line_bytes)
        {
            return Err(self.fail(ArmorDefect::BadEndMarker));
        }

        // Once a final body line has been parsed (a short line, or a
        // 64-char line containing Base64 padding), only the END
        // marker is a legal next line. Surface the structural defect
        // here, BEFORE the granular byte/length checks that would
        // otherwise mask `ShortLineInMiddle` with `InvalidUtf8`,
        // `LineContainsCr`, or `NonBase64Character`.
        if self.found_final_body_line {
            return Err(self.fail(ArmorDefect::ShortLineInMiddle));
        }

        let line = match std::str::from_utf8(&line_bytes) {
            Ok(line) => line,
            Err(_) => return Err(self.fail(ArmorDefect::InvalidUtf8)),
        };

        if line.contains('\r') {
            return Err(self.fail(ArmorDefect::LineContainsCr));
        }

        // Length and shape checks for the body line. A 64-char line
        // containing `=` IS allowed under `(_, 64)` here; the post-
        // decode block below promotes it to `found_final_body_line`
        // so the next non-END line is rejected as `ShortLineInMiddle`
        // (caught upstream by the post-final-body check before we
        // reach this match on later iterations).
        match line.len() {
            ARMORED_COLUMNS_PER_LINE => {}
            0 => return Err(self.fail(ArmorDefect::NotWrappedAt64Chars)),
            n if n > ARMORED_COLUMNS_PER_LINE => {
                return Err(self.fail(ArmorDefect::NotWrappedAt64Chars));
            }
            n if n % 4 != 0 => {
                return Err(self.fail(ArmorDefect::NonCanonicalBase64Padding));
            }
            _ => {} // valid short line — finalised below.
        }

        // Validate Base64 alphabet explicitly. Without this check,
        // ASCII whitespace would have been caught above by the early
        // whitespace test, but other non-Base64 ASCII bytes (like
        // `?`, `!`, etc.) would have slipped through to `decode_slice`
        // and surfaced as the less precise `Base64DecodeFailed`.
        // Folding both into a single alphabet check makes
        // `NonBase64Character` mean what its name implies.
        if line.as_bytes().iter().any(|&b| !is_base64_body_byte(b)) {
            return Err(self.fail(ArmorDefect::NonBase64Character));
        }

        // Decode into a stack-local temp first; only on success do we
        // promote the previous pending line and commit the new
        // decoded bytes. This is the lookahead-by-1 mechanism:
        // bytes from the most recently decoded body line sit in
        // `pending_buf` until the *next* line parses successfully —
        // at which point they're confirmed safe to expose. A parse
        // failure or EOF before END discards the *current* pending
        // line (and the just-promoted previous-line bytes that
        // haven't yet been read). It does NOT retract earlier body
        // lines that were already served to the caller in prior
        // `read` calls — see `discard_buffered_bytes`.
        let mut tmp: Zeroizing<[u8; ARMORED_BYTES_PER_LINE]> =
            Zeroizing::new([0u8; ARMORED_BYTES_PER_LINE]);
        let decoded_len = match BASE64_STANDARD.decode_slice(line.as_bytes(), tmp.as_mut()) {
            Ok(decoded_len) => decoded_len,
            Err(_) => return Err(self.fail(ArmorDefect::Base64DecodeFailed)),
        };

        // Capture line shape *before* `line_buf.clear()` releases the
        // `line` borrow. End-of-body if the line is short OR contains
        // Base64 padding (`=`). Padding is the canonical end-of-
        // stream signal; any further body line after one would be a
        // non-canonical concatenation of two Base64 streams.
        let line_len = line.len();
        let has_padding = line.as_bytes().contains(&b'=');

        // Decode succeeded. Promote previous pending → exposed
        // (`byte_buf`), then move the freshly decoded bytes into
        // pending. After this point, the previous body line's bytes
        // are visible to the caller and the current line's bytes are
        // held back for the next line's confirmation.
        self.promote_pending_to_exposed();
        self.pending_buf[..decoded_len].copy_from_slice(&tmp[..decoded_len]);
        self.pending_len = decoded_len;
        self.line_buf.clear();

        if line_len < ARMORED_COLUMNS_PER_LINE || has_padding {
            self.found_final_body_line = true;
        }

        Ok(false)
    }

    /// Moves bytes from `pending_buf` into the exposed `byte_buf` and
    /// clears pending. Called when the line *following* the pending
    /// body line has been successfully parsed (another body line, or
    /// the END marker after `check_no_trailing_garbage` passes).
    fn promote_pending_to_exposed(&mut self) {
        let len = self.pending_len;
        self.byte_buf[..len].copy_from_slice(&self.pending_buf[..len]);
        self.byte_start = 0;
        self.byte_end = len;
        self.pending_len = 0;
    }

    /// Discards the currently buffered exposed bytes (collapsing
    /// `[byte_start..byte_end]` to empty) and the pending line.
    /// Prevents the *most recently decoded* line from being returned
    /// to the caller after an EOF-before-END or trailing-garbage
    /// error. Note: this is one-line lookahead protection, not full-
    /// block fail-closed — earlier body lines may already have been
    /// exposed before the later error was detected, which the
    /// streaming lookahead-by-1 design accepts as a trade-off
    /// against buffering the entire body.
    fn discard_buffered_bytes(&mut self) {
        self.byte_start = self.byte_end;
        self.pending_len = 0;
    }

    fn read_next_armor_line(&mut self) -> io::Result<bool> {
        debug_assert_eq!(self.is_armored, Some(true));

        // If `detect_armor`'s leftover byte was itself a `\n`,
        // `line_buf` already contains a complete (empty) body line.
        // Parse it without reading more — otherwise the next
        // `read_until` would prepend the `\n` to the following body
        // line and fire `NonCanonicalBase64Padding` for what is
        // really a `NotWrappedAt64Chars` (blank body line) rejection.
        if self.line_buf.ends_with(b"\n") {
            if self.parse_armor_line()? {
                // END marker. Promote the pending body line (if any)
                // and verify nothing follows the END terminator.
                self.promote_pending_to_exposed();
                if let Err(e) = self.check_no_trailing_garbage() {
                    self.discard_buffered_bytes();
                    return Err(e);
                }
                return Ok(true);
            }
            return Ok(false);
        }

        // Read raw bytes via `read_until`, then validate UTF-8
        // ourselves. `BufRead::read_line` would return std's generic
        // `InvalidData("stream did not contain valid UTF-8")` for
        // non-UTF-8 input — that error wouldn't downcast to
        // `ArmorDefect` in our `From<io::Error> for CryptoError`
        // impl, so the user would see a cryptic `CryptoError::Io(_)`
        // instead of the typed `MalformedArmor(InvalidUtf8)`. The
        // explicit-validation path mirrors `detect_armor`'s leftover
        // handling.
        //
        // Cap at `MAX_LINE_BYTES` so an attacker who manages to
        // satisfy the BEGIN marker cannot OOM us by streaming an
        // unbounded line without an LF — `Take` reports its own
        // exhaustion as `Ok(0)` to `read_until`, which then stops
        // appending. `parse_armor_line` rejects the truncated line
        // (length > 64) as `NotWrappedAt64Chars`.
        let mut raw: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(MAX_LINE_BYTES));
        let read = (&mut self.inner)
            .take(MAX_LINE_BYTES as u64)
            .read_until(b'\n', &mut raw)?;
        self.line_buf.extend_from_slice(&raw);
        // `detect_armor` may have left a partial line in `line_buf`
        // (the bytes immediately after the BEGIN line's terminator).
        // Even with `read == 0` from inner, that leftover content is
        // a real body line that has to be parsed — its grammar
        // failure is more specific than the generic "missing END"
        // error and per §10 deserves the precise variant.
        if read == 0 && self.line_buf.is_empty() {
            return Err(self.fail(ArmorDefect::BadEndMarker));
        }

        // Capture whether the parsed line had its own terminator
        // before `parse_armor_line` clears `line_buf`. A line without
        // an LF means we hit EOF mid-line — no END marker can follow,
        // so we MUST NOT expose decoded bytes from it (or from the
        // previous pending line which would otherwise be promoted).
        let line_had_lf = self.line_buf.ends_with(b"\n");

        if self.parse_armor_line()? {
            // END marker. Promote the pending body line (if any)
            // BEFORE the trailing-garbage check, so that on success
            // those bytes become available to the caller; on garbage
            // failure we discard everything.
            self.promote_pending_to_exposed();
            if let Err(e) = self.check_no_trailing_garbage() {
                self.discard_buffered_bytes();
                return Err(e);
            }
            return Ok(true);
        }

        if !line_had_lf {
            // Body-looking line that ended at EOF without a
            // terminator. `parse_armor_line` already promoted the
            // *previous* pending line into `byte_buf` and put this
            // line's bytes into pending — but no END can follow, so
            // fail closed: discard everything.
            self.discard_buffered_bytes();
            return Err(self.fail(ArmorDefect::BadEndMarker));
        }

        Ok(false)
    }

    fn check_no_trailing_garbage(&mut self) -> io::Result<()> {
        // `BufRead::read_line` already consumed the END line's
        // terminator (LF or CRLF). FORMAT.md §10 permits "one final
        // line ending" — that's the one we just consumed. Any
        // additional bytes (a second LF, a stray space, junk, etc.)
        // are rejected as TrailingGarbage.
        let mut probe = [0u8; 1];
        let read = read_up_to(&mut self.inner, &mut probe)?;
        if read != 0 {
            return Err(self.fail(ArmorDefect::TrailingGarbage));
        }
        Ok(())
    }
}

impl<R: Read> Read for ArmoredReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Per the Read trait convention, an empty output buffer is a
        // no-op — must not consume input, run detection, or surface
        // armor errors.
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(defect) = self.failed {
            return Err(armor_io_error(defect));
        }
        if self.is_armored.is_none() {
            self.detect_armor()?;
        }
        match self.is_armored {
            Some(false) => self.read_binary(buf),
            Some(true) => self.read_armored(buf),
            None => unreachable!("detect_armor sets is_armored"),
        }
    }
}

impl<R: Read> ArmoredReader<R> {
    fn read_binary(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Replay any peeked bytes first, then delegate to the inner
        // reader.
        if self.binary_prefix_pos < self.binary_prefix.len() {
            let remaining = &self.binary_prefix[self.binary_prefix_pos..];
            let take = remaining.len().min(buf.len());
            buf[..take].copy_from_slice(&remaining[..take]);
            self.binary_prefix_pos += take;
            return Ok(take);
        }
        self.inner.read(buf)
    }

    fn read_armored(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Loop until either the exposed buffer has bytes to serve or
        // we've reached the end. Lookahead-by-1 means each call to
        // `read_next_armor_line` may produce zero exposed bytes (when
        // there was no previous pending to promote — i.e., the very
        // first body-line read after armor mode is entered). We then
        // need a second iteration to read the *next* line, which
        // promotes the first body line into `byte_buf`.
        loop {
            if self.byte_start < self.byte_end {
                let available = &self.byte_buf[self.byte_start..self.byte_end];
                let take = available.len().min(buf.len());
                buf[..take].copy_from_slice(&available[..take]);
                self.byte_start += take;
                return Ok(take);
            }
            if self.found_end {
                return Ok(0);
            }
            // Refill: parse the next armor line. On success this may
            // promote the previously pending body line into the
            // exposed `byte_buf`. On END or EOF-before-END the loop
            // re-enters and returns either bytes or 0.
            let _ = self.read_next_armor_line()?;
        }
    }
}

// ─── helpers ────────────────────────────────────────────────────────────────

/// Reads up to `buf.len()` bytes, retrying on `Interrupted`. Returns
/// the actual number of bytes read. This helper keeps reading until
/// the buffer is full, EOF is reached (`Ok(0)`), or an error occurs.
fn read_up_to<R: BufRead>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Wraps an [`ArmorDefect`] in an `io::Error` with `InvalidData`. The
/// `From<io::Error> for CryptoError` impl downcasts the inner back
/// into the typed [`FormatDefect::MalformedArmor`] variant when the
/// error crosses the `Read`/`Write` trait boundary — same pattern
/// `StreamError` uses for the AEAD stream layer.
fn armor_io_error(defect: ArmorDefect) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, defect)
}

fn bytes_contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Returns `true` for bytes in the RFC 4648 standard Base64 alphabet
/// (A–Z, a–z, 0–9, `+`, `/`) plus the padding character `=`. Used to
/// reject any non-Base64 byte in a body line with the precise
/// `NonBase64Character` defect rather than letting `decode_slice`
/// fail with the less specific `Base64DecodeFailed`.
fn is_base64_body_byte(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=')
}

fn looks_like_end_marker(line: &[u8]) -> bool {
    let trimmed = line
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map_or(&[][..], |pos| &line[pos..]);
    trimmed.starts_with(b"-----END")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an armored string from `bytes` and return it along with
    /// the round-tripped result for assertions.
    fn round_trip(bytes: &[u8]) -> (String, Vec<u8>) {
        let mut out = Vec::new();
        {
            let mut writer = ArmoredWriter::wrap_output(&mut out, Format::AsciiArmor).unwrap();
            writer.write_all(bytes).unwrap();
            writer.finish().unwrap();
        }
        let s = String::from_utf8(out).expect("encoder emits ASCII");
        let mut decoded = Vec::new();
        ArmoredReader::new(s.as_bytes())
            .read_to_end(&mut decoded)
            .unwrap();
        (s, decoded)
    }

    #[test]
    fn round_trip_small() {
        let (_, decoded) = round_trip(b"hello world");
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn round_trip_at_line_boundary() {
        // 48 plaintext bytes = exactly one full armored line.
        let payload = vec![0xABu8; ARMORED_BYTES_PER_LINE];
        let (s, decoded) = round_trip(&payload);
        assert_eq!(decoded, payload);
        // BEGIN + LF + 64-char line + LF + END + LF.
        assert_eq!(s.lines().count(), 3);
    }

    #[test]
    fn round_trip_multiple_lines() {
        let payload: Vec<u8> = (0..200u32).map(|i| (i & 0xFF) as u8).collect();
        let (s, decoded) = round_trip(&payload);
        assert_eq!(decoded, payload);
        // 200 bytes → 268 chars Base64 → 4 full lines of 64 + 1 short
        // line of 12 + BEGIN/END = 7 lines total.
        assert!(s.lines().count() >= 5);
    }

    #[test]
    fn round_trip_at_chunk_boundary() {
        // Exactly one buffered chunk's worth of plaintext.
        let payload = vec![0x5Au8; BASE64_CHUNK_SIZE_BYTES];
        let (_, decoded) = round_trip(&payload);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn round_trip_larger_than_chunk() {
        // Force the encoder's "encode and flush" branch.
        let payload = vec![0xCDu8; BASE64_CHUNK_SIZE_BYTES + 100];
        let (_, decoded) = round_trip(&payload);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn round_trip_byte_by_byte_io() {
        // Force the encoder's "single byte per write" path and the
        // decoder's "single byte per read" path. Different I/O
        // patterns from the chunk-sized cases above; both must
        // produce identical results.
        let payload: Vec<u8> = (0..200u32).map(|i| (i & 0xFF) as u8).collect();
        let mut out = Vec::new();
        {
            let mut writer = ArmoredWriter::wrap_output(&mut out, Format::AsciiArmor).unwrap();
            for byte in &payload {
                writer.write_all(std::slice::from_ref(byte)).unwrap();
            }
            writer.finish().unwrap();
        }
        let mut reader = ArmoredReader::new(out.as_slice());
        let mut decoded = Vec::new();
        let mut buf = [0u8; 1];
        loop {
            match reader.read(&mut buf).unwrap() {
                0 => break,
                1 => decoded.push(buf[0]),
                n => panic!("unexpected read len {n}"),
            }
        }
        assert_eq!(decoded, payload);
    }

    #[test]
    fn round_trip_empty_payload() {
        let (s, decoded) = round_trip(&[]);
        assert_eq!(decoded, &[] as &[u8]);
        // Just BEGIN + END markers.
        assert!(s.contains(BEGIN_MARKER));
        assert!(s.contains(END_MARKER));
    }

    #[test]
    fn binary_passthrough_when_not_armored() {
        // A plain binary `.fcr`-shaped prefix MUST stream through
        // unchanged — no armor detected.
        let payload: Vec<u8> = (0..200u8).collect();
        let mut out = Vec::new();
        ArmoredReader::new(payload.as_slice())
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn binary_passthrough_short_input() {
        // Shorter than MIN_ARMOR_LEN — still passes through cleanly.
        let payload = b"FCR\0\x01\x45";
        let mut out = Vec::new();
        ArmoredReader::new(&payload[..])
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn decode_accepts_crlf_line_endings() {
        // Encode normally then rewrite all `\n` as `\r\n`. The §10
        // reader MUST accept both terminators inside the body.
        let (lf, _) = round_trip(b"hello world!");
        let crlf = lf.replace('\n', "\r\n");
        let mut decoded = Vec::new();
        ArmoredReader::new(crlf.as_bytes())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, b"hello world!");
    }

    /// Downcasts an `io::Error` from the armor reader back to its
    /// inner `ArmorDefect`. The reader builds errors via
    /// `io::Error::new(InvalidData, defect)` so this is the inverse
    /// — used by both rejection-test helpers below.
    fn defect_of(err: io::Error) -> ArmorDefect {
        err.get_ref()
            .and_then(|inner| inner.downcast_ref::<ArmorDefect>())
            .copied()
            .unwrap_or_else(|| panic!("expected ArmorDefect inner, got {err:?}"))
    }

    /// Asserts that `decode(input)` fires the expected `ArmorDefect`.
    /// Does NOT verify whether bytes were emitted before the error —
    /// use [`assert_decode_rejects_without_output`] for tests
    /// claiming strict "no decoded bytes reach the caller" behavior.
    fn assert_decode_rejects(input: &[u8], expected: ArmorDefect) {
        let mut sink = Vec::new();
        let err = ArmoredReader::new(input)
            .read_to_end(&mut sink)
            .unwrap_err();
        let defect = defect_of(err);
        assert_eq!(defect, expected, "wrong defect class");
    }

    /// Stricter variant of [`assert_decode_rejects`] that ALSO
    /// asserts the decoder emitted zero bytes before the error. Use
    /// this for tests whose semantics require lookahead-by-1 fail-
    /// closed behavior — i.e. inputs where no valid body line could
    /// have been confirmed by a successfully parsed following line
    /// before the error fired. Do NOT use for multi-line malformed
    /// inputs whose earlier body lines may legitimately have been
    /// promoted-and-served before the later error: lookahead-by-1
    /// only protects the *most recent* body line, not the entire
    /// block (see `discard_buffered_bytes` doc).
    fn assert_decode_rejects_without_output(input: &[u8], expected: ArmorDefect) {
        let mut sink = Vec::new();
        let err = ArmoredReader::new(input)
            .read_to_end(&mut sink)
            .unwrap_err();
        assert!(
            sink.is_empty(),
            "decoder emitted {} byte(s) before returning {expected:?}",
            sink.len(),
        );
        let defect = defect_of(err);
        assert_eq!(defect, expected, "wrong defect class");
    }

    #[test]
    fn non_ferrocrypt_armor_falls_through_as_binary() {
        // A `-----BEGIN AGE ENCRYPTED FILE-----` prefix doesn't
        // match our BEGIN marker. Detection sets is_armored = false
        // and the bytes stream through as binary; the downstream
        // `.fcr` parser is responsible for rejecting them as
        // malformed at its own layer. This is intentional — the
        // armor reader's only job is to recognise OUR armor.
        let payload = b"-----BEGIN AGE ENCRYPTED FILE-----\nXXXX\n";
        let mut out = Vec::new();
        ArmoredReader::new(&payload[..])
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn decode_rejects_bad_begin_marker_terminator() {
        // Right marker, wrong terminator (a space instead of LF/CRLF).
        let mut bad = BEGIN_MARKER.as_bytes().to_vec();
        bad.push(b' ');
        bad.extend_from_slice(b"AAAA\n");
        bad.extend_from_slice(END_MARKER.as_bytes());
        bad.push(b'\n');
        assert_decode_rejects(&bad, ArmorDefect::BadBeginMarker);
    }

    #[test]
    fn decode_rejects_missing_end_marker() {
        let payload = vec![0xAAu8; 10];
        let (s, _) = round_trip(&payload);
        // Strip the END marker and its line terminator.
        let truncated = s.split(END_MARKER).next().unwrap().to_owned();
        assert_decode_rejects(truncated.as_bytes(), ArmorDefect::BadEndMarker);
    }

    #[test]
    fn decode_rejects_blank_line_in_body() {
        let payload: Vec<u8> = (0..200u32).map(|i| (i & 0xFF) as u8).collect();
        let (s, _) = round_trip(&payload);
        // Inject a blank line after the first body line.
        let mut lines: Vec<&str> = s.split('\n').collect();
        lines.insert(2, "");
        let bad = lines.join("\n");
        assert_decode_rejects(bad.as_bytes(), ArmorDefect::NotWrappedAt64Chars);
    }

    #[test]
    fn decode_rejects_short_line_in_middle() {
        // Two short lines back to back: the first short line is
        // accepted (treated as the final body line); the second
        // armor body line after it triggers ShortLineInMiddle.
        let mut bad = String::new();
        bad.push_str(BEGIN_MARKER);
        bad.push('\n');
        bad.push_str("AAAA\n"); // 4-char short line
        bad.push_str("AAAA\n"); // another short line — illegal
        bad.push_str(END_MARKER);
        bad.push('\n');
        assert_decode_rejects(bad.as_bytes(), ArmorDefect::ShortLineInMiddle);
    }

    #[test]
    fn decode_rejects_line_over_64_chars() {
        let mut bad = String::new();
        bad.push_str(BEGIN_MARKER);
        bad.push('\n');
        // 68-char line — exceeds the 64-char body limit.
        bad.push_str(&"A".repeat(68));
        bad.push('\n');
        bad.push_str(END_MARKER);
        bad.push('\n');
        assert_decode_rejects(bad.as_bytes(), ArmorDefect::NotWrappedAt64Chars);
    }

    #[test]
    fn decode_rejects_over_64_non_multiple_of_4() {
        // 65-char line: both "longer than 64" and "not a multiple of
        // 4" are true. The arm order in `parse_armor_line` puts the
        // length check first because the user clearly intended a body
        // line, not a final short line — so the diagnostic is
        // NotWrappedAt64Chars, not NonCanonicalBase64Padding.
        let mut bad = String::new();
        bad.push_str(BEGIN_MARKER);
        bad.push('\n');
        bad.push_str(&"A".repeat(65));
        bad.push('\n');
        bad.push_str(END_MARKER);
        bad.push('\n');
        assert_decode_rejects(bad.as_bytes(), ArmorDefect::NotWrappedAt64Chars);
    }

    #[test]
    fn decode_rejects_non_canonical_padding() {
        // 5-char short line — not a multiple of 4, so the Base64
        // padding cannot be canonical.
        let mut bad = String::new();
        bad.push_str(BEGIN_MARKER);
        bad.push('\n');
        bad.push_str("AAAAA\n");
        bad.push_str(END_MARKER);
        bad.push('\n');
        assert_decode_rejects(bad.as_bytes(), ArmorDefect::NonCanonicalBase64Padding);
    }

    #[test]
    fn decode_rejects_bare_cr_in_line() {
        // Build a body with a bare `\r` in the middle of a line.
        let mut bad = Vec::new();
        bad.extend_from_slice(BEGIN_MARKER.as_bytes());
        bad.push(b'\n');
        bad.extend_from_slice(b"AAAA\rAAAA\n");
        bad.extend_from_slice(END_MARKER.as_bytes());
        bad.push(b'\n');
        assert_decode_rejects(&bad, ArmorDefect::LineContainsCr);
    }

    #[test]
    fn decode_rejects_trailing_garbage() {
        let payload = vec![0u8; 10];
        let (s, _) = round_trip(&payload);
        let mut bad = s.into_bytes();
        bad.extend_from_slice(b"trailing junk\n");
        assert_decode_rejects(&bad, ArmorDefect::TrailingGarbage);
    }

    #[test]
    fn decode_accepts_canonical_single_lf_after_end() {
        // FORMAT.md §10 permits "one final line ending" after END.
        // The encoder always emits exactly one LF after END_MARKER;
        // round_trip uses that output, so this asserts the canonical
        // shape decodes cleanly.
        let payload = b"some bytes";
        let (s, _) = round_trip(payload);
        assert!(s.ends_with(&format!("{END_MARKER}\n")));
        let mut decoded = Vec::new();
        ArmoredReader::new(s.as_bytes())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn decode_accepts_no_trailing_terminator_after_end() {
        // The END line itself need not end with a terminator; a file
        // that ends exactly at `-----END FERROCRYPT...-----` is
        // canonical.
        let payload = b"some bytes";
        let (s, _) = round_trip(payload);
        let trimmed = s.trim_end_matches('\n');
        let mut decoded = Vec::new();
        ArmoredReader::new(trimmed.as_bytes())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn decode_rejects_double_line_ending_after_end() {
        // The END line's own terminator already consumes the "one
        // final line ending" allowance. A second terminator (an
        // empty trailing line) is TrailingGarbage.
        let payload = b"some bytes";
        let (s, _) = round_trip(payload);
        let mut bad = s.into_bytes();
        bad.push(b'\n');
        assert_decode_rejects(&bad, ArmorDefect::TrailingGarbage);
    }

    #[test]
    fn decode_rejects_blank_body_line_via_detect_armor_leftover() {
        // `BEGIN\n\n + body + \n + END + \n`: detect_armor's leftover
        // is `\n` (the second LF). Without the early-parse branch in
        // `read_next_armor_line`, the leftover gets merged with the
        // body line via `read_until`, producing `"\nAAAA"` and
        // surfacing as `NonCanonicalBase64Padding` instead of the
        // precise `NotWrappedAt64Chars` (blank body line) class.
        let mut bad = BEGIN_MARKER.as_bytes().to_vec();
        bad.push(b'\n');
        bad.push(b'\n'); // leftover for detect_armor
        bad.extend_from_slice(b"AAAA\n");
        bad.extend_from_slice(END_MARKER.as_bytes());
        bad.push(b'\n');
        assert_decode_rejects(&bad, ArmorDefect::NotWrappedAt64Chars);
    }

    #[test]
    fn decode_rejects_short_body_line_via_detect_armor_leftover() {
        // `BEGIN_MARKER\nX` — leftover `"X"` is a 1-char body line
        // with non-canonical Base64 padding (1 % 4 != 0). Same fix
        // path as the test above, different specific defect class.
        let mut bad = BEGIN_MARKER.as_bytes().to_vec();
        bad.push(b'\n');
        bad.push(b'X');
        assert_decode_rejects(&bad, ArmorDefect::NonCanonicalBase64Padding);
    }

    #[test]
    fn decode_rejects_invalid_utf8_in_body() {
        // A body byte outside ASCII (and not a valid UTF-8 start
        // byte) MUST surface as the typed `InvalidUtf8` defect, not
        // as std's generic `InvalidData("stream did not contain
        // valid UTF-8")` swallowed by `CryptoError::Io(_)`. 0xFF is
        // never valid in any UTF-8 sequence.
        let mut bad = Vec::new();
        bad.extend_from_slice(BEGIN_MARKER.as_bytes());
        bad.push(b'\n');
        bad.push(b'A');
        bad.push(0xFF); // invalid UTF-8 continuation/start byte
        bad.push(b'A');
        bad.push(b'\n');
        bad.extend_from_slice(END_MARKER.as_bytes());
        bad.push(b'\n');
        assert_decode_rejects(&bad, ArmorDefect::InvalidUtf8);
    }

    #[test]
    fn decode_rejects_unbounded_line_via_max_line_cap() {
        // Memory-DoS guard: an attacker that satisfies the BEGIN
        // marker can otherwise stream an arbitrarily long line
        // without an LF, growing `line_buf` until OOM. The
        // `MAX_LINE_BYTES` cap on `read_until` truncates at 128 bytes
        // and lets `parse_armor_line` reject as `NotWrappedAt64Chars`.
        // 10 KiB is a token over-length payload; the protection is
        // independent of the actual size.
        let mut bad = String::new();
        bad.push_str(BEGIN_MARKER);
        bad.push('\n');
        bad.push_str(&"A".repeat(10_000));
        // No END marker — but the cap kicks in first.
        assert_decode_rejects(bad.as_bytes(), ArmorDefect::NotWrappedAt64Chars);
    }

    #[test]
    fn decode_retries_after_parse_error_return_same_defect() {
        // Once an armor parse error fires, the reader is poisoned and
        // later reads return the same typed defect without consuming
        // or appending more data. This keeps the per-line cap useful
        // even if a caller incorrectly retries after an error.
        let mut bad = String::new();
        bad.push_str(BEGIN_MARKER);
        bad.push('\n');
        bad.push_str(&"A".repeat(10_000));

        let mut reader = ArmoredReader::new(bad.as_bytes());
        let mut out = [0u8; 16];
        let first = reader.read(&mut out).unwrap_err();
        let second = reader.read(&mut out).unwrap_err();
        assert_eq!(defect_of(first), ArmorDefect::NotWrappedAt64Chars);
        assert_eq!(defect_of(second), ArmorDefect::NotWrappedAt64Chars);
    }

    #[test]
    fn decode_rejects_body_after_padded_line() {
        // A 64-char Base64 line ending in `=` is end-of-stream by
        // the canonical Base64 spec. Any further body line is a
        // non-canonical concatenation and must be rejected as
        // `ShortLineInMiddle` (the post-final-body rule).
        let mut bad = String::new();
        bad.push_str(BEGIN_MARKER);
        bad.push('\n');
        // 62 'A's + "==" = 64 chars, valid Base64 with padding,
        // decodes to 46 bytes.
        bad.push_str(&"A".repeat(62));
        bad.push_str("==");
        bad.push('\n');
        // Extra body line after a padded 64-char line — illegal.
        bad.push_str("AAAA");
        bad.push('\n');
        bad.push_str(END_MARKER);
        bad.push('\n');
        assert_decode_rejects(bad.as_bytes(), ArmorDefect::ShortLineInMiddle);
    }

    #[test]
    fn decode_rejects_truncated_armor_lf() {
        // `BEGIN_MARKER + LF` alone (42 bytes). Pre-fix this slipped
        // below MIN_ARMOR_LEN and silently passed through as binary,
        // diverging from the CRLF case which fired BadEndMarker.
        // Post-fix both terminator styles are classified as armor.
        let mut bad = BEGIN_MARKER.as_bytes().to_vec();
        bad.push(b'\n');
        assert_decode_rejects(&bad, ArmorDefect::BadEndMarker);
    }

    #[test]
    fn decode_rejects_truncated_armor_marker_only() {
        // BEGIN_MARKER alone — no terminator at all. The marker
        // matches but the terminator validation fails.
        let bad = BEGIN_MARKER.as_bytes().to_vec();
        assert_decode_rejects(&bad, ArmorDefect::BadBeginMarker);
    }

    #[test]
    fn decode_rejects_terminated_body_at_eof_without_end_marker() {
        // `BEGIN\nAAAA\n` — body line WITH terminator, but no END
        // marker follows. Pre-strong-fix this exposed the 3 decoded
        // bytes from "AAAA" before BadEndMarker fired on the next
        // read (the line had its `\n`, so the minimal `line_had_lf`
        // check didn't fire). With lookahead-by-1, the bytes sit in
        // `pending_buf` and only get promoted to `byte_buf` once the
        // *next* line is parsed. EOF before END means pending is
        // never promoted, and `BadEndMarker` fires from the EOF
        // check on the second `read_next_armor_line` call — BEFORE
        // any decoded bytes reach the caller.
        let mut bad = String::new();
        bad.push_str(BEGIN_MARKER);
        bad.push('\n');
        bad.push_str("AAAA\n");
        // No END marker.
        assert_decode_rejects_without_output(bad.as_bytes(), ArmorDefect::BadEndMarker);
    }

    #[test]
    fn decode_rejects_body_at_eof_without_terminator() {
        // A body line that reaches EOF without an LF cannot be
        // followed by an END marker. Fail closed with `BadEndMarker`
        // before exposing the decoded bytes to the caller.
        let mut bad = String::new();
        bad.push_str(BEGIN_MARKER);
        bad.push('\n');
        bad.push_str("AAAA"); // 4-char body line, no terminator, no END
        assert_decode_rejects_without_output(bad.as_bytes(), ArmorDefect::BadEndMarker);
    }

    #[test]
    fn read_with_empty_buf_is_no_op() {
        // Per the Read trait convention, an empty output buffer is a
        // no-op — must not consume input, run detection, or surface
        // armor errors. This must hold even for malformed
        // input that would otherwise fire BadBeginMarker.
        let mut bad = BEGIN_MARKER.as_bytes().to_vec();
        bad.push(b' '); // wrong terminator — would fire BadBeginMarker on a real read
        let mut reader = ArmoredReader::new(bad.as_slice());
        let mut empty: [u8; 0] = [];
        // Empty-buf read returns 0 with NO detection error.
        assert_eq!(reader.read(&mut empty).unwrap(), 0);
        // Now a real read DOES surface the typed defect — confirms
        // detection wasn't already triggered by the empty read.
        let mut out = [0u8; 8];
        let err = reader.read(&mut out).unwrap_err();
        assert_eq!(defect_of(err), ArmorDefect::BadBeginMarker);
    }

    #[test]
    fn decode_rejects_non_base64_character() {
        // `?` is not in the Base64 alphabet. The explicit alphabet
        // check fires `NonBase64Character` before `decode_slice` can
        // surface the less precise `Base64DecodeFailed`.
        let mut bad = String::new();
        bad.push_str(BEGIN_MARKER);
        bad.push('\n');
        bad.push_str(&"A".repeat(63));
        bad.push('?'); // 64-char line, last char invalid
        bad.push('\n');
        bad.push_str(END_MARKER);
        bad.push('\n');
        assert_decode_rejects(bad.as_bytes(), ArmorDefect::NonBase64Character);
    }

    #[test]
    fn decode_rejects_end_marker_with_trailing_whitespace() {
        let mut bad = String::new();
        bad.push_str(BEGIN_MARKER);
        bad.push('\n');
        bad.push_str(&"A".repeat(64));
        bad.push('\n');
        bad.push_str(END_MARKER);
        bad.push(' '); // trailing space — not part of the marker
        bad.push('\n');
        assert_decode_rejects(bad.as_bytes(), ArmorDefect::BadEndMarker);
    }

    #[test]
    fn decode_rejects_end_marker_with_leading_whitespace() {
        let mut bad = String::new();
        bad.push_str(BEGIN_MARKER);
        bad.push('\n');
        bad.push_str(&"A".repeat(64));
        bad.push('\n');
        bad.push(' '); // leading space
        bad.push_str(END_MARKER);
        bad.push('\n');
        assert_decode_rejects(bad.as_bytes(), ArmorDefect::BadEndMarker);
    }

    #[test]
    fn decode_rejects_mistyped_end_marker_as_bad_end_marker() {
        let mut bad = String::new();
        bad.push_str(BEGIN_MARKER);
        bad.push('\n');
        bad.push_str("AAAA\n");
        bad.push_str("-----END FERROCRYPT ENCRYPTED FILE----X\n");
        assert_decode_rejects(bad.as_bytes(), ArmorDefect::BadEndMarker);
    }

    #[test]
    fn decode_rejects_end_marker_with_bare_cr_as_bad_end_marker() {
        let mut bad = String::new();
        bad.push_str(BEGIN_MARKER);
        bad.push('\n');
        bad.push_str("AAAA\n");
        bad.push_str(END_MARKER);
        bad.push('\r');
        assert_decode_rejects(bad.as_bytes(), ArmorDefect::BadEndMarker);
    }

    #[test]
    fn decode_rejects_split_multibyte_body_char_stably() {
        // LF detection consumes one raw byte after BEGIN. If that byte
        // is the first byte of a valid multi-byte UTF-8 sequence, the
        // byte-buffered line path should wait for the rest of the line
        // before validating UTF-8. The complete line is valid UTF-8
        // but not Base64, so this must not be `InvalidUtf8`.
        let mut bad = Vec::new();
        bad.extend_from_slice(BEGIN_MARKER.as_bytes());
        bad.push(b'\n');
        bad.extend_from_slice("éAAA".as_bytes());
        bad.push(b'\n');
        bad.extend_from_slice(END_MARKER.as_bytes());
        bad.push(b'\n');
        assert_decode_rejects(&bad, ArmorDefect::NonCanonicalBase64Padding);
    }
}
