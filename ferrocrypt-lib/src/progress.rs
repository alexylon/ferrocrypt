//! Byte progress of the payload phase. [`ByteProgress`] turns a running count
//! of `.fcr` bytes into [`ProgressEvent::BytesProcessed`] events, one per
//! whole percent; [`ProgressWriter`] and [`ProgressReader`] feed it from the
//! file being written or read.

use std::io::{self, Read, Write};

use crate::ProgressEvent;

/// The whole percent of `total` that `done` represents, rounded down, so it
/// reaches 100 only once `done` reaches `total`. A zero `total` counts as
/// complete.
pub(crate) fn percent(done: u64, total: u64) -> u8 {
    if total == 0 {
        return 100;
    }

    let share = u128::from(done.min(total)) * 100 / u128::from(total);
    u8::try_from(share).unwrap_or(100)
}

/// Counts bytes against a fixed total and reports each whole percent reached,
/// so an operation emits at most 101 events whatever its size.
pub(crate) struct ByteProgress<'a> {
    done: u64,
    total: u64,
    reported: u8,
    on_event: &'a dyn Fn(&ProgressEvent),
}

impl<'a> ByteProgress<'a> {
    /// Starts at `done` bytes of `total` and reports that point. A zero
    /// `total` means the size is unknown: nothing is reported, now or later.
    pub(crate) fn start(done: u64, total: u64, on_event: &'a dyn Fn(&ProgressEvent)) -> Self {
        let done = done.min(total);
        let progress = Self {
            done,
            total,
            reported: percent(done, total),
            on_event,
        };
        progress.report();

        progress
    }

    /// Adds `bytes` to the count, never past the total, and reports a newly
    /// reached whole percent.
    fn advance(&mut self, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        self.done = self.done.saturating_add(bytes).min(self.total);

        let reached = percent(self.done, self.total);
        if reached > self.reported {
            self.reported = reached;
            self.report();
        }
    }

    fn report(&self) {
        if self.total > 0 {
            (self.on_event)(&ProgressEvent::BytesProcessed {
                done: self.done,
                total: self.total,
            });
        }
    }
}

/// A writer that counts the bytes `inner` accepts.
pub(crate) struct ProgressWriter<'a, W> {
    inner: W,
    progress: ByteProgress<'a>,
}

impl<'a, W: Write> ProgressWriter<'a, W> {
    pub(crate) fn new(inner: W, progress: ByteProgress<'a>) -> Self {
        Self { inner, progress }
    }

    pub(crate) fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for ProgressWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.progress.advance(written);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A reader that counts the bytes `inner` returns.
pub(crate) struct ProgressReader<'a, R> {
    inner: R,
    progress: ByteProgress<'a>,
}

impl<'a, R: Read> ProgressReader<'a, R> {
    pub(crate) fn new(inner: R, progress: ByteProgress<'a>) -> Self {
        Self { inner, progress }
    }
}

impl<R: Read> Read for ProgressReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.progress.advance(read);
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// Runs `run` with a callback and returns the `(done, total)` of every
    /// event it receives.
    fn events(run: impl FnOnce(&dyn Fn(&ProgressEvent))) -> Vec<(u64, u64)> {
        let seen = RefCell::new(Vec::new());
        run(&|event| match event {
            ProgressEvent::BytesProcessed { done, total } => {
                seen.borrow_mut().push((*done, *total))
            }
            other => panic!("unexpected event {other:?}"),
        });
        seen.into_inner()
    }

    #[test]
    fn percent_rounds_down_and_reaches_100_only_at_the_total() {
        assert_eq!(percent(0, 3), 0);
        assert_eq!(percent(2, 3), 66);
        assert_eq!(percent(u64::MAX - 1, u64::MAX), 99);
        assert_eq!(percent(u64::MAX, u64::MAX), 100);
        assert_eq!(percent(7, 5), 100);
        assert_eq!(percent(0, 0), 100);
    }

    #[test]
    fn one_byte_at_a_time_reports_each_percent_once() {
        let seen = events(|on_event| {
            let mut progress = ByteProgress::start(0, 1000, on_event);
            for _ in 0..1000 {
                progress.advance(1);
            }
        });

        assert_eq!(seen.len(), 101);
        assert_eq!(seen.first(), Some(&(0, 1000)));
        assert_eq!(seen.last(), Some(&(1000, 1000)));
        for (i, (done, total)) in seen.iter().enumerate() {
            assert_eq!(*total, 1000);
            assert_eq!(usize::from(percent(*done, *total)), i);
        }
    }

    #[test]
    fn large_steps_skip_percents_and_stop_at_the_total() {
        let seen = events(|on_event| {
            let mut progress = ByteProgress::start(10, 100, on_event);
            progress.advance(5);
            progress.advance(0);
            progress.advance(60);
            progress.advance(usize::MAX);
            progress.advance(1);
        });

        assert_eq!(seen, [(10, 100), (15, 100), (75, 100), (100, 100)]);
    }

    #[test]
    fn a_start_past_the_total_reports_the_total() {
        let seen = events(|on_event| {
            ByteProgress::start(150, 100, on_event).advance(1);
        });

        assert_eq!(seen, [(100, 100)]);
    }

    #[test]
    fn an_unknown_total_reports_nothing() {
        let seen = events(|on_event| {
            let mut progress = ByteProgress::start(0, 0, on_event);
            progress.advance(10);
        });

        assert!(seen.is_empty());
    }

    #[test]
    fn the_adapters_count_what_passes_through() {
        let seen = events(|on_event| {
            let mut writer = ProgressWriter::new(Vec::new(), ByteProgress::start(0, 4, on_event));
            writer.write_all(b"ab").unwrap();
            writer.write_all(b"cd").unwrap();
            assert_eq!(writer.into_inner(), b"abcd");
        });
        assert_eq!(seen, [(0, 4), (2, 4), (4, 4)]);

        let seen = events(|on_event| {
            let mut reader = ProgressReader::new(&b"abcd"[..], ByteProgress::start(1, 5, on_event));
            let mut out = Vec::new();
            reader.read_to_end(&mut out).unwrap();
            assert_eq!(out, b"abcd");
        });
        assert_eq!(seen, [(1, 5), (5, 5)]);
    }
}
