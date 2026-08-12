//! Open-file-limit control for tests that need the archive code to run
//! out of descriptors.
//!
//! Linux and macOS only, matching the `rustix` dev-dependency that
//! provides the safe `setrlimit`. The limit is process-wide while a
//! guard is alive, so every test using this module relies on the
//! workspace convention of running with `--test-threads=1`.

use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
use std::fs::File;

/// Lowers the soft open-file limit and restores the saved value on
/// drop, so a panicking assertion still leaves later tests
/// unrestricted.
pub(crate) struct NofileLimit(Rlimit);

impl NofileLimit {
    /// Lowers the soft limit to `soft`, keeping the hard limit. A
    /// process already below `soft` keeps what it has: the value never
    /// rises, so a low hard limit cannot refuse the call.
    ///
    /// # Panics
    ///
    /// Panics if the soft limit cannot be lowered, because a test that
    /// silently kept an unrestricted process would pass without
    /// measuring anything.
    pub(crate) fn lower_to(soft: u64) -> Self {
        let saved = getrlimit(Resource::Nofile);
        let guard = Self(saved);
        setrlimit(
            Resource::Nofile,
            Rlimit {
                current: Some(saved.current.map_or(soft, |current| soft.min(current))),
                maximum: saved.maximum,
            },
        )
        .expect("lower the NOFILE soft limit");
        guard
    }
}

impl Drop for NofileLimit {
    fn drop(&mut self) {
        let _ = setrlimit(Resource::Nofile, self.0);
    }
}

/// Descriptors held open so the code under test runs with a known
/// number free. Dropping the value releases them and restores the
/// limit.
pub(crate) struct HeldDescriptors {
    _held: Vec<File>,
    _limit: NofileLimit,
}

impl HeldDescriptors {
    /// Holds descriptors until no more can be opened, then releases
    /// `free` of them, so the next `free` opens succeed and the one
    /// after that fails.
    ///
    /// The ceiling is raised toward the process's own soft limit until
    /// it leaves enough room for that margin: a process already using
    /// more descriptors than the first ceiling allows would otherwise
    /// hold none and measure an unrestricted run.
    ///
    /// # Panics
    ///
    /// Panics if no ceiling leaves the required margin.
    pub(crate) fn leaving(free: usize) -> Self {
        const MARGIN: usize = 8;
        for soft in [128u64, 512, 2048] {
            let limit = NofileLimit::lower_to(soft);
            let mut held = Vec::new();
            while let Ok(file) = File::open("/dev/null") {
                held.push(file);
            }
            if held.len() >= free + MARGIN {
                held.truncate(held.len() - free);
                return Self {
                    _held: held,
                    _limit: limit,
                };
            }
        }
        panic!("no open-file ceiling left room to hold {free} descriptors free");
    }
}
