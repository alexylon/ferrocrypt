#![no_main]

//! Fuzzes `validate_archive_path` — the tar-entry path guard that
//! rejects `..`, `/`, drive prefixes, and leading `.` components before
//! any filesystem work happens.
//!
//! On Unix, the real extraction path builds `Path` values directly from
//! the raw bytes of tar entries (via `OsStr::from_bytes`), so the
//! target must also accept arbitrary byte sequences to match the
//! actual attack surface. On non-Unix, `Path` requires valid UTF-16
//! (which our tar reader already enforces), so the non-UTF-8 branch
//! is a no-op — kept only so `cargo check` builds the target on those
//! targets.

use std::path::Path;

use ferrocrypt::fuzz_exports::validate_archive_path;
use libfuzzer_sys::fuzz_target;

#[cfg(unix)]
fn to_path(data: &[u8]) -> &Path {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    Path::new(OsStr::from_bytes(data))
}

#[cfg(not(unix))]
fn to_path(data: &[u8]) -> &Path {
    match std::str::from_utf8(data) {
        Ok(s) => Path::new(s),
        Err(_) => Path::new(""),
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = validate_archive_path(to_path(data));
});
