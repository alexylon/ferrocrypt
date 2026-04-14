mod cli;

use ferrocrypt::CryptoError;
use std::fmt;

/// Wrapper that forces `main`'s error output to use `Display` formatting.
///
/// Rust's stdlib `Termination` prints the error via `Debug`, which would
/// show `CryptoError`'s derived variant name and wrapper cruft (for
/// example `Io(Custom { kind: Other, error: "..." })`). Implementing
/// `Debug` manually to delegate to `Display` surfaces the short,
/// user-facing message the library already provides.
struct CliError(CryptoError);

impl fmt::Debug for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<CryptoError> for CliError {
    fn from(e: CryptoError) -> Self {
        Self(e)
    }
}

fn main() -> Result<(), CliError> {
    cli::run().map_err(CliError::from)
}
