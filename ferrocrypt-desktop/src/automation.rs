//! Development-only stand-in for the file dialogs, compiled with the `mcp`
//! feature.
//!
//! An agent drives the window through Slint's MCP server, which sees only the
//! Slint window. A native file dialog is a separate window the server cannot
//! reach, and on macOS and Windows it also blocks the event loop the server
//! answers from. So when [`DIALOG_ANSWER_VAR`] names a file, no dialog opens:
//! the path written in that file is taken as the choice, and the file is
//! taken away so that each answer serves one dialog. A missing or empty file
//! counts as a cancelled dialog.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use crate::AppWindow;

/// The environment variable that names the answer file.
pub(crate) const DIALOG_ANSWER_VAR: &str = "FERROCRYPT_DESKTOP_DIALOG_ANSWER";

/// Appended to the answer file's name while one answer is being read.
const TAKEN_SUFFIX: &str = ".taken";

#[cfg(not(debug_assertions))]
compile_error!(
    "The `mcp` feature lets any local process drive the window; build it without `--release`."
);

/// Answers a file dialog from the answer file, passing a chosen path to
/// `on_pick`, and returns `None`. Returns `on_pick` unused when
/// [`DIALOG_ANSWER_VAR`] is unset, so the caller opens the real dialog.
pub(crate) fn answer_dialog<F>(app: &AppWindow, on_pick: F) -> Option<F>
where
    F: FnOnce(&AppWindow, PathBuf),
{
    let Some(answer_file) = std::env::var_os(DIALOG_ANSWER_VAR) else {
        return Some(on_pick);
    };

    if let Some(path) = take_answer(answer_file) {
        on_pick(app, path);
    }

    None
}

/// Takes the answer out of `answer_file`; `None` means a cancelled dialog.
fn take_answer(answer_file: OsString) -> Option<PathBuf> {
    // A rename takes the answer in one step: an answer written at the same
    // time is either this one or left for the next dialog, never lost.
    let mut taken = answer_file.clone();
    taken.push(TAKEN_SUFFIX);
    if let Err(e) = std::fs::rename(&answer_file, &taken) {
        if e.kind() != io::ErrorKind::NotFound {
            eprintln!("{DIALOG_ANSWER_VAR}: cannot take the answer file: {e}");
        }
        return None;
    }

    let text = std::fs::read_to_string(&taken);
    // A leftover is harmless: the next answer is renamed over it.
    let _ = std::fs::remove_file(&taken);

    let text = match text {
        Ok(text) => text,
        Err(e) => {
            eprintln!("{DIALOG_ANSWER_VAR}: cannot read the answer file: {e}");
            return None;
        }
    };

    let path = text.trim_end_matches(['\n', '\r']);
    (!path.is_empty()).then(|| PathBuf::from(path))
}
