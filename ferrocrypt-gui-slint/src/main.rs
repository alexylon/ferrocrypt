// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

slint::include_modules!();

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    detect_encryption_mode, generate_asymmetric_key_pair_with_progress,
    hybrid_encryption_with_progress, symmetric_encryption_with_progress, EncryptionMode,
};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// macOS: native NSOpenPanel with canChooseFiles + canChooseDirectories
// Single-click a folder selects it; double-click opens it.
// ---------------------------------------------------------------------------
#[cfg(target_os = "macos")]
fn pick_file_or_folder() -> Option<PathBuf> {
    use objc2::rc::Retained;
    use objc2::runtime::{AnyClass, AnyObject};
    use objc2::{msg_send, msg_send_id};

    unsafe {
        let cls = AnyClass::get("NSOpenPanel")?;
        let panel: Retained<AnyObject> = msg_send_id![cls, openPanel];

        let _: () = msg_send![&panel, setCanChooseFiles: true];
        let _: () = msg_send![&panel, setCanChooseDirectories: true];
        let _: () = msg_send![&panel, setAllowsMultipleSelection: false];

        let response: isize = msg_send![&panel, runModal];
        if response != 1 {
            return None;
        }

        let url: Option<Retained<AnyObject>> = msg_send_id![&panel, URL];
        let url = url?;
        let path: Option<Retained<AnyObject>> = msg_send_id![&url, path];
        let path = path?;
        let utf8: *const std::ffi::c_char = msg_send![&path, UTF8String];
        if utf8.is_null() {
            return None;
        }
        let s = std::ffi::CStr::from_ptr(utf8).to_str().ok()?;
        Some(PathBuf::from(s))
    }
}

// Non-macOS: plain file picker
#[cfg(not(target_os = "macos"))]
fn pick_file_or_folder() -> Option<PathBuf> {
    rfd::FileDialog::new().pick_file()
}

fn main() {
    let app = AppWindow::new().unwrap();

    app.set_combined_picker(cfg!(target_os = "macos"));

    // ── Select input file ───────────────────────────────────────────────
    // macOS: opens a combined file+folder picker (single-click folder = select it)
    // Other:  opens a plain file picker
    app.on_select_input_file({
        let weak = app.as_weak();
        move || {
            let Some(path) = pick_file_or_folder() else {
                return;
            };
            apply_input_path(&weak, path);
        }
    });

    // ── Select input folder ─────────────────────────────────────────────
    app.on_select_input_folder({
        let weak = app.as_weak();
        move || {
            let Some(path) = rfd::FileDialog::new().pick_folder() else {
                return;
            };
            apply_input_path(&weak, path);
        }
    });

    // ── Select key file ─────────────────────────────────────────────────
    app.on_select_key_file({
        let weak = app.as_weak();
        move || {
            let Some(path) = rfd::FileDialog::new()
                .add_filter("PEM files", &["pem"])
                .pick_file()
            else {
                return;
            };
            let Some(app) = weak.upgrade() else { return };
            app.set_keypath(path.to_string_lossy().to_string().into());
        }
    });

    // ── Select output directory ─────────────────────────────────────────
    app.on_select_output_dir({
        let weak = app.as_weak();
        move || {
            let Some(path) = rfd::FileDialog::new().pick_folder() else {
                return;
            };
            let Some(app) = weak.upgrade() else { return };
            app.set_outpath(path.to_string_lossy().to_string().into());
        }
    });

    // ── Start operation (threaded — crypto can take a while) ────────────
    app.on_start_operation({
        let weak = app.as_weak();
        move || {
            let Some(app) = weak.upgrade() else { return };

            let mode = app.get_mode();
            let inpath = app.get_inpath().to_string();
            let outpath = app.get_outpath().to_string();
            let password = app.get_password().to_string();
            let keypath = app.get_keypath().to_string();

            app.set_is_working(true);
            app.set_status_ok("".into());
            app.set_status_err("".into());

            let weak = weak.clone();
            std::thread::spawn(move || {
                let pwd = SecretString::from(password);

                let on_progress = {
                    let weak = weak.clone();
                    move |msg: &str| {
                        let msg = msg.to_string();
                        let weak = weak.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(app) = weak.upgrade() {
                                app.set_status_ok(msg.into());
                            }
                        });
                    }
                };

                let result = match mode {
                    0 | 1 => symmetric_encryption_with_progress(
                        &inpath, &outpath, &pwd, &on_progress,
                    ),
                    2 | 3 => hybrid_encryption_with_progress(
                        &inpath, &outpath, &keypath, &pwd, &on_progress,
                    ),
                    4 => generate_asymmetric_key_pair_with_progress(
                        4096, &pwd, &outpath, &on_progress,
                    ),
                    _ => unreachable!(),
                };

                let _ = slint::invoke_from_event_loop(move || {
                    let Some(app) = weak.upgrade() else { return };
                    app.set_is_working(false);

                    match result {
                        Ok(msg) => {
                            clear_form(&app);
                            app.set_status_ok(msg.into());
                        }
                        Err(e) => {
                            app.set_status_ok("".into());
                            app.set_status_err(e.to_string().into());
                        }
                    }
                });
            });
        }
    });

    // ── Clear form ──────────────────────────────────────────────────────
    app.on_clear_form({
        let weak = app.as_weak();
        move || {
            let Some(app) = weak.upgrade() else { return };
            clear_form(&app);
            app.set_status_ok("Ready".into());
        }
    });

    app.run().unwrap();
}

/// Apply a selected input path to the UI (shared by file and folder selection).
fn apply_input_path(weak: &slint::Weak<AppWindow>, path: PathBuf) {
    let selected_path = path.to_string_lossy().to_string();
    let dir_path = if path.is_dir() {
        path.parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| selected_path.clone())
    } else {
        path.parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    };
    let detected_mode = detect_mode_from_path(&selected_path);

    let Some(app) = weak.upgrade() else { return };
    app.set_inpath(selected_path.into());
    app.set_outpath(dir_path.into());
    if let Some(m) = detected_mode {
        app.set_mode(m);
    }
    app.set_status_ok("Ready".into());
    app.set_status_err("".into());
}

/// Auto-detect encryption mode from a `.fcr` file.
fn detect_mode_from_path(path: &str) -> Option<i32> {
    if !path.ends_with(".fcr") {
        return None;
    }
    match detect_encryption_mode(path) {
        Some(EncryptionMode::Symmetric) => Some(1), // SD
        Some(EncryptionMode::Hybrid) => Some(3),    // HD
        None => None,
    }
}

/// Reset all form fields to defaults.
fn clear_form(app: &AppWindow) {
    app.set_inpath("".into());
    app.set_outpath("".into());
    app.set_password("".into());
    app.set_password_repeated("".into());
    app.set_keypath("".into());
    app.set_mode(0);
    app.set_hide_password(true);
    app.set_status_ok("".into());
    app.set_status_err("".into());
}
