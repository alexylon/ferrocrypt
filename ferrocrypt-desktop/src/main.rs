// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

slint::include_modules!();

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    EncryptionMode, default_encrypted_filename, detect_encryption_mode,
    generate_asymmetric_key_pair_with_progress, hybrid_encryption_with_progress,
    symmetric_encryption_with_progress,
};
use std::path::{Path, PathBuf};

const ELIDE_INPUT: usize = 42;
const ELIDE_OUTPUT: usize = ELIDE_INPUT - 1;
const RSA_KEY_BITS: u32 = 4096;

// ---------------------------------------------------------------------------
// macOS: native NSOpenPanel with canChooseFiles + canChooseDirectories.
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
        let path: Option<Retained<AnyObject>> = msg_send_id![&url?, path];
        let utf8: *const std::ffi::c_char = msg_send![&path?, UTF8String];
        if utf8.is_null() {
            return None;
        }
        Some(PathBuf::from(std::ffi::CStr::from_ptr(utf8).to_str().ok()?))
    }
}

#[cfg(not(target_os = "macos"))]
fn pick_file_or_folder() -> Option<PathBuf> {
    rfd::FileDialog::new().pick_file()
}

fn main() {
    let app = AppWindow::new().unwrap();

    app.set_combined_picker(cfg!(target_os = "macos"));

    app.on_mode_changed({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                check_conflicts(&app);
            }
        }
    });

    app.on_select_input_file({
        let weak = app.as_weak();
        move || {
            if let Some(path) = pick_file_or_folder() {
                apply_input_path(&weak, path);
            }
        }
    });

    app.on_select_input_folder({
        let weak = app.as_weak();
        move || {
            if let Some(path) = rfd::FileDialog::new().pick_folder() {
                apply_input_path(&weak, path);
            }
        }
    });

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
            let key_path = path_to_string(&path);
            app.set_keypath_display(elide_left(&key_path, ELIDE_INPUT).into());
            app.set_keypath(key_path.into());
            check_conflicts(&app);
        }
    });

    app.on_select_output_dir({
        let weak = app.as_weak();
        move || {
            let Some(path) = rfd::FileDialog::new().pick_folder() else {
                return;
            };
            let Some(app) = weak.upgrade() else { return };
            set_outpath(&app, &path_to_string(&path));
        }
    });

    app.on_select_output_file({
        let weak = app.as_weak();
        move || {
            let Some(app) = weak.upgrade() else { return };
            let mut dialog = rfd::FileDialog::new();

            let inpath = app.get_inpath().to_string();
            if let Ok(name) = default_encrypted_filename(&inpath) {
                dialog = dialog.set_file_name(&name);
            }

            let outpath = app.get_outpath().to_string();
            if let Some(parent) = parent_dir(&outpath) {
                dialog = dialog.set_directory(parent);
            }

            if let Some(path) = dialog.save_file() {
                set_outpath(&app, &path_to_string(&path));
            }
        }
    });

    app.on_start_operation({
        let weak = app.as_weak();
        move || {
            let Some(app) = weak.upgrade() else { return };

            let mode = app.get_mode();
            let inpath = app.get_inpath().to_string();
            let outpath = app.get_outpath().to_string();
            let password = app.get_password().to_string();
            let keypath = app.get_keypath().to_string();

            let is_encrypt = mode == 0 || mode == 2;
            let (output_dir, output_file) = if is_encrypt {
                (parent_dir(&outpath).unwrap_or_default(), Some(outpath))
            } else {
                (outpath, None)
            };

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
                        &inpath,
                        &output_dir,
                        &pwd,
                        output_file.as_deref(),
                        &on_progress,
                    ),
                    2 | 3 => hybrid_encryption_with_progress(
                        &inpath,
                        &output_dir,
                        &keypath,
                        &pwd,
                        output_file.as_deref(),
                        &on_progress,
                    ),
                    4 => generate_asymmetric_key_pair_with_progress(
                        RSA_KEY_BITS,
                        &pwd,
                        &output_dir,
                        &on_progress,
                    ),
                    _ => unreachable!(),
                };

                let _ = slint::invoke_from_event_loop(move || {
                    let Some(app) = weak.upgrade() else { return };
                    app.set_is_working(false);

                    match result {
                        Ok(msg) => {
                            clear_form(&app);
                            app.set_status_ok(elide_result_path(&msg).into());
                        }
                        Err(e) => {
                            app.set_status_ok("".into());
                            app.set_status_err(elide_result_path(&e.to_string()).into());
                        }
                    }
                });
            });
        }
    });

    app.on_clear_form({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                clear_form(&app);
            }
        }
    });

    app.run().unwrap();
}

fn apply_input_path(weak: &slint::Weak<AppWindow>, path: PathBuf) {
    let selected = path_to_string(&path);
    let dir = path
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| {
            if path.is_dir() {
                selected.clone()
            } else {
                String::new()
            }
        });

    let detected_mode = detect_mode_from_path(&selected);
    let is_decrypt = matches!(detected_mode, Some(1) | Some(3));

    let Some(app) = weak.upgrade() else { return };
    app.set_inpath_display(elide_left(&selected, ELIDE_INPUT).into());
    app.set_inpath(selected.clone().into());
    if let Some(m) = detected_mode {
        app.set_mode(m);
    }

    if is_decrypt || app.get_mode() == 4 {
        set_outpath(&app, &dir);
    } else if let Ok(filename) = default_encrypted_filename(&selected) {
        set_outpath(&app, &path_to_string(&Path::new(&dir).join(filename)));
    }

    app.set_status_ok("Ready".into());
    app.set_status_err("".into());
    check_conflicts(&app);
}

fn set_outpath(app: &AppWindow, path: &str) {
    app.set_outpath_display(elide_left(path, ELIDE_OUTPUT).into());
    app.set_outpath(path.into());
    check_conflicts(app);
}

fn check_conflicts(app: &AppWindow) {
    let mode = app.get_mode();
    let outpath = app.get_outpath().to_string();

    let warning = match mode {
        0 | 2 if !outpath.is_empty() && Path::new(&outpath).exists() => {
            format!("Already exists: {}", elide_left(&outpath, ELIDE_OUTPUT))
        }
        4 if !outpath.is_empty() => {
            let dir = Path::new(&outpath);
            let priv_exists = dir
                .join(format!("rsa-{RSA_KEY_BITS}-priv-key.pem"))
                .exists();
            let pub_exists = dir.join(format!("rsa-{RSA_KEY_BITS}-pub-key.pem")).exists();
            match (priv_exists, pub_exists) {
                (true, true) => "Key pair already exists in output directory".into(),
                (true, false) => "Private key already exists in output directory".into(),
                (false, true) => "Public key already exists in output directory".into(),
                _ => String::new(),
            }
        }
        _ => String::new(),
    };

    app.set_conflict_warning(warning.into());
}

fn clear_form(app: &AppWindow) {
    let empty = slint::SharedString::default();
    app.set_inpath(empty.clone());
    app.set_inpath_display(empty.clone());
    app.set_outpath(empty.clone());
    app.set_outpath_display(empty.clone());
    app.set_password(empty.clone());
    app.set_password_repeated(empty.clone());
    app.set_keypath(empty.clone());
    app.set_keypath_display(empty.clone());
    app.set_conflict_warning(empty.clone());
    app.set_status_ok(empty.clone());
    app.set_status_err(empty);
    app.set_mode(0);
    app.set_hide_password(true);
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn parent_dir(path: &str) -> Option<String> {
    Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
}

/// Left-elides a path, keeping the rightmost `max` characters visible.
/// Uses char boundaries to avoid panicking on non-ASCII paths.
fn elide_left(path: &str, max: usize) -> String {
    if path.len() <= max {
        return path.to_string();
    }
    let start = path.len() - max;
    // Walk forward to the nearest char boundary
    let start = path.ceil_char_boundary(start);
    format!("\u{2026}{}", &path[start..])
}

/// Shortens the path inside library result messages like "Encrypted to /long/path in 1.23 sec".
fn elide_result_path(msg: &str) -> String {
    let msg = msg.trim();
    for prefix in ["Encrypted to ", "Decrypted to "] {
        if let Some(rest) = msg.strip_prefix(prefix) {
            if let Some((path, duration)) = rest.rsplit_once(" in ") {
                return format!("{prefix}{} in {duration}", elide_left(path, ELIDE_OUTPUT));
            }
        }
    }
    msg.to_string()
}

fn detect_mode_from_path(path: &str) -> Option<i32> {
    match detect_encryption_mode(path) {
        Some(EncryptionMode::Symmetric) => Some(1),
        Some(EncryptionMode::Hybrid) => Some(3),
        None => None,
    }
}
