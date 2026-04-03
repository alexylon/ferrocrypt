// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

slint::include_modules!();

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    EncryptionMode, default_encrypted_filename, detect_encryption_mode,
    generate_asymmetric_key_pair, hybrid_encryption, symmetric_encryption,
};
use std::path::{Path, PathBuf};

mod password_scorer;

const ELIDE: usize = 42;
const RSA_KEY_BITS: u32 = 4096;

#[cfg(target_os = "macos")]
fn pick_file_or_folder() -> Option<PathBuf> {
    rfd::FileDialog::new().pick_file_or_folder()
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
                app.set_password(Default::default());
                app.set_password_repeated(Default::default());
                app.set_hide_password(true);
                app.set_password_strength(0);
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
            app.set_keypath_display(elide_left(&key_path, ELIDE).into());
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

    app.on_select_keygen_outdir({
        let weak = app.as_weak();
        move || {
            let Some(path) = rfd::FileDialog::new().pick_folder() else {
                return;
            };
            let Some(app) = weak.upgrade() else { return };
            let dir = path_to_string(&path);
            app.set_keygen_outdir_display(elide_left(&dir, ELIDE).into());
            app.set_keygen_outdir(dir.into());
            check_conflicts(&app);
        }
    });

    app.on_password_edited({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                let pwd = app.get_password().to_string();
                app.set_password_strength(password_scorer::password_strength(&pwd));
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
            let keygen_outdir = app.get_keygen_outdir().to_string();

            let is_encrypt = mode == 0 || mode == 2;
            let (output_dir, output_file) = if mode == 4 {
                (keygen_outdir, None)
            } else if is_encrypt {
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
                let keygen_dir = if mode == 4 {
                    Some(output_dir.clone())
                } else {
                    None
                };

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
                    0 | 1 => symmetric_encryption(
                        &inpath,
                        &output_dir,
                        &pwd,
                        output_file.as_deref(),
                        &on_progress,
                    ),
                    2 | 3 => hybrid_encryption(
                        &inpath,
                        &output_dir,
                        &keypath,
                        &pwd,
                        output_file.as_deref(),
                        &on_progress,
                    ),
                    4 => {
                        generate_asymmetric_key_pair(RSA_KEY_BITS, &pwd, &output_dir, &on_progress)
                    }
                    _ => unreachable!(),
                };

                let _ = slint::invoke_from_event_loop(move || {
                    let Some(app) = weak.upgrade() else { return };
                    app.set_is_working(false);

                    match result {
                        Ok(msg) => {
                            if let Some(dir) = keygen_dir {
                                let pub_key = pub_key_path(&dir);
                                app.set_password(Default::default());
                                app.set_password_repeated(Default::default());
                                app.set_hide_password(true);
                                app.set_password_strength(0);
                                app.set_keygen_outdir(Default::default());
                                app.set_keygen_outdir_display(Default::default());
                                app.set_conflict_warning(Default::default());
                                app.set_status_err(Default::default());
                                app.set_mode(2);
                                app.set_keypath_display(elide_left(&pub_key, ELIDE).into());
                                app.set_keypath(pub_key.into());
                                app.set_status_ok(
                                    "Key pair generated \u{2014} public key selected".into(),
                                );
                            } else {
                                clear_fields(&app);
                                app.set_status_ok(elide_result_path(&msg).into());
                            }
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
                clear_fields(&app);
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
    app.set_inpath_display(elide_left(&selected, ELIDE).into());
    app.set_inpath(selected.clone().into());
    match detected_mode {
        Some(m) => app.set_mode(m),
        None => match app.get_mode() {
            1 => app.set_mode(0),
            3 => app.set_mode(2),
            _ => {}
        },
    }

    if is_decrypt {
        set_outpath(&app, &dir);
    } else if let Ok(filename) = default_encrypted_filename(&selected) {
        set_outpath(&app, &path_to_string(&Path::new(&dir).join(filename)));
    }

    app.set_status_ok("Ready".into());
    app.set_status_err("".into());
    check_conflicts(&app);
}

fn set_outpath(app: &AppWindow, path: &str) {
    app.set_outpath_display(elide_left(path, ELIDE).into());
    app.set_outpath(path.into());
    check_conflicts(app);
}

fn check_conflicts(app: &AppWindow) {
    let mode = app.get_mode();
    let outpath = app.get_outpath().to_string();

    let mut warning = String::new();

    if matches!(mode, 0 | 2 | 4) && !outpath.is_empty() && Path::new(&outpath).exists() {
        warning = format!("Already exists: {}", elide_left(&outpath, ELIDE));
    }

    if mode == 4 && warning.is_empty() {
        let kg_dir = app.get_keygen_outdir().to_string();
        if !kg_dir.is_empty() {
            let priv_exists = Path::new(&priv_key_path(&kg_dir)).exists();
            let pub_exists = Path::new(&pub_key_path(&kg_dir)).exists();
            warning = match (priv_exists, pub_exists) {
                (true, true) => "Key pair already exists in output directory".into(),
                (true, false) => "Private key already exists in output directory".into(),
                (false, true) => "Public key already exists in output directory".into(),
                _ => String::new(),
            };
        }
    }

    app.set_conflict_warning(warning.into());
}

fn clear_fields(app: &AppWindow) {
    let empty = slint::SharedString::default();
    app.set_inpath(empty.clone());
    app.set_inpath_display(empty.clone());
    app.set_outpath(empty.clone());
    app.set_outpath_display(empty.clone());
    app.set_password(empty.clone());
    app.set_password_repeated(empty.clone());
    app.set_keypath(empty.clone());
    app.set_keypath_display(empty.clone());
    app.set_keygen_outdir(empty.clone());
    app.set_keygen_outdir_display(empty.clone());
    app.set_conflict_warning(empty.clone());
    app.set_status_ok(empty.clone());
    app.set_status_err(empty);
    app.set_hide_password(true);
    app.set_password_strength(0);
    // Snap back to the encrypt mode of the current tab
    match app.get_mode() {
        1 => app.set_mode(0),
        3 | 4 => app.set_mode(2),
        _ => {}
    }
}

fn pub_key_path(dir: &str) -> String {
    format!("{dir}/rsa-{RSA_KEY_BITS}-pub-key.pem")
}

fn priv_key_path(dir: &str) -> String {
    format!("{dir}/rsa-{RSA_KEY_BITS}-priv-key.pem")
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
                return format!("{prefix}{} in {duration}", elide_left(path, ELIDE - 5));
            }
        }
    }
    for prefix in ["Output file already exists: ", "Output already exists: "] {
        if let Some(path) = msg.strip_prefix(prefix) {
            return format!("{prefix}{}", elide_left(path, ELIDE - 5));
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
