// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

slint::include_modules!();

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    EncryptionMode, PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME, default_encrypted_filename,
    detect_encryption_mode, generate_key_pair, hybrid_auto, public_key_fingerprint, symmetric_auto,
    validate_secret_key_file,
};
use std::path::{Path, PathBuf};

mod password_scorer;

const ELIDE: usize = 52;

// Slint app modes — must match the `mode` property values in app.slint
const MODE_SYMMETRIC_ENCRYPT: i32 = 0;
const MODE_SYMMETRIC_DECRYPT: i32 = 1;
const MODE_HYBRID_ENCRYPT: i32 = 2;
const MODE_HYBRID_DECRYPT: i32 = 3;
const MODE_KEYGEN: i32 = 4;

fn is_encrypt_mode(mode: i32) -> bool {
    matches!(mode, MODE_SYMMETRIC_ENCRYPT | MODE_HYBRID_ENCRYPT)
}

fn is_decrypt_mode(mode: i32) -> bool {
    matches!(mode, MODE_SYMMETRIC_DECRYPT | MODE_HYBRID_DECRYPT)
}

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
                app.set_password_strength(password_scorer::PW_EMPTY);
                app.set_status_ok(Default::default());
                app.set_status_err(Default::default());
                let keypath = app.get_key_path().to_string();
                if !keypath.is_empty() {
                    validate_selected_key(&app, &keypath);
                } else {
                    app.set_key_fingerprint(Default::default());
                    app.set_key_invalid(false);
                }
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
                .add_filter("Key files", &["key"])
                .pick_file()
            else {
                return;
            };
            let Some(app) = weak.upgrade() else { return };
            let key_path = path_to_string(&path);
            app.set_key_path_display(elide_left(&key_path, ELIDE).into());
            app.set_key_path(key_path.clone().into());
            validate_selected_key(&app, &key_path);
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
            update_output_path(&app, &path_to_string(&path));
        }
    });

    app.on_select_output_file({
        let weak = app.as_weak();
        move || {
            let Some(app) = weak.upgrade() else { return };
            let mut dialog = rfd::FileDialog::new();

            let inpath = app.get_input_path().to_string();
            if let Ok(name) = default_encrypted_filename(&inpath) {
                dialog = dialog.set_file_name(&name);
            }

            let outpath = app.get_output_path().to_string();
            if let Some(parent) = parent_dir(&outpath) {
                dialog = dialog.set_directory(parent);
            }

            if let Some(path) = dialog.save_file() {
                update_output_path(&app, &path_to_string(&path));
            }
        }
    });

    app.on_select_keygen_output_dir({
        let weak = app.as_weak();
        move || {
            let Some(path) = rfd::FileDialog::new().pick_folder() else {
                return;
            };
            let Some(app) = weak.upgrade() else { return };
            let dir = path_to_string(&path);
            app.set_keygen_output_dir_display(elide_left(&dir, ELIDE).into());
            app.set_keygen_output_dir(dir.into());
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
            let inpath = app.get_input_path().to_string();
            let outpath = app.get_output_path().to_string();
            let password = app.get_password().to_string();
            let keypath = app.get_key_path().to_string();
            let keygen_outdir = app.get_keygen_output_dir().to_string();

            let is_encrypt = is_encrypt_mode(mode);
            let (output_dir, output_file) = if mode == MODE_KEYGEN {
                (keygen_outdir, None)
            } else if is_encrypt {
                (parent_dir(&outpath).unwrap_or_default(), Some(outpath))
            } else {
                (outpath, None)
            };

            app.set_is_working(true);
            app.set_status_ok("".into());
            app.set_status_err("".into());
            app.set_conflict_warning("".into());

            let weak = weak.clone();
            std::thread::spawn(move || {
                let pwd = SecretString::from(password);
                let keygen_dir = if mode == MODE_KEYGEN {
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

                let inpath = Path::new(&inpath);
                let output_dir_path = Path::new(&output_dir);
                let keypath = Path::new(&keypath);
                let save_as = output_file.as_deref().map(Path::new);

                let is_decrypt = is_decrypt_mode(mode);
                let start = std::time::Instant::now();
                let result: Result<PathBuf, _> = match mode {
                    MODE_SYMMETRIC_ENCRYPT | MODE_SYMMETRIC_DECRYPT => {
                        symmetric_auto(inpath, output_dir_path, &pwd, save_as, None, &on_progress)
                    }
                    MODE_HYBRID_ENCRYPT | MODE_HYBRID_DECRYPT => hybrid_auto(
                        inpath,
                        output_dir_path,
                        keypath,
                        &pwd,
                        save_as,
                        None,
                        &on_progress,
                    ),
                    MODE_KEYGEN => generate_key_pair(&pwd, output_dir_path, &on_progress)
                        .map(|info| info.public_key_path),
                    _ => unreachable!(),
                };
                let elapsed = start.elapsed().as_secs_f64();

                let _ = slint::invoke_from_event_loop(move || {
                    let Some(app) = weak.upgrade() else { return };
                    app.set_is_working(false);

                    match result {
                        Ok(output) => {
                            if let Some(dir) = keygen_dir {
                                let pub_key = path_to_string(&public_key_path(&dir));
                                app.set_password(Default::default());
                                app.set_password_repeated(Default::default());
                                app.set_hide_password(true);
                                app.set_password_strength(password_scorer::PW_EMPTY);
                                app.set_keygen_output_dir(Default::default());
                                app.set_keygen_output_dir_display(Default::default());
                                app.set_conflict_warning(Default::default());
                                app.set_status_err(Default::default());
                                app.set_mode(MODE_HYBRID_ENCRYPT);
                                app.set_key_path_display(elide_left(&pub_key, ELIDE).into());
                                app.set_key_path(pub_key.clone().into());
                                validate_selected_key(&app, &pub_key);
                                app.set_status_ok(
                                    "Key pair generated \u{2014} public key selected".into(),
                                );
                            } else {
                                clear_fields(&app);
                                let action = if is_decrypt {
                                    "Decrypted to"
                                } else {
                                    "Encrypted to"
                                };
                                let status = format_duration(action, &output, elapsed);
                                app.set_status_ok(elide_result_path(&status).into());
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

    app.on_copy_fingerprint({
        let weak = app.as_weak();
        move || {
            let Some(app) = weak.upgrade() else { return };
            let fp = app.get_key_fingerprint().to_string();
            if !fp.is_empty() {
                if let Ok(mut clipboard) = arboard::Clipboard::new() {
                    let _ = clipboard.set_text(fp);
                }
            }
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

    let Some(app) = weak.upgrade() else { return };

    let detected_mode = match detected_mode {
        Ok(mode) => mode,
        Err(e) => {
            app.set_status_err(e.to_string().into());
            return;
        }
    };
    let is_decrypt = detected_mode.is_some_and(is_decrypt_mode);

    let inpath_elide = if app.get_combined_picker() {
        ELIDE
    } else {
        ELIDE - 12
    };
    app.set_input_path_display(elide_left(&selected, inpath_elide).into());
    app.set_input_path(selected.clone().into());
    let old_mode = app.get_mode();
    match detected_mode {
        Some(m) => app.set_mode(m),
        None => match old_mode {
            MODE_SYMMETRIC_DECRYPT => app.set_mode(MODE_SYMMETRIC_ENCRYPT),
            MODE_HYBRID_DECRYPT => app.set_mode(MODE_HYBRID_ENCRYPT),
            _ => {}
        },
    }
    if app.get_mode() != old_mode {
        app.set_password(Default::default());
        app.set_password_repeated(Default::default());
        app.set_hide_password(true);
        app.set_password_strength(password_scorer::PW_EMPTY);
    }

    let keypath = app.get_key_path().to_string();
    if !keypath.is_empty() {
        validate_selected_key(&app, &keypath);
    }

    if is_decrypt {
        update_output_path(&app, &dir);
    } else if let Ok(filename) = default_encrypted_filename(&selected) {
        update_output_path(&app, &path_to_string(&Path::new(&dir).join(filename)));
    }

    if !app.get_key_invalid() {
        app.set_status_ok("".into());
        app.set_status_err("".into());
    }
    check_conflicts(&app);
}

fn update_output_path(app: &AppWindow, path: &str) {
    app.set_output_path_display(elide_left(path, ELIDE).into());
    app.set_output_path(path.into());
    check_conflicts(app);
}

fn check_conflicts(app: &AppWindow) {
    let mode = app.get_mode();
    let outpath = app.get_output_path().to_string();

    let mut warning = String::new();

    if is_encrypt_mode(mode) && !outpath.is_empty() && Path::new(&outpath).exists() {
        warning = format!("Already exists: {}", elide_left(&outpath, ELIDE));
    }

    if mode == MODE_KEYGEN && warning.is_empty() {
        let kg_dir = app.get_keygen_output_dir().to_string();
        if !kg_dir.is_empty() {
            let secret_exists = private_key_path(&kg_dir).exists();
            let pub_exists = public_key_path(&kg_dir).exists();
            warning = match (secret_exists, pub_exists) {
                (true, true) => "Key pair already exists in output folder".into(),
                (true, false) => "Private key already exists in output folder".into(),
                (false, true) => "Public key already exists in output folder".into(),
                _ => String::new(),
            };
        }
    }

    app.set_conflict_warning(warning.into());
}

fn clear_fields(app: &AppWindow) {
    let empty = slint::SharedString::default();
    app.set_input_path(empty.clone());
    app.set_input_path_display(empty.clone());
    app.set_output_path(empty.clone());
    app.set_output_path_display(empty.clone());
    app.set_password(empty.clone());
    app.set_password_repeated(empty.clone());
    app.set_key_path(empty.clone());
    app.set_key_path_display(empty.clone());
    app.set_keygen_output_dir(empty.clone());
    app.set_keygen_output_dir_display(empty.clone());
    app.set_conflict_warning(empty.clone());
    app.set_status_ok(empty.clone());
    app.set_status_err(empty);
    app.set_hide_password(true);
    app.set_password_strength(password_scorer::PW_EMPTY);
    app.set_key_fingerprint(Default::default());
    app.set_key_invalid(false);
    // Snap back to the encrypt mode of the current tab
    match app.get_mode() {
        MODE_SYMMETRIC_DECRYPT => app.set_mode(MODE_SYMMETRIC_ENCRYPT),
        MODE_HYBRID_DECRYPT | MODE_KEYGEN => app.set_mode(MODE_HYBRID_ENCRYPT),
        _ => {}
    }
}

fn public_key_path(dir: &str) -> PathBuf {
    Path::new(dir).join(PUBLIC_KEY_FILENAME)
}

fn private_key_path(dir: &str) -> PathBuf {
    Path::new(dir).join(PRIVATE_KEY_FILENAME)
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn parent_dir(path: &str) -> Option<String> {
    Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
}

fn format_duration(action: &str, path: &Path, seconds: f64) -> String {
    if seconds < 60.0 {
        format!("{} {} in {:.2} sec", action, path.display(), seconds)
    } else {
        format!(
            "{} {} in {} min, {:.2} sec",
            action,
            path.display(),
            seconds as u32 / 60,
            seconds % 60.0
        )
    }
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

fn validate_selected_key(app: &AppWindow, key_path: &str) {
    let key_path = Path::new(key_path);
    match app.get_mode() {
        MODE_HYBRID_ENCRYPT => match public_key_fingerprint(key_path) {
            Ok(fp) => {
                app.set_key_fingerprint(fp.into());
                app.set_key_invalid(false);
                app.set_status_err(Default::default());
            }
            Err(e) => {
                app.set_key_fingerprint(Default::default());
                app.set_key_invalid(true);
                app.set_status_err(e.to_string().into());
            }
        },
        MODE_HYBRID_DECRYPT => {
            app.set_key_fingerprint(Default::default());
            if let Err(e) = validate_secret_key_file(key_path) {
                app.set_key_invalid(true);
                app.set_status_err(e.to_string().into());
            } else {
                app.set_key_invalid(false);
                app.set_status_err(Default::default());
            }
        }
        _ => {
            app.set_key_fingerprint(Default::default());
            app.set_key_invalid(false);
        }
    }
}

fn detect_mode_from_path(path: &str) -> Result<Option<i32>, ferrocrypt::CryptoError> {
    match detect_encryption_mode(Path::new(path))? {
        Some(EncryptionMode::Symmetric) => Ok(Some(MODE_SYMMETRIC_DECRYPT)),
        Some(EncryptionMode::Hybrid) => Ok(Some(MODE_HYBRID_DECRYPT)),
        Some(_) => Ok(None),
        None => Ok(None),
    }
}
