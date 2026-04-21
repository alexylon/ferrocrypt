// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

slint::include_modules!();

use ferrocrypt::secrecy::{ExposeSecret, SecretString};
use ferrocrypt::{
    EncryptionMode, HybridDecryptConfig, HybridEncryptConfig, KeyGenConfig, PRIVATE_KEY_FILENAME,
    PUBLIC_KEY_FILENAME, PrivateKey, ProgressEvent, PublicKey, SymmetricDecryptConfig,
    SymmetricEncryptConfig, default_encrypted_filename, detect_encryption_mode, generate_key_pair,
    hybrid_decrypt, hybrid_encrypt, symmetric_decrypt, symmetric_encrypt, validate_secret_key_file,
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

    app.set_app_version(env!("CARGO_PKG_VERSION").into());
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
                let pwd = SecretString::from(app.get_password().to_string());
                app.set_password_strength(password_scorer::password_strength(pwd.expose_secret()));
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
            // Wrap immediately so the password bytes are zeroized on drop,
            // even on the hybrid-encrypt path where the library doesn't
            // consume them, and even if the worker panics before the
            // crypto call runs.
            let pwd = SecretString::from(app.get_password().to_string());
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
                // If the worker body panics without `catch_unwind`, the
                // success handler below (which clears `is-working` via
                // `invoke_from_event_loop`) never runs and the UI stays
                // permanently disabled. The library is designed to avoid
                // panics, but Argon2id can still OOM on constrained hosts.
                let panic_weak = weak.clone();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let keygen_dir = if mode == MODE_KEYGEN {
                        Some(output_dir.clone())
                    } else {
                        None
                    };

                    let on_event = {
                        let weak = weak.clone();
                        move |event: &ProgressEvent| {
                            let msg = event.to_string();
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
                    let save_as = output_file.as_deref().map(Path::new);

                    let is_decrypt = is_decrypt_mode(mode);
                    let start = std::time::Instant::now();
                    let result: Result<PathBuf, _> = match mode {
                        MODE_SYMMETRIC_ENCRYPT => {
                            let mut config =
                                SymmetricEncryptConfig::new(inpath, output_dir_path, pwd);
                            if let Some(s) = save_as {
                                config = config.save_as(s);
                            }
                            symmetric_encrypt(config, &on_event).map(|o| o.output_path)
                        }
                        MODE_SYMMETRIC_DECRYPT => {
                            let config = SymmetricDecryptConfig::new(inpath, output_dir_path, pwd);
                            symmetric_decrypt(config, &on_event).map(|o| o.output_path)
                        }
                        MODE_HYBRID_ENCRYPT => {
                            let mut config = HybridEncryptConfig::new(
                                inpath,
                                output_dir_path,
                                PublicKey::from_key_file(Path::new(&keypath)),
                            );
                            if let Some(s) = save_as {
                                config = config.save_as(s);
                            }
                            hybrid_encrypt(config, &on_event).map(|o| o.output_path)
                        }
                        MODE_HYBRID_DECRYPT => {
                            let config = HybridDecryptConfig::new(
                                inpath,
                                output_dir_path,
                                PrivateKey::from_key_file(Path::new(&keypath)),
                                pwd,
                            );
                            hybrid_decrypt(config, &on_event).map(|o| o.output_path)
                        }
                        MODE_KEYGEN => {
                            let config = KeyGenConfig::new(output_dir_path, pwd);
                            generate_key_pair(config, &on_event).map(|o| o.public_key_path)
                        }
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
                }));

                if result.is_err() {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(app) = panic_weak.upgrade() {
                            app.set_is_working(false);
                            app.set_status_ok("".into());
                            app.set_status_err(
                                "Operation failed unexpectedly (internal error)".into(),
                            );
                        }
                    });
                }
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
    let new_mode = next_mode(old_mode, detected_mode);
    if new_mode != old_mode {
        app.set_mode(new_mode);
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
    let keygen_dir = app.get_keygen_output_dir().to_string();

    let out_exists = is_encrypt_mode(mode) && !outpath.is_empty() && Path::new(&outpath).exists();
    let (secret_exists, pub_exists) = if mode == MODE_KEYGEN && !keygen_dir.is_empty() {
        (
            private_key_path(&keygen_dir).exists(),
            public_key_path(&keygen_dir).exists(),
        )
    } else {
        (false, false)
    };

    let warning = compute_conflict_warning(
        mode,
        &outpath,
        &keygen_dir,
        out_exists,
        secret_exists,
        pub_exists,
    );
    app.set_conflict_warning(warning.into());
}

/// Pure conflict-detection logic: given the current UI mode, resolved output
/// paths, and the filesystem existence of each, return the warning string to
/// display (or empty string when there is no conflict).
fn compute_conflict_warning(
    mode: i32,
    outpath: &str,
    keygen_dir: &str,
    out_exists: bool,
    secret_exists: bool,
    pub_exists: bool,
) -> String {
    if is_encrypt_mode(mode) && !outpath.is_empty() && out_exists {
        return format!("Already exists: {}", elide_left(outpath, ELIDE));
    }
    if mode == MODE_KEYGEN && !keygen_dir.is_empty() {
        return match (secret_exists, pub_exists) {
            (true, true) => "Key pair already exists in output folder".into(),
            (true, false) => "Private key already exists in output folder".into(),
            (false, true) => "Public key already exists in output folder".into(),
            _ => String::new(),
        };
    }
    String::new()
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
    let current = app.get_mode();
    let snapped = snap_back_mode(current);
    if snapped != current {
        app.set_mode(snapped);
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
        MODE_HYBRID_ENCRYPT => match PublicKey::from_key_file(key_path).fingerprint() {
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

/// Given the current UI mode and the mode detected from a newly selected input
/// file's header, decide which mode the UI should switch to.
///
/// - `detected = Some(m)`: the file self-identifies as encrypted in mode `m`.
/// - `detected = None`: the file is not a FerroCrypt payload. If we were in a
///   decrypt mode, flip back to the matching encrypt mode of the same tab;
///   otherwise leave the mode alone.
fn next_mode(old_mode: i32, detected: Option<i32>) -> i32 {
    match detected {
        Some(m) => m,
        None => match old_mode {
            MODE_SYMMETRIC_DECRYPT => MODE_SYMMETRIC_ENCRYPT,
            MODE_HYBRID_DECRYPT => MODE_HYBRID_ENCRYPT,
            _ => old_mode,
        },
    }
}

/// Maps the current mode to the mode `clear_fields` should leave the UI in:
/// decrypt and keygen modes snap back to the encrypt mode of their tab, all
/// other modes are unchanged.
fn snap_back_mode(mode: i32) -> i32 {
    match mode {
        MODE_SYMMETRIC_DECRYPT => MODE_SYMMETRIC_ENCRYPT,
        MODE_HYBRID_DECRYPT | MODE_KEYGEN => MODE_HYBRID_ENCRYPT,
        _ => mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_mode_predicates() {
        assert!(is_encrypt_mode(MODE_SYMMETRIC_ENCRYPT));
        assert!(is_encrypt_mode(MODE_HYBRID_ENCRYPT));
        assert!(!is_encrypt_mode(MODE_SYMMETRIC_DECRYPT));
        assert!(!is_encrypt_mode(MODE_HYBRID_DECRYPT));
        assert!(!is_encrypt_mode(MODE_KEYGEN));

        assert!(is_decrypt_mode(MODE_SYMMETRIC_DECRYPT));
        assert!(is_decrypt_mode(MODE_HYBRID_DECRYPT));
        assert!(!is_decrypt_mode(MODE_SYMMETRIC_ENCRYPT));
        assert!(!is_decrypt_mode(MODE_HYBRID_ENCRYPT));
        assert!(!is_decrypt_mode(MODE_KEYGEN));
    }

    #[test]
    fn next_mode_adopts_detected_mode() {
        assert_eq!(
            next_mode(MODE_SYMMETRIC_ENCRYPT, Some(MODE_HYBRID_DECRYPT)),
            MODE_HYBRID_DECRYPT
        );
        assert_eq!(
            next_mode(MODE_HYBRID_ENCRYPT, Some(MODE_SYMMETRIC_DECRYPT)),
            MODE_SYMMETRIC_DECRYPT
        );
    }

    #[test]
    fn next_mode_flips_decrypt_back_to_encrypt_when_not_detected() {
        assert_eq!(
            next_mode(MODE_SYMMETRIC_DECRYPT, None),
            MODE_SYMMETRIC_ENCRYPT
        );
        assert_eq!(next_mode(MODE_HYBRID_DECRYPT, None), MODE_HYBRID_ENCRYPT);
    }

    #[test]
    fn next_mode_keeps_non_decrypt_modes_when_not_detected() {
        assert_eq!(
            next_mode(MODE_SYMMETRIC_ENCRYPT, None),
            MODE_SYMMETRIC_ENCRYPT
        );
        assert_eq!(next_mode(MODE_HYBRID_ENCRYPT, None), MODE_HYBRID_ENCRYPT);
        assert_eq!(next_mode(MODE_KEYGEN, None), MODE_KEYGEN);
    }

    #[test]
    fn snap_back_mode_folds_decrypt_and_keygen_to_tab_encrypt() {
        assert_eq!(
            snap_back_mode(MODE_SYMMETRIC_DECRYPT),
            MODE_SYMMETRIC_ENCRYPT
        );
        assert_eq!(snap_back_mode(MODE_HYBRID_DECRYPT), MODE_HYBRID_ENCRYPT);
        assert_eq!(snap_back_mode(MODE_KEYGEN), MODE_HYBRID_ENCRYPT);
    }

    #[test]
    fn snap_back_mode_leaves_encrypt_modes_alone() {
        assert_eq!(
            snap_back_mode(MODE_SYMMETRIC_ENCRYPT),
            MODE_SYMMETRIC_ENCRYPT
        );
        assert_eq!(snap_back_mode(MODE_HYBRID_ENCRYPT), MODE_HYBRID_ENCRYPT);
    }

    #[test]
    fn conflict_warning_empty_when_no_output_path() {
        let w = compute_conflict_warning(MODE_SYMMETRIC_ENCRYPT, "", "", false, false, false);
        assert!(w.is_empty());
    }

    #[test]
    fn conflict_warning_empty_when_encrypt_output_missing() {
        let w =
            compute_conflict_warning(MODE_HYBRID_ENCRYPT, "/tmp/out.fcr", "", false, false, false);
        assert!(w.is_empty());
    }

    #[test]
    fn conflict_warning_flags_existing_encrypt_output() {
        let w = compute_conflict_warning(
            MODE_SYMMETRIC_ENCRYPT,
            "/tmp/out.fcr",
            "",
            true,
            false,
            false,
        );
        assert_eq!(w, "Already exists: /tmp/out.fcr");

        let w =
            compute_conflict_warning(MODE_HYBRID_ENCRYPT, "/tmp/out.fcr", "", true, false, false);
        assert_eq!(w, "Already exists: /tmp/out.fcr");
    }

    #[test]
    fn conflict_warning_ignores_existing_decrypt_output() {
        // Decrypt modes must never block on output existence — the library's
        // atomic output handling is authoritative, and the output path in
        // decrypt mode is a directory.
        for mode in [MODE_SYMMETRIC_DECRYPT, MODE_HYBRID_DECRYPT] {
            let w = compute_conflict_warning(mode, "/tmp/out", "", true, false, false);
            assert!(w.is_empty(), "mode {} unexpectedly warned", mode);
        }
    }

    #[test]
    fn conflict_warning_elides_long_encrypt_paths() {
        let long = format!("/tmp/{}", "a".repeat(80));
        let w = compute_conflict_warning(MODE_SYMMETRIC_ENCRYPT, &long, "", true, false, false);
        assert!(w.starts_with("Already exists: \u{2026}"), "got: {}", w);
    }

    #[test]
    fn conflict_warning_keygen_variants() {
        let cases = [
            (true, true, "Key pair already exists in output folder"),
            (true, false, "Private key already exists in output folder"),
            (false, true, "Public key already exists in output folder"),
            (false, false, ""),
        ];
        for (sec, pubk, expected) in cases {
            let w = compute_conflict_warning(MODE_KEYGEN, "", "/tmp/keys", false, sec, pubk);
            assert_eq!(w, expected, "sec={sec} pub={pubk}");
        }
    }

    #[test]
    fn conflict_warning_keygen_empty_dir_never_warns() {
        for (sec, pubk) in [(true, true), (true, false), (false, true), (false, false)] {
            let w = compute_conflict_warning(MODE_KEYGEN, "", "", false, sec, pubk);
            assert!(w.is_empty());
        }
    }

    #[test]
    fn elide_left_passthrough_when_short() {
        assert_eq!(elide_left("short", 52), "short");
        assert_eq!(elide_left("", 52), "");
    }

    #[test]
    fn elide_left_passthrough_at_exact_boundary() {
        let s = "a".repeat(52);
        assert_eq!(elide_left(&s, 52), s);
    }

    #[test]
    fn elide_left_shortens_longer_paths_with_ellipsis() {
        let s = "a".repeat(60);
        let out = elide_left(&s, 52);
        assert!(out.starts_with('\u{2026}'));
        // 52 'a's preserved + one ellipsis char (3 UTF-8 bytes) prefix.
        assert_eq!(out.chars().filter(|c| *c == 'a').count(), 52);
    }

    #[test]
    fn elide_left_respects_multibyte_boundaries() {
        // 60 'é' glyphs (2 bytes each) => 120 bytes. Must not panic and must
        // still produce a valid UTF-8 string.
        let s = "é".repeat(60);
        let out = elide_left(&s, 52);
        assert!(out.is_char_boundary(out.len()));
        assert!(out.starts_with('\u{2026}'));
        // ceil_char_boundary may skip one byte to land on a boundary, so we
        // get either 26 or 25 'é' glyphs — both are acceptable.
        let count = out.chars().filter(|c| *c == 'é').count();
        assert!((25..=26).contains(&count), "got {count} é glyphs");
    }

    #[test]
    fn elide_result_path_shortens_encrypted_to_message() {
        let long = "a".repeat(200);
        let msg = format!("Encrypted to /tmp/{long} in 1.23 sec");
        let out = elide_result_path(&msg);
        assert!(out.starts_with("Encrypted to "));
        assert!(out.ends_with(" in 1.23 sec"));
        assert!(out.contains('\u{2026}'));
    }

    #[test]
    fn elide_result_path_shortens_decrypted_to_message() {
        let long = "b".repeat(200);
        let msg = format!("Decrypted to /tmp/{long} in 0.50 sec");
        let out = elide_result_path(&msg);
        assert!(out.starts_with("Decrypted to "));
        assert!(out.ends_with(" in 0.50 sec"));
        assert!(out.contains('\u{2026}'));
    }

    #[test]
    fn elide_result_path_shortens_output_conflict_messages() {
        let long = "c".repeat(200);
        for prefix in ["Output file already exists: ", "Output already exists: "] {
            let msg = format!("{prefix}/tmp/{long}");
            let out = elide_result_path(&msg);
            assert!(out.starts_with(prefix));
            assert!(out.contains('\u{2026}'));
        }
    }

    #[test]
    fn elide_result_path_passthrough_for_unknown_prefix() {
        assert_eq!(
            elide_result_path("Some other message"),
            "Some other message"
        );
    }

    #[test]
    fn elide_result_path_trims_whitespace() {
        assert_eq!(elide_result_path("  Short message  "), "Short message");
    }

    #[test]
    fn format_duration_under_one_minute() {
        let out = format_duration("Encrypted to", Path::new("/tmp/out"), 1.234);
        assert_eq!(out, "Encrypted to /tmp/out in 1.23 sec");
    }

    #[test]
    fn format_duration_at_and_past_one_minute() {
        // Exact 60s must cross into the min/sec branch.
        let out = format_duration("Decrypted to", Path::new("/tmp/out"), 60.0);
        assert!(out.contains("1 min"));

        let out = format_duration("Encrypted to", Path::new("/tmp/out"), 125.5);
        assert!(out.contains("2 min"));
        assert!(out.contains("5.50 sec"));
    }

    #[test]
    fn parent_dir_returns_parent() {
        assert_eq!(parent_dir("/tmp/foo/bar"), Some("/tmp/foo".to_string()));
    }

    #[test]
    fn parent_dir_of_bare_filename_is_empty_string() {
        // `Path::parent()` returns Some("") for relative bare names.
        assert_eq!(parent_dir("bare"), Some(String::new()));
    }

    #[test]
    fn parent_dir_of_root_is_none() {
        // On Unix, "/" has no parent.
        #[cfg(unix)]
        assert_eq!(parent_dir("/"), None);
    }

    #[test]
    fn key_paths_join_directory() {
        let pub_p = public_key_path("/tmp/keys");
        let priv_p = private_key_path("/tmp/keys");
        assert!(pub_p.ends_with(PUBLIC_KEY_FILENAME));
        assert!(priv_p.ends_with(PRIVATE_KEY_FILENAME));
        assert_eq!(pub_p.parent(), Some(Path::new("/tmp/keys")));
        assert_eq!(priv_p.parent(), Some(Path::new("/tmp/keys")));
    }
}
