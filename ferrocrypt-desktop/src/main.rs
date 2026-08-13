// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

slint::include_modules!();

use ferrocrypt::Passphrase;
use ferrocrypt::{
    CryptoError, Decryptor, Encryptor, KdfParams, KeyPairGenerator, PRIVATE_KEY_FILENAME,
    PUBLIC_KEY_FILENAME, PrivateKey, ProgressEvent, PublicKey, UnauthenticatedRecipientMode,
    default_encrypted_filename, generate_key_pair, probe_recipient_mode, validate_private_key_file,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

mod password_scorer;

/// The recipient key resolved at the moment the user selected it, shared
/// between the key-selection callbacks and the operation launcher.
///
/// Keeping the resolved key rather than its path is what gives the displayed
/// fingerprint meaning: encryption uses this value, so a key file replaced
/// after selection cannot change the recipient behind the user's back.
type SelectedPublicKey = Arc<Mutex<Option<PublicKey>>>;

/// Replaces the retained recipient key. A poisoned lock leaves no key
/// retained, so the next encryption refuses instead of using a stale one.
fn store_selected_public_key(selected: &SelectedPublicKey, key: Option<PublicKey>) {
    if let Ok(mut slot) = selected.lock() {
        *slot = key;
    }
}

/// Reads the retained recipient key for one operation.
fn take_selected_public_key(selected: &SelectedPublicKey) -> Option<PublicKey> {
    selected.lock().ok().and_then(|slot| slot.clone())
}

/// Drops the retained recipient key together with the fingerprint describing
/// it.
///
/// The two always move together. A key retained while no fingerprint is on
/// screen could be encrypted to without the user seeing which key it is, so
/// every path that clears one clears the other through this function.
fn forget_selected_key(app: &AppWindow, selected: &SelectedPublicKey) {
    store_selected_public_key(selected, None);
    app.set_key_fingerprint(Default::default());
}

/// Width budget for a path shown in a form field (narrower: a picker button shares the row).
const ELIDE: usize = 44;

/// Width budget for the status line (wider, no button): two chars above the
/// library's 64-char message budget, so a full-length library message always
/// renders verbatim and only longer variable text (OS errors, paths) is elided.
const STATUS_LINE_MAX: usize = 66;

// Slint app modes — must match the `mode` property values in app.slint
const MODE_PASSPHRASE_ENCRYPT: i32 = 0;
const MODE_PASSPHRASE_DECRYPT: i32 = 1;
const MODE_RECIPIENT_ENCRYPT: i32 = 2;
const MODE_RECIPIENT_DECRYPT: i32 = 3;
const MODE_KEYGEN: i32 = 4;

fn is_encrypt_mode(mode: i32) -> bool {
    matches!(mode, MODE_PASSPHRASE_ENCRYPT | MODE_RECIPIENT_ENCRYPT)
}

fn is_decrypt_mode(mode: i32) -> bool {
    matches!(mode, MODE_PASSPHRASE_DECRYPT | MODE_RECIPIENT_DECRYPT)
}

/// The inputs the worker thread needs to run one crypto operation. Grouping
/// them keeps [`run_operation`] to a few arguments and lets a test describe an
/// operation in a single value.
struct Operation<'a> {
    mode: i32,
    input: &'a Path,
    output_dir: &'a Path,
    /// Exact output file path; when `None` the name is derived under `output_dir`.
    save_as: Option<&'a Path>,
    /// Private key file; used only by the recipient-decrypt mode.
    key_path: &'a Path,
    /// Recipient key resolved when the user selected it; used only by the
    /// recipient-encrypt mode. Carrying the resolved key instead of its path
    /// keeps the operation bound to the fingerprint the user verified.
    public_key: Option<PublicKey>,
    /// Argon2id override for the passphrase-encrypt and key-generation paths;
    /// `None` uses the library default. It has no effect on decrypt (whose cost
    /// is fixed by the input file) or on recipient encrypt (no Argon2id). Tests
    /// pass fast parameters here; production passes `None`.
    kdf_params: Option<KdfParams>,
}

/// Runs the crypto operation described by `op` and returns the resulting path
/// (the encrypted file, the decrypted output, or the generated public key).
/// The worker thread drives this single dispatch point; keeping it a free
/// function makes the mode routing and the cross-mode rejection messages
/// testable without the UI event loop.
fn run_operation(
    op: Operation<'_>,
    passphrase: Passphrase,
    on_event: &dyn Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    let Operation {
        mode,
        input,
        output_dir,
        save_as,
        key_path,
        public_key,
        kdf_params,
    } = op;
    match mode {
        MODE_PASSPHRASE_ENCRYPT => {
            let mut encryptor = Encryptor::with_passphrase(passphrase);
            if let Some(params) = kdf_params {
                encryptor = encryptor.kdf_params(params);
            }
            if let Some(s) = save_as {
                encryptor = encryptor.save_as(s);
            }
            encryptor
                .write(input, output_dir, on_event)
                .map(|o| o.output_path)
        }
        MODE_PASSPHRASE_DECRYPT => match Decryptor::open(input) {
            Ok(Decryptor::Passphrase(d)) => d
                .decrypt(passphrase, output_dir, on_event)
                .map(|o| o.output_path),
            Ok(Decryptor::PrivateKey(_)) => Err(CryptoError::InvalidInput(
                "This file is sealed for public-key recipients; switch to the 'Key pair' tab"
                    .to_string(),
            )),
            Ok(_) => Err(CryptoError::InvalidInput(
                "Unsupported FerroCrypt encryption mode for the 'Password' tab".to_string(),
            )),
            Err(e) => Err(e),
        },
        MODE_RECIPIENT_ENCRYPT => {
            let Some(public_key) = public_key else {
                return Err(CryptoError::InvalidInput(
                    "Select a public key file before encrypting".to_string(),
                ));
            };
            let mut encryptor = Encryptor::with_public_key(public_key);
            if let Some(s) = save_as {
                encryptor = encryptor.save_as(s);
            }
            encryptor
                .write(input, output_dir, on_event)
                .map(|o| o.output_path)
        }
        MODE_RECIPIENT_DECRYPT => match Decryptor::open(input) {
            Ok(Decryptor::PrivateKey(d)) => d
                .decrypt(
                    PrivateKey::from_key_file(key_path, passphrase),
                    output_dir,
                    on_event,
                )
                .map(|o| o.output_path),
            Ok(Decryptor::Passphrase(_)) => Err(CryptoError::InvalidInput(
                "This file is sealed with a passphrase; switch to the 'Password' tab".to_string(),
            )),
            Ok(_) => Err(CryptoError::InvalidInput(
                "Unsupported FerroCrypt encryption mode for the 'Key pair' tab".to_string(),
            )),
            Err(e) => Err(e),
        },
        MODE_KEYGEN => {
            let outcome = match kdf_params {
                Some(params) => KeyPairGenerator::with_passphrase(passphrase)
                    .kdf_params(params)
                    .write(output_dir, on_event),
                None => generate_key_pair(output_dir, passphrase, on_event),
            };
            outcome.map(|o| o.public_key_path)
        }
        _ => unreachable!(),
    }
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

    // Show the library version (the one cargo-release bumps) rather than this
    // crate's own, so the displayed version can't silently drift from a release.
    app.set_app_version(ferrocrypt::VERSION.into());
    app.set_combined_picker(cfg!(target_os = "macos"));

    let selected_public_key: SelectedPublicKey = Arc::new(Mutex::new(None));

    app.on_mode_changed({
        let weak = app.as_weak();
        let selected_public_key = selected_public_key.clone();
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
                    validate_selected_key(&app, &keypath, &selected_public_key);
                } else {
                    forget_selected_key(&app, &selected_public_key);
                    app.set_key_invalid(false);
                }
                check_conflicts(&app);
            }
        }
    });

    app.on_select_input_file({
        let weak = app.as_weak();
        let selected_public_key = selected_public_key.clone();
        move || {
            if let Some(path) = pick_file_or_folder() {
                apply_input_path(&weak, path, &selected_public_key);
            }
        }
    });

    app.on_select_input_folder({
        let weak = app.as_weak();
        let selected_public_key = selected_public_key.clone();
        move || {
            if let Some(path) = rfd::FileDialog::new().pick_folder() {
                apply_input_path(&weak, path, &selected_public_key);
            }
        }
    });

    app.on_select_key_file({
        let weak = app.as_weak();
        let selected_public_key = selected_public_key.clone();
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
            validate_selected_key(&app, &key_path, &selected_public_key);
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
                app.set_password_strength(password_scorer::password_strength(
                    app.get_password().as_str(),
                ));
            }
        }
    });

    app.on_start_operation({
        let weak = app.as_weak();
        let selected_public_key = selected_public_key.clone();
        move || {
            let Some(app) = weak.upgrade() else { return };

            let mode = app.get_mode();
            let inpath = app.get_input_path().to_string();
            let outpath = app.get_output_path().to_string();
            // Wrap immediately so the password bytes are zeroized on drop,
            // even on the recipient-encrypt path where the library doesn't
            // consume them, and even if the worker panics before the
            // crypto call runs.
            let pwd = Passphrase::new(app.get_password().to_string());
            let keypath = app.get_key_path().to_string();
            let keygen_outdir = app.get_keygen_output_dir().to_string();
            // Snapshot the key resolved when the user selected it, so the
            // operation encrypts to the key whose fingerprint is on screen.
            let public_key = take_selected_public_key(&selected_public_key);
            let selected_public_key = selected_public_key.clone();

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
                    let result = run_operation(
                        Operation {
                            mode,
                            input: inpath,
                            output_dir: output_dir_path,
                            save_as,
                            key_path: Path::new(&keypath),
                            public_key,
                            kdf_params: None,
                        },
                        pwd,
                        &on_event,
                    );
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
                                    app.set_mode(MODE_RECIPIENT_ENCRYPT);
                                    app.set_key_path_display(elide_left(&pub_key, ELIDE).into());
                                    app.set_key_path(pub_key.clone().into());
                                    validate_selected_key(&app, &pub_key, &selected_public_key);
                                    app.set_status_ok(
                                        "Key pair generated \u{2014} public key selected".into(),
                                    );
                                } else {
                                    clear_fields(&app, &selected_public_key);
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
                                app.set_status_err(elide_error_for_status(&e.to_string()).into());
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
        let selected_public_key = selected_public_key.clone();
        move || {
            if let Some(app) = weak.upgrade() {
                clear_fields(&app, &selected_public_key);
            }
        }
    });

    // Re-check for a name clash every second while the window is idle, so the
    // "already exists" note clears on its own once you delete or rename the
    // clashing file outside the app (for example in Finder or Explorer) and
    // switch back. The Start button is never turned off by a clash, so you can
    // always free up the name and press Encrypt again. The timer is held for
    // the lifetime of the window; it skips work while an operation is running.
    let conflict_refresh = slint::Timer::default();
    conflict_refresh.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(1000),
        {
            let weak = app.as_weak();
            move || {
                if let Some(app) = weak.upgrade() {
                    if !app.get_is_working() {
                        check_conflicts(&app);
                    }
                }
            }
        },
    );

    app.run().unwrap();
}

fn apply_input_path(
    weak: &slint::Weak<AppWindow>,
    path: PathBuf,
    selected_public_key: &SelectedPublicKey,
) {
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
            // The chosen file could not be read (a damaged encrypted file, or
            // one we cannot open). Clear whatever was selected before, so a
            // failed pick never leaves the previous file ready to run. With no
            // input selected the Start button turns itself off.
            app.set_status_err(elide_error_for_status(&e.to_string()).into());
            app.set_input_path(Default::default());
            app.set_input_path_display(Default::default());
            app.set_output_path(Default::default());
            app.set_output_path_display(Default::default());
            check_conflicts(&app);
            return;
        }
    };
    let is_decrypt = detected_mode.is_some_and(is_decrypt_mode);

    let inpath_elide = if app.get_combined_picker() {
        ELIDE
    } else {
        ELIDE - 8
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
        validate_selected_key(&app, &keypath, selected_public_key);
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
        return elide_path_message("Already exists: ", outpath, "");
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

/// Resets the form after a finished operation or an explicit clear.
///
/// Clearing the retained recipient key alongside the key path and fingerprint
/// keeps the one invariant the key selection rests on: a retained key exists
/// only while the fingerprint describing it is on screen.
fn clear_fields(app: &AppWindow, selected_public_key: &SelectedPublicKey) {
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
    forget_selected_key(app, selected_public_key);
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

/// Left-elides text to at most `max` chars, keeping the right edge visible.
/// Uses character indices so non-ASCII paths stay valid UTF-8.
fn elide_left(text: &str, max: usize) -> String {
    let char_count = text.chars().count();
    if char_count <= max {
        return text.to_string();
    }
    if max == 0 {
        return String::new();
    }
    if max == 1 {
        return "\u{2026}".to_string();
    }

    let keep = max - 1;
    let start = text
        .char_indices()
        .nth(char_count - keep)
        .map(|(idx, _)| idx)
        .unwrap_or(0);
    format!("\u{2026}{}", &text[start..])
}

fn elide_path_message(prefix: &str, path: &str, suffix: &str) -> String {
    let path_budget =
        STATUS_LINE_MAX.saturating_sub(prefix.chars().count() + suffix.chars().count());
    format!("{prefix}{}{suffix}", elide_left(path, path_budget))
}

/// Shortens the path inside status messages such as
/// "Encrypted to /long/path in 1.23 sec" while keeping the whole message within
/// the status-line budget.
fn elide_result_path(msg: &str) -> String {
    let msg = msg.trim();
    for prefix in ["Encrypted to ", "Decrypted to "] {
        if let Some(rest) = msg.strip_prefix(prefix) {
            if let Some((path, duration)) = rest.rsplit_once(" in ") {
                let suffix = format!(" in {duration}");
                return elide_path_message(prefix, path, &suffix);
            }
        }
    }
    for prefix in ["Output file already exists: ", "Output already exists: "] {
        if let Some(path) = msg.strip_prefix(prefix) {
            return elide_path_message(prefix, path, "");
        }
    }
    msg.to_string()
}

/// Bounds an error message to the status line. Known result/conflict prefixes
/// keep their leading text and left-elide the path (via [`elide_result_path`]);
/// any message still longer than [`STATUS_LINE_MAX`] — typically a long OS error string
/// or archive path — is truncated with a trailing `…`. This is UI-only: the
/// library keeps the full message for CLI and library callers.
fn elide_error_for_status(msg: &str) -> String {
    let elided = elide_result_path(msg);
    if elided.chars().count() <= STATUS_LINE_MAX {
        return elided;
    }
    let kept: String = elided.chars().take(STATUS_LINE_MAX - 1).collect();
    format!("{kept}\u{2026}")
}

/// Validates the selected key file for the current mode and updates the UI.
///
/// In recipient-encrypt mode the key is read once here and retained in
/// `selected`, so the fingerprint shown to the user and the key the next
/// encryption uses are the same bytes. Every other outcome clears the
/// retained key, so a stale one can never be reused.
fn validate_selected_key(app: &AppWindow, key_path: &str, selected: &SelectedPublicKey) {
    let key_path = Path::new(key_path);
    match app.get_mode() {
        MODE_RECIPIENT_ENCRYPT => {
            let loaded = PublicKey::from_key_file(key_path)
                .and_then(|key| key.fingerprint().map(|fp| (key, fp)));
            match loaded {
                Ok((key, fp)) => {
                    store_selected_public_key(selected, Some(key));
                    app.set_key_fingerprint(fp.into());
                    app.set_key_invalid(false);
                    app.set_status_err(Default::default());
                }
                Err(e) => {
                    forget_selected_key(app, selected);
                    app.set_key_invalid(true);
                    app.set_status_err(elide_error_for_status(&e.to_string()).into());
                }
            }
        }
        MODE_RECIPIENT_DECRYPT => {
            forget_selected_key(app, selected);
            if let Err(e) = validate_private_key_file(key_path) {
                app.set_key_invalid(true);
                app.set_status_err(elide_error_for_status(&e.to_string()).into());
            } else {
                app.set_key_invalid(false);
                app.set_status_err(Default::default());
            }
        }
        _ => {
            forget_selected_key(app, selected);
            app.set_key_invalid(false);
        }
    }
}

fn detect_mode_from_path(path: &str) -> Result<Option<i32>, ferrocrypt::CryptoError> {
    match probe_recipient_mode(Path::new(path))? {
        Some(UnauthenticatedRecipientMode::Passphrase) => Ok(Some(MODE_PASSPHRASE_DECRYPT)),
        Some(UnauthenticatedRecipientMode::PublicKey) => Ok(Some(MODE_RECIPIENT_DECRYPT)),
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
            MODE_PASSPHRASE_DECRYPT => MODE_PASSPHRASE_ENCRYPT,
            MODE_RECIPIENT_DECRYPT => MODE_RECIPIENT_ENCRYPT,
            _ => old_mode,
        },
    }
}

/// Maps the current mode to the mode `clear_fields` should leave the UI in:
/// decrypt and keygen modes snap back to the encrypt mode of their tab, all
/// other modes are unchanged.
fn snap_back_mode(mode: i32) -> i32 {
    match mode {
        MODE_PASSPHRASE_DECRYPT => MODE_PASSPHRASE_ENCRYPT,
        MODE_RECIPIENT_DECRYPT | MODE_KEYGEN => MODE_RECIPIENT_ENCRYPT,
        _ => mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrocrypt_test_support::{fast_kdf_params, fs_matrix_tempdir};
    use std::fs;

    /// Drives `run_operation` through all five modes plus the two cross-mode
    /// rejections, so the mode routing and its tab-specific messages are
    /// covered without the UI event loop. Fast Argon2id keeps it quick.
    #[test]
    fn run_operation_routes_every_mode() {
        let noop = |_: &ProgressEvent| {};
        let pass = "desktop-dispatch-test-passphrase";
        let dir = fs_matrix_tempdir().expect("tempdir");
        let root = dir.path();
        let payload: &[u8] = b"desktop dispatch payload";
        let input = root.join("secret.txt");
        fs::write(&input, payload).unwrap();
        let dummy_key = Path::new("");

        // Run one operation with fast Argon2id and no explicit save-as path.
        let run = |mode: i32, src: &Path, out: &Path, key: &Path| {
            // Recipient encrypt takes the resolved key, as the UI does once
            // the user has selected it; the other modes carry none.
            let public_key = (mode == MODE_RECIPIENT_ENCRYPT)
                .then(|| PublicKey::from_key_file(key))
                .transpose()?;
            run_operation(
                Operation {
                    mode,
                    input: src,
                    output_dir: out,
                    save_as: None,
                    key_path: key,
                    public_key,
                    kdf_params: Some(fast_kdf_params()),
                },
                Passphrase::new(pass),
                &noop,
            )
        };

        // Passphrase encrypt -> decrypt round-trip.
        let pw_out = root.join("pw_out");
        fs::create_dir_all(&pw_out).unwrap();
        let pw_fcr =
            run(MODE_PASSPHRASE_ENCRYPT, &input, &pw_out, dummy_key).expect("passphrase encrypt");
        let pw_dec = root.join("pw_dec");
        fs::create_dir_all(&pw_dec).unwrap();
        let pw_plain =
            run(MODE_PASSPHRASE_DECRYPT, &pw_fcr, &pw_dec, dummy_key).expect("passphrase decrypt");
        assert_eq!(fs::read(&pw_plain).unwrap(), payload);

        // Key generation writes both key files.
        let keys = root.join("keys");
        fs::create_dir_all(&keys).unwrap();
        let pub_key = run(MODE_KEYGEN, dummy_key, &keys, dummy_key).expect("keygen");
        let priv_key = keys.join(PRIVATE_KEY_FILENAME);
        assert!(pub_key.exists(), "public key not written");
        assert!(priv_key.exists(), "private key not written");

        // Recipient encrypt -> decrypt round-trip.
        let rc_out = root.join("rc_out");
        fs::create_dir_all(&rc_out).unwrap();
        let rc_fcr =
            run(MODE_RECIPIENT_ENCRYPT, &input, &rc_out, &pub_key).expect("recipient encrypt");
        let rc_dec = root.join("rc_dec");
        fs::create_dir_all(&rc_dec).unwrap();
        let rc_plain =
            run(MODE_RECIPIENT_DECRYPT, &rc_fcr, &rc_dec, &priv_key).expect("recipient decrypt");
        assert_eq!(fs::read(&rc_plain).unwrap(), payload);

        // Cross-mode routing: a recipient-sealed file is rejected on the
        // passphrase path, and a passphrase-sealed file on the recipient path,
        // each with its tab-specific message.
        let x1 = root.join("x1");
        fs::create_dir_all(&x1).unwrap();
        let e1 = run(MODE_PASSPHRASE_DECRYPT, &rc_fcr, &x1, dummy_key)
            .expect_err("passphrase path must reject a recipient file");
        assert!(
            matches!(&e1, CryptoError::InvalidInput(m) if m.contains("public-key recipients")),
            "unexpected error: {e1:?}"
        );

        let x2 = root.join("x2");
        fs::create_dir_all(&x2).unwrap();
        let e2 = run(MODE_RECIPIENT_DECRYPT, &pw_fcr, &x2, &priv_key)
            .expect_err("recipient path must reject a passphrase file");
        assert!(
            matches!(&e2, CryptoError::InvalidInput(m) if m.contains("sealed with a passphrase")),
            "unexpected error: {e2:?}"
        );
    }

    /// Recipient encrypt must use the key it was handed, not whatever key file
    /// sits at `key_path`. That binding is what makes the fingerprint shown
    /// when the user picked the key describe the file actually produced: the
    /// UI resolves the key once at selection and passes the value here. The
    /// test proves it by handing over key A while `key_path` points at key B,
    /// and pins the refusal when no key was retained at all.
    #[test]
    fn recipient_encrypt_uses_the_retained_key_not_the_key_path() {
        let noop = |_: &ProgressEvent| {};
        let pass = "desktop-retained-key-passphrase";
        let dir = fs_matrix_tempdir().expect("tempdir");
        let root = dir.path();
        let payload: &[u8] = b"bound to the retained key";
        let input = root.join("secret.txt");
        fs::write(&input, payload).unwrap();
        let dummy_key = Path::new("");

        let run = |mode: i32, src: &Path, out: &Path, key: &Path, public_key: Option<PublicKey>| {
            run_operation(
                Operation {
                    mode,
                    input: src,
                    output_dir: out,
                    save_as: None,
                    key_path: key,
                    public_key,
                    kdf_params: Some(fast_kdf_params()),
                },
                Passphrase::new(pass),
                &noop,
            )
        };

        let keys_a = root.join("keys_a");
        let keys_b = root.join("keys_b");
        fs::create_dir_all(&keys_a).unwrap();
        fs::create_dir_all(&keys_b).unwrap();
        let pub_a = run(MODE_KEYGEN, dummy_key, &keys_a, dummy_key, None).expect("keygen A");
        let pub_b = run(MODE_KEYGEN, dummy_key, &keys_b, dummy_key, None).expect("keygen B");

        // Key A is handed over; `key_path` points at B's public key.
        let retained = PublicKey::from_key_file(&pub_a).expect("read A's public key");
        let out_dir = root.join("out");
        fs::create_dir_all(&out_dir).unwrap();
        let fcr = run(
            MODE_RECIPIENT_ENCRYPT,
            &input,
            &out_dir,
            &pub_b,
            Some(retained),
        )
        .expect("recipient encrypt");

        let restored = root.join("restored");
        fs::create_dir_all(&restored).unwrap();
        let plain = run(
            MODE_RECIPIENT_DECRYPT,
            &fcr,
            &restored,
            &keys_a.join(PRIVATE_KEY_FILENAME),
            None,
        )
        .expect("A's private key must decrypt the output");
        assert_eq!(fs::read(&plain).unwrap(), payload);

        let restored_b = root.join("restored_b");
        fs::create_dir_all(&restored_b).unwrap();
        assert!(
            run(
                MODE_RECIPIENT_DECRYPT,
                &fcr,
                &restored_b,
                &keys_b.join(PRIVATE_KEY_FILENAME),
                None,
            )
            .is_err(),
            "the key at key_path must not be able to read the output"
        );

        // No key retained: refuse rather than fall back to reading `key_path`.
        let out_none = root.join("out_none");
        fs::create_dir_all(&out_none).unwrap();
        let err = run(MODE_RECIPIENT_ENCRYPT, &input, &out_none, &pub_a, None)
            .expect_err("recipient encrypt without a retained key must be refused");
        assert!(
            matches!(&err, CryptoError::InvalidInput(m) if m.contains("Select a public key file")),
            "unexpected error: {err:?}"
        );
    }

    /// The magic-byte auto-detection that routes a dropped/selected file to
    /// the right decrypt tab. A swap of the two `Some(_)` arms would send
    /// every passphrase file to the key-pair tab and vice versa — a total
    /// workflow break that no other test catches, since the arms are pure
    /// mapping with no round-trip. This pins each probe outcome to its UI
    /// mode. The library's own probe classification is unit-tested; here we
    /// pin the desktop mapping on top of it.
    #[test]
    fn detect_mode_from_path_maps_every_probe_outcome() {
        let noop = |_: &ProgressEvent| {};
        let pass = "desktop-detect-passphrase";
        let dir = fs_matrix_tempdir().expect("tempdir");
        let root = dir.path();
        let input = root.join("secret.txt");
        fs::write(&input, b"detect payload").unwrap();
        let dummy_key = Path::new("");

        let run = |mode: i32, src: &Path, out: &Path, key: &Path| {
            // Recipient encrypt takes the resolved key, as the UI does once
            // the user has selected it; the other modes carry none.
            let public_key = (mode == MODE_RECIPIENT_ENCRYPT)
                .then(|| PublicKey::from_key_file(key))
                .transpose()?;
            run_operation(
                Operation {
                    mode,
                    input: src,
                    output_dir: out,
                    save_as: None,
                    key_path: key,
                    public_key,
                    kdf_params: Some(fast_kdf_params()),
                },
                Passphrase::new(pass),
                &noop,
            )
        };

        // A passphrase-sealed file routes to the passphrase-decrypt mode.
        let pw_out = root.join("pw_out");
        fs::create_dir_all(&pw_out).unwrap();
        let pw_fcr = run(MODE_PASSPHRASE_ENCRYPT, &input, &pw_out, dummy_key).expect("pw encrypt");
        assert_eq!(
            detect_mode_from_path(pw_fcr.to_str().unwrap()).unwrap(),
            Some(MODE_PASSPHRASE_DECRYPT)
        );

        // A recipient-sealed file routes to the recipient-decrypt mode.
        let keys = root.join("keys");
        fs::create_dir_all(&keys).unwrap();
        let pub_key = run(MODE_KEYGEN, dummy_key, &keys, dummy_key).expect("keygen");
        let rc_out = root.join("rc_out");
        fs::create_dir_all(&rc_out).unwrap();
        let rc_fcr = run(MODE_RECIPIENT_ENCRYPT, &input, &rc_out, &pub_key).expect("rc encrypt");
        assert_eq!(
            detect_mode_from_path(rc_fcr.to_str().unwrap()).unwrap(),
            Some(MODE_RECIPIENT_DECRYPT)
        );

        // A plaintext file and an empty file are not FerroCrypt payloads, so
        // detection returns None (the UI then treats them as encrypt input).
        assert_eq!(
            detect_mode_from_path(input.to_str().unwrap()).unwrap(),
            None
        );
        let empty = root.join("empty.bin");
        fs::write(&empty, b"").unwrap();
        assert_eq!(
            detect_mode_from_path(empty.to_str().unwrap()).unwrap(),
            None
        );

        // A missing path is an error (the UI surfaces it rather than
        // switching modes).
        let missing = root.join("does-not-exist.fcr");
        assert!(detect_mode_from_path(missing.to_str().unwrap()).is_err());

        // A directory must never be classified as a decryptable file,
        // whichever way the library reports it (error or None).
        assert!(
            !matches!(detect_mode_from_path(root.to_str().unwrap()), Ok(Some(_))),
            "a directory must not be offered as a decrypt mode"
        );
    }

    /// Both `save_as` branches of `run_operation`, which the dispatch test
    /// never exercises (it always passes `save_as: None`). Covers the
    /// "Choose output file" flow: a fresh path is honoured exactly, and a
    /// pre-existing target is rejected without being overwritten. The
    /// rejection also pins the "already exists" wording the desktop status
    /// line relies on when it elides that message by prefix.
    #[test]
    fn run_operation_save_as_writes_exact_path_and_rejects_existing() {
        let noop = |_: &ProgressEvent| {};
        let pass = "desktop-save-as-passphrase";
        let dir = fs_matrix_tempdir().expect("tempdir");
        let root = dir.path();
        let payload: &[u8] = b"desktop save-as payload";
        let input = root.join("secret.txt");
        fs::write(&input, payload).unwrap();
        let dummy_key = Path::new("");
        let out_dir = root.join("out");
        fs::create_dir_all(&out_dir).unwrap();

        // Fresh save_as path: the returned path is exactly the chosen one,
        // the file exists there, and it round-trips back to the payload.
        let target = out_dir.join("chosen-name.fcr");
        let produced = run_operation(
            Operation {
                mode: MODE_PASSPHRASE_ENCRYPT,
                input: &input,
                output_dir: &out_dir,
                save_as: Some(&target),
                key_path: dummy_key,
                public_key: None,
                kdf_params: Some(fast_kdf_params()),
            },
            Passphrase::new(pass),
            &noop,
        )
        .expect("save_as encrypt");
        assert_eq!(
            produced, target,
            "save_as must produce exactly the chosen path"
        );
        assert!(target.exists());

        let dec_dir = root.join("dec");
        fs::create_dir_all(&dec_dir).unwrap();
        let plain = run_operation(
            Operation {
                mode: MODE_PASSPHRASE_DECRYPT,
                input: &target,
                output_dir: &dec_dir,
                save_as: None,
                key_path: dummy_key,
                public_key: None,
                kdf_params: Some(fast_kdf_params()),
            },
            Passphrase::new(pass),
            &noop,
        )
        .expect("decrypt save_as output");
        assert_eq!(fs::read(&plain).unwrap(), payload);

        // save_as onto an existing file: rejected no-clobber, existing file
        // left byte-intact.
        let occupied = out_dir.join("occupied.fcr");
        let sentinel: &[u8] = b"pre-existing bytes";
        fs::write(&occupied, sentinel).unwrap();
        let err = run_operation(
            Operation {
                mode: MODE_PASSPHRASE_ENCRYPT,
                input: &input,
                output_dir: &out_dir,
                save_as: Some(&occupied),
                key_path: dummy_key,
                public_key: None,
                kdf_params: Some(fast_kdf_params()),
            },
            Passphrase::new(pass),
            &noop,
        )
        .expect_err("save_as onto an existing file must be rejected");
        assert!(
            err.to_string().contains("already exists"),
            "expected an already-exists rejection (the desktop status line elides \
             this message by its 'Output file already exists:' prefix); got: {err}"
        );
        assert_eq!(
            fs::read(&occupied).unwrap(),
            sentinel,
            "a rejected save_as must not overwrite the existing file"
        );
    }

    #[test]
    fn encrypt_decrypt_mode_predicates() {
        assert!(is_encrypt_mode(MODE_PASSPHRASE_ENCRYPT));
        assert!(is_encrypt_mode(MODE_RECIPIENT_ENCRYPT));
        assert!(!is_encrypt_mode(MODE_PASSPHRASE_DECRYPT));
        assert!(!is_encrypt_mode(MODE_RECIPIENT_DECRYPT));
        assert!(!is_encrypt_mode(MODE_KEYGEN));

        assert!(is_decrypt_mode(MODE_PASSPHRASE_DECRYPT));
        assert!(is_decrypt_mode(MODE_RECIPIENT_DECRYPT));
        assert!(!is_decrypt_mode(MODE_PASSPHRASE_ENCRYPT));
        assert!(!is_decrypt_mode(MODE_RECIPIENT_ENCRYPT));
        assert!(!is_decrypt_mode(MODE_KEYGEN));
    }

    #[test]
    fn next_mode_adopts_detected_mode() {
        assert_eq!(
            next_mode(MODE_PASSPHRASE_ENCRYPT, Some(MODE_RECIPIENT_DECRYPT)),
            MODE_RECIPIENT_DECRYPT
        );
        assert_eq!(
            next_mode(MODE_RECIPIENT_ENCRYPT, Some(MODE_PASSPHRASE_DECRYPT)),
            MODE_PASSPHRASE_DECRYPT
        );
    }

    #[test]
    fn next_mode_flips_decrypt_back_to_encrypt_when_not_detected() {
        assert_eq!(
            next_mode(MODE_PASSPHRASE_DECRYPT, None),
            MODE_PASSPHRASE_ENCRYPT
        );
        assert_eq!(
            next_mode(MODE_RECIPIENT_DECRYPT, None),
            MODE_RECIPIENT_ENCRYPT
        );
    }

    #[test]
    fn next_mode_keeps_non_decrypt_modes_when_not_detected() {
        assert_eq!(
            next_mode(MODE_PASSPHRASE_ENCRYPT, None),
            MODE_PASSPHRASE_ENCRYPT
        );
        assert_eq!(
            next_mode(MODE_RECIPIENT_ENCRYPT, None),
            MODE_RECIPIENT_ENCRYPT
        );
        assert_eq!(next_mode(MODE_KEYGEN, None), MODE_KEYGEN);
    }

    #[test]
    fn snap_back_mode_folds_decrypt_and_keygen_to_tab_encrypt() {
        assert_eq!(
            snap_back_mode(MODE_PASSPHRASE_DECRYPT),
            MODE_PASSPHRASE_ENCRYPT
        );
        assert_eq!(
            snap_back_mode(MODE_RECIPIENT_DECRYPT),
            MODE_RECIPIENT_ENCRYPT
        );
        assert_eq!(snap_back_mode(MODE_KEYGEN), MODE_RECIPIENT_ENCRYPT);
    }

    #[test]
    fn snap_back_mode_leaves_encrypt_modes_alone() {
        assert_eq!(
            snap_back_mode(MODE_PASSPHRASE_ENCRYPT),
            MODE_PASSPHRASE_ENCRYPT
        );
        assert_eq!(
            snap_back_mode(MODE_RECIPIENT_ENCRYPT),
            MODE_RECIPIENT_ENCRYPT
        );
    }

    #[test]
    fn conflict_warning_empty_when_no_output_path() {
        let w = compute_conflict_warning(MODE_PASSPHRASE_ENCRYPT, "", "", false, false, false);
        assert!(w.is_empty());
    }

    #[test]
    fn conflict_warning_empty_when_encrypt_output_missing() {
        let w = compute_conflict_warning(
            MODE_RECIPIENT_ENCRYPT,
            "/tmp/out.fcr",
            "",
            false,
            false,
            false,
        );
        assert!(w.is_empty());
    }

    #[test]
    fn conflict_warning_flags_existing_encrypt_output() {
        let w = compute_conflict_warning(
            MODE_PASSPHRASE_ENCRYPT,
            "/tmp/out.fcr",
            "",
            true,
            false,
            false,
        );
        assert_eq!(w, "Already exists: /tmp/out.fcr");

        let w = compute_conflict_warning(
            MODE_RECIPIENT_ENCRYPT,
            "/tmp/out.fcr",
            "",
            true,
            false,
            false,
        );
        assert_eq!(w, "Already exists: /tmp/out.fcr");
    }

    #[test]
    fn conflict_warning_ignores_existing_decrypt_output() {
        // Decrypt modes must never block on output existence — the library's
        // atomic output handling is authoritative, and the output path in
        // decrypt mode is a directory.
        for mode in [MODE_PASSPHRASE_DECRYPT, MODE_RECIPIENT_DECRYPT] {
            let w = compute_conflict_warning(mode, "/tmp/out", "", true, false, false);
            assert!(w.is_empty(), "mode {} unexpectedly warned", mode);
        }
    }

    #[test]
    fn conflict_warning_elides_long_encrypt_paths() {
        let long = format!("/tmp/{}", "a".repeat(80));
        let w = compute_conflict_warning(MODE_PASSPHRASE_ENCRYPT, &long, "", true, false, false);
        assert!(w.starts_with("Already exists: \u{2026}"), "got: {}", w);
        assert!(w.chars().count() <= STATUS_LINE_MAX, "got: {w}");
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
        assert_eq!(out.chars().count(), 52);
        // 51 'a's preserved + one ellipsis char.
        assert_eq!(out.chars().filter(|c| *c == 'a').count(), 51);
    }

    #[test]
    fn elide_left_respects_multibyte_boundaries() {
        let s = "é".repeat(60);
        let out = elide_left(&s, 52);
        assert!(out.is_char_boundary(out.len()));
        assert!(out.starts_with('\u{2026}'));
        assert_eq!(out.chars().count(), 52);
        assert_eq!(out.chars().filter(|c| *c == 'é').count(), 51);
    }

    #[test]
    fn elide_left_handles_tiny_budgets() {
        assert_eq!(elide_left("abcdef", 0), "");
        assert_eq!(elide_left("abcdef", 1), "\u{2026}");
    }

    #[test]
    fn elide_result_path_shortens_encrypted_to_message() {
        let long = "a".repeat(200);
        let msg = format!("Encrypted to /tmp/{long} in 1.23 sec");
        let out = elide_result_path(&msg);
        assert!(out.starts_with("Encrypted to "));
        assert!(out.ends_with(" in 1.23 sec"));
        assert!(out.contains('\u{2026}'));
        assert!(out.chars().count() <= STATUS_LINE_MAX, "got: {out}");
    }

    /// A decrypt whose destination folder changed under it reports the
    /// output's name and then the folder. The status line drops the tail
    /// of anything too long, so the name — the only part the operator can
    /// act on, the folder no longer holding the output — must survive
    /// that trim.
    #[test]
    fn output_directory_changed_keeps_the_output_name_in_the_status_line() {
        let long = "c".repeat(200);
        let msg = format!("Output report.pdf is complete but its directory changed: /tmp/{long}");

        let out = elide_error_for_status(&msg);

        assert!(out.chars().count() <= STATUS_LINE_MAX, "got: {out}");
        assert!(
            out.contains("Output report.pdf is complete"),
            "the trim must keep the output's name, got: {out}"
        );
    }

    #[test]
    fn elide_result_path_shortens_decrypted_to_message() {
        let long = "b".repeat(200);
        let msg = format!("Decrypted to /tmp/{long} in 0.50 sec");
        let out = elide_result_path(&msg);
        assert!(out.starts_with("Decrypted to "));
        assert!(out.ends_with(" in 0.50 sec"));
        assert!(out.contains('\u{2026}'));
        assert!(out.chars().count() <= STATUS_LINE_MAX, "got: {out}");
    }

    #[test]
    fn elide_result_path_shortens_output_conflict_messages() {
        let long = "c".repeat(200);
        for prefix in ["Output file already exists: ", "Output already exists: "] {
            let msg = format!("{prefix}/tmp/{long}");
            let out = elide_result_path(&msg);
            assert!(out.starts_with(prefix));
            assert!(out.contains('\u{2026}'));
            assert!(out.chars().count() <= STATUS_LINE_MAX, "got: {out}");
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
    fn elide_error_for_status_passes_messages_within_budget() {
        let msg = "Decryption failed: wrong passphrase or modified file";
        assert!(msg.chars().count() <= STATUS_LINE_MAX);
        assert_eq!(elide_error_for_status(msg), msg);
    }

    #[test]
    fn elide_error_for_status_keeps_full_64_char_message() {
        let msg = "Private key unlock failed: wrong passphrase or modified key file";
        assert_eq!(msg.chars().count(), 64);
        assert_eq!(elide_error_for_status(msg), msg);
    }

    #[test]
    fn elide_error_for_status_truncates_long_unknown_messages() {
        let long = format!("Unsafe archive path (traversal): /tmp/{}", "d".repeat(200));
        let out = elide_error_for_status(&long);
        assert!(out.chars().count() <= STATUS_LINE_MAX);
        assert!(out.ends_with('\u{2026}'));
        assert!(out.starts_with("Unsafe archive path"));
    }

    #[test]
    fn elide_error_for_status_bounds_known_prefix_messages() {
        let long = format!("Output already exists: /tmp/{}", "e".repeat(200));
        let out = elide_error_for_status(&long);
        assert!(out.chars().count() <= STATUS_LINE_MAX);
        assert!(out.contains('\u{2026}'));
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
