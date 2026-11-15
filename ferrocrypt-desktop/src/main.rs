// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

slint::include_modules!();

use ferrocrypt::Passphrase;
use ferrocrypt::{
    CryptoError, Decryptor, Encryptor, KdfLimit, KdfParams, KeyPairGenerator, PRIVATE_KEY_FILENAME,
    PUBLIC_KEY_FILENAME, PrivateKey, ProgressEvent, PublicKey, UnauthenticatedRecipientMode,
    default_encrypted_filename, escape_path_for_display, generate_key_pair, probe_recipient_mode,
    validate_private_key_file,
};
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

#[cfg(feature = "mcp")]
mod automation;
#[cfg(all(unix, not(target_vendor = "apple")))]
mod own_frame;
mod password_scorer;

/// The recipient key resolved at the moment the user selected it, shared
/// between the key-selection callbacks and the operation launcher.
///
/// Keeping the resolved key rather than its path is what gives the displayed
/// fingerprint meaning: encryption uses this value, so a key file replaced
/// after selection cannot change the recipient behind the user's back.
type SelectedPublicKey = Arc<Mutex<Option<PublicKey>>>;

/// Locks the retained recipient key. A poisoned lock is recovered: the
/// slot holds plain data no panic can leave half-written, and applying
/// every store is what keeps each clearing path effective, so a retained
/// key can never outlive the fingerprint describing it, and the slot always
/// holds the last selection or clearing.
fn lock_selected_public_key(selected: &SelectedPublicKey) -> MutexGuard<'_, Option<PublicKey>> {
    selected.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Replaces the retained recipient key.
fn store_selected_public_key(selected: &SelectedPublicKey, key: Option<PublicKey>) {
    *lock_selected_public_key(selected) = key;
}

/// Reads the retained recipient key for one operation.
fn take_selected_public_key(selected: &SelectedPublicKey) -> Option<PublicKey> {
    lock_selected_public_key(selected).clone()
}

/// Whether a recipient key is retained.
fn has_selected_public_key(selected: &SelectedPublicKey) -> bool {
    lock_selected_public_key(selected).is_some()
}

/// Drops the retained recipient key together with the fingerprint describing
/// it.
///
/// The two always move together, and only recipient encryption uses the key,
/// in the one mode that shows the fingerprint. A key retained without its
/// fingerprint could be encrypted to without the user seeing which key it
/// is, so every path that clears one clears the other through this function.
fn forget_selected_key(app: &AppWindow, selected: &SelectedPublicKey) {
    store_selected_public_key(selected, None);
    show_fingerprint(app, "");
}

/// A zero-width space: invisible, but a place where a line may break.
const LINE_BREAK_OPPORTUNITY: char = '\u{200b}';

/// Shows `fingerprint` in the fingerprint field; an empty one hides the field.
///
/// The field shows it with a line break opportunity halfway through. Digits
/// differ in width, so a fingerprint made mostly of wide ones does not fit on
/// one line; it then shows as two equal halves rather than losing its end,
/// which the user needs to compare it.
fn show_fingerprint(app: &AppWindow, fingerprint: &str) {
    // A fingerprint is ASCII hex, so its middle byte is a character boundary.
    let display = match fingerprint.split_at_checked(fingerprint.len() / 2) {
        Some((first, second)) if !first.is_empty() => {
            format!("{first}{LINE_BREAK_OPPORTUNITY}{second}")
        }
        _ => fingerprint.to_string(),
    };
    app.set_key_fingerprint(fingerprint.into());
    app.set_key_fingerprint_display(display.into());
}

/// Width budget for a path shown in a form field (narrower: a picker button shares the row).
const ELIDE: usize = 44;

/// Width budget for one status line (wider, no button): two chars above the
/// library's 64-char message budget, so a full-length library message always
/// renders verbatim and only longer variable text (OS errors, paths) is elided.
const STATUS_LINE_MAX: usize = 66;

/// Character budget for an error, in multiples of [`STATUS_LINE_MAX`]. The
/// status bar wraps its text and rises into the free space above it, so an
/// error keeps the path that says which entry was refused instead of losing
/// it to a one-line cut. Narrow glyphs can wrap the full budget onto one
/// more line than this number; every mode that can show an archive-path
/// error has room for that. Create key pair has room for less, so there the
/// bar shows the first lines and ends the last one shown in "…".
const STATUS_ERROR_LINES: usize = 3;

/// Character budget for an error or a warning in the status bar.
const STATUS_ERROR_BUDGET: usize = STATUS_LINE_MAX * STATUS_ERROR_LINES;

/// Ends the warning about a source that opens like an encrypted file but
/// cannot be decrypted.
const ORDINARY_FILE_NOTE: &str = "; encrypting treats it as an ordinary file";

/// Ends that warning instead when the encrypted file would take the source's
/// own name, which is taken.
const OWN_NAME_NOTE: &str = "; to encrypt it as an ordinary file, choose another name";

// Each note is ASCII, so its length in bytes is its length in characters, and
// leaves room for a reason before it.
const _: () =
    assert!(ORDINARY_FILE_NOTE.is_ascii() && ORDINARY_FILE_NOTE.len() < STATUS_ERROR_BUDGET);
const _: () = assert!(OWN_NAME_NOTE.is_ascii() && OWN_NAME_NOTE.len() < STATUS_ERROR_BUDGET);

/// The `progress` value in app.slint while the share of the file handled is
/// not known.
const NO_PROGRESS: f32 = -1.0;

/// Status once every byte of the file is handled: the flush to disk and the
/// final rename still follow.
const FINISHING: &str = "Finishing\u{2026}";

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

/// Decrypt acceptance envelope for the GUI. Memory stays at the
/// library's default cap; the combined-work cap is raised to what that
/// memory cap already admits at the format's maximum pass count. That
/// equals what earlier releases accepted by default, so a file the
/// previous desktop version decrypted still decrypts — the GUI, unlike
/// the CLI's `--max-kdf-work`, has no per-run override to raise.
fn desktop_kdf_limit() -> KdfLimit {
    KdfLimit::default().max_work(
        u64::from(KdfLimit::MEM_COST_KIB_DEFAULT) * u64::from(KdfLimit::TIME_COST_STRUCTURAL_MAX),
    )
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
                .kdf_limit(desktop_kdf_limit())
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
                .kdf_limit(desktop_kdf_limit())
                .decrypt(
                    PrivateKey::from_key_file(key_path, passphrase),
                    output_dir,
                    on_event,
                )
                .map(|o| o.output_path),
            Ok(Decryptor::Passphrase(_)) => Err(CryptoError::InvalidInput(
                "This file is sealed with a password; switch to the 'Password' tab".to_string(),
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

/// The file dialog builder.
///
/// On Linux, and on the other desktops rfd serves through the XDG portal, the
/// dialog runs in a separate process. Waiting for it inside a UI callback
/// freezes the window until it closes, and GNOME then reports the app as not
/// responding, so there the dialog is the asynchronous one, awaited on the
/// event loop. macOS and Windows keep the window responsive while a blocking
/// dialog is open, so they keep the blocking one.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
type FileDialog = rfd::AsyncFileDialog;
#[cfg(any(target_os = "macos", target_os = "windows"))]
type FileDialog = rfd::FileDialog;

#[cfg(target_os = "macos")]
fn pick_file_or_folder(dialog: FileDialog) -> Option<PathBuf> {
    dialog.pick_file_or_folder()
}

#[cfg(target_os = "windows")]
fn pick_file_or_folder(dialog: FileDialog) -> Option<PathBuf> {
    dialog.pick_file()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn pick_file_or_folder(dialog: FileDialog) -> impl Future<Output = Option<rfd::FileHandle>> {
    dialog.pick_file()
}

/// Opens a file dialog and passes the chosen path to `on_pick` once the
/// dialog closes, without blocking the event loop.
///
/// The dialog is not attached to the window, so the form stays usable while
/// it is open. A choice that arrives while an operation runs is dropped: the
/// controls that open a dialog are disabled during an operation, so that
/// dialog was opened before it started.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn open_dialog<F>(
    app: &AppWindow,
    open: impl FnOnce(FileDialog) -> F,
    on_pick: impl FnOnce(&AppWindow, PathBuf) + 'static,
) where
    F: Future<Output = Option<rfd::FileHandle>> + 'static,
{
    #[cfg(feature = "mcp")]
    let Some(on_pick) = automation::answer_dialog(app, on_pick) else {
        return;
    };

    let chosen = open(FileDialog::new());
    let weak = app.as_weak();
    // Fails only without a running event loop, and UI callbacks run inside one.
    let _ = slint::spawn_local(async move {
        let Some(file) = chosen.await else { return };
        let Some(app) = weak.upgrade() else { return };
        if !app.get_is_working() {
            on_pick(&app, file.path().to_path_buf());
        }
    });
}

/// Opens a file dialog and passes the chosen path to `on_pick`, blocking
/// until the dialog closes.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn open_dialog(
    app: &AppWindow,
    open: impl FnOnce(FileDialog) -> Option<PathBuf>,
    on_pick: impl FnOnce(&AppWindow, PathBuf),
) {
    #[cfg(feature = "mcp")]
    let Some(on_pick) = automation::answer_dialog(app, on_pick) else {
        return;
    };

    if let Some(path) = open(FileDialog::new()) {
        on_pick(app, path);
    }
}

fn main() {
    let app = AppWindow::new().unwrap();
    // Without an app ID the Linux desktop names the window "Unknown". The
    // `.deb` package's `.desktop` entry is named after the binary, so this ID
    // gives the window that entry's name and icon.
    let _ = slint::set_xdg_app_id(env!("CARGO_BIN_NAME"));

    // Show the library version (the one cargo-release bumps) rather than this
    // crate's own, so the displayed version can't silently drift from a release.
    app.set_app_version(ferrocrypt::VERSION.into());
    app.set_combined_picker(cfg!(target_os = "macos"));
    // Slint fills the X11 or Wayland selection clipboard only on these targets.
    app.set_selection_clipboard(cfg!(all(unix, not(target_vendor = "apple"))));
    #[cfg(all(unix, not(target_vendor = "apple")))]
    own_frame::install(&app);

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
                show_key_for_mode(&app, &selected_public_key);
                check_conflicts(&app);
            }
        }
    });

    app.on_select_input_file({
        let weak = app.as_weak();
        let selected_public_key = selected_public_key.clone();
        move || {
            let Some(app) = weak.upgrade() else { return };
            let selected_public_key = selected_public_key.clone();
            open_dialog(&app, pick_file_or_folder, move |app, path| {
                apply_input_path(app, path, &selected_public_key);
            });
        }
    });

    app.on_select_input_folder({
        let weak = app.as_weak();
        let selected_public_key = selected_public_key.clone();
        move || {
            let Some(app) = weak.upgrade() else { return };
            let selected_public_key = selected_public_key.clone();
            open_dialog(
                &app,
                |dialog| dialog.pick_folder(),
                move |app, path| {
                    apply_input_path(app, path, &selected_public_key);
                },
            );
        }
    });

    app.on_select_key_file({
        let weak = app.as_weak();
        let selected_public_key = selected_public_key.clone();
        move || {
            let Some(app) = weak.upgrade() else { return };
            let selected_public_key = selected_public_key.clone();
            // The dialog may close after the mode has changed, when its
            // answer no longer applies.
            let mode = app.get_mode();
            open_dialog(
                &app,
                |dialog| dialog.add_filter("Key files", &["key"]).pick_file(),
                move |app, path| {
                    apply_key_path(app, path, mode, &selected_public_key);
                },
            );
        }
    });

    app.on_select_output_dir({
        let weak = app.as_weak();
        move || {
            let Some(app) = weak.upgrade() else { return };
            open_dialog(
                &app,
                |dialog| dialog.pick_folder(),
                |app, path| {
                    update_output_path(app, &path_to_string(&path));
                    clear_stale_status(app);
                },
            );
        }
    });

    app.on_select_output_file({
        let weak = app.as_weak();
        move || {
            let Some(app) = weak.upgrade() else { return };
            let inpath = app.get_input_path().to_string();
            let file_name = default_encrypted_filename(&inpath).ok();
            let outpath = app.get_output_path().to_string();
            let directory = parent_dir(&outpath);

            open_dialog(
                &app,
                move |mut dialog| {
                    if let Some(name) = file_name {
                        dialog = dialog.set_file_name(name);
                    }
                    if let Some(parent) = directory {
                        dialog = dialog.set_directory(parent);
                    }
                    dialog.save_file()
                },
                |app, path| {
                    update_output_path(app, &path_to_string(&path));
                    clear_stale_status(app);
                },
            );
        }
    });

    app.on_select_keygen_output_dir({
        let weak = app.as_weak();
        move || {
            let Some(app) = weak.upgrade() else { return };
            open_dialog(
                &app,
                |dialog| dialog.pick_folder(),
                |app, path| {
                    let dir = path_to_string(&path);
                    app.set_keygen_output_dir_display(elide_path(&dir, ELIDE).into());
                    app.set_keygen_output_dir(dir.into());
                    clear_stale_status(app);
                    check_conflicts(app);
                },
            );
        }
    });

    app.on_password_edited({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                app.set_password_strength(password_scorer::password_strength(
                    app.get_password().as_str(),
                ));
                clear_stale_status(&app);
            }
        }
    });

    app.on_form_edited({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                clear_stale_status(&app);
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
            app.set_progress(NO_PROGRESS);
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
                            let (status, progress) = progress_display(event);
                            let weak = weak.clone();
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Some(app) = weak.upgrade() {
                                    if let Some(status) = status {
                                        app.set_status_ok(status.into());
                                    }
                                    app.set_progress(progress);
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
                        app.set_progress(NO_PROGRESS);

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
                                    // A private key chosen before belongs to
                                    // another pair, so the user chooses again.
                                    choose_public_key(&app, &pub_key, &selected_public_key);
                                    app.set_chosen_private_key_path(Default::default());
                                    show_key_for_mode(&app, &selected_public_key);
                                    app.set_status_ok(
                                        "Key pair generated \u{2014} public key selected".into(),
                                    );
                                } else {
                                    clear_after_operation(&app, mode, &selected_public_key);

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

                        // Starting cleared the warnings; bring back those
                        // that still hold.
                        check_conflicts(&app);
                    });
                }));

                if result.is_err() {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(app) = panic_weak.upgrade() {
                            app.set_is_working(false);
                            app.set_progress(NO_PROGRESS);
                            app.set_status_ok("".into());
                            app.set_status_err(
                                "Operation failed unexpectedly (internal error)".into(),
                            );
                            check_conflicts(&app);
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
                    // Said in the status bar too, so a screen reader reads it.
                    if clipboard.set_text(fp).is_ok() {
                        app.set_status_ok("Fingerprint copied".into());
                    }
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

fn apply_input_path(app: &AppWindow, path: PathBuf, selected_public_key: &SelectedPublicKey) {
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

    let (detected_mode, input_reason) = match detect_mode_from_path(&selected) {
        Ok(mode) => (mode, String::new()),
        Err(e @ (CryptoError::Io(_) | CryptoError::InputPath | CryptoError::InvalidInput(_))) => {
            // The path could not be read, or is not a file or folder. Clear
            // whatever was selected before, so a failed pick never leaves the
            // previous file ready to run. With no input selected the Start
            // button turns itself off.
            app.set_status_err(elide_error_for_status(&e.to_string()).into());
            app.set_input_path(Default::default());
            app.set_input_path_display(Default::default());
            app.set_input_reason(Default::default());
            app.set_output_path(Default::default());
            app.set_output_path_display(Default::default());
            check_conflicts(app);
            return;
        }
        // The file opens like an encrypted file but cannot be decrypted here:
        // damaged, from a newer FerroCrypt, over this app's limits, or an
        // ordinary file that happens to start with the same bytes. It can
        // still be encrypted, which reads it as opaque bytes and trusts
        // nothing in it, but never without a warning that says why, so an
        // encrypted file is not encrypted again unnoticed. A private key
        // needs no warning: encrypting it is an ordinary thing to do.
        Err(_) if validate_private_key_file(Path::new(&selected)).is_ok() => (None, String::new()),
        Err(e) => (None, e.to_string()),
    };
    let is_decrypt = detected_mode.is_some_and(is_decrypt_mode);

    let inpath_elide = if app.get_combined_picker() {
        ELIDE
    } else {
        ELIDE - 8
    };
    app.set_input_path_display(elide_path(&selected, inpath_elide).into());
    app.set_input_path(selected.clone().into());
    app.set_input_reason(input_reason.into());
    let old_mode = app.get_mode();
    let new_mode = next_mode(old_mode, detected_mode);
    let mode_changed = new_mode != old_mode;
    if mode_changed {
        app.set_mode(new_mode);
        app.set_password(Default::default());
        app.set_password_repeated(Default::default());
        app.set_hide_password(true);
        app.set_password_strength(password_scorer::PW_EMPTY);
    }

    show_key_for_mode(app, selected_public_key);

    if is_decrypt {
        update_output_path(app, &dir);
    } else if let Ok(filename) = default_encrypted_filename(&selected) {
        update_output_path(app, &path_to_string(&Path::new(&dir).join(filename)));
    } else {
        // No output name follows from this source, so none from the last one
        // may stay.
        update_output_path(app, "");
    }

    clear_stale_status(app);
}

/// The warning for a source that opens like an encrypted file but cannot be
/// decrypted, for the `reason` given, ending in `note`. A long `reason` is
/// cut, so the note always fits.
fn source_warning(reason: &str, note: &str) -> String {
    let budget = STATUS_ERROR_BUDGET - note.chars().count();
    format!("{}{note}", elide_end(reason, budget))
}

/// Clears the last operation's result once the user changes the form. An
/// error about the selected key stays: it still applies, and it is what
/// explains the disabled action button.
fn clear_stale_status(app: &AppWindow) {
    if !app.get_key_invalid() {
        app.set_status_ok(Default::default());
        app.set_status_err(Default::default());
    }
}

fn update_output_path(app: &AppWindow, path: &str) {
    app.set_output_path_display(elide_path(path, ELIDE).into());
    app.set_output_path(path.into());
    check_conflicts(app);
}

fn check_conflicts(app: &AppWindow) {
    let mode = app.get_mode();
    let outpath = app.get_output_path().to_string();
    let keygen_dir = app.get_keygen_output_dir().to_string();

    let out_exists = is_encrypt_mode(mode) && !outpath.is_empty() && Path::new(&outpath).exists();
    let output_is_source = !outpath.is_empty() && app.get_input_path() == outpath.as_str();
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
        &app.get_input_reason(),
        &outpath,
        &keygen_dir,
        OutputFacts {
            out_exists,
            secret_exists,
            pub_exists,
            output_is_source,
        },
    );
    app.set_conflict_warning(warning.into());
}

/// What the filesystem says about the chosen outputs.
#[derive(Default)]
struct OutputFacts {
    /// The encrypted file's path is taken.
    out_exists: bool,
    /// The key pair folder holds a `private.key`.
    secret_exists: bool,
    /// The key pair folder holds a `public.key`.
    pub_exists: bool,
    /// The encrypted file's path is the source's own.
    output_is_source: bool,
}

/// Pure conflict-detection logic: given the current UI mode, why the selected
/// source cannot be decrypted (empty if it can, or is no encrypted file),
/// resolved output paths, and what the filesystem says about them, return the
/// warning string to display (or empty string when there is no conflict).
///
/// A name clash comes first: an operation cannot succeed while it lasts, so
/// the source warning is on screen whenever encryption can. A source whose
/// output would take its own name, such as a damaged `x.fcr`, gets one
/// warning for both: why it cannot be decrypted, and that another name is
/// needed.
fn compute_conflict_warning(
    mode: i32,
    input_reason: &str,
    outpath: &str,
    keygen_dir: &str,
    facts: OutputFacts,
) -> String {
    if is_encrypt_mode(mode) && !outpath.is_empty() && facts.out_exists {
        if facts.output_is_source && !input_reason.is_empty() {
            return source_warning(input_reason, OWN_NAME_NOTE);
        }

        return elide_path_message("Already exists: ", &escape_path_for_display(outpath), "");
    }

    if mode == MODE_KEYGEN && !keygen_dir.is_empty() {
        let clash = match (facts.secret_exists, facts.pub_exists) {
            (true, true) => Some("Key pair already exists in output folder"),
            (true, false) => Some("Private key already exists in output folder"),
            (false, true) => Some("Public key already exists in output folder"),
            (false, false) => None,
        };
        if let Some(clash) = clash {
            return clash.into();
        }
    }

    if is_encrypt_mode(mode) && !input_reason.is_empty() {
        return source_warning(input_reason, ORDINARY_FILE_NOTE);
    }

    String::new()
}

/// Resets the whole form, keys included, as the Reset button does. The
/// retained recipient key goes with its fingerprint.
fn clear_fields(app: &AppWindow, selected_public_key: &SelectedPublicKey) {
    clear_all_but_key(app);
    choose_public_key(app, "", selected_public_key);
    app.set_chosen_private_key_path(Default::default());
    app.set_mode(snap_back_mode(app.get_mode()));
    show_key_for_mode(app, selected_public_key);
}

/// Takes `path`, chosen in the key field while the form was in `mode`, as
/// the key for that mode's direction, unless the form has left that mode.
fn apply_key_path(
    app: &AppWindow,
    path: PathBuf,
    mode: i32,
    selected_public_key: &SelectedPublicKey,
) {
    // A dialog left open while the form moved on answers a question the
    // form no longer asks.
    if app.get_mode() != mode {
        return;
    }
    let path = path_to_string(&path);
    match mode {
        MODE_RECIPIENT_ENCRYPT => choose_public_key(app, &path, selected_public_key),
        MODE_RECIPIENT_DECRYPT => app.set_chosen_private_key_path(path.into()),
        _ => return,
    }
    show_key_for_mode(app, selected_public_key);
    clear_stale_status(app);
    check_conflicts(app);
}

/// Makes `path` the public key chosen for encrypting to a recipient, or
/// clears the choice when it is empty. The key read for the previous choice
/// is dropped with it, so the next showing reads the new one.
fn choose_public_key(app: &AppWindow, path: &str, selected_public_key: &SelectedPublicKey) {
    forget_selected_key(app, selected_public_key);
    app.set_chosen_public_key_path(path.into());
}

/// Shows in the key field the key chosen for the current mode's direction:
/// the public key while encrypting to a recipient, the private key while
/// decrypting. Each direction keeps its own, so a switch between them shows
/// neither the other's key nor an error about it, and a switch back brings
/// the first key back. Other modes show none.
///
/// A public key already read stays as read, so a key file replaced since
/// cannot change the recipient; one not read yet, or one that failed, is
/// read here. A private key is checked again each time, so damage since it
/// was chosen is reported before a password is typed.
fn show_key_for_mode(app: &AppWindow, selected_public_key: &SelectedPublicKey) {
    let mode = app.get_mode();
    let path = match mode {
        MODE_RECIPIENT_ENCRYPT => app.get_chosen_public_key_path(),
        MODE_RECIPIENT_DECRYPT => app.get_chosen_private_key_path(),
        _ => Default::default(),
    };
    app.set_key_path_display(elide_path(&path, ELIDE).into());
    app.set_key_path(path.clone());
    let already_read =
        mode == MODE_RECIPIENT_ENCRYPT && has_selected_public_key(selected_public_key);
    if path.is_empty() || already_read {
        app.set_key_invalid(false);
    } else {
        validate_selected_key(app, &path, selected_public_key);
    }
}

/// Resets the form after a finished operation in `mode`. The key chosen for
/// encrypting to a recipient stays, so more files can go to it; after a
/// public-key encryption it stays as read, with its fingerprint. A finished
/// decryption also clears the private key it used.
fn clear_after_operation(app: &AppWindow, mode: i32, selected_public_key: &SelectedPublicKey) {
    clear_all_but_key(app);
    if mode == MODE_RECIPIENT_ENCRYPT {
        return;
    }
    if mode == MODE_RECIPIENT_DECRYPT {
        app.set_chosen_private_key_path(Default::default());
    }
    app.set_mode(snap_back_mode(mode));
    show_key_for_mode(app, selected_public_key);
    // The result the caller shows next comes first: a recipient key that
    // cannot be read is forgotten without an error.
    if app.get_key_invalid() {
        choose_public_key(app, "", selected_public_key);
        show_key_for_mode(app, selected_public_key);
        app.set_status_err(Default::default());
    }
}

/// Resets every field but the key file, whose retained key and fingerprint
/// stay with it.
fn clear_all_but_key(app: &AppWindow) {
    let empty = slint::SharedString::default();
    app.set_input_path(empty.clone());
    app.set_input_path_display(empty.clone());
    app.set_input_reason(empty.clone());
    app.set_output_path(empty.clone());
    app.set_output_path_display(empty.clone());
    app.set_password(empty.clone());
    app.set_password_repeated(empty.clone());
    app.set_keygen_output_dir(empty.clone());
    app.set_keygen_output_dir_display(empty.clone());
    app.set_conflict_warning(empty.clone());
    app.set_status_ok(empty.clone());
    app.set_status_err(empty);
    app.set_hide_password(true);
    app.set_password_strength(password_scorer::PW_EMPTY);
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

/// A space at which a line never breaks.
const NO_BREAK_SPACE: &str = "\u{a0}";

/// The word that starts the duration in a result message.
const DURATION_WORD: &str = "in";

/// What separates the path from the duration in a result message.
fn duration_lead() -> String {
    format!(" {DURATION_WORD}{NO_BREAK_SPACE}")
}

const CENTISECONDS_PER_SECOND: u64 = 100;
const CENTISECONDS_PER_MINUTE: u64 = 60 * CENTISECONDS_PER_SECOND;

/// The result message of an operation that wrote `path` in `seconds`. Its
/// duration, such as "in 1.23 sec", is held together, so a message too long
/// for one line moves it whole to the next.
fn format_duration(action: &str, path: &Path, seconds: f64) -> String {
    // Rounded once, so 59.996 seconds reads "1 min, 0.00 sec", never "60.00 sec".
    let centiseconds = (seconds * CENTISECONDS_PER_SECOND as f64).round() as u64;
    let (minutes, rest) = (
        centiseconds / CENTISECONDS_PER_MINUTE,
        centiseconds % CENTISECONDS_PER_MINUTE,
    );
    let secs = format!(
        "{}.{:02} sec",
        rest / CENTISECONDS_PER_SECOND,
        rest % CENTISECONDS_PER_SECOND
    );
    let took = if minutes == 0 {
        secs
    } else {
        format!("{minutes} min, {secs}")
    };
    format!(
        "{action} {}{}{}",
        escape_path_for_display(path),
        duration_lead(),
        took.replace(' ', NO_BREAK_SPACE)
    )
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

/// Left-elides a path for a display field, after escaping it with
/// [`escape_path_for_display`]. The field's real value keeps the raw path.
fn elide_path(path: &str, max: usize) -> String {
    elide_left(&escape_path_for_display(path), max)
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
            let lead = duration_lead();
            if let Some((path, duration)) = rest.rsplit_once(lead.as_str()) {
                let suffix = format!("{lead}{duration}");
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

/// What a progress event shows: the status text, when the event changes it,
/// and the share of the file handled, or [`NO_PROGRESS`].
fn progress_display(event: &ProgressEvent) -> (Option<String>, f32) {
    match *event {
        // The library never reports a zero total; one would mean no share.
        ProgressEvent::BytesProcessed { total: 0, .. } => (None, NO_PROGRESS),
        ProgressEvent::BytesProcessed { done, total, .. } => {
            let status = (done == total).then(|| FINISHING.to_string());
            (status, (done as f64 / total as f64) as f32)
        }
        _ => (Some(event.to_string()), NO_PROGRESS),
    }
}

/// Bounds an error message to the status bar's wrapped budget,
/// [`STATUS_ERROR_BUDGET`] characters. A message longer than that — a long
/// OS error string, or a conflict on a very long path — is truncated with a
/// trailing `…`. This is UI-only: the library keeps the full message for CLI
/// and library callers.
fn elide_error_for_status(msg: &str) -> String {
    elide_end(msg, STATUS_ERROR_BUDGET)
}

/// Trims `msg` and cuts it to at most `max` chars, ending a cut one with `…`.
/// `max` must be at least 1.
fn elide_end(msg: &str, max: usize) -> String {
    let msg = msg.trim();
    if msg.chars().count() <= max {
        return msg.to_string();
    }

    let kept: String = msg.chars().take(max - 1).collect();
    format!("{kept}\u{2026}")
}

/// Validates the selected key file for the current mode and updates the UI.
///
/// In recipient-encrypt mode the key is read here and retained in
/// `selected`, so the fingerprint shown to the user and the key the next
/// encryption uses are the same bytes; a key that fails clears the retained
/// one. Other modes leave the retained key, which belongs to recipient
/// encryption, as it is.
fn validate_selected_key(app: &AppWindow, key_path: &str, selected: &SelectedPublicKey) {
    let key_path = Path::new(key_path);
    match app.get_mode() {
        MODE_RECIPIENT_ENCRYPT => {
            let loaded = PublicKey::from_key_file(key_path)
                .and_then(|key| key.fingerprint().map(|fp| (key, fp)));
            match loaded {
                Ok((key, fp)) => {
                    store_selected_public_key(selected, Some(key));
                    show_fingerprint(app, &fp);
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
            if let Err(e) = validate_private_key_file(key_path) {
                app.set_key_invalid(true);
                app.set_status_err(elide_error_for_status(&e.to_string()).into());
            } else {
                app.set_key_invalid(false);
                app.set_status_err(Default::default());
            }
        }
        _ => app.set_key_invalid(false),
    }
}

fn detect_mode_from_path(path: &str) -> Result<Option<i32>, ferrocrypt::CryptoError> {
    match probe_recipient_mode(Path::new(path))? {
        Some(UnauthenticatedRecipientMode::Passphrase) => Ok(Some(MODE_PASSPHRASE_DECRYPT)),
        Some(UnauthenticatedRecipientMode::PublicKey) => Ok(Some(MODE_RECIPIENT_DECRYPT)),
        // An encrypted file of a mode this app does not know is one it cannot
        // decrypt, and must not pass for an ordinary file.
        Some(_) => Err(CryptoError::NoSupportedRecipient),
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
    use i_slint_backend_testing::{ElementHandle, ElementRoot};
    use slint::platform::software_renderer::MinimalSoftwareWindow;
    use slint::platform::{
        Clipboard, Key, Platform, PointerEventButton, WindowAdapter, WindowEvent,
    };
    use std::cell::{Cell, RefCell};
    use std::fs;
    use std::rc::Rc;
    use std::time::Duration;

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
            matches!(&e2, CryptoError::InvalidInput(m) if m.contains("sealed with a password")),
            "unexpected error: {e2:?}"
        );
    }

    /// The GUI decrypt envelope equals what earlier releases accepted
    /// by default: memory capped at the library default, combined work
    /// at what that memory cap admits at the format's maximum pass
    /// count. Pinned numerically so a change in the library's defaults
    /// resurfaces here for review — the GUI has no per-run override a
    /// user could raise.
    #[test]
    fn desktop_kdf_limit_pins_the_previous_acceptance_envelope() {
        assert_eq!(
            desktop_kdf_limit(),
            KdfLimit::default().max_work(12_582_912),
            "1 GiB of memory times 12 passes"
        );
    }

    /// The retained-key slot recovers a poisoned lock on both
    /// accessors: the slot holds plain data no panic can leave
    /// half-written, and applying every store is what keeps the
    /// clearing paths effective — a wiped fingerprint with a stale key
    /// still retained would let a later encryption use a key the user
    /// never saw.
    #[test]
    fn a_poisoned_key_slot_still_applies_stores_and_reads() {
        let selected: SelectedPublicKey = Arc::new(Mutex::new(None));
        let for_poison = selected.clone();
        let _ = std::thread::spawn(move || {
            let _guard = for_poison.lock().unwrap();
            panic!("poison the slot");
        })
        .join();
        assert!(
            selected.is_poisoned(),
            "the slot must be poisoned for this test to prove anything"
        );

        let key = PublicKey::from_x25519_bytes([1u8; 32]).expect("a valid X25519 key");
        store_selected_public_key(&selected, Some(key));
        assert!(
            take_selected_public_key(&selected).is_some(),
            "a store must apply through a poisoned lock"
        );
        store_selected_public_key(&selected, None);
        assert!(
            take_selected_public_key(&selected).is_none(),
            "a clearing store must apply through a poisoned lock"
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

    /// The status names each phase, then says "Finishing…" once the whole
    /// file is handled; the bar follows the bytes in between.
    #[test]
    fn progress_events_drive_the_status_and_the_bar() {
        let dir = fs_matrix_tempdir().expect("tempdir");
        let input = dir.path().join("several-chunks.bin");
        fs::write(&input, vec![0x2e; 300_000]).unwrap();

        let shown = std::cell::RefCell::new(Vec::new());
        run_operation(
            Operation {
                mode: MODE_PASSPHRASE_ENCRYPT,
                input: &input,
                output_dir: dir.path(),
                save_as: None,
                key_path: Path::new(""),
                public_key: None,
                kdf_params: Some(fast_kdf_params()),
            },
            Passphrase::new("desktop-progress-passphrase"),
            &|event: &ProgressEvent| shown.borrow_mut().push(progress_display(event)),
        )
        .expect("encrypt");
        let shown = shown.into_inner();

        assert_eq!(
            shown.first(),
            Some(&(
                Some("Deriving passphrase key\u{2026}".to_string()),
                NO_PROGRESS
            ))
        );
        assert_eq!(shown.last(), Some(&(Some(FINISHING.to_string()), 1.0)));

        let counted: Vec<_> = shown[..shown.len() - 1]
            .iter()
            .filter(|(_, share)| *share >= 0.0)
            .collect();
        assert!(counted.len() > 2, "{shown:?}");
        assert!(counted.iter().all(|(status, _)| status.is_none()));
        assert!(counted.windows(2).all(|pair| pair[0].1 < pair[1].1));
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

    /// Filesystem facts about a source that is not its own output.
    fn facts(out_exists: bool, secret_exists: bool, pub_exists: bool) -> OutputFacts {
        OutputFacts {
            out_exists,
            secret_exists,
            pub_exists,
            ..OutputFacts::default()
        }
    }

    #[test]
    fn conflict_warning_empty_when_no_output_path() {
        let w = compute_conflict_warning(
            MODE_PASSPHRASE_ENCRYPT,
            "",
            "",
            "",
            facts(false, false, false),
        );
        assert!(w.is_empty());
    }

    #[test]
    fn conflict_warning_empty_when_encrypt_output_missing() {
        let w = compute_conflict_warning(
            MODE_RECIPIENT_ENCRYPT,
            "",
            "/tmp/out.fcr",
            "",
            facts(false, false, false),
        );
        assert!(w.is_empty());
    }

    #[test]
    fn conflict_warning_flags_existing_encrypt_output() {
        let w = compute_conflict_warning(
            MODE_PASSPHRASE_ENCRYPT,
            "",
            "/tmp/out.fcr",
            "",
            facts(true, false, false),
        );
        assert_eq!(w, "Already exists: /tmp/out.fcr");

        let w = compute_conflict_warning(
            MODE_RECIPIENT_ENCRYPT,
            "",
            "/tmp/out.fcr",
            "",
            facts(true, false, false),
        );
        assert_eq!(w, "Already exists: /tmp/out.fcr");
    }

    #[test]
    fn conflict_warning_ignores_existing_decrypt_output() {
        // Decrypt modes must never block on output existence — the library's
        // atomic output handling is authoritative, and the output path in
        // decrypt mode is a directory.
        for mode in [MODE_PASSPHRASE_DECRYPT, MODE_RECIPIENT_DECRYPT] {
            let w = compute_conflict_warning(mode, "", "/tmp/out", "", facts(true, false, false));
            assert!(w.is_empty(), "mode {} unexpectedly warned", mode);
        }
    }

    #[test]
    fn conflict_warning_elides_long_encrypt_paths() {
        let long = format!("/tmp/{}", "a".repeat(80));
        let w = compute_conflict_warning(
            MODE_PASSPHRASE_ENCRYPT,
            "",
            &long,
            "",
            facts(true, false, false),
        );
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
            let w =
                compute_conflict_warning(MODE_KEYGEN, "", "", "/tmp/keys", facts(false, sec, pubk));
            assert_eq!(w, expected, "sec={sec} pub={pubk}");
        }
    }

    /// A warning about the source shows in both encrypt modes once no name
    /// clashes, or when the clash is with the source itself, and nowhere
    /// else: the other modes do not encrypt it.
    #[test]
    fn conflict_warning_shows_the_source_warning_in_encrypt_modes_after_a_clash() {
        let reason = "File is too short";
        let source = source_warning(reason, ORDINARY_FILE_NOTE);

        for mode in [MODE_PASSPHRASE_ENCRYPT, MODE_RECIPIENT_ENCRYPT] {
            let w = compute_conflict_warning(
                mode,
                reason,
                "/tmp/out.fcr",
                "",
                facts(true, false, false),
            );
            assert_eq!(w, "Already exists: /tmp/out.fcr", "mode {mode}");

            let w = compute_conflict_warning(
                mode,
                reason,
                "/tmp/out.fcr",
                "",
                facts(false, false, false),
            );
            assert_eq!(w, source, "mode {mode}");

            let w = compute_conflict_warning(
                mode,
                reason,
                "/tmp/out.fcr",
                "",
                OutputFacts {
                    output_is_source: true,
                    ..facts(true, false, false)
                },
            );
            assert_eq!(
                w,
                source_warning(reason, OWN_NAME_NOTE),
                "mode {mode}: the clash with the source's own name"
            );
        }

        for mode in [MODE_PASSPHRASE_DECRYPT, MODE_RECIPIENT_DECRYPT, MODE_KEYGEN] {
            let w =
                compute_conflict_warning(mode, reason, "/tmp/out", "", facts(true, false, false));
            assert!(w.is_empty(), "mode {mode} showed the source warning");
        }
    }

    #[test]
    fn conflict_warning_keygen_empty_dir_never_warns() {
        for (sec, pubk) in [(true, true), (true, false), (false, true), (false, false)] {
            let w = compute_conflict_warning(MODE_KEYGEN, "", "", "", facts(false, sec, pubk));
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
        let msg = format_duration("Encrypted to", Path::new(&format!("/tmp/{long}")), 1.234);
        let out = elide_result_path(&msg);
        assert!(out.starts_with("Encrypted to "));
        assert!(out.ends_with(&took("1.23 sec")));
        assert!(out.contains('\u{2026}'));
        assert!(out.chars().count() <= STATUS_LINE_MAX, "got: {out}");
    }

    /// A decrypt whose destination folder changed under it reports the
    /// output's name and then the folder. The status bar drops the tail
    /// of anything too long, so the name — the only part the operator can
    /// act on, the folder no longer holding the output — must survive
    /// that trim.
    #[test]
    fn output_directory_changed_keeps_the_output_name_in_the_status_line() {
        let long = "c".repeat(300);
        let msg = format!("Output report.pdf is complete but its directory changed: /tmp/{long}");

        let out = elide_error_for_status(&msg);

        assert!(out.chars().count() <= STATUS_ERROR_BUDGET, "got: {out}");
        assert!(
            out.contains("Output report.pdf is complete"),
            "the trim must keep the output's name, got: {out}"
        );
    }

    #[test]
    fn elide_result_path_shortens_decrypted_to_message() {
        let long = "b".repeat(200);
        let msg = format_duration("Decrypted to", Path::new(&format!("/tmp/{long} in")), 0.5);
        let out = elide_result_path(&msg);
        assert!(out.starts_with("Decrypted to "));
        assert!(out.ends_with(&took("0.50 sec")));
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

    /// A rejected archive path is the longest message the library emits
    /// in normal use: the prefix plus a path the library already cut to
    /// its own display budget. It must reach the status bar whole, so
    /// the bar can wrap it and show which entry was refused.
    #[test]
    fn elide_error_for_status_keeps_a_rejected_archive_path_whole() {
        let msg = format!(
            "Unsafe archive path (contains a control, text-direction, or line-break character): {}…",
            "d".repeat(63)
        );
        assert!(msg.chars().count() > STATUS_LINE_MAX);
        assert_eq!(elide_error_for_status(&msg), msg);
    }

    #[test]
    fn elide_error_for_status_truncates_past_the_wrapped_budget() {
        let long = format!("Output already exists: /tmp/{}", "e".repeat(300));
        let out = elide_error_for_status(&long);
        assert_eq!(out.chars().count(), STATUS_ERROR_BUDGET);
        assert!(out.ends_with('\u{2026}'));
        assert!(out.starts_with("Output already exists: /tmp/"));
    }

    /// The duration of a result message as `format_duration` writes it,
    /// from `text` written with ordinary spaces.
    fn took(text: &str) -> String {
        format!("{}{}", duration_lead(), text.replace(' ', NO_BREAK_SPACE))
    }

    #[test]
    fn format_duration_under_one_minute() {
        let out = format_duration("Encrypted to", Path::new("/tmp/out"), 1.234);
        assert_eq!(out, format!("Encrypted to /tmp/out{}", took("1.23 sec")));
        // The bytes themselves, so the helper above cannot hide a change.
        assert_eq!(out, "Encrypted to /tmp/out in\u{a0}1.23\u{a0}sec");
    }

    /// A minute starts where the shown seconds would reach 60, not where the
    /// exact ones do, so a duration never reads "60.00 sec".
    #[test]
    fn format_duration_at_and_past_one_minute() {
        for (seconds, expected) in [
            (59.994, "59.99 sec"),
            (59.996, "1 min, 0.00 sec"),
            (60.0, "1 min, 0.00 sec"),
            (119.996, "2 min, 0.00 sec"),
            (125.5, "2 min, 5.50 sec"),
        ] {
            let out = format_duration("Encrypted to", Path::new("/tmp/out"), seconds);
            assert!(out.ends_with(&took(expected)), "{seconds}: got {out}");
        }
    }

    #[test]
    fn shown_paths_escape_control_and_direction_characters() {
        let out = format_duration("Decrypted to", Path::new("/tmp/re\u{200f}port"), 1.0);
        assert_eq!(
            out,
            format!("Decrypted to /tmp/re\\u{{200f}}port{}", took("1.00 sec"))
        );

        assert_eq!(elide_path("/tmp/a\u{1b}b", ELIDE), "/tmp/a\\u{1b}b");

        let w = compute_conflict_warning(
            MODE_PASSPHRASE_ENCRYPT,
            "",
            "/tmp/a\nb.fcr",
            "",
            facts(true, false, false),
        );
        assert_eq!(w, "Already exists: /tmp/a\\nb.fcr");
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

    /// A headless platform that records clipboard writes instead of passing
    /// them to the system. Its clock moves only when the test advances it,
    /// so double clicks happen only where the test intends them.
    struct ClipboardRecorder {
        window: Rc<MinimalSoftwareWindow>,
        clock: Rc<Cell<Duration>>,
        copied: Rc<RefCell<Vec<(Clipboard, String)>>>,
    }

    impl Platform for ClipboardRecorder {
        fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
            Ok(self.window.clone())
        }

        fn duration_since_start(&self) -> Duration {
            self.clock.get()
        }

        fn set_clipboard_text(&self, text: &str, clipboard: Clipboard) {
            self.copied.borrow_mut().push((clipboard, text.to_string()));
        }
    }

    /// A masked passphrase never leaves its field: neither copy and cut nor
    /// a mouse selection, which fills the selection clipboard on X11 and
    /// Wayland, hands it out. Each blocked case is paired with an unmasked
    /// or unguarded one that does copy the text, so the test cannot pass
    /// just because its input missed the fields.
    #[test]
    #[cfg_attr(
        not(debug_assertions),
        ignore = "needs Slint debug info, which is compiled in only when debug assertions are on"
    )]
    fn masked_passphrase_fields_keep_their_text_in_the_window() {
        const PASSPHRASE: &str = "hunter2";
        const PASSWORD: &str = "AppWindow::pwd-ti";
        const CONFIRM: &str = "AppWindow::rpwd-ti";

        let window = MinimalSoftwareWindow::new(Default::default());
        let clock = Rc::new(Cell::new(Duration::ZERO));
        let copied = Rc::new(RefCell::new(Vec::new()));
        slint::platform::set_platform(Box::new(ClipboardRecorder {
            window,
            clock: clock.clone(),
            copied: copied.clone(),
        }))
        .expect("no other test sets a platform on this thread");

        let app = AppWindow::new().unwrap();
        app.show().unwrap();
        app.set_password(PASSPHRASE.into());
        app.set_password_repeated(PASSPHRASE.into());
        let w = app.window();

        // Starts a new click sequence, so `times` alone decides between a
        // single and a double click.
        let click = |id: &str, times: usize| {
            clock.set(clock.get() + Duration::from_secs(1));
            let position = centre_of(&app, id);
            let button = PointerEventButton::Left;
            for _ in 0..times {
                w.dispatch_event(WindowEvent::PointerPressed { position, button });
                w.dispatch_event(WindowEvent::PointerReleased { position, button });
            }
        };
        let tap = |key: slint::SharedString| tap_key(&app, key);
        // Slint reports Cmd on macOS as Ctrl, so this covers both.
        let shortcuts = |keys: &[&str]| {
            let control: slint::SharedString = Key::Control.into();
            w.dispatch_event(WindowEvent::KeyPressed {
                text: control.clone(),
            });
            for key in keys {
                tap((*key).into());
            }
            w.dispatch_event(WindowEvent::KeyReleased { text: control });
        };
        let take_copied = || copied.borrow_mut().drain(..).collect::<Vec<_>>();
        let nothing: Vec<(Clipboard, String)> = Vec::new();

        // Copy and cut do nothing in a masked field and work once it is shown.
        app.set_selection_clipboard(false);
        click(PASSWORD, 1);
        shortcuts(&["a", "c", "x"]);
        assert_eq!(take_copied(), nothing, "masked password copied");
        assert_eq!(app.get_password(), PASSPHRASE, "masked password cut");
        app.set_hide_password(false);
        shortcuts(&["a", "c"]);
        assert_eq!(
            take_copied(),
            [(Clipboard::DefaultClipboard, PASSPHRASE.to_string())],
            "a shown password must stay copyable"
        );
        app.set_hide_password(true);

        click(CONFIRM, 1);
        shortcuts(&["a", "c", "x"]);
        assert_eq!(take_copied(), nothing, "confirmation copied");
        assert_eq!(app.get_password_repeated(), PASSPHRASE, "confirmation cut");

        // A double click selects the masked text and copies it to the
        // selection clipboard, unless the field is guarded.
        click(PASSWORD, 2);
        assert_eq!(
            take_copied(),
            [(Clipboard::SelectionClipboard, PASSPHRASE.to_string())],
            "an unguarded double click must reach the field"
        );
        app.set_selection_clipboard(true);
        click(PASSWORD, 2);
        click(CONFIRM, 2);
        assert_eq!(take_copied(), nothing, "a selection left a guarded field");

        // A guarded click must move the focus here from the other field and
        // clear the selection, so a key typed after select-all adds to the
        // hidden text instead of replacing it.
        app.set_selection_clipboard(false);
        click(CONFIRM, 1);
        app.set_selection_clipboard(true);
        click(PASSWORD, 1);
        shortcuts(&["a"]);
        click(PASSWORD, 1);
        tap("!".into());
        assert_eq!(
            app.get_password(),
            format!("{PASSPHRASE}!"),
            "a guarded click must focus the password and drop its selection"
        );
        assert_eq!(app.get_password_repeated(), PASSPHRASE);

        // Tab must reach the next field: the wrapper around each input never
        // takes focus. The button that shows the password comes between.
        let password = app.get_password();
        tap(Key::Tab.into());
        tap(Key::Tab.into());
        tap("?".into());
        assert!(
            app.get_password_repeated().ends_with('?'),
            "Tab did not reach the confirmation"
        );
        assert_eq!(app.get_password(), password);
    }

    /// The keyboard reaches the buttons past the last field and presses them:
    /// Tab moves from the confirmation to Reset, then to the action button,
    /// Space or Enter presses the one that has the focus, and a single ring
    /// shows where the focus is.
    #[test]
    #[cfg_attr(
        not(debug_assertions),
        ignore = "needs Slint debug info, which is compiled in only when debug assertions are on"
    )]
    fn the_keyboard_reaches_and_presses_the_buttons() {
        let app = headless_app();
        let presses = Rc::new(RefCell::new(Vec::new()));
        let record = |name: &'static str| {
            let presses = presses.clone();
            move || presses.borrow_mut().push(name)
        };
        app.on_clear_form(record("reset"));
        app.on_start_operation(record("start"));
        app.show().unwrap();

        // A form ready to encrypt, so both buttons can be pressed.
        app.set_input_path("source.txt".into());
        app.set_password("pw".into());
        app.set_password_repeated("pw".into());

        let tap = |key: slint::SharedString| tap_key(&app, key);
        click(&app, "AppWindow::rpwd-ti", PointerEventButton::Left);
        tap(Key::Tab.into());
        tap(Key::Space.into());
        tap(Key::Tab.into());
        tap(Key::Return.into());

        assert_eq!(*presses.borrow(), ["reset", "start"]);

        // One ring shows the focus, across the control that has it. It stays
        // while that control is turned off, and none is left behind once the
        // focus moves on.
        let rings =
            || ElementHandle::find_by_element_id(&app, "Pressable::focus-ring").collect::<Vec<_>>();
        let start = ElementHandle::find_by_element_id(&app, "AppWindow::start-ta")
            .next()
            .expect("the action button exists");
        let on_start = |ring: &ElementHandle| {
            ring.absolute_position() == start.absolute_position() && ring.size() == start.size()
        };
        let ring = rings();
        assert_eq!(ring.len(), 1, "one ring");
        assert!(on_start(&ring[0]), "the ring does not cover the button");

        app.set_password_repeated("other".into());
        let ring = rings();
        assert!(
            ring.len() == 1 && on_start(&ring[0]),
            "the focus is out of sight"
        );

        tap(Key::Tab.into());
        app.set_password_repeated("pw".into());
        let ring = rings();
        assert!(
            ring.len() == 1 && !on_start(&ring[0]),
            "a ring was left behind"
        );
    }

    /// Every button, tab, tab list, and text input tells assistive technology
    /// what it is called, and a tab's default action does what a click does:
    /// it switches the form, unless it is already the active one. The status
    /// is read out as it changes.
    #[test]
    #[cfg_attr(
        not(debug_assertions),
        ignore = "needs Slint debug info, which is compiled in only when debug assertions are on"
    )]
    fn every_control_is_named_for_assistive_technology() {
        use i_slint_backend_testing::{AccessibleLiveness, AccessibleRole};

        let app = headless_app();
        app.show().unwrap();
        show_fingerprint(&app, "0123456789abcdef");

        // A few controls each mode must have, among the others it has.
        let forms: [(i32, &[(AccessibleRole, &str)]); 5] = [
            (
                MODE_PASSPHRASE_ENCRYPT,
                &[
                    (AccessibleRole::TextInput, "Confirm password"),
                    (AccessibleRole::Button, "Show password"),
                ],
            ),
            (
                MODE_PASSPHRASE_DECRYPT,
                &[(AccessibleRole::Button, "Choose output location")],
            ),
            (
                MODE_RECIPIENT_ENCRYPT,
                &[
                    (AccessibleRole::Button, "Copy fingerprint"),
                    (AccessibleRole::Button, "Choose public key"),
                ],
            ),
            (
                MODE_RECIPIENT_DECRYPT,
                &[
                    (AccessibleRole::TextInput, "Private key password"),
                    (AccessibleRole::Button, "Show private key password"),
                ],
            ),
            (
                MODE_KEYGEN,
                &[
                    (AccessibleRole::Button, "Choose key pair folder"),
                    (AccessibleRole::Tab, "Create key pair"),
                ],
            ),
        ];

        for (mode, expected) in forms {
            app.set_mode(mode);
            let mut controls = Vec::new();

            for role in [
                AccessibleRole::Button,
                AccessibleRole::Tab,
                AccessibleRole::TabList,
                AccessibleRole::TextInput,
            ] {
                controls.extend(
                    app.root_element()
                        .query_descendants()
                        .match_accessible_role(role)
                        .find_all(),
                );
            }

            let named: Vec<_> = controls
                .iter()
                .map(|control| {
                    let label = control.accessible_label().unwrap_or_default();
                    assert!(
                        !label.is_empty(),
                        "mode {mode}: a {:?} has no name",
                        control.accessible_role()
                    );
                    (control.accessible_role(), label.to_string())
                })
                .collect();

            for (role, label) in expected {
                assert!(
                    named.contains(&(Some(*role), label.to_string())),
                    "mode {mode}: no {role:?} named {label}"
                );
            }
        }

        let element = |id: &str| {
            ElementHandle::find_by_element_id(&app, id)
                .next()
                .unwrap_or_else(|| panic!("no element {id}"))
        };
        app.set_mode(MODE_PASSPHRASE_DECRYPT);
        element("AppWindow::password-tab").invoke_accessible_default_action();
        assert_eq!(app.get_mode(), MODE_PASSPHRASE_DECRYPT);
        assert_eq!(
            element("AppWindow::password-tab").accessible_item_selected(),
            Some(true)
        );

        app.set_mode(MODE_PASSPHRASE_ENCRYPT);
        element("AppWindow::key-pair-tab").invoke_accessible_default_action();
        assert_eq!(app.get_mode(), MODE_RECIPIENT_ENCRYPT);

        // The status is read out as it changes.
        let status = element("AppWindow::notify-text");
        assert_eq!(
            status.accessible_live_region(),
            Some(AccessibleLiveness::Polite)
        );
        app.set_status_err("Something failed".into());
        assert_eq!(
            status.accessible_label().as_deref(),
            Some("Something failed")
        );
    }

    /// The bar shows only while an operation counts the bytes of the file,
    /// and tells assistive technology how far it has come.
    #[test]
    fn the_progress_bar_shows_only_while_bytes_are_counted() {
        use i_slint_backend_testing::AccessibleRole;

        let app = headless_app();
        app.show().unwrap();
        let bars = || {
            app.root_element()
                .query_descendants()
                .match_accessible_role(AccessibleRole::ProgressIndicator)
                .find_all()
        };
        assert!(bars().is_empty());

        app.set_is_working(true);
        assert!(bars().is_empty(), "key derivation has no share to show");

        app.set_progress(0.25);
        let shown = bars();
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].accessible_label().as_deref(), Some("Progress"));
        assert_eq!(shown[0].accessible_value().as_deref(), Some("0.25"));
        assert_eq!(shown[0].accessible_value_maximum(), Some(1.0));

        app.set_is_working(false);
        assert!(bars().is_empty());
    }

    /// Whether the confirmation matches is said by a check or a cross with a
    /// name, not by colour alone.
    #[test]
    fn the_password_match_mark_has_a_name() {
        use i_slint_backend_testing::AccessibleRole;

        let app = headless_app();
        app.show().unwrap();
        let marks = || -> Vec<String> {
            app.root_element()
                .query_descendants()
                .match_accessible_role(AccessibleRole::Image)
                .find_all()
                .iter()
                .filter_map(|mark| mark.accessible_label())
                .map(|label| label.to_string())
                .collect()
        };
        assert!(marks().is_empty());

        app.set_password("first".into());
        app.set_password_repeated("firs".into());
        assert_eq!(marks(), ["Passwords do not match"]);

        app.set_password_repeated("first".into());
        assert_eq!(marks(), ["Passwords match"]);

        app.set_password_repeated("".into());
        assert!(marks().is_empty());
    }

    /// A headless platform for layout checks.
    struct Headless(Rc<MinimalSoftwareWindow>);

    impl Platform for Headless {
        fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
            Ok(self.0.clone())
        }
    }

    /// The app's window on a headless platform, for tests that measure or
    /// click it.
    fn headless_app() -> AppWindow {
        slint::platform::set_platform(Box::new(Headless(MinimalSoftwareWindow::new(
            Default::default(),
        ))))
        .expect("no other test sets a platform on this thread");
        AppWindow::new().unwrap()
    }

    /// Every form fits the fixed window: the Reset and action buttons stay
    /// inside it, at the same height in every mode, and the last field ends
    /// above the notification bar. Each form is also checked with an error
    /// long enough to wrap, which makes the bar ask for more room: the bar
    /// takes only room the form leaves free, so no field moves. Create key
    /// pair once pushed the buttons half out of the window, in a system font
    /// with taller lines; the app now brings its own font, which these checks
    /// measure. Both window frames are checked: the system's, and the app's
    /// own with its title bar.
    #[test]
    #[cfg_attr(
        not(debug_assertions),
        ignore = "needs Slint debug info, which is compiled in only when debug assertions are on"
    )]
    fn every_form_fits_the_window() {
        const FINGERPRINT: &str =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        // Made of the widest hex digit, so it takes two lines.
        const WIDEST_FINGERPRINT: &str =
            "4444444444444444444444444444444444444444444444444444444444444444";
        // The last field of each form is one of these, depending on the mode.
        const FIELDS: [&str; 6] = [
            "AppWindow::out-ta",
            "AppWindow::key-ta",
            "AppWindow::fp-field",
            "AppWindow::kgout-ta",
            "AppWindow::pwd-ti",
            "AppWindow::rpwd-ti",
        ];
        // Only public-key encryption shows a fingerprint.
        const FORMS: [(i32, &str); 7] = [
            (MODE_PASSPHRASE_ENCRYPT, ""),
            (MODE_PASSPHRASE_DECRYPT, ""),
            (MODE_RECIPIENT_ENCRYPT, ""),
            (MODE_RECIPIENT_ENCRYPT, FINGERPRINT),
            (MODE_RECIPIENT_ENCRYPT, WIDEST_FINGERPRINT),
            (MODE_RECIPIENT_DECRYPT, ""),
            (MODE_KEYGEN, ""),
        ];

        let app = headless_app();
        app.show().unwrap();
        for own_frame in [false, true] {
            app.set_own_frame(own_frame);
            // The headless window has no size of its own; the root element has
            // the window's.
            let window_height = app.root_element().size().height;
            assert!(window_height > 0.0, "the window has no height");
            let element = |id: &str| ElementHandle::find_by_element_id(&app, id).next();

            const WORD: &str = "word ";
            let long_error = WORD.repeat(STATUS_ERROR_BUDGET / WORD.len());
            let mut button_tops = Vec::new();
            let mut fingerprint_heights = Vec::new();
            let mut bar_grew = false;
            for (mode, fingerprint) in FORMS {
                let mut without_error = None;
                for error in ["", long_error.as_str()] {
                    app.set_mode(mode);
                    show_fingerprint(&app, fingerprint);
                    app.set_status_err(error.into());
                    let case = format!(
                        "own frame {own_frame}, mode {mode}, fingerprint {fingerprint:?}, error {}",
                        !error.is_empty()
                    );
                    if let Some(field) = element("AppWindow::fp-field") {
                        fingerprint_heights.push((fingerprint, field.size().height));
                    }

                    let button = element("AppWindow::start-ta").expect("the action button exists");
                    let button_top = button.absolute_position().y;
                    let button_bottom = button_top + button.size().height;
                    assert!(
                        button_bottom <= window_height,
                        "{case}: the button ends at {button_bottom}, below the window's {window_height}"
                    );
                    button_tops.push((case.clone(), button_top));

                    let last_field_bottom = FIELDS
                        .iter()
                        .filter_map(|id| element(id))
                        .map(|field| field.absolute_position().y + field.size().height)
                        .reduce(f32::max)
                        .unwrap_or_else(|| panic!("{case}: none of the fields was found"));
                    let bar =
                        element("AppWindow::notify-text").expect("the notification bar exists");
                    let (bar_top, bar_height) = (bar.absolute_position().y, bar.size().height);
                    assert!(
                        last_field_bottom <= bar_top,
                        "{case}: the last field ends at {last_field_bottom}, under the bar at {bar_top}"
                    );
                    let (field_bottom_without_error, bar_height_without_error) =
                        *without_error.get_or_insert((last_field_bottom, bar_height));
                    assert_eq!(
                        last_field_bottom, field_bottom_without_error,
                        "{case}: the error moves the last field"
                    );
                    bar_grew |= bar_height > bar_height_without_error;
                }
            }
            // A fingerprint too wide for one line takes a second one rather than
            // hiding its end.
            let height_of = |wanted: &str| {
                fingerprint_heights
                    .iter()
                    .find(|(fingerprint, _)| *fingerprint == wanted)
                    .map(|(_, height)| *height)
                    .expect("the fingerprint was shown")
            };
            assert!(
                height_of(WIDEST_FINGERPRINT) > height_of(FINGERPRINT),
                "the widest fingerprint did not take a second line"
            );
            // Otherwise the error never asked for room, and the check above that
            // no field moves tested nothing.
            assert!(
                bar_grew,
                "the long error did not make the bar taller in any mode"
            );
            let (first_case, first_top) = &button_tops[0];
            for (case, top) in &button_tops {
                assert_eq!(
                    top, first_top,
                    "{case} moves the button from where {first_case} has it"
                );
            }
        }
    }

    /// Generates a key pair in `dir` with fast Argon2id and returns the path
    /// of its public key.
    fn generate_test_key_pair(dir: &Path) -> PathBuf {
        run_operation(
            Operation {
                mode: MODE_KEYGEN,
                input: Path::new(""),
                output_dir: dir,
                save_as: None,
                key_path: Path::new(""),
                public_key: None,
                kdf_params: Some(fast_kdf_params()),
            },
            Passphrase::new("desktop-test-key-passphrase"),
            &|_: &ProgressEvent| {},
        )
        .expect("keygen")
    }

    /// A file that opens like an encrypted file but cannot be decrypted
    /// here stays selected for encryption, with a warning that gives the
    /// reason, whether it is a look-alike or an encrypted file over this
    /// app's limits. A private key and an ordinary file carry no warning, and
    /// only a path that cannot be read is refused.
    #[test]
    fn a_source_that_cannot_be_decrypted_is_kept_with_a_warning() {
        let dir = fs_matrix_tempdir().expect("tempdir");
        let lookalike = dir.path().join("lookalike.txt");
        fs::write(&lookalike, b"FCR\0").unwrap();
        // A sound prefix declaring a 2 MiB header, over the 1 MiB default.
        let oversized = dir.path().join("oversized.bin");
        fs::write(&oversized, b"FCR\0\x01E\0\0\0\x20\0\0").unwrap();
        assert!(
            matches!(
                detect_mode_from_path(oversized.to_str().unwrap()),
                Err(CryptoError::HeaderLenCapExceeded { .. })
            ),
            "the file must be over the header cap for this test to prove anything"
        );

        let ordinary = dir.path().join("ordinary.txt");
        fs::write(&ordinary, b"plain text").unwrap();

        let keys = dir.path().join("keys");
        generate_test_key_pair(&keys);
        let private_key = keys.join(PRIVATE_KEY_FILENAME);

        let missing = dir.path().join("missing.txt");
        let selected: SelectedPublicKey = Arc::new(Mutex::new(None));
        let app = headless_app();

        for (source, reason) in [
            (&lookalike, "File is too short"),
            (&oversized, "Header too large"),
        ] {
            app.set_mode(MODE_PASSPHRASE_DECRYPT);
            apply_input_path(&app, source.clone(), &selected);
            assert_eq!(app.get_input_path(), path_to_string(source));
            assert_eq!(app.get_mode(), MODE_PASSPHRASE_ENCRYPT);
            assert_eq!(app.get_status_err(), "");
            let warning = app.get_conflict_warning();
            assert!(
                app.get_input_reason().starts_with(reason)
                    && warning.starts_with(reason)
                    && warning.ends_with(ORDINARY_FILE_NOTE),
                "got: {warning}"
            );
        }

        for source in [&private_key, &ordinary] {
            apply_input_path(&app, source.clone(), &selected);
            assert_eq!(app.get_input_path(), path_to_string(source));
            assert_eq!(app.get_input_reason(), "", "{source:?} warned");
            assert_eq!(app.get_conflict_warning(), "");
        }

        apply_input_path(&app, lookalike, &selected);
        apply_input_path(&app, missing, &selected);
        assert_eq!(app.get_input_path(), "");
        assert_eq!(app.get_input_reason(), "");
        assert_ne!(app.get_status_err(), "", "the refusal is not shown");
    }

    /// However long the reason, the warning for a source that cannot be
    /// decrypted still ends in its note.
    #[test]
    fn the_note_survives_a_long_reason() {
        let reason = "reason ".repeat(STATUS_ERROR_BUDGET);
        for note in [ORDINARY_FILE_NOTE, OWN_NAME_NOTE] {
            let warning = source_warning(&reason, note);
            assert!(warning.ends_with(note), "got: {warning}");
            assert_eq!(warning.chars().count(), STATUS_ERROR_BUDGET);
        }
    }

    /// Picking a new source in the same mode keeps the public key read when
    /// it was selected, even after its file changes: the fingerprint on
    /// screen and the key the next encryption uses stay the same. A key that
    /// failed, and a private key, are read again.
    #[test]
    fn a_new_source_keeps_the_key_read_at_selection() {
        let dir = fs_matrix_tempdir().expect("tempdir");
        let key_a = generate_test_key_pair(&dir.path().join("a"));
        let key_b = generate_test_key_pair(&dir.path().join("b"));
        let source = dir.path().join("source.txt");
        fs::write(&source, b"plain text").unwrap();
        let selected: SelectedPublicKey = Arc::new(Mutex::new(None));

        let app = headless_app();
        app.set_mode(MODE_RECIPIENT_ENCRYPT);
        apply_key_path(&app, key_a.clone(), MODE_RECIPIENT_ENCRYPT, &selected);
        let fingerprint = app.get_key_fingerprint();
        assert_ne!(fingerprint, "");

        fs::copy(&key_b, &key_a).unwrap();
        apply_input_path(&app, source, &selected);
        assert_eq!(app.get_key_fingerprint(), fingerprint);
        assert!(!app.get_key_invalid());
        let kept = take_selected_public_key(&selected).expect("the key is kept");
        assert_eq!(kept.fingerprint().unwrap(), fingerprint.as_str());

        // A key that failed is read again, so a fixed file is picked up.
        fs::write(&key_a, b"not a key").unwrap();
        apply_key_path(&app, key_a.clone(), MODE_RECIPIENT_ENCRYPT, &selected);
        assert!(app.get_key_invalid());
        fs::copy(&key_b, &key_a).unwrap();
        apply_input_path(&app, dir.path().join("source.txt"), &selected);
        assert!(!app.get_key_invalid(), "the fixed key was not read again");
        assert_ne!(app.get_key_fingerprint(), "");

        // A private key is checked again on every pick, so a key damaged
        // since it was chosen is reported before a password is typed.
        let sealed = run_operation(
            Operation {
                mode: MODE_RECIPIENT_ENCRYPT,
                input: &dir.path().join("source.txt"),
                output_dir: dir.path(),
                save_as: None,
                key_path: Path::new(""),
                public_key: Some(PublicKey::from_key_file(&key_b).unwrap()),
                kdf_params: None,
            },
            Passphrase::new("unused"),
            &|_: &ProgressEvent| {},
        )
        .expect("recipient encrypt");
        let private_key = dir.path().join("b").join(PRIVATE_KEY_FILENAME);
        app.set_mode(MODE_RECIPIENT_DECRYPT);
        apply_key_path(&app, private_key.clone(), MODE_RECIPIENT_DECRYPT, &selected);
        assert!(!app.get_key_invalid());

        fs::write(&private_key, b"damaged").unwrap();
        apply_input_path(&app, sealed, &selected);
        assert_eq!(app.get_mode(), MODE_RECIPIENT_DECRYPT);
        assert!(
            app.get_key_invalid(),
            "the damaged private key was not reported"
        );
    }

    /// Each direction keeps its own key. A source that switches between
    /// encrypting and decrypting shows the key chosen for the new direction,
    /// with no error about the other one, such as the public key of the
    /// encryption just made when its file is picked to decrypt; a switch back
    /// brings the first key back. A key of the wrong kind chosen in the key
    /// field itself, and a damaged key, are still reported. A public key stays
    /// as read across the switches, whatever happens to its file. A finished
    /// decryption clears its private key and keeps the recipient key.
    #[test]
    fn each_direction_keeps_its_own_key() {
        let dir = fs_matrix_tempdir().expect("tempdir");
        let public_key = generate_test_key_pair(&dir.path().join("keys"));
        let private_key = dir.path().join("keys").join(PRIVATE_KEY_FILENAME);
        let source = dir.path().join("source.txt");
        fs::write(&source, b"plain text").unwrap();
        let sealed = run_operation(
            Operation {
                mode: MODE_RECIPIENT_ENCRYPT,
                input: &source,
                output_dir: dir.path(),
                save_as: None,
                key_path: Path::new(""),
                public_key: Some(PublicKey::from_key_file(&public_key).unwrap()),
                kdf_params: None,
            },
            Passphrase::new("unused"),
            &|_: &ProgressEvent| {},
        )
        .expect("recipient encrypt");
        let selected: SelectedPublicKey = Arc::new(Mutex::new(None));
        let app = headless_app();
        let shows = |mode: i32, key: &str| {
            assert_eq!(app.get_mode(), mode);
            assert_eq!(app.get_key_path(), key);
            assert!(!app.get_key_invalid(), "{key:?} is reported");
            assert_eq!(app.get_status_err(), "");
            if mode == MODE_RECIPIENT_ENCRYPT {
                assert_eq!(app.get_key_fingerprint() != "", !key.is_empty());
                assert_eq!(has_selected_public_key(&selected), !key.is_empty());
            }
        };
        let (public_key, private_key) = (path_to_string(&public_key), path_to_string(&private_key));

        app.set_mode(MODE_RECIPIENT_ENCRYPT);
        apply_key_path(
            &app,
            public_key.clone().into(),
            MODE_RECIPIENT_ENCRYPT,
            &selected,
        );
        apply_input_path(&app, sealed.clone(), &selected);
        assert_eq!(app.get_mode(), MODE_RECIPIENT_DECRYPT);
        assert_eq!(
            app.get_key_path(),
            "",
            "the public key is offered to decrypt"
        );
        assert!(!app.get_key_invalid());
        assert_eq!(app.get_status_err(), "");

        apply_key_path(
            &app,
            private_key.clone().into(),
            MODE_RECIPIENT_DECRYPT,
            &selected,
        );
        shows(MODE_RECIPIENT_DECRYPT, &private_key);
        apply_input_path(&app, source.clone(), &selected);
        shows(MODE_RECIPIENT_ENCRYPT, &public_key);
        let fingerprint = app.get_key_fingerprint();

        // A public key file replaced while the form decrypts does not change
        // the recipient: the key stays as read when it was chosen.
        let other_key = generate_test_key_pair(&dir.path().join("other"));
        let original = fs::read(&public_key).unwrap();
        fs::copy(&other_key, &public_key).unwrap();
        apply_input_path(&app, sealed.clone(), &selected);
        shows(MODE_RECIPIENT_DECRYPT, &private_key);
        apply_input_path(&app, source.clone(), &selected);
        shows(MODE_RECIPIENT_ENCRYPT, &public_key);
        assert_eq!(app.get_key_fingerprint(), fingerprint);
        let kept = take_selected_public_key(&selected).expect("the key is kept");
        assert_eq!(kept.fingerprint().unwrap(), fingerprint.as_str());
        fs::write(&public_key, original).unwrap();

        apply_input_path(&app, sealed.clone(), &selected);
        shows(MODE_RECIPIENT_DECRYPT, &private_key);

        // A key of the wrong kind chosen in the key field is reported.
        apply_input_path(&app, source.clone(), &selected);
        apply_key_path(
            &app,
            private_key.clone().into(),
            MODE_RECIPIENT_ENCRYPT,
            &selected,
        );
        assert!(app.get_key_invalid());
        assert_ne!(app.get_status_err(), "");

        // A damaged key is reported again whenever its direction comes back.
        let damaged = path_to_string(&dir.path().join("damaged.key"));
        fs::write(&damaged, b"not a key").unwrap();
        apply_key_path(
            &app,
            damaged.clone().into(),
            MODE_RECIPIENT_ENCRYPT,
            &selected,
        );
        assert!(app.get_key_invalid());
        apply_input_path(&app, sealed.clone(), &selected);
        shows(MODE_RECIPIENT_DECRYPT, &private_key);
        apply_input_path(&app, source, &selected);
        assert_eq!(app.get_key_path(), damaged.as_str());
        assert!(app.get_key_invalid(), "the damaged key's error was lost");
        assert_ne!(app.get_status_err(), "");

        // A key from a dialog opened before the mode changed is dropped.
        apply_input_path(&app, sealed.clone(), &selected);
        apply_key_path(
            &app,
            public_key.clone().into(),
            MODE_RECIPIENT_ENCRYPT,
            &selected,
        );
        shows(MODE_RECIPIENT_DECRYPT, &private_key);
        assert_eq!(app.get_chosen_public_key_path(), damaged.as_str());

        // A finished decryption clears its private key and shows the
        // recipient key again.
        choose_public_key(&app, &public_key, &selected);
        clear_after_operation(&app, MODE_RECIPIENT_DECRYPT, &selected);
        shows(MODE_RECIPIENT_ENCRYPT, &public_key);
        assert_eq!(app.get_chosen_private_key_path(), "");

        // A recipient key that can no longer be read is forgotten after a
        // decryption, so no error hides the result.
        apply_input_path(&app, sealed, &selected);
        choose_public_key(&app, &damaged, &selected);
        clear_after_operation(&app, MODE_RECIPIENT_DECRYPT, &selected);
        shows(MODE_RECIPIENT_ENCRYPT, "");
        assert_eq!(app.get_chosen_public_key_path(), "");

        // Reset forgets both.
        clear_fields(&app, &selected);
        assert_eq!(app.get_chosen_public_key_path(), "");
        assert_eq!(app.get_chosen_private_key_path(), "");
    }

    /// The font that draws masked passwords is the one the UI names: with any
    /// other name, Slint would fall back to Inter's much larger dot.
    #[test]
    fn the_password_mask_font_has_the_name_the_ui_uses() {
        const PROPERTY: &str = "password-mask-font: \"";
        let slint = include_str!("../ui/app.slint");
        let family = slint
            .split_once(PROPERTY)
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(family, _)| family)
            .expect("app.slint names the password mask font");
        let font = include_bytes!("../fonts/PasswordMask.ttf");
        assert_eq!(font_family_name(font), family);
    }

    /// The family name a font is looked up by, as its `name` table records it
    /// for Windows: the typographic family name if there is one, otherwise
    /// the family name.
    fn font_family_name(font: &[u8]) -> String {
        const TABLE_RECORDS: usize = 12;
        const TABLE_RECORD_SIZE: usize = 16;
        const NAME_RECORDS: usize = 6;
        const NAME_RECORD_SIZE: usize = 12;
        const WINDOWS_PLATFORM: usize = 3;
        const FAMILY_NAME: usize = 1;
        const TYPOGRAPHIC_FAMILY_NAME: usize = 16;

        let u16_at = |at: usize| usize::from(u16::from_be_bytes([font[at], font[at + 1]]));
        let u32_at = |at: usize| u32::from_be_bytes(font[at..at + 4].try_into().unwrap()) as usize;
        let table = (0..u16_at(4))
            .map(|i| TABLE_RECORDS + TABLE_RECORD_SIZE * i)
            .find(|&record| &font[record..record + 4] == b"name")
            .map(|record| u32_at(record + 8))
            .expect("the font has a name table");
        let strings = table + u16_at(table + 4);
        let name = |id: usize| {
            (0..u16_at(table + 2))
                .map(|i| table + NAME_RECORDS + NAME_RECORD_SIZE * i)
                .find(|&record| u16_at(record) == WINDOWS_PLATFORM && u16_at(record + 6) == id)
                .map(|record| {
                    let start = strings + u16_at(record + 10);
                    let units: Vec<u16> = font[start..start + u16_at(record + 8)]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|pair| u16::from_be_bytes(*pair))
                        .collect();
                    String::from_utf16(&units).expect("a UTF-16 name")
                })
        };
        name(TYPOGRAPHIC_FAMILY_NAME)
            .or_else(|| name(FAMILY_NAME))
            .expect("the font has a family name")
    }

    /// The fingerprint field shows the fingerprint with a line break
    /// opportunity halfway, and nothing else; the value copied stays as it is.
    #[test]
    fn the_fingerprint_may_break_only_halfway() {
        let app = headless_app();
        let fingerprint = "0123456789abcdef".repeat(4);
        show_fingerprint(&app, &fingerprint);
        assert_eq!(app.get_key_fingerprint(), fingerprint.as_str());
        let display = app.get_key_fingerprint_display();
        let (first, second) = display
            .split_once(LINE_BREAK_OPPORTUNITY)
            .expect("a break opportunity");
        assert_eq!(first.len(), fingerprint.len() / 2);
        assert_eq!(format!("{first}{second}"), fingerprint);

        show_fingerprint(&app, "");
        assert_eq!(app.get_key_fingerprint(), "");
        assert_eq!(app.get_key_fingerprint_display(), "");
    }

    /// A click on the active tab, or on the active key source, changes
    /// nothing, so a decrypt form stays a decrypt form and the passwords
    /// typed for a new key pair stay. A click on the other tab still
    /// switches, which shows the clicks land. The two tabs, and the two key
    /// sources, are equally wide whichever is active.
    #[test]
    #[cfg_attr(
        not(debug_assertions),
        ignore = "needs Slint debug info, which is compiled in only when debug assertions are on"
    )]
    fn a_click_on_the_active_choice_changes_nothing() {
        let app = headless_app();
        app.show().unwrap();
        let width = |id: &str| {
            ElementHandle::find_by_element_id(&app, id)
                .next()
                .unwrap_or_else(|| panic!("no element {id}"))
                .size()
                .width
        };

        for (mode, active) in [
            (MODE_PASSPHRASE_ENCRYPT, "AppWindow::password-tab"),
            (MODE_PASSPHRASE_DECRYPT, "AppWindow::password-tab"),
            (MODE_RECIPIENT_ENCRYPT, "AppWindow::key-pair-tab"),
            (MODE_RECIPIENT_DECRYPT, "AppWindow::key-pair-tab"),
            (MODE_RECIPIENT_ENCRYPT, "AppWindow::existing-key-choice"),
            (MODE_KEYGEN, "AppWindow::key-pair-tab"),
            (MODE_KEYGEN, "AppWindow::new-key-choice"),
        ] {
            app.set_mode(mode);
            click(&app, active, PointerEventButton::Left);
            assert_eq!(app.get_mode(), mode, "a click on {active} changed the mode");
            assert_eq!(
                width("AppWindow::password-tab"),
                width("AppWindow::key-pair-tab"),
                "mode {mode}: the tabs differ in width"
            );
            if matches!(mode, MODE_RECIPIENT_ENCRYPT | MODE_KEYGEN) {
                assert_eq!(
                    width("AppWindow::existing-key-choice"),
                    width("AppWindow::new-key-choice"),
                    "mode {mode}: the key sources differ in width"
                );
            }
        }

        app.set_mode(MODE_PASSPHRASE_ENCRYPT);
        click(&app, "AppWindow::key-pair-tab", PointerEventButton::Left);
        assert_eq!(
            app.get_mode(),
            MODE_RECIPIENT_ENCRYPT,
            "the other tab did not switch"
        );
    }

    /// The centre of the element `id`, in window coordinates.
    fn centre_of(app: &AppWindow, id: &str) -> slint::LogicalPosition {
        let element = ElementHandle::find_by_element_id(app, id)
            .next()
            .unwrap_or_else(|| panic!("no element {id}"));
        let (origin, size) = (element.absolute_position(), element.size());
        slint::LogicalPosition::new(origin.x + size.width / 2.0, origin.y + size.height / 2.0)
    }

    /// Presses `key` and releases it.
    fn tap_key(app: &AppWindow, key: slint::SharedString) {
        app.window()
            .dispatch_event(WindowEvent::KeyPressed { text: key.clone() });
        app.window()
            .dispatch_event(WindowEvent::KeyReleased { text: key });
    }

    /// Presses `id`'s centre with `button` and releases it there.
    fn click(app: &AppWindow, id: &str, button: PointerEventButton) {
        let position = centre_of(app, id);
        app.window()
            .dispatch_event(WindowEvent::PointerPressed { position, button });
        app.window()
            .dispatch_event(WindowEvent::PointerReleased { position, button });
    }

    /// The app's own title bar passes each gesture to the matching window
    /// action: pressing the bar moves the window, a right click opens the
    /// window menu where it was clicked, and each button does what its
    /// label says.
    #[test]
    #[cfg_attr(
        not(debug_assertions),
        ignore = "needs Slint debug info, which is compiled in only when debug assertions are on"
    )]
    fn the_own_title_bar_passes_each_gesture_to_its_action() {
        let app = headless_app();
        app.set_own_frame(true);
        let actions = Rc::new(RefCell::new(Vec::new()));
        let record = |action: &'static str| {
            let actions = actions.clone();
            move || actions.borrow_mut().push(action.to_string())
        };
        app.on_move_window(record("move"));
        app.on_minimize_window(record("minimize"));
        app.on_close_window(record("close"));
        app.on_show_window_menu({
            let actions = actions.clone();
            move |x, y| actions.borrow_mut().push(format!("menu at {x},{y}"))
        });
        app.show().unwrap();

        click(&app, "AppWindow::title-bar", PointerEventButton::Left);
        click(&app, "TitleBar::minimize-button", PointerEventButton::Left);
        click(&app, "TitleBar::close-button", PointerEventButton::Left);
        click(&app, "AppWindow::title-bar", PointerEventButton::Right);

        let bar = ElementHandle::find_by_element_id(&app, "AppWindow::title-bar")
            .next()
            .expect("the title bar exists");
        let centre = (bar.size().width / 2.0, bar.size().height / 2.0);
        assert_eq!(
            *actions.borrow(),
            [
                "move".to_string(),
                "minimize".to_string(),
                "close".to_string(),
                format!("menu at {},{}", centre.0, centre.1),
            ]
        );
    }

    /// The close button of the app's own title bar sends the request the
    /// system's close button sends, which closes the window.
    #[test]
    #[cfg(all(unix, not(target_vendor = "apple")))]
    #[cfg_attr(
        not(debug_assertions),
        ignore = "needs Slint debug info, which is compiled in only when debug assertions are on"
    )]
    fn the_own_close_button_closes_the_window() {
        let app = headless_app();
        app.set_own_frame(true);
        own_frame::wire(&app);
        app.show().unwrap();
        assert!(app.window().is_visible());

        click(&app, "TitleBar::close-button", PointerEventButton::Left);
        assert!(!app.window().is_visible(), "the window is still open");
    }

    /// A click after a window move reaches what is under the pointer. The
    /// compositor keeps the release of the press that started the move, so
    /// without it the title bar would keep the pointer, and the next press
    /// anywhere would start another move instead of reaching its target.
    #[test]
    #[cfg(all(unix, not(target_vendor = "apple")))]
    #[cfg_attr(
        not(debug_assertions),
        ignore = "needs Slint debug info, which is compiled in only when debug assertions are on"
    )]
    fn a_click_after_a_window_move_reaches_its_target() {
        let app = headless_app();
        app.set_own_frame(true);
        own_frame::wire(&app);
        app.show().unwrap();

        let position = centre_of(&app, "AppWindow::title-bar");
        let button = PointerEventButton::Left;
        app.window()
            .dispatch_event(WindowEvent::PointerPressed { position, button });
        slint::platform::update_timers_and_animations();

        click(&app, "TitleBar::close-button", button);
        assert!(
            !app.window().is_visible(),
            "the close button did not get the click"
        );
    }
}
