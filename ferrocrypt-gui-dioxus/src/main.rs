use dioxus::desktop::{Config, WindowBuilder};
use dioxus::prelude::*;
use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{generate_asymmetric_key_pair, hybrid_encryption, symmetric_encryption};
use manganis::Asset;
use rfd::FileDialog;

const ICON_HIDE: Asset = asset!("/assets/icon-hide-50.png");
const ICON_UNHIDE: Asset = asset!("/assets/icon-unhide-50.png");
const ICON_DOT_GREEN: Asset = asset!("/assets/icon-dot-green-30.png");
const ICON_DOT_RED: Asset = asset!("/assets/icon-dot-red-30.png");
const LOGO: Asset = asset!("/assets/padlock-red-256.png");

fn main() {
    let config = Config::new().with_window(
        WindowBuilder::new()
            .with_title("Ferrocrypt")
            .with_resizable(false)
            .with_inner_size(dioxus::desktop::tao::dpi::LogicalSize::new(450.0, 720.0)),
    );

    LaunchBuilder::desktop().with_cfg(config).launch(App);
}

#[derive(Clone, PartialEq)]
enum Mode {
    SymmetricEncrypt,
    SymmetricDecrypt,
    HybridEncrypt,
    HybridDecrypt,
    GenerateKeyPair,
}

impl Mode {
    fn from_file(path: &str) -> Option<Self> {
        match ferrocrypt::detect_encryption_mode(path) {
            Some(ferrocrypt::EncryptionMode::Symmetric) => Some(Mode::SymmetricDecrypt),
            Some(ferrocrypt::EncryptionMode::Hybrid) => Some(Mode::HybridDecrypt),
            None => None,
        }
    }
}

#[component]
fn App() -> Element {
    let mut inpath = use_signal(|| String::new());
    let mut outpath = use_signal(|| String::new());
    let mut password = use_signal(|| String::new());
    let mut password_repeated = use_signal(|| String::new());
    let mut keypath = use_signal(|| String::new());
    let mut mode = use_signal(|| Mode::SymmetricEncrypt);
    let mut hide_password = use_signal(|| true);
    let mut status_ok = use_signal(|| String::from("Ready"));
    let mut status_err = use_signal(|| String::new());

    // Computed properties
    let require_password = move || {
        matches!(
            mode(),
            Mode::SymmetricEncrypt
                | Mode::SymmetricDecrypt
                | Mode::HybridDecrypt
                | Mode::GenerateKeyPair
        )
    };

    let require_password_repeated =
        move || matches!(mode(), Mode::SymmetricEncrypt | Mode::GenerateKeyPair) && hide_password();

    let require_key = move || matches!(mode(), Mode::HybridEncrypt | Mode::HybridDecrypt);

    let password_match = move || password() == password_repeated();

    let disable_start = move || match mode() {
        Mode::SymmetricEncrypt => {
            inpath().is_empty()
                || password().is_empty()
                || (require_password_repeated() && !password_match())
        }
        Mode::SymmetricDecrypt => inpath().is_empty() || password().is_empty(),
        Mode::HybridEncrypt => inpath().is_empty() || keypath().is_empty(),
        Mode::HybridDecrypt => inpath().is_empty() || password().is_empty() || keypath().is_empty(),
        Mode::GenerateKeyPair => {
            outpath().is_empty()
                || password().is_empty()
                || (require_password_repeated() && !password_match())
        }
    };

    let button_text = move || match mode() {
        Mode::SymmetricEncrypt | Mode::HybridEncrypt => "Encrypt",
        Mode::SymmetricDecrypt | Mode::HybridDecrypt => "Decrypt",
        Mode::GenerateKeyPair => "Create key pair",
    };

    let handle_select_input = move |_| {
        spawn(async move {
            if let Some(file) = FileDialog::new().pick_file() {
                let path = file.to_string_lossy().to_string();
                let dir_path = file
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                inpath.set(path.clone());
                outpath.set(dir_path);

                // Auto-detect mode from file extension
                if let Some(detected_mode) = Mode::from_file(&path) {
                    mode.set(detected_mode);
                }

                status_ok.set(String::from("Ready"));
                status_err.set(String::new());
            }
        });
    };

    let handle_select_key = move |_| {
        spawn(async move {
            if let Some(file) = FileDialog::new().pick_file() {
                keypath.set(file.to_string_lossy().to_string());
            }
        });
    };

    let handle_select_output_dir = move |_| {
        spawn(async move {
            if let Some(folder) = FileDialog::new().pick_folder() {
                outpath.set(folder.to_string_lossy().to_string());
            }
        });
    };

    let handle_clear = move |_| {
        inpath.set(String::new());
        outpath.set(String::new());
        password.set(String::new());
        password_repeated.set(String::new());
        keypath.set(String::new());
        mode.set(Mode::SymmetricEncrypt);
        hide_password.set(true);
        status_ok.set(String::from("Ready"));
        status_err.set(String::new());
    };

    let handle_start = move |_| {
        spawn(async move {
            status_ok.set(String::from("Working..."));
            status_err.set(String::new());

            let result = match mode() {
                Mode::SymmetricEncrypt | Mode::SymmetricDecrypt => {
                    let pwd = SecretString::from(password());
                    symmetric_encryption(&inpath(), &outpath(), &pwd)
                }
                Mode::HybridEncrypt | Mode::HybridDecrypt => {
                    let mut key = keypath();
                    let pwd = SecretString::from(password());
                    hybrid_encryption(&inpath(), &outpath(), key.as_mut_str(), &pwd)
                }
                Mode::GenerateKeyPair => {
                    let pwd = SecretString::from(password());
                    generate_asymmetric_key_pair(4096, &pwd, &outpath())
                }
            };

            match result {
                Ok(message) => {
                    // Clear form on success
                    inpath.set(String::new());
                    outpath.set(String::new());
                    password.set(String::new());
                    password_repeated.set(String::new());
                    keypath.set(String::new());
                    mode.set(Mode::SymmetricEncrypt);
                    hide_password.set(true);

                    status_ok.set(message);
                    status_err.set(String::new());
                }
                Err(error) => {
                    status_ok.set(String::new());
                    status_err.set(error.to_string());
                }
            }
        });
    };

    rsx! {
        style { {include_str!("../assets/styles.css")} }

        div {
            class: "container",

            // Logo/Header
            div {
                class: "row",
                div {
                    class: "link",
                    img {
                        src: LOGO,
                        class: "logo ferrocrypt",
                        alt: "Ferrocrypt logo"
                    }
                }
            }

            // Helper text
            div {
                class: if matches!(mode(), Mode::GenerateKeyPair) { "helper disabled" } else { "helper" },
                "Select a file or folder"
            }

            // Input path
            div {
                class: "row",
                input {
                    id: "inpath",
                    disabled: true,
                    value: if matches!(mode(), Mode::GenerateKeyPair) { "" } else { "{inpath}" },
                    style: "margin-right: 10px;"
                }
                button {
                    onclick: handle_select_input,
                    disabled: matches!(mode(), Mode::GenerateKeyPair),
                    style: "margin-right: 10px;",
                    "Select"
                }
                button {
                    onclick: handle_clear,
                    "Clear"
                }
            }

            // Mode selection radios
            div {
                class: "cbx-form",
                label {
                    r#for: "rdo1",
                    input {
                        r#type: "radio",
                        id: "rdo1",
                        name: "radio",
                        checked: matches!(mode(), Mode::SymmetricEncrypt | Mode::SymmetricDecrypt),
                        disabled: matches!(mode(), Mode::HybridDecrypt),
                        onchange: move |_| mode.set(Mode::SymmetricEncrypt)
                    }
                    span { class: "rdo" }
                    span { class: "rdo-label", "Symmetric" }
                }
                span { class: "spacer-15" }
                label {
                    r#for: "rdo2",
                    input {
                        r#type: "radio",
                        id: "rdo2",
                        name: "radio",
                        checked: matches!(mode(), Mode::HybridEncrypt | Mode::HybridDecrypt),
                        disabled: matches!(mode(), Mode::SymmetricDecrypt),
                        onchange: move |_| mode.set(Mode::HybridEncrypt)
                    }
                    span { class: "rdo" }
                    span { class: "rdo-label", "Hybrid" }
                }
                span { class: "spacer-15" }
                label {
                    r#for: "rdo3",
                    input {
                        r#type: "radio",
                        id: "rdo3",
                        name: "radio",
                        checked: matches!(mode(), Mode::GenerateKeyPair),
                        disabled: matches!(mode(), Mode::SymmetricDecrypt | Mode::HybridDecrypt) || !inpath().is_empty(),
                        onchange: move |_| mode.set(Mode::GenerateKeyPair)
                    }
                    span { class: "rdo" }
                    span { class: "rdo-label", "Create key pair" }
                }
            }

            // Password input
            label {
                class: if require_password() { "helper" } else { "helper disabled" },
                "Password:"
            }
            div {
                class: "row",
                input {
                    id: "password-input",
                    r#type: if hide_password() { "password" } else { "text" },
                    value: "{password}",
                    disabled: !require_password(),
                    oninput: move |e| password.set(e.value()),
                    placeholder: if require_password() { "Enter a password..." } else { "" }
                }
                if require_password() && matches!(mode(), Mode::SymmetricEncrypt | Mode::SymmetricDecrypt | Mode::HybridDecrypt | Mode::GenerateKeyPair) {
                    div {
                        class: "visibility-icon",
                        onclick: move |_| hide_password.set(!hide_password()),
                        img {
                            src: if hide_password() { ICON_UNHIDE } else { ICON_HIDE },
                            alt: "visibility icon",
                            style: "width: 20px; height: 20px; cursor: pointer;"
                        }
                    }
                }
            }

            // Password repeat input
            div {
                class: "row",
                input {
                    id: "repeat-password-input",
                    r#type: "password",
                    value: "{password_repeated}",
                    disabled: !require_password_repeated(),
                    oninput: move |e| password_repeated.set(e.value()),
                    placeholder: if require_password_repeated() { "Repeat the password..." } else { "" }
                }
                if require_password_repeated() && !password_repeated().is_empty() {
                    div {
                        class: "match-icon",
                        img {
                            src: if password_match() { ICON_DOT_GREEN } else { ICON_DOT_RED },
                            alt: "match icon",
                            style: "width: 20px; height: 20px;"
                        }
                    }
                }
            }

            // Key input
            label {
                class: if require_key() { "helper" } else { "helper disabled" },
                "Key (PEM format):"
            }
            div {
                class: "row",
                input {
                    id: "key",
                    disabled: true,
                    value: "{keypath}",
                    placeholder: match mode() {
                        Mode::HybridEncrypt => "Select a public key...",
                        Mode::HybridDecrypt => "Select your private key...",
                        _ => ""
                    },
                    style: "margin-right: 10px;"
                }
                button {
                    onclick: handle_select_key,
                    disabled: !require_key(),
                    "Select"
                }
            }


            // Output directory
            div {
                class: "helper",
                "Save output to this folder:"
            }
            div {
                class: "row",
                input {
                    id: "outpath",
                    disabled: true,
                    value: "{outpath}",
                    style: "margin-right: 10px;"
                }
                button {
                    onclick: handle_select_output_dir,
                    "Select"
                }
            }

            hr { class: "solid" }

            // Start button
            div {
                class: "row",
                style: "justify-content: center;",
                button {
                    onclick: handle_start,
                    disabled: disable_start(),
                    style: "width: 350px;",
                    "{button_text()}"
                }
            }

            // Status messages
            div {
                class: "helper",
                style: "color: darkseagreen;",
                "{status_ok}"
            }
            div {
                class: "helper",
                style: "color: #C41E3A;",
                "{status_err}"
            }
        }
    }
}
