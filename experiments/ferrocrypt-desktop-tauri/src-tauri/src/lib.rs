// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    EncryptionMode, detect_encryption_mode, generate_asymmetric_key_pair, hybrid_encryption,
    symmetric_encryption,
};

#[tauri::command]
fn start(
    inpath: &str,
    outpath: &str,
    password: String,
    keypath: String,
    mode: String,
) -> Result<String, String> {
    let password = SecretString::from(password);

    if mode == "se" || mode == "sd" {
        match symmetric_encryption(inpath, outpath, &password) {
            Ok(result) => Ok(result),
            Err(error) => Err(error.to_string()),
        }
    } else if mode == "he" || mode == "hd" {
        match hybrid_encryption(inpath, outpath, &keypath, &password) {
            Ok(result) => Ok(result),
            Err(error) => Err(error.to_string()),
        }
    } else {
        match generate_asymmetric_key_pair(4096, &password, outpath) {
            Ok(result) => Ok(result),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// Returns "sd" for symmetric, "hd" for hybrid, or "" if not a valid .fcr file.
#[tauri::command]
fn detect_mode(inpath: &str) -> String {
    match detect_encryption_mode(inpath) {
        Some(EncryptionMode::Symmetric) => "sd".to_string(),
        Some(EncryptionMode::Hybrid) => "hd".to_string(),
        None => String::new(),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![start, detect_mode])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
