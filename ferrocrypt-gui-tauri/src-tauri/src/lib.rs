// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{generate_asymmetric_key_pair, hybrid_encryption, symmetric_encryption};

#[tauri::command]
fn start(
    inpath: &str,
    outpath: &str,
    password: String,
    is_large_file: bool,
    mut keypath: String,
    mode: String,
) -> Result<String, String> {
    let password = SecretString::from(password);

    if mode == "se" || mode == "sd" {
        match symmetric_encryption(inpath, outpath, &password, is_large_file) {
            Ok(result) => Ok(result),
            Err(error) => Err(error.to_string()),
        }
    } else if mode == "he" || mode == "hd" {
        match hybrid_encryption(inpath, outpath, keypath.as_mut_str(), &password) {
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![start])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
