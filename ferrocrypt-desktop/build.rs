use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

fn main() {
    // Slint debug info lets the tests find window elements by id; release
    // builds leave it out. This variable follows the app's debug assertions,
    // where `cfg!(debug_assertions)` would follow the build script's own.
    let debug_info = std::env::var_os("CARGO_CFG_DEBUG_ASSERTIONS").is_some();
    slint_build::compile_with_config(
        "ui/app.slint",
        slint_build::CompilerConfiguration::new().with_debug_info(debug_info),
    )
    .unwrap();

    println!("cargo:rerun-if-changed=passwords.txt");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let output_path = Path::new(&out_dir).join("common_passwords.rs");
    let mut output_file = File::create(output_path).expect("could not create common_passwords.rs");
    output_file
        .write_all(b"pub(crate) const COMMON_PASSWORDS: &[&str] = &[")
        .unwrap();
    let input_file = BufReader::new(File::open("passwords.txt").expect("passwords.txt not found"));
    for line in input_file.lines() {
        let word = line.expect("error reading passwords.txt");
        let word = word.trim();
        if !word.is_empty() {
            write!(output_file, "\"{word}\",").unwrap();
        }
    }
    output_file.write_all(b"];").unwrap();
}
