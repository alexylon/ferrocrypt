use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

fn main() {
    slint_build::compile("ui/app.slint").unwrap();

    println!("cargo:rerun-if-changed=passwords.txt");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let output_path = Path::new(&out_dir).join("common_passwords.rs");
    let mut output_file = File::create(output_path).expect("could not create common_passwords.rs");
    output_file
        .write_all(b"const COMMON_PASSWORDS: &[&str] = &[")
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
