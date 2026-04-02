use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

fn main() {
    slint_build::compile("ui/app.slint").unwrap();

    println!("cargo:rerun-if-changed=passwords.txt");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest = Path::new(&out_dir).join("common_passwords.rs");
    let mut out = File::create(dest).expect("could not create common_passwords.rs");
    out.write_all(b"const COMMON_PASSWORDS: &[&str] = &[")
        .unwrap();
    let src = BufReader::new(File::open("passwords.txt").expect("passwords.txt not found"));
    for line in src.lines() {
        let word = line.expect("error reading passwords.txt");
        let word = word.trim();
        if !word.is_empty() {
            write!(out, "\"{word}\",").unwrap();
        }
    }
    out.write_all(b"];").unwrap();
}
