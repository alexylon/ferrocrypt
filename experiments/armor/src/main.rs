//! Smoke-test driver for the parked armor encoder/decoder.
//!
//! Round-trips a sample payload through `ArmoredWriter` →
//! `ArmoredReader`, prints the armored intermediate, the decoded
//! plaintext, and a couple of malformed-input rejections so you can
//! eyeball the typed `ArmorDefect` classes.
//!
//! Run with `cargo run --bin armor-demo` from `experiments/armor/`.

use std::io::{Read, Write};

use ferrocrypt_armor_experiment::{
    ArmorDefect, ArmoredReader, ArmoredWriter, BEGIN_MARKER, END_MARKER, Format,
};

fn main() {
    let payload =
        b"FerroCrypt armor experiment - round-tripping some bytes through the encoder/decoder.";

    println!("=== Round-trip ===");
    let armored = encode(payload);
    println!("--- armored ({} bytes) ---", armored.len());
    println!("{}", armored);
    let decoded = decode(armored.as_bytes()).expect("round-trip should succeed");
    println!("--- decoded ({} bytes) ---", decoded.len());
    println!("{}", String::from_utf8_lossy(&decoded));
    assert_eq!(decoded, payload);
    println!("OK: payload round-trips.\n");

    println!("=== Rejection samples (typed ArmorDefect classes) ===");

    show_rejection(
        "BEGIN_MARKER alone (no terminator)",
        BEGIN_MARKER.as_bytes(),
    );

    let mut bad = Vec::new();
    bad.extend_from_slice(BEGIN_MARKER.as_bytes());
    bad.push(b'\n');
    bad.extend_from_slice(&b"A".repeat(63));
    bad.push(b'?');
    bad.push(b'\n');
    bad.extend_from_slice(END_MARKER.as_bytes());
    bad.push(b'\n');
    show_rejection("Body line containing '?' (not in Base64 alphabet)", &bad);

    let mut bad = Vec::new();
    bad.extend_from_slice(BEGIN_MARKER.as_bytes());
    bad.push(b'\n');
    bad.extend_from_slice(b"AAAA\n");
    show_rejection("Body line, then EOF without END marker", &bad);
}

fn encode(plaintext: &[u8]) -> String {
    let mut out = Vec::new();
    {
        let mut w =
            ArmoredWriter::wrap_output(&mut out, Format::AsciiArmor).expect("writer init succeeds");
        w.write_all(plaintext).expect("write_all succeeds");
        w.finish().expect("finish succeeds");
    }
    String::from_utf8(out).expect("encoder emits ASCII")
}

fn decode(armored: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    ArmoredReader::new(armored).read_to_end(&mut out)?;
    Ok(out)
}

fn show_rejection(label: &str, input: &[u8]) {
    let mut sink = Vec::new();
    let result = ArmoredReader::new(input).read_to_end(&mut sink);
    match result {
        Ok(n) => {
            println!("[{label}] unexpectedly accepted {n} decoded bytes");
        }
        Err(e) => {
            let defect = e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<ArmorDefect>())
                .copied();
            match defect {
                Some(d) => println!("[{label}] -> ArmorDefect::{:?} ({d})", d),
                None => println!("[{label}] -> non-armor io::Error: {e}"),
            }
        }
    }
}
