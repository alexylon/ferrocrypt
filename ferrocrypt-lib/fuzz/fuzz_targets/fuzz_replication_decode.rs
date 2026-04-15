#![no_main]

//! Fuzzes the triple-replicated majority-vote decoder.
//!
//! `decode` is always called on the raw bytes. `decode_exact` is then
//! called with an expected logical length taken from the first input
//! byte (bounded to 255), which exercises the length-mismatch path
//! that guards `InvalidFormat(FormatDefect::CorruptedHeader)`.

use ferrocrypt::fuzz_exports::{decode, decode_exact};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode(data);

    if let Some((&len_byte, rest)) = data.split_first() {
        let _ = decode_exact(rest, usize::from(len_byte));
    }
});
