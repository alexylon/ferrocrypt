#![no_main]

//! Fuzzes `validate_tlv` — the canonical TLV extension-region parser.
//! Exercises every rejection path (reserved tags, non-ascending
//! ordering, duplicates, `len`-past-end, `ext_len` over cap, unknown
//! critical tags) without running any crypto.

use ferrocrypt::fuzz_exports::validate_tlv;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = validate_tlv(data);
});
