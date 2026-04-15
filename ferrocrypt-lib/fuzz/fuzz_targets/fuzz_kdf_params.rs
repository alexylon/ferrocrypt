#![no_main]

//! Fuzzes `KdfParams::from_bytes` — the 12-byte KDF parameter parser
//! that enforces every dimension's structural bound (lanes, mem_cost,
//! time_cost, plus rejection of zero values). No limit is supplied, so
//! only the hard structural bounds are exercised.

use ferrocrypt::fuzz_exports::{KDF_PARAMS_SIZE, KdfParams};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < KDF_PARAMS_SIZE {
        return;
    }
    let mut bytes = [0u8; KDF_PARAMS_SIZE];
    bytes.copy_from_slice(&data[..KDF_PARAMS_SIZE]);
    let _ = KdfParams::from_bytes(&bytes, None);
});
