#![no_main]

//! Fuzzes `KdfParams::from_bytes` — the 12-byte KDF parameter parser
//! that enforces every dimension's structural bound (lanes, mem_cost,
//! time_cost, plus rejection of zero values). `from_bytes(.., None)`
//! also applies the library default 1 GiB memory ceiling on top of
//! the structural bounds, so this target exercises the public parser
//! exactly as untrusted callers would invoke it. The structural-only
//! path (`KdfParams::from_bytes_structural`) is covered by in-module
//! unit tests in `crypto/kdf.rs`.

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
