#![no_main]
//! End-to-end fuzz target for the passphrase decrypt pipeline. Drives
//! arbitrary bytes through `Decryptor::open` + `PassphraseDecryptor::decrypt`
//! to keep coverage on the full wire-format → MAC → AEAD path. The
//! fuzz harness ignores all errors (rejection is the expected outcome
//! for almost every input); we only care that the library never panics.

use std::fs;
use std::io::Write;

use ferrocrypt::Passphrase;
use ferrocrypt::fuzz_exports::MIN_WRITE_MEM_COST;
use ferrocrypt::{Decryptor, KdfLimit};
use libfuzzer_sys::fuzz_target;

/// Passphrase the seed corpus is written under. A seed only reaches the
/// payload region if the harness offers the same one.
const FUZZ_PASSPHRASE: &str = "fuzz";

/// Argon2id budget for the harness, bounding what a crafted header can
/// demand per iteration.
///
/// Memory sits at the writer's floor rather than below it: a cap under
/// that floor refuses every file this library writes, so the seeds would
/// reach the cap and nothing beyond it. Time cost and lanes are pinned
/// to the cheapest legal values the seeds use, and the work cap follows
/// from them, so no header can order more than one floor-sized pass.
fn harness_kdf_limit() -> KdfLimit {
    KdfLimit::new(MIN_WRITE_MEM_COST)
        .max_time_cost(1)
        .max_lanes(4)
        .max_work(u64::from(MIN_WRITE_MEM_COST))
}

fuzz_target!(|data: &[u8]| {
    let tmp_dir = tempfile::tempdir().unwrap();
    let input_path = tmp_dir.path().join("input.fcr");
    let output_dir = tmp_dir.path().join("output");
    fs::create_dir_all(&output_dir).unwrap();

    let mut f = fs::File::create(&input_path).unwrap();
    f.write_all(data).unwrap();
    drop(f);

    if let Ok(Decryptor::Passphrase(d)) = Decryptor::open(&input_path) {
        let passphrase = Passphrase::new(FUZZ_PASSPHRASE);
        let _ = d
            .kdf_limit(harness_kdf_limit())
            .decrypt(passphrase, &output_dir, |_| {});
    }
});
