//! Streaming memory bound for encryption.
//!
//! A `stats_alloc` global allocator records how many bytes a public-key encrypt
//! of a large file allocates. Public-key mode is used so Argon2id — which
//! legitimately allocates its whole memory cost — stays off the measured path.
//! The encryptor reuses one fixed chunk buffer, so a streaming run allocates a
//! near-constant amount regardless of file size. Total bytes allocated far
//! below the file size proves the payload streams in fixed-size chunks; a
//! regression that buffered the whole file would allocate at least the file
//! size and trip the bound.

use std::alloc::System;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use ferrocrypt::Passphrase;
use ferrocrypt::{Encryptor, PublicKey};
use ferrocrypt_test_support::{
    fast_keypair_generator, per_process_workspace, remove_per_process_workspace,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const PASSPHRASE: &str = "memory-bounds-test-passphrase";
const TEST_WORKSPACE: &str = "tests/workspace_memory_bounds";
const MIB: usize = 1024 * 1024;
/// Large enough that a whole-file buffer could not hide under the bound.
const FILE_BYTES: usize = 64 * MIB;
/// A streaming run allocates a near-constant ~90 KiB (one reused 64 KiB chunk
/// buffer plus the small manifest and header). This bound sits far below the
/// file size: a whole-file buffer (>= 64 MiB) cannot pass, while genuine
/// streaming clears it with wide margin.
const ALLOC_BOUND: usize = 8 * MIB;

#[ctor::dtor]
fn cleanup() {
    remove_per_process_workspace(TEST_WORKSPACE);
}

fn fresh_workspace(name: &str) -> PathBuf {
    let dir = per_process_workspace(TEST_WORKSPACE).join(name);
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clean memory-bounds workspace");
    }
    fs::create_dir_all(&dir).expect("create memory-bounds workspace");
    dir
}

#[test]
fn public_key_encrypt_streams_without_buffering_whole_file() {
    let work = fresh_workspace("stream_bound");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let kg = fast_keypair_generator(Passphrase::new(PASSPHRASE))
        .write(&keys, |_| {})
        .expect("keygen");
    let key = PublicKey::from_key_file(&kg.public_key_path).expect("read public key");

    // Write the input in fixed-size chunks so its bytes are never all resident
    // at once; this runs before the measured region begins.
    let input = work.join("large.bin");
    {
        let mut f = File::create(&input).unwrap();
        let chunk = vec![0xA5u8; MIB];
        for _ in 0..(FILE_BYTES / MIB) {
            f.write_all(&chunk).unwrap();
        }
        f.sync_all().unwrap();
    }

    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let region = Region::new(GLOBAL);
    Encryptor::with_public_key(key)
        .write(&input, &out_dir, |_| {})
        .expect("encrypt");
    let allocated = region.change().bytes_allocated;

    // Visible with `cargo test -- --nocapture` for calibration.
    eprintln!(
        "bytes allocated during {} MiB encrypt: {} bytes ({} KiB)",
        FILE_BYTES / MIB,
        allocated,
        allocated / 1024,
    );

    assert!(
        allocated < ALLOC_BOUND,
        "a {} MiB encrypt allocated {allocated} bytes, over the {} MiB streaming bound — \
         the payload appears to be buffered rather than streamed",
        FILE_BYTES / MIB,
        ALLOC_BOUND / MIB,
    );
}
