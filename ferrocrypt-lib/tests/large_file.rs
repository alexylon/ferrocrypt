//! Large-file round trip crossing the 4 GiB (`u32::MAX`) boundary.
//!
//! The STREAM chunk counter is bounded far above this size, so 4 GiB is not
//! about counter overflow — it is about the `u64` size and byte-total fields
//! and any `usize`/`u32` cast in size accounting or progress math. No other
//! test moves more than 3 GiB through real I/O, so a truncation or wrap in a
//! size field above `u32::MAX` would be invisible. This test encrypts and
//! decrypts a file just over 4 GiB with a position-dependent payload (so a
//! reordered or truncated stream changes the checksum) and asserts the round
//! trip preserves both the exact length and a streamed content hash.
//!
//! Ignored by default (multi-GiB I/O and disk). Run it in a release
//! qualification lane, on a machine with a few spare GiB of disk:
//!
//! ```text
//! cargo test -p ferrocrypt --release --test large_file -- --ignored --test-threads=1
//! ```
//!
//! `FERROCRYPT_LARGE_FILE_BYTES` overrides the payload size (bytes); the
//! default is `4 * 1024 * 1024 * 1024 + 3`. A small override (e.g. a few MiB)
//! exercises the harness quickly without crossing the boundary.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{Decryptor, Encryptor, PrivateKey, PublicKey};
use ferrocrypt_test_support::{
    fast_keypair_generator, per_process_workspace, remove_per_process_workspace,
};

const TEST_WORKSPACE: &str = "tests/workspace_large_file";
const PASSPHRASE: &str = "large-file-test-passphrase";
/// Just over `u32::MAX` (4 GiB) so the payload length and total-file-byte
/// fields hold a value no 32-bit type can represent.
const DEFAULT_BYTES: u64 = 4 * 1024 * 1024 * 1024 + 3;
/// Streaming buffer for writing and comparing the payload.
const CHUNK: usize = 1024 * 1024;

#[ctor::dtor]
fn cleanup() {
    remove_per_process_workspace(TEST_WORKSPACE);
}

fn payload_bytes() -> u64 {
    match std::env::var("FERROCRYPT_LARGE_FILE_BYTES") {
        Ok(v) => v
            .trim()
            .parse()
            .expect("FERROCRYPT_LARGE_FILE_BYTES must be a byte count"),
        Err(_) => DEFAULT_BYTES,
    }
}

/// Byte value at logical offset `pos`. Position-dependent (not a constant
/// fill) so a stream that dropped, duplicated, or reordered a region above
/// `u32::MAX` produces a different hash, not an accidental match.
fn payload_byte(pos: u64) -> u8 {
    (pos % 251) as u8
}

/// Writes a `len`-byte position-dependent payload to `path`, streaming so the
/// whole file never sits in memory.
fn write_payload(path: &Path, len: u64) {
    let mut f = File::create(path).expect("create payload");
    let mut buf = vec![0u8; CHUNK];
    let mut written: u64 = 0;
    while written < len {
        let n = std::cmp::min(CHUNK as u64, len - written) as usize;
        for (i, b) in buf.iter_mut().enumerate().take(n) {
            *b = payload_byte(written + i as u64);
        }
        f.write_all(&buf[..n]).expect("write payload chunk");
        written += n as u64;
    }
    f.sync_all().expect("sync payload");
}

/// Streams `path`, returning `(length, FNV-1a-64 hash)`. Length plus a
/// full-content hash detects truncation, extension, and any content change
/// without holding the file in memory.
fn hash_file(path: &Path) -> (u64, u64) {
    let mut f = File::open(path).expect("open for hashing");
    let mut buf = vec![0u8; CHUNK];
    let mut len: u64 = 0;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis.
    loop {
        let n = f.read(&mut buf).expect("read for hashing");
        if n == 0 {
            break;
        }
        len += n as u64;
        for &b in &buf[..n] {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3); // FNV prime.
        }
    }
    (len, hash)
}

#[test]
#[ignore = "slow-large-file: >4 GiB I/O; run in a release qualification lane"]
fn round_trip_file_larger_than_4gib() {
    let len = payload_bytes();
    let work = per_process_workspace(TEST_WORKSPACE).join("over_4gib");
    if work.exists() {
        fs::remove_dir_all(&work).unwrap();
    }
    fs::create_dir_all(&work).unwrap();

    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let pass = SecretString::from(PASSPHRASE.to_string());
    let kg = fast_keypair_generator(pass.clone())
        .write(&keys, |_| {})
        .expect("keygen");

    // Public-key mode keeps Argon2id off the encrypt path so the run is
    // dominated by streaming the payload, not key derivation.
    let input = work.join("big.bin");
    write_payload(&input, len);
    let (input_len, input_hash) = hash_file(&input);
    assert_eq!(
        input_len, len,
        "payload was not written at the requested length"
    );

    let enc_dir = work.join("enc");
    fs::create_dir_all(&enc_dir).unwrap();
    let fcr: PathBuf = Encryptor::with_public_key(PublicKey::from_key_file(&kg.public_key_path))
        .write(&input, &enc_dir, |_| {})
        .expect("encrypt >4 GiB file")
        .output_path;

    // Free the input's disk before decrypting so peak usage stays near
    // two copies, not three.
    fs::remove_file(&input).unwrap();

    let dec_dir = work.join("dec");
    fs::create_dir_all(&dec_dir).unwrap();
    let out = match Decryptor::open(&fcr).expect("open") {
        Decryptor::PrivateKey(d) => {
            d.decrypt(
                PrivateKey::from_key_file(&kg.private_key_path),
                pass,
                &dec_dir,
                |_| {},
            )
            .expect("decrypt >4 GiB file")
            .output_path
        }
        _ => panic!("expected private-key decryptor"),
    };

    let (out_len, out_hash) = hash_file(&out);
    assert_eq!(
        out_len, input_len,
        "decrypted length differs from the original"
    );
    assert_eq!(
        out_hash, input_hash,
        "decrypted content differs from the original"
    );
}
