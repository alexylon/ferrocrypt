//! Concurrency safety for output finalization.
//!
//! Two races are covered, both on one shared output name:
//! - Several threads encrypt the same input into the same output directory, so
//!   they all target one derived `.fcr` name.
//! - Several threads decrypt the same `.fcr` into the same output directory, so
//!   they all target one derived output name and race the `.incomplete`
//!   staging plus the no-clobber promotion.
//!
//! Atomic no-clobber finalization means exactly one thread commits and the
//! committed output is complete and correct — never an interleaved blend of two
//! runs — and, on the decrypt side, no loser leaves `.incomplete` staging
//! behind (the default `DeleteOnError` policy cleans up under contention). The
//! invariant holds for any thread scheduling, so the tests are deterministic:
//! even if the threads serialize, the later ones fail the no-clobber check.

use std::fs;
use std::path::PathBuf;
use std::thread;

use ferrocrypt::Passphrase;
use ferrocrypt::{CryptoError, Decryptor, Encryptor, PrivateKey, PublicKey};
use ferrocrypt_test_support::{
    fast_keypair_generator, per_process_workspace, remove_per_process_workspace,
};

const PASSPHRASE: &str = "concurrency-test-passphrase";
const TEST_WORKSPACE: &str = "tests/workspace_concurrency";
const WRITERS: usize = 8;
const PAYLOAD_LEN: usize = 4 * 1024 * 1024;
const PAYLOAD_BYTE: u8 = 0x5A;

#[ctor::dtor]
fn cleanup() {
    remove_per_process_workspace(TEST_WORKSPACE);
}

fn fresh_workspace(name: &str) -> PathBuf {
    // Per-process subtree, so a concurrent `cargo test` invocation of this
    // binary cannot delete files this run is using.
    let dir = per_process_workspace(TEST_WORKSPACE).join(name);
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clean concurrency workspace");
    }
    fs::create_dir_all(&dir).expect("create concurrency workspace");
    dir
}

fn pass() -> Passphrase {
    Passphrase::new(PASSPHRASE)
}

#[test]
fn concurrent_encrypts_to_same_output_stay_no_clobber() {
    let work = fresh_workspace("same_output_race");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let kg = fast_keypair_generator(pass())
        .write(&keys, |_| {})
        .expect("keygen");

    // A payload large enough that the writers genuinely overlap on the final
    // rename rather than each finishing before the next begins.
    let input = work.join("payload.bin");
    fs::write(&input, vec![PAYLOAD_BYTE; PAYLOAD_LEN]).unwrap();

    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    // Every writer derives the same `payload.fcr` name in `out_dir` and races
    // the no-clobber finalize. Each loads the public key independently so no
    // key value is shared across threads.
    let outcomes: Vec<Result<PathBuf, CryptoError>> = thread::scope(|scope| {
        let handles: Vec<_> = (0..WRITERS)
            .map(|_| {
                scope.spawn(|| {
                    Encryptor::with_public_key(
                        PublicKey::from_key_file(&kg.public_key_path).expect("read public key"),
                    )
                    .write(&input, &out_dir, |_| {})
                    .map(|o| o.output_path)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("writer thread panicked"))
            .collect()
    });

    let winners = outcomes.iter().filter(|r| r.is_ok()).count();
    let losers = outcomes.len() - winners;
    assert_eq!(
        winners, 1,
        "exactly one writer must win the no-clobber race (got {winners} winners, {losers} losers)"
    );

    // Exactly one committed `.fcr` exists — no loser left a second file behind.
    let committed: Vec<PathBuf> = fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "fcr"))
        .collect();
    assert_eq!(
        committed.len(),
        1,
        "exactly one committed .fcr expected, found {committed:?}"
    );

    // The committed file is a complete, valid encryption of the original, not
    // a partial or blended write.
    let restore = work.join("restored");
    fs::create_dir_all(&restore).unwrap();
    let decrypted = match Decryptor::open(&committed[0]).expect("open committed file") {
        Decryptor::PrivateKey(d) => d
            .decrypt(
                PrivateKey::from_key_file(&kg.private_key_path, pass()),
                &restore,
                |_| {},
            )
            .expect("committed file must decrypt cleanly"),
        Decryptor::Passphrase(_) => panic!("expected private-key decryptor"),
        _ => {
            unreachable!("Decryptor is non_exhaustive; only Passphrase and PrivateKey exist today")
        }
    };
    let restored = fs::read(decrypted.output_path).unwrap();
    assert_eq!(
        restored,
        vec![PAYLOAD_BYTE; PAYLOAD_LEN],
        "committed output is not a clean encryption of the original"
    );
}

#[test]
fn concurrent_decrypts_to_same_output_stay_no_clobber() {
    let work = fresh_workspace("same_decrypt_output_race");
    let keys = work.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let kg = fast_keypair_generator(pass())
        .write(&keys, |_| {})
        .expect("keygen");

    // Encrypt one file to a single `.fcr` every decrypt thread will target.
    let input = work.join("payload.bin");
    fs::write(&input, vec![PAYLOAD_BYTE; PAYLOAD_LEN]).unwrap();
    let enc_dir = work.join("enc");
    fs::create_dir_all(&enc_dir).unwrap();
    let fcr = Encryptor::with_public_key(
        PublicKey::from_key_file(&kg.public_key_path).expect("read public key"),
    )
    .write(&input, &enc_dir, |_| {})
    .expect("encrypt")
    .output_path;

    // Every thread decrypts the same `.fcr` into one directory, so they all
    // derive the same `payload.bin` output name and race the `.incomplete`
    // staging plus the no-clobber promotion. Each loads its own private key so
    // no key value is shared across threads.
    let out_dir = work.join("dec");
    fs::create_dir_all(&out_dir).unwrap();

    let outcomes: Vec<Result<PathBuf, CryptoError>> = thread::scope(|scope| {
        let handles: Vec<_> = (0..WRITERS)
            .map(|_| {
                scope.spawn(
                    || match Decryptor::open(&fcr).expect("open committed file") {
                        Decryptor::PrivateKey(d) => d
                            .decrypt(
                                PrivateKey::from_key_file(&kg.private_key_path, pass()),
                                &out_dir,
                                |_| {},
                            )
                            .map(|o| o.output_path),
                        Decryptor::Passphrase(_) => panic!("expected private-key decryptor"),
                        _ => unreachable!(
                            "Decryptor is non_exhaustive; only Passphrase and PrivateKey exist today"
                        ),
                    },
                )
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("decrypt thread panicked"))
            .collect()
    });

    let winners = outcomes.iter().filter(|r| r.is_ok()).count();
    let losers = outcomes.len() - winners;
    assert_eq!(
        winners, 1,
        "exactly one decrypt must win the no-clobber race (got {winners} winners, {losers} losers)"
    );

    // The winning output is byte-identical to the original.
    let committed = out_dir.join("payload.bin");
    assert!(
        committed.exists(),
        "the winning decrypt must leave the final output in place"
    );
    assert_eq!(
        fs::read(&committed).unwrap(),
        vec![PAYLOAD_BYTE; PAYLOAD_LEN],
        "committed decrypt output does not match the original"
    );

    // No loser left `.incomplete` staging behind: the final output is the only
    // entry in the directory. `thread::scope` has already joined every thread
    // (including each loser's failure-path cleanup), so this is deterministic.
    let entries: Vec<PathBuf> = fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    assert_eq!(
        entries,
        vec![committed],
        "the race must leave exactly the final output, no .incomplete staging"
    );
}
