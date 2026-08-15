//! Regenerates the checked-in corpus seeds under `seeds/`.
//!
//! Run from `ferrocrypt-lib/fuzz` after any wire-format change:
//!
//! ```bash
//! cargo run --example gen_seeds
//! ```
//!
//! Every seed is produced by the production writer (or patched from
//! its output) and then validated through the same reader entry point
//! the fuzz target drives, so a seed that no longer matches the format
//! fails regeneration instead of silently rotting. Seeds are also
//! copied into the gitignored local `corpus/` directories so local
//! runs pick them up without extra arguments.

use std::fs;
use std::path::{Path, PathBuf};

use ferrocrypt::fuzz_exports::{
    FCA_HEADER_SIZE, MIN_WRITE_MEM_COST, archive_for_fuzz, decrypt_stream_for_fuzz,
    empty_final_after_data_stream_for_fuzz, encrypt_stream_for_fuzz, parse_public_key_file_bytes,
    unarchive_for_fuzz,
};
use ferrocrypt::{
    ArchiveLimits, CryptoError, Decryptor, Encryptor, FormatDefect, KdfLimit, KdfParams,
    KeyPairGenerator, Passphrase, PrivateKey, PublicKey,
};

/// FCA fixed-header layout fact needed to splice an `archive_ext`
/// region into writer output (the v1 writer always emits a zero-length
/// region): `magic(4) || version(1) || flags(2) || entry_count(4)`
/// puts `archive_ext_len` at offset 11 (`FORMAT.md` §9.2). The header
/// length itself comes from `FCA_HEADER_SIZE`, so the two crates cannot
/// disagree about it.
const FCA_ARCHIVE_EXT_LEN_OFFSET: usize = 11;

/// One ignorable TLV entry (`FORMAT.md` §6): tag `0x0001` (ignorable
/// range), length 2, two value bytes.
const IGNORABLE_TLV: [u8; 8] = [0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB];

/// Six-byte `private.key` signature `magic(4) || version(1) || kind(1)
/// = 'K'` (`FORMAT.md` §8), used to pin wrong-file-type routing in the
/// `public.key` parser.
const PRIVATE_KEY_SIGNATURE: [u8; 6] = [b'F', b'C', b'R', 0x00, 0x01, b'K'];

/// Passphrase the decrypt harnesses use. A seed only reaches the
/// payload region if it was written under the same one.
const FUZZ_PASSPHRASE: &str = "fuzz";

/// Passphrase sealing the committed fixture `private.key`.
const FUZZ_KEY_PASSPHRASE: &str = "fuzz_key";

/// Argon2id parameters every fuzz artefact is written with: memory at
/// the writer's floor (the least it will emit) and the cheapest legal
/// time and lane counts, so an unlock costs the fuzzer as little as the
/// format allows. The harnesses cap their readers' memory and total
/// work at that floor, which bounds what a crafted header can demand
/// per iteration.
fn fuzz_kdf_params() -> KdfParams {
    KdfParams {
        mem_cost: MIN_WRITE_MEM_COST,
        time_cost: 1,
        lanes: 4,
    }
}

/// The reader budget every decrypt seed is validated under. Kept in
/// lockstep with `harness_kdf_limit` in both decrypt targets, so a seed
/// that validates here is exactly one the fuzzers accept.
fn fuzz_kdf_limit() -> KdfLimit {
    KdfLimit::new(MIN_WRITE_MEM_COST).max_work(u64::from(MIN_WRITE_MEM_COST))
}

fn main() {
    let fuzz_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    write_fca_seeds(&fuzz_root);
    write_stream_seeds(&fuzz_root);
    write_public_key_seeds(&fuzz_root);
    write_symmetric_decrypt_seeds(&fuzz_root);
    write_hybrid_decrypt_seeds(&fuzz_root);
    println!("seeds regenerated and validated");
}

/// The plaintexts both decrypt targets are seeded with: an empty file,
/// a short one, and one crossing the 64 KiB payload chunk boundary so
/// the multi-chunk path is reachable from the first iteration.
fn decrypt_seed_inputs() -> [(&'static str, Vec<u8>); 3] {
    const CHUNK: usize = 65_536;
    [
        ("empty.fcr", Vec::new()),
        ("small.fcr", b"hello ferrocrypt decrypt".to_vec()),
        (
            "chunk_plus_seven.fcr",
            (0..CHUNK + 7).map(|i| (i % 251) as u8).collect(),
        ),
    ]
}

/// Reads a committed seed, or writes one with `produce` when it is
/// absent.
///
/// Encryption draws fresh randomness for every file, so these seeds
/// cannot be reproduced byte for byte the way the archive and key seeds
/// are. Regenerating them unconditionally would rewrite them on every
/// run and leave a maintainer unable to tell a wire-format change from
/// ordinary randomness. They are therefore committed artefacts, minted
/// once and validated from then on — delete the file and rerun to
/// replace it deliberately.
fn committed_seed(
    fuzz_root: &Path,
    target: &str,
    name: &str,
    produce: impl Fn() -> Vec<u8>,
) -> Vec<u8> {
    let committed = fuzz_root.join("seeds").join(target).join(name);
    match fs::read(&committed) {
        Ok(bytes) => bytes,
        Err(_) => {
            println!("  minting {target}/{name}");
            produce()
        }
    }
}

/// Encrypted-file seeds for the passphrase decrypt target.
///
/// Every seed is decrypted under [`fuzz_kdf_limit`] — the harness's own
/// budget — so a seed the harness would refuse at its cap, or one the
/// reader no longer accepts, fails generation instead of quietly
/// covering nothing.
fn write_symmetric_decrypt_seeds(fuzz_root: &Path) {
    for (name, plaintext) in decrypt_seed_inputs() {
        let staging = tempfile::tempdir().expect("staging tempdir");
        let input = staging.path().join("payload.bin");
        fs::write(&input, &plaintext).unwrap();
        let out_dir = staging.path().join("out");
        fs::create_dir_all(&out_dir).unwrap();

        let bytes = committed_seed(fuzz_root, "fuzz_symmetric_decrypt", name, || {
            let written = Encryptor::with_passphrase(Passphrase::new(FUZZ_PASSPHRASE))
                .kdf_params(fuzz_kdf_params())
                .write(&input, &out_dir, |_| {})
                .unwrap_or_else(|e| panic!("seed {name} must encrypt: {e}"))
                .output_path;
            fs::read(&written).unwrap()
        });
        let encrypted = staging.path().join("seed.fcr");
        fs::write(&encrypted, &bytes).unwrap();

        let restore = staging.path().join("restore");
        fs::create_dir_all(&restore).unwrap();
        let Decryptor::Passphrase(decryptor) =
            Decryptor::open(&encrypted).unwrap_or_else(|e| panic!("seed {name} must open: {e}"))
        else {
            panic!("seed {name} must open as a passphrase decryptor");
        };
        let restored = decryptor
            .kdf_limit(fuzz_kdf_limit())
            .decrypt(Passphrase::new(FUZZ_PASSPHRASE), &restore, |_| {})
            .unwrap_or_else(|e| panic!("seed {name} must decrypt under the harness budget: {e}"))
            .output_path;
        assert_eq!(fs::read(&restored).unwrap(), plaintext, "seed {name}");

        persist(fuzz_root, "fuzz_symmetric_decrypt", name, &bytes);
    }
}

/// The committed fixture key pair the hybrid harness decrypts with.
///
/// It is committed rather than generated per run because a seed can only
/// reach the payload region if the harness holds the matching private
/// key: a harness generating its own key can never be handed a valid
/// input. Key generation is not deterministic, so this is a stable
/// artefact like the frozen format fixtures — delete the directory and
/// rerun to mint a new one, which invalidates the seeds below and
/// regenerates them in the same pass.
fn fixture_key_pair(fuzz_root: &Path) -> (PathBuf, PathBuf) {
    let dir = fuzz_root.join("fixtures").join("hybrid");
    let private = dir.join("private.key");
    let public = dir.join("public.key");
    if !private.exists() || !public.exists() {
        fs::create_dir_all(&dir).unwrap();
        let _ = fs::remove_file(&private);
        let _ = fs::remove_file(&public);
        KeyPairGenerator::with_passphrase(Passphrase::new(FUZZ_KEY_PASSPHRASE))
            .kdf_params(fuzz_kdf_params())
            .write(&dir, |_| {})
            .expect("generate the fixture key pair");
        println!(
            "  minted a new hybrid fixture key pair in {}",
            dir.display()
        );
    }
    (private, public)
}

/// Encrypted-file seeds for the public-key decrypt target, written to
/// the committed fixture recipient and validated with its private key.
fn write_hybrid_decrypt_seeds(fuzz_root: &Path) {
    let (private_key_path, public_key_path) = fixture_key_pair(fuzz_root);

    for (name, plaintext) in decrypt_seed_inputs() {
        let staging = tempfile::tempdir().expect("staging tempdir");
        let input = staging.path().join("payload.bin");
        fs::write(&input, &plaintext).unwrap();
        let out_dir = staging.path().join("out");
        fs::create_dir_all(&out_dir).unwrap();

        let bytes = committed_seed(fuzz_root, "fuzz_hybrid_decrypt", name, || {
            let written = Encryptor::with_public_key(
                PublicKey::from_key_file(&public_key_path).expect("read the fixture public key"),
            )
            .write(&input, &out_dir, |_| {})
            .unwrap_or_else(|e| panic!("seed {name} must encrypt: {e}"))
            .output_path;
            fs::read(&written).unwrap()
        });
        let encrypted = staging.path().join("seed.fcr");
        fs::write(&encrypted, &bytes).unwrap();

        let restore = staging.path().join("restore");
        fs::create_dir_all(&restore).unwrap();
        let Decryptor::PrivateKey(decryptor) =
            Decryptor::open(&encrypted).unwrap_or_else(|e| panic!("seed {name} must open: {e}"))
        else {
            panic!("seed {name} must open as a private-key decryptor");
        };
        let restored = decryptor
            .kdf_limit(fuzz_kdf_limit())
            .decrypt(
                PrivateKey::from_key_file(&private_key_path, Passphrase::new(FUZZ_KEY_PASSPHRASE)),
                &restore,
                |_| {},
            )
            .unwrap_or_else(|e| panic!("seed {name} must decrypt under the harness budget: {e}"))
            .output_path;
        assert_eq!(fs::read(&restored).unwrap(), plaintext, "seed {name}");

        persist(fuzz_root, "fuzz_hybrid_decrypt", name, &bytes);
    }
}

/// Pins every staged path to a fixed mode so regenerated seeds are
/// byte-identical on any machine — without this, the process umask
/// leaks into the archived entry modes. No-op on non-Unix, where the
/// writer records fixed default modes already.
fn normalize_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

fn write_fca_seeds(fuzz_root: &Path) {
    let staging = tempfile::tempdir().expect("staging tempdir");

    // Single-file root.
    let file_root = staging.path().join("hello.txt");
    fs::write(&file_root, b"hello ferrocrypt\n").unwrap();
    normalize_mode(&file_root, 0o644);
    let single_file = archive_for_fuzz(&file_root).expect("archive single-file root");

    // Nested tree: directories, a sub-file, and an empty file.
    let tree_root = staging.path().join("tree");
    fs::create_dir_all(tree_root.join("sub/inner")).unwrap();
    fs::write(tree_root.join("a.txt"), b"alpha").unwrap();
    fs::write(tree_root.join("sub/b.bin"), [0u8; 300]).unwrap();
    fs::write(tree_root.join("sub/inner/empty"), b"").unwrap();
    for dir in ["", "sub", "sub/inner"] {
        normalize_mode(&tree_root.join(dir), 0o755);
    }
    for file in ["a.txt", "sub/b.bin", "sub/inner/empty"] {
        normalize_mode(&tree_root.join(file), 0o644);
    }
    let nested_tree = archive_for_fuzz(&tree_root).expect("archive nested tree");

    // Directory root with no children.
    let empty_root = staging.path().join("emptydir");
    fs::create_dir(&empty_root).unwrap();
    normalize_mode(&empty_root, 0o755);
    let empty_dir = archive_for_fuzz(&empty_root).expect("archive empty dir root");

    // Ignorable `archive_ext`: the v1 writer emits a zero-length
    // region, so patch one in — set `archive_ext_len` and insert the
    // TLV bytes right after the fixed header. The reader validation
    // below proves the offsets.
    let mut with_ext = single_file.clone();
    with_ext[FCA_ARCHIVE_EXT_LEN_OFFSET..FCA_ARCHIVE_EXT_LEN_OFFSET + 4]
        .copy_from_slice(&(IGNORABLE_TLV.len() as u32).to_be_bytes());
    with_ext.splice(FCA_HEADER_SIZE..FCA_HEADER_SIZE, IGNORABLE_TLV);

    let seeds: [(&str, &[u8]); 4] = [
        ("single_file_root.fca", &single_file),
        ("nested_tree.fca", &nested_tree),
        ("empty_dir_root.fca", &empty_dir),
        ("ignorable_archive_ext.fca", &with_ext),
    ];
    for (name, bytes) in seeds {
        let out = tempfile::tempdir().expect("validation tempdir");
        unarchive_for_fuzz(bytes, out.path(), ArchiveLimits::default())
            .unwrap_or_else(|e| panic!("seed {name} must extract cleanly: {e}"));
        persist(fuzz_root, "fuzz_fca_full_pipeline", name, bytes);
        // The same bytes are valid inputs for the manifest-layer
        // target (it parses the identical header + manifest region),
        // so seed it too.
        persist(fuzz_root, "fuzz_fca_manifest", name, bytes);
    }
}

fn write_stream_seeds(fuzz_root: &Path) {
    const CHUNK: usize = 65_536;
    let patterned: Vec<u8> = (0..CHUNK + 7).map(|i| (i % 251) as u8).collect();
    let seeds: [(&str, &[u8]); 4] = [
        ("empty_plaintext.bin", b""),
        ("small.bin", b"hello ferrocrypt stream"),
        // Exact one-chunk plaintext: exercises the full-size FINAL
        // chunk and the one-byte peek that classifies it.
        ("exact_chunk.bin", &patterned[..CHUNK]),
        // One full chunk plus a short tail: exercises `decrypt_next`
        // followed by a short final chunk.
        ("chunk_plus_seven.bin", &patterned),
    ];
    for (name, plaintext) in seeds {
        let ciphertext = encrypt_stream_for_fuzz(plaintext).expect("seed encrypt");
        let recovered = decrypt_stream_for_fuzz(&ciphertext)
            .unwrap_or_else(|e| panic!("seed {name} must decrypt: {e}"));
        assert_eq!(recovered, plaintext, "seed {name} round-trip");
        persist(fuzz_root, "fuzz_stream_decrypt", name, &ciphertext);
    }

    let noncanonical =
        empty_final_after_data_stream_for_fuzz().expect("build empty-final negative seed");
    match decrypt_stream_for_fuzz(&noncanonical) {
        Err(CryptoError::InvalidFormat(FormatDefect::MalformedPayloadStream)) => {}
        other => panic!("empty-final negative seed must be rejected, got {other:?}"),
    }
    persist(
        fuzz_root,
        "fuzz_stream_decrypt",
        "empty_final_after_data.bin",
        &noncanonical,
    );
}

/// Seeds the accepted `public.key` form written by key generation and
/// the `private.key` signature rejected as `WrongKeyFileType`. The
/// accepted seed reaches the grammar beyond both recipient-string
/// checksums on the first iteration.
fn write_public_key_seeds(fuzz_root: &Path) {
    // Any non-zero 32-byte value satisfies public-key validation.
    let key = PublicKey::from_x25519_bytes([0x2A; 32]).expect("non-zero key material");
    let recipient = key
        .to_recipient_string()
        .expect("encode canonical recipient string");
    let valid = format!("{recipient}\n");
    parse_public_key_file_bytes(valid.as_bytes()).expect("valid seed must parse");
    persist(
        fuzz_root,
        "fuzz_public_key_file",
        "generated_public.key",
        valid.as_bytes(),
    );

    match parse_public_key_file_bytes(&PRIVATE_KEY_SIGNATURE) {
        Err(CryptoError::InvalidFormat(FormatDefect::WrongKeyFileType)) => {}
        other => panic!("private-key signature seed must be rejected, got {other:?}"),
    }
    persist(
        fuzz_root,
        "fuzz_public_key_file",
        "private_key_signature.key",
        &PRIVATE_KEY_SIGNATURE,
    );
}

/// Writes one seed into the checked-in `seeds/<target>/` directory and
/// copies it into the gitignored local `corpus/<target>/`.
fn persist(fuzz_root: &Path, target: &str, name: &str, bytes: &[u8]) {
    for dir in ["seeds", "corpus"] {
        let dir = fuzz_root.join(dir).join(target);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(name), bytes).unwrap();
    }
    println!("  {target}/{name}: {} bytes", bytes.len());
}
