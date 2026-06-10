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

use ferrocrypt::ArchiveLimits;
use ferrocrypt::fuzz_exports::{
    archive_for_fuzz, decrypt_stream_for_fuzz, encrypt_stream_for_fuzz, unarchive_for_fuzz,
};

/// FCA fixed-header layout facts needed to splice an `archive_ext`
/// region into writer output (the v1 writer always emits a zero-length
/// region): `magic(4) || version(1) || flags(2) || entry_count(4)`
/// puts `archive_ext_len` at offset 11, and the fixed header is 27
/// bytes long (`FORMAT.md` §9.2).
const FCA_ARCHIVE_EXT_LEN_OFFSET: usize = 11;
const FCA_HEADER_SIZE: usize = 27;

/// One ignorable TLV entry (`FORMAT.md` §6): tag `0x0001` (ignorable
/// range), length 2, two value bytes.
const IGNORABLE_TLV: [u8; 8] = [0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB];

fn main() {
    let fuzz_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    write_fca_seeds(&fuzz_root);
    write_stream_seeds(&fuzz_root);
    println!("seeds regenerated and validated");
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
