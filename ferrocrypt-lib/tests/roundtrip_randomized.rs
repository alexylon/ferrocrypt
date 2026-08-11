//! Randomized round-trip invariants.
//!
//! The fixed-example integration tests check specific inputs; this suite
//! exercises the `encrypt -> decrypt` identity over many random payloads and
//! random directory trees, including sizes on and around the 64 KiB chunk
//! boundary. It uses a dependency-free deterministic PRNG so a failure is
//! reproducible: the case's seed determines its bytes exactly.
//!
//! Each test round-trips all of its random inputs inside one archive, so a
//! single Argon2id unlock is amortized over the whole batch and the suite stays
//! fast under the test-fast key parameters.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ferrocrypt::Passphrase;
use ferrocrypt::{Decryptor, Encryptor, PrivateKey, PublicKey};
use ferrocrypt_test_support::{
    fast_keypair_generator, per_process_workspace, remove_per_process_workspace,
};

const PASSPHRASE: &str = "randomized-roundtrip-passphrase";
const TEST_WORKSPACE: &str = "tests/workspace_roundtrip_randomized";

#[ctor::dtor]
fn cleanup() {
    remove_per_process_workspace(TEST_WORKSPACE);
}

/// splitmix64 — a tiny, fast, dependency-free PRNG. Deterministic per seed, so
/// a case's random bytes are fixed by the seed baked into the test.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..n` (returns 0 when `n == 0`).
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next_u64() & 0xFF) as u8).collect()
    }

    /// A valid FCA path component: `x` followed by 0..7 of `[a-z0-9_]`. The
    /// leading `x` keeps it clear of every Windows-reserved device name.
    fn name(&mut self) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
        let extra = self.below(8) as usize;
        let mut s = String::with_capacity(1 + extra);
        s.push('x');
        for _ in 0..extra {
            s.push(ALPHABET[self.below(ALPHABET.len() as u64) as usize] as char);
        }
        s
    }
}

fn pass() -> Passphrase {
    Passphrase::new(PASSPHRASE)
}

struct KeyPaths {
    public: PathBuf,
    private: PathBuf,
}

/// Generates one shared key pair with fast Argon2id parameters.
fn shared_keypair(scope: &str) -> KeyPaths {
    let keys = per_process_workspace(TEST_WORKSPACE)
        .join(scope)
        .join("keys");
    let _ = fs::remove_dir_all(&keys);
    fs::create_dir_all(&keys).unwrap();
    let kg = fast_keypair_generator(pass())
        .write(&keys, |_| {})
        .expect("keygen");
    KeyPaths {
        public: kg.public_key_path,
        private: kg.private_key_path,
    }
}

fn scope_dir(scope: &str) -> PathBuf {
    let dir = per_process_workspace(TEST_WORKSPACE)
        .join(scope)
        .join("work");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("work dir");
    dir
}

/// Encrypts `source` to a recipient and decrypts it back, returning the
/// decrypted output path.
fn roundtrip(work: &Path, keys: &KeyPaths, source: &Path) -> PathBuf {
    let enc = work.join("enc");
    fs::create_dir_all(&enc).unwrap();
    let outcome = Encryptor::with_public_key(
        PublicKey::from_key_file(&keys.public).expect("read public key"),
    )
    .write(source, &enc, |_| {})
    .expect("encrypt");
    let dec = work.join("dec");
    fs::create_dir_all(&dec).unwrap();
    match Decryptor::open(&outcome.output_path).expect("open") {
        Decryptor::PrivateKey(d) => {
            d.decrypt(
                PrivateKey::from_key_file(&keys.private, pass()),
                &dec,
                |_| {},
            )
            .expect("decrypt")
            .output_path
        }
        Decryptor::Passphrase(_) => panic!("expected private-key decryptor"),
        _ => {
            unreachable!("Decryptor is non_exhaustive; only Passphrase and PrivateKey exist today")
        }
    }
}

#[test]
fn content_roundtrip_across_sizes_and_random_bytes() {
    let keys = shared_keypair("content");
    let work = scope_dir("content");
    let src = work.join("payloads");
    fs::create_dir(&src).unwrap();

    // Many files of boundary and random sizes with random content, round-tripped
    // together so one Argon2id unlock covers the whole batch.
    let mut expected: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let boundary = [
        0usize, 1, 2, 63, 64, 65_535, 65_536, 65_537, 131_072, 131_073,
    ];
    for (i, &size) in boundary.iter().enumerate() {
        let content = Rng(0x00C0_FFEE ^ size as u64).bytes(size);
        let name = format!("b{i:04}");
        fs::write(src.join(&name), &content).unwrap();
        expected.insert(name, content);
    }
    for i in 0..80u64 {
        let mut rng = Rng(0x0BAD_C0DE_u64.wrapping_add(i.wrapping_mul(0x1000_0001)));
        let len = rng.below(80_000) as usize;
        let content = rng.bytes(len);
        let name = format!("r{i:04}");
        fs::write(src.join(&name), &content).unwrap();
        expected.insert(name, content);
    }

    let out = roundtrip(&work, &keys, &src);

    for (name, content) in &expected {
        assert_eq!(
            &fs::read(out.join(name)).unwrap(),
            content,
            "content mismatch for {name} ({} bytes)",
            content.len()
        );
    }
    let restored = fs::read_dir(&out).unwrap().count();
    assert_eq!(restored, expected.len(), "restored file count differs");
}

#[derive(Debug, PartialEq, Eq)]
enum Shape {
    File(Vec<u8>),
    Dir,
}

/// Creates a random tree of files and directories under `dir`, deduping sibling
/// names (case-insensitive is exact here — names are lowercase) so no path
/// collision is produced.
fn build_tree(rng: &mut Rng, dir: &Path, depth: u32) {
    use std::collections::HashSet;
    let mut used: HashSet<String> = HashSet::new();
    let children = rng.below(5); // 0..4
    for _ in 0..children {
        let name = rng.name();
        if !used.insert(name.clone()) {
            continue;
        }
        let child = dir.join(&name);
        let make_dir = depth > 0 && rng.next_u64() & 1 == 0;
        if make_dir {
            fs::create_dir(&child).unwrap();
            build_tree(rng, &child, depth - 1);
            // Owner keeps rwx so the writer can traverse and cleanup can remove.
            set_mode(&child, 0o700 | rng.below(0o100) as u32);
        } else {
            let len = rng.below(300) as usize;
            let content = rng.bytes(len);
            fs::write(&child, &content).unwrap();
            // Owner keeps read so the writer can open the file.
            set_mode(&child, 0o400 | rng.below(0o400) as u32);
        }
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

/// Maps every descendant of `base` (relative path) to its shape and content.
fn walk_shapes(base: &Path) -> BTreeMap<PathBuf, Shape> {
    let mut map = BTreeMap::new();
    walk_into(base, base, &mut map);
    map
}

fn walk_into(base: &Path, dir: &Path, map: &mut BTreeMap<PathBuf, Shape>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let rel = path.strip_prefix(base).unwrap().to_path_buf();
        let meta = fs::symlink_metadata(&path).unwrap();
        if meta.is_dir() {
            map.insert(rel, Shape::Dir);
            walk_into(base, &path, map);
        } else if meta.is_file() {
            map.insert(rel, Shape::File(fs::read(&path).unwrap()));
        }
    }
}

#[cfg(unix)]
fn walk_modes(base: &Path) -> BTreeMap<PathBuf, u32> {
    use std::os::unix::fs::PermissionsExt;
    walk_shapes(base)
        .into_keys()
        .map(|rel| {
            let mode = fs::metadata(base.join(&rel)).unwrap().permissions().mode() & 0o777;
            (rel, mode)
        })
        .collect()
}

#[test]
fn directory_tree_roundtrip_preserves_structure_content_and_modes() {
    let keys = shared_keypair("tree");
    let work = scope_dir("tree");
    let root = work.join("root");
    fs::create_dir(&root).unwrap();

    // Many independent random subtrees under one root, round-tripped together.
    for i in 0..20u64 {
        let mut rng = Rng(0x0000_7EE5_u64.wrapping_add(i.wrapping_mul(0x1000_0193)));
        let sub = root.join(format!("s{i:04}"));
        fs::create_dir(&sub).unwrap();
        build_tree(&mut rng, &sub, 4);
        set_mode(&sub, 0o700 | rng.below(0o100) as u32);
    }

    let expected_shapes = walk_shapes(&root);
    #[cfg(unix)]
    let expected_modes = walk_modes(&root);

    let out = roundtrip(&work, &keys, &root);

    assert_eq!(
        walk_shapes(&out),
        expected_shapes,
        "tree structure or content changed across the round-trip"
    );
    #[cfg(unix)]
    assert_eq!(
        walk_modes(&out),
        expected_modes,
        "tree permission bits changed across the round-trip"
    );
}
