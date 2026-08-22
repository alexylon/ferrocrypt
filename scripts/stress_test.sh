#!/usr/bin/env bash
set -euo pipefail

# The build and the binary path below are relative to the repository root.
cd "$(dirname "$0")/.."

echo "Building release binary..."
cargo build --release

FC="./target/release/ferrocrypt"
WORKDIR="$(mktemp -d)"
PASS="stress-test-passphrase-2024!"
PASS2="wrong-passphrase-nope"
export FERROCRYPT_PASSPHRASE="$PASS"
PASSED=0
FAILED=0
TOTAL=0

cleanup() {
    echo ""
    echo "=========================================="
    echo "Cleaning up $WORKDIR"
    rm -rf "$WORKDIR"
    echo "=========================================="
    echo "RESULTS: $PASSED passed, $FAILED failed, $TOTAL total"
    if [ "$FAILED" -gt 0 ]; then
        echo "SOME TESTS FAILED"
        exit 1
    else
        echo "ALL TESTS PASSED"
        exit 0
    fi
}
trap cleanup EXIT

run_test() {
    local name="$1"
    shift
    TOTAL=$((TOTAL + 1))
    echo -n "[$TOTAL] $name ... "
    if "$@" >/dev/null 2>&1; then
        echo "PASS"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL"
        FAILED=$((FAILED + 1))
    fi
}

run_test_expect_fail() {
    local name="$1"
    shift
    TOTAL=$((TOTAL + 1))
    echo -n "[$TOTAL] $name ... "
    if "$@" >/dev/null 2>&1; then
        echo "FAIL (should have failed but succeeded)"
        FAILED=$((FAILED + 1))
    else
        echo "PASS (correctly rejected)"
        PASSED=$((PASSED + 1))
    fi
}

# Compare two files byte-for-byte
assert_identical() {
    cmp -s "$1" "$2"
}

# Compare two directories recursively
assert_dirs_identical() {
    diff -rq "$1" "$2" >/dev/null 2>&1
}

# Read the low permission bits of a path in octal (e.g. 600, 755). macOS uses
# `stat -f %Lp`; GNU/Linux uses `stat -c %a`.
perm_mode() {
    stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1" 2>/dev/null
}

# True when the platform preserves Unix permission bits and supports the
# symlink / FIFO tests below.
is_unix_perms() {
    case "$(uname -s)" in
        Linux|Darwin|*BSD) return 0 ;;
        *) return 1 ;;
    esac
}

echo "=========================================="
echo "FerroCrypt Stress Test Suite"
echo "Working directory: $WORKDIR"
echo "Binary: $FC"
echo "=========================================="
echo ""

# ──────────────────────────────────────────────
# PHASE 1: Key Generation
# ──────────────────────────────────────────────
echo "--- Phase 1: Key Generation ---"

KEYS="$WORKDIR/keys"
mkdir -p "$KEYS"

run_test "keygen: generate key pair" \
    $FC keygen -o "$KEYS"

# Generate a second key pair for wrong-key tests
KEYS2="$WORKDIR/keys2"
mkdir -p "$KEYS2"
run_test "keygen: generate second key pair" \
    env FERROCRYPT_PASSPHRASE="$PASS2" $FC keygen -o "$KEYS2"

# Verify key files exist
run_test "keygen: verify keys exist" \
    test -f "$KEYS/public.key" -a -f "$KEYS/private.key"

# private.key: 90-byte fixed header + "x25519"(6) + public(32) + wrapped secret(48) = 176.
# public.key: 108-char Bech32 recipient string (61-byte typed payload) + one LF = 109.
run_test "keygen: verify key file sizes" \
    test "$(stat -f%z "$KEYS/private.key" 2>/dev/null || stat -c%s "$KEYS/private.key" 2>/dev/null)" -eq 176 -a \
         "$(stat -f%z "$KEYS/public.key" 2>/dev/null || stat -c%s "$KEYS/public.key" 2>/dev/null)" -eq 109

PUB="$KEYS/public.key"
SECRET_KEY="$KEYS/private.key"
PUB2="$KEYS2/public.key"
SECRET_KEY2="$KEYS2/private.key"

echo ""

# ──────────────────────────────────────────────
# PHASE 2: Symmetric Roundtrips
# ──────────────────────────────────────────────
echo "--- Phase 2: Symmetric Encryption Roundtrips ---"

# Helper: passphrase roundtrip test for a single file
sym_roundtrip_file() {
    local src="$1"
    local label="$2"
    local enc_dir="$WORKDIR/enc_sym_${label}"
    local dec_dir="$WORKDIR/dec_sym_${label}"
    mkdir -p "$enc_dir" "$dec_dir"
    $FC encrypt -i "$src" -o "$enc_dir" && \
    $FC decrypt -i "$enc_dir"/*.fcr -o "$dec_dir" && \
    assert_identical "$src" "$dec_dir/$(basename "$src")"
}

# Helper: passphrase roundtrip test for a directory
sym_roundtrip_dir() {
    local src="$1"
    local label="$2"
    local enc_dir="$WORKDIR/enc_sym_${label}"
    local dec_dir="$WORKDIR/dec_sym_${label}"
    mkdir -p "$enc_dir" "$dec_dir"
    $FC encrypt -i "$src" -o "$enc_dir" && \
    $FC decrypt -i "$enc_dir"/*.fcr -o "$dec_dir" && \
    assert_dirs_identical "$src" "$dec_dir/$(basename "$src")"
}

# Test 2a: Empty file
touch "$WORKDIR/empty.txt"
run_test "sym: empty file roundtrip" sym_roundtrip_file "$WORKDIR/empty.txt" "empty"

# Test 2b: Single byte
printf 'A' > "$WORKDIR/onebyte.bin"
run_test "sym: 1-byte file roundtrip" sym_roundtrip_file "$WORKDIR/onebyte.bin" "onebyte"

# Test 2c: Small text file
echo "Hello, FerroCrypt!" > "$WORKDIR/small.txt"
run_test "sym: small text file roundtrip" sym_roundtrip_file "$WORKDIR/small.txt" "small"

# Test 2d: Exactly one chunk (65536 bytes)
dd if=/dev/urandom of="$WORKDIR/one_chunk.bin" bs=65536 count=1 2>/dev/null
run_test "sym: exact chunk boundary (64KB)" sym_roundtrip_file "$WORKDIR/one_chunk.bin" "onechunk"

# Test 2e: One byte under chunk boundary
dd if=/dev/urandom of="$WORKDIR/chunk_minus1.bin" bs=65535 count=1 2>/dev/null
run_test "sym: chunk boundary - 1 byte (65535B)" sym_roundtrip_file "$WORKDIR/chunk_minus1.bin" "chunkminus1"

# Test 2f: One byte over chunk boundary
dd if=/dev/urandom of="$WORKDIR/chunk_plus1.bin" bs=65537 count=1 2>/dev/null
run_test "sym: chunk boundary + 1 byte (65537B)" sym_roundtrip_file "$WORKDIR/chunk_plus1.bin" "chunkplus1"

# Test 2g: 1MB random data
dd if=/dev/urandom of="$WORKDIR/1mb.bin" bs=1048576 count=1 2>/dev/null
run_test "sym: 1MB random data roundtrip" sym_roundtrip_file "$WORKDIR/1mb.bin" "1mb"

# Test 2h: 10MB random data
dd if=/dev/urandom of="$WORKDIR/10mb.bin" bs=1048576 count=10 2>/dev/null
run_test "sym: 10MB random data roundtrip" sym_roundtrip_file "$WORKDIR/10mb.bin" "10mb"

# Test 2i: 100MB random data
echo -n "[next] sym: 100MB random data roundtrip ... "
TOTAL=$((TOTAL + 1))
dd if=/dev/urandom of="$WORKDIR/100mb.bin" bs=1048576 count=100 2>/dev/null
enc100="$WORKDIR/enc_sym_100mb"
dec100="$WORKDIR/dec_sym_100mb"
mkdir -p "$enc100" "$dec100"
if $FC encrypt -i "$WORKDIR/100mb.bin" -o "$enc100" 2>/dev/null && \
   $FC decrypt -i "$enc100"/*.fcr -o "$dec100" 2>/dev/null && \
   assert_identical "$WORKDIR/100mb.bin" "$dec100/100mb.bin"; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL"
    FAILED=$((FAILED + 1))
fi
# Free space
rm -f "$WORKDIR/100mb.bin" "$enc100"/*.fcr "$dec100"/100mb.bin

# Test 2j: All zeros
dd if=/dev/zero of="$WORKDIR/zeros.bin" bs=1048576 count=5 2>/dev/null
run_test "sym: 5MB all-zeros roundtrip" sym_roundtrip_file "$WORKDIR/zeros.bin" "zeros"

# Test 2k: All 0xFF bytes
dd if=/dev/zero bs=1048576 count=5 2>/dev/null | tr '\0' '\377' > "$WORKDIR/ones.bin"
run_test "sym: 5MB all-0xFF roundtrip" sym_roundtrip_file "$WORKDIR/ones.bin" "ones"

# Test 2l: Repeating pattern (ABCD...)
python3 -c "import sys; sys.stdout.buffer.write(b'ABCD' * 262144)" > "$WORKDIR/pattern.bin"
run_test "sym: 1MB repeating pattern roundtrip" sym_roundtrip_file "$WORKDIR/pattern.bin" "pattern"

# Test 2m: File with null bytes embedded in text
printf 'Hello\x00World\x00Test\x00' > "$WORKDIR/nulls.bin"
run_test "sym: file with embedded nulls" sym_roundtrip_file "$WORKDIR/nulls.bin" "nulls"

# Test 2n: Unicode content
printf 'こんにちは世界 🔐 Ñoño Ünïcödé Привет мир 🇺🇸🇩🇪🇯🇵' > "$WORKDIR/unicode.txt"
run_test "sym: unicode content roundtrip" sym_roundtrip_file "$WORKDIR/unicode.txt" "unicode"

echo ""

# ──────────────────────────────────────────────
# PHASE 3: Hybrid Roundtrips
# ──────────────────────────────────────────────
echo "--- Phase 3: Hybrid Encryption Roundtrips ---"

hyb_roundtrip_file() {
    local src="$1"
    local label="$2"
    local pubkey="$3"
    local secretkey="$4"
    local enc_dir="$WORKDIR/enc_hyb_${label}"
    local dec_dir="$WORKDIR/dec_hyb_${label}"
    mkdir -p "$enc_dir" "$dec_dir"
    $FC encrypt -i "$src" -o "$enc_dir" -k "$pubkey" && \
    $FC decrypt -i "$enc_dir"/*.fcr -o "$dec_dir" -K "$secretkey" && \
    assert_identical "$src" "$dec_dir/$(basename "$src")"
}

hyb_roundtrip_dir() {
    local src="$1"
    local label="$2"
    local pubkey="$3"
    local secretkey="$4"
    local enc_dir="$WORKDIR/enc_hyb_${label}"
    local dec_dir="$WORKDIR/dec_hyb_${label}"
    mkdir -p "$enc_dir" "$dec_dir"
    $FC encrypt -i "$src" -o "$enc_dir" -k "$pubkey" && \
    $FC decrypt -i "$enc_dir"/*.fcr -o "$dec_dir" -K "$secretkey" && \
    assert_dirs_identical "$src" "$dec_dir/$(basename "$src")"
}

# Re-use small test files
run_test "hyb: empty file roundtrip" hyb_roundtrip_file "$WORKDIR/empty.txt" "empty" "$PUB" "$SECRET_KEY"
run_test "hyb: 1-byte file roundtrip" hyb_roundtrip_file "$WORKDIR/onebyte.bin" "onebyte" "$PUB" "$SECRET_KEY"
run_test "hyb: small text file roundtrip" hyb_roundtrip_file "$WORKDIR/small.txt" "small" "$PUB" "$SECRET_KEY"
run_test "hyb: 64KB chunk boundary" hyb_roundtrip_file "$WORKDIR/one_chunk.bin" "chunk" "$PUB" "$SECRET_KEY"
run_test "hyb: 1MB random data" hyb_roundtrip_file "$WORKDIR/1mb.bin" "1mb" "$PUB" "$SECRET_KEY"
run_test "hyb: 10MB random data" hyb_roundtrip_file "$WORKDIR/10mb.bin" "10mb" "$PUB" "$SECRET_KEY"
run_test "hyb: unicode content" hyb_roundtrip_file "$WORKDIR/unicode.txt" "unicode" "$PUB" "$SECRET_KEY"

# 100MB hybrid
echo -n "[next] hyb: 100MB random data roundtrip ... "
TOTAL=$((TOTAL + 1))
dd if=/dev/urandom of="$WORKDIR/100mb_hyb.bin" bs=1048576 count=100 2>/dev/null
enc100h="$WORKDIR/enc_hyb_100mb"
dec100h="$WORKDIR/dec_hyb_100mb"
mkdir -p "$enc100h" "$dec100h"
if $FC encrypt -i "$WORKDIR/100mb_hyb.bin" -o "$enc100h" -k "$PUB" 2>/dev/null && \
   $FC decrypt -i "$enc100h"/*.fcr -o "$dec100h" -K "$SECRET_KEY" 2>/dev/null && \
   assert_identical "$WORKDIR/100mb_hyb.bin" "$dec100h/100mb_hyb.bin"; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL"
    FAILED=$((FAILED + 1))
fi
rm -f "$WORKDIR/100mb_hyb.bin" "$enc100h"/*.fcr "$dec100h"/100mb_hyb.bin

echo ""

# ──────────────────────────────────────────────
# PHASE 4: Directory Roundtrips
# ──────────────────────────────────────────────
echo "--- Phase 4: Directory Encryption Roundtrips ---"

# Simple flat directory
FLATDIR="$WORKDIR/flatdir"
mkdir -p "$FLATDIR"
for i in $(seq 1 20); do
    dd if=/dev/urandom of="$FLATDIR/file_$i.bin" bs=4096 count=$((RANDOM % 50 + 1)) 2>/dev/null
done
run_test "sym: flat dir with 20 files" sym_roundtrip_dir "$FLATDIR" "flatdir"
run_test "hyb: flat dir with 20 files" hyb_roundtrip_dir "$FLATDIR" "flatdir_hyb" "$PUB" "$SECRET_KEY"

# Deep nested directory
DEEPDIR="$WORKDIR/deepdir"
NESTED="$DEEPDIR"
for i in $(seq 1 15); do
    NESTED="$NESTED/level_$i"
    mkdir -p "$NESTED"
    echo "Content at depth $i" > "$NESTED/data.txt"
    dd if=/dev/urandom of="$NESTED/random.bin" bs=1024 count=$((i * 2)) 2>/dev/null
done
run_test "sym: 15-level deep nested dir" sym_roundtrip_dir "$DEEPDIR" "deepdir"
run_test "hyb: 15-level deep nested dir" hyb_roundtrip_dir "$DEEPDIR" "deepdir_hyb" "$PUB" "$SECRET_KEY"

# Directory with many small files
MANYDIR="$WORKDIR/manyfiles"
mkdir -p "$MANYDIR"
for i in $(seq 1 200); do
    printf "file content %04d" "$i" > "$MANYDIR/f_$i.txt"
done
run_test "sym: dir with 200 small files" sym_roundtrip_dir "$MANYDIR" "manyfiles"
run_test "hyb: dir with 200 small files" hyb_roundtrip_dir "$MANYDIR" "manyfiles_hyb" "$PUB" "$SECRET_KEY"

# Directory with mixed content types
MIXDIR="$WORKDIR/mixdir"
mkdir -p "$MIXDIR/subA" "$MIXDIR/subB/nested"
echo "text file" > "$MIXDIR/readme.txt"
dd if=/dev/urandom of="$MIXDIR/binary.dat" bs=65536 count=3 2>/dev/null
dd if=/dev/zero of="$MIXDIR/subA/zeros.dat" bs=1024 count=100 2>/dev/null
printf 'こんにちは' > "$MIXDIR/subA/japanese.txt"
touch "$MIXDIR/subB/empty"
dd if=/dev/urandom of="$MIXDIR/subB/nested/deep.bin" bs=8192 count=5 2>/dev/null
run_test "sym: mixed content directory" sym_roundtrip_dir "$MIXDIR" "mixdir"
run_test "hyb: mixed content directory" hyb_roundtrip_dir "$MIXDIR" "mixdir_hyb" "$PUB" "$SECRET_KEY"

# Directory with empty subdirectories
EMPTYSUBDIR="$WORKDIR/emptysubs"
mkdir -p "$EMPTYSUBDIR/has_file" "$EMPTYSUBDIR/also_has_file"
echo "content" > "$EMPTYSUBDIR/has_file/data.txt"
echo "more" > "$EMPTYSUBDIR/also_has_file/info.txt"
run_test "sym: dir with empty subdirs" sym_roundtrip_dir "$EMPTYSUBDIR" "emptysubs"

echo ""

# ──────────────────────────────────────────────
# PHASE 5: Save-as (custom output name)
# ──────────────────────────────────────────────
echo "--- Phase 5: Custom Output Name (--save-as) ---"

sym_saveas_roundtrip() {
    local saveas_dir="$WORKDIR/saveas"
    local saveas_dec="$WORKDIR/saveas_dec"
    mkdir -p "$saveas_dir" "$saveas_dec"
    # `--save-as` carries the full output path; the CLI rejects `-o` and
    # `-s` together (clap-level conflict introduced in the CLI redesign).
    $FC encrypt -i "$WORKDIR/small.txt" -s "$saveas_dir/custom_name.fcr" && \
    test -f "$saveas_dir/custom_name.fcr" && \
    $FC decrypt -i "$saveas_dir/custom_name.fcr" -o "$saveas_dec" && \
    assert_identical "$WORKDIR/small.txt" "$saveas_dec/small.txt"
}
run_test "sym: custom output name" sym_saveas_roundtrip

hyb_saveas_roundtrip() {
    local saveas2_dir="$WORKDIR/saveas2"
    local saveas2_dec="$WORKDIR/saveas2_dec"
    mkdir -p "$saveas2_dir" "$saveas2_dec"
    $FC encrypt -i "$WORKDIR/small.txt" -k "$PUB" -s "$saveas2_dir/renamed.fcr" && \
    test -f "$saveas2_dir/renamed.fcr" && \
    $FC decrypt -i "$saveas2_dir/renamed.fcr" -o "$saveas2_dec" -K "$SECRET_KEY" && \
    assert_identical "$WORKDIR/small.txt" "$saveas2_dec/small.txt"
}
run_test "hyb: custom output name" hyb_saveas_roundtrip

# Recipient-string encrypt → decrypt roundtrip. `public.key` is itself the
# canonical fcr1... text (UTF-8, single line), so reading the file is enough.
hyb_recipient_roundtrip() {
    local rcpt_enc="$WORKDIR/rcpt_enc"
    local rcpt_dec="$WORKDIR/rcpt_dec"
    mkdir -p "$rcpt_enc" "$rcpt_dec"
    local RCPT
    RCPT=$(tr -d '\n' < "$PUB")
    $FC encrypt -i "$WORKDIR/small.txt" -o "$rcpt_enc" -r "$RCPT" && \
    $FC decrypt -i "$rcpt_enc"/*.fcr -o "$rcpt_dec" -K "$SECRET_KEY" && \
    assert_identical "$WORKDIR/small.txt" "$rcpt_dec/small.txt"
}
run_test "hyb: recipient string roundtrip" hyb_recipient_roundtrip

echo ""

# ──────────────────────────────────────────────
# PHASE 6: Error Handling & Rejection
# ──────────────────────────────────────────────
echo "--- Phase 6: Error Handling & Rejection ---"

# Wrong password on passphrase decrypt
err1_enc="$WORKDIR/err1_enc"
err1_dec="$WORKDIR/err1_dec"
mkdir -p "$err1_enc" "$err1_dec"
$FC encrypt -i "$WORKDIR/small.txt" -o "$err1_enc" 2>/dev/null
run_test_expect_fail "sym: wrong password rejects" \
    env FERROCRYPT_PASSPHRASE="$PASS2" $FC decrypt -i "$err1_enc"/*.fcr -o "$err1_dec"
# Wrong passphrase on recipient decrypt
err2_enc="$WORKDIR/err2_enc"
err2_dec="$WORKDIR/err2_dec"
mkdir -p "$err2_enc" "$err2_dec"
$FC encrypt -i "$WORKDIR/small.txt" -o "$err2_enc" -k "$PUB" 2>/dev/null
run_test_expect_fail "hyb: wrong passphrase rejects" \
    env FERROCRYPT_PASSPHRASE="$PASS2" $FC decrypt -i "$err2_enc"/*.fcr -o "$err2_dec" -K "$SECRET_KEY"
# Wrong key entirely (different keypair)
err3_dec="$WORKDIR/err3_dec"
mkdir -p "$err3_dec"
run_test_expect_fail "hyb: wrong key rejects" \
    env FERROCRYPT_PASSPHRASE="$PASS2" $FC decrypt -i "$err2_enc"/*.fcr -o "$err3_dec" -K "$SECRET_KEY2"
# Non-existent input file
run_test_expect_fail "sym: non-existent input rejects" \
    $FC encrypt -i "$WORKDIR/does_not_exist.txt" -o "$WORKDIR"
run_test_expect_fail "hyb: non-existent input rejects" \
    $FC encrypt -i "$WORKDIR/does_not_exist.txt" -o "$WORKDIR" -k "$PUB"

# Empty password
run_test_expect_fail "sym: empty password rejects" \
    env FERROCRYPT_PASSPHRASE="" $FC encrypt -i "$WORKDIR/small.txt" -o "$WORKDIR/err_empty"

# Corrupted ciphertext: flip bytes in the middle of encrypted file
corr_enc="$WORKDIR/corr_enc"
corr_dec="$WORKDIR/corr_dec"
mkdir -p "$corr_enc" "$corr_dec"
$FC encrypt -i "$WORKDIR/1mb.bin" -o "$corr_enc" 2>/dev/null
CORR_FILE="$corr_enc/1mb.fcr"
# Flip 100 bytes near the middle of the file
FILE_SIZE=$(stat -f%z "$CORR_FILE" 2>/dev/null || stat -c%s "$CORR_FILE" 2>/dev/null)
MIDPOINT=$((FILE_SIZE / 2))
python3 -c "
import sys
data = bytearray(open('$CORR_FILE', 'rb').read())
mid = $MIDPOINT
for i in range(100):
    data[mid + i] ^= 0xFF
open('$CORR_FILE', 'wb').write(data)
"
run_test_expect_fail "sym: corrupted ciphertext rejects" \
    $FC decrypt -i "$CORR_FILE" -o "$corr_dec"
# Corrupted header: flip the first byte of the 4-byte magic
corr2_enc="$WORKDIR/corr2_enc"
corr2_dec="$WORKDIR/corr2_dec"
mkdir -p "$corr2_enc" "$corr2_dec"
$FC encrypt -i "$WORKDIR/small.txt" -o "$corr2_enc" 2>/dev/null
CORR2_FILE="$corr2_enc/small.fcr"
python3 -c "
data = bytearray(open('$CORR2_FILE', 'rb').read())
# v1 prefix: magic(4) || version(1) || kind(1) || prefix_flags(2) || header_len(4)
# Corrupt the first magic byte so the .fcr is no longer recognized: encrypt
# proceeds (the magic-byte peek does not match), and decrypt would error.
data[0] ^= 0xFF
open('$CORR2_FILE', 'wb').write(data)
"
run_test "sym: corrupted-magic .fcr accepted as plaintext input by encrypt" \
    $FC encrypt -i "$CORR2_FILE" -o "$corr2_dec"
# Truncated file (cut at half)
trunc_enc="$WORKDIR/trunc_enc"
trunc_dec="$WORKDIR/trunc_dec"
mkdir -p "$trunc_enc" "$trunc_dec"
$FC encrypt -i "$WORKDIR/1mb.bin" -o "$trunc_enc" 2>/dev/null
TRUNC_FILE="$trunc_enc/1mb.fcr"
TRUNC_SIZE=$(stat -f%z "$TRUNC_FILE" 2>/dev/null || stat -c%s "$TRUNC_FILE" 2>/dev/null)
dd if="$TRUNC_FILE" of="$TRUNC_FILE.trunc" bs=$((TRUNC_SIZE / 2)) count=1 2>/dev/null
run_test_expect_fail "sym: truncated file rejects" \
    $FC decrypt -i "$TRUNC_FILE.trunc" -o "$trunc_dec"
# Corrupted recipient file
corr3_enc="$WORKDIR/corr3_enc"
corr3_dec="$WORKDIR/corr3_dec"
mkdir -p "$corr3_enc" "$corr3_dec"
$FC encrypt -i "$WORKDIR/1mb.bin" -o "$corr3_enc" -k "$PUB" 2>/dev/null
CORR3_FILE=$(ls "$corr3_enc"/*.fcr)
python3 -c "
data = bytearray(open('$CORR3_FILE', 'rb').read())
mid = len(data) // 2
for i in range(200):
    data[mid + i] ^= 0xFF
open('$CORR3_FILE', 'wb').write(data)
"
run_test_expect_fail "hyb: corrupted ciphertext rejects" \
    $FC decrypt -i "$CORR3_FILE" -o "$corr3_dec" -K "$SECRET_KEY"
echo ""

# ──────────────────────────────────────────────
# PHASE 7: Cross-mode Rejection
# ──────────────────────────────────────────────
echo "--- Phase 7: Cross-mode Rejection ---"

cross_enc="$WORKDIR/cross_enc"
cross_dec="$WORKDIR/cross_dec"
mkdir -p "$cross_enc" "$cross_dec"

# Encrypt with passphrase, then try to decrypt with -K (private key supplied
# against a passphrase-sealed file).
$FC encrypt -i "$WORKDIR/small.txt" -o "$cross_enc" 2>/dev/null
run_test_expect_fail "cross: passphrase-sealed file decrypted with -K rejects" \
    $FC decrypt -i "$cross_enc"/small.fcr -o "$cross_dec" -K "$SECRET_KEY"
# Encrypt to a recipient, then try to decrypt without -K.
cross2_enc="$WORKDIR/cross2_enc"
cross2_dec="$WORKDIR/cross2_dec"
mkdir -p "$cross2_enc" "$cross2_dec"
$FC encrypt -i "$WORKDIR/small.txt" -o "$cross2_enc" -k "$PUB" 2>/dev/null
run_test_expect_fail "cross: recipient-sealed file decrypted without -K rejects" \
    $FC decrypt -i "$cross2_enc"/small.fcr -o "$cross2_dec"
echo ""

# ──────────────────────────────────────────────
# PHASE 8: Additional Robustness
# ──────────────────────────────────────────────
echo "--- Phase 8: Additional Robustness ---"

# Malformed key file
malformed_key="$WORKDIR/malformed.key"
printf 'this is not a valid key file at all' > "$malformed_key"
mal_enc="$WORKDIR/mal_enc"
mal_dec="$WORKDIR/mal_dec"
mkdir -p "$mal_enc" "$mal_dec"
run_test_expect_fail "hyb: malformed key file rejects (encrypt)" \
    $FC encrypt -i "$WORKDIR/small.txt" -o "$mal_enc" -k "$malformed_key"
# Also try malformed key for decryption
$FC encrypt -i "$WORKDIR/small.txt" -o "$mal_enc" -k "$PUB" 2>/dev/null
run_test_expect_fail "hyb: malformed key file rejects (decrypt)" \
    $FC decrypt -i "$mal_enc"/small.fcr -o "$mal_dec" -K "$malformed_key"
# Key overwrite (keygen into directory with existing keys)
run_test_expect_fail "keygen: refuses to overwrite existing keys" \
    $FC keygen -o "$KEYS"
# Tiny random files with .fcr extension are not detected as FerroCrypt files
# (magic-byte routing), so the CLI encrypts them. Verify roundtrip works.
tiny_enc="$WORKDIR/tiny_enc"
tiny_dec="$WORKDIR/tiny_dec"
mkdir -p "$tiny_enc" "$tiny_dec"
for sz in 1 3 5 7; do
    dd if=/dev/urandom of="$WORKDIR/tiny_${sz}.fcr" bs="$sz" count=1 2>/dev/null
    run_test "sym: ${sz}-byte .fcr file encrypts (not detected as FerroCrypt)" \
        $FC encrypt -i "$WORKDIR/tiny_${sz}.fcr" -o "$tiny_enc"
done

# Corrupted header fields (version, header length, HMAC tag)
hdr_src="$WORKDIR/hdr_enc"
hdr_dec="$WORKDIR/hdr_dec"
mkdir -p "$hdr_src" "$hdr_dec"
$FC encrypt -i "$WORKDIR/1mb.bin" -o "$hdr_src" 2>/dev/null
HDR_FILE="$hdr_src/1mb.fcr"
HDR_SIZE=$(stat -f%z "$HDR_FILE" 2>/dev/null || stat -c%s "$HDR_FILE" 2>/dev/null)

# Flip the version byte (v1 prefix byte 4). Decryption rejects with
# UnsupportedVersion / InvalidFormat before any KDF runs.
cp "$HDR_FILE" "$WORKDIR/corrupt_version.fcr"
python3 -c "
data = bytearray(open('$WORKDIR/corrupt_version.fcr', 'rb').read())
data[4] ^= 0x10
open('$WORKDIR/corrupt_version.fcr', 'wb').write(data)
"
run_test_expect_fail "sym: corrupted version byte rejects" \
    $FC decrypt -i "$WORKDIR/corrupt_version.fcr" -o "$hdr_dec"

# Flip a byte in header_len (v1 prefix bytes 8..=11). Either parses as an
# oversized declared length and rejects with OversizedHeader, or as a
# truncation and rejects with MalformedHeader / Truncated. Either way,
# decrypt fails before any crypto runs.
cp "$HDR_FILE" "$WORKDIR/corrupt_hdrlen.fcr"
python3 -c "
data = bytearray(open('$WORKDIR/corrupt_hdrlen.fcr', 'rb').read())
data[8] ^= 0xFF
open('$WORKDIR/corrupt_hdrlen.fcr', 'wb').write(data)
"
run_test_expect_fail "sym: corrupted header length rejects" \
    $FC decrypt -i "$WORKDIR/corrupt_hdrlen.fcr" -o "$hdr_dec"

# Corrupt a byte inside the argon2id recipient body's argon2_salt. The
# argon2_salt lives at file offset PREFIX_SIZE(12) + HEADER_FIXED_SIZE(31)
# + ENTRY_HEADER_SIZE(8) + len("argon2id")(8) = 59. Tampering yields a
# different wrap_key, so AEAD-decrypt of wrapped_file_key fails with
# RecipientUnwrapFailed{argon2id} — verifying that recipient bodies are
# under MAC scope but unwrap-failure surfaces before MAC verify.
cp "$HDR_FILE" "$WORKDIR/corrupt_salt.fcr"
python3 -c "
data = bytearray(open('$WORKDIR/corrupt_salt.fcr', 'rb').read())
data[59] ^= 0xFF
open('$WORKDIR/corrupt_salt.fcr', 'wb').write(data)
"
run_test_expect_fail "sym: corrupted argon2_salt rejects" \
    $FC decrypt -i "$WORKDIR/corrupt_salt.fcr" -o "$hdr_dec"
echo ""

# ──────────────────────────────────────────────
# PHASE 9: Concurrent Operations
# ──────────────────────────────────────────────
echo "--- Phase 9: Concurrent Operations ---"

CONC_DIR="$WORKDIR/concurrent"
mkdir -p "$CONC_DIR"

# Generate 8 different source files
for i in $(seq 1 8); do
    dd if=/dev/urandom of="$CONC_DIR/src_$i.bin" bs=1048576 count=5 2>/dev/null
done

# Run 8 symmetric encrypt operations in parallel
echo -n "[$((TOTAL + 1))] sym: 8 concurrent encryptions (5MB each) ... "
TOTAL=$((TOTAL + 1))
pids=()
all_ok=true
for i in $(seq 1 8); do
    mkdir -p "$CONC_DIR/enc_$i"
    $FC encrypt -i "$CONC_DIR/src_$i.bin" -o "$CONC_DIR/enc_$i" 2>/dev/null &
    pids+=($!)
done
for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
        all_ok=false
    fi
done
if $all_ok; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL"
    FAILED=$((FAILED + 1))
fi

# Run 8 concurrent decryptions
echo -n "[$((TOTAL + 1))] sym: 8 concurrent decryptions ... "
TOTAL=$((TOTAL + 1))
pids=()
all_ok=true
for i in $(seq 1 8); do
    mkdir -p "$CONC_DIR/dec_$i"
    $FC decrypt -i "$CONC_DIR/enc_$i"/*.fcr -o "$CONC_DIR/dec_$i" 2>/dev/null &
    pids+=($!)
done
for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
        all_ok=false
    fi
done
if $all_ok; then
    # Verify all match
    verify_ok=true
    for i in $(seq 1 8); do
        if ! assert_identical "$CONC_DIR/src_$i.bin" "$CONC_DIR/dec_$i/src_$i.bin"; then
            verify_ok=false
        fi
    done
    if $verify_ok; then
        echo "PASS"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL (data mismatch)"
        FAILED=$((FAILED + 1))
    fi
else
    echo "FAIL"
    FAILED=$((FAILED + 1))
fi

# Run 4 hybrid + 4 symmetric in parallel
echo -n "[$((TOTAL + 1))] mixed: 4 sym + 4 hyb concurrent encryptions ... "
TOTAL=$((TOTAL + 1))
pids=()
all_ok=true
for i in $(seq 1 4); do
    mkdir -p "$CONC_DIR/mix_sym_enc_$i" "$CONC_DIR/mix_hyb_enc_$i"
    $FC encrypt -i "$CONC_DIR/src_$i.bin" -o "$CONC_DIR/mix_sym_enc_$i" 2>/dev/null &
    pids+=($!)
    $FC encrypt -i "$CONC_DIR/src_$((i+4)).bin" -o "$CONC_DIR/mix_hyb_enc_$i" -k "$PUB" 2>/dev/null &
    pids+=($!)
done
for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
        all_ok=false
    fi
done
if $all_ok; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL"
    FAILED=$((FAILED + 1))
fi

echo ""

# ──────────────────────────────────────────────
# PHASE 10: Large File Stress Test (3GB)
# ──────────────────────────────────────────────
echo "--- Phase 10: Large File Stress (3GB) ---"

echo -n "[$((TOTAL + 1))] sym: 3GB file roundtrip ... "
TOTAL=$((TOTAL + 1))
dd if=/dev/urandom of="$WORKDIR/3gb.bin" bs=1048576 count=3072 2>/dev/null
big_enc="$WORKDIR/big_enc"
big_dec="$WORKDIR/big_dec"
mkdir -p "$big_enc" "$big_dec"
START=$(date +%s)
if $FC encrypt -i "$WORKDIR/3gb.bin" -o "$big_enc" 2>/dev/null && \
   $FC decrypt -i "$big_enc"/*.fcr -o "$big_dec" 2>/dev/null && \
   assert_identical "$WORKDIR/3gb.bin" "$big_dec/3gb.bin"; then
    END=$(date +%s)
    echo "PASS ($((END - START))s)"
    PASSED=$((PASSED + 1))
else
    echo "FAIL"
    FAILED=$((FAILED + 1))
fi
rm -f "$WORKDIR/3gb.bin" "$big_enc"/*.fcr "$big_dec"/3gb.bin

echo ""

# ──────────────────────────────────────────────
# PHASE 11: Repeated Encrypt-Decrypt Cycles
# ──────────────────────────────────────────────
echo "--- Phase 11: Repeated Cycles (Idempotency) ---"

dd if=/dev/urandom of="$WORKDIR/cycle_src.bin" bs=65536 count=10 2>/dev/null
cp "$WORKDIR/cycle_src.bin" "$WORKDIR/cycle_current.bin"

echo -n "[$((TOTAL + 1))] sym: 10 encrypt-decrypt cycles on same data ... "
TOTAL=$((TOTAL + 1))
cycle_ok=true
for round in $(seq 1 10); do
    cyc_enc="$WORKDIR/cycle_enc_$round"
    cyc_dec="$WORKDIR/cycle_dec_$round"
    mkdir -p "$cyc_enc" "$cyc_dec"
    if ! $FC encrypt -i "$WORKDIR/cycle_current.bin" -o "$cyc_enc" 2>/dev/null; then
        cycle_ok=false
        break
    fi
    if ! $FC decrypt -i "$cyc_enc"/*.fcr -o "$cyc_dec" 2>/dev/null; then
        cycle_ok=false
        break
    fi
    cp "$cyc_dec/cycle_current.bin" "$WORKDIR/cycle_current.bin"
done
if $cycle_ok && assert_identical "$WORKDIR/cycle_src.bin" "$WORKDIR/cycle_current.bin"; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL"
    FAILED=$((FAILED + 1))
fi

echo ""

# ──────────────────────────────────────────────
# PHASE 12: Double-encrypt gate
# ──────────────────────────────────────────────
echo "--- Phase 12: Double-encrypt gate ---"

dbl_enc1="$WORKDIR/dbl_enc1"
dbl_enc2="$WORKDIR/dbl_enc2"
dbl_dec_outer="$WORKDIR/dbl_dec_outer"
dbl_dec_inner="$WORKDIR/dbl_dec_inner"
mkdir -p "$dbl_enc1" "$dbl_enc2" "$dbl_dec_outer" "$dbl_dec_inner"
$FC encrypt -i "$WORKDIR/1mb.bin" -o "$dbl_enc1" 2>/dev/null
INNER_FCR="$dbl_enc1/1mb.fcr"

# Without --allow-double-encrypt and with stdin closed (no TTY), encrypt
# must refuse a .fcr input.
run_test_expect_fail "sym: double-encrypt without flag refuses (non-TTY)" \
    bash -c "$FC encrypt -i '$INNER_FCR' -o '$dbl_enc2' </dev/null"

# With --allow-double-encrypt, encrypt proceeds and a full onion round trip
# (outer decrypt → inner decrypt) recovers the plaintext.
echo -n "[$((TOTAL + 1))] sym: double-encrypt with --allow-double-encrypt round-trips ... "
TOTAL=$((TOTAL + 1))
if $FC encrypt -i "$INNER_FCR" -o "$dbl_enc2" --allow-double-encrypt </dev/null 2>/dev/null && \
   $FC decrypt -i "$dbl_enc2"/1mb.fcr -o "$dbl_dec_outer" 2>/dev/null && \
   $FC decrypt -i "$dbl_dec_outer"/1mb.fcr -o "$dbl_dec_inner" 2>/dev/null && \
   assert_identical "$WORKDIR/1mb.bin" "$dbl_dec_inner/1mb.bin"; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL"
    FAILED=$((FAILED + 1))
fi

echo ""

# ──────────────────────────────────────────────
# PHASE 13: Special Filenames
# ──────────────────────────────────────────────
echo "--- Phase 13: Special Filenames ---"

# Spaces in filename
echo "spaces test" > "$WORKDIR/file with spaces.txt"
run_test "sym: filename with spaces" sym_roundtrip_file "$WORKDIR/file with spaces.txt" "spaces"

# Dots in filename
echo "dots test" > "$WORKDIR/file.multiple.dots.here.txt"
run_test "sym: filename with multiple dots" sym_roundtrip_file "$WORKDIR/file.multiple.dots.here.txt" "dots"

# Long filename (99 bytes). FCA's `path_len` is u16 with default
# max_path_bytes = 4096, so single-component names up to ~4 KiB are
# representable; this case tests a comfortable mid-range value where
# the legacy ustar subset's 100-byte name-field cap would have rejected.
# (See ferrocrypt-lib/FORMAT.md §9 for the FCA path grammar.)
LONGNAME=$(python3 -c "print('a' * 95 + '.txt')")
echo "long name test" > "$WORKDIR/$LONGNAME"
run_test "sym: long filename (99 bytes)" sym_roundtrip_file "$WORKDIR/$LONGNAME" "longname"

# Directory with spaces
SPACEDIR="$WORKDIR/dir with spaces/sub dir"
mkdir -p "$SPACEDIR"
echo "content" > "$SPACEDIR/file.txt"
run_test "sym: directory path with spaces" sym_roundtrip_dir "$WORKDIR/dir with spaces" "spacedir"

echo ""

# ──────────────────────────────────────────────
# PHASE 14: Determinism Check
# ──────────────────────────────────────────────
echo "--- Phase 14: Non-determinism Verification ---"

det_enc1="$WORKDIR/det_enc1"
det_enc2="$WORKDIR/det_enc2"
mkdir -p "$det_enc1" "$det_enc2"
$FC encrypt -i "$WORKDIR/small.txt" -o "$det_enc1" 2>/dev/null
$FC encrypt -i "$WORKDIR/small.txt" -o "$det_enc2" 2>/dev/null

echo -n "[$((TOTAL + 1))] sym: encryptions produce different ciphertexts (non-deterministic) ... "
TOTAL=$((TOTAL + 1))
if ! cmp -s "$det_enc1"/small.fcr "$det_enc2"/small.fcr; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL (identical ciphertexts - salt/nonce not random!)"
    FAILED=$((FAILED + 1))
fi

det_enc3="$WORKDIR/det_enc3"
det_enc4="$WORKDIR/det_enc4"
mkdir -p "$det_enc3" "$det_enc4"
$FC encrypt -i "$WORKDIR/small.txt" -o "$det_enc3" -k "$PUB" 2>/dev/null
$FC encrypt -i "$WORKDIR/small.txt" -o "$det_enc4" -k "$PUB" 2>/dev/null

echo -n "[$((TOTAL + 1))] hyb: encryptions produce different ciphertexts (non-deterministic) ... "
TOTAL=$((TOTAL + 1))
if ! cmp -s "$det_enc3"/small.fcr "$det_enc4"/small.fcr; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL (identical ciphertexts!)"
    FAILED=$((FAILED + 1))
fi

echo ""

# ──────────────────────────────────────────────
# PHASE 15: Rapid Sequential Operations
# ──────────────────────────────────────────────
echo "--- Phase 15: Rapid Fire (30 sequential operations) ---"

echo -n "[$((TOTAL + 1))] sym: 30 rapid encrypt-decrypt cycles (small files) ... "
TOTAL=$((TOTAL + 1))
rapid_ok=true
for i in $(seq 1 30); do
    rdir="$WORKDIR/rapid_$i"
    rdec="$WORKDIR/rapid_dec_$i"
    mkdir -p "$rdir" "$rdec"
    printf "rapid test data #%d with some padding to make it interesting %s" "$i" "$(head -c 100 /dev/urandom | base64)" > "$WORKDIR/rapid_src_$i.txt"
    if ! $FC encrypt -i "$WORKDIR/rapid_src_$i.txt" -o "$rdir" 2>/dev/null; then
        rapid_ok=false
        break
    fi
    if ! $FC decrypt -i "$rdir"/*.fcr -o "$rdec" 2>/dev/null; then
        rapid_ok=false
        break
    fi
    if ! assert_identical "$WORKDIR/rapid_src_$i.txt" "$rdec/rapid_src_$i.txt"; then
        rapid_ok=false
        break
    fi
done
if $rapid_ok; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL (at iteration $i)"
    FAILED=$((FAILED + 1))
fi

echo ""

# ──────────────────────────────────────────────
# PHASE 16: Multi-recipient Encryption
# ──────────────────────────────────────────────
echo "--- Phase 16: Multi-recipient Encryption ---"

# One file sealed to two public keys; each private key opens it independently.
multi_enc="$WORKDIR/multi_enc"
mkdir -p "$multi_enc"
$FC encrypt -i "$WORKDIR/small.txt" -o "$multi_enc" -k "$PUB" -k "$PUB2" 2>/dev/null
MULTI_FCR=$(ls "$multi_enc"/*.fcr 2>/dev/null | head -1)

multi_dec_a() {
    local d="$WORKDIR/multi_dec_a"; mkdir -p "$d"
    env FERROCRYPT_PASSPHRASE="$PASS" $FC decrypt -i "$MULTI_FCR" -o "$d" -K "$SECRET_KEY" && \
    assert_identical "$WORKDIR/small.txt" "$d/small.txt"
}
run_test "multi: recipient A (key1) decrypts 2-recipient file" multi_dec_a

multi_dec_b() {
    local d="$WORKDIR/multi_dec_b"; mkdir -p "$d"
    env FERROCRYPT_PASSPHRASE="$PASS2" $FC decrypt -i "$MULTI_FCR" -o "$d" -K "$SECRET_KEY2" && \
    assert_identical "$WORKDIR/small.txt" "$d/small.txt"
}
run_test "multi: recipient B (key2) decrypts same file" multi_dec_b

# Two recipient strings via repeated -r; the second key decrypts.
multi_r() {
    local e="$WORKDIR/multi_r_enc" d="$WORKDIR/multi_r_dec"
    mkdir -p "$e" "$d"
    local R1 R2
    R1=$(tr -d '\n' < "$PUB"); R2=$(tr -d '\n' < "$PUB2")
    $FC encrypt -i "$WORKDIR/small.txt" -o "$e" -r "$R1" -r "$R2" && \
    env FERROCRYPT_PASSPHRASE="$PASS2" $FC decrypt -i "$e"/*.fcr -o "$d" -K "$SECRET_KEY2" && \
    assert_identical "$WORKDIR/small.txt" "$d/small.txt"
}
run_test "multi: two recipient strings, second key decrypts" multi_r

# A private key that is not among the recipients is rejected.
multi_wrong_enc="$WORKDIR/multi_wrong_enc"
mkdir -p "$multi_wrong_enc" "$WORKDIR/multi_wrong_dec"
$FC encrypt -i "$WORKDIR/small.txt" -o "$multi_wrong_enc" -k "$PUB" 2>/dev/null
run_test_expect_fail "multi: non-recipient key rejected" \
    env FERROCRYPT_PASSPHRASE="$PASS2" $FC decrypt -i "$multi_wrong_enc"/small.fcr -o "$WORKDIR/multi_wrong_dec" -K "$SECRET_KEY2"

echo ""

# ──────────────────────────────────────────────
# PHASE 17: KDF Resource Caps (decrypt-side DoS guard)
# ──────────────────────────────────────────────
echo "--- Phase 17: KDF Resource Caps (decrypt-side DoS guard) ---"

kdf_enc="$WORKDIR/kdf_enc"
mkdir -p "$kdf_enc"
$FC encrypt -i "$WORKDIR/small.txt" -o "$kdf_enc" 2>/dev/null
KDF_FCR="$kdf_enc/small.fcr"

# A memory cap of 0 rejects every file; a cap below the file's cost rejects
# before Argon2id runs; a cap at or above the cost decrypts normally.
mkdir -p "$WORKDIR/kdf_dec0"
run_test_expect_fail "kdf: --max-kdf-memory 0 rejects" \
    $FC decrypt -i "$KDF_FCR" -o "$WORKDIR/kdf_dec0" --max-kdf-memory 0
mkdir -p "$WORKDIR/kdf_dec_low"
run_test_expect_fail "kdf: cap below file's memory cost rejects" \
    $FC decrypt -i "$KDF_FCR" -o "$WORKDIR/kdf_dec_low" --max-kdf-memory 1
kdf_ok() {
    local d="$WORKDIR/kdf_dec_ok"; mkdir -p "$d"
    $FC decrypt -i "$KDF_FCR" -o "$d" --max-kdf-memory 2048 && \
    assert_identical "$WORKDIR/small.txt" "$d/small.txt"
}
run_test "kdf: cap above file's memory cost succeeds" kdf_ok
mkdir -p "$WORKDIR/kdf_dect0"
run_test_expect_fail "kdf: --max-kdf-time-cost 0 rejects" \
    $FC decrypt -i "$KDF_FCR" -o "$WORKDIR/kdf_dect0" --max-kdf-time-cost 0

echo ""

# ──────────────────────────────────────────────
# PHASE 18: keep-partial (incomplete-output policy)
# ──────────────────────────────────────────────
echo "--- Phase 18: keep-partial (incomplete-output policy) ---"

# Corrupt a byte at ~90% so early payload chunks stage under .incomplete
# before the tampered chunk fails authentication.
kp_enc="$WORKDIR/kp_enc"
mkdir -p "$kp_enc"
$FC encrypt -i "$WORKDIR/1mb.bin" -o "$kp_enc" 2>/dev/null
KP_FCR="$kp_enc/1mb.fcr"
KP_SIZE=$(stat -f%z "$KP_FCR" 2>/dev/null || stat -c%s "$KP_FCR" 2>/dev/null)
KP_OFF=$(( KP_SIZE * 9 / 10 ))
python3 -c "
data = bytearray(open('$KP_FCR','rb').read())
data[$KP_OFF] ^= 0xFF
open('$KP_FCR','wb').write(data)
"

# Default policy: a failed decrypt leaves no .incomplete behind.
kp_default() {
    local d="$WORKDIR/kp_default"; mkdir -p "$d"
    if $FC decrypt -i "$KP_FCR" -o "$d" 2>/dev/null; then return 1; fi
    ! ls -d "$d"/*.incomplete >/dev/null 2>&1
}
run_test "keep-partial: default removes .incomplete on failure" kp_default

# --keep-partial: a failed decrypt retains the staged .incomplete.
kp_keep() {
    local d="$WORKDIR/kp_keep"; mkdir -p "$d"
    if $FC decrypt -i "$KP_FCR" -o "$d" --keep-partial 2>/dev/null; then return 1; fi
    ls -d "$d"/*.incomplete >/dev/null 2>&1
}
run_test "keep-partial: --keep-partial retains .incomplete on failure" kp_keep

echo ""

# ──────────────────────────────────────────────
# PHASE 19: Symlink & Special-file Rejection
# ──────────────────────────────────────────────
echo "--- Phase 19: Symlink & Special-file Rejection ---"

if is_unix_perms; then
    # Symlink as the input root.
    ln -s "$WORKDIR/small.txt" "$WORKDIR/rootlink.txt"
    mkdir -p "$WORKDIR/syml_enc1"
    run_test_expect_fail "symlink: root symlink input rejected" \
        $FC encrypt -i "$WORKDIR/rootlink.txt" -o "$WORKDIR/syml_enc1" -k "$PUB"

    # Symlink inside a directory tree.
    symdir="$WORKDIR/symdir"
    mkdir -p "$symdir"
    echo "real" > "$symdir/real.txt"
    ln -s real.txt "$symdir/link.txt"
    mkdir -p "$WORKDIR/syml_enc2"
    run_test_expect_fail "symlink: symlink inside directory rejected" \
        $FC encrypt -i "$symdir" -o "$WORKDIR/syml_enc2" -k "$PUB"

    # FIFO inside a directory tree.
    fifodir="$WORKDIR/fifodir"
    mkdir -p "$fifodir"
    echo "ok" > "$fifodir/plain.txt"
    if mkfifo "$fifodir/pipe" 2>/dev/null; then
        mkdir -p "$WORKDIR/fifo_enc"
        run_test_expect_fail "special: FIFO inside directory rejected" \
            $FC encrypt -i "$fifodir" -o "$WORKDIR/fifo_enc" -k "$PUB"
    fi
else
    echo "[skip] symlink/special-file rejection (non-Unix)"
fi

echo ""

# ──────────────────────────────────────────────
# PHASE 20: Unix Permission-bit Preservation
# ──────────────────────────────────────────────
echo "--- Phase 20: Unix Permission-bit Preservation ---"

if is_unix_perms; then
    permdir="$WORKDIR/permdir"
    mkdir -p "$permdir/sub"
    echo "a" > "$permdir/f600.txt"; chmod 600 "$permdir/f600.txt"
    echo "b" > "$permdir/f640.txt"; chmod 640 "$permdir/f640.txt"
    echo "c" > "$permdir/f755.sh";  chmod 755 "$permdir/f755.sh"
    echo "d" > "$permdir/sub/inner.txt"; chmod 644 "$permdir/sub/inner.txt"
    chmod 700 "$permdir/sub"

    perm_roundtrip() {
        local e="$WORKDIR/perm_enc" d="$WORKDIR/perm_dec"
        mkdir -p "$e" "$d"
        $FC encrypt -i "$permdir" -o "$e" -k "$PUB" 2>/dev/null || return 1
        env FERROCRYPT_PASSPHRASE="$PASS" $FC decrypt -i "$e"/*.fcr -o "$d" -K "$SECRET_KEY" 2>/dev/null || return 1
        local base="$d/permdir"
        [ "$(perm_mode "$base/f600.txt")" = "600" ] && \
        [ "$(perm_mode "$base/f640.txt")" = "640" ] && \
        [ "$(perm_mode "$base/f755.sh")"  = "755" ] && \
        [ "$(perm_mode "$base/sub")"      = "700" ] && \
        [ "$(perm_mode "$base/sub/inner.txt")" = "644" ]
    }
    run_test "perms: file & directory modes preserved through round-trip" perm_roundtrip
else
    echo "[skip] permission preservation (non-Unix)"
fi

echo ""

# ──────────────────────────────────────────────
# PHASE 21: Fingerprint Subcommand
# ──────────────────────────────────────────────
echo "--- Phase 21: Fingerprint Subcommand ---"

run_test "fingerprint: prints fingerprint for valid public key" \
    $FC fingerprint "$PUB"
run_test "fingerprint: 'fp' alias works" \
    $FC fp "$PUB2"
run_test_expect_fail "fingerprint: rejects non-public-key file" \
    $FC fingerprint "$WORKDIR/small.txt"

echo ""

# ──────────────────────────────────────────────
# PHASE 22: Atomic Crash Safety (SIGKILL mid-operation)
# ──────────────────────────────────────────────
echo "--- Phase 22: Atomic Crash Safety (SIGKILL mid-operation) ---"

# Iteration count and payload size are overridable so the phase can be dialed
# down on slow machines. Hybrid mode keeps the 1 GiB Argon2id off the encrypt
# path so kills land in the streaming window, not the KDF.
CRASH_ITERS="${FERROCRYPT_STRESS_CRASH_ITERS:-12}"
CRASH_MIB="${FERROCRYPT_STRESS_CRASH_MIB:-250}"
dd if=/dev/urandom of="$WORKDIR/crash_src.bin" bs=1048576 count="$CRASH_MIB" 2>/dev/null

# Encrypt-crash: the committed .fcr is never a partial file. After each SIGKILL
# it is either absent (killed before the atomic rename) or a complete file that
# decrypts back to the original.
echo -n "[$((TOTAL + 1))] crash: SIGKILL during encrypt never commits a partial .fcr ... "
TOTAL=$((TOTAL + 1))
set +e
crash_enc_ok=true
crash_enc_committed=0
for i in $(seq 1 "$CRASH_ITERS"); do
    cdir="$WORKDIR/crash_enc"
    rm -rf "$cdir"; mkdir -p "$cdir"
    $FC encrypt -i "$WORKDIR/crash_src.bin" -o "$cdir" -k "$PUB" >/dev/null 2>&1 &
    cpid=$!
    sleep "0.$(printf '%02d' $(( (RANDOM % 50) + 1 )))"
    kill -9 "$cpid" 2>/dev/null
    wait "$cpid" 2>/dev/null
    committed="$cdir/crash_src.fcr"
    if [ -f "$committed" ]; then
        crash_enc_committed=$((crash_enc_committed + 1))
        vdir="$WORKDIR/crash_enc_verify"
        rm -rf "$vdir"; mkdir -p "$vdir"
        if ! env FERROCRYPT_PASSPHRASE="$PASS" $FC decrypt -i "$committed" -o "$vdir" -K "$SECRET_KEY" >/dev/null 2>&1 \
             || ! assert_identical "$WORKDIR/crash_src.bin" "$vdir/crash_src.bin"; then
            crash_enc_ok=false
            break
        fi
    fi
done
set -e
if $crash_enc_ok; then
    echo "PASS (${crash_enc_committed}/${CRASH_ITERS} completed & verified)"
    PASSED=$((PASSED + 1))
else
    echo "FAIL (committed .fcr was partial/corrupt)"
    FAILED=$((FAILED + 1))
fi

# Decrypt-crash: pre-encrypt cleanly, then SIGKILL the instant extraction
# begins (the .incomplete staging entry appears only after the KDF unlock, so
# this deterministically lands mid-extraction). The committed output is never a
# partial file, and a fresh decrypt still recovers the plaintext.
clean_enc="$WORKDIR/crash_clean_enc"
mkdir -p "$clean_enc"
$FC encrypt -i "$WORKDIR/crash_src.bin" -o "$clean_enc" -k "$PUB" 2>/dev/null
CLEAN_FCR="$clean_enc/crash_src.fcr"

echo -n "[$((TOTAL + 1))] crash: SIGKILL during decrypt extraction never commits a partial output ... "
TOTAL=$((TOTAL + 1))
set +e
crash_dec_ok=true
crash_dec_caught=0
for i in $(seq 1 "$CRASH_ITERS"); do
    ddir="$WORKDIR/crash_dec"
    rm -rf "$ddir"; mkdir -p "$ddir"
    env FERROCRYPT_PASSPHRASE="$PASS" $FC decrypt -i "$CLEAN_FCR" -o "$ddir" -K "$SECRET_KEY" >/dev/null 2>&1 &
    dpid=$!
    while kill -0 "$dpid" 2>/dev/null; do
        if ls -d "$ddir"/*.incomplete >/dev/null 2>&1; then
            kill -9 "$dpid" 2>/dev/null
            crash_dec_caught=$((crash_dec_caught + 1))
            break
        fi
        sleep 0.005
    done
    wait "$dpid" 2>/dev/null
    committed="$ddir/crash_src.bin"
    if [ -f "$committed" ] && ! assert_identical "$WORKDIR/crash_src.bin" "$committed"; then
        crash_dec_ok=false
        break
    fi
done
rdir="$WORKDIR/crash_dec_recover"; mkdir -p "$rdir"
if ! env FERROCRYPT_PASSPHRASE="$PASS" $FC decrypt -i "$CLEAN_FCR" -o "$rdir" -K "$SECRET_KEY" >/dev/null 2>&1 \
     || ! assert_identical "$WORKDIR/crash_src.bin" "$rdir/crash_src.bin"; then
    crash_dec_ok=false
fi
set -e
if $crash_dec_ok; then
    echo "PASS (${crash_dec_caught}/${CRASH_ITERS} killed mid-extraction, recovery OK)"
    PASSED=$((PASSED + 1))
else
    echo "FAIL (committed output partial, or recovery failed)"
    FAILED=$((FAILED + 1))
fi
rm -f "$WORKDIR/crash_src.bin"

echo ""

# ──────────────────────────────────────────────
# PHASE 23: Concurrent Same-path No-clobber Race
# ──────────────────────────────────────────────
echo "--- Phase 23: Concurrent Same-path No-clobber Race ---"

# Several writers race for the same --save-as path. Atomic no-clobber
# finalization means exactly one commits and the output is a valid file, never
# an interleaved blend of two encryptions.
echo -n "[$((TOTAL + 1))] race: concurrent encrypts to one --save-as path stay no-clobber ... "
TOTAL=$((TOTAL + 1))
racedir="$WORKDIR/race"
rm -rf "$racedir"; mkdir -p "$racedir"
RACE_TARGET="$racedir/same.fcr"
set +e
race_pids=()
for i in $(seq 1 6); do
    $FC encrypt -i "$WORKDIR/1mb.bin" -s "$RACE_TARGET" -k "$PUB" >/dev/null 2>&1 &
    race_pids+=($!)
done
race_success=0
for pid in "${race_pids[@]}"; do
    if wait "$pid"; then race_success=$((race_success + 1)); fi
done
set -e
race_valid=false
if [ -f "$RACE_TARGET" ]; then
    rdec="$WORKDIR/race_dec"; mkdir -p "$rdec"
    if env FERROCRYPT_PASSPHRASE="$PASS" $FC decrypt -i "$RACE_TARGET" -o "$rdec" -K "$SECRET_KEY" >/dev/null 2>&1 \
       && assert_identical "$WORKDIR/1mb.bin" "$rdec/1mb.bin"; then
        race_valid=true
    fi
fi
if $race_valid && [ "$race_success" -eq 1 ]; then
    echo "PASS (1/6 committed, output valid)"
    PASSED=$((PASSED + 1))
elif $race_valid && [ "$race_success" -gt 1 ]; then
    echo "FAIL (clobber: $race_success writers committed)"
    FAILED=$((FAILED + 1))
else
    echo "FAIL (success=$race_success, output valid=$race_valid)"
    FAILED=$((FAILED + 1))
fi

echo ""

# ──────────────────────────────────────────────
# PHASE 24: Bounded Memory on Large Input (streaming)
# ──────────────────────────────────────────────
echo "--- Phase 24: Bounded Memory on Large Input (streaming) ---"

# A streaming encryptor must not load the whole file. Hybrid mode is used so the
# 1 GiB Argon2id does not dominate resident memory. Peak RSS well under the file
# size proves streaming; a whole-file load would blow past the limit.
MEM_MIB="${FERROCRYPT_STRESS_MEM_MIB:-2048}"
MEM_LIMIT_MIB="${FERROCRYPT_STRESS_MEM_LIMIT_MIB:-512}"
if [ ! -x /usr/bin/time ]; then
    echo "[skip] memory ceiling (/usr/bin/time not available)"
else
    echo -n "[$((TOTAL + 1))] mem: ${MEM_MIB}MiB hybrid encrypt stays under ${MEM_LIMIT_MIB}MiB RSS ... "
    TOTAL=$((TOTAL + 1))
    dd if=/dev/urandom of="$WORKDIR/mem_src.bin" bs=1048576 count="$MEM_MIB" 2>/dev/null
    mem_enc="$WORKDIR/mem_enc"; mkdir -p "$mem_enc"
    TIMELOG="$WORKDIR/mem_time.log"
    set +e
    case "$(uname -s)" in
        Darwin)
            /usr/bin/time -l $FC encrypt -i "$WORKDIR/mem_src.bin" -o "$mem_enc" -k "$PUB" >/dev/null 2>"$TIMELOG"
            rss_bytes=$(awk '/maximum resident set size/ {print $1}' "$TIMELOG" | head -1)
            ;;
        *)
            /usr/bin/time -v $FC encrypt -i "$WORKDIR/mem_src.bin" -o "$mem_enc" -k "$PUB" >/dev/null 2>"$TIMELOG"
            rss_kib=$(awk -F': ' '/Maximum resident set size/ {print $2}' "$TIMELOG" | head -1)
            rss_bytes=$(( ${rss_kib:-0} * 1024 ))
            ;;
    esac
    set -e
    rm -f "$WORKDIR/mem_src.bin"
    case "${rss_bytes:-}" in
        ''|*[!0-9]*)
            echo "[skip] (could not read RSS from /usr/bin/time)"
            TOTAL=$((TOTAL - 1))
            ;;
        *)
            rss_mib=$(( rss_bytes / 1048576 ))
            if [ "$rss_mib" -lt "$MEM_LIMIT_MIB" ]; then
                echo "PASS (peak RSS ${rss_mib}MiB)"
                PASSED=$((PASSED + 1))
            else
                echo "FAIL (peak RSS ${rss_mib}MiB >= ${MEM_LIMIT_MIB}MiB — not streaming?)"
                FAILED=$((FAILED + 1))
            fi
            ;;
    esac
fi

echo ""

# ──────────────────────────────────────────────
# PHASE 25: Soak (repeated operations, no staging litter)
# ──────────────────────────────────────────────
echo "--- Phase 25: Soak (repeated operations, no staging litter) ---"

# Many encrypt cycles exercise staging and no-clobber finalization repeatedly;
# a sparse decrypt confirms integrity without paying the KDF on every loop. No
# .incomplete or temp staging file may accumulate.
SOAK_ITERS="${FERROCRYPT_STRESS_SOAK_ITERS:-200}"
echo -n "[$((TOTAL + 1))] soak: ${SOAK_ITERS} encrypt cycles, sparse verify, no litter ... "
TOTAL=$((TOTAL + 1))
soakdir="$WORKDIR/soak"
rm -rf "$soakdir"; mkdir -p "$soakdir/enc" "$soakdir/dec"
soak_ok=true
for i in $(seq 1 "$SOAK_ITERS"); do
    src="$soakdir/src.bin"
    head -c "$(( (RANDOM % 4096) + 1 ))" /dev/urandom > "$src"
    tgt="$soakdir/enc/src_$i.fcr"
    if ! $FC encrypt -i "$src" -s "$tgt" -k "$PUB" >/dev/null 2>&1; then
        soak_ok=false; break
    fi
    if [ "$(( i % 50 ))" -eq 0 ]; then
        rm -f "$soakdir/dec/src.bin"
        if ! env FERROCRYPT_PASSPHRASE="$PASS" $FC decrypt -i "$tgt" -o "$soakdir/dec" -K "$SECRET_KEY" >/dev/null 2>&1 \
             || ! assert_identical "$src" "$soakdir/dec/src.bin"; then
            soak_ok=false; break
        fi
    fi
done
litter=$(find "$soakdir" \( -name '*.incomplete' -o -name '.tmp*' \) 2>/dev/null | wc -l | tr -d ' ')
if $soak_ok && [ "$litter" -eq 0 ]; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL (all-ok=$soak_ok, staging litter=$litter)"
    FAILED=$((FAILED + 1))
fi

echo ""

# ──────────────────────────────────────────────
# PHASE 26: Disk-full (ENOSPC) atomicity
# ──────────────────────────────────────────────
echo "--- Phase 26: Disk-full (ENOSPC) atomicity ---"

# Needs a small, fillable filesystem. macOS gets one from hdiutil with no root;
# elsewhere point FERROCRYPT_STRESS_ENOSPC_DIR at a small pre-mounted volume.
enospc_supported=false
ENOSPC_MNT=""
ENOSPC_IMG=""
if [ -n "${FERROCRYPT_STRESS_ENOSPC_DIR:-}" ]; then
    ENOSPC_MNT="$FERROCRYPT_STRESS_ENOSPC_DIR"
    enospc_supported=true
elif [ "$(uname -s)" = "Darwin" ]; then
    ENOSPC_IMG="$WORKDIR/enospc.dmg"
    if hdiutil create -size 24m -fs APFS -volname fcenospc -quiet "$ENOSPC_IMG" 2>/dev/null; then
        ATTACH_OUT=$(hdiutil attach "$ENOSPC_IMG" -nobrowse 2>/dev/null)
        ENOSPC_MNT=$(echo "$ATTACH_OUT" | awk '{for(i=1;i<=NF;i++) if($i ~ /^\/Volumes\//){print $i; exit}}')
        [ -z "$ENOSPC_MNT" ] && ENOSPC_MNT="/Volumes/fcenospc"
        [ -d "$ENOSPC_MNT" ] && enospc_supported=true
    fi
fi

if $enospc_supported; then
    echo -n "[$((TOTAL + 1))] enospc: encrypt into a full filesystem commits no partial .fcr ... "
    TOTAL=$((TOTAL + 1))
    set +e
    # Fill the volume, then try to write an output larger than the whole
    # volume so it cannot fit regardless of filesystem overhead.
    dd if=/dev/zero of="$ENOSPC_MNT/filler.bin" bs=1048576 2>/dev/null
    dd if=/dev/urandom of="$WORKDIR/enospc_src.bin" bs=1048576 count=32 2>/dev/null
    $FC encrypt -i "$WORKDIR/enospc_src.bin" -s "$ENOSPC_MNT/out.fcr" -k "$PUB" >/dev/null 2>&1
    enc_rc=$?
    set -e
    if [ "$enc_rc" -ne 0 ] && [ ! -f "$ENOSPC_MNT/out.fcr" ]; then
        echo "PASS (failed cleanly, no committed output)"
        PASSED=$((PASSED + 1))
    else
        present=$( [ -f "$ENOSPC_MNT/out.fcr" ] && echo yes || echo no )
        echo "FAIL (rc=$enc_rc, committed out.fcr present=$present)"
        FAILED=$((FAILED + 1))
    fi
    rm -f "$ENOSPC_MNT/filler.bin" "$ENOSPC_MNT/out.fcr" 2>/dev/null
    if [ -n "$ENOSPC_IMG" ]; then
        hdiutil detach "$ENOSPC_MNT" -quiet 2>/dev/null || hdiutil detach "$ENOSPC_MNT" -force 2>/dev/null
    fi
else
    echo "[skip] ENOSPC atomicity (needs macOS hdiutil or FERROCRYPT_STRESS_ENOSPC_DIR)"
fi

echo ""
echo "=========================================="
