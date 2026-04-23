#!/usr/bin/env bash
set -euo pipefail

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

run_test "keygen: verify key file sizes" \
    test "$(stat -f%z "$KEYS/private.key" 2>/dev/null || stat -c%s "$KEYS/private.key" 2>/dev/null)" -eq 125 -a \
         "$(stat -f%z "$KEYS/public.key" 2>/dev/null || stat -c%s "$KEYS/public.key" 2>/dev/null)" -eq 64

PUB="$KEYS/public.key"
SECRET_KEY="$KEYS/private.key"
PUB2="$KEYS2/public.key"
SECRET_KEY2="$KEYS2/private.key"

echo ""

# ──────────────────────────────────────────────
# PHASE 2: Symmetric Roundtrips
# ──────────────────────────────────────────────
echo "--- Phase 2: Symmetric Encryption Roundtrips ---"

# Helper: symmetric roundtrip test for a single file
sym_roundtrip_file() {
    local src="$1"
    local label="$2"
    local enc_dir="$WORKDIR/enc_sym_${label}"
    local dec_dir="$WORKDIR/dec_sym_${label}"
    mkdir -p "$enc_dir" "$dec_dir"
    $FC symmetric -i "$src" -o "$enc_dir" && \
    $FC symmetric -i "$enc_dir"/*.fcr -o "$dec_dir" && \
    assert_identical "$src" "$dec_dir/$(basename "$src")"
}

# Helper: symmetric roundtrip test for a directory
sym_roundtrip_dir() {
    local src="$1"
    local label="$2"
    local enc_dir="$WORKDIR/enc_sym_${label}"
    local dec_dir="$WORKDIR/dec_sym_${label}"
    mkdir -p "$enc_dir" "$dec_dir"
    $FC symmetric -i "$src" -o "$enc_dir" && \
    $FC symmetric -i "$enc_dir"/*.fcr -o "$dec_dir" && \
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
if $FC symmetric -i "$WORKDIR/100mb.bin" -o "$enc100" 2>/dev/null && \
   $FC symmetric -i "$enc100"/*.fcr -o "$dec100" 2>/dev/null && \
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
    $FC hybrid -i "$src" -o "$enc_dir" -k "$pubkey" && \
    $FC hybrid -i "$enc_dir"/*.fcr -o "$dec_dir" -k "$secretkey" && \
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
    $FC hybrid -i "$src" -o "$enc_dir" -k "$pubkey" && \
    $FC hybrid -i "$enc_dir"/*.fcr -o "$dec_dir" -k "$secretkey" && \
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
if $FC hybrid -i "$WORKDIR/100mb_hyb.bin" -o "$enc100h" -k "$PUB" 2>/dev/null && \
   $FC hybrid -i "$enc100h"/*.fcr -o "$dec100h" -k "$SECRET_KEY" 2>/dev/null && \
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
    $FC symmetric -i "$WORKDIR/small.txt" -o "$saveas_dir" -s "$saveas_dir/custom_name.fcr" && \
    test -f "$saveas_dir/custom_name.fcr" && \
    $FC symmetric -i "$saveas_dir/custom_name.fcr" -o "$saveas_dec" && \
    assert_identical "$WORKDIR/small.txt" "$saveas_dec/small.txt"
}
run_test "sym: custom output name" sym_saveas_roundtrip

hyb_saveas_roundtrip() {
    local saveas2_dir="$WORKDIR/saveas2"
    local saveas2_dec="$WORKDIR/saveas2_dec"
    mkdir -p "$saveas2_dir" "$saveas2_dec"
    $FC hybrid -i "$WORKDIR/small.txt" -o "$saveas2_dir" -k "$PUB" -s "$saveas2_dir/renamed.fcr" && \
    test -f "$saveas2_dir/renamed.fcr" && \
    $FC hybrid -i "$saveas2_dir/renamed.fcr" -o "$saveas2_dec" -k "$SECRET_KEY" && \
    assert_identical "$WORKDIR/small.txt" "$saveas2_dec/small.txt"
}
run_test "hyb: custom output name" hyb_saveas_roundtrip

# Recipient-string encrypt → decrypt roundtrip
hyb_recipient_roundtrip() {
    local rcpt_enc="$WORKDIR/rcpt_enc"
    local rcpt_dec="$WORKDIR/rcpt_dec"
    mkdir -p "$rcpt_enc" "$rcpt_dec"
    local RCPT
    RCPT=$($FC recipient "$PUB")
    $FC hybrid -i "$WORKDIR/small.txt" -o "$rcpt_enc" -r "$RCPT" && \
    $FC hybrid -i "$rcpt_enc"/*.fcr -o "$rcpt_dec" -k "$SECRET_KEY" && \
    assert_identical "$WORKDIR/small.txt" "$rcpt_dec/small.txt"
}
run_test "hyb: recipient string roundtrip" hyb_recipient_roundtrip

echo ""

# ──────────────────────────────────────────────
# PHASE 6: Error Handling & Rejection
# ──────────────────────────────────────────────
echo "--- Phase 6: Error Handling & Rejection ---"

# Wrong password on symmetric decrypt
err1_enc="$WORKDIR/err1_enc"
err1_dec="$WORKDIR/err1_dec"
mkdir -p "$err1_enc" "$err1_dec"
$FC symmetric -i "$WORKDIR/small.txt" -o "$err1_enc" 2>/dev/null
run_test_expect_fail "sym: wrong password rejects" \
    env FERROCRYPT_PASSPHRASE="$PASS2" $FC symmetric -i "$err1_enc"/*.fcr -o "$err1_dec"
# Wrong passphrase on hybrid decrypt
err2_enc="$WORKDIR/err2_enc"
err2_dec="$WORKDIR/err2_dec"
mkdir -p "$err2_enc" "$err2_dec"
$FC hybrid -i "$WORKDIR/small.txt" -o "$err2_enc" -k "$PUB" 2>/dev/null
run_test_expect_fail "hyb: wrong passphrase rejects" \
    env FERROCRYPT_PASSPHRASE="$PASS2" $FC hybrid -i "$err2_enc"/*.fcr -o "$err2_dec" -k "$SECRET_KEY"
# Wrong key entirely (different keypair)
err3_dec="$WORKDIR/err3_dec"
mkdir -p "$err3_dec"
run_test_expect_fail "hyb: wrong key rejects" \
    env FERROCRYPT_PASSPHRASE="$PASS2" $FC hybrid -i "$err2_enc"/*.fcr -o "$err3_dec" -k "$SECRET_KEY2"
# Non-existent input file
run_test_expect_fail "sym: non-existent input rejects" \
    $FC symmetric -i "$WORKDIR/does_not_exist.txt" -o "$WORKDIR"
run_test_expect_fail "hyb: non-existent input rejects" \
    $FC hybrid -i "$WORKDIR/does_not_exist.txt" -o "$WORKDIR" -k "$PUB"

# Empty password for symmetric
run_test_expect_fail "sym: empty password rejects" \
    env FERROCRYPT_PASSPHRASE="" $FC symmetric -i "$WORKDIR/small.txt" -o "$WORKDIR/err_empty"

# Corrupted ciphertext: flip bytes in the middle of encrypted file
corr_enc="$WORKDIR/corr_enc"
corr_dec="$WORKDIR/corr_dec"
mkdir -p "$corr_enc" "$corr_dec"
$FC symmetric -i "$WORKDIR/1mb.bin" -o "$corr_enc" 2>/dev/null
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
    $FC symmetric -i "$CORR_FILE" -o "$corr_dec"
# Corrupted header: flip the first byte of the 4-byte magic
corr2_enc="$WORKDIR/corr2_enc"
corr2_dec="$WORKDIR/corr2_dec"
mkdir -p "$corr2_enc" "$corr2_dec"
$FC symmetric -i "$WORKDIR/small.txt" -o "$corr2_enc" 2>/dev/null
CORR2_FILE="$corr2_enc/small.fcr"
python3 -c "
data = bytearray(open('$CORR2_FILE', 'rb').read())
# The 4-byte magic starts at logical prefix offset 0; corrupt the first
# magic byte across 2 of 3 replicated copies.
# Encoded prefix: [pad(3)] [copy0(8)] [copy1(8)] [copy2(8)]
data[3] ^= 0xFF   # copy 0
data[11] ^= 0xFF  # copy 1
open('$CORR2_FILE', 'wb').write(data)
"
# With 2 of 3 copies corrupted at the first magic byte, majority vote yields
# the corrupted value → file is not detected as FerroCrypt → routes to encrypt
# (not decrypt). The file is treated as a normal input and encrypted successfully.
run_test "sym: corrupted magic encrypts (not detected as FerroCrypt)" \
    $FC symmetric -i "$CORR2_FILE" -o "$corr2_dec"
# Truncated file (cut at half)
trunc_enc="$WORKDIR/trunc_enc"
trunc_dec="$WORKDIR/trunc_dec"
mkdir -p "$trunc_enc" "$trunc_dec"
$FC symmetric -i "$WORKDIR/1mb.bin" -o "$trunc_enc" 2>/dev/null
TRUNC_FILE="$trunc_enc/1mb.fcr"
TRUNC_SIZE=$(stat -f%z "$TRUNC_FILE" 2>/dev/null || stat -c%s "$TRUNC_FILE" 2>/dev/null)
dd if="$TRUNC_FILE" of="$TRUNC_FILE.trunc" bs=$((TRUNC_SIZE / 2)) count=1 2>/dev/null
run_test_expect_fail "sym: truncated file rejects" \
    $FC symmetric -i "$TRUNC_FILE.trunc" -o "$trunc_dec"
# Corrupted hybrid file
corr3_enc="$WORKDIR/corr3_enc"
corr3_dec="$WORKDIR/corr3_dec"
mkdir -p "$corr3_enc" "$corr3_dec"
$FC hybrid -i "$WORKDIR/1mb.bin" -o "$corr3_enc" -k "$PUB" 2>/dev/null
CORR3_FILE=$(ls "$corr3_enc"/*.fcr)
python3 -c "
data = bytearray(open('$CORR3_FILE', 'rb').read())
mid = len(data) // 2
for i in range(200):
    data[mid + i] ^= 0xFF
open('$CORR3_FILE', 'wb').write(data)
"
run_test_expect_fail "hyb: corrupted ciphertext rejects" \
    $FC hybrid -i "$CORR3_FILE" -o "$corr3_dec" -k "$SECRET_KEY"
echo ""

# ──────────────────────────────────────────────
# PHASE 7: Cross-mode Rejection
# ──────────────────────────────────────────────
echo "--- Phase 7: Cross-mode Rejection ---"

cross_enc="$WORKDIR/cross_enc"
cross_dec="$WORKDIR/cross_dec"
mkdir -p "$cross_enc" "$cross_dec"

# Encrypt with symmetric, try to decrypt with hybrid
$FC symmetric -i "$WORKDIR/small.txt" -o "$cross_enc" 2>/dev/null
run_test_expect_fail "cross: sym-encrypted file via hybrid rejects" \
    $FC hybrid -i "$cross_enc"/small.fcr -o "$cross_dec" -k "$SECRET_KEY"
# Encrypt with hybrid, try to decrypt with symmetric
cross2_enc="$WORKDIR/cross2_enc"
cross2_dec="$WORKDIR/cross2_dec"
mkdir -p "$cross2_enc" "$cross2_dec"
$FC hybrid -i "$WORKDIR/small.txt" -o "$cross2_enc" -k "$PUB" 2>/dev/null
run_test_expect_fail "cross: hyb-encrypted file via symmetric rejects" \
    $FC symmetric -i "$cross2_enc"/small.fcr -o "$cross2_dec"
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
    $FC hybrid -i "$WORKDIR/small.txt" -o "$mal_enc" -k "$malformed_key"
# Also try malformed key for decryption
$FC hybrid -i "$WORKDIR/small.txt" -o "$mal_enc" -k "$PUB" 2>/dev/null
run_test_expect_fail "hyb: malformed key file rejects (decrypt)" \
    $FC hybrid -i "$mal_enc"/small.fcr -o "$mal_dec" -k "$malformed_key"
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
        $FC symmetric -i "$WORKDIR/tiny_${sz}.fcr" -o "$tiny_enc"
done

# Corrupted header fields (version, header length, HMAC tag)
hdr_src="$WORKDIR/hdr_enc"
hdr_dec="$WORKDIR/hdr_dec"
mkdir -p "$hdr_src" "$hdr_dec"
$FC symmetric -i "$WORKDIR/1mb.bin" -o "$hdr_src" 2>/dev/null
HDR_FILE="$hdr_src/1mb.fcr"
HDR_SIZE=$(stat -f%z "$HDR_FILE" 2>/dev/null || stat -c%s "$HDR_FILE" 2>/dev/null)

# Flip major version (logical prefix byte 2) in 2 of 3 replicated copies
# Encoded prefix: [pad(3)] [copy0(8)] [copy1(8)] [copy2(8)]
cp "$HDR_FILE" "$WORKDIR/corrupt_version.fcr"
python3 -c "
data = bytearray(open('$WORKDIR/corrupt_version.fcr', 'rb').read())
data[3 + 2] ^= 0xFF   # copy 0, major version
data[11 + 2] ^= 0xFF  # copy 1, major version
open('$WORKDIR/corrupt_version.fcr', 'wb').write(data)
"
run_test_expect_fail "sym: corrupted version byte rejects" \
    $FC symmetric -i "$WORKDIR/corrupt_version.fcr" -o "$hdr_dec"
# Flip header length bytes (logical prefix bytes 4-5) in all 3 replicated copies
# Encoded prefix: [pad(3)] [copy0(8)] [copy1(8)] [copy2(8)]
cp "$HDR_FILE" "$WORKDIR/corrupt_hdrlen.fcr"
python3 -c "
data = bytearray(open('$WORKDIR/corrupt_hdrlen.fcr', 'rb').read())
for copy_start in [3, 11, 19]:
    data[copy_start + 4] ^= 0xFF
    data[copy_start + 5] ^= 0xFF
open('$WORKDIR/corrupt_hdrlen.fcr', 'wb').write(data)
"
run_test_expect_fail "sym: corrupted header length rejects" \
    $FC symmetric -i "$WORKDIR/corrupt_hdrlen.fcr" -o "$hdr_dec"
# Corrupt the same salt byte in all three replicated copies so majority vote
# cannot recover the original, causing HMAC mismatch.
# Symmetric header: [prefix(27)] [encoded_salt(99)] ...
# encoded_salt layout: [padding(3)] [copy0(32)] [copy1(32)] [copy2(32)]
cp "$HDR_FILE" "$WORKDIR/corrupt_hmac.fcr"
python3 -c "
data = bytearray(open('$WORKDIR/corrupt_hmac.fcr', 'rb').read())
base = 27  # start of encoded_salt (after 27-byte encoded prefix)
byte_pos = 5  # which salt byte to corrupt
data[base + 3 + byte_pos] ^= 0xFF           # copy 0
data[base + 3 + 32 + byte_pos] ^= 0xFF      # copy 1
data[base + 3 + 64 + byte_pos] ^= 0xFF      # copy 2
open('$WORKDIR/corrupt_hmac.fcr', 'wb').write(data)
"
run_test_expect_fail "sym: corrupted header data (HMAC mismatch) rejects" \
    $FC symmetric -i "$WORKDIR/corrupt_hmac.fcr" -o "$hdr_dec"
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
    $FC symmetric -i "$CONC_DIR/src_$i.bin" -o "$CONC_DIR/enc_$i" 2>/dev/null &
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
    $FC symmetric -i "$CONC_DIR/enc_$i"/*.fcr -o "$CONC_DIR/dec_$i" 2>/dev/null &
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
    $FC symmetric -i "$CONC_DIR/src_$i.bin" -o "$CONC_DIR/mix_sym_enc_$i" 2>/dev/null &
    pids+=($!)
    $FC hybrid -i "$CONC_DIR/src_$((i+4)).bin" -o "$CONC_DIR/mix_hyb_enc_$i" -k "$PUB" 2>/dev/null &
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
if $FC symmetric -i "$WORKDIR/3gb.bin" -o "$big_enc" 2>/dev/null && \
   $FC symmetric -i "$big_enc"/*.fcr -o "$big_dec" 2>/dev/null && \
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
    if ! $FC symmetric -i "$WORKDIR/cycle_current.bin" -o "$cyc_enc" 2>/dev/null; then
        cycle_ok=false
        break
    fi
    if ! $FC symmetric -i "$cyc_enc"/*.fcr -o "$cyc_dec" 2>/dev/null; then
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
# PHASE 12: Auto-detection (encrypted input auto-decrypts)
# ──────────────────────────────────────────────
echo "--- Phase 12: Auto-detection ---"

dbl_enc1="$WORKDIR/dbl_enc1"
dbl_dec1="$WORKDIR/dbl_dec1"
mkdir -p "$dbl_enc1" "$dbl_dec1"

echo -n "[$((TOTAL + 1))] sym: passing .fcr to symmetric auto-decrypts ... "
TOTAL=$((TOTAL + 1))
if $FC symmetric -i "$WORKDIR/1mb.bin" -o "$dbl_enc1" 2>/dev/null && \
   $FC symmetric -i "$dbl_enc1"/*.fcr -o "$dbl_dec1" 2>/dev/null && \
   assert_identical "$WORKDIR/1mb.bin" "$dbl_dec1/1mb.bin"; then
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

# Long filename (200 chars)
LONGNAME=$(python3 -c "print('a' * 200 + '.txt')")
echo "long name test" > "$WORKDIR/$LONGNAME"
run_test "sym: very long filename (200 chars)" sym_roundtrip_file "$WORKDIR/$LONGNAME" "longname"

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
$FC symmetric -i "$WORKDIR/small.txt" -o "$det_enc1" 2>/dev/null
$FC symmetric -i "$WORKDIR/small.txt" -o "$det_enc2" 2>/dev/null

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
$FC hybrid -i "$WORKDIR/small.txt" -o "$det_enc3" -k "$PUB" 2>/dev/null
$FC hybrid -i "$WORKDIR/small.txt" -o "$det_enc4" -k "$PUB" 2>/dev/null

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
    if ! $FC symmetric -i "$WORKDIR/rapid_src_$i.txt" -o "$rdir" 2>/dev/null; then
        rapid_ok=false
        break
    fi
    if ! $FC symmetric -i "$rdir"/*.fcr -o "$rdec" 2>/dev/null; then
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
echo "=========================================="
