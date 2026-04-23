//! Triple-replication encoder and decoder for the 8-byte `.fcr`
//! logical prefix.
//!
//! v1 replicates exactly one field — the 8-byte on-disk header
//! prefix — so the encoder and decoder here only need to handle
//! even-length payloads. The wire format is:
//!
//! ```text
//! [ pad(0x00) | pad(0x00) | pad(0x00) | copy_0 | copy_1 | copy_2 ]
//! ```
//!
//! The three leading pad bytes are always `0x00` per FORMAT.md §5.1.
//! Older drafts used the leading pad bytes as an odd-length padding
//! indicator; v1 never replicates odd-length payloads, so the pad
//! bytes are literal zeros and the odd-length machinery has been
//! removed. Non-zero pad bytes break canonicity and are rejected by
//! [`decode_and_canonicalize_prefix`](crate::format::decode_and_canonicalize_prefix).

use crate::CryptoError;

/// Encoded size for a replicated payload of `original_size` bytes.
///
/// v1 only replicates the 8-byte `.fcr` logical prefix; callers MUST
/// pass an even value. `build_encoded_header_prefix` is the single
/// in-tree caller.
pub const fn encoded_size(original_size: usize) -> usize {
    3 + original_size * 3
}

/// Triple-replicates `data` with three zero pad bytes prepended. The
/// output is exactly [`encoded_size(data.len())`](encoded_size) bytes.
///
/// Callers MUST pass even-length `data`. The single v1 call site
/// passes the 8-byte logical prefix. `debug_assert!` pins the
/// invariant so a future caller that passes odd-length data fails
/// loudly in tests instead of silently producing output that would be
/// rejected at decode time.
pub fn encode(data: &[u8]) -> Vec<u8> {
    debug_assert!(
        data.len().is_multiple_of(2),
        "replication::encode: v1 only replicates even-length payloads"
    );
    let mut output = Vec::with_capacity(3 + data.len() * 3);
    output.push(0);
    output.push(0);
    output.push(0);
    output.extend_from_slice(data);
    output.extend_from_slice(data);
    output.extend_from_slice(data);
    output
}

/// Majority-vote decodes a triple-replicated payload, corrects
/// single-copy bit flips at every byte position, and returns the
/// recovered logical bytes.
///
/// Structural checks:
/// - `data.len() >= 3` (room for three pad bytes);
/// - `(data.len() - 3) % 3 == 0` (payload splits evenly into three
///   copies).
///
/// Leading pad-byte inspection is deliberately NOT a rejection point
/// here: callers that need canonicity (writers emit three zero pads,
/// any non-zero pad breaks canonicity) verify it by re-encoding and
/// comparing on-disk bytes — see
/// [`crate::format::decode_and_canonicalize_prefix`]. The fuzz target
/// drives this function on arbitrary input, so keeping `decode`
/// permissive about pad bytes means fuzzing exercises the
/// majority-vote core without pre-filtering canonical inputs.
pub fn decode(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 3 {
        return Err(CryptoError::InvalidInput(
            "Data too short for decoding".to_string(),
        ));
    }

    let remaining = &data[3..];
    if !remaining.len().is_multiple_of(3) {
        return Err(CryptoError::InvalidInput(
            "Incorrect encoded bytes length".to_string(),
        ));
    }

    let shard_bytes = remaining.len() / 3;
    let copy_0 = &remaining[0..shard_bytes];
    let copy_1 = &remaining[shard_bytes..2 * shard_bytes];
    let copy_2 = &remaining[2 * shard_bytes..3 * shard_bytes];

    // Majority vote across 3 copies per byte position.
    let mut result = Vec::with_capacity(shard_bytes);
    for i in 0..shard_bytes {
        let (a, b, c) = (copy_0[i], copy_1[i], copy_2[i]);
        result.push(if a == b || a == c { a } else { b });
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_8_byte_prefix() {
        let original: [u8; 8] = [b'F', b'C', b'R', 0, 1, b'S', 0, 0];
        let encoded = encode(&original);
        assert_eq!(encoded.len(), encoded_size(original.len()));
        assert_eq!(&encoded[0..3], &[0, 0, 0]); // pads always zero
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.as_slice(), original.as_slice());
    }

    #[test]
    fn encode_emits_three_zero_pads() {
        // Pads are always 0 for any even-length input — v1 has no
        // odd-length replicated fields.
        let encoded = encode(&[0xAA; 8]);
        assert_eq!(&encoded[0..3], &[0, 0, 0]);
    }

    #[test]
    fn encode_decode_even_length_data() {
        let original = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            0, 1, 2,
        ];

        let encoded = encode(&original);
        assert_eq!(encoded.len(), encoded_size(original.len()));

        let decoded = decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn encode_decode_two_bytes() {
        let original = [0xFF, 0x00];
        let encoded = encode(&original);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn reconstruct_with_corrupted_first_copy() {
        let original: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            0, 1, 2,
        ];

        let mut encoded = encode(&original);

        // Corrupt bytes in the first copy (indices 3..35).
        encoded[3] = 0xFF;
        encoded[12] = 0xFF;
        encoded[22] = 0xFF;
        encoded[32] = 0xFF;

        // Other two copies should outvote the corrupted one.
        let decoded = decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn reconstruct_with_corrupted_second_copy() {
        let original: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            0, 1, 2,
        ];

        let mut encoded = encode(&original);

        // Corrupt bytes in the second copy (indices 35..67).
        encoded[35] = 0xFF;
        encoded[42] = 0xFF;
        encoded[52] = 0xFF;

        // First + third copies should outvote the corrupted second.
        let decoded = decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn decode_empty_data_returns_error() {
        let result = decode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_too_short_returns_error() {
        let result = decode(&[0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_invalid_length_returns_error() {
        // After removing the 3 padding bytes, remaining length must be divisible by 3.
        let result = decode(&[0, 0, 0, 1, 2, 3, 4]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_permissive_about_nonzero_pads() {
        // `decode` itself does not enforce zero pads — that invariant
        // is enforced by the canonicity check in
        // `format::decode_and_canonicalize_prefix`. Keeping decode
        // permissive lets the fuzz harness exercise the majority-vote
        // core on arbitrary inputs without the pad check filtering
        // them out first.
        let mut encoded = encode(&[0xAAu8; 8]);
        encoded[0] = 0xFF;
        encoded[1] = 0xFF;
        encoded[2] = 0xFF;
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, vec![0xAA; 8]);
    }

    #[test]
    fn encoded_size_calculation() {
        // v1 only calls this for the 8-byte prefix, but the helper
        // stays valid for any even-length input.
        assert_eq!(encoded_size(8), 27);
        assert_eq!(encoded_size(32), 99);
        assert_eq!(encoded_size(24), 75);
    }
}
