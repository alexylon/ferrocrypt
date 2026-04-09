use crate::CryptoError;

/// Calculates the size of triple-replicated data for a given original data size.
/// The encoded format is: [pad, pad, pad, copy_0, copy_1, copy_2]
/// where each copy is even-length (zero-padded if input is odd-length)
/// and the padding indicator is itself triple-replicated.
pub const fn encoded_size(original_size: usize) -> usize {
    let padded_size = if !original_size.is_multiple_of(2) {
        original_size + 1
    } else {
        original_size
    };

    3 + (padded_size * 3)
}

/// Encodes data using triple replication for error correction.
/// Wire format: [pad, pad, pad, copy_0, copy_1, copy_2]
pub fn encode(data: &[u8]) -> Vec<u8> {
    let mut padded = data.to_vec();
    let padding_byte = if !data.len().is_multiple_of(2) {
        padded.push(0);
        1u8
    } else {
        0u8
    };

    let mut output = Vec::with_capacity(3 + padded.len() * 3);
    output.push(padding_byte);
    output.push(padding_byte);
    output.push(padding_byte);
    output.extend_from_slice(&padded);
    output.extend_from_slice(&padded);
    output.extend_from_slice(&padded);
    output
}

/// Decodes triple-replicated data using majority vote per byte position.
/// Corrects any single-copy corruption at each byte, including the
/// padding indicator.
pub fn decode(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 3 {
        return Err(CryptoError::InvalidInput(
            "Data too short for decoding".to_string(),
        ));
    }

    let (p0, p1, p2) = (data[0], data[1], data[2]);
    let padding_byte = if p0 == p1 || p0 == p2 { p0 } else { p1 };
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

    // Majority vote across 3 copies per byte position
    let mut result = Vec::with_capacity(shard_bytes);
    for i in 0..shard_bytes {
        let (a, b, c) = (copy_0[i], copy_1[i], copy_2[i]);
        result.push(if a == b || a == c { a } else { b });
    }

    if padding_byte == 1 && !result.is_empty() {
        result.pop();
    }

    Ok(result)
}

/// Decodes and validates the output is exactly `expected_len` bytes.
/// Prevents panics from indexing decoded output before HMAC verification.
pub fn decode_exact(data: &[u8], expected_len: usize) -> Result<Vec<u8>, CryptoError> {
    let decoded = decode(data)?;
    if decoded.len() != expected_len {
        return Err(CryptoError::CryptoOperation(
            "File is corrupted (invalid field length after decoding)".to_string(),
        ));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn encode_decode_odd_length_data() {
        let original = [10, 20, 30, 40, 50];

        let encoded = encode(&original);
        // Odd length (5) gets padded to 6, so encoded = 3 + 6*3 = 21
        assert_eq!(encoded.len(), encoded_size(original.len()));
        assert_eq!(encoded[0], 1); // padding bytes should be 1
        assert_eq!(encoded[1], 1);
        assert_eq!(encoded[2], 1);

        let decoded = decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn encode_decode_single_byte() {
        let original = [42u8];
        let encoded = encode(&original);
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

        // Corrupt bytes in the first copy (indices 3..35)
        encoded[3] = 0xFF;
        encoded[12] = 0xFF;
        encoded[22] = 0xFF;
        encoded[32] = 0xFF;

        // Other two copies should outvote the corrupted one
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

        // Corrupt bytes in the second copy (indices 35..67)
        encoded[35] = 0xFF;
        encoded[42] = 0xFF;
        encoded[52] = 0xFF;

        // First + third copies should outvote the corrupted second
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
        // After removing the 3 padding bytes, remaining length must be divisible by 3
        let result = decode(&[0, 0, 0, 1, 2, 3, 4]);
        assert!(result.is_err());
    }

    #[test]
    fn encoded_size_calculation() {
        // Even: 32 -> 3 + 32*3 = 99
        assert_eq!(encoded_size(32), 99);
        // Odd: 5 -> padded to 6 -> 3 + 6*3 = 21
        assert_eq!(encoded_size(5), 21);
        // Even: 24 -> 3 + 24*3 = 75
        assert_eq!(encoded_size(24), 75);
        // Odd: 19 -> padded to 20 -> 3 + 20*3 = 63
        assert_eq!(encoded_size(19), 63);
    }

    #[test]
    fn decode_exact_wrong_length_returns_error() {
        let original = [1u8; 32];
        let mut encoded = encode(&original);
        // Corrupt 2 of 3 padding bytes to make majority vote pick 1,
        // causing decode to pop a byte and return 31 instead of 32
        encoded[0] = 1;
        encoded[1] = 1;
        let result = decode_exact(&encoded, 32);
        assert!(result.is_err());
    }

    #[test]
    fn reconstruct_with_corrupted_padding_byte() {
        let original = [10, 20, 30, 40, 50]; // odd-length, padding byte = 1
        let mut encoded = encode(&original);
        assert_eq!(encoded[0], 1);

        // Corrupt one of the 3 padding bytes — majority vote recovers
        encoded[0] = 0;
        let decoded = decode_exact(&encoded, original.len()).unwrap();
        assert_eq!(decoded, original.to_vec());
    }

    #[test]
    fn decode_exact_correct_length() {
        let original = [1u8; 32];
        let encoded = encode(&original);
        let decoded = decode_exact(&encoded, 32).unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded, original.to_vec());
    }
}
