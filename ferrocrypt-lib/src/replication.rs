use crate::CryptoError;

/// Calculates the size of triple-replicated data for a given original data size.
/// The encoded format is: [padding_byte, copy_0, copy_1, copy_2]
/// where each copy is even-length (zero-padded if input is odd-length).
pub fn rep_encoded_size(original_size: usize) -> usize {
    let padded_size = if original_size % 2 != 0 {
        original_size + 1
    } else {
        original_size
    };

    1 + (padded_size * 3)
}

/// Encodes data using triple replication for error correction.
/// Wire format: [padding_byte, copy_0, copy_1, copy_2]
pub fn rep_encode(data: &[u8]) -> Vec<u8> {
    let mut padded = data.to_vec();
    let padding_byte = if data.len() % 2 != 0 {
        padded.push(0);
        1u8
    } else {
        0u8
    };

    let mut output = Vec::with_capacity(1 + padded.len() * 3);
    output.push(padding_byte);
    output.extend_from_slice(&padded);
    output.extend_from_slice(&padded);
    output.extend_from_slice(&padded);
    output
}

/// Decodes triple-replicated data using majority vote per byte position.
/// Corrects any single-copy corruption at each byte.
pub fn rep_decode(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::InvalidInput(
            "Empty data for decoding".to_string(),
        ));
    }

    let padding_byte = data[0];
    let remaining = &data[1..];

    if remaining.len() % 3 != 0 {
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
pub fn rep_decode_exact(data: &[u8], expected_len: usize) -> Result<Vec<u8>, CryptoError> {
    let decoded = rep_decode(data)?;
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

        let encoded = rep_encode(&original);
        assert_eq!(encoded.len(), rep_encoded_size(original.len()));

        let decoded = rep_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn encode_decode_odd_length_data() {
        let original = [10, 20, 30, 40, 50];

        let encoded = rep_encode(&original);
        // Odd length (5) gets padded to 6, so encoded = 1 + 6*3 = 19
        assert_eq!(encoded.len(), rep_encoded_size(original.len()));
        assert_eq!(encoded[0], 1); // padding byte should be 1

        let decoded = rep_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn encode_decode_single_byte() {
        let original = [42u8];
        let encoded = rep_encode(&original);
        let decoded = rep_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn encode_decode_two_bytes() {
        let original = [0xFF, 0x00];
        let encoded = rep_encode(&original);
        let decoded = rep_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn reconstruct_with_corrupted_first_copy() {
        let original: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            0, 1, 2,
        ];

        let mut encoded = rep_encode(&original);

        // Corrupt bytes in the first copy (indices 1..33)
        encoded[1] = 0xFF;
        encoded[10] = 0xFF;
        encoded[20] = 0xFF;
        encoded[30] = 0xFF;

        // Other two copies should outvote the corrupted one
        let decoded = rep_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn reconstruct_with_corrupted_second_copy() {
        let original: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            0, 1, 2,
        ];

        let mut encoded = rep_encode(&original);

        // Corrupt bytes in the second copy (indices 33..65)
        encoded[33] = 0xFF;
        encoded[40] = 0xFF;
        encoded[50] = 0xFF;

        // First + third copies should outvote the corrupted second
        let decoded = rep_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn decode_empty_data_returns_error() {
        let result = rep_decode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_invalid_length_returns_error() {
        // After removing the padding byte, remaining length must be divisible by 3
        let result = rep_decode(&[0, 1, 2, 3, 4]);
        assert!(result.is_err());
    }

    #[test]
    fn encoded_size_calculation() {
        // Even: 32 -> 1 + 32*3 = 97
        assert_eq!(rep_encoded_size(32), 97);
        // Odd: 5 -> padded to 6 -> 1 + 6*3 = 19
        assert_eq!(rep_encoded_size(5), 19);
        // Even: 24 -> 1 + 24*3 = 73
        assert_eq!(rep_encoded_size(24), 73);
        // Odd: 19 -> padded to 20 -> 1 + 20*3 = 61
        assert_eq!(rep_encoded_size(19), 61);
    }

    #[test]
    fn decode_exact_wrong_length_returns_error() {
        let original = [1u8; 32];
        let mut encoded = rep_encode(&original);
        // Corrupt the padding byte to make rep_decode return 31 instead of 32
        encoded[0] = 1;
        let result = rep_decode_exact(&encoded, 32);
        assert!(result.is_err());
    }

    #[test]
    fn decode_exact_correct_length() {
        let original = [1u8; 32];
        let encoded = rep_encode(&original);
        let decoded = rep_decode_exact(&encoded, 32).unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded, original.to_vec());
    }
}
