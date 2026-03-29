use reed_solomon_simd::ReedSolomonEncoder;

use crate::CryptoError;

/// Calculates the size of encoded data for a given original data size.
/// The encoded format is: [padding_byte, original_shard, recovery_shard_0, recovery_shard_1]
/// where each shard must be even-length.
pub fn rs_encoded_size(original_size: usize) -> usize {
    let padded_size = if original_size % 2 != 0 {
        original_size + 1
    } else {
        original_size
    };

    1 + (padded_size * 3)
}

/// Encodes data using Reed-Solomon erasure coding for error correction.
pub fn rs_encode(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // reed-solomon-simd requires even-length shards
    let mut data_vec = data.to_vec();
    let padding_byte = if data.len() % 2 != 0 {
        data_vec.push(0);
        1u8
    } else {
        0u8
    };

    let shard_bytes = data_vec.len();

    // Create encoder with 1 original shard and 2 recovery shards
    let mut encoder = ReedSolomonEncoder::new(1, 2, shard_bytes)?;

    // Add the original shard
    encoder.add_original_shard(&data_vec)?;

    // Encode to get recovery shards
    let result = encoder.encode()?;

    // Build output: [padding_byte, original_shard, recovery_shard_0, recovery_shard_1]
    let mut output = vec![padding_byte];
    output.extend_from_slice(&data_vec);

    // Get recovery shards - these are Option<&[u8]>, so we need to unwrap
    let recovery_0 = result
        .recovery(0)
        .ok_or_else(|| CryptoError::Message("Missing recovery shard 0".to_string()))?;
    let recovery_1 = result
        .recovery(1)
        .ok_or_else(|| CryptoError::Message("Missing recovery shard 1".to_string()))?;

    output.extend_from_slice(recovery_0);
    output.extend_from_slice(recovery_1);

    Ok(output)
}

/// Decodes data using Reed-Solomon erasure coding for error correction.
pub fn rs_decode(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::Message("Empty data for decoding".to_string()));
    }

    let padding_byte = data[0];
    let remaining = &data[1..];

    if remaining.len() % 3 != 0 {
        return Err(CryptoError::Message(
            "Incorrect encoded bytes length".to_string(),
        ));
    }

    let shard_bytes = remaining.len() / 3;
    let original = &remaining[0..shard_bytes];
    let recovery_0 = &remaining[shard_bytes..2 * shard_bytes];
    let recovery_1 = &remaining[2 * shard_bytes..3 * shard_bytes];

    // Majority vote across 3 shards per byte position
    let mut result = Vec::with_capacity(shard_bytes);
    for i in 0..shard_bytes {
        let (a, b, c) = (original[i], recovery_0[i], recovery_1[i]);
        result.push(if a == b || a == c { a } else { b });
    }

    if padding_byte == 1 && !result.is_empty() {
        result.pop();
    }

    Ok(result)
}

/// Decodes and validates the output is exactly `expected_len` bytes.
/// Prevents panics from indexing rs_decode output before HMAC verification.
pub fn rs_decode_exact(data: &[u8], expected_len: usize) -> Result<Vec<u8>, CryptoError> {
    let decoded = rs_decode(data)?;
    if decoded.len() != expected_len {
        return Err(CryptoError::EncryptionDecryptionError(
            "File is corrupted (invalid field length after Reed-Solomon decoding)".to_string(),
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

        let encoded = rs_encode(&original).unwrap();
        assert_eq!(encoded.len(), rs_encoded_size(original.len()));

        let decoded = rs_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn encode_decode_odd_length_data() {
        let original = [10, 20, 30, 40, 50];

        let encoded = rs_encode(&original).unwrap();
        // Odd length (5) gets padded to 6, so encoded = 1 + 6*3 = 19
        assert_eq!(encoded.len(), rs_encoded_size(original.len()));
        assert_eq!(encoded[0], 1); // padding byte should be 1

        let decoded = rs_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn encode_decode_single_byte() {
        let original = [42u8];
        let encoded = rs_encode(&original).unwrap();
        let decoded = rs_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn encode_decode_two_bytes() {
        let original = [0xFF, 0x00];
        let encoded = rs_encode(&original).unwrap();
        let decoded = rs_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn reconstruct_with_corrupted_original_shard() {
        let original: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            0, 1, 2,
        ];

        let mut encoded = rs_encode(&original).unwrap();

        // Corrupt bytes in the original shard (indices 1..33)
        encoded[1] = 0xFF;
        encoded[10] = 0xFF;
        encoded[20] = 0xFF;
        encoded[30] = 0xFF;

        // Recovery shards should outvote the corrupted original
        let decoded = rs_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn reconstruct_with_corrupted_recovery_shard() {
        let original: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            0, 1, 2,
        ];

        let mut encoded = rs_encode(&original).unwrap();

        // Corrupt bytes in the first recovery shard (indices 33..65)
        encoded[33] = 0xFF;
        encoded[40] = 0xFF;
        encoded[50] = 0xFF;

        // Original + second recovery should outvote the corrupted first recovery
        let decoded = rs_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn decode_empty_data_returns_error() {
        let result = rs_decode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_invalid_length_returns_error() {
        // After removing the padding byte, remaining length must be divisible by 3
        let result = rs_decode(&[0, 1, 2, 3, 4]);
        assert!(result.is_err());
    }

    #[test]
    fn encoded_size_calculation() {
        // Even: 32 -> 1 + 32*3 = 97
        assert_eq!(rs_encoded_size(32), 97);
        // Odd: 5 -> padded to 6 -> 1 + 6*3 = 19
        assert_eq!(rs_encoded_size(5), 19);
        // Even: 24 -> 1 + 24*3 = 73
        assert_eq!(rs_encoded_size(24), 73);
        // Odd: 19 -> padded to 20 -> 1 + 20*3 = 61
        assert_eq!(rs_encoded_size(19), 61);
    }

    #[test]
    fn decode_exact_wrong_length_returns_error() {
        let original = [1u8; 32];
        let mut encoded = rs_encode(&original).unwrap();
        // Corrupt the padding byte to make rs_decode return 31 instead of 32
        encoded[0] = 1;
        let result = rs_decode_exact(&encoded, 32);
        assert!(result.is_err());
    }

    #[test]
    fn decode_exact_correct_length() {
        let original = [1u8; 32];
        let encoded = rs_encode(&original).unwrap();
        let decoded = rs_decode_exact(&encoded, 32).unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded, original.to_vec());
    }
}
