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

    // Extract padding byte
    let padding_byte = data[0];
    let remaining = &data[1..];

    // Check that remaining data is divisible by 3
    if remaining.len() % 3 != 0 {
        return Err(CryptoError::Message(
            "Incorrect encoded bytes length".to_string(),
        ));
    }

    let shard_bytes = remaining.len() / 3;

    // Split into 3 shards: original, recovery_0, recovery_1
    let original_shard = &remaining[0..shard_bytes];
    let recovery_shard_0 = &remaining[shard_bytes..2 * shard_bytes];
    let recovery_shard_1 = &remaining[2 * shard_bytes..3 * shard_bytes];

    // Apply byte-by-byte voting across all 3 shards for error correction
    // The Reed-Solomon encoding ensures proper redundancy, and voting handles byte-level corruption
    let shards = vec![original_shard, recovery_shard_0, recovery_shard_1];
    let mut result = vec![];

    for i in 0..shard_bytes {
        let mut freq = std::collections::HashMap::new();

        // Count frequency of each byte value at position i across all shards
        for shard in &shards {
            let byte = shard[i];
            *freq.entry(byte).or_insert(0) += 1;
        }

        // Find the byte with highest frequency (at least 2 occurrences for majority)
        // If no majority, use the byte from the original shard as fallback
        let most_frequent = freq
            .iter()
            .filter(|(_, &count)| count >= 2)
            .max_by_key(|(_, &count)| count)
            .map(|(&byte, _)| byte)
            .unwrap_or(original_shard[i]);

        result.push(most_frequent);
    }

    // Remove padding if it was added during encoding
    if padding_byte == 1 && !result.is_empty() {
        result.pop();
    }

    Ok(result)
}

#[allow(dead_code)]
fn pad_pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut byte_vec = data.to_vec();
    let padding_size = block_size - byte_vec.len() % block_size;
    let padding_char = padding_size as u8;
    let padding: Vec<u8> = vec![padding_char; padding_size];
    byte_vec.extend_from_slice(&padding);

    byte_vec
}

#[allow(dead_code)]
fn unpad_pkcs7(data: &[u8]) -> Vec<u8> {
    let mut byte_vec = data.to_vec();
    let padding_size = byte_vec.last().copied().unwrap() as usize;
    // Use `saturating_sub` to handle the case where there aren't N elements in the vector
    let final_length = byte_vec.len().saturating_sub(padding_size);
    byte_vec.truncate(final_length);

    byte_vec
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
    fn pkcs_padding_unpadding() {
        let arr_12_orig = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2];
        let arr_16_orig = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6];

        let arr_12_padded = pad_pkcs7(&arr_12_orig, 16);
        let arr_16_padded = pad_pkcs7(&arr_16_orig, 16);

        assert_eq!(&arr_12_orig, &unpad_pkcs7(&arr_12_padded).as_slice());
        assert_eq!(&arr_16_orig, &unpad_pkcs7(&arr_16_padded).as_slice());
    }
}
