//! Padding and size calculation utilities with sharing integration
//! Location: src/crypto/utils/padding.rs

use crate::error::{CryptoError, CryptoResult};
use super::random_bytes;
use std::convert::TryInto;
use rand::Rng;

pub(crate) const ALIGNMENT: usize = 16;
const LENGTH_SIZE: usize = 8; // Using u64 for length prefix

/// Calculates the required padded size for input while handling large messages
#[inline]
pub fn calculate_padded_size(input_size: usize) -> usize {
    // Add 8 bytes for length prefix (u64)
    ((input_size + LENGTH_SIZE + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT
}

/// Adds padding to input data with 64-bit length prefix
pub fn pad_data(data: &[u8]) -> CryptoResult<Vec<u8>> {
    if data.len() > u64::MAX as usize {
        return Err(CryptoError::InvalidInput("Input too large".into()));
    }

    let padded_size = calculate_padded_size(data.len());
    let mut padded = Vec::with_capacity(padded_size);

    // Add length prefix as u64 (little endian)
    let len_bytes = (data.len() as u64).to_le_bytes();
    padded.extend_from_slice(&len_bytes);

    // Add original data
    padded.extend_from_slice(data);

    // Add random padding
    padded.resize(padded_size, 0);
    let padding_start = data.len() + LENGTH_SIZE;
    let mut rng = rand::thread_rng();
    for i in padding_start..padded_size {
        padded[i] = rng.gen();
    }

    Ok(padded)
}

/// Removes padding and validates length prefix
pub fn unpad_data(padded: &[u8]) -> CryptoResult<Vec<u8>> {
    if padded.len() < LENGTH_SIZE {
        return Err(CryptoError::InvalidInput("Invalid padded data length".into()));
    }

    // Read length prefix as u64 (little endian)
    let len_bytes: [u8; 8] = padded[..LENGTH_SIZE].try_into().map_err(|_| {
        CryptoError::InvalidInput("Failed to read length prefix".into())
    })?;

    let original_len = u64::from_le_bytes(len_bytes) as usize;
    if original_len + LENGTH_SIZE > padded.len() {
        return Err(CryptoError::InvalidInput("Invalid length prefix".into()));
    }

    Ok(padded[LENGTH_SIZE..LENGTH_SIZE + original_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_large_data_padding() -> CryptoResult<()> {
        let sizes = [100_000, 500_000, 1_000_000];

        for size in sizes {
            let original = vec![0u8; size];
            let padded = pad_data(&original)?;

            // Verify alignment
            assert_eq!(padded.len() % ALIGNMENT, 0);

            // Verify data recovery
            let unpadded = unpad_data(&padded)?;
            assert_eq!(unpadded.len(), original.len(), "Size mismatch for {}", size);
            assert_eq!(unpadded, original, "Data mismatch for {}", size);
        }

        Ok(())
    }

    #[test]
    fn test_medical_image_size() -> CryptoResult<()> {
        let image_size = 2048 * 2048 * 2; // 8MB image
        let data = vec![0u8; image_size];
        let padded = pad_data(&data)?;
        assert_eq!(padded.len() % ALIGNMENT, 0);
        let unpadded = unpad_data(&padded)?;
        assert_eq!(unpadded.len(), image_size);
        assert_eq!(unpadded, data);
        Ok(())
    }

    #[test]
    fn test_padding_alignment() {
        for size in (1..100).chain(1000..1100) {
            let padded_size = calculate_padded_size(size);
            assert_eq!(padded_size % ALIGNMENT, 0, "Size {} not aligned", size);
            assert!(padded_size >= size + LENGTH_SIZE, "Size {} too small", size);
        }
    }

    #[test]
    fn test_empty_input() -> CryptoResult<()> {
        let padded = pad_data(&[])?;
        assert_eq!(padded.len(), ALIGNMENT);

        let unpadded = unpad_data(&padded)?;
        assert!(unpadded.is_empty());
        Ok(())
    }
}