//! Utility functions for cryptographic operations
//! Location: src/crypto/utils/mod.rs

pub mod padding;

use crate::error::CryptoResult;
use std::time::{Duration, Instant};

/// Performs XOR operation on two byte slices
#[inline(always)]
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect()
}

/// Creates random bytes with specified length
pub fn random_bytes(length: usize) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..length).map(|_| rng.gen::<u8>()).collect()
}

/// Enforces minimum time delay for operation
pub fn enforce_delay(start: Instant, min_delay: Duration) {
    let elapsed = start.elapsed();
    if elapsed < min_delay {
        std::thread::sleep(min_delay - elapsed);
    }
}

/// Aligns data to specified block size with random padding
pub fn pad_to_block_size(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = (block_size - (data.len() % block_size)) % block_size;
    let mut padded = Vec::with_capacity(data.len() + padding_len);
    padded.extend_from_slice(data);
    padded.extend(random_bytes(padding_len));
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_bytes() {
        let a = vec![1, 2, 3, 4];
        let b = vec![5, 6, 7, 8];
        let result = xor_bytes(&a, &b);
        assert_eq!(result, vec![4, 4, 4, 12]);

        // XOR with itself should yield zeros
        let zeros = xor_bytes(&a, &a);
        assert!(zeros.iter().all(|&x| x == 0));
    }

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(1000);
        let bytes2 = random_bytes(1000);
        assert_eq!(bytes1.len(), 1000);
        assert_eq!(bytes2.len(), 1000);
        assert_ne!(bytes1, bytes2); // Should be different (astronomically unlikely to be same)
    }

    #[test]
    fn test_enforce_delay() {
        let start = Instant::now();
        let delay = Duration::from_millis(100);
        enforce_delay(start, delay);
        assert!(start.elapsed() >= delay);
    }

    #[test]
    fn test_pad_to_block_size() {
        let data = vec![1, 2, 3];
        let block_size = 16;
        let padded = pad_to_block_size(&data, block_size);
        assert_eq!(padded.len(), 16);
        assert_eq!(&padded[..3], &[1, 2, 3]);
    }
}