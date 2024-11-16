//! Three-party secret sharing implementation based on McAfee's XOR properties
//! Location: src/crypto/sharing/mod.rs

use crate::error::{CryptoError, CryptoResult};
use crate::crypto::utils::padding;
use rand::Rng;
use sha2::{Sha256, Digest};
use std::sync::Arc;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Size of blocks for parallel processing
const BLOCK_SIZE: usize = 1024 * 64; // 64KB blocks

/// A share in the secret sharing scheme
#[derive(Debug, Clone)]
pub struct Share {
    /// The share data
    data: Vec<u8>,
    /// Share identifier (0, 1, or 2)
    id: u8,
    /// Hash of the share for verification
    hash: [u8; 32],
}

impl Share {
    /// Creates a new share with given data and ID
    pub fn new(data: Vec<u8>, id: u8) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hasher.finalize().into();

        Self { data, id, hash }
    }

    /// Verifies the integrity of the share
    pub fn verify(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&self.data);
        let computed_hash: [u8; 32] = hasher.finalize().into();
        computed_hash == self.hash
    }

    /// Gets a reference to the share data
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Configuration for the sharing scheme
#[derive(Debug, Clone)]
pub struct SharingConfig {
    /// Whether to use parallel processing for large messages
    pub parallel: bool,
    /// Minimum size for using parallel processing
    pub parallel_threshold: usize,
    /// Block size for processing
    pub block_size: usize,
}

impl Default for SharingConfig {
    fn default() -> Self {
        Self {
            parallel: cfg!(feature = "parallel"),
            parallel_threshold: BLOCK_SIZE,
            block_size: BLOCK_SIZE,
        }
    }
}

/// Implementation of three-party secret sharing
pub struct ThreePartySecretSharing {
    config: SharingConfig,
    shares: Vec<Option<Share>>,
}

impl ThreePartySecretSharing {
    /// Creates a new instance with given configuration
    pub fn new(config: SharingConfig) -> Self {
        Self {
            config,
            shares: vec![None, None, None],
        }
    }

    /// Creates a new instance with default configuration
    pub fn default() -> Self {
        Self::new(SharingConfig::default())
    }

    /// Splits a secret into three shares
    pub fn split(&mut self, secret: &[u8]) -> CryptoResult<Vec<Share>> {
        if secret.is_empty() {
            return Err(CryptoError::InvalidInput("Secret cannot be empty".into()));
        }

        // Use the new padding utility instead of internal pad_data
        let padded = padding::pad_data(secret)?;

        if self.config.parallel && padded.len() >= self.config.parallel_threshold {
            self.split_parallel(&padded)
        } else {
            self.split_sequential(&padded)
        }
    }

    /// Reconstructs the secret from shares
    pub fn reconstruct(&self, shares: &[Share]) -> CryptoResult<Vec<u8>> {
        // Validate shares
        if shares.len() != 3 {
            return Err(CryptoError::InvalidInput("Need exactly 3 shares".into()));
        }

        // Validate share lengths match
        let share_len = shares[0].data.len();
        if shares.iter().any(|s| s.data.len() != share_len) {
            return Err(CryptoError::InvalidInput("Share lengths must match".into()));
        }

        // Check alignment
        if share_len % padding::ALIGNMENT != 0 {
            return Err(CryptoError::InvalidInput(
                format!("Share length must be aligned to {} bytes", padding::ALIGNMENT)
            ));
        }

        for share in shares {
            if !share.verify() {
                return Err(CryptoError::VerificationFailed("Share verification failed".into()));
            }
        }

        // Reconstruct padded data
        let reconstructed = if self.config.parallel &&
            shares[0].data.len() >= self.config.parallel_threshold {
            self.reconstruct_parallel(shares)
        } else {
            self.reconstruct_sequential(shares)
        }?;

        // Unpad using the new padding utility
        padding::unpad_data(&reconstructed)
    }

    // Private helper methods

    fn pad_data(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut padded = Vec::with_capacity(data.len() + 32);

        // Store original length
        padded.push(data.len() as u8);
        padded.extend_from_slice(data);

        // Add random padding to block size
        let padding_len = (self.config.block_size -
            (padded.len() % self.config.block_size)) % self.config.block_size;

        let mut rng = rand::thread_rng();
        padded.extend((0..padding_len).map(|_| rng.gen::<u8>()));

        Ok(padded)
    }

    #[cfg(feature = "parallel")]
    fn split_parallel(&mut self, data: &[u8]) -> CryptoResult<Vec<Share>> {
        let block_size = self.config.block_size;
        let num_blocks = (data.len() + block_size - 1) / block_size;

        // Process blocks in parallel
        let blocks: Vec<_> = data.chunks(block_size)
            .collect();

        let share_blocks: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = blocks.par_iter()
            .map(|block| {
                let mut rng = rand::thread_rng();
                let share_a: Vec<u8> = (0..block.len()).map(|_| rng.gen()).collect();
                let share_b: Vec<u8> = (0..block.len()).map(|_| rng.gen()).collect();

                // Calculate share_c
                let mut share_c = vec![0u8; block.len()];
                for i in 0..block.len() {
                    share_c[i] = block[i] ^ share_a[i] ^ share_b[i];
                }

                (share_a, share_b, share_c)
            })
            .collect();

        // Combine blocks for each share
        let mut share_a = Vec::with_capacity(data.len());
        let mut share_b = Vec::with_capacity(data.len());
        let mut share_c = Vec::with_capacity(data.len());

        for (a, b, c) in share_blocks {
            share_a.extend(a);
            share_b.extend(b);
            share_c.extend(c);
        }

        Ok(vec![
            Share::new(share_a, 0),
            Share::new(share_b, 1),
            Share::new(share_c, 2),
        ])
    }

    #[cfg(not(feature = "parallel"))]
    fn split_parallel(&mut self, data: &[u8]) -> CryptoResult<Vec<Share>> {
        // Fallback to sequential if parallel feature is not enabled
        self.split_sequential(data)
    }

    fn split_sequential(&mut self, data: &[u8]) -> CryptoResult<Vec<Share>> {
        let mut rng = rand::thread_rng();

        // Generate random shares A and B
        let share_a: Vec<u8> = (0..data.len()).map(|_| rng.gen()).collect();
        let share_b: Vec<u8> = (0..data.len()).map(|_| rng.gen()).collect();

        // Calculate share C
        let mut share_c = vec![0u8; data.len()];
        for i in 0..data.len() {
            share_c[i] = data[i] ^ share_a[i] ^ share_b[i];
        }

        Ok(vec![
            Share::new(share_a, 0),
            Share::new(share_b, 1),
            Share::new(share_c, 2),
        ])
    }

    #[cfg(feature = "parallel")]
    fn reconstruct_parallel(&self, shares: &[Share]) -> CryptoResult<Vec<u8>> {
        let block_size = self.config.block_size;
        let blocks_a: Vec<_> = shares[0].data.chunks(block_size).collect();
        let blocks_b: Vec<_> = shares[1].data.chunks(block_size).collect();
        let blocks_c: Vec<_> = shares[2].data.chunks(block_size).collect();

        let reconstructed_blocks: Vec<Vec<u8>> = blocks_a.par_iter()
            .zip(blocks_b.par_iter())
            .zip(blocks_c.par_iter())
            .map(|((a, b), c)| {
                let mut result = vec![0u8; a.len()];
                for i in 0..a.len() {
                    result[i] = a[i] ^ b[i] ^ c[i];
                }
                result
            })
            .collect();

        let mut result = Vec::with_capacity(shares[0].data.len());
        for block in reconstructed_blocks {
            result.extend(block);
        }

        Ok(result)
    }

    #[cfg(not(feature = "parallel"))]
    fn reconstruct_parallel(&self, shares: &[Share]) -> CryptoResult<Vec<u8>> {
        // Fallback to sequential if parallel feature is not enabled
        self.reconstruct_sequential(shares)
    }

    fn reconstruct_sequential(&self, shares: &[Share]) -> CryptoResult<Vec<u8>> {
        let mut result = vec![0u8; shares[0].data.len()];

        for i in 0..shares[0].data.len() {
            result[i] = shares[0].data[i] ^ shares[1].data[i] ^ shares[2].data[i];
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_basic_sharing() -> CryptoResult<()> {
        let mut sharing = ThreePartySecretSharing::default();
        let secret = b"This is a test secret message!";

        // Split secret
        let shares = sharing.split(secret)?;
        assert_eq!(shares.len(), 3);

        // Verify shares have correct padding alignment
        for share in &shares {
            assert_eq!(share.data.len() % padding::ALIGNMENT, 0);
            assert!(share.verify());
        }

        // Reconstruct
        let reconstructed = sharing.reconstruct(&shares)?;
        assert_eq!(&reconstructed, secret);

        Ok(())
    }

    #[test]
    fn test_large_data_sharing() -> CryptoResult<()> {
        let mut sharing = ThreePartySecretSharing::default();
        let large_secret: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

        let shares = sharing.split(&large_secret)?;
        let reconstructed = sharing.reconstruct(&shares)?;

        assert_eq!(reconstructed, large_secret);
        Ok(())
    }
    #[test]
    fn test_invalid_shares() -> CryptoResult<()> {
        let mut sharing = ThreePartySecretSharing::default();
        let secret = b"Test secret";

        // Split secret
        let mut shares = sharing.split(secret)?;

        // Tamper with one share
        shares[0].data[0] ^= 1;

        // Verify should fail
        assert!(!shares[0].verify());

        // Reconstruction should fail
        assert!(sharing.reconstruct(&shares).is_err());

        Ok(())
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_parallel_large_message() -> CryptoResult<()> {
        let config = SharingConfig {
            parallel: true,
            parallel_threshold: 1024,
            block_size: 1024,
        };

        let mut sharing = ThreePartySecretSharing::new(config);
        let secret: Vec<u8> = (0..10240).map(|i| (i % 256) as u8).collect();

        let shares = sharing.split(&secret)?;
        for share in &shares {
            assert_eq!(share.data.len() % padding::ALIGNMENT, 0);
        }

        let reconstructed = sharing.reconstruct(&shares)?;
        assert_eq!(reconstructed, secret);
        Ok(())
    }
}