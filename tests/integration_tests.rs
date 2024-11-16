//! Integration tests for the mcafee library
//! Location: tests/integration_tests.rs

use mcafee::{
    crypto::{
        vdf::temporal::TemporalVDF,
        sharing::ThreePartySecretSharing,
    },
    error::CryptoResult,
};
use std::time::Duration;
use rand::Rng;
use tracing::{debug, info};

#[test]
fn test_secret_sharing_with_vdf() -> CryptoResult<()> {
    // Initialize logging for debugging
    let _ = tracing_subscriber::fmt::try_init();

    // Create and configure components
    let mut sharing = ThreePartySecretSharing::default();
    let config = mcafee::crypto::vdf::temporal::TemporalConfig {
        min_iteration_time: Duration::from_millis(1), // Fast for tests
        enforce_timing: false,
        memory_size: 1024,
        verification_steps: 4,
    };
    let mut vdf = TemporalVDF::new(config);

    // Original secret
    let secret = b"This is a secret message that needs protection!";
    debug!("Original secret length: {}", secret.len());

    // First split the secret
    let shares = sharing.split(secret)?;
    debug!("Created {} shares", shares.len());

    // Apply VDF to each share
    let mut protected_shares = Vec::new();
    for share in &shares {
        vdf.initialize(share.data())?;

        // Complete all required iterations
        for _ in 0..4 {
            vdf.iterate()?;
            debug!("Completed VDF iteration");
        }

        let output = vdf.get_output()?;
        protected_shares.push(output);
        debug!("Processed share");
    }

    // Create new shares from protected data
    let protected_shares: Vec<_> = protected_shares.into_iter()
        .enumerate()
        .map(|(i, data)| mcafee::crypto::sharing::Share::new(data, i as u8))
        .collect();

    // Reconstruct and verify
    let reconstructed = sharing.reconstruct(&protected_shares)?;
    assert_eq!(&reconstructed, secret, "Reconstruction failed");

    Ok(())
}

#[test]
fn test_large_data_parallel() -> CryptoResult<()> {
    let _ = tracing_subscriber::fmt::try_init();

    // Create sharing configuration with parallel processing enabled
    let sharing_config = mcafee::crypto::sharing::SharingConfig {
        parallel: true,
        parallel_threshold: 1024,  // Use parallel for data > 1KB
        block_size: 1024,
    };

    let mut sharing = ThreePartySecretSharing::new(sharing_config);

    // Create test data with known pattern
    let data_size = 100_000;
    let mut secret = Vec::with_capacity(data_size);
    for i in 0..data_size {
        secret.push((i % 251) as u8);  // Use prime to avoid patterns
    }

    // Calculate padded size using our padding utility
    let padded_size = mcafee::crypto::utils::padding::calculate_padded_size(secret.len());
    info!("Original size: {}, Padded size: {}", secret.len(), padded_size);

    // Split into shares
    info!("Splitting data into shares...");
    let shares = sharing.split(&secret)?;

    // Verify share properties
    assert_eq!(shares.len(), 3, "Should have exactly 3 shares");
    for (i, share) in shares.iter().enumerate() {
        let share_len = share.data().len();
        assert_eq!(share_len, padded_size,
                   "Share {} length: got {}, expected {}",
                   i, share_len, padded_size);
        assert!(share.verify(), "Share {} failed verification", i);
    }

    // Reconstruct and verify
    info!("Reconstructing from shares...");
    let reconstructed = sharing.reconstruct(&shares)?;

    // Compare original data (trim padding)
    assert_eq!(&reconstructed[..secret.len()], &secret[..],
               "Reconstructed data doesn't match original");

    Ok(())
}

#[test]
fn test_realistic_medical_image() -> CryptoResult<()> {
    let _ = tracing_subscriber::fmt::try_init();

    // Simulate a real medical image (e.g., DICOM format)
    let image_size = 512 * 512 * 2;  // 512x512 16-bit pixels
    let mut image_data = Vec::with_capacity(image_size);

    // Create realistic-looking image data
    let mut rng = rand::thread_rng();
    for i in 0..image_size {
        // Simulate typical medical image histogram
        let value = if i % 512 < 100 {
            // Background (mostly dark)
            rng.gen_range(0..1000) as u8
        } else if i % 512 > 400 {
            // Bright features
            rng.gen_range(200..255) as u8
        } else {
            // Mid-range tissue values
            rng.gen_range(100..200) as u8
        };
        image_data.push(value);
    }

    // Configure VDF for testing (faster iterations)
    let vdf_config = mcafee::crypto::vdf::temporal::TemporalConfig {
        min_iteration_time: Duration::from_millis(1),
        enforce_timing: false,
        memory_size: image_size,
        verification_steps: 4,
    };

    let sharing_config = mcafee::crypto::sharing::SharingConfig {
        parallel: true,
        parallel_threshold: 1024 * 64,  // 64KB for parallel processing
        block_size: 1024 * 16,  // 16KB blocks
    };

    // Create protection system
    let mut vdf = TemporalVDF::new(vdf_config);
    let mut sharing = ThreePartySecretSharing::new(sharing_config);

    // Phase 1: Split into shares
    info!("Splitting medical image...");
    let mut shares = sharing.split(&image_data)?;
    let padded_size = shares[0].data().len();

    // Phase 2: Apply temporal protection
    info!("Applying temporal protection...");
    let mut protected_shares = Vec::new();
    for share in &shares {
        vdf.initialize(share.data())?;

        // Complete full VDF cycle
        for i in 0..4 {
            debug!("VDF iteration {} for share", i + 1);
            vdf.iterate()?;
        }

        protected_shares.push(vdf.get_output()?);
    }

    // Convert back to Share objects
    shares = protected_shares.into_iter()
        .enumerate()
        .map(|(i, data)| mcafee::crypto::sharing::Share::new(data, i as u8))
        .collect();

    // Phase 3: Verify reconstruction
    info!("Verifying reconstruction...");
    let reconstructed = sharing.reconstruct(&shares)?;
    assert_eq!(reconstructed.len(), image_data.len(),
               "Reconstructed size {} != Original size {}",
               reconstructed.len(), image_data.len());
    assert_eq!(reconstructed, image_data, "Data mismatch after reconstruction");

    Ok(())
}