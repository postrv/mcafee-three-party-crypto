//! Example: Medical Image Protection System with proper iteration management
//! Location: examples/medical_image.rs

use mcafee::{
    crypto::{
        vdf::temporal::TemporalVDF,
        sharing::ThreePartySecretSharing,
        utils::padding,
    },
    error::CryptoResult,
};
use std::time::{Duration, Instant};
use rand::Rng;
use tracing::{debug, info};

/// Represents a protected medical image
#[derive(Debug)]
struct ProtectedImage {
    dimensions: (usize, usize),
    bits_per_pixel: usize,
    modality: ImageModality,
    shares: Vec<Vec<u8>>,
    vdf_states: Vec<TemporalVDF>,
    processed_shares: Vec<bool>,
    share_padded: bool,
}

#[derive(Debug, Clone, Copy)]
enum ImageModality {
    XRay,
    MRI,
    CT,
    Ultrasound,
}

impl ProtectedImage {
    fn new(data: &[u8], dimensions: (usize, usize),
           bits_per_pixel: usize, modality: ImageModality) -> CryptoResult<Self> {
        debug!("Creating new protected image");
        let expected_size = dimensions.0 * dimensions.1 * (bits_per_pixel / 8);
        if data.len() != expected_size {
            return Err(mcafee::error::CryptoError::InvalidInput(
                format!("Data size {} doesn't match dimensions", data.len())
            ));
        }

        // Pad the input data first
        let padded_data = padding::pad_data(data)?;
        debug!("Padded data size: {}", padded_data.len());

        let sharing_config = mcafee::crypto::sharing::SharingConfig {
            parallel: true,
            parallel_threshold: 1024 * 64,
            block_size: 1024 * 16,
        };

        let mut sharing = ThreePartySecretSharing::new(sharing_config);
        let shares = sharing.split(&padded_data)?;
        let shares_data = shares.iter().map(|s| s.data().to_vec()).collect();

        // Initialize VDF configs for each share
        let vdf_config = mcafee::crypto::vdf::temporal::TemporalConfig {
            min_iteration_time: Duration::from_millis(50),
            enforce_timing: true,
            memory_size: padded_data.len(),
            verification_steps: 4,
        };

        let vdf_states: Vec<_> = (0..3).map(|_| TemporalVDF::new(vdf_config.clone())).collect();
        let processed_shares = vec![false; 3];

        Ok(Self {
            dimensions,
            bits_per_pixel,
            modality,
            shares: shares_data,
            vdf_states,
            processed_shares,
            share_padded: true,
        })
    }

    fn advance_temporal_state(&mut self) -> CryptoResult<()> {
        debug!("Starting temporal state advancement");

        // Find the next unprocessed share
        if let Some(share_idx) = self.processed_shares.iter().position(|&x| !x) {
            let vdf = &mut self.vdf_states[share_idx];

            // Initialize VDF if needed
            if !vdf.is_initialized() {
                debug!("Initializing VDF with share {}", share_idx);
                vdf.initialize(&self.shares[share_idx])?;
            }

            // Perform iteration
            debug!("Performing VDF iteration for share {}", share_idx);
            vdf.iterate()?;

            // Check if share processing is complete
            if vdf.is_complete() {
                let processed_share = vdf.get_output()?;
                self.shares[share_idx] = processed_share;
                self.processed_shares[share_idx] = true;
            }
        }

        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.processed_shares.iter().all(|&x| x)
    }

    fn reconstruct(&self) -> CryptoResult<Vec<u8>> {
        if !self.is_complete() {
            return Err(mcafee::error::CryptoError::InvalidState(
                "Image not ready for reconstruction".into()
            ));
        }

        let sharing_config = mcafee::crypto::sharing::SharingConfig::default();
        let sharing = ThreePartySecretSharing::new(sharing_config);

        // Convert shares back to Share objects
        let shares: Vec<_> = self.shares.iter()
            .enumerate()
            .map(|(i, data)| {
                debug!(share_id = i, share_size = data.len(), "Creating share for reconstruction");
                mcafee::crypto::sharing::Share::new(data.clone(), i as u8)
            })
            .collect();

        // First reconstruct the padded data
        let padded = sharing.reconstruct(&shares)?;

        // Then unpad to get original data
        padding::unpad_data(&padded)
    }
}

fn main() -> CryptoResult<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Simulate a medical image (e.g., chest X-ray)
    let width = 2048;
    let height = 2048;
    let bits_per_pixel = 16;
    let image_size = width * height * (bits_per_pixel / 8);

    info!("Creating simulated X-ray image ({} x {}, {} bits)",
         width, height, bits_per_pixel);

    // Create realistic-looking image data
    let mut image_data = Vec::with_capacity(image_size);
    let mut rng = rand::thread_rng();

    for y in 0..height {
        for x in 0..width {
            let value = if (x as f32 - width as f32/2.0).hypot(y as f32 - height as f32/2.0) < 500.0 {
                rng.gen_range(3000..4000) as u16
            } else {
                rng.gen_range(1000..2000) as u16
            };
            image_data.extend_from_slice(&value.to_le_bytes());
        }
    }

    // Protect the image
    let start = Instant::now();
    let mut protected = ProtectedImage::new(
        &image_data,
        (width, height),
        bits_per_pixel,
        ImageModality::XRay
    )?;

    info!("Image protected in {:?}", start.elapsed());

    // Complete all iterations for all shares
    let total_iterations = 12; // 4 iterations for each of 3 shares
    for i in 1..=total_iterations {
        let start = Instant::now();
        info!("Advancing temporal state {} of {}", i, total_iterations);
        protected.advance_temporal_state()?;
        info!("Advanced in {:?}", start.elapsed());
    }

    // Reconstruct
    let start = Instant::now();
    info!("Reconstructing image...");
    let reconstructed = protected.reconstruct()?;
    info!("Reconstructed in {:?}", start.elapsed());

    // Verify reconstruction
    assert_eq!(reconstructed.len(), image_data.len(),
               "Reconstructed size mismatch");
    assert_eq!(&reconstructed[..], &image_data[..],
               "Image data mismatch");
    info!("Image successfully protected and reconstructed!");

    Ok(())
}