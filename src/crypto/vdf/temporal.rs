//! Temporal XOR-based Verifiable Delay Function implementation
//! Location: src/crypto/vdf/temporal.rs

use crate::error::{CryptoError, CryptoResult};
use sha2::{Sha256, Digest};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};
use rand::Rng;

/// Number of iterations required for a complete cycle
pub const CYCLE_LENGTH: usize = 4;

/// Represents proof of temporal computation
#[derive(Debug, Clone)]
pub struct TemporalProof {
    /// Hash of initial state
    initial_state_hash: [u8; 32],
    /// Hash of final state
    final_state_hash: [u8; 32],
    /// Time taken for computation
    computation_time: Duration,
    /// Number of iterations performed
    iteration_count: usize,
}

/// Configuration for the temporal VDF
#[derive(Debug, Clone)]
pub struct TemporalConfig {
    /// Minimum time that must be spent on each iteration
    pub min_iteration_time: Duration,
    /// Whether to enforce strict timing requirements
    pub enforce_timing: bool,
    /// Size of the working memory in bytes
    pub memory_size: usize,
    /// Number of verification steps required
    pub verification_steps: usize,
}

impl Default for TemporalConfig {
    fn default() -> Self {
        Self {
            min_iteration_time: Duration::from_millis(100),
            enforce_timing: true,
            memory_size: 1024 * 1024, // 1MB
            verification_steps: 4,
        }
    }
}

/// Temporal VDF implementation using XOR operations
#[derive(Debug)]
pub struct TemporalVDF {
    pub config: TemporalConfig,
    state: Vec<Vec<u8>>,
    current_iteration: usize,
    start_time: Option<Instant>,
    initial_hash: Option<[u8; 32]>,  // Add this field
}

impl TemporalVDF {
    /// Check if the VDF has been initialized with input data
    pub fn is_initialized(&self) -> bool {
        !self.state.is_empty() && self.initial_hash.is_some() && self.start_time.is_some()
    }
}

impl TemporalVDF {
    pub fn new(config: TemporalConfig) -> Self {
        Self {
            config,
            state: Vec::new(),
            current_iteration: 0,
            start_time: None,
            initial_hash: None,
        }
    }

    pub fn initialize(&mut self, input: &[u8]) -> CryptoResult<()> {
        if input.is_empty() {
            return Err(CryptoError::InvalidInput("Input cannot be empty".into()));
        }

        debug!("Initializing VDF with input length {}", input.len());

        // Create three shares from input
        let mut rng = rand::thread_rng();
        let padded_len = ((input.len() + 15) / 16) * 16; // Align to 16 bytes

        // Generate first two shares randomly
        let share_a: Vec<u8> = (0..padded_len).map(|_| rng.gen()).collect();
        let share_b: Vec<u8> = (0..padded_len).map(|_| rng.gen()).collect();

        // Calculate third share to make XOR equal input
        let mut share_c = vec![0u8; padded_len];
        for i in 0..input.len() {
            share_c[i] = input[i] ^ share_a[i] ^ share_b[i];
        }

        // Fill remaining padding
        for i in input.len()..padded_len {
            share_c[i] = rng.gen();
        }

        self.state = vec![share_a, share_b, share_c];

        // Calculate initial state hash
        let mut hasher = Sha256::new();
        for share in &self.state {
            hasher.update(share);
        }
        self.initial_hash = Some(hasher.finalize().into());

        self.current_iteration = 0;
        self.start_time = Some(Instant::now());

        debug!("VDF initialized with {} shares of {} bytes each", 
               self.state.len(), padded_len);

        Ok(())
    }

    /// Perform one iteration of the VDF
    pub fn iterate(&mut self) -> CryptoResult<()> {
        if self.state.is_empty() {
            return Err(CryptoError::InvalidState("VDF not initialized".into()));
        }

        if self.current_iteration >= CYCLE_LENGTH {
            return Err(CryptoError::InvalidState(
                format!("Maximum iterations ({}) already reached", CYCLE_LENGTH)
            ));
        }

        let iteration_start = Instant::now();
        debug!("Starting iteration {}/{}", self.current_iteration + 1, CYCLE_LENGTH);

        // Perform XOR transformation
        let mut new_state = Vec::with_capacity(3);
        for i in 0..3 {
            let mut result = self.state[i].clone();
            for j in 0..3 {
                if i != j {
                    for (r, v) in result.iter_mut().zip(&self.state[j]) {
                        *r ^= v;
                    }
                }
            }
            new_state.push(result);
        }

        self.state = new_state;
        self.current_iteration += 1;

        // Enforce minimum time if required
        if self.config.enforce_timing {
            let elapsed = iteration_start.elapsed();
            if elapsed < self.config.min_iteration_time {
                std::thread::sleep(self.config.min_iteration_time - elapsed);
            }
        }

        info!("Completed iteration {}/{} in {:?}", 
              self.current_iteration, CYCLE_LENGTH, iteration_start.elapsed());

        Ok(())
    }

    /// Generate proof of computation
    pub fn generate_proof(&self) -> CryptoResult<TemporalProof> {
        if !self.is_complete() {
            return Err(CryptoError::InvalidState(
                format!("Cannot generate proof: {}/{} iterations complete",
                        self.current_iteration, CYCLE_LENGTH)
            ));
        }

        let initial_state_hash = self.initial_hash.ok_or_else(||
            CryptoError::InvalidState("VDF not properly initialized".into())
        )?;

        // Calculate final state hash
        let mut hasher = Sha256::new();
        for share in &self.state {
            hasher.update(share);
        }
        let final_state_hash = hasher.finalize().into();

        let computation_time = self.start_time
            .expect("start_time should be set during initialization")
            .elapsed();

        debug!(
            ?initial_state_hash,
            ?final_state_hash,
            ?computation_time,
            current_iteration = self.current_iteration,
            "Generating VDF proof"
        );

        Ok(TemporalProof {
            initial_state_hash,
            final_state_hash,
            computation_time,
            iteration_count: self.current_iteration,
        })
    }
    
    /// Verify proof of computation
    pub fn verify_proof(&self, proof: &TemporalProof) -> CryptoResult<bool> {
        // Check initialization
        let initial_hash = self.initial_hash.ok_or_else(||
            CryptoError::InvalidState("VDF not properly initialized".into())
        )?;

        debug!(
            stored_hash = ?initial_hash,
            proof_hash = ?proof.initial_state_hash,
            "Checking initial state hash"
        );

        // Verify initial state
        if initial_hash != proof.initial_state_hash {
            warn!(
                stored_hash = ?initial_hash,
                proof_hash = ?proof.initial_state_hash,
                "Initial state hash mismatch"
            );
            return Ok(false);
        }

        debug!(
            expected = CYCLE_LENGTH,
            actual = proof.iteration_count,
            "Checking iteration count"
        );

        // Verify iteration count
        if proof.iteration_count != CYCLE_LENGTH {
            warn!("Iteration count mismatch");
            return Ok(false);
        }

        // Get current final state hash
        let mut hasher = Sha256::new();
        for share in &self.state {
            hasher.update(share);
        }
        let current_hash: [u8; 32] = hasher.finalize().into();

        debug!(
            current = ?current_hash,
            proof = ?proof.final_state_hash,
            "Checking final state hash"
        );

        // Verify final state
        if current_hash != proof.final_state_hash {
            warn!(
                current = ?current_hash,
                proof = ?proof.final_state_hash,
                "Final state hash mismatch"
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Check if computation is complete
    pub fn is_complete(&self) -> bool {
        self.current_iteration == CYCLE_LENGTH
    }

    /// Get the current state if iteration is complete
    pub fn get_output(&self) -> CryptoResult<Vec<u8>> {
        if !self.is_complete() {
            return Err(CryptoError::InvalidState(
                format!("Computation not complete: {}/{} iterations",
                        self.current_iteration, CYCLE_LENGTH)
            ));
        }

        if self.state.is_empty() {
            return Err(CryptoError::InvalidState("VDF not initialized".into()));
        }

        let mut output = Vec::with_capacity(self.state[0].len());
        for i in 0..self.state[0].len() {
            output.push(self.state[0][i] ^ self.state[1][i] ^ self.state[2][i]);
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdf_cycle() -> CryptoResult<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let config = TemporalConfig {
            min_iteration_time: Duration::from_millis(1), // Fast for tests
            enforce_timing: false,
            ..Default::default()
        };

        let mut vdf = TemporalVDF::new(config);
        let input = b"Test input data";
        vdf.initialize(input)?;

        // Complete one cycle
        for i in 0..CYCLE_LENGTH {
            debug!("Running iteration {}", i + 1);
            vdf.iterate()?;
        }

        // Verify we get original input back
        let output = vdf.get_output()?;
        assert_eq!(&output[..input.len()], input);

        Ok(())
    }


    #[test]
    fn test_proof_verification() -> CryptoResult<()> {
        let _ = tracing_subscriber::fmt::try_init();

        debug!("Starting proof verification test");

        let config = TemporalConfig {
            min_iteration_time: Duration::from_millis(1),
            enforce_timing: false,
            ..Default::default()
        };

        let mut vdf = TemporalVDF::new(config);
        let input = b"Test input";

        debug!("Initializing VDF with input");
        vdf.initialize(input)?;

        let initial_hash = vdf.initial_hash.expect("Initial hash should be set");
        debug!(?initial_hash, "Initial state hash recorded");

        // Complete iteration cycle
        for i in 0..CYCLE_LENGTH {
            debug!("Starting iteration {}/{}", i + 1, CYCLE_LENGTH);
            vdf.iterate()?;
        }

        debug!("Generating proof after {} iterations", CYCLE_LENGTH);
        let proof = vdf.generate_proof()?;

        debug!(
            initial_hash = ?proof.initial_state_hash,
            final_hash = ?proof.final_state_hash,
            iterations = proof.iteration_count,
            time = ?proof.computation_time,
            "Generated proof"
        );

        debug!("Verifying proof");
        let result = vdf.verify_proof(&proof)?;
        assert!(result, "Proof verification failed");

        Ok(())
    }

    // Add a new test to verify state consistency
    #[test]
    fn test_state_consistency() -> CryptoResult<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let mut vdf = TemporalVDF::new(Default::default());
        let input = b"State consistency test";

        vdf.initialize(input)?;
        let initial_hash = vdf.initial_hash.expect("Initial hash not set");

        // Store state hashes at each iteration - now with explicit type
        let mut state_hashes: Vec<[u8; 32]> = Vec::new();
        for i in 0..CYCLE_LENGTH {
            let mut hasher = Sha256::new();
            for share in &vdf.state {
                hasher.update(share);
            }
            state_hashes.push(hasher.finalize().into());

            debug!(
                iteration = i,
                hash = ?state_hashes.last(),
                "State hash before iteration"
            );

            vdf.iterate()?;
        }

        // Generate and immediately verify proof
        let proof = vdf.generate_proof()?;
        assert_eq!(proof.initial_state_hash, initial_hash, "Initial hash mismatch");
        assert_eq!(proof.final_state_hash, state_hashes[CYCLE_LENGTH - 1],
                   "Final hash mismatch");

        Ok(())
    }
    
    #[test]
    fn test_proof_state_tracking() -> CryptoResult<()> {
        let config = TemporalConfig {
            min_iteration_time: Duration::from_millis(1),
            enforce_timing: false,
            ..Default::default()
        };

        let mut vdf = TemporalVDF::new(config);
        vdf.initialize(b"Test input")?;

        // Record initial state
        let initial_hash = vdf.initial_hash.expect("Initial hash should be set");

        // Perform 4 iterations
        for _ in 0..CYCLE_LENGTH {
            vdf.iterate()?;
        }

        let proof = vdf.generate_proof()?;
        assert_eq!(proof.initial_state_hash, initial_hash, "Initial state not preserved");
        assert_eq!(proof.iteration_count, CYCLE_LENGTH, "Wrong iteration count");

        Ok(())
    }

    #[test]
    fn test_incomplete_state() {
        let mut vdf = TemporalVDF::new(Default::default());
        vdf.initialize(b"Test input").unwrap();

        // Try to get output before completing iterations
        assert!(vdf.get_output().is_err());

        // Try to generate proof before completing
        assert!(vdf.generate_proof().is_err());
    }
}