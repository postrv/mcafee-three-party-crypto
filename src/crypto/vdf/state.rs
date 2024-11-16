//! Temporal VDF state management
//! Location: src/crypto/vdf/state.rs

use crate::error::{CryptoError, CryptoResult};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Maximum number of iterations for temporal VDF
pub const MAX_ITERATIONS: usize = 4;

/// Represents the state of a VDF computation
#[derive(Debug, Clone)]
pub struct VDFState {
    /// Current iteration number
    iteration: usize,
    /// Start time of computation
    start_time: Instant,
    /// Minimum time per iteration
    min_iteration_time: Duration,
    /// Whether timing requirements are enforced
    enforce_timing: bool,
    /// Last iteration completion time
    last_iteration: Option<Instant>,
}

impl VDFState {
    /// Creates a new VDF state tracker
    pub fn new(min_iteration_time: Duration, enforce_timing: bool) -> Self {
        Self {
            iteration: 0,
            start_time: Instant::now(),
            min_iteration_time,
            enforce_timing,
            last_iteration: None,
        }
    }

    /// Advances the state by one iteration
    pub fn advance(&mut self) -> CryptoResult<()> {
        if self.iteration >= MAX_ITERATIONS {
            return Err(CryptoError::InvalidState("Maximum iterations reached".into()));
        }

        // Check timing requirements
        if let Some(last) = self.last_iteration {
            let elapsed = last.elapsed();
            if self.enforce_timing && elapsed < self.min_iteration_time {
                return Err(CryptoError::TimingViolation {
                    expected: self.min_iteration_time,
                    actual: elapsed,
                });
            }
        }

        debug!(iteration = self.iteration + 1, "Starting VDF iteration");
        self.iteration += 1;
        self.last_iteration = Some(Instant::now());

        info!(
            iteration = self.iteration,
            elapsed = ?self.start_time.elapsed(),
            "Completed VDF iteration"
        );

        Ok(())
    }

    /// Returns the current iteration number
    pub fn current_iteration(&self) -> usize {
        self.iteration
    }

    /// Returns whether computation is complete
    pub fn is_complete(&self) -> bool {
        self.iteration >= MAX_ITERATIONS
    }

    /// Returns total elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_state_progression() -> CryptoResult<()> {
        let mut state = VDFState::new(Duration::from_millis(1), false);

        for i in 1..=MAX_ITERATIONS {
            assert_eq!(state.current_iteration(), i - 1);
            assert!(!state.is_complete());
            state.advance()?;
        }

        assert!(state.is_complete());
        assert!(state.advance().is_err());

        Ok(())
    }

    #[test]
    fn test_timing_enforcement() {
        let min_time = Duration::from_millis(50);
        let mut state = VDFState::new(min_time, true);

        // First iteration should succeed
        state.advance().unwrap();

        // Immediate next iteration should fail timing check
        assert!(matches!(
            state.advance(),
            Err(CryptoError::TimingViolation { .. })
        ));

        // Wait and try again
        thread::sleep(min_time);
        assert!(state.advance().is_ok());
    }
}