//! Error types for the McAfee cryptographic library
//! Location: src/error.rs

use thiserror::Error;
use std::time::Duration;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Timing violation: expected {expected:?}, got {actual:?}")]
    TimingViolation {
        expected: Duration,
        actual: Duration,
    },

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Operation timeout after {0:?}")]
    Timeout(Duration),
}

pub type CryptoResult<T> = Result<T, CryptoError>;