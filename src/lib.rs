//! McAfee Cryptographic Library
//! Location: src/lib.rs

pub mod crypto;
pub mod error;

use tracing_subscriber;

/// Initialize the library with default settings
pub fn init() {
    // Initialize logging
    tracing_subscriber::fmt::init();
}

/// Library configuration struct
#[derive(Debug, Clone)]
pub struct Config {
    /// VDF configuration
    pub vdf_config: crypto::vdf::temporal::TemporalConfig,
    /// Number of shares for secret sharing
    pub share_count: usize,
    /// Enable parallel processing for large messages
    pub enable_parallel: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vdf_config: crypto::vdf::temporal::TemporalConfig::default(),
            share_count: 3,
            enable_parallel: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.share_count, 3);
        assert!(!config.enable_parallel);
    }
}