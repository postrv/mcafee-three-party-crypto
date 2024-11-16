# John McAfee Inspired Three-Party Cryptographic System

## Overview

This project implements a fascinating cryptographic concept proposed by the legendary cybersecurity pioneer John McAfee shortly before his untimely passing. The system combines temporal verification (VDF - Verifiable Delay Functions) with a novel three-party XOR-based secret sharing scheme to create a secure and verifiable data protection system.

## The Problem It Solves

Modern AI training, particularly in medical imaging, faces a critical challenge: how to securely share sensitive training data whilst maintaining temporal control over access. Traditional encryption methods offer binary access control - data is either accessible or it isn't. Our implementation offers a more nuanced approach, allowing:

1. Temporal access control (data becomes available only after a specific computational delay)
2. Three-party security (no single party can reconstruct the data)
3. Verifiable reconstruction (tamper-evident shares)

## How It Works

The system employs three core mechanisms:

### 1. Three-Party Secret Sharing
- Input data is split into three shares using XOR operations
- Each share appears completely random in isolation
- All three shares are required for reconstruction
- Mathematical property: `Data = Share_A ⊕ Share_B ⊕ Share_C`

### 2. Temporal Protection
The system applies a Verifiable Delay Function (VDF) that:
- Requires a specific number of sequential computations
- Cannot be parallelised (ensuring actual time delay)
- Provides cryptographic proof of computation
- Implements McAfee's observation about XOR properties over multiple iterations

### 3. Secure Reconstruction
- Requires all three shares
- Verifies integrity via cryptographic hashes
- Ensures proper temporal delay has been observed
- Provides tamper-evident reconstruction

## Real-World Application: Medical Image Training

This implementation specifically addresses the challenge of sharing medical imaging data for AI training:

1. Hospitals can share training data with researchers
2. Temporal delays ensure proper data handling protocols
3. Three-party sharing prevents unauthorised access
4. Verifiable reconstruction ensures data integrity

## Technical Implementation

The system is implemented in Rust, featuring:

- Zero-copy optimised data handling
- Parallel processing for large datasets
- Cryptographic verification at each step
- Comprehensive error handling and validation
- SIMD-optimised XOR operations where available

## Performance Characteristics

- Scales linearly with data size
- Parallel processing for large files (>64KB)
- Configurable temporal delay
- Memory-efficient share handling

## Security Properties

- Information-theoretic security for shares
- Cryptographic verification of reconstruction
- Temporal security through VDF
- Tamper-evident share validation

## Usage Example

```rust
let mut protector = ProtectedImage::new(
    &image_data,
    (2048, 2048),
    16,  // 16-bit depth
    ImageModality::XRay
)?;

// Protect the image (splits and applies VDF)
protector.advance_temporal_state()?;

// After sufficient time...
let original = protector.reconstruct()?;
```

## Mathematical Foundation

McAfee's observation about XOR properties forms the basis of the temporal protection:

1. Initial state: Three random shares A, B, C where A ⊕ B ⊕ C = Data
2. Four iterations of:
    - A' = B ⊕ C
    - B' = C ⊕ A
    - C' = A ⊕ B
3. Final steps:
    - A' = B ⊕ C
    - B' = C ⊕ A

This creates a verifiable temporal requirement whilst maintaining the core XOR relationship.

## Visualisation

An interactive visualisation of the system is available in the web interface, demonstrating:
- Share generation
- Temporal protection process
- Secure reconstruction
- Verification steps

[Visualization coming soon]

## Contributing

Contributions are welcome! Please see our contributing guidelines for details.

## Licence

MIT

## Acknowledgements

- John McAfee for the original cryptographic insight
- The Rust Cryptography Working Group for their excellent libraries
- The medical imaging community for their input on practical requirements