use rand::Rng;
use sha2::{Sha256, Digest};
use chrono::prelude::*;

// Helper function to XOR two byte slices
fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect()
}

struct ThreePartySecretSharing {
    party_a: Option<Vec<u8>>,
    party_b: Option<Vec<u8>>,
    party_c: Option<Vec<u8>>,
}

impl ThreePartySecretSharing {
    fn new() -> Self {
        ThreePartySecretSharing {
            party_a: None,
            party_b: None,
            party_c: None,
        }
    }

    fn pad_secret(&self, secret: &str) -> Vec<u8> {
        let mut secret_bytes = secret.as_bytes().to_vec();
        let original_length = secret_bytes.len();

        // We'll prepend the length byte instead of appending it
        let mut padded = Vec::with_capacity(original_length + 16);
        padded.push(original_length as u8);  // Store length at the start
        padded.extend(secret_bytes);

        // Calculate and add padding to reach multiple of 16
        let padding_needed = (16 - (padded.len() % 16)) % 16;
        let mut rng = rand::thread_rng();
        padded.extend((0..padding_needed).map(|_| rng.gen::<u8>()));

        assert_eq!(padded.len() % 16, 0, "Final length must be multiple of 16");
        println!("Debug: Original length: {}, Padded length: {}", original_length, padded.len());
        padded
    }

    fn distribute_secret(&mut self, secret: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let padded_secret = self.pad_secret(secret);
        let length = padded_secret.len();

        let mut rng = rand::thread_rng();
        self.party_a = Some((0..length).map(|_| rng.gen::<u8>()).collect());
        self.party_b = Some((0..length).map(|_| rng.gen::<u8>()).collect());

        let intermediate = xor_bytes(&padded_secret, self.party_a.as_ref().unwrap());
        self.party_c = Some(xor_bytes(&intermediate, self.party_b.as_ref().unwrap()));

        (
            self.party_a.as_ref().unwrap().clone(),
            self.party_b.as_ref().unwrap().clone(),
            self.party_c.as_ref().unwrap().clone()
        )
    }

    fn reconstruct_secret(&self, share_a: &[u8], share_b: &[u8], share_c: &[u8]) -> String {
        let temp_b = xor_bytes(share_a, share_b);
        let temp_c = xor_bytes(&temp_b, share_c);

        // Get length from first byte
        let original_length = temp_c[0] as usize;

        println!("Debug: Reconstructing - Total length: {}, Original length: {}",
                 temp_c.len(), original_length);

        // Verify we're not exceeding bounds
        assert!(original_length < temp_c.len(),
                "Invalid length byte: {} for buffer of size {}",
                original_length, temp_c.len());

        // Convert message bytes to string (skip length byte)
        String::from_utf8_lossy(&temp_c[1..original_length + 1]).into_owned()
    }
}

struct SecureThreeWayKeyExchange {
    iteration_count: usize,
}

impl SecureThreeWayKeyExchange {
    fn new() -> Self {
        SecureThreeWayKeyExchange { iteration_count: 4 }
    }

    fn generate_key_share(&self, length: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        (0..length).map(|_| rng.gen::<u8>()).collect()
    }

    fn perform_key_exchange(&self, share_a: &Vec<u8>, share_b: &Vec<u8>, share_c: &Vec<u8>) -> String {
        let (mut a, mut b, mut c) = (share_a.clone(), share_b.clone(), share_c.clone());

        for _ in 0..self.iteration_count {
            let temp_b = xor_bytes(&a, &b);
            let temp_c = xor_bytes(&temp_b, &c);
            let temp_a = xor_bytes(&temp_c, &a);
            a = temp_a;
            b = temp_b;
            c = temp_c;
        }

        b = xor_bytes(&a, &b);
        c = xor_bytes(&b, &c);

        let mut hasher = Sha256::new();
        hasher.update([a, b, c].concat());
        format!("{:x}", hasher.finalize())
    }
}

struct ThreePartyAuthentication {
    token_length: usize,
}

impl ThreePartyAuthentication {
    fn new() -> Self {
        ThreePartyAuthentication { token_length: 32 }
    }

    fn generate_auth_tokens(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut rng = rand::thread_rng();
        (
            (0..self.token_length).map(|_| rng.gen::<u8>()).collect(),
            (0..self.token_length).map(|_| rng.gen::<u8>()).collect(),
            (0..self.token_length).map(|_| rng.gen::<u8>()).collect(),
        )
    }

    fn create_auth_challenge(&self, message: &str, token_a: &[u8], token_b: &[u8], token_c: &[u8]) -> (Vec<Vec<u8>>, String, String) {
        let timestamp = Utc::now().to_string();
        let data = format!("{}{}", message, timestamp);

        let mut sharing = ThreePartySecretSharing::new();
        let auth_parts = sharing.distribute_secret(&data);

        let combined = auth_parts.0.iter()
            .chain(auth_parts.1.iter())
            .chain(auth_parts.2.iter())
            .cloned()
            .collect::<Vec<u8>>();
        let mut hasher = Sha256::new();
        hasher.update(&combined);
        let verification_hash = format!("{:x}", hasher.finalize());

        (vec![auth_parts.0, auth_parts.1, auth_parts.2], verification_hash, timestamp)
    }
}

fn main() {
    // Secret Sharing Example
    println!("1. Three-Party Secret Sharing Demonstration");
    let mut sharing = ThreePartySecretSharing::new();
    let secret = "This is a highly confidential message!";
    println!("Original secret: {}", secret);

    let (share_a, share_b, share_c) = sharing.distribute_secret(secret);
    println!("Share lengths: {}, {}, {}", share_a.len(), share_b.len(), share_c.len());

    let reconstructed = sharing.reconstruct_secret(&share_a, &share_b, &share_c);
    println!("Reconstructed secret: {}", reconstructed);
    println!("\n{}\n", "=".repeat(50));

    // Key Exchange Example
    println!("2. Three-Way Key Exchange Demonstration");
    let exchange = SecureThreeWayKeyExchange::new();
    let share_a = exchange.generate_key_share(32);
    let share_b = exchange.generate_key_share(32);
    let share_c = exchange.generate_key_share(32);
    let shared_key = exchange.perform_key_exchange(&share_a, &share_b, &share_c);
    println!("Generated shared key: {}", shared_key);
    println!("\n{}\n", "=".repeat(50));

    // Three-Party Authentication Example
    println!("3. Three-Party Authentication Demonstration");
    let auth = ThreePartyAuthentication::new();
    let (token_a, token_b, token_c) = auth.generate_auth_tokens();
    let message = "Request for access to secure resource";
    let (auth_parts, verification_hash, timestamp) = auth.create_auth_challenge(
        message,
        &token_a,
        &token_b,
        &token_c
    );

    println!("Authentication message: {}", message);
    println!("Verification hash: {}", verification_hash);
    println!("Timestamp: {}", timestamp);
}