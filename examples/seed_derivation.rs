//! Seed derivation and key generation example
//!
//! Demonstrates hierarchical deterministic key derivation matching
//! Cardano's seed handling patterns.

use cardano_crypto::seed::{derive_seed, expand_seed, SecureSeed, SEED_SIZE};

fn main() {
    println!("=== Cardano Seed Derivation Example ===\n");

    // Display seed size constant
    println!("Seed size: {} bytes (matches Ed25519 seed size)", SEED_SIZE);
    println!();

    // -------------------------------------------------------------------
    // 1. Derive a master seed from entropy (e.g., mnemonic phrase)
    // -------------------------------------------------------------------
    section("1. Master Seed Derivation");

    let entropy = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let master_seed = derive_seed(entropy);

    println!(
        "Entropy: \"{}...\" ({} bytes)",
        &String::from_utf8_lossy(&entropy[..40]),
        entropy.len()
    );
    println!("Master seed: {}...", hex(&master_seed[..16]));
    println!();

    // Derivation is deterministic
    let master_seed2 = derive_seed(entropy);
    assert_eq!(master_seed, master_seed2);
    println!("✓ Seed derivation is deterministic");

    // -------------------------------------------------------------------
    // 2. Hierarchical key derivation using expand_seed
    // -------------------------------------------------------------------
    section("2. Hierarchical Key Derivation");

    // Derive purpose-specific seeds using indices
    let payment_seed = expand_seed(&master_seed, 0); // Purpose 0: Payment keys
    let stake_seed = expand_seed(&master_seed, 1); // Purpose 1: Stake keys
    let vrf_seed = expand_seed(&master_seed, 2); // Purpose 2: VRF keys
    let kes_seed = expand_seed(&master_seed, 3); // Purpose 3: KES keys

    println!("Master seed: {}...", hex(&master_seed[..8]));
    println!("├── Purpose 0 (Payment): {}...", hex(&payment_seed[..8]));
    println!("├── Purpose 1 (Stake):   {}...", hex(&stake_seed[..8]));
    println!("├── Purpose 2 (VRF):     {}...", hex(&vrf_seed[..8]));
    println!("└── Purpose 3 (KES):     {}...", hex(&kes_seed[..8]));
    println!();

    // Child seeds are independent
    assert_ne!(payment_seed, stake_seed);
    assert_ne!(stake_seed, vrf_seed);
    println!("✓ Child seeds are cryptographically independent");

    // -------------------------------------------------------------------
    // 3. Multi-level derivation (accounts and addresses)
    // -------------------------------------------------------------------
    section("3. Multi-Level Derivation (Account/Address)");

    // Account 0
    let account_0 = expand_seed(&payment_seed, 0);
    let account_0_addr_0 = expand_seed(&account_0, 0);
    let account_0_addr_1 = expand_seed(&account_0, 1);

    // Account 1
    let account_1 = expand_seed(&payment_seed, 1);
    let account_1_addr_0 = expand_seed(&account_1, 0);

    println!("Payment purpose seed");
    println!("├── Account 0: {}...", hex(&account_0[..8]));
    println!("│   ├── Address 0: {}...", hex(&account_0_addr_0[..8]));
    println!("│   └── Address 1: {}...", hex(&account_0_addr_1[..8]));
    println!("└── Account 1: {}...", hex(&account_1[..8]));
    println!("    └── Address 0: {}...", hex(&account_1_addr_0[..8]));
    println!();

    // -------------------------------------------------------------------
    // 4. SecureSeed for automatic memory cleanup
    // -------------------------------------------------------------------
    section("4. SecureSeed - Memory-Safe Wrapper");

    {
        let secure_master = SecureSeed::new(master_seed);
        println!("SecureSeed created (debug output): {:?}", secure_master);

        // Can still derive from it
        let (child_0, child_1) = secure_master.expand();
        println!("Child 0: {}...", hex(&child_0.as_bytes()[..8]));
        println!("Child 1: {}...", hex(&child_1.as_bytes()[..8]));
        println!();

        // Verify expand() matches expand_seed()
        assert_eq!(
            child_0.as_bytes(),
            &expand_seed(secure_master.as_bytes(), 0)
        );
        assert_eq!(
            child_1.as_bytes(),
            &expand_seed(secure_master.as_bytes(), 1)
        );
        println!("✓ SecureSeed.expand() matches expand_seed()");

        // SecureSeed will be zeroized when it goes out of scope
    }
    println!("✓ SecureSeed automatically zeroized on drop");

    // -------------------------------------------------------------------
    // 5. Using seeds with cryptographic primitives
    // -------------------------------------------------------------------
    section("5. Using Seeds with Crypto Primitives");

    // Generate Ed25519 keys
    use cardano_crypto::dsign::{DsignAlgorithm, Ed25519};
    let signing_key = Ed25519::gen_key(&payment_seed);
    let verification_key = Ed25519::derive_verification_key(&signing_key);
    println!(
        "Payment Ed25519 VK: {}...",
        hex(&verification_key.as_bytes()[..8])
    );

    // Generate VRF keys
    use cardano_crypto::vrf::VrfDraft03;
    let (vrf_sk, vrf_pk) = VrfDraft03::keypair_from_seed(&vrf_seed);
    println!("VRF Public Key: {}...", hex(&vrf_pk[..8]));
    let _ = vrf_sk; // suppress unused warning

    // Generate KES keys
    use cardano_crypto::kes::{KesAlgorithm, Sum6Kes};
    let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed).expect("KES keygen");
    let kes_vk = Sum6Kes::derive_verification_key(&kes_sk).expect("KES VK derivation");
    println!("KES Verification Key: {}...", hex(&kes_vk[..8]));

    println!();
    println!("✓ All key types generated from derived seeds");

    // -------------------------------------------------------------------
    // 6. Security best practices
    // -------------------------------------------------------------------
    section("6. Security Best Practices");

    println!("• Use high-entropy sources for master seed (hardware RNG, BIP39)");
    println!("• Never reuse seeds across different applications");
    println!("• Use SecureSeed wrapper for automatic memory cleanup");
    println!("• Derive separate seeds for each key purpose");
    println!("• Consider using constant-time operations for sensitive data");
    println!();

    println!("=== Seed derivation example complete! ===");
}

fn section(title: &str) {
    println!("{}", title);
    println!("{}", "-".repeat(title.len()));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
