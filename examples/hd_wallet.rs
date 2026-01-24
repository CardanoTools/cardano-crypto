//! Hierarchical Deterministic Wallet Example
//!
//! Demonstrates CIP-1852 HD derivation and Cardano address generation

use cardano_crypto::hd::{ExtendedPrivateKey, DerivationPath, Address, Network};
use cardano_crypto::key::hash::{hash_payment_verification_key, hash_stake_verification_key};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Cardano HD Wallet Example ===\n");

    // Step 1: Create root key from BIP39 seed
    // In production, this would come from a mnemonic phrase
    let seed = [42u8; 64];
    let root = ExtendedPrivateKey::from_seed(&seed);
    println!("✓ Root extended private key created");

    // Step 2: Derive payment key (m/1852'/1815'/0'/0/0)
    println!("\n--- Payment Key Derivation ---");
    let payment_path = DerivationPath::cardano_payment(0, 0);
    let payment_key = root.derive_path(&payment_path)?;
    println!("Path: m/1852'/1815'/0'/0/0");
    println!("✓ Payment key derived");

    // Step 3: Derive stake key (m/1852'/1815'/0'/2/0)
    println!("\n--- Stake Key Derivation ---");
    let stake_path = DerivationPath::cardano_stake(0, 0);
    let stake_key = root.derive_path(&stake_path)?;
    println!("Path: m/1852'/1815'/0'/2/0");
    println!("✓ Stake key derived");

    // Step 4: Generate public keys and hashes (type-safe!)
    println!("\n--- Key Hashing ---");
    let payment_pub = payment_key.to_public();
    let payment_hash = hash_payment_verification_key(payment_pub.key_bytes());
    println!("Payment key hash: {}", payment_hash);

    let stake_pub = stake_key.to_public();
    let stake_hash = hash_stake_verification_key(stake_pub.key_bytes());
    println!("Stake key hash: {}", stake_hash);

    // Step 5: Create different address types
    println!("\n--- Address Generation ---");

    // Base address (payment + stake) - Type-safe! Can't mix payment and stake hashes
    let base_addr = Address::base(Network::Mainnet, payment_hash, stake_hash);
    let base_bytes = base_addr.to_bytes();
    println!("Base address (57 bytes): {}", hex::encode(&base_bytes));

    #[cfg(feature = "bech32-encoding")]
    {
        let base_bech32 = base_addr.to_bech32()?;
        println!("Base address (bech32): {}", base_bech32);
    }

    // Enterprise address (payment only)
    let enterprise_addr = Address::enterprise(Network::Mainnet, payment_hash);
    let enterprise_bytes = enterprise_addr.to_bytes();
    println!("\nEnterprise address (29 bytes): {}", hex::encode(&enterprise_bytes));

    #[cfg(feature = "bech32-encoding")]
    {
        let enterprise_bech32 = enterprise_addr.to_bech32()?;
        println!("Enterprise address (bech32): {}", enterprise_bech32);
    }

    // Reward address (stake only)
    let reward_addr = Address::reward(Network::Mainnet, stake_hash);
    let reward_bytes = reward_addr.to_bytes();
    println!("\nReward address (29 bytes): {}", hex::encode(&reward_bytes));

    #[cfg(feature = "bech32-encoding")]
    {
        let reward_bech32 = reward_addr.to_bech32()?;
        println!("Reward address (bech32): {}", reward_bech32);
    }

    // Step 6: Derive multiple addresses
    println!("\n--- Multiple Address Derivation ---");
    for i in 0..3 {
        let path = DerivationPath::cardano_payment(0, i);
        let key = root.derive_path(&path)?;
        let pub_key = key.to_public();
        let hash = hash_payment_verification_key(pub_key.key_bytes());
        println!("Address {} key hash: {}", i, hash);
    }

    println!("\n✓ All operations successful!");
    Ok(())
}
