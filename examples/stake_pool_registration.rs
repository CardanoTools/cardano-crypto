//! Stake Pool Registration Example
//!
//! Demonstrates creating and validating stake pool parameters for
//! pool registration certificates on the Cardano blockchain.

use cardano_crypto::hash::{Blake2b256, HashAlgorithm};
use cardano_crypto::key::hash::{
    PoolKeyHash, hash_pool_verification_key, hash_stake_verification_key,
};
use cardano_crypto::key::stake_pool::{
    PoolMetadata, Rational, RewardAccount, StakePoolParams, StakePoolRelay, VrfKeyHash,
};
use std::collections::BTreeSet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Cardano Stake Pool Registration Example ===\n");

    // Step 1: Generate pool keys (in production, these come from cardano-cli)
    println!("--- Step 1: Pool Keys ---");

    // Pool cold key (identifies the pool on-chain)
    let pool_cold_vk = [1u8; 32];
    let pool_id: PoolKeyHash = hash_pool_verification_key(&pool_cold_vk);
    println!("Pool ID (cold key hash): {}", pool_id);

    // VRF key (for leader election)
    // VRF key hash uses Blake2b-256 (32 bytes) for stake pool registration
    let vrf_vk = [2u8; 32];
    let vrf_hash_vec = Blake2b256::hash(&vrf_vk);
    let vrf_hash: VrfKeyHash = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&vrf_hash_vec);
        arr
    };
    println!("VRF key hash: {}", hex::encode(vrf_hash));

    // Step 2: Define economic parameters
    println!("\n--- Step 2: Economic Parameters ---");

    // Pledge: Amount operator commits to their own pool
    let pledge: u64 = 500_000_000_000; // 500,000 ADA
    println!("Pledge: {} ADA", pledge / 1_000_000);

    // Cost: Fixed fee per epoch (minimum 340 ADA)
    let cost: u64 = 340_000_000; // 340 ADA
    println!("Cost: {} ADA/epoch", cost / 1_000_000);

    // Margin: Variable fee (5% in this example)
    let margin = Rational::from_percentage(5)?;
    println!(
        "Margin: {}% ({}/{})",
        margin.numerator(),
        margin.numerator(),
        margin.denominator()
    );

    // Step 3: Set up reward account
    println!("\n--- Step 3: Reward Account ---");

    // Operator's stake key for receiving rewards
    let operator_stake_vk = [3u8; 32];
    let operator_stake_hash = hash_stake_verification_key(&operator_stake_vk);
    let reward_account = RewardAccount::from_stake_key_hash(operator_stake_hash.to_bytes());
    println!("Reward account (stake key): {}", operator_stake_hash);

    // Step 4: Define pool owners
    println!("\n--- Step 4: Pool Owners ---");

    // At least one owner required (usually the operator)
    let mut owners = BTreeSet::new();
    owners.insert(operator_stake_hash);
    println!("Owner 1: {}", operator_stake_hash);

    // Optional: Add additional owners (e.g., multi-operator pool)
    let owner2_vk = [4u8; 32];
    let owner2_hash = hash_stake_verification_key(&owner2_vk);
    owners.insert(owner2_hash);
    println!("Owner 2: {}", owner2_hash);

    println!("Total owners: {}", owners.len());

    // Step 5: Create pool parameters
    println!("\n--- Step 5: Pool Registration Parameters ---");

    let margin_for_display = margin.clone();
    let mut params = StakePoolParams::new(
        pool_id,
        vrf_hash,
        pledge,
        cost,
        margin,
        reward_account,
        owners,
    )?;

    println!("✓ Pool parameters created successfully");

    // Step 6: Add relay information
    println!("\n--- Step 6: Network Relays ---");

    // Relay 1: IPv4 address
    let relay1 = StakePoolRelay::SingleHostAddr {
        port: Some(3001),
        ipv4: Some([192, 168, 1, 100]),
        ipv6: None,
    };
    params.add_relay(relay1)?;
    println!("✓ Added IPv4 relay: 192.168.1.100:3001");

    // Relay 2: DNS hostname
    let relay2 = StakePoolRelay::SingleHostName {
        port: Some(3001),
        dns_name: "relay1.mypool.example.com".to_string(),
    };
    params.add_relay(relay2)?;
    println!("✓ Added DNS relay: relay1.mypool.example.com:3001");

    // Relay 3: IPv6 address
    let relay3 = StakePoolRelay::SingleHostAddr {
        port: Some(3001),
        ipv4: None,
        ipv6: Some([
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x34,
        ]),
    };
    params.add_relay(relay3)?;
    println!("✓ Added IPv6 relay: 2001:db8:85a3::8a2e:370:7334:3001");

    // Relay 4: Multi-host DNS SRV
    let relay4 = StakePoolRelay::MultiHostName {
        dns_name: "_cardano._tcp.mypool.example.com".to_string(),
    };
    params.add_relay(relay4)?;
    println!("✓ Added multi-host relay: _cardano._tcp.mypool.example.com");

    println!("Total relays: {}", params.relays.len());

    // Step 7: Add metadata (optional but recommended)
    println!("\n--- Step 7: Pool Metadata ---");

    // Metadata JSON file hosted externally
    let metadata_url = "https://mypool.example.com/metadata.json".to_string();

    // Blake2b-256 hash of metadata file contents
    // In production, this would be computed from the actual JSON file
    let metadata_hash = [0xab; 32]; // Example hash

    let metadata = PoolMetadata::new(metadata_url.clone(), metadata_hash)?;
    params.set_metadata(metadata)?;

    println!("✓ Metadata URL: {}", metadata_url);
    println!("✓ Metadata hash: {}", hex::encode(metadata_hash));

    // Step 8: Validate all parameters
    println!("\n--- Step 8: Validation ---");

    params.validate()?;
    println!("✓ All parameters validated successfully");

    // Step 9: Display summary
    println!("\n--- Step 9: Registration Summary ---");
    println!("┌─────────────────────────────────────────────────┐");
    println!("│ Pool Registration Certificate Parameters       │");
    println!("├─────────────────────────────────────────────────┤");
    println!("│ Pool ID:    {}              │", pool_id);
    println!(
        "│ Pledge:     {:>10} ADA                    │",
        pledge / 1_000_000
    );
    println!(
        "│ Cost:       {:>10} ADA/epoch             │",
        cost / 1_000_000
    );
    println!(
        "│ Margin:     {:>10.2}%                     │",
        margin_for_display.to_f64() * 100.0
    );
    println!(
        "│ Owners:     {:>10}                        │",
        params.owners.len()
    );
    println!(
        "│ Relays:     {:>10}                        │",
        params.relays.len()
    );
    println!(
        "│ Metadata:   {:>10}                        │",
        if params.metadata.is_some() {
            "Yes"
        } else {
            "No"
        }
    );
    println!("└─────────────────────────────────────────────────┘");

    // Step 10: Next steps
    println!("\n--- Step 10: Next Steps ---");
    println!("1. Create pool registration certificate with these parameters");
    println!("2. Sign certificate with pool cold key");
    println!("3. Submit transaction with certificate to blockchain");
    println!("4. Wait for transaction confirmation (2-3 epochs)");
    println!("5. Start block production once pool is registered");

    println!("\n✓ Example completed successfully!");
    println!("\nNote: This example demonstrates parameter construction.");
    println!("In production, use cardano-cli for actual pool registration.");

    Ok(())
}
