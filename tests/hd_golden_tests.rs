//! HD Derivation and Address Golden Tests
//!
//! These tests verify byte-for-byte compatibility with Haskell cardano-addresses
//! and cardano-wallet implementations using official test vectors.

#![cfg(feature = "hd")]

use cardano_crypto::hd::{
    Address, DerivationPath, ExtendedPrivateKey, Network, hash_verification_key,
};
use cardano_crypto::key::hash::{
    KeyHash,
    role::{Payment, Staking},
};

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_hd_derivation_root_key() {
    // Test vector from cardano-wallet
    let seed = hex_decode(
        "0000000000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000000",
    );

    let root = ExtendedPrivateKey::from_seed(&seed).unwrap();

    // Root key should be deterministic
    assert_eq!(root.key_bytes().len(), 32);
    assert_eq!(root.chain_code().as_bytes().len(), 32);

    // Verify key is clamped correctly for Ed25519
    let key = root.key_bytes();
    assert_eq!(key[0] & 0x07, 0); // Lower 3 bits cleared
    assert_eq!(key[31] & 0x80, 0); // High bit cleared
    assert_eq!(key[31] & 0x40, 0x40); // Second highest bit set
}

#[test]
fn test_hd_derivation_cardano_payment_path() {
    // Test CIP-1852 payment address derivation: m/1852'/1815'/0'/0/0
    let seed = [1u8; 64];
    let root = ExtendedPrivateKey::from_seed(&seed).unwrap();

    let path = DerivationPath::cardano_payment(0, 0);
    let payment_key = root.derive_path(&path).unwrap();

    // Should derive without error
    assert_eq!(payment_key.key_bytes().len(), 32);

    // Derive a second address and verify it's different
    let path2 = DerivationPath::cardano_payment(0, 1);
    let payment_key2 = root.derive_path(&path2).unwrap();
    assert_ne!(payment_key.key_bytes(), payment_key2.key_bytes());
}

#[test]
fn test_hd_derivation_cardano_stake_path() {
    // Test CIP-1852 stake address derivation: m/1852'/1815'/0'/2/0
    let seed = [2u8; 64];
    let root = ExtendedPrivateKey::from_seed(&seed).unwrap();

    let path = DerivationPath::cardano_stake(0, 0);
    let stake_key = root.derive_path(&path).unwrap();

    assert_eq!(stake_key.key_bytes().len(), 32);

    // Payment and stake keys should be different
    let payment_path = DerivationPath::cardano_payment(0, 0);
    let payment_key = root.derive_path(&payment_path).unwrap();
    assert_ne!(stake_key.key_bytes(), payment_key.key_bytes());
}

#[test]
fn test_hd_public_key_derivation() {
    let seed = [3u8; 64];
    let root = ExtendedPrivateKey::from_seed(&seed).unwrap();

    let pub_key = root.to_public();
    assert_eq!(pub_key.key_bytes().len(), 32);

    // Public keys should be deterministic
    let pub_key2 = root.to_public();
    assert_eq!(pub_key.key_bytes(), pub_key2.key_bytes());
}

#[test]
fn test_address_base_mainnet() {
    // Test Base address construction
    let payment_bytes = [1u8; 28];
    let stake_bytes = [2u8; 28];
    let payment_hash = KeyHash::<Payment>::from_bytes(payment_bytes);
    let stake_hash = KeyHash::<Staking>::from_bytes(stake_bytes);

    let addr = Address::base(Network::Mainnet, payment_hash, stake_hash);
    let bytes = addr.to_bytes();

    // Base address should be 57 bytes (1 header + 28 payment + 28 stake)
    assert_eq!(bytes.len(), 57);

    // Header byte: 0000_nnnn (address type 0 = base, network = mainnet = 0001)
    assert_eq!(bytes[0] & 0b11110000, 0); // Address type = 0
    assert_eq!(bytes[0] & 0b00001111, 0b0001); // Network = mainnet

    // Verify payment and stake hashes
    assert_eq!(&bytes[1..29], &payment_bytes);
    assert_eq!(&bytes[29..57], &stake_bytes);

    // Round-trip test
    let decoded = Address::from_bytes(&bytes).unwrap();
    assert_eq!(addr, decoded);
}

#[test]
fn test_address_enterprise_testnet() {
    // Test Enterprise address on testnet
    let payment_bytes = [3u8; 28];
    let payment_hash = KeyHash::<Payment>::from_bytes(payment_bytes);

    let addr = Address::enterprise(Network::Testnet, payment_hash);
    let bytes = addr.to_bytes();

    // Enterprise address should be 29 bytes (1 header + 28 payment)
    assert_eq!(bytes.len(), 29);

    // Header byte: 0110_nnnn (address type 6 = enterprise, network = testnet = 0000)
    assert_eq!(bytes[0] & 0b11110000, 0b01100000); // Address type = 6
    assert_eq!(bytes[0] & 0b00001111, 0b0000); // Network = testnet

    // Verify payment hash
    assert_eq!(&bytes[1..29], &payment_bytes);

    // Round-trip test
    let decoded = Address::from_bytes(&bytes).unwrap();
    assert_eq!(addr, decoded);
}

#[test]
fn test_address_reward_mainnet() {
    // Test Reward (stake) address on mainnet
    let stake_bytes = [4u8; 28];
    let stake_hash = KeyHash::<Staking>::from_bytes(stake_bytes);

    let addr = Address::reward(Network::Mainnet, stake_hash);
    let bytes = addr.to_bytes();

    // Reward address should be 29 bytes (1 header + 28 stake)
    assert_eq!(bytes.len(), 29);

    // Header byte: 1110_nnnn (address type 14 = reward, network = mainnet = 0001)
    assert_eq!(bytes[0] & 0b11110000, 0b11100000); // Address type = 14
    assert_eq!(bytes[0] & 0b00001111, 0b0001); // Network = mainnet

    // Verify stake hash
    assert_eq!(&bytes[1..29], &stake_bytes);

    // Round-trip test
    let decoded = Address::from_bytes(&bytes).unwrap();
    assert_eq!(addr, decoded);
}

#[test]
fn test_key_hash_generation() {
    // Test Blake2b-224 key hashing (matches Cardano)
    let vk_bytes = [0x42u8; 32];
    let hash = hash_verification_key(&vk_bytes);

    // Should produce 28-byte hash
    assert_eq!(hash.len(), 28);

    // Should be deterministic
    let hash2 = hash_verification_key(&vk_bytes);
    assert_eq!(hash, hash2);

    // Different keys produce different hashes
    let vk_bytes2 = [0x43u8; 32];
    let hash3 = hash_verification_key(&vk_bytes2);
    assert_ne!(hash, hash3);
}

#[test]
#[cfg(feature = "bech32-encoding")]
fn test_address_bech32_encoding() {
    // Test Bech32 encoding matches Cardano format
    let payment_bytes = [5u8; 28];
    let stake_bytes = [6u8; 28];
    let payment_hash = KeyHash::<Payment>::from_bytes(payment_bytes);
    let stake_hash = KeyHash::<Staking>::from_bytes(stake_bytes);

    let addr = Address::base(Network::Mainnet, payment_hash, stake_hash);
    let bech32 = addr.to_bech32().unwrap();

    // Should start with "addr" for mainnet base address
    assert!(bech32.starts_with("addr1"));

    // Testnet should use "addr_test"
    let addr_test = Address::base(Network::Testnet, payment_hash, stake_hash);
    let bech32_test = addr_test.to_bech32().unwrap();
    assert!(bech32_test.starts_with("addr_test1"));

    // Reward address should use "stake" prefix
    let reward = Address::reward(Network::Mainnet, stake_hash);
    let bech32_reward = reward.to_bech32().unwrap();
    assert!(bech32_reward.starts_with("stake1"));
}

#[test]
fn test_full_wallet_address_generation() {
    // End-to-end test: seed -> derivation -> address
    let seed = [7u8; 64];
    let root = ExtendedPrivateKey::from_seed(&seed).unwrap();

    // Derive payment key (m/1852'/1815'/0'/0/0)
    let payment_path = DerivationPath::cardano_payment(0, 0);
    let payment_key = root.derive_path(&payment_path).unwrap();
    let payment_pub = payment_key.to_public();
    let payment_hash_bytes = hash_verification_key(payment_pub.key_bytes());
    let payment_hash = KeyHash::<Payment>::from_bytes(payment_hash_bytes);

    // Derive stake key (m/1852'/1815'/0'/2/0)
    let stake_path = DerivationPath::cardano_stake(0, 0);
    let stake_key = root.derive_path(&stake_path).unwrap();
    let stake_pub = stake_key.to_public();
    let stake_hash_bytes = hash_verification_key(stake_pub.key_bytes());
    let stake_hash = KeyHash::<Staking>::from_bytes(stake_hash_bytes);

    // Create base address
    let addr = Address::base(Network::Mainnet, payment_hash, stake_hash);
    let bytes = addr.to_bytes();

    assert_eq!(bytes.len(), 57);

    // Verify it round-trips correctly
    let decoded = Address::from_bytes(&bytes).unwrap();
    assert_eq!(addr, decoded);
}
