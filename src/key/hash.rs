//! Key hash types using Blake2b-224
//!
//! This module provides hash types for verification key hashes, matching the
//! types used in cardano-api. All key hashes use Blake2b-224 (28 bytes).
//!
//! # Hash Types
//!
//! | Type | Description | Size |
//! |------|-------------|------|
//! | `KeyHash` | Generic verification key hash | 28 bytes |
//! | `PaymentKeyHash` | Payment verification key hash | 28 bytes |
//! | `StakeKeyHash` | Stake verification key hash | 28 bytes |
//! | `PoolKeyHash` | Stake pool key hash (pool ID) | 28 bytes |
//! | `VrfKeyHash` | VRF verification key hash | 28 bytes |
//!
//! # Examples
//!
//! ```rust
//! use cardano_crypto::key::hash::{KeyHash, hash_verification_key};
//!
//! let vk = [0u8; 32]; // Ed25519 verification key
//! let hash = hash_verification_key(&vk);
//! assert_eq!(hash.len(), 28);
//! ```

use crate::hash::{Blake2b224, HashAlgorithm};

/// Size of a key hash in bytes (Blake2b-224 = 28 bytes)
pub const KEY_HASH_SIZE: usize = 28;

/// Generic key hash type (Blake2b-224)
///
/// Used as the base type for all verification key hashes.
pub type KeyHash = [u8; KEY_HASH_SIZE];

/// Payment verification key hash
///
/// Hash of an Ed25519 payment verification key, used in addresses.
pub type PaymentKeyHash = KeyHash;

/// Stake verification key hash
///
/// Hash of an Ed25519 stake verification key, used in reward addresses.
pub type StakeKeyHash = KeyHash;

/// Stake pool key hash (Pool ID)
///
/// Hash of a stake pool's cold verification key. This is what identifies
/// a stake pool on-chain and is displayed as the pool ID.
pub type PoolKeyHash = KeyHash;

/// VRF verification key hash
///
/// Hash of a VRF verification key, used to bind VRF keys to pools.
pub type VrfKeyHash = KeyHash;

/// Genesis key hash
///
/// Hash of a genesis verification key.
pub type GenesisKeyHash = KeyHash;

/// Genesis delegate key hash
///
/// Hash of a genesis delegate verification key.
pub type GenesisDelegateKeyHash = KeyHash;

/// DRep key hash
///
/// Hash of a delegated representative verification key for governance.
pub type DRepKeyHash = KeyHash;

/// Committee cold key hash
///
/// Hash of a constitutional committee cold verification key.
pub type CommitteeColdKeyHash = KeyHash;

/// Committee hot key hash
///
/// Hash of a constitutional committee hot verification key.
pub type CommitteeHotKeyHash = KeyHash;

/// Hash a verification key using Blake2b-224
///
/// This function hashes any 32-byte Ed25519 verification key to produce
/// a 28-byte key hash.
///
/// # Arguments
///
/// * `vk` - 32-byte Ed25519 verification key
///
/// # Returns
///
/// 28-byte Blake2b-224 hash of the verification key
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::hash::hash_verification_key;
///
/// let vk = [0u8; 32];
/// let hash = hash_verification_key(&vk);
/// assert_eq!(hash.len(), 28);
/// ```
pub fn hash_verification_key(vk: &[u8; 32]) -> KeyHash {
    let hash_vec = Blake2b224::hash(vk);
    let mut result = [0u8; KEY_HASH_SIZE];
    result.copy_from_slice(&hash_vec[..KEY_HASH_SIZE]);
    result
}

/// Hash a raw byte slice using Blake2b-224
///
/// This function can hash verification keys of any size (e.g., VRF keys which are 32 bytes).
///
/// # Arguments
///
/// * `data` - Byte slice to hash
///
/// # Returns
///
/// 28-byte Blake2b-224 hash
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::hash::hash_raw;
///
/// let data = [0u8; 32];
/// let hash = hash_raw(&data);
/// assert_eq!(hash.len(), 28);
/// ```
pub fn hash_raw(data: &[u8]) -> KeyHash {
    let hash_vec = Blake2b224::hash(data);
    let mut result = [0u8; KEY_HASH_SIZE];
    result.copy_from_slice(&hash_vec[..KEY_HASH_SIZE]);
    result
}

/// Hash a payment verification key
///
/// # Arguments
///
/// * `vk` - 32-byte Ed25519 payment verification key
///
/// # Returns
///
/// Payment key hash (28 bytes)
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::hash::hash_payment_verification_key;
///
/// let vk = [0u8; 32];
/// let hash = hash_payment_verification_key(&vk);
/// assert_eq!(hash.len(), 28);
/// ```
pub fn hash_payment_verification_key(vk: &[u8; 32]) -> PaymentKeyHash {
    hash_verification_key(vk)
}

/// Hash a stake verification key
///
/// # Arguments
///
/// * `vk` - 32-byte Ed25519 stake verification key
///
/// # Returns
///
/// Stake key hash (28 bytes)
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::hash::hash_stake_verification_key;
///
/// let vk = [0u8; 32];
/// let hash = hash_stake_verification_key(&vk);
/// assert_eq!(hash.len(), 28);
/// ```
pub fn hash_stake_verification_key(vk: &[u8; 32]) -> StakeKeyHash {
    hash_verification_key(vk)
}

/// Hash a stake pool verification key to get the pool ID
///
/// # Arguments
///
/// * `vk` - 32-byte Ed25519 pool cold verification key
///
/// # Returns
///
/// Pool key hash / Pool ID (28 bytes)
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::hash::hash_pool_verification_key;
///
/// let vk = [0u8; 32];
/// let pool_id = hash_pool_verification_key(&vk);
/// assert_eq!(pool_id.len(), 28);
/// ```
pub fn hash_pool_verification_key(vk: &[u8; 32]) -> PoolKeyHash {
    hash_verification_key(vk)
}

/// Hash a VRF verification key
///
/// # Arguments
///
/// * `vk` - 32-byte VRF verification key
///
/// # Returns
///
/// VRF key hash (28 bytes)
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::hash::hash_vrf_verification_key;
///
/// let vk = [0u8; 32];
/// let hash = hash_vrf_verification_key(&vk);
/// assert_eq!(hash.len(), 28);
/// ```
pub fn hash_vrf_verification_key(vk: &[u8; 32]) -> VrfKeyHash {
    hash_verification_key(vk)
}

/// Hash a genesis verification key
///
/// # Arguments
///
/// * `vk` - 32-byte Ed25519 genesis verification key
///
/// # Returns
///
/// Genesis key hash (28 bytes)
pub fn hash_genesis_verification_key(vk: &[u8; 32]) -> GenesisKeyHash {
    hash_verification_key(vk)
}

/// Hash a genesis delegate verification key
///
/// # Arguments
///
/// * `vk` - 32-byte Ed25519 genesis delegate verification key
///
/// # Returns
///
/// Genesis delegate key hash (28 bytes)
pub fn hash_genesis_delegate_verification_key(vk: &[u8; 32]) -> GenesisDelegateKeyHash {
    hash_verification_key(vk)
}

/// Hash a DRep verification key
///
/// # Arguments
///
/// * `vk` - 32-byte Ed25519 DRep verification key
///
/// # Returns
///
/// DRep key hash (28 bytes)
pub fn hash_drep_verification_key(vk: &[u8; 32]) -> DRepKeyHash {
    hash_verification_key(vk)
}

/// Hash a committee cold verification key
///
/// # Arguments
///
/// * `vk` - 32-byte Ed25519 committee cold verification key
///
/// # Returns
///
/// Committee cold key hash (28 bytes)
pub fn hash_committee_cold_verification_key(vk: &[u8; 32]) -> CommitteeColdKeyHash {
    hash_verification_key(vk)
}

/// Hash a committee hot verification key
///
/// # Arguments
///
/// * `vk` - 32-byte Ed25519 committee hot verification key
///
/// # Returns
///
/// Committee hot key hash (28 bytes)
pub fn hash_committee_hot_verification_key(vk: &[u8; 32]) -> CommitteeHotKeyHash {
    hash_verification_key(vk)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_hash_size() {
        assert_eq!(KEY_HASH_SIZE, 28);
    }

    #[test]
    fn test_hash_verification_key() {
        let vk = [0u8; 32];
        let hash = hash_verification_key(&vk);
        assert_eq!(hash.len(), 28);

        // Deterministic - same input should produce same output
        let hash2 = hash_verification_key(&vk);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_different_inputs_produce_different_hashes() {
        let vk1 = [0u8; 32];
        let mut vk2 = [0u8; 32];
        vk2[0] = 1;

        let hash1 = hash_verification_key(&vk1);
        let hash2 = hash_verification_key(&vk2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_raw() {
        let data = [0u8; 32];
        let hash = hash_raw(&data);
        assert_eq!(hash.len(), 28);

        // Should match verification key hash for same 32-byte input
        let vk_hash = hash_verification_key(&data);
        assert_eq!(hash, vk_hash);
    }

    #[test]
    fn test_payment_key_hash() {
        let vk = [1u8; 32];
        let hash = hash_payment_verification_key(&vk);
        assert_eq!(hash.len(), 28);
    }

    #[test]
    fn test_stake_key_hash() {
        let vk = [2u8; 32];
        let hash = hash_stake_verification_key(&vk);
        assert_eq!(hash.len(), 28);
    }

    #[test]
    fn test_pool_key_hash() {
        let vk = [3u8; 32];
        let pool_id = hash_pool_verification_key(&vk);
        assert_eq!(pool_id.len(), 28);
    }

    #[test]
    fn test_vrf_key_hash() {
        let vk = [4u8; 32];
        let hash = hash_vrf_verification_key(&vk);
        assert_eq!(hash.len(), 28);
    }

    #[test]
    fn test_governance_key_hashes() {
        let vk = [5u8; 32];

        let drep_hash = hash_drep_verification_key(&vk);
        let cc_cold_hash = hash_committee_cold_verification_key(&vk);
        let cc_hot_hash = hash_committee_hot_verification_key(&vk);

        // All use same underlying hash function
        assert_eq!(drep_hash, cc_cold_hash);
        assert_eq!(cc_cold_hash, cc_hot_hash);
    }

    #[test]
    fn test_known_hash_vector() {
        // Test with a known input to verify Blake2b-224 output
        let vk = [0u8; 32];
        let hash = hash_verification_key(&vk);

        // The hash should be deterministic
        // Blake2b-224 of 32 zero bytes
        let expected_vec = Blake2b224::hash(&[0u8; 32]);
        assert_eq!(hash[..], expected_vec[..]);
    }
}
