//! Key hash types using Blake2b-224
//!
//! This module provides role-parameterized hash types for verification key hashes,
//! matching the types used in cardano-api. All key hashes use Blake2b-224 (28 bytes).
//!
//! # Type-Safe Key Hashes
//!
//! Key hashes are parameterized by their role to prevent mixing different key types
//! at compile time. This matches the Haskell implementation's type-safe approach.
//!
//! | Type | Description | Size |
//! |------|-------------|------|
//! | `KeyHash<Payment>` | Payment verification key hash | 28 bytes |
//! | `KeyHash<Staking>` | Stake verification key hash | 28 bytes |
//! | `KeyHash<PoolOperator>` | Stake pool key hash (pool ID) | 28 bytes |
//! | `KeyHash<Genesis>` | Genesis key hash | 28 bytes |
//! | `KeyHash<DRep>` | Delegated representative key hash | 28 bytes |
//!
//! # Examples
//!
//! ```rust
//! use cardano_crypto::key::hash::{KeyHash, hash_key};
//! use cardano_crypto::key::hash::role::Payment;
//!
//! let vk = [0u8; 32]; // Ed25519 verification key
//! let hash: KeyHash<Payment> = hash_key(&vk);
//! assert_eq!(hash.as_bytes().len(), 28);
//! ```
//!
//! # Backward Compatibility
//!
//! Legacy type aliases are provided for backward compatibility:
//! - `PaymentKeyHash` = `KeyHash<Payment>`
//! - `StakeKeyHash` = `KeyHash<Staking>`
//! - `PoolKeyHash` = `KeyHash<PoolOperator>`
//!
//! # References
//!
//! - [Cardano Ledger Hashes](https://github.com/IntersectMBO/cardano-ledger/blob/master/libs/cardano-ledger-core/src/Cardano/Ledger/Hashes.hs)

use crate::hash::{Blake2b224, HashAlgorithm};
use core::marker::PhantomData;

/// Size of a key hash in bytes (Blake2b-224 = 28 bytes)
pub const KEY_HASH_SIZE: usize = 28;

// =============================================================================
// Role Marker Types
// =============================================================================

/// Key role marker types
///
/// These zero-sized types are used as type parameters to `KeyHash<R>` to
/// distinguish between different key purposes at compile time.
///
/// This matches the Haskell implementation:
/// ```haskell
/// data KeyRole = Payment | Staking | Genesis | PoolOperator | ...
/// newtype KeyHash (r :: KeyRole) = KeyHash (Hash ADDRHASH VerKey)
/// ```
pub mod role {
    /// Payment key role - Spending funds from addresses
    ///
    /// Payment keys are used to control UTxOs and authorize spending.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct Payment;

    /// Staking key role - Delegating stake and withdrawing rewards
    ///
    /// Staking keys are used for delegation certificates and reward withdrawals.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct Staking;

    /// Genesis key role - Genesis block signing and initial distribution
    ///
    /// Genesis keys are used in the genesis block and initial stake distribution.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct Genesis;

    /// Pool operator key role - Stake pool cold keys
    ///
    /// Pool operator keys identify stake pools and sign operational certificates.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct PoolOperator;

    /// Genesis delegate key role - Genesis delegation keys
    ///
    /// Genesis delegate keys are used for genesis delegation certificates.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct GenesisDelegate;

    /// Delegated representative key role - Governance voting
    ///
    /// DRep keys are used for governance voting in CIP-1694.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct DRep;

    /// Constitutional committee cold key role - Committee membership
    ///
    /// Committee cold keys identify constitutional committee members.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct CommitteeCold;

    /// Constitutional committee hot key role - Committee voting
    ///
    /// Committee hot keys are used for actual voting by committee members.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct CommitteeHot;

    /// VRF key role - Verifiable random functions
    ///
    /// VRF keys are used for leader election in the consensus protocol.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct Vrf;
}

// =============================================================================
// Role-Parameterized KeyHash
// =============================================================================

/// Role-parameterized key hash
///
/// A Blake2b-224 hash of a verification key, parameterized by the key's role.
/// The role parameter `R` encodes the key's intended use at compile time,
/// preventing misuse of keys (e.g., using a payment key where a staking key is expected).
///
/// # Type Safety
///
/// ```compile_fail
/// use cardano_crypto::key::hash::{KeyHash, role::{Payment, Staking}};
///
/// let payment_hash: KeyHash<Payment> = KeyHash::from_bytes([0u8; 28]);
/// let staking_hash: KeyHash<Staking> = payment_hash; // Compile error!
/// ```
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::hash::{KeyHash, hash_key};
/// use cardano_crypto::key::hash::role::Payment;
///
/// let vk = [0u8; 32];
/// let hash = hash_key::<Payment>(&vk);
/// assert_eq!(hash.as_bytes().len(), 28);
///
/// // Type-safe: can't mix payment and staking hashes
/// // let staking: KeyHash<Staking> = hash; // Won't compile!
/// ```
///
/// # Cardano Compatibility
///
/// This matches the Haskell type from cardano-ledger:
/// ```haskell
/// newtype KeyHash (r :: KeyRole) crypto = KeyHash (Hash crypto VerKey)
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyHash<R> {
    hash: [u8; KEY_HASH_SIZE],
    _role: PhantomData<R>,
}

impl<R> KeyHash<R> {
    /// Create a key hash from raw bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - 28-byte Blake2b-224 hash
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::key::hash::{KeyHash, role::Payment};
    ///
    /// let bytes = [0u8; 28];
    /// let hash = KeyHash::<Payment>::from_bytes(bytes);
    /// ```
    #[inline]
    pub fn from_bytes(bytes: [u8; KEY_HASH_SIZE]) -> Self {
        Self {
            hash: bytes,
            _role: PhantomData,
        }
    }

    /// Get the hash bytes
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::key::hash::{KeyHash, role::Payment};
    ///
    /// let hash = KeyHash::<Payment>::from_bytes([0u8; 28]);
    /// assert_eq!(hash.as_bytes().len(), 28);
    /// ```
    #[inline]
    pub fn as_bytes(&self) -> &[u8; KEY_HASH_SIZE] {
        &self.hash
    }

    /// Get the hash bytes as a slice
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.hash
    }

    /// Convert to raw bytes
    #[inline]
    pub fn to_bytes(self) -> [u8; KEY_HASH_SIZE] {
        self.hash
    }
}

impl<R> core::fmt::Debug for KeyHash<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyHash")
            .field("hash", &hex_preview(&self.hash))
            .finish()
    }
}

impl<R> core::fmt::Display for KeyHash<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in &self.hash {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

// =============================================================================
// Type Aliases (Backward Compatibility & Convenience)
// =============================================================================

/// Generic key hash type (Blake2b-224) - Legacy compatibility
///
/// For new code, prefer using `KeyHash<R>` with explicit role types.
pub type LegacyKeyHash = [u8; KEY_HASH_SIZE];

/// Payment verification key hash
///
/// Hash of an Ed25519 payment verification key, used in addresses.
pub type PaymentKeyHash = KeyHash<role::Payment>;

/// Stake verification key hash
///
/// Hash of an Ed25519 stake verification key, used in reward addresses.
pub type StakeKeyHash = KeyHash<role::Staking>;

/// Stake pool key hash (Pool ID)
///
/// Hash of a stake pool's cold verification key. This is what identifies
/// a stake pool on-chain and is displayed as the pool ID.
pub type PoolKeyHash = KeyHash<role::PoolOperator>;

/// VRF verification key hash
///
/// Hash of a VRF verification key, used to bind VRF keys to pools.
pub type VrfKeyHash = KeyHash<role::Vrf>;

/// Genesis key hash
///
/// Hash of a genesis verification key.
pub type GenesisKeyHash = KeyHash<role::Genesis>;

/// Genesis delegate key hash
///
/// Hash of a genesis delegate verification key.
pub type GenesisDelegateKeyHash = KeyHash<role::GenesisDelegate>;

/// DRep key hash
///
/// Hash of a delegated representative verification key for governance.
pub type DRepKeyHash = KeyHash<role::DRep>;

/// Committee cold key hash
///
/// Hash of a constitutional committee cold verification key.
pub type CommitteeColdKeyHash = KeyHash<role::CommitteeCold>;

/// Committee hot key hash
///
/// Hash of a constitutional committee hot verification key.
pub type CommitteeHotKeyHash = KeyHash<role::CommitteeHot>;

// =============================================================================
// Hashing Functions
// =============================================================================

/// Hash a verification key with a specific role
///
/// Type-safe version that produces a role-parameterized KeyHash.
///
/// # Arguments
///
/// * `vk` - 32-byte Ed25519 verification key
///
/// # Returns
///
/// Role-parameterized key hash (28 bytes)
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::hash::{hash_key, role::Payment};
///
/// let vk = [0u8; 32];
/// let hash = hash_key::<Payment>(&vk);
/// assert_eq!(hash.as_bytes().len(), 28);
/// ```
pub fn hash_key<R>(vk: &[u8; 32]) -> KeyHash<R> {
    let hash_vec = Blake2b224::hash(vk);
    let mut result = [0u8; KEY_HASH_SIZE];
    result.copy_from_slice(&hash_vec[..KEY_HASH_SIZE]);
    KeyHash::from_bytes(result)
}

/// Hash a raw byte slice with a specific role
///
/// Type-safe version for arbitrary-length input.
///
/// # Arguments
///
/// * `data` - Byte slice to hash
///
/// # Returns
///
/// Role-parameterized key hash (28 bytes)
pub fn hash_key_raw<R>(data: &[u8]) -> KeyHash<R> {
    let hash_vec = Blake2b224::hash(data);
    let mut result = [0u8; KEY_HASH_SIZE];
    result.copy_from_slice(&hash_vec[..KEY_HASH_SIZE]);
    KeyHash::from_bytes(result)
}

/// Hash a verification key using Blake2b-224 (legacy function)
///
/// This function hashes any 32-byte Ed25519 verification key to produce
/// a 28-byte key hash.
///
/// **Note:** For new code, prefer `hash_key::<Role>()` for type safety.
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
pub fn hash_verification_key(vk: &[u8; 32]) -> LegacyKeyHash {
    let hash_vec = Blake2b224::hash(vk);
    let mut result = [0u8; KEY_HASH_SIZE];
    result.copy_from_slice(&hash_vec[..KEY_HASH_SIZE]);
    result
}

/// Hash a raw byte slice using Blake2b-224 (legacy function)
///
/// This function can hash verification keys of any size (e.g., VRF keys which are 32 bytes).
///
/// **Note:** For new code, prefer `hash_key_raw::<Role>()` for type safety.
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
pub fn hash_raw(data: &[u8]) -> LegacyKeyHash {
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
    hash_key(vk)
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
    hash_key(vk)
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
    hash_key(vk)
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
    hash_key(vk)
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
    hash_key(vk)
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
    hash_key(vk)
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
    hash_key(vk)
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
    hash_key(vk)
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
    hash_key(vk)
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Returns a hex preview of bytes for debug output
fn hex_preview(bytes: &[u8]) -> alloc::string::String {
    use alloc::format;
    use alloc::string::String;
    use core::fmt::Write;

    if bytes.len() <= 8 {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{:02x}", b);
        }
        s
    } else {
        format!(
            "{}...{}",
            {
                let mut s = String::with_capacity(8);
                for b in &bytes[..4] {
                    let _ = write!(s, "{:02x}", b);
                }
                s
            },
            {
                let mut s = String::with_capacity(8);
                for b in &bytes[bytes.len() - 4..] {
                    let _ = write!(s, "{:02x}", b);
                }
                s
            }
        )
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::role::*;

    #[test]
    fn test_key_hash_size() {
        assert_eq!(KEY_HASH_SIZE, 28);
    }

    #[test]
    fn test_keyhash_from_bytes() {
        let bytes = [0u8; 28];
        let hash = KeyHash::<Payment>::from_bytes(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_keyhash_to_bytes() {
        let bytes = [42u8; 28];
        let hash = KeyHash::<Staking>::from_bytes(bytes);
        assert_eq!(hash.to_bytes(), bytes);
    }

    #[test]
    fn test_type_safety() {
        // This test verifies that different role types are distinct
        let bytes = [1u8; 28];
        let payment_hash = KeyHash::<Payment>::from_bytes(bytes);
        let staking_hash = KeyHash::<Staking>::from_bytes(bytes);

        // Same bytes, but different types
        assert_eq!(payment_hash.as_bytes(), staking_hash.as_bytes());

        // This would not compile:
        // let _: KeyHash<Payment> = staking_hash;
    }

    #[test]
    fn test_hash_key_payment() {
        let vk = [0u8; 32];
        let hash = hash_key::<Payment>(&vk);
        assert_eq!(hash.as_bytes().len(), 28);
    }

    #[test]
    fn test_hash_key_staking() {
        let vk = [1u8; 32];
        let hash = hash_key::<Staking>(&vk);
        assert_eq!(hash.as_bytes().len(), 28);
    }

    #[test]
    fn test_hash_key_pool_operator() {
        let vk = [2u8; 32];
        let hash = hash_key::<PoolOperator>(&vk);
        assert_eq!(hash.as_bytes().len(), 28);
    }

    #[test]
    fn test_hash_verification_key_legacy() {
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

        let hash1 = hash_key::<Payment>(&vk1);
        let hash2 = hash_key::<Payment>(&vk2);

        assert_ne!(hash1.as_bytes(), hash2.as_bytes());
    }

    #[test]
    fn test_hash_raw_legacy() {
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
        assert_eq!(hash.as_bytes().len(), 28);
    }

    #[test]
    fn test_stake_key_hash() {
        let vk = [2u8; 32];
        let hash = hash_stake_verification_key(&vk);
        assert_eq!(hash.as_bytes().len(), 28);
    }

    #[test]
    fn test_pool_key_hash() {
        let vk = [3u8; 32];
        let pool_id = hash_pool_verification_key(&vk);
        assert_eq!(pool_id.as_bytes().len(), 28);
    }

    #[test]
    fn test_vrf_key_hash() {
        let vk = [4u8; 32];
        let hash = hash_vrf_verification_key(&vk);
        assert_eq!(hash.as_bytes().len(), 28);
    }

    #[test]
    fn test_governance_key_hashes() {
        let vk = [5u8; 32];

        let drep_hash = hash_drep_verification_key(&vk);
        let cc_cold_hash = hash_committee_cold_verification_key(&vk);
        let cc_hot_hash = hash_committee_hot_verification_key(&vk);

        // All use same underlying hash function
        assert_eq!(drep_hash.as_bytes(), cc_cold_hash.as_bytes());
        assert_eq!(cc_cold_hash.as_bytes(), cc_hot_hash.as_bytes());
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

    #[test]
    fn test_role_type_distinctness() {
        // Verify that different role types cannot be interchanged at compile time
        let vk = [42u8; 32];

        let payment = hash_payment_verification_key(&vk);
        let staking = hash_stake_verification_key(&vk);
        let pool = hash_pool_verification_key(&vk);

        // Same underlying bytes since same input
        assert_eq!(payment.as_bytes(), staking.as_bytes());
        assert_eq!(staking.as_bytes(), pool.as_bytes());

        // But they have different types at compile time
        // These would not compile:
        // let _: PaymentKeyHash = staking;
        // let _: StakeKeyHash = pool;
        // let _: PoolKeyHash = payment;
    }

    #[test]
    fn test_keyhash_debug_display() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28];
        let hash = KeyHash::<Payment>::from_bytes(bytes);

        // Debug should show preview
        let debug_str = alloc::format!("{:?}", hash);
        assert!(debug_str.contains("01020304"));
        assert!(debug_str.contains("191a1b1c"));

        // Display should show full hex
        let display_str = alloc::format!("{}", hash);
        assert_eq!(display_str.len(), 56); // 28 bytes * 2 hex chars
        assert!(display_str.starts_with("01020304"));
    }
}
