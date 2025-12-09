//! Seed management and derivation utilities
//!
//! This module provides secure seed generation and hierarchical key derivation
//! matching Cardano's seed handling from cardano-base.
//!
//! # Cardano Seed Handling
//!
//! In Cardano's Haskell implementation, seeds are managed through:
//! - `Seed` - Basic 32-byte seed value
//! - `MLockedSeed` - Memory-locked seed for protection against memory dumps
//!
//! This Rust implementation provides equivalent functionality with:
//! - `Seed` - 32-byte seed type
//! - `SecureSeed` - Wrapper with automatic zeroization
//! - Hierarchical derivation matching Cardano's expand functions
//!
//! # Security Considerations
//!
//! - Seeds should be generated from high-entropy sources (e.g., hardware RNG)
//! - Seeds must be kept secret - they can regenerate all derived keys
//! - Use `SecureSeed` wrapper for automatic zeroization on drop
//! - Never reuse seeds across different applications or protocols
//!
//! # Examples
//!
//! ```
//! use cardano_crypto::seed::{derive_seed, expand_seed, SecureSeed};
//!
//! // Derive a seed from mnemonic or passphrase
//! let mnemonic = b"example mnemonic phrase with high entropy";
//! let master_seed = derive_seed(mnemonic);
//!
//! // Derive child seeds for hierarchical key derivation
//! let child_seed_0 = expand_seed(&master_seed, 0);
//! let child_seed_1 = expand_seed(&master_seed, 1);
//!
//! // Each child seed can be used for different purposes
//! assert_ne!(child_seed_0, child_seed_1);
//!
//! // Use SecureSeed for automatic memory cleanup
//! let secure = SecureSeed::new(master_seed);
//! assert_eq!(secure.as_bytes().len(), 32);
//! // Seed will be zeroized when `secure` goes out of scope
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// Error Types
// ============================================================================

/// Error type for seed operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedError {
    /// Seed data has invalid length
    InvalidLength {
        /// Expected seed length in bytes
        expected: usize,
        /// Actual seed length received
        actual: usize,
    },
    /// Seed failed validation checks
    ValidationFailed(&'static str),
}

impl core::fmt::Display for SeedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SeedError::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "Invalid seed length: expected {expected} bytes, got {actual}"
                )
            }
            SeedError::ValidationFailed(msg) => {
                write!(f, "Seed validation failed: {msg}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SeedError {}

// ============================================================================
// Seed Types
// ============================================================================

/// Seed type for cryptographic key generation
///
/// A 32-byte (256-bit) seed value used as the root secret for deterministic
/// key generation. This provides sufficient entropy for cryptographic security.
///
/// # Size
///
/// The 32-byte size matches:
/// - `SeedSizeDSIGN Ed25519DSIGN = 32` from cardano-base
/// - `SeedSizeKES (SingleKES d) = SeedSizeDSIGN d`
/// - Standard Ed25519 seed size
///
/// # Example
///
/// ```rust
/// use cardano_crypto::seed::Seed;
///
/// let seed: Seed = [42u8; 32];
/// assert_eq!(seed.len(), 32);
/// ```
pub type Seed = [u8; 32];

/// Seed size constant (matches SeedSizeDSIGN Ed25519DSIGN)
pub const SEED_SIZE: usize = 32;

/// A secure seed wrapper with automatic zeroization
///
/// This type wraps a 32-byte seed and automatically zeroizes it when dropped,
/// providing protection similar to Cardano's `MLockedSeed` for environments
/// where memory locking is not available.
///
/// # Security Features
///
/// - Automatic zeroization on drop (prevents lingering in memory)
/// - Debug output is redacted
/// - Clone is explicit (not Copy) to prevent accidental duplication
///
/// # Example
///
/// ```rust
/// use cardano_crypto::seed::SecureSeed;
///
/// fn generate_key() {
///     let seed = SecureSeed::from_bytes(&[42u8; 32]);
///     // Use the seed...
///     // Seed is automatically zeroized when this function returns
/// }
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureSeed([u8; SEED_SIZE]);

impl SecureSeed {
    /// Create a new SecureSeed from a seed value
    ///
    /// # Example
    ///
    /// ```rust
    /// use cardano_crypto::seed::SecureSeed;
    ///
    /// let seed = [1u8; 32];
    /// let secure = SecureSeed::new(seed);
    /// ```
    #[must_use]
    pub fn new(seed: Seed) -> Self {
        Self(seed)
    }

    /// Create from a byte slice
    ///
    /// # Panics
    ///
    /// Panics if the slice is not exactly 32 bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cardano_crypto::seed::SecureSeed;
    ///
    /// let bytes = [2u8; 32];
    /// let secure = SecureSeed::from_bytes(&bytes);
    /// ```
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), SEED_SIZE, "Seed must be exactly 32 bytes");
        let mut seed = [0u8; SEED_SIZE];
        seed.copy_from_slice(bytes);
        Self(seed)
    }

    /// Try to create from a byte slice
    ///
    /// Returns None if the slice is not exactly 32 bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cardano_crypto::seed::SecureSeed;
    ///
    /// assert!(SecureSeed::try_from_bytes(&[0u8; 32]).is_some());
    /// assert!(SecureSeed::try_from_bytes(&[0u8; 31]).is_none());
    /// ```
    #[must_use]
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SEED_SIZE {
            return None;
        }
        let mut seed = [0u8; SEED_SIZE];
        seed.copy_from_slice(bytes);
        Some(Self(seed))
    }

    /// Get the seed bytes
    ///
    /// # Example
    ///
    /// ```rust
    /// use cardano_crypto::seed::SecureSeed;
    ///
    /// let seed = [3u8; 32];
    /// let secure = SecureSeed::new(seed);
    /// assert_eq!(secure.as_bytes(), &seed);
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SEED_SIZE] {
        &self.0
    }

    /// Convert to raw seed (consumes self and zeroizes)
    ///
    /// This extracts the inner seed and returns ownership.
    /// The SecureSeed wrapper is consumed but NOT zeroized
    /// since the data is being returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cardano_crypto::seed::SecureSeed;
    ///
    /// let seed = [4u8; 32];
    /// let secure = SecureSeed::new(seed);
    /// let extracted = secure.into_seed();
    /// assert_eq!(extracted, seed);
    /// ```
    #[must_use]
    pub fn into_seed(mut self) -> Seed {
        let seed = self.0;
        // Prevent the Drop implementation from zeroizing since we're returning the data
        self.0 = [0u8; SEED_SIZE];
        seed
    }

    /// Expand this seed into two child seeds
    ///
    /// Uses domain separation to derive two independent seeds from this parent.
    /// This matches Cardano's seed expansion pattern.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cardano_crypto::seed::SecureSeed;
    ///
    /// let parent = SecureSeed::new([5u8; 32]);
    /// let (child0, child1) = parent.expand();
    /// assert_ne!(child0.as_bytes(), child1.as_bytes());
    /// ```
    #[must_use]
    pub fn expand(&self) -> (SecureSeed, SecureSeed) {
        let seed0 = expand_seed(&self.0, 0);
        let seed1 = expand_seed(&self.0, 1);
        (SecureSeed::new(seed0), SecureSeed::new(seed1))
    }
}

impl core::fmt::Debug for SecureSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecureSeed([REDACTED])")
    }
}

impl PartialEq for SecureSeed {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SecureSeed {}

// ============================================================================
// Seed Derivation Functions
// ============================================================================

/// Generate a deterministic seed from input data using Blake2b-256
///
/// Derives a cryptographically secure 32-byte seed from arbitrary input data.
/// This function uses Blake2b-256 hash to ensure uniform distribution of the
/// output regardless of the input structure.
///
/// # Use Cases
///
/// - Converting mnemonics or passwords to seeds
/// - Deriving seeds from master secrets
/// - Creating deterministic test seeds for reproducible testing
///
/// # Security Warning
///
/// The security of the derived seed depends entirely on the entropy of the input.
/// Do not use predictable or low-entropy inputs (like simple passwords) for
/// production cryptographic keys.
///
/// # Examples
///
/// ```
/// use cardano_crypto::seed::derive_seed;
///
/// let mnemonic = b"example mnemonic phrase with high entropy";
/// let seed = derive_seed(mnemonic);
/// assert_eq!(seed.len(), 32);
/// ```
///
/// # Parameters
///
/// * `data` - Input data to hash (should have sufficient entropy for security)
///
/// # Returns
///
/// A deterministic 32-byte seed derived from the input
pub fn derive_seed(data: &[u8]) -> Seed {
    use crate::hash::{Blake2b256, HashAlgorithm};

    let hash = Blake2b256::hash(data);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash);
    seed
}

/// Expand a parent seed into a child seed using hierarchical derivation
///
/// Implements a simple hierarchical deterministic (HD) key derivation scheme.
/// Given a parent seed and an index, this function deterministically generates
/// a child seed using domain separation to ensure independence between children.
///
/// # Derivation Scheme
///
/// The child seed is derived as: `Blake2b256(parent_seed || index)`
/// where `||` denotes concatenation and the index is encoded as big-endian u32.
///
/// # Use Cases
///
/// - Creating multiple independent keys from a single master seed
/// - Implementing BIP32-style HD wallets
/// - Separating keys by purpose (signing, encryption, etc.)
/// - Generating per-period keys in KES schemes
///
/// # Security Properties
///
/// - Different indices produce independent, uncorrelated seeds
/// - Knowledge of a child seed does not reveal the parent seed (one-way function)
/// - Supports up to 2^32 child seeds from a single parent
///
/// # Examples
///
/// ```
/// use cardano_crypto::seed::{derive_seed, expand_seed};
///
/// let master_seed = derive_seed(b"high entropy master secret");
/// let child_0 = expand_seed(&master_seed, 0);
/// let child_1 = expand_seed(&master_seed, 1);
///
/// // Child seeds are independent
/// assert_ne!(child_0, child_1);
/// assert_eq!(child_0.len(), 32);
/// ```
///
/// # Parameters
///
/// * `parent` - Parent seed to derive from (32 bytes)
/// * `index` - Derivation index (0 to 2^32-1)
///
/// # Returns
///
/// A deterministic 32-byte child seed
pub fn expand_seed(parent: &Seed, index: u32) -> Seed {
    use crate::hash::{Blake2b256, HashAlgorithm};

    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(parent);
    data.extend_from_slice(&index.to_be_bytes());

    let hash = Blake2b256::hash(&data);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash);
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_seed() {
        let data = b"test data";
        let seed1 = derive_seed(data);
        let seed2 = derive_seed(data);

        // Should be deterministic
        assert_eq!(seed1, seed2);

        // Different input should give different seed
        let seed3 = derive_seed(b"different data");
        assert_ne!(seed1, seed3);
    }

    #[test]
    fn test_expand_seed() {
        let parent = [42u8; 32];

        let child0 = expand_seed(&parent, 0);
        let child1 = expand_seed(&parent, 1);
        let child2 = expand_seed(&parent, 2);

        // Children should be different
        assert_ne!(child0, child1);
        assert_ne!(child1, child2);
        assert_ne!(child0, child2);

        // Should be deterministic
        assert_eq!(child0, expand_seed(&parent, 0));
        assert_eq!(child1, expand_seed(&parent, 1));
    }
}
