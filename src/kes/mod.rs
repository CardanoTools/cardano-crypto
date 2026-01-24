//! Key Evolving Signatures (KES)
//!
//! This module provides KES implementations following the paper:
//! "Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures"
//! by Malkin, Micciancio, and Miner.
//!
//! Implementations:
//! - SingleKES - Single-period signature (base case)
//! - Sum0Kes through Sum7Kes - Binary tree composition (2^0 to 2^7 periods)
//! - CompactSum variants - Optimized signatures with smaller size
//!
//! # Examples
//!
//! ```
//! use cardano_crypto::kes::{Sum6Kes, KesAlgorithm};
//!
//! // Generate a key for 64 periods (2^6)
//! let seed = [0u8; 32];
//! let mut signing_key = Sum6Kes::gen_key_kes_from_seed_bytes(&seed).unwrap();
//! let verification_key = Sum6Kes::derive_verification_key(&signing_key).unwrap();
//!
//! // Sign at period 0
//! let message = b"Block data for period 0";
//! let signature = Sum6Kes::sign_kes(&(), 0, message, &signing_key).unwrap();
//!
//! // Verify signature
//! assert!(Sum6Kes::verify_kes(&(), &verification_key, 0, message, &signature).is_ok());
//!
//! // Evolve key to period 1
//! signing_key = Sum6Kes::update_kes(&(), signing_key, 0).unwrap().unwrap();
//!
//! // Sign at period 1
//! let message1 = b"Block data for period 1";
//! let signature1 = Sum6Kes::sign_kes(&(), 1, message1, &signing_key).unwrap();
//! assert!(Sum6Kes::verify_kes(&(), &verification_key, 1, message1, &signature1).is_ok());
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::common::error::Result;

pub mod hash;
pub mod single;
pub mod sum;
pub mod test_vectors;

pub use hash::{Blake2b224, Blake2b256, Blake2b512, KesHashAlgorithm};
pub use single::{CompactSingleKes, CompactSingleSig, OptimizedKesSignature, SingleKes};
pub use sum::{
    CompactSum0Kes, CompactSum1Kes, CompactSum2Kes, CompactSum3Kes, CompactSum4Kes, CompactSum5Kes,
    CompactSum6Kes, CompactSum7Kes, CompactSumKes, Sum0Kes, Sum1Kes, Sum2Kes, Sum3Kes, Sum4Kes,
    Sum5Kes, Sum6Kes, Sum7Kes, SumKes,
};

/// KES period type (0 to 2^N - 1)
///
/// # Example
///
/// ```rust
/// use cardano_crypto::kes::Period;
///
/// let period: Period = 42;
/// assert_eq!(period, 42u64);
/// ```
pub type Period = u64;

/// KES-specific errors
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::kes::KesError;
///
/// let err = KesError::PeriodOutOfRange { period: 100, max_period: 63 };
/// let s = format!("{}", err);
/// assert!(s.contains("100"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KesError {
    /// Period out of valid range
    PeriodOutOfRange {
        /// Current period
        period: Period,
        /// Maximum allowed period
        max_period: Period,
    },
    /// Key has expired
    KeyExpired,
    /// Verification failed
    VerificationFailed,
    /// Invalid seed length
    InvalidSeedLength {
        /// Expected seed length
        expected: usize,
        /// Actual seed length provided
        actual: usize,
    },
    /// Key update failed
    UpdateFailed,
}

impl core::fmt::Display for KesError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PeriodOutOfRange { period, max_period } => {
                write!(f, "Period {} out of range (max: {})", period, max_period)
            }
            Self::KeyExpired => write!(f, "KES key has expired"),
            Self::VerificationFailed => write!(f, "KES signature verification failed"),
            Self::InvalidSeedLength { expected, actual } => {
                write!(
                    f,
                    "Invalid seed length: expected {} bytes, got {}",
                    expected, actual
                )
            }
            Self::UpdateFailed => write!(f, "KES key update failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KesError {}

/// Trait for KES algorithms
///
/// Follows the design from "Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures"
/// by Tal Malkin, Daniele Micciancio, and Sara Miner (<https://eprint.iacr.org/2001/034>).
pub trait KesAlgorithm {
    /// Verification key type
    type VerificationKey;
    /// Signing key type
    type SigningKey;
    /// Signature type
    type Signature;
    /// Context type (usually () for most implementations)
    type Context;

    /// Algorithm name
    const ALGORITHM_NAME: &'static str;
    /// Seed size in bytes
    const SEED_SIZE: usize;
    /// Verification key size in bytes
    const VERIFICATION_KEY_SIZE: usize;
    /// Signing key size in bytes
    const SIGNING_KEY_SIZE: usize;
    /// Signature size in bytes
    const SIGNATURE_SIZE: usize;

    /// Total number of periods this KES scheme supports
    fn total_periods() -> Period;

    /// Generate signing key from seed bytes
    fn gen_key_kes_from_seed_bytes(seed: &[u8]) -> Result<Self::SigningKey>;

    /// Derive verification key from signing key
    fn derive_verification_key(signing_key: &Self::SigningKey) -> Result<Self::VerificationKey>;

    /// Generate a KES keypair from seed bytes
    ///
    /// Convenience method that combines `gen_key_kes_from_seed_bytes` and `derive_verification_key`.
    ///
    /// # Arguments
    ///
    /// * `seed` - 32-byte seed for key generation
    ///
    /// # Returns
    ///
    /// Tuple of (signing_key, verification_key)
    ///
    /// # Example
    ///
    /// ```
    /// use cardano_crypto::kes::{Sum6Kes, KesAlgorithm};
    ///
    /// let seed = [42u8; 32];
    /// let (sk, vk) = Sum6Kes::keygen(&seed).unwrap();
    /// ```
    fn keygen(seed: &[u8]) -> Result<(Self::SigningKey, Self::VerificationKey)> {
        let signing_key = Self::gen_key_kes_from_seed_bytes(seed)?;
        let verification_key = Self::derive_verification_key(&signing_key)?;
        Ok((signing_key, verification_key))
    }

    /// Sign a message at a specific period
    fn sign_kes(
        context: &Self::Context,
        period: Period,
        message: &[u8],
        signing_key: &Self::SigningKey,
    ) -> Result<Self::Signature>;

    /// Verify a signature at a specific period
    fn verify_kes(
        context: &Self::Context,
        verification_key: &Self::VerificationKey,
        period: Period,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<()>;

    /// Update signing key to next period (returns None if key expired)
    fn update_kes(
        context: &Self::Context,
        signing_key: Self::SigningKey,
        period: Period,
    ) -> Result<Option<Self::SigningKey>>;

    /// Serialize verification key
    #[cfg(feature = "alloc")]
    fn raw_serialize_verification_key_kes(key: &Self::VerificationKey) -> Vec<u8>;

    /// Deserialize verification key
    fn raw_deserialize_verification_key_kes(bytes: &[u8]) -> Option<Self::VerificationKey>;

    /// Serialize signature
    #[cfg(feature = "alloc")]
    fn raw_serialize_signature_kes(signature: &Self::Signature) -> Vec<u8>;

    /// Deserialize signature
    fn raw_deserialize_signature_kes(bytes: &[u8]) -> Option<Self::Signature>;

    /// Securely forget/zeroize signing key
    fn forget_signing_key_kes(signing_key: Self::SigningKey);

    /// Hash a verification key
    ///
    /// This corresponds to `hashVerKeyKES` in cardano-base. The default
    /// implementation uses the raw serialization of the verification key.
    ///
    /// # Type Parameters
    ///
    /// - `H`: The hash algorithm to use
    ///
    /// # Example
    ///
    /// ```
    /// use cardano_crypto::kes::{Sum6Kes, KesAlgorithm};
    /// use cardano_crypto::hash::{Blake2b256, HashAlgorithm};
    ///
    /// let seed = [42u8; 32];
    /// let signing_key = Sum6Kes::gen_key_kes_from_seed_bytes(&seed).unwrap();
    /// let vk = Sum6Kes::derive_verification_key(&signing_key).unwrap();
    /// let hash = Sum6Kes::hash_verification_key::<Blake2b256>(&vk);
    /// assert_eq!(hash.len(), 32);
    /// ```
    #[cfg(feature = "alloc")]
    fn hash_verification_key<H: crate::hash::HashAlgorithm>(
        key: &Self::VerificationKey,
    ) -> Vec<u8> {
        let raw = Self::raw_serialize_verification_key_kes(key);
        H::hash(&raw)
    }
}

// ============================================================================
// SignedKES wrapper
// ============================================================================

/// A value signed with KES at a specific period
///
/// Matches Cardano's `SignedKES v a` type from cardano-crypto-class.
/// Associates a KES signature with the period at which it was created.
///
/// # Type Parameters
///
/// - `K`: The KES algorithm type
///
/// # Examples
///
/// ```
/// use cardano_crypto::kes::{Sum6Kes, KesAlgorithm, SignedKes};
///
/// let seed = [42u8; 32];
/// let signing_key = Sum6Kes::gen_key_kes_from_seed_bytes(&seed).unwrap();
/// let verification_key = Sum6Kes::derive_verification_key(&signing_key).unwrap();
///
/// let message = b"Block data";
/// let period = 0u64;
///
/// // Sign using SignedKes wrapper
/// let signed = SignedKes::<Sum6Kes>::sign(&(), period, message, &signing_key).unwrap();
///
/// // Verify
/// assert!(signed.verify(&(), &verification_key, period, message).is_ok());
/// ```
pub struct SignedKes<K: KesAlgorithm> {
    /// The KES signature
    pub signature: K::Signature,
}

impl<K: KesAlgorithm> core::fmt::Debug for SignedKes<K>
where
    K::Signature: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedKes")
            .field("signature", &self.signature)
            .finish()
    }
}

impl<K: KesAlgorithm> Clone for SignedKes<K>
where
    K::Signature: Clone,
{
    fn clone(&self) -> Self {
        Self {
            signature: self.signature.clone(),
        }
    }
}

impl<K: KesAlgorithm> SignedKes<K> {
    /// Sign a message with KES at the given period
    ///
    /// Corresponds to `signedKES` in cardano-crypto-class.
    ///
    /// # Parameters
    ///
    /// * `context` - Algorithm context
    /// * `period` - Current KES period
    /// * `message` - Message to sign
    /// * `signing_key` - KES signing key
    ///
    /// # Returns
    ///
    /// A `SignedKes` containing the signature
    pub fn sign(
        context: &K::Context,
        period: Period,
        message: &[u8],
        signing_key: &K::SigningKey,
    ) -> Result<Self> {
        let signature = K::sign_kes(context, period, message, signing_key)?;
        Ok(Self { signature })
    }

    /// Verify this SignedKes
    ///
    /// Corresponds to `verifySignedKES` in cardano-crypto-class.
    ///
    /// # Parameters
    ///
    /// * `context` - Algorithm context
    /// * `verification_key` - KES verification key
    /// * `period` - Period at which message was signed
    /// * `message` - Original message
    ///
    /// # Returns
    ///
    /// * `Ok(())` if verification succeeds
    /// * `Err(...)` if verification fails
    pub fn verify(
        &self,
        context: &K::Context,
        verification_key: &K::VerificationKey,
        period: Period,
        message: &[u8],
    ) -> Result<()> {
        K::verify_kes(context, verification_key, period, message, &self.signature)
    }

    /// Get the underlying signature
    pub fn get_signature(&self) -> &K::Signature {
        &self.signature
    }

    /// Create from a raw signature
    pub fn from_signature(signature: K::Signature) -> Self {
        Self { signature }
    }
}

// ============================================================================
// SignKeyWithPeriodKES - Sign key bundled with its period
// ============================================================================

/// A KES signing key bundled with its current period
///
/// Matches Cardano's `SignKeyWithPeriodKES v` type.
/// Useful for tracking the current period alongside the key.
///
/// # Example
///
/// ```
/// use cardano_crypto::kes::{Sum6Kes, KesAlgorithm, SignKeyWithPeriodKes};
///
/// let seed = [42u8; 32];
/// let signing_key = Sum6Kes::gen_key_kes_from_seed_bytes(&seed).unwrap();
///
/// let mut keyed = SignKeyWithPeriodKes::<Sum6Kes>::new(signing_key, 0);
/// assert_eq!(keyed.period(), 0);
/// ```
pub struct SignKeyWithPeriodKes<K: KesAlgorithm> {
    /// The signing key
    pub signing_key: K::SigningKey,
    /// Current period for this key
    pub period: Period,
}

impl<K: KesAlgorithm> core::fmt::Debug for SignKeyWithPeriodKes<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignKeyWithPeriodKes")
            .field("signing_key", &"<redacted>")
            .field("period", &self.period)
            .finish()
    }
}

impl<K: KesAlgorithm> SignKeyWithPeriodKes<K> {
    /// Create a new sign key with period
    pub fn new(signing_key: K::SigningKey, period: Period) -> Self {
        Self {
            signing_key,
            period,
        }
    }

    /// Get the current period
    pub fn period(&self) -> Period {
        self.period
    }

    /// Get a reference to the signing key
    pub fn signing_key(&self) -> &K::SigningKey {
        &self.signing_key
    }

    /// Update the key to the next period
    ///
    /// Returns `Ok(Some(self))` if update succeeded,
    /// `Ok(None)` if key has expired.
    pub fn update(self, context: &K::Context) -> Result<Option<Self>> {
        let current = self.period;
        match K::update_kes(context, self.signing_key, current)? {
            Some(new_key) => Ok(Some(Self {
                signing_key: new_key,
                period: current + 1,
            })),
            None => Ok(None),
        }
    }
}

// ============================================================================
// Cardano-node compatible type aliases
// ============================================================================

/// KES signing key type (matches cardano-node's `KesSigningKey`)
///
/// This is a generic alias for a KES signing key. For concrete types,
/// use `Sum6Kes::SigningKey` directly.
pub type KesSigningKey<K> = <K as KesAlgorithm>::SigningKey;

/// KES verification key type (matches cardano-node's `KesVerificationKey`)
///
/// This is a generic alias for a KES verification key.
pub type KesVerificationKey<K> = <K as KesAlgorithm>::VerificationKey;

/// KES signature type
///
/// This is a generic alias for a KES signature.
pub type KesSignature<K> = <K as KesAlgorithm>::Signature;

/// KES key pair (matches cardano-node's `KeyPair KesKey`)
///
/// Contains both the signing key (with period) and verification key.
///
/// # Type Parameters
///
/// - `K`: The KES algorithm type (e.g., `Sum6Kes`)
///
/// # Example
///
/// ```
/// use cardano_crypto::kes::{Sum6Kes, KesAlgorithm, KesKeyPair};
///
/// let seed = [42u8; 32];
/// let keypair = KesKeyPair::<Sum6Kes>::generate(&seed).unwrap();
///
/// let message = b"test";
/// let signature = Sum6Kes::sign_kes(&(), keypair.period(), message, keypair.signing_key()).unwrap();
/// assert!(Sum6Kes::verify_kes(&(), &keypair.verification_key, keypair.period(), message, &signature).is_ok());
/// ```
pub struct KesKeyPair<K: KesAlgorithm> {
    /// The KES signing key with period tracking
    pub signing_key_with_period: SignKeyWithPeriodKes<K>,
    /// The KES verification key
    pub verification_key: K::VerificationKey,
}

impl<K: KesAlgorithm> core::fmt::Debug for KesKeyPair<K>
where
    K::VerificationKey: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KesKeyPair")
            .field("signing_key", &"<redacted>")
            .field("period", &self.signing_key_with_period.period)
            .field("verification_key", &self.verification_key)
            .finish()
    }
}

impl<K: KesAlgorithm> KesKeyPair<K> {
    /// Generate a KES key pair from a seed (starts at period 0)
    pub fn generate(seed: &[u8]) -> Result<Self> {
        let signing_key = K::gen_key_kes_from_seed_bytes(seed)?;
        let verification_key = K::derive_verification_key(&signing_key)?;
        Ok(Self {
            signing_key_with_period: SignKeyWithPeriodKes::new(signing_key, 0),
            verification_key,
        })
    }

    /// Get the current period
    pub fn period(&self) -> Period {
        self.signing_key_with_period.period()
    }

    /// Get a reference to the signing key
    pub fn signing_key(&self) -> &K::SigningKey {
        self.signing_key_with_period.signing_key()
    }

    /// Update the key pair to the next period
    ///
    /// Returns `Ok(Some(self))` if update succeeded,
    /// `Ok(None)` if key has expired.
    pub fn update(self, context: &K::Context) -> Result<Option<Self>> {
        match self.signing_key_with_period.update(context)? {
            Some(new_sk) => Ok(Some(Self {
                signing_key_with_period: new_sk,
                verification_key: self.verification_key,
            })),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_period_type() {
        let period: Period = 42;
        assert_eq!(period, 42u64);
    }
}
