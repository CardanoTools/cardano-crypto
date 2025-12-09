//! Bech32 encoding and decoding for Cardano keys
//!
//! This module provides full Bech32 encoding/decoding functionality matching
//! the Haskell `bech32` library used by cardano-node. It wraps the `bech32` crate
//! and provides Cardano-specific helper functions.
//!
//! # Overview
//!
//! Bech32 is a human-readable encoding format defined in BIP-0173. It consists of:
//! - A **human-readable part (HRP)** identifying the data type (e.g., `vrf_vk`)
//! - A **separator** character `1`
//! - A **data part** encoded in base32 using a specific character set
//! - A **checksum** for error detection
//!
//! # Cardano Key Encoding
//!
//! Cardano uses standard prefixes for different key types:
//!
//! | Key Type | Verification Key | Signing Key |
//! |----------|-----------------|-------------|
//! | Payment | `addr_vk` | `addr_sk` |
//! | Stake | `stake_vk` | `stake_sk` |
//! | Pool | `pool_vk` | `pool_sk` |
//! | VRF | `vrf_vk` | `vrf_sk` |
//! | KES | `kes_vk` | `kes_sk` |
//!
//! # Length Limitations
//!
//! Standard Bech32 encoding has a maximum encoded length of 90 characters,
//! which limits the data payload to approximately 50-55 bytes depending on HRP length.
//! For larger keys (e.g., KES signing keys which can be 600+ bytes), use
//! the TextEnvelope format with hex encoding instead.
//!
//! # Examples
//!
//! ```rust
//! use cardano_crypto::key::encoding::{encode_to_bech32, decode_from_bech32};
//!
//! // Encode a 32-byte verification key
//! let vk = [0u8; 32];
//! let encoded = encode_to_bech32("vrf_vk", &vk).unwrap();
//! assert!(encoded.starts_with("vrf_vk1"));
//!
//! // Decode back
//! let (hrp, decoded) = decode_from_bech32(&encoded).unwrap();
//! assert_eq!(hrp, "vrf_vk");
//! assert_eq!(decoded, vk);
//! ```
//!
//! # Compatibility
//!
//! This implementation is fully compatible with:
//! - `Codec.Binary.Bech32` from the Haskell `bech32` package
//! - `cardano-api` key serialization
//! - `cardano-cli` key file formats

use alloc::string::String;
use alloc::vec::Vec;

use bech32::{Bech32, Hrp};

use super::bech32 as prefixes;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during Bech32 encoding/decoding
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bech32Error {
    /// The human-readable part is invalid
    InvalidHrp(String),
    /// The encoded string is invalid
    InvalidEncoding(String),
    /// The data part is invalid
    InvalidData(String),
    /// The checksum verification failed
    ChecksumError,
    /// The decoded data has unexpected length
    UnexpectedLength {
        /// Expected length in bytes
        expected: usize,
        /// Actual length in bytes
        actual: usize,
    },
    /// The HRP doesn't match the expected value
    HrpMismatch {
        /// Expected HRP
        expected: String,
        /// Actual HRP found
        actual: String,
    },
}

impl core::fmt::Display for Bech32Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidHrp(s) => write!(f, "Invalid human-readable part: {}", s),
            Self::InvalidEncoding(s) => write!(f, "Invalid Bech32 encoding: {}", s),
            Self::InvalidData(s) => write!(f, "Invalid data: {}", s),
            Self::ChecksumError => write!(f, "Bech32 checksum verification failed"),
            Self::UnexpectedLength { expected, actual } => {
                write!(
                    f,
                    "Unexpected data length: expected {} bytes, got {}",
                    expected, actual
                )
            }
            Self::HrpMismatch { expected, actual } => {
                write!(f, "HRP mismatch: expected '{}', got '{}'", expected, actual)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Bech32Error {}

/// Result type for Bech32 operations
pub type Bech32Result<T> = core::result::Result<T, Bech32Error>;

// =============================================================================
// Core Encoding/Decoding Functions
// =============================================================================

/// Encode bytes to a Bech32 string with the given human-readable prefix
///
/// This function encodes arbitrary bytes into a Bech32 string using the
/// standard Bech32 checksum (not Bech32m).
///
/// # Arguments
///
/// * `hrp` - Human-readable prefix (e.g., "vrf_vk", "addr_sk")
/// * `data` - Raw bytes to encode
///
/// # Returns
///
/// A Bech32-encoded string
///
/// # Errors
///
/// Returns an error if the HRP is invalid or encoding fails
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::encoding::encode_to_bech32;
///
/// let key = [1u8; 32];
/// let encoded = encode_to_bech32("vrf_vk", &key).unwrap();
/// assert!(encoded.starts_with("vrf_vk1"));
/// ```
#[inline]
pub fn encode_to_bech32(hrp: &str, data: &[u8]) -> Bech32Result<String> {
    let hrp = Hrp::parse(hrp).map_err(|e| Bech32Error::InvalidHrp(e.to_string()))?;

    bech32::encode::<Bech32>(hrp, data).map_err(|e| Bech32Error::InvalidEncoding(e.to_string()))
}

/// Decode a Bech32 string into its HRP and data bytes
///
/// This function decodes a Bech32-encoded string and returns both the
/// human-readable prefix and the decoded bytes.
///
/// # Arguments
///
/// * `encoded` - Bech32-encoded string
///
/// # Returns
///
/// A tuple of (hrp, decoded_bytes)
///
/// # Errors
///
/// Returns an error if the string is not valid Bech32
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::encoding::{encode_to_bech32, decode_from_bech32};
///
/// let key = [1u8; 32];
/// let encoded = encode_to_bech32("vrf_vk", &key).unwrap();
///
/// let (hrp, decoded) = decode_from_bech32(&encoded).unwrap();
/// assert_eq!(hrp, "vrf_vk");
/// assert_eq!(decoded, key);
/// ```
#[inline]
pub fn decode_from_bech32(encoded: &str) -> Bech32Result<(String, Vec<u8>)> {
    let (hrp, data) =
        bech32::decode(encoded).map_err(|e| Bech32Error::InvalidEncoding(e.to_string()))?;

    Ok((hrp.to_string(), data))
}

/// Decode a Bech32 string and verify the HRP matches expected
///
/// This is a stricter version of `decode_from_bech32` that also validates
/// the human-readable prefix matches the expected value.
///
/// # Arguments
///
/// * `encoded` - Bech32-encoded string
/// * `expected_hrp` - Expected human-readable prefix
///
/// # Returns
///
/// The decoded bytes if HRP matches
///
/// # Errors
///
/// Returns an error if decoding fails or HRP doesn't match
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::encoding::{encode_to_bech32, decode_with_hrp};
///
/// let key = [1u8; 32];
/// let encoded = encode_to_bech32("vrf_vk", &key).unwrap();
///
/// // This succeeds
/// let decoded = decode_with_hrp(&encoded, "vrf_vk").unwrap();
/// assert_eq!(decoded, key);
///
/// // This fails - wrong HRP
/// let result = decode_with_hrp(&encoded, "kes_vk");
/// assert!(result.is_err());
/// ```
#[inline]
pub fn decode_with_hrp(encoded: &str, expected_hrp: &str) -> Bech32Result<Vec<u8>> {
    let (hrp, data) = decode_from_bech32(encoded)?;

    if hrp != expected_hrp {
        return Err(Bech32Error::HrpMismatch {
            expected: expected_hrp.to_string(),
            actual: hrp,
        });
    }

    Ok(data)
}

/// Decode a Bech32 string into a fixed-size array
///
/// This function decodes and validates that the result has the expected length.
///
/// # Arguments
///
/// * `encoded` - Bech32-encoded string
/// * `expected_hrp` - Expected human-readable prefix
///
/// # Returns
///
/// The decoded bytes as a fixed-size array
///
/// # Errors
///
/// Returns an error if decoding fails, HRP doesn't match, or length is wrong
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::encoding::{encode_to_bech32, decode_to_array};
///
/// let key = [1u8; 32];
/// let encoded = encode_to_bech32("vrf_vk", &key).unwrap();
///
/// let decoded: [u8; 32] = decode_to_array(&encoded, "vrf_vk").unwrap();
/// assert_eq!(decoded, key);
/// ```
#[inline]
pub fn decode_to_array<const N: usize>(encoded: &str, expected_hrp: &str) -> Bech32Result<[u8; N]> {
    let data = decode_with_hrp(encoded, expected_hrp)?;

    if data.len() != N {
        return Err(Bech32Error::UnexpectedLength {
            expected: N,
            actual: data.len(),
        });
    }

    let mut result = [0u8; N];
    result.copy_from_slice(&data);
    Ok(result)
}

// =============================================================================
// Payment Key Encoding
// =============================================================================

/// Encode a payment verification key to Bech32
///
/// # Arguments
///
/// * `vk` - 32-byte Ed25519 verification key
///
/// # Returns
///
/// Bech32-encoded string with prefix `addr_vk`
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::encoding::encode_payment_verification_key;
///
/// let vk = [0u8; 32];
/// let encoded = encode_payment_verification_key(&vk).unwrap();
/// assert!(encoded.starts_with("addr_vk1"));
/// ```
pub fn encode_payment_verification_key(vk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::PAYMENT_VERIFICATION_KEY_PREFIX, vk)
}

/// Decode a payment verification key from Bech32
///
/// # Arguments
///
/// * `encoded` - Bech32-encoded string with prefix `addr_vk`
///
/// # Returns
///
/// 32-byte Ed25519 verification key
pub fn decode_payment_verification_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::PAYMENT_VERIFICATION_KEY_PREFIX)
}

/// Encode a payment signing key to Bech32
///
/// # Arguments
///
/// * `sk` - 32-byte Ed25519 signing key seed
///
/// # Returns
///
/// Bech32-encoded string with prefix `addr_sk`
pub fn encode_payment_signing_key(sk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::PAYMENT_SIGNING_KEY_PREFIX, sk)
}

/// Decode a payment signing key from Bech32
pub fn decode_payment_signing_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::PAYMENT_SIGNING_KEY_PREFIX)
}

// =============================================================================
// Stake Key Encoding
// =============================================================================

/// Encode a stake verification key to Bech32
///
/// # Arguments
///
/// * `vk` - 32-byte Ed25519 verification key
///
/// # Returns
///
/// Bech32-encoded string with prefix `stake_vk`
pub fn encode_stake_verification_key(vk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::STAKE_VERIFICATION_KEY_PREFIX, vk)
}

/// Decode a stake verification key from Bech32
pub fn decode_stake_verification_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::STAKE_VERIFICATION_KEY_PREFIX)
}

/// Encode a stake signing key to Bech32
pub fn encode_stake_signing_key(sk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::STAKE_SIGNING_KEY_PREFIX, sk)
}

/// Decode a stake signing key from Bech32
pub fn decode_stake_signing_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::STAKE_SIGNING_KEY_PREFIX)
}

// =============================================================================
// Pool Key Encoding
// =============================================================================

/// Encode a pool verification key (cold key) to Bech32
///
/// # Arguments
///
/// * `vk` - 32-byte Ed25519 verification key
///
/// # Returns
///
/// Bech32-encoded string with prefix `pool_vk`
pub fn encode_pool_verification_key(vk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::POOL_VERIFICATION_KEY_PREFIX, vk)
}

/// Decode a pool verification key from Bech32
pub fn decode_pool_verification_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::POOL_VERIFICATION_KEY_PREFIX)
}

/// Encode a pool signing key (cold key) to Bech32
pub fn encode_pool_signing_key(sk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::POOL_SIGNING_KEY_PREFIX, sk)
}

/// Decode a pool signing key from Bech32
pub fn decode_pool_signing_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::POOL_SIGNING_KEY_PREFIX)
}

// =============================================================================
// VRF Key Encoding
// =============================================================================

/// Encode a VRF verification key to Bech32
///
/// # Arguments
///
/// * `vk` - 32-byte VRF verification key
///
/// # Returns
///
/// Bech32-encoded string with prefix `vrf_vk`
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::encoding::encode_vrf_verification_key;
///
/// let vk = [0u8; 32];
/// let encoded = encode_vrf_verification_key(&vk).unwrap();
/// assert!(encoded.starts_with("vrf_vk1"));
/// ```
pub fn encode_vrf_verification_key(vk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::VRF_VERIFICATION_KEY_PREFIX, vk)
}

/// Decode a VRF verification key from Bech32
///
/// # Arguments
///
/// * `encoded` - Bech32-encoded string with prefix `vrf_vk`
///
/// # Returns
///
/// 32-byte VRF verification key
pub fn decode_vrf_verification_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::VRF_VERIFICATION_KEY_PREFIX)
}

/// Encode a VRF signing key to Bech32
///
/// Note: VRF signing keys are 64 bytes (32-byte seed + 32-byte public key)
/// but Cardano typically stores only the 32-byte seed.
///
/// # Arguments
///
/// * `sk` - 32-byte VRF signing key seed
///
/// # Returns
///
/// Bech32-encoded string with prefix `vrf_sk`
pub fn encode_vrf_signing_key(sk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::VRF_SIGNING_KEY_PREFIX, sk)
}

/// Decode a VRF signing key from Bech32
pub fn decode_vrf_signing_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::VRF_SIGNING_KEY_PREFIX)
}

/// Encode a VRF signing key (full 64-byte format) to Bech32
///
/// Some tools use the full 64-byte format which includes both
/// the seed and the derived public key.
pub fn encode_vrf_signing_key_full(sk: &[u8; 64]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::VRF_SIGNING_KEY_PREFIX, sk)
}

/// Decode a VRF signing key (full 64-byte format) from Bech32
pub fn decode_vrf_signing_key_full(encoded: &str) -> Bech32Result<[u8; 64]> {
    decode_to_array(encoded, prefixes::VRF_SIGNING_KEY_PREFIX)
}

// =============================================================================
// KES Key Encoding
// =============================================================================

/// Encode a KES verification key to Bech32
///
/// # Arguments
///
/// * `vk` - 32-byte KES verification key
///
/// # Returns
///
/// Bech32-encoded string with prefix `kes_vk`
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::encoding::encode_kes_verification_key;
///
/// let vk = [0u8; 32];
/// let encoded = encode_kes_verification_key(&vk).unwrap();
/// assert!(encoded.starts_with("kes_vk1"));
/// ```
pub fn encode_kes_verification_key(vk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::KES_VERIFICATION_KEY_PREFIX, vk)
}

/// Decode a KES verification key from Bech32
pub fn decode_kes_verification_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::KES_VERIFICATION_KEY_PREFIX)
}

/// Encode a KES signing key to Bech32
///
/// Note: KES signing keys vary in size depending on the algorithm.
/// For Sum6KES (mainnet), the signing key is 2112 bytes.
///
/// # Arguments
///
/// * `sk` - KES signing key bytes
///
/// # Returns
///
/// Bech32-encoded string with prefix `kes_sk`
pub fn encode_kes_signing_key(sk: &[u8]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::KES_SIGNING_KEY_PREFIX, sk)
}

/// Decode a KES signing key from Bech32
///
/// Returns the raw bytes since KES signing key sizes vary.
pub fn decode_kes_signing_key(encoded: &str) -> Bech32Result<Vec<u8>> {
    decode_with_hrp(encoded, prefixes::KES_SIGNING_KEY_PREFIX)
}

// =============================================================================
// Genesis Key Encoding
// =============================================================================

/// Encode a genesis verification key to Bech32
pub fn encode_genesis_verification_key(vk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::GENESIS_VERIFICATION_KEY_PREFIX, vk)
}

/// Decode a genesis verification key from Bech32
pub fn decode_genesis_verification_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::GENESIS_VERIFICATION_KEY_PREFIX)
}

/// Encode a genesis signing key to Bech32
pub fn encode_genesis_signing_key(sk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::GENESIS_SIGNING_KEY_PREFIX, sk)
}

/// Decode a genesis signing key from Bech32
pub fn decode_genesis_signing_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::GENESIS_SIGNING_KEY_PREFIX)
}

// =============================================================================
// Genesis Delegate Key Encoding
// =============================================================================

/// Encode a genesis delegate verification key to Bech32
pub fn encode_genesis_delegate_verification_key(vk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::GENESIS_DELEGATE_VERIFICATION_KEY_PREFIX, vk)
}

/// Decode a genesis delegate verification key from Bech32
pub fn decode_genesis_delegate_verification_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::GENESIS_DELEGATE_VERIFICATION_KEY_PREFIX)
}

/// Encode a genesis delegate signing key to Bech32
pub fn encode_genesis_delegate_signing_key(sk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::GENESIS_DELEGATE_SIGNING_KEY_PREFIX, sk)
}

/// Decode a genesis delegate signing key from Bech32
pub fn decode_genesis_delegate_signing_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::GENESIS_DELEGATE_SIGNING_KEY_PREFIX)
}

// =============================================================================
// DRep Key Encoding (Governance)
// =============================================================================

/// Encode a DRep verification key to Bech32
pub fn encode_drep_verification_key(vk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::DREP_VERIFICATION_KEY_PREFIX, vk)
}

/// Decode a DRep verification key from Bech32
pub fn decode_drep_verification_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::DREP_VERIFICATION_KEY_PREFIX)
}

/// Encode a DRep signing key to Bech32
pub fn encode_drep_signing_key(sk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::DREP_SIGNING_KEY_PREFIX, sk)
}

/// Decode a DRep signing key from Bech32
pub fn decode_drep_signing_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::DREP_SIGNING_KEY_PREFIX)
}

// =============================================================================
// Committee Key Encoding (Governance)
// =============================================================================

/// Encode a committee cold verification key to Bech32
pub fn encode_committee_cold_verification_key(vk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::COMMITTEE_COLD_VERIFICATION_KEY_PREFIX, vk)
}

/// Decode a committee cold verification key from Bech32
pub fn decode_committee_cold_verification_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::COMMITTEE_COLD_VERIFICATION_KEY_PREFIX)
}

/// Encode a committee cold signing key to Bech32
pub fn encode_committee_cold_signing_key(sk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::COMMITTEE_COLD_SIGNING_KEY_PREFIX, sk)
}

/// Decode a committee cold signing key from Bech32
pub fn decode_committee_cold_signing_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::COMMITTEE_COLD_SIGNING_KEY_PREFIX)
}

/// Encode a committee hot verification key to Bech32
pub fn encode_committee_hot_verification_key(vk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::COMMITTEE_HOT_VERIFICATION_KEY_PREFIX, vk)
}

/// Decode a committee hot verification key from Bech32
pub fn decode_committee_hot_verification_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::COMMITTEE_HOT_VERIFICATION_KEY_PREFIX)
}

/// Encode a committee hot signing key to Bech32
pub fn encode_committee_hot_signing_key(sk: &[u8; 32]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::COMMITTEE_HOT_SIGNING_KEY_PREFIX, sk)
}

/// Decode a committee hot signing key from Bech32
pub fn decode_committee_hot_signing_key(encoded: &str) -> Bech32Result<[u8; 32]> {
    decode_to_array(encoded, prefixes::COMMITTEE_HOT_SIGNING_KEY_PREFIX)
}

// =============================================================================
// Key Hash Encoding
// =============================================================================

/// Encode a pool key hash (pool ID) to Bech32
///
/// # Arguments
///
/// * `hash` - 28-byte Blake2b-224 hash of pool verification key
///
/// # Returns
///
/// Bech32-encoded string with prefix `pool`
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::encoding::encode_pool_id;
///
/// let pool_hash = [0u8; 28];
/// let encoded = encode_pool_id(&pool_hash).unwrap();
/// assert!(encoded.starts_with("pool1"));
/// ```
pub fn encode_pool_id(hash: &[u8; 28]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::POOL_HASH_PREFIX, hash)
}

/// Decode a pool ID from Bech32
pub fn decode_pool_id(encoded: &str) -> Bech32Result<[u8; 28]> {
    decode_to_array(encoded, prefixes::POOL_HASH_PREFIX)
}

/// Encode a verification key hash to Bech32
///
/// # Arguments
///
/// * `hash` - 28-byte Blake2b-224 hash of verification key
///
/// # Returns
///
/// Bech32-encoded string with prefix `addr_vkh`
pub fn encode_verification_key_hash(hash: &[u8; 28]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::VERIFICATION_KEY_HASH_PREFIX, hash)
}

/// Decode a verification key hash from Bech32
pub fn decode_verification_key_hash(encoded: &str) -> Bech32Result<[u8; 28]> {
    decode_to_array(encoded, prefixes::VERIFICATION_KEY_HASH_PREFIX)
}

/// Encode a stake verification key hash to Bech32
pub fn encode_stake_verification_key_hash(hash: &[u8; 28]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::STAKE_VERIFICATION_KEY_HASH_PREFIX, hash)
}

/// Decode a stake verification key hash from Bech32
pub fn decode_stake_verification_key_hash(encoded: &str) -> Bech32Result<[u8; 28]> {
    decode_to_array(encoded, prefixes::STAKE_VERIFICATION_KEY_HASH_PREFIX)
}

/// Encode a VRF verification key hash to Bech32
pub fn encode_vrf_verification_key_hash(hash: &[u8; 28]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::VRF_VERIFICATION_KEY_HASH_PREFIX, hash)
}

/// Decode a VRF verification key hash from Bech32
pub fn decode_vrf_verification_key_hash(encoded: &str) -> Bech32Result<[u8; 28]> {
    decode_to_array(encoded, prefixes::VRF_VERIFICATION_KEY_HASH_PREFIX)
}

/// Encode a script hash to Bech32
pub fn encode_script_hash(hash: &[u8; 28]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::SCRIPT_HASH_PREFIX, hash)
}

/// Decode a script hash from Bech32
pub fn decode_script_hash(encoded: &str) -> Bech32Result<[u8; 28]> {
    decode_to_array(encoded, prefixes::SCRIPT_HASH_PREFIX)
}

/// Encode a DRep key hash to Bech32
pub fn encode_drep_key_hash(hash: &[u8; 28]) -> Bech32Result<String> {
    encode_to_bech32(prefixes::DREP_KEY_HASH_PREFIX, hash)
}

/// Decode a DRep key hash from Bech32
pub fn decode_drep_key_hash(encoded: &str) -> Bech32Result<[u8; 28]> {
    decode_to_array(encoded, prefixes::DREP_KEY_HASH_PREFIX)
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Check if a string is valid Bech32
///
/// # Arguments
///
/// * `s` - String to validate
///
/// # Returns
///
/// `true` if the string is valid Bech32
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::encoding::{is_valid_bech32, encode_to_bech32};
///
/// // Generate a valid bech32 string for testing
/// let valid = encode_to_bech32("vrf_vk", &[0u8; 32]).unwrap();
/// assert!(is_valid_bech32(&valid));
/// assert!(!is_valid_bech32("invalid"));
/// ```
pub fn is_valid_bech32(s: &str) -> bool {
    bech32::decode(s).is_ok()
}

/// Extract the human-readable prefix from a Bech32 string
///
/// # Arguments
///
/// * `s` - Bech32-encoded string
///
/// # Returns
///
/// The HRP if valid, None otherwise
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::encoding::{get_hrp, encode_to_bech32};
///
/// // Generate a valid bech32 string for testing
/// let encoded = encode_to_bech32("vrf_vk", &[0u8; 32]).unwrap();
/// assert_eq!(get_hrp(&encoded), Some("vrf_vk".to_string()));
/// ```
pub fn get_hrp(s: &str) -> Option<String> {
    bech32::decode(s).ok().map(|(hrp, _)| hrp.to_string())
}

/// Get the separator character used in Bech32 encoding
///
/// This is always '1' as defined by BIP-0173.
pub const SEPARATOR_CHAR: char = '1';

/// Maximum length of a Bech32-encoded string (BIP-0173)
pub const ENCODED_STRING_MAX_LENGTH: usize = 90;

/// Minimum length of a Bech32-encoded string
pub const ENCODED_STRING_MIN_LENGTH: usize = 8; // 1 char HRP + separator + 6 char checksum

/// Length of the Bech32 checksum
pub const CHECKSUM_LENGTH: usize = 6;

/// Minimum length of the human-readable part
pub const HRP_MIN_LENGTH: usize = 1;

/// Maximum length of the human-readable part
pub const HRP_MAX_LENGTH: usize = 83;

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let data = [1u8; 32];
        let encoded = encode_to_bech32("test", &data).unwrap();
        let (hrp, decoded) = decode_from_bech32(&encoded).unwrap();
        assert_eq!(hrp, "test");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_payment_key_roundtrip() {
        let vk = [42u8; 32];
        let encoded = encode_payment_verification_key(&vk).unwrap();
        assert!(encoded.starts_with("addr_vk1"));
        let decoded = decode_payment_verification_key(&encoded).unwrap();
        assert_eq!(decoded, vk);
    }

    #[test]
    fn test_stake_key_roundtrip() {
        let vk = [42u8; 32];
        let encoded = encode_stake_verification_key(&vk).unwrap();
        assert!(encoded.starts_with("stake_vk1"));
        let decoded = decode_stake_verification_key(&encoded).unwrap();
        assert_eq!(decoded, vk);
    }

    #[test]
    fn test_pool_key_roundtrip() {
        let vk = [42u8; 32];
        let encoded = encode_pool_verification_key(&vk).unwrap();
        assert!(encoded.starts_with("pool_vk1"));
        let decoded = decode_pool_verification_key(&encoded).unwrap();
        assert_eq!(decoded, vk);
    }

    #[test]
    fn test_vrf_key_roundtrip() {
        let vk = [42u8; 32];
        let encoded = encode_vrf_verification_key(&vk).unwrap();
        assert!(encoded.starts_with("vrf_vk1"));
        let decoded = decode_vrf_verification_key(&encoded).unwrap();
        assert_eq!(decoded, vk);
    }

    #[test]
    fn test_kes_key_roundtrip() {
        let vk = [42u8; 32];
        let encoded = encode_kes_verification_key(&vk).unwrap();
        assert!(encoded.starts_with("kes_vk1"));
        let decoded = decode_kes_verification_key(&encoded).unwrap();
        assert_eq!(decoded, vk);
    }

    #[test]
    fn test_pool_id_roundtrip() {
        let hash = [42u8; 28];
        let encoded = encode_pool_id(&hash).unwrap();
        assert!(encoded.starts_with("pool1"));
        let decoded = decode_pool_id(&encoded).unwrap();
        assert_eq!(decoded, hash);
    }

    #[test]
    fn test_decode_with_wrong_hrp() {
        let vk = [42u8; 32];
        let encoded = encode_vrf_verification_key(&vk).unwrap();
        let result = decode_with_hrp(&encoded, "kes_vk");
        assert!(matches!(result, Err(Bech32Error::HrpMismatch { .. })));
    }

    #[test]
    fn test_decode_invalid_string() {
        let result = decode_from_bech32("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_valid_bech32() {
        let vk = [0u8; 32];
        let encoded = encode_vrf_verification_key(&vk).unwrap();
        assert!(is_valid_bech32(&encoded));
        assert!(!is_valid_bech32("invalid"));
    }

    #[test]
    fn test_get_hrp() {
        let vk = [0u8; 32];
        let encoded = encode_vrf_verification_key(&vk).unwrap();
        assert_eq!(get_hrp(&encoded), Some("vrf_vk".to_string()));
        assert_eq!(get_hrp("invalid"), None);
    }

    #[test]
    fn test_constants() {
        assert_eq!(SEPARATOR_CHAR, '1');
        assert_eq!(ENCODED_STRING_MAX_LENGTH, 90);
        assert_eq!(CHECKSUM_LENGTH, 6);
        assert_eq!(HRP_MIN_LENGTH, 1);
        assert_eq!(HRP_MAX_LENGTH, 83);
    }

    #[test]
    fn test_governance_keys() {
        let vk = [42u8; 32];

        // DRep keys
        let drep_encoded = encode_drep_verification_key(&vk).unwrap();
        assert!(drep_encoded.starts_with("drep_vk1"));
        let drep_decoded = decode_drep_verification_key(&drep_encoded).unwrap();
        assert_eq!(drep_decoded, vk);

        // Committee cold keys
        let cc_cold_encoded = encode_committee_cold_verification_key(&vk).unwrap();
        assert!(cc_cold_encoded.starts_with("cc_cold_vk1"));
        let cc_cold_decoded = decode_committee_cold_verification_key(&cc_cold_encoded).unwrap();
        assert_eq!(cc_cold_decoded, vk);

        // Committee hot keys
        let cc_hot_encoded = encode_committee_hot_verification_key(&vk).unwrap();
        assert!(cc_hot_encoded.starts_with("cc_hot_vk1"));
        let cc_hot_decoded = decode_committee_hot_verification_key(&cc_hot_encoded).unwrap();
        assert_eq!(cc_hot_decoded, vk);
    }

    #[test]
    fn test_key_hash_encoding() {
        let hash = [42u8; 28];

        // Verification key hash
        let vkh_encoded = encode_verification_key_hash(&hash).unwrap();
        assert!(vkh_encoded.starts_with("addr_vkh1"));
        let vkh_decoded = decode_verification_key_hash(&vkh_encoded).unwrap();
        assert_eq!(vkh_decoded, hash);

        // Stake verification key hash
        let stake_vkh_encoded = encode_stake_verification_key_hash(&hash).unwrap();
        assert!(stake_vkh_encoded.starts_with("stake_vkh1"));
        let stake_vkh_decoded = decode_stake_verification_key_hash(&stake_vkh_encoded).unwrap();
        assert_eq!(stake_vkh_decoded, hash);

        // VRF verification key hash
        let vrf_vkh_encoded = encode_vrf_verification_key_hash(&hash).unwrap();
        assert!(vrf_vkh_encoded.starts_with("vrf_vkh1"));
        let vrf_vkh_decoded = decode_vrf_verification_key_hash(&vrf_vkh_encoded).unwrap();
        assert_eq!(vrf_vkh_decoded, hash);

        // Script hash
        let script_encoded = encode_script_hash(&hash).unwrap();
        assert!(script_encoded.starts_with("script1"));
        let script_decoded = decode_script_hash(&script_encoded).unwrap();
        assert_eq!(script_decoded, hash);
    }

    #[test]
    fn test_kes_signing_key_variable_length() {
        // KES signing keys can be various sizes
        let sk_small = vec![42u8; 100];
        let encoded = encode_kes_signing_key(&sk_small).unwrap();
        assert!(encoded.starts_with("kes_sk1"));
        let decoded = decode_kes_signing_key(&encoded).unwrap();
        assert_eq!(decoded, sk_small);

        // Medium KES key - fits within bech32 limit (max ~613 bytes with hrp)
        let sk_medium = vec![42u8; 500];
        let encoded_medium = encode_kes_signing_key(&sk_medium).unwrap();
        let decoded_medium = decode_kes_signing_key(&encoded_medium).unwrap();
        assert_eq!(decoded_medium, sk_medium);

        // Note: Very large KES keys (e.g., Sum6KES with 2112 bytes) exceed
        // the standard Bech32 maximum encoded length of 90 characters.
        // For such keys, use a different encoding (e.g., hex in TextEnvelope).
    }

    #[test]
    fn test_signing_keys() {
        let sk = [42u8; 32];

        // Payment signing key
        let payment_sk = encode_payment_signing_key(&sk).unwrap();
        assert!(payment_sk.starts_with("addr_sk1"));
        assert_eq!(decode_payment_signing_key(&payment_sk).unwrap(), sk);

        // Stake signing key
        let stake_sk = encode_stake_signing_key(&sk).unwrap();
        assert!(stake_sk.starts_with("stake_sk1"));
        assert_eq!(decode_stake_signing_key(&stake_sk).unwrap(), sk);

        // Pool signing key
        let pool_sk = encode_pool_signing_key(&sk).unwrap();
        assert!(pool_sk.starts_with("pool_sk1"));
        assert_eq!(decode_pool_signing_key(&pool_sk).unwrap(), sk);

        // VRF signing key
        let vrf_sk = encode_vrf_signing_key(&sk).unwrap();
        assert!(vrf_sk.starts_with("vrf_sk1"));
        assert_eq!(decode_vrf_signing_key(&vrf_sk).unwrap(), sk);
    }

    #[test]
    fn test_vrf_full_signing_key() {
        let sk = [42u8; 64];
        let encoded = encode_vrf_signing_key_full(&sk).unwrap();
        assert!(encoded.starts_with("vrf_sk1"));
        let decoded = decode_vrf_signing_key_full(&encoded).unwrap();
        assert_eq!(decoded, sk);
    }

    #[test]
    fn test_genesis_keys() {
        let key = [42u8; 32];

        // Genesis verification key
        let genesis_vk = encode_genesis_verification_key(&key).unwrap();
        assert!(genesis_vk.starts_with("genesis_vk1"));
        assert_eq!(decode_genesis_verification_key(&genesis_vk).unwrap(), key);

        // Genesis signing key
        let genesis_sk = encode_genesis_signing_key(&key).unwrap();
        assert!(genesis_sk.starts_with("genesis_sk1"));
        assert_eq!(decode_genesis_signing_key(&genesis_sk).unwrap(), key);

        // Genesis delegate verification key
        let gen_del_vk = encode_genesis_delegate_verification_key(&key).unwrap();
        assert!(gen_del_vk.starts_with("genesis_delegate_vk1"));
        assert_eq!(
            decode_genesis_delegate_verification_key(&gen_del_vk).unwrap(),
            key
        );

        // Genesis delegate signing key
        let gen_del_sk = encode_genesis_delegate_signing_key(&key).unwrap();
        assert!(gen_del_sk.starts_with("genesis_delegate_sk1"));
        assert_eq!(
            decode_genesis_delegate_signing_key(&gen_del_sk).unwrap(),
            key
        );
    }

    #[test]
    fn test_drep_key_hash() {
        let hash = [42u8; 28];
        let encoded = encode_drep_key_hash(&hash).unwrap();
        assert!(encoded.starts_with("drep1"));
        let decoded = decode_drep_key_hash(&encoded).unwrap();
        assert_eq!(decoded, hash);
    }

    #[test]
    fn test_error_display() {
        let err = Bech32Error::InvalidHrp("test".to_string());
        assert!(err.to_string().contains("Invalid human-readable part"));

        let err = Bech32Error::HrpMismatch {
            expected: "vrf_vk".to_string(),
            actual: "kes_vk".to_string(),
        };
        assert!(err.to_string().contains("HRP mismatch"));

        let err = Bech32Error::UnexpectedLength {
            expected: 32,
            actual: 28,
        };
        assert!(err.to_string().contains("Unexpected data length"));
    }

    #[test]
    fn test_zero_key() {
        // Test with all-zero keys (edge case)
        let zero_key = [0u8; 32];
        let encoded = encode_vrf_verification_key(&zero_key).unwrap();
        let decoded = decode_vrf_verification_key(&encoded).unwrap();
        assert_eq!(decoded, zero_key);
    }

    #[test]
    fn test_max_key() {
        // Test with all-255 keys (edge case)
        let max_key = [255u8; 32];
        let encoded = encode_vrf_verification_key(&max_key).unwrap();
        let decoded = decode_vrf_verification_key(&encoded).unwrap();
        assert_eq!(decoded, max_key);
    }
}
