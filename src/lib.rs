//! # Cardano Crypto
//!
//! Pure Rust implementation of Cardano cryptographic primitives.
//!
//! This crate provides a unified interface for all Cardano cryptographic operations:
//! - **VRF** (Verifiable Random Functions) - IETF Draft-03 and Draft-13
//! - **KES** (Key Evolving Signatures) - Forward-secure signature schemes
//! - **DSIGN** (Digital Signatures) - Ed25519 and variants
//! - **Hash** - Blake2b, SHA-2, and other Cardano hash functions
//! - **Seed** - Deterministic key derivation
//! - **CBOR** - Optional serialization support
//!
//! # Feature Flags
//!
//! This crate uses feature flags to allow selective compilation:
//!
//! - `std` (default) - Standard library support
//! - `alloc` - Allocation support for no_std
//! - `vrf` - VRF implementations (includes `dsign`, `hash`)
//! - `kes` - KES implementations (includes `dsign`, `hash`)
//! - `dsign` - Digital signature algorithms (includes `hash`)
//! - `hash` - Hash functions
//! - `cbor` - CBOR serialization
//! - `serde` - Serde serialization for keys/signatures
//! - `metrics` - Performance metrics collection
//! - `logging` - Debug logging support
//!
//! # Examples
//!
//! ## VRF Proof Generation
//!
//! ```rust,ignore
//! use cardano_crypto::vrf::{VrfDraft03, VrfKeyPair};
//!
//! let seed = [0u8; 32];
//! let keypair = VrfKeyPair::from_seed(&seed);
//! let proof = keypair.prove(b"message")?;
//! let output = proof.verify(&keypair.public_key(), b"message")?;
//! ```
//!
//! ## KES Signing
//!
//! ```rust,ignore
//! use cardano_crypto::kes::{Sum6Kes, KesAlgorithm};
//!
//! let seed = [0u8; 32];
//! let signing_key = Sum6Kes::gen_key_from_seed(&seed)?;
//! let signature = Sum6Kes::sign(&signing_key, 0, b"message")?;
//! ```
//!
//! ## Digital Signatures
//!
//! ```rust,ignore
//! use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};
//!
//! let seed = [0u8; 32];
//! let signing_key = Ed25519::gen_key(&seed).unwrap();
//! let signature = Ed25519::sign(&signing_key, b"message");
//! ```

//! ## Crate metadata
//!
//! ```rust
//! use cardano_crypto::{NAME, VERSION};
//! assert_eq!(NAME, "cardano-crypto");
//! // VERSION comes from Cargo.toml at build time and should be present
//! assert!(VERSION.len() > 0);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
#![warn(
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub,
    clippy::all
)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

// ============================================================================
// Common utilities and traits
// ============================================================================

pub mod common;

// ============================================================================
// Core cryptographic components
// ============================================================================

#[cfg(feature = "hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "hash")))]
pub mod hash;

#[cfg(feature = "seed")]
#[cfg_attr(docsrs, doc(cfg(feature = "seed")))]
pub mod seed;

#[cfg(feature = "dsign")]
#[cfg_attr(docsrs, doc(cfg(feature = "dsign")))]
pub mod dsign;

#[cfg(feature = "vrf")]
#[cfg_attr(docsrs, doc(cfg(feature = "vrf")))]
pub mod vrf;

#[cfg(feature = "kes")]
#[cfg_attr(docsrs, doc(cfg(feature = "kes")))]
pub mod kes;

#[cfg(feature = "cbor")]
#[cfg_attr(docsrs, doc(cfg(feature = "cbor")))]
pub mod cbor;

/// BLS12-381 curve operations for Plutus V2+ (CIP-0381)
#[cfg(feature = "bls")]
#[cfg_attr(docsrs, doc(cfg(feature = "bls")))]
pub mod bls;

/// Key types, serialization, and utilities matching cardano-api
pub mod key;

/// Hierarchical Deterministic key derivation (CIP-1852) and address construction
#[cfg(feature = "hd")]
#[cfg_attr(docsrs, doc(cfg(feature = "hd")))]
pub mod hd;

// ============================================================================
// Re-exports for convenience
// ============================================================================

#[cfg(feature = "hash")]
pub use hash::{Blake2b224, Blake2b256, Blake2b512, HashAlgorithm};

#[cfg(feature = "dsign")]
pub use dsign::{
    DsignAlgorithm, DsignKeyPair, DsignSignature, DsignSigningKey, DsignVerificationKey, Ed25519,
    SignedDsign,
    ed25519::{Ed25519Signature, Ed25519SigningKey, Ed25519VerificationKey},
};

#[cfg(feature = "vrf")]
pub use vrf::{
    CertifiedVrf, OutputVrf, PraosBatchCompatVRF, VrfAlgorithm, VrfDraft03, VrfDraft13, VrfKeyPair,
    VrfProof, VrfSigningKey, VrfVerificationKey,
};

#[cfg(feature = "kes")]
pub use kes::{
    CompactSum0Kes, CompactSum1Kes, CompactSum2Kes, CompactSum3Kes, CompactSum4Kes, CompactSum5Kes,
    CompactSum6Kes, CompactSum7Kes, KesAlgorithm, KesError, KesKeyPair, KesSignature,
    KesSigningKey, KesVerificationKey, Period, SignKeyWithPeriodKes, SignedKes, SingleKes, Sum0Kes,
    Sum1Kes, Sum2Kes, Sum3Kes, Sum4Kes, Sum5Kes, Sum6Kes, Sum7Kes,
};

#[cfg(feature = "bls")]
pub use bls::{
    Bls12381, BlsPublicKey, BlsSecretKey, BlsSignature, G1_COMPRESSED_SIZE, G1Point,
    G2_COMPRESSED_SIZE, G2Point, PairingResult, SCALAR_SIZE, Scalar, bls_verify,
    bls_verify_with_dst,
};

// Re-export secp256k1 types when feature is enabled
#[cfg(feature = "secp256k1")]
pub use dsign::{
    Secp256k1Ecdsa, Secp256k1EcdsaSignature, Secp256k1EcdsaSigningKey,
    Secp256k1EcdsaVerificationKey, Secp256k1Schnorr, Secp256k1SchnorrSignature,
    Secp256k1SchnorrSigningKey, Secp256k1SchnorrVerificationKey,
};

#[cfg(feature = "cbor")]
pub use cbor::{
    // Error type
    CborError,
    // Traits
    FromCbor,
    ToCbor,
    // Core CBOR functions
    decode_bytes,
    // Hash CBOR
    decode_hash,
    // VRF-specific CBOR
    decode_output_vrf,
    decode_proof_vrf,
    // Generic verification key / signature
    decode_signature,
    // DSIGN-specific CBOR
    decode_signature_dsign,
    // KES-specific CBOR
    decode_signature_kes,
    decode_signing_key_dsign,
    decode_signing_key_kes,
    decode_signing_key_vrf,
    decode_verification_key,
    decode_verification_key_dsign,
    decode_verification_key_kes,
    decode_verification_key_vrf,
    encode_bytes,
    encode_hash,
    encode_output_vrf,
    encode_proof_vrf,
    encode_signature,
    encode_signature_dsign,
    encode_signature_kes,
    encode_signing_key_dsign,
    encode_signing_key_kes,
    encode_signing_key_vrf,
    encode_verification_key,
    encode_verification_key_dsign,
    encode_verification_key_kes,
    encode_verification_key_vrf,
    // Size expressions (Hash)
    encoded_hash_blake2b224_size,
    encoded_hash_blake2b256_size,
    // Size expressions (VRF)
    encoded_output_vrf_size,
    encoded_proof_vrf_draft03_size,
    encoded_proof_vrf_draft13_size,
    encoded_signature_dsign_size,
    // Size utilities (generic)
    encoded_signature_size,
    // Size expressions (KES)
    encoded_signature_sum6kes_size,
    // Size expressions (DSIGN)
    encoded_signing_key_dsign_size,
    encoded_signing_key_sum6kes_size,
    encoded_signing_key_vrf_size,
    encoded_size_bytes,
    encoded_verification_key_dsign_size,
    encoded_verification_key_kes_size,
    encoded_verification_key_size,
    encoded_verification_key_vrf_size,
};

#[cfg(feature = "seed")]
pub use seed::{SEED_SIZE, SecureSeed, Seed, SeedError, derive_seed, expand_seed};

// Re-export key module types
pub use key::bech32;
pub use key::text_envelope;

#[cfg(feature = "hash")]
pub use key::hash::{
    CommitteeColdKeyHash, CommitteeHotKeyHash, DRepKeyHash, GenesisDelegateKeyHash, GenesisKeyHash,
    KEY_HASH_SIZE, KeyHash, PaymentKeyHash, PoolKeyHash, StakeKeyHash, VrfKeyHash,
    hash_payment_verification_key, hash_pool_verification_key, hash_raw,
    hash_stake_verification_key, hash_verification_key, hash_vrf_verification_key,
};

#[cfg(feature = "kes")]
pub use key::kes_period::{
    KES_MAX_PERIOD_SUM6, KES_SLOTS_PER_PERIOD_MAINNET, KES_SLOTS_PER_PERIOD_TESTNET, KESPeriod,
    KESPeriodInfo, KesPeriod, is_kes_expired, is_valid_period, kes_expiry_slot, kes_period_info,
    period_from_slot, slot_from_period,
};

#[cfg(feature = "hash")]
pub use key::stake_pool::{PoolMetadata, Rational, RewardAccount, StakePoolParams, StakePoolRelay};

// ============================================================================
// Crate metadata
// ============================================================================

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate name
pub const NAME: &str = env!("CARGO_PKG_NAME");
