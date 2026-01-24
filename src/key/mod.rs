//! Key types and serialization matching cardano-api
//!
//! This module provides key types and constants that align with the
//! cardano-api Key class pattern, including:
//!
//! - Bech32 prefixes for human-readable key encoding
//! - Bech32 encoding/decoding functions (with `bech32-encoding` feature)
//! - TextEnvelope type descriptions for key files
//! - Key hash types using Blake2b-224
//! - KES period handling
//!
//! # Bech32 Encoding
//!
//! Keys and addresses use Bech32 encoding with standard prefixes:
//!
//! | Type | Verification Key | Signing Key |
//! |------|-----------------|-------------|
//! | Payment | `addr_vk` | `addr_sk` |
//! | Stake | `stake_vk` | `stake_sk` |
//! | Pool | `pool_vk` | `pool_sk` |
//! | VRF | `vrf_vk` | `vrf_sk` |
//! | KES | `kes_vk` | `kes_sk` |
//!
//! # TextEnvelope Format
//!
//! Keys are stored in files using TextEnvelope JSON format with type descriptions.
//!
//! # Examples
//!
//! ## Using Prefix Constants
//!
//! ```rust
//! use cardano_crypto::key::bech32::*;
//!
//! assert_eq!(PAYMENT_VERIFICATION_KEY_PREFIX, "addr_vk");
//! assert_eq!(VRF_SIGNING_KEY_PREFIX, "vrf_sk");
//! ```
//!
//! ## Encoding Keys (requires `bech32-encoding` feature)
//!
//! ```rust,ignore
//! use cardano_crypto::key::encoding::{encode_vrf_verification_key, decode_vrf_verification_key};
//!
//! let vk = [0u8; 32];
//! let encoded = encode_vrf_verification_key(&vk).unwrap();
//! assert!(encoded.starts_with("vrf_vk1"));
//!
//! let decoded = decode_vrf_verification_key(&encoded).unwrap();
//! assert_eq!(decoded, vk);
//! ```

/// Bech32 human-readable prefix constants
pub mod bech32;

/// TextEnvelope type description constants
pub mod text_envelope;

/// Key hash types using Blake2b-224
#[cfg(feature = "hash")]
pub mod hash;

/// KES period handling
#[cfg(feature = "kes")]
pub mod kes_period;

/// Stake pool parameters
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub mod stake_pool;

/// Operational Certificates for stake pool block production
#[cfg(feature = "kes")]
#[cfg_attr(docsrs, doc(cfg(feature = "kes")))]
pub mod operational_cert;

/// Bech32 encoding and decoding functions
#[cfg(feature = "bech32-encoding")]
#[cfg_attr(docsrs, doc(cfg(feature = "bech32-encoding")))]
pub mod encoding;

// Re-exports
pub use bech32::*;
pub use text_envelope::*;

#[cfg(feature = "hash")]
pub use hash::*;

#[cfg(feature = "kes")]
pub use kes_period::*;

#[cfg(feature = "alloc")]
pub use stake_pool::{PoolMetadata, Rational, RewardAccount, StakePoolParams, StakePoolRelay};

#[cfg(feature = "kes")]
pub use operational_cert::*;

#[cfg(feature = "bech32-encoding")]
pub use encoding::*;
