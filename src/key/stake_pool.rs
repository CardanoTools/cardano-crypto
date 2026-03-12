//! Stake Pool Parameters
//!
//! This module implements stake pool registration parameters matching the
//! Cardano ledger's `PoolParams` structure from Shelley onwards.
//!
//! # Overview
//!
//! Stake pool operators register their pools on-chain by submitting a pool
//! registration certificate containing these parameters. The parameters define:
//! - Pool identification (cold key hash, VRF key)
//! - Economic parameters (pledge, cost, margin)
//! - Operational information (relays, metadata)
//! - Ownership (list of stake key hashes)
//!
//! # Cardano Compatibility
//!
//! This matches the Haskell type from cardano-ledger:
//! ```haskell
//! data PoolParams = PoolParams
//!   { ppId       :: !(KeyHash 'PoolOperator)
//!   , ppVrf      :: !(Hash VRFVerKey)
//!   , ppPledge   :: !Coin
//!   , ppCost     :: !Coin
//!   , ppMargin   :: !UnitInterval
//!   , ppRewardAcnt :: !RewardAcnt
//!   , ppOwners   :: !(Set (KeyHash 'Staking))
//!   , ppRelays   :: !(StrictSeq StakePoolRelay)
//!   , ppMetadata :: !(StrictMaybe PoolMetadata)
//!   }
//! ```
//!
//! # Examples
//!
//! ```rust
//! use cardano_crypto::key::stake_pool::{StakePoolParams, Rational, StakePoolRelay, RewardAccount};
//! use cardano_crypto::key::hash::{PoolKeyHash, StakeKeyHash, role};
//! use std::collections::BTreeSet;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create pool parameters
//! let pool_id = PoolKeyHash::from_bytes([1u8; 28]);
//! let vrf_hash = [2u8; 32];
//! let reward_account = RewardAccount::from_stake_key_hash([3u8; 28]);
//!
//! let mut owners = BTreeSet::new();
//! owners.insert(StakeKeyHash::from_bytes([4u8; 28]));
//!
//! let params = StakePoolParams {
//!     pool_id,
//!     vrf_key_hash: vrf_hash,
//!     pledge: 500_000_000_000, // 500k ADA
//!     cost: 340_000_000,        // 340 ADA min cost
//!     margin: Rational::from_percentage(5)?, // 5%
//!     reward_account,
//!     owners,
//!     relays: vec![],
//!     metadata: None,
//! };
//!
//! // Validate parameters
//! params.validate()?;
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - [Shelley Ledger Spec](https://github.com/IntersectMBO/cardano-ledger/tree/master/eras/shelley/impl)
//! - [Pool Registration](https://developers.cardano.org/docs/operate-a-stake-pool/)

use crate::common::{CryptoError, Result};

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::collections::BTreeSet;
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::key::hash::{PoolKeyHash, StakeKeyHash};

/// VRF verification key hash (Blake2b-256)
pub type VrfKeyHash = [u8; 32];

// =============================================================================
// Reward Account
// =============================================================================

/// Reward account for stake pool operator rewards
///
/// A reward account is a Shelley address tied to a staking credential.
/// Pool operator rewards are paid to this account.
///
/// # Format
///
/// The reward account is represented as the stake key hash (28 bytes).
/// When serialized on-chain, it's prefixed with the network tag and
/// credential type to form a full stake address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RewardAccount {
    stake_key_hash: [u8; 28],
}

impl RewardAccount {
    /// Create from stake key hash
    ///
    /// # Arguments
    ///
    /// * `stake_key_hash` - 28-byte Blake2b-224 hash of stake verification key
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::key::stake_pool::RewardAccount;
    ///
    /// let stake_hash = [0u8; 28];
    /// let reward_account = RewardAccount::from_stake_key_hash(stake_hash);
    /// ```
    pub fn from_stake_key_hash(stake_key_hash: [u8; 28]) -> Self {
        Self { stake_key_hash }
    }

    /// Get the stake key hash
    pub fn stake_key_hash(&self) -> &[u8; 28] {
        &self.stake_key_hash
    }
}

// =============================================================================
// Rational Number (Unit Interval)
// =============================================================================

/// Rational number for representing pool margin as a fraction
///
/// Represents a value in the range [0, 1] as `numerator / denominator`.
/// Used for the pool margin (percentage of rewards taken by the operator).
///
/// # Cardano Compatibility
///
/// This matches the Haskell `UnitInterval` type from cardano-ledger:
/// ```haskell
/// newtype UnitInterval = UnitInterval Rational
/// ```
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::stake_pool::Rational;
///
/// // 5% margin
/// let margin = Rational::from_percentage(5).unwrap();
/// assert_eq!(margin.numerator(), 5);
/// assert_eq!(margin.denominator(), 100);
///
/// // 0% margin (community pool)
/// let zero_margin = Rational::from_percentage(0).unwrap();
///
/// // Maximum 100% (unusual but valid)
/// let max_margin = Rational::from_percentage(100).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Rational {
    numerator: u64,
    denominator: u64,
}

impl Rational {
    /// Create a rational number
    ///
    /// # Arguments
    ///
    /// * `numerator` - Numerator of the fraction
    /// * `denominator` - Denominator of the fraction (must be non-zero)
    ///
    /// # Returns
    ///
    /// Returns `Ok(Rational)` if valid, or `Err` if denominator is zero or
    /// the fraction is greater than 1.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::key::stake_pool::Rational;
    ///
    /// // 1/2 (50%)
    /// let half = Rational::new(1, 2).unwrap();
    ///
    /// // 3/4 (75%)
    /// let three_quarters = Rational::new(3, 4).unwrap();
    ///
    /// // Invalid: denominator is zero
    /// assert!(Rational::new(1, 0).is_err());
    ///
    /// // Invalid: greater than 1
    /// assert!(Rational::new(3, 2).is_err());
    /// ```
    pub fn new(numerator: u64, denominator: u64) -> Result<Self> {
        if denominator == 0 {
            return Err(CryptoError::InvalidParameter(
                "Denominator cannot be zero".into(),
            ));
        }
        if numerator > denominator {
            return Err(CryptoError::InvalidParameter(
                "Margin must be in range [0, 1]".into(),
            ));
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    /// Create from percentage (0-100)
    ///
    /// # Arguments
    ///
    /// * `percent` - Percentage value (0-100)
    ///
    /// # Returns
    ///
    /// Returns `Ok(Rational)` representing `percent/100`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::key::stake_pool::Rational;
    ///
    /// let five_percent = Rational::from_percentage(5).unwrap();
    /// assert_eq!(five_percent.numerator(), 5);
    /// assert_eq!(five_percent.denominator(), 100);
    ///
    /// // Invalid: over 100%
    /// assert!(Rational::from_percentage(101).is_err());
    /// ```
    pub fn from_percentage(percent: u8) -> Result<Self> {
        if percent > 100 {
            return Err(CryptoError::InvalidParameter(
                "Percentage must be 0-100".into(),
            ));
        }
        Ok(Self {
            numerator: percent as u64,
            denominator: 100,
        })
    }

    /// Get the numerator
    pub fn numerator(&self) -> u64 {
        self.numerator
    }

    /// Get the denominator
    pub fn denominator(&self) -> u64 {
        self.denominator
    }

    /// Validate that the rational is in [0, 1]
    ///
    /// This is automatically checked in `new()` and `from_percentage()`,
    /// but can be called explicitly if needed.
    pub fn validate(&self) -> Result<()> {
        if self.denominator == 0 {
            return Err(CryptoError::InvalidParameter(
                "Denominator cannot be zero".into(),
            ));
        }
        if self.numerator > self.denominator {
            return Err(CryptoError::InvalidParameter(
                "Margin must be in range [0, 1]".into(),
            ));
        }
        Ok(())
    }

    /// Convert to floating point (for display purposes only)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::key::stake_pool::Rational;
    ///
    /// let margin = Rational::from_percentage(5).unwrap();
    /// assert_eq!(margin.to_f64(), 0.05);
    /// ```
    pub fn to_f64(&self) -> f64 {
        self.numerator as f64 / self.denominator as f64
    }
}

// =============================================================================
// Stake Pool Relay
// =============================================================================

/// Stake pool relay information
///
/// Defines how to connect to a stake pool's relay nodes. Pools should
/// register at least one relay to enable peer discovery on the network.
///
/// # Relay Types
///
/// - **SingleHostAddr**: Direct connection via IP address and port
/// - **SingleHostName**: Connection via DNS name and port
/// - **MultiHostName**: Connection via DNS SRV record (for multiple relays)
///
/// # Cardano Compatibility
///
/// This matches the Haskell `StakePoolRelay` type from cardano-ledger:
/// ```haskell
/// data StakePoolRelay
///   = SingleHostAddr !(StrictMaybe Port) !(StrictMaybe IPv4) !(StrictMaybe IPv6)
///   | SingleHostName !(StrictMaybe Port) !DnsName
///   | MultiHostName !DnsName
/// ```
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::stake_pool::StakePoolRelay;
///
/// // IPv4 relay
/// let relay1 = StakePoolRelay::SingleHostAddr {
///     port: Some(3001),
///     ipv4: Some([192, 168, 1, 100]),
///     ipv6: None,
/// };
///
/// // DNS relay
/// let relay2 = StakePoolRelay::SingleHostName {
///     port: Some(3001),
///     dns_name: "relay.example.com".to_string(),
/// };
///
/// // Multi-host DNS SRV
/// let relay3 = StakePoolRelay::MultiHostName {
///     dns_name: "_cardano._tcp.pool.example.com".to_string(),
/// };
/// ```
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum StakePoolRelay {
    /// Single host by IP address
    ///
    /// Direct connection to a relay node via IPv4 or IPv6 address.
    /// At least one of `ipv4` or `ipv6` should be provided.
    SingleHostAddr {
        /// TCP port number (default: 3001)
        port: Option<u16>,
        /// IPv4 address (4 bytes)
        ipv4: Option<[u8; 4]>,
        /// IPv6 address (16 bytes)
        ipv6: Option<[u8; 16]>,
    },

    /// Single host by DNS name
    ///
    /// Connection to a relay node via DNS hostname resolution.
    /// The DNS name will be resolved to an IP address at connection time.
    SingleHostName {
        /// TCP port number (default: 3001)
        port: Option<u16>,
        /// DNS hostname (e.g., "relay.example.com")
        dns_name: String,
    },

    /// Multi-host by DNS SRV record
    ///
    /// Uses DNS SRV records to discover multiple relay endpoints.
    /// This allows a single registration to point to multiple relays.
    ///
    /// The DNS name should follow the SRV record format:
    /// `_service._proto.name` (e.g., `_cardano._tcp.pool.example.com`)
    MultiHostName {
        /// DNS SRV name
        dns_name: String,
    },
}

#[cfg(feature = "alloc")]
impl StakePoolRelay {
    /// Validate relay parameters
    pub fn validate(&self) -> Result<()> {
        match self {
            StakePoolRelay::SingleHostAddr { ipv4, ipv6, .. } => {
                if ipv4.is_none() && ipv6.is_none() {
                    return Err(CryptoError::InvalidParameter(
                        "SingleHostAddr must have at least one IP address".into(),
                    ));
                }
                Ok(())
            }
            StakePoolRelay::SingleHostName { dns_name, .. }
            | StakePoolRelay::MultiHostName { dns_name } => {
                if dns_name.is_empty() {
                    return Err(CryptoError::InvalidParameter(
                        "DNS name cannot be empty".into(),
                    ));
                }
                if dns_name.len() > 64 {
                    return Err(CryptoError::InvalidParameter(
                        "DNS name too long (max 64 chars)".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

// =============================================================================
// Pool Metadata
// =============================================================================

/// Pool metadata reference
///
/// Points to off-chain metadata (JSON file) containing pool description,
/// ticker symbol, homepage, etc. The metadata is referenced by URL and
/// verified by its Blake2b-256 hash.
///
/// # Metadata Format
///
/// The metadata JSON file should contain:
/// ```json
/// {
///   "name": "My Stake Pool",
///   "description": "A great stake pool",
///   "ticker": "POOL",
///   "homepage": "https://pool.example.com"
/// }
/// ```
///
/// # Cardano Compatibility
///
/// This matches the Haskell `PoolMetadata` type:
/// ```haskell
/// data PoolMetadata = PoolMetadata
///   { pmUrl  :: !Url
///   , pmHash :: !(Hash PoolMetadata)
///   }
/// ```
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::stake_pool::PoolMetadata;
///
/// let metadata = PoolMetadata {
///     url: "https://pool.example.com/metadata.json".to_string(),
///     hash: [0u8; 32], // Blake2b-256 hash of metadata JSON
/// };
/// ```
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PoolMetadata {
    /// URL to metadata JSON file (max 64 characters)
    pub url: String,
    /// Blake2b-256 hash of metadata file contents
    pub hash: [u8; 32],
}

#[cfg(feature = "alloc")]
impl PoolMetadata {
    /// Create new pool metadata
    ///
    /// # Arguments
    ///
    /// * `url` - URL to metadata JSON (max 64 characters)
    /// * `hash` - Blake2b-256 hash of metadata file
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::key::stake_pool::PoolMetadata;
    ///
    /// let metadata = PoolMetadata::new(
    ///     "https://pool.example.com/metadata.json".to_string(),
    ///     [0u8; 32],
    /// ).unwrap();
    /// ```
    pub fn new(url: String, hash: [u8; 32]) -> Result<Self> {
        if url.is_empty() {
            return Err(CryptoError::InvalidParameter("URL cannot be empty".into()));
        }
        if url.len() > 64 {
            return Err(CryptoError::InvalidParameter(
                "URL too long (max 64 chars)".into(),
            ));
        }
        Ok(Self { url, hash })
    }

    /// Validate metadata
    pub fn validate(&self) -> Result<()> {
        if self.url.is_empty() {
            return Err(CryptoError::InvalidParameter("URL cannot be empty".into()));
        }
        if self.url.len() > 64 {
            return Err(CryptoError::InvalidParameter(
                "URL too long (max 64 chars)".into(),
            ));
        }
        Ok(())
    }
}

// =============================================================================
// Stake Pool Parameters
// =============================================================================

/// Stake pool registration parameters
///
/// Contains all parameters required to register a stake pool on the Cardano
/// blockchain. Pool operators submit these parameters via a pool registration
/// certificate to announce their pool to the network.
///
/// # Parameters
///
/// - **pool_id**: Pool operator cold key hash (identifies the pool)
/// - **vrf_key_hash**: VRF verification key hash (for leader election)
/// - **pledge**: Amount operator pledges to delegate to their own pool (lovelace)
/// - **cost**: Fixed cost per epoch deducted before reward distribution (lovelace)
/// - **margin**: Variable fee as fraction of remaining rewards (0-100%)
/// - **reward_account**: Account to receive pool operator rewards
/// - **owners**: Stake key hashes of pool owners (at least one required)
/// - **relays**: Network relay information (optional but recommended)
/// - **metadata**: Off-chain metadata reference (optional)
///
/// # Cardano Compatibility
///
/// This matches the Haskell `PoolParams` type from cardano-ledger:
/// ```haskell
/// data PoolParams = PoolParams
///   { ppId       :: !(KeyHash 'PoolOperator)
///   , ppVrf      :: !(Hash VRFVerKey)
///   , ppPledge   :: !Coin
///   , ppCost     :: !Coin
///   , ppMargin   :: !UnitInterval
///   , ppRewardAcnt :: !RewardAcnt
///   , ppOwners   :: !(Set (KeyHash 'Staking))
///   , ppRelays   :: !(StrictSeq StakePoolRelay)
///   , ppMetadata :: !(StrictMaybe PoolMetadata)
///   }
/// ```
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::key::stake_pool::{StakePoolParams, Rational, RewardAccount};
/// use cardano_crypto::key::hash::{PoolKeyHash, StakeKeyHash};
/// use std::collections::BTreeSet;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let pool_id = PoolKeyHash::from_bytes([1u8; 28]);
/// let vrf_hash = [2u8; 32];
/// let reward_account = RewardAccount::from_stake_key_hash([3u8; 28]);
///
/// let mut owners = BTreeSet::new();
/// owners.insert(StakeKeyHash::from_bytes([4u8; 28]));
///
/// let params = StakePoolParams {
///     pool_id,
///     vrf_key_hash: vrf_hash,
///     pledge: 500_000_000_000,  // 500k ADA
///     cost: 340_000_000,         // 340 ADA (minimum)
///     margin: Rational::from_percentage(5)?, // 5%
///     reward_account,
///     owners,
///     relays: vec![],
///     metadata: None,
/// };
///
/// // Validate all parameters
/// params.validate()?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakePoolParams {
    /// Pool operator ID (cold key hash)
    ///
    /// This is the Blake2b-224 hash of the pool's cold verification key.
    /// It uniquely identifies the pool on-chain and is displayed as the "Pool ID".
    pub pool_id: PoolKeyHash,

    /// VRF verification key hash
    ///
    /// Blake2b-256 hash of the pool's VRF verification key.
    /// Used to bind the VRF key to the pool for leader election.
    pub vrf_key_hash: VrfKeyHash,

    /// Pledge amount (lovelace)
    ///
    /// Amount the pool operator commits to delegate to their own pool.
    /// Higher pledge increases rewards and demonstrates operator commitment.
    ///
    /// Minimum: 0 (but higher pledge is recommended)  
    /// Typical: 100k - 1M ADA (100,000,000,000 - 1,000,000,000,000 lovelace)
    pub pledge: u64,

    /// Fixed pool cost per epoch (lovelace)
    ///
    /// Minimum fixed fee deducted from pool rewards before distribution.
    ///
    /// Minimum: 340 ADA (340,000,000 lovelace) as per protocol parameters  
    /// Typical: 340-500 ADA
    pub cost: u64,

    /// Pool margin (0-100%)
    ///
    /// Variable fee taken from remaining rewards after fixed cost.
    /// Represented as a rational number (fraction in [0, 1]).
    ///
    /// Typical: 0-5% (0.00 - 0.05)  
    /// Maximum: 100% (1.0) though unusual for public pools
    pub margin: Rational,

    /// Reward account for pool operator
    ///
    /// Stake address to receive pool operator rewards (margin + cost).
    pub reward_account: RewardAccount,

    /// Pool owners (stake key hashes)
    ///
    /// Set of stake key hashes of pool owners. At least one owner required.
    /// Owners can delegate to the pool and sign pool retirement certificates.
    ///
    /// In practice, often just the operator's stake key.
    pub owners: BTreeSet<StakeKeyHash>,

    /// Pool relay information
    ///
    /// List of network relays for peer discovery. At least one relay
    /// is recommended for proper pool operation, though not required.
    pub relays: Vec<StakePoolRelay>,

    /// Optional pool metadata
    ///
    /// Reference to off-chain JSON metadata containing pool description,
    /// ticker symbol, homepage, etc. Highly recommended for public pools.
    pub metadata: Option<PoolMetadata>,
}

#[cfg(feature = "alloc")]
impl StakePoolParams {
    /// Create new stake pool parameters
    ///
    /// This is a convenience constructor with validation.
    ///
    /// # Arguments
    ///
    /// * `pool_id` - Pool operator cold key hash
    /// * `vrf_key_hash` - VRF verification key hash
    /// * `pledge` - Pledge amount in lovelace
    /// * `cost` - Fixed cost per epoch in lovelace (min 340 ADA)
    /// * `margin` - Pool margin as rational number
    /// * `reward_account` - Reward account for operator
    /// * `owners` - Set of owner stake key hashes (at least one)
    ///
    /// # Returns
    ///
    /// Returns `Ok(StakePoolParams)` if all parameters are valid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::key::stake_pool::{StakePoolParams, Rational, RewardAccount};
    /// use cardano_crypto::key::hash::{PoolKeyHash, StakeKeyHash};
    /// use std::collections::BTreeSet;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut owners = BTreeSet::new();
    /// owners.insert(StakeKeyHash::from_bytes([0u8; 28]));
    ///
    /// let params = StakePoolParams::new(
    ///     PoolKeyHash::from_bytes([1u8; 28]),
    ///     [2u8; 32],
    ///     500_000_000_000,  // 500k ADA pledge
    ///     340_000_000,       // 340 ADA cost
    ///     Rational::from_percentage(5)?,
    ///     RewardAccount::from_stake_key_hash([3u8; 28]),
    ///     owners,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        pool_id: PoolKeyHash,
        vrf_key_hash: VrfKeyHash,
        pledge: u64,
        cost: u64,
        margin: Rational,
        reward_account: RewardAccount,
        owners: BTreeSet<StakeKeyHash>,
    ) -> Result<Self> {
        let params = Self {
            pool_id,
            vrf_key_hash,
            pledge,
            cost,
            margin,
            reward_account,
            owners,
            relays: Vec::new(),
            metadata: None,
        };
        params.validate()?;
        Ok(params)
    }

    /// Add a relay to the pool
    pub fn add_relay(&mut self, relay: StakePoolRelay) -> Result<()> {
        relay.validate()?;
        self.relays.push(relay);
        Ok(())
    }

    /// Set pool metadata
    pub fn set_metadata(&mut self, metadata: PoolMetadata) -> Result<()> {
        metadata.validate()?;
        self.metadata = Some(metadata);
        Ok(())
    }

    /// Validate all pool parameters
    ///
    /// Checks that all parameters meet Cardano protocol requirements:
    /// - Margin is in valid range [0, 1]
    /// - At least one owner is specified
    /// - Cost meets minimum requirement (340 ADA)
    /// - Metadata URL is valid length if present
    /// - All relays are valid
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidParameter` if any validation fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::key::stake_pool::{StakePoolParams, Rational, RewardAccount};
    /// use cardano_crypto::key::hash::{PoolKeyHash, StakeKeyHash};
    /// use std::collections::BTreeSet;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut owners = BTreeSet::new();
    /// owners.insert(StakeKeyHash::from_bytes([0u8; 28]));
    ///
    /// let params = StakePoolParams {
    ///     pool_id: PoolKeyHash::from_bytes([1u8; 28]),
    ///     vrf_key_hash: [2u8; 32],
    ///     pledge: 500_000_000_000,
    ///     cost: 340_000_000,
    ///     margin: Rational::from_percentage(5)?,
    ///     reward_account: RewardAccount::from_stake_key_hash([3u8; 28]),
    ///     owners,
    ///     relays: vec![],
    ///     metadata: None,
    /// };
    ///
    /// // Validate
    /// params.validate()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn validate(&self) -> Result<()> {
        // Validate margin
        self.margin.validate()?;

        // Validate cost (minimum 340 ADA = 340,000,000 lovelace)
        const MIN_POOL_COST: u64 = 340_000_000;
        if self.cost < MIN_POOL_COST {
            return Err(CryptoError::InvalidParameter(
                "Pool cost below minimum (340 ADA)".into(),
            ));
        }

        // Validate at least one owner
        if self.owners.is_empty() {
            return Err(CryptoError::InvalidParameter(
                "At least one owner required".into(),
            ));
        }

        // Validate metadata if present
        if let Some(ref metadata) = self.metadata {
            metadata.validate()?;
        }

        // Validate all relays
        for relay in &self.relays {
            relay.validate()?;
        }

        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rational_from_percentage() {
        let r = Rational::from_percentage(5).unwrap();
        assert_eq!(r.numerator(), 5);
        assert_eq!(r.denominator(), 100);
        assert_eq!(r.to_f64(), 0.05);
    }

    #[test]
    fn test_rational_zero_percent() {
        let r = Rational::from_percentage(0).unwrap();
        assert_eq!(r.numerator(), 0);
        assert_eq!(r.to_f64(), 0.0);
    }

    #[test]
    fn test_rational_max_percent() {
        let r = Rational::from_percentage(100).unwrap();
        assert_eq!(r.numerator(), 100);
        assert_eq!(r.to_f64(), 1.0);
    }

    #[test]
    fn test_rational_invalid_percentage() {
        assert!(Rational::from_percentage(101).is_err());
    }

    #[test]
    fn test_rational_new() {
        let r = Rational::new(1, 4).unwrap();
        assert_eq!(r.to_f64(), 0.25);
    }

    #[test]
    fn test_rational_invalid_zero_denominator() {
        assert!(Rational::new(1, 0).is_err());
    }

    #[test]
    fn test_rational_invalid_greater_than_one() {
        assert!(Rational::new(5, 4).is_err());
    }

    #[test]
    fn test_reward_account() {
        let stake_hash = [42u8; 28];
        let account = RewardAccount::from_stake_key_hash(stake_hash);
        assert_eq!(account.stake_key_hash(), &stake_hash);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_pool_metadata_new() {
        let metadata =
            PoolMetadata::new("https://pool.example.com/meta.json".to_string(), [0u8; 32]).unwrap();
        assert_eq!(metadata.url, "https://pool.example.com/meta.json");
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_pool_metadata_url_too_long() {
        let long_url = "a".repeat(65);
        assert!(PoolMetadata::new(long_url, [0u8; 32]).is_err());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_relay_single_host_addr() {
        let relay = StakePoolRelay::SingleHostAddr {
            port: Some(3001),
            ipv4: Some([192, 168, 1, 1]),
            ipv6: None,
        };
        assert!(relay.validate().is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_relay_single_host_addr_no_ip() {
        let relay = StakePoolRelay::SingleHostAddr {
            port: Some(3001),
            ipv4: None,
            ipv6: None,
        };
        assert!(relay.validate().is_err());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_relay_single_host_name() {
        let relay = StakePoolRelay::SingleHostName {
            port: Some(3001),
            dns_name: "relay.example.com".to_string(),
        };
        assert!(relay.validate().is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_relay_multi_host_name() {
        let relay = StakePoolRelay::MultiHostName {
            dns_name: "_cardano._tcp.pool.example.com".to_string(),
        };
        assert!(relay.validate().is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_stake_pool_params_new() {
        let pool_id = PoolKeyHash::from_bytes([1u8; 28]);
        let vrf_hash = [2u8; 32];
        let reward_account = RewardAccount::from_stake_key_hash([3u8; 28]);

        let mut owners = BTreeSet::new();
        owners.insert(StakeKeyHash::from_bytes([4u8; 28]));

        let params = StakePoolParams::new(
            pool_id,
            vrf_hash,
            500_000_000_000,
            340_000_000,
            Rational::from_percentage(5).unwrap(),
            reward_account,
            owners,
        );

        assert!(params.is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_stake_pool_params_no_owners() {
        let pool_id = PoolKeyHash::from_bytes([1u8; 28]);
        let vrf_hash = [2u8; 32];
        let reward_account = RewardAccount::from_stake_key_hash([3u8; 28]);

        let owners = BTreeSet::new(); // Empty!

        let params = StakePoolParams::new(
            pool_id,
            vrf_hash,
            500_000_000_000,
            340_000_000,
            Rational::from_percentage(5).unwrap(),
            reward_account,
            owners,
        );

        assert!(params.is_err());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_stake_pool_params_cost_too_low() {
        let pool_id = PoolKeyHash::from_bytes([1u8; 28]);
        let vrf_hash = [2u8; 32];
        let reward_account = RewardAccount::from_stake_key_hash([3u8; 28]);

        let mut owners = BTreeSet::new();
        owners.insert(StakeKeyHash::from_bytes([4u8; 28]));

        let params = StakePoolParams::new(
            pool_id,
            vrf_hash,
            500_000_000_000,
            100_000_000, // Only 100 ADA, min is 340
            Rational::from_percentage(5).unwrap(),
            reward_account,
            owners,
        );

        assert!(params.is_err());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_stake_pool_params_add_relay() {
        let pool_id = PoolKeyHash::from_bytes([1u8; 28]);
        let vrf_hash = [2u8; 32];
        let reward_account = RewardAccount::from_stake_key_hash([3u8; 28]);

        let mut owners = BTreeSet::new();
        owners.insert(StakeKeyHash::from_bytes([4u8; 28]));

        let mut params = StakePoolParams::new(
            pool_id,
            vrf_hash,
            500_000_000_000,
            340_000_000,
            Rational::from_percentage(5).unwrap(),
            reward_account,
            owners,
        )
        .unwrap();

        let relay = StakePoolRelay::SingleHostName {
            port: Some(3001),
            dns_name: "relay.example.com".to_string(),
        };

        assert!(params.add_relay(relay).is_ok());
        assert_eq!(params.relays.len(), 1);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_stake_pool_params_set_metadata() {
        let pool_id = PoolKeyHash::from_bytes([1u8; 28]);
        let vrf_hash = [2u8; 32];
        let reward_account = RewardAccount::from_stake_key_hash([3u8; 28]);

        let mut owners = BTreeSet::new();
        owners.insert(StakeKeyHash::from_bytes([4u8; 28]));

        let mut params = StakePoolParams::new(
            pool_id,
            vrf_hash,
            500_000_000_000,
            340_000_000,
            Rational::from_percentage(5).unwrap(),
            reward_account,
            owners,
        )
        .unwrap();

        let metadata =
            PoolMetadata::new("https://pool.example.com/meta.json".to_string(), [0u8; 32]).unwrap();

        assert!(params.set_metadata(metadata).is_ok());
        assert!(params.metadata.is_some());
    }
}
