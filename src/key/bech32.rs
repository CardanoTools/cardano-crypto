//! Bech32 human-readable prefix constants
//!
//! These constants define the Bech32 prefixes used by Cardano for encoding keys,
//! matching the prefixes defined in `cardano-api/src/Cardano/Api/Key/Internal/Class.hs`.
//!
//! # Overview
//!
//! Bech32 is a human-readable address format that includes:
//! - A human-readable part (HRP) prefix identifying the type
//! - A separator `1`
//! - A base32-encoded data part
//! - A checksum
//!
//! # Prefix Naming Convention
//!
//! - `_vk` suffix = verification (public) key
//! - `_sk` suffix = signing (secret) key
//! - `_xvk` suffix = extended verification key
//! - `_xsk` suffix = extended signing key
//!
//! # Examples
//!
//! ```rust
//! use cardano_crypto::key::bech32::*;
//!
//! // Payment key prefixes
//! assert_eq!(PAYMENT_VERIFICATION_KEY_PREFIX, "addr_vk");
//! assert_eq!(PAYMENT_SIGNING_KEY_PREFIX, "addr_sk");
//!
//! // VRF key prefixes
//! assert_eq!(VRF_VERIFICATION_KEY_PREFIX, "vrf_vk");
//! assert_eq!(VRF_SIGNING_KEY_PREFIX, "vrf_sk");
//!
//! // KES key prefixes
//! assert_eq!(KES_VERIFICATION_KEY_PREFIX, "kes_vk");
//! assert_eq!(KES_SIGNING_KEY_PREFIX, "kes_sk");
//! ```

// =============================================================================
// Payment Key Prefixes (Ed25519)
// =============================================================================

/// Bech32 prefix for payment verification keys
///
/// Used for Ed25519 public keys that can receive payments.
///
/// # Example
/// ```rust
/// use cardano_crypto::key::bech32::PAYMENT_VERIFICATION_KEY_PREFIX;
/// assert_eq!(PAYMENT_VERIFICATION_KEY_PREFIX, "addr_vk");
/// ```
pub const PAYMENT_VERIFICATION_KEY_PREFIX: &str = "addr_vk";

/// Bech32 prefix for payment signing keys
///
/// Used for Ed25519 private keys that can sign payment transactions.
pub const PAYMENT_SIGNING_KEY_PREFIX: &str = "addr_sk";

/// Bech32 prefix for extended payment verification keys
///
/// Used for BIP32-Ed25519 extended public keys.
pub const PAYMENT_EXTENDED_VERIFICATION_KEY_PREFIX: &str = "addr_xvk";

/// Bech32 prefix for extended payment signing keys
///
/// Used for BIP32-Ed25519 extended private keys.
pub const PAYMENT_EXTENDED_SIGNING_KEY_PREFIX: &str = "addr_xsk";

// =============================================================================
// Stake Key Prefixes (Ed25519)
// =============================================================================

/// Bech32 prefix for stake verification keys
///
/// Used for Ed25519 public keys that control staking delegation.
///
/// # Example
/// ```rust
/// use cardano_crypto::key::bech32::STAKE_VERIFICATION_KEY_PREFIX;
/// assert_eq!(STAKE_VERIFICATION_KEY_PREFIX, "stake_vk");
/// ```
pub const STAKE_VERIFICATION_KEY_PREFIX: &str = "stake_vk";

/// Bech32 prefix for stake signing keys
///
/// Used for Ed25519 private keys that can sign staking operations.
pub const STAKE_SIGNING_KEY_PREFIX: &str = "stake_sk";

/// Bech32 prefix for extended stake verification keys
pub const STAKE_EXTENDED_VERIFICATION_KEY_PREFIX: &str = "stake_xvk";

/// Bech32 prefix for extended stake signing keys
pub const STAKE_EXTENDED_SIGNING_KEY_PREFIX: &str = "stake_xsk";

// =============================================================================
// Stake Pool Key Prefixes (Ed25519)
// =============================================================================

/// Bech32 prefix for stake pool verification keys
///
/// Used for Ed25519 public keys that identify stake pool operators.
/// This is the cold verification key used in pool registration certificates.
///
/// # Example
/// ```rust
/// use cardano_crypto::key::bech32::POOL_VERIFICATION_KEY_PREFIX;
/// assert_eq!(POOL_VERIFICATION_KEY_PREFIX, "pool_vk");
/// ```
pub const POOL_VERIFICATION_KEY_PREFIX: &str = "pool_vk";

/// Bech32 prefix for stake pool signing keys (cold key)
///
/// Used for Ed25519 private keys that sign pool registration/retirement certificates.
pub const POOL_SIGNING_KEY_PREFIX: &str = "pool_sk";

/// Bech32 prefix for extended pool verification keys
pub const POOL_EXTENDED_VERIFICATION_KEY_PREFIX: &str = "pool_xvk";

/// Bech32 prefix for extended pool signing keys
pub const POOL_EXTENDED_SIGNING_KEY_PREFIX: &str = "pool_xsk";

// =============================================================================
// VRF Key Prefixes (Praos VRF)
// =============================================================================

/// Bech32 prefix for VRF verification keys
///
/// Used for VRF public keys that verify random outputs.
/// VRF keys are used in the Praos consensus protocol for leader selection.
///
/// # Example
/// ```rust
/// use cardano_crypto::key::bech32::VRF_VERIFICATION_KEY_PREFIX;
/// assert_eq!(VRF_VERIFICATION_KEY_PREFIX, "vrf_vk");
/// ```
pub const VRF_VERIFICATION_KEY_PREFIX: &str = "vrf_vk";

/// Bech32 prefix for VRF signing keys
///
/// Used for VRF private keys that generate random outputs with proofs.
pub const VRF_SIGNING_KEY_PREFIX: &str = "vrf_sk";

// =============================================================================
// KES Key Prefixes (Sum6 KES)
// =============================================================================

/// Bech32 prefix for KES verification keys
///
/// Used for KES public keys that verify forward-secure signatures.
/// KES keys are used in block header signatures for operational security.
///
/// # Example
/// ```rust
/// use cardano_crypto::key::bech32::KES_VERIFICATION_KEY_PREFIX;
/// assert_eq!(KES_VERIFICATION_KEY_PREFIX, "kes_vk");
/// ```
pub const KES_VERIFICATION_KEY_PREFIX: &str = "kes_vk";

/// Bech32 prefix for KES signing keys
///
/// Used for KES private keys that create forward-secure signatures.
pub const KES_SIGNING_KEY_PREFIX: &str = "kes_sk";

// =============================================================================
// Genesis Key Prefixes
// =============================================================================

/// Bech32 prefix for genesis verification keys
pub const GENESIS_VERIFICATION_KEY_PREFIX: &str = "genesis_vk";

/// Bech32 prefix for genesis signing keys
pub const GENESIS_SIGNING_KEY_PREFIX: &str = "genesis_sk";

/// Bech32 prefix for extended genesis verification keys
pub const GENESIS_EXTENDED_VERIFICATION_KEY_PREFIX: &str = "genesis_xvk";

/// Bech32 prefix for extended genesis signing keys
pub const GENESIS_EXTENDED_SIGNING_KEY_PREFIX: &str = "genesis_xsk";

// =============================================================================
// Genesis Delegate Key Prefixes
// =============================================================================

/// Bech32 prefix for genesis delegate verification keys
pub const GENESIS_DELEGATE_VERIFICATION_KEY_PREFIX: &str = "genesis_delegate_vk";

/// Bech32 prefix for genesis delegate signing keys
pub const GENESIS_DELEGATE_SIGNING_KEY_PREFIX: &str = "genesis_delegate_sk";

/// Bech32 prefix for extended genesis delegate verification keys
pub const GENESIS_DELEGATE_EXTENDED_VERIFICATION_KEY_PREFIX: &str = "genesis_delegate_xvk";

/// Bech32 prefix for extended genesis delegate signing keys
pub const GENESIS_DELEGATE_EXTENDED_SIGNING_KEY_PREFIX: &str = "genesis_delegate_xsk";

// =============================================================================
// Genesis UTxO Key Prefixes
// =============================================================================

/// Bech32 prefix for genesis UTxO verification keys
pub const GENESIS_UTXO_VERIFICATION_KEY_PREFIX: &str = "genesis_utxo_vk";

/// Bech32 prefix for genesis UTxO signing keys
pub const GENESIS_UTXO_SIGNING_KEY_PREFIX: &str = "genesis_utxo_sk";

// =============================================================================
// DRep Key Prefixes (Governance)
// =============================================================================

/// Bech32 prefix for DRep verification keys
///
/// Used for delegated representative verification keys in governance.
pub const DREP_VERIFICATION_KEY_PREFIX: &str = "drep_vk";

/// Bech32 prefix for DRep signing keys
pub const DREP_SIGNING_KEY_PREFIX: &str = "drep_sk";

/// Bech32 prefix for extended DRep verification keys
pub const DREP_EXTENDED_VERIFICATION_KEY_PREFIX: &str = "drep_xvk";

/// Bech32 prefix for extended DRep signing keys
pub const DREP_EXTENDED_SIGNING_KEY_PREFIX: &str = "drep_xsk";

// =============================================================================
// Committee Key Prefixes (Governance)
// =============================================================================

/// Bech32 prefix for committee cold verification keys
pub const COMMITTEE_COLD_VERIFICATION_KEY_PREFIX: &str = "cc_cold_vk";

/// Bech32 prefix for committee cold signing keys
pub const COMMITTEE_COLD_SIGNING_KEY_PREFIX: &str = "cc_cold_sk";

/// Bech32 prefix for extended committee cold verification keys
pub const COMMITTEE_COLD_EXTENDED_VERIFICATION_KEY_PREFIX: &str = "cc_cold_xvk";

/// Bech32 prefix for extended committee cold signing keys
pub const COMMITTEE_COLD_EXTENDED_SIGNING_KEY_PREFIX: &str = "cc_cold_xsk";

/// Bech32 prefix for committee hot verification keys
pub const COMMITTEE_HOT_VERIFICATION_KEY_PREFIX: &str = "cc_hot_vk";

/// Bech32 prefix for committee hot signing keys
pub const COMMITTEE_HOT_SIGNING_KEY_PREFIX: &str = "cc_hot_sk";

/// Bech32 prefix for extended committee hot verification keys
pub const COMMITTEE_HOT_EXTENDED_VERIFICATION_KEY_PREFIX: &str = "cc_hot_xvk";

/// Bech32 prefix for extended committee hot signing keys
pub const COMMITTEE_HOT_EXTENDED_SIGNING_KEY_PREFIX: &str = "cc_hot_xsk";

// =============================================================================
// Hash Prefixes
// =============================================================================

/// Bech32 prefix for pool ID hashes
///
/// Pool IDs are Blake2b-224 hashes of pool verification keys.
pub const POOL_HASH_PREFIX: &str = "pool";

/// Bech32 prefix for stake pool metadata hashes
pub const POOL_METADATA_HASH_PREFIX: &str = "pool_md";

/// Bech32 prefix for verification key hashes (generic)
pub const VERIFICATION_KEY_HASH_PREFIX: &str = "addr_vkh";

/// Bech32 prefix for stake verification key hashes
pub const STAKE_VERIFICATION_KEY_HASH_PREFIX: &str = "stake_vkh";

/// Bech32 prefix for VRF verification key hashes
pub const VRF_VERIFICATION_KEY_HASH_PREFIX: &str = "vrf_vkh";

/// Bech32 prefix for script hashes
pub const SCRIPT_HASH_PREFIX: &str = "script";

/// Bech32 prefix for DRep key hashes
pub const DREP_KEY_HASH_PREFIX: &str = "drep";

/// Bech32 prefix for committee cold key hashes
pub const COMMITTEE_COLD_KEY_HASH_PREFIX: &str = "cc_cold";

/// Bech32 prefix for committee hot key hashes
pub const COMMITTEE_HOT_KEY_HASH_PREFIX: &str = "cc_hot";

// =============================================================================
// Node Operational Certificate
// =============================================================================

/// Bech32 prefix for node operational certificates
pub const NODE_OPCERT_PREFIX: &str = "node_opcert";

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_key_prefixes() {
        assert_eq!(PAYMENT_VERIFICATION_KEY_PREFIX, "addr_vk");
        assert_eq!(PAYMENT_SIGNING_KEY_PREFIX, "addr_sk");
        assert_eq!(PAYMENT_EXTENDED_VERIFICATION_KEY_PREFIX, "addr_xvk");
        assert_eq!(PAYMENT_EXTENDED_SIGNING_KEY_PREFIX, "addr_xsk");
    }

    #[test]
    fn test_stake_key_prefixes() {
        assert_eq!(STAKE_VERIFICATION_KEY_PREFIX, "stake_vk");
        assert_eq!(STAKE_SIGNING_KEY_PREFIX, "stake_sk");
        assert_eq!(STAKE_EXTENDED_VERIFICATION_KEY_PREFIX, "stake_xvk");
        assert_eq!(STAKE_EXTENDED_SIGNING_KEY_PREFIX, "stake_xsk");
    }

    #[test]
    fn test_pool_key_prefixes() {
        assert_eq!(POOL_VERIFICATION_KEY_PREFIX, "pool_vk");
        assert_eq!(POOL_SIGNING_KEY_PREFIX, "pool_sk");
        assert_eq!(POOL_EXTENDED_VERIFICATION_KEY_PREFIX, "pool_xvk");
        assert_eq!(POOL_EXTENDED_SIGNING_KEY_PREFIX, "pool_xsk");
    }

    #[test]
    fn test_vrf_key_prefixes() {
        assert_eq!(VRF_VERIFICATION_KEY_PREFIX, "vrf_vk");
        assert_eq!(VRF_SIGNING_KEY_PREFIX, "vrf_sk");
    }

    #[test]
    fn test_kes_key_prefixes() {
        assert_eq!(KES_VERIFICATION_KEY_PREFIX, "kes_vk");
        assert_eq!(KES_SIGNING_KEY_PREFIX, "kes_sk");
    }

    #[test]
    fn test_genesis_key_prefixes() {
        assert_eq!(GENESIS_VERIFICATION_KEY_PREFIX, "genesis_vk");
        assert_eq!(GENESIS_SIGNING_KEY_PREFIX, "genesis_sk");
    }

    #[test]
    fn test_governance_key_prefixes() {
        assert_eq!(DREP_VERIFICATION_KEY_PREFIX, "drep_vk");
        assert_eq!(DREP_SIGNING_KEY_PREFIX, "drep_sk");
        assert_eq!(COMMITTEE_COLD_VERIFICATION_KEY_PREFIX, "cc_cold_vk");
        assert_eq!(COMMITTEE_HOT_VERIFICATION_KEY_PREFIX, "cc_hot_vk");
    }

    #[test]
    fn test_hash_prefixes() {
        assert_eq!(POOL_HASH_PREFIX, "pool");
        assert_eq!(VERIFICATION_KEY_HASH_PREFIX, "addr_vkh");
        assert_eq!(STAKE_VERIFICATION_KEY_HASH_PREFIX, "stake_vkh");
        assert_eq!(VRF_VERIFICATION_KEY_HASH_PREFIX, "vrf_vkh");
        assert_eq!(SCRIPT_HASH_PREFIX, "script");
    }

    #[test]
    fn test_prefix_naming_convention() {
        // All verification key prefixes end with _vk
        assert!(PAYMENT_VERIFICATION_KEY_PREFIX.ends_with("_vk"));
        assert!(STAKE_VERIFICATION_KEY_PREFIX.ends_with("_vk"));
        assert!(POOL_VERIFICATION_KEY_PREFIX.ends_with("_vk"));
        assert!(VRF_VERIFICATION_KEY_PREFIX.ends_with("_vk"));
        assert!(KES_VERIFICATION_KEY_PREFIX.ends_with("_vk"));

        // All signing key prefixes end with _sk
        assert!(PAYMENT_SIGNING_KEY_PREFIX.ends_with("_sk"));
        assert!(STAKE_SIGNING_KEY_PREFIX.ends_with("_sk"));
        assert!(POOL_SIGNING_KEY_PREFIX.ends_with("_sk"));
        assert!(VRF_SIGNING_KEY_PREFIX.ends_with("_sk"));
        assert!(KES_SIGNING_KEY_PREFIX.ends_with("_sk"));

        // Extended keys end with _xvk or _xsk
        assert!(PAYMENT_EXTENDED_VERIFICATION_KEY_PREFIX.ends_with("_xvk"));
        assert!(PAYMENT_EXTENDED_SIGNING_KEY_PREFIX.ends_with("_xsk"));
    }
}
