//! TextEnvelope type description constants
//!
//! These constants define the type strings used in TextEnvelope JSON files
//! for storing keys and certificates, matching the types defined in
//! `cardano-api/src/Cardano/Api/Key/Internal/Class.hs`.
//!
//! # TextEnvelope Format
//!
//! Keys are stored in JSON files with the following structure:
//!
//! ```json
//! {
//!     "type": "PaymentVerificationKeyShelley_ed25519",
//!     "description": "Payment Verification Key",
//!     "cborHex": "5820..."
//! }
//! ```
//!
//! The `type` field uses these constants to identify the key type.
//!
//! # Examples
//!
//! ```rust
//! use cardano_crypto::key::text_envelope::*;
//!
//! assert_eq!(PAYMENT_VERIFICATION_KEY_TYPE, "PaymentVerificationKeyShelley_ed25519");
//! assert_eq!(VRF_VERIFICATION_KEY_TYPE, "VrfVerificationKey_PraosVRF");
//! ```

// =============================================================================
// Payment Key Types (Ed25519)
// =============================================================================

/// TextEnvelope type for payment verification keys
///
/// # Example
/// ```rust
/// use cardano_crypto::key::text_envelope::PAYMENT_VERIFICATION_KEY_TYPE;
/// assert_eq!(PAYMENT_VERIFICATION_KEY_TYPE, "PaymentVerificationKeyShelley_ed25519");
/// ```
pub const PAYMENT_VERIFICATION_KEY_TYPE: &str = "PaymentVerificationKeyShelley_ed25519";

/// TextEnvelope type for payment signing keys
pub const PAYMENT_SIGNING_KEY_TYPE: &str = "PaymentSigningKeyShelley_ed25519";

/// TextEnvelope type for extended payment verification keys
pub const PAYMENT_EXTENDED_VERIFICATION_KEY_TYPE: &str =
    "PaymentExtendedVerificationKeyShelley_ed25519_bip32";

/// TextEnvelope type for extended payment signing keys
pub const PAYMENT_EXTENDED_SIGNING_KEY_TYPE: &str =
    "PaymentExtendedSigningKeyShelley_ed25519_bip32";

// =============================================================================
// Stake Key Types (Ed25519)
// =============================================================================

/// TextEnvelope type for stake verification keys
pub const STAKE_VERIFICATION_KEY_TYPE: &str = "StakeVerificationKeyShelley_ed25519";

/// TextEnvelope type for stake signing keys
pub const STAKE_SIGNING_KEY_TYPE: &str = "StakeSigningKeyShelley_ed25519";

/// TextEnvelope type for extended stake verification keys
pub const STAKE_EXTENDED_VERIFICATION_KEY_TYPE: &str =
    "StakeExtendedVerificationKeyShelley_ed25519_bip32";

/// TextEnvelope type for extended stake signing keys
pub const STAKE_EXTENDED_SIGNING_KEY_TYPE: &str = "StakeExtendedSigningKeyShelley_ed25519_bip32";

// =============================================================================
// Stake Pool Key Types (Ed25519)
// =============================================================================

/// TextEnvelope type for stake pool verification keys (cold key)
///
/// # Example
/// ```rust
/// use cardano_crypto::key::text_envelope::POOL_VERIFICATION_KEY_TYPE;
/// assert_eq!(POOL_VERIFICATION_KEY_TYPE, "StakePoolVerificationKey_ed25519");
/// ```
pub const POOL_VERIFICATION_KEY_TYPE: &str = "StakePoolVerificationKey_ed25519";

/// TextEnvelope type for stake pool signing keys (cold key)
pub const POOL_SIGNING_KEY_TYPE: &str = "StakePoolSigningKey_ed25519";

/// TextEnvelope type for extended pool verification keys
pub const POOL_EXTENDED_VERIFICATION_KEY_TYPE: &str =
    "StakePoolExtendedVerificationKey_ed25519_bip32";

/// TextEnvelope type for extended pool signing keys
pub const POOL_EXTENDED_SIGNING_KEY_TYPE: &str = "StakePoolExtendedSigningKey_ed25519_bip32";

// =============================================================================
// VRF Key Types (Praos VRF)
// =============================================================================

/// TextEnvelope type for VRF verification keys
///
/// # Example
/// ```rust
/// use cardano_crypto::key::text_envelope::VRF_VERIFICATION_KEY_TYPE;
/// assert_eq!(VRF_VERIFICATION_KEY_TYPE, "VrfVerificationKey_PraosVRF");
/// ```
pub const VRF_VERIFICATION_KEY_TYPE: &str = "VrfVerificationKey_PraosVRF";

/// TextEnvelope type for VRF signing keys
pub const VRF_SIGNING_KEY_TYPE: &str = "VrfSigningKey_PraosVRF";

// =============================================================================
// KES Key Types (Sum6 KES)
// =============================================================================

/// TextEnvelope type for KES verification keys
///
/// # Example
/// ```rust
/// use cardano_crypto::key::text_envelope::KES_VERIFICATION_KEY_TYPE;
/// assert_eq!(KES_VERIFICATION_KEY_TYPE, "KesVerificationKey_ed25519_kes_2^6");
/// ```
pub const KES_VERIFICATION_KEY_TYPE: &str = "KesVerificationKey_ed25519_kes_2^6";

/// TextEnvelope type for KES signing keys
pub const KES_SIGNING_KEY_TYPE: &str = "KesSigningKey_ed25519_kes_2^6";

// =============================================================================
// Genesis Key Types
// =============================================================================

/// TextEnvelope type for genesis verification keys
pub const GENESIS_VERIFICATION_KEY_TYPE: &str = "GenesisVerificationKey_ed25519";

/// TextEnvelope type for genesis signing keys
pub const GENESIS_SIGNING_KEY_TYPE: &str = "GenesisSigningKey_ed25519";

/// TextEnvelope type for extended genesis verification keys
pub const GENESIS_EXTENDED_VERIFICATION_KEY_TYPE: &str =
    "GenesisExtendedVerificationKey_ed25519_bip32";

/// TextEnvelope type for extended genesis signing keys
pub const GENESIS_EXTENDED_SIGNING_KEY_TYPE: &str = "GenesisExtendedSigningKey_ed25519_bip32";

// =============================================================================
// Genesis Delegate Key Types
// =============================================================================

/// TextEnvelope type for genesis delegate verification keys
pub const GENESIS_DELEGATE_VERIFICATION_KEY_TYPE: &str = "GenesisDelegateVerificationKey_ed25519";

/// TextEnvelope type for genesis delegate signing keys
pub const GENESIS_DELEGATE_SIGNING_KEY_TYPE: &str = "GenesisDelegateSigningKey_ed25519";

/// TextEnvelope type for extended genesis delegate verification keys
pub const GENESIS_DELEGATE_EXTENDED_VERIFICATION_KEY_TYPE: &str =
    "GenesisDelegateExtendedVerificationKey_ed25519_bip32";

/// TextEnvelope type for extended genesis delegate signing keys
pub const GENESIS_DELEGATE_EXTENDED_SIGNING_KEY_TYPE: &str =
    "GenesisDelegateExtendedSigningKey_ed25519_bip32";

// =============================================================================
// Genesis UTxO Key Types
// =============================================================================

/// TextEnvelope type for genesis UTxO verification keys
pub const GENESIS_UTXO_VERIFICATION_KEY_TYPE: &str = "GenesisUTxOVerificationKey_ed25519";

/// TextEnvelope type for genesis UTxO signing keys
pub const GENESIS_UTXO_SIGNING_KEY_TYPE: &str = "GenesisUTxOSigningKey_ed25519";

// =============================================================================
// DRep Key Types (Governance)
// =============================================================================

/// TextEnvelope type for DRep verification keys
pub const DREP_VERIFICATION_KEY_TYPE: &str = "DRepVerificationKey_ed25519";

/// TextEnvelope type for DRep signing keys
pub const DREP_SIGNING_KEY_TYPE: &str = "DRepSigningKey_ed25519";

/// TextEnvelope type for extended DRep verification keys
pub const DREP_EXTENDED_VERIFICATION_KEY_TYPE: &str = "DRepExtendedVerificationKey_ed25519_bip32";

/// TextEnvelope type for extended DRep signing keys
pub const DREP_EXTENDED_SIGNING_KEY_TYPE: &str = "DRepExtendedSigningKey_ed25519_bip32";

// =============================================================================
// Committee Key Types (Governance)
// =============================================================================

/// TextEnvelope type for committee cold verification keys
pub const COMMITTEE_COLD_VERIFICATION_KEY_TYPE: &str =
    "ConstitutionalCommitteeColdVerificationKey_ed25519";

/// TextEnvelope type for committee cold signing keys
pub const COMMITTEE_COLD_SIGNING_KEY_TYPE: &str = "ConstitutionalCommitteeColdSigningKey_ed25519";

/// TextEnvelope type for extended committee cold verification keys
pub const COMMITTEE_COLD_EXTENDED_VERIFICATION_KEY_TYPE: &str =
    "ConstitutionalCommitteeColdExtendedVerificationKey_ed25519_bip32";

/// TextEnvelope type for extended committee cold signing keys
pub const COMMITTEE_COLD_EXTENDED_SIGNING_KEY_TYPE: &str =
    "ConstitutionalCommitteeColdExtendedSigningKey_ed25519_bip32";

/// TextEnvelope type for committee hot verification keys
pub const COMMITTEE_HOT_VERIFICATION_KEY_TYPE: &str =
    "ConstitutionalCommitteeHotVerificationKey_ed25519";

/// TextEnvelope type for committee hot signing keys
pub const COMMITTEE_HOT_SIGNING_KEY_TYPE: &str = "ConstitutionalCommitteeHotSigningKey_ed25519";

/// TextEnvelope type for extended committee hot verification keys
pub const COMMITTEE_HOT_EXTENDED_VERIFICATION_KEY_TYPE: &str =
    "ConstitutionalCommitteeHotExtendedVerificationKey_ed25519_bip32";

/// TextEnvelope type for extended committee hot signing keys
pub const COMMITTEE_HOT_EXTENDED_SIGNING_KEY_TYPE: &str =
    "ConstitutionalCommitteeHotExtendedSigningKey_ed25519_bip32";

// =============================================================================
// Certificate Types
// =============================================================================

/// TextEnvelope type for node operational certificates
pub const NODE_OPERATIONAL_CERTIFICATE_TYPE: &str = "NodeOperationalCertificate";

/// TextEnvelope type for operational certificate issue counter
pub const OPERATIONAL_CERTIFICATE_ISSUE_COUNTER_TYPE: &str =
    "NodeOperationalCertificateIssueCounter";

// =============================================================================
// Signature Types
// =============================================================================

/// TextEnvelope type for Ed25519 signatures
pub const ED25519_SIGNATURE_TYPE: &str = "Ed25519Signature";

/// TextEnvelope type for KES signatures
pub const KES_SIGNATURE_TYPE: &str = "KesSignature_ed25519_kes_2^6";

/// TextEnvelope type for VRF proofs
pub const VRF_PROOF_TYPE: &str = "VrfProof_PraosVRF";

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_key_types() {
        assert_eq!(
            PAYMENT_VERIFICATION_KEY_TYPE,
            "PaymentVerificationKeyShelley_ed25519"
        );
        assert_eq!(PAYMENT_SIGNING_KEY_TYPE, "PaymentSigningKeyShelley_ed25519");
        assert_eq!(
            PAYMENT_EXTENDED_VERIFICATION_KEY_TYPE,
            "PaymentExtendedVerificationKeyShelley_ed25519_bip32"
        );
        assert_eq!(
            PAYMENT_EXTENDED_SIGNING_KEY_TYPE,
            "PaymentExtendedSigningKeyShelley_ed25519_bip32"
        );
    }

    #[test]
    fn test_stake_key_types() {
        assert_eq!(
            STAKE_VERIFICATION_KEY_TYPE,
            "StakeVerificationKeyShelley_ed25519"
        );
        assert_eq!(STAKE_SIGNING_KEY_TYPE, "StakeSigningKeyShelley_ed25519");
    }

    #[test]
    fn test_pool_key_types() {
        assert_eq!(
            POOL_VERIFICATION_KEY_TYPE,
            "StakePoolVerificationKey_ed25519"
        );
        assert_eq!(POOL_SIGNING_KEY_TYPE, "StakePoolSigningKey_ed25519");
    }

    #[test]
    fn test_vrf_key_types() {
        assert_eq!(VRF_VERIFICATION_KEY_TYPE, "VrfVerificationKey_PraosVRF");
        assert_eq!(VRF_SIGNING_KEY_TYPE, "VrfSigningKey_PraosVRF");
    }

    #[test]
    fn test_kes_key_types() {
        assert_eq!(
            KES_VERIFICATION_KEY_TYPE,
            "KesVerificationKey_ed25519_kes_2^6"
        );
        assert_eq!(KES_SIGNING_KEY_TYPE, "KesSigningKey_ed25519_kes_2^6");
    }

    #[test]
    fn test_governance_key_types() {
        assert_eq!(DREP_VERIFICATION_KEY_TYPE, "DRepVerificationKey_ed25519");
        assert_eq!(
            COMMITTEE_COLD_VERIFICATION_KEY_TYPE,
            "ConstitutionalCommitteeColdVerificationKey_ed25519"
        );
        assert_eq!(
            COMMITTEE_HOT_VERIFICATION_KEY_TYPE,
            "ConstitutionalCommitteeHotVerificationKey_ed25519"
        );
    }

    #[test]
    fn test_certificate_types() {
        assert_eq!(
            NODE_OPERATIONAL_CERTIFICATE_TYPE,
            "NodeOperationalCertificate"
        );
        assert_eq!(
            OPERATIONAL_CERTIFICATE_ISSUE_COUNTER_TYPE,
            "NodeOperationalCertificateIssueCounter"
        );
    }

    #[test]
    fn test_type_naming_convention() {
        // Ed25519 keys include the algorithm suffix
        assert!(PAYMENT_VERIFICATION_KEY_TYPE.contains("ed25519"));
        assert!(STAKE_VERIFICATION_KEY_TYPE.contains("ed25519"));
        assert!(POOL_VERIFICATION_KEY_TYPE.contains("ed25519"));

        // Extended keys include bip32 suffix
        assert!(PAYMENT_EXTENDED_VERIFICATION_KEY_TYPE.contains("bip32"));
        assert!(STAKE_EXTENDED_VERIFICATION_KEY_TYPE.contains("bip32"));

        // VRF keys specify PraosVRF
        assert!(VRF_VERIFICATION_KEY_TYPE.contains("PraosVRF"));
        assert!(VRF_SIGNING_KEY_TYPE.contains("PraosVRF"));

        // KES keys specify the scheme (kes_2^6)
        assert!(KES_VERIFICATION_KEY_TYPE.contains("kes_2^6"));
        assert!(KES_SIGNING_KEY_TYPE.contains("kes_2^6"));
    }
}
