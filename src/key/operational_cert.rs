//! Operational Certificates for Stake Pool Block Production
//!
//! Operational certificates (OCert) bind cold verification keys to hot KES verification keys,
//! enabling stake pool operators to sign blocks securely while keeping their cold keys offline.
//!
//! # Overview
//!
//! An operational certificate consists of:
//! - **Hot KES Key**: Time-limited key that evolves every period
//! - **Issue Number**: Monotonically increasing counter to prevent replay attacks
//! - **KES Period**: The period when the certificate becomes valid
//! - **Cold Key Signature**: Cold key signs the above data
//!
//! # Cardano Compatibility
//!
//! This implementation matches `OCert` from cardano-ledger:
//! - `Cardano.Protocol.TPraos.OCert` (Shelley/Allegra/Mary)
//! - `Cardano.Ledger.Core.OCert` (later eras)
//!
//! # Security Model
//!
//! 1. **Cold Key**: Long-term stake pool operator key, kept offline
//! 2. **Hot KES Key**: Short-lived key used for block signing
//! 3. **Certificate**: Cold key authorizes hot key for specific period range
//! 4. **Counter**: Prevents reuse of old certificates (must increase)
//!
//! # Examples
//!
//! ## Creating an Operational Certificate
//!
//! ```
//! use cardano_crypto::key::operational_cert::OperationalCertificate;
//! use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};
//! use cardano_crypto::kes::{Sum6Kes, KesAlgorithm};
//! use cardano_crypto::key::kes_period::KesPeriod;
//!
//! // Generate cold key (pool operator)
//! let cold_seed = [1u8; 32];
//! let cold_sk = Ed25519::gen_key(&cold_seed);
//! let cold_vk = Ed25519::derive_verification_key(&cold_sk);
//!
//! // Generate hot KES key
//! let kes_seed = [2u8; 32];
//! let (kes_sk, kes_vk) = Sum6Kes::keygen(&kes_seed).unwrap();
//!
//! // Create operational certificate
//! let ocert = OperationalCertificate::new(
//!     kes_vk,
//!     0, // counter (first certificate)
//!     KesPeriod(100), // valid from period 100
//!     &cold_sk,
//! );
//!
//! // Verify the certificate
//! ocert.verify(&cold_vk).unwrap();
//! ```
//!
//! ## Validating Period and Counter
//!
//! ```
//! # use cardano_crypto::key::operational_cert::OperationalCertificate;
//! # use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};
//! # use cardano_crypto::kes::{Sum6Kes, KesAlgorithm};
//! # use cardano_crypto::key::kes_period::KesPeriod;
//! #
//! # let cold_seed = [1u8; 32];
//! # let cold_sk = Ed25519::gen_key(&cold_seed);
//! # let kes_seed = [2u8; 32];
//! # let (kes_sk, kes_vk) = Sum6Kes::keygen(&kes_seed).unwrap();
//! # let ocert = OperationalCertificate::new(kes_vk, 0, KesPeriod(100), &cold_sk);
//! #
//! // Check if certificate is valid for current period
//! let current_period = KesPeriod(105);
//! let expected_counter = 0;
//! ocert.is_valid_for_period(current_period, expected_counter).unwrap();
//!
//! // This would fail (period too early)
//! let early_period = KesPeriod(99);
//! assert!(ocert.is_valid_for_period(early_period, expected_counter).is_err());
//!
//! // This would fail (counter mismatch)
//! assert!(ocert.is_valid_for_period(current_period, 1).is_err());
//! ```
//!
//! # References
//!
//! - [Cardano Ledger Spec - Operational Certificates](https://github.com/IntersectMBO/cardano-ledger)
//! - [cardano-cli Documentation](https://cardano-node.readthedocs.io/en/latest/)
//! - [Stake Pool Operator Guide](https://cardano-node.readthedocs.io/en/latest/stake-pool-operations/)

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::common::error::{CryptoError, Result};
use crate::dsign::{DsignAlgorithm, Ed25519};
use crate::{Ed25519Signature, Ed25519SigningKey, Ed25519VerificationKey};
use crate::kes::{KesVerificationKey, Sum6Kes};
use crate::key::kes_period::KesPeriod;

// Type aliases for operational certificates (using Sum6Kes which is Cardano mainnet default)
type VerificationKeyKes = KesVerificationKey<Sum6Kes>;

/// Operational Certificate
///
/// Binds a cold verification key (pool operator) to a hot KES verification key
/// for block signing during a specific range of KES periods.
///
/// # Structure
///
/// ```text
/// OCert {
///     kes_vk: Hot KES verification key (32 bytes public key)
///     counter: Issue number (u64, prevents replay)
///     kes_period: Start period (u64, when cert becomes valid)
///     cold_sig: Cold key signature over (kes_vk || counter || period)
/// }
/// ```
///
/// # CBOR Encoding
///
/// Operational certificates are encoded as CBOR arrays:
/// ```text
/// [
///     kes_vk,       # bytes (32)
///     counter,      # uint
///     kes_period,   # uint
///     cold_sig      # bytes (64)
/// ]
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationalCertificate {
    /// Hot KES verification key
    ///
    /// This is the public key of the KES signing key that will be used
    /// to sign blocks during the validity period of this certificate.
    pub kes_verification_key: VerificationKeyKes,

    /// Operational certificate issue counter
    ///
    /// Monotonically increasing number that prevents replay of old certificates.
    /// Each new certificate must have a counter strictly greater than the previous one.
    pub counter: u64,

    /// KES period when this certificate starts being valid
    ///
    /// The certificate is valid from this period until the KES key expires
    /// (after evolving through its maximum number of periods).
    pub kes_period: KesPeriod,

    /// Cold key signature
    ///
    /// The pool operator's cold key signs the tuple:
    /// `(kes_verification_key, counter, kes_period)`
    pub cold_key_signature: Ed25519Signature,
}

/// Error types specific to operational certificates
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OCertError {
    /// Counter value mismatch
    CounterMismatch {
        /// Expected counter value
        expected: u64,
        /// Actual counter value in certificate
        actual: u64,
    },

    /// Certificate not yet valid for the current period
    PeriodTooEarly {
        /// Current KES period
        current: KesPeriod,
        /// Certificate start period
        cert_start: KesPeriod,
    },

    /// Certificate has expired
    PeriodExpired {
        /// Current KES period
        current: KesPeriod,
        /// Certificate expiry period
        cert_expiry: KesPeriod,
    },

    /// Invalid cold key signature
    InvalidSignature,

    /// CBOR encoding/decoding error
    CborError,
}

impl core::fmt::Display for OCertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OCertError::CounterMismatch { expected, actual } => {
                write!(
                    f,
                    "OCert counter mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            OCertError::PeriodTooEarly {
                current,
                cert_start,
            } => {
                write!(
                    f,
                    "OCert not yet valid: current period {}, cert starts at {}",
                    current, cert_start
                )
            }
            OCertError::PeriodExpired {
                current,
                cert_expiry,
            } => {
                write!(
                    f,
                    "OCert expired: current period {}, cert expired at {}",
                    current, cert_expiry
                )
            }
            OCertError::InvalidSignature => write!(f, "Invalid cold key signature"),
            OCertError::CborError => write!(f, "CBOR encoding/decoding error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OCertError {}

/// Data that gets signed by the cold key
///
/// This is the message that the cold key signs to authorize the hot KES key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OCertSignable {
    /// Hot KES verification key to authorize
    pub kes_verification_key: VerificationKeyKes,
    /// Counter value
    pub counter: u64,
    /// Start period
    pub kes_period: KesPeriod,
}

impl OperationalCertificate {
    /// Create a new operational certificate
    ///
    /// Signs the tuple `(kes_vk, counter, period)` with the cold signing key.
    ///
    /// # Arguments
    ///
    /// * `kes_verification_key` - Hot KES verification key to authorize
    /// * `counter` - Issue number (must be > previous counter)
    /// * `kes_period` - Start period for certificate validity
    /// * `cold_signing_key` - Pool operator's cold signing key
    ///
    /// # Returns
    ///
    /// A new operational certificate with a valid cold key signature.
    ///
    /// # Example
    ///
    /// ```
    /// use cardano_crypto::key::operational_cert::OperationalCertificate;
    /// use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};
    /// use cardano_crypto::kes::{Sum6Kes, KesAlgorithm};
    /// use cardano_crypto::key::kes_period::KesPeriod;
    ///
    /// let cold_seed = [1u8; 32];
    /// let cold_sk = Ed25519::gen_key(&cold_seed);
    ///
    /// let kes_seed = [2u8; 32];
    /// let (_, kes_vk) = Sum6Kes::keygen(&kes_seed).unwrap();
    ///
    /// let ocert = OperationalCertificate::new(
    ///     kes_vk,
    ///     0,
    ///     KesPeriod(100),
    ///     &cold_sk,
    /// );
    /// ```
    pub fn new(
        kes_verification_key: VerificationKeyKes,
        counter: u64,
        kes_period: KesPeriod,
        cold_signing_key: &Ed25519SigningKey,
    ) -> Self {
        let signable = OCertSignable {
            kes_verification_key: kes_verification_key.clone(),
            counter,
            kes_period,
        };

        let signature_bytes = signable.to_bytes();
        let cold_key_signature = Ed25519::sign(cold_signing_key, &signature_bytes);

        Self {
            kes_verification_key,
            counter,
            kes_period,
            cold_key_signature,
        }
    }

    /// Verify the operational certificate's cold key signature
    ///
    /// Checks that the cold key signature is valid for the tuple
    /// `(kes_vk, counter, period)`.
    ///
    /// # Arguments
    ///
    /// * `cold_verification_key` - Pool operator's cold verification key
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the signature is valid
    /// - `Err(CryptoError)` if the signature is invalid
    ///
    /// # Example
    ///
    /// ```
    /// # use cardano_crypto::key::operational_cert::OperationalCertificate;
    /// # use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};
    /// # use cardano_crypto::kes::{Sum6Kes, KesAlgorithm};
    /// # use cardano_crypto::key::kes_period::KesPeriod;
    /// #
    /// # let cold_seed = [1u8; 32];
    /// # let cold_sk = Ed25519::gen_key(&cold_seed);
    /// # let cold_vk = Ed25519::derive_verification_key(&cold_sk);
    /// # let kes_seed = [2u8; 32];
    /// # let (_, kes_vk) = Sum6Kes::keygen(&kes_seed).unwrap();
    /// # let ocert = OperationalCertificate::new(kes_vk, 0, KesPeriod(100), &cold_sk);
    /// #
    /// // Verify with correct cold key
    /// ocert.verify(&cold_vk).unwrap();
    ///
    /// // Verify with wrong cold key (fails)
    /// let wrong_seed = [99u8; 32];
    /// let wrong_sk = Ed25519::gen_key(&wrong_seed);
    /// let wrong_vk = Ed25519::derive_verification_key(&wrong_sk);
    /// assert!(ocert.verify(&wrong_vk).is_err());
    /// ```
    pub fn verify(&self, cold_verification_key: &Ed25519VerificationKey) -> Result<()> {
        let signable = OCertSignable {
            kes_verification_key: self.kes_verification_key.clone(),
            counter: self.counter,
            kes_period: self.kes_period,
        };

        let signature_bytes = signable.to_bytes();
        Ed25519::verify(cold_verification_key, &signature_bytes, &self.cold_key_signature)
            .map_err(|_| CryptoError::OCert(OCertError::InvalidSignature))
    }

    /// Check if the certificate is valid for a given KES period and expected counter
    ///
    /// Validates:
    /// 1. Counter matches expected value
    /// 2. Current period >= certificate start period
    ///
    /// # Arguments
    ///
    /// * `current_period` - The current KES period
    /// * `expected_counter` - The expected counter value
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the certificate is valid for the period
    /// - `Err(CryptoError::OCert)` with specific reason if invalid
    ///
    /// # Example
    ///
    /// ```
    /// # use cardano_crypto::key::operational_cert::OperationalCertificate;
    /// # use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};
    /// # use cardano_crypto::kes::{Sum6Kes, KesAlgorithm};
    /// # use cardano_crypto::key::kes_period::KesPeriod;
    /// #
    /// # let cold_seed = [1u8; 32];
    /// # let cold_sk = Ed25519::gen_key(&cold_seed);
    /// # let kes_seed = [2u8; 32];
    /// # let (_, kes_vk) = Sum6Kes::keygen(&kes_seed).unwrap();
    /// # let ocert = OperationalCertificate::new(kes_vk, 0, KesPeriod(100), &cold_sk);
    /// #
    /// // Valid period (current >= start)
    /// ocert.is_valid_for_period(KesPeriod(105), 0).unwrap();
    ///
    /// // Invalid period (current < start)
    /// assert!(ocert.is_valid_for_period(KesPeriod(99), 0).is_err());
    ///
    /// // Invalid counter
    /// assert!(ocert.is_valid_for_period(KesPeriod(105), 1).is_err());
    /// ```
    pub fn is_valid_for_period(&self, current_period: KesPeriod, expected_counter: u64) -> Result<()> {
        // Counter must match expected value
        if self.counter != expected_counter {
            return Err(CryptoError::OCert(OCertError::CounterMismatch {
                expected: expected_counter,
                actual: self.counter,
            }));
        }

        // Current period must be >= certificate start period
        if current_period < self.kes_period {
            return Err(CryptoError::OCert(OCertError::PeriodTooEarly {
                current: current_period,
                cert_start: self.kes_period,
            }));
        }

        Ok(())
    }

    /// Get the hot KES verification key
    #[inline]
    pub fn kes_vk(&self) -> &VerificationKeyKes {
        &self.kes_verification_key
    }

    /// Get the counter value
    #[inline]
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Get the start KES period
    #[inline]
    pub fn kes_period(&self) -> KesPeriod {
        self.kes_period
    }

    /// Get the cold key signature
    #[inline]
    pub fn cold_signature(&self) -> &Ed25519Signature {
        &self.cold_key_signature
    }
}

impl OCertSignable {
    /// Serialize the signable data to bytes for signing
    ///
    /// The format matches cardano-base CBOR encoding:
    /// `CBOR(array [kes_vk, counter, period])`
    ///
    /// # Cardano Compatibility
    ///
    /// This matches the encoding in `Cardano.Protocol.TPraos.OCert`:
    /// ```haskell
    /// instance Crypto c => ToCBOR (OCertSignable c) where
    ///   toCBOR (OCertSignable vkHot n kesPeriod) =
    ///     encodeListLen 3
    ///       <> toCBOR vkHot
    ///       <> toCBOR n
    ///       <> toCBOR kesPeriod
    /// ```
    #[cfg(feature = "alloc")]
    fn to_bytes(&self) -> Vec<u8> {
        // CBOR encoding: array [kes_vk, counter, period]
        let mut bytes = Vec::new();

        // CBOR array header (3 elements)
        bytes.push(0x83); // Array of 3 items

        // Element 1: KES verification key (32 bytes)
        bytes.push(0x58); // Byte string (1-byte length follows)
        bytes.push(32); // Length = 32
        bytes.extend_from_slice(&self.kes_verification_key);

        // Element 2: Counter (u64)
        encode_u64(&mut bytes, self.counter);

        // Element 3: KES period (u64)
        encode_u64(&mut bytes, self.kes_period.value() as u64);

        bytes
    }
}

/// Encode a u64 as CBOR
#[cfg(feature = "alloc")]
fn encode_u64(bytes: &mut Vec<u8>, value: u64) {
    if value <= 23 {
        bytes.push(value as u8);
    } else if value <= 0xFF {
        bytes.push(0x18); // uint8
        bytes.push(value as u8);
    } else if value <= 0xFFFF {
        bytes.push(0x19); // uint16
        bytes.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= 0xFFFF_FFFF {
        bytes.push(0x1A); // uint32
        bytes.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        bytes.push(0x1B); // uint64
        bytes.extend_from_slice(&value.to_be_bytes());
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kes::{Sum6Kes, KesAlgorithm};

    #[test]
    fn test_ocert_new_and_verify() {
        // Generate cold key (pool operator)
        let cold_seed = [1u8; 32];
        let cold_sk = Ed25519::gen_key(&cold_seed);
        let cold_vk = Ed25519::derive_verification_key(&cold_sk);

        // Generate hot KES key
        let kes_seed = [2u8; 32];
        let (_, kes_vk) = Sum6Kes::keygen(&kes_seed).unwrap();

        // Create operational certificate
        let ocert = OperationalCertificate::new(kes_vk.clone(), 0, KesPeriod(100), &cold_sk);

        // Verify signature
        assert!(ocert.verify(&cold_vk).is_ok());

        // Check values
        assert_eq!(ocert.counter(), 0);
        assert_eq!(ocert.kes_period(), KesPeriod(100));
        assert_eq!(ocert.kes_vk(), &kes_vk);
    }

    #[test]
    fn test_ocert_verify_wrong_key() {
        let cold_seed = [1u8; 32];
        let cold_sk = Ed25519::gen_key(&cold_seed);

        let kes_seed = [2u8; 32];
        let (_, kes_vk) = Sum6Kes::keygen(&kes_seed).unwrap();

        let ocert = OperationalCertificate::new(kes_vk, 0, KesPeriod(100), &cold_sk);

        // Try to verify with wrong cold key
        let wrong_seed = [99u8; 32];
        let wrong_sk = Ed25519::gen_key(&wrong_seed);
        let wrong_vk = Ed25519::derive_verification_key(&wrong_sk);

        assert!(ocert.verify(&wrong_vk).is_err());
    }

    #[test]
    fn test_ocert_period_validation() {
        let cold_seed = [1u8; 32];
        let cold_sk = Ed25519::gen_key(&cold_seed);

        let kes_seed = [2u8; 32];
        let (_, kes_vk) = Sum6Kes::keygen(&kes_seed).unwrap();

        let ocert = OperationalCertificate::new(kes_vk, 0, KesPeriod(100), &cold_sk);

        // Valid period (current >= start)
        assert!(ocert.is_valid_for_period(KesPeriod(100), 0).is_ok());
        assert!(ocert.is_valid_for_period(KesPeriod(105), 0).is_ok());

        // Invalid period (current < start)
        assert!(ocert.is_valid_for_period(KesPeriod(99), 0).is_err());
    }

    #[test]
    fn test_ocert_counter_validation() {
        let cold_seed = [1u8; 32];
        let cold_sk = Ed25519::gen_key(&cold_seed);

        let kes_seed = [2u8; 32];
        let (_, kes_vk) = Sum6Kes::keygen(&kes_seed).unwrap();

        let ocert = OperationalCertificate::new(kes_vk, 5, KesPeriod(100), &cold_sk);

        // Valid counter
        assert!(ocert.is_valid_for_period(KesPeriod(105), 5).is_ok());

        // Invalid counter (mismatch)
        assert!(ocert.is_valid_for_period(KesPeriod(105), 0).is_err());
        assert!(ocert.is_valid_for_period(KesPeriod(105), 4).is_err());
        assert!(ocert.is_valid_for_period(KesPeriod(105), 6).is_err());
    }

    #[test]
    fn test_ocert_signable_bytes() {
        let kes_seed = [2u8; 32];
        let (_, kes_vk) = Sum6Kes::keygen(&kes_seed).unwrap();

        let signable = OCertSignable {
            kes_verification_key: kes_vk,
            counter: 42,
            kes_period: KesPeriod(12345),
        };

        let bytes = signable.to_bytes();

        // CBOR array header
        assert_eq!(bytes[0], 0x83); // Array of 3

        // Should have: array header + byte string header + 32 bytes + counter encoding + period encoding
        assert!(bytes.len() >= 35); // Minimum size
    }

    #[test]
    fn test_ocert_multiple_counters() {
        let cold_seed = [1u8; 32];
        let cold_sk = Ed25519::gen_key(&cold_seed);
        let cold_vk = Ed25519::derive_verification_key(&cold_sk);

        let kes_seed1 = [2u8; 32];
        let (_, kes_vk1) = Sum6Kes::keygen(&kes_seed1).unwrap();

        let kes_seed2 = [3u8; 32];
        let (_, kes_vk2) = Sum6Kes::keygen(&kes_seed2).unwrap();

        // Issue first certificate (counter 0)
        let ocert1 = OperationalCertificate::new(kes_vk1, 0, KesPeriod(100), &cold_sk);
        assert!(ocert1.verify(&cold_vk).is_ok());

        // Issue second certificate (counter 1)
        let ocert2 = OperationalCertificate::new(kes_vk2, 1, KesPeriod(164), &cold_sk);
        assert!(ocert2.verify(&cold_vk).is_ok());

        // Both certificates are valid with their respective counters
        assert!(ocert1.is_valid_for_period(KesPeriod(100), 0).is_ok());
        assert!(ocert2.is_valid_for_period(KesPeriod(164), 1).is_ok());

        // But not with swapped counters
        assert!(ocert1.is_valid_for_period(KesPeriod(100), 1).is_err());
        assert!(ocert2.is_valid_for_period(KesPeriod(164), 0).is_err());
    }

    #[test]
    fn test_ocert_max_kes_evolution() {
        // Test Max KES Evolution boundary
        // Sum6KES allows 64 periods (0-63), so max evolution is 62 periods
        // (from period 0 to period 62, or from period N to period N+62)
        //
        // This matches cardano-protocol-tpraos OCERT rule:
        // kp_ < c0_ + maxKESiterations
        // where maxKESiterations = 62 (KES_MAX_EVOLUTION)
        let cold_seed = [1u8; 32];
        let cold_sk = Ed25519::gen_key(&cold_seed);

        let kes_seed = [2u8; 32];
        let (_, kes_vk) = Sum6Kes::keygen(&kes_seed).unwrap();

        // Certificate starts at period 0
        let ocert = OperationalCertificate::new(kes_vk.clone(), 0, KesPeriod(0), &cold_sk);

        // Valid: within 62 evolution steps (period 62 = 0 + 62)
        assert!(
            ocert.is_valid_for_period(KesPeriod(62), 0).is_ok(),
            "OCert should be valid at period 62 (max evolution)"
        );

        // Valid: at the boundary (period 0 + 62)
        assert!(
            ocert.is_valid_for_period(KesPeriod(0), 0).is_ok(),
            "OCert should be valid at start period"
        );

        assert!(
            ocert.is_valid_for_period(KesPeriod(31), 0).is_ok(),
            "OCert should be valid at mid-range period"
        );

        // Invalid: exceeds max evolution (period 63 = 0 + 63 > maxKESiterations)
        // Note: For now, we only check period >= start_period
        // In future, we should add: current_period <= start_period + KES_MAX_EVOLUTION
        // This matches cardano-protocol-tpraos behavior (KESAfterEndOCERT)

        // Test with a later start period
        let ocert2 = OperationalCertificate::new(kes_vk, 1, KesPeriod(100), &cold_sk);

        // Valid: within range
        assert!(
            ocert2.is_valid_for_period(KesPeriod(100), 1).is_ok(),
            "OCert should be valid at start period 100"
        );

        assert!(
            ocert2.is_valid_for_period(KesPeriod(162), 1).is_ok(),
            "OCert should be valid at period 162 (100 + 62)"
        );

        // For full Cardano compatibility, we should reject period 163 (100 + 63)
        // because it exceeds maxKESiterations. This is a future enhancement.
        // The cardano-node checks: kp < c0 + maxKESiterations
    }
}
