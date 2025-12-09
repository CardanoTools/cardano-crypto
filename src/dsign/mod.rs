//! Digital signature algorithms (DSIGN)
//!
//! Provides digital signature schemes used in Cardano:
//!
//! - [`Ed25519`] - Standard Ed25519 signatures (used in Cardano transactions)
//! - Additional signature schemes for cross-chain compatibility
//!
//! # Examples
//!
//! ```
//! use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};
//!
//! // Generate a key pair
//! let seed = [42u8; 32];
//! let signing_key = Ed25519::gen_key(&seed);
//! let verification_key = Ed25519::derive_verification_key(&signing_key);
//!
//! // Sign a message
//! let message = b"Cardano transaction data";
//! let signature = Ed25519::sign(&signing_key, message);
//!
//! // Verify the signature
//! assert!(Ed25519::verify(&verification_key, message, &signature).is_ok());
//! ```

/// Digital signature module providing Ed25519 implementation
pub mod ed25519;

pub use ed25519::Ed25519;

/// Trait for digital signature algorithms
pub trait DsignAlgorithm: Clone + Send + Sync + 'static {
    /// Signing key type
    type SigningKey;

    /// Verification key type
    type VerificationKey;

    /// Signature type
    type Signature;

    /// Algorithm name
    const ALGORITHM_NAME: &'static str;

    /// Size of the signing key in bytes
    const SIGNING_KEY_SIZE: usize;

    /// Size of the verification key in bytes
    const VERIFICATION_KEY_SIZE: usize;

    /// Size of the signature in bytes
    const SIGNATURE_SIZE: usize;

    /// Derive verification key from signing key
    fn derive_verification_key(signing_key: &Self::SigningKey) -> Self::VerificationKey;

    /// Sign a message
    fn sign(signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature;

    /// Verify a signature
    fn verify(
        verification_key: &Self::VerificationKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> crate::common::Result<()>;

    /// Generate a key from a seed
    fn gen_key(seed: &[u8]) -> Self::SigningKey;

    /// Serialize verification key to raw bytes
    fn raw_serialize_verification_key(key: &Self::VerificationKey) -> &[u8];

    /// Deserialize verification key from raw bytes
    fn raw_deserialize_verification_key(bytes: &[u8]) -> Option<Self::VerificationKey>;

    /// Serialize signature to raw bytes
    fn raw_serialize_signature(sig: &Self::Signature) -> &[u8];

    /// Deserialize signature from raw bytes
    fn raw_deserialize_signature(bytes: &[u8]) -> Option<Self::Signature>;

    /// Hash a verification key
    ///
    /// This corresponds to `hashVerKeyDSIGN` in cardano-base. The default
    /// implementation uses the raw serialization of the verification key.
    ///
    /// # Type Parameters
    ///
    /// - `H`: The hash algorithm to use
    ///
    /// # Example
    ///
    /// ```
    /// use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};
    /// use cardano_crypto::hash::{Blake2b256, HashAlgorithm};
    ///
    /// let signing_key = Ed25519::gen_key(&[1u8; 32]);
    /// let vk = Ed25519::derive_verification_key(&signing_key);
    /// let hash = Ed25519::hash_verification_key::<Blake2b256>(&vk);
    /// assert_eq!(hash.len(), 32);
    /// ```
    fn hash_verification_key<H: crate::hash::HashAlgorithm>(
        key: &Self::VerificationKey,
    ) -> alloc::vec::Vec<u8> {
        let raw = Self::raw_serialize_verification_key(key);
        H::hash(raw)
    }
}

// ============================================================================
// SignedDSIGN wrapper
// ============================================================================

/// A value signed with a digital signature
///
/// This wrapper type matches Cardano's `SignedDSIGN v a` type from cardano-base.
/// It associates a signature with the type of value that was signed, providing
/// additional type safety.
///
/// # Type Parameters
///
/// - `D`: The DSIGN algorithm type
///
/// # Examples
///
/// ```
/// use cardano_crypto::dsign::{Ed25519, DsignAlgorithm, SignedDsign};
///
/// let seed = [42u8; 32];
/// let signing_key = Ed25519::gen_key(&seed);
/// let verification_key = Ed25519::derive_verification_key(&signing_key);
///
/// let message = b"important data";
/// let signed = SignedDsign::<Ed25519>::sign(&signing_key, message);
///
/// assert!(signed.verify(&verification_key, message).is_ok());
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct SignedDsign<D: DsignAlgorithm> {
    signature: D::Signature,
}

impl<D: DsignAlgorithm> core::fmt::Debug for SignedDsign<D>
where
    D::Signature: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedDsign")
            .field("signature", &self.signature)
            .finish()
    }
}

impl<D: DsignAlgorithm> SignedDsign<D> {
    /// Create a SignedDsign by signing a message
    ///
    /// This corresponds to `signedDSIGN` in cardano-base.
    ///
    /// # Parameters
    ///
    /// * `signing_key` - The secret key to sign with
    /// * `message` - The message bytes to sign
    ///
    /// # Returns
    ///
    /// A `SignedDsign` containing the signature
    ///
    /// # Example
    ///
    /// ```
    /// use cardano_crypto::dsign::{Ed25519, DsignAlgorithm, SignedDsign};
    ///
    /// let signing_key = Ed25519::gen_key(&[1u8; 32]);
    /// let signed = SignedDsign::<Ed25519>::sign(&signing_key, b"message");
    /// ```
    pub fn sign(signing_key: &D::SigningKey, message: &[u8]) -> Self {
        let signature = D::sign(signing_key, message);
        Self { signature }
    }

    /// Verify this SignedDsign against a message
    ///
    /// This corresponds to `verifySignedDSIGN` in cardano-base.
    ///
    /// # Parameters
    ///
    /// * `verification_key` - The public key to verify against
    /// * `message` - The message that was supposedly signed
    ///
    /// # Returns
    ///
    /// * `Ok(())` if signature is valid
    /// * `Err(...)` if verification fails
    pub fn verify(
        &self,
        verification_key: &D::VerificationKey,
        message: &[u8],
    ) -> crate::common::Result<()> {
        D::verify(verification_key, message, &self.signature)
    }

    /// Get the underlying signature
    pub fn get_signature(&self) -> &D::Signature {
        &self.signature
    }

    /// Create from a raw signature
    pub fn from_signature(signature: D::Signature) -> Self {
        Self { signature }
    }
}

// ============================================================================
// Cardano-node compatible type aliases
// ============================================================================

/// DSIGN signing key type (matches cardano-node's `SigningKey`)
///
/// For Ed25519, this is the `Ed25519SigningKey` type.
pub type DsignSigningKey = ed25519::Ed25519SigningKey;

/// DSIGN verification key type (matches cardano-node's `VerificationKey`)
///
/// For Ed25519, this is the `Ed25519VerificationKey` type.
pub type DsignVerificationKey = ed25519::Ed25519VerificationKey;

/// DSIGN signature type
///
/// For Ed25519, this is the `Ed25519Signature` type.
pub type DsignSignature = ed25519::Ed25519Signature;

/// DSIGN key pair (matches cardano-node's `KeyPair` pattern)
///
/// Contains both the signing key and verification key.
///
/// # Example
///
/// ```
/// use cardano_crypto::dsign::{Ed25519, DsignAlgorithm, DsignKeyPair};
///
/// let seed = [42u8; 32];
/// let keypair = DsignKeyPair::generate(&seed);
///
/// let message = b"test";
/// let signature = Ed25519::sign(&keypair.signing_key, message);
/// assert!(Ed25519::verify(&keypair.verification_key, message, &signature).is_ok());
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct DsignKeyPair {
    /// The DSIGN signing (secret) key
    pub signing_key: DsignSigningKey,
    /// The DSIGN verification (public) key
    pub verification_key: DsignVerificationKey,
}

impl core::fmt::Debug for DsignKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DsignKeyPair")
            .field("signing_key", &"<redacted>")
            .field("verification_key", &self.verification_key)
            .finish()
    }
}

impl DsignKeyPair {
    /// Generate a DSIGN key pair from a seed
    pub fn generate(seed: &[u8; 32]) -> Self {
        let signing_key = Ed25519::gen_key(seed);
        let verification_key = Ed25519::derive_verification_key(&signing_key);
        Self {
            signing_key,
            verification_key,
        }
    }

    /// Create from existing keys
    pub fn from_keys(signing_key: DsignSigningKey, verification_key: DsignVerificationKey) -> Self {
        Self {
            signing_key,
            verification_key,
        }
    }
}

// ============================================================================
// CBOR Trait Implementations for DSIGN Types
// ============================================================================

#[cfg(feature = "cbor")]
mod cbor_impl {
    use super::*;
    use crate::cbor::{
        decode_bytes, encode_bytes, encoded_size_bytes, CborError, FromCbor, ToCbor,
    };

    // Implementation for Ed25519-specific SignedDsign
    impl ToCbor for SignedDsign<Ed25519> {
        #[cfg(feature = "alloc")]
        fn to_cbor(&self) -> Vec<u8> {
            encode_bytes(self.signature.as_bytes())
        }

        fn encoded_size(&self) -> usize {
            encoded_size_bytes(Ed25519::SIGNATURE_SIZE)
        }
    }

    impl FromCbor for SignedDsign<Ed25519> {
        fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
            let decoded = decode_bytes(bytes)?;
            let sig =
                ed25519::Ed25519Signature::from_bytes(&decoded).ok_or(CborError::InvalidLength)?;
            Ok(SignedDsign::from_signature(sig))
        }
    }

    impl ToCbor for ed25519::Ed25519VerificationKey {
        #[cfg(feature = "alloc")]
        fn to_cbor(&self) -> Vec<u8> {
            encode_bytes(self.as_bytes())
        }

        fn encoded_size(&self) -> usize {
            encoded_size_bytes(Ed25519::VERIFICATION_KEY_SIZE)
        }
    }

    impl FromCbor for ed25519::Ed25519VerificationKey {
        fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
            let decoded = decode_bytes(bytes)?;
            Self::from_bytes(&decoded).ok_or(CborError::InvalidLength)
        }
    }

    impl ToCbor for ed25519::Ed25519Signature {
        #[cfg(feature = "alloc")]
        fn to_cbor(&self) -> Vec<u8> {
            encode_bytes(self.as_bytes())
        }

        fn encoded_size(&self) -> usize {
            encoded_size_bytes(64)
        }
    }

    impl FromCbor for ed25519::Ed25519Signature {
        fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
            let decoded = decode_bytes(bytes)?;
            Self::from_bytes(&decoded).ok_or(CborError::InvalidLength)
        }
    }
}
