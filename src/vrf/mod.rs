//! Verifiable Random Functions (VRF)
//!
//! This module provides VRF implementations following IETF specifications:
//! - **Draft-03** (ECVRF-ED25519-SHA512-Elligator2) - 80-byte proofs, Cardano standard
//! - **Draft-13** (ECVRF-ED25519-SHA512-TAI) - 128-byte proofs, batch-compatible
//!
//! Both variants maintain byte-level compatibility with Cardano's libsodium VRF implementation.
//!
//! # Examples
//!
//! ## VRF Draft-03 (Cardano Standard)
//!
//! ```
//! use cardano_crypto::vrf::VrfDraft03;
//!
//! // Generate keypair
//! let seed = [42u8; 32];
//! let (secret_key, public_key) = VrfDraft03::keypair_from_seed(&seed);
//!
//! // Prove
//! let message = b"Cardano block slot 12345";
//! let proof = VrfDraft03::prove(&secret_key, message).unwrap();
//!
//! // Verify and get output
//! let output = VrfDraft03::verify(&public_key, &proof, message).unwrap();
//! assert_eq!(output.len(), 64);
//! ```
//!
//! ## VRF Draft-13
//!
//! ```
//! use cardano_crypto::vrf::VrfDraft13;
//!
//! let seed = [42u8; 32];
//! let (secret_key, public_key) = VrfDraft13::keypair_from_seed(&seed);
//!
//! let message = b"Random seed input";
//! let proof = VrfDraft13::prove(&secret_key, message).unwrap();
//! let output = VrfDraft13::verify(&public_key, &proof, message).unwrap();
//! ```

#[cfg(feature = "alloc")]
use alloc::{format, vec::Vec};

pub mod cardano_compat;
pub mod draft03;
pub mod draft13;
pub mod test_vectors;

// Re-export main types
pub use draft03::{
    OUTPUT_SIZE, PROOF_SIZE as DRAFT03_PROOF_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SEED_SIZE,
    VrfDraft03,
};

pub use draft13::{PROOF_SIZE as DRAFT13_PROOF_SIZE, VrfDraft13};

/// VRF algorithm compatible with Cardano's batch verification (IETF Draft-13)
///
/// This type alias matches Cardano's `PraosBatchCompatVRF` from the cardano-crypto-praos
/// package in cardano-base. It refers to the ECVRF-ED25519-SHA512-TAI algorithm from
/// IETF draft-irtf-cfrg-vrf-13, which supports batch verification of multiple VRF proofs.
///
/// # Cardano Compatibility
///
/// In cardano-base, this is defined as:
/// ```haskell
/// type PraosBatchCompatVRF = VRF_DRAFT13
/// ```
///
/// This VRF variant is used in newer protocol versions that support batch verification,
/// improving consensus performance when validating multiple VRF proofs simultaneously.
///
/// # Differences from PraosVRF (Draft-03)
///
/// - **Proof Size**: 128 bytes (vs 80 bytes for Draft-03)
/// - **Batch Verification**: Supports efficient batch proof validation
/// - **Hash-to-Curve**: Uses Try-And-Increment (TAI) instead of Elligator2
///
/// # Example
///
/// ```
/// use cardano_crypto::vrf::PraosBatchCompatVRF;
///
/// let seed = [42u8; 32];
/// let (secret_key, public_key) = PraosBatchCompatVRF::keypair_from_seed(&seed);
///
/// let message = b"Cardano block slot 67890";
/// let proof = PraosBatchCompatVRF::prove(&secret_key, message).unwrap();
/// let output = PraosBatchCompatVRF::verify(&public_key, &proof, message).unwrap();
/// ```
pub type PraosBatchCompatVRF = VrfDraft13;

// Re-export Cardano compatibility functions for advanced usage
pub use cardano_compat::{
    cardano_clear_cofactor, cardano_hash_to_curve, cardano_vrf_prove, cardano_vrf_verify,
};

// ============================================================================
// VRF Algorithm trait (matching Cardano's VRFAlgorithm class)
// ============================================================================

/// Trait for VRF algorithms
///
/// This trait provides a unified interface for VRF implementations,
/// matching the structure of Cardano's `VRFAlgorithm` type class.
///
/// # Associated Types
///
/// - `SecretKey`: VRF secret key type
/// - `VerificationKey`: VRF public key type
/// - `Proof`: VRF proof type
/// - `Output`: VRF output type (hash)
///
/// # Example
///
/// ```
/// use cardano_crypto::vrf::{VrfAlgorithm, VrfDraft03};
/// use cardano_crypto::hash::{Blake2b256, HashAlgorithm};
///
/// let seed = [42u8; 32];
/// let (sk, vk) = VrfDraft03::keypair_from_seed(&seed);
///
/// // Hash the verification key
/// let vk_hash = VrfDraft03::hash_verification_key::<Blake2b256>(&vk);
/// assert_eq!(vk_hash.len(), 32);
/// ```
pub trait VrfAlgorithm: Clone + Send + Sync + 'static {
    /// Secret key type
    type SecretKey;
    /// Verification key type
    type VerificationKey;
    /// Proof type
    type Proof;
    /// Output type
    type Output;

    /// Algorithm name
    const ALGORITHM_NAME: &'static str;
    /// Seed size in bytes
    const SEED_SIZE: usize;
    /// Secret key size in bytes
    const SECRET_KEY_SIZE: usize;
    /// Verification key size in bytes
    const VERIFICATION_KEY_SIZE: usize;
    /// Proof size in bytes
    const PROOF_SIZE: usize;
    /// Output size in bytes
    const OUTPUT_SIZE: usize;

    /// Generate keypair from seed
    fn keypair_from_seed(seed: &[u8; 32]) -> (Self::SecretKey, Self::VerificationKey);

    /// Derive verification key from secret key
    fn derive_verification_key(sk: &Self::SecretKey) -> Self::VerificationKey;

    /// Generate a VRF proof
    fn prove(sk: &Self::SecretKey, message: &[u8]) -> crate::common::CryptoResult<Self::Proof>;

    /// Verify a VRF proof and return the output
    fn verify(
        vk: &Self::VerificationKey,
        proof: &Self::Proof,
        message: &[u8],
    ) -> crate::common::CryptoResult<Self::Output>;

    /// Convert proof to output hash directly (without verification)
    fn proof_to_hash(proof: &Self::Proof) -> crate::common::CryptoResult<Self::Output>;

    /// Serialize verification key to raw bytes
    fn raw_serialize_verification_key(vk: &Self::VerificationKey) -> &[u8];

    /// Deserialize verification key from raw bytes
    fn raw_deserialize_verification_key(bytes: &[u8]) -> Option<Self::VerificationKey>;

    /// Serialize proof to raw bytes
    fn raw_serialize_proof(proof: &Self::Proof) -> &[u8];

    /// Deserialize proof from raw bytes
    fn raw_deserialize_proof(bytes: &[u8]) -> Option<Self::Proof>;

    /// Hash a verification key
    ///
    /// This corresponds to `hashVerKeyVRF` in cardano-base.
    ///
    /// # Type Parameters
    ///
    /// - `H`: The hash algorithm to use
    #[cfg(feature = "alloc")]
    fn hash_verification_key<H: crate::hash::HashAlgorithm>(vk: &Self::VerificationKey) -> Vec<u8> {
        let raw = Self::raw_serialize_verification_key(vk);
        H::hash(raw)
    }
}

// ============================================================================
// OutputVRF - VRF output wrapper matching Cardano's OutputVRF
// ============================================================================

/// VRF output wrapper
///
/// Matches Cardano's `OutputVRF v` type from cardano-crypto-class.
/// The output is the result of a VRF evaluation and can be converted
/// to a natural number for use in leader election.
///
/// # Examples
///
/// ```
/// use cardano_crypto::vrf::{VrfDraft03, OutputVrf};
///
/// let seed = [42u8; 32];
/// let (secret_key, public_key) = VrfDraft03::keypair_from_seed(&seed);
/// let message = b"test";
/// let proof = VrfDraft03::prove(&secret_key, message).unwrap();
/// let output_bytes = VrfDraft03::verify(&public_key, &proof, message).unwrap();
///
/// let output = OutputVrf::new(output_bytes);
/// assert_eq!(output.as_bytes().len(), 64);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct OutputVrf([u8; OUTPUT_SIZE]);

impl core::fmt::Debug for OutputVrf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "OutputVrf(<{} bytes>)", self.0.len())
    }
}

impl OutputVrf {
    /// Create an OutputVrf from raw bytes
    pub fn new(bytes: [u8; OUTPUT_SIZE]) -> Self {
        Self(bytes)
    }

    /// Create from a slice (returns None if wrong length)
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != OUTPUT_SIZE {
            return None;
        }
        let mut arr = [0u8; OUTPUT_SIZE];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    /// Get the raw output bytes
    pub fn as_bytes(&self) -> &[u8; OUTPUT_SIZE] {
        &self.0
    }

    /// Convert VRF output to a natural number (big-endian)
    ///
    /// This matches Cardano's `getOutputVRFNatural` function used in
    /// leader election to compare against the stake threshold.
    ///
    /// # Example
    ///
    /// ```
    /// use cardano_crypto::vrf::OutputVrf;
    ///
    /// let output = OutputVrf::new([0u8; 64]);
    /// let natural = output.to_natural();
    /// // natural is a big integer representation
    /// ```
    #[cfg(feature = "alloc")]
    pub fn to_natural(&self) -> alloc::vec::Vec<u8> {
        // Return bytes in big-endian order (already in big-endian from SHA-512)
        self.0.to_vec()
    }

    /// Convert to u128 (truncated, using first 16 bytes)
    ///
    /// Useful for quick comparisons where full precision isn't needed.
    pub fn to_u128(&self) -> u128 {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&self.0[..16]);
        u128::from_be_bytes(bytes)
    }
}

// ============================================================================
// CertifiedVRF - VRF output with proof (certificate)
// ============================================================================

/// A VRF output certified by its proof
///
/// Matches Cardano's `CertifiedVRF v a` type from cardano-crypto-class.
/// Bundles the VRF output with its proof (certificate) for verification.
///
/// # Examples
///
/// ```
/// use cardano_crypto::vrf::{VrfDraft03, CertifiedVrf};
///
/// let seed = [42u8; 32];
/// let (secret_key, public_key) = VrfDraft03::keypair_from_seed(&seed);
/// let message = b"test input";
///
/// // Generate certified VRF output
/// let certified = CertifiedVrf::eval(&secret_key, message).unwrap();
///
/// // Verify the certified output
/// assert!(certified.verify(&public_key, message).is_ok());
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct CertifiedVrf {
    /// The VRF output (hash)
    pub output: OutputVrf,
    /// The VRF proof (certificate)
    pub proof: [u8; DRAFT03_PROOF_SIZE],
}

impl core::fmt::Debug for CertifiedVrf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CertifiedVrf")
            .field("output", &self.output)
            .field("proof", &format!("<{} bytes>", self.proof.len()))
            .finish()
    }
}

impl CertifiedVrf {
    /// Evaluate VRF and return certified output
    ///
    /// This corresponds to `evalCertified` in cardano-crypto-class.
    ///
    /// # Parameters
    ///
    /// * `secret_key` - The VRF secret key (64 bytes)
    /// * `message` - The input message to hash
    ///
    /// # Returns
    ///
    /// A `CertifiedVrf` containing both the output and proof
    pub fn eval(
        secret_key: &[u8; SECRET_KEY_SIZE],
        message: &[u8],
    ) -> crate::common::CryptoResult<Self> {
        let proof = VrfDraft03::prove(secret_key, message)?;
        let output_bytes = VrfDraft03::proof_to_hash(&proof)?;

        Ok(Self {
            output: OutputVrf::new(output_bytes),
            proof,
        })
    }

    /// Verify the certified VRF output
    ///
    /// This corresponds to `verifyCertified` in cardano-crypto-class.
    ///
    /// # Parameters
    ///
    /// * `public_key` - The VRF public key
    /// * `message` - The original input message
    ///
    /// # Returns
    ///
    /// * `Ok(())` if verification succeeds
    /// * `Err(...)` if verification fails
    pub fn verify(
        &self,
        public_key: &[u8; PUBLIC_KEY_SIZE],
        message: &[u8],
    ) -> crate::common::CryptoResult<()> {
        let output = VrfDraft03::verify(public_key, &self.proof, message)?;

        if output != *self.output.as_bytes() {
            return Err(crate::common::CryptoError::VerificationFailed);
        }

        Ok(())
    }

    /// Get the VRF output
    pub fn get_output(&self) -> &OutputVrf {
        &self.output
    }

    /// Get the VRF proof (certificate)
    pub fn get_proof(&self) -> &[u8; DRAFT03_PROOF_SIZE] {
        &self.proof
    }
}

// ============================================================================
// Cardano-node compatible type aliases
// ============================================================================

/// VRF signing key type (matches cardano-node's `VrfSigningKey`)
///
/// This is a 64-byte array containing the seed and public key.
pub type VrfSigningKey = [u8; SECRET_KEY_SIZE];

/// VRF verification key type (matches cardano-node's `VrfVerificationKey`)
///
/// This is a 32-byte compressed Edwards curve point.
pub type VrfVerificationKey = [u8; PUBLIC_KEY_SIZE];

/// VRF proof type
///
/// This is an 80-byte proof for Draft-03.
pub type VrfProof = [u8; DRAFT03_PROOF_SIZE];

/// VRF key pair (matches cardano-node's `KeyPair VrfKey`)
///
/// Contains both the signing key and verification key.
///
/// # Example
///
/// ```
/// use cardano_crypto::vrf::{VrfDraft03, VrfKeyPair};
///
/// let seed = [42u8; 32];
/// let keypair = VrfKeyPair::generate(&seed);
///
/// let message = b"test";
/// let proof = VrfDraft03::prove(&keypair.signing_key, message).unwrap();
/// let output = VrfDraft03::verify(&keypair.verification_key, &proof, message).unwrap();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct VrfKeyPair {
    /// The VRF signing (secret) key
    pub signing_key: VrfSigningKey,
    /// The VRF verification (public) key
    pub verification_key: VrfVerificationKey,
}

impl core::fmt::Debug for VrfKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VrfKeyPair")
            .field("signing_key", &"<redacted>")
            .field(
                "verification_key",
                &format!("<{} bytes>", self.verification_key.len()),
            )
            .finish()
    }
}

impl VrfKeyPair {
    /// Generate a VRF key pair from a seed
    pub fn generate(seed: &[u8; SEED_SIZE]) -> Self {
        let (signing_key, verification_key) = VrfDraft03::keypair_from_seed(seed);
        Self {
            signing_key,
            verification_key,
        }
    }

    /// Create from existing keys
    pub fn from_keys(signing_key: VrfSigningKey, verification_key: VrfVerificationKey) -> Self {
        Self {
            signing_key,
            verification_key,
        }
    }
}

// ============================================================================
// CBOR Trait Implementations for VRF Types
// ============================================================================

#[cfg(feature = "cbor")]
mod cbor_impl {
    use super::*;
    use crate::cbor::{
        CborError, FromCbor, ToCbor, decode_bytes, encode_bytes, encoded_size_bytes,
    };

    impl ToCbor for OutputVrf {
        #[cfg(feature = "alloc")]
        fn to_cbor(&self) -> Vec<u8> {
            encode_bytes(&self.0)
        }

        fn encoded_size(&self) -> usize {
            encoded_size_bytes(OUTPUT_SIZE)
        }
    }

    impl FromCbor for OutputVrf {
        fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
            let decoded = decode_bytes(bytes)?;
            Self::from_slice(&decoded).ok_or(CborError::InvalidLength)
        }
    }

    impl ToCbor for CertifiedVrf {
        #[cfg(feature = "alloc")]
        fn to_cbor(&self) -> Vec<u8> {
            // Encode as CBOR bytes containing the proof
            // The output can be recomputed from the proof
            encode_bytes(&self.proof)
        }

        fn encoded_size(&self) -> usize {
            encoded_size_bytes(DRAFT03_PROOF_SIZE)
        }
    }

    impl FromCbor for CertifiedVrf {
        fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
            let decoded = decode_bytes(bytes)?;
            if decoded.len() != DRAFT03_PROOF_SIZE {
                return Err(CborError::InvalidLength);
            }
            let mut proof = [0u8; DRAFT03_PROOF_SIZE];
            proof.copy_from_slice(&decoded);

            // Compute output from proof
            let output_bytes =
                VrfDraft03::proof_to_hash(&proof).map_err(|_| CborError::DeserializationFailed)?;

            Ok(Self {
                output: OutputVrf::new(output_bytes),
                proof,
            })
        }
    }

    // Note: VrfVerificationKey, VrfSigningKey, and VrfProof are type aliases for [u8; N],
    // so they use the implementations in cbor/mod.rs for [u8; 32], [u8; 64], and [u8; 80].
}
