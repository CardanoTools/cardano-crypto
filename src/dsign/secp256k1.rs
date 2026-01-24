//! # secp256k1 Digital Signature Algorithms
//!
//! This module provides ECDSA and Schnorr signatures on the secp256k1 curve,
//! enabling Bitcoin interoperability and Plutus smart contract support.
//!
//! ## Features
//!
//! - **ECDSA** - Standard Bitcoin-compatible ECDSA signatures (CIP-0049)
//! - **Schnorr** - BIP-340 Schnorr signatures for Plutus builtins
//!
//! ## CIP Support
//!
//! - [CIP-0049](https://cips.cardano.org/cip/CIP-0049) - ECDSA and Schnorr signatures in Plutus
//!
//! ## Example
//!
//! ```rust,ignore
//! use cardano_crypto::dsign::{Secp256k1Ecdsa, DsignAlgorithm};
//!
//! let seed = [0u8; 32];
//! let signing_key = Secp256k1Ecdsa::gen_key(&seed);
//! let verification_key = Secp256k1Ecdsa::derive_verification_key(&signing_key);
//! let signature = Secp256k1Ecdsa::sign(&signing_key, b"message");
//! assert!(Secp256k1Ecdsa::verify(&verification_key, b"message", &signature).is_ok());
//! ```

use crate::common::error::CryptoError;
use k256::{
    ecdsa::{
        signature::{Signer as EcdsaSigner, Verifier as EcdsaVerifier},
        Signature as K256EcdsaSignature, SigningKey as K256SigningKey,
        VerifyingKey as K256VerifyingKey,
    },
    schnorr::{
        Signature as K256SchnorrSignature, SigningKey as K256SchnorrSigningKey,
        VerifyingKey as K256SchnorrVerifyingKey,
    },
    SecretKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// ECDSA Types
// ============================================================================

/// ECDSA signing key on secp256k1 (32 bytes).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secp256k1EcdsaSigningKey {
    bytes: [u8; Self::SIZE],
}

impl Secp256k1EcdsaSigningKey {
    /// Size of the signing key in bytes.
    pub const SIZE: usize = 32;

    /// Creates a signing key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::SIZE,
                got: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; Self::SIZE];
        key_bytes.copy_from_slice(bytes);
        // Validate that the key is valid
        SecretKey::from_bytes((&key_bytes).into()).map_err(|_| CryptoError::InvalidPrivateKey)?;
        Ok(Self { bytes: key_bytes })
    }

    /// Returns the key as bytes.
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.bytes
    }

    /// Converts to the k256 signing key.
    fn to_k256_signing_key(&self) -> K256SigningKey {
        K256SigningKey::from_bytes((&self.bytes).into()).expect("validated in constructor")
    }
}

impl core::fmt::Debug for Secp256k1EcdsaSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Secp256k1EcdsaSigningKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// ECDSA verification key on secp256k1 (33 bytes compressed).
#[derive(Clone, PartialEq, Eq)]
pub struct Secp256k1EcdsaVerificationKey {
    bytes: [u8; Self::SIZE],
}

impl Secp256k1EcdsaVerificationKey {
    /// Size of the verification key in bytes (compressed SEC1 format).
    pub const SIZE: usize = 33;

    /// Creates a verification key from compressed SEC1 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::SIZE,
                got: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; Self::SIZE];
        key_bytes.copy_from_slice(bytes);
        // Validate that the key is valid
        K256VerifyingKey::from_sec1_bytes(&key_bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(Self { bytes: key_bytes })
    }

    /// Returns the key as bytes.
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.bytes
    }

    /// Converts to the k256 verifying key.
    fn to_k256_verifying_key(&self) -> K256VerifyingKey {
        K256VerifyingKey::from_sec1_bytes(&self.bytes).expect("validated in constructor")
    }
}

impl core::fmt::Debug for Secp256k1EcdsaVerificationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Secp256k1EcdsaVerificationKey")
            .field("bytes", &hex_preview(&self.bytes))
            .finish()
    }
}

/// ECDSA signature on secp256k1 (64 bytes, r || s format).
#[derive(Clone, PartialEq, Eq)]
pub struct Secp256k1EcdsaSignature {
    bytes: [u8; Self::SIZE],
}

impl Secp256k1EcdsaSignature {
    /// Size of the signature in bytes.
    pub const SIZE: usize = 64;

    /// Creates a signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::SIZE {
            return Err(CryptoError::InvalidSignatureLength {
                expected: Self::SIZE,
                got: bytes.len(),
            });
        }
        let mut sig_bytes = [0u8; Self::SIZE];
        sig_bytes.copy_from_slice(bytes);
        // Validate that the signature is valid
        K256EcdsaSignature::from_slice(&sig_bytes).map_err(|_| CryptoError::InvalidSignature)?;
        Ok(Self { bytes: sig_bytes })
    }

    /// Returns the signature as bytes.
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.bytes
    }

    /// Converts to the k256 signature.
    fn to_k256_signature(&self) -> K256EcdsaSignature {
        K256EcdsaSignature::from_slice(&self.bytes).expect("validated in constructor")
    }
}

impl core::fmt::Debug for Secp256k1EcdsaSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Secp256k1EcdsaSignature")
            .field("bytes", &hex_preview(&self.bytes))
            .finish()
    }
}

// ============================================================================
// Schnorr Types
// ============================================================================

/// Schnorr signing key on secp256k1 (32 bytes).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secp256k1SchnorrSigningKey {
    bytes: [u8; Self::SIZE],
}

impl Secp256k1SchnorrSigningKey {
    /// Size of the signing key in bytes.
    pub const SIZE: usize = 32;

    /// Creates a signing key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::SIZE,
                got: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; Self::SIZE];
        key_bytes.copy_from_slice(bytes);
        // Validate that the key is valid
        K256SchnorrSigningKey::from_bytes(&key_bytes)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        Ok(Self { bytes: key_bytes })
    }

    /// Returns the key as bytes.
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.bytes
    }

    /// Converts to the k256 schnorr signing key.
    fn to_k256_signing_key(&self) -> K256SchnorrSigningKey {
        K256SchnorrSigningKey::from_bytes(&self.bytes).expect("validated in constructor")
    }
}

impl core::fmt::Debug for Secp256k1SchnorrSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Secp256k1SchnorrSigningKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Schnorr verification key on secp256k1 (32 bytes, x-only public key).
#[derive(Clone, PartialEq, Eq)]
pub struct Secp256k1SchnorrVerificationKey {
    bytes: [u8; Self::SIZE],
}

impl Secp256k1SchnorrVerificationKey {
    /// Size of the verification key in bytes (x-only format).
    pub const SIZE: usize = 32;

    /// Creates a verification key from x-only bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::SIZE,
                got: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; Self::SIZE];
        key_bytes.copy_from_slice(bytes);
        // Validate that the key is valid
        K256SchnorrVerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(Self { bytes: key_bytes })
    }

    /// Returns the key as bytes.
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.bytes
    }

    /// Converts to the k256 schnorr verifying key.
    fn to_k256_verifying_key(&self) -> K256SchnorrVerifyingKey {
        K256SchnorrVerifyingKey::from_bytes(&self.bytes).expect("validated in constructor")
    }
}

impl core::fmt::Debug for Secp256k1SchnorrVerificationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Secp256k1SchnorrVerificationKey")
            .field("bytes", &hex_preview(&self.bytes))
            .finish()
    }
}

/// Schnorr signature on secp256k1 (64 bytes, BIP-340 format).
#[derive(Clone, PartialEq, Eq)]
pub struct Secp256k1SchnorrSignature {
    bytes: [u8; Self::SIZE],
}

impl Secp256k1SchnorrSignature {
    /// Size of the signature in bytes.
    pub const SIZE: usize = 64;

    /// Creates a signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::SIZE {
            return Err(CryptoError::InvalidSignatureLength {
                expected: Self::SIZE,
                got: bytes.len(),
            });
        }
        let mut sig_bytes = [0u8; Self::SIZE];
        sig_bytes.copy_from_slice(bytes);
        // Validate that the signature is valid
        K256SchnorrSignature::try_from(&sig_bytes[..])
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(Self { bytes: sig_bytes })
    }

    /// Returns the signature as bytes.
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.bytes
    }

    /// Converts to the k256 schnorr signature.
    fn to_k256_signature(&self) -> K256SchnorrSignature {
        K256SchnorrSignature::try_from(&self.bytes[..]).expect("validated in constructor")
    }
}

impl core::fmt::Debug for Secp256k1SchnorrSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Secp256k1SchnorrSignature")
            .field("bytes", &hex_preview(&self.bytes))
            .finish()
    }
}

// ============================================================================
// Algorithm Implementations
// ============================================================================

/// ECDSA signature algorithm on secp256k1 (CIP-0049).
///
/// This provides Bitcoin-compatible ECDSA signatures for use in
/// Plutus smart contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Secp256k1Ecdsa;

impl Secp256k1Ecdsa {
    /// Algorithm name.
    pub const NAME: &'static str = "ECDSA-secp256k1";

    /// Size of the signing key in bytes.
    pub const SIGNING_KEY_SIZE: usize = 32;

    /// Size of the verification key in bytes (compressed).
    pub const VERIFICATION_KEY_SIZE: usize = 33;

    /// Size of the signature in bytes.
    pub const SIGNATURE_SIZE: usize = 64;

    /// Generates a signing key from a 32-byte seed.
    pub fn gen_key(seed: &[u8; 32]) -> Secp256k1EcdsaSigningKey {
        Secp256k1EcdsaSigningKey::from_bytes(seed).expect("32-byte seed is valid")
    }

    /// Derives the verification key from a signing key.
    pub fn derive_verification_key(
        signing_key: &Secp256k1EcdsaSigningKey,
    ) -> Secp256k1EcdsaVerificationKey {
        let k256_sk = signing_key.to_k256_signing_key();
        let k256_vk = k256_sk.verifying_key();
        let bytes = k256_vk.to_sec1_bytes();
        let mut vk_bytes = [0u8; 33];
        vk_bytes.copy_from_slice(&bytes);
        Secp256k1EcdsaVerificationKey { bytes: vk_bytes }
    }

    /// Signs a message using the signing key.
    ///
    /// The message is hashed with SHA-256 before signing (standard ECDSA).
    pub fn sign(signing_key: &Secp256k1EcdsaSigningKey, message: &[u8]) -> Secp256k1EcdsaSignature {
        let k256_sk = signing_key.to_k256_signing_key();
        let signature: K256EcdsaSignature = k256_sk.sign(message);
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&signature.to_bytes());
        Secp256k1EcdsaSignature { bytes }
    }

    /// Verifies a signature against a message and verification key.
    pub fn verify(
        verification_key: &Secp256k1EcdsaVerificationKey,
        message: &[u8],
        signature: &Secp256k1EcdsaSignature,
    ) -> Result<(), CryptoError> {
        let k256_vk = verification_key.to_k256_verifying_key();
        let k256_sig = signature.to_k256_signature();
        k256_vk
            .verify(message, &k256_sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Signs a pre-hashed message (for Plutus compatibility).
    ///
    /// Use this when the message has already been hashed.
    pub fn sign_prehashed(
        signing_key: &Secp256k1EcdsaSigningKey,
        message_hash: &[u8; 32],
    ) -> Result<Secp256k1EcdsaSignature, CryptoError> {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let k256_sk = signing_key.to_k256_signing_key();
        let signature: K256EcdsaSignature = k256_sk
            .sign_prehash(message_hash)
            .map_err(|_| CryptoError::SigningFailed)?;
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&signature.to_bytes());
        Ok(Secp256k1EcdsaSignature { bytes })
    }

    /// Verifies a signature against a pre-hashed message (for Plutus compatibility).
    pub fn verify_prehashed(
        verification_key: &Secp256k1EcdsaVerificationKey,
        message_hash: &[u8; 32],
        signature: &Secp256k1EcdsaSignature,
    ) -> Result<(), CryptoError> {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let k256_vk = verification_key.to_k256_verifying_key();
        let k256_sig = signature.to_k256_signature();
        k256_vk
            .verify_prehash(message_hash, &k256_sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

/// Schnorr signature algorithm on secp256k1 (CIP-0049, BIP-340).
///
/// This provides BIP-340 Schnorr signatures for use in Plutus smart contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Secp256k1Schnorr;

impl Secp256k1Schnorr {
    /// Algorithm name.
    pub const NAME: &'static str = "Schnorr-secp256k1";

    /// Size of the signing key in bytes.
    pub const SIGNING_KEY_SIZE: usize = 32;

    /// Size of the verification key in bytes (x-only).
    pub const VERIFICATION_KEY_SIZE: usize = 32;

    /// Size of the signature in bytes.
    pub const SIGNATURE_SIZE: usize = 64;

    /// Generates a signing key from a 32-byte seed.
    pub fn gen_key(seed: &[u8; 32]) -> Secp256k1SchnorrSigningKey {
        Secp256k1SchnorrSigningKey::from_bytes(seed).expect("32-byte seed is valid")
    }

    /// Derives the verification key from a signing key.
    pub fn derive_verification_key(
        signing_key: &Secp256k1SchnorrSigningKey,
    ) -> Secp256k1SchnorrVerificationKey {
        let k256_sk = signing_key.to_k256_signing_key();
        let k256_vk = k256_sk.verifying_key();
        let bytes = k256_vk.to_bytes();
        Secp256k1SchnorrVerificationKey {
            bytes: bytes.into(),
        }
    }

    /// Signs a message using the signing key.
    ///
    /// Uses BIP-340 tagged hashing internally.
    pub fn sign(
        signing_key: &Secp256k1SchnorrSigningKey,
        message: &[u8],
    ) -> Secp256k1SchnorrSignature {
        let k256_sk = signing_key.to_k256_signing_key();
        let signature: K256SchnorrSignature = k256_sk.sign(message);
        let bytes: [u8; 64] = signature.to_bytes();
        Secp256k1SchnorrSignature { bytes }
    }

    /// Verifies a signature against a message and verification key.
    pub fn verify(
        verification_key: &Secp256k1SchnorrVerificationKey,
        message: &[u8],
        signature: &Secp256k1SchnorrSignature,
    ) -> Result<(), CryptoError> {
        let k256_vk = verification_key.to_k256_verifying_key();
        let k256_sig = signature.to_k256_signature();
        k256_vk
            .verify(message, &k256_sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Signs a pre-hashed message (for Plutus compatibility).
    ///
    /// Use this when the message has already been hashed.
    /// Note: BIP-340 uses tagged hashing, so pre-hashed verification
    /// requires the verifier to use the same approach.
    pub fn sign_prehashed(
        signing_key: &Secp256k1SchnorrSigningKey,
        message_hash: &[u8; 32],
    ) -> Result<Secp256k1SchnorrSignature, CryptoError> {
        use k256::schnorr::signature::hazmat::PrehashSigner;
        let k256_sk = signing_key.to_k256_signing_key();
        let signature: K256SchnorrSignature = k256_sk
            .sign_prehash(message_hash)
            .map_err(|_| CryptoError::SigningFailed)?;
        let bytes: [u8; 64] = signature.to_bytes();
        Ok(Secp256k1SchnorrSignature { bytes })
    }

    /// Verifies a signature against a pre-hashed message.
    pub fn verify_prehashed(
        verification_key: &Secp256k1SchnorrVerificationKey,
        message_hash: &[u8; 32],
        signature: &Secp256k1SchnorrSignature,
    ) -> Result<(), CryptoError> {
        use k256::schnorr::signature::hazmat::PrehashVerifier;
        let k256_vk = verification_key.to_k256_verifying_key();
        let k256_sig = signature.to_k256_signature();
        k256_vk
            .verify_prehash(message_hash, &k256_sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Returns a hex preview of bytes for debug output.
fn hex_preview(bytes: &[u8]) -> alloc::string::String {
    if bytes.len() <= 8 {
        hex_encode(bytes)
    } else {
        alloc::format!(
            "{}...{} ({} bytes)",
            hex_encode(&bytes[..4]),
            hex_encode(&bytes[bytes.len() - 4..]),
            bytes.len()
        )
    }
}

/// Simple hex encoding.
fn hex_encode(bytes: &[u8]) -> alloc::string::String {
    use alloc::string::String;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_sign_verify() {
        let seed = [1u8; 32];
        let signing_key = Secp256k1Ecdsa::gen_key(&seed);
        let verification_key = Secp256k1Ecdsa::derive_verification_key(&signing_key);

        let message = b"Hello, Cardano!";
        let signature = Secp256k1Ecdsa::sign(&signing_key, message);

        assert!(Secp256k1Ecdsa::verify(&verification_key, message, &signature).is_ok());
    }

    #[test]
    fn test_ecdsa_invalid_signature() {
        let seed = [1u8; 32];
        let signing_key = Secp256k1Ecdsa::gen_key(&seed);
        let verification_key = Secp256k1Ecdsa::derive_verification_key(&signing_key);

        let message = b"Hello, Cardano!";
        let signature = Secp256k1Ecdsa::sign(&signing_key, message);

        // Wrong message
        assert!(Secp256k1Ecdsa::verify(&verification_key, b"Wrong message", &signature).is_err());
    }

    #[test]
    fn test_ecdsa_prehashed() {
        use sha2::{Digest, Sha256};

        let seed = [2u8; 32];
        let signing_key = Secp256k1Ecdsa::gen_key(&seed);
        let verification_key = Secp256k1Ecdsa::derive_verification_key(&signing_key);

        let message = b"Pre-hashed message";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash: [u8; 32] = hasher.finalize().into();

        let signature = Secp256k1Ecdsa::sign_prehashed(&signing_key, &hash).unwrap();
        assert!(Secp256k1Ecdsa::verify_prehashed(&verification_key, &hash, &signature).is_ok());
    }

    #[test]
    fn test_schnorr_sign_verify() {
        let seed = [3u8; 32];
        let signing_key = Secp256k1Schnorr::gen_key(&seed);
        let verification_key = Secp256k1Schnorr::derive_verification_key(&signing_key);

        let message = b"Hello, Plutus!";
        let signature = Secp256k1Schnorr::sign(&signing_key, message);

        assert!(Secp256k1Schnorr::verify(&verification_key, message, &signature).is_ok());
    }

    #[test]
    fn test_schnorr_invalid_signature() {
        let seed = [3u8; 32];
        let signing_key = Secp256k1Schnorr::gen_key(&seed);
        let verification_key = Secp256k1Schnorr::derive_verification_key(&signing_key);

        let message = b"Hello, Plutus!";
        let signature = Secp256k1Schnorr::sign(&signing_key, message);

        // Wrong message
        assert!(Secp256k1Schnorr::verify(&verification_key, b"Wrong message", &signature).is_err());
    }

    #[test]
    fn test_ecdsa_key_sizes() {
        assert_eq!(Secp256k1Ecdsa::SIGNING_KEY_SIZE, 32);
        assert_eq!(Secp256k1Ecdsa::VERIFICATION_KEY_SIZE, 33);
        assert_eq!(Secp256k1Ecdsa::SIGNATURE_SIZE, 64);
    }

    #[test]
    fn test_schnorr_key_sizes() {
        assert_eq!(Secp256k1Schnorr::SIGNING_KEY_SIZE, 32);
        assert_eq!(Secp256k1Schnorr::VERIFICATION_KEY_SIZE, 32);
        assert_eq!(Secp256k1Schnorr::SIGNATURE_SIZE, 64);
    }

    #[test]
    fn test_key_serialization() {
        let seed = [4u8; 32];

        // ECDSA
        let ecdsa_sk = Secp256k1Ecdsa::gen_key(&seed);
        let ecdsa_vk = Secp256k1Ecdsa::derive_verification_key(&ecdsa_sk);

        let ecdsa_sk_bytes = ecdsa_sk.as_bytes();
        let ecdsa_vk_bytes = ecdsa_vk.as_bytes();

        let ecdsa_sk2 = Secp256k1EcdsaSigningKey::from_bytes(ecdsa_sk_bytes).unwrap();
        let ecdsa_vk2 = Secp256k1EcdsaVerificationKey::from_bytes(ecdsa_vk_bytes).unwrap();

        assert_eq!(ecdsa_sk.as_bytes(), ecdsa_sk2.as_bytes());
        assert_eq!(ecdsa_vk, ecdsa_vk2);

        // Schnorr
        let schnorr_sk = Secp256k1Schnorr::gen_key(&seed);
        let schnorr_vk = Secp256k1Schnorr::derive_verification_key(&schnorr_sk);

        let schnorr_sk_bytes = schnorr_sk.as_bytes();
        let schnorr_vk_bytes = schnorr_vk.as_bytes();

        let schnorr_sk2 = Secp256k1SchnorrSigningKey::from_bytes(schnorr_sk_bytes).unwrap();
        let schnorr_vk2 = Secp256k1SchnorrVerificationKey::from_bytes(schnorr_vk_bytes).unwrap();

        assert_eq!(schnorr_sk.as_bytes(), schnorr_sk2.as_bytes());
        assert_eq!(schnorr_vk, schnorr_vk2);
    }

    #[test]
    fn test_different_keys_different_signatures() {
        let seed1 = [5u8; 32];
        let seed2 = [6u8; 32];

        let sk1 = Secp256k1Ecdsa::gen_key(&seed1);
        let sk2 = Secp256k1Ecdsa::gen_key(&seed2);

        let message = b"Same message";
        let sig1 = Secp256k1Ecdsa::sign(&sk1, message);
        let sig2 = Secp256k1Ecdsa::sign(&sk2, message);

        // Different keys should produce different signatures
        assert_ne!(sig1.as_bytes(), sig2.as_bytes());
    }
}
