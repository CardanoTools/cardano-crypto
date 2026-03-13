//! VRF implementation following IETF draft-13 specification (batch-compatible)
//!
//! Implements **ECVRF-ED25519-SHA512-ELL2** (Elligator2 hash-to-curve) as defined in
//! [draft-irtf-cfrg-vrf-13](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-13)
//! with the batch-compatible proof format used by Cardano (`PraosBatchCompatVRF`).
//!
//! # Specification Details
//!
//! - **Suite**: ECVRF-ED25519-SHA512-ELL2 (suite byte 0x04)
//! - **Curve**: Edwards25519 (Ed25519)
//! - **Hash Function**: SHA-512
//! - **Hash-to-Curve**: Elligator2 via XMD-SHA-512 (deterministic, uniform distribution)
//! - **Proof Size**: 128 bytes (Gamma 32 + kB 32 + kH 32 + s 32)
//! - **Public Key Size**: 32 bytes
//! - **Secret Key Size**: 64 bytes (Ed25519 expanded key format)
//! - **Output Size**: 64 bytes (SHA-512)
//!
//! # Differences from Draft-03
//!
//! | Feature | Draft-03 | Draft-13 Batchcompat |
//! |---------|----------|----------------------|
//! | Proof Size | 80 bytes | 128 bytes |
//! | Proof Layout | Gamma\|\|c\|\|s | Gamma\|\|kB\|\|kH\|\|s |
//! | Hash-to-Curve | Elligator2 (direct) | Elligator2 (XMD-SHA-512, byte-reversed) |
//! | Batch Verification | No | Yes |
//!
//! # Upstream Reference
//!
//! This implementation matches [`cardano-crypto-praos/cbits/vrf13_batchcompat/`](
//! https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-praos/cbits/vrf13_batchcompat)
//! byte-for-byte.
//!
//! # Examples
//!
//! ```rust
//! use cardano_crypto::vrf::VrfDraft13;
//! use cardano_crypto::common::Result;
//!
//! # fn main() -> Result<()> {
//! // Generate keypair
//! let seed = [99u8; 32];
//! let (secret_key, public_key) = VrfDraft13::keypair_from_seed(&seed);
//!
//! // Generate proof
//! let message = b"Block slot 54321";
//! let proof = VrfDraft13::prove(&secret_key, message)?;
//! assert_eq!(proof.len(), 128);
//!
//! // Verify proof
//! let output = VrfDraft13::verify(&public_key, &proof, message)?;
//! assert_eq!(output.len(), 64);
//!
//! // Extract hash without verification
//! let hash = VrfDraft13::proof_to_hash(&proof)?;
//! assert_eq!(hash, output);
//! # Ok(())
//! # }
//! ```

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::common::{
    Result, SUITE_DRAFT13, THREE, TWO, bytes_to_point, clamp_scalar, point_to_bytes,
};
use crate::vrf::cardano_compat::{cardano_clear_cofactor, cardano_hash_to_curve_draft13};

/// Zero byte for trailing domain separation
const ZERO: u8 = 0x00;

/// VRF proof size for draft-13 batchcompat: 128 bytes
///
/// Structure: Gamma (32 bytes) || kB (32 bytes) || kH (32 bytes) || s (32 bytes)
/// - Gamma: VRF output point
/// - kB: k*B commitment (enables batch verification)
/// - kH: k*H commitment (enables batch verification)
/// - s: Response scalar (s = c*x + k mod L)
///
/// Upstream: `cardano-crypto-praos/cbits/vrf13_batchcompat/prove.c`
pub const PROOF_SIZE: usize = 128;

/// Ed25519 public key size: 32 bytes
///
/// # Example
///
/// ```
/// use cardano_crypto::vrf::draft13::PUBLIC_KEY_SIZE;
///
/// assert_eq!(PUBLIC_KEY_SIZE, 32);
/// ```
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 secret key size: 64 bytes
///
/// Format: seed (32 bytes) || public_key (32 bytes)
///
/// # Example
///
/// ```
/// use cardano_crypto::vrf::draft13::SECRET_KEY_SIZE;
///
/// assert_eq!(SECRET_KEY_SIZE, 64);
/// ```
pub const SECRET_KEY_SIZE: usize = 64;

/// Random seed size for keypair generation: 32 bytes
///
/// # Example
///
/// ```
/// use cardano_crypto::vrf::draft13::SEED_SIZE;
///
/// assert_eq!(SEED_SIZE, 32);
/// ```
pub const SEED_SIZE: usize = 32;

/// VRF output hash size: 64 bytes (SHA-512)
///
/// # Example
///
/// ```
/// use cardano_crypto::vrf::draft13::OUTPUT_SIZE;
///
/// assert_eq!(OUTPUT_SIZE, 64);
/// ```
pub const OUTPUT_SIZE: usize = 64;

/// VRF Draft-13 batch-compatible implementation (PraosBatchCompatVRF)
///
/// Zero-sized type providing static methods for VRF operations following
/// the draft-13 specification with the batch-compatible proof format.
///
/// Upstream: [`cardano-crypto-praos/cbits/vrf13_batchcompat/`](
/// https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-praos/cbits/vrf13_batchcompat)
#[derive(Clone, Debug)]
pub struct VrfDraft13;

impl VrfDraft13 {
    /// Generates a batch-compatible VRF proof using draft-13 specification
    ///
    /// Produces a 128-byte proof in the batchcompat format: Gamma || kB || kH || s.
    /// This stores the commitment points kB and kH directly in the proof,
    /// enabling efficient batch verification.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - 64-byte Ed25519 secret key (seed || public_key)
    /// * `message` - Arbitrary-length message to prove
    ///
    /// # Returns
    ///
    /// 128-byte proof containing (Gamma || kB || kH || s)
    ///
    /// # Errors
    ///
    /// Returns error if the secret key is malformed or hash-to-curve fails.
    ///
    /// # Upstream
    ///
    /// Matches `crypto_vrf_ietfdraft13_prove_batchcompat` in
    /// `cardano-crypto-praos/cbits/vrf13_batchcompat/prove.c`
    pub fn prove(secret_key: &[u8; SECRET_KEY_SIZE], message: &[u8]) -> Result<[u8; PROOF_SIZE]> {
        // Step 1: Expand secret key via SHA-512
        let mut az = Zeroizing::new([0u8; 64]);
        let mut hasher = Sha512::new();
        hasher.update(&secret_key[0..32]);
        let hash = hasher.finalize();
        az.copy_from_slice(&hash);

        // Step 2: Clamp scalar
        az[0] &= 248;
        az[31] &= 127;
        az[31] |= 64;

        let secret_scalar_bytes: [u8; 32] = az[0..32].try_into().map_err(|_| {
            crate::common::error::CryptoError::InvalidKeyLength {
                expected: 32,
                got: az[0..32].len(),
            }
        })?;
        let x = Scalar::from_bytes_mod_order(secret_scalar_bytes);

        let pk = &secret_key[32..64];

        // Step 3: Hash to curve → H point and its 32-byte compressed form (h_string)
        let (h_point, h_string) = cardano_hash_to_curve_draft13(pk, message)?;

        // Step 4: Compute Gamma = x * H
        let gamma = h_point * x;
        let gamma_bytes = point_to_bytes(&gamma);

        // Step 5: Compute nonce k = SHA-512(az[32..64] || H_string) reduced as scalar
        // Upstream: nonce is derived from the second half of expanded key and the
        // 32-byte compressed hash-to-curve point
        let mut nonce_hasher = Sha512::new();
        nonce_hasher.update(&az[32..64]);
        nonce_hasher.update(h_string);
        let nonce_hash = nonce_hasher.finalize();
        let nonce_hash_bytes: [u8; 64] = nonce_hash.into();
        let k = Scalar::from_bytes_mod_order_wide(&nonce_hash_bytes);

        // Step 6: Compute commitment points kB and kH
        let k_b = ED25519_BASEPOINT_POINT * k;
        let k_h = h_point * k;
        let k_b_bytes = point_to_bytes(&k_b);
        let k_h_bytes = point_to_bytes(&k_h);

        // Step 7: Compute challenge c = SHA-512(SUITE || TWO || pk || H_string || Gamma || kB || kH || ZERO)[0..16]
        let mut c_hasher = Sha512::new();
        c_hasher.update([SUITE_DRAFT13]);
        c_hasher.update([TWO]);
        c_hasher.update(pk);
        c_hasher.update(h_string);
        c_hasher.update(gamma_bytes);
        c_hasher.update(k_b_bytes);
        c_hasher.update(k_h_bytes);
        c_hasher.update([ZERO]);
        let c_hash = c_hasher.finalize();

        let mut c_scalar_bytes = [0u8; 32];
        c_scalar_bytes[0..16].copy_from_slice(&c_hash[0..16]);
        let c = Scalar::from_bytes_mod_order(c_scalar_bytes);

        // Step 8: Compute s = c*x + k mod L (sc25519_muladd)
        let s = (c * x) + k;
        let s_bytes = s.to_bytes();

        // Step 9: Construct batchcompat proof: Gamma(32) || kB(32) || kH(32) || s(32)
        let mut proof = [0u8; PROOF_SIZE];
        proof[0..32].copy_from_slice(&gamma_bytes);
        proof[32..64].copy_from_slice(&k_b_bytes);
        proof[64..96].copy_from_slice(&k_h_bytes);
        proof[96..128].copy_from_slice(&s_bytes);

        Ok(proof)
    }

    /// Verify a batch-compatible VRF proof and return the output
    ///
    /// Verifies the proof by recomputing the challenge from the stored
    /// commitment points (kB, kH) and checking that the algebraic
    /// relations s*B - c*Y == kB and s*H - c*Gamma == kH hold.
    ///
    /// # Arguments
    /// * `public_key` - 32-byte public key
    /// * `proof` - 128-byte batchcompat proof (Gamma || kB || kH || s)
    /// * `message` - Message that was proven
    ///
    /// # Returns
    /// 64-byte VRF output on success
    ///
    /// # Errors
    ///
    /// Returns error if proof verification fails
    ///
    /// # Upstream
    ///
    /// Matches `crypto_vrf_ietfdraft13_verify_batchcompat` in
    /// `cardano-crypto-praos/cbits/vrf13_batchcompat/verify.c`
    pub fn verify(
        public_key: &[u8; PUBLIC_KEY_SIZE],
        proof: &[u8; PROOF_SIZE],
        message: &[u8],
    ) -> Result<[u8; OUTPUT_SIZE]> {
        // Upstream: check small-order and canonical before decompressing pk
        let y_point = bytes_to_point(public_key)?;

        // Parse proof: Gamma(32) || U_proof(32) || V_proof(32) || s(32)
        let gamma = bytes_to_point(&proof[0..32].try_into().map_err(|_| {
            crate::common::error::CryptoError::InvalidProof
        })?)?;

        let u_proof: [u8; 32] = proof[32..64]
            .try_into()
            .map_err(|_| crate::common::error::CryptoError::InvalidProof)?;
        let v_proof: [u8; 32] = proof[64..96]
            .try_into()
            .map_err(|_| crate::common::error::CryptoError::InvalidProof)?;

        let s_bytes: [u8; 32] = proof[96..128]
            .try_into()
            .map_err(|_| crate::common::error::CryptoError::InvalidProof)?;

        // Upstream: check s is canonical scalar (< L)
        // s[31] & 0xF0 being nonzero is a quick pre-check
        if s_bytes[31] & 0xF0 != 0 {
            // Could still be canonical, but upstream checks sc25519_is_canonical
            // For safety, reject if the high nibble is set and the scalar is non-canonical
            let s_check = Scalar::from_canonical_bytes(s_bytes);
            if s_check.is_none().into() {
                return Err(crate::common::error::CryptoError::InvalidProof);
            }
        }
        let s = Scalar::from_bytes_mod_order(s_bytes);

        // Hash to curve: recompute H from pk || message
        let (h_point, h_string) = cardano_hash_to_curve_draft13(public_key, message)?;

        // Recompute challenge c from proof contents:
        // c = SHA-512(SUITE || TWO || pk || H_string || Gamma || U_proof || V_proof || ZERO)[0..16]
        let mut c_hasher = Sha512::new();
        c_hasher.update([SUITE_DRAFT13]);
        c_hasher.update([TWO]);
        c_hasher.update(public_key);
        c_hasher.update(h_string);
        c_hasher.update(point_to_bytes(&gamma));
        c_hasher.update(u_proof);
        c_hasher.update(v_proof);
        c_hasher.update([ZERO]);
        let c_hash = c_hasher.finalize();

        let mut c_scalar_bytes = [0u8; 32];
        c_scalar_bytes[0..16].copy_from_slice(&c_hash[0..16]);
        let c = Scalar::from_bytes_mod_order(c_scalar_bytes);
        let neg_c = -c;

        // Recompute U' = s*B + (-c)*Y  (should equal kB from proof)
        let u_recomputed = (ED25519_BASEPOINT_POINT * s) + (y_point * neg_c);
        let u_recomputed_bytes = point_to_bytes(&u_recomputed);

        // Recompute V' = s*H + (-c)*Gamma  (should equal kH from proof)
        let v_recomputed = (h_point * s) + (gamma * neg_c);
        let v_recomputed_bytes = point_to_bytes(&v_recomputed);

        // Verify: U' == U_proof AND V' == V_proof (byte-by-byte)
        let u_match = subtle::ConstantTimeEq::ct_eq(&u_recomputed_bytes[..], &u_proof[..]);
        let v_match = subtle::ConstantTimeEq::ct_eq(&v_recomputed_bytes[..], &v_proof[..]);

        if !bool::from(u_match & v_match) {
            return Err(crate::common::error::CryptoError::VerificationFailed);
        }

        // Compute VRF output: SHA-512(SUITE || THREE || cofactor_cleared(Gamma) || ZERO)
        Self::proof_to_hash(proof)
    }

    /// Convert a proof to VRF output hash without verification
    ///
    /// Extracts the VRF output from a proof **without verifying** its validity.
    /// This is useful when the proof has already been verified.
    ///
    /// **WARNING**: This function does NOT verify the proof's authenticity.
    /// Use [`verify`](Self::verify) if you need cryptographic assurance.
    ///
    /// # Upstream
    ///
    /// Matches `crypto_vrf_ietfdraft13_proof_to_hash_batchcompat` in
    /// `cardano-crypto-praos/cbits/vrf13_batchcompat/verify.c`
    pub fn proof_to_hash(proof: &[u8; PROOF_SIZE]) -> Result<[u8; OUTPUT_SIZE]> {
        let gamma_bytes: [u8; 32] = proof[0..32]
            .try_into()
            .map_err(|_| crate::common::error::CryptoError::InvalidProof)?;

        let gamma = bytes_to_point(&gamma_bytes)?;

        // Upstream checks sc25519_is_canonical on s (last 32 bytes of proof)
        let s_bytes: [u8; 32] = proof[96..128]
            .try_into()
            .map_err(|_| crate::common::error::CryptoError::InvalidProof)?;
        if s_bytes[31] & 0xF0 != 0 {
            let s_check = Scalar::from_canonical_bytes(s_bytes);
            if s_check.is_none().into() {
                return Err(crate::common::error::CryptoError::InvalidProof);
            }
        }

        let gamma_cleared = cardano_clear_cofactor(&gamma);

        // SHA-512(SUITE || THREE || cofactor_cleared(Gamma) || ZERO)
        // Note: trailing ZERO byte is required per upstream
        let mut hasher = Sha512::new();
        hasher.update([SUITE_DRAFT13]);
        hasher.update([THREE]);
        hasher.update(point_to_bytes(&gamma_cleared));
        hasher.update([ZERO]);
        let hash = hasher.finalize();

        let mut output = [0u8; OUTPUT_SIZE];
        output.copy_from_slice(&hash);
        Ok(output)
    }

    /// Generate keypair from seed
    ///
    /// Derives an Ed25519 keypair from a 32-byte seed using SHA-512 and scalar clamping.
    /// The secret key format is: seed (32 bytes) || public_key (32 bytes).
    ///
    /// # Arguments
    ///
    /// * `seed` - 32-byte random seed (use a CSPRNG)
    ///
    /// # Returns
    ///
    /// Tuple of (secret_key, public_key) where:
    /// - secret_key: 64 bytes (seed || public_key)
    /// - public_key: 32 bytes (compressed Edwards point)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::vrf::VrfDraft13;
    ///
    /// let seed = [42u8; 32];
    /// let (secret_key, public_key) = VrfDraft13::keypair_from_seed(&seed);
    /// assert_eq!(secret_key.len(), 64);
    /// assert_eq!(public_key.len(), 32);
    /// assert_eq!(&secret_key[32..64], &public_key[..]);
    /// ```
    #[must_use]
    pub fn keypair_from_seed(
        seed: &[u8; SEED_SIZE],
    ) -> ([u8; SECRET_KEY_SIZE], [u8; PUBLIC_KEY_SIZE]) {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        let hash = hasher.finalize();

        let mut secret_scalar = Zeroizing::new([0u8; 32]);
        secret_scalar.copy_from_slice(&hash[0..32]);
        *secret_scalar = clamp_scalar(*secret_scalar);

        let scalar = Scalar::from_bytes_mod_order(*secret_scalar);
        let public_point = ED25519_BASEPOINT_POINT * scalar;
        let public_key_bytes = point_to_bytes(&public_point);

        let mut secret_key = [0u8; SECRET_KEY_SIZE];
        secret_key[0..32].copy_from_slice(seed);
        secret_key[32..64].copy_from_slice(&public_key_bytes);

        (secret_key, public_key_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prove_verify_roundtrip() {
        let seed = [42u8; SEED_SIZE];
        let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);
        let message = b"test message";

        let proof = VrfDraft13::prove(&sk, message).expect("prove failed");
        let output = VrfDraft13::verify(&pk, &proof, message).expect("verify failed");

        assert_eq!(output.len(), OUTPUT_SIZE);
    }

    #[test]
    fn test_verify_rejects_invalid_proof() {
        let seed = [42u8; SEED_SIZE];
        let (_sk, pk) = VrfDraft13::keypair_from_seed(&seed);
        let message = b"test message";

        let invalid_proof = [0u8; PROOF_SIZE];
        let result = VrfDraft13::verify(&pk, &invalid_proof, message);

        assert!(result.is_err());
    }

    #[test]
    fn test_proof_to_hash_deterministic() {
        let seed = [42u8; SEED_SIZE];
        let (sk, _pk) = VrfDraft13::keypair_from_seed(&seed);
        let message = b"test message";

        let proof = VrfDraft13::prove(&sk, message).expect("prove failed");
        let hash1 = VrfDraft13::proof_to_hash(&proof).expect("hash failed");
        let hash2 = VrfDraft13::proof_to_hash(&proof).expect("hash failed");

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_proof_to_hash_matches_verify() {
        let seed = [99u8; SEED_SIZE];
        let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);
        let message = b"consistency check";

        let proof = VrfDraft13::prove(&sk, message).expect("prove failed");
        let hash = VrfDraft13::proof_to_hash(&proof).expect("hash failed");
        let output = VrfDraft13::verify(&pk, &proof, message).expect("verify failed");

        assert_eq!(hash, output);
    }

    #[test]
    fn test_keypair_structure() {
        let seed = [7u8; SEED_SIZE];
        let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);

        // Verify secret key contains seed and public key
        assert_eq!(&sk[0..32], &seed[..]);
        assert_eq!(&sk[32..64], &pk[..]);
    }

    #[test]
    fn test_proof_size() {
        let seed = [1u8; SEED_SIZE];
        let (sk, _pk) = VrfDraft13::keypair_from_seed(&seed);
        let message = b"size check";

        let proof = VrfDraft13::prove(&sk, message).expect("prove failed");
        assert_eq!(proof.len(), PROOF_SIZE);
        assert_eq!(proof.len(), 128);
    }
}
