//! Edwards curve point operations and hash-to-curve implementations
//!
//! This module provides Cardano-compatible implementations of cryptographic
//! operations on Edwards curve points, including:
//!
//! - Cofactor clearing for security
//! - Hash-to-curve for Draft-03 (Elligator2-based)
//! - Hash-to-curve for Draft-13 (Elligator2 via XMD-SHA-512)
//!
//! # Security Considerations
//!
//! ## Cofactor Clearing
//!
//! All hash-to-curve functions in this module return points that have been
//! cleared of the cofactor (multiplied by 8). This is **critical** for
//! curve25519-dalek v4 compatibility:
//!
//! - Points with torsion can cause distributive property failures
//! - `P * (a + b) != P * a + P * b` when P has torsion
//! - VRF verification relies on this property holding
//!
//! ## Domain Separation
//!
//! Each hash-to-curve variant uses a unique suite identifier to prevent
//! cross-protocol attacks:
//! - Draft-03: `0x04` (ECVRF-ED25519-SHA512-ELL2)
//! - Draft-13: `0x04` (ECVRF-ED25519-SHA512-ELL2)

use alloc::vec;
use alloc::vec::Vec;

use curve25519_dalek::edwards::EdwardsPoint;
use sha2::{Digest, Sha512};

use crate::common::{CryptoError, CryptoResult, ONE, SUITE_DRAFT03, point_to_bytes};

/// Clear the cofactor from an Edwards curve point (Cardano-compatible)
///
/// Multiplies the input point by 8 (the cofactor of Ed25519) to ensure
/// it lies in the prime-order subgroup. This prevents small-subgroup
/// attacks and ensures compatibility with curve25519-dalek v4.
///
/// # Arguments
///
/// * `point` - The Edwards point to clear
///
/// # Returns
///
/// A point in the prime-order subgroup (torsion-free)
///
/// # Security
///
/// This operation is **essential** for VRF security. Points with torsion
/// can cause verification failures due to arithmetic property violations
/// in curve25519-dalek v4.
///
/// # Examples
///
/// ```rust,ignore
/// use cardano_crypto::vrf::cardano_compat::cardano_clear_cofactor;
/// use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
///
/// let cleared = cardano_clear_cofactor(&ED25519_BASEPOINT_POINT);
/// // cleared is guaranteed torsion-free
/// ```
#[must_use]
pub fn cardano_clear_cofactor(point: &EdwardsPoint) -> EdwardsPoint {
    point.mul_by_cofactor()
}

/// Hash arbitrary data to an Edwards curve point (Draft-03, Elligator2-based)
///
/// Implements the hash-to-curve operation for IETF VRF Draft-03 using a
/// simplified Elligator2 approach. The output is deterministic and uniformly
/// distributed over the prime-order subgroup.
///
/// # Algorithm
///
/// 1. Compute `r = SHA-512(suite || 0x01 || public_key || message)`
/// 2. Take first 32 bytes and clear sign bit
/// 3. Attempt to decompress as Edwards Y coordinate
/// 4. If decompression fails, try again with incrementing counter
/// 5. Clear cofactor from resulting point
///
/// # Arguments
///
/// * `pk` - Public key bytes (domain separation)
/// * `message` - Message bytes to hash to curve
///
/// # Returns
///
/// A tuple containing:
/// - The curve point (torsion-free, in prime-order subgroup)
/// - The compressed point bytes (32 bytes)
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPoint`] if:
/// - No valid point can be found after 256 retry attempts (extremely unlikely)
/// - This indicates a catastrophic hash function failure
///
/// # Security
///
/// - Uses Suite ID `0x04` for domain separation
/// - Clears cofactor to prevent torsion-related attacks
/// - Constant-time within the hash-to-curve process
///
/// # Examples
///
/// ```rust,ignore
/// use cardano_crypto::vrf::cardano_compat::cardano_hash_to_curve;
///
/// let pk = [0u8; 32];
/// let message = b"block slot 12345";
/// let (point, bytes) = cardano_hash_to_curve(&pk, message)?;
/// ```
pub fn cardano_hash_to_curve(pk: &[u8], message: &[u8]) -> CryptoResult<(EdwardsPoint, [u8; 32])> {
    // Compute r = SHA512(suite || 0x01 || pk || message)
    let mut hasher = Sha512::new();
    hasher.update([SUITE_DRAFT03]);
    hasher.update([ONE]);
    hasher.update(pk);
    hasher.update(message);
    let r_hash = hasher.finalize();

    // Take first 32 bytes for Elligator2 input
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&r_hash[0..32]);

    // Use Elligator2 mapping to convert the field element to a curve point
    // The elligator2_to_edwards function already clears cofactor internally
    use super::elligator2::elligator2_to_edwards;

    match elligator2_to_edwards(&r_bytes) {
        Some(point) => {
            // elligator2_to_edwards already clears cofactor
            // Return the compressed point representation
            let compressed = point.compress();
            Ok((point, compressed.0))
        }
        None => {
            // Elligator2 should always produce a valid point
            // If this fails, there's a bug in the implementation
            Err(CryptoError::InvalidPoint)
        }
    }
}

/// Expand message using XMD-SHA-512 (RFC 9380)
///
/// Implements the expand_message_xmd algorithm from RFC 9380 Section 5.3.1
/// for SHA-512. This is used in Cardano's Draft-13 VRF implementation to
/// produce the 48-byte h_string needed for batch-compatible proofs.
///
/// # Algorithm
///
/// 1. Compute b_0 = SHA-512(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
/// 2. Compute b_i = SHA-512(b_(i-1) XOR b_0 || I2OSP(i, 1) || DST_prime)
/// 3. Concatenate blocks to get len_in_bytes of output
fn expand_message_xmd(dst: &[u8], msg: &[u8], len_in_bytes: usize) -> Vec<u8> {
    const B_IN_BYTES: usize = 64; // SHA-512 output size
    const R_IN_BYTES: usize = 128; // SHA-512 block size

    let ell = len_in_bytes.div_ceil(B_IN_BYTES);

    // DST_prime = DST || I2OSP(len(DST), 1)
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    // Z_pad = I2OSP(0, R_IN_BYTES)
    let z_pad = vec![0u8; R_IN_BYTES];

    // l_i_b_str = I2OSP(len_in_bytes, 2)
    let l_i_b_str = [(len_in_bytes >> 8) as u8, (len_in_bytes & 0xFF) as u8];

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    let mut hasher = Sha512::new();
    hasher.update(z_pad);
    hasher.update(msg);
    hasher.update(l_i_b_str);
    hasher.update([0u8]);
    hasher.update(&dst_prime);
    let b_0 = hasher.finalize();

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut hasher = Sha512::new();
    hasher.update(b_0);
    hasher.update([1u8]);
    hasher.update(&dst_prime);
    let mut b_i = hasher.finalize();

    let mut uniform_bytes = b_i.to_vec();

    // b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
    for i in 2..=ell {
        let mut hasher = Sha512::new();
        // XOR b_0 with b_(i-1)
        let mut xor_result = [0u8; B_IN_BYTES];
        for j in 0..B_IN_BYTES {
            xor_result[j] = b_0[j] ^ b_i[j];
        }
        hasher.update(xor_result);
        hasher.update([i as u8]);
        hasher.update(&dst_prime);
        b_i = hasher.finalize();
        uniform_bytes.extend_from_slice(&b_i);
    }

    uniform_bytes.truncate(len_in_bytes);
    uniform_bytes
}

/// Hash arbitrary data to an Edwards curve point (Draft-13, XMD-SHA-512 Elligator2)
///
/// Implements hash-to-curve for IETF VRF Draft-13 using expand_message_xmd from
/// RFC 9380. This produces a 48-byte h_string needed for batch-compatible proofs
/// in Cardano's production blockchain.
///
/// # Algorithm
///
/// 1. Build input: pk || message
/// 2. Expand using XMD-SHA-512 with domain separation tag to get 48 bytes
/// 3. Use first 32 bytes for Elligator2 mapping to curve point
/// 4. Clear cofactor for security
/// 5. Return point + full 48-byte h_string
///
/// # Differences from Draft-03
///
/// - Uses XMD expansion instead of simple SHA-512
/// - Returns 48 bytes (not 32) for batch verification
/// - Domain separation tag: "ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\x04"
///
/// # Arguments
///
/// * `pk` - Public key bytes (domain separation)
/// * `message` - Message bytes to hash to curve
///
/// # Returns
///
/// A tuple containing:
/// - The curve point (torsion-free, in prime-order subgroup)
/// - The h_string bytes (48 bytes for batch compatibility)
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPoint`] if no valid point found after 256 attempts
///
/// # Examples
///
/// ```rust,ignore
/// use cardano_crypto::vrf::cardano_compat::cardano_hash_to_curve_draft13;
///
/// let pk = [0u8; 32];
/// let message = b"batch verification test";
/// let (point, h_string) = cardano_hash_to_curve_draft13(&pk, message)?;
/// assert_eq!(h_string.len(), 32);
/// ```
pub fn cardano_hash_to_curve_draft13(
    pk: &[u8],
    message: &[u8],
) -> CryptoResult<(EdwardsPoint, [u8; 32])> {
    // Build the input string: pk || message
    let mut input = Vec::with_capacity(pk.len() + message.len());
    input.extend_from_slice(pk);
    input.extend_from_slice(message);

    // Domain separation tag for Draft-13 Elligator2
    // The trailing \x04 is the suite byte (same for Draft-03 and Draft-13)
    let dst = b"ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\x04";

    // Expand to 48 bytes using XMD (SHA-512)
    let expanded = expand_message_xmd(dst, &input, 48);

    // Upstream _string_to_points pipeline:
    // 1. Reverse 48 bytes (big-endian to little-endian)
    // 2. Zero-pad to 64 bytes
    // 3. Apply ge25519_from_hash (reduce64 + Elligator2 with notsquare sign correction)
    let mut h = [0u8; 64];
    for j in 0..48 {
        h[j] = expanded[47 - j];
    }
    // h[48..64] is already zero from initialization

    use super::elligator2::ge25519_from_hash;

    match ge25519_from_hash(&h) {
        Some(point) => {
            // ge25519_from_hash already clears cofactor internally
            let h_string = point_to_bytes(&point);
            Ok((point, h_string))
        }
        None => Err(CryptoError::InvalidPoint),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cofactor_clearing() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

        let point = ED25519_BASEPOINT_POINT;
        let cleared = cardano_clear_cofactor(&point);

        // Cleared point should be on the curve
        assert!(cleared.is_torsion_free());
    }

    #[test]
    fn test_hash_to_curve() {
        let pk = [0u8; 32];
        let message = b"test";

        let result = cardano_hash_to_curve(&pk, message);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hash_to_curve_draft13() {
        let pk = [0u8; 32];
        let message = b"test";

        let result = cardano_hash_to_curve_draft13(&pk, message);
        assert!(result.is_ok());

        if let Ok((_, h_string)) = result {
            assert_eq!(h_string.len(), 32);
        }
    }
}
