//! # BLS12-381 Cryptographic Primitives
//!
//! This module provides BLS12-381 curve operations for Plutus V2+ smart contracts,
//! implementing CIP-0381 primitives.
//!
//! ## Features
//!
//! - **G1 Operations** - Point operations on the G1 curve
//! - **G2 Operations** - Point operations on the G2 curve
//! - **Pairing** - Miller loop and final exponentiation
//! - **Hash-to-curve** - Hashing arbitrary data to curve points
//! - **BLS Signatures** - Aggregate signature support
//!
//! ## CIP Support
//!
//! - [CIP-0381](https://cips.cardano.org/cip/CIP-0381) - Plutus support for pairings over BLS12-381
//!
//! ## Example
//!
//! ```rust,ignore
//! use cardano_crypto::bls::{G1Point, G2Point, Bls12381};
//!
//! // Hash a message to G1
//! let point = Bls12381::hash_to_g1(b"Hello, Cardano!");
//!
//! // Perform pairing
//! let g1 = G1Point::generator();
//! let g2 = G2Point::generator();
//! let result = Bls12381::pairing(&g1, &g2);
//! ```

use crate::common::error::CryptoError;
use blst::{
    blst_encode_to_g1, blst_encode_to_g2, blst_final_exp, blst_fp12, blst_fp12_is_one,
    blst_miller_loop, blst_p1, blst_p1_add, blst_p1_affine, blst_p1_cneg, blst_p1_compress,
    blst_p1_from_affine, blst_p1_mult, blst_p1_on_curve, blst_p1_to_affine, blst_p1_uncompress,
    blst_p2, blst_p2_add, blst_p2_affine, blst_p2_cneg, blst_p2_compress, blst_p2_from_affine,
    blst_p2_mult, blst_p2_on_curve, blst_p2_to_affine, blst_p2_uncompress, blst_scalar,
    blst_scalar_from_bendian, min_pk, BLST_ERROR,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

// ============================================================================
// Constants
// ============================================================================

/// Size of compressed G1 point in bytes.
pub const G1_COMPRESSED_SIZE: usize = 48;

/// Size of compressed G2 point in bytes.
pub const G2_COMPRESSED_SIZE: usize = 96;

/// Size of BLS scalar in bytes.
pub const SCALAR_SIZE: usize = 32;

/// Size of pairing result (Fp12) in bytes (for serialization reference).
pub const FP12_SIZE: usize = 576;

// ============================================================================
// G1 Point
// ============================================================================

/// A point on the BLS12-381 G1 curve.
///
/// G1 points are used for public keys in the min-pk BLS signature scheme
/// and as the first argument in pairing operations.
#[derive(Clone)]
pub struct G1Point {
    point: blst_p1,
}

impl G1Point {
    /// Size of a compressed G1 point in bytes.
    pub const COMPRESSED_SIZE: usize = G1_COMPRESSED_SIZE;

    /// Returns the generator point of G1.
    pub fn generator() -> Self {
        unsafe {
            let gen_ptr = blst::blst_p1_generator();
            let point = *gen_ptr;
            Self { point }
        }
    }

    /// Creates the identity (zero) point of G1.
    pub fn identity() -> Self {
        Self {
            point: blst_p1::default(),
        }
    }

    /// Creates a G1 point from compressed bytes.
    pub fn from_compressed(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != G1_COMPRESSED_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: G1_COMPRESSED_SIZE,
                got: bytes.len(),
            });
        }

        let mut affine = blst_p1_affine::default();
        let result = unsafe { blst_p1_uncompress(&mut affine, bytes.as_ptr()) };

        if result != BLST_ERROR::BLST_SUCCESS {
            return Err(CryptoError::InvalidPublicKey);
        }

        let mut point = blst_p1::default();
        unsafe {
            blst_p1_from_affine(&mut point, &affine);
        }

        // Verify point is on curve
        if unsafe { !blst_p1_on_curve(&point) } {
            return Err(CryptoError::InvalidPublicKey);
        }

        Ok(Self { point })
    }

    /// Compresses the point to bytes.
    pub fn to_compressed(&self) -> [u8; G1_COMPRESSED_SIZE] {
        let mut out = [0u8; G1_COMPRESSED_SIZE];
        unsafe {
            blst_p1_compress(out.as_mut_ptr(), &self.point);
        }
        out
    }

    /// Adds two G1 points.
    pub fn add(&self, other: &Self) -> Self {
        let mut result = blst_p1::default();
        unsafe {
            blst_p1_add(&mut result, &self.point, &other.point);
        }
        Self { point: result }
    }

    /// Negates the point.
    pub fn neg(&self) -> Self {
        let mut result = self.point;
        unsafe {
            blst_p1_cneg(&mut result, true);
        }
        Self { point: result }
    }

    /// Scalar multiplication.
    pub fn mul(&self, scalar: &Scalar) -> Self {
        let mut result = blst_p1::default();
        unsafe {
            blst_p1_mult(&mut result, &self.point, scalar.bytes.as_ptr(), 256);
        }
        Self { point: result }
    }

    /// Checks if this is the identity point.
    pub fn is_identity(&self) -> bool {
        let compressed = self.to_compressed();
        // Check if the compressed point represents infinity
        compressed[0] & 0xc0 == 0xc0
    }

    /// Returns the internal point for pairing operations.
    pub(crate) fn to_affine(&self) -> blst_p1_affine {
        let mut affine = blst_p1_affine::default();
        unsafe {
            blst_p1_to_affine(&mut affine, &self.point);
        }
        affine
    }
}

impl PartialEq for G1Point {
    fn eq(&self, other: &Self) -> bool {
        self.to_compressed() == other.to_compressed()
    }
}

impl Eq for G1Point {}

impl core::fmt::Debug for G1Point {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let compressed = self.to_compressed();
        f.debug_struct("G1Point")
            .field("compressed", &hex_preview(&compressed))
            .finish()
    }
}

// ============================================================================
// G2 Point
// ============================================================================

/// A point on the BLS12-381 G2 curve.
///
/// G2 points are used for signatures in the min-pk BLS signature scheme
/// and as the second argument in pairing operations.
#[derive(Clone)]
pub struct G2Point {
    point: blst_p2,
}

impl G2Point {
    /// Size of a compressed G2 point in bytes.
    pub const COMPRESSED_SIZE: usize = G2_COMPRESSED_SIZE;

    /// Returns the generator point of G2.
    pub fn generator() -> Self {
        unsafe {
            let gen_ptr = blst::blst_p2_generator();
            let point = *gen_ptr;
            Self { point }
        }
    }

    /// Creates the identity (zero) point of G2.
    pub fn identity() -> Self {
        Self {
            point: blst_p2::default(),
        }
    }

    /// Creates a G2 point from compressed bytes.
    pub fn from_compressed(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != G2_COMPRESSED_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: G2_COMPRESSED_SIZE,
                got: bytes.len(),
            });
        }

        let mut affine = blst_p2_affine::default();
        let result = unsafe { blst_p2_uncompress(&mut affine, bytes.as_ptr()) };

        if result != BLST_ERROR::BLST_SUCCESS {
            return Err(CryptoError::InvalidPublicKey);
        }

        let mut point = blst_p2::default();
        unsafe {
            blst_p2_from_affine(&mut point, &affine);
        }

        // Verify point is on curve
        if unsafe { !blst_p2_on_curve(&point) } {
            return Err(CryptoError::InvalidPublicKey);
        }

        Ok(Self { point })
    }

    /// Compresses the point to bytes.
    pub fn to_compressed(&self) -> [u8; G2_COMPRESSED_SIZE] {
        let mut out = [0u8; G2_COMPRESSED_SIZE];
        unsafe {
            blst_p2_compress(out.as_mut_ptr(), &self.point);
        }
        out
    }

    /// Adds two G2 points.
    pub fn add(&self, other: &Self) -> Self {
        let mut result = blst_p2::default();
        unsafe {
            blst_p2_add(&mut result, &self.point, &other.point);
        }
        Self { point: result }
    }

    /// Negates the point.
    pub fn neg(&self) -> Self {
        let mut result = self.point;
        unsafe {
            blst_p2_cneg(&mut result, true);
        }
        Self { point: result }
    }

    /// Scalar multiplication.
    pub fn mul(&self, scalar: &Scalar) -> Self {
        let mut result = blst_p2::default();
        unsafe {
            blst_p2_mult(&mut result, &self.point, scalar.bytes.as_ptr(), 256);
        }
        Self { point: result }
    }

    /// Checks if this is the identity point.
    pub fn is_identity(&self) -> bool {
        let compressed = self.to_compressed();
        // Check if the compressed point represents infinity
        compressed[0] & 0xc0 == 0xc0
    }

    /// Returns the internal point for pairing operations.
    pub(crate) fn to_affine(&self) -> blst_p2_affine {
        let mut affine = blst_p2_affine::default();
        unsafe {
            blst_p2_to_affine(&mut affine, &self.point);
        }
        affine
    }
}

impl PartialEq for G2Point {
    fn eq(&self, other: &Self) -> bool {
        self.to_compressed() == other.to_compressed()
    }
}

impl Eq for G2Point {}

impl core::fmt::Debug for G2Point {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let compressed = self.to_compressed();
        f.debug_struct("G2Point")
            .field("compressed", &hex_preview(&compressed))
            .finish()
    }
}

// ============================================================================
// Scalar
// ============================================================================

/// A scalar value for BLS12-381 curve operations.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Scalar {
    bytes: [u8; SCALAR_SIZE],
}

impl Scalar {
    /// Size of a scalar in bytes.
    pub const SIZE: usize = SCALAR_SIZE;

    /// Creates a scalar from big-endian bytes.
    pub fn from_bytes_be(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != SCALAR_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SCALAR_SIZE,
                got: bytes.len(),
            });
        }
        let mut scalar_bytes = [0u8; SCALAR_SIZE];
        scalar_bytes.copy_from_slice(bytes);
        Ok(Self {
            bytes: scalar_bytes,
        })
    }

    /// Returns the scalar as big-endian bytes.
    pub fn as_bytes(&self) -> &[u8; SCALAR_SIZE] {
        &self.bytes
    }

    /// Converts to blst scalar type.
    fn to_blst_scalar(&self) -> blst_scalar {
        let mut scalar = blst_scalar::default();
        unsafe {
            blst_scalar_from_bendian(&mut scalar, self.bytes.as_ptr());
        }
        scalar
    }
}

impl core::fmt::Debug for Scalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Scalar")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// Pairing Result
// ============================================================================

/// Result of a BLS12-381 pairing operation (element of Fp12).
#[derive(Clone)]
pub struct PairingResult {
    value: blst_fp12,
}

impl PairingResult {
    /// Checks if this is the identity element (one in Fp12).
    pub fn is_one(&self) -> bool {
        unsafe { blst_fp12_is_one(&self.value) }
    }

    /// Multiplies two pairing results.
    pub fn mul(&self, other: &Self) -> Self {
        let mut result = blst_fp12::default();
        unsafe {
            blst::blst_fp12_mul(&mut result, &self.value, &other.value);
        }
        Self { value: result }
    }
}

impl PartialEq for PairingResult {
    fn eq(&self, other: &Self) -> bool {
        // Compare byte representations
        unsafe {
            let self_bytes = core::slice::from_raw_parts(
                &self.value as *const _ as *const u8,
                core::mem::size_of::<blst_fp12>(),
            );
            let other_bytes = core::slice::from_raw_parts(
                &other.value as *const _ as *const u8,
                core::mem::size_of::<blst_fp12>(),
            );
            self_bytes == other_bytes
        }
    }
}

impl Eq for PairingResult {}

impl core::fmt::Debug for PairingResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PairingResult")
            .field("is_one", &self.is_one())
            .finish()
    }
}

// ============================================================================
// BLS Operations
// ============================================================================

/// BLS12-381 curve operations matching CIP-0381 Plutus primitives.
///
/// This provides the cryptographic primitives required for Plutus V2+
/// smart contracts that use pairings over BLS12-381.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bls12381;

impl Bls12381 {
    // ========================================================================
    // G1 Operations (CIP-0381)
    // ========================================================================

    /// Adds two G1 points.
    ///
    /// Corresponds to `bls12_381_G1_add` in Plutus.
    pub fn g1_add(a: &G1Point, b: &G1Point) -> G1Point {
        a.add(b)
    }

    /// Negates a G1 point.
    ///
    /// Corresponds to `bls12_381_G1_neg` in Plutus.
    pub fn g1_neg(p: &G1Point) -> G1Point {
        p.neg()
    }

    /// Multiplies a G1 point by a scalar.
    ///
    /// Corresponds to `bls12_381_G1_scalarMul` in Plutus.
    pub fn g1_scalar_mul(scalar: &Scalar, p: &G1Point) -> G1Point {
        p.mul(scalar)
    }

    /// Checks if a G1 point equals the identity.
    ///
    /// Corresponds to checking against `bls12_381_G1_zero` in Plutus.
    pub fn g1_is_identity(p: &G1Point) -> bool {
        p.is_identity()
    }

    /// Compresses a G1 point to bytes.
    ///
    /// Corresponds to `bls12_381_G1_compress` in Plutus.
    pub fn g1_compress(p: &G1Point) -> [u8; G1_COMPRESSED_SIZE] {
        p.to_compressed()
    }

    /// Decompresses bytes to a G1 point.
    ///
    /// Corresponds to `bls12_381_G1_uncompress` in Plutus.
    pub fn g1_uncompress(bytes: &[u8]) -> Result<G1Point, CryptoError> {
        G1Point::from_compressed(bytes)
    }

    /// Hash arbitrary bytes to a G1 point using hash-to-curve.
    ///
    /// Corresponds to `bls12_381_G1_hashToGroup` in Plutus.
    pub fn g1_hash_to_curve(msg: &[u8], dst: &[u8]) -> G1Point {
        let mut point = blst_p1::default();
        unsafe {
            blst_encode_to_g1(
                &mut point,
                msg.as_ptr(),
                msg.len(),
                dst.as_ptr(),
                dst.len(),
                core::ptr::null(),
                0,
            );
        }
        G1Point { point }
    }

    // ========================================================================
    // G2 Operations (CIP-0381)
    // ========================================================================

    /// Adds two G2 points.
    ///
    /// Corresponds to `bls12_381_G2_add` in Plutus.
    pub fn g2_add(a: &G2Point, b: &G2Point) -> G2Point {
        a.add(b)
    }

    /// Negates a G2 point.
    ///
    /// Corresponds to `bls12_381_G2_neg` in Plutus.
    pub fn g2_neg(p: &G2Point) -> G2Point {
        p.neg()
    }

    /// Multiplies a G2 point by a scalar.
    ///
    /// Corresponds to `bls12_381_G2_scalarMul` in Plutus.
    pub fn g2_scalar_mul(scalar: &Scalar, p: &G2Point) -> G2Point {
        p.mul(scalar)
    }

    /// Checks if a G2 point equals the identity.
    ///
    /// Corresponds to checking against `bls12_381_G2_zero` in Plutus.
    pub fn g2_is_identity(p: &G2Point) -> bool {
        p.is_identity()
    }

    /// Compresses a G2 point to bytes.
    ///
    /// Corresponds to `bls12_381_G2_compress` in Plutus.
    pub fn g2_compress(p: &G2Point) -> [u8; G2_COMPRESSED_SIZE] {
        p.to_compressed()
    }

    /// Decompresses bytes to a G2 point.
    ///
    /// Corresponds to `bls12_381_G2_uncompress` in Plutus.
    pub fn g2_uncompress(bytes: &[u8]) -> Result<G2Point, CryptoError> {
        G2Point::from_compressed(bytes)
    }

    /// Hash arbitrary bytes to a G2 point using hash-to-curve.
    ///
    /// Corresponds to `bls12_381_G2_hashToGroup` in Plutus.
    pub fn g2_hash_to_curve(msg: &[u8], dst: &[u8]) -> G2Point {
        let mut point = blst_p2::default();
        unsafe {
            blst_encode_to_g2(
                &mut point,
                msg.as_ptr(),
                msg.len(),
                dst.as_ptr(),
                dst.len(),
                core::ptr::null(),
                0,
            );
        }
        G2Point { point }
    }

    // ========================================================================
    // Pairing Operations (CIP-0381)
    // ========================================================================

    /// Computes the pairing e(g1, g2) followed by final exponentiation.
    ///
    /// Corresponds to `bls12_381_millerLoop` followed by `bls12_381_finalVerify`
    /// semantics in Plutus.
    pub fn pairing(g1: &G1Point, g2: &G2Point) -> PairingResult {
        let g1_affine = g1.to_affine();
        let g2_affine = g2.to_affine();

        let mut result = blst_fp12::default();
        unsafe {
            blst_miller_loop(&mut result, &g2_affine, &g1_affine);
            blst_final_exp(&mut result, &result);
        }

        PairingResult { value: result }
    }

    /// Computes just the Miller loop without final exponentiation.
    ///
    /// Corresponds to `bls12_381_millerLoop` in Plutus.
    pub fn miller_loop(g1: &G1Point, g2: &G2Point) -> PairingResult {
        let g1_affine = g1.to_affine();
        let g2_affine = g2.to_affine();

        let mut result = blst_fp12::default();
        unsafe {
            blst_miller_loop(&mut result, &g2_affine, &g1_affine);
        }

        PairingResult { value: result }
    }

    /// Performs final exponentiation on a Miller loop result.
    ///
    /// Corresponds to `bls12_381_finalVerify` in Plutus (checking if result is one).
    pub fn final_exponentiate(ml_result: &PairingResult) -> PairingResult {
        let mut result = blst_fp12::default();
        unsafe {
            blst_final_exp(&mut result, &ml_result.value);
        }
        PairingResult { value: result }
    }

    /// Verifies a pairing equation: e(g1_1, g2_1) * e(g1_2, g2_2) == 1.
    ///
    /// This is useful for BLS signature verification where we check:
    /// e(sig, g2_gen) * e(-hash, pk) == 1
    pub fn verify_pairing_equation(pairs: &[(G1Point, G2Point)]) -> bool {
        if pairs.is_empty() {
            return true;
        }

        let mut acc = blst_fp12::default();
        let mut first = true;

        for (g1, g2) in pairs {
            let g1_affine = g1.to_affine();
            let g2_affine = g2.to_affine();

            let mut ml = blst_fp12::default();
            unsafe {
                blst_miller_loop(&mut ml, &g2_affine, &g1_affine);
            }

            if first {
                acc = ml;
                first = false;
            } else {
                unsafe {
                    blst::blst_fp12_mul(&mut acc, &acc, &ml);
                }
            }
        }

        // Final exponentiation and check if result is one
        let mut result = blst_fp12::default();
        unsafe {
            blst_final_exp(&mut result, &acc);
            blst_fp12_is_one(&result)
        }
    }
}

// ============================================================================
// BLS Signature Support
// ============================================================================

/// BLS signature (min-pk variant) using G1 for public keys.
///
/// This is the standard BLS signature scheme where:
/// - Public keys are G1 points (48 bytes compressed)
/// - Signatures are G2 points (96 bytes compressed)
#[derive(Clone, PartialEq, Eq)]
pub struct BlsSignature {
    point: G2Point,
}

impl BlsSignature {
    /// Size of a compressed BLS signature.
    pub const COMPRESSED_SIZE: usize = G2_COMPRESSED_SIZE;

    /// Creates a signature from compressed bytes.
    pub fn from_compressed(bytes: &[u8]) -> Result<Self, CryptoError> {
        let point = G2Point::from_compressed(bytes)?;
        Ok(Self { point })
    }

    /// Compresses the signature to bytes.
    pub fn to_compressed(&self) -> [u8; G2_COMPRESSED_SIZE] {
        self.point.to_compressed()
    }
}

impl core::fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlsSignature")
            .field("point", &self.point)
            .finish()
    }
}

/// BLS public key (min-pk variant).
#[derive(Clone, PartialEq, Eq)]
pub struct BlsPublicKey {
    point: G1Point,
}

impl BlsPublicKey {
    /// Size of a compressed BLS public key.
    pub const COMPRESSED_SIZE: usize = G1_COMPRESSED_SIZE;

    /// Creates a public key from compressed bytes.
    pub fn from_compressed(bytes: &[u8]) -> Result<Self, CryptoError> {
        let point = G1Point::from_compressed(bytes)?;
        Ok(Self { point })
    }

    /// Compresses the public key to bytes.
    pub fn to_compressed(&self) -> [u8; G1_COMPRESSED_SIZE] {
        self.point.to_compressed()
    }
}

impl core::fmt::Debug for BlsPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlsPublicKey")
            .field("point", &self.point)
            .finish()
    }
}

/// BLS secret key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlsSecretKey {
    scalar: Scalar,
}

impl BlsSecretKey {
    /// Size of a BLS secret key.
    pub const SIZE: usize = SCALAR_SIZE;

    /// Creates a secret key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let scalar = Scalar::from_bytes_be(bytes)?;
        Ok(Self { scalar })
    }

    /// Derives the public key from this secret key.
    pub fn public_key(&self) -> BlsPublicKey {
        let point = G1Point::generator().mul(&self.scalar);
        BlsPublicKey { point }
    }

    /// Signs a message.
    ///
    /// Uses the BLS-SIG-BLS12-381-SHA256-SSWU-RO-POP scheme with
    /// the standard domain separation tag.
    pub fn sign(&self, msg: &[u8]) -> BlsSignature {
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        let hash_point = Bls12381::g2_hash_to_curve(msg, dst);
        let sig_point = hash_point.mul(&self.scalar);
        BlsSignature { point: sig_point }
    }

    /// Signs a message with a custom domain separation tag.
    pub fn sign_with_dst(&self, msg: &[u8], dst: &[u8]) -> BlsSignature {
        let hash_point = Bls12381::g2_hash_to_curve(msg, dst);
        let sig_point = hash_point.mul(&self.scalar);
        BlsSignature { point: sig_point }
    }
}

impl core::fmt::Debug for BlsSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlsSecretKey")
            .field("scalar", &"[REDACTED]")
            .finish()
    }
}

/// Verifies a BLS signature.
///
/// Uses the standard domain separation tag.
pub fn bls_verify(pk: &BlsPublicKey, msg: &[u8], sig: &BlsSignature) -> Result<(), CryptoError> {
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    bls_verify_with_dst(pk, msg, sig, dst)
}

/// Verifies a BLS signature with a custom domain separation tag.
pub fn bls_verify_with_dst(
    pk: &BlsPublicKey,
    msg: &[u8],
    sig: &BlsSignature,
    dst: &[u8],
) -> Result<(), CryptoError> {
    let hash_point = Bls12381::g2_hash_to_curve(msg, dst);
    let g1_gen = G1Point::generator();

    // Verify: e(pk, hash) == e(g1, sig)
    // Equivalently: e(pk, hash) * e(-g1, sig) == 1
    let neg_g1 = g1_gen.neg();

    let valid = Bls12381::verify_pairing_equation(&[
        (pk.point.clone(), hash_point),
        (neg_g1, sig.point.clone()),
    ]);

    if valid {
        Ok(())
    } else {
        Err(CryptoError::SignatureVerificationFailed)
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
    fn test_g1_generator() {
        let gen = G1Point::generator();
        assert!(!gen.is_identity());

        // Verify roundtrip
        let compressed = gen.to_compressed();
        let restored = G1Point::from_compressed(&compressed).unwrap();
        assert_eq!(gen, restored);
    }

    #[test]
    fn test_g2_generator() {
        let gen = G2Point::generator();
        assert!(!gen.is_identity());

        // Verify roundtrip
        let compressed = gen.to_compressed();
        let restored = G2Point::from_compressed(&compressed).unwrap();
        assert_eq!(gen, restored);
    }

    #[test]
    fn test_g1_identity() {
        let id = G1Point::identity();
        assert!(id.is_identity());

        // Adding identity should give the same point
        let gen = G1Point::generator();
        let result = gen.add(&id);
        assert_eq!(gen, result);
    }

    #[test]
    fn test_g2_identity() {
        let id = G2Point::identity();
        assert!(id.is_identity());

        // Adding identity should give the same point
        let gen = G2Point::generator();
        let result = gen.add(&id);
        assert_eq!(gen, result);
    }

    #[test]
    fn test_g1_add() {
        let gen = G1Point::generator();
        let doubled = gen.add(&gen);

        // Create scalar 2
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes[31] = 2;
        let scalar = Scalar::from_bytes_be(&scalar_bytes).unwrap();

        let also_doubled = gen.mul(&scalar);
        assert_eq!(doubled, also_doubled);
    }

    #[test]
    fn test_g1_neg() {
        let gen = G1Point::generator();
        let neg = gen.neg();

        // g + (-g) should be identity
        let sum = gen.add(&neg);
        assert!(sum.is_identity());
    }

    #[test]
    fn test_pairing_bilinearity() {
        // Test: e(aP, bQ) = e(P, Q)^(ab) = e(abP, Q) = e(P, abQ)
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        let mut a_bytes = [0u8; 32];
        a_bytes[31] = 5;
        let a = Scalar::from_bytes_be(&a_bytes).unwrap();

        let mut b_bytes = [0u8; 32];
        b_bytes[31] = 7;
        let b = Scalar::from_bytes_be(&b_bytes).unwrap();

        // e(aG1, bG2)
        let ag1 = g1.mul(&a);
        let bg2 = g2.mul(&b);
        let result1 = Bls12381::pairing(&ag1, &bg2);

        // e(abG1, G2)
        let mut ab_bytes = [0u8; 32];
        ab_bytes[31] = 35; // 5 * 7 = 35
        let ab = Scalar::from_bytes_be(&ab_bytes).unwrap();
        let abg1 = g1.mul(&ab);
        let result2 = Bls12381::pairing(&abg1, &g2);

        // e(G1, abG2)
        let abg2 = g2.mul(&ab);
        let result3 = Bls12381::pairing(&g1, &abg2);

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_bls_sign_verify() {
        let seed = [42u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        let msg = b"Hello, Cardano!";
        let sig = sk.sign(msg);

        assert!(bls_verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn test_bls_invalid_message() {
        let seed = [42u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        let msg = b"Hello, Cardano!";
        let sig = sk.sign(msg);

        // Wrong message should fail
        assert!(bls_verify(&pk, b"Wrong message", &sig).is_err());
    }

    #[test]
    fn test_bls_key_roundtrip() {
        let seed = [123u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        let compressed = pk.to_compressed();
        let restored = BlsPublicKey::from_compressed(&compressed).unwrap();

        assert_eq!(pk, restored);
    }

    #[test]
    fn test_scalar_roundtrip() {
        let bytes = [1u8; 32];
        let scalar = Scalar::from_bytes_be(&bytes).unwrap();
        assert_eq!(scalar.as_bytes(), &bytes);
    }

    #[test]
    fn test_g1_hash_to_curve() {
        let msg1 = b"message1";
        let msg2 = b"message2";
        let dst = b"TEST_DST";

        let p1 = Bls12381::g1_hash_to_curve(msg1, dst);
        let p2 = Bls12381::g1_hash_to_curve(msg2, dst);

        // Different messages should hash to different points
        assert_ne!(p1, p2);

        // Same message should hash to same point
        let p1_again = Bls12381::g1_hash_to_curve(msg1, dst);
        assert_eq!(p1, p1_again);
    }

    #[test]
    fn test_g2_hash_to_curve() {
        let msg1 = b"message1";
        let msg2 = b"message2";
        let dst = b"TEST_DST";

        let p1 = Bls12381::g2_hash_to_curve(msg1, dst);
        let p2 = Bls12381::g2_hash_to_curve(msg2, dst);

        // Different messages should hash to different points
        assert_ne!(p1, p2);

        // Same message should hash to same point
        let p1_again = Bls12381::g2_hash_to_curve(msg1, dst);
        assert_eq!(p1, p1_again);
    }

    #[test]
    fn test_miller_loop_and_final_exp() {
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        // Miller loop followed by final exp should equal direct pairing
        let ml = Bls12381::miller_loop(&g1, &g2);
        let result1 = Bls12381::final_exponentiate(&ml);

        let result2 = Bls12381::pairing(&g1, &g2);

        assert_eq!(result1, result2);
    }
}
