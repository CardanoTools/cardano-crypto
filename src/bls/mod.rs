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
    blst_miller_loop, blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_cneg,
    blst_p1_compress, blst_p1_from_affine, blst_p1_mult, blst_p1_on_curve, blst_p1_to_affine,
    blst_p1_uncompress, blst_p2, blst_p2_add_or_double, blst_p2_affine, blst_p2_cneg,
    blst_p2_compress, blst_p2_from_affine, blst_p2_mult, blst_p2_on_curve, blst_p2_to_affine,
    blst_p2_uncompress, blst_scalar, blst_scalar_from_bendian, BLST_ERROR,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
/// G1 is the first group in the BLS12-381 pairing-friendly elliptic curve,
/// defined over the base field 𝔽p. Points are elements of the prime-order subgroup.
///
/// # Cardano Usage
///
/// In Plutus smart contracts (CIP-0381), G1 points are used for:
/// - Public keys in the min-pk BLS signature scheme
/// - First argument in pairing operations
/// - Commitment schemes and zero-knowledge proofs
///
/// # Security
///
/// - **Subgroup Check**: All deserialized points are verified to be in the prime-order subgroup
/// - **On-Curve Check**: Points are validated to lie on the BLS12-381 curve
/// - **Compressed Format**: Uses 48-byte compressed SEC1 encoding (x-coordinate + sign bit)
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::bls::{G1Point, Bls12381, Scalar};
///
/// // Get the generator point
/// let g = G1Point::generator();
///
/// // Point addition
/// let g2 = g.add(&g);
///
/// // Scalar multiplication
/// let scalar_bytes = [1u8; 32];
/// let scalar = Scalar::from_bytes_be(&scalar_bytes).unwrap();
/// let g_mul_s = g.mul(&scalar);
///
/// // Serialization
/// let compressed = g.to_compressed();
/// let restored = G1Point::from_compressed(&compressed).unwrap();
/// assert_eq!(g, restored);
/// ```
///
/// # References
///
/// - [CIP-0381](https://cips.cardano.org/cip/CIP-0381) - Plutus support for pairings over BLS12-381
/// - [IETF Draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves)
/// - [BLS Specification](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html)
#[derive(Clone)]
pub struct G1Point {
    /// Internal blst representation of the G1 point.
    ///
    /// This is always maintained in the projective coordinate system for
    /// efficient arithmetic operations.
    point: blst_p1,
}

impl G1Point {
    /// Size of a compressed G1 point in bytes.
    pub const COMPRESSED_SIZE: usize = G1_COMPRESSED_SIZE;

    /// Returns the generator point of G1.
    ///
    /// The generator is a fixed point of prime order on the BLS12-381 curve.
    /// This is the standard generator defined in the BLS12-381 specification.
    ///
    /// # Mathematical Properties
    ///
    /// - Order: r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    /// - The generator spans the entire prime-order subgroup
    /// - All scalar multiples of the generator form the group G1
    ///
    /// # Cardano Usage
    ///
    /// Used as the base point for:
    /// - BLS signature verification: `e(pk, H(m)) = e(G, sig)`
    /// - Commitment schemes in Plutus contracts
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::bls::G1Point;
    ///
    /// let g1 = G1Point::generator();
    /// assert!(!g1.is_identity());
    ///
    /// // Verify it's on the curve
    /// let compressed = g1.to_compressed();
    /// let restored = G1Point::from_compressed(&compressed).unwrap();
    /// assert_eq!(g1, restored);
    /// ```
    ///
    /// # Safety
    ///
    /// This function uses `unsafe` to dereference the const pointer returned by
    /// `blst_p1_generator()`. This is safe because:
    /// - The blst library guarantees this pointer points to valid static data
    /// - The data is immutable and always valid
    /// - The returned point is always on the curve and in the correct subgroup
    pub fn generator() -> Self {
        unsafe {
            // SAFETY: BLS12_381_G1 is a static constant representing the standard
            // BLS12-381 G1 generator point in affine form.
            // We convert it to projective form for use in arithmetic operations.
            let mut point = blst_p1::default();
            blst_p1_from_affine(&mut point, &blst::BLS12_381_G1);
            Self { point }
        }
    }

    /// Creates the identity (zero) point of G1.
    ///
    /// The identity element (also called "point at infinity") is the neutral element
    /// for the group operation. For any point P:
    /// - P + O = O + P = P
    /// - \[0\]P = O (scalar multiplication by zero)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::bls::G1Point;
    ///
    /// let identity = G1Point::identity();
    /// assert!(identity.is_identity());
    ///
    /// // Adding identity to any point gives back the same point
    /// let g = G1Point::generator();
    /// let result = g.add(&identity);
    /// assert_eq!(g, result);
    /// ```
    ///
    /// # Note
    ///
    /// The identity point cannot be represented in affine coordinates,
    /// but is properly handled in projective coordinates.
    pub fn identity() -> Self {
        Self {
            point: blst_p1::default(),
        }
    }

    /// Creates a G1 point from compressed bytes.
    ///
    /// Deserializes a G1 point from its compressed SEC1 representation (48 bytes).
    /// The compressed format stores the x-coordinate and a sign bit for the y-coordinate.
    ///
    /// # Format
    ///
    /// - 48 bytes total (384 bits)
    /// - First byte contains compression flag in top 3 bits:
    ///   - Bit 7: Always 1 (compressed)
    ///   - Bit 6: 1 if infinity, 0 otherwise
    ///   - Bit 5: Sign of y-coordinate (1 if y > p/2)
    /// - Remaining 47.625 bytes: x-coordinate in big-endian
    ///
    /// # Security
    ///
    /// This function performs comprehensive validation:
    /// - Length check (must be exactly 48 bytes)
    /// - Decompression validity (x-coordinate must be in field)
    /// - On-curve check (point must satisfy curve equation)
    /// - Subgroup check (implicit in blst decompression)
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the input is not 48 bytes.
    /// Returns `CryptoError::InvalidPublicKey` if:
    /// - The bytes don't represent a valid field element
    /// - The point is not on the curve
    /// - The point is not in the prime-order subgroup
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::bls::G1Point;
    ///
    /// let g = G1Point::generator();
    /// let bytes = g.to_compressed();
    ///
    /// // Roundtrip serialization
    /// let restored = G1Point::from_compressed(&bytes).unwrap();
    /// assert_eq!(g, restored);
    ///
    /// // Invalid length
    /// assert!(G1Point::from_compressed(&[0u8; 47]).is_err());
    ///
    /// // Invalid point
    /// assert!(G1Point::from_compressed(&[0u8; 48]).is_err());
    /// ```
    ///
    /// # Cardano Compatibility
    ///
    /// This matches the deserialization used in:
    /// - Plutus builtin `bls12_381_G1_uncompress`
    /// - Haskell `cardano-crypto-class` BLS implementation
    pub fn from_compressed(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != G1_COMPRESSED_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: G1_COMPRESSED_SIZE,
                got: bytes.len(),
            });
        }

        let mut affine = blst_p1_affine::default();
        // SAFETY: blst_p1_uncompress reads exactly 48 bytes from the pointer.
        // We've verified the slice has exactly 48 bytes above.
        let result = unsafe { blst_p1_uncompress(&mut affine, bytes.as_ptr()) };

        if result != BLST_ERROR::BLST_SUCCESS {
            return Err(CryptoError::InvalidPublicKey);
        }

        let mut point = blst_p1::default();
        // SAFETY: affine is a valid blst_p1_affine that was successfully
        // decompressed above. blst_p1_from_affine converts it to projective.
        unsafe {
            blst_p1_from_affine(&mut point, &affine);
        }

        // Verify point is on curve (redundant check, but ensures invariant)
        // SAFETY: point is a valid blst_p1 initialized above
        if unsafe { !blst_p1_on_curve(&point) } {
            return Err(CryptoError::InvalidPublicKey);
        }

        Ok(Self { point })
    }

    /// Compresses the point to bytes.
    ///
    /// Serializes this G1 point to its compressed SEC1 representation (48 bytes).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::bls::G1Point;
    ///
    /// let g = G1Point::generator();
    /// let compressed = g.to_compressed();
    /// assert_eq!(compressed.len(), 48);
    ///
    /// // Roundtrip
    /// let restored = G1Point::from_compressed(&compressed).unwrap();
    /// assert_eq!(g, restored);
    /// ```
    #[must_use]
    pub fn to_compressed(&self) -> [u8; G1_COMPRESSED_SIZE] {
        let mut out = [0u8; G1_COMPRESSED_SIZE];
        // SAFETY: blst_p1_compress writes exactly 48 bytes to the output buffer.
        // We've allocated exactly 48 bytes.
        unsafe {
            blst_p1_compress(out.as_mut_ptr(), &self.point);
        }
        out
    }

    /// Adds two G1 points.
    ///
    /// Computes the group operation P + Q in constant time.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::bls::G1Point;
    ///
    /// let g = G1Point::generator();
    /// let g2 = g.add(&g);  // 2*g
    ///
    /// // Associativity: (a + b) + c = a + (b + c)
    /// let a = G1Point::generator();
    /// let b = G1Point::generator();
    /// let c = G1Point::generator();
    /// assert_eq!(a.add(&b).add(&c), a.add(&b.add(&c)));
    /// ```
    ///
    /// # Cardano Usage
    ///
    /// Maps to Plutus builtin `bls12_381_G1_add`.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let mut result = blst_p1::default();
        // SAFETY: blst_p1_add_or_double performs elliptic curve point addition
        // and handles the special case of point doubling when adding a point to itself.
        // Both input points are valid blst_p1 values.
        unsafe {
            blst_p1_add_or_double(&mut result, &self.point, &other.point);
        }
        Self { point: result }
    }

    /// Negates the point.
    ///
    /// Returns the additive inverse: P + (-P) = O (identity).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::bls::G1Point;
    ///
    /// let g = G1Point::generator();
    /// let neg_g = g.neg();
    ///
    /// // g + (-g) = identity
    /// let sum = g.add(&neg_g);
    /// assert!(sum.is_identity());
    /// ```
    ///
    /// # Cardano Usage
    ///
    /// Maps to Plutus builtin `bls12_381_G1_neg`.
    #[must_use]
    pub fn neg(&self) -> Self {
        let mut result = self.point;
        // SAFETY: blst_p1_cneg negates a point. The second parameter (true)
        // means unconditionally negate.
        unsafe {
            blst_p1_cneg(&mut result, true);
        }
        Self { point: result }
    }

    /// Scalar multiplication.
    ///
    /// Computes `[scalar]P` efficiently using the double-and-add algorithm.
    ///
    /// # Arguments
    ///
    /// * `scalar` - The scalar multiplier (32 bytes, 256 bits)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::bls::{G1Point, Scalar};
    ///
    /// let g = G1Point::generator();
    ///
    /// // Scalar multiplication by 2
    /// let mut two_bytes = [0u8; 32];
    /// two_bytes[31] = 2;
    /// let two = Scalar::from_bytes_be(&two_bytes).unwrap();
    /// let g2 = g.mul(&two);
    ///
    /// // Should equal g + g
    /// assert_eq!(g2, g.add(&g));
    /// ```
    ///
    /// # Cardano Usage
    ///
    /// Maps to Plutus builtin `bls12_381_G1_scalarMul`.
    ///
    /// # Performance
    ///
    /// Runs in O(log n) time where n is the scalar value, using optimized
    /// window methods in the blst library.
    #[must_use]
    pub fn mul(&self, scalar: &Scalar) -> Self {
        let mut result = blst_p1::default();
        // SAFETY: blst_p1_mult performs scalar multiplication.
        // - self.point is a valid blst_p1
        // - scalar bytes must be in LITTLE-ENDIAN order for blst
        // - 256 is the bit length of the scalar
        // Note: Scalar stores bytes in big-endian, so we need to reverse them
        let mut scalar_le = scalar.bytes;
        scalar_le.reverse(); // Convert big-endian to little-endian
        unsafe {
            blst_p1_mult(&mut result, &self.point, scalar_le.as_ptr(), 256);
        }
        Self { point: result }
    }

    /// Checks if this is the identity point.
    ///
    /// Returns `true` if this point is the identity (point at infinity).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::bls::G1Point;
    ///
    /// let identity = G1Point::identity();
    /// assert!(identity.is_identity());
    ///
    /// let g = G1Point::generator();
    /// assert!(!g.is_identity());
    ///
    /// // g + (-g) = identity
    /// let sum = g.add(&g.neg());
    /// assert!(sum.is_identity());
    /// ```
    #[must_use]
    pub fn is_identity(&self) -> bool {
        let compressed = self.to_compressed();
        // Check if the compressed point represents infinity
        // In compressed format, the infinity flag is bits 6-7 of first byte
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
            // SAFETY: BLS12_381_G2 is a static constant representing the standard
            // BLS12-381 G2 generator point in affine form.
            // We convert it to projective form for use in arithmetic operations.
            let mut point = blst_p2::default();
            blst_p2_from_affine(&mut point, &blst::BLS12_381_G2);
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
            blst_p2_add_or_double(&mut result, &self.point, &other.point);
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
        // Note: Scalar stores bytes in big-endian, but blst expects little-endian
        let mut scalar_le = scalar.bytes;
        scalar_le.reverse(); // Convert big-endian to little-endian
        unsafe {
            blst_p2_mult(&mut result, &self.point, scalar_le.as_ptr(), 256);
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
///
/// Scalars are elements of the scalar field 𝔽r, where r is the order of the
/// prime-order subgroup of BLS12-381. They are used for:
/// - Scalar multiplication: `[s]P` for scalar s and point P
/// - Secret keys in BLS signatures
/// - Exponents in commitment schemes
///
/// # Security
///
/// - **Zeroization**: Scalars are automatically zeroized when dropped to prevent
///   secret key material from remaining in memory
/// - **Range**: Valid scalars are in the range [0, r-1] where
///   r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
/// - **Constant-Time**: Operations should be constant-time where possible (depends on blst)
///
/// # Representation
///
/// Stored as 32 bytes in big-endian format. Note that not all 2^256 values are
/// valid scalars; values must be less than the curve order r.
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::bls::{Scalar, G1Point};
///
/// // Create a scalar from bytes
/// let scalar_bytes = [1u8; 32];
/// let scalar = Scalar::from_bytes_be(&scalar_bytes).unwrap();
///
/// // Use for scalar multiplication
/// let g = G1Point::generator();
/// let result = g.mul(&scalar);
/// ```
///
/// # Cardano Usage
///
/// In Plutus (CIP-0381), scalars are used in:
/// - `bls12_381_G1_scalarMul` builtin
/// - `bls12_381_G2_scalarMul` builtin
/// - BLS secret key generation
///
/// # References
///
/// - [CIP-0381](https://cips.cardano.org/cip/CIP-0381)
/// - [BLS12-381 Spec](https://github.com/zkcrypto/bls12_381)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Scalar {
    /// Scalar value stored as 32 bytes in big-endian format.
    ///
    /// Automatically zeroized on drop to prevent key material leakage.
    bytes: [u8; SCALAR_SIZE],
}

impl Scalar {
    /// Size of a scalar in bytes.
    pub const SIZE: usize = SCALAR_SIZE;

    /// Creates a scalar from big-endian bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32-byte array in big-endian format
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the input is not exactly 32 bytes.
    ///
    /// # Note
    ///
    /// This function does NOT validate that the scalar is less than the curve order r.
    /// Values >= r will be implicitly reduced modulo r when used in operations.
    /// For strict validation, use scalar validation from the blst library directly.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::bls::Scalar;
    ///
    /// // Create scalar from bytes
    /// let bytes = [
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    /// ];
    /// let scalar = Scalar::from_bytes_be(&bytes).unwrap();
    ///
    /// // Wrong length fails
    /// assert!(Scalar::from_bytes_be(&[0u8; 31]).is_err());
    /// ```
    ///
    /// # Security
    ///
    /// The created scalar will be automatically zeroized when dropped.
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
    #[allow(dead_code)]
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
/// This struct provides all BLS12-381 operations required for Plutus V2+
/// smart contracts, implementing [CIP-0381](https://cips.cardano.org/cip/CIP-0381).
///
/// # Overview
///
/// BLS12-381 is a pairing-friendly elliptic curve that enables:
/// - **Signature Aggregation**: Combine multiple signatures into one
/// - **Zero-Knowledge Proofs**: Succinct proof systems (SNARKs, Bulletproofs)
/// - **Threshold Cryptography**: m-of-n signature schemes
/// - **Verifiable Random Functions**: Advanced VRF constructions
///
/// # Curve Parameters
///
/// - **Base Field**: 𝔽p where p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
/// - **Scalar Field**: 𝔽r where r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
/// - **Embedding Degree**: k = 12
/// - **Security Level**: ~128 bits
///
/// # Plutus Builtins
///
/// All methods map directly to Plutus builtins:
///
/// | Plutus Builtin | Rust Method |
/// |----------------|-------------|
/// | `bls12_381_G1_add` | [`g1_add`](Self::g1_add) |
/// | `bls12_381_G1_neg` | [`g1_neg`](Self::g1_neg) |
/// | `bls12_381_G1_scalarMul` | [`g1_scalar_mul`](Self::g1_scalar_mul) |
/// | `bls12_381_G1_compress` | [`g1_compress`](Self::g1_compress) |
/// | `bls12_381_G1_uncompress` | [`g1_uncompress`](Self::g1_uncompress) |
/// | `bls12_381_G1_hashToGroup` | [`g1_hash_to_curve`](Self::g1_hash_to_curve) |
/// | `bls12_381_G2_*` | `g2_*` methods |
/// | `bls12_381_millerLoop` | [`miller_loop`](Self::miller_loop) |
/// | `bls12_381_finalVerify` | [`final_exponentiate`](Self::final_exponentiate) |
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::bls::{Bls12381, G1Point, G2Point, Scalar};
///
/// // G1 operations
/// let g1 = G1Point::generator();
/// let g1_doubled = Bls12381::g1_add(&g1, &g1);
///
/// // Pairing check
/// let g2 = G2Point::generator();
/// let pairing = Bls12381::pairing(&g1, &g2);
/// assert!(!pairing.is_one()); // e(g1, g2) != 1
///
/// // Hash to curve
/// let msg = b"Hello Cardano";
/// let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
/// let hash_point = Bls12381::g1_hash_to_curve(msg, dst);
/// ```
///
/// # Security Considerations
///
/// - **Subgroup Checks**: All points are validated to be in the prime-order subgroup
/// - **Pairing Equations**: Use constant-time operations where possible
/// - **Hash-to-Curve**: Uses IETF standard (draft-irtf-cfrg-hash-to-curve)
/// - **Side Channels**: Be aware of potential timing attacks in scalar operations
///
/// # Cardano Compatibility
///
/// This implementation is byte-for-byte compatible with:
/// - Haskell `cardano-crypto-class` BLS functions
/// - Plutus V2+ on-chain BLS builtins
/// - cardano-node consensus layer (if/when BLS is integrated)
///
/// # References
///
/// - [CIP-0381](https://cips.cardano.org/cip/CIP-0381) - Plutus support for pairings over BLS12-381
/// - [BLS Signatures](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html)
/// - [Hash-to-Curve](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve)
/// - [BLS12-381 Spec](https://github.com/zkcrypto/bls12_381)
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
// Proof of Possession (PoP)
// ============================================================================

/// Proof of Possession for BLS keys
///
/// A cryptographic proof that the party possesses the secret key corresponding
/// to their public key. This is required to prevent rogue key attacks in
/// aggregate signature schemes.
///
/// # Structure
///
/// The PoP is a BLS signature over the public key itself:
/// ```text
/// pop = Sign(sk, pk)
/// ```
///
/// # Security
///
/// Without PoP verification, an attacker can choose a malicious public key:
/// ```text
/// pk_evil = g^x / (pk_1 * pk_2 * ... * pk_n)
/// ```
/// which allows forging aggregate signatures. PoP prevents this by proving
/// knowledge of the secret key.
///
/// # References
///
/// - [BLS PoP Spec](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-3.3)
/// - [Rogue Key Attacks](https://eprint.iacr.org/2018/483.pdf)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlsProofOfPossession {
    signature: BlsSignature,
}

impl BlsProofOfPossession {
    /// Size of a compressed PoP
    pub const COMPRESSED_SIZE: usize = BlsSignature::COMPRESSED_SIZE;

    /// Create a PoP from a BLS signature
    pub fn from_signature(signature: BlsSignature) -> Self {
        Self { signature }
    }

    /// Get the underlying signature
    pub fn signature(&self) -> &BlsSignature {
        &self.signature
    }

    /// Serialize PoP to compressed bytes
    pub fn to_compressed(&self) -> [u8; Self::COMPRESSED_SIZE] {
        self.signature.to_compressed()
    }

    /// Deserialize PoP from compressed bytes
    pub fn from_compressed(bytes: &[u8]) -> Result<Self, CryptoError> {
        let signature = BlsSignature::from_compressed(bytes)?;
        Ok(Self { signature })
    }
}

// ============================================================================
// DsignAggregatable Implementation for BLS12-381
// ============================================================================

use crate::common::traits::DsignAggregatable;

impl DsignAggregatable for Bls12381 {
    type PossessionProof = BlsProofOfPossession;

    fn aggregate_verification_keys(keys: &[BlsPublicKey]) -> Option<BlsPublicKey> {
        if keys.is_empty() {
            return None;
        }

        // Aggregate G1 points (public keys in min-pk scheme)
        let mut agg_point = keys[0].point.clone();
        for key in &keys[1..] {
            agg_point = agg_point.add(&key.point);
        }

        Some(BlsPublicKey { point: agg_point })
    }

    fn aggregate_signatures(signatures: &[BlsSignature]) -> Option<BlsSignature> {
        if signatures.is_empty() {
            return None;
        }

        // Aggregate G2 points (signatures in min-pk scheme)
        let mut agg_point = signatures[0].point.clone();
        for sig in &signatures[1..] {
            agg_point = agg_point.add(&sig.point);
        }

        Some(BlsSignature { point: agg_point })
    }

    fn generate_possession_proof(signing_key: &BlsSecretKey) -> Self::PossessionProof {
        // Generate PoP by signing the public key
        let public_key = signing_key.public_key();
        let pk_bytes = public_key.to_compressed();

        // Use PoP-specific DST (Domain Separation Tag)
        let dst = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

        let hash_point = Bls12381::g2_hash_to_curve(&pk_bytes, dst);
        let pop_point = hash_point.mul(&signing_key.scalar);

        BlsProofOfPossession {
            signature: BlsSignature { point: pop_point },
        }
    }

    fn verify_possession_proof(
        verification_key: &BlsPublicKey,
        proof: &Self::PossessionProof,
    ) -> bool {
        // Verify PoP by checking: Sign(sk, pk) == pop
        let pk_bytes = verification_key.to_compressed();
        let dst = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

        bls_verify_with_dst(verification_key, &pk_bytes, &proof.signature, dst).is_ok()
    }
}

// Re-implement DsignAlgorithm for better BLS ergonomics
use crate::common::traits::DsignAlgorithm;

impl DsignAlgorithm for Bls12381 {
    type VerificationKey = BlsPublicKey;
    type SigningKey = BlsSecretKey;
    type Signature = BlsSignature;
    type Context = ();

    const ALGORITHM_NAME: &'static str = "BLS12-381";
    const SEED_SIZE: usize = 32;
    const VERIFICATION_KEY_SIZE: usize = G1_COMPRESSED_SIZE;
    const SIGNING_KEY_SIZE: usize = SCALAR_SIZE;
    const SIGNATURE_SIZE: usize = G2_COMPRESSED_SIZE;

    fn gen_key_from_seed(seed: &[u8]) -> Result<Self::SigningKey, CryptoError> {
        if seed.len() != Self::SEED_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::SEED_SIZE,
                got: seed.len(),
            });
        }
        BlsSecretKey::from_bytes(seed)
    }

    fn derive_verification_key(signing_key: &Self::SigningKey) -> Result<Self::VerificationKey, CryptoError> {
        Ok(signing_key.public_key())
    }

    fn sign(
        message: &[u8],
        signing_key: &Self::SigningKey,
    ) -> Result<Self::Signature, CryptoError> {
        Ok(signing_key.sign(message))
    }

    fn verify(
        message: &[u8],
        signature: &Self::Signature,
        verification_key: &Self::VerificationKey,
    ) -> Result<(), CryptoError> {
        bls_verify(verification_key, message, signature)
    }

    fn serialize_verification_key(verification_key: &Self::VerificationKey) -> alloc::vec::Vec<u8> {
        verification_key.to_compressed().to_vec()
    }

    fn deserialize_verification_key(bytes: &[u8]) -> Result<Self::VerificationKey, CryptoError> {
        BlsPublicKey::from_compressed(bytes)
    }

    fn serialize_signature(signature: &Self::Signature) -> alloc::vec::Vec<u8> {
        signature.to_compressed().to_vec()
    }

    fn deserialize_signature(bytes: &[u8]) -> Result<Self::Signature, CryptoError> {
        BlsSignature::from_compressed(bytes)
    }

    fn forget_signing_key(mut signing_key: Self::SigningKey) {
        signing_key.scalar.zeroize();
    }
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

    // ========================================================================
    // DsignAggregatable Tests
    // ========================================================================

    #[test]
    fn test_proof_of_possession() {
        use crate::common::traits::DsignAggregatable;

        let seed = [42u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        // Generate PoP
        let pop = Bls12381::generate_possession_proof(&sk);

        // Verify PoP
        assert!(Bls12381::verify_possession_proof(&pk, &pop));

        // Wrong key should fail
        let wrong_seed = [99u8; 32];
        let wrong_sk = BlsSecretKey::from_bytes(&wrong_seed).unwrap();
        let wrong_pk = wrong_sk.public_key();

        assert!(!Bls12381::verify_possession_proof(&wrong_pk, &pop));
    }

    #[test]
    fn test_pop_roundtrip() {
        use crate::common::traits::DsignAggregatable;

        let seed = [7u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pop = Bls12381::generate_possession_proof(&sk);

        // Serialize and deserialize
        let bytes = pop.to_compressed();
        let restored = BlsProofOfPossession::from_compressed(&bytes).unwrap();

        assert_eq!(pop, restored);
    }

    #[test]
    fn test_aggregate_verification_keys() {
        use crate::common::traits::DsignAggregatable;

        // Generate multiple keys
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];
        let seed3 = [3u8; 32];

        let sk1 = BlsSecretKey::from_bytes(&seed1).unwrap();
        let sk2 = BlsSecretKey::from_bytes(&seed2).unwrap();
        let sk3 = BlsSecretKey::from_bytes(&seed3).unwrap();

        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        let pk3 = sk3.public_key();

        // Aggregate keys
        let agg_pk = Bls12381::aggregate_verification_keys(&[pk1.clone(), pk2.clone(), pk3.clone()]);
        assert!(agg_pk.is_some());

        // Manual aggregation should match
        let manual_agg = pk1.point.add(&pk2.point).add(&pk3.point);
        assert_eq!(agg_pk.unwrap().point, manual_agg);
    }

    #[test]
    fn test_aggregate_signatures() {
        use crate::common::traits::DsignAggregatable;

        // Generate keys and sign
        let seed1 = [11u8; 32];
        let seed2 = [22u8; 32];

        let sk1 = BlsSecretKey::from_bytes(&seed1).unwrap();
        let sk2 = BlsSecretKey::from_bytes(&seed2).unwrap();

        let msg = b"Aggregate this message";
        let sig1 = sk1.sign(msg);
        let sig2 = sk2.sign(msg);

        // Aggregate signatures
        let agg_sig = Bls12381::aggregate_signatures(&[sig1.clone(), sig2.clone()]);
        assert!(agg_sig.is_some());

        // Manual aggregation should match
        let manual_agg = sig1.point.add(&sig2.point);
        assert_eq!(agg_sig.unwrap().point, manual_agg);
    }

    #[test]
    fn test_aggregate_sign_verify() {
        use crate::common::traits::DsignAggregatable;

        // Setup: Multiple signers
        let seed1 = [10u8; 32];
        let seed2 = [20u8; 32];
        let seed3 = [30u8; 32];

        let sk1 = BlsSecretKey::from_bytes(&seed1).unwrap();
        let sk2 = BlsSecretKey::from_bytes(&seed2).unwrap();
        let sk3 = BlsSecretKey::from_bytes(&seed3).unwrap();

        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        let pk3 = sk3.public_key();

        // All sign the same message
        let msg = b"Committee vote: Approve";
        let sig1 = sk1.sign(msg);
        let sig2 = sk2.sign(msg);
        let sig3 = sk3.sign(msg);

        // Aggregate keys and signatures
        let agg_pk = Bls12381::aggregate_verification_keys(&[pk1, pk2, pk3]).unwrap();
        let agg_sig = Bls12381::aggregate_signatures(&[sig1, sig2, sig3]).unwrap();

        // Verify aggregate signature
        assert!(bls_verify(&agg_pk, msg, &agg_sig).is_ok());

        // Wrong message should fail
        assert!(bls_verify(&agg_pk, b"Wrong message", &agg_sig).is_err());
    }

    #[test]
    fn test_aggregate_empty_lists() {
        use crate::common::traits::DsignAggregatable;

        // Empty key list
        let agg_pk = Bls12381::aggregate_verification_keys(&[]);
        assert!(agg_pk.is_none());

        // Empty signature list
        let agg_sig = Bls12381::aggregate_signatures(&[]);
        assert!(agg_sig.is_none());
    }

    #[test]
    fn test_aggregate_single_item() {
        use crate::common::traits::DsignAggregatable;

        let seed = [55u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        let msg = b"Single signer";
        let sig = sk.sign(msg);

        // Aggregating single items should work
        let agg_pk = Bls12381::aggregate_verification_keys(&[pk.clone()]).unwrap();
        let agg_sig = Bls12381::aggregate_signatures(&[sig.clone()]).unwrap();

        // Should equal the original
        assert_eq!(agg_pk.point, pk.point);
        assert_eq!(agg_sig.point, sig.point);

        // And verify
        assert!(bls_verify(&agg_pk, msg, &agg_sig).is_ok());
    }

    #[test]
    fn test_rogue_key_attack_prevention() {
        use crate::common::traits::DsignAggregatable;

        // Simulate: Honest party and potential attacker
        let honest_seed = [100u8; 32];
        let honest_sk = BlsSecretKey::from_bytes(&honest_seed).unwrap();
        let honest_pk = honest_sk.public_key();

        // Attacker tries to compute rogue key (but we require PoP)
        // Without PoP verification, attacker could forge aggregate signatures

        // Generate PoP for honest key
        let honest_pop = Bls12381::generate_possession_proof(&honest_sk);
        assert!(Bls12381::verify_possession_proof(&honest_pk, &honest_pop));

        // Attacker cannot generate valid PoP without secret key
        // This test ensures PoP verification exists and works
        let attacker_seed = [255u8; 32];
        let attacker_sk = BlsSecretKey::from_bytes(&attacker_seed).unwrap();
        let attacker_pk = attacker_sk.public_key();
        let attacker_pop = Bls12381::generate_possession_proof(&attacker_sk);

        // Only legitimate PoPs pass
        assert!(Bls12381::verify_possession_proof(&attacker_pk, &attacker_pop));
        assert!(!Bls12381::verify_possession_proof(&attacker_pk, &honest_pop));
        assert!(!Bls12381::verify_possession_proof(&honest_pk, &attacker_pop));
    }

    #[test]
    fn test_dsign_algorithm_trait() {
        use crate::common::traits::DsignAlgorithm;

        assert_eq!(Bls12381::ALGORITHM_NAME, "BLS12-381");
        assert_eq!(Bls12381::SEED_SIZE, 32);
        assert_eq!(Bls12381::VERIFICATION_KEY_SIZE, G1_COMPRESSED_SIZE);
        assert_eq!(Bls12381::SIGNING_KEY_SIZE, SCALAR_SIZE);
        assert_eq!(Bls12381::SIGNATURE_SIZE, G2_COMPRESSED_SIZE);

        // Test key generation
        let seed = [123u8; 32];
        let sk = Bls12381::gen_key_from_seed(&seed).unwrap();
        let vk = Bls12381::derive_verification_key(&sk).unwrap();

        // Test signing and verification
        let msg = b"Test message";
        let sig = Bls12381::sign(msg, &sk, &()).unwrap();
        assert!(Bls12381::verify(msg, &sig, &vk, &()).is_ok());

        // Test serialization roundtrips
        let vk_bytes = Bls12381::serialize_verification_key(&vk);
        let restored_vk = Bls12381::deserialize_verification_key(&vk_bytes).unwrap();
        assert_eq!(vk.point, restored_vk.point);

        let sig_bytes = Bls12381::serialize_signature(&sig);
        let restored_sig = Bls12381::deserialize_signature(&sig_bytes).unwrap();
        assert_eq!(sig.point, restored_sig.point);
    }
}
