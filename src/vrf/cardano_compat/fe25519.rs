//! Field element arithmetic for Curve25519
//!
//! This module implements field arithmetic for the prime field GF(2^255 - 19)
//! using the fiat-crypto verified implementations for the core operations.
//!
//! The implementation matches libsodium's fe25519 operations used in Cardano's
//! Elligator2 implementation.

use fiat_crypto::curve25519_64::{
    fiat_25519_add, fiat_25519_carry, fiat_25519_carry_mul, fiat_25519_carry_square,
    fiat_25519_from_bytes, fiat_25519_loose_field_element, fiat_25519_opp, fiat_25519_sub,
    fiat_25519_tight_field_element, fiat_25519_to_bytes,
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A field element in GF(2^255 - 19)
#[derive(Clone, Copy)]
pub struct Fe25519(fiat_25519_tight_field_element);

impl core::fmt::Debug for Fe25519 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Fe25519({:?})", self.to_bytes())
    }
}

impl Default for Fe25519 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ConstantTimeEq for Fe25519 {
    fn ct_eq(&self, other: &Self) -> Choice {
        let a = self.to_bytes();
        let b = other.to_bytes();
        a.ct_eq(&b)
    }
}

impl ConditionallySelectable for Fe25519 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut result = fiat_25519_tight_field_element([0u64; 5]);
        for i in 0..5 {
            result.0[i] = u64::conditional_select(&a.0.0[i], &b.0.0[i], choice);
        }
        Fe25519(result)
    }
}

impl Fe25519 {
    /// Zero
    pub const ZERO: Fe25519 = Fe25519(fiat_25519_tight_field_element([0, 0, 0, 0, 0]));

    /// One
    pub const ONE: Fe25519 = Fe25519(fiat_25519_tight_field_element([1, 0, 0, 0, 0]));

    /// curve25519_A = 486662 (Montgomery curve parameter)
    pub const CURVE25519_A: Fe25519 = Fe25519(fiat_25519_tight_field_element([486662, 0, 0, 0, 0]));

    /// sqrt(-A-2) = sqrt(-486664) for Montgomery to Edwards conversion
    /// From libsodium: { 1693982333959686, 608509411481997, 2235573344831311, 947681270984193, 266558006233600 }
    pub const SQRT_AM2: Fe25519 = Fe25519(fiat_25519_tight_field_element([
        1693982333959686,
        608509411481997,
        2235573344831311,
        947681270984193,
        266558006233600,
    ]));

    /// sqrt(-1) for use in square root computation
    /// From libsodium: { 1718705420411056, 234908883556509, 2233514472574048, 2117202627021982, 765476049583133 }
    pub const SQRT_M1: Fe25519 = Fe25519(fiat_25519_tight_field_element([
        1718705420411056,
        234908883556509,
        2233514472574048,
        2117202627021982,
        765476049583133,
    ]));

    /// Create from bytes (little-endian)
    #[inline]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut result = fiat_25519_tight_field_element([0u64; 5]);
        fiat_25519_from_bytes(&mut result, bytes);
        Fe25519(result)
    }

    /// Reduce a 64-byte little-endian integer modulo p = 2^255 - 19
    ///
    /// This matches libsodium's `fe25519_reduce64` used in `ge25519_from_hash`.
    /// The 512-bit input is split into two 256-bit halves and reduced using
    /// the identity 2^256 ≡ 38 (mod p):
    ///
    ///   result = lo + hi × 38 (mod p)
    ///
    /// where lo = bytes\[0..32\] and hi = bytes\[32..64\] as little-endian integers.
    #[inline]
    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
        let mut lo = [0u8; 32];
        lo.copy_from_slice(&bytes[0..32]);
        let mut hi = [0u8; 32];
        hi.copy_from_slice(&bytes[32..64]);

        let fe_lo = Self::from_bytes(&lo);
        let fe_hi = Self::from_bytes(&hi);
        let fe_38 = Self(fiat_25519_tight_field_element([38, 0, 0, 0, 0]));

        fe_lo.add(&fe_hi.mul(&fe_38))
    }

    /// Convert to bytes (little-endian)
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut result = [0u8; 32];
        fiat_25519_to_bytes(&mut result, &self.0);
        result
    }

    /// Check if zero
    #[inline]
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Check if "negative" (odd when reduced)
    /// This matches libsodium's fe25519_isnegative
    pub fn is_negative(&self) -> Choice {
        let bytes = self.to_bytes();
        Choice::from(bytes[0] & 1)
    }

    /// Addition
    #[inline]
    pub fn add(&self, other: &Self) -> Self {
        let mut loose = fiat_25519_loose_field_element([0u64; 5]);
        fiat_25519_add(&mut loose, &self.0, &other.0);
        let mut result = fiat_25519_tight_field_element([0u64; 5]);
        fiat_25519_carry(&mut result, &loose);
        Fe25519(result)
    }

    /// Subtraction
    #[inline]
    pub fn sub(&self, other: &Self) -> Self {
        let mut loose = fiat_25519_loose_field_element([0u64; 5]);
        fiat_25519_sub(&mut loose, &self.0, &other.0);
        let mut result = fiat_25519_tight_field_element([0u64; 5]);
        fiat_25519_carry(&mut result, &loose);
        Fe25519(result)
    }

    /// Negation
    #[inline]
    pub fn neg(&self) -> Self {
        let mut loose = fiat_25519_loose_field_element([0u64; 5]);
        fiat_25519_opp(&mut loose, &self.0);
        let mut result = fiat_25519_tight_field_element([0u64; 5]);
        fiat_25519_carry(&mut result, &loose);
        Fe25519(result)
    }

    /// Convert tight to loose for operations
    #[inline]
    fn as_loose(&self) -> fiat_25519_loose_field_element {
        fiat_25519_loose_field_element(self.0.0)
    }

    /// Multiplication
    #[inline]
    pub fn mul(&self, other: &Self) -> Self {
        let mut result = fiat_25519_tight_field_element([0u64; 5]);
        fiat_25519_carry_mul(&mut result, &self.as_loose(), &other.as_loose());
        Fe25519(result)
    }

    /// Square
    #[inline]
    pub fn square(&self) -> Self {
        let mut result = fiat_25519_tight_field_element([0u64; 5]);
        fiat_25519_carry_square(&mut result, &self.as_loose());
        Fe25519(result)
    }

    /// Square and double (2 * x^2)
    /// Used in Elligator2: rr2 = 2*r^2
    #[inline]
    pub fn sq2(&self) -> Self {
        self.square().add(&self.square())
    }

    /// Compute x^n using square-and-multiply
    fn pow_internal(&self, mut n: [u64; 4]) -> Self {
        let mut result = Self::ONE;
        let mut base = *self;

        // Process all 256 bits
        for _ in 0..256 {
            if n[0] & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.square();

            // Shift right by 1 across all limbs
            n[0] = (n[0] >> 1) | (n[1] << 63);
            n[1] = (n[1] >> 1) | (n[2] << 63);
            n[2] = (n[2] >> 1) | (n[3] << 63);
            n[3] >>= 1;
        }

        result
    }

    /// Inversion: compute x^(p-2) where p = 2^255 - 19
    /// p - 2 = 2^255 - 21 = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
    pub fn invert(&self) -> Self {
        // p - 2 as little-endian u64 array
        let exp: [u64; 4] = [
            0xffffffffffffffeb,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x7fffffffffffffff,
        ];
        self.pow_internal(exp)
    }

    /// Check if x is a quadratic residue (square)
    /// Returns true if x^((p-1)/2) == 1
    pub fn is_square(&self) -> Choice {
        // (p-1)/2 = (2^255 - 20) / 2 = 2^254 - 10
        let exp: [u64; 4] = [
            0xfffffffffffffff6,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x3fffffffffffffff,
        ];
        let result = self.pow_internal(exp);
        // Result is 1 if square, p-1 if not
        result.ct_eq(&Self::ONE)
    }

    /// Check if NOT a square (for Elligator2)
    pub fn is_not_square(&self) -> Choice {
        !self.is_square()
    }

    /// Square root using Tonelli-Shanks
    /// For p ≡ 5 (mod 8), we have a simpler formula
    /// Returns (sqrt exists, sqrt value)
    pub fn sqrt(&self) -> (Choice, Self) {
        // For p = 2^255 - 19, p ≡ 5 (mod 8)
        // sqrt(a) = a^((p+3)/8) if a^((p-1)/4) = 1
        // sqrt(a) = sqrt(-1) * a^((p+3)/8) if a^((p-1)/4) = -1

        // (p+3)/8 = (2^255 - 16) / 8 = 2^252 - 2
        let exp: [u64; 4] = [
            0xfffffffffffffffe,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x0fffffffffffffff,
        ];

        let beta = self.pow_internal(exp); // a^((p+3)/8)
        let beta_sq = beta.square();

        // Check if beta^2 = a
        let is_correct = beta_sq.ct_eq(self);

        // Check if beta^2 = -a (need to multiply by sqrt(-1))
        let neg_self = self.neg();
        let needs_sqrt_m1 = beta_sq.ct_eq(&neg_self);

        // If beta^2 = -a, multiply beta by sqrt(-1)
        let sqrt_m1_beta = beta.mul(&Self::SQRT_M1);
        let result = Self::conditional_select(&beta, &sqrt_m1_beta, needs_sqrt_m1);

        let exists = is_correct | needs_sqrt_m1;

        (exists, result)
    }

    /// Conditional move: if choice is set, replace self with other
    pub fn cmov(&mut self, other: &Self, choice: Choice) {
        *self = Self::conditional_select(self, other, choice);
    }

    /// Conditional negate: if choice is set, negate self
    pub fn conditional_negate(&mut self, choice: Choice) {
        let negated = self.neg();
        self.cmov(&negated, choice);
    }

    /// Absolute value: return the non-negative representative
    /// In ed25519 field, an element is "negative" if its lowest bit is 1
    /// This returns the negated value if negative, otherwise unchanged
    pub fn abs(&self) -> Self {
        let negated = self.neg();
        Self::conditional_select(self, &negated, self.is_negative())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_one() {
        let zero = Fe25519::ZERO;
        let one = Fe25519::ONE;

        assert!(bool::from(zero.is_zero()));
        assert!(!bool::from(one.is_zero()));

        let zero_bytes = zero.to_bytes();
        let one_bytes = one.to_bytes();

        assert_eq!(zero_bytes, [0u8; 32]);
        assert_eq!(one_bytes[0], 1);
        for byte in &one_bytes[1..32] {
            assert_eq!(*byte, 0);
        }
    }

    #[test]
    fn test_add_sub() {
        let a = Fe25519::from_bytes(&[42u8; 32]);
        let b = Fe25519::from_bytes(&[17u8; 32]);

        let c = a.add(&b);
        let d = c.sub(&b);

        assert!(bool::from(d.ct_eq(&a)));
    }

    #[test]
    fn test_mul() {
        let two = Fe25519::ONE.add(&Fe25519::ONE);
        let four = two.mul(&two);
        let also_four = two.add(&two);

        assert!(bool::from(four.ct_eq(&also_four)));
    }

    #[test]
    fn test_square() {
        let three = Fe25519::ONE.add(&Fe25519::ONE).add(&Fe25519::ONE);
        let nine_mul = three.mul(&three);
        let nine_sq = three.square();

        assert!(bool::from(nine_mul.ct_eq(&nine_sq)));
    }

    #[test]
    fn test_invert() {
        let a = Fe25519::from_bytes(&[42u8; 32]);
        let a_inv = a.invert();
        let product = a.mul(&a_inv);

        assert!(bool::from(product.ct_eq(&Fe25519::ONE)));
    }

    #[test]
    fn test_sqrt() {
        // Test sqrt(4) = 2 or -2
        let four = Fe25519::ONE
            .add(&Fe25519::ONE)
            .add(&Fe25519::ONE)
            .add(&Fe25519::ONE);
        let (exists, sqrt_four) = four.sqrt();

        assert!(bool::from(exists));
        let should_be_four = sqrt_four.square();
        assert!(bool::from(should_be_four.ct_eq(&four)));
    }

    #[test]
    fn test_is_negative() {
        // 1 is odd, so "negative"
        assert!(bool::from(Fe25519::ONE.is_negative()));

        // 2 is even, so not "negative"
        let two = Fe25519::ONE.add(&Fe25519::ONE);
        assert!(!bool::from(two.is_negative()));
    }

    #[test]
    fn test_curve25519_a() {
        let a = Fe25519::CURVE25519_A;
        let a_bytes = a.to_bytes();

        // 486662 = 0x76D06 in little-endian
        assert_eq!(a_bytes[0], 0x06);
        assert_eq!(a_bytes[1], 0x6D);
        assert_eq!(a_bytes[2], 0x07);
        for byte in &a_bytes[3..32] {
            assert_eq!(*byte, 0);
        }
    }
}
