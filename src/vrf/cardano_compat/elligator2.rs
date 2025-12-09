//! Elligator2 mapping from field elements to Edwards curve points
//!
//! This module implements the Elligator2 algorithm as specified in
//! IETF VRF draft-03 section 5.4.1.2.
//!
//! # Algorithm (IETF VRF Elligator2)
//!
//! 1. Clear the high bit of the input (0x7f mask on byte\[31\])
//! 2. Interpret as field element r
//! 3. Compute Elligator2 to get Montgomery point (x, y)
//! 4. Convert Montgomery to Edwards (X_ed, Y_ed)
//! 5. Clear cofactor (multiply by 8)
//! 6. Serialize (encoding the sign of X_ed in the high bit of the Y coordinate)
//!
//! Note: Unlike libsodium's `ge25519_from_uniform` which extracts and uses
//! a sign bit for its own purposes, the IETF VRF spec does NOT use
//! sign correction. The high bit is simply cleared before interpretation.
//!
//! # References
//!
//! - IETF VRF draft-irtf-cfrg-vrf-03 section 5.4.1.2

use super::fe25519::Fe25519;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use subtle::Choice;

/// Montgomery point (x, y) on Curve25519
struct MontgomeryPointInternal {
    x: Fe25519,
    y: Fe25519,
}

/// Elligator2 mapping from r to Montgomery curve point (x, y)
///
/// This matches libsodium's `ge25519_elligator2` exactly.
///
/// Algorithm:
/// 1. rr2 = 2*r^2 + 1
/// 2. x = -A / rr2
/// 3. gx1 = x^3 + A*x^2 + x
/// 4. if gx1 is not a square:
///    x = -x - A
/// 5. y = sqrt(x^3 + A*x^2 + x)
fn elligator2(r: &Fe25519) -> (MontgomeryPointInternal, Choice) {
    let a = Fe25519::CURVE25519_A;

    // rr2 = 2*r^2
    let mut rr2 = r.sq2();
    // rr2 = 2*r^2 + 1
    rr2 = rr2.add(&Fe25519::ONE);

    // rr2 = 1/(2*r^2 + 1)
    rr2 = rr2.invert();

    // x = A * rr2 = A/(2*r^2 + 1)
    let mut x = a.mul(&rr2);

    // x = -A/(2*r^2 + 1)
    x = x.neg();

    // x2 = x^2
    let x2 = x.square();
    // x3 = x^3
    let x3 = x.mul(&x2);
    // ax2 = A * x^2
    let ax2 = a.mul(&x2);

    // gx1 = x^3 + A*x^2 + x
    let gx1 = x3.add(&x).add(&ax2);

    // Check if gx1 is a quadratic residue
    let notsquare = gx1.is_not_square();

    // If gx1 is not a square: x = -x - A
    let negx = x.neg();
    x.cmov(&negx, notsquare);
    let mut x2_adj = Fe25519::ZERO;
    x2_adj.cmov(&a, notsquare);
    x = x.sub(&x2_adj);

    // Compute y from the curve equation
    // y = sqrt(x^3 + A*x^2 + x)
    let x2_new = x.square();
    let x3_new = x.mul(&x2_new);
    let ax2_new = a.mul(&x2_new);
    let gy = x3_new.add(&x).add(&ax2_new);

    let (sqrt_exists, y) = gy.sqrt();
    debug_assert!(bool::from(sqrt_exists), "sqrt must exist at this point");

    (MontgomeryPointInternal { x, y }, notsquare)
}

/// Convert Montgomery point (x, y) to Edwards point (xed, yed)
///
/// This matches libsodium's `ge25519_mont_to_ed` exactly.
///
/// Formula:
///   xed = sqrt(-A-2) * x / y
///   yed = (x - 1) / (x + 1)
fn mont_to_ed(mont: &MontgomeryPointInternal) -> (Fe25519, Fe25519) {
    let one = Fe25519::ONE;
    let x_plus_one = mont.x.add(&one);
    let x_minus_one = mont.x.sub(&one);

    // Compute 1/((x+1)*y)
    let x_plus_one_y = x_plus_one.mul(&mont.y);
    let x_plus_one_y_inv = x_plus_one_y.invert();

    // Check for zero (degenerate case)
    let is_zero = x_plus_one_y_inv.is_zero();

    // xed = sqrt(-A-2) * x / y
    // = sqrt(-A-2) * x * (x+1) / ((x+1)*y)
    // = sqrt(-A-2) * x / ((x+1)*y) * (x+1)
    let mut xed = mont.x.mul(&Fe25519::SQRT_AM2);
    xed = xed.mul(&x_plus_one_y_inv);
    xed = xed.mul(&x_plus_one);

    // yed = (x-1)/(x+1)
    // = (x-1) * y / ((x+1)*y)
    // = (x-1) * (1/(x+1))
    let one_over_x_plus_one = x_plus_one_y_inv.mul(&mont.y);
    let mut yed = one_over_x_plus_one.mul(&x_minus_one);

    // Handle degenerate case: if (x+1)*y = 0, set yed = 1
    yed.cmov(&one, is_zero);

    (xed, yed)
}

/// Map a 32-byte value to an Edwards curve point using IETF VRF Elligator2
///
/// This implements the Elligator2 mapping as used in IETF VRF draft-03.
///
/// Key detail: The VRF prove/verify code clears the high bit of the input
/// BEFORE calling ge25519_from_uniform, so x_sign is always 0.
/// With x_sign=0, the sign correction logic in ge25519_from_uniform becomes:
/// "If xed is negative, negate it to make it positive"
/// This is equivalent to: fe25519_abs(xed) or always use non-negative xed.
///
/// Algorithm:
/// 1. Clear only the high bit (0x7f mask on byte\[31\])
/// 2. Interpret as field element r
/// 3. Compute Elligator2 to get Montgomery point (x, y)
/// 4. Convert Montgomery to Edwards (xed, yed)
/// 5. Make xed non-negative (since x_sign from input is always 0 after clearing)
/// 6. Clear cofactor (multiply by 8)
/// 7. Serialize
pub fn elligator2_to_edwards(input: &[u8; 32]) -> Option<EdwardsPoint> {
    // Step 1: Clear ONLY the high bit (0x7f mask) per IETF VRF spec
    // Note: In libsodium, VRF code clears this BEFORE calling ge25519_from_uniform,
    // so x_sign extraction in that function always yields 0.
    let mut s = *input;
    s[31] &= 0x7f;

    // Step 2: Convert to field element
    let r_fe = Fe25519::from_bytes(&s);

    // Step 3: Compute Elligator2 to get Montgomery point
    let (mont, _notsquare) = elligator2(&r_fe);

    // Step 4: Convert Montgomery to Edwards
    let (xed, yed) = mont_to_ed(&mont);

    // Step 5: Apply sign correction with x_sign = 0 (always)
    // This is equivalent to: if xed is negative, negate it to make it positive
    // In libsodium: fe25519_cmov(p3.X, negxed, fe25519_isnegative(p3.X) ^ 0)
    // Since x_sign = 0, condition = fe25519_isnegative(p3.X) ^ 0 = fe25519_isnegative(p3.X)
    // So: if xed is negative, use negxed (making it positive)
    let final_xed = xed.abs();

    // Step 6: Convert to curve25519-dalek EdwardsPoint for cofactor clearing
    // The compressed format is y with sign of x in high bit
    let mut point_bytes = yed.to_bytes();
    let xed_sign = bool::from(final_xed.is_negative()) as u8; // Should be 0 after abs()
    point_bytes[31] |= xed_sign << 7;

    let compressed_before_cofactor = CompressedEdwardsY(point_bytes);
    let point_before_cofactor = compressed_before_cofactor.decompress()?;

    // Step 7: Clear cofactor using curve25519-dalek's correct implementation
    let point_cleared = point_before_cofactor.mul_by_cofactor();

    Some(point_cleared)
}

/// Hash to curve using full Elligator2 with cofactor clearing
pub fn hash_to_curve_elligator2(uniform_bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    elligator2_to_edwards(uniform_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elligator2_zero_input() {
        let input = [0u8; 32];
        let result = elligator2_to_edwards(&input);
        assert!(result.is_some(), "Zero input should produce valid point");
    }

    #[test]
    fn test_elligator2_nonzero_input() {
        let mut input = [0u8; 32];
        input[0] = 42;
        let result = elligator2_to_edwards(&input);
        assert!(result.is_some(), "Nonzero input should produce valid point");
    }

    #[test]
    fn test_elligator2_sign_bit_cleared() {
        // For VRF, the sign bit (high bit of byte 31) is always cleared before
        // Elligator2 processing. This means inputs that only differ in the sign
        // bit will produce the same output.
        let mut input1 = [0u8; 32];
        input1[0] = 42;
        input1[31] = 0x00;

        let mut input2 = [0u8; 32];
        input2[0] = 42;
        input2[31] = 0x80; // Only differs in sign bit

        let point1 = elligator2_to_edwards(&input1).unwrap();
        let point2 = elligator2_to_edwards(&input2).unwrap();

        // These should be EQUAL because the sign bit is cleared
        assert_eq!(
            point1.compress().as_bytes(),
            point2.compress().as_bytes(),
            "Inputs differing only in sign bit should produce same point (sign bit is cleared)"
        );
    }

    #[test]
    fn test_elligator2_deterministic() {
        let mut input = [0u8; 32];
        input[0] = 123;
        input[15] = 45;

        let point1 = elligator2_to_edwards(&input).unwrap();
        let point2 = elligator2_to_edwards(&input).unwrap();

        assert_eq!(
            point1.compress().as_bytes(),
            point2.compress().as_bytes(),
            "Same input should produce same output"
        );
    }
}
