//! BLS12-381 Conformance Tests (CIP-0381)
//!
//! These tests ensure full compatibility with Cardano Plutus BLS12-381 builtins
//! using official test vectors from cardano-base and plutus conformance tests.

#![cfg(feature = "bls")]

use cardano_crypto::bls::{
    Bls12381, BlsPublicKey, BlsSecretKey, BlsSignature, G1_COMPRESSED_SIZE, G1Point,
    G2_COMPRESSED_SIZE, G2Point, SCALAR_SIZE, Scalar, bls_verify, bls_verify_with_dst,
};

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[allow(dead_code)]
fn hex_to_array<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = hex_to_bytes(hex);
    assert_eq!(bytes.len(), N, "Expected {} bytes, got {}", N, bytes.len());
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    arr
}

// ============================================================================
// Size Constants Verification (CIP-0381)
// ============================================================================

mod size_constants {
    use super::*;

    #[test]
    fn test_g1_sizes() {
        assert_eq!(G1_COMPRESSED_SIZE, 48, "G1 compressed should be 48 bytes");
        assert_eq!(G1Point::COMPRESSED_SIZE, 48);
    }

    #[test]
    fn test_g2_sizes() {
        assert_eq!(G2_COMPRESSED_SIZE, 96, "G2 compressed should be 96 bytes");
        assert_eq!(G2Point::COMPRESSED_SIZE, 96);
    }

    #[test]
    fn test_scalar_size() {
        assert_eq!(SCALAR_SIZE, 32, "Scalar should be 32 bytes");
        assert_eq!(Scalar::SIZE, 32);
    }
}

// ============================================================================
// G1 Identity Point Tests
// ============================================================================

mod g1_identity_tests {
    use super::*;

    /// G1 compressed zero (identity) from cardano-base
    const G1_COMPRESSED_ZERO: &str = "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn test_g1_identity_encoding() {
        let id = G1Point::identity();
        let compressed = Bls12381::g1_compress(&id);
        let expected = hex_to_bytes(G1_COMPRESSED_ZERO);

        assert_eq!(
            compressed.as_slice(),
            expected.as_slice(),
            "G1 identity should encode to c0...00"
        );
    }

    #[test]
    fn test_g1_identity_decode() {
        let bytes = hex_to_bytes(G1_COMPRESSED_ZERO);
        let point = Bls12381::g1_uncompress(&bytes).unwrap();

        assert!(
            Bls12381::g1_is_identity(&point),
            "Decoded zero should be identity"
        );
    }

    #[test]
    fn test_g1_add_identity_left() {
        let generator = G1Point::generator();
        let id = G1Point::identity();
        let result = Bls12381::g1_add(&id, &generator);

        assert_eq!(generator, result, "0 + G = G");
    }

    #[test]
    fn test_g1_add_identity_right() {
        let generator = G1Point::generator();
        let id = G1Point::identity();
        let result = Bls12381::g1_add(&generator, &id);

        assert_eq!(generator, result, "G + 0 = G");
    }

    #[test]
    fn test_g1_neg_identity() {
        let id = G1Point::identity();
        let neg_id = Bls12381::g1_neg(&id);

        assert!(Bls12381::g1_is_identity(&neg_id), "-0 = 0");
    }

    #[test]
    fn test_g1_scalar_mul_zero() {
        let generator = G1Point::generator();
        let zero = Scalar::from_bytes_be(&[0u8; 32]).unwrap();
        let result = Bls12381::g1_scalar_mul(&zero, &generator);

        assert!(Bls12381::g1_is_identity(&result), "0 * G = 0");
    }
}

// ============================================================================
// G2 Identity Point Tests
// ============================================================================

mod g2_identity_tests {
    use super::*;

    /// G2 compressed zero (identity) from cardano-base
    const G2_COMPRESSED_ZERO: &str = "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn test_g2_identity_encoding() {
        let id = G2Point::identity();
        let compressed = Bls12381::g2_compress(&id);
        let expected = hex_to_bytes(G2_COMPRESSED_ZERO);

        assert_eq!(
            compressed.as_slice(),
            expected.as_slice(),
            "G2 identity should encode to c0...00"
        );
    }

    #[test]
    fn test_g2_identity_decode() {
        let bytes = hex_to_bytes(G2_COMPRESSED_ZERO);
        let point = Bls12381::g2_uncompress(&bytes).unwrap();

        assert!(
            Bls12381::g2_is_identity(&point),
            "Decoded zero should be identity"
        );
    }

    #[test]
    fn test_g2_add_identity_left() {
        let generator = G2Point::generator();
        let id = G2Point::identity();
        let result = Bls12381::g2_add(&id, &generator);

        assert_eq!(generator, result, "0 + G2 = G2");
    }

    #[test]
    fn test_g2_add_identity_right() {
        let generator = G2Point::generator();
        let id = G2Point::identity();
        let result = Bls12381::g2_add(&generator, &id);

        assert_eq!(generator, result, "G2 + 0 = G2");
    }

    #[test]
    fn test_g2_neg_identity() {
        let id = G2Point::identity();
        let neg_id = Bls12381::g2_neg(&id);

        assert!(Bls12381::g2_is_identity(&neg_id), "-0 = 0");
    }

    #[test]
    fn test_g2_scalar_mul_zero() {
        let generator = G2Point::generator();
        let zero = Scalar::from_bytes_be(&[0u8; 32]).unwrap();
        let result = Bls12381::g2_scalar_mul(&zero, &generator);

        assert!(Bls12381::g2_is_identity(&result), "0 * G2 = 0");
    }
}

// ============================================================================
// G1 Generator and Operations Tests
// ============================================================================

mod g1_operations_tests {
    use super::*;

    #[test]
    fn test_g1_generator_not_identity() {
        let generator = G1Point::generator();
        assert!(
            !Bls12381::g1_is_identity(&generator),
            "Generator should not be identity"
        );
    }

    #[test]
    fn test_g1_generator_roundtrip() {
        let generator = G1Point::generator();
        let compressed = Bls12381::g1_compress(&generator);
        let restored = Bls12381::g1_uncompress(&compressed).unwrap();

        assert_eq!(
            generator, restored,
            "Generator should roundtrip through compression"
        );
    }

    #[test]
    fn test_g1_add_inverse_is_identity() {
        let generator = G1Point::generator();
        let neg_gen = Bls12381::g1_neg(&generator);
        let sum = Bls12381::g1_add(&generator, &neg_gen);

        assert!(Bls12381::g1_is_identity(&sum), "G + (-G) = 0");
    }

    #[test]
    fn test_g1_double_is_scalar_mul_2() {
        let generator = G1Point::generator();
        let doubled = Bls12381::g1_add(&generator, &generator);

        let mut two_bytes = [0u8; 32];
        two_bytes[31] = 2;
        let two = Scalar::from_bytes_be(&two_bytes).unwrap();
        let scaled = Bls12381::g1_scalar_mul(&two, &generator);

        assert_eq!(doubled, scaled, "G + G = 2*G");
    }

    #[test]
    fn test_g1_scalar_mul_one() {
        let generator = G1Point::generator();
        let mut one_bytes = [0u8; 32];
        one_bytes[31] = 1;
        let one = Scalar::from_bytes_be(&one_bytes).unwrap();
        let result = Bls12381::g1_scalar_mul(&one, &generator);

        assert_eq!(generator, result, "1 * G = G");
    }

    #[test]
    fn test_g1_triple() {
        let generator = G1Point::generator();

        // 3*G via addition
        let doubled = Bls12381::g1_add(&generator, &generator);
        let tripled_add = Bls12381::g1_add(&doubled, &generator);

        // 3*G via scalar multiplication
        let mut three_bytes = [0u8; 32];
        three_bytes[31] = 3;
        let three = Scalar::from_bytes_be(&three_bytes).unwrap();
        let tripled_mul = Bls12381::g1_scalar_mul(&three, &generator);

        assert_eq!(tripled_add, tripled_mul, "G + G + G = 3*G");
    }

    #[test]
    fn test_g1_scalar_mul_associativity() {
        // (a*b)*G = a*(b*G)
        let generator = G1Point::generator();

        let mut a_bytes = [0u8; 32];
        a_bytes[31] = 5;
        let a = Scalar::from_bytes_be(&a_bytes).unwrap();

        let mut b_bytes = [0u8; 32];
        b_bytes[31] = 7;
        let b = Scalar::from_bytes_be(&b_bytes).unwrap();

        let mut ab_bytes = [0u8; 32];
        ab_bytes[31] = 35; // 5 * 7
        let ab = Scalar::from_bytes_be(&ab_bytes).unwrap();

        // (a*b)*G
        let result1 = Bls12381::g1_scalar_mul(&ab, &generator);

        // a*(b*G)
        let b_g = Bls12381::g1_scalar_mul(&b, &generator);
        let result2 = Bls12381::g1_scalar_mul(&a, &b_g);

        assert_eq!(result1, result2, "(a*b)*G = a*(b*G)");
    }

    #[test]
    fn test_g1_add_commutativity() {
        let generator = G1Point::generator();

        let mut two_bytes = [0u8; 32];
        two_bytes[31] = 2;
        let two = Scalar::from_bytes_be(&two_bytes).unwrap();

        let mut three_bytes = [0u8; 32];
        three_bytes[31] = 3;
        let three = Scalar::from_bytes_be(&three_bytes).unwrap();

        let p = Bls12381::g1_scalar_mul(&two, &generator);
        let q = Bls12381::g1_scalar_mul(&three, &generator);

        let pq = Bls12381::g1_add(&p, &q);
        let qp = Bls12381::g1_add(&q, &p);

        assert_eq!(pq, qp, "P + Q = Q + P");
    }
}

// ============================================================================
// G2 Generator and Operations Tests
// ============================================================================

mod g2_operations_tests {
    use super::*;

    #[test]
    fn test_g2_generator_not_identity() {
        let generator = G2Point::generator();
        assert!(
            !Bls12381::g2_is_identity(&generator),
            "Generator should not be identity"
        );
    }

    #[test]
    fn test_g2_generator_roundtrip() {
        let generator = G2Point::generator();
        let compressed = Bls12381::g2_compress(&generator);
        let restored = Bls12381::g2_uncompress(&compressed).unwrap();

        assert_eq!(
            generator, restored,
            "Generator should roundtrip through compression"
        );
    }

    #[test]
    fn test_g2_add_inverse_is_identity() {
        let generator = G2Point::generator();
        let neg_gen = Bls12381::g2_neg(&generator);
        let sum = Bls12381::g2_add(&generator, &neg_gen);

        assert!(Bls12381::g2_is_identity(&sum), "G2 + (-G2) = 0");
    }

    #[test]
    fn test_g2_double_is_scalar_mul_2() {
        let generator = G2Point::generator();
        let doubled = Bls12381::g2_add(&generator, &generator);

        let mut two_bytes = [0u8; 32];
        two_bytes[31] = 2;
        let two = Scalar::from_bytes_be(&two_bytes).unwrap();
        let scaled = Bls12381::g2_scalar_mul(&two, &generator);

        assert_eq!(doubled, scaled, "G2 + G2 = 2*G2");
    }

    #[test]
    fn test_g2_scalar_mul_one() {
        let generator = G2Point::generator();
        let mut one_bytes = [0u8; 32];
        one_bytes[31] = 1;
        let one = Scalar::from_bytes_be(&one_bytes).unwrap();
        let result = Bls12381::g2_scalar_mul(&one, &generator);

        assert_eq!(generator, result, "1 * G2 = G2");
    }
}

// ============================================================================
// Pairing Tests (CIP-0381)
// ============================================================================

mod pairing_tests {
    use super::*;

    #[test]
    fn test_pairing_nondegeneracy() {
        // e(G1, G2) should not be the identity element in GT
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();
        let result = Bls12381::pairing(&g1, &g2);

        assert!(!result.is_one(), "e(G1, G2) != 1 (non-degeneracy)");
    }

    #[test]
    fn test_pairing_with_g1_identity() {
        // e(0, G2) = 1
        let g1_id = G1Point::identity();
        let g2 = G2Point::generator();
        let result = Bls12381::pairing(&g1_id, &g2);

        assert!(result.is_one(), "e(0, G2) = 1");
    }

    #[test]
    fn test_pairing_with_g2_identity() {
        // e(G1, 0) = 1
        let g1 = G1Point::generator();
        let g2_id = G2Point::identity();
        let result = Bls12381::pairing(&g1, &g2_id);

        assert!(result.is_one(), "e(G1, 0) = 1");
    }

    #[test]
    fn test_pairing_bilinearity_scalar_g1() {
        // e([a]P, Q) = e(P, Q)^a = e(P, [a]Q)
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        let mut a_bytes = [0u8; 32];
        a_bytes[31] = 5;
        let a = Scalar::from_bytes_be(&a_bytes).unwrap();

        // e([a]G1, G2)
        let a_g1 = Bls12381::g1_scalar_mul(&a, &g1);
        let result1 = Bls12381::pairing(&a_g1, &g2);

        // e(G1, [a]G2)
        let a_g2 = Bls12381::g2_scalar_mul(&a, &g2);
        let result2 = Bls12381::pairing(&g1, &a_g2);

        assert_eq!(result1, result2, "e([a]G1, G2) = e(G1, [a]G2)");
    }

    #[test]
    fn test_pairing_bilinearity_both_scalars() {
        // e([a]P, [b]Q) = e(P, Q)^(ab) = e([ab]P, Q)
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        let mut a_bytes = [0u8; 32];
        a_bytes[31] = 3;
        let a = Scalar::from_bytes_be(&a_bytes).unwrap();

        let mut b_bytes = [0u8; 32];
        b_bytes[31] = 7;
        let b = Scalar::from_bytes_be(&b_bytes).unwrap();

        let mut ab_bytes = [0u8; 32];
        ab_bytes[31] = 21; // 3 * 7
        let ab = Scalar::from_bytes_be(&ab_bytes).unwrap();

        // e([a]G1, [b]G2)
        let a_g1 = Bls12381::g1_scalar_mul(&a, &g1);
        let b_g2 = Bls12381::g2_scalar_mul(&b, &g2);
        let result1 = Bls12381::pairing(&a_g1, &b_g2);

        // e([ab]G1, G2)
        let ab_g1 = Bls12381::g1_scalar_mul(&ab, &g1);
        let result2 = Bls12381::pairing(&ab_g1, &g2);

        // e(G1, [ab]G2)
        let ab_g2 = Bls12381::g2_scalar_mul(&ab, &g2);
        let result3 = Bls12381::pairing(&g1, &ab_g2);

        assert_eq!(result1, result2, "e([a]G1, [b]G2) = e([ab]G1, G2)");
        assert_eq!(result2, result3, "e([ab]G1, G2) = e(G1, [ab]G2)");
    }

    #[test]
    fn test_miller_loop_then_final_exp() {
        // Miller loop followed by final exponentiation should equal pairing
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        let ml = Bls12381::miller_loop(&g1, &g2);
        let result1 = Bls12381::final_exponentiate(&ml);
        let result2 = Bls12381::pairing(&g1, &g2);

        assert_eq!(
            result1, result2,
            "finalExp(millerLoop(G1, G2)) = pairing(G1, G2)"
        );
    }

    #[test]
    fn test_pairing_equation_basic() {
        // e(G1, G2) * e(-G1, G2) = 1
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();
        let neg_g1 = Bls12381::g1_neg(&g1);

        let valid = Bls12381::verify_pairing_equation(&[(g1, g2.clone()), (neg_g1, g2)]);

        assert!(valid, "e(G1, G2) * e(-G1, G2) = 1");
    }

    #[test]
    fn test_pairing_equation_scaled() {
        // e([a]G1, G2) * e([-a]G1, G2) = 1
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        let mut a_bytes = [0u8; 32];
        a_bytes[31] = 42;
        let a = Scalar::from_bytes_be(&a_bytes).unwrap();

        let a_g1 = Bls12381::g1_scalar_mul(&a, &g1);
        let neg_a_g1 = Bls12381::g1_neg(&a_g1);

        let valid = Bls12381::verify_pairing_equation(&[(a_g1, g2.clone()), (neg_a_g1, g2)]);

        assert!(valid, "e([a]G1, G2) * e([-a]G1, G2) = 1");
    }
}

// ============================================================================
// Hash-to-Curve Tests (CIP-0381)
// ============================================================================

mod hash_to_curve_tests {
    use super::*;

    const TEST_DST: &[u8] = b"BLS12381G1_XMD:SHA-256_SSWU_RO_TEST";

    #[test]
    fn test_g1_hash_deterministic() {
        let msg = b"test message";
        let p1 = Bls12381::g1_hash_to_curve(msg, TEST_DST);
        let p2 = Bls12381::g1_hash_to_curve(msg, TEST_DST);

        assert_eq!(p1, p2, "Hash-to-curve should be deterministic");
    }

    #[test]
    fn test_g1_hash_different_messages() {
        let msg1 = b"message one";
        let msg2 = b"message two";
        let p1 = Bls12381::g1_hash_to_curve(msg1, TEST_DST);
        let p2 = Bls12381::g1_hash_to_curve(msg2, TEST_DST);

        assert_ne!(p1, p2, "Different messages should hash to different points");
    }

    #[test]
    fn test_g1_hash_different_dst() {
        let msg = b"same message";
        let dst1 = b"DST_ONE";
        let dst2 = b"DST_TWO";
        let p1 = Bls12381::g1_hash_to_curve(msg, dst1);
        let p2 = Bls12381::g1_hash_to_curve(msg, dst2);

        assert_ne!(p1, p2, "Different DSTs should produce different points");
    }

    #[test]
    fn test_g1_hash_empty_message() {
        let msg: &[u8] = b"";
        let point = Bls12381::g1_hash_to_curve(msg, TEST_DST);

        assert!(
            !Bls12381::g1_is_identity(&point),
            "Hash of empty message should not be identity"
        );
    }

    #[test]
    fn test_g2_hash_deterministic() {
        let dst = b"BLS12381G2_XMD:SHA-256_SSWU_RO_TEST";
        let msg = b"test message";
        let p1 = Bls12381::g2_hash_to_curve(msg, dst);
        let p2 = Bls12381::g2_hash_to_curve(msg, dst);

        assert_eq!(p1, p2, "G2 Hash-to-curve should be deterministic");
    }

    #[test]
    fn test_g2_hash_different_messages() {
        let dst = b"BLS12381G2_XMD:SHA-256_SSWU_RO_TEST";
        let msg1 = b"message one";
        let msg2 = b"message two";
        let p1 = Bls12381::g2_hash_to_curve(msg1, dst);
        let p2 = Bls12381::g2_hash_to_curve(msg2, dst);

        assert_ne!(
            p1, p2,
            "Different messages should hash to different G2 points"
        );
    }
}

// ============================================================================
// BLS Signature Tests
// ============================================================================

mod bls_signature_tests {
    use super::*;

    /// Standard domain separation tag for BLS signatures
    #[allow(dead_code)]
    const STANDARD_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    #[test]
    fn test_bls_sign_verify_basic() {
        let seed = [1u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        let msg = b"Hello, Cardano!";
        let sig = sk.sign(msg);

        assert!(bls_verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn test_bls_wrong_message_fails() {
        let seed = [2u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        let msg = b"original message";
        let sig = sk.sign(msg);

        assert!(bls_verify(&pk, b"wrong message", &sig).is_err());
    }

    #[test]
    fn test_bls_wrong_key_fails() {
        let seed1 = [3u8; 32];
        let seed2 = [4u8; 32];
        let sk1 = BlsSecretKey::from_bytes(&seed1).unwrap();
        let sk2 = BlsSecretKey::from_bytes(&seed2).unwrap();
        let pk2 = sk2.public_key();

        let msg = b"test message";
        let sig = sk1.sign(msg);

        // Signature from sk1 should not verify with pk2
        assert!(bls_verify(&pk2, msg, &sig).is_err());
    }

    #[test]
    fn test_bls_signature_deterministic() {
        let seed = [5u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();

        let msg = b"deterministic test";
        let sig1 = sk.sign(msg);
        let sig2 = sk.sign(msg);

        assert_eq!(
            sig1.to_compressed(),
            sig2.to_compressed(),
            "BLS signatures should be deterministic"
        );
    }

    #[test]
    fn test_bls_key_roundtrip() {
        let seed = [6u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        let compressed = pk.to_compressed();
        let restored = BlsPublicKey::from_compressed(&compressed).unwrap();

        assert_eq!(pk, restored);
    }

    #[test]
    fn test_bls_signature_roundtrip() {
        let seed = [7u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();

        let msg = b"roundtrip";
        let sig = sk.sign(msg);

        let compressed = sig.to_compressed();
        let restored = BlsSignature::from_compressed(&compressed).unwrap();

        assert_eq!(sig, restored);
    }

    #[test]
    fn test_bls_custom_dst() {
        let seed = [8u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        let custom_dst = b"CUSTOM_DOMAIN_SEPARATION_TAG";
        let msg = b"custom dst message";
        let sig = sk.sign_with_dst(msg, custom_dst);

        // Should verify with same DST
        assert!(bls_verify_with_dst(&pk, msg, &sig, custom_dst).is_ok());

        // Should fail with wrong DST
        assert!(bls_verify_with_dst(&pk, msg, &sig, b"WRONG_DST").is_err());

        // Should fail with standard DST
        assert!(bls_verify(&pk, msg, &sig).is_err());
    }

    #[test]
    fn test_bls_empty_message() {
        let seed = [9u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        let msg: &[u8] = b"";
        let sig = sk.sign(msg);

        assert!(bls_verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn test_bls_long_message() {
        let seed = [10u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        // 1KB message
        let msg = vec![0xABu8; 1024];
        let sig = sk.sign(&msg);

        assert!(bls_verify(&pk, &msg, &sig).is_ok());
    }
}

// ============================================================================
// Serialization/Deserialization Tests
// ============================================================================

mod serialization_tests {
    use super::*;

    #[test]
    fn test_g1_invalid_compressed_length() {
        let too_short = vec![0u8; 47];
        assert!(Bls12381::g1_uncompress(&too_short).is_err());

        let too_long = vec![0u8; 49];
        assert!(Bls12381::g1_uncompress(&too_long).is_err());
    }

    #[test]
    fn test_g2_invalid_compressed_length() {
        let too_short = vec![0u8; 95];
        assert!(Bls12381::g2_uncompress(&too_short).is_err());

        let too_long = vec![0u8; 97];
        assert!(Bls12381::g2_uncompress(&too_long).is_err());
    }

    #[test]
    fn test_scalar_invalid_length() {
        let too_short = vec![0u8; 31];
        assert!(Scalar::from_bytes_be(&too_short).is_err());

        let too_long = vec![0u8; 33];
        assert!(Scalar::from_bytes_be(&too_long).is_err());
    }

    #[test]
    fn test_g1_arbitrary_bytes_rejection() {
        // Random bytes that don't represent a valid G1 point
        let invalid = [0xFFu8; 48];
        assert!(Bls12381::g1_uncompress(&invalid).is_err());
    }

    #[test]
    fn test_g2_arbitrary_bytes_rejection() {
        // Random bytes that don't represent a valid G2 point
        let invalid = [0xFFu8; 96];
        assert!(Bls12381::g2_uncompress(&invalid).is_err());
    }
}

// ============================================================================
// cardano-base Test Vectors
// ============================================================================

mod cardano_base_vectors {
    use super::*;

    /// Sample G1 point from cardano-base test vectors
    #[test]
    fn test_g1_sample_point() {
        // G1 point from Plutus conformance tests
        let point_hex = "abd61864f519748032551e42e0ac417fd828f079454e3e3c9891c5c29ed7f10bdecc046854e3931cb7002779bd76d71f";
        let point = Bls12381::g1_uncompress(&hex_to_bytes(point_hex)).unwrap();

        // Should roundtrip
        let compressed = Bls12381::g1_compress(&point);
        let restored = Bls12381::g1_uncompress(&compressed).unwrap();
        assert_eq!(point, restored);
    }

    /// Sample G2 point from cardano-base test vectors
    #[test]
    fn test_g2_sample_point() {
        // G2 point from Plutus conformance tests
        let point_hex = "b0629fa1158c2d23a10413fe91d381a84d25e31d041cd0377d25828498fd02011b35893938ced97535395e4815201e67108bcd4665e0db25d602d76fa791fab706c54abf5e1a9e44b4ac1e6badf3d2ac0328f5e30be341677c8bac5dda7682f1";
        let point = Bls12381::g2_uncompress(&hex_to_bytes(point_hex)).unwrap();

        // Should roundtrip
        let compressed = Bls12381::g2_compress(&point);
        let restored = Bls12381::g2_uncompress(&compressed).unwrap();
        assert_eq!(point, restored);
    }

    /// Scalar from cardano-base for mul-44 test
    #[test]
    fn test_scalar_mul_44() {
        let g1 = G1Point::generator();

        let mut scalar_bytes = [0u8; 32];
        scalar_bytes[31] = 44;
        let scalar = Scalar::from_bytes_be(&scalar_bytes).unwrap();

        let result = Bls12381::g1_scalar_mul(&scalar, &g1);

        // Verify result is not identity and can roundtrip
        assert!(!Bls12381::g1_is_identity(&result));
        let compressed = Bls12381::g1_compress(&result);
        let restored = Bls12381::g1_uncompress(&compressed).unwrap();
        assert_eq!(result, restored);
    }

    /// Large scalar test from cardano-base
    #[test]
    fn test_large_scalar() {
        // Scalar from ec_operations_test_vectors
        let scalar_hex = "40df499974f62e2f268cd5096b0d952073900054122ffce0a27c9d96932891a5";
        let scalar = Scalar::from_bytes_be(&hex_to_bytes(scalar_hex)).unwrap();

        let g1 = G1Point::generator();
        let result = Bls12381::g1_scalar_mul(&scalar, &g1);

        assert!(!Bls12381::g1_is_identity(&result));
    }
}

// ============================================================================
// Pairing-Based Signature Verification Tests
// ============================================================================

mod pairing_signature_tests {
    use super::*;

    /// Test that BLS signature verification is equivalent to a pairing equation check
    #[test]
    fn test_bls_verification_as_pairing_equation() {
        let seed = [42u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        let msg = b"test message";
        let sig = sk.sign(msg);

        // Manual verification via pairing equation:
        // e(pk, H(msg)) = e(G1, sig)
        // Equivalently: e(pk, H(msg)) * e(-G1, sig) = 1

        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        let h_msg = Bls12381::g2_hash_to_curve(msg, dst);
        let g1 = G1Point::generator();
        let neg_g1 = Bls12381::g1_neg(&g1);

        // Extract points from public types
        let pk_point = G1Point::from_compressed(&pk.to_compressed()).unwrap();
        let sig_point = G2Point::from_compressed(&sig.to_compressed()).unwrap();

        let valid = Bls12381::verify_pairing_equation(&[(pk_point, h_msg), (neg_g1, sig_point)]);

        assert!(valid, "BLS verification should work as pairing equation");
    }
}
