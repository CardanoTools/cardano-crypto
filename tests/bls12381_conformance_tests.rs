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

// ============================================================================
// Upstream cardano-base Test Vector Tests
// ============================================================================
// These tests use the exact test vector files from IntersectMBO/cardano-base
// cardano-crypto-class/bls12-381-test-vectors/test_vectors/
// Source: https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-class/bls12-381-test-vectors

mod upstream_test_vectors {
    use super::*;
    use cardano_crypto::hash::sha256;

    /// Parse hex lines from a test vector string, one hex value per line.
    fn parse_hex_lines(data: &str) -> Vec<Vec<u8>> {
        data.lines()
            .filter(|l| !l.is_empty())
            .map(|l| hex_to_bytes(l.trim()))
            .collect()
    }

    // ---- EC Operations Test Vectors ----
    // Format: g1p, g1q, g1add, g1sub, g1mul, g1neg, g2p, g2q, g2add, g2sub, g2mul, g2neg
    // Scalar: 0x40df499974f62e2f268cd5096b0d952073900054122ffce0a27c9d96932891a5

    const EC_OPS_VECTORS: &str = "\
b93105d0cff4c3f6a42ab790900a26bb1843f4b07fc83d527a66e4a2ddf6c49ea86fe37b1106dbd20dc280ec5996dadf
a077246742bfbffdefc1193aba17434d337f231478bf63173065c1e09c34429e76877983ae5f3add1438e5d237f63724
9863eb0a7f8b092fca1a4333866ae3579ad2a4edef84bfcdf736333b3adf0100820c7603b002bf911b564cf032392f07
b7fbd72bc365d8b7ea3954d0203bb4c6539cdec8feef30e6f44a3c67b2480e922a70b382bd5642737095c433938529bf
a07796202c3fcad405a5da58d99f0194c8ee21999dd03291f0bfe97e68eb4e69077cf8052b9f5d9cbc4a1394baa0e0d8
993105d0cff4c3f6a42ab790900a26bb1843f4b07fc83d527a66e4a2ddf6c49ea86fe37b1106dbd20dc280ec5996dadf
b5ed6482bf5486831a9eb445b8b9a77aa6330005b8b432523c69fee7085d3032856de9f857c55ac9745eabcf14894205149cc67393687289e6c2728be69ad1f8ea1a6c0a5a65bf93eca984f3dac5da1abc6f7156ccbc5a33c655f7b17724eb19
a6cc0f01663fd65a95d1359758ebe3a412ce05f4242b0c1f5964351b38e188362a8ceb6c2f86d3f7e5f73b60cd04288005d2a50f8ddf1751d7a915515054276fbae7569c3f18c614c9954177d8e745e98404654cf759d4747b0c806bbd336b7d
b3db03681aaf0d218be32f7cc94bd6a975c6870b4a1d4e461b77b60eee2461ca367154b0c4583b2d5f81124aa21fdf3e09ff6b54ce7c57572283a175fba381a32ac6f46abaf11cdbaeb206dcd7d4269caa4d0ebbb3adc1b8fce42ccfa855ea83
b0e55ab637ca0ed203af268bda8d681c04bd0696cf8cdba4e61c3ba2f3e4fa4ac5a2a7cb93a4a3feaea162506d73222d13caa80d0471afc79e8e5c97b1fccf27e024897545827c654a089d654c1987053b1baaaff3af25c5610d65c3345ae361
89b8e839c317ab3c735c6a65122fff4654f469c30c480701f6e4d9f311f3c5f3411c7cd2876c539bf56f983d14e550b5172765f62bba1235394a33413c21667a57214e9a6f2516f8d7bf57321c20bf8cd8ecd290691ad6bd5ab9e391304240a4
95ed6482bf5486831a9eb445b8b9a77aa6330005b8b432523c69fee7085d3032856de9f857c55ac9745eabcf14894205149cc67393687289e6c2728be69ad1f8ea1a6c0a5a65bf93eca984f3dac5da1abc6f7156ccbc5a33c655f7b17724eb19";

    /// EC operations test vectors from cardano-base: add, sub, mul, neg for G1 and G2.
    /// Source: cardano-crypto-class/bls12-381-test-vectors/test_vectors/ec_operations_test_vectors
    #[test]
    fn test_upstream_ec_operations() {
        let vecs = parse_hex_lines(EC_OPS_VECTORS);
        assert_eq!(vecs.len(), 12, "Expected    12 hex    lines");

        let scalar_hex = "40df499974f62e2f268cd5096b0d952073900054122ffce0a27c9d96932891a5";
        let scalar = Scalar::from_bytes_be(&hex_to_bytes(scalar_hex)).unwrap();

        // G1 points
        let g1p = G1Point::from_compressed(&vecs[0]).unwrap();
        let g1q = G1Point::from_compressed(&vecs[1]).unwrap();
        let g1add_expected = G1Point::from_compressed(&vecs[2]).unwrap();
        let g1sub_expected = G1Point::from_compressed(&vecs[3]).unwrap();
        let g1mul_expected = G1Point::from_compressed(&vecs[4]).unwrap();
        let g1neg_expected = G1Point::from_compressed(&vecs[5]).unwrap();

        // G2 points
        let g2p = G2Point::from_compressed(&vecs[6]).unwrap();
        let g2q = G2Point::from_compressed(&vecs[7]).unwrap();
        let g2add_expected = G2Point::from_compressed(&vecs[8]).unwrap();
        let g2sub_expected = G2Point::from_compressed(&vecs[9]).unwrap();
        let g2mul_expected = G2Point::from_compressed(&vecs[10]).unwrap();
        let g2neg_expected = G2Point::from_compressed(&vecs[11]).unwrap();

        // G1 operations
        let g1add = Bls12381::g1_add(&g1p, &g1q);
        assert_eq!(
            Bls12381::g1_compress(&g1add),
            Bls12381::g1_compress(&g1add_expected),
            "G1 add mismatch"
        );

        let g1sub = Bls12381::g1_add(&g1p, &Bls12381::g1_neg(&g1q));
        assert_eq!(
            Bls12381::g1_compress(&g1sub),
            Bls12381::g1_compress(&g1sub_expected),
            "G1 sub mismatch"
        );

        let g1mul = Bls12381::g1_scalar_mul(&scalar, &g1q);
        assert_eq!(
            Bls12381::g1_compress(&g1mul),
            Bls12381::g1_compress(&g1mul_expected),
            "G1 mul mismatch"
        );

        let g1neg = Bls12381::g1_neg(&g1p);
        assert_eq!(
            Bls12381::g1_compress(&g1neg),
            Bls12381::g1_compress(&g1neg_expected),
            "G1 neg mismatch"
        );

        // G2 operations
        let g2add = Bls12381::g2_add(&g2p, &g2q);
        assert_eq!(
            Bls12381::g2_compress(&g2add),
            Bls12381::g2_compress(&g2add_expected),
            "G2 add mismatch"
        );

        let g2sub = Bls12381::g2_add(&g2p, &Bls12381::g2_neg(&g2q));
        assert_eq!(
            Bls12381::g2_compress(&g2sub),
            Bls12381::g2_compress(&g2sub_expected),
            "G2 sub mismatch"
        );

        let g2mul = Bls12381::g2_scalar_mul(&scalar, &g2q);
        assert_eq!(
            Bls12381::g2_compress(&g2mul),
            Bls12381::g2_compress(&g2mul_expected),
            "G2 mul mismatch"
        );

        let g2neg = Bls12381::g2_neg(&g2p);
        assert_eq!(
            Bls12381::g2_compress(&g2neg),
            Bls12381::g2_compress(&g2neg_expected),
            "G2 neg mismatch"
        );
    }

    // ---- Pairing Test Vectors ----
    // Format: P, aP, bP, (a+b)P, (a*b)P, Q, aQ, bQ, (a+b)Q, (a*b)Q

    const PAIRING_VECTORS: &str = "\
840463aa2f2cda89985b1f3f5eb43b9c29809765d2747d60734b19d6f90610effdfc500af7d458a3e78cee0945ddc669
8baa4f3fcd895033f93494b040ccd7dfb77cb759cd2e150bfff4264873174509cd22230423b70896b17c8fc3660f6b21
a4a925cb9c0580c14cbc8ec54447eb20070336a61c349c6a64b0d87e4db89d77734021cd88e2da369bdd85c0518c66c4
aecf54083187026a6b689e70af54375ab7cc6d0d311acb6203730a2904654d6e92f82e62006c0d5e21094155eb93cc98
b2bb2433441c452b78f5be911aa136dd2c886a9ac329cb6c805e50d5255891fcc389b1190432f16a109c6f431f0f8023
b67029fbf3ab8e62ab6b499f541537fc07d9466e668392df2bc19762d7dc48b64be09a448cd46dbfe21819a91cd0ab3205f1316ad1cc32853f3f1a1d06497f5cfbc2d753dfc01bff177adeb93f24d452045435dc6eb29f5610b66cd0dd3fb352
a80f311db6f2fdc45404870f4c55b65a9a59a35efcfa2a7c595f3955226076bbaa33e403c0d4749495d9423b806f9dbe08cca770e08fa535daefb6dba2edb62f8b9aff6bae83bf48819bcdf98f07e79de8635e8521ddecae19b01a6777bc4684
9906a15ff959b496f478dd17348b32c033236db5a7437768a30c5ce87d9b6adfa7bf2223a0721c93a92f33abac9b2faf00d25e48b0f3cc52595264ef9ad0aa7b81e20b3c8634d577883ff5fc2373a021a1e57826f420a74f3ce0fbd2dcf79415
a63be4a1a776cadc7fc2e2d823bcc905f8f9cb0ebe662360d28d9964b022a99ce34a48b2e93cfceebc9bc1d79a3338da03a41393717239e66d4db06a87510b99fe04b0840c87c4051030b25e56ba34248d9ed30c82e8e501a616097299eefd62
82606f4c771ca685bfc1bb9c51c886d0daa0f63fbb0f6a24b512a1b9b92d401e556cbffdc204c0a85192c865ed73f8090da58ecd1690d5a3b236cc5d40a98988f9602a6d114edb59954ef4e21692f2d48219aeacb964604849336059ceece69f";

    /// Pairing test vectors from cardano-base: bilinearity checks.
    /// Source: cardano-crypto-class/bls12-381-test-vectors/test_vectors/pairing_test_vectors
    #[test]
    fn test_upstream_pairing_vectors() {
        let vecs = parse_hex_lines(PAIRING_VECTORS);
        assert_eq!(vecs.len(), 10, "Expected 10 hex lines");

        let p = G1Point::from_compressed(&vecs[0]).unwrap();
        let a_p = G1Point::from_compressed(&vecs[1]).unwrap();
        let b_p = G1Point::from_compressed(&vecs[2]).unwrap();
        let apb_p = G1Point::from_compressed(&vecs[3]).unwrap();
        let axb_p = G1Point::from_compressed(&vecs[4]).unwrap();
        let q = G2Point::from_compressed(&vecs[5]).unwrap();
        let a_q = G2Point::from_compressed(&vecs[6]).unwrap();
        let b_q = G2Point::from_compressed(&vecs[7]).unwrap();
        let apb_q = G2Point::from_compressed(&vecs[8]).unwrap();
        let axb_q = G2Point::from_compressed(&vecs[9]).unwrap();

        // e([a]P, Q) = e(P, [a]Q)
        assert!(
            Bls12381::final_verify(
                &Bls12381::miller_loop(&a_p, &q),
                &Bls12381::miller_loop(&p, &a_q)
            ),
            "e([a]P, Q) should equal e(P, [a]Q)"
        );

        // e([a]P, [b]Q) = e([b]P, [a]Q)
        assert!(
            Bls12381::final_verify(
                &Bls12381::miller_loop(&a_p, &b_q),
                &Bls12381::miller_loop(&b_p, &a_q)
            ),
            "e([a]P, [b]Q) should equal e([b]P, [a]Q)"
        );

        // e([a]P, [b]Q) = e([a*b]P, Q)
        assert!(
            Bls12381::final_verify(
                &Bls12381::miller_loop(&a_p, &b_q),
                &Bls12381::miller_loop(&axb_p, &q)
            ),
            "e([a]P, [b]Q) should equal e([a*b]P, Q)"
        );

        // e([a]P, Q) * e([b]P, Q) = e([a+b]P, Q)
        let ml_ap_q = Bls12381::miller_loop(&a_p, &q);
        let ml_bp_q = Bls12381::miller_loop(&b_p, &q);
        let combined = Bls12381::mul_ml_result(&ml_ap_q, &ml_bp_q);
        assert!(
            Bls12381::final_verify(&combined, &Bls12381::miller_loop(&apb_p, &q)),
            "e([a]P, Q) * e([b]P, Q) should equal e([a+b]P, Q)"
        );

        // e([a]P, [b]Q) = e(P, [a*b]Q)
        assert!(
            Bls12381::final_verify(
                &Bls12381::miller_loop(&a_p, &b_q),
                &Bls12381::miller_loop(&p, &axb_q)
            ),
            "e([a]P, [b]Q) should equal e(P, [a*b]Q)"
        );

        // e(P, [a]Q) * e(P, [b]Q) = e(P, [a+b]Q)
        let ml_p_aq = Bls12381::miller_loop(&p, &a_q);
        let ml_p_bq = Bls12381::miller_loop(&p, &b_q);
        let combined2 = Bls12381::mul_ml_result(&ml_p_aq, &ml_p_bq);
        assert!(
            Bls12381::final_verify(&combined2, &Bls12381::miller_loop(&p, &apb_q)),
            "e(P, [a]Q) * e(P, [b]Q) should equal e(P, [a+b]Q)"
        );
    }

    // ---- SerDe Test Vectors ----
    // Format: g1UncompNotOnCurve, g1CompNotOnCurve, g1CompNotInGroup, g1UncompNotInGroup,
    //         g2UncompNotOnCurve, g2CompNotOnCurve, g2CompNotInGroup, g2UncompNotInGroup

    const SERDE_VECTORS: &str = "\
16b8f1d20fe2c13c6248d3d73d4d66d9c8587ac68a7976a3bbb8b5808320607400dbdb1918e3d3b90cfc38c4ddfade990a213d208fbf7898334f4deed7e5830fd266751315435ae19bb94f4d3dc92652f243dd1f96f3595ab473d2356d8fa8f6
864cc4f64b12ca99ecdd1962572e6add609d9c619aab678b3fc298bc2f0f81feb4f0d3ebad7e850a8bcb52ca467e649d
9483141c933166b61990a706aca07f467d22bc34c6552f5bba91cb1fc21db51d03dfff6523a5e1b4285d54c47660eda1
04092fbc9b385639343cf26c9faf845e7a98cb1f2c9306e8200185d95de059f83ad17c4b97f8c62cf6c347dc6eb5f2b10c07b24a20cbcbd5121ba97f906bee018c34a71c6075ec91556ef67edda7e5ca42e3a785a183f630d7e330d7384a9ccd
14f2c0c96d9f70e48a42cdcdae542bae833eb4a976d4f98410b4a3d77857762d1527ec6714a040baaec3bec41bf9cff00e1cf81ce61e95d97792d7c0db7a88545f10d9b0a5940457018817725da257766906ffbc6172b9c4d2d32a14d00c0d1d01e15280074a4a9fd2d21393f078ef55b16cfea5327993263bffe8e99e56837b2763abd221ed85d83f9187af8b9e928f00deff423fffdadb786e6678a59af305cdc02546d0f8ab4681acc1f00069b0c47bbc9f13d12fd9411f8df532096d53e4
87861839e602fc5dfa0d0b72232dd81d2b0e4b660a7eba353da27e66ceaf2d6c7734925247281866a12d67752a1edaad01ea59e4e86e2e85a81a573cd68f6dfb526558d81a8f488f261f355ddac23f6caf07d27fda71d8f3968d4ceeda89a09d
8bd83699f607412448d202d948bb111badd456d68086ff9a5906ea3b2cda4111d3638391f7a7b153eea77ab47215d6fe13b350f59f884c6e31ac087239d9145b816424cba2c8bcb7b3ed7e19638089d91e5c9136d2aefc8da165284b42229a70
1120dda4e2d4bcc2fb6984277af23a282ceabebfcd847b8e6130b31c1f2febc638de2fb90d366743bcd4147a974235210462011fd256214f85e5591a3574a3003ec2eeff92634fd9fdd3a64dde1ecd92f0beb5f9eeb4697348a60921b6d3feb303a20332decaaa7fab892e34a43c5e6a2e90455a754b92a2cde128c3eeb46e8c9e22f1920d338f5107e86baa934c5c5f11589c6d345e5adefc0cd27d079e22f4d21f6f4a3f764c3d47062299c2f56bf49f5ff7e6cd2966aa3f2c1d125b76049c";

    /// SerDe error test vectors from cardano-base: invalid points should be rejected.
    /// Source: cardano-crypto-class/bls12-381-test-vectors/test_vectors/serde_test_vectors
    #[test]
    fn test_upstream_serde_invalid_points() {
        let vecs = parse_hex_lines(SERDE_VECTORS);
        assert_eq!(vecs.len(), 8, "Expected 8 hex lines");

        // Line 1: g1UncompNotOnCurve (96 bytes uncompressed G1)
        assert!(
            G1Point::from_compressed(&vecs[0]).is_err(),
            "g1UncompNotOnCurve should fail deserialization"
        );

        // Line 2: g1CompNotOnCurve (48 bytes compressed G1)
        assert!(
            G1Point::from_compressed(&vecs[1]).is_err(),
            "g1CompNotOnCurve should fail deserialization"
        );

        // Line 3: g1CompNotInGroup (48 bytes compressed G1)
        assert!(
            G1Point::from_compressed(&vecs[2]).is_err(),
            "g1CompNotInGroup should fail deserialization"
        );

        // Line 4: g1UncompNotInGroup (96 bytes uncompressed G1)
        assert!(
            G1Point::from_compressed(&vecs[3]).is_err(),
            "g1UncompNotInGroup should fail deserialization"
        );

        // Line 5: g2UncompNotOnCurve (192 bytes uncompressed G2)
        assert!(
            G2Point::from_compressed(&vecs[4]).is_err(),
            "g2UncompNotOnCurve should fail deserialization"
        );

        // Line 6: g2CompNotOnCurve (96 bytes compressed G2)
        assert!(
            G2Point::from_compressed(&vecs[5]).is_err(),
            "g2CompNotOnCurve should fail deserialization"
        );

        // Line 7: g2CompNotInGroup (96 bytes compressed G2)
        assert!(
            G2Point::from_compressed(&vecs[6]).is_err(),
            "g2CompNotInGroup should fail deserialization"
        );

        // Line 8: g2UncompNotInGroup (192 bytes uncompressed G2)
        assert!(
            G2Point::from_compressed(&vecs[7]).is_err(),
            "g2UncompNotInGroup should fail deserialization"
        );
    }

    // ---- Signature Augmentation Test Vectors ----
    // Format: sig (G2 compressed 96 bytes), pk (G1 compressed 48 bytes)
    // DST: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
    // msg: "blst is such a blast"
    // aug: "Random value for test aug. "

    const SIG_AUG_VECTORS: &str = "\
83422fd1d8f134fbbc7ad2949a0b7c38dc1f85bfd398bc58ae824ad34ace68eaa49f438872ee22e90778513a91f9685e
b756d6223a92609cccf660b6f37e6e34fbb23972fc3955710f9bb202cc84cffacd337792700ebcb4324a99c7e7c9ed6d0e1cfdce8cd879a35300957c69c524c5365f6f0a85130735f27510618bbea605a1d024bb2d3bee2a5d68a827406f11c7";

    /// BLS signature with augmentation test vector from cardano-base.
    /// Source: cardano-crypto-class/bls12-381-test-vectors/test_vectors/bls_sig_aug_test_vectors
    #[test]
    fn test_upstream_sig_aug() {
        let vecs = parse_hex_lines(SIG_AUG_VECTORS);
        assert_eq!(vecs.len(), 2, "Expected 2 hex lines (sig, pk)");

        // Line 1 = sig (G1 compressed, 48 bytes), Line 2 = pk (G2 compressed, 96 bytes)
        // This is the "signature on G1" variant matching upstream millerLoop(sig, G2gen)
        let sig = G1Point::from_compressed(&vecs[0]).unwrap();
        let pk = G2Point::from_compressed(&vecs[1]).unwrap();

        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let msg = b"blst is such a blast";
        let aug = b"Random value for test aug. ";

        // Hash augmented message (aug || msg) to G1
        let h_msg = Bls12381::g1_hash_to_curve(&[&aug[..], &msg[..]].concat(), dst);
        let g2_gen = G2Point::generator();

        // Verify: e(sig, G2_gen) == e(H(aug||msg), pk)
        // Matches upstream: ptFinalVerify (millerLoop sig blsGenerator) (millerLoop hashedMsg pk)
        assert!(
            Bls12381::final_verify(
                &Bls12381::miller_loop(&sig, &g2_gen),
                &Bls12381::miller_loop(&h_msg, &pk)
            ),
            "BLS sig-aug verification should succeed"
        );
    }

    // ---- Hash-to-Curve with Large DST Test Vectors ----
    // Format: msg, large_dst, expected_output
    // When DST > 255 bytes, use SHA-256 hash of "H2C-OVERSIZE-DST-" || large_dst

    const H2C_LARGE_DST_VECTORS: &str = "\
54657374696e67206c61726765206473742e
62f5804020e6a8e242c736d1c97bcd8262f91b88e1d70b00d10d5e315c8c6501ead0a7e367e5d394b9fcff9c15aa0f6a05e5085fdc56bcdee3865016f1c49b20e1e609a606eccabc9b9199a42345c25e06ae70028397f8fb95576f264239da3eb49629d5efeb1f1d74a3b1ac58608d893f98058f5ab870833489f5dfec52db5f92e70db05c9704cd9d644b1ae16aaafcc173d48db17e207d91308d3045b042b7241f87b8d42ac5df97d94fdf3f29d20ca2ae22c22e9c5b84b48d6daf1f7959c7c71d0169f370ebf2838479b3731885ff0d278deb632fcb83aef0ab593dddd4f5d21dac56abe08b8cb4aaf4235b1a292b91d6e8b90e39dc953c75fc460e7dd6d2bc8a372ac4efce161f5f18f861e67e5717c86805a05cc53ff493e91de2b85d3166b353f5bbc64bae0d2a4787
a16b5778b5b88519b6caf05921d0d9b8b94a33d1daaa0c7fbfa66d52e801a5e798fae840bb9608aa31712e0b1b3a054a";

    /// Hash-to-curve with oversize DST test vector from cardano-base.
    /// When DST > 255 bytes, it gets SHA-256 hashed with "H2C-OVERSIZE-DST-" prefix.
    /// Source: cardano-crypto-class/bls12-381-test-vectors/test_vectors/h2c_large_dst
    #[test]
    fn test_upstream_h2c_large_dst() {
        let vecs = parse_hex_lines(H2C_LARGE_DST_VECTORS);
        assert_eq!(vecs.len(), 3, "Expected 3 hex lines (msg, dst, output)");

        let msg = &vecs[0];
        let large_dst = &vecs[1];
        let expected_output = G1Point::from_compressed(&vecs[2]).unwrap();

        // When DST > 255 bytes, hash it: SHA-256("H2C-OVERSIZE-DST-" || large_dst)
        let prefix = b"H2C-OVERSIZE-DST-";
        let dst_input = [&prefix[..], large_dst].concat();
        let dst_sha = sha256(&dst_input);

        let hashed = Bls12381::g1_hash_to_curve(msg, &dst_sha);
        assert_eq!(
            Bls12381::g1_compress(&hashed),
            Bls12381::g1_compress(&expected_output),
            "Hash-to-curve with large DST should match expected output"
        );
    }
}
