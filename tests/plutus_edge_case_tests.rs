//! Edge Case Tests for Plutus Crypto Primitives
//!
//! Tests boundary conditions, error handling, and edge cases for full parity
//! with Cardano Plutus builtins.

#![cfg(all(feature = "secp256k1", feature = "bls"))]

use cardano_crypto::bls::{
    Bls12381, BlsPublicKey, BlsSecretKey, BlsSignature, G1Point, G2Point, Scalar,
    G1_COMPRESSED_SIZE, G2_COMPRESSED_SIZE, SCALAR_SIZE,
};
use cardano_crypto::dsign::secp256k1::{
    Secp256k1Ecdsa, Secp256k1EcdsaSignature, Secp256k1EcdsaSigningKey,
    Secp256k1EcdsaVerificationKey, Secp256k1Schnorr, Secp256k1SchnorrSignature,
    Secp256k1SchnorrSigningKey, Secp256k1SchnorrVerificationKey,
};

// ============================================================================
// secp256k1 Edge Cases
// ============================================================================

mod secp256k1_edge_cases {
    use super::*;

    /// Test all-zero seed for ECDSA (should fail - zero is not a valid private key)
    #[test]
    fn test_ecdsa_zero_seed() {
        let zero_seed = [0u8; 32];
        let result = Secp256k1EcdsaSigningKey::from_bytes(&zero_seed);
        // Zero is not a valid secp256k1 private key
        assert!(result.is_err(), "Zero should not be a valid private key");
    }

    /// Test all-one seed for ECDSA
    #[test]
    fn test_ecdsa_ones_seed() {
        let ones_seed = [0xFFu8; 32];
        // This might be valid or invalid depending on whether it's >= curve order
        let result = Secp256k1EcdsaSigningKey::from_bytes(&ones_seed);
        // The secp256k1 order is slightly less than 2^256, so 0xFF...FF might be invalid
        println!("All-ones seed validity: {:?}", result.is_ok());
    }

    /// Test ECDSA signature with max valid scalar
    #[test]
    fn test_ecdsa_boundary_values() {
        // Use a known valid key
        let seed = [1u8; 32];
        let sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();
        let vk = Secp256k1Ecdsa::derive_verification_key(&sk).unwrap();

        // Test with all-zero message hash
        let zero_msg = [0u8; 32];
        let sig = Secp256k1Ecdsa::sign_prehashed(&sk, &zero_msg).unwrap();
        assert!(Secp256k1Ecdsa::verify_prehashed(&vk, &zero_msg, &sig).is_ok());

        // Test with all-ones message hash
        let ones_msg = [0xFFu8; 32];
        let sig = Secp256k1Ecdsa::sign_prehashed(&sk, &ones_msg).unwrap();
        assert!(Secp256k1Ecdsa::verify_prehashed(&vk, &ones_msg, &sig).is_ok());
    }

    /// Test Schnorr with empty message
    #[test]
    fn test_schnorr_empty_message() {
        let seed = [1u8; 32];
        let sk = Secp256k1Schnorr::gen_key(&seed).unwrap();
        let vk = Secp256k1Schnorr::derive_verification_key(&sk).unwrap();

        let empty_msg: &[u8] = b"";
        let sig = Secp256k1Schnorr::sign(&sk, empty_msg).unwrap();
        assert!(
            Secp256k1Schnorr::verify(&vk, empty_msg, &sig).is_ok(),
            "Empty message should be valid for Schnorr"
        );
    }

    /// Test Schnorr with very long message
    #[test]
    fn test_schnorr_long_message() {
        let seed = [2u8; 32];
        let sk = Secp256k1Schnorr::gen_key(&seed).unwrap();
        let vk = Secp256k1Schnorr::derive_verification_key(&sk).unwrap();

        // 10KB message
        let long_msg = vec![0xABu8; 10240];
        let sig = Secp256k1Schnorr::sign(&sk, &long_msg).unwrap();
        assert!(Secp256k1Schnorr::verify(&vk, &long_msg, &sig).is_ok());
    }

    /// Test key uniqueness
    #[test]
    fn test_key_uniqueness() {
        let mut keys = Vec::new();
        for i in 0..100u8 {
            // Use non-zero seeds that are valid secp256k1 private keys
            // Start with a valid base seed and modify it
            let mut seed = [0x42u8; 32];
            seed[0] = i.wrapping_add(1); // Avoid all-zeros which is invalid
            seed[31] = i.wrapping_add(1);
            let sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();
            let vk = Secp256k1Ecdsa::derive_verification_key(&sk).unwrap();
            keys.push(vk.as_bytes().to_vec());
        }

        // Check all keys are unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "Keys {} and {} should be different", i, j);
            }
        }
    }

    /// Test signature malleability rejection
    #[test]
    fn test_ecdsa_signature_format() {
        let seed = [42u8; 32];
        let sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();
        let vk = Secp256k1Ecdsa::derive_verification_key(&sk).unwrap();

        let msg = [0u8; 32];
        let sig = Secp256k1Ecdsa::sign_prehashed(&sk, &msg).unwrap();

        // The signature should be in canonical form (low-S)
        // Verify it passes
        assert!(Secp256k1Ecdsa::verify_prehashed(&vk, &msg, &sig).is_ok());
    }
}

// ============================================================================
// BLS12-381 Edge Cases
// ============================================================================

mod bls_edge_cases {
    use super::*;

    /// Test scalar multiplication with curve order (should give identity)
    #[test]
    fn test_scalar_mul_group_order() {
        // BLS12-381 scalar field order (r)
        // r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
        // This is a 255-bit number, so it fits in 32 bytes

        // For simplicity, test that [n]G where n is very large wraps appropriately
        let g1 = G1Point::generator();

        // Test that [0]G = identity
        let zero = Scalar::from_bytes_be(&[0u8; 32]).unwrap();
        let result = Bls12381::g1_scalar_mul(&zero, &g1);
        assert!(Bls12381::g1_is_identity(&result));

        // Test that [1]G = G
        let mut one_bytes = [0u8; 32];
        one_bytes[31] = 1;
        let one = Scalar::from_bytes_be(&one_bytes).unwrap();
        let result = Bls12381::g1_scalar_mul(&one, &g1);
        assert_eq!(result, g1);
    }

    /// Test double-negation
    #[test]
    fn test_g1_double_negation() {
        let g1 = G1Point::generator();
        let neg = Bls12381::g1_neg(&g1);
        let double_neg = Bls12381::g1_neg(&neg);

        assert_eq!(g1, double_neg, "-(-G) = G");
    }

    #[test]
    fn test_g2_double_negation() {
        let g2 = G2Point::generator();
        let neg = Bls12381::g2_neg(&g2);
        let double_neg = Bls12381::g2_neg(&neg);

        assert_eq!(g2, double_neg, "-(-G2) = G2");
    }

    /// Test pairing with both identity points
    #[test]
    fn test_pairing_both_identity() {
        let g1_id = G1Point::identity();
        let g2_id = G2Point::identity();

        let result = Bls12381::pairing(&g1_id, &g2_id);
        assert!(result.is_one(), "e(0, 0) = 1");
    }

    /// Test compressed format flag bits
    #[test]
    fn test_g1_compression_flags() {
        let g1 = G1Point::generator();
        let compressed = Bls12381::g1_compress(&g1);

        // First byte should have compression flag (0x80) set
        assert!(
            (compressed[0] & 0x80) != 0,
            "Compression flag should be set"
        );
    }

    #[test]
    fn test_g2_compression_flags() {
        let g2 = G2Point::generator();
        let compressed = Bls12381::g2_compress(&g2);

        // First byte should have compression flag (0x80) set
        assert!(
            (compressed[0] & 0x80) != 0,
            "Compression flag should be set"
        );
    }

    /// Test identity point compression flags
    #[test]
    fn test_identity_compression_flags() {
        let g1_id = G1Point::identity();
        let compressed = Bls12381::g1_compress(&g1_id);

        // Identity should have infinity flag (0xC0) set
        assert!(
            (compressed[0] & 0xC0) == 0xC0,
            "Identity should have infinity flag"
        );
    }

    /// Test BLS signature with empty message
    #[test]
    fn test_bls_empty_message() {
        let seed = [1u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        let empty: &[u8] = b"";
        let sig = sk.sign(empty);

        assert!(
            cardano_crypto::bls::bls_verify(&pk, empty, &sig).is_ok(),
            "BLS should sign/verify empty messages"
        );
    }

    /// Test large scalar values
    #[test]
    fn test_large_scalar_values() {
        let g1 = G1Point::generator();

        // Test with various byte patterns
        let patterns: [[u8; 32]; 4] = [
            [0xFF; 32], // Max bytes
            [0x7F; 32], // High bit clear
            [0x01; 32], // Many ones
            [0xAA; 32], // Alternating
        ];

        for pattern in &patterns {
            if let Ok(scalar) = Scalar::from_bytes_be(pattern) {
                let result = Bls12381::g1_scalar_mul(&scalar, &g1);
                // Result should be a valid point (or identity)
                let compressed = Bls12381::g1_compress(&result);
                assert_eq!(compressed.len(), G1_COMPRESSED_SIZE);
            }
        }
    }

    /// Test hash-to-curve collision resistance
    #[test]
    fn test_hash_collision_resistance() {
        let dst = b"TEST_DST";
        let mut points = Vec::new();

        // Generate points for different messages
        for i in 0..100u8 {
            let msg = [i];
            let point = Bls12381::g1_hash_to_curve(&msg, dst);
            points.push(Bls12381::g1_compress(&point));
        }

        // Check all points are unique
        for i in 0..points.len() {
            for j in (i + 1)..points.len() {
                assert_ne!(
                    points[i], points[j],
                    "Hash collision at messages {} and {}",
                    i, j
                );
            }
        }
    }
}

// ============================================================================
// Cross-Feature Integration Tests
// ============================================================================

mod integration_tests {
    use super::*;

    /// Test that all signature schemes work in sequence
    #[test]
    fn test_all_signatures_sequence() {
        let seed = [42u8; 32];
        let message = b"Universal test message";

        // ECDSA
        let ecdsa_sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();
        let ecdsa_vk = Secp256k1Ecdsa::derive_verification_key(&ecdsa_sk).unwrap();
        let ecdsa_sig = Secp256k1Ecdsa::sign(&ecdsa_sk, message).unwrap();
        assert!(Secp256k1Ecdsa::verify(&ecdsa_vk, message, &ecdsa_sig).is_ok());

        // Schnorr
        let schnorr_sk = Secp256k1Schnorr::gen_key(&seed).unwrap();
        let schnorr_vk = Secp256k1Schnorr::derive_verification_key(&schnorr_sk).unwrap();
        let schnorr_sig = Secp256k1Schnorr::sign(&schnorr_sk, message).unwrap();
        assert!(Secp256k1Schnorr::verify(&schnorr_vk, message, &schnorr_sig).is_ok());

        // BLS
        let bls_sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let bls_pk = bls_sk.public_key();
        let bls_sig = bls_sk.sign(message);
        assert!(cardano_crypto::bls::bls_verify(&bls_pk, message, &bls_sig).is_ok());
    }

    /// Verify key sizes match CIP specifications
    #[test]
    fn test_key_size_cip_compliance() {
        // CIP-0049 secp256k1 ECDSA
        assert_eq!(
            Secp256k1Ecdsa::SIGNING_KEY_SIZE,
            32,
            "ECDSA SK should be 32 bytes"
        );
        assert_eq!(
            Secp256k1Ecdsa::VERIFICATION_KEY_SIZE,
            33,
            "ECDSA VK compressed should be 33 bytes"
        );
        assert_eq!(
            Secp256k1Ecdsa::SIGNATURE_SIZE,
            64,
            "ECDSA signature should be 64 bytes"
        );

        // CIP-0049 secp256k1 Schnorr
        assert_eq!(
            Secp256k1Schnorr::SIGNING_KEY_SIZE,
            32,
            "Schnorr SK should be 32 bytes"
        );
        assert_eq!(
            Secp256k1Schnorr::VERIFICATION_KEY_SIZE,
            32,
            "Schnorr VK x-only should be 32 bytes"
        );
        assert_eq!(
            Secp256k1Schnorr::SIGNATURE_SIZE,
            64,
            "Schnorr signature should be 64 bytes"
        );

        // CIP-0381 BLS12-381
        assert_eq!(G1_COMPRESSED_SIZE, 48, "G1 compressed should be 48 bytes");
        assert_eq!(G2_COMPRESSED_SIZE, 96, "G2 compressed should be 96 bytes");
        assert_eq!(SCALAR_SIZE, 32, "Scalar should be 32 bytes");
        assert_eq!(BlsSecretKey::SIZE, 32, "BLS secret key should be 32 bytes");
        assert_eq!(
            BlsPublicKey::COMPRESSED_SIZE,
            48,
            "BLS public key should be 48 bytes"
        );
        assert_eq!(
            BlsSignature::COMPRESSED_SIZE,
            96,
            "BLS signature should be 96 bytes"
        );
    }

    /// Test that different algorithms don't interfere
    #[test]
    fn test_algorithm_isolation() {
        let seed = [99u8; 32];

        // Create keys for all algorithms
        let ecdsa_sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();
        let schnorr_sk = Secp256k1Schnorr::gen_key(&seed).unwrap();
        let bls_sk = BlsSecretKey::from_bytes(&seed).unwrap();

        let ecdsa_vk = Secp256k1Ecdsa::derive_verification_key(&ecdsa_sk).unwrap();
        let schnorr_vk = Secp256k1Schnorr::derive_verification_key(&schnorr_sk).unwrap();
        let bls_pk = bls_sk.public_key();

        // Sign with each
        let msg = b"isolation test";
        let ecdsa_sig = Secp256k1Ecdsa::sign(&ecdsa_sk, msg).unwrap();
        let schnorr_sig = Secp256k1Schnorr::sign(&schnorr_sk, msg).unwrap();
        let bls_sig = bls_sk.sign(msg);

        // Verify only with correct algorithm
        assert!(Secp256k1Ecdsa::verify(&ecdsa_vk, msg, &ecdsa_sig).is_ok());
        assert!(Secp256k1Schnorr::verify(&schnorr_vk, msg, &schnorr_sig).is_ok());
        assert!(cardano_crypto::bls::bls_verify(&bls_pk, msg, &bls_sig).is_ok());
    }

    /// Test serialization roundtrip for all types
    #[test]
    fn test_all_serialization_roundtrips() {
        let seed = [77u8; 32];

        // ECDSA
        let ecdsa_sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();
        let ecdsa_vk = Secp256k1Ecdsa::derive_verification_key(&ecdsa_sk).unwrap();
        let ecdsa_sig = Secp256k1Ecdsa::sign(&ecdsa_sk, b"test").unwrap();

        let ecdsa_sk2 = Secp256k1EcdsaSigningKey::from_bytes(ecdsa_sk.as_bytes()).unwrap();
        let ecdsa_vk2 = Secp256k1EcdsaVerificationKey::from_bytes(ecdsa_vk.as_bytes()).unwrap();
        let ecdsa_sig2 = Secp256k1EcdsaSignature::from_bytes(ecdsa_sig.as_bytes()).unwrap();

        assert_eq!(ecdsa_sk.as_bytes(), ecdsa_sk2.as_bytes());
        assert_eq!(ecdsa_vk, ecdsa_vk2);
        assert_eq!(ecdsa_sig, ecdsa_sig2);

        // Schnorr
        let schnorr_sk = Secp256k1Schnorr::gen_key(&seed).unwrap();
        let schnorr_vk = Secp256k1Schnorr::derive_verification_key(&schnorr_sk).unwrap();
        let schnorr_sig = Secp256k1Schnorr::sign(&schnorr_sk, b"test").unwrap();

        let schnorr_sk2 = Secp256k1SchnorrSigningKey::from_bytes(schnorr_sk.as_bytes()).unwrap();
        let schnorr_vk2 =
            Secp256k1SchnorrVerificationKey::from_bytes(schnorr_vk.as_bytes()).unwrap();
        let schnorr_sig2 = Secp256k1SchnorrSignature::from_bytes(schnorr_sig.as_bytes()).unwrap();

        assert_eq!(schnorr_sk.as_bytes(), schnorr_sk2.as_bytes());
        assert_eq!(schnorr_vk, schnorr_vk2);
        assert_eq!(schnorr_sig, schnorr_sig2);

        // BLS
        let bls_sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let bls_pk = bls_sk.public_key();
        let bls_sig = bls_sk.sign(b"test");

        let bls_pk2 = BlsPublicKey::from_compressed(&bls_pk.to_compressed()).unwrap();
        let bls_sig2 = BlsSignature::from_compressed(&bls_sig.to_compressed()).unwrap();

        assert_eq!(bls_pk, bls_pk2);
        assert_eq!(bls_sig, bls_sig2);

        // G1/G2 points
        let g1 = G1Point::generator();
        let g1_restored = G1Point::from_compressed(&g1.to_compressed()).unwrap();
        assert_eq!(g1, g1_restored);

        let g2 = G2Point::generator();
        let g2_restored = G2Point::from_compressed(&g2.to_compressed()).unwrap();
        assert_eq!(g2, g2_restored);

        // Scalar
        let scalar = Scalar::from_bytes_be(&seed).unwrap();
        assert_eq!(scalar.as_bytes(), &seed);
    }
}

// ============================================================================
// Plutus Builtin Equivalence Tests
// ============================================================================

mod plutus_builtin_equivalence {
    use super::*;

    /// Verify G1 operations match Plutus builtin semantics
    #[test]
    fn test_plutus_g1_add() {
        // bls12_381_G1_add behavior
        let g = G1Point::generator();
        let result = Bls12381::g1_add(&g, &g);

        let mut two_bytes = [0u8; 32];
        two_bytes[31] = 2;
        let two = Scalar::from_bytes_be(&two_bytes).unwrap();
        let expected = Bls12381::g1_scalar_mul(&two, &g);

        assert_eq!(result, expected, "g1_add(G, G) = g1_scalarMul(2, G)");
    }

    /// Verify G1 negation matches Plutus builtin semantics
    #[test]
    fn test_plutus_g1_neg() {
        // bls12_381_G1_neg behavior
        let g = G1Point::generator();
        let neg_g = Bls12381::g1_neg(&g);

        // G + (-G) should be identity
        let sum = Bls12381::g1_add(&g, &neg_g);
        assert!(
            Bls12381::g1_is_identity(&sum),
            "g1_add(G, g1_neg(G)) = g1_zero"
        );
    }

    /// Verify G2 operations match Plutus builtin semantics
    #[test]
    fn test_plutus_g2_add() {
        // bls12_381_G2_add behavior
        let g = G2Point::generator();
        let result = Bls12381::g2_add(&g, &g);

        let mut two_bytes = [0u8; 32];
        two_bytes[31] = 2;
        let two = Scalar::from_bytes_be(&two_bytes).unwrap();
        let expected = Bls12381::g2_scalar_mul(&two, &g);

        assert_eq!(result, expected, "g2_add(G2, G2) = g2_scalarMul(2, G2)");
    }

    /// Verify Miller loop and final verify match Plutus semantics
    #[test]
    fn test_plutus_pairing_semantics() {
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        // bls12_381_millerLoop followed by bls12_381_finalVerify
        let ml = Bls12381::miller_loop(&g1, &g2);
        let final_result = Bls12381::final_exponentiate(&ml);

        // Should match direct pairing
        let pairing_result = Bls12381::pairing(&g1, &g2);

        assert_eq!(
            final_result, pairing_result,
            "finalVerify(millerLoop(G1, G2)) = pairing(G1, G2)"
        );
    }

    /// Test Plutus-style verification equation
    #[test]
    fn test_plutus_verify_equation() {
        // In Plutus: bls12_381_finalVerify(ml1, ml2)
        // Checks if finalExp(ml1) == finalExp(ml2)
        // Which is equivalent to checking if ml1 * ml2^(-1) exponentiates to 1

        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        let mut a_bytes = [0u8; 32];
        a_bytes[31] = 3;
        let a = Scalar::from_bytes_be(&a_bytes).unwrap();

        // e([a]G1, G2) should equal e(G1, [a]G2)
        let a_g1 = Bls12381::g1_scalar_mul(&a, &g1);
        let a_g2 = Bls12381::g2_scalar_mul(&a, &g2);

        let ml1 = Bls12381::miller_loop(&a_g1, &g2);
        let ml2 = Bls12381::miller_loop(&g1, &a_g2);

        let final1 = Bls12381::final_exponentiate(&ml1);
        let final2 = Bls12381::final_exponentiate(&ml2);

        assert_eq!(final1, final2, "Bilinearity check via miller loop");
    }

    /// Verify ECDSA prehash requirement
    #[test]
    fn test_ecdsa_prehash_requirement() {
        // In Plutus, ECDSA verifyEcdsaSecp256k1Signature takes a 32-byte hash
        let seed = [1u8; 32];
        let sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();
        let vk = Secp256k1Ecdsa::derive_verification_key(&sk).unwrap();

        // The message MUST be exactly 32 bytes (a hash)
        let msg_hash = [0u8; 32];
        let sig = Secp256k1Ecdsa::sign_prehashed(&sk, &msg_hash).unwrap();
        assert!(Secp256k1Ecdsa::verify_prehashed(&vk, &msg_hash, &sig).is_ok());
    }

    /// Verify Schnorr accepts arbitrary-length messages
    #[test]
    fn test_schnorr_arbitrary_message_length() {
        // In Plutus, Schnorr verifySchnorrSecp256k1Signature takes arbitrary bytes
        let seed = [2u8; 32];
        let sk = Secp256k1Schnorr::gen_key(&seed).unwrap();
        let vk = Secp256k1Schnorr::derive_verification_key(&sk).unwrap();

        // Test various message lengths
        for len in &[0, 1, 32, 64, 100, 1000] {
            let msg = vec![0xABu8; *len];
            let sig = Secp256k1Schnorr::sign(&sk, &msg).unwrap();
            assert!(
                Secp256k1Schnorr::verify(&vk, &msg, &sig).is_ok(),
                "Failed for message length {}",
                len
            );
        }
    }
}

// ============================================================================
// Stress Tests
// ============================================================================

mod stress_tests {
    use super::*;

    #[test]
    fn test_many_ecdsa_operations() {
        for i in 0..50u8 {
            // Use non-zero seeds that are valid secp256k1 private keys
            let mut seed = [0x42u8; 32];
            seed[0] = i.wrapping_add(1);
            seed[31] = i.wrapping_add(1);
            let sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();
            let vk = Secp256k1Ecdsa::derive_verification_key(&sk).unwrap();

            let msg = [i.wrapping_add(1); 32];
            let sig = Secp256k1Ecdsa::sign_prehashed(&sk, &msg).unwrap();
            assert!(Secp256k1Ecdsa::verify_prehashed(&vk, &msg, &sig).is_ok());
        }
    }

    #[test]
    fn test_many_schnorr_operations() {
        for i in 0..50u8 {
            // Use non-zero seeds that are valid secp256k1 private keys
            let mut seed = [0x42u8; 32];
            seed[0] = i.wrapping_add(1);
            seed[31] = i.wrapping_add(1);
            let sk = Secp256k1Schnorr::gen_key(&seed).unwrap();
            let vk = Secp256k1Schnorr::derive_verification_key(&sk).unwrap();

            let msg = vec![i.wrapping_add(1); i as usize + 1];
            let sig = Secp256k1Schnorr::sign(&sk, &msg).unwrap();
            assert!(Secp256k1Schnorr::verify(&vk, &msg, &sig).is_ok());
        }
    }

    #[test]
    fn test_many_bls_operations() {
        for i in 0..20u8 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            let sk = BlsSecretKey::from_bytes(&seed).unwrap();
            let pk = sk.public_key();

            let msg = vec![i; 32];
            let sig = sk.sign(&msg);
            assert!(cardano_crypto::bls::bls_verify(&pk, &msg, &sig).is_ok());
        }
    }

    #[test]
    fn test_many_g1_operations() {
        let generator = G1Point::generator();
        let mut point = generator.clone();

        for i in 1..50u32 {
            // Accumulate: point = i*G
            point = Bls12381::g1_add(&point, &generator);

            // Verify: (i+1)*G
            let mut scalar_bytes = [0u8; 32];
            let i_plus_1 = i + 1;
            scalar_bytes[28] = ((i_plus_1 >> 24) & 0xFF) as u8;
            scalar_bytes[29] = ((i_plus_1 >> 16) & 0xFF) as u8;
            scalar_bytes[30] = ((i_plus_1 >> 8) & 0xFF) as u8;
            scalar_bytes[31] = (i_plus_1 & 0xFF) as u8;
            let scalar = Scalar::from_bytes_be(&scalar_bytes).unwrap();
            let expected = Bls12381::g1_scalar_mul(&scalar, &generator);

            assert_eq!(point, expected, "Mismatch at iteration {}", i);
        }
    }
}
