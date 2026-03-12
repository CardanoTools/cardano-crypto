//! Tests for Plutus-compatible cryptographic primitives (CIP-0049, CIP-0381)
//!
//! These tests verify compatibility with Cardano Plutus smart contract builtins.

#![cfg(all(feature = "secp256k1", feature = "bls"))]

use cardano_crypto::bls::{
    bls_verify, bls_verify_with_dst, Bls12381, BlsPublicKey, BlsSecretKey, BlsSignature, G1Point,
    G2Point, Scalar, G1_COMPRESSED_SIZE, G2_COMPRESSED_SIZE, SCALAR_SIZE,
};
use cardano_crypto::dsign::secp256k1::{
    Secp256k1Ecdsa, Secp256k1EcdsaSignature, Secp256k1EcdsaSigningKey,
    Secp256k1EcdsaVerificationKey, Secp256k1Schnorr, Secp256k1SchnorrSignature,
    Secp256k1SchnorrSigningKey, Secp256k1SchnorrVerificationKey,
};

// ============================================================================
// secp256k1 ECDSA Tests (CIP-0049)
// ============================================================================

mod ecdsa_tests {
    use super::*;

    #[test]
    fn test_ecdsa_key_generation() {
        let seed = [1u8; 32];
        let sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();
        let vk = Secp256k1Ecdsa::derive_verification_key(&sk).unwrap();

        assert_eq!(sk.as_bytes().len(), 32);
        assert_eq!(vk.as_bytes().len(), 33);
    }

    #[test]
    fn test_ecdsa_sign_verify() {
        let seed = [2u8; 32];
        let sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();
        let vk = Secp256k1Ecdsa::derive_verification_key(&sk).unwrap();

        let message = b"Hello, Cardano Plutus!";
        let signature = Secp256k1Ecdsa::sign(&sk, message).unwrap();

        assert!(Secp256k1Ecdsa::verify(&vk, message, &signature).is_ok());
    }

    #[test]
    fn test_ecdsa_wrong_message() {
        let seed = [3u8; 32];
        let sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();
        let vk = Secp256k1Ecdsa::derive_verification_key(&sk).unwrap();

        let message = b"Original message";
        let signature = Secp256k1Ecdsa::sign(&sk, message).unwrap();

        assert!(Secp256k1Ecdsa::verify(&vk, b"Modified message", &signature).is_err());
    }

    #[test]
    fn test_ecdsa_wrong_key() {
        let seed1 = [4u8; 32];
        let seed2 = [5u8; 32];
        let sk1 = Secp256k1Ecdsa::gen_key(&seed1).unwrap();
        let sk2 = Secp256k1Ecdsa::gen_key(&seed2).unwrap();
        let vk2 = Secp256k1Ecdsa::derive_verification_key(&sk2).unwrap();

        let message = b"Test message";
        let signature = Secp256k1Ecdsa::sign(&sk1, message).unwrap();

        // Signature from sk1 should not verify with vk2
        assert!(Secp256k1Ecdsa::verify(&vk2, message, &signature).is_err());
    }

    #[test]
    fn test_ecdsa_key_roundtrip() {
        let seed = [6u8; 32];
        let sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();
        let vk = Secp256k1Ecdsa::derive_verification_key(&sk).unwrap();

        let sk_bytes = sk.as_bytes().to_vec();
        let vk_bytes = vk.as_bytes().to_vec();

        let sk_restored = Secp256k1EcdsaSigningKey::from_bytes(&sk_bytes).unwrap();
        let vk_restored = Secp256k1EcdsaVerificationKey::from_bytes(&vk_bytes).unwrap();

        assert_eq!(sk.as_bytes(), sk_restored.as_bytes());
        assert_eq!(vk, vk_restored);
    }

    #[test]
    fn test_ecdsa_signature_roundtrip() {
        let seed = [7u8; 32];
        let sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();

        let message = b"Roundtrip test";
        let signature = Secp256k1Ecdsa::sign(&sk, message).unwrap();

        let sig_bytes = signature.as_bytes().to_vec();
        let sig_restored = Secp256k1EcdsaSignature::from_bytes(&sig_bytes).unwrap();

        assert_eq!(signature, sig_restored);
    }

    #[test]
    fn test_ecdsa_prehashed() {
        use sha2::{Digest, Sha256};

        let seed = [8u8; 32];
        let sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();
        let vk = Secp256k1Ecdsa::derive_verification_key(&sk).unwrap();

        let message = b"Pre-hashed message for Plutus";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash: [u8; 32] = hasher.finalize().into();

        let signature = Secp256k1Ecdsa::sign_prehashed(&sk, &hash).unwrap();
        assert!(Secp256k1Ecdsa::verify_prehashed(&vk, &hash, &signature).is_ok());
    }

    #[test]
    fn test_ecdsa_deterministic() {
        let seed = [9u8; 32];
        let sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();

        let message = b"Deterministic test";
        let sig1 = Secp256k1Ecdsa::sign(&sk, message).unwrap();
        let sig2 = Secp256k1Ecdsa::sign(&sk, message).unwrap();

        // ECDSA is deterministic with RFC 6979
        assert_eq!(sig1, sig2);
    }
}

// ============================================================================
// secp256k1 Schnorr Tests (CIP-0049, BIP-340)
// ============================================================================

mod schnorr_tests {
    use super::*;

    #[test]
    fn test_schnorr_key_generation() {
        let seed = [10u8; 32];
        let sk = Secp256k1Schnorr::gen_key(&seed).unwrap();
        let vk = Secp256k1Schnorr::derive_verification_key(&sk).unwrap();

        assert_eq!(sk.as_bytes().len(), 32);
        assert_eq!(vk.as_bytes().len(), 32); // x-only public key
    }

    #[test]
    fn test_schnorr_sign_verify() {
        let seed = [11u8; 32];
        let sk = Secp256k1Schnorr::gen_key(&seed).unwrap();
        let vk = Secp256k1Schnorr::derive_verification_key(&sk).unwrap();

        let message = b"Schnorr signature for Plutus!";
        let signature = Secp256k1Schnorr::sign(&sk, message).unwrap();

        assert!(Secp256k1Schnorr::verify(&vk, message, &signature).is_ok());
    }

    #[test]
    fn test_schnorr_wrong_message() {
        let seed = [12u8; 32];
        let sk = Secp256k1Schnorr::gen_key(&seed).unwrap();
        let vk = Secp256k1Schnorr::derive_verification_key(&sk).unwrap();

        let message = b"Original Schnorr message";
        let signature = Secp256k1Schnorr::sign(&sk, message).unwrap();

        assert!(Secp256k1Schnorr::verify(&vk, b"Different message", &signature).is_err());
    }

    #[test]
    fn test_schnorr_key_roundtrip() {
        let seed = [13u8; 32];
        let sk = Secp256k1Schnorr::gen_key(&seed).unwrap();
        let vk = Secp256k1Schnorr::derive_verification_key(&sk).unwrap();

        let sk_bytes = sk.as_bytes().to_vec();
        let vk_bytes = vk.as_bytes().to_vec();

        let sk_restored = Secp256k1SchnorrSigningKey::from_bytes(&sk_bytes).unwrap();
        let vk_restored = Secp256k1SchnorrVerificationKey::from_bytes(&vk_bytes).unwrap();

        assert_eq!(sk.as_bytes(), sk_restored.as_bytes());
        assert_eq!(vk, vk_restored);
    }

    #[test]
    fn test_schnorr_signature_roundtrip() {
        let seed = [14u8; 32];
        let sk = Secp256k1Schnorr::gen_key(&seed).unwrap();

        let message = b"Schnorr roundtrip";
        let signature = Secp256k1Schnorr::sign(&sk, message).unwrap();

        let sig_bytes = signature.as_bytes().to_vec();
        let sig_restored = Secp256k1SchnorrSignature::from_bytes(&sig_bytes).unwrap();

        assert_eq!(signature, sig_restored);
    }

    #[test]
    fn test_schnorr_prehashed() {
        use sha2::{Digest, Sha256};

        let seed = [15u8; 32];
        let sk = Secp256k1Schnorr::gen_key(&seed).unwrap();
        let vk = Secp256k1Schnorr::derive_verification_key(&sk).unwrap();

        let message = b"Pre-hashed Schnorr message";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash: [u8; 32] = hasher.finalize().into();

        let signature = Secp256k1Schnorr::sign_prehashed(&sk, &hash).unwrap();
        assert!(Secp256k1Schnorr::verify_prehashed(&vk, &hash, &signature).is_ok());
    }
}

// ============================================================================
// BLS12-381 G1 Tests (CIP-0381)
// ============================================================================

mod bls_g1_tests {
    use super::*;

    #[test]
    fn test_g1_generator() {
        let gen = G1Point::generator();
        assert!(!Bls12381::g1_is_identity(&gen));
    }

    #[test]
    fn test_g1_identity() {
        let id = G1Point::identity();
        assert!(Bls12381::g1_is_identity(&id));
    }

    #[test]
    fn test_g1_add_identity() {
        let gen = G1Point::generator();
        let id = G1Point::identity();
        let result = Bls12381::g1_add(&gen, &id);
        assert_eq!(gen, result);
    }

    #[test]
    fn test_g1_neg() {
        let gen = G1Point::generator();
        let neg = Bls12381::g1_neg(&gen);
        let sum = Bls12381::g1_add(&gen, &neg);
        assert!(Bls12381::g1_is_identity(&sum));
    }

    #[test]
    fn test_g1_scalar_mul() {
        let gen = G1Point::generator();

        // 2 * G = G + G
        let mut two_bytes = [0u8; 32];
        two_bytes[31] = 2;
        let two = Scalar::from_bytes_be(&two_bytes).unwrap();

        let doubled = Bls12381::g1_scalar_mul(&two, &gen);
        let also_doubled = Bls12381::g1_add(&gen, &gen);

        assert_eq!(doubled, also_doubled);
    }

    #[test]
    fn test_g1_compress_uncompress() {
        let gen = G1Point::generator();
        let compressed = Bls12381::g1_compress(&gen);
        let restored = Bls12381::g1_uncompress(&compressed).unwrap();
        assert_eq!(gen, restored);
    }

    #[test]
    fn test_g1_compress_size() {
        let gen = G1Point::generator();
        let compressed = Bls12381::g1_compress(&gen);
        assert_eq!(compressed.len(), G1_COMPRESSED_SIZE);
    }

    #[test]
    fn test_g1_hash_to_curve() {
        let dst = b"BLS12381G1_XMD:SHA-256_SSWU_RO_";
        let msg1 = b"message1";
        let msg2 = b"message2";

        let p1 = Bls12381::g1_hash_to_curve(msg1, dst);
        let p2 = Bls12381::g1_hash_to_curve(msg2, dst);

        // Different messages should hash to different points
        assert_ne!(p1, p2);

        // Same message should hash to same point
        let p1_again = Bls12381::g1_hash_to_curve(msg1, dst);
        assert_eq!(p1, p1_again);
    }
}

// ============================================================================
// BLS12-381 G2 Tests (CIP-0381)
// ============================================================================

mod bls_g2_tests {
    use super::*;

    #[test]
    fn test_g2_generator() {
        let gen = G2Point::generator();
        assert!(!Bls12381::g2_is_identity(&gen));
    }

    #[test]
    fn test_g2_identity() {
        let id = G2Point::identity();
        assert!(Bls12381::g2_is_identity(&id));
    }

    #[test]
    fn test_g2_add_identity() {
        let gen = G2Point::generator();
        let id = G2Point::identity();
        let result = Bls12381::g2_add(&gen, &id);
        assert_eq!(gen, result);
    }

    #[test]
    fn test_g2_neg() {
        let gen = G2Point::generator();
        let neg = Bls12381::g2_neg(&gen);
        let sum = Bls12381::g2_add(&gen, &neg);
        assert!(Bls12381::g2_is_identity(&sum));
    }

    #[test]
    fn test_g2_scalar_mul() {
        let gen = G2Point::generator();

        let mut three_bytes = [0u8; 32];
        three_bytes[31] = 3;
        let three = Scalar::from_bytes_be(&three_bytes).unwrap();

        let tripled = Bls12381::g2_scalar_mul(&three, &gen);
        let also_tripled = Bls12381::g2_add(&gen, &Bls12381::g2_add(&gen, &gen));

        assert_eq!(tripled, also_tripled);
    }

    #[test]
    fn test_g2_compress_uncompress() {
        let gen = G2Point::generator();
        let compressed = Bls12381::g2_compress(&gen);
        let restored = Bls12381::g2_uncompress(&compressed).unwrap();
        assert_eq!(gen, restored);
    }

    #[test]
    fn test_g2_compress_size() {
        let gen = G2Point::generator();
        let compressed = Bls12381::g2_compress(&gen);
        assert_eq!(compressed.len(), G2_COMPRESSED_SIZE);
    }

    #[test]
    fn test_g2_hash_to_curve() {
        let dst = b"BLS12381G2_XMD:SHA-256_SSWU_RO_";
        let msg1 = b"message1";
        let msg2 = b"message2";

        let p1 = Bls12381::g2_hash_to_curve(msg1, dst);
        let p2 = Bls12381::g2_hash_to_curve(msg2, dst);

        assert_ne!(p1, p2);

        let p1_again = Bls12381::g2_hash_to_curve(msg1, dst);
        assert_eq!(p1, p1_again);
    }
}

// ============================================================================
// BLS12-381 Pairing Tests (CIP-0381)
// ============================================================================

mod bls_pairing_tests {
    use super::*;

    #[test]
    fn test_pairing_bilinearity() {
        // Test: e(aG1, bG2) = e(abG1, G2) = e(G1, abG2)
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        let mut a_bytes = [0u8; 32];
        a_bytes[31] = 5;
        let a = Scalar::from_bytes_be(&a_bytes).unwrap();

        let mut b_bytes = [0u8; 32];
        b_bytes[31] = 7;
        let b = Scalar::from_bytes_be(&b_bytes).unwrap();

        // e(aG1, bG2)
        let ag1 = Bls12381::g1_scalar_mul(&a, &g1);
        let bg2 = Bls12381::g2_scalar_mul(&b, &g2);
        let result1 = Bls12381::pairing(&ag1, &bg2);

        // e(abG1, G2)
        let mut ab_bytes = [0u8; 32];
        ab_bytes[31] = 35; // 5 * 7
        let ab = Scalar::from_bytes_be(&ab_bytes).unwrap();
        let abg1 = Bls12381::g1_scalar_mul(&ab, &g1);
        let result2 = Bls12381::pairing(&abg1, &g2);

        // e(G1, abG2)
        let abg2 = Bls12381::g2_scalar_mul(&ab, &g2);
        let result3 = Bls12381::pairing(&g1, &abg2);

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_pairing_non_degeneracy() {
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        let result = Bls12381::pairing(&g1, &g2);

        // e(G1, G2) should not be one (non-degeneracy)
        assert!(!result.is_one());
    }

    #[test]
    fn test_pairing_identity() {
        let g1 = G1Point::generator();
        let g2 = G2Point::identity();

        // e(G1, 0) should be one
        let result = Bls12381::pairing(&g1, &g2);
        assert!(result.is_one());
    }

    #[test]
    fn test_miller_loop_and_final_exp() {
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        // Miller loop + final exp should equal pairing
        let ml = Bls12381::miller_loop(&g1, &g2);
        let result1 = Bls12381::final_exponentiate(&ml);
        let result2 = Bls12381::pairing(&g1, &g2);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_pairing_equation_verify() {
        // Verify: e(G1, G2) * e(-G1, G2) = 1
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();
        let neg_g1 = Bls12381::g1_neg(&g1);

        let valid = Bls12381::verify_pairing_equation(&[(g1, g2.clone()), (neg_g1, g2)]);

        assert!(valid);
    }
}

// ============================================================================
// BLS Signature Tests
// ============================================================================

mod bls_signature_tests {
    use super::*;

    #[test]
    fn test_bls_sign_verify() {
        let seed = [42u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        let message = b"Hello, Cardano!";
        let signature = sk.sign(message);

        assert!(bls_verify(&pk, message, &signature).is_ok());
    }

    #[test]
    fn test_bls_wrong_message() {
        let seed = [43u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        let message = b"Original";
        let signature = sk.sign(message);

        assert!(bls_verify(&pk, b"Modified", &signature).is_err());
    }

    #[test]
    fn test_bls_wrong_key() {
        let seed1 = [44u8; 32];
        let seed2 = [45u8; 32];
        let sk1 = BlsSecretKey::from_bytes(&seed1).unwrap();
        let sk2 = BlsSecretKey::from_bytes(&seed2).unwrap();
        let pk2 = sk2.public_key();

        let message = b"Test";
        let signature = sk1.sign(message);

        // Signature from sk1 should not verify with pk2
        assert!(bls_verify(&pk2, message, &signature).is_err());
    }

    #[test]
    fn test_bls_key_roundtrip() {
        let seed = [46u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        let pk_compressed = pk.to_compressed();
        let pk_restored = BlsPublicKey::from_compressed(&pk_compressed).unwrap();

        assert_eq!(pk, pk_restored);
    }

    #[test]
    fn test_bls_signature_roundtrip() {
        let seed = [47u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();

        let message = b"Roundtrip";
        let signature = sk.sign(message);

        let sig_compressed = signature.to_compressed();
        let sig_restored = BlsSignature::from_compressed(&sig_compressed).unwrap();

        assert_eq!(signature, sig_restored);
    }

    #[test]
    fn test_bls_custom_dst() {
        let seed = [48u8; 32];
        let sk = BlsSecretKey::from_bytes(&seed).unwrap();
        let pk = sk.public_key();

        let message = b"Custom DST message";
        let dst = b"CUSTOM_DST_FOR_TESTING";
        let signature = sk.sign_with_dst(message, dst);

        assert!(bls_verify_with_dst(&pk, message, &signature, dst).is_ok());

        // Wrong DST should fail
        assert!(bls_verify_with_dst(&pk, message, &signature, b"WRONG_DST").is_err());
    }

    #[test]
    fn test_bls_key_sizes() {
        assert_eq!(BlsSecretKey::SIZE, SCALAR_SIZE);
        assert_eq!(BlsPublicKey::COMPRESSED_SIZE, G1_COMPRESSED_SIZE);
        assert_eq!(BlsSignature::COMPRESSED_SIZE, G2_COMPRESSED_SIZE);
    }
}

// ============================================================================
// Scalar Tests
// ============================================================================

mod scalar_tests {
    use super::*;

    #[test]
    fn test_scalar_roundtrip() {
        let bytes = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc, 0xde, 0xf0,
        ];
        let scalar = Scalar::from_bytes_be(&bytes).unwrap();
        assert_eq!(scalar.as_bytes(), &bytes);
    }

    #[test]
    fn test_scalar_size() {
        assert_eq!(Scalar::SIZE, 32);
    }

    #[test]
    fn test_scalar_zero() {
        let zero = [0u8; 32];
        let scalar = Scalar::from_bytes_be(&zero).unwrap();

        let g1 = G1Point::generator();
        let result = Bls12381::g1_scalar_mul(&scalar, &g1);

        // 0 * G = identity
        assert!(Bls12381::g1_is_identity(&result));
    }

    #[test]
    fn test_scalar_one() {
        let mut one = [0u8; 32];
        one[31] = 1;
        let scalar = Scalar::from_bytes_be(&one).unwrap();

        let g1 = G1Point::generator();
        let result = Bls12381::g1_scalar_mul(&scalar, &g1);

        // 1 * G = G
        assert_eq!(result, g1);
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

mod integration_tests {
    use super::*;

    #[test]
    fn test_all_signature_types() {
        // Test that all three signature types work correctly
        let seed = [100u8; 32];
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
        assert!(bls_verify(&bls_pk, message, &bls_sig).is_ok());
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        // ECDSA
        let ecdsa_vk1 =
            Secp256k1Ecdsa::derive_verification_key(&Secp256k1Ecdsa::gen_key(&seed1).unwrap())
                .unwrap();
        let ecdsa_vk2 =
            Secp256k1Ecdsa::derive_verification_key(&Secp256k1Ecdsa::gen_key(&seed2).unwrap())
                .unwrap();
        assert_ne!(ecdsa_vk1, ecdsa_vk2);

        // Schnorr
        let schnorr_vk1 =
            Secp256k1Schnorr::derive_verification_key(&Secp256k1Schnorr::gen_key(&seed1).unwrap())
                .unwrap();
        let schnorr_vk2 =
            Secp256k1Schnorr::derive_verification_key(&Secp256k1Schnorr::gen_key(&seed2).unwrap())
                .unwrap();
        assert_ne!(schnorr_vk1, schnorr_vk2);

        // BLS
        let bls_pk1 = BlsSecretKey::from_bytes(&seed1).unwrap().public_key();
        let bls_pk2 = BlsSecretKey::from_bytes(&seed2).unwrap().public_key();
        assert_ne!(bls_pk1, bls_pk2);
    }
}
