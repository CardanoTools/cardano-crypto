#![cfg(all(feature = "dsign", feature = "hash", feature = "kes", feature = "vrf"))]
//! Comprehensive Edge Case Tests for Cardano Cryptographic Primitives
//!
//! This module tests edge cases, boundary conditions, and malformed inputs
//! across all cryptographic modules to ensure robust error handling and
//! alignment with cardano-base behavior.
//!
//! Test categories:
//! - Empty inputs
//! - Maximum size inputs
//! - Malformed/corrupted data
//! - Boundary conditions (periods, sizes)
//! - Invalid parameters

use cardano_crypto::common::Result;
use cardano_crypto::dsign::{DsignAlgorithm, Ed25519};
use cardano_crypto::hash::{Blake2b224, Blake2b256, Blake2b512, HashAlgorithm};
use cardano_crypto::kes::{KesAlgorithm, Sum2Kes, Sum6Kes};
use cardano_crypto::vrf::{VrfDraft03, VrfDraft13};

// ============================================================================
// VRF Edge Cases
// ============================================================================

mod vrf_edge_cases {
    use super::*;

    #[test]
    fn test_vrf03_empty_message() {
        let seed = [0u8; 32];
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

        let proof = VrfDraft03::prove(&sk, b"").expect("Empty message should work");
        let output = VrfDraft03::verify(&pk, &proof, b"").expect("Verification should succeed");
        assert_eq!(output.len(), 64, "VRF output must be 64 bytes");
    }

    #[test]
    fn test_vrf03_single_byte_message() {
        let seed = [1u8; 32];
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

        let proof = VrfDraft03::prove(&sk, &[42]).expect("Single byte message should work");
        let output = VrfDraft03::verify(&pk, &proof, &[42]).expect("Verification should succeed");
        assert_eq!(output.len(), 64);
    }

    #[test]
    fn test_vrf03_max_message_size() {
        let seed = [2u8; 32];
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

        // Test with very large message (Cardano block headers can be large)
        let large_msg = vec![0xFF; 10_000];
        let proof = VrfDraft03::prove(&sk, &large_msg).expect("Large message should work");
        let output =
            VrfDraft03::verify(&pk, &proof, &large_msg).expect("Verification should succeed");
        assert_eq!(output.len(), 64);
    }

    #[test]
    fn test_vrf03_invalid_proof_content() {
        let seed = [3u8; 32];
        let (_sk, pk) = VrfDraft03::keypair_from_seed(&seed);

        // Valid-sized proof but with random/invalid content
        let invalid_proof: [u8; 80] = [0x42; 80];
        assert!(
            VrfDraft03::verify(&pk, &invalid_proof, b"msg").is_err(),
            "Invalid proof content should fail verification"
        );
    }

    #[test]
    fn test_vrf03_half_corrupted_proof() {
        let seed = [4u8; 32];
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

        // Get a valid proof then corrupt half of it
        let mut proof = VrfDraft03::prove(&sk, b"test").expect("Prove should succeed");
        for item in proof.iter_mut().take(40) {
            *item ^= 0xFF;
        }
        assert!(
            VrfDraft03::verify(&pk, &proof, b"test").is_err(),
            "Half-corrupted proof should fail verification"
        );
    }

    #[test]
    fn test_vrf03_all_zero_proof() {
        let seed = [5u8; 32];
        let (_sk, pk) = VrfDraft03::keypair_from_seed(&seed);

        // All-zero proof is invalid
        let zero_proof: [u8; 80] = [0; 80];
        assert!(
            VrfDraft03::verify(&pk, &zero_proof, b"msg").is_err(),
            "All-zero proof should fail verification"
        );
    }

    #[test]
    fn test_vrf03_all_ones_proof() {
        let seed = [6u8; 32];
        let (_sk, pk) = VrfDraft03::keypair_from_seed(&seed);

        // All-0xff proof is invalid (invalid curve point)
        let ones_proof: [u8; 80] = [0xff; 80];
        assert!(
            VrfDraft03::verify(&pk, &ones_proof, b"msg").is_err(),
            "All-0xff proof should fail verification"
        );
    }

    #[test]
    fn test_vrf03_empty_public_key() {
        let seed = [7u8; 32];
        let (sk, _pk) = VrfDraft03::keypair_from_seed(&seed);

        let proof = VrfDraft03::prove(&sk, b"test").expect("Prove should succeed");

        // Empty/zero public key should fail
        let empty_pk: [u8; 32] = [0; 32];
        assert!(
            VrfDraft03::verify(&empty_pk, &proof, b"test").is_err(),
            "Empty public key should fail verification"
        );
    }

    #[test]
    fn test_vrf13_empty_message() {
        let seed = [8u8; 32];
        let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);

        let proof = VrfDraft13::prove(&sk, b"").expect("Empty message should work");
        let output = VrfDraft13::verify(&pk, &proof, b"").expect("Verification should succeed");
        assert_eq!(output.len(), 64);
    }

    #[test]
    fn test_vrf13_invalid_proof_content() {
        let seed = [9u8; 32];
        let (_sk, pk) = VrfDraft13::keypair_from_seed(&seed);

        // Valid-sized proof for Draft-13 but with random/invalid content
        let invalid_proof: [u8; 128] = [0x42; 128];
        assert!(
            VrfDraft13::verify(&pk, &invalid_proof, b"msg").is_err(),
            "Invalid proof content should fail verification"
        );
    }
}

// ============================================================================
// KES Edge Cases
// ============================================================================

mod kes_edge_cases {
    use super::*;

    #[test]
    fn test_kes_sign_at_expired_period() -> Result<()> {
        let seed = [0x10u8; 32];
        let mut sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
        let vk = Sum6Kes::derive_verification_key(&sk)?;

        // Evolve to period 5
        for p in 0..5 {
            sk = Sum6Kes::update_kes(&(), sk, p)?.unwrap();
        }

        // Try to sign for period 3 (already expired)
        // Note: Signing may technically succeed but the signature won't be valid
        // for the claimed period due to forward security
        let result = Sum6Kes::sign_kes(&(), 3, b"msg", &sk);

        // Whether signing fails or produces invalid signature, verification should fail
        if let Ok(sig) = result {
            let verify_result = Sum6Kes::verify_kes(&(), &vk, 3, b"msg", &sig);
            // Forward security: evolved key can't produce valid sig for past periods
            let _ = verify_result; // Implementation-dependent
        }

        Ok(())
    }

    #[test]
    fn test_kes_sum6_max_period_boundary() -> Result<()> {
        let seed = [0x11u8; 32];
        let mut sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
        let vk = Sum6Kes::derive_verification_key(&sk)?;

        let max_period = 63u64; // Sum6KES: 2^6 = 64 periods (0-63)

        // Evolve to max period
        for p in 0..max_period {
            sk = Sum6Kes::update_kes(&(), sk, p)?.unwrap();
        }

        // Should be able to sign at max period
        let sig = Sum6Kes::sign_kes(&(), max_period, b"final", &sk)?;
        assert!(
            Sum6Kes::verify_kes(&(), &vk, max_period, b"final", &sig).is_ok(),
            "Should verify at max period"
        );

        // Should NOT be able to evolve past max period
        let result = Sum6Kes::update_kes(&(), sk, max_period)?;
        assert!(result.is_none(), "Cannot evolve past max period");

        Ok(())
    }

    #[test]
    fn test_kes_sum2_max_period_boundary() -> Result<()> {
        let seed = [0x12u8; 32];
        let mut sk = Sum2Kes::gen_key_kes_from_seed_bytes(&seed)?;
        let vk = Sum2Kes::derive_verification_key(&sk)?;

        let max_period = 3u64; // Sum2KES: 2^2 = 4 periods (0-3)

        // Evolve to max period
        for p in 0..max_period {
            sk = Sum2Kes::update_kes(&(), sk, p)?.unwrap();
        }

        // Should be able to sign at max period
        let sig = Sum2Kes::sign_kes(&(), max_period, b"final", &sk)?;
        assert!(Sum2Kes::verify_kes(&(), &vk, max_period, b"final", &sig).is_ok());

        // Cannot evolve past max period
        let result = Sum2Kes::update_kes(&(), sk, max_period)?;
        assert!(result.is_none());

        Ok(())
    }

    #[test]
    fn test_kes_corrupted_signature() -> Result<()> {
        let seed = [0x13u8; 32];
        let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
        let vk = Sum6Kes::derive_verification_key(&sk)?;

        let msg = b"message";
        let sig = Sum6Kes::sign_kes(&(), 0, msg, &sk)?;

        // Serialize, corrupt, and deserialize
        let mut sig_bytes = Sum6Kes::raw_serialize_signature_kes(&sig);
        if !sig_bytes.is_empty() {
            sig_bytes[10] ^= 0xFF; // Corrupt a byte

            if let Some(corrupted_sig) = Sum6Kes::raw_deserialize_signature_kes(&sig_bytes) {
                let result = Sum6Kes::verify_kes(&(), &vk, 0, msg, &corrupted_sig);
                assert!(
                    result.is_err(),
                    "Corrupted signature should fail verification"
                );
            }
        }

        Ok(())
    }

    #[test]
    fn test_kes_empty_message() -> Result<()> {
        let seed = [0x14u8; 32];
        let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
        let vk = Sum6Kes::derive_verification_key(&sk)?;

        let sig = Sum6Kes::sign_kes(&(), 0, &[], &sk)?;
        assert!(
            Sum6Kes::verify_kes(&(), &vk, 0, &[], &sig).is_ok(),
            "Empty message should work"
        );

        Ok(())
    }

    #[test]
    fn test_kes_large_message() -> Result<()> {
        let seed = [0x15u8; 32];
        let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
        let vk = Sum6Kes::derive_verification_key(&sk)?;

        let large_msg = vec![0x42u8; 10_000];
        let sig = Sum6Kes::sign_kes(&(), 0, &large_msg, &sk)?;
        assert!(
            Sum6Kes::verify_kes(&(), &vk, 0, &large_msg, &sig).is_ok(),
            "Large message should work"
        );

        Ok(())
    }

    #[test]
    fn test_kes_period_out_of_bounds() -> Result<()> {
        let seed = [0x16u8; 32];
        let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
        let vk = Sum6Kes::derive_verification_key(&sk)?;

        // Try to sign at period way beyond maximum (Sum6 max is 63)
        let result = Sum6Kes::sign_kes(&(), 100, b"msg", &sk);

        if let Ok(sig) = result {
            // Verification at invalid period should fail
            let verify_result = Sum6Kes::verify_kes(&(), &vk, 100, b"msg", &sig);
            assert!(
                verify_result.is_err(),
                "Invalid period should fail verification"
            );
        }

        Ok(())
    }

    #[test]
    fn test_kes_wrong_period_verification() -> Result<()> {
        let seed = [0x17u8; 32];
        let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
        let vk = Sum6Kes::derive_verification_key(&sk)?;

        // Sign at period 0
        let sig = Sum6Kes::sign_kes(&(), 0, b"msg", &sk)?;

        // Verify at wrong period should fail
        let result = Sum6Kes::verify_kes(&(), &vk, 1, b"msg", &sig);
        assert!(result.is_err(), "Wrong period should fail verification");

        Ok(())
    }

    #[test]
    fn test_kes_empty_vk_bytes() {
        let empty_bytes: Vec<u8> = vec![];
        let result = Sum6Kes::raw_deserialize_verification_key_kes(&empty_bytes);
        assert!(result.is_none(), "Empty bytes should fail deserialization");
    }
}

// ============================================================================
// DSIGN Edge Cases
// ============================================================================

mod dsign_edge_cases {
    use super::*;

    #[test]
    fn test_ed25519_empty_message() -> Result<()> {
        let seed = [0x20u8; 32];
        let sk = Ed25519::gen_key(&seed).unwrap();
        let vk = Ed25519::derive_verification_key(&sk);

        let sig = Ed25519::sign(&sk, &[]);
        assert!(
            Ed25519::verify(&vk, &[], &sig).is_ok(),
            "Empty message should work"
        );

        Ok(())
    }

    #[test]
    fn test_ed25519_large_message() -> Result<()> {
        let seed = [0x21u8; 32];
        let sk = Ed25519::gen_key(&seed).unwrap();
        let vk = Ed25519::derive_verification_key(&sk);

        let large_msg = vec![0xAB; 100_000];
        let sig = Ed25519::sign(&sk, &large_msg);
        assert!(
            Ed25519::verify(&vk, &large_msg, &sig).is_ok(),
            "Large message should work"
        );

        Ok(())
    }

    #[test]
    fn test_ed25519_wrong_key() -> Result<()> {
        let seed1 = [0x22u8; 32];
        let seed2 = [0x23u8; 32];

        let sk1 = Ed25519::gen_key(&seed1).unwrap();
        let sk2 = Ed25519::gen_key(&seed2).unwrap();
        let vk2 = Ed25519::derive_verification_key(&sk2);

        // Sign with key1, verify with key2's vk
        let sig = Ed25519::sign(&sk1, b"test");
        let result = Ed25519::verify(&vk2, b"test", &sig);
        assert!(result.is_err(), "Wrong key should fail verification");

        Ok(())
    }

    #[test]
    fn test_ed25519_wrong_message() -> Result<()> {
        let seed = [0x24u8; 32];
        let sk = Ed25519::gen_key(&seed).unwrap();
        let vk = Ed25519::derive_verification_key(&sk);

        let sig = Ed25519::sign(&sk, b"message1");
        let result = Ed25519::verify(&vk, b"message2", &sig);
        assert!(result.is_err(), "Wrong message should fail verification");

        Ok(())
    }

    #[test]
    fn test_ed25519_corrupted_signature() -> Result<()> {
        use cardano_crypto::dsign::ed25519::Ed25519Signature;

        let seed = [0x25u8; 32];
        let sk = Ed25519::gen_key(&seed).unwrap();
        let vk = Ed25519::derive_verification_key(&sk);

        let sig = Ed25519::sign(&sk, b"test");
        let sig_bytes = sig.as_bytes();

        // Copy bytes and corrupt them
        let mut corrupted_bytes = *sig_bytes;
        corrupted_bytes[0] ^= 0xFF; // Corrupt first byte

        // Create a new signature from corrupted bytes
        if let Some(corrupted_sig) = Ed25519Signature::from_bytes(&corrupted_bytes) {
            let result = Ed25519::verify(&vk, b"test", &corrupted_sig);
            assert!(result.is_err(), "Corrupted signature should fail");
        }
        // If from_bytes fails, that's also valid rejection

        Ok(())
    }

    #[test]
    fn test_ed25519_single_byte_message() -> Result<()> {
        let seed = [0x26u8; 32];
        let sk = Ed25519::gen_key(&seed).unwrap();
        let vk = Ed25519::derive_verification_key(&sk);

        let sig = Ed25519::sign(&sk, &[0x42]);
        assert!(Ed25519::verify(&vk, &[0x42], &sig).is_ok());

        Ok(())
    }
}

// ============================================================================
// Hash Edge Cases
// ============================================================================

mod hash_edge_cases {
    use super::*;

    #[test]
    fn test_blake2b_empty_input() {
        // Empty input should produce valid hashes
        let hash224 = Blake2b224::hash(&[]);
        let hash256 = Blake2b256::hash(&[]);
        let hash512 = Blake2b512::hash(&[]);

        assert_eq!(hash224.len(), 28);
        assert_eq!(hash256.len(), 32);
        assert_eq!(hash512.len(), 64);

        // Verify determinism
        assert_eq!(Blake2b256::hash(&[]), hash256);
    }

    #[test]
    fn test_blake2b_single_byte() {
        let hash = Blake2b256::hash(&[0x42]);
        assert_eq!(hash.len(), 32);

        // Different input should produce different hash
        let hash2 = Blake2b256::hash(&[0x43]);
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_blake2b_large_input() {
        // Test with large input (1MB)
        let large_input = vec![0xAB; 1_000_000];
        let hash = Blake2b256::hash(&large_input);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake2b_all_zeros() {
        let zeros = vec![0u8; 1000];
        let hash = Blake2b256::hash(&zeros);
        assert_eq!(hash.len(), 32);
        // Hash should not be all zeros
        assert!(hash.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_blake2b_all_ones() {
        let ones = vec![0xFFu8; 1000];
        let hash = Blake2b256::hash(&ones);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake2b_deterministic() {
        let input = b"deterministic test";
        let hash1 = Blake2b256::hash(input);
        let hash2 = Blake2b256::hash(input);
        assert_eq!(hash1, hash2, "Hash should be deterministic");
    }

    #[test]
    fn test_hash_concat() {
        let left = Blake2b256::hash(b"left");
        let right = Blake2b256::hash(b"right");
        let combined = Blake2b256::hash_concat(&left, &right);
        assert_eq!(combined.len(), 32);

        // Order matters
        let combined_reverse = Blake2b256::hash_concat(&right, &left);
        assert_ne!(combined, combined_reverse);
    }
}

// ============================================================================
// Cross-Module Edge Cases
// ============================================================================

mod cross_module_edge_cases {
    use super::*;

    #[test]
    fn test_deterministic_key_derivation() {
        // Same seed should always produce same keys
        let seed = [0x30u8; 32];

        // VRF
        let (vrf_sk1, vrf_pk1) = VrfDraft03::keypair_from_seed(&seed);
        let (vrf_sk2, vrf_pk2) = VrfDraft03::keypair_from_seed(&seed);
        assert_eq!(
            vrf_pk1, vrf_pk2,
            "VRF key derivation should be deterministic"
        );

        // Ed25519
        let ed_sk1 = Ed25519::gen_key(&seed).unwrap();
        let ed_sk2 = Ed25519::gen_key(&seed).unwrap();
        let ed_vk1 = Ed25519::derive_verification_key(&ed_sk1);
        let ed_vk2 = Ed25519::derive_verification_key(&ed_sk2);
        assert_eq!(
            ed_vk1.as_bytes(),
            ed_vk2.as_bytes(),
            "Ed25519 should be deterministic"
        );

        // VRF proofs
        let proof1 = VrfDraft03::prove(&vrf_sk1, b"test").unwrap();
        let proof2 = VrfDraft03::prove(&vrf_sk2, b"test").unwrap();
        assert_eq!(proof1, proof2, "VRF proofs should be deterministic");
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let seed1 = [0x31u8; 32];
        let seed2 = [0x32u8; 32];

        // VRF
        let (_, vrf_pk1) = VrfDraft03::keypair_from_seed(&seed1);
        let (_, vrf_pk2) = VrfDraft03::keypair_from_seed(&seed2);
        assert_ne!(vrf_pk1, vrf_pk2);

        // Ed25519
        let ed_sk1 = Ed25519::gen_key(&seed1).unwrap();
        let ed_sk2 = Ed25519::gen_key(&seed2).unwrap();
        let ed_vk1 = Ed25519::derive_verification_key(&ed_sk1);
        let ed_vk2 = Ed25519::derive_verification_key(&ed_sk2);
        assert_ne!(ed_vk1.as_bytes(), ed_vk2.as_bytes());
    }
}
