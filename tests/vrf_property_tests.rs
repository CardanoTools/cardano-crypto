//! Property-based tests for VRF implementations
//!
//! These tests use proptest to verify VRF invariants across random inputs,
//! complementing the deterministic golden tests.

use cardano_crypto::common::Result;
use cardano_crypto::vrf::{VrfDraft03, VrfDraft13};
use proptest::prelude::*;

// ============================================================================
// Property Test Strategies
// ============================================================================

/// Generate a random seed for VRF keypair
fn seed_strategy() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate a random message
fn message_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..256)
}

// ============================================================================
// VRF Draft-03 Property Tests
// ============================================================================

proptest! {
    /// Property: For any valid keypair and message, prove → verify succeeds
    #[test]
    fn prop_vrf03_prove_verify_roundtrip(
        seed in seed_strategy(),
        msg in message_strategy()
    ) {
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

        let proof = VrfDraft03::prove(&sk, &msg)
            .expect("Prove should succeed with valid inputs");

        let beta = VrfDraft03::verify(&pk, &proof, &msg)
            .expect("Verify should succeed with valid proof");

        // Verify proof_to_hash matches
        let beta2 = VrfDraft03::proof_to_hash(&proof)
            .expect("proof_to_hash should succeed");

        prop_assert_eq!(beta, beta2, "proof_to_hash should match verify output");
    }

    /// Property: Wrong key always fails verification
    #[test]
    fn prop_vrf03_wrong_key_fails(
        seed1 in seed_strategy(),
        seed2 in seed_strategy(),
        msg in message_strategy()
    ) {
        // Skip if seeds are identical
        prop_assume!(seed1 != seed2);

        let (sk1, _pk1) = VrfDraft03::keypair_from_seed(&seed1);
        let (_sk2, pk2) = VrfDraft03::keypair_from_seed(&seed2);

        let proof = VrfDraft03::prove(&sk1, &msg)
            .expect("Prove should succeed");

        // Verification with wrong key should fail
        let result = VrfDraft03::verify(&pk2, &proof, &msg);
        prop_assert!(result.is_err(), "Verification with wrong key should fail");
    }

    /// Property: Wrong message fails verification
    #[test]
    fn prop_vrf03_wrong_message_fails(
        seed in seed_strategy(),
        msg1 in message_strategy(),
        msg2 in message_strategy()
    ) {
        prop_assume!(msg1 != msg2);

        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);
        let proof = VrfDraft03::prove(&sk, &msg1)
            .expect("Prove should succeed");

        // Verification with wrong message should fail
        let result = VrfDraft03::verify(&pk, &proof, &msg2);
        prop_assert!(result.is_err(), "Verification with wrong message should fail");
    }

    /// Property: Same input always produces same output (determinism)
    #[test]
    fn prop_vrf03_deterministic(
        seed in seed_strategy(),
        msg in message_strategy()
    ) {
        let (sk1, pk1) = VrfDraft03::keypair_from_seed(&seed);
        let (sk2, pk2) = VrfDraft03::keypair_from_seed(&seed);

        // Same seed produces same keys
        prop_assert_eq!(&pk1[..], &pk2[..], "Same seed should produce same public key");

        let proof1 = VrfDraft03::prove(&sk1, &msg)
            .expect("Prove should succeed");
        let proof2 = VrfDraft03::prove(&sk2, &msg)
            .expect("Prove should succeed");

        // Same key and message produce same proof
        prop_assert_eq!(&proof1[..], &proof2[..], "Same inputs should produce same proof");
    }

    /// Property: Output is always 64 bytes
    #[test]
    fn prop_vrf03_output_size(
        seed in seed_strategy(),
        msg in message_strategy()
    ) {
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);
        let proof = VrfDraft03::prove(&sk, &msg)
            .expect("Prove should succeed");
        let beta = VrfDraft03::verify(&pk, &proof, &msg)
            .expect("Verify should succeed");

        prop_assert_eq!(beta.len(), 64, "VRF output should always be 64 bytes");
    }

    /// Property: Proof is always 80 bytes for Draft-03
    #[test]
    fn prop_vrf03_proof_size(
        seed in seed_strategy(),
        msg in message_strategy()
    ) {
        let (sk, _pk) = VrfDraft03::keypair_from_seed(&seed);
        let proof = VrfDraft03::prove(&sk, &msg)
            .expect("Prove should succeed");

        prop_assert_eq!(proof.len(), 80, "VRF Draft-03 proof should be 80 bytes");
    }

    /// Property: Public key is always 32 bytes
    #[test]
    fn prop_vrf03_pubkey_size(seed in seed_strategy()) {
        let (_sk, pk) = VrfDraft03::keypair_from_seed(&seed);
        prop_assert_eq!(pk.len(), 32, "VRF public key must be 32 bytes");
    }

    /// Property: Corrupted proof byte always fails verification
    #[test]
    fn prop_vrf03_corrupted_proof_fails(
        seed in seed_strategy(),
        msg in message_strategy(),
        corrupt_idx in 0..80usize
    ) {
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);
        let mut proof = VrfDraft03::prove(&sk, &msg)
            .expect("Prove should succeed");

        // Corrupt a single byte
        proof[corrupt_idx] ^= 0xFF;

        // Verification should fail
        let result = VrfDraft03::verify(&pk, &proof, &msg);
        prop_assert!(result.is_err(), "Corrupted proof (byte {}) should fail verification", corrupt_idx);
    }
}

// ============================================================================
// VRF Draft-13 Property Tests
// ============================================================================

proptest! {
    /// Property: Draft-13 prove → verify succeeds
    #[test]
    fn prop_vrf13_prove_verify_roundtrip(
        seed in seed_strategy(),
        msg in message_strategy()
    ) {
        let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);

        let proof = VrfDraft13::prove(&sk, &msg)
            .expect("Prove should succeed");

        let beta = VrfDraft13::verify(&pk, &proof, &msg)
            .expect("Verify should succeed");

        // Verify proof_to_hash matches
        let beta2 = VrfDraft13::proof_to_hash(&proof)
            .expect("proof_to_hash should succeed");

        prop_assert_eq!(beta, beta2);
    }

    /// Property: Draft-13 wrong key fails
    #[test]
    fn prop_vrf13_wrong_key_fails(
        seed1 in seed_strategy(),
        seed2 in seed_strategy(),
        msg in message_strategy()
    ) {
        prop_assume!(seed1 != seed2);

        let (sk1, _pk1) = VrfDraft13::keypair_from_seed(&seed1);
        let (_sk2, pk2) = VrfDraft13::keypair_from_seed(&seed2);

        let proof = VrfDraft13::prove(&sk1, &msg)
            .expect("Prove should succeed");

        let result = VrfDraft13::verify(&pk2, &proof, &msg);
        prop_assert!(result.is_err());
    }

    /// Property: Draft-13 proof size is 128 bytes
    #[test]
    fn prop_vrf13_proof_size(
        seed in seed_strategy(),
        msg in message_strategy()
    ) {
        let (sk, _pk) = VrfDraft13::keypair_from_seed(&seed);
        let proof = VrfDraft13::prove(&sk, &msg)
            .expect("Prove should succeed");

        prop_assert_eq!(proof.len(), 128, "VRF Draft-13 proof should be 128 bytes");
    }
}

// ============================================================================
// Malformed Input Tests
// ============================================================================

#[test]
fn test_vrf03_malformed_proof_invalid_point() {
    let seed = [0u8; 32];
    let (_sk, pk) = VrfDraft03::keypair_from_seed(&seed);

    // Proof with invalid curve point (all 0xff bytes)
    let bad_proof: [u8; 80] = [0xff; 80];
    assert!(
        VrfDraft03::verify(&pk, &bad_proof, b"msg").is_err(),
        "Proof with invalid point should fail verification"
    );
}

#[test]
fn test_vrf03_malformed_proof_zero_bytes() {
    let seed = [0x42u8; 32];
    let (_sk, pk) = VrfDraft03::keypair_from_seed(&seed);

    // All-zero proof
    let bad_proof: [u8; 80] = [0; 80];
    assert!(
        VrfDraft03::verify(&pk, &bad_proof, b"msg").is_err(),
        "All-zero proof should fail verification"
    );
}

#[test]
fn test_vrf13_malformed_proof_invalid() {
    let seed = [0u8; 32];
    let (_sk, pk) = VrfDraft13::keypair_from_seed(&seed);

    // All-zero proof - invalid
    let bad_proof: [u8; 128] = [0; 128];
    assert!(
        VrfDraft13::verify(&pk, &bad_proof, b"msg").is_err(),
        "All-zero proof should fail verification"
    );
}

#[test]
fn test_vrf_empty_public_key() {
    let empty_pk: [u8; 32] = [0; 32];

    // Create a valid-looking proof
    let seed = [0x42u8; 32];
    let (sk, _pk) = VrfDraft03::keypair_from_seed(&seed);
    let proof = VrfDraft03::prove(&sk, b"test").expect("Prove should succeed");

    // Try to verify with empty public key
    assert!(
        VrfDraft03::verify(&empty_pk, &proof, b"test").is_err(),
        "Empty public key should fail verification"
    );
}

#[test]
fn test_vrf_corrupted_proof() {
    let seed = [0x42u8; 32];
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);
    let msg = b"test message";

    let mut proof = VrfDraft03::prove(&sk, msg).expect("Prove should succeed");

    // Corrupt each byte of the proof one at a time
    for i in 0..proof.len() {
        let original = proof[i];
        proof[i] ^= 0xff; // Flip all bits

        assert!(
            VrfDraft03::verify(&pk, &proof, msg).is_err(),
            "Corrupted proof (byte {}) should fail verification",
            i
        );

        proof[i] = original; // Restore for next iteration
    }
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_vrf_empty_message() -> Result<()> {
    let seed = [0x99u8; 32];
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

    let empty_msg: &[u8] = &[];
    let proof = VrfDraft03::prove(&sk, empty_msg)?;
    let beta = VrfDraft03::verify(&pk, &proof, empty_msg)?;

    assert_eq!(beta.len(), 64);
    Ok(())
}

#[test]
fn test_vrf_maximum_message_size() -> Result<()> {
    let seed = [0xaau8; 32];
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

    // Test with very large message (10KB)
    let large_msg = vec![0x42u8; 10_000];
    let proof = VrfDraft03::prove(&sk, &large_msg)?;
    let beta = VrfDraft03::verify(&pk, &proof, &large_msg)?;

    assert_eq!(beta.len(), 64);
    Ok(())
}

#[test]
fn test_vrf_single_byte_message() -> Result<()> {
    let seed = [0x11u8; 32];
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

    // Test with single byte message
    let msg = &[42u8];
    let proof = VrfDraft03::prove(&sk, msg)?;
    let beta = VrfDraft03::verify(&pk, &proof, msg)?;

    assert_eq!(beta.len(), 64);
    Ok(())
}

// Note: VRF verify functions require exact array sizes at compile time,
// so invalid length tests are enforced by the type system.
// The tests below verify that correctly-sized but invalid content fails.

#[test]
fn test_vrf03_random_proof_content_fails() {
    let seed = [0x22u8; 32];
    let (_sk, pk) = VrfDraft03::keypair_from_seed(&seed);

    // Valid-sized proof but random content
    let random_proof: [u8; 80] = [0x42u8; 80];
    let result = VrfDraft03::verify(&pk, &random_proof, b"msg");
    assert!(result.is_err(), "Random proof content should fail verification");
}

#[test]
fn test_vrf13_random_proof_content_fails() {
    let seed = [0x44u8; 32];
    let (_sk, pk) = VrfDraft13::keypair_from_seed(&seed);

    // Valid-sized proof for Draft-13 but random content
    let random_proof: [u8; 128] = [0x42u8; 128];
    let result = VrfDraft13::verify(&pk, &random_proof, b"msg");
    assert!(result.is_err(), "Random proof content should fail verification");
}
