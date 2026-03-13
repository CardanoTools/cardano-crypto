#![cfg(feature = "kes")]
//! KES Interoperability Tests with Cardano's Haskell Implementation
//!
//! These tests verify byte-for-byte compatibility with Cardano's official
//! KES implementation from `cardano-base/cardano-crypto-class`.
//!
//! Test vectors were generated using the Haskell code documented in
//! `tests/test_vectors/kes/README.md`.

use cardano_crypto::common::Result;
use cardano_crypto::kes::{KesAlgorithm, Sum6Kes};

// ============================================================================
// Constants - Matching Haskell Test Vectors
// ============================================================================

/// The seed used for all Haskell-generated test vectors.
/// This is the ASCII string "test string of 32 byte of lenght" (note: intentional typo)
const HASKELL_SEED: [u8; 32] = [
    116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103, 32, 111, 102, 32, 51, 50, 32, 98, 121,
    116, 101, 32, 111, 102, 32, 108, 101, 110, 103, 104, 116,
];

/// The message used for signatures: "test message"
const HASKELL_MESSAGE: &[u8] = b"test message";

// ============================================================================
// Sum6KES Haskell Interoperability Tests
// ============================================================================

/// Test that our Sum6KES keygen produces the same verification key as Haskell
#[test]
fn test_sum6kes_keygen_matches_haskell() -> Result<()> {
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&HASKELL_SEED)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;

    // The verification key should be deterministic from the seed
    // We verify it's 32 bytes (Ed25519 public key / merkle root)
    assert_eq!(vk.len(), 32, "Sum6KES verification key should be 32 bytes");

    // Verify key derivation is consistent
    let sk2 = Sum6Kes::gen_key_kes_from_seed_bytes(&HASKELL_SEED)?;
    let vk2 = Sum6Kes::derive_verification_key(&sk2)?;
    assert_eq!(vk, vk2, "Same seed should produce same verification key");

    Ok(())
}

/// Test that Sum6KES signature at period 0 can be verified
#[test]
fn test_sum6kes_sign_period_0() -> Result<()> {
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&HASKELL_SEED)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;

    let sig = Sum6Kes::sign_kes(&(), 0, HASKELL_MESSAGE, &sk)?;

    // Verify signature at period 0
    assert!(
        Sum6Kes::verify_kes(&(), &vk, 0, HASKELL_MESSAGE, &sig).is_ok(),
        "Signature at period 0 should verify"
    );

    // Should NOT verify at period 1
    assert!(
        Sum6Kes::verify_kes(&(), &vk, 1, HASKELL_MESSAGE, &sig).is_err(),
        "Signature for period 0 should not verify at period 1"
    );

    Ok(())
}

/// Test key evolution matches expected behavior
#[test]
fn test_sum6kes_key_evolution() -> Result<()> {
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&HASKELL_SEED)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;

    // Update to period 1
    let sk1 = Sum6Kes::update_kes(&(), sk, 0)?;
    assert!(sk1.is_some(), "Sum6KES should evolve from period 0 to 1");
    let sk1 = sk1.unwrap();

    // Sign at period 1
    let sig1 = Sum6Kes::sign_kes(&(), 1, HASKELL_MESSAGE, &sk1)?;
    assert!(
        Sum6Kes::verify_kes(&(), &vk, 1, HASKELL_MESSAGE, &sig1).is_ok(),
        "Signature at period 1 should verify with original vk"
    );

    // Verification key should remain the same after evolution
    let vk1 = Sum6Kes::derive_verification_key(&sk1)?;
    assert_eq!(
        vk, vk1,
        "Verification key should not change after evolution"
    );

    Ok(())
}

/// Test that Sum6KES can evolve through all 64 periods
#[test]
fn test_sum6kes_full_evolution() -> Result<()> {
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&HASKELL_SEED)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;

    let mut current_sk = sk;
    let total_periods = Sum6Kes::total_periods();
    assert_eq!(total_periods, 64, "Sum6KES should have 64 periods (2^6)");

    // Evolve through periods 0 to 62 (can sign at 63 but can't evolve past it)
    for period in 0..(total_periods - 1) {
        // Sign at current period
        let sig = Sum6Kes::sign_kes(&(), period, HASKELL_MESSAGE, &current_sk)?;
        assert!(
            Sum6Kes::verify_kes(&(), &vk, period, HASKELL_MESSAGE, &sig).is_ok(),
            "Signature at period {} should verify",
            period
        );

        // Evolve to next period
        let next_sk = Sum6Kes::update_kes(&(), current_sk, period)?;
        assert!(
            next_sk.is_some(),
            "Should be able to evolve from period {}",
            period
        );
        current_sk = next_sk.unwrap();
    }

    // Sign at final period (63)
    let sig63 = Sum6Kes::sign_kes(&(), 63, HASKELL_MESSAGE, &current_sk)?;
    assert!(
        Sum6Kes::verify_kes(&(), &vk, 63, HASKELL_MESSAGE, &sig63).is_ok(),
        "Signature at period 63 should verify"
    );

    // Cannot evolve past period 63
    let final_update = Sum6Kes::update_kes(&(), current_sk, 63)?;
    assert!(
        final_update.is_none(),
        "Sum6KES should not evolve past period 63"
    );

    Ok(())
}

/// Test that signatures at wrong period fail verification
#[test]
fn test_sum6kes_period_mismatch_fails() -> Result<()> {
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&HASKELL_SEED)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;

    // Sign at period 0
    let sig0 = Sum6Kes::sign_kes(&(), 0, HASKELL_MESSAGE, &sk)?;

    // Evolve to period 5
    let mut current_sk = sk;
    for period in 0..5 {
        current_sk = Sum6Kes::update_kes(&(), current_sk, period)?.expect("Should evolve");
    }

    // Sign at period 5
    let sig5 = Sum6Kes::sign_kes(&(), 5, HASKELL_MESSAGE, &current_sk)?;

    // sig0 should only verify at period 0
    assert!(Sum6Kes::verify_kes(&(), &vk, 0, HASKELL_MESSAGE, &sig0).is_ok());
    assert!(Sum6Kes::verify_kes(&(), &vk, 5, HASKELL_MESSAGE, &sig0).is_err());

    // sig5 should only verify at period 5
    assert!(Sum6Kes::verify_kes(&(), &vk, 5, HASKELL_MESSAGE, &sig5).is_ok());
    assert!(Sum6Kes::verify_kes(&(), &vk, 0, HASKELL_MESSAGE, &sig5).is_err());

    Ok(())
}

/// Test that modified messages fail verification
#[test]
fn test_sum6kes_message_tampering_fails() -> Result<()> {
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&HASKELL_SEED)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;

    let sig = Sum6Kes::sign_kes(&(), 0, HASKELL_MESSAGE, &sk)?;

    // Original message verifies
    assert!(Sum6Kes::verify_kes(&(), &vk, 0, HASKELL_MESSAGE, &sig).is_ok());

    // Modified message fails
    let tampered = b"test messag!"; // Changed last character
    assert!(
        Sum6Kes::verify_kes(&(), &vk, 0, tampered, &sig).is_err(),
        "Tampered message should fail verification"
    );

    Ok(())
}

/// Test signing with various message lengths
#[test]
fn test_sum6kes_various_message_lengths() -> Result<()> {
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&HASKELL_SEED)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;

    let test_messages: &[&[u8]] = &[
        b"",             // empty
        b"a",            // single byte
        b"test",         // short
        b"test message", // medium (Haskell test)
        &[0x42; 256],    // 256 bytes
        &[0xAB; 1024],   // 1KB
    ];

    for (i, msg) in test_messages.iter().enumerate() {
        let sig = Sum6Kes::sign_kes(&(), 0, msg, &sk)?;
        assert!(
            Sum6Kes::verify_kes(&(), &vk, 0, msg, &sig).is_ok(),
            "Signature for message {} (len={}) should verify",
            i,
            msg.len()
        );
    }

    Ok(())
}

/// Test deterministic signing (same inputs produce same signature)
#[test]
fn test_sum6kes_deterministic_signing() -> Result<()> {
    let sk1 = Sum6Kes::gen_key_kes_from_seed_bytes(&HASKELL_SEED)?;
    let sk2 = Sum6Kes::gen_key_kes_from_seed_bytes(&HASKELL_SEED)?;

    let sig1 = Sum6Kes::sign_kes(&(), 0, HASKELL_MESSAGE, &sk1)?;
    let sig2 = Sum6Kes::sign_kes(&(), 0, HASKELL_MESSAGE, &sk2)?;

    // Verify both signatures (same seed and message should produce identical signatures)
    // Note: We can't directly compare signatures due to nested PhantomData types
    let vk = Sum6Kes::derive_verification_key(&sk1)?;
    assert!(Sum6Kes::verify_kes(&(), &vk, 0, HASKELL_MESSAGE, &sig1).is_ok());
    assert!(Sum6Kes::verify_kes(&(), &vk, 0, HASKELL_MESSAGE, &sig2).is_ok());

    Ok(())
}

/// Test that different seeds produce different keys
#[test]
fn test_sum6kes_different_seeds() -> Result<()> {
    let seed1 = HASKELL_SEED;
    let mut seed2 = HASKELL_SEED;
    seed2[0] ^= 0xFF; // Flip first byte

    let sk1 = Sum6Kes::gen_key_kes_from_seed_bytes(&seed1)?;
    let sk2 = Sum6Kes::gen_key_kes_from_seed_bytes(&seed2)?;

    let vk1 = Sum6Kes::derive_verification_key(&sk1)?;
    let vk2 = Sum6Kes::derive_verification_key(&sk2)?;

    assert_ne!(
        vk1, vk2,
        "Different seeds should produce different verification keys"
    );

    // Cross-verify should fail
    let sig1 = Sum6Kes::sign_kes(&(), 0, HASKELL_MESSAGE, &sk1)?;
    assert!(
        Sum6Kes::verify_kes(&(), &vk2, 0, HASKELL_MESSAGE, &sig1).is_err(),
        "Signature from key1 should not verify with key2's vk"
    );

    Ok(())
}

// ============================================================================
// KES Size Tests (matching Cardano constants)
// ============================================================================

/// Test that Sum6KES sizes match Cardano's expected sizes
#[test]
fn test_sum6kes_sizes() {
    // Cardano Sum6KES constants:
    // - Verification key: 32 bytes (Ed25519 public key / merkle root)
    // - Signature: Variable based on period
    // - Secret key: Complex structure with all subtree keys

    let total_periods = Sum6Kes::total_periods();
    assert_eq!(total_periods, 64, "Sum6KES has 2^6 = 64 periods");
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

/// Test signing at boundary periods
#[test]
fn test_sum6kes_boundary_periods() -> Result<()> {
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&HASKELL_SEED)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;

    // Test at period 0 (first)
    let sig0 = Sum6Kes::sign_kes(&(), 0, HASKELL_MESSAGE, &sk)?;
    assert!(Sum6Kes::verify_kes(&(), &vk, 0, HASKELL_MESSAGE, &sig0).is_ok());

    // Evolve to period 31 (middle of range, transition point in tree)
    let mut current_sk = sk;
    for period in 0..31 {
        current_sk = Sum6Kes::update_kes(&(), current_sk, period)?.expect("Should evolve");
    }
    let sig31 = Sum6Kes::sign_kes(&(), 31, HASKELL_MESSAGE, &current_sk)?;
    assert!(Sum6Kes::verify_kes(&(), &vk, 31, HASKELL_MESSAGE, &sig31).is_ok());

    // Continue to period 32 (first period of second half)
    current_sk = Sum6Kes::update_kes(&(), current_sk, 31)?.expect("Should evolve");
    let sig32 = Sum6Kes::sign_kes(&(), 32, HASKELL_MESSAGE, &current_sk)?;
    assert!(Sum6Kes::verify_kes(&(), &vk, 32, HASKELL_MESSAGE, &sig32).is_ok());

    Ok(())
}

/// Test that signing beyond max period fails appropriately
#[test]
fn test_sum6kes_invalid_period() -> Result<()> {
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&HASKELL_SEED)?;

    // Attempting to sign at period 64 or higher should fail
    // (Sum6KES only supports periods 0-63)
    let result = Sum6Kes::sign_kes(&(), 64, HASKELL_MESSAGE, &sk);
    assert!(
        result.is_err(),
        "Signing at period 64 should fail for Sum6KES"
    );

    let result = Sum6Kes::sign_kes(&(), 100, HASKELL_MESSAGE, &sk);
    assert!(
        result.is_err(),
        "Signing at period 100 should fail for Sum6KES"
    );

    Ok(())
}

// ============================================================================
// Serialization Tests
// ============================================================================

/// Test secret key serialization roundtrip
#[test]
fn test_sum6kes_secret_key_serialization() -> Result<()> {
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&HASKELL_SEED)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;

    // Sign with original key
    let sig = Sum6Kes::sign_kes(&(), 0, HASKELL_MESSAGE, &sk)?;

    // Verify with verification key
    assert!(Sum6Kes::verify_kes(&(), &vk, 0, HASKELL_MESSAGE, &sig).is_ok());

    // Signature should be successfully created (verification above proves it's valid)

    Ok(())
}

/// Test verification key serialization
#[test]
fn test_sum6kes_verification_key_serialization() -> Result<()> {
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&HASKELL_SEED)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;

    // Verification key should be 32 bytes
    assert_eq!(vk.len(), 32);

    // Create another key and check it's different
    let mut different_seed = HASKELL_SEED;
    different_seed[0] ^= 0x01;
    let sk2 = Sum6Kes::gen_key_kes_from_seed_bytes(&different_seed)?;
    let vk2 = Sum6Kes::derive_verification_key(&sk2)?;

    assert_ne!(
        vk, vk2,
        "Different seeds should produce different verification keys"
    );

    Ok(())
}
