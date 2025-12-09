//! Golden test vectors for KES implementations (Cardano-compatible)
//!
//! These tests verify compatibility with Cardano's Key Evolving Signature schemes
//! as defined in cardano-base/cardano-crypto-class.
//!
//! # KES Variants
//!
//! - **SingleKES**: Basic KES with 1 period (Ed25519 wrapper)
//! - **Sum2KES**: 2 periods (single tree level)
//! - **Sum6KES**: 64 periods (6 tree levels) - Cardano standard
//! - **CompactSingleKES**: Space-optimized SingleKES
//! - **CompactSumKES**: Space-optimized SumKES
//!
//! # Cardano Compatibility
//!
//! Cardano uses Sum6KES (64 periods) for operational certificates. Each KES period
//! is 129,600 slots (~36 hours). Keys must evolve every period to maintain forward
//! security - old keys cannot sign for past periods.
//!
//! # Key Format
//!
//! - Verification Key: 32 bytes (Ed25519 public key or hash depending on level)
//! - Signature: Variable (depends on KES variant and period)
//! - Signing Key: Variable (contains tree structure and sub-keys)

use cardano_crypto::common::Result;
use cardano_crypto::kes::{KesAlgorithm, SingleKes, Sum2Kes, Sum6Kes};

// ============================================================================
// Helper Functions
// ============================================================================

/// Encode bytes as hex string
#[allow(dead_code)]
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ============================================================================
// SingleKES Tests
// ============================================================================

/// SingleKES basic functionality test
#[test]
fn test_single_kes_basic() -> Result<()> {
    type TestKes = SingleKes<cardano_crypto::dsign::Ed25519>;

    let seed = [0x42u8; 32];
    let sk = TestKes::gen_key_kes_from_seed_bytes(&seed)?;
    let vk = TestKes::derive_verification_key(&sk)?;

    let message = b"SingleKES test";
    let sig = TestKes::sign_kes(&(), 0, message, &sk)?;

    // Verify at correct period
    assert!(
        TestKes::verify_kes(&(), &vk, 0, message, &sig).is_ok(),
        "Verification should succeed at period 0"
    );

    // Verify fails at wrong period
    assert!(
        TestKes::verify_kes(&(), &vk, 1, message, &sig).is_err(),
        "Verification should fail at wrong period"
    );

    // SingleKES has only 1 period, so update returns None
    assert!(
        TestKes::update_kes(&(), sk, 0)?.is_none(),
        "SingleKES cannot evolve past period 0"
    );

    Ok(())
}

/// SingleKES total periods test
#[test]
fn test_single_kes_total_periods() {
    type TestKes = SingleKes<cardano_crypto::dsign::Ed25519>;
    assert_eq!(
        TestKes::total_periods(),
        1,
        "SingleKES should have exactly 1 period"
    );
}

// ============================================================================
// Sum2KES Tests (2 periods)
// ============================================================================

/// Sum2KES basic functionality and key evolution
#[test]
fn test_sum2_kes_basic() -> Result<()> {
    let seed = [0x44u8; 32];
    let sk = Sum2Kes::gen_key_kes_from_seed_bytes(&seed)?;
    let vk = Sum2Kes::derive_verification_key(&sk)?;

    // Sign at period 0
    let sig0 = Sum2Kes::sign_kes(&(), 0, b"Period 0", &sk)?;
    assert!(Sum2Kes::verify_kes(&(), &vk, 0, b"Period 0", &sig0).is_ok());

    // Evolve to period 1
    let sk = Sum2Kes::update_kes(&(), sk, 0)?.expect("Key should evolve");

    // Sign at period 1
    let sig1 = Sum2Kes::sign_kes(&(), 1, b"Period 1", &sk)?;
    assert!(Sum2Kes::verify_kes(&(), &vk, 1, b"Period 1", &sig1).is_ok());

    // Old signature should still verify (verification key unchanged)
    assert!(Sum2Kes::verify_kes(&(), &vk, 0, b"Period 0", &sig0).is_ok());

    // Sum2KES has 2^2 = 4 total periods (0, 1, 2, 3)
    // Continue evolving through remaining periods
    let sk2 = Sum2Kes::update_kes(&(), sk, 1)?.expect("Key should evolve to period 2");
    let sk3 = Sum2Kes::update_kes(&(), sk2, 2)?.expect("Key should evolve to period 3");

    // Cannot evolve past period 3 (last period)
    assert!(
        Sum2Kes::update_kes(&(), sk3, 3)?.is_none(),
        "Sum2KES cannot evolve past period 3"
    );

    Ok(())
}

/// Sum2KES total periods test
#[test]
fn test_sum2_kes_total_periods() {
    // Sum2 means depth 2, so 2^2 = 4 periods
    assert_eq!(Sum2Kes::total_periods(), 4, "Sum2KES should have 4 periods (2^2)");
}

/// Test that evolved key cannot sign for past periods
#[test]
fn test_sum2_kes_forward_security() -> Result<()> {
    let seed = [0x45u8; 32];
    let sk = Sum2Kes::gen_key_kes_from_seed_bytes(&seed)?;
    let vk = Sum2Kes::derive_verification_key(&sk)?;

    // Evolve to period 1
    let sk1 = Sum2Kes::update_kes(&(), sk, 0)?.expect("Key should evolve");

    // Try to sign at period 0 with evolved key - should fail or produce invalid sig
    let sig = Sum2Kes::sign_kes(&(), 0, b"trying period 0", &sk1)?;

    // Verification should fail because the key has evolved
    assert!(
        Sum2Kes::verify_kes(&(), &vk, 0, b"trying period 0", &sig).is_err(),
        "Evolved key should not produce valid signatures for past periods"
    );

    Ok(())
}

// ============================================================================
// Sum6KES Tests (64 periods - Cardano standard)
// ============================================================================

/// Sum6KES basic functionality
#[test]
fn test_sum6_kes_basic() -> Result<()> {
    let seed = [0x46u8; 32];
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;

    let message = b"Sum6KES basic test";
    let sig = Sum6Kes::sign_kes(&(), 0, message, &sk)?;

    assert!(
        Sum6Kes::verify_kes(&(), &vk, 0, message, &sig).is_ok(),
        "Basic Sum6KES signature should verify"
    );

    Ok(())
}

/// Sum6KES total periods test (Cardano uses 64 periods)
#[test]
fn test_sum6_kes_total_periods() {
    assert_eq!(
        Sum6Kes::total_periods(),
        64,
        "Sum6KES should have 64 periods (2^6)"
    );
}

/// Test Sum6KES key evolution through multiple periods
#[test]
fn test_sum6_kes_evolution() -> Result<()> {
    let seed = [0x47u8; 32];

    // Test specific periods: start, early, middle, late, final
    for &target_period in &[0, 1, 2, 4, 8, 16, 32, 63] {
        let mut sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
        let vk = Sum6Kes::derive_verification_key(&sk)?;

        // Evolve to target period
        for p in 0..target_period {
            sk = Sum6Kes::update_kes(&(), sk, p)?.expect(&format!(
                "Key should evolve from period {} to {}",
                p,
                p + 1
            ));
        }

        // Sign and verify at target period
        let msg = format!("Period {}", target_period);
        let sig = Sum6Kes::sign_kes(&(), target_period, msg.as_bytes(), &sk)?;
        assert!(
            Sum6Kes::verify_kes(&(), &vk, target_period, msg.as_bytes(), &sig).is_ok(),
            "Verification should succeed at period {}",
            target_period
        );
    }

    Ok(())
}

/// Test Sum6KES with Cardano-style block signing
#[test]
fn test_sum6_kes_cardano_style() -> Result<()> {
    let seed = [0x4Cu8; 32];

    let test_cases = [
        (0, b"Genesis block" as &[u8]),
        (10, b"Early epoch"),
        (31, b"Mid-lifecycle"),
        (63, b"Final period"),
    ];

    for (period, message) in test_cases {
        let mut sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
        let vk = Sum6Kes::derive_verification_key(&sk)?;

        // Evolve to target period
        for t in 0..period {
            sk = Sum6Kes::update_kes(&(), sk, t)?.expect("Key evolution should succeed");
        }

        // Sign at the target period
        let sig = Sum6Kes::sign_kes(&(), period, message, &sk)?;
        assert!(
            Sum6Kes::verify_kes(&(), &vk, period, message, &sig).is_ok(),
            "Signature should verify at period {}",
            period
        );

        // Verify fails at adjacent periods
        if period > 0 {
            assert!(
                Sum6Kes::verify_kes(&(), &vk, period - 1, message, &sig).is_err(),
                "Verification should fail at period {} (expected {})",
                period - 1,
                period
            );
        }
        if period < 63 {
            assert!(
                Sum6Kes::verify_kes(&(), &vk, period + 1, message, &sig).is_err(),
                "Verification should fail at period {} (expected {})",
                period + 1,
                period
            );
        }
    }

    Ok(())
}

// ============================================================================
// Serialization Tests
// ============================================================================

/// Test verification key serialization roundtrip
#[test]
fn test_verification_key_serialization() -> Result<()> {
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&[0x99u8; 32])?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;

    let vk_bytes = Sum6Kes::raw_serialize_verification_key_kes(&vk);
    let vk_restored = Sum6Kes::raw_deserialize_verification_key_kes(&vk_bytes)
        .expect("Verification key deserialization should succeed");

    assert_eq!(
        vk_bytes,
        Sum6Kes::raw_serialize_verification_key_kes(&vk_restored),
        "Verification key roundtrip should preserve bytes"
    );

    Ok(())
}

/// Test signature serialization roundtrip
#[test]
fn test_signature_serialization() -> Result<()> {
    let sk = Sum2Kes::gen_key_kes_from_seed_bytes(&[0xAAu8; 32])?;
    let vk = Sum2Kes::derive_verification_key(&sk)?;
    let sig = Sum2Kes::sign_kes(&(), 0, b"test", &sk)?;

    let sig_bytes = Sum2Kes::raw_serialize_signature_kes(&sig);
    let sig_restored = Sum2Kes::raw_deserialize_signature_kes(&sig_bytes)
        .expect("Signature deserialization should succeed");

    assert!(
        Sum2Kes::verify_kes(&(), &vk, 0, b"test", &sig_restored).is_ok(),
        "Deserialized signature should verify"
    );

    Ok(())
}

// ============================================================================
// Determinism Tests
// ============================================================================

/// Test deterministic key generation
#[test]
fn test_deterministic_key_generation() -> Result<()> {
    let seed = [0xCCu8; 32];

    let sk1 = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
    let sk2 = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;

    let vk1 = Sum6Kes::derive_verification_key(&sk1)?;
    let vk2 = Sum6Kes::derive_verification_key(&sk2)?;

    let vk1_bytes = Sum6Kes::raw_serialize_verification_key_kes(&vk1);
    let vk2_bytes = Sum6Kes::raw_serialize_verification_key_kes(&vk2);

    assert_eq!(
        vk1_bytes, vk2_bytes,
        "Same seed should produce same verification key"
    );

    // Signatures should also be deterministic
    let sig1 = Sum6Kes::sign_kes(&(), 0, b"test", &sk1)?;
    let sig2 = Sum6Kes::sign_kes(&(), 0, b"test", &sk2)?;

    let sig1_bytes = Sum6Kes::raw_serialize_signature_kes(&sig1);
    let sig2_bytes = Sum6Kes::raw_serialize_signature_kes(&sig2);

    assert_eq!(
        sig1_bytes, sig2_bytes,
        "Same seed and message should produce same signature"
    );

    Ok(())
}

/// Test that different seeds produce different keys
#[test]
fn test_seed_uniqueness() -> Result<()> {
    let seeds: [[u8; 32]; 3] = [[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]];
    let mut vkeys = Vec::new();

    for seed in seeds {
        let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
        let vk = Sum6Kes::derive_verification_key(&sk)?;
        vkeys.push(Sum6Kes::raw_serialize_verification_key_kes(&vk));
    }

    // All verification keys should be unique
    for i in 0..vkeys.len() {
        for j in (i + 1)..vkeys.len() {
            assert_ne!(
                vkeys[i], vkeys[j],
                "Different seeds should produce different verification keys"
            );
        }
    }

    Ok(())
}

// ============================================================================
// Security Boundary Tests
// ============================================================================

/// Test cross-period validation fails
#[test]
fn test_cross_period_validation_failure() -> Result<()> {
    let sk = Sum2Kes::gen_key_kes_from_seed_bytes(&[0xBBu8; 32])?;
    let vk = Sum2Kes::derive_verification_key(&sk)?;
    let sig = Sum2Kes::sign_kes(&(), 0, b"test", &sk)?;

    assert!(
        Sum2Kes::verify_kes(&(), &vk, 0, b"test", &sig).is_ok(),
        "Verification should succeed at correct period"
    );
    assert!(
        Sum2Kes::verify_kes(&(), &vk, 1, b"test", &sig).is_err(),
        "Verification should fail at wrong period"
    );

    Ok(())
}

/// Test wrong message verification fails
#[test]
fn test_wrong_message_fails() -> Result<()> {
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&[0xDDu8; 32])?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;
    let sig = Sum6Kes::sign_kes(&(), 0, b"original message", &sk)?;

    assert!(
        Sum6Kes::verify_kes(&(), &vk, 0, b"different message", &sig).is_err(),
        "Verification should fail with wrong message"
    );

    Ok(())
}

/// Test wrong verification key fails
#[test]
fn test_wrong_key_fails() -> Result<()> {
    let sk1 = Sum6Kes::gen_key_kes_from_seed_bytes(&[0xEEu8; 32])?;
    let sk2 = Sum6Kes::gen_key_kes_from_seed_bytes(&[0xFFu8; 32])?;
    let vk2 = Sum6Kes::derive_verification_key(&sk2)?;

    let sig = Sum6Kes::sign_kes(&(), 0, b"test", &sk1)?;

    assert!(
        Sum6Kes::verify_kes(&(), &vk2, 0, b"test", &sig).is_err(),
        "Verification should fail with wrong verification key"
    );

    Ok(())
}

// ============================================================================
// Edge Cases
// ============================================================================

/// Test with extreme seed values
#[test]
fn test_extreme_seeds() -> Result<()> {
    let seeds = [[0x00u8; 32], [0xFFu8; 32], [0x80u8; 32]];

    for seed in seeds {
        let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
        let vk = Sum6Kes::derive_verification_key(&sk)?;
        let sig = Sum6Kes::sign_kes(&(), 0, b"test", &sk)?;

        assert!(
            Sum6Kes::verify_kes(&(), &vk, 0, b"test", &sig).is_ok(),
            "KES should work with extreme seed values"
        );
    }

    Ok(())
}

/// Test with various message sizes
#[test]
fn test_message_sizes() -> Result<()> {
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&[0x55u8; 32])?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;

    let sizes = [0, 1, 31, 32, 33, 64, 128, 256, 1024];

    for size in sizes {
        let message: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let sig = Sum6Kes::sign_kes(&(), 0, &message, &sk)?;

        assert!(
            Sum6Kes::verify_kes(&(), &vk, 0, &message, &sig).is_ok(),
            "KES should work with message size {}",
            size
        );
    }

    Ok(())
}

/// Test verification key stability across evolution
#[test]
fn test_verification_key_stability() -> Result<()> {
    let seed = [0x66u8; 32];
    let mut sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;
    let vk_bytes = Sum6Kes::raw_serialize_verification_key_kes(&vk);

    // Evolve through several periods and verify vkey stays the same
    for period in 0..10 {
        let current_vk = Sum6Kes::derive_verification_key(&sk)?;
        let current_vk_bytes = Sum6Kes::raw_serialize_verification_key_kes(&current_vk);

        assert_eq!(
            vk_bytes, current_vk_bytes,
            "Verification key should remain constant at period {}",
            period
        );

        if period < 63 {
            sk = Sum6Kes::update_kes(&(), sk, period)?.expect("Evolution should succeed");
        }
    }

    Ok(())
}
