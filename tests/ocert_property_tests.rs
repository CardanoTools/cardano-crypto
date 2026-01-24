//! Property-based tests for Operational Certificate functionality
//!
//! These tests verify operational certificate invariants using property-based testing.
//!
//! Note: This test file requires the `kes` feature to be enabled.

#![cfg(feature = "kes")]

use cardano_crypto::common::Result;
use cardano_crypto::dsign::Ed25519;
use cardano_crypto::common::traits::DsignAlgorithm;
use cardano_crypto::key::{
    operational_cert::{
        compute_operational_cert_hash, create_operational_certificate, verify_operational_certificate,
    },
    kes_period::compute_kes_period,
};
use cardano_crypto::kes::{KesAlgorithm, Sum6Kes};
use proptest::prelude::*;

// ============================================================================
// Property Test Strategies
// ============================================================================

fn seed_strategy() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

fn counter_strategy() -> impl Strategy<Value = u64> {
    0..1000u64
}

fn period_strategy() -> impl Strategy<Value = u32> {
    0..64u32
}

fn start_period_strategy() -> impl Strategy<Value = u64> {
    0..100_000u64
}

// ============================================================================
// Operational Certificate Property Tests
// ============================================================================

proptest! {
    /// Property: OCert creation and verification roundtrip succeeds
    #[test]
    fn prop_ocert_create_verify_roundtrip(
        kes_seed in seed_strategy(),
        cold_seed in seed_strategy(),
        counter in counter_strategy(),
        start_period in start_period_strategy()
    ) {
        // Generate KES key
        let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)
            .expect("KES key generation should succeed");
        let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)
            .expect("KES verkey derivation should succeed");

        // Generate cold key (using Ed25519 for simplicity)
        use cardano_crypto::dsign::Ed25519;
        use cardano_crypto::common::traits::DsignAlgorithm;
        let cold_sk = Ed25519::gen_key_from_seed(&cold_seed);
        let cold_vk = Ed25519::derive_verification_key(&cold_sk);

        // Create operational certificate
        let ocert = create_operational_certificate(
            &kes_vk,
            counter,
            start_period,
            &cold_sk,
        ).expect("OCert creation should succeed");

        // Verify operational certificate
        let result = verify_operational_certificate(
            &ocert,
            &kes_vk,
            counter,
            start_period,
            &cold_vk,
        );

        prop_assert!(result.is_ok(), "OCert verification should succeed");
    }

    /// Property: Wrong counter always fails verification
    #[test]
    fn prop_ocert_wrong_counter_fails(
        kes_seed in seed_strategy(),
        cold_seed in seed_strategy(),
        create_counter in counter_strategy(),
        verify_counter in counter_strategy(),
        start_period in start_period_strategy()
    ) {
        prop_assume!(create_counter != verify_counter);

        use cardano_crypto::dsign::Ed25519;
        use cardano_crypto::common::traits::DsignAlgorithm;

        let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)
            .expect("KES key generation should succeed");
        let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)
            .expect("KES verkey derivation should succeed");

        let cold_sk = Ed25519::gen_key_from_seed(&cold_seed);
        let cold_vk = Ed25519::derive_verification_key(&cold_sk);

        // Create with one counter
        let ocert = create_operational_certificate(
            &kes_vk,
            create_counter,
            start_period,
            &cold_sk,
        ).expect("OCert creation should succeed");

        // Verify with different counter
        let result = verify_operational_certificate(
            &ocert,
            &kes_vk,
            verify_counter,
            start_period,
            &cold_vk,
        );

        prop_assert!(result.is_err(), "OCert with wrong counter should fail verification");
    }

    /// Property: Wrong start period fails verification
    #[test]
    fn prop_ocert_wrong_start_period_fails(
        kes_seed in seed_strategy(),
        cold_seed in seed_strategy(),
        counter in counter_strategy(),
        create_period in start_period_strategy(),
        verify_period in start_period_strategy()
    ) {
        prop_assume!(create_period != verify_period);

        use cardano_crypto::dsign::Ed25519;
        use cardano_crypto::common::traits::DsignAlgorithm;

        let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)
            .expect("KES key generation should succeed");
        let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)
            .expect("KES verkey derivation should succeed");

        let cold_sk = Ed25519::gen_key_from_seed(&cold_seed);
        let cold_vk = Ed25519::derive_verification_key(&cold_sk);

        let ocert = create_operational_certificate(
            &kes_vk,
            counter,
            create_period,
            &cold_sk,
        ).expect("OCert creation should succeed");

        let result = verify_operational_certificate(
            &ocert,
            &kes_vk,
            counter,
            verify_period,
            &cold_vk,
        );

        prop_assert!(result.is_err(), "OCert with wrong start period should fail");
    }

    /// Property: Wrong cold key fails verification
    #[test]
    fn prop_ocert_wrong_cold_key_fails(
        kes_seed in seed_strategy(),
        cold_seed1 in seed_strategy(),
        cold_seed2 in seed_strategy(),
        counter in counter_strategy(),
        start_period in start_period_strategy()
    ) {
        prop_assume!(cold_seed1 != cold_seed2);

        use cardano_crypto::dsign::Ed25519;
        use cardano_crypto::common::traits::DsignAlgorithm;

        let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)
            .expect("KES key generation should succeed");
        let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)
            .expect("KES verkey derivation should succeed");

        let cold_sk1 = Ed25519::gen_key_from_seed(&cold_seed1);
        let cold_sk2 = Ed25519::gen_key_from_seed(&cold_seed2);
        let cold_vk2 = Ed25519::derive_verification_key(&cold_sk2);

        // Create with first cold key
        let ocert = create_operational_certificate(
            &kes_vk,
            counter,
            start_period,
            &cold_sk1,
        ).expect("OCert creation should succeed");

        // Verify with second cold key
        let result = verify_operational_certificate(
            &ocert,
            &kes_vk,
            counter,
            start_period,
            &cold_vk2,
        );

        prop_assert!(result.is_err(), "OCert with wrong cold key should fail");
    }

    /// Property: OCert hash is deterministic
    #[test]
    fn prop_ocert_hash_deterministic(
        kes_seed in seed_strategy(),
        counter in counter_strategy(),
        start_period in start_period_strategy()
    ) {
        let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)
            .expect("KES key generation should succeed");
        let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)
            .expect("KES verkey derivation should succeed");

        // Compute hash twice
        let hash1 = compute_operational_cert_hash(&kes_vk, counter, start_period)
            .expect("Hash computation should succeed");
        let hash2 = compute_operational_cert_hash(&kes_vk, counter, start_period)
            .expect("Hash computation should succeed");

        prop_assert_eq!(
            hash1, hash2,
            "OCert hash should be deterministic"
        );
    }

    /// Property: Different inputs produce different hashes
    #[test]
    fn prop_ocert_hash_unique(
        kes_seed1 in seed_strategy(),
        kes_seed2 in seed_strategy(),
        counter in counter_strategy(),
        start_period in start_period_strategy()
    ) {
        prop_assume!(kes_seed1 != kes_seed2);

        let kes_sk1 = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed1)
            .expect("KES key generation should succeed");
        let kes_vk1 = Sum6Kes::derive_verification_key(&kes_sk1)
            .expect("KES verkey derivation should succeed");

        let kes_sk2 = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed2)
            .expect("KES key generation should succeed");
        let kes_vk2 = Sum6Kes::derive_verification_key(&kes_sk2)
            .expect("KES verkey derivation should succeed");

        let hash1 = compute_operational_cert_hash(&kes_vk1, counter, start_period)
            .expect("Hash computation should succeed");
        let hash2 = compute_operational_cert_hash(&kes_vk2, counter, start_period)
            .expect("Hash computation should succeed");

        prop_assert_ne!(
            hash1, hash2,
            "Different inputs should produce different hashes"
        );
    }
}

// ============================================================================
// KES Period Property Tests
// ============================================================================

proptest! {
    /// Property: KES period calculation is deterministic
    #[test]
    fn prop_kes_period_deterministic(
        slot in 0..1_000_000_000u64,
        slots_per_period in 1..10_000u64
    ) {
        let period1 = compute_kes_period(slot, slots_per_period);
        let period2 = compute_kes_period(slot, slots_per_period);

        prop_assert_eq!(period1, period2, "KES period should be deterministic");
    }

    /// Property: Later slots have equal or higher period
    #[test]
    fn prop_kes_period_monotonic(
        slot1 in 0..1_000_000u64,
        slot2 in 0..1_000_000u64,
        slots_per_period in 1..10_000u64
    ) {
        prop_assume!(slot1 <= slot2);

        let period1 = compute_kes_period(slot1, slots_per_period);
        let period2 = compute_kes_period(slot2, slots_per_period);

        prop_assert!(
            period1 <= period2,
            "Later slot should have >= period: slot1={}, period1={}, slot2={}, period2={}",
            slot1, period1, slot2, period2
        );
    }

    /// Property: Slot within same period has same period number
    #[test]
    fn prop_kes_period_within_period(
        period_num in 0..1000u64,
        slots_per_period in 100..10_000u64,
        offset in 0..100u64
    ) {
        prop_assume!(offset < slots_per_period);

        let slot = period_num * slots_per_period + offset;
        let computed_period = compute_kes_period(slot, slots_per_period);

        prop_assert_eq!(
            computed_period, period_num,
            "Slot {} should be in period {} (slots_per_period={})",
            slot, period_num, slots_per_period
        );
    }
}

// ============================================================================
// Malformed Input Tests
// ============================================================================

#[test]
fn test_ocert_empty_signature() {
    use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};

    let kes_seed = [0u8; 32];
    let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)
        .expect("KES key generation should succeed");
    let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)
        .expect("KES verkey derivation should succeed");

    let cold_seed = [0x42u8; 32];
    let cold_sk = Ed25519::gen_key_from_seed(&cold_seed);
    let cold_vk = Ed25519::derive_verification_key(&cold_sk);

    // Empty signature
    let empty_sig: Vec<u8> = vec![];

    let result = verify_operational_certificate(
        &empty_sig,
        &kes_vk,
        0,
        0,
        &cold_vk,
    );

    assert!(
        result.is_err(),
        "Empty signature should fail verification"
    );
}

#[test]
fn test_ocert_corrupted_signature() -> Result<()> {
    use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};

    let kes_seed = [0u8; 32];
    let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)?;
    let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)?;

    let cold_seed = [0x42u8; 32];
    let cold_sk = Ed25519::gen_key_from_seed(&cold_seed);
    let cold_vk = Ed25519::derive_verification_key(&cold_sk);

    let mut ocert = create_operational_certificate(&kes_vk, 0, 0, &cold_sk)?;

    // Corrupt the signature
    if !ocert.is_empty() {
        ocert[0] ^= 0xff;

        let result = verify_operational_certificate(&ocert, &kes_vk, 0, 0, &cold_vk);
        assert!(
            result.is_err(),
            "Corrupted OCert should fail verification"
        );
    }

    Ok(())
}

#[test]
fn test_ocert_counter_overflow() -> Result<()> {
    use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};

    let kes_seed = [0xffu8; 32];
    let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)?;
    let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)?;

    let cold_seed = [0xaau8; 32];
    let cold_sk = Ed25519::gen_key_from_seed(&cold_seed);
    let cold_vk = Ed25519::derive_verification_key(&cold_sk);

    // Maximum counter value
    let max_counter = u64::MAX;
    let ocert = create_operational_certificate(&kes_vk, max_counter, 0, &cold_sk)?;

    let result = verify_operational_certificate(&ocert, &kes_vk, max_counter, 0, &cold_vk);
    assert!(
        result.is_ok(),
        "Maximum counter value should be handled correctly"
    );

    Ok(())
}

#[test]
fn test_ocert_very_large_start_period() -> Result<()> {
    use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};

    let kes_seed = [0x99u8; 32];
    let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)?;
    let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)?;

    let cold_seed = [0x66u8; 32];
    let cold_sk = Ed25519::gen_key_from_seed(&cold_seed);
    let cold_vk = Ed25519::derive_verification_key(&cold_sk);

    // Very large start period
    let large_period = 1_000_000_000u64;
    let ocert = create_operational_certificate(&kes_vk, 0, large_period, &cold_sk)?;

    let result = verify_operational_certificate(&ocert, &kes_vk, 0, large_period, &cold_vk);
    assert!(
        result.is_ok(),
        "Large start period should be handled correctly"
    );

    Ok(())
}

#[test]
fn test_kes_period_zero_slots_per_period() {
    // Edge case: zero slots per period would cause division by zero
    // Should be handled gracefully (though this is invalid config)
    let slot = 100u64;
    let slots_per_period = 0u64;

    // This should not panic
    let _period = compute_kes_period(slot, slots_per_period);

    // Note: The implementation should either return a sensible default
    // or handle this edge case appropriately
}

#[test]
fn test_kes_period_max_values() {
    // Test with maximum u64 values
    let max_slot = u64::MAX;
    let slots_per_period = 129600u64; // Mainnet value

    let _period = compute_kes_period(max_slot, slots_per_period);

    // Should not panic or overflow
}

#[test]
fn test_ocert_zero_values() -> Result<()> {
    use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};

    let kes_seed = [0u8; 32];
    let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)?;
    let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)?;

    let cold_seed = [0u8; 32];
    let cold_sk = Ed25519::gen_key_from_seed(&cold_seed);
    let cold_vk = Ed25519::derive_verification_key(&cold_sk);

    // All zero values
    let ocert = create_operational_certificate(&kes_vk, 0, 0, &cold_sk)?;

    let result = verify_operational_certificate(&ocert, &kes_vk, 0, 0, &cold_vk);
    assert!(
        result.is_ok(),
        "Zero values should be valid"
    );

    Ok(())
}
