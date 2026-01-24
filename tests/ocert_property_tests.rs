//! Property-based tests for Operational Certificate functionality
//!
//! These tests verify operational certificate invariants using property-based testing.
//!
//! Note: This test file requires the `kes` feature to be enabled.

#![cfg(feature = "kes")]

use cardano_crypto::common::Result;
use cardano_crypto::dsign::{DsignAlgorithm, Ed25519};
use cardano_crypto::key::operational_cert::OperationalCertificate;
use cardano_crypto::key::kes_period::KesPeriod;
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
        start_period in period_strategy()
    ) {
        // Generate KES key
        let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)
            .expect("KES key generation should succeed");
        let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)
            .expect("KES verkey derivation should succeed");

        // Generate cold key
        let cold_sk = Ed25519::gen_key(&cold_seed);
        let cold_vk = Ed25519::derive_verification_key(&cold_sk);

        // Create operational certificate
        let ocert = OperationalCertificate::new(
            kes_vk,
            counter,
            KesPeriod(start_period),
            &cold_sk,
        );

        // Verify operational certificate
        let result = ocert.verify(&cold_vk);
        prop_assert!(result.is_ok(), "OCert verification should succeed");
    }

    /// Property: OCert with wrong cold key fails verification
    #[test]
    fn prop_ocert_wrong_cold_key_fails(
        kes_seed in seed_strategy(),
        cold_seed1 in seed_strategy(),
        cold_seed2 in seed_strategy(),
        counter in counter_strategy(),
        start_period in period_strategy()
    ) {
        // Skip if seeds are the same
        prop_assume!(cold_seed1 != cold_seed2);

        // Generate KES key
        let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)
            .expect("KES key generation should succeed");
        let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)
            .expect("KES verkey derivation should succeed");

        // Generate two different cold keys
        let cold_sk1 = Ed25519::gen_key(&cold_seed1);
        let cold_sk2 = Ed25519::gen_key(&cold_seed2);
        let cold_vk2 = Ed25519::derive_verification_key(&cold_sk2);

        // Create OCert with cold_sk1
        let ocert = OperationalCertificate::new(
            kes_vk,
            counter,
            KesPeriod(start_period),
            &cold_sk1,
        );

        // Verify with cold_vk2 should fail
        let result = ocert.verify(&cold_vk2);
        prop_assert!(result.is_err(), "OCert verification with wrong key should fail");
    }

    /// Property: OCert period validation works correctly
    #[test]
    fn prop_ocert_period_validation(
        kes_seed in seed_strategy(),
        cold_seed in seed_strategy(),
        counter in counter_strategy(),
        start_period in 0..32u32,
        check_offset in 0..32i32
    ) {
        // Generate keys
        let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)
            .expect("KES key generation should succeed");
        let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)
            .expect("KES verkey derivation should succeed");
        let cold_sk = Ed25519::gen_key(&cold_seed);

        // Create OCert at start_period
        let ocert = OperationalCertificate::new(
            kes_vk,
            counter,
            KesPeriod(start_period),
            &cold_sk,
        );

        // Calculate check period (may be before or after start)
        let check_period = (start_period as i32 + check_offset).max(0) as u32;

        // Validation depends on whether check_period >= start_period
        let result = ocert.is_valid_for_period(KesPeriod(check_period), counter);

        if check_period >= start_period {
            prop_assert!(result.is_ok(), "Should be valid at or after start period");
        } else {
            prop_assert!(result.is_err(), "Should be invalid before start period");
        }
    }

    /// Property: OCert counter validation works correctly
    #[test]
    fn prop_ocert_counter_validation(
        kes_seed in seed_strategy(),
        cold_seed in seed_strategy(),
        ocert_counter in counter_strategy(),
        check_counter in counter_strategy(),
        start_period in period_strategy()
    ) {
        // Generate keys
        let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)
            .expect("KES key generation should succeed");
        let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)
            .expect("KES verkey derivation should succeed");
        let cold_sk = Ed25519::gen_key(&cold_seed);

        // Create OCert
        let ocert = OperationalCertificate::new(
            kes_vk,
            ocert_counter,
            KesPeriod(start_period),
            &cold_sk,
        );

        // Check current period (at or after start)
        let current_period = KesPeriod(start_period);
        let result = ocert.is_valid_for_period(current_period, check_counter);

        if check_counter == ocert_counter {
            prop_assert!(result.is_ok(), "Should be valid with matching counter");
        } else {
            prop_assert!(result.is_err(), "Should be invalid with wrong counter");
        }
    }

    /// Property: OCert determinism - same inputs produce equivalent certificates
    #[test]
    fn prop_ocert_deterministic(
        kes_seed in seed_strategy(),
        cold_seed in seed_strategy(),
        counter in counter_strategy(),
        start_period in period_strategy()
    ) {
        // Generate keys twice
        let kes_sk1 = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)
            .expect("KES key generation should succeed");
        let kes_vk1 = Sum6Kes::derive_verification_key(&kes_sk1)
            .expect("KES verkey derivation should succeed");
        let cold_sk1 = Ed25519::gen_key(&cold_seed);
        let cold_vk1 = Ed25519::derive_verification_key(&cold_sk1);

        let kes_sk2 = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)
            .expect("KES key generation should succeed");
        let kes_vk2 = Sum6Kes::derive_verification_key(&kes_sk2)
            .expect("KES verkey derivation should succeed");
        let cold_sk2 = Ed25519::gen_key(&cold_seed);

        // Create two OCerts with same parameters
        let ocert1 = OperationalCertificate::new(
            kes_vk1,
            counter,
            KesPeriod(start_period),
            &cold_sk1,
        );

        let ocert2 = OperationalCertificate::new(
            kes_vk2,
            counter,
            KesPeriod(start_period),
            &cold_sk2,
        );

        // Both should verify
        prop_assert!(ocert1.verify(&cold_vk1).is_ok());
        prop_assert!(ocert2.verify(&cold_vk1).is_ok());

        // And have same counter/period
        prop_assert_eq!(ocert1.counter(), ocert2.counter());
        prop_assert_eq!(ocert1.kes_period(), ocert2.kes_period());
    }
}

// ============================================================================
// Non-property Tests
// ============================================================================

#[test]
fn test_ocert_basic_creation() -> Result<()> {
    let kes_seed = [1u8; 32];
    let cold_seed = [2u8; 32];

    let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)?;
    let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)?;

    let cold_sk = Ed25519::gen_key(&cold_seed);
    let cold_vk = Ed25519::derive_verification_key(&cold_sk);

    let ocert = OperationalCertificate::new(kes_vk, 0, KesPeriod(100), &cold_sk);

    // Should verify successfully
    ocert.verify(&cold_vk)?;

    // Check accessors
    assert_eq!(ocert.counter(), 0);
    assert_eq!(ocert.kes_period(), KesPeriod(100));

    Ok(())
}

#[test]
fn test_ocert_counter_increment() -> Result<()> {
    let kes_seed = [3u8; 32];
    let cold_seed = [4u8; 32];

    let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)?;
    let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)?;

    let cold_sk = Ed25519::gen_key(&cold_seed);
    let cold_vk = Ed25519::derive_verification_key(&cold_sk);

    // Create OCerts with increasing counters
    for counter in 0..5 {
        let ocert = OperationalCertificate::new(
            kes_vk.clone(),
            counter,
            KesPeriod(0),
            &cold_sk,
        );
        ocert.verify(&cold_vk)?;
        assert_eq!(ocert.counter(), counter);
    }

    Ok(())
}

#[test]
fn test_ocert_period_boundary() -> Result<()> {
    let kes_seed = [5u8; 32];
    let cold_seed = [6u8; 32];

    let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)?;
    let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)?;

    let cold_sk = Ed25519::gen_key(&cold_seed);

    // Create OCert at period 50
    let ocert = OperationalCertificate::new(
        kes_vk,
        0,
        KesPeriod(50),
        &cold_sk,
    );

    // Valid at exactly period 50
    assert!(ocert.is_valid_for_period(KesPeriod(50), 0).is_ok());

    // Valid after period 50
    assert!(ocert.is_valid_for_period(KesPeriod(51), 0).is_ok());
    assert!(ocert.is_valid_for_period(KesPeriod(63), 0).is_ok());

    // Invalid before period 50
    assert!(ocert.is_valid_for_period(KesPeriod(49), 0).is_err());
    assert!(ocert.is_valid_for_period(KesPeriod(0), 0).is_err());

    Ok(())
}

#[test]
fn test_ocert_zero_values() -> Result<()> {
    let kes_seed = [0u8; 32];
    let cold_seed = [0u8; 32];

    let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)?;
    let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)?;

    let cold_sk = Ed25519::gen_key(&cold_seed);
    let cold_vk = Ed25519::derive_verification_key(&cold_sk);

    // All zero values should work
    let ocert = OperationalCertificate::new(kes_vk, 0, KesPeriod(0), &cold_sk);

    assert!(ocert.verify(&cold_vk).is_ok(), "Zero values should be valid");

    Ok(())
}

#[test]
fn test_ocert_max_counter() -> Result<()> {
    let kes_seed = [0xffu8; 32];
    let cold_seed = [0xaau8; 32];

    let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)?;
    let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)?;

    let cold_sk = Ed25519::gen_key(&cold_seed);
    let cold_vk = Ed25519::derive_verification_key(&cold_sk);

    // Maximum counter value should work
    let max_counter = u64::MAX;
    let ocert = OperationalCertificate::new(kes_vk, max_counter, KesPeriod(0), &cold_sk);

    assert!(
        ocert.verify(&cold_vk).is_ok(),
        "Maximum counter value should be handled correctly"
    );

    Ok(())
}
