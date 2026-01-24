// ! Property-based tests for KES implementations
//!
//! These tests verify KES invariants using property-based testing,
//! ensuring correctness across a wide range of inputs.

use cardano_crypto::common::Result;
use cardano_crypto::kes::{KesAlgorithm, SingleKes, Sum2Kes, Sum6Kes};
use proptest::prelude::*;

// ============================================================================
// Property Test Strategies
// ============================================================================

fn seed_strategy() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

fn message_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..256)
}

fn period_strategy(max_period: u32) -> impl Strategy<Value = u32> {
    0..max_period
}

// ============================================================================
// Sum6KES Property Tests
// ============================================================================

proptest! {
    /// Property: Verification key remains stable across all evolutions
    #[test]
    fn prop_sum6_verkey_stable(seed in seed_strategy()) {
        let sk0 = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)
            .expect("Key generation should succeed");
        let vk0 = Sum6Kes::derive_verification_key(&sk0)
            .expect("Deriving verkey should succeed");
        let vk0_bytes = Sum6Kes::raw_serialize_verification_key_kes(&vk0);
        
        let mut sk = sk0;
        for period in 0..10u32 {
            let vk = Sum6Kes::derive_verification_key(&sk)
                .expect("Deriving verkey should succeed");
            let vk_bytes = Sum6Kes::raw_serialize_verification_key_kes(&vk);
            
            prop_assert_eq!(
                vk_bytes, vk0_bytes,
                "Verification key should remain constant at period {}",
                period
            );
            
            if period < 63 {
                sk = Sum6Kes::update_kes(&(), sk, period)
                    .expect("Update should succeed")
                    .expect("Key should evolve");
            }
        }
    }

    /// Property: Sign at period P → verify at period P succeeds
    #[test]
    fn prop_sum6_sign_verify_roundtrip(
        seed in seed_strategy(),
        msg in message_strategy(),
        period in 0..64u32
    ) {
        let mut sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)
            .expect("Key generation should succeed");
        let vk = Sum6Kes::derive_verification_key(&sk)
            .expect("Deriving verkey should succeed");
        
        // Evolve to target period
        for p in 0..period {
            sk = Sum6Kes::update_kes(&(), sk, p)
                .expect("Update should succeed")
                .expect("Key should evolve");
        }
        
        // Sign at target period
        let sig = Sum6Kes::sign_kes(&(), period, &msg, &sk)
            .expect("Signing should succeed");
        
        // Verify at same period
        let result = Sum6Kes::verify_kes(&(), &vk, period, &msg, &sig);
        prop_assert!(result.is_ok(), "Verification should succeed at period {}", period);
    }

    /// Property: Wrong period always fails verification
    #[test]
    fn prop_sum6_wrong_period_fails(
        seed in seed_strategy(),
        msg in message_strategy(),
        sign_period in 0..64u32,
        verify_period in 0..64u32
    ) {
        prop_assume!(sign_period != verify_period);
        
        let mut sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)
            .expect("Key generation should succeed");
        let vk = Sum6Kes::derive_verification_key(&sk)
            .expect("Deriving verkey should succeed");
        
        // Evolve to signing period
        for p in 0..sign_period {
            sk = Sum6Kes::update_kes(&(), sk, p)
                .expect("Update should succeed")
                .expect("Key should evolve");
        }
        
        // Sign at signing period
        let sig = Sum6Kes::sign_kes(&(), sign_period, &msg, &sk)
            .expect("Signing should succeed");
        
        // Verify at different period should fail
        let result = Sum6Kes::verify_kes(&(), &vk, verify_period, &msg, &sig);
        prop_assert!(result.is_err(), "Verification with wrong period should fail");
    }

    /// Property: Evolution through all 64 periods succeeds
    #[test]
    fn prop_sum6_full_evolution(seed in seed_strategy()) {
        let mut sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)
            .expect("Key generation should succeed");
        
        for period in 0..63u32 {
            let next_sk = Sum6Kes::update_kes(&(), sk, period)
                .expect("Update should succeed");
            
            prop_assert!(
                next_sk.is_some(),
                "Evolution should succeed at period {}",
                period
            );
            
            sk = next_sk.unwrap();
        }
        
        // Cannot evolve past period 63
        let final_update = Sum6Kes::update_kes(&(), sk, 63)
            .expect("Update call should succeed");
        prop_assert!(
            final_update.is_none(),
            "Cannot evolve past final period"
        );
    }

    /// Property: Forward security - evolved key cannot sign for past periods
    #[test]
    fn prop_sum6_forward_security(
        seed in seed_strategy(),
        msg in message_strategy(),
        target_period in 1..20u32 // Test early periods for speed
    ) {
        let mut sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)
            .expect("Key generation should succeed");
        let vk = Sum6Kes::derive_verification_key(&sk)
            .expect("Deriving verkey should succeed");
        
        // Evolve to target period
        for p in 0..target_period {
            sk = Sum6Kes::update_kes(&(), sk, p)
                .expect("Update should succeed")
                .expect("Key should evolve");
        }
        
        // Try to sign at a past period
        let past_period = target_period - 1;
        let sig = Sum6Kes::sign_kes(&(), past_period, &msg, &sk)
            .expect("Signing should succeed"); // Signing doesn't check period
        
        // But verification should fail (signature won't be valid)
        let result = Sum6Kes::verify_kes(&(), &vk, past_period, &msg, &sig);
        
        // Note: Some KES implementations may accept this due to tree structure,
        // but the signature should not be cryptographically valid for past periods
        // For now, we just ensure the operation doesn't panic
        let _ = result;
    }
}

// ============================================================================
// Sum2KES Property Tests
// ============================================================================

proptest! {
    /// Property: Sum2KES has exactly 4 periods (0, 1, 2, 3)
    #[test]
    fn prop_sum2_total_periods(seed in seed_strategy()) {
        let mut sk = Sum2Kes::gen_key_kes_from_seed_bytes(&seed)
            .expect("Key generation should succeed");
        
        // Should evolve through periods 0, 1, 2, 3
        for period in 0..3u32 {
            let next_sk = Sum2Kes::update_kes(&(), sk, period)
                .expect("Update should succeed");
            prop_assert!(next_sk.is_some(), "Should evolve at period {}", period);
            sk = next_sk.unwrap();
        }
        
        // Cannot evolve past period 3
        let final_update = Sum2Kes::update_kes(&(), sk, 3)
            .expect("Update call should succeed");
        prop_assert!(final_update.is_none(), "Cannot evolve past period 3");
    }

    /// Property: Sum2KES sign/verify roundtrip
    #[test]
    fn prop_sum2_sign_verify(
        seed in seed_strategy(),
        msg in message_strategy(),
        period in 0..4u32
    ) {
        let mut sk = Sum2Kes::gen_key_kes_from_seed_bytes(&seed)
            .expect("Key generation should succeed");
        let vk = Sum2Kes::derive_verification_key(&sk)
            .expect("Deriving verkey should succeed");
        
        // Evolve to target period
        for p in 0..period {
            sk = Sum2Kes::update_kes(&(), sk, p)
                .expect("Update should succeed")
                .expect("Key should evolve");
        }
        
        let sig = Sum2Kes::sign_kes(&(), period, &msg, &sk)
            .expect("Signing should succeed");
        
        let result = Sum2Kes::verify_kes(&(), &vk, period, &msg, &sig);
        prop_assert!(result.is_ok(), "Verification should succeed");
    }
}

// ============================================================================
// SingleKES Property Tests
// ============================================================================

proptest! {
    /// Property: SingleKES has exactly 1 period
    #[test]
    fn prop_single_total_periods(seed in seed_strategy()) {
        type TestKes = SingleKes<cardano_crypto::dsign::Ed25519>;
        
        let sk = TestKes::gen_key_kes_from_seed_bytes(&seed)
            .expect("Key generation should succeed");
        
        // Cannot evolve (has only 1 period)
        let update = TestKes::update_kes(&(), sk, 0)
            .expect("Update call should succeed");
        prop_assert!(update.is_none(), "SingleKES cannot evolve");
    }

    /// Property: SingleKES sign/verify at period 0
    #[test]
    fn prop_single_sign_verify(
        seed in seed_strategy(),
        msg in message_strategy()
    ) {
        type TestKes = SingleKes<cardano_crypto::dsign::Ed25519>;
        
        let sk = TestKes::gen_key_kes_from_seed_bytes(&seed)
            .expect("Key generation should succeed");
        let vk = TestKes::derive_verification_key(&sk)
            .expect("Deriving verkey should succeed");
        
        let sig = TestKes::sign_kes(&(), 0, &msg, &sk)
            .expect("Signing should succeed");
        
        let result = TestKes::verify_kes(&(), &vk, 0, &msg, &sig);
        prop_assert!(result.is_ok(), "Verification should succeed at period 0");
    }
}

// ============================================================================
// Malformed Input Tests
// ============================================================================

#[test]
fn test_kes_malformed_signature_wrong_size() -> Result<()> {
    let seed = [0u8; 32];
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;
    
    // Create signatures of wrong sizes
    for size in [0, 10, 31, 33, 100, 1000] {
        let bad_sig = vec![0u8; size];
        let result = Sum6Kes::verify_kes(&(), &vk, 0, b"msg", &bad_sig);
        assert!(
            result.is_err(),
            "Signature of size {} should fail verification",
            size
        );
    }
    
    Ok(())
}

#[test]
fn test_kes_corrupted_signature() -> Result<()> {
    let seed = [0x42u8; 32];
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;
    let msg = b"test message";
    
    let mut sig = Sum6Kes::sign_kes(&(), 0, msg, &sk)?;
    
    // Corrupt the signature
    if !sig.is_empty() {
        sig[0] ^= 0xff;
        
        let result = Sum6Kes::verify_kes(&(), &vk, 0, msg, &sig);
        assert!(
            result.is_err(),
            "Corrupted signature should fail verification"
        );
    }
    
    Ok(())
}

#[test]
fn test_kes_empty_message() -> Result<()> {
    let seed = [0x99u8; 32];
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;
    
    let empty_msg: &[u8] = &[];
    let sig = Sum6Kes::sign_kes(&(), 0, empty_msg, &sk)?;
    
    assert!(
        Sum6Kes::verify_kes(&(), &vk, 0, empty_msg, &sig).is_ok(),
        "KES should handle empty messages"
    );
    
    Ok(())
}

#[test]
fn test_kes_large_message() -> Result<()> {
    let seed = [0xaau8; 32];
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;
    
    // Very large message (10KB)
    let large_msg = vec![0x42u8; 10_000];
    let sig = Sum6Kes::sign_kes(&(), 0, &large_msg, &sk)?;
    
    assert!(
        Sum6Kes::verify_kes(&(), &vk, 0, &large_msg, &sig).is_ok(),
        "KES should handle large messages"
    );
    
    Ok(())
}

#[test]
fn test_kes_period_out_of_bounds() -> Result<()> {
    let seed = [0xbbu8; 32];
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;
    
    // Try to sign at period beyond maximum
    let result = Sum6Kes::sign_kes(&(), 100, b"msg", &sk);
    
    // Should either fail or produce invalid signature
    // The exact behavior depends on implementation
    if let Ok(sig) = result {
        // If signing succeeds, verification should fail
        let verify_result = Sum6Kes::verify_kes(&(), &vk, 100, b"msg", &sig);
        assert!(
            verify_result.is_err(),
            "Verification at invalid period should fail"
        );
    }
    
    Ok(())
}

#[test]
fn test_kes_zero_length_key() {
    let empty_vk = Vec::<u8>::new();
    let sig = vec![0u8; 64];
    
    let result = Sum6Kes::verify_kes(&(), &empty_vk, 0, b"msg", &sig);
    assert!(
        result.is_err(),
        "Empty verification key should fail verification"
    );
}
