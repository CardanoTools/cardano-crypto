//! Operational Certificate Example
//!
//! Demonstrates how stake pool operators create and verify operational certificates
//! that bind cold keys to hot KES keys for block production.
//!
//! Run with: cargo run --example operational_cert

use cardano_crypto::dsign::{DsignAlgorithm, Ed25519};
use cardano_crypto::key::operational_cert::OperationalCertificate;
use cardano_crypto::key::kes_period::KesPeriod;
use cardano_crypto::kes::{KesAlgorithm, Sum6Kes};

fn main() {
    println!("=== Cardano Operational Certificate Example ===\n");

    // ========================================================================
    // Step 1: Generate Cold Key (Pool Operator)
    // ========================================================================
    println!("1. Generating pool operator cold key...");

    let cold_seed = [42u8; 32]; // In production: Use secure random seed
    let cold_signing_key = Ed25519::gen_key(&cold_seed);
    let cold_verification_key = Ed25519::derive_verification_key(&cold_signing_key);

    println!("   Cold verification key hash: {:02x?}...", &cold_verification_key.as_bytes()[..8]);
    println!();

    // ========================================================================
    // Step 2: Generate Hot KES Key (Time-Limited)
    // ========================================================================
    println!("2. Generating hot KES key...");

    let kes_seed = [99u8; 32]; // In production: Use secure random seed
    let (kes_signing_key, kes_verification_key) = Sum6Kes::keygen(&kes_seed).unwrap();

    println!("   KES verification key hash: {:02x?}...", &kes_verification_key.as_bytes()[..8]);
    println!("   KES key total periods: {}", Sum6Kes::total_periods());
    println!();

    // ========================================================================
    // Step 3: Create Operational Certificate
    // ========================================================================
    println!("3. Creating operational certificate...");

    let counter = 0; // First operational certificate
    let start_period = KesPeriod(100); // Certificate valid from period 100

    let operational_cert = OperationalCertificate::new(
        kes_verification_key.clone(),
        counter,
        start_period,
        &cold_signing_key,
    );

    println!("   Counter: {}", operational_cert.counter());
    println!("   Start period: {}", operational_cert.kes_period().0);
    println!("   Certificate created successfully!");
    println!();

    // ========================================================================
    // Step 4: Verify Cold Key Signature
    // ========================================================================
    println!("4. Verifying cold key signature...");

    match operational_cert.verify(&cold_verification_key) {
        Ok(()) => println!("   ✓ Signature valid - Cold key authorized this hot key"),
        Err(e) => println!("   ✗ Signature invalid: {:?}", e),
    }
    println!();

    // ========================================================================
    // Step 5: Validate Period (Block Production)
    // ========================================================================
    println!("5. Validating certificate for block production...");

    // Simulate current blockchain state
    let current_period = KesPeriod(105); // 5 periods after start
    let expected_counter = 0;

    match operational_cert.is_valid_for_period(current_period, expected_counter) {
        Ok(()) => {
            println!("   ✓ Certificate valid for period {}", current_period.0);
            println!("   Pool can sign blocks!");
        }
        Err(e) => println!("   ✗ Certificate invalid: {:?}", e),
    }
    println!();

    // ========================================================================
    // Step 6: Test Period Validation (Too Early)
    // ========================================================================
    println!("6. Testing period validation (period too early)...");

    let too_early = KesPeriod(99); // Before start period
    match operational_cert.is_valid_for_period(too_early, expected_counter) {
        Ok(()) => println!("   ✓ Unexpectedly valid!"),
        Err(_) => println!("   ✓ Correctly rejected - Period too early"),
    }
    println!();

    // ========================================================================
    // Step 7: Test Counter Validation
    // ========================================================================
    println!("7. Testing counter validation (wrong counter)...");

    let wrong_counter = 1; // Certificate counter is 0
    match operational_cert.is_valid_for_period(current_period, wrong_counter) {
        Ok(()) => println!("   ✓ Unexpectedly valid!"),
        Err(_) => println!("   ✓ Correctly rejected - Counter mismatch"),
    }
    println!();

    // ========================================================================
    // Step 8: Certificate Renewal (Higher Counter)
    // ========================================================================
    println!("8. Renewing operational certificate (new KES key)...");

    // Generate new KES key
    let new_kes_seed = [77u8; 32];
    let (_, new_kes_vk) = Sum6Kes::keygen(&new_kes_seed).unwrap();

    // Issue certificate with counter = 1 (must be > previous)
    let new_counter = 1;
    let new_start_period = KesPeriod(164); // 64 periods later (Sum6 max period)

    let renewed_cert = OperationalCertificate::new(
        new_kes_vk,
        new_counter,
        new_start_period,
        &cold_signing_key,
    );

    println!("   New counter: {}", renewed_cert.counter());
    println!("   New start period: {}", renewed_cert.kes_period().0);

    // Verify new certificate
    match renewed_cert.verify(&cold_verification_key) {
        Ok(()) => println!("   ✓ Renewed certificate signature valid"),
        Err(e) => println!("   ✗ Verification failed: {:?}", e),
    }
    println!();

    // ========================================================================
    // Step 9: Sign Block with KES Key
    // ========================================================================
    println!("9. Signing block with KES key (period {})...", current_period.0);

    let block_hash = b"block_header_hash_12345";
    let kes_signature = Sum6Kes::sign(&kes_signing_key, current_period.0, block_hash).unwrap();

    println!("   Block signed successfully");
    println!("   Signature size: {} bytes", kes_signature.to_bytes().len());

    // Verify block signature
    match Sum6Kes::verify(&kes_verification_key, current_period.0, block_hash, &kes_signature) {
        Ok(()) => println!("   ✓ Block signature verified"),
        Err(e) => println!("   ✗ Block verification failed: {:?}", e),
    }
    println!();

    // ========================================================================
    // Summary
    // ========================================================================
    println!("=== Summary ===");
    println!("Operational certificates enable secure block production by:");
    println!("1. Keeping cold keys offline (sign OCerts only)");
    println!("2. Using time-limited hot KES keys for block signing");
    println!("3. Preventing replay attacks via monotonic counters");
    println!("4. Validating period ranges for certificate validity");
    println!();
    println!("This matches cardano-cli operational certificate format!");
}
