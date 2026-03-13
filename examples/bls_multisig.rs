//! BLS Multi-Signature Example
//!
//! Demonstrates BLS12-381 aggregate signatures for multi-party signing ceremonies,
//! such as Cardano governance voting or threshold signature schemes.
//!
//! Run with: cargo run --example bls_multisig --features bls

#[cfg(not(feature = "bls"))]
fn main() {
    println!("This example requires the 'bls' feature.");
    println!("Run with: cargo run --example bls_multisig --features bls");
}

#[cfg(feature = "bls")]
fn main() {
    use cardano_crypto::bls::{Bls12381, BlsSecretKey};
    use cardano_crypto::common::traits::DsignAggregatable;

    println!("=== BLS Multi-Signature Example ===\n");

    // ========================================================================
    // Scenario: Cardano Governance Committee Vote
    // 5 committee members need to vote on a proposal
    // ========================================================================

    println!("Scenario: Cardano Governance Committee Vote");
    println!("5 committee members voting on proposal #42\n");

    // ========================================================================
    // Step 1: Committee Setup (Key Generation)
    // ========================================================================
    println!("1. Setting up committee members...");

    let members = vec![
        ("Alice", [1u8; 32]),
        ("Bob", [2u8; 32]),
        ("Carol", [3u8; 32]),
        ("Dave", [4u8; 32]),
        ("Eve", [5u8; 32]),
    ];

    let mut keys = Vec::new();

    for (name, seed) in &members {
        let sk = BlsSecretKey::from_bytes(seed).unwrap();
        let pk = sk.public_key();
        let pop = Bls12381::generate_possession_proof(&sk);

        println!("   {} - Key generated", name);
        println!("      Public key: {:02x?}...", &pk.to_compressed()[..8]);

        keys.push((name.to_string(), sk, pk, pop));
    }
    println!();

    // ========================================================================
    // Step 2: Proof of Possession Verification
    // ========================================================================
    println!("2. Verifying Proofs of Possession (prevents rogue key attacks)...");

    for (name, _, pk, pop) in &keys {
        let valid = Bls12381::verify_possession_proof(pk, pop);
        if valid {
            println!("   ✓ {} - PoP verified", name);
        } else {
            println!("   ✗ {} - PoP INVALID (would be rejected)", name);
            return;
        }
    }
    println!();

    // ========================================================================
    // Step 3: Each Member Signs the Vote
    // ========================================================================
    println!("3. Committee members signing proposal...");

    let proposal_vote = b"VOTE: Approve Proposal #42 - Treasury Allocation";

    let mut signatures = Vec::new();
    let mut public_keys = Vec::new();

    for (name, sk, pk, _) in &keys {
        let signature = sk.sign(proposal_vote);
        println!("   {} signed the vote", name);

        signatures.push(signature);
        public_keys.push(pk.clone());
    }
    println!();

    // ========================================================================
    // Step 4: Aggregate Signatures
    // ========================================================================
    println!("4. Aggregating signatures...");

    let aggregate_signature = Bls12381::aggregate_signatures(&signatures).unwrap();
    println!(
        "   ✓ {} individual signatures → 1 aggregate signature",
        signatures.len()
    );
    println!(
        "   Aggregate signature size: {} bytes",
        aggregate_signature.to_compressed().len()
    );
    println!();

    // ========================================================================
    // Step 5: Aggregate Public Keys
    // ========================================================================
    println!("5. Aggregating public keys...");

    let aggregate_key = Bls12381::aggregate_verification_keys(&public_keys).unwrap();
    println!("   ✓ {} public keys → 1 aggregate key", public_keys.len());
    println!(
        "   Aggregate key size: {} bytes",
        aggregate_key.to_compressed().len()
    );
    println!();

    // ========================================================================
    // Step 6: Verify Aggregate Signature
    // ========================================================================
    println!("6. Verifying aggregate signature...");

    use cardano_crypto::bls::bls_verify;
    match bls_verify(&aggregate_key, proposal_vote, &aggregate_signature) {
        Ok(()) => {
            println!("   ✓ Aggregate signature VALID");
            println!("   All 5 committee members approved the proposal!");
        }
        Err(_) => {
            println!("   ✗ Aggregate signature INVALID");
            return;
        }
    }
    println!();

    // ========================================================================
    // Step 7: Demonstrate Size Savings
    // ========================================================================
    println!("7. Size comparison:");

    let individual_size = signatures
        .iter()
        .map(|s| s.to_compressed().len())
        .sum::<usize>();
    let aggregate_size = aggregate_signature.to_compressed().len();

    println!(
        "   Individual signatures: {} bytes ({} × 96)",
        individual_size,
        signatures.len()
    );
    println!("   Aggregate signature:   {} bytes", aggregate_size);
    println!(
        "   Space saved:           {} bytes ({}%)",
        individual_size - aggregate_size,
        ((individual_size - aggregate_size) as f64 / individual_size as f64 * 100.0) as usize
    );
    println!();

    // ========================================================================
    // Step 8: Partial Signature (Threshold)
    // ========================================================================
    println!("8. Threshold scenario: Only 3 out of 5 members sign...");

    // Take first 3 signatures
    let threshold_sigs = &signatures[0..3];
    let threshold_keys = &public_keys[0..3];

    let threshold_agg_sig = Bls12381::aggregate_signatures(threshold_sigs).unwrap();
    let threshold_agg_key = Bls12381::aggregate_verification_keys(threshold_keys).unwrap();

    match bls_verify(&threshold_agg_key, proposal_vote, &threshold_agg_sig) {
        Ok(()) => {
            println!("   ✓ 3-of-5 threshold signature VALID");
            println!("   Signers: Alice, Bob, Carol");
        }
        Err(_) => {
            println!("   ✗ Threshold verification failed");
        }
    }
    println!();

    // ========================================================================
    // Step 9: Security Demo - Wrong Message Fails
    // ========================================================================
    println!("9. Security check: Wrong message should fail...");

    let wrong_message = b"VOTE: Reject Proposal #42";
    match bls_verify(&aggregate_key, wrong_message, &aggregate_signature) {
        Ok(()) => {
            println!("   ✗ SECURITY FAILURE - Wrong message verified!");
        }
        Err(_) => {
            println!("   ✓ Wrong message correctly rejected");
        }
    }
    println!();

    // ========================================================================
    // Step 10: Individual Verification Still Works
    // ========================================================================
    println!("10. Individual signature verification (for auditing)...");

    for (i, ((name, _, pk, _), sig)) in keys.iter().zip(signatures.iter()).enumerate() {
        match bls_verify(pk, proposal_vote, sig) {
            Ok(()) => println!("   ✓ Member {} ({}) - Signature valid", i + 1, name),
            Err(_) => println!("   ✗ Member {} ({}) - Signature INVALID", i + 1, name),
        }
    }
    println!();

    // ========================================================================
    // Summary
    // ========================================================================
    println!("=== Summary ===");
    println!();
    println!("BLS Multi-Signatures provide:");
    println!("1. **Compact Size** - Aggregate signature = single signature size");
    println!("2. **Efficient Verification** - One pairing operation for all signers");
    println!("3. **Threshold Support** - Any subset can create valid aggregate");
    println!("4. **Rogue Key Protection** - Proof of Possession prevents attacks");
    println!();
    println!("Use cases in Cardano:");
    println!("• Governance committee voting (CIP-1694)");
    println!("• Multi-party threshold signatures");
    println!("• Batch transaction validation");
    println!("• Cross-chain bridge signatures");
    println!();
    println!(
        "Space efficiency: {}%",
        ((individual_size - aggregate_size) as f64 / individual_size as f64 * 100.0) as usize
    );
}
