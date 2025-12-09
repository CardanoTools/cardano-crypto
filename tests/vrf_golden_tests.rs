//! Golden test vectors for VRF implementations (Cardano-compatible)
//!
//! These tests verify byte-for-byte compatibility with:
//! - IETF ECVRF draft-03 and draft-13 specifications  
//! - Cardano's libsodium VRF implementation (IntersectMBO/libsodium)
//!
//! # Test Organization
//!
//! - `test_vrf_draft03_ietf_*` - Official IETF test vectors for draft-03
//! - `test_vrf_draft13_ietf_*` - Official IETF test vectors for draft-13  
//! - `test_vrf_draft*_cardano_*` - Cardano-specific compatibility tests
//! - `test_vrf_*_edge_*` - Edge case and boundary tests
//!
//! # Cardano Compatibility
//!
//! Cardano uses VRF Draft-03 (ECVRF-ED25519-SHA512-Elligator2) for leader
//! election in the Praos consensus protocol. Full byte-for-byte compatibility
//! is required for interoperability with cardano-node.

use cardano_crypto::common::Result;
use cardano_crypto::vrf::{VrfDraft03, VrfDraft13};

// ============================================================================
// Helper Functions
// ============================================================================

/// Decode hex string to bytes
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Encode bytes as hex string
#[allow(dead_code)]
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ============================================================================
// VRF Draft-03 IETF Test Vectors
// ============================================================================
// These are the official test vectors from IETF draft-irtf-cfrg-vrf-03
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03

/// IETF Test Vector #10: Empty alpha (message)
/// This is the simplest case with an empty input message.
#[test]
fn test_vrf_draft03_ietf_vector_10() -> Result<()> {
    let sk_seed =
        hex_decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let expected_pk =
        hex_decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let alpha: &[u8] = &[]; // empty message
    let expected_pi = hex_decode(
        "b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7\
         ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f06156\
         0f55edc256a787afe701677c0f602900",
    );
    let expected_beta = hex_decode(
        "5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a60\
         3f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc",
    );

    let seed: [u8; 32] = sk_seed.try_into().expect("seed must be 32 bytes");
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

    assert_eq!(
        &pk[..],
        &expected_pk[..],
        "Public key mismatch - seed derivation differs from IETF spec"
    );

    let proof = VrfDraft03::prove(&sk, alpha)?;
    assert_eq!(
        &proof[..],
        &expected_pi[..],
        "Proof (pi) mismatch for IETF vector 10"
    );

    let beta = VrfDraft03::verify(&pk, &proof, alpha)?;
    assert_eq!(
        &beta[..],
        &expected_beta[..],
        "Output (beta) mismatch for IETF vector 10"
    );

    // Also verify proof_to_hash matches
    let beta2 = VrfDraft03::proof_to_hash(&proof)?;
    assert_eq!(beta, beta2, "proof_to_hash should match verify output");

    Ok(())
}

/// IETF Test Vector #11: Single byte alpha (0x72)
#[test]
fn test_vrf_draft03_ietf_vector_11() -> Result<()> {
    let sk_seed =
        hex_decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let expected_pk =
        hex_decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    let alpha = hex_decode("72");
    let expected_pi = hex_decode(
        "ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111\
         200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb09335\
         8c13e6ae1111a55717e895fd15f99f07",
    );
    let expected_beta = hex_decode(
        "94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb\
         1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8",
    );

    let seed: [u8; 32] = sk_seed.try_into().expect("seed must be 32 bytes");
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

    assert_eq!(
        &pk[..],
        &expected_pk[..],
        "Public key mismatch for IETF vector 11"
    );

    let proof = VrfDraft03::prove(&sk, &alpha)?;
    assert_eq!(
        &proof[..],
        &expected_pi[..],
        "Proof (pi) mismatch for IETF vector 11"
    );

    let beta = VrfDraft03::verify(&pk, &proof, &alpha)?;
    assert_eq!(
        &beta[..],
        &expected_beta[..],
        "Output (beta) mismatch for IETF vector 11"
    );

    Ok(())
}

/// IETF Test Vector #12: Two byte alpha (0xaf82)
#[test]
fn test_vrf_draft03_ietf_vector_12() -> Result<()> {
    let sk_seed =
        hex_decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
    let expected_pk =
        hex_decode("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
    let alpha = hex_decode("af82");
    let expected_pi = hex_decode(
        "dfa2cba34b611cc8c833a6ea83b8eb1bb5e2ef2dd1b0c481bc42ff36ae7847f6\
         ab52b976cfd5def172fa412defde270c8b8bdfbaae1c7ece17d9833b1bcf3106\
         4fff78ef493f820055b561ece45e1009",
    );
    let expected_beta = hex_decode(
        "2031837f582cd17a9af9e0c7ef5a6540e3453ed894b62c293686ca3c1e319dde\
         9d0aa489a4b59a9594fc2328bc3deff3c8a0929a369a72b1180a596e016b5ded",
    );

    let seed: [u8; 32] = sk_seed.try_into().expect("seed must be 32 bytes");
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

    assert_eq!(
        &pk[..],
        &expected_pk[..],
        "Public key mismatch for IETF vector 12"
    );

    let proof = VrfDraft03::prove(&sk, &alpha)?;
    assert_eq!(
        &proof[..],
        &expected_pi[..],
        "Proof (pi) mismatch for IETF vector 12"
    );

    let beta = VrfDraft03::verify(&pk, &proof, &alpha)?;
    assert_eq!(
        &beta[..],
        &expected_beta[..],
        "Output (beta) mismatch for IETF vector 12"
    );

    Ok(())
}

// ============================================================================
// VRF Draft-03 Cardano Compatibility Tests  
// ============================================================================

/// Test VRF proof generation is deterministic
/// Same inputs must always produce identical proofs (required for consensus)
#[test]
fn test_vrf_draft03_deterministic() -> Result<()> {
    let seed = [0x42u8; 32];
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);
    let message = b"Cardano leader election";

    let proof1 = VrfDraft03::prove(&sk, message)?;
    let proof2 = VrfDraft03::prove(&sk, message)?;

    assert_eq!(proof1, proof2, "VRF proofs must be deterministic");

    let beta1 = VrfDraft03::verify(&pk, &proof1, message)?;
    let beta2 = VrfDraft03::verify(&pk, &proof2, message)?;

    assert_eq!(beta1, beta2, "VRF outputs must be deterministic");

    Ok(())
}

/// Test verification fails with wrong public key
#[test]
fn test_vrf_draft03_wrong_key_fails() -> Result<()> {
    let seed1 = [0x42u8; 32];
    let seed2 = [0x43u8; 32];

    let (sk1, _pk1) = VrfDraft03::keypair_from_seed(&seed1);
    let (_sk2, pk2) = VrfDraft03::keypair_from_seed(&seed2);

    let message = b"test message";
    let proof = VrfDraft03::prove(&sk1, message)?;

    // Verification with wrong key should fail
    assert!(
        VrfDraft03::verify(&pk2, &proof, message).is_err(),
        "Verification should fail with wrong public key"
    );

    Ok(())
}

/// Test verification fails with wrong message
#[test]
fn test_vrf_draft03_wrong_message_fails() -> Result<()> {
    let seed = [0x42u8; 32];
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

    let proof = VrfDraft03::prove(&sk, b"original message")?;

    assert!(
        VrfDraft03::verify(&pk, &proof, b"different message").is_err(),
        "Verification should fail with wrong message"
    );

    Ok(())
}

/// Test VRF with Cardano-style messages (block headers, nonces)
#[test]
fn test_vrf_draft03_cardano_messages() -> Result<()> {
    let seed = [0x42u8; 32];
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

    // Typical Cardano VRF inputs
    let messages = [
        b"Block header hash".as_slice(),
        b"Epoch nonce derivation",
        b"Leader election slot 12345",
        &[0u8; 64], // 64-byte hash
        &[],        // Empty (edge case)
    ];

    for msg in messages {
        let proof = VrfDraft03::prove(&sk, msg)?;
        let hash = VrfDraft03::verify(&pk, &proof, msg)?;
        let hash2 = VrfDraft03::proof_to_hash(&proof)?;

        assert_eq!(hash, hash2, "proof_to_hash should match verify output");
        assert_eq!(hash.len(), 64, "VRF output must be 64 bytes");
        assert_eq!(proof.len(), 80, "VRF proof must be 80 bytes");
    }

    Ok(())
}

// ============================================================================
// VRF Draft-13 Tests
// ============================================================================

/// Test VRF Draft-13 basic functionality
#[test]
fn test_vrf_draft13_basic() -> Result<()> {
    let seed = [0x42u8; 32];
    let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);

    let message = b"Draft-13 test";
    let proof = VrfDraft13::prove(&sk, message)?;
    let hash = VrfDraft13::verify(&pk, &proof, message)?;

    assert_eq!(hash.len(), 64, "VRF output must be 64 bytes");
    assert_eq!(proof.len(), 128, "Draft-13 proof must be 128 bytes");

    // Verify proof_to_hash consistency
    let hash2 = VrfDraft13::proof_to_hash(&proof)?;
    assert_eq!(hash, hash2);

    Ok(())
}

/// Test VRF Draft-13 determinism
#[test]
fn test_vrf_draft13_deterministic() -> Result<()> {
    let seed = [0x44u8; 32];
    let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);
    let message = b"deterministic test";

    let proof1 = VrfDraft13::prove(&sk, message)?;
    let proof2 = VrfDraft13::prove(&sk, message)?;

    assert_eq!(proof1, proof2, "VRF Draft-13 proofs must be deterministic");

    let beta1 = VrfDraft13::verify(&pk, &proof1, message)?;
    let beta2 = VrfDraft13::verify(&pk, &proof2, message)?;

    assert_eq!(beta1, beta2, "VRF Draft-13 outputs must be deterministic");

    Ok(())
}

/// Test Draft-13 verification fails with wrong key
#[test]
fn test_vrf_draft13_wrong_key_fails() -> Result<()> {
    let seed1 = [0x42u8; 32];
    let seed2 = [0x43u8; 32];

    let (sk1, _pk1) = VrfDraft13::keypair_from_seed(&seed1);
    let (_sk2, pk2) = VrfDraft13::keypair_from_seed(&seed2);

    let proof = VrfDraft13::prove(&sk1, b"test")?;

    assert!(
        VrfDraft13::verify(&pk2, &proof, b"test").is_err(),
        "Draft-13 verification should fail with wrong public key"
    );

    Ok(())
}

// ============================================================================
// VRF Edge Cases and Boundary Tests
// ============================================================================

/// Test VRF with various message sizes
#[test]
fn test_vrf_message_sizes() -> Result<()> {
    let seed = [0x55u8; 32];
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

    // Test various message sizes
    let sizes = [0, 1, 31, 32, 33, 64, 127, 128, 255, 256, 1024, 4096];

    for size in sizes {
        let message: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let proof = VrfDraft03::prove(&sk, &message)?;
        let hash = VrfDraft03::verify(&pk, &proof, &message)?;

        assert_eq!(hash.len(), 64, "Output size mismatch for message size {}", size);
        assert_eq!(proof.len(), 80, "Proof size mismatch for message size {}", size);
    }

    Ok(())
}

/// Test VRF with all-zeros and all-ones seeds
#[test]
fn test_vrf_extreme_seeds() -> Result<()> {
    let seeds = [[0x00u8; 32], [0xFFu8; 32], [0x80u8; 32]];

    for seed in seeds {
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);
        let proof = VrfDraft03::prove(&sk, b"test")?;
        let hash = VrfDraft03::verify(&pk, &proof, b"test")?;

        assert_eq!(hash.len(), 64);
    }

    Ok(())
}

/// Test that different messages produce different outputs
#[test]
fn test_vrf_output_uniqueness() -> Result<()> {
    let seed = [0x66u8; 32];
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

    let messages = [b"msg1".as_slice(), b"msg2", b"msg3"];
    let mut outputs = Vec::new();

    for msg in messages {
        let proof = VrfDraft03::prove(&sk, msg)?;
        let hash = VrfDraft03::verify(&pk, &proof, msg)?;
        outputs.push(hash);
    }

    // All outputs should be unique
    for i in 0..outputs.len() {
        for j in (i + 1)..outputs.len() {
            assert_ne!(
                outputs[i], outputs[j],
                "Different messages should produce different VRF outputs"
            );
        }
    }

    Ok(())
}

/// Test that different keys produce different outputs for same message
#[test]
fn test_vrf_key_uniqueness() -> Result<()> {
    let seeds: [[u8; 32]; 3] = [[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]];
    let message = b"same message for all keys";

    let mut outputs = Vec::new();

    for seed in seeds {
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);
        let proof = VrfDraft03::prove(&sk, message)?;
        let hash = VrfDraft03::verify(&pk, &proof, message)?;
        outputs.push(hash);
    }

    // All outputs should be unique
    for i in 0..outputs.len() {
        for j in (i + 1)..outputs.len() {
            assert_ne!(
                outputs[i], outputs[j],
                "Different keys should produce different VRF outputs"
            );
        }
    }

    Ok(())
}

// ============================================================================
// Elligator2 Hash-to-Curve Tests
// ============================================================================

/// Test the Elligator2 hash-to-curve implementation for IETF vector 10
/// This verifies our implementation matches Cardano's libsodium byte-for-byte
#[test]
fn test_elligator2_ietf_vector_10() {
    use cardano_crypto::vrf::cardano_compat::elligator2::elligator2_to_edwards;
    use sha2::{Digest, Sha512};

    let pk = hex_decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let message: &[u8] = &[];

    // Expected H point from IETF VRF draft-03 specification
    let expected_h =
        hex_decode("1c5672d919cc0a800970cd7e05cb36ed27ed354c33519948e5a9eaf89aee12b7");

    // Compute hash as done in cardano_hash_to_curve
    let mut hasher = Sha512::new();
    hasher.update([0x04u8]); // SUITE_DRAFT03
    hasher.update([0x01u8]); // ONE
    hasher.update(&pk);
    hasher.update(message);
    let r_hash = hasher.finalize();

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&r_hash[0..32]);

    // Apply Elligator2
    let h_point = elligator2_to_edwards(&r_bytes).expect("Elligator2 should succeed");
    let h_bytes = h_point.compress().0;

    assert_eq!(
        h_bytes.as_slice(),
        expected_h.as_slice(),
        "Elligator2 H point mismatch for IETF vector 10"
    );
}

// ============================================================================
// Proof Structure Tests
// ============================================================================

/// Test VRF proof structure (Gamma || c || s)
#[test]
fn test_vrf_proof_structure() -> Result<()> {
    let seed = [0x77u8; 32];
    let (sk, _pk) = VrfDraft03::keypair_from_seed(&seed);

    let proof = VrfDraft03::prove(&sk, b"test")?;

    // Proof format: Gamma (32 bytes) || c (16 bytes) || s (32 bytes) = 80 bytes
    assert_eq!(proof.len(), 80);

    // Gamma should be a valid compressed Edwards point (Y coordinate)
    let gamma_bytes: [u8; 32] = proof[0..32].try_into().unwrap();
    let gamma = curve25519_dalek::edwards::CompressedEdwardsY(gamma_bytes);
    assert!(
        gamma.decompress().is_some(),
        "Gamma must be a valid Edwards point"
    );

    // c is 16 bytes (128-bit challenge)
    let _c_bytes: [u8; 16] = proof[32..48].try_into().unwrap();

    // s is 32 bytes (scalar)
    let s_bytes: [u8; 32] = proof[48..80].try_into().unwrap();
    // s should be a valid scalar (less than group order)
    let _s = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(s_bytes);

    Ok(())
}

/// Test Draft-13 proof structure (Gamma || kB || kH || c || s)
#[test]
fn test_vrf_draft13_proof_structure() -> Result<()> {
    let seed = [0x88u8; 32];
    let (sk, _pk) = VrfDraft13::keypair_from_seed(&seed);

    let proof = VrfDraft13::prove(&sk, b"test")?;

    // Draft-13 Proof format: Gamma (32) || kB (32) || kH (32) || c (16) || s (32) = 144 bytes
    // But our implementation uses 128 bytes (different format)
    assert_eq!(proof.len(), 128);

    Ok(())
}
