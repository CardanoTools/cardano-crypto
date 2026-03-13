#![cfg(feature = "vrf")]
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
    let sk_seed = hex_decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
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
    let sk_seed = hex_decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
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
    let sk_seed = hex_decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
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
// VRF Draft-03 Cardano Generated Test Vectors
// ============================================================================
// These vectors are from IntersectMBO/cardano-base cardano-crypto-praos test suite.
// Source: cardano-crypto-praos/test_vectors/vrf_ver03_generated_*

/// Draft-03 generated test vector 1: all-zero seed, single zero byte
#[test]
fn test_vrf_draft03_generated_1() -> Result<()> {
    let sk_seed = hex_decode("0000000000000000000000000000000000000000000000000000000000000000");
    let expected_pk =
        hex_decode("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
    let alpha = hex_decode("00");
    let expected_pi = hex_decode(
        "000f006e64c91f84212919fe0899970cd341206fc081fe599339c8492e2cea329\
         9ae9de4b6ce21cda0a975f65f45b70f82b3952ba6d0dbe11a06716e67aca233c\
         0d78f115a655aa1952ada9f3d692a0a",
    );
    let expected_beta = hex_decode(
        "9930b5dddc0938f01cf6f9746eded569ee676bd6ff3b4f19233d74b903ec53a4\
         5c5728116088b7c622b6d6c354f7125c7d09870b56ec6f1e4bf4970f607e04b2",
    );

    let seed: [u8; 32] = sk_seed.try_into().expect("seed must be 32 bytes");
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);
    assert_eq!(&pk[..], &expected_pk[..], "Public key mismatch");

    let proof = VrfDraft03::prove(&sk, &alpha)?;
    assert_eq!(
        &proof[..],
        &expected_pi[..],
        "Proof mismatch for draft03 generated_1.\nExpected: {}\nGot:      {}",
        hex_encode(&expected_pi),
        hex_encode(&proof)
    );

    let beta = VrfDraft03::verify(&pk, &proof, &alpha)?;
    assert_eq!(&beta[..], &expected_beta[..], "Output (beta) mismatch");

    let beta2 = VrfDraft03::proof_to_hash(&proof)?;
    assert_eq!(beta, beta2, "proof_to_hash should match verify output");

    Ok(())
}

/// Draft-03 generated test vector 2: all-zero seed, 10-byte alpha
#[test]
fn test_vrf_draft03_generated_2() -> Result<()> {
    let sk_seed = hex_decode("0000000000000000000000000000000000000000000000000000000000000000");
    let expected_pk =
        hex_decode("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
    let alpha = hex_decode("00010203040506070809");
    let expected_pi = hex_decode(
        "0031f929352875995e3d55c4abdac7bfb92e706beb182999dd7d78f61e1bdc3f\
         83b746a9ae6caee317a7c47597ece1801799c06ca2180cdb5392677cd8815353\
         c1d0d5691956b3be52b322be049fc20c",
    );
    let expected_beta = hex_decode(
        "ca4171883d173a3f03bdb87c45ce349f0bb168ca8171d64f9b9aeaf20d0869ba\
         b9f74e819ccdc6754656468ccc2aa85e5f903a31375a39be84464fa515b51512",
    );

    let seed: [u8; 32] = sk_seed.try_into().expect("seed must be 32 bytes");
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);
    assert_eq!(&pk[..], &expected_pk[..], "Public key mismatch");

    let proof = VrfDraft03::prove(&sk, &alpha)?;
    assert_eq!(
        &proof[..],
        &expected_pi[..],
        "Proof mismatch for draft03 generated_2.\nExpected: {}\nGot:      {}",
        hex_encode(&expected_pi),
        hex_encode(&proof)
    );

    let beta = VrfDraft03::verify(&pk, &proof, &alpha)?;
    assert_eq!(&beta[..], &expected_beta[..], "Output (beta) mismatch");

    Ok(())
}

/// Draft-03 generated test vector 3: non-zero seed, single zero byte
#[test]
fn test_vrf_draft03_generated_3() -> Result<()> {
    let sk_seed = hex_decode("a70b8f607568df8ae26cf438b1057d8d0a94b7f3ac44cd984577fc43c2da55b7");
    let expected_pk =
        hex_decode("f1eb347d5c59e24f9f5f33c80cfd866e79fd72e0c370da3c011b1c9f045e23f1");
    let alpha = hex_decode("00");
    let expected_pi = hex_decode(
        "aa349327d919c8c96de316855de6fe5fa841ef25af913cfb9b33d6b663c425bd\
         024456ca193f10da319a2205c67222e8a62da87101904f453de0beb79568902c\
         edeea891f3db8202690f51c8e7d3210b",
    );
    let expected_beta = hex_decode(
        "d4b4deef941fc3ece4e86f837c784951b4a0cbc4accd79cdcbc882123befeb17\
         c63b329730c59bbe9253294496f730428d588b9221832cb336bfd9d67754030f",
    );

    let seed: [u8; 32] = sk_seed.try_into().expect("seed must be 32 bytes");
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);
    assert_eq!(&pk[..], &expected_pk[..], "Public key mismatch");

    let proof = VrfDraft03::prove(&sk, &alpha)?;
    assert_eq!(
        &proof[..],
        &expected_pi[..],
        "Proof mismatch for draft03 generated_3.\nExpected: {}\nGot:      {}",
        hex_encode(&expected_pi),
        hex_encode(&proof)
    );

    let beta = VrfDraft03::verify(&pk, &proof, &alpha)?;
    assert_eq!(&beta[..], &expected_beta[..], "Output (beta) mismatch");

    Ok(())
}

/// Draft-03 generated test vector 4: non-zero seed, 10-byte alpha
#[test]
fn test_vrf_draft03_generated_4() -> Result<()> {
    let sk_seed = hex_decode("a70b8f607568df8ae26cf438b1057d8d0a94b7f3ac44cd984577fc43c2da55b7");
    let expected_pk =
        hex_decode("f1eb347d5c59e24f9f5f33c80cfd866e79fd72e0c370da3c011b1c9f045e23f1");
    let alpha = hex_decode("00010203040506070809");
    let expected_pi = hex_decode(
        "989c0c477b4a0c07e0dabd7b73cdb42beb4b4e09471377e6d0b75e8ffd5d0917\
         04394c5ea4e2be5d5244b02c03cf85984adfa12c61280bc8c6e46f02035ee57d\
         6cd18b96695ea04ff5ec541869ea890a",
    );
    let expected_beta = hex_decode(
        "933f886e8648796a968dccc71a3ce09a8026b28fdf5ffcc50be4b97431f3e390\
         4375870b0bd196509dc33606846bb14820acdf36170e1667dbe9d3a940717bbd",
    );

    let seed: [u8; 32] = sk_seed.try_into().expect("seed must be 32 bytes");
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);
    assert_eq!(&pk[..], &expected_pk[..], "Public key mismatch");

    let proof = VrfDraft03::prove(&sk, &alpha)?;
    assert_eq!(
        &proof[..],
        &expected_pi[..],
        "Proof mismatch for draft03 generated_4.\nExpected: {}\nGot:      {}",
        hex_encode(&expected_pi),
        hex_encode(&proof)
    );

    let beta = VrfDraft03::verify(&pk, &proof, &alpha)?;
    assert_eq!(&beta[..], &expected_beta[..], "Output (beta) mismatch");

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

        assert_eq!(
            hash.len(),
            64,
            "Output size mismatch for message size {}",
            size
        );
        assert_eq!(
            proof.len(),
            80,
            "Proof size mismatch for message size {}",
            size
        );
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
    let expected_h = hex_decode("1c5672d919cc0a800970cd7e05cb36ed27ed354c33519948e5a9eaf89aee12b7");

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

/// Test Draft-13 batchcompat proof structure (Gamma || kB || kH || s)
#[test]
fn test_vrf_draft13_proof_structure() -> Result<()> {
    let seed = [0x88u8; 32];
    let (sk, _pk) = VrfDraft13::keypair_from_seed(&seed);

    let proof = VrfDraft13::prove(&sk, b"test")?;

    // Batchcompat proof format: Gamma(32) || kB(32) || kH(32) || s(32) = 128 bytes
    assert_eq!(proof.len(), 128);

    // Gamma should be a valid compressed Edwards point
    let gamma_bytes: [u8; 32] = proof[0..32].try_into().unwrap();
    let gamma = curve25519_dalek::edwards::CompressedEdwardsY(gamma_bytes);
    assert!(
        gamma.decompress().is_some(),
        "Gamma must be a valid Edwards point"
    );

    // kB (U) should be a valid compressed Edwards point
    let kb_bytes: [u8; 32] = proof[32..64].try_into().unwrap();
    let kb = curve25519_dalek::edwards::CompressedEdwardsY(kb_bytes);
    assert!(
        kb.decompress().is_some(),
        "kB must be a valid Edwards point"
    );

    // kH (V) should be a valid compressed Edwards point
    let kh_bytes: [u8; 32] = proof[64..96].try_into().unwrap();
    let kh = curve25519_dalek::edwards::CompressedEdwardsY(kh_bytes);
    assert!(
        kh.decompress().is_some(),
        "kH must be a valid Edwards point"
    );

    Ok(())
}

// ============================================================================
// VRF Draft-13 Batchcompat Golden Test Vectors
// ============================================================================
// These vectors are from IntersectMBO/cardano-base cardano-crypto-praos test suite.
// They verify byte-for-byte compatibility with the upstream C implementation.
// Source: cardano-crypto-praos/test_vectors/vrf_ver13_*

/// Draft-13 batchcompat test vector: generated_1 (all-zero seed, single zero byte message)
#[test]
fn test_vrf_draft13_batchcompat_generated_1() -> Result<()> {
    let sk_seed = hex_decode("0000000000000000000000000000000000000000000000000000000000000000");
    let expected_pk =
        hex_decode("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
    let alpha = hex_decode("00");
    let expected_pi = hex_decode(
        "93d70c5ed59ccb21ca9991be561756939ff9753bf85764d2a7b937d6fbf91834\
         43cd118bee8a0f61e8bdc5403c03d6c94ead31956e98bfd6a5e02d3be5900d17\
         a540852d586f0891caed3e3b0e0871d6a741fb0edcdb586f7f10252f79c35176\
         474ece4936e0190b5167832c10712884ad12acdfff2e434aacb165e1f789660f",
    );
    let expected_beta = hex_decode(
        "9a4d34f87003412e413ca42feba3b6158bdf11db41c2bbde98961c5865400cfd\
         ee07149b928b376db365c5d68459378b0981f1cb0510f1e0c194c4a17603d44d",
    );

    let seed: [u8; 32] = sk_seed.try_into().expect("seed must be 32 bytes");
    let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);
    assert_eq!(&pk[..], &expected_pk[..], "Public key mismatch");

    let proof = VrfDraft13::prove(&sk, &alpha)?;
    assert_eq!(
        &proof[..],
        &expected_pi[..],
        "Proof mismatch for draft13 batchcompat generated_1.\n\
         Expected: {}\n\
         Got:      {}",
        hex_encode(&expected_pi),
        hex_encode(&proof)
    );

    let beta = VrfDraft13::verify(&pk, &proof, &alpha)?;
    assert_eq!(&beta[..], &expected_beta[..], "Output (beta) mismatch");

    let beta2 = VrfDraft13::proof_to_hash(&proof)?;
    assert_eq!(beta, beta2, "proof_to_hash should match verify output");

    Ok(())
}

/// Draft-13 batchcompat test vector: generated_2 (all-zero seed, 10-byte message)
#[test]
fn test_vrf_draft13_batchcompat_generated_2() -> Result<()> {
    let sk_seed = hex_decode("0000000000000000000000000000000000000000000000000000000000000000");
    let expected_pk =
        hex_decode("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
    let alpha = hex_decode("00010203040506070809");
    let expected_pi = hex_decode(
        "235d7f05374c05e2ca22017575c572d708b0fbd22c90d1ca5a94d0596b28a6cb\
         d2e5de31550e43281ebe23b7b1393e166b796a1193ff3cb41900082688a191a8\
         ee8431e51c0a007a5860f8e72a9a1ed4aa1535d3161b462bf8a0bc54dae8df59\
         20598aeb7752acfdfe56a158e754d9ee48e345aa65128348d0dc7953add5ad0a",
    );
    let expected_beta = hex_decode(
        "a8ad413d234680303a14203ca624cabe5f061798a7c248f687883993b1ac7cf8\
         08868efcc47f5cf565bca51cb95cb7d8d18f2eb4c7ad3e648c369b477a7d45cd",
    );

    let seed: [u8; 32] = sk_seed.try_into().expect("seed must be 32 bytes");
    let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);
    assert_eq!(&pk[..], &expected_pk[..], "Public key mismatch");

    let proof = VrfDraft13::prove(&sk, &alpha)?;
    assert_eq!(
        &proof[..],
        &expected_pi[..],
        "Proof mismatch for draft13 batchcompat generated_2.\n\
         Expected: {}\n\
         Got:      {}",
        hex_encode(&expected_pi),
        hex_encode(&proof)
    );

    let beta = VrfDraft13::verify(&pk, &proof, &alpha)?;
    assert_eq!(&beta[..], &expected_beta[..], "Output (beta) mismatch");

    Ok(())
}

/// Draft-13 batchcompat test vector: generated_3 (non-zero seed, single zero byte)
#[test]
fn test_vrf_draft13_batchcompat_generated_3() -> Result<()> {
    let sk_seed = hex_decode("a70b8f607568df8ae26cf438b1057d8d0a94b7f3ac44cd984577fc43c2da55b7");
    let expected_pk =
        hex_decode("f1eb347d5c59e24f9f5f33c80cfd866e79fd72e0c370da3c011b1c9f045e23f1");
    let alpha = hex_decode("00");
    let expected_pi = hex_decode(
        "fe7fe305611dbd8402bf580ceaa4775b573a3be110bc30901880cfd81903852b\
         306d432fc2d197b79a690ba8af62d166134ad57ec546b4675554207465e5d92d\
         5570ba7336636f78afdf4ed2362c220572c2735752b975773ec3289c803689cb\
         fa9b8d841d2e603e3d9376c9c884a156c70cfd0a4293cc4edcd8902da8972f04",
    );
    let expected_beta = hex_decode(
        "05cff584ea083ae01537fc43a2456f70cbd0d1abc60b8f62170b83b647a00228\
         40c27f747134e16641428d6cc6f66675b13fff7f975a5c6891172360417ac62d",
    );

    let seed: [u8; 32] = sk_seed.try_into().expect("seed must be 32 bytes");
    let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);
    assert_eq!(&pk[..], &expected_pk[..], "Public key mismatch");

    let proof = VrfDraft13::prove(&sk, &alpha)?;
    assert_eq!(
        &proof[..],
        &expected_pi[..],
        "Proof mismatch for draft13 batchcompat generated_3.\n\
         Expected: {}\n\
         Got:      {}",
        hex_encode(&expected_pi),
        hex_encode(&proof)
    );

    let beta = VrfDraft13::verify(&pk, &proof, &alpha)?;
    assert_eq!(&beta[..], &expected_beta[..], "Output (beta) mismatch");

    Ok(())
}

/// Draft-13 batchcompat test vector: generated_4 (non-zero seed, 10-byte message)
#[test]
fn test_vrf_draft13_batchcompat_generated_4() -> Result<()> {
    let sk_seed = hex_decode("a70b8f607568df8ae26cf438b1057d8d0a94b7f3ac44cd984577fc43c2da55b7");
    let expected_pk =
        hex_decode("f1eb347d5c59e24f9f5f33c80cfd866e79fd72e0c370da3c011b1c9f045e23f1");
    let alpha = hex_decode("00010203040506070809");
    let expected_pi = hex_decode(
        "2ad402fec38563095e0a355fe580084812d7728f613da256ddd01140c29d5ec9\
         f76dcef18ef955bf74db970736e12b50968444fd7e69ebd15b83cbd27bb6cc27\
         d49a39e8eb6c1242d9ccc9c0bab9eebbdd81eed1571316e2f9644fda6519e674\
         0556a8d28c38ccddb23978d2e1c180afacea6e7fff589772ff10a1ea5cfc8700",
    );
    let expected_beta = hex_decode(
        "52f6d5f46c02df6231503b8ef6dbf870726235e41063e8698d69a72c17c05040\
         e0cfe86215f4497747dff787a03470d285d05f5a7c88d545e2e28baf2ceeaa2a",
    );

    let seed: [u8; 32] = sk_seed.try_into().expect("seed must be 32 bytes");
    let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);
    assert_eq!(&pk[..], &expected_pk[..], "Public key mismatch");

    let proof = VrfDraft13::prove(&sk, &alpha)?;
    assert_eq!(
        &proof[..],
        &expected_pi[..],
        "Proof mismatch for draft13 batchcompat generated_4.\n\
         Expected: {}\n\
         Got:      {}",
        hex_encode(&expected_pi),
        hex_encode(&proof)
    );

    let beta = VrfDraft13::verify(&pk, &proof, &alpha)?;
    assert_eq!(&beta[..], &expected_beta[..], "Output (beta) mismatch");

    Ok(())
}

/// Draft-13 batchcompat IETF test vector: standard_10 (empty alpha)
#[test]
fn test_vrf_draft13_batchcompat_standard_10() -> Result<()> {
    let sk_seed = hex_decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let expected_pk =
        hex_decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let alpha: &[u8] = &[]; // empty message
    let expected_pi = hex_decode(
        "7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f\
         762f5c178b68f0cddcc1157918edf45ec334ac8e8286601a3256c3bbf858edd9\
         4652eba1c4612e6fce762977a59420b451e12964adbe4fbecd58a7aeff5860af\
         cafa73589b023d14311c331a9ad15ff2fb37831e00f0acaa6d73bc9997b06501",
    );
    let expected_beta = hex_decode(
        "9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cc\
         cf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54",
    );

    let seed: [u8; 32] = sk_seed.try_into().expect("seed must be 32 bytes");
    let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);
    assert_eq!(&pk[..], &expected_pk[..], "Public key mismatch");

    let proof = VrfDraft13::prove(&sk, alpha)?;
    assert_eq!(
        &proof[..],
        &expected_pi[..],
        "Proof mismatch for draft13 batchcompat standard_10.\n\
         Expected: {}\n\
         Got:      {}",
        hex_encode(&expected_pi),
        hex_encode(&proof)
    );

    let beta = VrfDraft13::verify(&pk, &proof, alpha)?;
    assert_eq!(&beta[..], &expected_beta[..], "Output (beta) mismatch");

    Ok(())
}

/// Draft-13 batchcompat IETF test vector: standard_11 (single byte 0x72)
#[test]
fn test_vrf_draft13_batchcompat_standard_11() -> Result<()> {
    let sk_seed = hex_decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let expected_pk =
        hex_decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    let alpha = hex_decode("72");
    let expected_pi = hex_decode(
        "47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef\
         8ec26e77b8cb3114dd2265fe1564a4efb40d109aa3312536d93dfe3d8d80a061\
         fe799eb5770b4e3a5a27d22518bb631db183c8316bb552155f442c62a47d1c8b\
         d60e93908f93df1623ad78a86a028d6bc064dbfc75a6a57379ef855dc6733801",
    );
    let expected_beta = hex_decode(
        "38561d6b77b71d30eb97a062168ae12b667ce5c28caccdf76bc88e093e463598\
         7cd96814ce55b4689b3dd2947f80e59aac7b7675f8083865b46c89b2ce9cc735",
    );

    let seed: [u8; 32] = sk_seed.try_into().expect("seed must be 32 bytes");
    let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);
    assert_eq!(&pk[..], &expected_pk[..], "Public key mismatch");

    let proof = VrfDraft13::prove(&sk, &alpha)?;
    assert_eq!(
        &proof[..],
        &expected_pi[..],
        "Proof mismatch for draft13 batchcompat standard_11.\n\
         Expected: {}\n\
         Got:      {}",
        hex_encode(&expected_pi),
        hex_encode(&proof)
    );

    let beta = VrfDraft13::verify(&pk, &proof, &alpha)?;
    assert_eq!(&beta[..], &expected_beta[..], "Output (beta) mismatch");

    Ok(())
}

/// Draft-13 batchcompat IETF test vector: standard_12 (two bytes 0xaf82)
#[test]
fn test_vrf_draft13_batchcompat_standard_12() -> Result<()> {
    let sk_seed = hex_decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
    let expected_pk =
        hex_decode("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
    let alpha = hex_decode("af82");
    let expected_pi = hex_decode(
        "926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdce\
         a012f35433df219a88ab0f9481f4e0065d00422c3285f3d34a8b0202f20bac60\
         fb613986d171b3e98319c7ca4dc44c5dd8314a6e5616c1a4f16ce72bd7a0c25a\
         374e7ef73027e14760d42e77341fe05467bb286cc2c9d7fde29120a0b2320d04",
    );
    let expected_beta = hex_decode(
        "121b7f9b9aaaa29099fc04a94ba52784d44eac976dd1a3cca458733be5cd090a\
         7b5fbd148444f17f8daf1fb55cb04b1ae85a626e30a54b4b0f8abf4a43314a58",
    );

    let seed: [u8; 32] = sk_seed.try_into().expect("seed must be 32 bytes");
    let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);
    assert_eq!(&pk[..], &expected_pk[..], "Public key mismatch");

    let proof = VrfDraft13::prove(&sk, &alpha)?;
    assert_eq!(
        &proof[..],
        &expected_pi[..],
        "Proof mismatch for draft13 batchcompat standard_12.\n\
         Expected: {}\n\
         Got:      {}",
        hex_encode(&expected_pi),
        hex_encode(&proof)
    );

    let beta = VrfDraft13::verify(&pk, &proof, &alpha)?;
    assert_eq!(&beta[..], &expected_beta[..], "Output (beta) mismatch");

    Ok(())
}
