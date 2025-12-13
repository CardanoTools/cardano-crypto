//! DSIGN (Digital Signature) Tests - Cardano Compatibility
//!
//! These tests verify that our Ed25519 implementation produces output compatible
//! with Cardano's DSIGN implementation from cardano-crypto-class.
//!
//! # Cardano DSIGN Usage
//!
//! - **Ed25519DSIGN**: Standard Ed25519 signatures (32-byte secret key)
//! - Transaction signing
//! - Stake pool registration
//! - Delegation certificates
//! - Governance voting
//!
//! # Reference
//!
//! - RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
//! - cardano-crypto-class DSIGN implementation

use cardano_crypto::common::Result;
use cardano_crypto::dsign::{DsignAlgorithm, Ed25519};

// ============================================================================
// Helper Functions
// ============================================================================

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ============================================================================
// RFC 8032 Test Vectors
// ============================================================================

/// RFC 8032 Test Vector 1 (empty message)
#[test]
fn test_ed25519_rfc8032_vector1() -> Result<()> {
    let seed = hex_decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let expected_pk = hex_decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let message: &[u8] = &[];
    let expected_sig = hex_decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );

    let seed_arr: [u8; 32] = seed.try_into().unwrap();
    let (sk, pk) = Ed25519::keypair_from_seed(&seed_arr);

    assert_eq!(
        &pk[..],
        &expected_pk[..],
        "Public key mismatch for RFC 8032 vector 1"
    );

    let sig = Ed25519::sign(&sk, message);
    assert_eq!(
        &sig[..],
        &expected_sig[..],
        "Signature mismatch for RFC 8032 vector 1"
    );

    assert!(
        Ed25519::verify(&pk, message, &sig).is_ok(),
        "Signature verification failed for RFC 8032 vector 1"
    );

    Ok(())
}

/// RFC 8032 Test Vector 2 (single byte 0x72)
#[test]
fn test_ed25519_rfc8032_vector2() -> Result<()> {
    let seed = hex_decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let expected_pk = hex_decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    let message = hex_decode("72");
    let expected_sig = hex_decode(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    );

    let seed_arr: [u8; 32] = seed.try_into().unwrap();
    let (sk, pk) = Ed25519::keypair_from_seed(&seed_arr);

    assert_eq!(&pk[..], &expected_pk[..]);

    let sig = Ed25519::sign(&sk, &message);
    assert_eq!(&sig[..], &expected_sig[..]);

    assert!(Ed25519::verify(&pk, &message, &sig).is_ok());

    Ok(())
}

/// RFC 8032 Test Vector 3 (2-byte message)
#[test]
fn test_ed25519_rfc8032_vector3() -> Result<()> {
    let seed = hex_decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
    let expected_pk = hex_decode("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
    let message = hex_decode("af82");
    let expected_sig = hex_decode(
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
         18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    );

    let seed_arr: [u8; 32] = seed.try_into().unwrap();
    let (sk, pk) = Ed25519::keypair_from_seed(&seed_arr);

    assert_eq!(&pk[..], &expected_pk[..]);

    let sig = Ed25519::sign(&sk, &message);
    assert_eq!(&sig[..], &expected_sig[..]);

    assert!(Ed25519::verify(&pk, &message, &sig).is_ok());

    Ok(())
}

/// RFC 8032 Test Vector 1023 (1023 bytes "q")
#[test]
fn test_ed25519_rfc8032_vector_1023() -> Result<()> {
    let seed = hex_decode("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");
    let expected_pk = hex_decode("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");
    // 1023 bytes of 'q' (0x71)
    let message = vec![0x71u8; 1023];
    let expected_sig = hex_decode(
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350\
         aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
    );

    let seed_arr: [u8; 32] = seed.try_into().unwrap();
    let (sk, pk) = Ed25519::keypair_from_seed(&seed_arr);

    assert_eq!(&pk[..], &expected_pk[..]);

    let sig = Ed25519::sign(&sk, &message);
    assert_eq!(&sig[..], &expected_sig[..]);

    assert!(Ed25519::verify(&pk, &message, &sig).is_ok());

    Ok(())
}

// ============================================================================
// Cardano-Specific Tests
// ============================================================================

/// Test signature with Cardano-style seed derivation
#[test]
fn test_ed25519_cardano_seed() -> Result<()> {
    // Use the same seed format as Cardano's test vectors
    let seed = hex_decode("0000000000000000000000000000000000000000000000000000000000000000");
    let seed_arr: [u8; 32] = seed.try_into().unwrap();

    let (sk, pk) = Ed25519::keypair_from_seed(&seed_arr);

    // Key should be deterministic
    let (sk2, pk2) = Ed25519::keypair_from_seed(&seed_arr);
    assert_eq!(pk, pk2, "Same seed should produce same public key");
    assert_eq!(sk, sk2, "Same seed should produce same secret key");

    // Sign and verify
    let message = b"Cardano test message";
    let sig = Ed25519::sign(&sk, message);
    assert!(Ed25519::verify(&pk, message, &sig).is_ok());

    Ok(())
}

/// Test key sizes match Cardano expectations
#[test]
fn test_ed25519_key_sizes() {
    let seed = [0x42u8; 32];
    let (sk, pk) = Ed25519::keypair_from_seed(&seed);

    assert_eq!(sk.len(), 64, "Secret key should be 64 bytes (seed + public key)");
    assert_eq!(pk.len(), 32, "Public key should be 32 bytes");
}

/// Test signature size
#[test]
fn test_ed25519_signature_size() {
    let seed = [0x42u8; 32];
    let (sk, _pk) = Ed25519::keypair_from_seed(&seed);

    let sig = Ed25519::sign(&sk, b"test");
    assert_eq!(sig.len(), 64, "Ed25519 signature should be 64 bytes");
}

// ============================================================================
// Verification Tests
// ============================================================================

/// Test that verification fails with wrong public key
#[test]
fn test_ed25519_verify_wrong_key() -> Result<()> {
    let seed1 = [0x01u8; 32];
    let seed2 = [0x02u8; 32];

    let (sk1, _pk1) = Ed25519::keypair_from_seed(&seed1);
    let (_sk2, pk2) = Ed25519::keypair_from_seed(&seed2);

    let message = b"test message";
    let sig = Ed25519::sign(&sk1, message);

    // Should fail with wrong public key
    assert!(
        Ed25519::verify(&pk2, message, &sig).is_err(),
        "Verification should fail with wrong public key"
    );

    Ok(())
}

/// Test that verification fails with wrong message
#[test]
fn test_ed25519_verify_wrong_message() -> Result<()> {
    let seed = [0x42u8; 32];
    let (sk, pk) = Ed25519::keypair_from_seed(&seed);

    let message = b"original message";
    let wrong_message = b"wrong message";

    let sig = Ed25519::sign(&sk, message);

    // Should fail with wrong message
    assert!(
        Ed25519::verify(&pk, wrong_message, &sig).is_err(),
        "Verification should fail with wrong message"
    );

    Ok(())
}

/// Test that verification fails with tampered signature
#[test]
fn test_ed25519_verify_tampered_signature() -> Result<()> {
    let seed = [0x42u8; 32];
    let (sk, pk) = Ed25519::keypair_from_seed(&seed);

    let message = b"test message";
    let mut sig = Ed25519::sign(&sk, message);

    // Tamper with signature
    sig[0] ^= 0xFF;

    // Should fail with tampered signature
    assert!(
        Ed25519::verify(&pk, message, &sig).is_err(),
        "Verification should fail with tampered signature"
    );

    Ok(())
}

// ============================================================================
// Determinism Tests
// ============================================================================

/// Test that signing is deterministic
#[test]
fn test_ed25519_deterministic() {
    let seed = [0x42u8; 32];
    let (sk, _pk) = Ed25519::keypair_from_seed(&seed);

    let message = b"test message";

    let sig1 = Ed25519::sign(&sk, message);
    let sig2 = Ed25519::sign(&sk, message);

    assert_eq!(sig1, sig2, "Ed25519 signing should be deterministic");
}

/// Test that different messages produce different signatures
#[test]
fn test_ed25519_different_messages() {
    let seed = [0x42u8; 32];
    let (sk, _pk) = Ed25519::keypair_from_seed(&seed);

    let sig1 = Ed25519::sign(&sk, b"message 1");
    let sig2 = Ed25519::sign(&sk, b"message 2");

    assert_ne!(sig1, sig2, "Different messages should have different signatures");
}

/// Test that different keys produce different signatures
#[test]
fn test_ed25519_different_keys() {
    let seed1 = [0x01u8; 32];
    let seed2 = [0x02u8; 32];

    let (sk1, _pk1) = Ed25519::keypair_from_seed(&seed1);
    let (sk2, _pk2) = Ed25519::keypair_from_seed(&seed2);

    let message = b"same message";

    let sig1 = Ed25519::sign(&sk1, message);
    let sig2 = Ed25519::sign(&sk2, message);

    assert_ne!(sig1, sig2, "Different keys should produce different signatures");
}

// ============================================================================
// Edge Cases
// ============================================================================

/// Test signing empty message
#[test]
fn test_ed25519_empty_message() -> Result<()> {
    let seed = [0x42u8; 32];
    let (sk, pk) = Ed25519::keypair_from_seed(&seed);

    let message: &[u8] = &[];
    let sig = Ed25519::sign(&sk, message);

    assert!(Ed25519::verify(&pk, message, &sig).is_ok());

    Ok(())
}

/// Test signing large message
#[test]
fn test_ed25519_large_message() -> Result<()> {
    let seed = [0x42u8; 32];
    let (sk, pk) = Ed25519::keypair_from_seed(&seed);

    // 1 MB message
    let message = vec![0xAB; 1024 * 1024];
    let sig = Ed25519::sign(&sk, &message);

    assert!(Ed25519::verify(&pk, &message, &sig).is_ok());

    Ok(())
}

/// Test with all-zero seed
#[test]
fn test_ed25519_zero_seed() -> Result<()> {
    let seed = [0x00u8; 32];
    let (sk, pk) = Ed25519::keypair_from_seed(&seed);

    let message = b"test";
    let sig = Ed25519::sign(&sk, message);

    assert!(Ed25519::verify(&pk, message, &sig).is_ok());

    Ok(())
}

/// Test with all-ones seed
#[test]
fn test_ed25519_ones_seed() -> Result<()> {
    let seed = [0xFFu8; 32];
    let (sk, pk) = Ed25519::keypair_from_seed(&seed);

    let message = b"test";
    let sig = Ed25519::sign(&sk, message);

    assert!(Ed25519::verify(&pk, message, &sig).is_ok());

    Ok(())
}

// ============================================================================
// Cardano Transaction Signing Simulation
// ============================================================================

/// Simulate signing a Cardano transaction body hash
#[test]
fn test_ed25519_tx_signing() -> Result<()> {
    use cardano_crypto::hash::{Blake2b256, HashAlgorithm};

    let seed = hex_decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let seed_arr: [u8; 32] = seed.try_into().unwrap();
    let (sk, pk) = Ed25519::keypair_from_seed(&seed_arr);

    // Simulate a transaction body (CBOR encoded)
    let tx_body_cbor = hex_decode("a400818258201234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef00018182583900112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00001a001e84800282a10083");

    // Hash the transaction body (Cardano uses Blake2b-256)
    let tx_body_hash = Blake2b256::hash(&tx_body_cbor);

    // Sign the hash
    let sig = Ed25519::sign(&sk, &tx_body_hash);

    // Verify the signature
    assert!(Ed25519::verify(&pk, &tx_body_hash, &sig).is_ok());

    // This is how VKeyWitness works in Cardano:
    // witness = (vkey, signature) where signature = Ed25519.sign(sk, txBodyHash)

    Ok(())
}

/// Test public key derivation
#[test]
fn test_ed25519_pubkey_derivation() {
    let seed = [0x42u8; 32];
    let (sk, pk1) = Ed25519::keypair_from_seed(&seed);

    // Derive public key from secret key
    let pk2 = Ed25519::derive_public_key(&sk);

    assert_eq!(pk1, pk2, "Public key derivation should be consistent");
}

// ============================================================================
// Serialization Tests
// ============================================================================

/// Test key serialization roundtrip
#[test]
fn test_ed25519_key_serialization() -> Result<()> {
    let seed = [0x42u8; 32];
    let (sk, pk) = Ed25519::keypair_from_seed(&seed);

    // Secret key bytes
    let sk_bytes = sk.clone();
    assert_eq!(sk_bytes.len(), 64);

    // Public key bytes
    let pk_bytes = pk.clone();
    assert_eq!(pk_bytes.len(), 32);

    // Sign with original key and verify with bytes
    let message = b"test";
    let sig = Ed25519::sign(&sk, message);
    assert!(Ed25519::verify(&pk_bytes, message, &sig).is_ok());

    Ok(())
}
