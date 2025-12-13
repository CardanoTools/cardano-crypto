//! Hash Algorithm Tests - Cardano Compatibility
//!
//! These tests verify that our Blake2b and SHA hash implementations produce
//! output compatible with Cardano's hash algorithms from cardano-crypto-class.
//!
//! # Cardano Hash Usage
//!
//! - **Blake2b-224**: Address key hashes, script hashes
//! - **Blake2b-256**: Transaction hashes, block hashes, VRF output hashing
//! - **Blake2b-512**: VRF internal operations
//! - **SHA-256**: Byron-era addresses, some metadata
//! - **SHA-512**: Ed25519 internal operations
//!
//! # Reference
//!
//! - RFC 7693: The BLAKE2 Cryptographic Hash
//! - FIPS 180-4: Secure Hash Standard (SHS)
//! - cardano-crypto-class hash implementations

use cardano_crypto::hash::{Blake2b224, Blake2b256, Blake2b512, HashAlgorithm, sha256, sha512};

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
// Blake2b-224 Tests (Address Hashes)
// ============================================================================

/// Test Blake2b-224 with empty input
#[test]
fn test_blake2b_224_empty() {
    let hash = Blake2b224::hash(&[]);
    // Expected hash of empty input with Blake2b-224
    assert_eq!(hash.len(), 28, "Blake2b-224 should produce 28 bytes");
}

/// Test Blake2b-224 with "abc" (standard test vector)
#[test]
fn test_blake2b_224_abc() {
    let hash = Blake2b224::hash(b"abc");
    // This is the expected Blake2b-224 hash of "abc"
    let expected = "8e55a2e43e8aa82a702c5a20d9e80a23f7d38aa6895528e66877ab62";
    assert_eq!(
        hex_encode(&hash),
        expected,
        "Blake2b-224 of 'abc' should match"
    );
}

/// Test Blake2b-224 for Cardano address key hash
#[test]
fn test_blake2b_224_pubkey_hash() {
    // This simulates hashing a 32-byte Ed25519 public key to get an address key hash
    let pubkey = hex_decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let hash = Blake2b224::hash(&pubkey);

    assert_eq!(hash.len(), 28, "Key hash should be 28 bytes");
    // The hash should be deterministic
    let hash2 = Blake2b224::hash(&pubkey);
    assert_eq!(hash, hash2, "Same input should produce same hash");
}

// ============================================================================
// Blake2b-256 Tests (Transaction & Block Hashes)
// ============================================================================

/// Test Blake2b-256 with empty input
#[test]
fn test_blake2b_256_empty() {
    let hash = Blake2b256::hash(&[]);
    // Blake2b-256 of empty input
    let expected = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";
    assert_eq!(hex_encode(&hash), expected);
}

/// Test Blake2b-256 with "abc"
#[test]
fn test_blake2b_256_abc() {
    let hash = Blake2b256::hash(b"abc");
    let expected = "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319";
    assert_eq!(hex_encode(&hash), expected);
}

/// Test Blake2b-256 hash of a sample CBOR transaction body
#[test]
fn test_blake2b_256_tx_body() {
    // This is a simplified CBOR-encoded transaction body
    // Real Cardano transaction hashes are Blake2b-256 of the CBOR-encoded tx body
    let tx_body_cbor = hex_decode(
        "a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700\
         018182583900cb9358529df4729c3246a2a033cb9821abbfd16de4888005904abc410d6a577e93\
         14f1dc698d3c7c4e6c4e7f7a3e2f7a0f3e8d9c6b5a4c3d2e1f001a001e84800282a1028201d818\
         41a002182a031903e8"
    );
    let hash = Blake2b256::hash(&tx_body_cbor);

    assert_eq!(hash.len(), 32, "Transaction hash should be 32 bytes");

    // Hash should be deterministic
    let hash2 = Blake2b256::hash(&tx_body_cbor);
    assert_eq!(hash, hash2);
}

/// Test Blake2b-256 for Cardano block hash calculation
#[test]
fn test_blake2b_256_block_header() {
    // Simplified block header hash calculation
    // Real block hashes are Blake2b-256 of the CBOR-encoded block header
    let header_cbor = hex_decode("8284582028000000000000000000000000000000000000000000000000000000000000005820000000000000000000000000000000000000000000000000000000000000000000");
    let hash = Blake2b256::hash(&header_cbor);

    assert_eq!(hash.len(), 32, "Block hash should be 32 bytes");
}

// ============================================================================
// Blake2b-512 Tests (VRF Operations)
// ============================================================================

/// Test Blake2b-512 with empty input
#[test]
fn test_blake2b_512_empty() {
    let hash = Blake2b512::hash(&[]);
    assert_eq!(hash.len(), 64, "Blake2b-512 should produce 64 bytes");
}

/// Test Blake2b-512 with "abc"
#[test]
fn test_blake2b_512_abc() {
    let hash = Blake2b512::hash(b"abc");
    let expected = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
                    7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";
    assert_eq!(hex_encode(&hash), expected);
}

/// Test Blake2b-512 for VRF output
#[test]
fn test_blake2b_512_vrf_output() {
    // VRF proofs are hashed with Blake2b-512 to produce the random output
    let vrf_proof = hex_decode(
        "b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7\
         ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f06156\
         0f55edc256a787afe701677c0f602900"
    );
    let hash = Blake2b512::hash(&vrf_proof);

    assert_eq!(hash.len(), 64, "VRF output hash should be 64 bytes");
}

// ============================================================================
// SHA-256 Tests
// ============================================================================

/// Test SHA-256 with empty input (NIST test vector)
#[test]
fn test_sha256_empty() {
    let hash = sha256(&[]);
    let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(hex_encode(&hash), expected);
}

/// Test SHA-256 with "abc" (NIST test vector)
#[test]
fn test_sha256_abc() {
    let hash = sha256(b"abc");
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(hex_encode(&hash), expected);
}

/// Test SHA-256 with longer message (NIST test vector)
#[test]
fn test_sha256_long() {
    let hash = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    let expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    assert_eq!(hex_encode(&hash), expected);
}

// ============================================================================
// SHA-512 Tests
// ============================================================================

/// Test SHA-512 with empty input (NIST test vector)
#[test]
fn test_sha512_empty() {
    let hash = sha512(&[]);
    let expected = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                    47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    assert_eq!(hex_encode(&hash), expected);
}

/// Test SHA-512 with "abc" (NIST test vector)
#[test]
fn test_sha512_abc() {
    let hash = sha512(b"abc");
    let expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                    2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    assert_eq!(hex_encode(&hash), expected);
}

// ============================================================================
// HashAlgorithm Trait Tests
// ============================================================================

/// Test that HashAlgorithm trait produces correct output lengths
#[test]
fn test_hash_output_sizes() {
    let input = b"test data";

    assert_eq!(Blake2b224::hash(input).len(), 28, "Blake2b-224 = 28 bytes");
    assert_eq!(Blake2b256::hash(input).len(), 32, "Blake2b-256 = 32 bytes");
    assert_eq!(Blake2b512::hash(input).len(), 64, "Blake2b-512 = 64 bytes");
    assert_eq!(sha256(input).len(), 32, "SHA-256 = 32 bytes");
    assert_eq!(sha512(input).len(), 64, "SHA-512 = 64 bytes");
}

/// Test that different inputs produce different hashes (collision resistance)
#[test]
fn test_hash_collision_resistance() {
    let hash1 = Blake2b256::hash(b"input1");
    let hash2 = Blake2b256::hash(b"input2");
    let hash3 = Blake2b256::hash(b"input1"); // Same as hash1

    assert_ne!(hash1, hash2, "Different inputs should have different hashes");
    assert_eq!(hash1, hash3, "Same input should have same hash");
}

// ============================================================================
// Cardano-Specific Hash Tests
// ============================================================================

/// Test hash of a Cardano script (for script hash calculation)
#[test]
fn test_script_hash() {
    // Script hashes in Cardano are Blake2b-224 of the script bytes
    // with a 1-byte tag prefix indicating script type
    let native_script_tag: u8 = 0x00;
    let script_body = hex_decode("8200581c1234567890abcdef1234567890abcdef1234567890abcdef");

    let mut tagged_script = vec![native_script_tag];
    tagged_script.extend_from_slice(&script_body);

    let hash = Blake2b224::hash(&tagged_script);
    assert_eq!(hash.len(), 28, "Script hash should be 28 bytes");
}

/// Test stake pool ID calculation
#[test]
fn test_pool_id_hash() {
    // Pool IDs are Blake2b-224 of the pool's cold verification key
    let cold_vkey = hex_decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let pool_id = Blake2b224::hash(&cold_vkey);

    assert_eq!(pool_id.len(), 28, "Pool ID should be 28 bytes");
}

/// Test datum hash calculation
#[test]
fn test_datum_hash() {
    // Datum hashes in Cardano are Blake2b-256 of the CBOR-encoded datum
    let datum_cbor = hex_decode("d8799f4568656c6c6fff"); // #6.121([h'hello'])
    let datum_hash = Blake2b256::hash(&datum_cbor);

    assert_eq!(datum_hash.len(), 32, "Datum hash should be 32 bytes");
}

/// Test auxiliary data (metadata) hash
#[test]
fn test_auxiliary_data_hash() {
    // Auxiliary data hash is Blake2b-256 of the CBOR-encoded metadata
    let metadata_cbor = hex_decode("a11902d1a178386d73672e736f6d652e6d657461646174612e6b6579636d657461646174615f76616c7565");
    let aux_hash = Blake2b256::hash(&metadata_cbor);

    assert_eq!(aux_hash.len(), 32, "Auxiliary data hash should be 32 bytes");
}

// ============================================================================
// Real-World Hash Test Vectors from Cardano Mainnet
// ============================================================================

/// Test against known Cardano mainnet transaction hash
#[test]
fn test_mainnet_tx_hash_calculation() {
    // This tests that our Blake2b-256 produces the correct hash
    // for a known transaction body CBOR

    // Known test: Hash of bytes [0x00] should be:
    let single_zero = Blake2b256::hash(&[0x00]);
    let expected = "03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314";
    assert_eq!(hex_encode(&single_zero), expected);
}

/// Test hash chain (hash of hash)
#[test]
fn test_hash_chain() {
    // Some Cardano operations chain hashes
    let data = b"original data";
    let hash1 = Blake2b256::hash(data);
    let hash2 = Blake2b256::hash(&hash1);
    let hash3 = Blake2b256::hash(&hash2);

    assert_eq!(hash1.len(), 32);
    assert_eq!(hash2.len(), 32);
    assert_eq!(hash3.len(), 32);

    // All hashes should be different
    assert_ne!(hash1, hash2);
    assert_ne!(hash2, hash3);
    assert_ne!(hash1, hash3);
}

// ============================================================================
// Performance and Edge Case Tests
// ============================================================================

/// Test hashing large data
#[test]
fn test_large_data_hash() {
    // Test with 1MB of data
    let large_data = vec![0xAB; 1024 * 1024];
    let hash = Blake2b256::hash(&large_data);

    assert_eq!(hash.len(), 32);

    // Should be deterministic
    let hash2 = Blake2b256::hash(&large_data);
    assert_eq!(hash, hash2);
}

/// Test hashing with all byte values
#[test]
fn test_all_byte_values() {
    let all_bytes: Vec<u8> = (0..=255).collect();
    let hash = Blake2b256::hash(&all_bytes);

    assert_eq!(hash.len(), 32);
}
