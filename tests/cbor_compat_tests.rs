//! CBOR Encoding Tests - Cardano Compatibility
//!
//! These tests verify that our CBOR implementation produces output compatible
//! with Cardano's serialization format (Cardano.Binary from cardano-base).
//!
//! # Test Categories
//!
//! 1. **Basic Type Encoding** - Byte strings with length prefixes
//! 2. **Cardano-Specific** - encodeBytes/decodeBytes with length prefix
//! 3. **ToCbor/FromCbor Traits** - Trait implementations for common types
//!
//! # Reference
//!
//! - RFC 8949: Concise Binary Object Representation (CBOR)
//! - Cardano.Binary from cardano-base

use cardano_crypto::cbor::{
    decode_bytes, decode_signature, decode_verification_key, encode_bytes, encode_signature,
    encode_verification_key, CborError, FromCbor, ToCbor,
};

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
// CBOR Byte String Encoding Tests (Major Type 2)
// ============================================================================

/// Test CBOR byte string encoding (major type 2)
#[test]
fn test_cbor_byte_string_encoding() {
    // Empty byte string
    let empty = encode_bytes(&[]);
    assert_eq!(hex_encode(&empty), "40");

    // Short byte strings (0-23 bytes) - length in header
    let bytes_4 = encode_bytes(&[1, 2, 3, 4]);
    assert_eq!(hex_encode(&bytes_4), "4401020304");

    // 23 bytes - max short form
    let bytes_23 = encode_bytes(&[0xAB; 23]);
    assert_eq!(bytes_23[0], 0x57); // 0x40 + 23

    // 24 bytes - requires 1-byte length
    let bytes_24 = encode_bytes(&[0xCD; 24]);
    assert_eq!(bytes_24[0], 0x58); // 0x58 = major type 2 + additional info 24
    assert_eq!(bytes_24[1], 24); // length byte

    // 256 bytes - requires 2-byte length
    let bytes_256 = encode_bytes(&vec![0xEF; 256]);
    assert_eq!(bytes_256[0], 0x59); // 0x59 = major type 2 + additional info 25
    assert_eq!(bytes_256[1], 0x01); // length high byte
    assert_eq!(bytes_256[2], 0x00); // length low byte
}

/// Test CBOR byte string decoding
#[test]
fn test_cbor_byte_string_decoding() -> std::result::Result<(), CborError> {
    // Empty byte string
    let decoded = decode_bytes(&hex_decode("40"))?;
    assert!(decoded.is_empty());

    // Short byte string
    let decoded = decode_bytes(&hex_decode("4401020304"))?;
    assert_eq!(decoded, vec![1, 2, 3, 4]);

    // 24-byte string with 1-byte length
    let mut cbor = vec![0x58, 24];
    cbor.extend_from_slice(&[0xAB; 24]);
    let decoded = decode_bytes(&cbor)?;
    assert_eq!(decoded, vec![0xAB; 24]);

    Ok(())
}

/// Test encode/decode roundtrip
#[test]
fn test_encode_decode_roundtrip() -> std::result::Result<(), CborError> {
    let buf_100 = [0xAB; 100];
    let buf_1000 = [0xCD; 1000];
    let test_cases: &[&[u8]] = &[
        &[],
        &[0x00],
        &[0xFF],
        &[0x01, 0x02, 0x03, 0x04, 0x05],
        &[0xDE, 0xAD, 0xBE, 0xEF],
        &buf_100,
        &buf_1000,
    ];

    for original in test_cases {
        let encoded = encode_bytes(original);
        let decoded = decode_bytes(&encoded)?;
        assert_eq!(decoded, *original, "Roundtrip failed for {:?}", original);
    }

    Ok(())
}

// ============================================================================
// Cardano-Specific Encoding Tests
// ============================================================================

/// Test verification key encoding (32 bytes - Ed25519)
#[test]
fn test_verification_key_encoding() -> std::result::Result<(), CborError> {
    let vk = [0x42u8; 32];
    let encoded = encode_verification_key(&vk);

    // Should be 0x58 (major type 2, 1-byte length) + 0x20 (32) + 32 bytes
    assert_eq!(encoded.len(), 34);
    assert_eq!(encoded[0], 0x58);
    assert_eq!(encoded[1], 0x20);
    assert_eq!(&encoded[2..], &vk);

    // Decode and verify
    let decoded = decode_verification_key(&encoded)?;
    assert_eq!(&decoded[..], &vk[..]);

    Ok(())
}

/// Test signature encoding (64 bytes - Ed25519)
#[test]
fn test_signature_encoding() -> std::result::Result<(), CborError> {
    let sig = [0x99u8; 64];
    let encoded = encode_signature(&sig);

    // Should be 0x58 (major type 2, 1-byte length) + 0x40 (64) + 64 bytes
    assert_eq!(encoded.len(), 66);
    assert_eq!(encoded[0], 0x58);
    assert_eq!(encoded[1], 0x40);
    assert_eq!(&encoded[2..], &sig);

    // Decode and verify
    let decoded = decode_signature(&encoded)?;
    assert_eq!(&decoded[..], &sig[..]);

    Ok(())
}

// ============================================================================
// ToCbor/FromCbor Trait Tests
// ============================================================================

/// Test ToCbor trait implementation for byte arrays
#[test]
fn test_to_cbor_trait() {
    // [u8; 32]
    let bytes: [u8; 32] = [1u8; 32];
    let encoded = bytes.to_cbor();
    // Should be: header (0x58, 0x20 = 32) + 32 bytes
    assert_eq!(encoded.len(), 2 + 32);
    assert_eq!(encoded[0], 0x58); // Major type 2, 1-byte length
    assert_eq!(encoded[1], 0x20); // Length = 32

    // Vec<u8>
    let bytes: Vec<u8> = vec![1, 2, 3, 4];
    let encoded = bytes.to_cbor();
    assert_eq!(hex_encode(&encoded), "4401020304");
}

/// Test FromCbor trait implementation
#[test]
fn test_from_cbor_trait() -> std::result::Result<(), CborError> {
    // Vec<u8>
    let data = hex_decode("4401020304");
    let bytes = Vec::<u8>::from_cbor(&data)?;
    assert_eq!(bytes, vec![1, 2, 3, 4]);

    // [u8; 32]
    let mut cbor_encoded = vec![0x58, 0x20]; // Major type 2, length 32
    cbor_encoded.extend_from_slice(&[0xABu8; 32]);
    let decoded = <[u8; 32]>::from_cbor(&cbor_encoded)?;
    assert_eq!(decoded, [0xAB; 32]);

    Ok(())
}

// ============================================================================
// Error Handling Tests
// ============================================================================

/// Test decoding of invalid CBOR
#[test]
fn test_invalid_cbor_decoding() {
    // Empty input
    assert!(decode_bytes(&[]).is_err());

    // Wrong major type (integer instead of bytes)
    assert!(decode_bytes(&[0x00]).is_err());

    // Truncated data
    assert!(decode_bytes(&[0x44, 0x01, 0x02]).is_err()); // Claims 4 bytes, has 2

    // Invalid length header
    assert!(decode_bytes(&[0x58]).is_err()); // 1-byte length missing
}

/// Test decoding with wrong length for fixed-size types
#[test]
fn test_wrong_length_decoding() {
    // 31 bytes when 32 expected
    let mut cbor = vec![0x58, 31];
    cbor.extend_from_slice(&[0xAB; 31]);
    assert!(<[u8; 32]>::from_cbor(&cbor).is_err());

    // 33 bytes when 32 expected
    let mut cbor = vec![0x58, 33];
    cbor.extend_from_slice(&[0xAB; 33]);
    assert!(<[u8; 32]>::from_cbor(&cbor).is_err());
}

// ============================================================================
// Edge Case Tests
// ============================================================================

/// Test encoding/decoding of maximum short-form length (23 bytes)
#[test]
fn test_short_form_boundary() -> std::result::Result<(), CborError> {
    // 23 bytes - last value that fits in short form
    let data_23 = vec![0xFFu8; 23];
    let encoded_23 = encode_bytes(&data_23);
    assert_eq!(encoded_23[0], 0x40 + 23); // Short form header
    let decoded_23 = decode_bytes(&encoded_23)?;
    assert_eq!(decoded_23, data_23);

    // 24 bytes - first value requiring 1-byte length
    let data_24 = vec![0xFFu8; 24];
    let encoded_24 = encode_bytes(&data_24);
    assert_eq!(encoded_24[0], 0x58); // 1-byte length header
    assert_eq!(encoded_24[1], 24);
    let decoded_24 = decode_bytes(&encoded_24)?;
    assert_eq!(decoded_24, data_24);

    Ok(())
}

/// Test encoding/decoding of 2-byte length boundary (255-256 bytes)
#[test]
fn test_two_byte_length_boundary() -> std::result::Result<(), CborError> {
    // 255 bytes - last value that fits in 1-byte length
    let data_255 = vec![0xAAu8; 255];
    let encoded_255 = encode_bytes(&data_255);
    assert_eq!(encoded_255[0], 0x58); // 1-byte length header
    assert_eq!(encoded_255[1], 255);
    let decoded_255 = decode_bytes(&encoded_255)?;
    assert_eq!(decoded_255, data_255);

    // 256 bytes - first value requiring 2-byte length
    let data_256 = vec![0xBBu8; 256];
    let encoded_256 = encode_bytes(&data_256);
    assert_eq!(encoded_256[0], 0x59); // 2-byte length header
    assert_eq!(encoded_256[1], 0x01);
    assert_eq!(encoded_256[2], 0x00);
    let decoded_256 = decode_bytes(&encoded_256)?;
    assert_eq!(decoded_256, data_256);

    Ok(())
}

/// Test all-zeros and all-ones patterns
#[test]
fn test_bit_patterns() -> std::result::Result<(), CborError> {
    let zeros = vec![0x00u8; 100];
    let ones = vec![0xFFu8; 100];

    let decoded_zeros = decode_bytes(&encode_bytes(&zeros))?;
    assert_eq!(decoded_zeros, zeros);

    let decoded_ones = decode_bytes(&encode_bytes(&ones))?;
    assert_eq!(decoded_ones, ones);

    Ok(())
}
