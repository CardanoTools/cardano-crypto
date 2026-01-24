//! CBOR Encoding Tests - Cardano Compatibility
//!
//! These tests verify that our CBOR implementation produces output compatible
//! with Cardano's serialization format (Cardano.Binary from cardano-base).
//!
//! # Test Categories
//!
//! 1. **Basic Type Encoding** - Integers, bytes, text strings
//! 2. **Variable-Length Encoding** - CBOR's compact integer encoding
//! 3. **Collection Encoding** - Arrays and maps (definite and indefinite)
//! 4. **Cardano-Specific** - encodeBytes/decodeBytes with length prefix
//!
//! # Reference
//!
//! - RFC 8949: Concise Binary Object Representation (CBOR)
//! - Cardano.Binary from cardano-base

use cardano_crypto::cbor::{decode_bytes, encode_bytes, Cbor, CborBuilder, FromCbor, ToCbor};
use cardano_crypto::common::Result;

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
// CBOR Integer Encoding Tests
// ============================================================================

/// Test CBOR unsigned integer encoding (major type 0)
#[test]
fn test_cbor_unsigned_integer_encoding() {
    // Small integers (0-23) encode as single byte
    let test_cases: &[(u64, &str)] = &[
        (0, "00"),
        (1, "01"),
        (10, "0a"),
        (23, "17"),
        // 1-byte additional info (24-255)
        (24, "1818"),
        (100, "1864"),
        (255, "18ff"),
        // 2-byte additional info (256-65535)
        (256, "190100"),
        (1000, "1903e8"),
        (65535, "19ffff"),
        // 4-byte additional info (65536-4294967295)
        (65536, "1a00010000"),
        (1000000, "1a000f4240"),
        // 8-byte additional info
        (1000000000000u64, "1b000000e8d4a51000"),
    ];

    for (value, expected_hex) in test_cases {
        let mut builder = CborBuilder::new();
        builder.write_unsigned(*value);
        let encoded = builder.build();
        assert_eq!(
            hex_encode(&encoded),
            *expected_hex,
            "Encoding of {} failed",
            value
        );
    }
}

/// Test CBOR negative integer encoding (major type 1)
#[test]
fn test_cbor_negative_integer_encoding() {
    // CBOR negative integers: encode -(n+1)
    let test_cases: &[(i64, &str)] = &[
        (-1, "20"),
        (-10, "29"),
        (-24, "37"),
        (-25, "3818"),
        (-100, "3863"),
        (-1000, "3903e7"),
    ];

    for (value, expected_hex) in test_cases {
        let mut builder = CborBuilder::new();
        builder.write_negative(*value);
        let encoded = builder.build();
        assert_eq!(
            hex_encode(&encoded),
            *expected_hex,
            "Encoding of {} failed",
            value
        );
    }
}

// ============================================================================
// CBOR Bytes Encoding Tests
// ============================================================================

/// Test CBOR byte string encoding (major type 2)
#[test]
fn test_cbor_bytes_encoding() {
    let test_cases: &[(&[u8], &str)] = &[
        // Empty bytes
        (&[], "40"),
        // Single byte
        (&[0x01], "4101"),
        // Multiple bytes
        (&[0x01, 0x02, 0x03, 0x04], "4401020304"),
        // 23 bytes (max single-byte length)
        (
            &[0xAA; 23],
            "57aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        // 24 bytes (requires 1-byte length)
        (
            &[0xBB; 24],
            "5818bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
    ];

    for (bytes, expected_hex) in test_cases {
        let mut builder = CborBuilder::new();
        builder.write_bytes(bytes);
        let encoded = builder.build();
        assert_eq!(
            hex_encode(&encoded),
            *expected_hex,
            "Encoding of {:?} failed",
            bytes
        );
    }
}

/// Test CBOR indefinite byte string encoding
#[test]
fn test_cbor_indefinite_bytes_encoding() {
    let mut builder = CborBuilder::new();
    builder.begin_bytes();
    builder.write_bytes(&[0x01, 0x02]);
    builder.write_bytes(&[0x03, 0x04]);
    builder.end();
    let encoded = builder.build();

    // 5f = indefinite bytes, 42 = 2-byte string, 42 = 2-byte string, ff = break
    assert_eq!(hex_encode(&encoded), "5f42010242030fff");
}

// ============================================================================
// CBOR Text String Encoding Tests
// ============================================================================

/// Test CBOR text string encoding (major type 3)
#[test]
fn test_cbor_text_encoding() {
    let test_cases: &[(&str, &str)] = &[
        ("", "60"),
        ("a", "6161"),
        ("IETF", "6449455446"),
        ("\"\\", "62225c"),
        // UTF-8: ü
        ("\u{00fc}", "62c3bc"),
        // UTF-8: 水
        ("\u{6c34}", "63e6b0b4"),
    ];

    for (text, expected_hex) in test_cases {
        let mut builder = CborBuilder::new();
        builder.write_text(text);
        let encoded = builder.build();
        assert_eq!(
            hex_encode(&encoded),
            *expected_hex,
            "Encoding of {:?} failed",
            text
        );
    }
}

// ============================================================================
// CBOR Array Encoding Tests
// ============================================================================

/// Test CBOR definite-length array encoding (major type 4)
#[test]
fn test_cbor_array_encoding() {
    // Empty array
    let mut builder = CborBuilder::new();
    builder.begin_array(Some(0));
    let encoded = builder.build();
    assert_eq!(hex_encode(&encoded), "80");

    // [1, 2, 3]
    let mut builder = CborBuilder::new();
    builder.begin_array(Some(3));
    builder.write_unsigned(1);
    builder.write_unsigned(2);
    builder.write_unsigned(3);
    let encoded = builder.build();
    assert_eq!(hex_encode(&encoded), "83010203");

    // [1, [2, 3], [4, 5]]
    let mut builder = CborBuilder::new();
    builder.begin_array(Some(3));
    builder.write_unsigned(1);
    builder.begin_array(Some(2));
    builder.write_unsigned(2);
    builder.write_unsigned(3);
    builder.begin_array(Some(2));
    builder.write_unsigned(4);
    builder.write_unsigned(5);
    let encoded = builder.build();
    assert_eq!(hex_encode(&encoded), "8301820203820405");
}

/// Test CBOR indefinite-length array encoding
#[test]
fn test_cbor_indefinite_array_encoding() {
    let mut builder = CborBuilder::new();
    builder.begin_array(None); // indefinite
    builder.write_unsigned(1);
    builder.write_unsigned(2);
    builder.write_unsigned(3);
    builder.end(); // break
    let encoded = builder.build();

    // 9f = indefinite array, 01 02 03 = items, ff = break
    assert_eq!(hex_encode(&encoded), "9f010203ff");
}

// ============================================================================
// CBOR Map Encoding Tests
// ============================================================================

/// Test CBOR map encoding (major type 5)
#[test]
fn test_cbor_map_encoding() {
    // Empty map
    let mut builder = CborBuilder::new();
    builder.begin_map(Some(0));
    let encoded = builder.build();
    assert_eq!(hex_encode(&encoded), "a0");

    // {1: 2, 3: 4}
    let mut builder = CborBuilder::new();
    builder.begin_map(Some(2));
    builder.write_unsigned(1);
    builder.write_unsigned(2);
    builder.write_unsigned(3);
    builder.write_unsigned(4);
    let encoded = builder.build();
    assert_eq!(hex_encode(&encoded), "a201020304");
}

// ============================================================================
// CBOR Tags Tests
// ============================================================================

/// Test CBOR tag encoding (major type 6)
#[test]
fn test_cbor_tag_encoding() {
    // Tag 0 (standard date/time string)
    let mut builder = CborBuilder::new();
    builder.write_tag(0);
    builder.write_text("2013-03-21T20:04:00Z");
    let encoded = builder.build();
    assert_eq!(
        hex_encode(&encoded),
        "c074323031332d30332d32315432303a30343a30305a"
    );

    // Tag 1 (epoch-based date/time)
    let mut builder = CborBuilder::new();
    builder.write_tag(1);
    builder.write_unsigned(1363896240);
    let encoded = builder.build();
    assert_eq!(hex_encode(&encoded), "c11a514b67b0");
}

// ============================================================================
// CBOR Special Values Tests
// ============================================================================

/// Test CBOR special value encoding (major type 7)
#[test]
fn test_cbor_special_values() {
    // false
    let mut builder = CborBuilder::new();
    builder.write_bool(false);
    assert_eq!(hex_encode(&builder.build()), "f4");

    // true
    let mut builder = CborBuilder::new();
    builder.write_bool(true);
    assert_eq!(hex_encode(&builder.build()), "f5");

    // null
    let mut builder = CborBuilder::new();
    builder.write_null();
    assert_eq!(hex_encode(&builder.build()), "f6");
}

// ============================================================================
// Cardano-Specific encodeBytes/decodeBytes Tests
// ============================================================================

/// Test Cardano's encodeBytes format (CBOR bytes with leading length tag)
#[test]
fn test_cardano_encode_bytes() {
    // Empty bytes
    let encoded = encode_bytes(&[]);
    assert_eq!(
        hex_encode(&encoded),
        "40",
        "Empty bytes should encode as 40"
    );

    // Small bytes (< 24)
    let encoded = encode_bytes(&[0x01, 0x02, 0x03]);
    assert_eq!(hex_encode(&encoded), "43010203");

    // 24 bytes (1-byte length prefix)
    let data: Vec<u8> = (0..24).collect();
    let encoded = encode_bytes(&data);
    // 58 18 = bytes with 1-byte length (24)
    assert!(encoded.starts_with(&[0x58, 0x18]));

    // 256 bytes (2-byte length prefix)
    let data: Vec<u8> = (0..=255).collect();
    let encoded = encode_bytes(&data);
    // 59 01 00 = bytes with 2-byte length (256)
    assert!(encoded.starts_with(&[0x59, 0x01, 0x00]));
}

/// Test Cardano's decodeBytes roundtrip
#[test]
fn test_cardano_encode_decode_roundtrip() -> Result<()> {
    let test_cases: &[&[u8]] = &[
        &[],
        &[0x00],
        &[0xFF],
        &[0x01, 0x02, 0x03, 0x04, 0x05],
        &[0xDE, 0xAD, 0xBE, 0xEF],
        &vec![0xAB; 100],
        &vec![0xCD; 1000],
    ];

    for original in test_cases {
        let encoded = encode_bytes(original);
        let (decoded, consumed) = decode_bytes(&encoded)?;
        assert_eq!(decoded, *original, "Roundtrip failed for {:?}", original);
        assert_eq!(consumed, encoded.len(), "Should consume all bytes");
    }

    Ok(())
}

// ============================================================================
// CBOR Decoding Tests
// ============================================================================

/// Test decoding of various CBOR values
#[test]
fn test_cbor_decoding() -> Result<()> {
    // Decode unsigned integers
    let test_cases: &[(&str, u64)] = &[
        ("00", 0),
        ("01", 1),
        ("17", 23),
        ("1818", 24),
        ("1903e8", 1000),
        ("1a000f4240", 1000000),
    ];

    for (hex, expected) in test_cases {
        let data = hex_decode(hex);
        let cbor = Cbor::from_slice(&data)?;
        if let Cbor::Unsigned(n) = cbor {
            assert_eq!(n, *expected, "Decoding {} failed", hex);
        } else {
            panic!("Expected unsigned integer for {}", hex);
        }
    }

    Ok(())
}

/// Test decoding of CBOR byte strings
#[test]
fn test_cbor_bytes_decoding() -> Result<()> {
    let test_cases: &[(&str, &[u8])] = &[
        ("40", &[]),
        ("4101", &[0x01]),
        ("4401020304", &[0x01, 0x02, 0x03, 0x04]),
    ];

    for (hex, expected) in test_cases {
        let data = hex_decode(hex);
        let cbor = Cbor::from_slice(&data)?;
        if let Cbor::Bytes(bytes) = cbor {
            assert_eq!(bytes.as_ref(), *expected, "Decoding {} failed", hex);
        } else {
            panic!("Expected bytes for {}", hex);
        }
    }

    Ok(())
}

// ============================================================================
// Size Expression Tests (Cardano compatibility)
// ============================================================================

/// Test that size expressions match Cardano's encodedSizeExpr
#[test]
fn test_cbor_size_expressions() {
    // Test size calculation for various data types
    // Cardano uses these for pre-calculating transaction sizes

    // Empty bytes: 1 byte (0x40)
    assert_eq!(encode_bytes(&[]).len(), 1);

    // 23 bytes: 1 + 23 = 24 bytes
    assert_eq!(encode_bytes(&[0u8; 23]).len(), 24);

    // 24 bytes: 2 + 24 = 26 bytes (needs 1-byte length)
    assert_eq!(encode_bytes(&[0u8; 24]).len(), 26);

    // 255 bytes: 2 + 255 = 257 bytes
    assert_eq!(encode_bytes(&[0u8; 255]).len(), 257);

    // 256 bytes: 3 + 256 = 259 bytes (needs 2-byte length)
    assert_eq!(encode_bytes(&[0u8; 256]).len(), 259);
}

// ============================================================================
// Real-World Cardano Data Tests
// ============================================================================

/// Test encoding of a structure similar to Cardano transaction hash
#[test]
fn test_cardano_tx_hash_encoding() {
    // Transaction hash is 32 bytes, encoded as CBOR bytes
    let tx_hash = [0x42u8; 32];
    let encoded = encode_bytes(&tx_hash);

    // Should be: 58 20 (bytes with 1-byte length 32) + 32 bytes
    assert_eq!(encoded.len(), 34);
    assert_eq!(encoded[0], 0x58); // bytes, 1-byte length follows
    assert_eq!(encoded[1], 0x20); // length = 32
    assert_eq!(&encoded[2..], &tx_hash[..]);
}

/// Test encoding of a structure similar to Cardano block header hash
#[test]
fn test_cardano_block_hash_encoding() {
    // Block header hash is also 32 bytes
    let block_hash = hex_decode("5c196e7394ace0449ba5a51c919369699b13896e97432894b4f0354dce8670b6");
    let encoded = encode_bytes(&block_hash);

    assert_eq!(encoded.len(), 34);
    assert_eq!(encoded[0], 0x58);
    assert_eq!(encoded[1], 0x20);
}

// ============================================================================
// ToCbor/FromCbor Trait Tests
// ============================================================================

/// Test ToCbor trait implementation for built-in types
#[test]
fn test_to_cbor_trait() {
    // u64
    let value: u64 = 1000;
    let encoded = value.to_cbor_bytes();
    assert_eq!(hex_encode(&encoded), "1903e8");

    // Vec<u8>
    let bytes: Vec<u8> = vec![1, 2, 3, 4];
    let encoded = bytes.to_cbor_bytes();
    assert_eq!(hex_encode(&encoded), "4401020304");

    // bool
    let b = true;
    let encoded = b.to_cbor_bytes();
    assert_eq!(hex_encode(&encoded), "f5");
}

/// Test FromCbor trait implementation
#[test]
fn test_from_cbor_trait() -> Result<()> {
    // u64
    let data = hex_decode("1903e8");
    let (value, _): (u64, _) = u64::from_cbor_bytes(&data)?;
    assert_eq!(value, 1000);

    // Vec<u8>
    let data = hex_decode("4401020304");
    let (bytes, _): (Vec<u8>, _) = Vec::<u8>::from_cbor_bytes(&data)?;
    assert_eq!(bytes, vec![1, 2, 3, 4]);

    Ok(())
}
