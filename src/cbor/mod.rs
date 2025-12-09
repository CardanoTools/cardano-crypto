//! CBOR serialization support for Cardano cryptographic types
//!
//! This module provides CBOR (Concise Binary Object Representation) encoding and decoding
//! that is fully compatible with Cardano's `Cardano.Binary` module from cardano-base.
//!
//! # Cardano CBOR Format
//!
//! Cardano uses CBOR for all on-chain data serialization. The format follows RFC 8949
//! with specific conventions:
//!
//! - **Verification keys**: CBOR byte string (major type 2) wrapping raw key bytes
//! - **Signatures**: CBOR byte string (major type 2) wrapping raw signature bytes
//! - **Signing keys**: Typically NOT serialized via CBOR to protect key material
//!
//! # Compatibility
//!
//! This implementation matches `encodeBytes`/`decodeBytes` from Haskell's `Cardano.Binary`:
//! - Proper CBOR major type 2 headers with length encoding
//! - Big-endian length fields for multi-byte lengths
//! - Canonical encoding (minimal length headers)
//!
//! # Examples
//!
//! Basic CBOR encoding/decoding:
//!
//! ```rust
//! use cardano_crypto::cbor::{encode_bytes, decode_bytes};
//!
//! # fn main() -> Result<(), cardano_crypto::cbor::CborError> {
//! // Encode data as CBOR byte string
//! let data = b"verification key data";
//! let cbor_encoded = encode_bytes(data);
//!
//! // Decode CBOR byte string
//! let decoded = decode_bytes(&cbor_encoded)?;
//! assert_eq!(data, &decoded[..]);
//! # Ok(())
//! # }
//! ```
//!
//! KES verification key serialization:
//!
//! ```rust
//! use cardano_crypto::cbor::{encode_verification_key, decode_verification_key};
//!
//! # fn main() -> Result<(), cardano_crypto::cbor::CborError> {
//! let vkey_raw = [0x42u8; 32]; // 32-byte Ed25519 verification key
//! let cbor = encode_verification_key(&vkey_raw);
//! let recovered = decode_verification_key(&cbor)?;
//! assert_eq!(&vkey_raw[..], &recovered[..]);
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

// ============================================================================
// Error Types
// ============================================================================

/// CBOR serialization errors
///
/// These errors correspond to failure modes in Cardano's CBOR processing.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::cbor::CborError;
///
/// let err = CborError::BufferTooSmall;
/// let s = format!("{}", err);
/// assert!(s.len() > 0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum CborError {
    /// Invalid CBOR encoding (malformed header or structure)
    #[cfg_attr(feature = "thiserror", error("Invalid CBOR encoding"))]
    InvalidEncoding,

    /// Unexpected CBOR structure (wrong major type)
    #[cfg_attr(feature = "thiserror", error("Unexpected CBOR structure"))]
    UnexpectedStructure,

    /// Serialization failed
    #[cfg_attr(feature = "thiserror", error("Serialization failed"))]
    SerializationFailed,

    /// Deserialization failed
    #[cfg_attr(feature = "thiserror", error("Deserialization failed"))]
    DeserializationFailed,

    /// Invalid byte length for the expected type
    #[cfg_attr(feature = "thiserror", error("Invalid byte length"))]
    InvalidLength,

    /// Buffer too small to hold the data
    #[cfg_attr(feature = "thiserror", error("Buffer too small"))]
    BufferTooSmall,

    /// Invalid UTF-8 in text string
    #[cfg_attr(feature = "thiserror", error("Invalid UTF-8 encoding"))]
    InvalidUtf8,

    /// Unsupported CBOR feature or extension
    #[cfg_attr(feature = "thiserror", error("Unsupported CBOR feature"))]
    Unsupported,
}

#[cfg(not(feature = "thiserror"))]
impl core::fmt::Display for CborError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CborError::InvalidEncoding => write!(f, "Invalid CBOR encoding"),
            CborError::UnexpectedStructure => write!(f, "Unexpected CBOR structure"),
            CborError::SerializationFailed => write!(f, "Serialization failed"),
            CborError::DeserializationFailed => write!(f, "Deserialization failed"),
            CborError::InvalidLength => write!(f, "Invalid byte length"),
            CborError::BufferTooSmall => write!(f, "Buffer too small"),
            CborError::InvalidUtf8 => write!(f, "Invalid UTF-8 encoding"),
            CborError::Unsupported => write!(f, "Unsupported CBOR feature"),
        }
    }
}

#[cfg(all(not(feature = "thiserror"), feature = "std"))]
impl std::error::Error for CborError {}

/// Encode bytes as CBOR byte string (major type 2)
///
/// This matches the behavior of `encodeBytes` from Haskell's Cardano.Binary module.
///
/// CBOR byte strings use major type 2:
/// - For length < 24: single byte header
/// - For length < 256: header + 1 byte length
/// - For length < 65536: header + 2 bytes length
/// - For length < 2^32: header + 4 bytes length
///
/// # Example
///
/// ```
/// use cardano_crypto::cbor::encode_bytes;
///
/// let data = b"short data";
/// let cbor = encode_bytes(data);
/// assert!(cbor.len() > data.len()); // Has CBOR header
/// ```
#[cfg(feature = "alloc")]
pub fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    let len = bytes.len();
    let mut result = Vec::new();

    // Encode CBOR header based on length
    if len < 24 {
        // Short form: header byte contains length directly
        result.push(0x40 | len as u8); // Major type 2, additional info = length
    } else if len < 256 {
        // 1-byte length
        result.push(0x58); // Major type 2, additional info = 24 (1-byte uint follows)
        result.push(len as u8);
    } else if len < 65536 {
        // 2-byte length
        result.push(0x59); // Major type 2, additional info = 25 (2-byte uint follows)
        result.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        // 4-byte length (for very large keys/signatures)
        result.push(0x5a); // Major type 2, additional info = 26 (4-byte uint follows)
        result.extend_from_slice(&(len as u32).to_be_bytes());
    }

    result.extend_from_slice(bytes);
    result
}

/// Decode CBOR byte string (major type 2)
///
/// This matches the behavior of `decodeBytes` from Haskell's Cardano.Binary module.
///
/// # Example
///
/// ```
/// use cardano_crypto::cbor::{encode_bytes, decode_bytes};
///
/// let original = b"test data";
/// let cbor = encode_bytes(original);
/// let decoded = decode_bytes(&cbor).unwrap();
/// assert_eq!(original, &decoded[..]);
/// ```
#[cfg(feature = "alloc")]
pub fn decode_bytes(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    if cbor.is_empty() {
        return Err(CborError::InvalidEncoding);
    }

    let header = cbor[0];
    let major_type = (header >> 5) & 0x07;

    // Must be major type 2 (byte string)
    if major_type != 2 {
        return Err(CborError::UnexpectedStructure);
    }

    let additional_info = header & 0x1f;

    let (length, offset) = if additional_info < 24 {
        // Short form: length encoded in header
        (additional_info as usize, 1)
    } else if additional_info == 24 {
        // 1-byte length follows
        if cbor.len() < 2 {
            return Err(CborError::BufferTooSmall);
        }
        (cbor[1] as usize, 2)
    } else if additional_info == 25 {
        // 2-byte length follows
        if cbor.len() < 3 {
            return Err(CborError::BufferTooSmall);
        }
        let len = u16::from_be_bytes([cbor[1], cbor[2]]) as usize;
        (len, 3)
    } else if additional_info == 26 {
        // 4-byte length follows
        if cbor.len() < 5 {
            return Err(CborError::BufferTooSmall);
        }
        let len = u32::from_be_bytes([cbor[1], cbor[2], cbor[3], cbor[4]]) as usize;
        (len, 5)
    } else {
        return Err(CborError::InvalidEncoding);
    };

    // Check if we have enough bytes
    if cbor.len() < offset + length {
        return Err(CborError::BufferTooSmall);
    }

    // Extract the byte string
    Ok(cbor[offset..offset + length].to_vec())
}

/// Encode verification key to CBOR format
///
/// Wraps the raw serialized verification key in CBOR byte string encoding.
///
/// # Example
///
/// ```
/// use cardano_crypto::cbor::encode_verification_key;
///
/// let vkey_bytes = b"32-byte-verification-key-data!!!";
/// let cbor = encode_verification_key(vkey_bytes);
/// assert!(cbor.len() >= 32);
/// ```
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_verification_key(raw_bytes: &[u8]) -> Vec<u8> {
    encode_bytes(raw_bytes)
}

/// Decode verification key from CBOR format
///
/// Extracts raw bytes from CBOR byte string encoding.
///
/// # Example
///
/// ```
/// use cardano_crypto::cbor::{encode_verification_key, decode_verification_key};
///
/// let vkey_bytes = b"verification-key-data-32-bytes!!";
/// let cbor = encode_verification_key(vkey_bytes);
/// let decoded = decode_verification_key(&cbor).unwrap();
/// assert_eq!(vkey_bytes, &decoded[..]);
/// ```
#[cfg(feature = "alloc")]
#[inline]
pub fn decode_verification_key(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    decode_bytes(cbor)
}

/// Encode signature to CBOR format
///
/// Wraps the raw serialized signature in CBOR byte string encoding.
///
/// # Example
///
/// ```
/// use cardano_crypto::cbor::encode_signature;
///
/// // Use a 64-byte signature (common for Ed25519)
/// let sig_bytes = vec![0u8; 64];
/// let cbor = encode_signature(&sig_bytes);
/// // CBOR wrapper adds at least a small header, so encoded length should be >= raw length
/// assert!(cbor.len() >= sig_bytes.len());
/// ```
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_signature(raw_bytes: &[u8]) -> Vec<u8> {
    encode_bytes(raw_bytes)
}

/// Decode signature from CBOR format
///
/// Extracts raw bytes from CBOR byte string encoding.
#[cfg(feature = "alloc")]
#[inline]
pub fn decode_signature(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    decode_bytes(cbor)
}

// ============================================================================
// CBOR Encoding/Decoding for KES Types
// ============================================================================

/// Encode KES verification key to CBOR format
///
/// Matches `encodeVerKeyKES` from Cardano.Crypto.KES.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_verification_key_kes(raw_bytes: &[u8]) -> Vec<u8> {
    encode_bytes(raw_bytes)
}

/// Decode KES verification key from CBOR format
///
/// Matches `decodeVerKeyKES` from Cardano.Crypto.KES.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn decode_verification_key_kes(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    decode_bytes(cbor)
}

/// Encode KES signature to CBOR format
///
/// Matches `encodeSigKES` from Cardano.Crypto.KES.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_signature_kes(raw_bytes: &[u8]) -> Vec<u8> {
    encode_bytes(raw_bytes)
}

/// Decode KES signature from CBOR format
///
/// Matches `decodeSigKES` from Cardano.Crypto.KES.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn decode_signature_kes(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    decode_bytes(cbor)
}

// ============================================================================
// CBOR Encoding/Decoding for VRF Types
// ============================================================================

/// Encode VRF verification key to CBOR format
///
/// Matches `encodeVerKeyVRF` from Cardano.Crypto.VRF.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_verification_key_vrf(raw_bytes: &[u8]) -> Vec<u8> {
    encode_bytes(raw_bytes)
}

/// Decode VRF verification key from CBOR format
///
/// Matches `decodeVerKeyVRF` from Cardano.Crypto.VRF.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn decode_verification_key_vrf(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    decode_bytes(cbor)
}

/// Encode VRF signing key to CBOR format
///
/// Matches `encodeSignKeyVRF` from Cardano.Crypto.VRF.Class
///
/// # Security Warning
///
/// VRF signing keys should be handled with extreme care.
/// Consider whether CBOR serialization is truly necessary.
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_signing_key_vrf(raw_bytes: &[u8]) -> Vec<u8> {
    encode_bytes(raw_bytes)
}

/// Decode VRF signing key from CBOR format
///
/// Matches `decodeSignKeyVRF` from Cardano.Crypto.VRF.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn decode_signing_key_vrf(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    decode_bytes(cbor)
}

/// Encode VRF proof/certificate to CBOR format
///
/// Matches `encodeCertVRF` from Cardano.Crypto.VRF.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_proof_vrf(raw_bytes: &[u8]) -> Vec<u8> {
    encode_bytes(raw_bytes)
}

/// Decode VRF proof/certificate from CBOR format
///
/// Matches `decodeCertVRF` from Cardano.Crypto.VRF.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn decode_proof_vrf(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    decode_bytes(cbor)
}

// ============================================================================
// CBOR Encoding/Decoding for DSIGN Types
// ============================================================================

/// Encode DSIGN verification key to CBOR format
///
/// Matches `encodeVerKeyDSIGN` from Cardano.Crypto.DSIGN.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_verification_key_dsign(raw_bytes: &[u8]) -> Vec<u8> {
    encode_bytes(raw_bytes)
}

/// Decode DSIGN verification key from CBOR format
///
/// Matches `decodeVerKeyDSIGN` from Cardano.Crypto.DSIGN.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn decode_verification_key_dsign(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    decode_bytes(cbor)
}

/// Encode DSIGN signing key to CBOR format
///
/// Matches `encodeSignKeyDSIGN` from Cardano.Crypto.DSIGN.Class
///
/// # Security Warning
///
/// DSIGN signing keys should be handled with extreme care.
/// Consider whether CBOR serialization is truly necessary.
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_signing_key_dsign(raw_bytes: &[u8]) -> Vec<u8> {
    encode_bytes(raw_bytes)
}

/// Decode DSIGN signing key from CBOR format
///
/// Matches `decodeSignKeyDSIGN` from Cardano.Crypto.DSIGN.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn decode_signing_key_dsign(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    decode_bytes(cbor)
}

/// Encode DSIGN signature to CBOR format
///
/// Matches `encodeSigDSIGN` from Cardano.Crypto.DSIGN.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_signature_dsign(raw_bytes: &[u8]) -> Vec<u8> {
    encode_bytes(raw_bytes)
}

/// Decode DSIGN signature from CBOR format
///
/// Matches `decodeSigDSIGN` from Cardano.Crypto.DSIGN.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn decode_signature_dsign(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    decode_bytes(cbor)
}

// ============================================================================
// CBOR Encoding/Decoding for Hash Types
// ============================================================================

/// Encode a hash digest to CBOR format
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_hash(raw_bytes: &[u8]) -> Vec<u8> {
    encode_bytes(raw_bytes)
}

/// Decode a hash digest from CBOR format
#[cfg(feature = "alloc")]
#[inline]
pub fn decode_hash(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    decode_bytes(cbor)
}

// ============================================================================
// CBOR Encoding/Decoding for VRF Output Types
// ============================================================================

/// Encode VRF output to CBOR format
///
/// Matches `encodeOutputVRF` from Cardano.Crypto.VRF.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_output_vrf(raw_bytes: &[u8]) -> Vec<u8> {
    encode_bytes(raw_bytes)
}

/// Decode VRF output from CBOR format
///
/// Matches `decodeOutputVRF` from Cardano.Crypto.VRF.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn decode_output_vrf(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    decode_bytes(cbor)
}

// ============================================================================
// CBOR Encoding/Decoding for KES Signing Keys
// ============================================================================

/// Encode KES signing key to CBOR format
///
/// Matches `encodeSignKeyKES` from Cardano.Crypto.KES.Class
///
/// # Security Warning
///
/// KES signing keys should be handled with extreme care.
/// Consider whether CBOR serialization is truly necessary.
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_signing_key_kes(raw_bytes: &[u8]) -> Vec<u8> {
    encode_bytes(raw_bytes)
}

/// Decode KES signing key from CBOR format
///
/// Matches `decodeSignKeyKES` from Cardano.Crypto.KES.Class
#[cfg(feature = "alloc")]
#[inline]
pub fn decode_signing_key_kes(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    decode_bytes(cbor)
}

// ============================================================================
// Size Calculation Utilities
// ============================================================================

/// Calculate CBOR encoded size for a byte string
///
/// Returns the total number of bytes needed to encode a byte string of the given length.
/// This is useful for pre-allocating buffers.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::cbor::encoded_size_bytes;
///
/// assert_eq!(encoded_size_bytes(5), 6);   // 1 byte header + 5 bytes data
/// assert_eq!(encoded_size_bytes(100), 102); // 2 byte header + 100 bytes data
/// assert_eq!(encoded_size_bytes(300), 303); // 3 byte header + 300 bytes data
/// ```
#[must_use]
pub const fn encoded_size_bytes(len: usize) -> usize {
    if len < 24 {
        1 + len
    } else if len < 256 {
        2 + len
    } else if len < 65536 {
        3 + len
    } else {
        5 + len
    }
}

/// Size expression for CBOR verification key encoding
///
/// Matches `encodedVerKeyDSIGNSizeExpr` pattern from cardano-base
#[must_use]
pub const fn encoded_verification_key_size(raw_size: usize) -> usize {
    encoded_size_bytes(raw_size)
}

/// Size expression for CBOR signature encoding
///
/// Matches `encodedSigDSIGNSizeExpr` pattern from cardano-base
#[must_use]
pub const fn encoded_signature_size(raw_size: usize) -> usize {
    encoded_size_bytes(raw_size)
}

// ============================================================================
// DSIGN Size Expressions (matching cardano-crypto-class)
// ============================================================================

/// Size expression for encoded DSIGN verification key
///
/// Returns the CBOR encoded size for an Ed25519 verification key (32 bytes).
/// Matches `encodedVerKeyDSIGNSizeExpr` from cardano-crypto-class.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::cbor::encoded_verification_key_dsign_size;
///
/// // Ed25519 verification key is 32 bytes
/// assert_eq!(encoded_verification_key_dsign_size(), 34); // 2-byte header + 32 bytes
/// ```
#[must_use]
pub const fn encoded_verification_key_dsign_size() -> usize {
    // Ed25519 verification key: 32 bytes
    encoded_size_bytes(32)
}

/// Size expression for encoded DSIGN signing key
///
/// Returns the CBOR encoded size for an Ed25519 signing key (64 bytes - includes seed + pubkey).
/// Matches `encodedSignKeyDSIGNSizeExpr` from cardano-crypto-class.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::cbor::encoded_signing_key_dsign_size;
///
/// // Ed25519 signing key is 64 bytes (seed + public key)
/// assert_eq!(encoded_signing_key_dsign_size(), 66); // 2-byte header + 64 bytes
/// ```
#[must_use]
pub const fn encoded_signing_key_dsign_size() -> usize {
    // Ed25519 signing key: 64 bytes (seed || public_key)
    encoded_size_bytes(64)
}

/// Size expression for encoded DSIGN signature
///
/// Returns the CBOR encoded size for an Ed25519 signature (64 bytes).
/// Matches `encodedSigDSIGNSizeExpr` from cardano-crypto-class.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::cbor::encoded_signature_dsign_size;
///
/// // Ed25519 signature is 64 bytes
/// assert_eq!(encoded_signature_dsign_size(), 66); // 2-byte header + 64 bytes
/// ```
#[must_use]
pub const fn encoded_signature_dsign_size() -> usize {
    // Ed25519 signature: 64 bytes
    encoded_size_bytes(64)
}

// ============================================================================
// VRF Size Expressions (matching cardano-crypto-class)
// ============================================================================

/// Size expression for encoded VRF verification key
///
/// Returns the CBOR encoded size for a VRF verification key (32 bytes).
/// Matches `encodedVerKeyVRFSizeExpr` from cardano-crypto-class.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::cbor::encoded_verification_key_vrf_size;
///
/// // VRF verification key is 32 bytes
/// assert_eq!(encoded_verification_key_vrf_size(), 34); // 2-byte header + 32 bytes
/// ```
#[must_use]
pub const fn encoded_verification_key_vrf_size() -> usize {
    // VRF verification key: 32 bytes (Ed25519 point)
    encoded_size_bytes(32)
}

/// Size expression for encoded VRF signing key
///
/// Returns the CBOR encoded size for a VRF signing key (64 bytes).
/// Matches `encodedSignKeyVRFSizeExpr` from cardano-crypto-class.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::cbor::encoded_signing_key_vrf_size;
///
/// // VRF signing key is 64 bytes
/// assert_eq!(encoded_signing_key_vrf_size(), 66); // 2-byte header + 64 bytes
/// ```
#[must_use]
pub const fn encoded_signing_key_vrf_size() -> usize {
    // VRF signing key: 64 bytes
    encoded_size_bytes(64)
}

/// Size expression for encoded VRF proof (Draft-03)
///
/// Returns the CBOR encoded size for a VRF Draft-03 proof (80 bytes).
/// Matches `encodedCertVRFSizeExpr` from cardano-crypto-class.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::cbor::encoded_proof_vrf_draft03_size;
///
/// // VRF Draft-03 proof is 80 bytes
/// assert_eq!(encoded_proof_vrf_draft03_size(), 82); // 2-byte header + 80 bytes
/// ```
#[must_use]
pub const fn encoded_proof_vrf_draft03_size() -> usize {
    // VRF Draft-03 proof: 80 bytes
    encoded_size_bytes(80)
}

/// Size expression for encoded VRF proof (Draft-13)
///
/// Returns the CBOR encoded size for a VRF Draft-13 proof (128 bytes).
///
/// # Example
///
/// ```rust
/// use cardano_crypto::cbor::encoded_proof_vrf_draft13_size;
///
/// // VRF Draft-13 proof is 128 bytes
/// assert_eq!(encoded_proof_vrf_draft13_size(), 130); // 2-byte header + 128 bytes
/// ```
#[must_use]
pub const fn encoded_proof_vrf_draft13_size() -> usize {
    // VRF Draft-13 proof: 128 bytes
    encoded_size_bytes(128)
}

/// Size expression for encoded VRF output
///
/// Returns the CBOR encoded size for a VRF output (64 bytes SHA-512 hash).
/// Matches `encodedOutputVRFSizeExpr` from cardano-crypto-class.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::cbor::encoded_output_vrf_size;
///
/// // VRF output is 64 bytes (SHA-512 hash)
/// assert_eq!(encoded_output_vrf_size(), 66); // 2-byte header + 64 bytes
/// ```
#[must_use]
pub const fn encoded_output_vrf_size() -> usize {
    // VRF output: 64 bytes (SHA-512)
    encoded_size_bytes(64)
}

// ============================================================================
// KES Size Expressions (matching cardano-crypto-class)
// ============================================================================

/// Size expression for encoded KES verification key
///
/// KES verification keys are 32 bytes (Ed25519 verification key).
/// Matches `encodedVerKeyKESSizeExpr` from cardano-crypto-class.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::cbor::encoded_verification_key_kes_size;
///
/// assert_eq!(encoded_verification_key_kes_size(), 34); // 2-byte header + 32 bytes
/// ```
#[must_use]
pub const fn encoded_verification_key_kes_size() -> usize {
    // KES verification key: 32 bytes
    encoded_size_bytes(32)
}

/// Size expression for encoded Sum6KES signing key
///
/// Sum6KES signing key size varies but is typically large.
/// This returns the size for a freshly generated Sum6KES key.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::cbor::encoded_signing_key_sum6kes_size;
///
/// let size = encoded_signing_key_sum6kes_size();
/// assert!(size > 100); // Sum6KES keys are large
/// ```
#[must_use]
pub const fn encoded_signing_key_sum6kes_size() -> usize {
    // Sum6KES signing key: 2112 bytes -> 2115 bytes CBOR (3 byte header + 2112 bytes)
    encoded_size_bytes(2112)
}

/// Size expression for encoded Sum6KES signature
///
/// Returns the CBOR encoded size for a Sum6KES signature.
/// Matches `encodedSigKESSizeExpr` from cardano-crypto-class.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::cbor::encoded_signature_sum6kes_size;
///
/// let size = encoded_signature_sum6kes_size();
/// assert!(size > 400); // Sum6KES signatures are 448 bytes
/// ```
#[must_use]
pub const fn encoded_signature_sum6kes_size() -> usize {
    // Sum6KES signature: 448 bytes
    encoded_size_bytes(448)
}

// ============================================================================
// Hash Size Expressions
// ============================================================================

/// Size expression for encoded Blake2b-224 hash
///
/// # Example
///
/// ```rust
/// use cardano_crypto::cbor::encoded_hash_blake2b224_size;
///
/// assert_eq!(encoded_hash_blake2b224_size(), 30); // 2-byte header + 28 bytes
/// ```
#[must_use]
pub const fn encoded_hash_blake2b224_size() -> usize {
    encoded_size_bytes(28)
}

/// Size expression for encoded Blake2b-256 hash
///
/// # Example
///
/// ```rust
/// use cardano_crypto::cbor::encoded_hash_blake2b256_size;
///
/// assert_eq!(encoded_hash_blake2b256_size(), 34); // 2-byte header + 32 bytes
/// ```
#[must_use]
pub const fn encoded_hash_blake2b256_size() -> usize {
    encoded_size_bytes(32)
}

// ============================================================================
// Traits for CBOR Serialization (matching Cardano.Binary)
// ============================================================================

/// Trait for types that can be encoded to CBOR
///
/// This trait matches the `ToCBOR` typeclass from Cardano.Binary.
/// Types implementing this trait can be serialized to CBOR format.
pub trait ToCbor {
    /// Encode this value to CBOR bytes
    #[cfg(feature = "alloc")]
    fn to_cbor(&self) -> Vec<u8>;

    /// Returns the encoded size in bytes
    fn encoded_size(&self) -> usize;
}

/// Trait for types that can be decoded from CBOR
///
/// This trait matches the `FromCBOR` typeclass from Cardano.Binary.
/// Types implementing this trait can be deserialized from CBOR format.
pub trait FromCbor: Sized {
    /// Decode this value from CBOR bytes
    fn from_cbor(bytes: &[u8]) -> Result<Self, CborError>;
}

// ============================================================================
// ToCbor/FromCbor implementations for primitive arrays
// ============================================================================

impl ToCbor for [u8; 32] {
    #[cfg(feature = "alloc")]
    fn to_cbor(&self) -> Vec<u8> {
        encode_bytes(self)
    }

    fn encoded_size(&self) -> usize {
        encoded_size_bytes(32)
    }
}

impl FromCbor for [u8; 32] {
    fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let decoded = decode_bytes(bytes)?;
        if decoded.len() != 32 {
            return Err(CborError::InvalidLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        Ok(arr)
    }
}

impl ToCbor for [u8; 64] {
    #[cfg(feature = "alloc")]
    fn to_cbor(&self) -> Vec<u8> {
        encode_bytes(self)
    }

    fn encoded_size(&self) -> usize {
        encoded_size_bytes(64)
    }
}

impl FromCbor for [u8; 64] {
    fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let decoded = decode_bytes(bytes)?;
        if decoded.len() != 64 {
            return Err(CborError::InvalidLength);
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&decoded);
        Ok(arr)
    }
}

impl ToCbor for [u8; 80] {
    #[cfg(feature = "alloc")]
    fn to_cbor(&self) -> Vec<u8> {
        encode_bytes(self)
    }

    fn encoded_size(&self) -> usize {
        encoded_size_bytes(80)
    }
}

impl FromCbor for [u8; 80] {
    fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let decoded = decode_bytes(bytes)?;
        if decoded.len() != 80 {
            return Err(CborError::InvalidLength);
        }
        let mut arr = [0u8; 80];
        arr.copy_from_slice(&decoded);
        Ok(arr)
    }
}

#[cfg(feature = "alloc")]
impl ToCbor for Vec<u8> {
    fn to_cbor(&self) -> Vec<u8> {
        encode_bytes(self)
    }

    fn encoded_size(&self) -> usize {
        encoded_size_bytes(self.len())
    }
}

#[cfg(feature = "alloc")]
impl FromCbor for Vec<u8> {
    fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        decode_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbor_encode_decode_short() {
        // Test with short byte string (< 24 bytes)
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let encoded = encode_bytes(&data);

        // Should be: header (0x45 = major type 2, length 5) + data
        assert_eq!(encoded[0], 0x45);
        assert_eq!(&encoded[1..], &data[..]);

        let decoded = decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_cbor_encode_decode_medium() {
        // Test with medium byte string (< 256 bytes)
        let data = vec![0xAB; 200];
        let encoded = encode_bytes(&data);

        // Should be: header (0x58) + length byte (200) + data
        assert_eq!(encoded[0], 0x58);
        assert_eq!(encoded[1], 200);

        let decoded = decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_cbor_encode_decode_large() {
        // Test with large byte string (>= 256 bytes)
        let data = vec![0xCD; 500];
        let encoded = encode_bytes(&data);

        // Should be: header (0x59) + 2-byte length (500) + data
        assert_eq!(encoded[0], 0x59);
        assert_eq!(u16::from_be_bytes([encoded[1], encoded[2]]), 500);

        let decoded = decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_cbor_verification_key_roundtrip() {
        // Simulate a 32-byte Ed25519 verification key
        let vk_bytes = vec![0x12; 32];

        let encoded = encode_verification_key(&vk_bytes);
        let decoded = decode_verification_key(&encoded).unwrap();

        assert_eq!(decoded, vk_bytes);
    }

    #[test]
    fn test_cbor_signature_roundtrip() {
        // Simulate a 64-byte Ed25519 signature
        let sig_bytes = vec![0x34; 64];

        let encoded = encode_signature(&sig_bytes);
        let decoded = decode_signature(&encoded).unwrap();

        assert_eq!(decoded, sig_bytes);
    }

    #[test]
    fn test_cbor_invalid_major_type() {
        // Try to decode a CBOR integer (major type 0) as byte string
        let invalid = vec![0x00]; // Integer 0

        let result = decode_bytes(&invalid);
        assert!(matches!(result, Err(CborError::UnexpectedStructure)));
    }

    #[test]
    fn test_cbor_buffer_too_small() {
        // Header says 1-byte length follows, but buffer is too short
        let invalid = vec![0x58]; // Missing length byte

        let result = decode_bytes(&invalid);
        assert!(matches!(result, Err(CborError::BufferTooSmall)));
    }

    #[test]
    fn test_cbor_empty() {
        let result = decode_bytes(&[]);
        assert!(matches!(result, Err(CborError::InvalidEncoding)));
    }

    #[test]
    fn test_encoded_size_bytes() {
        // Test size calculations
        assert_eq!(encoded_size_bytes(0), 1);
        assert_eq!(encoded_size_bytes(23), 24);
        assert_eq!(encoded_size_bytes(24), 26); // 2 byte header
        assert_eq!(encoded_size_bytes(255), 257);
        assert_eq!(encoded_size_bytes(256), 259); // 3 byte header
        assert_eq!(encoded_size_bytes(65535), 65538);
        assert_eq!(encoded_size_bytes(65536), 65541); // 5 byte header
    }

    #[test]
    fn test_kes_verification_key_cbor() {
        // Test with typical Sum6KES verification key size (64 bytes for Sum6)
        let vk_bytes = vec![0xAA; 64];
        let encoded = encode_verification_key_kes(&vk_bytes);
        let decoded = decode_verification_key_kes(&encoded).unwrap();
        assert_eq!(decoded, vk_bytes);
    }

    #[test]
    fn test_kes_signature_cbor() {
        // Test with typical KES signature size
        let sig_bytes = vec![0xBB; 448]; // Sum6KES signature is ~448 bytes
        let encoded = encode_signature_kes(&sig_bytes);
        let decoded = decode_signature_kes(&encoded).unwrap();
        assert_eq!(decoded, sig_bytes);
    }

    #[test]
    fn test_kes_signing_key_cbor() {
        // Test with KES signing key
        let sk_bytes = vec![0xCC; 128];
        let encoded = encode_signing_key_kes(&sk_bytes);
        let decoded = decode_signing_key_kes(&encoded).unwrap();
        assert_eq!(decoded, sk_bytes);
    }

    #[test]
    fn test_vrf_proof_cbor() {
        // VRF proofs are 80 bytes
        let proof_bytes = vec![0xCC; 80];
        let encoded = encode_proof_vrf(&proof_bytes);
        let decoded = decode_proof_vrf(&encoded).unwrap();
        assert_eq!(decoded, proof_bytes);
    }

    #[test]
    fn test_vrf_output_cbor() {
        // VRF output is 64 bytes
        let output_bytes = vec![0xDD; 64];
        let encoded = encode_output_vrf(&output_bytes);
        let decoded = decode_output_vrf(&encoded).unwrap();
        assert_eq!(decoded, output_bytes);
    }

    #[test]
    fn test_dsign_roundtrip() {
        // Ed25519 verification key (32 bytes)
        let vk = vec![0x11; 32];
        let vk_cbor = encode_verification_key_dsign(&vk);
        assert_eq!(decode_verification_key_dsign(&vk_cbor).unwrap(), vk);

        // Ed25519 signature (64 bytes)
        let sig = vec![0x22; 64];
        let sig_cbor = encode_signature_dsign(&sig);
        assert_eq!(decode_signature_dsign(&sig_cbor).unwrap(), sig);
    }

    #[test]
    fn test_hash_cbor() {
        // Blake2b-256 hash (32 bytes)
        let hash = vec![0xDD; 32];
        let encoded = encode_hash(&hash);
        let decoded = decode_hash(&encoded).unwrap();
        assert_eq!(decoded, hash);
    }

    #[test]
    fn test_cbor_edge_cases() {
        // Empty byte string
        let empty: Vec<u8> = vec![];
        let encoded = encode_bytes(&empty);
        assert_eq!(encoded, vec![0x40]); // Just the header
        assert_eq!(decode_bytes(&encoded).unwrap(), empty);

        // Exactly 23 bytes (boundary)
        let data_23 = vec![0xFF; 23];
        let encoded_23 = encode_bytes(&data_23);
        assert_eq!(encoded_23[0], 0x57); // 0x40 + 23
        assert_eq!(decode_bytes(&encoded_23).unwrap(), data_23);

        // Exactly 24 bytes (first to need 2-byte header)
        let data_24 = vec![0xEE; 24];
        let encoded_24 = encode_bytes(&data_24);
        assert_eq!(encoded_24[0], 0x58);
        assert_eq!(encoded_24[1], 24);
        assert_eq!(decode_bytes(&encoded_24).unwrap(), data_24);

        // Exactly 255 bytes (boundary)
        let data_255 = vec![0xDD; 255];
        let encoded_255 = encode_bytes(&data_255);
        assert_eq!(encoded_255[0], 0x58);
        assert_eq!(encoded_255[1], 255);
        assert_eq!(decode_bytes(&encoded_255).unwrap(), data_255);

        // Exactly 256 bytes (first to need 3-byte header)
        let data_256 = vec![0xCC; 256];
        let encoded_256 = encode_bytes(&data_256);
        assert_eq!(encoded_256[0], 0x59);
        assert_eq!(u16::from_be_bytes([encoded_256[1], encoded_256[2]]), 256);
        assert_eq!(decode_bytes(&encoded_256).unwrap(), data_256);
    }

    #[test]
    fn test_to_cbor_trait_array_32() {
        let arr: [u8; 32] = [0x42; 32];
        let encoded = arr.to_cbor();
        let decoded = <[u8; 32]>::from_cbor(&encoded).unwrap();
        assert_eq!(arr, decoded);
        assert_eq!(arr.encoded_size(), encoded.len());
    }

    #[test]
    fn test_to_cbor_trait_array_64() {
        let arr: [u8; 64] = [0x43; 64];
        let encoded = arr.to_cbor();
        let decoded = <[u8; 64]>::from_cbor(&encoded).unwrap();
        assert_eq!(arr, decoded);
        assert_eq!(arr.encoded_size(), encoded.len());
    }

    #[test]
    fn test_to_cbor_trait_array_80() {
        let arr: [u8; 80] = [0x44; 80];
        let encoded = arr.to_cbor();
        let decoded = <[u8; 80]>::from_cbor(&encoded).unwrap();
        assert_eq!(arr, decoded);
        assert_eq!(arr.encoded_size(), encoded.len());
    }

    #[test]
    fn test_to_cbor_trait_vec() {
        let vec = vec![0x45u8; 100];
        let encoded = vec.to_cbor();
        let decoded = Vec::<u8>::from_cbor(&encoded).unwrap();
        assert_eq!(vec, decoded);
        assert_eq!(vec.encoded_size(), encoded.len());
    }

    #[test]
    fn test_from_cbor_invalid_length() {
        // Try to decode a 31-byte payload as [u8; 32]
        let data = vec![0x42u8; 31];
        let encoded = encode_bytes(&data);
        let result = <[u8; 32]>::from_cbor(&encoded);
        assert!(matches!(result, Err(CborError::InvalidLength)));
    }

    #[test]
    fn test_vrf_output_trait_roundtrip() {
        use crate::vrf::{VrfDraft03, OutputVrf};

        let seed = [42u8; 32];
        let (secret_key, public_key) = VrfDraft03::keypair_from_seed(&seed);
        let proof = VrfDraft03::prove(&secret_key, b"test").unwrap();
        let output_bytes = VrfDraft03::verify(&public_key, &proof, b"test").unwrap();

        let output = OutputVrf::new(output_bytes);
        let encoded = output.to_cbor();
        let decoded = OutputVrf::from_cbor(&encoded).unwrap();
        assert_eq!(output.as_bytes(), decoded.as_bytes());
    }

    #[test]
    fn test_certified_vrf_cbor_roundtrip() {
        use crate::vrf::CertifiedVrf;

        let seed = [42u8; 32];
        let (secret_key, _) = crate::vrf::VrfDraft03::keypair_from_seed(&seed);
        let certified = CertifiedVrf::eval(&secret_key, b"test message").unwrap();

        let encoded = certified.to_cbor();
        let decoded = CertifiedVrf::from_cbor(&encoded).unwrap();

        assert_eq!(certified.get_output().as_bytes(), decoded.get_output().as_bytes());
        assert_eq!(certified.get_proof(), decoded.get_proof());
    }

    #[test]
    fn test_signed_dsign_cbor_roundtrip() {
        use crate::dsign::{Ed25519, DsignAlgorithm, SignedDsign};

        let signing_key = Ed25519::gen_key(&[42u8; 32]);
        let signed = SignedDsign::<Ed25519>::sign(&signing_key, b"test message");

        let encoded = signed.to_cbor();
        let decoded = SignedDsign::<Ed25519>::from_cbor(&encoded).unwrap();

        assert_eq!(signed.get_signature().as_bytes(), decoded.get_signature().as_bytes());
    }

    #[test]
    fn test_ed25519_verification_key_cbor_roundtrip() {
        use crate::dsign::{Ed25519, DsignAlgorithm};
        use crate::dsign::ed25519::Ed25519VerificationKey;

        let signing_key = Ed25519::gen_key(&[42u8; 32]);
        let vk = Ed25519::derive_verification_key(&signing_key);

        let encoded = vk.to_cbor();
        let decoded = Ed25519VerificationKey::from_cbor(&encoded).unwrap();

        assert_eq!(vk.as_bytes(), decoded.as_bytes());
    }

    #[test]
    fn test_ed25519_signature_cbor_roundtrip() {
        use crate::dsign::{Ed25519, DsignAlgorithm};
        use crate::dsign::ed25519::Ed25519Signature;

        let signing_key = Ed25519::gen_key(&[42u8; 32]);
        let sig = Ed25519::sign(&signing_key, b"test message");

        let encoded = sig.to_cbor();
        let decoded = Ed25519Signature::from_cbor(&encoded).unwrap();

        assert_eq!(sig.as_bytes(), decoded.as_bytes());
    }

    // ========================================================================
    // Size Expression Tests (matching cardano-crypto-class patterns)
    // ========================================================================

    #[test]
    fn test_dsign_size_expressions() {
        // Ed25519 verification key: 32 bytes -> 34 bytes CBOR (2 byte header + 32 bytes)
        assert_eq!(encoded_verification_key_dsign_size(), 34);

        // Ed25519 signing key: 64 bytes -> 66 bytes CBOR
        assert_eq!(encoded_signing_key_dsign_size(), 66);

        // Ed25519 signature: 64 bytes -> 66 bytes CBOR
        assert_eq!(encoded_signature_dsign_size(), 66);

        // Verify against actual encoding
        let vk = vec![0x42u8; 32];
        assert_eq!(encode_verification_key_dsign(&vk).len(), encoded_verification_key_dsign_size());

        let sig = vec![0x43u8; 64];
        assert_eq!(encode_signature_dsign(&sig).len(), encoded_signature_dsign_size());
    }

    #[test]
    fn test_vrf_size_expressions() {
        // VRF verification key: 32 bytes -> 34 bytes CBOR
        assert_eq!(encoded_verification_key_vrf_size(), 34);

        // VRF signing key: 64 bytes -> 66 bytes CBOR
        assert_eq!(encoded_signing_key_vrf_size(), 66);

        // VRF Draft-03 proof: 80 bytes -> 82 bytes CBOR
        assert_eq!(encoded_proof_vrf_draft03_size(), 82);

        // VRF Draft-13 proof: 128 bytes -> 130 bytes CBOR
        assert_eq!(encoded_proof_vrf_draft13_size(), 130);

        // VRF output: 64 bytes -> 66 bytes CBOR
        assert_eq!(encoded_output_vrf_size(), 66);

        // Verify against actual encoding
        let vk = vec![0x44u8; 32];
        assert_eq!(encode_verification_key_vrf(&vk).len(), encoded_verification_key_vrf_size());

        let proof = vec![0x45u8; 80];
        assert_eq!(encode_proof_vrf(&proof).len(), encoded_proof_vrf_draft03_size());

        let output = vec![0x46u8; 64];
        assert_eq!(encode_output_vrf(&output).len(), encoded_output_vrf_size());
    }

    #[test]
    fn test_kes_size_expressions() {
        // KES verification key: 32 bytes -> 34 bytes CBOR
        assert_eq!(encoded_verification_key_kes_size(), 34);

        // Sum6KES signing key: 2112 bytes -> 2115 bytes CBOR (3 byte header + 2112 bytes)
        assert_eq!(encoded_signing_key_sum6kes_size(), 2115);

        // Sum6KES signature: 448 bytes -> 451 bytes CBOR (3 byte header + 448 bytes)
        assert_eq!(encoded_signature_sum6kes_size(), 451);

        // Verify against actual encoding
        let vk = vec![0x47u8; 32];
        assert_eq!(encode_verification_key_kes(&vk).len(), encoded_verification_key_kes_size());

        let sig = vec![0x48u8; 448];
        assert_eq!(encode_signature_kes(&sig).len(), encoded_signature_sum6kes_size());
    }

    #[test]
    fn test_hash_size_expressions() {
        // Blake2b-224: 28 bytes -> 30 bytes CBOR (2 byte header + 28 bytes)
        assert_eq!(encoded_hash_blake2b224_size(), 30);

        // Blake2b-256: 32 bytes -> 34 bytes CBOR (2 byte header + 32 bytes)
        assert_eq!(encoded_hash_blake2b256_size(), 34);

        // Verify against actual encoding
        let hash224 = vec![0x49u8; 28];
        assert_eq!(encode_hash(&hash224).len(), encoded_hash_blake2b224_size());

        let hash256 = vec![0x4Au8; 32];
        assert_eq!(encode_hash(&hash256).len(), encoded_hash_blake2b256_size());
    }

    #[test]
    fn test_size_expression_generic() {
        // Test the generic size functions
        assert_eq!(encoded_verification_key_size(32), 34);
        assert_eq!(encoded_verification_key_size(64), 66);
        assert_eq!(encoded_signature_size(64), 66);
        assert_eq!(encoded_signature_size(448), 451);
    }

    #[test]
    fn test_size_expression_boundaries() {
        // Test boundary conditions
        // 0-23 bytes: 1 byte header
        assert_eq!(encoded_size_bytes(0), 1);
        assert_eq!(encoded_size_bytes(23), 24);

        // 24-255 bytes: 2 byte header
        assert_eq!(encoded_size_bytes(24), 26);
        assert_eq!(encoded_size_bytes(255), 257);

        // 256-65535 bytes: 3 byte header
        assert_eq!(encoded_size_bytes(256), 259);
        assert_eq!(encoded_size_bytes(65535), 65538);

        // 65536+ bytes: 5 byte header
        assert_eq!(encoded_size_bytes(65536), 65541);
    }

    // ========================================================================
    // Serialization Roundtrip Tests (matching cardano-crypto-tests patterns)
    // ========================================================================

    #[test]
    fn test_dsign_verification_key_serialization_roundtrip() {
        use crate::dsign::{Ed25519, DsignAlgorithm};

        // Generate a real verification key
        let signing_key = Ed25519::gen_key(&[0xABu8; 32]);
        let vk = Ed25519::derive_verification_key(&signing_key);

        // Raw serialization roundtrip
        let raw = Ed25519::raw_serialize_verification_key(&vk);
        let recovered = Ed25519::raw_deserialize_verification_key(raw).unwrap();
        assert_eq!(vk.as_bytes(), recovered.as_bytes());

        // CBOR serialization roundtrip
        let cbor = encode_verification_key_dsign(raw);
        let decoded = decode_verification_key_dsign(&cbor).unwrap();
        assert_eq!(raw, &decoded[..]);
    }

    #[test]
    fn test_dsign_signature_serialization_roundtrip() {
        use crate::dsign::{Ed25519, DsignAlgorithm};

        let signing_key = Ed25519::gen_key(&[0xCDu8; 32]);
        let sig = Ed25519::sign(&signing_key, b"test message");

        // Raw serialization roundtrip
        let raw = Ed25519::raw_serialize_signature(&sig);
        let recovered = Ed25519::raw_deserialize_signature(raw).unwrap();
        assert_eq!(sig.as_bytes(), recovered.as_bytes());

        // CBOR serialization roundtrip
        let cbor = encode_signature_dsign(raw);
        let decoded = decode_signature_dsign(&cbor).unwrap();
        assert_eq!(raw, &decoded[..]);
    }

    #[test]
    fn test_vrf_verification_key_serialization_roundtrip() {
        use crate::vrf::{VrfDraft03, VrfAlgorithm};

        let seed = [0xEFu8; 32];
        let (_, vk) = VrfDraft03::keypair_from_seed(&seed);

        // Raw serialization roundtrip
        let raw = VrfDraft03::raw_serialize_verification_key(&vk);
        let recovered = VrfDraft03::raw_deserialize_verification_key(raw).unwrap();
        assert_eq!(vk, recovered);

        // CBOR serialization roundtrip
        let cbor = encode_verification_key_vrf(raw);
        let decoded = decode_verification_key_vrf(&cbor).unwrap();
        assert_eq!(raw, &decoded[..]);
    }

    #[test]
    fn test_vrf_proof_serialization_roundtrip() {
        use crate::vrf::{VrfDraft03, VrfAlgorithm};

        let seed = [0x12u8; 32];
        let (sk, _) = VrfDraft03::keypair_from_seed(&seed);
        let proof = VrfDraft03::prove(&sk, b"test input").unwrap();

        // Raw serialization roundtrip
        let raw = VrfDraft03::raw_serialize_proof(&proof);
        let recovered = VrfDraft03::raw_deserialize_proof(raw).unwrap();
        assert_eq!(proof, recovered);

        // CBOR serialization roundtrip
        let cbor = encode_proof_vrf(raw);
        let decoded = decode_proof_vrf(&cbor).unwrap();
        assert_eq!(raw, &decoded[..]);
    }

    #[test]
    fn test_kes_verification_key_serialization_roundtrip() {
        use crate::kes::{Sum6Kes, KesAlgorithm};

        let seed = [0x34u8; 32];
        let signing_key = Sum6Kes::gen_key_kes_from_seed_bytes(&seed).unwrap();
        let vk = Sum6Kes::derive_verification_key(&signing_key).unwrap();

        // Raw serialization roundtrip
        let raw = Sum6Kes::raw_serialize_verification_key_kes(&vk);
        let recovered = Sum6Kes::raw_deserialize_verification_key_kes(&raw).unwrap();
        assert_eq!(vk, recovered);

        // CBOR serialization roundtrip
        let cbor = encode_verification_key_kes(&raw);
        let decoded = decode_verification_key_kes(&cbor).unwrap();
        assert_eq!(raw, decoded);
    }

    #[test]
    fn test_kes_signature_serialization_roundtrip() {
        use crate::kes::{Sum6Kes, KesAlgorithm};

        let seed = [0x56u8; 32];
        let signing_key = Sum6Kes::gen_key_kes_from_seed_bytes(&seed).unwrap();
        let signature = Sum6Kes::sign_kes(&(), 0, b"test message", &signing_key).unwrap();

        // Raw serialization roundtrip
        let raw = Sum6Kes::raw_serialize_signature_kes(&signature);
        let _recovered = Sum6Kes::raw_deserialize_signature_kes(&raw).unwrap();
        // Note: KES signature comparison would need proper Eq impl

        // CBOR serialization roundtrip
        let cbor = encode_signature_kes(&raw);
        let decoded = decode_signature_kes(&cbor).unwrap();
        assert_eq!(raw, decoded);
    }
}
