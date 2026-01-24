# GitHub Copilot Instructions for cardano-crypto

> **Last Updated:** 2026-01-24  
> **Version:** 1.1.0  
> **Purpose:** Guide GitHub Copilot and AI assistants in maintaining code quality, consistency, and Cardano compatibility

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Critical Compatibility Requirements](#critical-compatibility-requirements)
3. [Code Architecture](#code-architecture)
4. [Coding Standards](#coding-standards)
5. [Documentation Standards](#documentation-standards)
6. [Testing Requirements](#testing-requirements)
7. [Security Guidelines](#security-guidelines)
8. [Feature Implementation Guidelines](#feature-implementation-guidelines)
9. [Common Patterns](#common-patterns)
10. [Do's and Don'ts](#dos-and-donts)

---

## Project Overview

### Mission Statement

This is a **production-grade** Rust implementation of Cardano cryptographic primitives providing 100% binary compatibility with IntersectMBO/cardano-node. Every implementation must match byte-for-byte with the official Haskell cardano-base library.

### Core Principles

1. **Binary Compatibility First** - All outputs must match IntersectMBO/cardano-base exactly
2. **Security by Design** - Constant-time operations, proper zeroization, no panics in crypto code
3. **Zero-Trust Documentation** - Verify all claims with test vectors from official sources
4. **No-std by Default** - Support embedded systems; `std` is optional
5. **Rust Best Practices** - Modern Rust 2021 edition, idiomatic patterns, comprehensive RustDoc

### Target Rust Version

- **MSRV (Minimum Supported Rust Version):** 1.81
- **Edition:** 2021
- **Toolchain Features Used:**
  - `const` generics
  - `async` traits (where applicable)
  - GATs (Generic Associated Types)
  - Latest `derive` macros

---

## Critical Compatibility Requirements

### 1. IntersectMBO Alignment

**MANDATORY:** Every cryptographic primitive must match the IntersectMBO implementation:

- **Repository:** https://github.com/IntersectMBO/cardano-base
- **Key Packages:**
  - `cardano-crypto-class` - Core cryptographic abstractions
  - `cardano-crypto-praos` - VRF and KES implementations
  - `cardano-crypto` (legacy) - Blake2b and other hashes

#### Verification Process

When implementing or modifying any cryptographic function:

1. **Find the Haskell equivalent** in cardano-base
2. **Extract test vectors** from Haskell tests or IETF specs
3. **Verify byte-for-byte** output matches
4. **Document the mapping** in code comments

**Example:**
```rust
//! # Cardano Compatibility
//!
//! This implementation matches the Haskell `VRFAlgorithm` type class from:
//! `cardano-crypto-class/src/Cardano/Crypto/VRF.hs`
//!
//! Specifically, this is `VRF_DRAFT03` which implements ECVRF-ED25519-SHA512-Elligator2
//! as specified in IETF draft-irtf-cfrg-vrf-03.
```

### 2. Standards Compliance

Each cryptographic primitive follows specific standards:

| Primitive | Standard | Verification |
|-----------|----------|--------------|
| VRF Draft-03 | IETF draft-irtf-cfrg-vrf-03 | Official test vectors |
| VRF Draft-13 | IETF draft-irtf-cfrg-vrf-13 | Official test vectors |
| KES | MMM 2002 paper + Cardano spec | cardano-base golden tests |
| Ed25519 | RFC 8032 | ed25519-dalek (audited) |
| Blake2b | RFC 7693 | RustCrypto (audited) |
| secp256k1 | CIP-0049 + BIP-340 | k256 (audited) |
| BLS12-381 | CIP-0381 + BLS RFC draft | blst (audited) |
| HD Derivation | CIP-1852 + BIP32-Ed25519 | cardano-addresses tests |

### 3. CIP Support

Cardano Improvement Proposals (CIPs) define protocol extensions:

- **CIP-0049:** ECDSA and Schnorr signatures on secp256k1 for Plutus
- **CIP-0381:** Pairing-friendly curve operations for Plutus V2+
- **CIP-1852:** HD wallet derivation paths

**When implementing CIP features:**
1. Link to the CIP in module documentation
2. Include CIP reference in function doc comments
3. Test against official CIP test vectors
4. Mark with `#[cfg_attr(docsrs, doc(cfg(feature = "...")))]`

---

## Code Architecture

### Module Organization

```
src/
├── lib.rs                  # Public API, re-exports, feature flags
├── common/                 # Shared utilities
│   ├── mod.rs
│   ├── error.rs           # Error types (Result<T> = Result<T, CryptoError>)
│   ├── traits.rs          # Core traits (DsignAlgorithm, etc.)
│   ├── hash.rs            # Hash trait and utilities
│   ├── curve.rs           # Curve25519 utilities
│   ├── security.rs        # Constant-time ops, zeroization
│   └── vrf_constants.rs   # VRF domain separation tags
├── hash/                   # Hash algorithms
│   ├── mod.rs
│   ├── blake2b.rs         # Blake2b-224, 256, 512
│   └── sha.rs             # SHA-256, SHA-512 wrappers
├── dsign/                  # Digital signatures
│   ├── mod.rs
│   ├── ed25519.rs         # Ed25519 (Cardano standard)
│   └── secp256k1.rs       # ECDSA + Schnorr (Plutus CIP-0049)
├── vrf/                    # Verifiable Random Functions
│   ├── mod.rs
│   ├── draft03.rs         # VRF Draft-03 (Cardano Praos)
│   ├── draft13.rs         # VRF Draft-13 (batch verification)
│   ├── cardano_compat/    # Cardano-specific libsodium compat
│   └── test_vectors.rs
├── kes/                    # Key Evolving Signatures
│   ├── mod.rs
│   ├── hash.rs            # KES-specific hash operations
│   ├── single/            # SingleKES (1 period)
│   ├── sum/               # SumKES (2^N periods)
│   └── test_vectors.rs
├── bls/                    # BLS12-381 (Plutus CIP-0381)
│   └── mod.rs
├── seed/                   # Seed derivation
│   └── mod.rs
├── key/                    # Key management
│   ├── mod.rs
│   ├── encoding.rs        # CBOR, Bech32 encoding
│   ├── hash.rs            # Key hashing (KeyHash types)
│   ├── kes_period.rs      # KES period calculations
│   ├── text_envelope.rs   # cardano-cli key format
│   └── bech32.rs          # Bech32 encoding
├── hd/                     # HD wallet derivation
│   ├── mod.rs
│   └── address.rs         # Address construction
└── cbor/                   # CBOR serialization
    └── mod.rs
```

### Feature Flag Architecture

**Design Philosophy:**
- **Granular features** - Users enable only what they need
- **Feature composition** - Complex features automatically enable dependencies
- **No runtime overhead** - Features compile out completely when disabled

**Feature Hierarchy:**
```
default = ["std", "vrf", "kes", "dsign", "hash", "seed", "cbor", "key", "hd"]
├── std (implies alloc)
├── alloc
├── vrf (requires dsign, hash, alloc)
├── kes (requires dsign, hash, alloc)
├── dsign (requires hash, alloc)
├── hash (requires alloc)
├── seed (requires hash, alloc)
├── cbor (requires alloc)
├── key (requires hash)
├── hd (requires dsign, hash, alloc, seed)
├── bls (requires alloc)
├── secp256k1 (requires dsign, alloc)
└── plutus (enables secp256k1 + bls)
```

**When adding new features:**
1. Add to `[features]` section in Cargo.toml
2. Gate module with `#[cfg(feature = "...")]`
3. Add doc attribute: `#[cfg_attr(docsrs, doc(cfg(feature = "...")))]`
4. Update lib.rs re-exports
5. Add example in `examples/` directory
6. Document in README.md feature flags section

---

## Coding Standards

### 1. Error Handling

**NEVER use `.unwrap()` or `.expect()` in library code** (except in test code).

```rust
// ❌ WRONG - Panic in library code
let result = some_function().unwrap();

// ✅ CORRECT - Return Result
let result = some_function().map_err(|e| CryptoError::InvalidInput)?;

// ✅ CORRECT - Use if let/match for Option
if let Some(value) = maybe_value {
    // handle value
} else {
    return Err(CryptoError::InvalidInput);
}
```

**Error Type Hierarchy:**
```rust
// Main error type (in common/error.rs)
pub enum CryptoError {
    // Invalid input parameters
    InvalidInput,
    InvalidLength { expected: usize, actual: usize },
    InvalidFormat,
    
    // Verification failures
    VerificationFailed,
    SignatureMismatch,
    
    // Cryptographic errors
    KeyDerivationFailed,
    ProofGenerationFailed,
    
    // Algorithm-specific errors
    Vrf(VrfError),
    Kes(KesError),
    Dsign(DsignError),
}
```

**Custom Result Type:**
```rust
pub type Result<T> = core::result::Result<T, CryptoError>;
```

### 2. Type Safety

**Use newtypes for distinct concepts:**

```rust
// ❌ WRONG - Primitives are confusing
fn verify(period: u64, message: &[u8]) -> Result<()>

// ✅ CORRECT - Clear intent with newtypes
fn verify(period: Period, message: &Message) -> Result<()>

// Newtype definitions
pub struct Period(u64);
pub struct Message([u8]);  // or pub struct Message<'a>(&'a [u8])
```

**Use `#[must_use]` for pure functions:**

```rust
#[must_use]
pub fn add(&self, other: &Self) -> Self {
    // Point addition
}

#[must_use = "computing the hash is expensive, use the result"]
pub fn hash(&self) -> [u8; 32] {
    // Hash computation
}
```

**Derive common traits:**
```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

// For secret keys, use Zeroize
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);
```

### 3. Const Generics

Use const generics for fixed-size arrays:

```rust
// ✅ CORRECT - Type-safe sizes
pub struct Hash<const N: usize>([u8; N]);

pub type Blake2b256 = Hash<32>;
pub type Blake2b512 = Hash<64>;

impl<const N: usize> Hash<N> {
    pub fn from_bytes(bytes: &[u8; N]) -> Self {
        Self(*bytes)
    }
}
```

### 4. Memory Safety

**Always zeroize secret keys:**

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

// ✅ Automatic zeroization on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: [u8; 32],
}

// ✅ Manual zeroization when needed
impl SecretKey {
    pub fn forget(mut self) {
        self.bytes.zeroize();
    }
}
```

**Use constant-time operations for secrets:**

```rust
use subtle::ConstantTimeEq;

// ✅ CORRECT - Constant-time comparison
pub fn verify_tag(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a.ct_eq(b).into()
}

// ❌ WRONG - Timing side-channel
pub fn verify_tag(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a == b  // Early return leaks information!
}
```

### 5. `no_std` Support

**Always support `no_std` with `alloc`:**

```rust
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;  // std re-exports alloc types

// Conditional API
#[cfg(feature = "alloc")]
pub fn to_vec(&self) -> Vec<u8> {
    self.bytes.to_vec()
}
```

**Avoid `std`-only dependencies:**
```toml
# ✅ CORRECT
sha2 = { version = "0.10", default-features = false }

# ❌ WRONG
sha2 = "0.10"  # Pulls in std by default
```

### 6. Naming Conventions

**Follow Cardano/Haskell naming where appropriate:**

| Haskell | Rust | Notes |
|---------|------|-------|
| `genKey` | `gen_key()` | Snake case in Rust |
| `deriveVerKey` | `derive_verification_key()` | Full words preferred |
| `signKES` | `sign_kes()` | Acronyms uppercase: KES, VRF |
| `verifyVRF` | `verify_vrf()` | |
| `SignedKES` | `SignedKes` | Type names use CamelCase |

**Rust-specific conventions:**
- `new()` for constructors
- `from_*()` for conversions (implement `From` trait when appropriate)
- `to_*()` for conversions consuming self
- `as_*()` for cheap reference conversions
- `into_*()` for consuming conversions (implement `Into` trait)

---

## Documentation Standards

### 1. Module-Level Documentation

Every module must have comprehensive documentation:

```rust
//! # Module Name
//!
//! Brief one-line description.
//!
//! ## Overview
//!
//! Detailed explanation of what this module provides, its purpose in Cardano,
//! and how it fits into the larger cryptographic ecosystem.
//!
//! ## Cardano Usage
//!
//! Explain where this is used in Cardano:
//! - Consensus (VRF for leader election, KES for block signing)
//! - Transactions (Ed25519 signatures)
//! - Smart Contracts (BLS, secp256k1 via Plutus)
//!
//! ## Standards Compliance
//!
//! - [IETF VRF Draft-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03)
//! - [CIP-0049](https://cips.cardano.org/cip/CIP-0049) - secp256k1 in Plutus
//! - [cardano-base](https://github.com/IntersectMBO/cardano-base) compatibility
//!
//! ## Security Considerations
//!
//! Document any security-critical aspects:
//! - Constant-time operations
//! - Key zeroization
//! - Side-channel resistance
//!
//! ## Examples
//!
//! ```rust
//! use cardano_crypto::module::Function;
//!
//! let result = Function::new();
//! // Demonstrate usage
//! ```
```

### 2. Type Documentation

**Every public type needs documentation:**

```rust
/// A point on the BLS12-381 G1 curve.
///
/// G1 is the first group in the BLS12-381 pairing-friendly elliptic curve,
/// defined over the base field 𝔽p. Points are elements of the prime-order subgroup.
///
/// # Cardano Usage
///
/// In Plutus smart contracts (CIP-0381), G1 points are used for:
/// - Public keys in the min-pk BLS signature scheme
/// - First argument in pairing operations
/// - Commitment schemes and zero-knowledge proofs
///
/// # Representation
///
/// Points are stored in Jacobian coordinates internally for efficient arithmetic,
/// but are serialized in compressed SEC1 format (48 bytes).
///
/// # Security
///
/// - **Subgroup Check**: All deserialized points are verified to be in the prime-order subgroup
/// - **On-Curve Check**: Points are validated to lie on the BLS12-381 curve
/// - **Compressed Format**: Uses 48-byte compressed SEC1 encoding (x-coordinate + sign bit)
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::bls::G1Point;
///
/// // Get the generator
/// let g = G1Point::generator();
///
/// // Point addition
/// let g2 = g.add(&g);
///
/// // Serialization
/// let bytes = g.to_compressed();
/// let restored = G1Point::from_compressed(&bytes)?;
/// assert_eq!(g, restored);
/// # Ok::<(), cardano_crypto::common::CryptoError>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct G1Point {
    // ...
}
```

### 3. Function Documentation

**Every public function needs:**

```rust
/// Brief one-line description.
///
/// Longer description explaining what the function does, any important
/// algorithmic details, and how it relates to Cardano/standards.
///
/// # Cardano Compatibility
///
/// This matches `functionName` from `cardano-crypto-class` in cardano-base.
/// The output is byte-for-byte identical to the Haskell implementation.
///
/// # Arguments
///
/// * `key` - Description of the key parameter
/// * `message` - The message to sign/verify/hash
///
/// # Returns
///
/// Returns `Result<Signature>` containing the signature on success, or
/// `CryptoError` if the operation fails (e.g., invalid key, message too long).
///
/// # Errors
///
/// This function returns an error if:
/// - The key length is invalid (`CryptoError::InvalidLength`)
/// - The signature generation fails (`CryptoError::SignatureFailed`)
///
/// # Security
///
/// This function uses constant-time operations to prevent timing side-channels.
/// Keys are automatically zeroized when dropped.
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};
///
/// let seed = [42u8; 32];
/// let signing_key = Ed25519::gen_key(&seed);
/// let signature = Ed25519::sign(&signing_key, b"message");
/// ```
///
/// # Panics
///
/// This function does not panic. (Only include if relevant)
///
/// # See Also
///
/// - [`verify()`] for signature verification
/// - [RFC 8032](https://tools.ietf.org/html/rfc8032) for Ed25519 spec
pub fn sign(key: &SigningKey, message: &[u8]) -> Result<Signature> {
    // Implementation
}
```

### 4. Mathematical Notation

Use KaTeX/LaTeX for mathematical expressions:

```rust
/// Computes the Miller loop pairing: $e(P, Q) → \mathbb{F}_{p^{12}}$
///
/// The Miller loop is the first step of a pairing computation. The result
/// must be passed through final exponentiation to get the actual pairing value.
///
/// # Mathematics
///
/// Given points $P ∈ \mathbb{G}_1$ and $Q ∈ \mathbb{G}_2$, this computes:
///
/// $$f_{r,P}(Q) ∈ \mathbb{F}_{p^{12}}$$
///
/// where $r$ is the curve order.
```

### 5. Safety Documentation

**Document all `unsafe` blocks:**

```rust
/// # Safety
///
/// This function is unsafe because it:
/// - Dereferences a raw pointer without checking for null
/// - Assumes the caller has validated the FFI input
/// - Requires that `ptr` points to at least `len` valid bytes
///
/// # Requirements
///
/// Callers must ensure:
/// 1. `ptr` is non-null and properly aligned
/// 2. `ptr` points to `len` consecutive valid bytes
/// 3. The memory remains valid for the duration of this function
pub unsafe fn from_raw_parts(ptr: *const u8, len: usize) -> &[u8] {
    // SAFETY: Caller guarantees ptr is valid for len bytes
    core::slice::from_raw_parts(ptr, len)
}
```

### 6. Deprecation

When deprecating APIs:

```rust
#[deprecated(
    since = "1.1.0",
    note = "Use `new_function()` instead. This function will be removed in v2.0.0"
)]
pub fn old_function() {
    new_function()  // Forward to new implementation
}
```

---

## Testing Requirements

### 1. Test Organization

```
tests/
├── vrf_golden_tests.rs          # VRF test vectors (IETF + Cardano)
├── kes_golden_tests.rs          # KES test vectors (cardano-base)
├── dsign_compat_tests.rs        # Ed25519 compatibility
├── hash_compat_tests.rs         # Blake2b/SHA compatibility
├── bls12381_conformance_tests.rs # BLS12-381 CIP-0381 tests
├── secp256k1_conformance_tests.rs # secp256k1 CIP-0049 tests
├── cbor_compat_tests.rs         # CBOR encoding compatibility
├── hd_golden_tests.rs           # HD derivation CIP-1852 tests
└── test_vectors/                # External test vector files
    ├── vrf_ver03_standard_10
    ├── kes/README.md
    └── ...
```

### 2. Test Coverage Requirements

**Every public function must have:**

1. **Unit tests** - Test the function in isolation
2. **Golden tests** - Verify against known-good outputs
3. **Edge case tests** - Boundary conditions, empty inputs, maximum sizes
4. **Error tests** - Verify error handling
5. **Property tests** - Test invariants (when applicable)

**Example:**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Unit test - basic functionality
    #[test]
    fn test_sign_verify() {
        let seed = [0u8; 32];
        let sk = Ed25519::gen_key(&seed);
        let vk = Ed25519::derive_verification_key(&sk);
        let sig = Ed25519::sign(&sk, b"message");
        assert!(Ed25519::verify(&vk, b"message", &sig).is_ok());
    }

    /// Golden test - matches known output
    #[test]
    fn test_sign_golden() {
        let seed = hex_decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_sig = hex_decode("...");
        let sk = Ed25519::gen_key(&seed);
        let sig = Ed25519::sign(&sk, b"test");
        assert_eq!(&sig[..], &expected_sig[..]);
    }

    /// Edge case test
    #[test]
    fn test_sign_empty_message() {
        let seed = [0u8; 32];
        let sk = Ed25519::gen_key(&seed);
        let sig = Ed25519::sign(&sk, b"");
        // Should succeed with empty message
        assert_eq!(sig.len(), Ed25519::SIGNATURE_SIZE);
    }

    /// Error test
    #[test]
    fn test_verify_invalid_signature() {
        let seed = [0u8; 32];
        let sk = Ed25519::gen_key(&seed);
        let vk = Ed25519::derive_verification_key(&sk);
        let mut sig = Ed25519::sign(&sk, b"message");
        sig[0] ^= 0xFF;  // Corrupt signature
        assert!(Ed25519::verify(&vk, b"message", &sig).is_err());
    }

    /// Property test - signature roundtrip
    #[test]
    fn test_property_sign_verify_roundtrip() {
        for i in 0..100 {
            let seed = [i as u8; 32];
            let sk = Ed25519::gen_key(&seed);
            let vk = Ed25519::derive_verification_key(&sk);
            let message = format!("message_{}", i);
            let sig = Ed25519::sign(&sk, message.as_bytes());
            assert!(Ed25519::verify(&vk, message.as_bytes(), &sig).is_ok());
        }
    }
}
```

### 3. Test Vector Sources

**MANDATORY:** Document the source of all test vectors:

```rust
/// IETF Test Vector #10: Empty alpha (message)
/// Source: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03
/// Section: A.1 ECVRF-ED25519-SHA512-Elligator2 Test Vectors
#[test]
fn test_vrf_draft03_ietf_vector_10() {
    // Test implementation
}

/// Cardano-base compatibility test
/// Source: cardano-crypto-praos/tests/Test/Crypto/VRF.hs
/// Verifies byte-for-byte compatibility with Haskell implementation
#[test]
fn test_vrf_cardano_compat() {
    // Test implementation
}
```

### 4. Continuous Integration

Tests run on every commit via GitHub Actions:

```yaml
# .github/workflows/ci.yml
- name: Test all features
  run: cargo test --all-features

- name: Test no_std
  run: cargo test --no-default-features --features alloc,vrf

- name: Test minimal features
  run: cargo test --no-default-features --features hash
```

---

## Security Guidelines

### 1. Secret Key Management

**ALWAYS:**
- Use `Zeroize` and `ZeroizeOnDrop` for secret keys
- Never log or print secret keys
- Clear secrets before returning errors
- Use constant-time comparison for secrets

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: [u8; 32],
}

impl SecretKey {
    /// Never implement Display or Debug for secret keys!
    /// Use custom Debug that redacts the secret.
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretKey([REDACTED])")
    }
}
```

### 2. Input Validation

**Validate all inputs before processing:**

```rust
pub fn sign(key: &SigningKey, message: &[u8]) -> Result<Signature> {
    // Validate key
    if key.len() != SIGNING_KEY_SIZE {
        return Err(CryptoError::InvalidLength {
            expected: SIGNING_KEY_SIZE,
            actual: key.len(),
        });
    }

    // Validate message (if there are constraints)
    if message.len() > MAX_MESSAGE_SIZE {
        return Err(CryptoError::MessageTooLong);
    }

    // Proceed with signing
    // ...
}
```

### 3. Side-Channel Resistance

**Use constant-time operations for:**
- Secret comparisons
- Key derivation
- Signature verification (where applicable)

```rust
use subtle::{ConstantTimeEq, Choice};

pub fn verify_mac(tag: &[u8; 16], computed: &[u8; 16]) -> bool {
    // ✅ Constant-time comparison
    bool::from(tag.ct_eq(computed))
}

pub fn verify_mac_wrong(tag: &[u8; 16], computed: &[u8; 16]) -> bool {
    // ❌ Timing attack: early return reveals information!
    tag == computed
}
```

### 4. Integer Overflow

**Use checked arithmetic for security-critical code:**

```rust
// ✅ CORRECT
pub fn compute_period(slot: u64) -> Result<Period> {
    let period = slot.checked_div(SLOTS_PER_PERIOD)
        .ok_or(CryptoError::IntegerOverflow)?;
    Ok(Period(period))
}

// ❌ WRONG - Can overflow
pub fn compute_period(slot: u64) -> Period {
    Period(slot / SLOTS_PER_PERIOD)  // Panic on overflow in debug!
}
```

### 5. Randomness

**Never use predictable randomness for cryptographic operations:**

```rust
// ✅ CORRECT - Use provided seed or CSPRNG
pub fn gen_key(seed: &[u8; 32]) -> SecretKey {
    SecretKey::from_seed(seed)
}

// ❌ WRONG - Never use std::rand for crypto!
pub fn gen_key_wrong() -> SecretKey {
    use std::rand::random;
    SecretKey::from_seed(&random())  // Predictable!
}
```

### 6. Panic Safety

**Never panic in cryptographic operations:**

```rust
// ✅ CORRECT
pub fn decode(bytes: &[u8]) -> Result<Point> {
    if bytes.len() != POINT_SIZE {
        return Err(CryptoError::InvalidLength {
            expected: POINT_SIZE,
            actual: bytes.len(),
        });
    }
    // Safe to index now
    Ok(Point::from_bytes(bytes.try_into().unwrap()))
}

// ❌ WRONG - Can panic
pub fn decode_wrong(bytes: &[u8]) -> Point {
    Point::from_bytes(bytes[0..POINT_SIZE].try_into().unwrap())
}
```

---

## Feature Implementation Guidelines

### Adding a New Cryptographic Primitive

**Checklist:**

1. ✅ Research the standard (IETF RFC, CIP, academic paper)
2. ✅ Find the IntersectMBO/cardano-base equivalent (if applicable)
3. ✅ Create module in appropriate directory
4. ✅ Define trait interface (if needed)
5. ✅ Implement with comprehensive documentation
6. ✅ Add unit tests
7. ✅ Add golden tests with official test vectors
8. ✅ Add example in `examples/` directory
9. ✅ Update README.md
10. ✅ Update lib.rs with re-exports
11. ✅ Add feature flag if optional
12. ✅ Update CHANGELOG.md

**Example: Adding a new hash function**

```rust
// 1. Create src/hash/sha3.rs
//! # SHA-3 Hash Functions
//!
//! Implementation of SHA-3 (Keccak) hash functions as specified in FIPS 202.
//!
//! ## Standards
//!
//! - [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

use crate::common::error::Result;
use crate::common::hash::HashAlgorithm;

/// SHA3-256 hash function
#[derive(Clone)]
pub struct Sha3_256;

impl HashAlgorithm for Sha3_256 {
    const ALGORITHM_NAME: &'static str = "SHA3-256";
    const HASH_SIZE: usize = 32;

    fn hash(data: &[u8]) -> [u8; Self::HASH_SIZE] {
        use sha3::{Digest, Sha3_256 as Sha3_256_impl};
        let mut hasher = Sha3_256_impl::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

// 2. Add tests
#[cfg(test)]
mod tests {
    use super::*;

    /// NIST test vector for SHA3-256
    #[test]
    fn test_sha3_256_empty() {
        let hash = Sha3_256::hash(b"");
        let expected = hex::decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }
}

// 3. Update src/hash/mod.rs
pub mod sha3;
pub use sha3::Sha3_256;

// 4. Update src/lib.rs
#[cfg(feature = "hash")]
pub use hash::Sha3_256;

// 5. Add example examples/sha3_example.rs
// 6. Update README.md
// 7. Update CHANGELOG.md
```

### Adding CIP Support

When implementing a CIP:

1. **Read the CIP thoroughly**: https://cips.cardano.org/
2. **Check for reference implementations**: Often in cardano-ledger or cardano-node
3. **Find test vectors**: In the CIP or reference implementation
4. **Create a feature flag**: e.g., `cip-0050`
5. **Document extensively**: Link to CIP, explain Plutus integration

```rust
//! # CIP-0050: Shelley Bulk Serialization Format
//!
//! This module implements the bulk serialization format specified in
//! [CIP-0050](https://cips.cardano.org/cip/CIP-0050).
//!
//! ## Purpose
//!
//! Enables efficient serialization of multiple Cardano primitives in a
//! single CBOR structure, reducing overhead in chain sync protocols.
```

---

## Common Patterns

### 1. Trait-Based Algorithm Design

**Pattern:** Use traits to abstract over algorithm implementations

```rust
/// Generic digital signature trait
pub trait DsignAlgorithm: Clone + Send + Sync + 'static {
    type SigningKey;
    type VerificationKey;
    type Signature;

    const ALGORITHM_NAME: &'static str;
    const SIGNING_KEY_SIZE: usize;
    const VERIFICATION_KEY_SIZE: usize;
    const SIGNATURE_SIZE: usize;

    fn derive_verification_key(signing_key: &Self::SigningKey) -> Self::VerificationKey;
    fn sign(signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature;
    fn verify(vk: &Self::VerificationKey, message: &[u8], sig: &Self::Signature) -> Result<()>;
}

// Implement for specific algorithms
impl DsignAlgorithm for Ed25519 {
    type SigningKey = Ed25519SigningKey;
    type VerificationKey = Ed25519VerificationKey;
    type Signature = Ed25519Signature;
    // ...
}
```

### 2. Builder Pattern for Complex Types

```rust
/// Builder for BLS signature aggregation
pub struct BlsSignatureAggregator {
    signatures: Vec<BlsSignature>,
    public_keys: Vec<BlsPublicKey>,
}

impl BlsSignatureAggregator {
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
            public_keys: Vec::new(),
        }
    }

    pub fn add_signature(&mut self, sig: BlsSignature, pk: BlsPublicKey) -> &mut Self {
        self.signatures.push(sig);
        self.public_keys.push(pk);
        self
    }

    pub fn verify_aggregate(&self, message: &[u8]) -> Result<()> {
        // Verify all signatures at once
    }
}
```

### 3. Serialization Pattern

```rust
/// Standard serialization pattern for cryptographic types
impl G1Point {
    /// Serialize to compressed format (48 bytes)
    #[must_use]
    pub fn to_compressed(&self) -> [u8; G1_COMPRESSED_SIZE] {
        // Implementation
    }

    /// Deserialize from compressed format
    pub fn from_compressed(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != G1_COMPRESSED_SIZE {
            return Err(CryptoError::InvalidLength {
                expected: G1_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        // Parse and validate
    }

    /// Serialize to uncompressed format (96 bytes)
    #[must_use]
    pub fn to_uncompressed(&self) -> [u8; G1_UNCOMPRESSED_SIZE] {
        // Implementation
    }

    /// Deserialize from uncompressed format
    pub fn from_uncompressed(bytes: &[u8]) -> Result<Self> {
        // Implementation
    }
}
```

### 4. Zero-Copy Parsing

```rust
/// Parse without allocation
pub fn parse_signature(bytes: &[u8]) -> Result<&Signature> {
    if bytes.len() < SIGNATURE_SIZE {
        return Err(CryptoError::InvalidLength {
            expected: SIGNATURE_SIZE,
            actual: bytes.len(),
        });
    }

    // SAFETY: We checked the length above
    let sig_bytes = &bytes[0..SIGNATURE_SIZE];
    
    // Validate signature (important!)
    validate_signature(sig_bytes)?;

    // Cast to Signature reference
    // This is safe because Signature is repr(transparent) over [u8; N]
    Ok(unsafe { &*(sig_bytes.as_ptr() as *const Signature) })
}
```

### 5. Error Context

```rust
/// Provide context in error messages
pub fn verify_kes(
    vk: &VerificationKey,
    period: Period,
    message: &[u8],
    signature: &Signature,
) -> Result<()> {
    // Check period validity
    if period >= total_periods() {
        return Err(CryptoError::Kes(KesError::PeriodOutOfRange {
            period,
            max_period: total_periods() - 1,
        }));
    }

    // Perform verification
    if !internal_verify(vk, period, message, signature) {
        return Err(CryptoError::Kes(KesError::VerificationFailed));
    }

    Ok(())
}
```

---

## Do's and Don'ts

### ✅ DO

1. **DO** verify all outputs against cardano-base test vectors
2. **DO** use `Result<T>` for fallible operations
3. **DO** use `#[must_use]` on pure functions
4. **DO** zeroize secret keys with `Zeroize` trait
5. **DO** use constant-time operations for secrets
6. **DO** validate all inputs before processing
7. **DO** write comprehensive documentation
8. **DO** include examples in documentation
9. **DO** add test vectors from official sources
10. **DO** support `no_std` with `alloc`
11. **DO** use checked arithmetic for security-critical code
12. **DO** link to relevant standards (RFCs, CIPs)
13. **DO** use descriptive error types
14. **DO** mark features with `#[cfg(feature = "...")]`
15. **DO** implement `From`/`Into` for natural conversions
16. **DO** use newtypes for type safety
17. **DO** follow Rust naming conventions (snake_case for functions)
18. **DO** derive `Clone`, `Debug`, `PartialEq` where appropriate
19. **DO** add `Send` + `Sync` bounds where thread-safe
20. **DO** use const generics for fixed-size arrays

### ❌ DON'T

1. **DON'T** use `.unwrap()` or `.expect()` in library code
2. **DON'T** panic in cryptographic operations
3. **DON'T** trust existing documentation without verification
4. **DON'T** implement `Display`/`Debug` for secret keys (redact them)
5. **DON'T** use `==` for constant-time comparisons of secrets
6. **DON'T** use `std::rand` for cryptographic randomness
7. **DON'T** log or print secret keys
8. **DON'T** ignore integer overflow possibilities
9. **DON'T** assume inputs are valid (always validate)
10. **DON'T** use variable-time operations on secrets
11. **DON'T** pull in `std` dependencies by default
12. **DON'T** implement custom crypto (use audited libraries)
13. **DON'T** expose internal types in public API
14. **DON'T** break backward compatibility without major version bump
15. **DON'T** add dependencies without justification
16. **DON'T** copy-paste code (use helper functions)
17. **DON'T** use abbreviations in function names (be explicit)
18. **DON'T** add `unsafe` without thorough documentation
19. **DON'T** make breaking changes in patch releases
20. **DON'T** skip writing tests for new code

---

## Quick Reference

### Common Result Types

```rust
use cardano_crypto::common::Result;  // Result<T> = Result<T, CryptoError>

// ✅ Correct
pub fn my_function() -> Result<Output> { ... }

// ❌ Wrong
pub fn my_function() -> Option<Output> { ... }  // Loses error information
```

### Feature Flag Template

```rust
#[cfg(feature = "my_feature")]
#[cfg_attr(docsrs, doc(cfg(feature = "my_feature")))]
pub mod my_module {
    //! Module documentation
}
```

### Test Template

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        // Arrange
        let input = create_input();

        // Act
        let result = my_function(input);

        // Assert
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output, expected_output());
    }

    #[test]
    fn test_error_case() {
        let invalid_input = create_invalid_input();
        let result = my_function(invalid_input);
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::InvalidInput => {}, // Expected
            _ => panic!("Wrong error type"),
        }
    }
}
```

### Documentation Template

```rust
/// Brief one-line description.
///
/// Longer description with context.
///
/// # Cardano Usage
///
/// Explain where this is used in Cardano.
///
/// # Arguments
///
/// * `param1` - Description
///
/// # Returns
///
/// Description of return value.
///
/// # Errors
///
/// This function returns an error if:
/// - Condition 1
/// - Condition 2
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::module::Function;
///
/// let result = Function::new();
/// ```
pub fn my_function(param1: Type) -> Result<Output> {
    // Implementation
}
```

---

## Version History

- **v1.1.0** (2026-01-24): Added HD wallet derivation (CIP-1852), address construction, comprehensive copilot instructions
- **v1.0.0** (2025-12-15): Initial release with VRF, KES, DSIGN, BLS, secp256k1, full Cardano compatibility

---

## Additional Resources

### Official Cardano Resources

- **IntersectMBO GitHub**: https://github.com/IntersectMBO
  - `cardano-base` - Core cryptographic types
  - `cardano-node` - Node implementation
  - `cardano-ledger` - Ledger rules and serialization
  - `cardano-addresses` - Address derivation and encoding
- **CIPs**: https://cips.cardano.org/
- **Cardano Documentation**: https://docs.cardano.org/

### Standards

- **IETF RFCs**: https://datatracker.ietf.org/
  - RFC 8032 (Ed25519)
  - RFC 7693 (Blake2b)
  - VRF drafts (draft-irtf-cfrg-vrf)
- **NIST**: https://csrc.nist.gov/publications
  - FIPS 202 (SHA-3)
  - SP 800-185 (cSHAKE)

### Rust Resources

- **Rust Cryptography**: https://github.com/RustCrypto
- **BLST**: https://github.com/supranational/blst
- **k256**: https://github.com/RustCrypto/elliptic-curves

### Academic Papers

- **KES**: "Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures" (Malkin, Micciancio, Miner, 2002)
- **VRF**: "Verifiable Random Functions" (Micali, Rabin, Vadhan, 1999)
- **BLS**: "Short Signatures from the Weil Pairing" (Boneh, Lynn, Shacham, 2001)

---

**Last Updated:** 2026-01-24  
**Maintainer:** FractionEstate Team  
**License:** MIT OR Apache-2.0
