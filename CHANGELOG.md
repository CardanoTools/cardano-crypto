# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Operational Certificates** - New `OperationalCertificate` type for stake pool block production:
  - Binds cold verification keys to hot KES verification keys
  - Counter-based replay attack prevention
  - KES period validation
  - Full CBOR serialization compatibility with cardano-cli
  - Matches `Cardano.Protocol.TPraos.OCert` from cardano-ledger

- **PraosBatchCompatVRF Type Alias** - Documentation improvement for VRF naming:
  - `PraosBatchCompatVRF = VrfDraft13` - Matches cardano-base naming
  - Clarifies batch verification support in newer protocol versions

- **DSIGNAggregatable Trait** - BLS multi-signature support:
  - New trait for signature aggregation schemes
  - `aggregate_verification_keys()` - Combine multiple public keys
  - `aggregate_signatures()` - Combine multiple signatures into one
  - `generate_possession_proof()` / `verify_possession_proof()` - Rogue key attack prevention
  - Full implementation for BLS12-381
  - `DsignAlgorithm` trait implementation for BLS12-381
  - New example: `bls_multisig.rs` demonstrating multi-party signatures
  - 10+ comprehensive tests including threshold signatures and security checks

- Comprehensive benchmark suite using Criterion.rs
  - VRF benchmarks (Draft-03 and Draft-13)
  - KES benchmarks (Sum2 and Sum6)
  - Hash benchmarks (Blake2b-224/256/512)
  - DSIGN benchmarks (Ed25519, secp256k1)
- Benchmark documentation in `benches/README.md`
- Performance targets based on Cardano mainnet requirements
- IntersectMBO parity research audit complete (see `PARITY_IMPLEMENTATION_PLAN.md`)

### Changed
- Added `#[inline]` attributes to hot-path functions for micro-optimizations
- Updated Cargo.toml with benchmark harness configuration
- Updated error types to include `OCertError` variant

---

## [1.1.0] - 2026-01-24

### Added
- **secp256k1 Support** (CIP-0049) - New `secp256k1` feature for Plutus interoperability:
  - `Secp256k1Ecdsa` - ECDSA signatures on secp256k1 curve for Bitcoin/Plutus compatibility
  - `Secp256k1Schnorr` - BIP-340 Schnorr signatures for Plutus builtins
  - Prehashed signing/verification for both algorithms
  - Full key and signature serialization support

- **BLS12-381 Support** (CIP-0381) - New `bls` feature for Plutus V2+ primitives:
  - `G1Point` / `G2Point` - Curve point types with full arithmetic operations
  - `Bls12381` - Operations matching Plutus builtins:
    - `bls12_381_G1_add`, `bls12_381_G1_neg`, `bls12_381_G1_scalarMul`, `bls12_381_G1_compress/uncompress`
    - `bls12_381_G2_add`, `bls12_381_G2_neg`, `bls12_381_G2_scalarMul`, `bls12_381_G2_compress/uncompress`
    - `bls12_381_G1_hashToGroup`, `bls12_381_G2_hashToGroup`
    - `bls12_381_millerLoop`, `bls12_381_finalVerify`
  - `BlsSecretKey`, `BlsPublicKey`, `BlsSignature` - Full BLS signature support
  - `bls_verify()` / `bls_verify_with_dst()` - Signature verification

- **Plutus Feature** - New `plutus` convenience feature enabling both `secp256k1` and `bls`

- **New Example**: `plutus_crypto.rs` - Demonstrates all Plutus cryptographic primitives

- **New Tests**: `tests/plutus_crypto_tests.rs` - Comprehensive tests for CIP-0049 and CIP-0381 primitives

- **Extensive Test Suite** - New comprehensive test files for Cardano compatibility:
  - `tests/kes_interop_tests.rs` - KES Haskell interoperability tests with Cardano's test seed
  - `tests/cbor_compat_tests.rs` - CBOR encoding tests matching Cardano.Binary format
  - `tests/hash_compat_tests.rs` - Hash algorithm tests (Blake2b-224/256/512, SHA-256/512)
  - `tests/dsign_compat_tests.rs` - Ed25519 tests with RFC 8032 vectors
- **KES Test Vector Documentation** - `tests/test_vectors/kes/README.md` documenting Haskell test vector generation

### Changed
- Updated crate description to include BLS12-381 and secp256k1
- `CryptoError::InvalidKeyLength` now includes `expected` and `got` fields for better error messages
- Added `InvalidSignatureLength`, `SignatureVerificationFailed`, `SigningFailed`, `InvalidPrivateKey` error variants

## [1.0.8] - 2025-12-13

### Fixed
- **MSRV compatibility**: Pinned `base64ct` to `<1.8.0` to avoid edition 2024 requirement, ensuring compatibility with Rust 1.81

## [1.0.7] - 2025-12-13

### Fixed
- **docs.rs compatibility**: Changed `rust-version` from 1.91 to 1.81 to allow docs.rs to build documentation
- **CI workflow**: Updated MSRV in CI matrix from 1.91.0 to 1.81.0 to match Cargo.toml
- **README badge**: Updated Rust version badge from 1.91+ to 1.81+
- **GitHub Pages deployment**: Fixed docs workflow to only deploy from main branch (not tags) to avoid environment protection rule conflicts

## [1.0.6] - 2025-12-09

### Added
- **Key Module** (`key::*`) - Cardano-api compatible key types and serialization
  - `key::bech32` - Complete Bech32 HRP prefix constants for all Cardano key types
  - `key::text_envelope` - TextEnvelope type description constants
  - `key::hash` - Blake2b-224 key hash types (`KeyHash`, `PoolKeyHash`, `VrfKeyHash`, etc.)
  - `key::kes_period` - KES period handling with `kes_period_info()`, `is_valid_period()`, `kes_expiry_slot()`
  - `key::encoding` - Full Bech32 encode/decode functions (requires `bech32-encoding` feature)

- **Bech32 Encoding** (optional `bech32-encoding` feature)
  - `encode_to_bech32()` / `decode_from_bech32()` - Generic Bech32 functions
  - Type-specific functions for all key types: VRF, KES, Payment, Stake, Pool, Genesis, DRep, Committee
  - Hash encoding: `encode_pool_id()`, `encode_key_hash()`, `encode_stake_address_hash()`
  - Utility functions: `is_valid_bech32()`, `get_hrp()`

- **New Example**: `seed_derivation.rs` - Comprehensive seed derivation and HD key generation

### Changed
- Added `key` feature flag (default enabled)
- Improved feature flag organization for better modularity

### Fixed
- Fixed rustdoc broken link warnings in Elligator2 documentation
- Fixed clippy `wrong_self_convention` warning in `fe25519.rs`

### Tests
- 209 unit tests passing
- 19 KES golden tests passing
- 17 VRF golden tests passing
- 182 documentation tests passing
- Zero compiler warnings
- Zero clippy warnings

## [1.0.5] - 2025-12-08

### Added
- **CBOR Size Expression Functions** - Complete set of size calculation functions
  - `encoded_size_bytes()` - Generic CBOR size calculation
  - DSIGN: `encoded_verification_key_dsign_size()`, `encoded_signing_key_dsign_size()`, `encoded_signature_dsign_size()`
  - VRF: `encoded_verification_key_vrf_size()`, `encoded_signing_key_vrf_size()`, `encoded_proof_vrf_draft03_size()`, `encoded_proof_vrf_draft13_size()`, `encoded_output_vrf_size()`
  - KES: `encoded_verification_key_kes_size()`, `encoded_signing_key_sum6kes_size()`, `encoded_signature_sum6kes_size()`
  - Hash: `encoded_hash_blake2b224_size()`, `encoded_hash_blake2b256_size()`

- **Wrapper Types with CBOR Traits**
  - `ToCbor` and `FromCbor` traits for type-safe serialization
  - `VrfVerificationKey`, `VrfSigningKey`, `VrfProof`, `OutputVrf` wrapper types
  - `KesVerificationKey`, `KesSigningKey`, `KesSignature` wrapper types
  - `DsignVerificationKey`, `DsignSigningKey`, `DsignSignature` wrapper types

## [0.1.0] - 2025-11-10

### Added
- **Complete VRF Implementation**
  - IETF VRF Draft-03 (ECVRF-ED25519-SHA512-Elligator2)
  - IETF VRF Draft-13 (ECVRF-ED25519-SHA512-TAI)
  - Cardano-compatible hash-to-curve using Elligator2
  - Full prove/verify/proof_to_hash APIs
  - XMD expansion (expand_message_xmd) for Draft-13
  - 8 VRF golden tests passing

- **Complete KES Implementation**
  - SingleKES (1 period - base case)
  - Sum2KES (4 periods - binary tree composition)
  - Sum6KES (64 periods - Cardano standard for stake pools)
  - CompactSingleKES, CompactSum2KES, CompactSum6KES (optimized signatures)
  - Trait-based KesAlgorithm API with proper error handling
  - Forward-secure key evolution with move semantics
  - Type-safe period management
  - 9 KES golden tests passing

- **Digital Signatures (DSIGN)**
  - Ed25519 signature scheme with full trait implementation
  - Deterministic key generation from seed
  - Full sign/verify/keygen API

- **Hash Functions**
  - Blake2b (224, 256, 512-bit variants)
  - SHA-256, SHA-512, SHA-256d
  - RIPEMD-160
  - Keccak-256

- **CBOR Serialization**
  - Full CBOR encoding/decoding for all cryptographic types
  - Cardano-compatible binary format

- **no_std Support**
  - Works in embedded and WebAssembly environments
  - Optional `alloc` feature for heap allocation
  - No standard library required

- **Comprehensive Testing**
  - 95 library unit tests
  - 9 KES golden tests
  - 8 VRF golden tests
  - 4 documentation tests
  - 100% test pass rate (112/112 tests)
  - Zero compiler warnings
  - Zero clippy warnings

- **Documentation & Examples**
  - Complete API documentation with examples
  - `kes_lifecycle`: Complete KES demonstration
  - `dsign_sign_verify`: Digital signature examples
  - `vrf_basic`: VRF usage patterns

### Features
- `default`: Enables std, thiserror, vrf, kes, dsign, hash
- `std`: Standard library support
- `alloc`: Heap allocation support (for no_std)
- `vrf`: Verifiable Random Functions
- `kes`: Key Evolving Signatures
- `dsign`: Digital Signatures
- `hash`: Hash functions
- `cbor`: CBOR serialization support
- `serde`: Serde serialization support
- Component-specific features for selective compilation

### Security
- Zero unsafe code - Pure safe Rust implementation
- Forward-secure key evolution for KES
- Constant-time operations where applicable
- Comprehensive test coverage
- Security audit ready

### Compatibility
- Rust 1.81.0 or later (MSRV)
- 100% compatible with cardano-node cryptographic primitives
- Binary-compatible with Haskell cardano-crypto-class
- Sum6KES matches Cardano stake pool requirements (64 periods, ~90 days)
- VRF algorithms match IntersectMBO/cardano-base

[Unreleased]: https://github.com/FractionEstate/cardano-crypto/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/FractionEstate/cardano-crypto/releases/tag/v1.1.0
[1.0.8]: https://github.com/FractionEstate/cardano-crypto/releases/tag/v1.0.8
[1.0.7]: https://github.com/FractionEstate/cardano-crypto/releases/tag/v1.0.7
[1.0.6]: https://github.com/FractionEstate/cardano-crypto/releases/tag/v1.0.6
[1.0.5]: https://github.com/FractionEstate/cardano-crypto/releases/tag/v1.0.5
[0.1.0]: https://github.com/FractionEstate/cardano-crypto/releases/tag/v0.1.0

