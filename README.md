# Cardano Crypto - Pure Rust Implementation

<div align="center">

[![Crates.io](https://img.shields.io/crates/v/cardano-crypto.svg)](https://crates.io/crates/cardano-crypto)
[![Documentation](https://docs.rs/cardano-crypto/badge.svg)](https://docs.rs/cardano-crypto)
[![Docs](https://img.shields.io/badge/docs-github.io-blue)](https://fractionestate.github.io/cardano-crypto/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.81%2B-orange.svg)](https://www.rust-lang.org)

[![CI](https://github.com/FractionEstate/cardano-crypto/workflows/CI/badge.svg)](https://github.com/FractionEstate/cardano-crypto/actions/workflows/ci.yml)
[![Security](https://github.com/FractionEstate/cardano-crypto/workflows/Security/badge.svg)](https://github.com/FractionEstate/cardano-crypto/actions/workflows/security.yml)
[![Codecov](https://codecov.io/gh/FractionEstate/cardano-crypto/branch/main/graph/badge.svg)](https://codecov.io/gh/FractionEstate/cardano-crypto)
[![Dependencies](https://deps.rs/repo/github/FractionEstate/cardano-crypto/status.svg)](https://deps.rs/repo/github/FractionEstate/cardano-crypto)

[![Downloads](https://img.shields.io/crates/d/cardano-crypto.svg)](https://crates.io/crates/cardano-crypto)
[![GitHub Stars](https://img.shields.io/github/stars/FractionEstate/cardano-crypto?style=social)](https://github.com/FractionEstate/cardano-crypto)

</div>

Pure Rust implementation of Cardano cryptographic primitives, providing a unified interface for **VRF** (Verifiable Random Functions), **KES** (Key Evolving Signatures), **DSIGN** (Digital Signatures), **Hash** algorithms, and **Plutus-compatible** cryptographic primitives.

This crate consolidates all Cardano cryptographic components into a single, cohesive package with minimal external dependencies. All implementations ensure full control, auditability, and binary compatibility with Cardano consensus requirements.

## Features

### Core Cardano Primitives
- **VRF (Verifiable Random Functions)**: IETF VRF Draft-03 and Draft-13 with Cardano libsodium compatibility
- **KES (Key Evolving Signatures)**: Single, Sum, and Compact variants for forward-secure signatures
- **DSIGN (Digital Signatures)**: Ed25519 signatures with deterministic key generation
- **Hash Algorithms**: Blake2b (224/256/512), SHA-2 family, and other Cardano hash functions
- **Seed Management**: Deterministic entropy generation and key derivation
- **CBOR Support**: Optional serialization for Cardano binary formats

### Plutus Smart Contract Support (NEW)
- **secp256k1 ECDSA** (CIP-0049): Bitcoin-compatible ECDSA signatures
- **secp256k1 Schnorr** (CIP-0049): BIP-340 Schnorr signatures for Plutus
- **BLS12-381** (CIP-0381): Full pairing-friendly curve operations for Plutus V2+
  - G1/G2 point arithmetic (add, neg, scalar multiply)
  - Hash-to-curve operations
  - Miller loop and final exponentiation
  - BLS signature support

### Additional Highlights
- ✅ **Binary Compatible** - Matches Haskell `cardano-crypto-class` implementation
- ✅ **No Standard Library Required** - `no_std` compatible with `alloc`
- ✅ **Comprehensive Tests** - Full test vector coverage from Cardano
- ✅ **Well Documented** - Complete API documentation and examples

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
cardano-crypto = "1.0"
```

### Feature Flags

```toml
# Default features (VRF, KES, DSIGN, Hash, Seed, CBOR, Key)
cardano-crypto = "1.0"

# Add Plutus support (secp256k1 + BLS12-381)
cardano-crypto = { version = "1.0", features = ["plutus"] }

# Only specific features
cardano-crypto = { version = "1.0", default-features = false, features = ["vrf", "kes"] }

# secp256k1 only (ECDSA + Schnorr)
cardano-crypto = { version = "1.0", features = ["secp256k1"] }

# BLS12-381 only
cardano-crypto = { version = "1.0", features = ["bls"] }
```

Available features:
- `std` (default) - Standard library support
- `vrf` - VRF implementations
- `kes` - KES implementations
- `dsign` - Digital signatures (Ed25519)
- `hash` - Hash functions
- `seed` - Seed derivation
- `cbor` - CBOR serialization
- `key` - Key types and Bech32 encoding
- `secp256k1` - ECDSA/Schnorr on secp256k1 (CIP-0049)
- `bls` - BLS12-381 primitives (CIP-0381)
- `plutus` - Both secp256k1 and BLS12-381



## Quick Start

### VRF (Verifiable Random Function)

```rust
use cardano_crypto::vrf::{VrfDraft03, VrfKeyPair, VrfProof};

// Generate keypair from seed
let seed = [0u8; 32];
let keypair = VrfKeyPair::from_seed(&seed);

// Create proof
let message = b"epoch-nonce";
let proof = VrfProof::prove(&keypair, message)?;

// Verify proof
let output = proof.verify(&keypair.public_key(), message)?;

// Use VRF output for randomness
println!("VRF output: {:?}", output.as_bytes());
```

### KES (Key Evolving Signatures)

```rust
use cardano_crypto::kes::{Sum6Kes, KesAlgorithm};

// Generate KES key for 2^6 = 64 periods
let seed = [0u8; 32];
let mut signing_key = Sum6Kes::gen_key_from_seed(&seed)?;
let verification_key = Sum6Kes::derive_verification_key(&signing_key)?;

// Sign at period 0
let period = 0;
let message = b"block-header";
let signature = Sum6Kes::sign(&signing_key, period, message)?;

// Verify signature
Sum6Kes::verify(&verification_key, period, message, &signature)?;

// Evolve key to next period
signing_key = Sum6Kes::update_key(signing_key, period + 1)?;
```

### DSIGN (Digital Signatures)

```rust
use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};

// Generate keypair
let seed = [0u8; 32];
let signing_key = Ed25519::gen_key(&seed);
let verification_key = Ed25519::derive_verification_key(&signing_key);

// Sign message
let message = b"transaction-data";
let signature = Ed25519::sign(&signing_key, message);

// Verify signature
Ed25519::verify(&verification_key, message, &signature)?;
```

### Hash Functions

```rust
use cardano_crypto::hash::{Blake2b256, HashAlgorithm};

// Hash data with Blake2b-256
let data = b"block-content";
let hash = Blake2b256::hash(data);
println!("Blake2b-256: {:?}", hash);

// Hash concatenation (for Merkle trees)
let left = Blake2b256::hash(b"left-branch");
let right = Blake2b256::hash(b"right-branch");
let root = Blake2b256::hash_concat(&left, &right);
```

### HD Wallet Derivation (CIP-1852)

```rust
use cardano_crypto::hd::{ExtendedPrivateKey, HARDENED_OFFSET};

// Derive from mnemonic seed
let seed = [/* mnemonic seed */];
let root_key = ExtendedPrivateKey::from_seed(&seed);

// CIP-1852 path: m/1852'/1815'/0'/0/0
let account_key = root_key
    .derive_child(1852 + HARDENED_OFFSET)?  // Purpose
    .derive_child(1815 + HARDENED_OFFSET)?  // Coin type (ADA)
    .derive_child(0 + HARDENED_OFFSET)?;    // Account

let payment_key = account_key
    .derive_child(0)?  // External chain
    .derive_child(0)?; // Address index
```

## Architecture

### Component Independence with Shared Infrastructure

```
cardano-crypto/
├── vrf/           # VRF Draft-03 & Draft-13
├── kes/           # KES hierarchy (Single, Sum, Compact)
├── dsign/         # Ed25519, secp256k1 signatures
├── hash/          # Blake2b, SHA family
├── seed/          # Deterministic key derivation
├── bls/           # BLS12-381 for Plutus
├── hd/            # HD wallet derivation (CIP-1852)
├── key/           # Key management utilities
├── cbor/          # Optional CBOR serialization
└── common/        # Shared traits and utilities
```

### Feature Flag Architecture

Users can minimize binary size by selecting only needed components:

- `vrf` - Enables VRF (automatically includes `dsign` and `hash`)
- `kes` - Enables KES (automatically includes `dsign` and `hash`)
- `dsign` - Enables digital signatures (automatically includes `hash`)
- `hash` - Enables hash functions (minimal, no dependencies)
- `bls` - BLS12-381 for Plutus (CIP-0381)
- `secp256k1` - secp256k1 ECDSA/Schnorr for Plutus (CIP-0049)
- `plutus` - Both secp256k1 and BLS (convenience feature)
- `hd` - HD wallet derivation (CIP-1852)
- `cbor` - Optional CBOR serialization support
- `serde` - Optional serde serialization for key types
- `metrics` - Performance metrics collection
- `logging` - Structured logging for debugging

## Why Unified Package?

This crate consolidates all Cardano cryptographic primitives into one package because:

1. **Shared Dependencies**: All components need Blake2b hashing and Ed25519 signatures
2. **Atomic Versioning**: Guarantees all components work together (no version conflicts)
3. **Zero External Crypto**: Full in-house implementation for auditability
4. **Haskell Parity**: Matches `cardano-crypto-class` package structure
5. **Simpler Dependencies**: One crate instead of managing 6+ separate packages
6. **Better Testing**: Integration tests across all components
7. **Reduced Binary Bloat**: Shared code compiled once

## Binary Compatibility

All implementations maintain byte-level compatibility with:
- Haskell `cardano-crypto-class` library
- Cardano consensus layer requirements
- Official Cardano test vectors

## Security

- **No External Crypto Dependencies**: All cryptographic primitives implemented in-house
- **Constant-Time Operations**: Timing-safe comparisons where applicable
- **Memory Safety**: Zeroization of secret keys
- **Audit-Friendly**: Single codebase for comprehensive security review

### Forward Security (KES)

Once a key evolves past a period, it **cannot** sign for that period:

```rust
let mut sk = Sum2Kes::gen_key_kes_from_seed_bytes(&seed)?;

// Sign for period 0
let sig0 = Sum2Kes::sign_kes(&(), 0, b"msg0", &sk)?;

// Evolve to period 1
sk = Sum2Kes::update_kes(&(), sk, 0)?.unwrap();

// ❌ Cannot sign for period 0 anymore!
// This will return an error
let result = Sum2Kes::sign_kes(&(), 0, b"msg0", &sk);
assert!(result.is_err());
```

### Key Zeroization

Signing keys are automatically zeroized when dropped:

```rust
{
    let sk = Sum2Kes::gen_key_kes_from_seed_bytes(&seed)?;
    // Use sk...
} // sk is zeroized here
```

## no_std Support

This crate supports `no_std` environments with `alloc`:

```toml
[dependencies]
cardano-crypto = { version = "1.1", default-features = false, features = ["alloc", "vrf"] }
```

## Development

### Building

```bash
# Development build (fast compilation, no optimization)
cargo build --all-features

# Production release build (maximum optimization)
cargo build --release --all-features

# Build only VRF component
cargo build --no-default-features --features vrf

# Build with metrics enabled
cargo build --features metrics
```

### Testing

```rust
# Run all tests
cargo test --all-features

# Run specific test
cargo test vrf_golden_tests

# Run examples
cargo run --example vrf_basic
cargo run --example kes_lifecycle
cargo run --example dsign_sign_verify
cargo run --example plutus_crypto
cargo run --example hd_wallet

# Generate documentation
cargo doc --all-features --open
```

## Related Crates

Part of the Cardano Rust ecosystem:

- [`cardano-crypto`](https://crates.io/crates/cardano-crypto) - This crate (unified cryptography)

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development

```bash
# Format code
cargo fmt

# Lint
cargo clippy --all-targets --all-features

# Build docs
cargo doc --all-features --open

# Run all checks
cargo test --all-features && cargo clippy --all-targets --all-features
```

```bash
# Development build (fast compilation, no optimization)
cargo build --all-features

# Production release build (maximum optimization)
cargo build --release --all-features

# Build only VRF component
cargo build --no-default-features --features vrf

# Build with metrics enabled
cargo build --features kes-metrics
```

#### Build Profiles

This crate includes optimized build profiles in `Cargo.toml`:

- **dev** - Fast compilation, no optimization (default for `cargo build`)
  - `opt-level = 0` - No optimization
  - `incremental = true` - Fast rebuilds
  - `codegen-units = 256` - Parallel compilation

- **release** - Maximum optimization (`cargo build --release`)
  - `opt-level = 3` - Maximum optimization
  - `lto = "fat"` - Full Link-Time Optimization
  - `codegen-units = 1` - Best optimization quality
  - `strip = true` - Smaller binaries
  - `panic = 'abort'` - Smaller code size

- **release-with-debug** - Release optimizations + debug symbols (for profiling)
- **bench** - Optimized for benchmarking
- **test** - Balanced optimization for faster test execution

### Testing

```bash
# Run all tests
cargo test --all-features

# Run specific test
cargo test single_kes_basic

# Run with test vectors
cargo test --test vrf_golden_tests
cargo test --test kes_golden_tests

# Run examples
cargo run --example vrf_basic
cargo run --example kes_lifecycle
cargo run --example dsign_sign_verify

# Generate documentation
cargo doc --all-features --open
```

## Cardano-Base Alignment

This crate aims for full compatibility with [IntersectMBO/cardano-base](https://github.com/IntersectMBO/cardano-base). Our alignment status:

### ✅ Complete

| Area | Status | Details |
|------|--------|---------|
| **VRF Implementation** | ✅ | Draft-03 and Draft-13, binary compatible |
| **KES Implementation** | ✅ | Sum6Kes (Cardano standard), all variants |
| **DSIGN Implementation** | ✅ | Ed25519 with deterministic key generation |
| **Hash Functions** | ✅ | Blake2b-224/256/512, SHA family |
| **Property Tests** | ✅ | Comprehensive proptest coverage for VRF/KES |
| **Edge Case Tests** | ✅ | 34+ edge case tests covering all modules |
| **Benchmarks** | ✅ | Full benchmark suite with performance targets |
| **Documentation** | ✅ | SPO examples, wallet examples, Plutus examples |

### Test Coverage

- **VRF Property Tests**: 21 tests including roundtrip, wrong key/message rejection, determinism, corrupted proof detection
- **KES Property Tests**: 19 tests including key evolution, period boundaries, forward security guarantees
- **Edge Case Tests**: 34 tests covering empty inputs, max sizes, boundary conditions, cross-module interactions
- **Golden Tests**: Comprehensive test vectors from cardano-base

See [CARDANO_NODE_ALIGNMENT.md](CARDANO_NODE_ALIGNMENT.md) for detailed alignment documentation.

## Performance

This crate includes comprehensive benchmarks for all cryptographic operations. Performance targets are based on Cardano mainnet requirements:

| Operation | Target | Use Case |
|-----------|--------|----------|
| VRF Prove | <1ms | Block production (slot leader election) |
| VRF Verify | <500μs | Block validation |
| KES Sign | <2ms | Block signing |
| Ed25519 Sign | <100μs | Transaction signing |
| Blake2b-256 | >100 MB/s | UTXO hashing |

Run benchmarks:
```bash
cargo bench --all-features
```

View detailed reports in `target/criterion/report/index.html`.

## For AI Coding Agents

This crate provides comprehensive LLM-friendly documentation following the [llmstxt.org](https://llmstxt.org/) standard:

- **[llms.txt](llms.txt)** - Concise overview with quick start, architecture, and common patterns
- **[llms-full.txt](llms-full.txt)** - Complete reference including:
  - Detailed cryptographic algorithm specifications
  - Security guidelines and best practices
  - Implementation patterns and common pitfalls
  - Advanced usage examples
  - Testing strategies

These files help AI coding assistants understand the crate's design, use it correctly, and avoid common mistakes.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Acknowledgments

This implementation is based on the Haskell `cardano-crypto-class` library and the academic paper:

> "Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures"
> by Tal Malkin, Daniele Micciancio, and Sara Miner
> https://eprint.iacr.org/2001/034

Special thanks to:
- The Cardano Foundation
- IOHK/Input Output
- The Rust Cardano community
