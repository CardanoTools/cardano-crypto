# CLAUDE.md - AI Assistant Guide for cardano-crypto

> This document provides essential context for AI assistants working with this repository.

## Project Overview

**cardano-crypto** is a pure Rust implementation of Cardano cryptographic primitives with 100% binary compatibility with IntersectMBO/cardano-node. This is production-grade cryptographic code used in the Cardano blockchain.

| Attribute | Value |
|-----------|-------|
| Language | Rust 2021 Edition |
| MSRV | 1.81 |
| License | MIT OR Apache-2.0 |
| no_std | Supported with `alloc` |

## Quick Reference Commands

```bash
# Build
cargo build --all-features          # Development build
cargo build --release --all-features # Production build

# Test
cargo test --all-features           # All tests
cargo test --features vrf           # VRF module only
just test                           # Using just runner

# Lint & Format
cargo fmt --all                     # Format code
cargo clippy --all-targets --all-features -- -D warnings

# Full CI check
just check                          # Format + clippy + tests + docs
just quick-check                    # Format + clippy only

# Coverage
just test-coverage                  # Requires cargo-llvm-cov

# Documentation
cargo doc --all-features --no-deps --open

# Security
cargo audit                         # Dependency vulnerabilities
cargo deny check                    # License & security checks
```

## Repository Structure

```
cardano-crypto/
├── src/
│   ├── lib.rs              # Public API, feature flags, re-exports
│   ├── common/             # Shared utilities (error.rs, traits.rs, security.rs)
│   ├── hash/               # Blake2b-224/256/512, SHA-256/512
│   ├── dsign/              # Ed25519, secp256k1 (ECDSA + Schnorr)
│   ├── vrf/                # VRF Draft-03, Draft-13 + Cardano compat
│   ├── kes/                # KES Single, Sum, Compact variants
│   ├── bls/                # BLS12-381 for Plutus (CIP-0381)
│   ├── seed/               # Deterministic key derivation
│   ├── key/                # Key management, Bech32, TextEnvelope
│   ├── hd/                 # HD wallet derivation (CIP-1852)
│   └── cbor/               # CBOR serialization
├── tests/                  # Integration tests with golden test vectors
├── examples/               # Usage examples for each feature
├── benches/                # Criterion benchmarks
├── .github/workflows/      # CI/CD pipelines
└── justfile                # Task runner commands
```

## Feature Flags

**Default features:** `std`, `vrf`, `kes`, `dsign`, `hash`, `seed`, `cbor`, `key`, `hd`, `thiserror`

### Feature Dependency Graph

```
std → alloc
vrf → dsign, hash, alloc
kes → dsign, hash, alloc
dsign → hash, alloc
hash → alloc
seed → hash, alloc
cbor → alloc
key → hash
hd → dsign, hash, alloc, seed
bls → alloc (requires blst crate)
secp256k1 → dsign, alloc (requires k256 crate)
plutus → secp256k1 + bls
```

### Common Feature Combinations

```toml
# Standard (all features)
cardano-crypto = "1.1"

# Minimal for embedded
cardano-crypto = { version = "1.1", default-features = false, features = ["alloc", "hash"] }

# VRF only
cardano-crypto = { version = "1.1", default-features = false, features = ["vrf"] }

# Plutus support
cardano-crypto = { version = "1.1", features = ["plutus"] }
```

## Critical Conventions

### 1. Cardano Compatibility (MANDATORY)

All cryptographic outputs MUST match IntersectMBO/cardano-base byte-for-byte:
- VRF proofs use Elligator2 mapping (Cardano-specific libsodium compatibility)
- KES uses Sum composition with specific serialization
- Test against cardano-base golden test vectors

Reference implementation: https://github.com/IntersectMBO/cardano-base

### 2. Error Handling

**NEVER use `.unwrap()` or `.expect()` in library code** (tests are ok).

```rust
// ❌ WRONG
let result = some_function().unwrap();

// ✅ CORRECT
let result = some_function().map_err(|_| CryptoError::InvalidInput)?;
```

Use the crate's `Result<T>` type from `crate::common::error`.

### 3. Memory Safety for Secrets

Always use `zeroize` for secret keys:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: [u8; 32],
}

// Custom Debug that redacts secrets
impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretKey([REDACTED])")
    }
}
```

### 4. Constant-Time Operations

Use `subtle` crate for security-critical comparisons:

```rust
use subtle::ConstantTimeEq;

// ✅ CORRECT - constant-time
pub fn verify_tag(a: &[u8; 16], b: &[u8; 16]) -> bool {
    bool::from(a.ct_eq(b))
}

// ❌ WRONG - timing attack
pub fn verify_tag(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a == b  // Early return leaks info!
}
```

### 5. no_std Support

All modules must support `no_std` with `alloc`:

```rust
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
```

### 6. Documentation Standards

Every public item needs:
- Brief description
- Cardano usage context
- Example code
- Links to standards (RFCs, CIPs)

```rust
/// Brief description.
///
/// # Cardano Usage
///
/// Explain where this is used in Cardano consensus/transactions.
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::module::Type;
/// // example code
/// ```
///
/// # See Also
///
/// - [IETF VRF Draft-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03)
```

### 7. Feature Gating

```rust
#[cfg(feature = "my_feature")]
#[cfg_attr(docsrs, doc(cfg(feature = "my_feature")))]
pub mod my_module {
    //! Module documentation
}
```

## Testing Requirements

### Test Categories

1. **Unit tests** - Same file as implementation
2. **Golden tests** - `tests/` directory, verify against known outputs
3. **Property tests** - Using `proptest` crate
4. **Edge case tests** - Empty inputs, max values, malformed data

### Running Tests

```bash
# All tests
cargo test --all-features

# Specific test file
cargo test --test vrf_golden_tests --all-features

# Specific test function
cargo test vrf_draft03_ietf_vector_10 --all-features

# With output
cargo test --all-features -- --nocapture
```

### Test Vector Sources

- IETF RFCs for VRF, Ed25519, Blake2b
- cardano-base golden tests for KES
- CIP specifications for secp256k1, BLS

## Key Modules Overview

### VRF (`src/vrf/`)
- `draft03.rs` - ECVRF-ED25519-SHA512-Elligator2 (Cardano Praos)
- `draft13.rs` - Newer version with batch verification
- `cardano_compat/` - Cardano-specific libsodium compatibility layer

### KES (`src/kes/`)
- `single/` - SingleKES (1 period)
- `sum/` - SumKES hierarchy (Sum0-Sum7, 2^N periods)
- Sum6Kes (64 periods) is standard for Cardano

### DSIGN (`src/dsign/`)
- `ed25519.rs` - Standard Cardano signatures
- `secp256k1.rs` - ECDSA + Schnorr for Plutus (CIP-0049)

### BLS (`src/bls/`)
- G1/G2 point operations
- Pairing and Miller loop
- Signature verification for Plutus (CIP-0381)

## Common Tasks

### Adding a New Cryptographic Primitive

1. Create module in appropriate directory
2. Define trait implementation (if applicable)
3. Add feature flag in `Cargo.toml`
4. Gate with `#[cfg(feature = "...")]`
5. Add re-exports in `lib.rs`
6. Write unit tests
7. Add golden tests with official test vectors
8. Create example in `examples/`
9. Update README.md feature documentation

### Implementing CIP Support

1. Read CIP at https://cips.cardano.org/
2. Find reference implementation in cardano-ledger/cardano-node
3. Extract test vectors
4. Create feature flag (e.g., `secp256k1` for CIP-0049)
5. Document CIP reference in module docs

### Modifying Existing Code

1. **Read the code first** - Understand existing implementation
2. **Check test coverage** - Run existing tests
3. **Verify Cardano compatibility** - Don't break byte-level output
4. **Run full CI checks** - `just check`
5. **Update documentation** - If API changes

## Standards References

| Primitive | Standard | Reference |
|-----------|----------|-----------|
| VRF Draft-03 | IETF draft-irtf-cfrg-vrf-03 | ECVRF-ED25519-SHA512-Elligator2 |
| VRF Draft-13 | IETF draft-irtf-cfrg-vrf-13 | Batch verification support |
| Ed25519 | RFC 8032 | EdDSA |
| Blake2b | RFC 7693 | Blake2b-224/256/512 |
| secp256k1 | CIP-0049 + BIP-340 | ECDSA + Schnorr |
| BLS12-381 | CIP-0381 | Pairing-friendly curve |
| HD Wallets | CIP-1852 | BIP32-Ed25519 derivation |
| KES | MMM 2002 paper | "Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures" |

## Performance Targets (Cardano Mainnet)

| Operation | Target | Use Case |
|-----------|--------|----------|
| VRF Prove | <1ms | Block production |
| VRF Verify | <500μs | Block validation |
| KES Sign | <2ms | Block signing |
| Ed25519 Sign | <100μs | Transaction signing |
| Blake2b-256 | >100 MB/s | UTXO hashing |

Run benchmarks: `cargo bench --all-features`

## Do's and Don'ts

### ✅ DO

- Verify outputs against cardano-base test vectors
- Use `Result<T>` for fallible operations
- Zeroize secret keys with `Zeroize` trait
- Use constant-time operations for secrets
- Support `no_std` with `alloc`
- Link to standards (RFCs, CIPs)
- Add comprehensive documentation
- Run `just check` before committing

### ❌ DON'T

- Use `.unwrap()` or `.expect()` in library code
- Panic in cryptographic operations
- Use `==` for secret comparisons
- Log or print secret keys
- Implement `Display`/`Debug` that reveals secrets
- Use `std::rand` for crypto randomness
- Pull in `std` dependencies by default
- Break backward compatibility without major version bump

## CI/CD Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push/PR | Tests, clippy, fmt, coverage |
| `security.yml` | Push/Schedule | Audit, deny, CodeQL |
| `docs.yml` | Push to main | Deploy docs to GitHub Pages |
| `publish.yml` | Tag release | Publish to crates.io |
| `nightly.yml` | Daily | Extended tests, MSRV check |

## Useful Files

- `justfile` - Task runner commands
- `.pre-commit-config.yaml` - Pre-commit hooks
- `deny.toml` - Dependency policy
- `cliff.toml` - Changelog generation
- `llms.txt` / `llms-full.txt` - LLM context files

## Getting Help

- **Architecture details**: See `ARCHITECTURE.md`
- **Contributing guide**: See `CONTRIBUTING.md`
- **Security issues**: See `SECURITY.md`
- **API documentation**: https://docs.rs/cardano-crypto
- **Cardano base reference**: https://github.com/IntersectMBO/cardano-base

---

*Last updated: 2026-01-24*
