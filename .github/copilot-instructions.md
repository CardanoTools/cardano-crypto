# GitHub Copilot Instructions for cardano-crypto

> **Version:** 1.2.0 | **MSRV:** 1.85 | **Edition:** 2024 | **License:** MIT OR Apache-2.0

Production-grade Rust implementation of Cardano cryptographic primitives with 100% binary compatibility with [IntersectMBO/cardano-base](https://github.com/IntersectMBO/cardano-base). Every output must match the official Haskell implementation byte-for-byte.

For module-specific context, see the `AGENTS.md` files in each subdirectory under `src/`, `tests/`, `examples/`, and `benches/`.

---

## Core Principles

1. **Binary Compatibility** — All outputs match [cardano-base](https://github.com/IntersectMBO/cardano-base) exactly
2. **Security by Design** — Constant-time ops, zeroization, no panics in crypto code
3. **Verify with Test Vectors** — All claims backed by IETF/CIP/cardano-base vectors
4. **no_std First** — `std` is optional; support embedded via `alloc`
5. **Idiomatic Rust** — 2021 edition, `#![deny(missing_docs)]`, comprehensive RustDoc

---

## IntersectMBO Upstream References

Every module maps to a specific upstream Haskell package. **Always verify compatibility against these sources.**

### Primary Repositories

| Repository | URL | What It Contains |
|---|---|---|
| **cardano-base** | https://github.com/IntersectMBO/cardano-base | Core crypto type classes, VRF/KES/DSIGN abstractions |
| **cardano-node** | https://github.com/IntersectMBO/cardano-node | Node runtime, consensus integration |
| **cardano-ledger** | https://github.com/IntersectMBO/cardano-ledger | Ledger rules, CBOR serialization, key types |
| **cardano-addresses** | https://github.com/IntersectMBO/cardano-addresses | Address derivation, Bech32, HD wallets |
| **cardano-crypto** (legacy) | https://github.com/IntersectMBO/cardano-crypto | Legacy Blake2b, Ed25519 wrappers |
| **CIPs** | https://github.com/cardano-foundation/CIPs | Cardano Improvement Proposals |

### Module-to-Upstream Mapping

| Our Module | Upstream Package | Upstream Path | Standard |
|---|---|---|---|
| `vrf/draft03` | `cardano-crypto-praos` | [`cbits/crypto_vrf_ietfdraft03.c`](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-praos/cbits) | [IETF draft-irtf-cfrg-vrf-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03) |
| `vrf/draft13` | `cardano-crypto-praos` | [`cbits/crypto_vrf_ietfdraft13.c`](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-praos/cbits) | [IETF draft-irtf-cfrg-vrf-13](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-13) |
| `vrf/cardano_compat` | `cardano-crypto-praos` | [`cbits/vrf03/`](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-praos/cbits) | Elligator2 libsodium compat |
| `kes/single` | `cardano-crypto-class` | [`src/Cardano/Crypto/KES/Single.hs`](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/KES/Single.hs) | MMM 2002 |
| `kes/sum` | `cardano-crypto-class` | [`src/Cardano/Crypto/KES/Sum.hs`](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/KES/Sum.hs) | MMM 2002 |
| `dsign/ed25519` | `cardano-crypto-class` | [`src/Cardano/Crypto/DSIGN/Ed25519.hs`](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/DSIGN/Ed25519.hs) | [RFC 8032](https://tools.ietf.org/html/rfc8032) |
| `dsign/secp256k1` | `cardano-crypto-class` | [`src/Cardano/Crypto/DSIGN/EcdsaSecp256k1.hs`](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/DSIGN/EcdsaSecp256k1.hs) | [CIP-0049](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0049) |
| `hash/blake2b` | `cardano-crypto-class` | [`src/Cardano/Crypto/Hash/Blake2b.hs`](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/Hash/Blake2b.hs) | [RFC 7693](https://tools.ietf.org/html/rfc7693) |
| `hash/sha` | `cardano-crypto-class` | [`src/Cardano/Crypto/Hash/SHA256.hs`](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/Hash/SHA256.hs) | NIST FIPS 180-4 |
| `bls` | `cardano-crypto-class` | [`src/Cardano/Crypto/DSIGN/` (BLS modules)](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-class/src/Cardano/Crypto/DSIGN) | [CIP-0381](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0381) |
| `key` | `cardano-api` | [`src/Cardano/Api/Keys/`](https://github.com/IntersectMBO/cardano-api/tree/main/cardano-api/internal/Cardano/Api/Keys) | Bech32, TextEnvelope |
| `cbor` | `cardano-binary` | [`src/Cardano/Binary/`](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-binary/src/Cardano/Binary) | RFC 8949 |
| `hd` | `cardano-addresses` | [`core/lib/`](https://github.com/IntersectMBO/cardano-addresses/tree/master/core/lib) | [CIP-1852](https://github.com/cardano-foundation/CIPs/tree/master/CIP-1852) |
| `seed` | `cardano-crypto-class` | [`src/Cardano/Crypto/Seed.hs`](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/Seed.hs) | Internal |
| `common/traits` | `cardano-crypto-class` | [`src/Cardano/Crypto/DSIGN/Class.hs`](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/DSIGN/Class.hs) | Type class abstractions |

### Verification Process

When implementing or modifying any cryptographic function:

1. **Find the Haskell equivalent** in the upstream path listed above
2. **Extract test vectors** from Haskell tests or IETF specs
3. **Verify byte-for-byte** output matches
4. **Document the mapping** in code comments with upstream file path

---

## Coding Standards

### Error Handling

**NEVER use `.unwrap()` or `.expect()` in library code** (tests are OK).

```rust
// Use crate::common::Result which wraps CryptoError
let result = some_function().map_err(|_| CryptoError::InvalidInput)?;
```

### Memory Safety for Secrets

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};
use subtle::ConstantTimeEq;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey { bytes: [u8; 32] }

// Redact Debug output
impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretKey([REDACTED])")
    }
}

// Constant-time comparison only
fn verify_tag(a: &[u8; 16], b: &[u8; 16]) -> bool {
    bool::from(a.ct_eq(b))
}
```

### no_std Support

All modules must compile with `#![cfg_attr(not(feature = "std"), no_std)]`. Use `default-features = false` for dependencies.

### Feature Gating

```rust
#[cfg(feature = "my_feature")]
#[cfg_attr(docsrs, doc(cfg(feature = "my_feature")))]
pub mod my_module { /* ... */ }
```

### Naming

Follow Cardano/Haskell naming adapted to Rust conventions: `genKey` → `gen_key()`, `deriveVerKey` → `derive_verification_key()`, `SignedKES` → `SignedKes`.

---

## Testing

```bash
cargo test --all-features           # All tests
cargo test --features vrf           # Single module
cargo clippy --all-targets --all-features -- -D warnings
just check                          # Full CI: fmt + clippy + test + docs
```

### Requirements

Every public function needs: unit tests, golden tests (known-good outputs), edge case tests, error tests. Property tests with `proptest` where applicable.

### Test Vector Sources

Always document the source of test vectors in comments:

```rust
/// Source: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03 (Section A.1)
/// Cardano compat: cardano-crypto-praos/tests/Test/Crypto/VRF.hs
```

---

## Feature Flags

```
default = ["std", "thiserror", "vrf", "kes", "dsign", "hash", "seed", "cbor", "key", "hd"]

std → alloc                    vrf → dsign, hash, alloc
kes → dsign, hash, alloc       dsign → hash, alloc
hash → alloc                   seed → hash, alloc
cbor → alloc                   key → hash
hd → dsign, hash, alloc, seed  bls → alloc (dep: blst)
secp256k1 → dsign, alloc (dep: k256)
plutus → secp256k1 + bls
```

---

## Do's and Don'ts

**DO:** verify against cardano-base vectors | use `Result<T>` | zeroize secrets | constant-time ops | `no_std` + `alloc` | link to standards | `#[must_use]` on pure fns | feature-gate optional modules | use const generics for fixed arrays

**DON'T:** `.unwrap()` in lib code | panic in crypto | `==` for secret comparison | log secrets | `std::rand` for crypto | pull `std` deps by default | break semver | skip tests
