# src/common/ — Shared Cryptographic Utilities

Foundational types, traits, and utilities used by every other module.

## Upstream Reference

| File | Upstream | URL |
|---|---|---|
| `traits.rs` | `cardano-crypto-class` | [DSIGN/Class.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/DSIGN/Class.hs) |
| `error.rs` | — | Crate-internal error hierarchy |
| `curve.rs` | `cardano-crypto-praos` | [cbits/private/ed25519_ref10.h](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-praos/cbits) |
| `hash.rs` | `cardano-crypto-class` | [Hash/Class.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/Hash/Class.hs) |
| `security.rs` | — | Zeroize/constant-time wrappers |
| `vrf_constants.rs` | `cardano-crypto-praos` | [cbits/crypto_vrf_ietfdraft03.c](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-praos/cbits) |

## Files

| File | Purpose |
|---|---|
| `mod.rs` | Re-exports, module docs |
| `error.rs` | `CryptoError`, `CryptoResult<T>` — crate-wide error type |
| `traits.rs` | `DsignAlgorithm`, `SignableRepresentation` traits |
| `curve.rs` | Edwards25519 point/scalar ops (shared by VRF + KES) |
| `hash.rs` | `HashAlgorithm` trait, SHA-512 helpers |
| `security.rs` | Zeroize helpers, constant-time utilities |
| `vrf_constants.rs` | VRF suite strings, domain separation tags |

## Rules

- **Always `no_std`-safe** — this module must never depend on `std`.
- `error.rs` is the single source of truth for error types. Other modules wrap their errors via `From` impls into `CryptoError`.
- `curve.rs` contains low-level field/point arithmetic. Changes here affect VRF and KES — run both test suites after any edit.
- Never expose `subtle` or `zeroize` internals in the public API; wrap them in `security.rs`.

## Key Types

```rust
pub type Result<T> = core::result::Result<T, CryptoError>;
pub type CryptoResult<T> = Result<T>;
```
