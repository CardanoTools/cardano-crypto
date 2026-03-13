# src/seed/ — Seed Management and Derivation

Deterministic seed generation and hierarchical key derivation matching cardano-base.

## Upstream Reference

| Component | Upstream Package | Upstream Path |
|---|---|---|
| `Seed` | `cardano-crypto-class` | [Seed.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/Seed.hs) |
| `MLockedSeed` | `cardano-crypto-class` | [MLockedSeed.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/Seed.hs) |

## Files

| File | Purpose |
|---|---|
| `mod.rs` | `Seed`, `SecureSeed`, `derive_seed()`, `expand_seed()` |

## Type Mapping

| Haskell | Rust | Notes |
|---|---|---|
| `Seed` | `Seed` ([u8; 32]) | Basic 32-byte seed |
| `MLockedSeed` | `SecureSeed` | Auto-zeroizes on drop |
| `getSeedBytes` | `Seed::as_bytes()` | |
| `mkSeedFromBytes` | `Seed::from_bytes()` | |
| `expandSeed` | `expand_seed()` | Child derivation with index |

## Rules

- `seed` feature implies `hash` + `alloc`.
- `SecureSeed` must derive `Zeroize` + `ZeroizeOnDrop`; `Debug` must print `[REDACTED]`.
- `expand_seed()` uses Blake2b-256 for derivation: `Blake2b256(parent_seed || index)`.
- Seeds are the root of all key material; never log, print, or expose them.
