# src/bls/ — BLS12-381 Curve Operations

Pairing-friendly curve operations for Plutus V2+ smart contracts (CIP-0381).

## Upstream Reference

| Component | Upstream Package | Upstream Path | Standard |
|---|---|---|---|
| G1/G2 ops | `cardano-crypto-class` | [DSIGN/](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-class/src/Cardano/Crypto/DSIGN) | [CIP-0381](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0381) |
| Plutus builtins | `plutus-core` | [Builtins/](https://github.com/IntersectMBO/plutus/tree/master/plutus-core/plutus-core/src/PlutusCore/Default/Builtins.hs) | CIP-0381 §2 |

CIP: [CIP-0381 — Plutus support for pairings over BLS12-381](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0381)

## Files

| File | Purpose |
|---|---|
| `mod.rs` | G1/G2 point types, scalar type, pairing, hash-to-curve, BLS signatures, aggregate verification |

## Public Types

| Type | Size | Description |
|---|---|---|
| `G1Point` | 48 bytes (compressed) | Point on G1 (base field 𝔽p) |
| `G2Point` | 96 bytes (compressed) | Point on G2 (extension field 𝔽p²) |
| `Scalar` | 32 bytes | BLS12-381 scalar field element |
| `Bls12381` | — | Namespace for static methods |

## Plutus Builtin Mapping

| Plutus Builtin | Our Function |
|---|---|
| `bls12_381_G1_add` | `G1Point::add()` |
| `bls12_381_G1_neg` | `G1Point::neg()` |
| `bls12_381_G1_scalarMul` | `G1Point::mul()` |
| `bls12_381_G1_compress` | `G1Point::to_compressed()` |
| `bls12_381_G1_uncompress` | `G1Point::from_compressed()` |
| `bls12_381_G1_hashToGroup` | `Bls12381::hash_to_g1()` |
| `bls12_381_G2_*` | Same pattern for G2 |
| `bls12_381_millerLoop` | `Bls12381::miller_loop()` |
| `bls12_381_finalVerify` | `Bls12381::final_verify()` |

## Rules

- `bls` feature requires `dep:blst` + `alloc`. Not in default features.
- Uses the [blst](https://github.com/supranational/blst) crate for constant-time, assembly-optimized operations.
- Deserialized points must pass subgroup and on-curve checks — never skip validation.
- `Scalar` derives `Zeroize` + `ZeroizeOnDrop` (private keys).
- Conformance tests in `tests/bls12381_conformance_tests.rs`.
