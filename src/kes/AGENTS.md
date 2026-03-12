# src/kes/ — Key Evolving Signatures

Forward-secure signature scheme for Cardano block signing, based on the MMM 2002 paper.

## Upstream Reference

| File | Upstream Package | Upstream Path |
|---|---|---|
| `single/` | `cardano-crypto-class` | [KES/Single.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/KES/Single.hs) |
| `sum/` | `cardano-crypto-class` | [KES/Sum.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/KES/Sum.hs) |
| — | `cardano-crypto-class` | [KES/Class.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/KES/Class.hs) (trait) |
| — | `cardano-crypto-class` | [KES/CompactSingle.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/KES/CompactSingle.hs) |
| — | `cardano-crypto-class` | [KES/CompactSum.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/KES/CompactSum.hs) |

Paper: *"Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures"* — Malkin, Micciancio, Miner (2002)

## Files

| File | Purpose |
|---|---|
| `mod.rs` | Re-exports all KES variants, `Period` type, `KesError` |
| `hash.rs` | KES-specific `Blake2b224/256/512`, `KesHashAlgorithm` trait |
| `test_vectors.rs` | Golden test data from cardano-base |
| `single/mod.rs` | Re-exports SingleKes variants |
| `single/basic.rs` | `SingleKes` — 1-period base case (wraps Ed25519) |
| `single/compact.rs` | `CompactSingleKes` — optimized single-period variant |
| `sum/mod.rs` | Re-exports Sum0–Sum7 + CompactSum variants |
| `sum/basic.rs` | `SumKes<D, N>` — binary-tree composition, `Sum0Kes`–`Sum7Kes` |
| `sum/compact.rs` | `CompactSumKes` — reduced signature sizes |

## Architecture

```
SingleKes (1 period)
  └── SumKes<SingleKes, 0> = Sum0Kes (1 period)
       └── SumKes<Sum0Kes, 1> = Sum1Kes (2 periods)
            └── SumKes<Sum1Kes, 2> = Sum2Kes (4 periods)
                 └── ...
                      └── Sum6Kes (64 periods) ← Cardano mainnet
                           └── Sum7Kes (128 periods)
```

**Sum6Kes** is Cardano's operational standard — 64 KES periods per operational certificate.

## Rules

- `kes` feature implies `dsign` + `hash` + `alloc`.
- The `KesAlgorithm` trait (in `common/traits.rs`) defines `gen_key_kes_from_seed_bytes`, `sign_kes`, `verify_kes`, `update_kes`, `derive_verification_key`.
- Signing keys must derive `Zeroize` + `ZeroizeOnDrop`. After `update_kes`, the old period's key must be irrecoverable.
- Verification output must be byte-identical to `cardano-crypto-class` — golden tests in `tests/kes_golden_tests.rs`.
- Performance target: Sign < 2 ms.
