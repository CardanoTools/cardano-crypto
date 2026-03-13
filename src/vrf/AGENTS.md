# src/vrf/ — Verifiable Random Functions

VRF implementations for Cardano's Praos consensus leader election.

## Upstream Reference

| File | Upstream Package | Upstream Path | Standard |
|---|---|---|---|
| `draft03.rs` | `cardano-crypto-praos` | [cbits/crypto_vrf_ietfdraft03.c](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-praos/cbits) | [IETF draft-irtf-cfrg-vrf-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03) |
| `draft13.rs` | `cardano-crypto-praos` | [cbits/crypto_vrf_ietfdraft13.c](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-praos/cbits) | [IETF draft-irtf-cfrg-vrf-13](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-13) |
| `cardano_compat/` | `cardano-crypto-praos` | [cbits/vrf03/](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-praos/cbits) | Elligator2 libsodium compat |

Haskell type class: [`VRFAlgorithm`](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/VRF/Class.hs)

## Files

| File | Purpose |
|---|---|
| `mod.rs` | Re-exports, type aliases (`VrfKeyPair`, `PraosBatchCompatVrf`) |
| `draft03.rs` | `VrfDraft03` — 80-byte proofs, Cardano mainnet standard |
| `draft13.rs` | `VrfDraft13` — 128-byte proofs, batch-compatible |
| `test_vectors.rs` | IETF + Cardano golden vectors |
| `cardano_compat/mod.rs` | Top-level API: `cardano_vrf_prove`, `cardano_vrf_verify` |
| `cardano_compat/fe25519.rs` | Field element arithmetic GF(2²⁵⁵ − 19) |
| `cardano_compat/elligator2.rs` | Elligator2 hash-to-curve (libsodium-compatible) |
| `cardano_compat/point.rs` | Edwards point ops, coordinate conversions |
| `cardano_compat/prove.rs` | VRF proof generation |
| `cardano_compat/verify.rs` | VRF proof verification |

## Critical Details

- **Draft-03 is Cardano's mainnet VRF.** Proof size = 80 bytes. Output = 64 bytes (SHA-512 of Gamma point).
- The Elligator2 hash-to-curve in `cardano_compat/` must match libsodium's `crypto_core_ed25519_from_uniform()` — this is the hardest part to get right.
- `cardano_compat/fe25519.rs` reimplements libsodium's field arithmetic, not standard `curve25519-dalek` — because Cardano uses the libsodium-specific Elligator2 mapping.

## Rules

- `vrf` feature implies `dsign` + `hash` + `alloc`.
- Any change to `cardano_compat/` must pass all golden tests in `tests/vrf_golden_tests.rs` AND the generated vector files in `tests/test_vectors/vrf_ver03_*`.
- Constants in `common/vrf_constants.rs` define suite strings; do not duplicate them.
- Performance target: Prove < 1 ms, Verify < 500 µs.
