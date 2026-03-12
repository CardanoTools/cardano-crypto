# cardano-crypto — AI Assistant Guide

> **Version:** 1.2.0 | **MSRV:** 1.85 | **Edition:** 2024 | **License:** MIT OR Apache-2.0

Pure Rust implementation of Cardano cryptographic primitives with 100% binary compatibility with [IntersectMBO/cardano-base](https://github.com/IntersectMBO/cardano-base).

Full coding standards, upstream mapping, and security guidelines are in [.github/copilot-instructions.md](.github/copilot-instructions.md). This file provides quick-reference context and links to location-specific `AGENTS.md` files.

---

## Quick Commands

```bash
cargo test --all-features                                    # All tests
cargo clippy --all-targets --all-features -- -D warnings     # Lint
cargo fmt --all                                              # Format
just check                                                   # Full CI: fmt + clippy + test + docs
just quick-check                                             # Fast: fmt + clippy only
cargo doc --all-features --no-deps --open                    # Docs
cargo bench --all-features                                   # Benchmarks
```

---

## Module Map

Each subdirectory has its own `AGENTS.md` with upstream references, file inventory, and module-specific rules.

| Directory | Purpose | Upstream | AGENTS.md |
|---|---|---|---|
| `src/common/` | Error types, traits, curve ops, security utils | [cardano-crypto-class](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-class) | [src/common/AGENTS.md](src/common/AGENTS.md) |
| `src/hash/` | Blake2b-224/256/512, SHA-256/512 | [cardano-crypto-class/.../Hash/](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-class/src/Cardano/Crypto/Hash) | [src/hash/AGENTS.md](src/hash/AGENTS.md) |
| `src/dsign/` | Ed25519, secp256k1 ECDSA + Schnorr | [cardano-crypto-class/.../DSIGN/](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-class/src/Cardano/Crypto/DSIGN) | [src/dsign/AGENTS.md](src/dsign/AGENTS.md) |
| `src/vrf/` | VRF Draft-03/13 + Cardano compat | [cardano-crypto-praos](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-praos) | [src/vrf/AGENTS.md](src/vrf/AGENTS.md) |
| `src/kes/` | KES Single + Sum (Sum0–Sum7) | [cardano-crypto-class/.../KES/](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-class/src/Cardano/Crypto/KES) | [src/kes/AGENTS.md](src/kes/AGENTS.md) |
| `src/bls/` | BLS12-381 for Plutus (CIP-0381) | [cardano-crypto-class/.../DSIGN/](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-class/src/Cardano/Crypto/DSIGN) | [src/bls/AGENTS.md](src/bls/AGENTS.md) |
| `src/seed/` | Deterministic seed derivation | [cardano-crypto-class/.../Seed.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/Seed.hs) | [src/seed/AGENTS.md](src/seed/AGENTS.md) |
| `src/key/` | Bech32, TextEnvelope, key hashes | [cardano-api/.../Keys/](https://github.com/IntersectMBO/cardano-api/tree/main/cardano-api/internal/Cardano/Api/Keys) | [src/key/AGENTS.md](src/key/AGENTS.md) |
| `src/hd/` | HD wallet derivation (CIP-1852) | [cardano-addresses](https://github.com/IntersectMBO/cardano-addresses/tree/master/core/lib) | [src/hd/AGENTS.md](src/hd/AGENTS.md) |
| `src/cbor/` | CBOR serialization | [cardano-binary](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-binary/src/Cardano/Binary) | [src/cbor/AGENTS.md](src/cbor/AGENTS.md) |
| `tests/` | Golden, property, edge-case tests | — | [tests/AGENTS.md](tests/AGENTS.md) |
| `examples/` | Runnable usage examples | — | [examples/AGENTS.md](examples/AGENTS.md) |
| `benches/` | Criterion benchmarks | — | [benches/AGENTS.md](benches/AGENTS.md) |

---

## Feature Flags (quick ref)

```
default = ["std", "thiserror", "vrf", "kes", "dsign", "hash", "seed", "cbor", "key", "hd"]

std → alloc                    vrf → dsign, hash, alloc
kes → dsign, hash, alloc       dsign → hash, alloc
hash → alloc                   seed → hash, alloc
cbor → alloc                   key → hash
hd → dsign, hash, alloc, seed  bls → alloc (dep: blst)
secp256k1 → dsign, alloc       plutus → secp256k1 + bls
```

---

## Hard Rules (non-negotiable)

1. **Binary compat** — outputs must match [cardano-base](https://github.com/IntersectMBO/cardano-base) byte-for-byte
2. **No `.unwrap()` / `.expect()`** in library code — use `crate::common::Result<T>`
3. **Zeroize** all secret keys — derive `Zeroize` + `ZeroizeOnDrop`; redact `Debug`
4. **Constant-time** comparisons via `subtle::ConstantTimeEq` — never `==` on secrets
5. **`no_std` + `alloc`** — every module; `default-features = false` for deps
6. **Test vectors** — every public fn needs golden tests from IETF/CIP/cardano-base

---

## Performance Targets

| Operation | Target | Context |
|---|---|---|
| VRF Prove | <1 ms | Block production |
| VRF Verify | <500 µs | Block validation |
| KES Sign | <2 ms | Block signing |
| Ed25519 Sign | <100 µs | Tx signing |
| Blake2b-256 | >100 MB/s | UTXO hashing |

---

## Related Docs

- [ARCHITECTURE.md](ARCHITECTURE.md) — design decisions, data flows, security model
- [CONTRIBUTING.md](CONTRIBUTING.md) — PR workflow, commit conventions
- [SECURITY.md](SECURITY.md) — vulnerability disclosure
- [CHANGELOG.md](CHANGELOG.md) — release history
