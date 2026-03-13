# src/dsign/ — Digital Signatures

Ed25519 and secp256k1 (ECDSA + Schnorr) signature algorithms.

## Upstream Reference

| File | Upstream Package | Upstream Path | Standard |
|---|---|---|---|
| `ed25519.rs` | `cardano-crypto-class` | [DSIGN/Ed25519.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/DSIGN/Ed25519.hs) | [RFC 8032](https://tools.ietf.org/html/rfc8032) |
| `secp256k1.rs` | `cardano-crypto-class` | [DSIGN/EcdsaSecp256k1.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/DSIGN/EcdsaSecp256k1.hs), [DSIGN/SchnorrSecp256k1.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/DSIGN/SchnorrSecp256k1.hs) | [CIP-0049](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0049), [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) |

## Files

| File | Purpose |
|---|---|
| `mod.rs` | Re-exports, `DsignAlgorithm` usage docs |
| `ed25519.rs` | Ed25519 sign/verify via `ed25519-dalek` — standard Cardano tx signatures |
| `secp256k1.rs` | ECDSA + Schnorr on secp256k1 via `k256` — Plutus CIP-0049 interop |

## Cardano Usage

- **Ed25519** — every Cardano transaction signature; KES base layer; VRF keypair derivation.
- **secp256k1 ECDSA** — Plutus V2+ scripts for Bitcoin/Ethereum cross-chain verification.
- **secp256k1 Schnorr** — Plutus V2+ scripts per BIP-340 (Taproot-compatible).

## Rules

- `dsign` feature implies `hash` + `alloc`.
- `secp256k1` feature is optional, gated behind `dep:k256`.
- Ed25519 signing keys must derive `Zeroize` + `ZeroizeOnDrop`; `Debug` must redact.
- secp256k1 signatures use **low-S normalization** to match `cardano-crypto-class` — verify with `tests/secp256k1_conformance_tests.rs`.
- The `DsignAlgorithm` trait is defined in `common/traits.rs` and used as the base for KES.
