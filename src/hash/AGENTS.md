# src/hash/ — Hash Functions

Blake2b and SHA hash implementations used throughout Cardano.

## Upstream Reference

| File | Upstream Package | Upstream Path | Standard |
|---|---|---|---|
| `blake2b.rs` | `cardano-crypto-class` | [Hash/Blake2b.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/Hash/Blake2b.hs) | [RFC 7693](https://tools.ietf.org/html/rfc7693) |
| `sha.rs` | `cardano-crypto-class` | [Hash/SHA256.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/Hash/SHA256.hs) | NIST FIPS 180-4 |

## Files

| File | Purpose |
|---|---|
| `mod.rs` | Re-exports `Blake2b224`, `Blake2b256`, `Blake2b512`, `HashAlgorithm` |
| `blake2b.rs` | Blake2b-224 (addresses), Blake2b-256 (KES vkeys), Blake2b-512 (general) |
| `sha.rs` | SHA-256, SHA-512 wrappers via `sha2` crate |

## Cardano Usage

| Hash | Size | Used For |
|---|---|---|
| Blake2b-224 | 28 bytes | Address derivation, key hashes, script hashes |
| Blake2b-256 | 32 bytes | Transaction IDs, KES verification key hashes |
| Blake2b-512 | 64 bytes | VRF proof-to-output, Ed25519 internals |
| SHA-256 | 32 bytes | Cross-chain interop, BIP-340 tagged hashing |

## Rules

- Feature-gated under `hash` (implies `alloc`).
- Must use `default-features = false` on `blake2`, `sha2`, `digest` crates.
- Output must match `cardano-crypto-class` hashes byte-for-byte — verify with golden tests in `tests/hash_compat_tests.rs`.
- `HashAlgorithm` trait is the public API; concrete structs implement it.
