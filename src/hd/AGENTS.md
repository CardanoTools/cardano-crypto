# src/hd/ — HD Wallet Derivation

Hierarchical Deterministic key derivation per CIP-1852 and BIP32-Ed25519.

## Upstream Reference

| Component | Upstream Package | Upstream Path | Standard |
|---|---|---|---|
| HD derivation | `cardano-addresses` | [core/lib/](https://github.com/IntersectMBO/cardano-addresses/tree/master/core/lib) | [CIP-1852](https://github.com/cardano-foundation/CIPs/tree/master/CIP-1852) |
| BIP32-Ed25519 | `cardano-crypto` (legacy) | [cbits/ed25519/](https://github.com/IntersectMBO/cardano-crypto/tree/master/cbits/ed25519) | Khovratovich & Law (2017) |

CIPs:
- [CIP-1852](https://github.com/cardano-foundation/CIPs/tree/master/CIP-1852) — HD wallets for Cardano
- [CIP-11](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0011) — Staking key chain for HD wallets

## Files

| File | Purpose |
|---|---|
| `mod.rs` | `ExtendedPrivateKey`, `ChainCode`, derivation constants, HMAC-based child key derivation |
| `address.rs` | Address construction from derived keys |

## Derivation Path (CIP-1852)

```
m / purpose' / coin_type' / account' / role / index
m / 1852'    / 1815'      / 0'       / 0    / 0
```

| Constant | Value | Meaning |
|---|---|---|
| `PURPOSE_CIP1852` | 1852 | Cardano purpose |
| `COIN_TYPE_ADA` | 1815 | Ada coin type (birth year of Ada Lovelace) |
| `HARDENED_OFFSET` | 0x80000000 | Hardened derivation flag |

## Rules

- `hd` feature implies `dsign` + `hash` + `alloc` + `seed`.
- `ExtendedPrivateKey` and `ChainCode` must derive `Zeroize` + `ZeroizeOnDrop`.
- Child key derivation uses HMAC-SHA512; output must match `cardano-addresses` library.
- Golden tests in `tests/hd_golden_tests.rs`.
