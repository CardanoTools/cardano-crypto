# src/cbor/ — CBOR Serialization

Cardano-compatible CBOR encoding and decoding (RFC 8949).

## Upstream Reference

| Component | Upstream Package | Upstream Path | Standard |
|---|---|---|---|
| Encoding | `cardano-binary` | [ToCBOR.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-binary/src/Cardano/Binary/ToCBOR.hs) | [RFC 8949](https://tools.ietf.org/html/rfc8949) |
| Decoding | `cardano-binary` | [FromCBOR.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-binary/src/Cardano/Binary/FromCBOR.hs) | RFC 8949 |
| Serialization | `cardano-binary` | [Serialize.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-binary/src/Cardano/Binary/Serialize.hs) | |

## Files

| File | Purpose |
|---|---|
| `mod.rs` | `ToCbor`, `FromCbor` traits; encode/decode for fixed-length byte strings |

## Cardano CBOR Format

Cardano wraps cryptographic types in CBOR byte strings:

| Type | CBOR Tag | Encoded As |
|---|---|---|
| Ed25519 VK (32 B) | — | `5820` + 32 bytes |
| Ed25519 Sig (64 B) | — | `5840` + 64 bytes |
| VRF VK (32 B) | — | `5820` + 32 bytes |
| VRF Proof (80 B) | — | `5850` + 80 bytes |
| KES VK (32 B) | — | `5820` + 32 bytes |

Prefix `58xx` = CBOR major type 2 (byte string) with 1-byte length.

## Rules

- `cbor` feature implies `alloc`.
- Encoding must be **canonical CBOR** (deterministic) — smallest valid encoding.
- Must match `cardano-binary` output byte-for-byte — verify with `tests/cbor_compat_tests.rs`.
- No external CBOR library dependency; the encoding for fixed-size crypto types is hand-rolled for correctness and `no_std` compatibility.
