# src/key/ — Key Types and Serialization

Bech32 encoding, TextEnvelope format, key hashes, and KES period helpers matching cardano-api.

## Upstream Reference

| File | Upstream Package | Upstream Path |
|---|---|---|
| `bech32.rs` | `cardano-api` | [Keys/Class.hs](https://github.com/IntersectMBO/cardano-api/tree/main/cardano-api/internal/Cardano/Api/Keys) |
| `encoding.rs` | `cardano-api` | [SerialiseBech32.hs](https://github.com/IntersectMBO/cardano-api/blob/main/cardano-api/internal/Cardano/Api/SerialiseBech32.hs) |
| `text_envelope.rs` | `cardano-api` | [SerialiseTextEnvelope.hs](https://github.com/IntersectMBO/cardano-api/blob/main/cardano-api/internal/Cardano/Api/SerialiseTextEnvelope.hs) |
| `hash.rs` | `cardano-crypto-class` | [Hash/Class.hs](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/Hash/Class.hs) |
| `kes_period.rs` | `cardano-api` | [OperationalCertificate.hs](https://github.com/IntersectMBO/cardano-api/blob/main/cardano-api/internal/Cardano/Api/OperationalCertificate.hs) |
| `operational_cert.rs` | `cardano-api` | [OperationalCertificate.hs](https://github.com/IntersectMBO/cardano-api/blob/main/cardano-api/internal/Cardano/Api/OperationalCertificate.hs) |
| `stake_pool.rs` | `cardano-api` | [StakePoolMetadata.hs](https://github.com/IntersectMBO/cardano-api/blob/main/cardano-api/internal/Cardano/Api/StakePoolMetadata.hs) |

## Files

| File | Purpose |
|---|---|
| `mod.rs` | Re-exports, Bech32 prefix table docs |
| `bech32.rs` | Prefix constants (`addr_vk`, `vrf_sk`, `kes_vk`, etc.) |
| `encoding.rs` | `encode_*` / `decode_*` for Bech32 key serialization |
| `text_envelope.rs` | JSON-based key file format matching `cardano-cli` |
| `hash.rs` | `KeyHash` (Blake2b-224 of verification key) |
| `kes_period.rs` | KES period arithmetic, slot-to-period conversion |
| `operational_cert.rs` | Operational certificate types |
| `stake_pool.rs` | Stake pool ID and metadata hash types |

## Bech32 Prefixes (from cardano-api)

| Key Type | Verification Key | Signing Key |
|---|---|---|
| Payment | `addr_vk` | `addr_sk` |
| Stake | `stake_vk` | `stake_sk` |
| Pool operator | `pool_vk` | `pool_sk` |
| VRF | `vrf_vk` | `vrf_sk` |
| KES | `kes_vk` | `kes_sk` |

## Rules

- `key` feature implies `hash`. `bech32-encoding` feature adds `dep:bech32`.
- Prefix strings must exactly match cardano-api — any mismatch breaks wallet interop.
- `TextEnvelope` JSON format must match `cardano-cli key generate` output.
- `KeyHash` = Blake2b-224 of the raw verification key bytes (28 bytes).
