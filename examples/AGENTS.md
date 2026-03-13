# examples/ — Runnable Usage Examples

Each example demonstrates a real-world Cardano workflow using the crate's public API.

## Examples

| File | Features Required | What It Shows |
|---|---|---|
| `vrf_basic.rs` | `vrf` | VRF keypair generation, prove, verify (Draft-03 + Draft-13) |
| `kes_lifecycle.rs` | `kes` | KES key generation, signing, evolution across periods |
| `dsign_sign_verify.rs` | `dsign` | Ed25519 sign/verify workflow |
| `seed_derivation.rs` | `seed`, `dsign`, `vrf`, `kes` | Hierarchical seed → key derivation for multiple algorithms |
| `plutus_crypto.rs` | `secp256k1`, `bls` | BLS pairing + secp256k1 ECDSA/Schnorr for Plutus scripts |
| `bls_multisig.rs` | `bls` | BLS aggregate signature construction and verification |
| `hd_wallet.rs` | `hd` | CIP-1852 HD wallet derivation path |
| `operational_cert.rs` | `kes`, `dsign`, `key` | Stake pool operational certificate creation |
| `stake_pool_registration.rs` | `key`, `vrf` | Pool ID derivation, VRF key registration |
| `spo_kes_management.rs` | `kes`, `dsign`, `key` | SPO KES key rotation workflow |

## Running

```bash
cargo run --example vrf_basic --features vrf
cargo run --example plutus_crypto --features plutus
cargo run --example hd_wallet --features hd
```

## Rules

- Every example must compile and run without errors.
- Use `required-features` in `Cargo.toml` `[[example]]` entries.
- Examples should be self-contained — no external files or network access.
- Prefer realistic Cardano scenarios over abstract demos.
- Keep examples concise; link to module docs for details.
