# benches/ — Criterion Benchmarks

Performance benchmarks for cryptographic operations, targeting Cardano mainnet throughput requirements.

## Benchmark Files

| File | Module | Key Operations Benchmarked |
|---|---|---|
| `vrf_benchmarks.rs` | `vrf` | `prove`, `verify`, `keypair_from_seed` |
| `kes_benchmarks.rs` | `kes` | `sign_kes`, `verify_kes`, `update_kes`, `gen_key` |
| `dsign_benchmarks.rs` | `dsign` | `sign`, `verify`, `gen_key`, `derive_verification_key` |
| `hash_benchmarks.rs` | `hash` | Blake2b-224/256/512, SHA-256/512 throughput |

## Performance Targets

| Operation | Target | Cardano Context |
|---|---|---|
| VRF Prove | < 1 ms | Block production (every slot) |
| VRF Verify | < 500 µs | Block validation (every received block) |
| KES Sign (Sum6) | < 2 ms | Block signing |
| KES Verify (Sum6) | < 1 ms | Block header validation |
| Ed25519 Sign | < 100 µs | Transaction signing |
| Ed25519 Verify | < 200 µs | Transaction validation |
| Blake2b-256 | > 100 MB/s | UTXO hashing, address derivation |

## Running

```bash
cargo bench --all-features                       # All benchmarks
cargo bench --bench vrf_benchmarks --all-features # Single file
cargo bench --all-features -- "prove"             # Name filter
```

Results are written to `target/criterion/` with HTML reports.

## Rules

- Use `criterion` with `html_reports` feature.
- Benchmark both typical and worst-case inputs.
- Add `#[bench]` for any operation on the critical path (block production, validation).
- Compare against performance targets after any change to crypto internals.
