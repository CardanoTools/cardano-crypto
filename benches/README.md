# Benchmark Suite

This directory contains performance benchmarks for all cryptographic primitives in `cardano-crypto`.

## Running Benchmarks

Run all benchmarks:
```bash
cargo bench
```

Run specific benchmark suite:
```bash
cargo bench --bench vrf_benchmarks
cargo bench --bench kes_benchmarks
cargo bench --bench hash_benchmarks
cargo bench --bench dsign_benchmarks
```

Run with all features:
```bash
cargo bench --all-features
```

## Benchmark Suites

### VRF Benchmarks (`vrf_benchmarks.rs`)
- **Draft-03**: Keypair generation, prove, verify, proof-to-hash
- **Draft-13**: Prove, verify
- Message sizes: 0, 32, 64, 256, 1024 bytes

### KES Benchmarks (`kes_benchmarks.rs`)
- **Sum2Kes**: Key generation, derive VK, sign, verify, update (4 periods)
- **Sum6Kes**: Key generation, sign, verify, update (64 periods)
- Message sizes: 32, 64, 256, 1024, 4096 bytes

### Hash Benchmarks (`hash_benchmarks.rs`)
- **Blake2b-224**: Various data sizes
- **Blake2b-256**: Various data sizes, hash concatenation
- **Blake2b-512**: Various data sizes
- Data sizes: 32, 64, 128, 256, 512, 1024, 4096, 16384 bytes

### DSIGN Benchmarks (`dsign_benchmarks.rs`)
- **Ed25519**: Key generation, derive VK, sign, verify
- **secp256k1 ECDSA** (with `secp256k1` feature): Sign, verify
- **secp256k1 Schnorr** (with `secp256k1` feature): Sign, verify
- Message sizes: 32, 64, 256, 1024, 4096 bytes

## Interpreting Results

Criterion outputs:
- **time**: Mean execution time with confidence intervals
- **thrpt**: Throughput (bytes/second for hashing, operations/second for signatures)
- **change**: Performance change vs previous run (if available)

HTML reports are generated in `target/criterion/` with detailed statistical analysis.

## Baseline Comparisons

To establish a baseline:
```bash
cargo bench --all-features -- --save-baseline main
```

To compare against baseline:
```bash
cargo bench --all-features -- --baseline main
```

## CI Integration

Benchmarks run in CI to detect performance regressions. Thresholds:
- **Critical**: >10% regression on hot paths (prove, verify, hash)
- **Warning**: >5% regression on any operation

## Performance Targets

Based on Cardano mainnet requirements:

| Operation | Target | Justification |
|-----------|--------|---------------|
| VRF Prove | <1ms | Block production (slot leader election) |
| VRF Verify | <500μs | Block validation (critical path) |
| KES Sign | <2ms | Block signing (every 20s average) |
| KES Verify | <1ms | Block validation (critical path) |
| Ed25519 Sign | <100μs | Transaction signing (user experience) |
| Ed25519 Verify | <50μs | Transaction validation (throughput) |
| Blake2b-256 | >100 MB/s | UTXO hashing (chain sync) |

## Notes

- Benchmarks use `black_box()` to prevent compiler optimizations
- Each benchmark runs multiple iterations for statistical significance
- Warm-up period ensures consistent CPU frequency
- Results vary by CPU model, load, and system configuration
