# tests/ — Integration and Golden Tests

Test suites verifying binary compatibility with IntersectMBO/cardano-base and conformance with IETF/CIP specifications.

## Test Files

| File | Module | Vectors Source |
|---|---|---|
| `vrf_golden_tests.rs` | `vrf` | [IETF draft-03 §A.1](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03), [cardano-crypto-praos tests](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-praos) |
| `vrf_property_tests.rs` | `vrf` | `proptest` — prove/verify roundtrip, key derivation |
| `kes_golden_tests.rs` | `kes` | [cardano-crypto-class KES tests](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-class) |
| `kes_interop_tests.rs` | `kes` | Cross-variant interop (Sum vs CompactSum) |
| `kes_property_tests.rs` | `kes` | `proptest` — evolve/sign/verify invariants |
| `dsign_compat_tests.rs` | `dsign` | [RFC 8032 §7.1](https://tools.ietf.org/html/rfc8032#section-7.1), [cardano-crypto-class DSIGN tests](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-class) |
| `hash_compat_tests.rs` | `hash` | [RFC 7693 §Appendix](https://tools.ietf.org/html/rfc7693), [cardano-crypto-class Hash tests](https://github.com/IntersectMBO/cardano-base/blob/master/cardano-crypto-class/src/Cardano/Crypto/Hash) |
| `bls12381_conformance_tests.rs` | `bls` | [CIP-0381 test vectors](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0381), [Ethereum BLS tests](https://github.com/ethereum/bls12-381-tests) |
| `secp256k1_conformance_tests.rs` | `dsign` | [CIP-0049](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0049), [BIP-340 vectors](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv) |
| `cbor_compat_tests.rs` | `cbor` | [cardano-binary tests](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-binary) |
| `hd_golden_tests.rs` | `hd` | [cardano-addresses tests](https://github.com/IntersectMBO/cardano-addresses) |
| `plutus_crypto_tests.rs` | `bls`/`secp256k1` | CIP-0381 + CIP-0049 combined |
| `plutus_edge_case_tests.rs` | `bls`/`secp256k1` | Identity points, zero scalars, invalid inputs |
| `edge_case_tests.rs` | all | Boundary conditions, malformed data |
| `ocert_property_tests.rs` | `key`/`kes` | Operational certificate roundtrips |

## Test Vector Files

`test_vectors/` contains binary files with pre-computed VRF outputs:
- `vrf_ver03_standard_*` — IETF standard vectors
- `vrf_ver03_generated_*` — Generated from cardano-crypto-praos

## Running Tests

```bash
cargo test --all-features                          # Everything
cargo test --test vrf_golden_tests --all-features  # Single file
cargo test vrf_draft03 --all-features              # Name filter
cargo test --all-features -- --nocapture            # Show output
```

## Rules

- Every golden test must document its source (IETF section, upstream file, CIP).
- Property tests use `proptest` — keep strategy configs deterministic for reproducibility.
- `.unwrap()` is allowed in test code.
- New public API → add tests here, not just unit tests in `src/`.
