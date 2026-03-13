# Contributing to Cardano Crypto

Thank you for your interest in contributing to the Cardano Crypto library!

## Table of Contents

- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Project Structure](#project-structure)

## Development Setup

### Prerequisites

1. **Install Rust (1.81 or later):**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update
```

2. **Clone the repository:**
```bash
git clone https://github.com/FractionEstate/cardano-crypto.git
cd cardano-crypto
```

3. **Install development tools:**
```bash
# Using just (recommended)
just install-dev-tools

# Or manually
cargo install cargo-audit cargo-deny cargo-llvm-cov cargo-semver-checks
```

4. **Install pre-commit hooks (optional but recommended):**
```bash
pip install pre-commit
pre-commit install
```

5. **Build the project:**
```bash
cargo build --all-features
```

6. **Run tests:**
```bash
cargo test --all-features
# Or use the test script
./scripts/test.sh
```

## Development Workflow

### Quick Commands

We provide several ways to run common tasks:

#### Using Just (Recommended)
```bash
just check          # Run all checks
just quick-check    # Format + clippy only
just test           # Run tests
just test-coverage  # Run tests with coverage
just bench          # Run benchmarks
just docs           # Build and open docs
just ci             # Simulate CI locally
```

#### Using Scripts
```bash
./.github/scripts/check.sh  # Run all checks (like CI)
./.github/scripts/test.sh   # Run tests
./.github/scripts/bench.sh  # Run benchmarks
```

#### Using Cargo Directly
```bash
cargo fmt           # Format code
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo bench --all-features
```

### Before Committing

Run local checks to catch issues early:
```bash
# Quick check
just quick-check

# Full check (recommended)
just check

# Or use the check script
./.github/scripts/check.sh
```

If you installed pre-commit hooks, they'll run automatically on `git commit`.

## Project Structure

```
cardano-crypto/
├── src/
│   ├── lib.rs          # Main library with feature flags
│   ├── common.rs       # Shared utilities and error types
│   ├── hash.rs         # Blake2b and SHA implementations
│   ├── seed.rs         # Deterministic key derivation
│   ├── dsign.rs        # Ed25519 digital signatures
│   ├── vrf.rs          # VRF Draft-03 and Draft-13
│   ├── kes.rs          # KES module root
│   ├── kes/
│   │   ├── single.rs   # Single-period KES
│   │   ├── sum.rs      # Sum KES variants
│   │   └── compact_sum.rs  # Compact Sum KES variants
│   └── cbor.rs         # Optional CBOR support
├── examples/           # Usage examples
└── tests/              # Integration tests
```

## Implementation Roadmap

### Phase 1: Core Infrastructure (Current)
- [x] Project structure with feature flags
- [x] Common traits and error types
- [x] Module stubs with documentation
- [ ] Extract Blake2b from cardano-base-rust
- [ ] Extract Ed25519 from cardano-base-rust

### Phase 2: VRF Migration
- [ ] Migrate VRF Draft-03 from FractionEstate/cardano-VRF
- [ ] Migrate VRF Draft-13 from FractionEstate/cardano-VRF
- [ ] Migrate Cardano compatibility layer
- [ ] Port VRF test vectors

### Phase 3: KES Implementation
- [ ] Implement SingleKES
- [ ] Implement Sum KES hierarchy (Sum0-Sum7)
- [ ] Implement Compact Sum KES (CompactSum0-CompactSum7)
- [ ] Port KES test vectors

### Phase 4: Testing & Optimization
- [ ] Comprehensive test suite
- [ ] Benchmarks for all algorithms
- [ ] Security audit
- [ ] Performance optimization

## Coding Guidelines

### Style
- Follow Rust standard formatting (`cargo fmt`)
- Run clippy and fix warnings (`cargo clippy --all-features`)
- Write documentation for all public APIs
- Include examples in rustdoc

### Documentation
- Use `///` for public item documentation
- Use `//!` for module-level documentation
- Include examples in documentation:
```rust
/// Example function
///
/// # Examples
///
/// ```
/// use cardano_crypto::hash::Blake2b256;
/// let hash = Blake2b256::hash(b"data");
/// ```
pub fn example() {}
```

### Testing
- Write unit tests in the same file as the implementation
- Write integration tests in `tests/` directory
- Test with all feature combinations:
```bash
cargo test --no-default-features
cargo test --all-features
cargo test --features vrf
cargo test --features kes
```

### Error Handling
- Use `Result<T>` from `crate::common`
- Return descriptive errors
- Avoid panics in library code (use `Result` instead)

## Extraction Guidelines

When extracting code from cardano-base-rust:

1. **Preserve Haskell compatibility**: Maintain byte-level compatibility
2. **Remove external dependencies**: Replace with in-house implementations
3. **Add documentation**: Explain algorithms and implementation choices
4. **Port test vectors**: Include official Cardano test vectors
5. **Feature gate appropriately**: Use feature flags for optional components

### Example Extraction Checklist

- [ ] Copy source files from cardano-base-rust
- [ ] Remove external crypto crate dependencies
- [ ] Update imports to use our modules
- [ ] Add comprehensive rustdoc
- [ ] Port associated test vectors
- [ ] Verify binary compatibility
- [ ] Add feature flags if optional
- [ ] Update module re-exports in lib.rs

## Code Standards

### Rust Guidelines

- **Edition:** Rust 2024
- **MSRV:** 1.85+
- **Style:** `rustfmt` with default settings
- **Lints:** All Clippy warnings must be resolved

### Documentation Requirements

All public APIs must have:
- Summary documentation
- Example usage
- Links to relevant specifications (RFCs, CIPs, papers)
- Cardano compatibility notes (when applicable)

Example:
```rust
/// Generates a VRF proof for the given message.
///
/// This implements ECVRF-ED25519-SHA512-Elligator2 as specified in
/// [IETF VRF Draft-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03).
///
/// # Cardano Compatibility
///
/// This matches the VRF implementation in `cardano-crypto-praos` and is used
/// for slot leader election in the Praos consensus protocol.
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::vrf::{VrfDraft03, VrfAlgorithm};
///
/// let seed = [0u8; 32];
/// let sk = VrfDraft03::gen_key(&seed);
/// let (proof, output) = VrfDraft03::prove(&sk, b"message");
/// ```
pub fn prove(sk: &SigningKey, message: &[u8]) -> (Proof, Output) {
    // Implementation
}
```

## Testing

### Test Requirements

All new code must include:

1. **Unit Tests:** Test individual functions
2. **Golden Tests:** Verify against known outputs (when available)
3. **Property Tests:** Test invariants and properties
4. **Integration Tests:** Test cross-module interactions

### Running Tests

```bash
# Run all tests
just test

# Run with coverage
just test-coverage

# Run specific module tests
cargo test --test vrf_golden_tests

# Run benchmarks
just bench
```

## Release Process

### For Maintainers

1. **Update Version:**
   ```bash
   # Update version in Cargo.toml
   vim Cargo.toml
   ```

2. **Generate Changelog:**
   ```bash
   just changelog
   # Review and edit CHANGELOG.md
   ```

3. **Check API Compatibility:**
   ```bash
   just check-api breaking
   # Ensure no unexpected breaking changes
   ```

4. **Run Pre-release Checks:**
   ```bash
   just pre-release
   ```

5. **Create Release:**
   ```bash
   git tag -a v1.1.0 -m "Release v1.1.0"
   git push origin v1.1.0
   ```

6. **Automated Steps:**
   - CI runs all checks
   - Security scans execute
   - Package published to crates.io
   - GitHub Release created automatically
   - Documentation deployed to GitHub Pages

## Development Tools

### Recommended Tools

Install with `just install-dev-tools`:

- **cargo-audit:** Security vulnerability scanning
- **cargo-deny:** Dependency license and security checking
- **cargo-llvm-cov:** Code coverage measurement
- **cargo-semver-checks:** API compatibility verification
- **cargo-geiger:** Unsafe code detection
- **cargo-outdated:** Dependency version checking
- **cargo-public-api:** Public API surface tracking
- **git-cliff:** Changelog generation
- **just:** Modern task runner

### Workflow Scripts

Available in `.github/scripts/`:

- `check.sh` - Run all checks (like CI)
- `test.sh` - Test runner with coverage options
- `bench.sh` - Benchmark runner
- `validate-workflows.sh` - GitHub Actions validation
- `check-api.sh` - API compatibility checking

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests: `cargo test --all-features`
5. Run fmt: `cargo fmt`
6. Run clippy: `cargo clippy --all-features`
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

### PR Requirements
- All tests pass
- No clippy warnings
- Code is formatted with `cargo fmt`
- Documentation is updated
- CHANGELOG.md is updated

## Security

If you discover a security vulnerability, please email security@fractionestate.com instead of opening a public issue.

## Questions?

Open an issue or discussion on GitHub!

## License

By contributing, you agree that your contributions will be licensed under both MIT and Apache-2.0 licenses.
