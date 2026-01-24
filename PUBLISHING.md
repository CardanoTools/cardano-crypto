# Publishing Guide for Cardano-Crypto

This document describes the process for publishing the `cardano-crypto` crate to crates.io.

## Prerequisites

1. **Crates.io Account**
   - Create an account at [crates.io](https://crates.io/)
   - Generate an API token at https://crates.io/settings/tokens
   - Store the token securely

2. **GitHub Repository Secrets**
   - Go to repository Settings → Secrets and variables → Actions
   - Add a new repository secret named `CARGO_REGISTRY_TOKEN`
   - Paste your crates.io API token as the value

## Publishing Process

### 1. Pre-Release Checklist

- [ ] All tests passing (run `cargo test --all-features`)
- [ ] Zero compiler warnings (run `cargo build --release`)
- [ ] Zero clippy warnings (run `cargo clippy --all-targets --all-features`)
- [ ] Documentation builds successfully (run `cargo doc --all-features --no-deps`)
- [ ] CHANGELOG.md updated with version changes
- [ ] README.md updated with current version
- [ ] Cargo.toml version bumped following semantic versioning

### 2. Version Bump

Update version in `Cargo.toml`:

```toml
[package]
version = "1.1.0"  # Current version
```

Follow [Semantic Versioning](https://semver.org/):
- **MAJOR** version for incompatible API changes
- **MINOR** version for backwards-compatible functionality additions
- **PATCH** version for backwards-compatible bug fixes

### 3. Local Verification

```bash
# Clean build
cargo clean

# Build and test all features
cargo build --all-features
cargo test --all-features

# Verify package contents
cargo package --list

# Do a dry-run publish
cargo publish --dry-run
```

### 4. Create Release Tag

```bash
# Commit version changes
git add Cargo.toml CHANGELOG.md README.md
git commit -m "Release v1.2.0"  # Example for next release

# Create and push tag
git tag -a v1.2.0 -m "Release version 1.2.0"
git push origin main
git push origin v1.2.0
```

### 5. Automatic Publishing

Once you push the tag, GitHub Actions will:
1. Verify the tag matches Cargo.toml version
2. Run all tests
3. Build release binaries
4. Publish to crates.io using `CARGO_REGISTRY_TOKEN`
5. Create a GitHub Release with auto-generated notes

### 6. Manual Publishing (Alternative)

If you need to publish manually:

```bash
# Set your token (only needed once)
cargo login

# Publish to crates.io
cargo publish
```

## Post-Release

After successful publication:

1. **Verify on crates.io**
   - Visit https://crates.io/crates/cardano-crypto
   - Check that the new version appears
   - Verify documentation at https://docs.rs/cardano-crypto

2. **Announce the Release**
   - Update repository README with new version badge
   - Post announcement in relevant Cardano developer channels
   - Update any dependent projects

3. **Monitor**
   - Check GitHub Discussions for feedback
   - Monitor Issues for bug reports
   - Review download statistics on crates.io

## Troubleshooting

### "crate name already exists"
- The crate name is already taken. Choose a different name in Cargo.toml.

### "Authentication token is invalid"
- Your CARGO_REGISTRY_TOKEN may be expired or incorrect
- Generate a new token at https://crates.io/settings/tokens
- Update the GitHub secret

### "version already uploaded"
- You cannot republish the same version
- Bump the version number in Cargo.toml
- Create a new git tag

### "some files are not tracked by git"
- Ensure all necessary files are committed
- Check .gitignore isn't excluding required files
- Use `cargo package --list` to verify included files

## Continuous Integration

The repository includes several CI workflows:

- **ci.yml**: Main CI pipeline (test, clippy, fmt, docs, coverage)
- **publish.yml**: Automatic publishing to crates.io on tags
- **nightly.yml**: Nightly builds and Miri testing
- **dependencies.yml**: Dependency audit and update checks

All workflows run automatically on push/PR to main branch.

## Release Cadence

- **Patch releases**: As needed for bug fixes
- **Minor releases**: Monthly or when significant features are added
- **Major releases**: Only for breaking API changes (avoid if possible)

## Support

For questions or issues with publishing:
- Open an issue at https://github.com/FractionEstate/Cardano-KES/issues
- Contact the maintainers via the repository
