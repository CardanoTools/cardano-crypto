# Justfile - Modern command runner for cardano-crypto
# Install: cargo install just
# Usage: just <recipe>
# List all recipes: just --list

# Default recipe (runs when you type 'just')
default:
    @just --list

# Run all checks (format, clippy, tests, docs)
check:
    @echo "🔍 Running all checks..."
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --all-features
    cargo doc --all-features --no-deps

# Quick check (format and clippy only)
quick-check:
    @echo "⚡ Running quick checks..."
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings

# Format code
fmt:
    cargo fmt --all

# Run clippy
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

# Run tests
test *FLAGS:
    cargo test --all-features {{FLAGS}}

# Run tests with coverage
test-coverage:
    #!/usr/bin/env bash
    if command -v cargo-llvm-cov &> /dev/null; then
        cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
        cargo llvm-cov report --summary-only
    else
        echo "❌ cargo-llvm-cov not installed"
        echo "Install with: cargo install cargo-llvm-cov"
        exit 1
    fi

# Run benchmarks
bench *FLAGS:
    cargo bench --all-features {{FLAGS}}

# Build documentation
docs:
    cargo doc --all-features --no-deps --document-private-items --open

# Build release
build-release:
    cargo build --release --all-features

# Clean build artifacts
clean:
    cargo clean

# Update dependencies
update:
    cargo update

# Security audit
audit:
    cargo audit

# Dependency check with cargo-deny
deny:
    cargo deny check

# Check minimal versions
minimal-versions:
    cargo +nightly -Z minimal-versions check --all-features

# Run all security checks
security:
    @echo "🔒 Running security checks..."
    cargo audit
    cargo deny check
    cargo geiger || echo "⚠️  cargo-geiger not installed"

# Install development tools
install-dev-tools:
    @echo "📦 Installing development tools..."
    cargo install cargo-audit
    cargo install cargo-deny
    cargo install cargo-llvm-cov
    cargo install cargo-semver-checks
    cargo install cargo-geiger
    cargo install cargo-outdated
    cargo install cargo-public-api
    cargo install git-cliff
    cargo install just
    @echo "✅ Development tools installed!"

# Check for outdated dependencies
outdated:
    cargo outdated

# Check API compatibility
check-api MODE="diff" BASELINE="latest":
    ./.github/scripts/check-api.sh {{MODE}} {{BASELINE}}

# Save current API as baseline
save-api FILE="api-baseline.txt":
    ./.github/scripts/check-api.sh save {{FILE}}

# Generate changelog
changelog:
    #!/usr/bin/env bash
    if command -v git-cliff &> /dev/null; then
        git-cliff --output CHANGELOG.md
        echo "✅ Changelog generated!"
    else
        echo "❌ git-cliff not installed"
        echo "Install with: cargo install git-cliff"
        exit 1
    fi

# Generate changelog for unreleased changes
changelog-unreleased:
    #!/usr/bin/env bash
    if command -v git-cliff &> /dev/null; then
        git-cliff --unreleased
    else
        echo "❌ git-cliff not installed"
        exit 1
    fi

# Prepare for release (all checks)
pre-release: check test-coverage security changelog
    @echo "✅ Ready for release!"

# CI simulation (run what CI runs)
ci: check test-coverage docs audit
    @echo "✅ CI simulation complete!"
