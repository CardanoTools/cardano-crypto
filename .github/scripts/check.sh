#!/bin/bash
# Development check script - runs all checks locally matching CI
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

cd "$PROJECT_ROOT"

echo "🔍 Running development checks..."
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

run_check() {
    echo -e "${BLUE}▶ $1${NC}"
    if eval "$2"; then
        echo -e "${GREEN}✓ $1 passed${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}✗ $1 failed${NC}"
        echo ""
        return 1
    fi
}

# Format check
run_check "Format check" "cargo fmt --all -- --check"

# Clippy
run_check "Clippy (all features)" "cargo clippy --all-targets --all-features -- -D warnings"

# Build
run_check "Build (all features)" "cargo build --all-features"

# Tests
run_check "Tests (all features)" "cargo test --all-features"

# Documentation
run_check "Documentation build" "cargo doc --all-features --no-deps"

# Security audit (non-blocking)
if command -v cargo-audit &> /dev/null; then
    run_check "Security audit" "cargo audit" || echo "⚠️  Security issues found (non-blocking)"
else
    echo "⚠️  cargo-audit not installed, skipping security check"
    echo "   Install with: cargo install cargo-audit"
fi

# cargo-deny (non-blocking)
if command -v cargo-deny &> /dev/null; then
    run_check "Dependency check (cargo-deny)" "cargo deny check" || echo "⚠️  Dependency issues found (non-blocking)"
else
    echo "⚠️  cargo-deny not installed, skipping dependency check"
    echo "   Install with: cargo install cargo-deny"
fi

echo -e "${GREEN}✅ All checks passed!${NC}"
echo ""
echo "You can now commit and push your changes."
