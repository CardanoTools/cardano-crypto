#!/bin/bash
# Test script - runs all tests with various configurations
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

cd "$PROJECT_ROOT"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo "🧪 Running test suite..."
echo ""

# Parse arguments
COVERAGE=false
FEATURES="all"
NOCAPTURE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --coverage)
            COVERAGE=true
            shift
            ;;
        --features)
            FEATURES="$2"
            shift 2
            ;;
        --nocapture)
            NOCAPTURE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--coverage] [--features <features>] [--nocapture]"
            exit 1
            ;;
    esac
done

# Build feature flags
if [ "$FEATURES" == "all" ]; then
    FEATURE_FLAGS="--all-features"
elif [ "$FEATURES" == "none" ]; then
    FEATURE_FLAGS="--no-default-features"
else
    FEATURE_FLAGS="--no-default-features --features $FEATURES"
fi

# Add nocapture flag
if [ "$NOCAPTURE" == true ]; then
    TEST_FLAGS="-- --nocapture"
else
    TEST_FLAGS=""
fi

# Run tests
if [ "$COVERAGE" == true ]; then
    echo -e "${BLUE}Running tests with coverage...${NC}"
    
    if command -v cargo-llvm-cov &> /dev/null; then
        cargo llvm-cov $FEATURE_FLAGS --workspace --lcov --output-path lcov.info
        cargo llvm-cov report --summary-only
        echo ""
        echo -e "${GREEN}✓ Coverage report generated: lcov.info${NC}"
    elif command -v cargo-tarpaulin &> /dev/null; then
        cargo tarpaulin $FEATURE_FLAGS --workspace --timeout 300 --out Lcov
        echo ""
        echo -e "${GREEN}✓ Coverage report generated: lcov.info${NC}"
    else
        echo -e "${YELLOW}⚠️  No coverage tool installed${NC}"
        echo "Install cargo-llvm-cov: cargo install cargo-llvm-cov"
        echo "Or cargo-tarpaulin: cargo install cargo-tarpaulin"
        echo ""
        echo "Falling back to regular tests..."
        cargo test $FEATURE_FLAGS $TEST_FLAGS
    fi
else
    echo -e "${BLUE}Running tests...${NC}"
    cargo test $FEATURE_FLAGS $TEST_FLAGS
fi

echo ""
echo -e "${GREEN}✅ All tests passed!${NC}"
