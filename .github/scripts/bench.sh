#!/bin/bash
# Benchmark script - runs performance benchmarks
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

cd "$PROJECT_ROOT"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo "📊 Running benchmarks..."
echo ""

# Parse arguments
BASELINE=""
COMPARE=false
SAVE=false
NAME=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --baseline)
            BASELINE="$2"
            shift 2
            ;;
        --compare)
            COMPARE=true
            shift
            ;;
        --save)
            SAVE=true
            NAME="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--baseline <name>] [--compare] [--save <name>]"
            exit 1
            ;;
    esac
done

# Run benchmarks
if [ ! -z "$BASELINE" ]; then
    echo -e "${BLUE}Running benchmarks against baseline: $BASELINE${NC}"
    cargo bench --all-features -- --baseline "$BASELINE"
elif [ "$COMPARE" == true ]; then
    echo -e "${BLUE}Running benchmarks with comparison to baseline${NC}"
    cargo bench --all-features
elif [ "$SAVE" == true ]; then
    echo -e "${BLUE}Running benchmarks and saving as: $NAME${NC}"
    cargo bench --all-features -- --save-baseline "$NAME"
else
    echo -e "${BLUE}Running benchmarks...${NC}"
    cargo bench --all-features
fi

echo ""
echo -e "${GREEN}✓ Benchmarks complete${NC}"
echo ""
echo "Results are saved in: target/criterion/"
echo "View HTML report: target/criterion/report/index.html"
