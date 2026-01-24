#!/bin/bash
# API Compatibility Check Script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

cd "$PROJECT_ROOT"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "🔍 Checking API Compatibility..."
echo ""

# Check for cargo-public-api
if ! command -v cargo-public-api &> /dev/null; then
    echo -e "${YELLOW}⚠️  cargo-public-api not installed${NC}"
    echo "Install with: cargo install cargo-public-api --locked"
    echo ""
    exit 1
fi

# Parse arguments
MODE="${1:-diff}"
BASELINE="${2:-latest}"

case "$MODE" in
    "diff")
        echo -e "${BLUE}▶ Comparing API against $BASELINE${NC}"
        
        if [ "$BASELINE" = "latest" ]; then
            # Get latest tag
            LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
            if [ -z "$LATEST_TAG" ]; then
                echo -e "${YELLOW}No tags found, cannot compare${NC}"
                echo "Run with: $0 list"
                exit 0
            fi
            echo "Latest tag: $LATEST_TAG"
            
            # Check out tag, get API, return to current branch
            CURRENT_BRANCH=$(git branch --show-current)
            git checkout "$LATEST_TAG" 2>/dev/null || {
                echo -e "${RED}Failed to checkout tag${NC}"
                exit 1
            }
            
            cargo public-api > /tmp/api-baseline.txt
            
            git checkout "$CURRENT_BRANCH" 2>/dev/null
            
            # Get current API
            cargo public-api > /tmp/api-current.txt
            
            # Diff
            echo ""
            echo -e "${BLUE}API Changes:${NC}"
            if diff /tmp/api-baseline.txt /tmp/api-current.txt > /dev/null 2>&1; then
                echo -e "${GREEN}✓ No API changes detected${NC}"
            else
                diff -u /tmp/api-baseline.txt /tmp/api-current.txt || true
            fi
            
            # Cleanup
            rm -f /tmp/api-baseline.txt /tmp/api-current.txt
        else
            # Compare against specific baseline file
            if [ ! -f "$BASELINE" ]; then
                echo -e "${RED}Baseline file not found: $BASELINE${NC}"
                exit 1
            fi
            
            cargo public-api > /tmp/api-current.txt
            
            echo ""
            echo -e "${BLUE}API Changes:${NC}"
            if diff "$BASELINE" /tmp/api-current.txt > /dev/null 2>&1; then
                echo -e "${GREEN}✓ No API changes detected${NC}"
            else
                diff -u "$BASELINE" /tmp/api-current.txt || true
            fi
            
            rm -f /tmp/api-current.txt
        fi
        ;;
        
    "list")
        echo -e "${BLUE}▶ Listing current public API${NC}"
        cargo public-api
        ;;
        
    "save")
        OUTPUT="${2:-api-baseline.txt}"
        echo -e "${BLUE}▶ Saving current API to $OUTPUT${NC}"
        cargo public-api > "$OUTPUT"
        echo -e "${GREEN}✓ API saved to $OUTPUT${NC}"
        ;;
        
    "breaking")
        echo -e "${BLUE}▶ Checking for breaking changes${NC}"
        
        if ! command -v cargo-semver-checks &> /dev/null; then
            echo -e "${YELLOW}⚠️  cargo-semver-checks not installed${NC}"
            echo "Install with: cargo install cargo-semver-checks --locked"
            exit 1
        fi
        
        cargo semver-checks check-release
        ;;
        
    *)
        echo "Usage: $0 <mode> [baseline]"
        echo ""
        echo "Modes:"
        echo "  diff [baseline]  - Compare API (default: latest tag)"
        echo "  list             - List current public API"
        echo "  save [file]      - Save current API to file"
        echo "  breaking         - Check for breaking changes (uses cargo-semver-checks)"
        echo ""
        echo "Examples:"
        echo "  $0 diff                    # Compare against latest tag"
        echo "  $0 diff api-1.0.0.txt     # Compare against saved baseline"
        echo "  $0 list                    # Show current API"
        echo "  $0 save api-current.txt    # Save current API"
        echo "  $0 breaking                # Check for breaking changes"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}✅ API check complete!${NC}"
