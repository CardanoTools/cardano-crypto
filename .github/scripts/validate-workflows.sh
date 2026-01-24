#!/bin/bash
# Workflow Testing and Validation Script
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

echo "🧪 Validating GitHub Actions Workflows..."
echo ""

# Check for actionlint
if ! command -v actionlint &> /dev/null; then
    echo -e "${YELLOW}⚠️  actionlint not installed${NC}"
    echo "Install with: go install github.com/rhysd/actionlint/cmd/actionlint@latest"
    echo "Or: brew install actionlint (macOS)"
    echo ""
    echo "Skipping workflow validation..."
else
    echo -e "${BLUE}▶ Validating workflow files with actionlint${NC}"
    if actionlint; then
        echo -e "${GREEN}✓ All workflows are valid${NC}"
    else
        echo -e "${RED}✗ Workflow validation failed${NC}"
        exit 1
    fi
fi

echo ""
echo -e "${BLUE}▶ Checking workflow file syntax${NC}"

# Check YAML syntax
for file in .github/workflows/*.yml; do
    if [ -f "$file" ]; then
        echo "  Checking $file..."
        # Basic YAML validation (requires python with PyYAML)
        if command -v python3 &> /dev/null; then
            python3 -c "import yaml; yaml.safe_load(open('$file'))" 2>/dev/null
            if [ $? -eq 0 ]; then
                echo -e "    ${GREEN}✓${NC} Valid YAML"
            else
                echo -e "    ${RED}✗${NC} Invalid YAML"
                exit 1
            fi
        fi
    fi
done

echo ""
echo -e "${BLUE}▶ Checking required secrets${NC}"

REQUIRED_SECRETS=(
    "CARGO_REGISTRY_TOKEN"
    "CODECOV_TOKEN"
    "GITHUB_TOKEN"
)

echo "Required secrets for workflows:"
for secret in "${REQUIRED_SECRETS[@]}"; do
    echo "  - $secret"
done

echo ""
echo -e "${BLUE}▶ Checking workflow triggers${NC}"

echo "Workflows with push triggers:"
grep -r "on:" .github/workflows/*.yml | grep -A 5 "push:" | grep "branches:" | sort -u || echo "  None"

echo ""
echo "Workflows with PR triggers:"
grep -r "on:" .github/workflows/*.yml | grep -A 5 "pull_request:" | grep "branches:" | sort -u || echo "  None"

echo ""
echo "Workflows with schedule triggers:"
grep -r "schedule:" .github/workflows/*.yml -A 2 || echo "  None"

echo ""
echo -e "${BLUE}▶ Workflow summary${NC}"

WORKFLOW_COUNT=$(ls -1 .github/workflows/*.yml 2>/dev/null | wc -l)
echo "Total workflows: $WORKFLOW_COUNT"

echo ""
echo "Workflow files:"
ls -1 .github/workflows/*.yml 2>/dev/null | while read file; do
    name=$(basename "$file" .yml)
    jobs=$(grep "^  [a-zA-Z].*:" "$file" | grep -v "^  on:" | wc -l)
    echo "  - $name ($jobs jobs)"
done

echo ""
echo -e "${GREEN}✅ Workflow validation complete!${NC}"
echo ""
echo "To test workflows locally, you can use 'act': https://github.com/nektos/act"
echo "  Install: brew install act (macOS) or see GitHub releases"
echo ""
echo "Examples:"
echo "  act -l                  # List all jobs"
echo "  act -j test            # Run the 'test' job"
echo "  act pull_request       # Simulate a pull request event"
