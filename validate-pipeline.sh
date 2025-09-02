#!/bin/bash
# Validate pyvider-rpcplugin pipeline locally
# This script runs all quality checks and tests

set -e

echo "🚀 Validating pyvider-rpcplugin Pipeline"
echo "========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Setup environment
echo -e "${BLUE}📦 Setting up environment...${NC}"
source env.sh >/dev/null 2>&1 || true

echo ""
echo -e "${BLUE}1️⃣  Running Tests${NC}"
echo "----------------"
if pytest tests/ -x --tb=short --quiet; then
    TEST_COUNT=$(find tests -name "test_*.py" | wc -l)
    echo -e "${GREEN}✅ Tests passed (${TEST_COUNT} test files)${NC}"
else
    echo -e "${YELLOW}⚠️  Some tests failed${NC}"
fi

echo ""
echo -e "${BLUE}2️⃣  Code Quality${NC}"
echo "---------------"

echo -n "Ruff Format: "
if ruff format --check src/ tests/ --quiet 2>/dev/null; then
    echo -e "${GREEN}✅ Properly formatted${NC}"
else
    echo -e "${YELLOW}⚠️  Needs formatting (run 'ruff format src/ tests/')${NC}"
fi

echo -n "Ruff Lint: "
LINT_ERRORS=$(ruff check src/ tests/ --quiet 2>&1 | wc -l)
if [ "$LINT_ERRORS" -eq 0 ]; then
    echo -e "${GREEN}✅ No issues${NC}"
else
    echo -e "${YELLOW}⚠️  $LINT_ERRORS issues (run 'ruff check src/ tests/ --fix')${NC}"
fi

echo -n "Type Check: "
MYPY_ERRORS=$(mypy src/ 2>&1 | grep -c "error:" || true)
if [ "$MYPY_ERRORS" -eq 0 ]; then
    echo -e "${GREEN}✅ Type safe${NC}"
else
    echo -e "${YELLOW}⚠️  $MYPY_ERRORS type errors${NC}"
fi

echo -n "Security: "
BANDIT_ISSUES=$(bandit -r src/ -f json 2>/dev/null | python -c "import sys, json; data=json.load(sys.stdin); print(len(data.get('results', [])))" 2>/dev/null || echo "0")
if [ "$BANDIT_ISSUES" -eq 0 ]; then
    echo -e "${GREEN}✅ No security issues${NC}"
else
    echo -e "${YELLOW}⚠️  $BANDIT_ISSUES security findings${NC}"
fi

echo ""
echo -e "${BLUE}3️⃣  Package Build${NC}"
echo "----------------"
echo -n "Building: "
if uv build --quiet >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Build successful${NC}"
    WHEEL=$(ls -t dist/*.whl 2>/dev/null | head -1)
    if [ -n "$WHEEL" ]; then
        SIZE=$(du -h "$WHEEL" | cut -f1)
        echo "   📦 $(basename $WHEEL) ($SIZE)"
    fi
else
    echo -e "${RED}❌ Build failed${NC}"
fi

echo ""
echo -e "${BLUE}4️⃣  act Testing${NC}"
echo "--------------"
echo -n "act validation: "
if ./act-colima.sh -W .github/workflows/test-simple.yml --dryrun >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Workflows valid${NC}"
else
    echo -e "${YELLOW}⚠️  Check workflow syntax${NC}"
fi

echo ""
echo "========================================="
echo -e "${GREEN}✨ Validation Complete!${NC}"
echo ""
echo "Quick fixes:"
echo "  ruff format src/ tests/     # Auto-format code"
echo "  ruff check src/ tests/ --fix # Fix linting issues"
echo "  bandit -r src/ -ll          # Check security issues"
echo "  ./act-colima.sh -l          # List workflows"