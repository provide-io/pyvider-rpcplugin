#!/bin/bash
# Manual secret detection scan

echo "======================================================================"
echo "MANUAL SECRET DETECTION SCAN"
echo "======================================================================"

FOUND=0

# Check for common secret patterns
echo ""
echo "[1/10] Checking for API keys..."
if git grep -i "api[_-]key\s*=\s*['\"][^'\"]\{8,\}" -- '*.py' '*.md' '*.yml' '*.yaml' '*.json' '*.env' 2>/dev/null | grep -v "PLUGIN_MAGIC_COOKIE" | grep -v "example" | grep -v "your-api-key" | grep -v "test"; then
    echo "⚠️  Potential API keys found"
    ((FOUND++))
else
    echo "✅ No API keys found"
fi

echo ""
echo "[2/10] Checking for passwords..."
if git grep -iE "password\s*=\s*['\"][^'\"]{3,}" -- '*.py' '*.md' '*.yml' '*.yaml' '*.json' '*.env' 2>/dev/null | grep -v "PLUGIN_MAGIC_COOKIE" | grep -v "example" | grep -v "your-password" | grep -v "PASSWORD" | grep -v "test" | grep -v "docs/"; then
    echo "⚠️  Potential passwords found"
    ((FOUND++))
else
    echo "✅ No passwords found"
fi

echo ""
echo "[3/10] Checking for AWS credentials..."
if git grep -E "AKIA[0-9A-Z]{16}" 2>/dev/null; then
    echo "⚠️  AWS access keys found"
    ((FOUND++))
else
    echo "✅ No AWS credentials found"
fi

echo ""
echo "[4/10] Checking for private keys..."
if git grep -l "BEGIN.*PRIVATE KEY" 2>/dev/null | grep -v "keys/README.md" | grep -v ".md"; then
    echo "⚠️  Private keys found"
    ((FOUND++))
else
    echo "✅ No private keys found"
fi

echo ""
echo "[5/10] Checking for tokens..."
if git grep -iE "token\s*=\s*['\"][a-zA-Z0-9_-]{20,}" -- '*.py' '*.yml' '*.yaml' '*.json' 2>/dev/null | grep -v "PLUGIN_MAGIC_COOKIE" | grep -v "example" | grep -v "test"; then
    echo "⚠️  Potential tokens found"
    ((FOUND++))
else
    echo "✅ No tokens found"
fi

echo ""
echo "[6/10] Checking for database URLs..."
if git grep -iE "(postgres|mysql|mongodb)://[^'\"\s]+" -- '*.py' '*.yml' '*.yaml' '*.json' '*.env' 2>/dev/null | grep -v "example" | grep -v "localhost" | grep -v "test"; then
    echo "⚠️  Potential database URLs found"
    ((FOUND++))
else
    echo "✅ No database URLs found"
fi

echo ""
echo "[7/10] Checking for GitHub tokens..."
if git grep -E "gh[pousr]_[A-Za-z0-9_]{36,}" 2>/dev/null; then
    echo "⚠️  GitHub tokens found"
    ((FOUND++))
else
    echo "✅ No GitHub tokens found"
fi

echo ""
echo "[8/10] Checking for Slack tokens..."
if git grep -E "xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}" 2>/dev/null; then
    echo "⚠️  Slack tokens found"
    ((FOUND++))
else
    echo "✅ No Slack tokens found"
fi

echo ""
echo "[9/10] Checking for generic secrets (high entropy strings)..."
# Look for suspicious high-entropy strings (base64-like)
if git grep -E "['\"][A-Za-z0-9+/]{40,}={0,2}['\"]" -- '*.py' 2>/dev/null | grep -v "test" | grep -v "example" | grep -v "docs/" | grep -v "pb2" | head -5; then
    echo "ℹ️  High entropy strings found (may be legitimate base64)"
    # Don't count as found - could be legitimate
else
    echo "✅ No suspicious high entropy strings"
fi

echo ""
echo "[10/10] Checking .env and config files for secrets..."
if find . -name ".env*" -o -name "*.env" -o -name "secrets.*" 2>/dev/null | grep -v ".venv" | grep -v "node_modules"; then
    echo "⚠️  Environment/secret files found (checking if committed)..."
    if git ls-files | grep -E "\.env|secrets\."; then
        echo "❌ Secret files are committed!"
        ((FOUND++))
    else
        echo "✅ Secret files are gitignored (not committed)"
    fi
else
    echo "✅ No secret files found"
fi

echo ""
echo "======================================================================"
if [ $FOUND -eq 0 ]; then
    echo "✅ NO SECRETS DETECTED - Repository is clean"
    echo "======================================================================"
    exit 0
else
    echo "⚠️  POTENTIAL SECRETS FOUND - Review required"
    echo "======================================================================"
    exit 1
fi
