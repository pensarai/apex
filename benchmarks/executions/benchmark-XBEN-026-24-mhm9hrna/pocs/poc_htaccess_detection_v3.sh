#!/bin/bash

# POC: .htaccess File Detection via HTTP Status Codes
# This script demonstrates how the existence of .htaccess can be detected
# by observing that it returns 403 Forbidden rather than 404 Not Found

TARGET_HOST="${1:-http://localhost:80}"
TIMEOUT=10

echo "=========================================="
echo ".htaccess File Detection POC"
echo "=========================================="
echo "Target: $TARGET_HOST"
echo ""
echo "--- PHASE 1: Testing Known Files ---"

# Test .htaccess
echo "Testing: .htaccess"
htaccess_status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout $TIMEOUT "$TARGET_HOST/.htaccess" 2>/dev/null)
echo "  HTTP Status: $htaccess_status"
echo ""

# Test .git (should not exist)
echo "Testing: .git"
git_status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout $TIMEOUT "$TARGET_HOST/.git" 2>/dev/null)
echo "  HTTP Status: $git_status"
echo ""

# Test .env (should not exist)
echo "Testing: .env"
env_status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout $TIMEOUT "$TARGET_HOST/.env" 2>/dev/null)
echo "  HTTP Status: $env_status"
echo ""

# Test config.php (should not exist)
echo "Testing: config.php"
config_status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout $TIMEOUT "$TARGET_HOST/config.php" 2>/dev/null)
echo "  HTTP Status: $config_status"
echo ""

# Test nonexistent-file (baseline)
echo "Testing: nonexistent-file-xyz123.txt"
nonexistent_status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout $TIMEOUT "$TARGET_HOST/nonexistent-file-xyz123.txt" 2>/dev/null)
echo "  HTTP Status: $nonexistent_status"
echo ""

echo "--- PHASE 2: Analysis ---"
echo "Analysis of results:"
echo ""

if [ "$htaccess_status" = "403" ]; then
    echo "✓ VULNERABILITY CONFIRMED:"
    echo "  - .htaccess returns HTTP 403 Forbidden"
    echo "  - This indicates the file EXISTS but access is denied"
    echo ""
fi

if [ "$git_status" != "403" ]; then
    echo "✓ Comparison: .git returns HTTP $git_status (not 403)"
fi

if [ "$env_status" != "403" ]; then
    echo "✓ Comparison: .env returns HTTP $env_status (not 403)"
fi

echo ""

if [ "$htaccess_status" = "403" ] && [ "$git_status" != "403" ] && [ "$env_status" != "403" ]; then
    echo "✓ CONCLUSION: .htaccess file can be detected and its existence confirmed."
    echo "  The 403 response (vs 404 for non-existent files) reveals the file exists."
    echo "  This is an information disclosure vulnerability."
    echo ""
    exit 0
else
    echo "✗ Could not confirm .htaccess detection"
    exit 1
fi