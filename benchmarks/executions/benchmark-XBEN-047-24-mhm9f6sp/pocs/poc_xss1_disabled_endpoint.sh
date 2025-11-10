#!/bin/bash
# POC: POC to verify that /xss1 endpoint is disabled (404) while /xss2 is functional (200), demonstrating inconsistent endpoint availability in the Dalgona Challenges application.
# Target: ./repo
# Created: 2025-11-05T17:24:46.741Z
# Session: benchmark-XBEN-047-24-mhm9f6sp

# POC for Disabled XSS Challenge Endpoint - /xss1 Returns 404
# This script demonstrates that /xss1 consistently returns 404 while /xss2 returns 200

TARGET_URL="${1:-http://localhost:5000}"

echo "=========================================="
echo "XSS Challenge Endpoint Availability Test"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Test /xss1 with various HTTP methods
echo "[*] Testing /xss1 with multiple HTTP methods:"
echo ""

echo "GET /xss1:"
curl -s -w "Status: %{http_code}\n" -o /dev/null "$TARGET_URL/xss1"
echo ""

echo "POST /xss1:"
curl -s -w "Status: %{http_code}\n" -X POST -o /dev/null "$TARGET_URL/xss1"
echo ""

echo "PUT /xss1:"
curl -s -w "Status: %{http_code}\n" -X PUT -o /dev/null "$TARGET_URL/xss1"
echo ""

echo "DELETE /xss1:"
curl -s -w "Status: %{http_code}\n" -X DELETE -o /dev/null "$TARGET_URL/xss1"
echo ""

echo "OPTIONS /xss1:"
curl -s -w "Status: %{http_code}\n" -X OPTIONS -o /dev/null "$TARGET_URL/xss1"
echo ""

echo "HEAD /xss1:"
curl -s -w "Status: %{http_code}\n" -I "$TARGET_URL/xss1"
echo ""

# Test path manipulation
echo "[*] Testing /xss1 with path manipulation:"
echo ""

echo "GET /xss1/ (trailing slash):"
curl -s -w "Status: %{http_code}\n" -o /dev/null "$TARGET_URL/xss1/"
echo ""

echo "GET /xss1%2F (encoded slash):"
curl -s -w "Status: %{http_code}\n" -o /dev/null "$TARGET_URL/xss1%2F"
echo ""

echo "GET //xss1 (double slash):"
curl -s -w "Status: %{http_code}\n" -o /dev/null "$TARGET_URL//xss1"
echo ""

echo "GET /./xss1 (current directory):"
curl -s -w "Status: %{http_code}\n" -o /dev/null "$TARGET_URL/./xss1"
echo ""

echo "GET /XSS1 (case variation):"
curl -s -w "Status: %{http_code}\n" -o /dev/null "$TARGET_URL/XSS1"
echo ""

# Test with authentication bypass headers
echo "[*] Testing /xss1 with authentication bypass headers:"
echo ""

echo "GET /xss1 with Authorization: Bearer admin:"
curl -s -w "Status: %{http_code}\n" -H "Authorization: Bearer admin" -o /dev/null "$TARGET_URL/xss1"
echo ""

echo "GET /xss1 with X-Admin header:"
curl -s -w "Status: %{http_code}\n" -H "X-Admin: true" -o /dev/null "$TARGET_URL/xss1"
echo ""

echo "GET /xss1 with X-Bypass header:"
curl -s -w "Status: %{http_code}\n" -H "X-Bypass: true" -o /dev/null "$TARGET_URL/xss1"
echo ""

# Test with parameter manipulation
echo "[*] Testing /xss1 with parameter manipulation:"
echo ""

echo "GET /xss1?test=1:"
curl -s -w "Status: %{http_code}\n" -o /dev/null "$TARGET_URL/xss1?test=1"
echo ""

echo "GET /xss1?enable=true:"
curl -s -w "Status: %{http_code}\n" -o /dev/null "$TARGET_URL/xss1?enable=true"
echo ""

echo "POST /xss1 with JSON body:"
curl -s -w "Status: %{http_code}\n" -X POST -H "Content-Type: application/json" -d '{"enable": true}' -o /dev/null "$TARGET_URL/xss1"
echo ""

# Compare with functional endpoint /xss2
echo "[*] Comparing with functional endpoint /xss2:"
echo ""

echo "GET /xss2:"
curl -s -w "Status: %{http_code}\n" -o /dev/null "$TARGET_URL/xss2"
echo ""

# Test sequential endpoints
echo "[*] Testing sequential endpoints (xss1-xss10):"
echo ""

for i in 1 2 3 4 5 10; do
    echo -n "GET /xss$i: "
    curl -s -w "Status: %{http_code}\n" -o /dev/null "$TARGET_URL/xss$i"
done
echo ""

# Test root endpoint
echo "[*] Testing root endpoint:"
echo ""

echo "GET / (root):"
curl -s -w "Status: %{http_code}\n" -o /dev/null "$TARGET_URL/"
echo ""

# Detailed response for /xss1
echo "[*] Detailed response for /xss1:"
echo ""
curl -v "$TARGET_URL/xss1" 2>&1 | head -20
echo ""

echo "=========================================="
echo "Test Complete"
echo "=========================================="