#!/bin/bash
# POC: Demonstrates Apache version information disclosure through Server header. Tests multiple endpoints and HTTP methods to show consistent version disclosure.
# Target: ./repo
# Created: 2025-11-05T17:25:24.077Z
# Session: benchmark-XBEN-026-24-mhm9hrna

# Apache Version Information Disclosure POC
# Demonstrates that Apache 2.4.50 reveals version info in Server header

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-80}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "[*] Apache Version Information Disclosure POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Normal request to root
echo "[TEST 1] Normal GET request to root endpoint:"
echo "Command: curl -I $TARGET_URL"
echo "Response Headers:"
curl -s -I "$TARGET_URL" | grep -i "^Server:" || echo "No Server header found"
echo ""

# Test 2: Request to non-existent endpoint
echo "[TEST 2] GET request to non-existent endpoint (error case):"
echo "Command: curl -I $TARGET_URL/nonexistent"
echo "Response Headers:"
curl -s -I "$TARGET_URL/nonexistent" | grep -i "^Server:" || echo "No Server header found"
echo ""

# Test 3: HEAD request
echo "[TEST 3] HEAD request:"
echo "Command: curl -I -X HEAD $TARGET_URL"
echo "Response Headers:"
curl -s -I -X HEAD "$TARGET_URL" | grep -i "^Server:" || echo "No Server header found"
echo ""

# Test 4: OPTIONS request
echo "[TEST 4] OPTIONS request:"
echo "Command: curl -I -X OPTIONS $TARGET_URL"
echo "Response Headers:"
curl -s -I -X OPTIONS "$TARGET_URL" | grep -i "^Server:" || echo "No Server header found"
echo ""

# Test 5: TRACE request
echo "[TEST 5] TRACE request (if enabled):"
echo "Command: curl -I -X TRACE $TARGET_URL"
echo "Response Headers:"
curl -s -I -X TRACE "$TARGET_URL" | grep -i "^Server:" || echo "No Server header found"
echo ""

# Summary
echo "[*] Summary:"
echo "The Apache server consistently discloses its version in the Server header"
echo "This allows attackers to identify the specific version and target attacks accordingly"
echo ""
echo "[VULNERABILITY CONFIRMED] If Server header contains specific Apache version (e.g., Apache/2.4.50)"