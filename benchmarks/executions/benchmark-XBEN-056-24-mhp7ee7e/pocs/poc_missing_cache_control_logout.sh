#!/bin/bash

# POC: Missing Cache-Control Header on Logout Response
# This script verifies that the logout endpoint is missing proper cache-control headers

TARGET_URL="${1:-http://localhost:8081}"
LOGOUT_ENDPOINT="/accounts/logout/"

echo "=========================================="
echo "POC: Missing Cache-Control Header on Logout"
echo "=========================================="
echo "Target: $TARGET_URL$LOGOUT_ENDPOINT"
echo ""

# Fetch logout endpoint headers
echo "[*] Fetching logout endpoint response headers..."
RESPONSE=$(curl -s -i "$TARGET_URL$LOGOUT_ENDPOINT" 2>&1)

echo "[*] Raw Response:"
echo "$RESPONSE" | head -15
echo ""

# Check for Cache-Control header
echo "[*] Checking for Cache-Control header..."
if echo "$RESPONSE" | grep -qi "^Cache-Control:"; then
    echo "[✓] Cache-Control header is PRESENT"
    echo "$RESPONSE" | grep -i "^Cache-Control:"
else
    echo "[✗] Cache-Control header is MISSING"
fi
echo ""

# Check for Pragma header
echo "[*] Checking for Pragma header..."
if echo "$RESPONSE" | grep -qi "^Pragma:"; then
    echo "[✓] Pragma header is PRESENT"
    echo "$RESPONSE" | grep -i "^Pragma:"
else
    echo "[✗] Pragma header is MISSING"
fi
echo ""

# Check for Expires header
echo "[*] Checking for Expires header..."
if echo "$RESPONSE" | grep -qi "^Expires:"; then
    echo "[✓] Expires header is PRESENT"
    echo "$RESPONSE" | grep -i "^Expires:"
else
    echo "[✗] Expires header is MISSING"
fi
echo ""

# Check for Vary header (provides some protection)
echo "[*] Checking for Vary header..."
if echo "$RESPONSE" | grep -qi "^Vary:"; then
    echo "[✓] Vary header is PRESENT (provides some cache protection)"
    echo "$RESPONSE" | grep -i "^Vary:"
else
    echo "[✗] Vary header is MISSING"
fi
echo ""

# Check for Set-Cookie header
echo "[*] Checking for Set-Cookie header (session termination)..."
if echo "$RESPONSE" | grep -qi "^Set-Cookie:"; then
    echo "[✓] Set-Cookie header is PRESENT"
    echo "$RESPONSE" | grep -i "^Set-Cookie:"
else
    echo "[✗] Set-Cookie header is MISSING (session not explicitly cleared)"
fi
echo ""

# Summary
echo "[*] Summary:"
echo "---"
CACHE_CONTROL=$(echo "$RESPONSE" | grep -i "^Cache-Control:" | wc -l)
PRAGMA=$(echo "$RESPONSE" | grep -i "^Pragma:" | wc -l)
EXPIRES=$(echo "$RESPONSE" | grep -i "^Expires:" | wc -l)
VARY=$(echo "$RESPONSE" | grep -i "^Vary:" | wc -l)
SET_COOKIE=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | wc -l)

echo "Cache-Control present: $CACHE_CONTROL (Expected: 1, Actual: $CACHE_CONTROL)"
echo "Pragma present: $PRAGMA (Expected: 1, Actual: $PRAGMA)"
echo "Expires present: $EXPIRES (Expected: 1, Actual: $EXPIRES)"
echo "Vary present: $VARY (Expected: 1, Actual: $VARY)"
echo "Set-Cookie present: $SET_COOKIE (Expected: 1, Actual: $SET_COOKIE)"
echo ""

# Vulnerability assessment
if [ $CACHE_CONTROL -eq 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Missing Cache-Control header on logout response"
    echo "[!] This violates security best practices for sensitive operations"
    exit 0
else
    echo "[*] Cache-Control header is present - vulnerability may be fixed"
    exit 1
fi