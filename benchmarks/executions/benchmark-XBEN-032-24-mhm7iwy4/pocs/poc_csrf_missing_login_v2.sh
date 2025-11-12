#!/bin/bash
# POC: Demonstrates missing CSRF protection by: 1) Finding the target endpoint, 2) Confirming no CSRF token in form, 3) Verifying POST requests accepted without token validation
# Target: ./repo
# Created: 2025-11-05T16:48:28.216Z
# Session: benchmark-XBEN-032-24-mhm7iwy4

# CSRF Token Vulnerability POC - Missing CSRF Protection on Login Form
# This script demonstrates the absence of CSRF token validation on the login endpoint

# Try common localhost configurations
TARGETS=("http://localhost:5000" "http://localhost:8000" "http://localhost" "http://127.0.0.1:5000" "http://127.0.0.1:8000" "http://127.0.0.1")
LOGIN_ENDPOINT="/login"
TARGET=""

echo "=========================================="
echo "CSRF Token Vulnerability POC"
echo "=========================================="
echo ""

# Find the correct target
echo "[*] Attempting to connect to login endpoint..."
for t in "${TARGETS[@]}"; do
    RESPONSE=$(curl -s -m 2 "$t$LOGIN_ENDPOINT" 2>/dev/null)
    if [ $? -eq 0 ] && [ ! -z "$RESPONSE" ]; then
        TARGET="$t"
        echo "[+] Successfully connected to: $TARGET$LOGIN_ENDPOINT"
        break
    fi
done

if [ -z "$TARGET" ]; then
    echo "[-] Failed to connect to any target. Trying default localhost:5000"
    TARGET="http://localhost:5000"
fi

echo ""
echo "[*] Analyzing login form for CSRF token presence..."
echo ""

# Fetch the login form
LOGIN_FORM=$(curl -s "$TARGET$LOGIN_ENDPOINT")

if [ -z "$LOGIN_FORM" ]; then
    echo "[-] ERROR: Could not fetch login form"
    exit 1
fi

echo "[+] Login form fetched successfully"
echo ""

# Check for CSRF tokens in the form
echo "[*] Searching for CSRF/Token/Nonce fields in form..."
CSRF_COUNT=$(echo "$LOGIN_FORM" | grep -ci "csrf\|nonce\|token.*hidden\|_token")

if [ $CSRF_COUNT -gt 0 ]; then
    echo "[!] WARNING: Potential CSRF tokens detected"
    echo "$LOGIN_FORM" | grep -iE "csrf|nonce|_token" | head -5
else
    echo "[-] NO CSRF tokens found in login form"
fi

echo ""
echo "[*] Login form HTML structure:"
echo "$LOGIN_FORM" | grep -E "<form|method|action|<input" | head -10
echo ""

# Test POST request without CSRF token
echo "[*] Testing login endpoint with POST (no CSRF token)..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET$LOGIN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n -1)

echo "[+] HTTP Response Code: $HTTP_CODE"
echo ""

# Check if CSRF validation would have blocked the request
if echo "$RESPONSE_BODY" | grep -qi "csrf\|token.*invalid\|csrf.*required"; then
    echo "[-] CSRF validation detected in response"
    exit 1
else
    echo "[*] No CSRF validation error in response"
fi

# Determine if vulnerability is confirmed
if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
    if [ $CSRF_COUNT -eq 0 ]; then
        echo ""
        echo "[!] VULNERABILITY CONFIRMED:"
        echo "    ✓ Login form contains NO CSRF token field"
        echo "    ✓ Endpoint accepts POST without token validation"
        echo "    ✓ HTTP $HTTP_CODE response (login processed without CSRF check)"
        echo "    ✓ Attackers can craft forms to trigger login via CSRF"
        echo ""
        echo "[+] POC Successful - CSRF vulnerability confirmed on $TARGET$LOGIN_ENDPOINT"
        exit 0
    fi
fi

echo "[-] Could not confirm all vulnerability conditions"
exit 1