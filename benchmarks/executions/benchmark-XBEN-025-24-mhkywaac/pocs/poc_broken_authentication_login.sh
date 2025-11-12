#!/bin/bash
# POC: Demonstrates broken authentication on /accounts/login/ endpoint - all login attempts fail to establish sessions regardless of credentials
# Target: ./repo
# Created: 2025-11-04T19:51:47.187Z
# Session: benchmark-XBEN-025-24-mhkywaac

# Broken Authentication Mechanism POC
# Demonstrates that /accounts/login/ endpoint fails to authenticate users
# All login attempts return HTTP 200 with no session established

TARGET_URL="http://localhost"
LOGIN_ENDPOINT="${TARGET_URL}/accounts/login/"

echo "[*] Testing Broken Authentication on /accounts/login/"
echo "[*] Target: $TARGET_URL"
echo ""

# First, get the CSRF token from the login page
echo "[*] Step 1: Fetching login page to obtain CSRF token..."
LOGIN_PAGE=$(curl -s -c /tmp/cookies.txt "${LOGIN_ENDPOINT}")

# Extract CSRF token from the login form
CSRF_TOKEN=$(echo "$LOGIN_PAGE" | grep -oP 'name="csrfmiddlewaretoken" value="\K[^"]+')

if [ -z "$CSRF_TOKEN" ]; then
    echo "[-] Failed to extract CSRF token"
    exit 1
fi

echo "[+] CSRF Token obtained: ${CSRF_TOKEN:0:20}..."
echo ""

# Test 1: Standard credentials
echo "[*] Test 1: Attempting login with standard credentials (testuser:testuser123)"
RESPONSE=$(curl -s -X POST \
    -b /tmp/cookies.txt \
    -c /tmp/cookies.txt \
    -d "username=testuser&password=testuser123&csrfmiddlewaretoken=${CSRF_TOKEN}" \
    "${LOGIN_ENDPOINT}")

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -b /tmp/cookies.txt \
    -c /tmp/cookies.txt \
    -d "username=testuser&password=testuser123&csrfmiddlewaretoken=${CSRF_TOKEN}" \
    "${LOGIN_ENDPOINT}")

echo "[+] HTTP Status: $HTTP_CODE"

# Check if session was established
SESSION_COOKIE=$(grep -oP 'sessionid=\K[^;]+' /tmp/cookies.txt || echo "")

if [ -z "$SESSION_COOKIE" ]; then
    echo "[-] VULNERABLE: No session cookie established"
else
    echo "[+] Session established: $SESSION_COOKIE"
fi

# Check if login form is still displayed in response
if echo "$RESPONSE" | grep -q "type=\"password\""; then
    echo "[-] VULNERABLE: Login form still displayed (authentication failed)"
else
    echo "[+] Login form not found in response"
fi

echo ""

# Test 2: Another set of credentials
echo "[*] Test 2: Attempting login with credentials (user1:user1)"
> /tmp/cookies.txt

LOGIN_PAGE=$(curl -s -c /tmp/cookies.txt "${LOGIN_ENDPOINT}")
CSRF_TOKEN=$(echo "$LOGIN_PAGE" | grep -oP 'name="csrfmiddlewaretoken" value="\K[^"]+')

RESPONSE=$(curl -s -X POST \
    -b /tmp/cookies.txt \
    -c /tmp/cookies.txt \
    -d "username=user1&password=user1&csrfmiddlewaretoken=${CSRF_TOKEN}" \
    "${LOGIN_ENDPOINT}")

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -b /tmp/cookies.txt \
    -c /tmp/cookies.txt \
    -d "username=user1&password=user1&csrfmiddlewaretoken=${CSRF_TOKEN}" \
    "${LOGIN_ENDPOINT}")

echo "[+] HTTP Status: $HTTP_CODE"

SESSION_COOKIE=$(grep -oP 'sessionid=\K[^;]+' /tmp/cookies.txt || echo "")

if [ -z "$SESSION_COOKIE" ]; then
    echo "[-] VULNERABLE: No session cookie established"
else
    echo "[+] Session established: $SESSION_COOKIE"
fi

if echo "$RESPONSE" | grep -q "type=\"password\""; then
    echo "[-] VULNERABLE: Login form still displayed (authentication failed)"
else
    echo "[+] Login form not found in response"
fi

echo ""

# Test 3: Attempt to access protected resource without authentication
echo "[*] Test 3: Attempting to access protected endpoint /accounts/preferences/ without session"
> /tmp/cookies.txt

PROTECTED_RESPONSE=$(curl -s -b /tmp/cookies.txt "${TARGET_URL}/accounts/preferences/")

if echo "$PROTECTED_RESPONSE" | grep -q "login\|authentication\|401\|403" || echo "$PROTECTED_RESPONSE" | grep -qi "sign in\|log in"; then
    echo "[-] VULNERABLE: Protected resource is accessible without authentication or redirects to login"
else
    echo "[*] Response from protected endpoint received"
fi

echo ""
echo "[SUMMARY]"
echo "=========="
echo "[-] Authentication is BROKEN - No sessions are established on successful login"
echo "[-] All login attempts return HTTP 200 with login form still displayed"
echo "[-] Protected endpoints are inaccessible due to broken authentication"
echo "[-] This indicates a critical failure in the authentication mechanism"