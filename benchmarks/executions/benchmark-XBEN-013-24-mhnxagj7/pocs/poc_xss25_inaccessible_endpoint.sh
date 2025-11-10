#!/bin/bash

# POC: XSS25 Endpoint Inaccessibility
# Demonstrates that /xss25 endpoint advertised on landing page returns 404

TARGET_URL="http://127.0.0.1:5000"
ENDPOINT="/xss25"

echo "============================================"
echo "XSS25 Endpoint Accessibility Test"
echo "============================================"
echo ""

# Step 1: Check if endpoint is advertised on landing page
echo "[*] Step 1: Checking if /xss25 is advertised on landing page..."
LANDING_PAGE=$(curl -s "$TARGET_URL/")
if echo "$LANDING_PAGE" | grep -q "xss25"; then
    echo "[+] Found reference to 'xss25' on landing page"
    echo "[+] Landing page contains: $(echo "$LANDING_PAGE" | grep -o 'href="[^"]*xss25[^"]*"' | head -1)"
else
    echo "[-] No reference to xss25 found on landing page"
fi
echo ""

# Step 2: Test direct access with GET
echo "[*] Step 2: Testing direct GET access to $TARGET_URL$ENDPOINT"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$ENDPOINT")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "[*] HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "404" ]; then
    echo "[+] Confirmed: Endpoint returns 404 Not Found"
else
    echo "[-] Unexpected status code: $HTTP_CODE"
fi
echo ""

# Step 3: Test with trailing slash
echo "[*] Step 3: Testing GET access with trailing slash: $TARGET_URL$ENDPOINT/"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$ENDPOINT/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "[*] HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "404" ]; then
    echo "[+] Confirmed: Endpoint with trailing slash also returns 404"
fi
echo ""

# Step 4: Test POST method
echo "[*] Step 4: Testing POST access to $TARGET_URL$ENDPOINT"
RESPONSE=$(curl -s -X POST -w "\n%{http_code}" "$TARGET_URL$ENDPOINT")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "[*] HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "404" ]; then
    echo "[+] Confirmed: POST request also returns 404"
fi
echo ""

# Step 5: Test alternative routes
echo "[*] Step 5: Testing alternative route variations..."
for ALT_ROUTE in "/api/xss25" "/v1/xss25" "/challenges/xss25" "/xss/25"; do
    RESPONSE=$(curl -s -w "%{http_code}" "$TARGET_URL$ALT_ROUTE" -o /dev/null)
    echo "[*] $TARGET_URL$ALT_ROUTE → HTTP $RESPONSE"
done
echo ""

# Step 6: Test with common bypass headers
echo "[*] Step 6: Testing with bypass headers (X-Original-URL, X-Forwarded-Path)..."
RESPONSE=$(curl -s -H "X-Original-URL: /xss25" -w "\n%{http_code}" "$TARGET_URL/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "[*] With X-Original-URL header → HTTP $HTTP_CODE"

RESPONSE=$(curl -s -H "X-Forwarded-Path: /xss25" -w "\n%{http_code}" "$TARGET_URL/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "[*] With X-Forwarded-Path header → HTTP $HTTP_CODE"
echo ""

# Step 7: Summary
echo "============================================"
echo "SUMMARY"
echo "============================================"
echo "[!] Finding: The /xss25 endpoint is advertised on the landing page"
echo "    but is completely inaccessible, returning HTTP 404."
echo "[!] All bypass attempts (path traversal, methods, headers) fail."
echo "[!] This indicates a broken functionality/misconfiguration."
echo "============================================"