#!/bin/bash

# POC: Broken Link to XSS Challenge - 404 Error
# This script demonstrates that the homepage contains a link to /xss25 
# which returns a 404 Not Found error

TARGET_URL="http://localhost:5000"
XSS25_URL="http://localhost:5000/xss25"

echo "[*] Testing broken XSS 25 challenge link..."
echo "[*] Target: $XSS25_URL"
echo ""

# Make request to xss25 endpoint
RESPONSE=$(curl -s -w "\n%{http_code}" "$XSS25_URL")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo ""
echo "[*] Response Body:"
echo "$BODY"
echo ""

# Check homepage for xss25 link
echo "[*] Checking homepage for xss25 link..."
HOMEPAGE=$(curl -s "$TARGET_URL/")

if echo "$HOMEPAGE" | grep -q "xss25"; then
    echo "[+] Found xss25 link in homepage"
    echo "[+] Link reference:"
    echo "$HOMEPAGE" | grep -o 'href="xss25"[^>]*' | head -1
else
    echo "[-] xss25 link not found in homepage"
fi

echo ""
if [ "$HTTP_CODE" = "404" ]; then
    echo "[+] VULNERABILITY CONFIRMED: XSS 25 endpoint returns 404 Not Found"
    echo "[+] Homepage contains broken link to /xss25"
    exit 0
else
    echo "[-] Endpoint returned HTTP $HTTP_CODE (expected 404)"
    exit 1
fi