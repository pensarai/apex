#!/bin/bash

# POC: Session Cookie Missing Security Attributes (Secure and SameSite Flags)
# This script demonstrates that the session cookie lacks the Secure and SameSite security attributes

echo "=========================================="
echo "Session Cookie Security Attributes Test"
echo "=========================================="
echo ""

# Target endpoint
TARGET_URL="http://localhost/login"

echo "[*] Testing session cookie attributes..."
echo "[*] Target: $TARGET_URL"
echo ""

# Make POST request to login endpoint and capture Set-Cookie header
echo "[*] Sending login request..."
RESPONSE=$(curl -s -i -X POST "$TARGET_URL" \
  -d "username=test&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "[*] Response received. Analyzing Set-Cookie headers..."
echo ""

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | head -1)

if [ -z "$SET_COOKIE" ]; then
  echo "[-] No Set-Cookie header found in response"
  exit 1
fi

echo "[+] Set-Cookie Header Found:"
echo "    $SET_COOKIE"
echo ""

# Check for Secure flag
if echo "$SET_COOKIE" | grep -qi "Secure"; then
  echo "[+] Secure flag: PRESENT ✓"
else
  echo "[-] Secure flag: MISSING ✗"
fi

# Check for SameSite flag
if echo "$SET_COOKIE" | grep -qi "SameSite"; then
  echo "[+] SameSite flag: PRESENT ✓"
else
  echo "[-] SameSite flag: MISSING ✗"
fi

# Check for HttpOnly flag
if echo "$SET_COOKIE" | grep -qi "HttpOnly"; then
  echo "[+] HttpOnly flag: PRESENT ✓"
else
  echo "[-] HttpOnly flag: MISSING ✗"
fi

echo ""
echo "[*] Security Analysis:"
echo ""

VULNERABILITIES=0

if ! echo "$SET_COOKIE" | grep -qi "Secure"; then
  echo "[VULNERABILITY] Missing Secure Flag:"
  echo "  - Session cookie can be transmitted over unencrypted HTTP"
  echo "  - Vulnerable to Man-in-the-Middle (MITM) attacks"
  echo "  - Attackers on the network can intercept session tokens"
  ((VULNERABILITIES++))
fi

if ! echo "$SET_COOKIE" | grep -qi "SameSite"; then
  echo "[VULNERABILITY] Missing SameSite Flag:"
  echo "  - Cookie can be sent in cross-site requests"
  echo "  - Increases vulnerability to Cross-Site Request Forgery (CSRF)"
  echo "  - No protection against unwanted cross-origin cookie transmission"
  ((VULNERABILITIES++))
fi

echo ""
if [ $VULNERABILITIES -gt 0 ]; then
  echo "[!] VULNERABILITY CONFIRMED: $VULNERABILITIES security attribute(s) missing"
  exit 0
else
  echo "[+] All security attributes present - NO VULNERABILITY"
  exit 1
fi