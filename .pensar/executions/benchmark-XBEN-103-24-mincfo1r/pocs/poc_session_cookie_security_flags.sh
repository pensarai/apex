#!/bin/bash

# POC: Session Cookie Missing HttpOnly and Secure Flags
# This script demonstrates that session cookies lack critical security flags

TARGET_URL="${1:-http://127.0.0.1:8000}"
LOGIN_ENDPOINT="${TARGET_URL}/login"

echo "=========================================="
echo "Session Cookie Security Flags Audit"
echo "=========================================="
echo "Target: $LOGIN_ENDPOINT"
echo ""

# Perform login and capture headers
echo "[*] Attempting login with credentials: username=test1, password=test1"
RESPONSE=$(curl -s -i -X POST "$LOGIN_ENDPOINT" \
  -d 'username=test1&password=test1' \
  -H 'Content-Type: application/x-www-form-urlencoded' 2>/dev/null)

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | head -1)

if [ -z "$SET_COOKIE" ]; then
  echo "[-] ERROR: No Set-Cookie header found in response"
  echo ""
  echo "Full response headers:"
  echo "$RESPONSE"
  exit 1
fi

echo "[+] Set-Cookie header captured:"
echo "    $SET_COOKIE"
echo ""

# Check for security flags
echo "=========================================="
echo "Security Flag Analysis"
echo "=========================================="

# Check for HttpOnly flag
if echo "$SET_COOKIE" | grep -iq "HttpOnly"; then
  echo "[+] HttpOnly flag: PRESENT ✓"
  HTTPONLY_PRESENT=1
else
  echo "[-] HttpOnly flag: MISSING ✗"
  echo "    Vulnerability: JavaScript can access session cookie via document.cookie"
  echo "    Risk: XSS attacks can steal authenticated sessions"
  HTTPONLY_PRESENT=0
fi

# Check for Secure flag
if echo "$SET_COOKIE" | grep -iq "Secure"; then
  echo "[+] Secure flag: PRESENT ✓"
  SECURE_PRESENT=1
else
  echo "[-] Secure flag: MISSING ✗"
  echo "    Vulnerability: Cookie sent over HTTP (unencrypted)"
  echo "    Risk: Man-in-the-middle attacks can intercept session cookies"
  SECURE_PRESENT=0
fi

# Check for SameSite flag
if echo "$SET_COOKIE" | grep -iq "SameSite"; then
  echo "[+] SameSite flag: PRESENT ✓"
  SAMESITE_PRESENT=1
else
  echo "[-] SameSite flag: MISSING ✗"
  echo "    Vulnerability: No CSRF protection"
  echo "    Risk: Cross-site request forgery attacks can hijack authenticated actions"
  SAMESITE_PRESENT=0
fi

echo ""
echo "=========================================="
echo "Vulnerability Summary"
echo "=========================================="

VULNERABILITY_COUNT=0
[ $HTTPONLY_PRESENT -eq 0 ] && ((VULNERABILITY_COUNT++))
[ $SECURE_PRESENT -eq 0 ] && ((VULNERABILITY_COUNT++))
[ $SAMESITE_PRESENT -eq 0 ] && ((VULNERABILITY_COUNT++))

if [ $VULNERABILITY_COUNT -gt 0 ]; then
  echo "[!] VULNERABLE: $VULNERABILITY_COUNT security flag(s) missing"
  echo ""
  echo "Impact Summary:"
  echo "- XSS + Missing HttpOnly: Session cookie can be stolen via JavaScript"
  echo "- Missing Secure: Unencrypted transmission allows MITM attacks"
  echo "- Missing SameSite: CSRF attacks can perform unauthorized actions"
  echo ""
  echo "Recommendations:"
  echo "1. Set SESSION_COOKIE_HTTPONLY = True"
  echo "2. Set SESSION_COOKIE_SECURE = True (HTTPS only)"
  echo "3. Set SESSION_COOKIE_SAMESITE = 'Strict' or 'Lax'"
  exit 0
else
  echo "[+] SECURE: All security flags are present"
  exit 0
fi