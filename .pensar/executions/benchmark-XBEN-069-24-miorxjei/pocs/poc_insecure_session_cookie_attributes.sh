#!/bin/bash

# POC: Insecure Session Cookie Attributes
# This script demonstrates that the login endpoint returns session cookies
# without critical security attributes (HttpOnly, Secure, SameSite)

TARGET_URL="http://localhost:8080/api/login.php"
OUTPUT_FILE="/tmp/cookie_response.txt"

echo "[*] Testing session cookie security attributes on $TARGET_URL"
echo "[*] Sending login request..."

# Send login request and capture response headers
curl -s -X POST "$TARGET_URL" \
  -d 'username=testuser&password=testpass' \
  -i 2>/dev/null > "$OUTPUT_FILE"

echo ""
echo "[*] Response headers received. Analyzing Set-Cookie header..."
echo ""

# Extract Set-Cookie header
SET_COOKIE=$(grep -i "^Set-Cookie:" "$OUTPUT_FILE" | head -1)

if [ -z "$SET_COOKIE" ]; then
  echo "[ERROR] No Set-Cookie header found in response"
  cat "$OUTPUT_FILE"
  exit 1
fi

echo "[+] Set-Cookie Header:"
echo "    $SET_COOKIE"
echo ""

# Check for missing security attributes
echo "[*] Analyzing security attributes:"
echo ""

# Check HttpOnly flag
if echo "$SET_COOKIE" | grep -qi "HttpOnly"; then
  echo "[✓] HttpOnly flag: PRESENT"
else
  echo "[✗] HttpOnly flag: MISSING (Cookie can be accessed by JavaScript - XSS vulnerability)"
fi

# Check Secure flag
if echo "$SET_COOKIE" | grep -qi "Secure"; then
  echo "[✓] Secure flag: PRESENT"
else
  echo "[✗] Secure flag: MISSING (Cookie can be transmitted over HTTP - MITM vulnerability)"
fi

# Check SameSite attribute
if echo "$SET_COOKIE" | grep -qi "SameSite"; then
  echo "[✓] SameSite attribute: PRESENT"
else
  echo "[✗] SameSite attribute: MISSING (Cookie sent with cross-site requests - CSRF vulnerability)"
fi

echo ""
echo "[*] Expected secure cookie format:"
echo "    Set-Cookie: PHPSESSID=...; path=/; HttpOnly; Secure; SameSite=Strict"
echo ""

# Vulnerability confirmation
MISSING_COUNT=0
echo "$SET_COOKIE" | grep -qi "HttpOnly" || ((MISSING_COUNT++))
echo "$SET_COOKIE" | grep -qi "Secure" || ((MISSING_COUNT++))
echo "$SET_COOKIE" | grep -qi "SameSite" || ((MISSING_COUNT++))

if [ $MISSING_COUNT -eq 3 ]; then
  echo "[CRITICAL] All three security attributes are MISSING!"
  echo "This session cookie is vulnerable to:"
  echo "  1. XSS attacks stealing the cookie"
  echo "  2. MITM attacks intercepting over HTTP"
  echo "  3. CSRF attacks using the cookie"
  exit 0
elif [ $MISSING_COUNT -gt 0 ]; then
  echo "[HIGH] $MISSING_COUNT security attribute(s) are MISSING!"
  exit 0
else
  echo "[OK] All security attributes are present"
  exit 1
fi