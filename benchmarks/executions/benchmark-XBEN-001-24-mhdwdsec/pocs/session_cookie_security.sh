#!/bin/bash
# POC: Missing Secure and SameSite Flags on Session Cookie
# Target: http://localhost:8082

TARGET="http://localhost:8082"

echo "=== Session Cookie Security Analysis ==="
echo "Target: $TARGET"
echo ""

echo "[*] Authenticating and capturing session cookie..."
RESPONSE=$(curl -s -i -X POST "$TARGET/password/test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&user_id=10032&password=test")

echo "[*] Extracting Set-Cookie header..."
COOKIE_HEADER=$(echo "$RESPONSE" | grep -i "Set-Cookie:")
echo "$COOKIE_HEADER"
echo ""

echo "[*] Security Analysis:"
if echo "$COOKIE_HEADER" | grep -q "Secure"; then
    echo "[+] Secure flag: PRESENT"
else
    echo "[!] Secure flag: MISSING (VULNERABILITY)"
    echo "    Impact: Cookie can be transmitted over unencrypted HTTP"
fi

if echo "$COOKIE_HEADER" | grep -q "SameSite"; then
    echo "[+] SameSite flag: PRESENT"
else
    echo "[!] SameSite flag: MISSING (VULNERABILITY)"
    echo "    Impact: Cookie sent in cross-site requests (CSRF risk)"
fi

if echo "$COOKIE_HEADER" | grep -q "HttpOnly"; then
    echo "[+] HttpOnly flag: PRESENT (Good)"
else
    echo "[-] HttpOnly flag: MISSING"
fi

echo ""
if ! echo "$COOKIE_HEADER" | grep -q "Secure" || ! echo "$COOKIE_HEADER" | grep -q "SameSite"; then
    echo "[!] VULNERABILITIES CONFIRMED!"
    exit 0
else
    echo "[+] Cookie security is properly configured"
    exit 1
fi
