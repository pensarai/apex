#!/bin/bash

# POC: Missing SameSite Cookie Flag on Session Cookie
# Description: Verify that the session cookie lacks SameSite and Secure attributes

TARGET_URL="http://localhost:80/login"
RESPONSE_FILE="/tmp/login_response.txt"

echo "[*] Testing for missing SameSite flag on session cookie..."
echo "[*] Target: $TARGET_URL"
echo ""

# Make POST request to login endpoint and capture headers
curl -i -X POST -d "username=test&password=test" "$TARGET_URL" 2>/dev/null > "$RESPONSE_FILE"

# Extract the Set-Cookie header
SET_COOKIE=$(grep -i "^Set-Cookie:" "$RESPONSE_FILE" | head -1)

echo "[*] Response headers:"
echo "$SET_COOKIE"
echo ""

# Check for SameSite attribute
if echo "$SET_COOKIE" | grep -iq "SameSite"; then
    echo "[+] SameSite flag: PRESENT"
    SAMESITE_PRESENT=1
else
    echo "[-] SameSite flag: MISSING (VULNERABLE)"
    SAMESITE_PRESENT=0
fi

# Check for Secure attribute
if echo "$SET_COOKIE" | grep -iq "Secure"; then
    echo "[+] Secure flag: PRESENT"
    SECURE_PRESENT=1
else
    echo "[-] Secure flag: MISSING (VULNERABLE)"
    SECURE_PRESENT=0
fi

# Check for HttpOnly attribute
if echo "$SET_COOKIE" | grep -iq "HttpOnly"; then
    echo "[+] HttpOnly flag: PRESENT"
    HTTPONLY_PRESENT=1
else
    echo "[-] HttpOnly flag: MISSING"
    HTTPONLY_PRESENT=0
fi

echo ""
echo "[*] Analysis:"
if [ $SAMESITE_PRESENT -eq 0 ] || [ $SECURE_PRESENT -eq 0 ]; then
    echo "[VULNERABLE] Session cookie is missing critical security attributes"
    if [ $SAMESITE_PRESENT -eq 0 ]; then
        echo "  - Without SameSite, cookie will be sent in cross-site requests"
        echo "  - Reduces defense-in-depth against CSRF attacks"
    fi
    if [ $SECURE_PRESENT -eq 0 ]; then
        echo "  - Without Secure flag, cookie can be transmitted over HTTP"
        echo "  - Vulnerable to man-in-the-middle attacks"
    fi
    echo ""
    echo "[EXPECTED] Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax; Path=/"
    exit 0  # POC demonstrates the vulnerability (successful test)
else
    echo "[SECURE] Session cookie has all recommended security attributes"
    exit 1
fi