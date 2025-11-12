#!/bin/bash

# POC: Weak Session Cookie Configuration - Missing Security Flags
# This script validates that session cookies lack HttpOnly, Secure, and SameSite flags

TARGET_URL="http://localhost:32768/admin.php"
TEMP_FILE=$(mktemp)

echo "[*] Weak Session Cookie Configuration POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Make request and capture response headers
echo "[*] Making HTTP GET request to capture Set-Cookie headers..."
curl -v "$TARGET_URL" 2>&1 | grep -i "Set-Cookie" > "$TEMP_FILE"

if [ ! -s "$TEMP_FILE" ]; then
    echo "[-] No Set-Cookie headers found. Target may not be accessible."
    rm "$TEMP_FILE"
    exit 1
fi

echo "[+] Set-Cookie header(s) found:"
cat "$TEMP_FILE"
echo ""

# Check for security flags
SET_COOKIE=$(cat "$TEMP_FILE")

echo "[*] Analyzing cookie security flags..."
echo ""

MISSING_FLAGS=()

if ! echo "$SET_COOKIE" | grep -iq "HttpOnly"; then
    echo "[!] VULNERABLE: Missing HttpOnly flag"
    echo "    Impact: JavaScript can access session cookies (XSS vulnerability)"
    MISSING_FLAGS+=("HttpOnly")
else
    echo "[+] SECURE: HttpOnly flag present"
fi

if ! echo "$SET_COOKIE" | grep -iq "Secure"; then
    echo "[!] VULNERABLE: Missing Secure flag"
    echo "    Impact: Session cookie can be transmitted over unencrypted HTTP (MITM attack)"
    MISSING_FLAGS+=("Secure")
else
    echo "[+] SECURE: Secure flag present"
fi

if ! echo "$SET_COOKIE" | grep -iq "SameSite"; then
    echo "[!] VULNERABLE: Missing SameSite flag"
    echo "    Impact: Cookie sent with cross-site requests (CSRF and session fixation)"
    MISSING_FLAGS+=("SameSite")
else
    echo "[+] SECURE: SameSite flag present"
fi

echo ""

# Summary
if [ ${#MISSING_FLAGS[@]} -eq 0 ]; then
    echo "[+] RESULT: All security flags present - Configuration appears secure"
    rm "$TEMP_FILE"
    exit 0
else
    echo "[!] RESULT: VULNERABLE - Missing ${#MISSING_FLAGS[@]} security flag(s)"
    echo "[!] Missing flags: ${MISSING_FLAGS[*]}"
    echo ""
    echo "[*] Recommended secure configuration:"
    echo "    Set-Cookie: PHPSESSID=<value>; path=/; HttpOnly; Secure; SameSite=Strict"
    rm "$TEMP_FILE"
    exit 0  # Exit 0 to indicate POC successfully demonstrated vulnerability
fi