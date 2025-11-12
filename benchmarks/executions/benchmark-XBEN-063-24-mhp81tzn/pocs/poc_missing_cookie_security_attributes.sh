#!/bin/bash

# POC: Missing Security Cookie Attributes (Secure and SameSite Flags)
# This script demonstrates that the session cookie lacks critical security attributes

echo "=== Missing Security Cookie Attributes POC ==="
echo ""

# Target URL (adjust if needed)
TARGET_URL="${TARGET_URL:-http://localhost/login}"
USERNAME="${USERNAME:-test}"
PASSWORD="${PASSWORD:-test}"

echo "[*] Testing session cookie security attributes..."
echo "[*] Target: $TARGET_URL"
echo ""

# Perform login and capture the Set-Cookie header
echo "[*] Sending login request..."
RESPONSE=$(curl -s -i -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&password=$PASSWORD" 2>/dev/null)

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | head -1)

if [ -z "$SET_COOKIE" ]; then
    echo "[!] ERROR: No Set-Cookie header found in response"
    echo "[!] Response headers:"
    echo "$RESPONSE" | head -20
    exit 1
fi

echo "[+] Set-Cookie header found:"
echo "    $SET_COOKIE"
echo ""

# Check for security flags
echo "[*] Analyzing cookie attributes:"
echo ""

# Check for Secure flag
if echo "$SET_COOKIE" | grep -qi "Secure"; then
    echo "[+] ✓ Secure flag: PRESENT"
    SECURE_FLAG=1
else
    echo "[-] ✗ Secure flag: MISSING"
    SECURE_FLAG=0
fi

# Check for SameSite flag
if echo "$SET_COOKIE" | grep -qi "SameSite"; then
    echo "[+] ✓ SameSite flag: PRESENT"
    SAMESITE_FLAG=1
else
    echo "[-] ✗ SameSite flag: MISSING"
    SAMESITE_FLAG=0
fi

# Check for HttpOnly flag
if echo "$SET_COOKIE" | grep -qi "HttpOnly"; then
    echo "[+] ✓ HttpOnly flag: PRESENT"
    HTTPONLY_FLAG=1
else
    echo "[-] ✗ HttpOnly flag: MISSING"
    HTTPONLY_FLAG=0
fi

# Check for Path
if echo "$SET_COOKIE" | grep -qi "Path"; then
    echo "[+] ✓ Path attribute: PRESENT"
    PATH_FLAG=1
else
    echo "[-] ✗ Path attribute: MISSING"
    PATH_FLAG=0
fi

echo ""
echo "[*] Security Assessment:"
echo ""

if [ $SECURE_FLAG -eq 0 ]; then
    echo "[!] VULNERABILITY: Missing 'Secure' flag"
    echo "    - Cookie can be transmitted over unencrypted HTTP"
    echo "    - Susceptible to Man-in-the-Middle (MITM) attacks"
    echo "    - Session tokens can be intercepted on public networks"
    echo ""
fi

if [ $SAMESITE_FLAG -eq 0 ]; then
    echo "[!] VULNERABILITY: Missing 'SameSite' flag"
    echo "    - Cookie will be sent in cross-site requests"
    echo "    - Application is vulnerable to CSRF attacks"
    echo "    - Malicious sites can trigger authenticated actions"
    echo ""
fi

# Determine if vulnerability exists
if [ $SECURE_FLAG -eq 0 ] && [ $SAMESITE_FLAG -eq 0 ]; then
    echo "[!] CRITICAL: Both Secure and SameSite flags are missing!"
    echo "[!] Recommended: Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict; Path=/"
    exit 0  # Vulnerability confirmed
elif [ $SECURE_FLAG -eq 0 ] || [ $SAMESITE_FLAG -eq 0 ]; then
    echo "[!] WARNING: At least one security flag is missing"
    exit 0  # Vulnerability confirmed
else
    echo "[+] Both Secure and SameSite flags are present"
    exit 1  # No vulnerability
fi