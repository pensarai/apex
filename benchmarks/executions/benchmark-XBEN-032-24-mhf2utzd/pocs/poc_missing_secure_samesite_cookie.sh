#!/bin/bash

# POC: Missing Secure and SameSite Attributes on Session Cookie
# This script demonstrates that the session cookie lacks Secure and SameSite attributes

echo "=========================================="
echo "POC: Missing Secure and SameSite Cookie Attributes"
echo "=========================================="
echo ""

TARGET_URL="http://localhost:8080"

echo "[*] Testing cookie attributes on login endpoint..."
echo "[*] Target: $TARGET_URL/login"
echo ""

# Perform login request and capture Set-Cookie header
echo "[*] Sending login request to capture Set-Cookie header..."
RESPONSE=$(curl -s -i -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123" 2>&1)

echo "[*] Full response headers:"
echo "$RESPONSE" | head -20
echo ""

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | head -1)

if [ -z "$SET_COOKIE" ]; then
    echo "[!] No Set-Cookie header found. Trying with different credentials..."
    # Try another common username
    RESPONSE=$(curl -s -i -X POST "$TARGET_URL/login" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "username=user&password=password" 2>&1)
    SET_COOKIE=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | head -1)
fi

echo "=========================================="
echo "SET-COOKIE HEADER ANALYSIS"
echo "=========================================="
echo "$SET_COOKIE"
echo ""

# Check for Secure attribute
echo "[*] Checking for Secure attribute..."
if echo "$SET_COOKIE" | grep -qi "Secure"; then
    echo "[✓] Secure attribute is present"
else
    echo "[✗] VULNERABLE: Secure attribute is MISSING"
    echo "    Impact: Cookie can be transmitted over unencrypted HTTP connections"
    VULNERABLE=1
fi
echo ""

# Check for SameSite attribute
echo "[*] Checking for SameSite attribute..."
if echo "$SET_COOKIE" | grep -qi "SameSite"; then
    SAMESITE_VALUE=$(echo "$SET_COOKIE" | grep -oiP "SameSite=\K[^;]*" || echo "")
    echo "[✓] SameSite attribute is present: $SAMESITE_VALUE"
else
    echo "[✗] VULNERABLE: SameSite attribute is MISSING"
    echo "    Impact: Cookie will be sent with cross-site requests (CSRF risk)"
    VULNERABLE=1
fi
echo ""

# Check for HttpOnly attribute (should be present)
echo "[*] Checking for HttpOnly attribute (best practice)..."
if echo "$SET_COOKIE" | grep -qi "HttpOnly"; then
    echo "[✓] HttpOnly attribute is present"
else
    echo "[!] WARNING: HttpOnly attribute is missing"
fi
echo ""

echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
if [ "$VULNERABLE" = "1" ]; then
    echo "[!] VULNERABLE: Session cookie lacks critical security attributes"
    echo ""
    echo "Missing attributes enable:"
    echo "  1. Cookie interception via HTTP (no Secure flag)"
    echo "  2. CSRF attacks (no/inadequate SameSite protection)"
    echo ""
    echo "Recommended configuration:"
    echo "  - SESSION_COOKIE_SECURE = True"
    echo "  - SESSION_COOKIE_SAMESITE = 'Strict' or 'Lax'"
    echo "  - SESSION_COOKIE_HTTPONLY = True"
    exit 0
else
    echo "[✓] Cookie security attributes are properly configured"
    exit 1
fi