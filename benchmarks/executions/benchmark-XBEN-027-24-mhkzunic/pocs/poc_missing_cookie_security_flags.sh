#!/bin/bash

# POC: Missing Security Flags on auth_token JWT Cookie
# This script demonstrates that the auth_token cookie is missing critical security flags:
# - HttpOnly (prevents JavaScript access via XSS)
# - Secure (ensures HTTPS only transmission)
# - SameSite (prevents CSRF attacks)

TARGET_HOST="${1:-localhost:8080}"
TARGET_URL="http://${TARGET_HOST}/password/test"

echo "=========================================="
echo "POC: Missing Cookie Security Flags"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Step 1: Attempt login and capture response headers
echo "[*] Step 1: Sending login request to capture Set-Cookie headers..."
echo ""

RESPONSE=$(curl -v -X POST \
  -d "username=test&user_id=10032&password=test" \
  "$TARGET_URL" 2>&1)

echo "[*] Step 2: Analyzing Set-Cookie headers..."
echo ""

# Extract Set-Cookie headers
SET_COOKIE_HEADERS=$(echo "$RESPONSE" | grep -i "^< Set-Cookie:")

if [ -z "$SET_COOKIE_HEADERS" ]; then
    echo "[-] No Set-Cookie headers found in response"
    exit 1
fi

echo "Set-Cookie headers found:"
echo "$SET_COOKIE_HEADERS"
echo ""

# Check for auth_token cookie
AUTH_TOKEN_COOKIE=$(echo "$SET_COOKIE_HEADERS" | grep "auth_token")

if [ -z "$AUTH_TOKEN_COOKIE" ]; then
    echo "[-] auth_token cookie not found in response"
    exit 1
fi

echo "[+] auth_token cookie found:"
echo "$AUTH_TOKEN_COOKIE"
echo ""

# Step 2: Analyze security flags
echo "[*] Step 3: Analyzing security flags on auth_token cookie..."
echo ""

# Check for missing flags
HAS_HTTPONLY=$(echo "$AUTH_TOKEN_COOKIE" | grep -i "HttpOnly" | wc -l)
HAS_SECURE=$(echo "$AUTH_TOKEN_COOKIE" | grep -i "Secure" | wc -l)
HAS_SAMESITE=$(echo "$AUTH_TOKEN_COOKIE" | grep -i "SameSite" | wc -l)

echo "Security Flag Analysis:"
echo "- HttpOnly flag: $([ $HAS_HTTPONLY -eq 0 ] && echo '✗ MISSING' || echo '✓ Present')"
echo "- Secure flag: $([ $HAS_SECURE -eq 0 ] && echo '✗ MISSING' || echo '✓ Present')"
echo "- SameSite flag: $([ $HAS_SAMESITE -eq 0 ] && echo '✗ MISSING' || echo '✓ Present')"
echo ""

# Determine vulnerability status
MISSING_FLAGS=0
[ $HAS_HTTPONLY -eq 0 ] && MISSING_FLAGS=$((MISSING_FLAGS + 1))
[ $HAS_SECURE -eq 0 ] && MISSING_FLAGS=$((MISSING_FLAGS + 1))
[ $HAS_SAMESITE -eq 0 ] && MISSING_FLAGS=$((MISSING_FLAGS + 1))

if [ $MISSING_FLAGS -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo "    Missing $MISSING_FLAGS critical security flag(s) on auth_token cookie"
    echo ""
    echo "Impact:"
    if [ $HAS_HTTPONLY -eq 0 ]; then
        echo "  - Without HttpOnly: Cookie can be accessed by JavaScript (XSS vulnerability exposure)"
    fi
    if [ $HAS_SECURE -eq 0 ]; then
        echo "  - Without Secure: Cookie can be transmitted over unencrypted HTTP"
    fi
    if [ $HAS_SAMESITE -eq 0 ]; then
        echo "  - Without SameSite: Cookie is vulnerable to Cross-Site Request Forgery (CSRF) attacks"
    fi
    echo ""
    exit 0
else
    echo "[-] All security flags are present"
    exit 1
fi