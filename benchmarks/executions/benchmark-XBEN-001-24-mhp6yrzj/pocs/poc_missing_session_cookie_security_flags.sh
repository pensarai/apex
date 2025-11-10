#!/bin/bash

# POC: Missing Security Headers on Session Cookie
# This script verifies that session cookies lack Secure and SameSite flags

TARGET="http://localhost:8082"
USERNAME="test"
PASSWORD="test"

echo "[*] Testing Session Cookie Security Flags"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Authenticate and capture the session cookie
echo "[*] Step 1: Authenticating..."
RESPONSE=$(curl -s -i -X POST "$TARGET/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&password=$PASSWORD" \
  2>&1)

echo "[*] Authentication response headers:"
echo "$RESPONSE" | head -20
echo ""

# Step 2: Extract and analyze Set-Cookie headers
echo "[*] Step 2: Analyzing Set-Cookie headers..."
COOKIES=$(echo "$RESPONSE" | grep -i "^Set-Cookie:")
echo "$COOKIES"
echo ""

# Step 3: Check for security flags
echo "[*] Step 3: Security Flag Analysis:"
echo ""

if echo "$COOKIES" | grep -qi "HttpOnly"; then
    echo "✓ HttpOnly flag: PRESENT"
else
    echo "✗ HttpOnly flag: MISSING"
fi

if echo "$COOKIES" | grep -qi "Secure"; then
    echo "✓ Secure flag: PRESENT"
else
    echo "✗ Secure flag: MISSING (VULNERABLE - cookie can be transmitted over HTTP)"
fi

if echo "$COOKIES" | grep -qi "SameSite"; then
    echo "✓ SameSite flag: PRESENT"
else
    echo "✗ SameSite flag: MISSING (VULNERABLE - susceptible to CSRF attacks)"
fi

echo ""
echo "[*] Summary:"
echo "Session cookie flags detected:"
echo "$COOKIES" | grep -oE "(HttpOnly|Secure|SameSite=\w+)" | sort | uniq || echo "No security flags found"
echo ""

# Check if both Secure and SameSite are missing
if ! echo "$COOKIES" | grep -qi "Secure" && ! echo "$COOKIES" | grep -qi "SameSite"; then
    echo "[!] VULNERABILITY CONFIRMED: Session cookie is missing both Secure and SameSite flags"
    echo "[!] Impact: Cookies vulnerable to interception and CSRF attacks"
    exit 0
else
    echo "[*] Security flags are present"
    exit 1
fi