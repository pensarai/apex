#!/bin/bash

# POC: Insecure Session Cookie Configuration
# Tests for missing Secure and SameSite flags on session cookies

TARGET="${1:-http://localhost}"
ENDPOINT="/login"

echo "=========================================="
echo "Testing for Insecure Session Cookie Configuration"
echo "=========================================="
echo "Target: ${TARGET}${ENDPOINT}"
echo ""

# Perform login and capture Set-Cookie headers
echo "[*] Sending login request..."
RESPONSE=$(curl -s -v -X POST "${TARGET}${ENDPOINT}" \
  -d "username=test&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  2>&1)

# Extract Set-Cookie header
echo "[*] Analyzing response headers..."
SET_COOKIE=$(echo "$RESPONSE" | grep -i "Set-Cookie:" | head -1)

if [ -z "$SET_COOKIE" ]; then
    echo "[!] ERROR: No Set-Cookie header found in response"
    echo "Full response headers:"
    echo "$RESPONSE" | grep -i "^<"
    exit 1
fi

echo ""
echo "Set-Cookie Header Found:"
echo "$SET_COOKIE"
echo ""

# Check for security flags
echo "=========================================="
echo "Security Flag Analysis:"
echo "=========================================="

# Check for HttpOnly flag
if echo "$SET_COOKIE" | grep -qi "HttpOnly"; then
    echo "[✓] HttpOnly flag: PRESENT (protects against XSS cookie theft)"
else
    echo "[✗] HttpOnly flag: MISSING"
fi

# Check for Secure flag
if echo "$SET_COOKIE" | grep -qi "Secure"; then
    echo "[✓] Secure flag: PRESENT (enforces HTTPS)"
else
    echo "[✗] Secure flag: MISSING (VULNERABLE - cookie can be transmitted over HTTP)"
fi

# Check for SameSite attribute
if echo "$SET_COOKIE" | grep -qi "SameSite"; then
    SAMESITE=$(echo "$SET_COOKIE" | grep -io "SameSite=[^ ;]*")
    echo "[✓] SameSite attribute: PRESENT ($SAMESITE)"
else
    echo "[✗] SameSite attribute: MISSING (VULNERABLE - reduced CSRF protection)"
fi

echo ""
echo "=========================================="
echo "Expected Secure Configuration:"
echo "=========================================="
echo "Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict; Path=/; Domain=..."
echo ""

# Check if all required flags are present
SECURE_FLAG=$(echo "$SET_COOKIE" | grep -qi "Secure" && echo "1" || echo "0")
SAMESITE_FLAG=$(echo "$SET_COOKIE" | grep -qi "SameSite" && echo "1" || echo "0")

if [ "$SECURE_FLAG" = "0" ] || [ "$SAMESITE_FLAG" = "0" ]; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo "    Missing security flags detected on session cookie"
    exit 0
else
    echo "[+] Cookie appears to be properly configured"
    exit 1
fi