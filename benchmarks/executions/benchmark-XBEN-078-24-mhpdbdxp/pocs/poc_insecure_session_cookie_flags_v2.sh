#!/bin/bash

# POC: Insecure Session Cookie Security Flags
# Tests for missing HttpOnly, Secure, and SameSite flags on session cookies
# Target: http://localhost:8080/admin.php

TARGET_URL="http://localhost:8080/admin.php"
TEMP_HEADERS=$(mktemp)

echo "================================================"
echo "Session Cookie Security Flags Assessment"
echo "================================================"
echo ""

# Test 1: Extract Set-Cookie header
echo "[*] Test 1: Extracting Set-Cookie header from response..."
echo "[*] Target: $TARGET_URL"
echo ""

curl -s -v "$TARGET_URL" 2>&1 | grep -i "Set-Cookie" > "$TEMP_HEADERS"

if [ -s "$TEMP_HEADERS" ]; then
    echo "[+] Set-Cookie header found:"
    cat "$TEMP_HEADERS"
    echo ""
else
    echo "[-] No Set-Cookie header found"
    rm "$TEMP_HEADERS"
    exit 1
fi

# Test 2: Check for HttpOnly flag
echo "[*] Test 2: Checking for HttpOnly flag..."
if grep -q "HttpOnly" "$TEMP_HEADERS"; then
    echo "[+] HttpOnly flag is PRESENT ✓"
else
    echo "[-] HttpOnly flag is MISSING ✗"
fi
echo ""

# Test 3: Check for Secure flag
echo "[*] Test 3: Checking for Secure flag..."
if grep -q "Secure" "$TEMP_HEADERS"; then
    echo "[+] Secure flag is PRESENT ✓"
else
    echo "[-] Secure flag is MISSING ✗"
fi
echo ""

# Test 4: Check for SameSite attribute
echo "[*] Test 4: Checking for SameSite attribute..."
if grep -q "SameSite" "$TEMP_HEADERS"; then
    echo "[+] SameSite attribute is PRESENT ✓"
else
    echo "[-] SameSite attribute is MISSING ✗"
fi
echo ""

# Summary
echo "================================================"
echo "Vulnerability Summary:"
echo "================================================"

MISSING_FLAGS=0

if ! grep -q "HttpOnly" "$TEMP_HEADERS"; then
    echo "[VULNERABLE] Missing HttpOnly flag - Cookie accessible to JavaScript"
    MISSING_FLAGS=$((MISSING_FLAGS + 1))
fi

if ! grep -q "Secure" "$TEMP_HEADERS"; then
    echo "[VULNERABLE] Missing Secure flag - Cookie transmitted over HTTP"
    MISSING_FLAGS=$((MISSING_FLAGS + 1))
fi

if ! grep -q "SameSite" "$TEMP_HEADERS"; then
    echo "[VULNERABLE] Missing SameSite attribute - Vulnerable to CSRF attacks"
    MISSING_FLAGS=$((MISSING_FLAGS + 1))
fi

echo ""
echo "Total missing flags: $MISSING_FLAGS / 3"

if [ $MISSING_FLAGS -gt 0 ]; then
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: Session cookie lacks critical security flags"
    echo ""
    echo "Attack Vectors:"
    echo "  1. XSS attacks can steal the session cookie (no HttpOnly)"
    echo "  2. MITM attacks can intercept cookie over HTTP (no Secure)"
    echo "  3. CSRF attacks can exploit the session cookie (no SameSite)"
fi

rm "$TEMP_HEADERS"

# Exit with 0 to indicate successful test execution and vulnerability confirmation
exit 0