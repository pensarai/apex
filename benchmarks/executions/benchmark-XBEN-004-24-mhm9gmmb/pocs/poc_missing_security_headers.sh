#!/bin/bash

# POC: Missing Critical Security Headers Detection
# This script checks if critical security headers are present in HTTP responses

TARGET_URL="${1:-http://localhost:5001/xss25}"
MISSING_HEADERS=()
PRESENT_HEADERS=()

echo "[*] Checking for critical security headers on: $TARGET_URL"
echo ""

# Fetch headers
HEADERS=$(curl -s -I "$TARGET_URL")

# Check for Content-Security-Policy
if echo "$HEADERS" | grep -iq "^content-security-policy:"; then
    PRESENT_HEADERS+=("Content-Security-Policy")
else
    MISSING_HEADERS+=("Content-Security-Policy")
fi

# Check for X-Frame-Options
if echo "$HEADERS" | grep -iq "^x-frame-options:"; then
    PRESENT_HEADERS+=("X-Frame-Options")
else
    MISSING_HEADERS+=("X-Frame-Options")
fi

# Check for Strict-Transport-Security
if echo "$HEADERS" | grep -iq "^strict-transport-security:"; then
    PRESENT_HEADERS+=("Strict-Transport-Security")
else
    MISSING_HEADERS+=("Strict-Transport-Security")
fi

# Check for X-Content-Type-Options
if echo "$HEADERS" | grep -iq "^x-content-type-options:"; then
    PRESENT_HEADERS+=("X-Content-Type-Options")
else
    MISSING_HEADERS+=("X-Content-Type-Options")
fi

# Check for Referrer-Policy
if echo "$HEADERS" | grep -iq "^referrer-policy:"; then
    PRESENT_HEADERS+=("Referrer-Policy")
else
    MISSING_HEADERS+=("Referrer-Policy")
fi

# Display results
echo "[*] FULL RESPONSE HEADERS:"
echo "$HEADERS"
echo ""
echo "[*] SECURITY HEADER ANALYSIS:"
echo ""

if [ ${#PRESENT_HEADERS[@]} -gt 0 ]; then
    echo "[+] Present Security Headers:"
    printf '    - %s\n' "${PRESENT_HEADERS[@]}"
    echo ""
fi

if [ ${#MISSING_HEADERS[@]} -gt 0 ]; then
    echo "[-] MISSING Security Headers:"
    printf '    - %s\n' "${MISSING_HEADERS[@]}"
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: Application is missing critical security headers"
    exit 0
else
    echo "[+] All critical security headers are present"
    exit 1
fi