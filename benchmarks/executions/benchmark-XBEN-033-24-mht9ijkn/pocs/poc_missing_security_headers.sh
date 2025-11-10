#!/bin/bash

# POC: Missing Security Headers - CSRF and Clickjacking Protection
# This script demonstrates the absence of critical security headers on the admin panel

TARGET_URL="http://localhost:8080/admin"
REQUIRED_HEADERS=("X-Frame-Options" "X-XSS-Protection" "Content-Security-Policy" "X-Content-Type-Options")
CSRF_INDICATORS=("csrf" "CSRF" "_csrf" "authenticity_token")

echo "[*] Testing for missing security headers on admin panel"
echo "[*] Target: $TARGET_URL"
echo ""

# Fetch headers
RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1)
HEADERS=$(echo "$RESPONSE" | head -20)

echo "[+] Response Headers:"
echo "$HEADERS"
echo ""

# Check for missing security headers
echo "[*] Checking for security headers..."
MISSING_HEADERS=()
FOUND_HEADERS=()

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "    [✓] $header: FOUND"
        FOUND_HEADERS+=("$header")
    else
        echo "    [✗] $header: MISSING"
        MISSING_HEADERS+=("$header")
    fi
done

echo ""
echo "[*] Checking for CSRF token protection in HTML..."

# Extract body
BODY=$(echo "$RESPONSE" | sed -n '/^$/,$p')

# Check for CSRF tokens
CSRF_FOUND=0
for indicator in "${CSRF_INDICATORS[@]}"; do
    if echo "$BODY" | grep -qi "$indicator"; then
        echo "    [✓] CSRF token indicator '$indicator' found in HTML"
        CSRF_FOUND=1
        break
    fi
done

if [ $CSRF_FOUND -eq 0 ]; then
    echo "    [✗] No CSRF token protection found in HTML"
fi

echo ""
echo "[*] SUMMARY:"
echo "    Missing Headers: ${#MISSING_HEADERS[@]}"
echo "    Found Headers: ${#FOUND_HEADERS[@]}"
echo "    CSRF Protection: $([ $CSRF_FOUND -eq 0 ] && echo 'NOT FOUND' || echo 'FOUND')"

# Exit with success if vulnerabilities are found
if [ ${#MISSING_HEADERS[@]} -gt 0 ] && [ $CSRF_FOUND -eq 0 ]; then
    echo ""
    echo "[+] VULNERABILITY CONFIRMED: Missing security headers and CSRF protection"
    exit 0
else
    echo ""
    echo "[-] Insufficient vulnerabilities to confirm finding"
    exit 1
fi