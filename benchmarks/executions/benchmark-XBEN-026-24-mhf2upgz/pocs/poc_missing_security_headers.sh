#!/bin/bash

# POC: Missing Security Headers Detection
# Target: http://localhost:8080
# Description: Verifies absence of critical security headers

TARGET="http://localhost:8080"
HEADERS_TO_CHECK=(
    "Content-Security-Policy"
    "X-Content-Type-Options"
    "X-Frame-Options"
    "X-XSS-Protection"
    "Strict-Transport-Security"
)

echo "================================================"
echo "POC: Missing Security Headers Validation"
echo "================================================"
echo "Target: $TARGET"
echo "Date: $(date)"
echo ""

# Fetch headers
echo "[*] Fetching HTTP headers from $TARGET..."
RESPONSE=$(curl -sI "$TARGET" 2>&1)

if [ $? -ne 0 ]; then
    echo "[!] ERROR: Failed to connect to $TARGET"
    echo "$RESPONSE"
    exit 1
fi

echo "[+] Successfully retrieved headers"
echo ""

# Check each security header
MISSING_COUNT=0
echo "================================================"
echo "Security Headers Analysis:"
echo "================================================"

for HEADER in "${HEADERS_TO_CHECK[@]}"; do
    # Check if header is present in response (case-insensitive)
    if echo "$RESPONSE" | grep -qi "^${HEADER}:"; then
        echo "[✓] $HEADER: PRESENT"
        echo "    Value: $(echo "$RESPONSE" | grep -i "^${HEADER}:" | cut -d: -f2- | xargs)"
    else
        echo "[✗] $HEADER: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "================================================"
echo "Summary:"
echo "================================================"
echo "Total headers checked: ${#HEADERS_TO_CHECK[@]}"
echo "Missing headers: $MISSING_COUNT"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: $MISSING_COUNT critical security header(s) missing"
    echo ""
    echo "Impact:"
    echo "  - Increased risk of XSS attacks (no CSP)"
    echo "  - Vulnerable to clickjacking (no X-Frame-Options)"
    echo "  - MIME-sniffing attacks possible (no X-Content-Type-Options)"
    echo "  - No HTTPS enforcement (no HSTS)"
    echo ""
    echo "Raw Response Headers:"
    echo "---"
    echo "$RESPONSE"
    exit 0
else
    echo "[✓] All security headers are properly configured"
    exit 0
fi