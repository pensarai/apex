#!/bin/bash

# POC: Insecure Cookie Flags (Missing HttpOnly, Secure, SameSite)
# This script demonstrates the absence of security flags in Set-Cookie headers

TARGET_URL="${1:-http://localhost:5000/list}"
ENDPOINT=$(echo "$TARGET_URL" | sed 's|/list||g')
TEST_PATH="/list"

echo "=========================================="
echo "POC: Insecure Cookie Flags Detection"
echo "=========================================="
echo "Target: $ENDPOINT"
echo ""

# Test the endpoint and capture Set-Cookie headers
echo "[*] Testing endpoint: $ENDPOINT$TEST_PATH"
RESPONSE=$(curl -i "$ENDPOINT$TEST_PATH" 2>/dev/null)

echo "[*] Extracted Set-Cookie headers:"
echo ""

# Extract and analyze Set-Cookie headers
SET_COOKIES=$(echo "$RESPONSE" | grep -i "^set-cookie:" | head -20)

if [ -z "$SET_COOKIES" ]; then
    echo "[-] No Set-Cookie headers found"
    exit 1
fi

COOKIE_COUNT=0
VULNERABLE_COUNT=0

while IFS= read -r line; do
    if [ -n "$line" ]; then
        COOKIE_COUNT=$((COOKIE_COUNT + 1))
        COOKIE_NAME=$(echo "$line" | sed 's/^[Ss]et-[Cc]ookie: //' | cut -d'=' -f1)
        COOKIE_VALUE=$(echo "$line" | sed 's/^[Ss]et-[Cc]ookie: //' | cut -d';' -f1)
        
        echo "Cookie #$COOKIE_COUNT: $COOKIE_NAME"
        echo "  Raw: $line"
        echo "  Analysis:"
        
        # Check for security flags
        MISSING_FLAGS=()
        
        if ! echo "$line" | grep -qi "HttpOnly"; then
            MISSING_FLAGS+=("HttpOnly")
        fi
        
        if ! echo "$line" | grep -qi "Secure"; then
            MISSING_FLAGS+=("Secure")
        fi
        
        if ! echo "$line" | grep -qi "SameSite"; then
            MISSING_FLAGS+=("SameSite")
        fi
        
        if [ ${#MISSING_FLAGS[@]} -gt 0 ]; then
            VULNERABLE_COUNT=$((VULNERABLE_COUNT + 1))
            echo "  ⚠️  MISSING FLAGS: ${MISSING_FLAGS[*]}"
        else
            echo "  ✓ All security flags present"
        fi
        
        echo ""
    fi
done <<< "$SET_COOKIES"

echo "=========================================="
echo "Summary:"
echo "  Total cookies: $COOKIE_COUNT"
echo "  Vulnerable cookies: $VULNERABLE_COUNT"

if [ $VULNERABLE_COUNT -gt 0 ]; then
    echo "  Status: VULNERABLE - Insecure cookie flags detected"
    exit 0
else
    echo "  Status: SECURE - All cookies have proper flags"
    exit 1
fi