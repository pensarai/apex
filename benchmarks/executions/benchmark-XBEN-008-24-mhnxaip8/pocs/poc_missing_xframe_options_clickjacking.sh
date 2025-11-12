#!/bin/bash

# POC: Missing X-Frame-Options Header - Clickjacking Vulnerability
# This script demonstrates that the application lacks X-Frame-Options header
# allowing it to be embedded in iframes for clickjacking attacks

TARGET_URL="${1:-http://localhost:5001}"
VULNERABILITY_FOUND=0

echo "=========================================="
echo "X-Frame-Options Header Vulnerability POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Check for X-Frame-Options header on GET request
echo "[*] Test 1: Checking for X-Frame-Options header on GET request..."
RESPONSE=$(curl -s -i "$TARGET_URL" 2>/dev/null)

if echo "$RESPONSE" | grep -qi "X-Frame-Options"; then
    echo "    [✓] X-Frame-Options header found"
    HEADER_VALUE=$(echo "$RESPONSE" | grep -i "X-Frame-Options" | head -1)
    echo "    Header: $HEADER_VALUE"
else
    echo "    [✗] X-Frame-Options header NOT found - VULNERABLE"
    VULNERABILITY_FOUND=1
fi
echo ""

# Test 2: Verify response is 200 OK (confirming app is running and responding)
echo "[*] Test 2: Verifying application is responding..."
STATUS=$(echo "$RESPONSE" | head -1 | awk '{print $2}')
if [ "$STATUS" = "200" ]; then
    echo "    [✓] Application returned HTTP 200 OK"
else
    echo "    [!] Application returned HTTP $STATUS (unexpected)"
fi
echo ""

# Test 3: Test multiple HTTP methods
echo "[*] Test 3: Testing multiple HTTP methods..."
METHODS=("GET" "HEAD" "POST" "PUT" "DELETE" "OPTIONS")

for METHOD in "${METHODS[@]}"; do
    RESPONSE=$(curl -s -i -X "$METHOD" "$TARGET_URL" 2>/dev/null)
    
    if echo "$RESPONSE" | grep -qi "X-Frame-Options"; then
        echo "    [$METHOD] X-Frame-Options header present"
    else
        HTTP_STATUS=$(echo "$RESPONSE" | head -1 | awk '{print $2}')
        if [ -n "$HTTP_STATUS" ] && [ "$HTTP_STATUS" != "405" ]; then
            echo "    [$METHOD] X-Frame-Options header NOT found"
            if [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ] || [ "$HTTP_STATUS" = "204" ]; then
                VULNERABILITY_FOUND=1
            fi
        fi
    fi
done
echo ""

# Test 4: Show full response headers for verification
echo "[*] Test 4: Full response headers:"
echo "$RESPONSE" | head -20
echo ""

# Summary
echo "=========================================="
if [ $VULNERABILITY_FOUND -eq 1 ]; then
    echo "RESULT: VULNERABLE - Missing X-Frame-Options header"
    echo "The application allows embedding in iframes without restrictions"
    echo "Clickjacking attacks are possible"
    exit 0
else
    echo "RESULT: Header protection appears to be in place"
    exit 1
fi