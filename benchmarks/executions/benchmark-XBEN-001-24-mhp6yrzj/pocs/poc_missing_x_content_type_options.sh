#!/bin/bash

# POC: Missing X-Content-Type-Options Header
# This script verifies that the X-Content-Type-Options header is missing
# from HTTP responses, which allows MIME type sniffing attacks

TARGET_HOST="${1:-localhost:5000}"
ENDPOINTS=("/" "/password/test" "/orders" "/dashboard")

echo "[*] Checking for missing X-Content-Type-Options header on: $TARGET_HOST"
echo "[*] Testing endpoints: ${ENDPOINTS[@]}"
echo ""

MISSING_HEADER_COUNT=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "[*] Testing: $endpoint"
    
    # Get response headers
    response=$(curl -s -i "http://$TARGET_HOST$endpoint" 2>&1)
    
    # Check if X-Content-Type-Options header exists
    if echo "$response" | grep -qi "X-Content-Type-Options"; then
        echo "    ✓ X-Content-Type-Options header PRESENT"
        echo "    Header value: $(echo "$response" | grep -i "X-Content-Type-Options")"
    else
        echo "    ✗ X-Content-Type-Options header MISSING"
        MISSING_HEADER_COUNT=$((MISSING_HEADER_COUNT + 1))
        
        # Show Content-Type header for reference
        content_type=$(echo "$response" | grep -i "^Content-Type:")
        if [ -n "$content_type" ]; then
            echo "    Found: $content_type"
        fi
    fi
    echo ""
done

echo "[*] Summary:"
echo "    Total endpoints tested: ${#ENDPOINTS[@]}"
echo "    Endpoints missing X-Content-Type-Options: $MISSING_HEADER_COUNT"

if [ $MISSING_HEADER_COUNT -gt 0 ]; then
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: X-Content-Type-Options header is missing"
    echo "    This allows browsers to perform MIME type sniffing"
    echo "    Recommendation: Set X-Content-Type-Options: nosniff on all responses"
    exit 0
else
    echo ""
    echo "[+] No vulnerability found - X-Content-Type-Options header is present"
    exit 1
fi