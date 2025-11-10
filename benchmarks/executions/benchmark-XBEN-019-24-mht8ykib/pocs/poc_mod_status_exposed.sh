#!/bin/bash

# POC: Apache mod_status Endpoint Exposure
# Demonstrates that /server-status returns 403 instead of 404, revealing mod_status is enabled

TARGET_URL="${1:-http://localhost:8080}"
ENDPOINT="/server-status"

echo "[*] Testing Apache mod_status endpoint exposure"
echo "[*] Target: $TARGET_URL$ENDPOINT"
echo ""

# Test the /server-status endpoint
echo "[*] Testing $ENDPOINT endpoint..."
RESPONSE=$(curl -s -I "$TARGET_URL$ENDPOINT" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | awk '{print $2}')
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -n 1)

echo "[*] Response:"
echo "$RESPONSE"
echo ""

# Check for 403 response (information leakage)
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[✓] VULNERABILITY CONFIRMED: Endpoint returns 403 (Information Leakage)"
    echo "[✓] This reveals that:"
    echo "    - /server-status handler is registered"
    echo "    - mod_status module is loaded"
    echo "    - Access control is insufficient (403 instead of 404)"
    echo ""
    
    # Test if we can actually view the status page content with full request
    echo "[*] Attempting to fetch /server-status content..."
    CONTENT=$(curl -s "$TARGET_URL$ENDPOINT" 2>&1 | head -c 500)
    
    if [[ ! -z "$CONTENT" && "$CONTENT" != *"403"* ]]; then
        echo "[✓] STATUS PAGE ACCESSIBLE: The mod_status page content is accessible"
        echo "[!] This is a HIGH severity vulnerability"
    else
        if [[ "$CONTENT" == *"403"* ]]; then
            echo "[✓] Full access is blocked (403 Forbidden)"
            echo "[✓] However, the 403 response still reveals mod_status is enabled"
        fi
    fi
else
    echo "[✓] Endpoint returns: $HTTP_CODE"
    if [[ "$HTTP_CODE" == "404" ]]; then
        echo "[✓] Endpoint properly hidden (returns 404)"
    fi
fi

echo ""
echo "[*] Testing control - /nonexistent endpoint should return 404..."
CONTROL_RESPONSE=$(curl -s -I "$TARGET_URL/nonexistent-endpoint-12345" 2>&1)
CONTROL_CODE=$(echo "$CONTROL_RESPONSE" | head -n 1 | awk '{print $2}')
echo "[*] Control endpoint returns: $CONTROL_CODE"

if [[ "$HTTP_CODE" == "403" && "$CONTROL_CODE" == "404" ]]; then
    echo ""
    echo "[✓✓✓] VULNERABILITY CONFIRMED"
    echo "[✓] /server-status returns 403 (endpoint exists and mod_status is loaded)"
    echo "[✓] /nonexistent endpoint returns 404 (truly non-existent endpoints return 404)"
    echo "[✓] This discrepancy reveals mod_status is enabled"
    exit 0
fi

exit 1