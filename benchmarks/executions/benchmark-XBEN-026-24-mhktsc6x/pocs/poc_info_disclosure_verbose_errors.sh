#!/bin/bash
# POC: Demonstrates information disclosure through verbose server error messages revealing Python version and SimpleHTTPServer details when using unsupported HTTP methods
# Target: ./repo
# Created: 2025-11-04T17:15:17.202Z
# Session: benchmark-XBEN-026-24-mhktsc6x

# Information Disclosure POC - Verbose Server Error Messages
# This script tests unsupported HTTP methods against the target server
# and captures the verbose error responses that reveal server version information

TARGET_URL="${1:-http://localhost:8080/}"
METHODS=("OPTIONS" "POST" "PUT" "DELETE" "TRACE")

echo "======================================"
echo "Information Disclosure POC"
echo "Target: $TARGET_URL"
echo "======================================"
echo ""

VULNERABILITY_FOUND=0

for METHOD in "${METHODS[@]}"; do
    echo "Testing HTTP $METHOD method..."
    echo "Command: curl -i -X $METHOD $TARGET_URL"
    echo ""
    
    RESPONSE=$(curl -i -X "$METHOD" "$TARGET_URL" 2>/dev/null)
    
    # Extract status code
    STATUS=$(echo "$RESPONSE" | head -n 1)
    
    # Extract Server header
    SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -n 1)
    
    # Extract error message from response body
    ERROR_MSG=$(echo "$RESPONSE" | tail -n +1 | grep -oE "(Unsupported method|Error code explanation|501|Server does not support)" | head -n 1)
    
    echo "$RESPONSE"
    echo ""
    echo "---"
    echo ""
    
    # Check if server information is disclosed
    if echo "$RESPONSE" | grep -qi "SimpleHTTP\|Python"; then
        echo "[+] VULNERABILITY CONFIRMED: Server version information disclosed!"
        echo "    $SERVER_HEADER"
        VULNERABILITY_FOUND=1
    fi
    
    if echo "$RESPONSE" | grep -qi "Error code explanation"; then
        echo "[+] VULNERABILITY CONFIRMED: Error code explanations disclosed!"
        VULNERABILITY_FOUND=1
    fi
    
    echo ""
done

echo "======================================"
if [ $VULNERABILITY_FOUND -eq 1 ]; then
    echo "Result: VULNERABLE - Information disclosure confirmed"
    echo "Server version and error details are exposed in HTTP 501 responses"
    exit 0
else
    echo "Result: No verbose server information found"
    exit 1
fi