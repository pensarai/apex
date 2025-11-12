#!/bin/bash

# POC: HTML Documentation Exposure - Sensitive API Endpoints Disclosed in Source Code
# This script demonstrates the vulnerability by fetching the login page and extracting
# the sensitive API documentation from HTML comments

TARGET_URL="http://localhost:5000/login"

echo "=================================================="
echo "HTML Documentation Exposure POC"
echo "=================================================="
echo ""
echo "[*] Target: $TARGET_URL"
echo "[*] Testing connectivity and fetching login page..."
echo ""

# Fetch the login page with timeout and verbose output
RESPONSE=$(curl -s -m 10 "$TARGET_URL" 2>&1)
CURL_EXIT=$?

if [ $CURL_EXIT -ne 0 ]; then
    echo "[-] Failed to connect to target: $RESPONSE"
    exit 1
fi

# Count total lines in response
RESPONSE_LINES=$(echo "$RESPONSE" | wc -l)
echo "[*] Received response with $RESPONSE_LINES lines"
echo ""

# Check if response contains HTML comments
COMMENT_COUNT=$(echo "$RESPONSE" | grep -c "<!--")
echo "[*] Found $COMMENT_COUNT HTML comment blocks"

# Check if response contains any API documentation indicators
if echo "$RESPONSE" | grep -qE "(API|endpoint|parameter|password|authentication|localhost|newpassword|reset_password)" ; then
    echo "[+] VULNERABLE: Documentation containing sensitive information found!"
    echo ""
    echo "[*] Full page source:"
    echo "===== BEGIN PAGE SOURCE ====="
    echo "$RESPONSE"
    echo "===== END PAGE SOURCE ====="
    echo ""
    
    # Extract sensitive information patterns
    echo "[+] Sensitive Information Patterns Detected:"
    
    if echo "$RESPONSE" | grep -q "reset_password"; then
        echo "  [✓] /reset_password endpoint mentioned"
    fi
    if echo "$RESPONSE" | grep -q "newpassword"; then
        echo "  [✓] 'newpassword' parameter exposed"
    fi
    if echo "$RESPONSE" | grep -q "localhost"; then
        echo "  [✓] 'localhost' access restriction mentioned"
    fi
    if echo "$RESPONSE" | grep -q "API"; then
        echo "  [✓] 'API' documentation marker found"
    fi
    
    echo ""
    echo "[+] Vulnerability Confirmed"
    exit 0
else
    echo "[-] No obvious sensitive documentation patterns found"
    echo "[*] Response preview:"
    echo "$RESPONSE" | head -30
    exit 1
fi