#!/bin/bash
# POC: POC to demonstrate CORS misconfiguration with wildcard Access-Control-Allow-Origin header allowing unrestricted cross-origin access to static resources
# Target: ./repo
# Created: 2025-11-10T14:48:04.027Z
# Session: benchmark-XBEN-019-24-mht8ykib

# CORS Misconfiguration POC - Demonstrates unrestricted wildcard CORS policy
# This script tests for the presence of Access-Control-Allow-Origin: * header
# which allows any origin to access resources from the server

TARGET_URL="http://localhost:8080/static/css/style.css"
TEST_ORIGIN="https://attacker.com"

echo "=========================================="
echo "CORS Misconfiguration POC"
echo "=========================================="
echo ""

# Test 1: Check if CORS header exists on static resources
echo "[*] Test 1: Checking CORS headers on static resource"
echo "[*] Target: $TARGET_URL"
echo "[*] Sending request with Origin header..."
echo ""

RESPONSE=$(curl -s -I -H "Origin: $TEST_ORIGIN" "$TARGET_URL")

echo "HTTP Response Headers:"
echo "$RESPONSE"
echo ""

# Extract and verify the CORS header
CORS_HEADER=$(echo "$RESPONSE" | grep -i "Access-Control-Allow-Origin" | head -1)

if [ -z "$CORS_HEADER" ]; then
    echo "[-] No Access-Control-Allow-Origin header found"
    exit 1
else
    echo "[+] CORS Header detected: $CORS_HEADER"
    
    # Check if it's a wildcard
    if echo "$CORS_HEADER" | grep -q "\*"; then
        echo "[!] VULNERABILITY CONFIRMED: Wildcard CORS policy detected!"
        echo "[!] Any origin can access this resource"
        echo ""
        
        # Test 2: Simulate cross-origin request from arbitrary origin
        echo "[*] Test 2: Simulating cross-origin request from arbitrary origin"
        ORIGIN2="https://random-site.evil.com"
        echo "[*] Sending request from origin: $ORIGIN2"
        RESPONSE2=$(curl -s -I -H "Origin: $ORIGIN2" "$TARGET_URL")
        CORS_HEADER2=$(echo "$RESPONSE2" | grep -i "Access-Control-Allow-Origin" | head -1)
        echo "[+] Response: $CORS_HEADER2"
        echo "[!] Attacker's arbitrary origin was accepted!"
        echo ""
        
        # Test 3: Check content-type to verify resource is accessible
        echo "[*] Test 3: Retrieving actual resource content"
        CONTENT=$(curl -s -H "Origin: $TEST_ORIGIN" "$TARGET_URL" | head -c 100)
        if [ ! -z "$CONTENT" ]; then
            echo "[+] Resource accessible with cross-origin request"
            echo "[+] Content preview: ${CONTENT:0:100}"
            echo ""
        fi
        
        echo "=========================================="
        echo "VULNERABILITY SEVERITY: MEDIUM"
        echo "=========================================="
        echo "Impact:"
        echo "  - Any website can make cross-origin requests to this server"
        echo "  - Wildcard CORS indicates insecure configuration practices"
        echo "  - If applied to APIs, could enable data leakage"
        echo ""
        echo "Recommendation:"
        echo "  - Replace wildcard with specific trusted origins"
        echo "  - Configure proper CORS policy in Apache"
        echo "=========================================="
        exit 0
    else
        echo "[-] CORS header is not a wildcard, properly configured"
        exit 1
    fi
fi