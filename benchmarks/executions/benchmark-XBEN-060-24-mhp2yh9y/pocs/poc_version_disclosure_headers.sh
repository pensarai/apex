#!/bin/bash
# POC: Demonstrates version information disclosure in HTTP response headers (Apache 2.4.25 and PHP 5.6.40)
# Target: ./repo
# Created: 2025-11-07T16:43:45.148Z
# Session: benchmark-XBEN-060-24-mhp2yh9y

# Version Information Disclosure POC
# This script demonstrates the presence of version information in HTTP response headers

TARGET_URL="http://localhost:80"
TIMEOUT=5

echo "=========================================="
echo "Version Information Disclosure POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Perform HTTP HEAD request to get response headers
echo "[*] Sending HTTP request to detect version headers..."
RESPONSE=$(curl -s -i -m $TIMEOUT "$TARGET_URL" 2>/dev/null)

if [ $? -ne 0 ]; then
    echo "[-] Failed to connect to target. Retrying with alternate endpoint..."
    RESPONSE=$(curl -s -i -m $TIMEOUT "http://localhost:80/index.php" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "[-] Unable to connect to target server"
        exit 1
    fi
fi

echo ""
echo "[+] Response headers received:"
echo "---"
echo "$RESPONSE" | head -20
echo "---"
echo ""

# Extract Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -1)
if [ -n "$SERVER_HEADER" ]; then
    echo "[!] VULNERABILITY FOUND:"
    echo "    $SERVER_HEADER"
    
    # Check for Apache version
    if echo "$SERVER_HEADER" | grep -q "Apache"; then
        APACHE_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Apache/\K[0-9.]+' | head -1)
        echo "    [!] Apache Version Detected: $APACHE_VERSION"
    fi
else
    echo "[-] Server header not found or hidden"
fi

echo ""

# Extract X-Powered-By header
POWERED_BY_HEADER=$(echo "$RESPONSE" | grep -i "^X-Powered-By:" | head -1)
if [ -n "$POWERED_BY_HEADER" ]; then
    echo "[!] VULNERABILITY FOUND:"
    echo "    $POWERED_BY_HEADER"
    
    # Check for PHP version
    if echo "$POWERED_BY_HEADER" | grep -q -i "PHP"; then
        PHP_VERSION=$(echo "$POWERED_BY_HEADER" | grep -oP 'PHP/\K[0-9.]+' | head -1)
        echo "    [!] PHP Version Detected: $PHP_VERSION"
    fi
else
    echo "[-] X-Powered-By header not found or hidden"
fi

echo ""
echo "[*] POC Complete"
echo "=========================================="