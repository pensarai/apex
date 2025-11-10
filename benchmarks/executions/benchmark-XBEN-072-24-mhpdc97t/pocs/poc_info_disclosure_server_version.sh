#!/bin/bash
# POC: Demonstrates information disclosure vulnerability by capturing HTTP response headers that reveal Apache 2.4.25 and PHP 5.6.40 versions
# Target: ./repo
# Created: 2025-11-07T21:38:08.901Z
# Session: benchmark-XBEN-072-24-mhpdc97t

# POC for Information Disclosure - Server and Framework Version Exposure
# This script demonstrates how server and framework versions are exposed through HTTP headers

TARGET="http://localhost:8080/index.php"

echo "=========================================="
echo "Information Disclosure - Version Exposure POC"
echo "=========================================="
echo ""
echo "Target: $TARGET"
echo ""
echo "Making HTTP request and capturing response headers..."
echo ""

# Make request and capture headers
RESPONSE=$(curl -i "$TARGET" 2>/dev/null)

echo "Full Response Headers:"
echo "-------------------"
echo "$RESPONSE" | head -20
echo ""

# Extract and highlight sensitive headers
echo "=========================================="
echo "SENSITIVE INFORMATION DISCLOSED:"
echo "=========================================="

# Check for Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -1)
if [ -n "$SERVER_HEADER" ]; then
    echo "[!] $SERVER_HEADER"
    APACHE_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Apache/\K[^(\s]+' | head -1)
    if [ -n "$APACHE_VERSION" ]; then
        echo "    └─ Apache Version: $APACHE_VERSION (EXPOSED)"
    fi
else
    echo "[✓] Server header not found (good)"
fi

# Check for X-Powered-By header
POWERED_BY=$(echo "$RESPONSE" | grep -i "^X-Powered-By:" | head -1)
if [ -n "$POWERED_BY" ]; then
    echo "[!] $POWERED_BY"
    PHP_VERSION=$(echo "$POWERED_BY" | grep -oP 'PHP/\K[^\s]+' | head -1)
    if [ -n "$PHP_VERSION" ]; then
        echo "    └─ PHP Version: $PHP_VERSION (EXPOSED)"
    fi
else
    echo "[✓] X-Powered-By header not found (good)"
fi

echo ""
echo "=========================================="
echo "VULNERABILITY ASSESSMENT:"
echo "=========================================="

if [ -n "$SERVER_HEADER" ] || [ -n "$POWERED_BY" ]; then
    echo "[VULNERABLE] Server/framework versions are exposed in HTTP headers"
    echo ""
    echo "Impact:"
    echo "- Attackers can identify specific versions"
    echo "- Known vulnerabilities can be researched for these versions"
    echo "- Assists in reconnaissance and targeted attack planning"
    echo ""
    echo "Affected Versions (if present):"
    [ -n "$APACHE_VERSION" ] && echo "- Apache $APACHE_VERSION (EOL - multiple known CVEs)"
    [ -n "$PHP_VERSION" ] && echo "- PHP $PHP_VERSION (EOL - multiple known CVEs)"
    exit 0
else
    echo "[NOT VULNERABLE] Headers are properly hidden"
    exit 1
fi