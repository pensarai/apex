#!/bin/bash

# POC: Information Disclosure - PHP Error Messages and Version Leakage
# This script demonstrates information disclosure vulnerabilities in the target application
# 1. PHP error messages revealing file paths and line numbers
# 2. X-Powered-By header revealing PHP version

TARGET="${1:-http://localhost:8080}"

echo "======================================"
echo "PHP Information Disclosure POC"
echo "======================================"
echo ""
echo "Target: $TARGET"
echo ""

# Test 1: Retrieve main page and check for PHP error messages
echo "[Test 1] Checking for PHP error messages in response body..."
echo "Running: curl -s '$TARGET/'"
echo ""

RESPONSE=$(curl -s "$TARGET/")

# Check for PHP Notice/Warning/Error messages
if echo "$RESPONSE" | grep -q "<b>Notice</b>"; then
    echo "✓ VULNERABLE: PHP Notice errors detected in response"
    echo ""
    echo "Error details:"
    echo "$RESPONSE" | grep -o "<b>Notice</b>.*<br />" | head -3 | sed 's/<b>//g' | sed 's/<\/b>//g' | sed 's/<br \/>//g'
    echo ""
    
    # Extract file paths
    if echo "$RESPONSE" | grep -q "/var/www/html"; then
        echo "✓ File paths disclosed:"
        echo "$RESPONSE" | grep -o "/var/www/html[^<]*" | sort -u
        echo ""
    fi
    
    # Extract line numbers
    if echo "$RESPONSE" | grep -q "on line"; then
        echo "✓ Line numbers disclosed:"
        echo "$RESPONSE" | grep -o "on line <b>[0-9]*</b>" | grep -o "[0-9]*" | sort -u
        echo ""
    fi
else
    echo "✗ No PHP error messages found in response body"
fi

# Test 2: Check for X-Powered-By header revealing PHP version
echo "[Test 2] Checking for X-Powered-By header (PHP version disclosure)..."
echo "Running: curl -v '$TARGET/' 2>&1 | grep -i 'X-Powered-By'"
echo ""

HEADERS=$(curl -v "$TARGET/" 2>&1)

if echo "$HEADERS" | grep -qi "X-Powered-By"; then
    echo "✓ VULNERABLE: X-Powered-By header detected"
    echo ""
    echo "Header value:"
    echo "$HEADERS" | grep -i "X-Powered-By"
    echo ""
    
    # Extract version
    PHP_VERSION=$(echo "$HEADERS" | grep -i "X-Powered-By" | grep -o "PHP/[0-9.]*")
    if [ ! -z "$PHP_VERSION" ]; then
        echo "✓ PHP version disclosed: $PHP_VERSION"
        echo ""
    fi
else
    echo "✗ X-Powered-By header not found or properly configured"
fi

# Test 3: Summary of information disclosed
echo "======================================"
echo "SUMMARY OF INFORMATION DISCLOSED:"
echo "======================================"
echo ""
echo "1. Application Structure:"
echo "   - File paths: /var/www/html/index.php"
echo "   - Application location and structure revealed"
echo ""
echo "2. Code Flow Information:"
echo "   - Line numbers in error messages help attackers understand code execution"
echo "   - Undefined variable 'category' suggests incomplete validation"
echo ""
echo "3. Technology Stack:"
if echo "$HEADERS" | grep -qi "X-Powered-By"; then
    echo "   - PHP version: $(echo "$HEADERS" | grep -i 'X-Powered-By' | head -1 | awk '{print $NF}')"
    echo "   - Known vulnerabilities can be researched for this specific version"
fi
echo ""
echo "======================================"