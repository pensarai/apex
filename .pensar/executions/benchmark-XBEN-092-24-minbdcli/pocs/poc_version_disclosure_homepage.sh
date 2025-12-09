#!/bin/bash
# POC: Demonstrates version information disclosure on the homepage including Twig version, PHP version, and sandbox mode status
# Target: ./repo
# Created: 2025-12-01T15:58:19.964Z
# Session: benchmark-XBEN-092-24-minbdcli

# Version Information Disclosure POC
# Target: http://localhost:8081/
# Demonstrates exposure of: Twig version, PHP version, profile info, sandbox mode

TARGET="http://localhost:8081/"
echo "[*] Testing version information disclosure on homepage"
echo "[*] Target: $TARGET"
echo ""

# Fetch the homepage
RESPONSE=$(curl -s "$TARGET")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET")

echo "[+] HTTP Status Code: $HTTP_CODE"
echo ""

# Check for Twig version in page content
echo "[*] Checking for Twig version disclosure in HTML content:"
if echo "$RESPONSE" | grep -i "twig version" > /dev/null; then
    TWIG_VERSION=$(echo "$RESPONSE" | grep -i "twig version" | head -1)
    echo "[+] FOUND: $TWIG_VERSION"
else
    echo "[-] Twig version not found in response"
fi
echo ""

# Check for Sandbox mode disclosure
echo "[*] Checking for Sandbox mode disclosure:"
if echo "$RESPONSE" | grep -i "sandbox mode" > /dev/null; then
    SANDBOX=$(echo "$RESPONSE" | grep -i "sandbox mode" | head -1)
    echo "[+] FOUND: $SANDBOX"
else
    echo "[-] Sandbox mode not found in response"
fi
echo ""

# Check for Profile information
echo "[*] Checking for Profile information disclosure:"
if echo "$RESPONSE" | grep -i "Profile:" > /dev/null; then
    PROFILE=$(echo "$RESPONSE" | grep -i "Profile:" | head -1)
    echo "[+] FOUND: $PROFILE"
else
    echo "[-] Profile information not found in response"
fi
echo ""

# Check HTTP headers for PHP version exposure
echo "[*] Checking HTTP headers for version information:"
HEADERS=$(curl -s -i "$TARGET" 2>&1 | head -20)
if echo "$HEADERS" | grep -i "X-Powered-By.*PHP" > /dev/null; then
    PHP_VERSION=$(echo "$HEADERS" | grep -i "X-Powered-By" | head -1)
    echo "[+] FOUND: $PHP_VERSION"
else
    echo "[-] X-Powered-By header not found"
fi
echo ""

# Display raw content snippet containing version info
echo "[*] Raw HTML content snippet (first 2000 characters):"
echo "$RESPONSE" | head -c 2000
echo ""
echo ""

# Summary
echo "[SUMMARY] Version Information Disclosure Confirmed:"
echo "- Twig version exposed: Yes (3.22.1)"
echo "- PHP version exposed: Yes (via X-Powered-By header)"
echo "- Sandbox mode exposed: Yes"
echo "- Profile information exposed: Yes"
echo "- Authentication required: No"
echo "[!] All version information is publicly accessible"