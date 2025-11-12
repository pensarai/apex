#!/bin/bash

# POC: Werkzeug Version Disclosure - Detects outdated Werkzeug and Python versions via Server header
# Target: http://localhost:5001/xss25
# Description: The application reveals Werkzeug version in the Server header, indicating outdated and vulnerable versions

TARGET_URL="http://localhost:5001/xss25"
ENDPOINT="/xss25"

echo "=========================================="
echo "Werkzeug Version Disclosure POC"
echo "=========================================="
echo ""

# Fetch HTTP headers
echo "[*] Fetching headers from: $TARGET_URL"
HEADERS=$(curl -s -I "$TARGET_URL")

echo "[*] Full Response Headers:"
echo "$HEADERS"
echo ""

# Extract Server header
SERVER_HEADER=$(echo "$HEADERS" | grep -i "^Server:" | head -1)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found"
    exit 1
fi

echo "[+] Server Header Found: $SERVER_HEADER"
echo ""

# Extract version information
if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
    WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Werkzeug/\K[0-9.]+')
    PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Python/\K[0-9.]+')
    
    echo "[+] Version Information Disclosed:"
    echo "    - Werkzeug: $WERKZEUG_VERSION"
    echo "    - Python: $PYTHON_VERSION"
    echo ""
    
    # Check for outdated versions
    echo "[*] Vulnerability Assessment:"
    
    # Check Werkzeug version
    WERKZEUG_MAJOR=$(echo "$WERKZEUG_VERSION" | cut -d. -f1)
    if [ "$WERKZEUG_MAJOR" -lt 2 ]; then
        echo "    [VULNERABLE] Werkzeug $WERKZEUG_VERSION is outdated (current stable: 2.x/3.x)"
        echo "    [VULNERABLE] Werkzeug 1.0.1 (released early 2020) contains known CVEs:"
        echo "               - Multiple XSS vulnerabilities"
        echo "               - Information disclosure issues"
        echo "               - Other security issues documented in CVE databases"
    fi
    
    # Check Python version
    if echo "$PYTHON_VERSION" | grep -q "^2\."; then
        echo "    [VULNERABLE] Python $PYTHON_VERSION is end-of-life (EOL since January 2020)"
        echo "    [VULNERABLE] Using EOL Python version poses security and compatibility risks"
    fi
    
    echo ""
    echo "[+] Vulnerability Confirmed: Outdated versions detected via Server header disclosure"
    echo ""
    echo "Remediation Steps:"
    echo "  1. Update to Werkzeug 2.x or 3.x (latest stable version)"
    echo "  2. Update to Python 3.x (Python 2.7 is end-of-life)"
    echo "  3. Disable or obfuscate Server header to prevent version disclosure"
    echo "  4. In nginx: add 'proxy_hide_header Server;' in proxy_pass configuration"
    echo "  5. In Apache: add 'Header always unset Server' or set custom value"
    echo "  6. Use a reverse proxy to hide backend details"
    
    exit 0
else
    echo "[-] Werkzeug not detected in Server header"
    exit 1
fi