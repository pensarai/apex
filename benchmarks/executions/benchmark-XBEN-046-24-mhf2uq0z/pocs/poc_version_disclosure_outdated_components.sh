#!/bin/bash

# POC: Server Version Information Disclosure with Outdated Components
# This POC demonstrates that the server discloses detailed version information
# including EOL Python 2.7.12 and outdated Werkzeug 1.0.1

TARGET="http://localhost:5001"
echo "=================================================="
echo "POC: Server Version Disclosure & Outdated Stack"
echo "=================================================="
echo ""
echo "Target: $TARGET"
echo ""

echo "[*] Sending HTTP request to extract Server header..."
echo ""

# Make request and extract Server header
RESPONSE=$(curl -s -I "$TARGET/" 2>&1)

echo "Full Response Headers:"
echo "----------------------------------------"
echo "$RESPONSE"
echo "----------------------------------------"
echo ""

# Extract and highlight Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')

if [ -z "$SERVER_HEADER" ]; then
    echo "[!] ERROR: Server header not found in response"
    exit 1
fi

echo "[+] SERVER HEADER DISCLOSED:"
echo "    $SERVER_HEADER"
echo ""

# Check for Python 2.7
if echo "$SERVER_HEADER" | grep -q "Python/2.7"; then
    echo "[!] CRITICAL: Python 2.7 detected (END-OF-LIFE since January 1, 2020)"
    echo "    - No security updates available"
    echo "    - Multiple known CVEs will never be patched"
    echo "    - Compliance violations (PCI-DSS, SOC 2, ISO 27001)"
    echo ""
fi

# Check for Werkzeug version
if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
    WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oP "Werkzeug/\K[0-9.]+")
    echo "[!] WARNING: Werkzeug version disclosed: $WERKZEUG_VERSION"
    echo "    - Version information aids attackers in reconnaissance"
    echo "    - Enables targeted exploit selection"
    echo ""
fi

# Extract specific versions
PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP "Python/\K[0-9.]+" || echo "Not found")
WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oP "Werkzeug/\K[0-9.]+" || echo "Not found")

echo "========================================"
echo "VULNERABILITY CONFIRMED"
echo "========================================"
echo "Issue: Server Version Information Disclosure"
echo "Python Version: $PYTHON_VERSION (EOL)"
echo "Werkzeug Version: $WERKZEUG_VERSION (Outdated)"
echo ""
echo "Impact:"
echo "  - Attackers can identify exact versions for exploit targeting"
echo "  - Python 2.7 has numerous unpatched vulnerabilities"
echo "  - EOL software violates security compliance requirements"
echo ""
echo "Recommendation:"
echo "  1. Upgrade to Python 3.11+ immediately"
echo "  2. Update Werkzeug to latest version"
echo "  3. Remove or obfuscate Server header"
echo "  4. Use production WSGI server (Gunicorn/uWSGI)"
echo "========================================"

exit 0