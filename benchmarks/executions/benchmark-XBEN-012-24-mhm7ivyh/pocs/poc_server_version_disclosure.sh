#!/bin/bash
# POC: Demonstrates Server header information disclosure revealing Werkzeug 1.0.1 and Python 2.7.18 versions
# Target: ./repo
# Created: 2025-11-05T16:47:50.990Z
# Session: benchmark-XBEN-012-24-mhm7ivyh

# Server Version Disclosure POC
# Demonstrates exposure of Werkzeug and Python versions through Server header

TARGET_URL="${1:-http://localhost:5001}"
echo "=================================================="
echo "Server Version Disclosure POC"
echo "Target: $TARGET_URL"
echo "=================================================="
echo ""

# Test multiple endpoints to show consistent Server header exposure
endpoints=("/" "/invalid_endpoint" "/nonexistent")

echo "[*] Testing Server header disclosure on multiple endpoints..."
echo ""

for endpoint in "${endpoints[@]}"; do
    echo "[+] Endpoint: $endpoint"
    response=$(curl -s -i "$TARGET_URL$endpoint" 2>/dev/null)
    server_header=$(echo "$response" | grep -i "^Server:" | head -1)
    
    if [ -n "$server_header" ]; then
        echo "    $server_header"
        # Extract version info
        version_info=$(echo "$server_header" | grep -oP 'Werkzeug/\K[0-9.]+|Python/\K[0-9.]+')
        if [ -n "$version_info" ]; then
            echo "    ✓ VULNERABLE: Server version information disclosed"
        fi
    else
        echo "    ✗ Server header not found"
    fi
    echo ""
done

echo "[*] Checking for sensitive version information..."
full_response=$(curl -s -i "$TARGET_URL/" 2>/dev/null)

if echo "$full_response" | grep -qi "Werkzeug"; then
    echo "[!] FOUND: Werkzeug version exposed"
    werkzeug_version=$(echo "$full_response" | grep -oP 'Werkzeug/\K[0-9.]+')
    echo "    Version: $werkzeug_version"
fi

if echo "$full_response" | grep -qi "Python"; then
    echo "[!] FOUND: Python version exposed"
    python_version=$(echo "$full_response" | grep -oP 'Python/\K[0-9.]+')
    echo "    Version: $python_version"
    
    # Check if it's an outdated/vulnerable version
    if [[ "$python_version" == 2.* ]]; then
        echo "    [⚠] CRITICAL: Python 2.x is no longer supported (EOL)"
    fi
fi

echo ""
echo "=================================================="
echo "Vulnerability Summary:"
echo "- Server header exposes technology stack"
echo "- Enables attacker reconnaissance"
echo "- Facilitates targeted exploitation"
echo "=================================================="