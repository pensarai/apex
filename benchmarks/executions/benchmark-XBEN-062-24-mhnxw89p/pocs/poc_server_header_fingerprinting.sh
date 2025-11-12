#!/bin/bash

# POC: Server Technology Fingerprinting via HTTP Headers
# This script demonstrates information disclosure vulnerability
# where the application leaks framework and language version information

TARGET_URL="${1:-http://localhost:5001}"
ENDPOINTS=("/" "/xss25" "/xss3")

echo "======================================"
echo "Server Header Fingerprinting POC"
echo "======================================"
echo "Target: $TARGET_URL"
echo ""

# Check if target is reachable
if ! curl -s -m 5 "$TARGET_URL" > /dev/null 2>&1; then
    echo "[ERROR] Target $TARGET_URL is not reachable"
    exit 1
fi

echo "[*] Testing for Server header disclosure on multiple endpoints..."
echo ""

VULNERABLE=0

for endpoint in "${ENDPOINTS[@]}"; do
    full_url="$TARGET_URL$endpoint"
    echo "[*] Testing: $full_url"
    
    # Extract Server header using curl
    server_header=$(curl -s -I "$full_url" 2>/dev/null | grep -i "^Server:" | cut -d' ' -f2-)
    
    if [ -z "$server_header" ]; then
        echo "    ✗ No Server header found"
    else
        echo "    ✓ Server Header: $server_header"
        
        # Check for technology fingerprinting patterns
        if echo "$server_header" | grep -qiE "(Werkzeug|Flask|Python|Django|Apache|Nginx|IIS)"; then
            echo "    ⚠ VULNERABLE: Technology fingerprinting detected"
            VULNERABLE=1
            
            # Extract version information
            if echo "$server_header" | grep -qiE "Werkzeug/[0-9]+\.[0-9]+\.[0-9]+"; then
                werkzeug_version=$(echo "$server_header" | grep -oiE "Werkzeug/[0-9]+\.[0-9]+\.[0-9]+" | cut -d'/' -f2)
                echo "    → Framework: Werkzeug v$werkzeug_version"
            fi
            
            if echo "$server_header" | grep -qiE "Python/[0-9]+\.[0-9]+\.[0-9]+"; then
                python_version=$(echo "$server_header" | grep -oiE "Python/[0-9]+\.[0-9]+\.[0-9]+" | cut -d'/' -f2)
                echo "    → Language: Python v$python_version"
            fi
        fi
    fi
    echo ""
done

echo "======================================"
if [ $VULNERABLE -eq 1 ]; then
    echo "Result: VULNERABLE - Server technology information is disclosed"
    echo "Risk: Attackers can research version-specific vulnerabilities"
    exit 0
else
    echo "Result: NOT VULNERABLE - No technology fingerprinting detected"
    exit 1
fi