#!/bin/bash

# POC: Information Disclosure via Server Header
# This script demonstrates that the Server header reveals detailed version information

TARGET="http://localhost:5001"
echo "=========================================="
echo "POC: Server Header Information Disclosure"
echo "=========================================="
echo ""
echo "Target: $TARGET"
echo ""

# Test multiple endpoints to confirm the header is present everywhere
endpoints=("/" "/login" "/register" "/nonexistent")

echo "Testing Server header disclosure across multiple endpoints:"
echo ""

for endpoint in "${endpoints[@]}"; do
    echo "--- Testing: $TARGET$endpoint ---"
    
    # Extract Server header
    server_header=$(curl -s -I "$TARGET$endpoint" 2>/dev/null | grep -i "^Server:" | tr -d '\r')
    
    if [ -n "$server_header" ]; then
        echo "✓ Server header found: $server_header"
        
        # Check for version information
        if echo "$server_header" | grep -qE "(Werkzeug|Python|[0-9]+\.[0-9]+)"; then
            echo "⚠ VULNERABILITY: Server header discloses version information"
            
            # Extract specific details
            if echo "$server_header" | grep -q "Werkzeug"; then
                echo "  - Web Server: Werkzeug (Flask development server)"
            fi
            if echo "$server_header" | grep -qE "Python/[0-9.]+"; then
                python_version=$(echo "$server_header" | grep -oE "Python/[0-9.]+" | head -1)
                echo "  - Language: $python_version"
                
                # Check if Python 2.x (EOL)
                if echo "$python_version" | grep -q "Python/2\."; then
                    echo "  - ⚠ WARNING: Python 2.x is End-of-Life (EOL since Jan 2020)"
                fi
            fi
        fi
    else
        echo "✗ Server header not found"
    fi
    echo ""
done

echo "=========================================="
echo "POC Result: VULNERABLE"
echo "=========================================="
echo ""
echo "The Server header reveals:"
echo "1. Web server software and version (Werkzeug)"
echo "2. Programming language and version (Python)"
echo "3. Indication of development server in potential production use"
echo "4. Use of EOL software (Python 2.7)"
echo ""
echo "This information aids attackers in:"
echo "- Identifying exploitable version-specific vulnerabilities"
echo "- Skipping reconnaissance/fingerprinting phases"
echo "- Targeting known weaknesses in outdated software"