#!/bin/bash

# POC: Version Information Disclosure via HTTP Headers
# Target: localhost
# Purpose: Demonstrate that Server and X-Powered-By headers expose version information

echo "======================================"
echo "Version Information Disclosure POC"
echo "======================================"
echo ""

# Test on multiple endpoints to show headers are present everywhere
ENDPOINTS=("/" "/index.php" "/login.php")

for endpoint in "${ENDPOINTS[@]}"; do
    echo "[*] Testing endpoint: $endpoint"
    echo "---"
    
    response=$(curl -v "http://localhost$endpoint" 2>&1)
    
    # Extract relevant headers
    server_header=$(echo "$response" | grep -i "^< Server:" | head -1)
    xpoweredby_header=$(echo "$response" | grep -i "^< X-Powered-By:" | head -1)
    
    echo "Response Headers:"
    if [ -n "$server_header" ]; then
        echo "$server_header"
    else
        echo "Server: [NOT FOUND]"
    fi
    
    if [ -n "$xpoweredby_header" ]; then
        echo "$xpoweredby_header"
    else
        echo "X-Powered-By: [NOT FOUND]"
    fi
    echo ""
done

# Check if version information is disclosed
echo "[*] Checking for version disclosure..."
echo "---"

response=$(curl -v "http://localhost/" 2>&1)
server_info=$(echo "$response" | grep -i "^< Server:" | head -1)
php_info=$(echo "$response" | grep -i "^< X-Powered-By:" | head -1)

if echo "$server_info" | grep -qiE "Apache|nginx|IIS" && echo "$server_info" | grep -qE "[0-9]\.[0-9]"; then
    echo "[+] VULNERABLE: Server header exposes version information"
    echo "    Value: $server_info"
fi

if echo "$php_info" | grep -qiE "PHP" && echo "$php_info" | grep -qE "[0-9]\.[0-9]"; then
    echo "[+] VULNERABLE: X-Powered-By header exposes PHP version"
    echo "    Value: $php_info"
fi

echo ""
echo "[*] Version Information Disclosure Test Complete"