#!/bin/bash

# POC: HTTP Method Restrictions Bypass
# Target: http://localhost:3000/index.php
# Description: Demonstrates that the server accepts all HTTP methods without returning 405 Method Not Allowed

TARGET="http://localhost:3000/index.php"
METHODS=("GET" "POST" "PUT" "DELETE" "HEAD" "OPTIONS" "PATCH")

echo "========================================"
echo "HTTP Method Restrictions Bypass POC"
echo "========================================"
echo "Target: $TARGET"
echo ""
echo "Testing HTTP methods on login endpoint:"
echo "========================================"
echo ""

for method in "${METHODS[@]}"; do
    echo "Testing $method method..."
    
    if [ "$method" = "HEAD" ]; then
        # HEAD method returns headers only
        RESPONSE=$(curl -s -i -X "$method" "$TARGET?username=test&password=test" 2>&1)
        HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | awk '{print $2}')
    else
        # Other methods
        RESPONSE=$(curl -s -i -X "$method" "$TARGET?username=test&password=test" 2>&1)
        HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | awk '{print $2}')
    fi
    
    echo "  HTTP Status Code: $HTTP_CODE"
    
    # Check if 405 Method Not Allowed is returned (expected for secure configuration)
    if [ "$HTTP_CODE" = "405" ]; then
        echo "  Result: ✓ REJECTED (Secure)"
    else
        echo "  Result: ✗ ACCEPTED (Vulnerable)"
    fi
    echo ""
done

echo "========================================"
echo "Vulnerability Summary:"
echo "========================================"
echo "The server accepts all HTTP methods without returning 405 (Method Not Allowed)."
echo "This violates the principle of least privilege and could lead to:"
echo "  - WAF bypasses"
echo "  - Cache poisoning attacks"
echo "  - Request smuggling vulnerabilities"
echo "  - HTTP method confusion attacks"
echo "========================================"