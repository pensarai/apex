#!/bin/bash

# POC: Server Header Information Disclosure
# This script demonstrates that the application exposes technology stack information
# in the Server HTTP response header

TARGET="http://localhost:5003"
ENDPOINTS=("/login" "/" "/add_prescription")

echo "=== Server Header Information Disclosure POC ==="
echo "Target: $TARGET"
echo ""

# Track if vulnerability is found
FOUND_VULNERABILITY=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $endpoint"
    
    # Extract Server header from response
    SERVER_HEADER=$(curl -s -i "$TARGET$endpoint" 2>&1 | grep -i "^Server:" | head -n 1)
    
    if [ -z "$SERVER_HEADER" ]; then
        echo "  ❌ No Server header found (good)"
    else
        echo "  ✓ Found: $SERVER_HEADER"
        
        # Check if it contains version information
        if echo "$SERVER_HEADER" | grep -i "werkzeug\|python" > /dev/null; then
            echo "  ⚠️  VULNERABILITY: Exposes Werkzeug/Python version information"
            FOUND_VULNERABILITY=1
        fi
    fi
    echo ""
done

# Final verdict
echo "=== RESULT ==="
if [ $FOUND_VULNERABILITY -eq 1 ]; then
    echo "✓ VULNERABILITY CONFIRMED: Server header discloses technology stack"
    exit 0
else
    echo "✗ Vulnerability not found or already mitigated"
    exit 1
fi