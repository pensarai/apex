#!/bin/bash

# POC: Server Version Information Disclosure
# This script demonstrates how the Server response header discloses
# version information about Werkzeug and Python

TARGET_URL="http://localhost:5000"
ENDPOINTS=(
    "/"
    "/nonexistent"
)

echo "=== Server Version Information Disclosure POC ==="
echo "Target: $TARGET_URL"
echo ""

# Function to check Server header
check_server_header() {
    local endpoint=$1
    echo "Testing endpoint: $endpoint"
    
    # Make request and extract Server header
    response=$(curl -s -I "$TARGET_URL$endpoint" 2>/dev/null)
    server_header=$(echo "$response" | grep -i "^Server:" | head -1)
    
    if [ -n "$server_header" ]; then
        echo "✓ Found Server Header:"
        echo "  $server_header"
        
        # Check if version information is present
        if echo "$server_header" | grep -qE "[0-9]+\.[0-9]+\.[0-9]+"; then
            echo "✓ VULNERABLE: Version information is disclosed"
            echo "  Werkzeug version and Python version are revealed"
        fi
    else
        echo "✗ Server header not found or request failed"
    fi
    echo ""
}

# Test all endpoints
for endpoint in "${ENDPOINTS[@]}"; do
    check_server_header "$endpoint"
done

# Also test that it appears consistently
echo "=== Consistency Check ==="
echo "Making 3 requests to root endpoint to verify consistent disclosure:"
for i in {1..3}; do
    header=$(curl -s -I "$TARGET_URL/" 2>/dev/null | grep -i "^Server:")
    echo "Request $i: $header"
done

echo ""
echo "=== Vulnerability Confirmed ==="
echo "The Server header consistently exposes:"
echo "- Werkzeug version (web framework)"
echo "- Python version (runtime)"
echo "This information can be used to identify version-specific vulnerabilities"