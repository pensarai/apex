#!/bin/bash

# POC: Information Disclosure - Server Framework Exposed via Powered-By Header
# This script demonstrates that the Flask application exposes sensitive framework
# version information through response headers

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINTS=("/list" "/add" "/about")

echo "=========================================="
echo "Framework Information Disclosure POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Test each endpoint for exposed headers
for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $TARGET_URL$endpoint"
    echo "---"
    
    # Make request and capture headers
    response=$(curl -s -i "$TARGET_URL$endpoint" 2>&1)
    
    # Extract Powered-By header
    powered_by=$(echo "$response" | grep -i "^Powered-By:" | head -1)
    if [ ! -z "$powered_by" ]; then
        echo "✓ VULNERABLE: $powered_by"
    fi
    
    # Extract Server header
    server=$(echo "$response" | grep -i "^Server:" | head -1)
    if [ ! -z "$server" ]; then
        echo "✓ VULNERABLE: $server"
    fi
    
    # Check if headers are present
    if [ -z "$powered_by" ] && [ -z "$server" ]; then
        echo "✗ No information disclosure headers found"
    fi
    
    echo ""
done

# Detailed analysis
echo "=========================================="
echo "Detailed Header Analysis"
echo "=========================================="
echo ""

# Get full headers from one endpoint
full_headers=$(curl -s -i "$TARGET_URL/list" 2>&1)

echo "Full Response Headers:"
echo "$full_headers" | head -20
echo ""

# Extract and analyze sensitive headers
echo "Sensitive Information Disclosed:"
echo "$full_headers" | grep -iE "(Powered-By|Server|X-Powered-By)" || echo "No sensitive headers found"

# Verify the vulnerability
echo ""
echo "=========================================="
if echo "$full_headers" | grep -qi "Powered-By: Flask"; then
    echo "✓ CONFIRMED: Powered-By header exposes Flask framework"
    exit 0
elif echo "$full_headers" | grep -qi "Server: Werkzeug"; then
    echo "✓ CONFIRMED: Server header exposes Werkzeug/Python version"
    exit 0
else
    echo "✗ Could not confirm framework header disclosure"
    exit 1
fi