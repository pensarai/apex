#!/bin/bash

# POC: Missing Security Headers on Protected Endpoints
# Tests for absence of critical security headers on /dashboard and /admin_panel

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-80}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "================================"
echo "Security Headers Analysis POC"
echo "================================"
echo "Target: $BASE_URL"
echo ""

# Array of endpoints to test
endpoints=("/dashboard" "/admin_panel")

# Array of required security headers
required_headers=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Content-Security-Policy"
    "Strict-Transport-Security"
)

# Function to test endpoint
test_endpoint() {
    local endpoint=$1
    echo "Testing: $endpoint"
    echo "-------------------"
    
    # Make HEAD request and capture headers
    response=$(curl -s -I "$BASE_URL$endpoint" 2>&1)
    
    if [ $? -ne 0 ]; then
        echo "Could not reach endpoint: $BASE_URL$endpoint"
        return 1
    fi
    
    # Extract headers (first line is HTTP status)
    http_status=$(echo "$response" | head -1)
    echo "HTTP Response: $http_status"
    echo ""
    
    # Check for presence of security headers
    missing_count=0
    for header in "${required_headers[@]}"; do
        if echo "$response" | grep -iq "^$header:"; then
            echo "[PRESENT] $header"
        else
            echo "[MISSING] $header"
            missing_count=$((missing_count + 1))
        fi
    done
    
    echo ""
    
    # Display present headers (for reference)
    echo "Current headers present:"
    echo "$response" | grep -E "^[A-Za-z-]+:" | sed 's/^/  /'
    echo ""
    
    return $missing_count
}

# Test all endpoints
total_missing=0
for endpoint in "${endpoints[@]}"; do
    test_endpoint "$endpoint"
    missing=$?
    total_missing=$((total_missing + missing))
done

echo "================================"
if [ $total_missing -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED"
    echo "Total missing security headers: $total_missing"
    echo "All endpoints are missing critical security headers"
    exit 0
else
    echo "No vulnerability detected"
    exit 0
fi