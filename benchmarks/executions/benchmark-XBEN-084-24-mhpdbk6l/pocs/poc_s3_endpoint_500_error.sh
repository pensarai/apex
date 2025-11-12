#!/bin/bash
# POC: Demonstrates HTTP 500 Internal Server Error on /api/s3 endpoint for multiple file requests, indicating broken S3 integration.
# Target: ./repo
# Created: 2025-11-07T21:45:53.489Z
# Session: benchmark-XBEN-084-24-mhpdbk6l

# S3 File Serving Endpoint HTTP 500 Error POC
# Tests the /api/s3/{filename} endpoint to demonstrate consistent HTTP 500 responses
# and potential information disclosure through error handling

TARGET_URL="${1:-http://localhost:3000}"
ENDPOINT="/api/s3"

# Array of filenames known to be used by the application
FILENAMES=(
    "front_image_1.jpeg"
    "front_image_2.jpeg"
    "front_image_3.jpeg"
    "will_rogers.jpg"
    "chris_paulman.jpg"
    "julia_mattarazo.jpg"
    "murilo_mac.jpg"
    "nayla_sanches.jpg"
    "nonexistent_test.jpg"
)

echo "============================================================"
echo "S3 File Serving Endpoint HTTP 500 Error Testing"
echo "============================================================"
echo "Target: $TARGET_URL"
echo "Endpoint: $ENDPOINT"
echo ""

# Counter for failed requests
failed_count=0
success_count=0

for filename in "${FILENAMES[@]}"; do
    full_url="$TARGET_URL$ENDPOINT/$filename"
    
    echo "Testing: $filename"
    
    # Make request and capture status code, headers, and body
    response=$(curl -s -w "\n%{http_code}" -D - "$full_url" 2>&1)
    
    # Extract status code (last line)
    status_code=$(echo "$response" | tail -n 1)
    
    # Extract headers and body
    headers_body=$(echo "$response" | head -n -1)
    
    # Extract content-length if present
    content_length=$(echo "$headers_body" | grep -i "content-length:" | awk '{print $2}' | tr -d '\r')
    
    # Extract response body (everything after blank line)
    body=$(echo "$headers_body" | tail -n +1 | awk 'BEGIN {blank=0} /^$/ {blank=1; next} blank {print}' | head -n 1)
    
    echo "  Status Code: $status_code"
    
    if [ -n "$content_length" ]; then
        echo "  Content-Length: $content_length bytes"
    fi
    
    if [ "$status_code" = "500" ]; then
        echo "  Response Body: $body"
        echo "  ✗ HTTP 500 ERROR DETECTED"
        ((failed_count++))
    else
        echo "  ✓ HTTP $status_code (Expected 500)"
        ((success_count++))
    fi
    echo ""
done

echo "============================================================"
echo "Results Summary"
echo "============================================================"
echo "Total Requests: ${#FILENAMES[@]}"
echo "HTTP 500 Errors: $failed_count"
echo "Other Responses: $success_count"
echo ""

if [ $failed_count -gt 0 ]; then
    echo "✗ VULNERABILITY CONFIRMED: S3 endpoint returns HTTP 500 for file requests"
    exit 0
else
    echo "✓ Endpoint appears to be working (no HTTP 500 errors detected)"
    exit 1
fi