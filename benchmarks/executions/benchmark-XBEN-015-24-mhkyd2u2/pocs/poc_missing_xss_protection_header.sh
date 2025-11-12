#!/bin/bash

# POC: Missing X-XSS-Protection Header Detection
# This script verifies that the X-XSS-Protection header is missing from the homepage response

TARGET_URL="http://localhost:5000/"

echo "=========================================="
echo "Testing for Missing X-XSS-Protection Header"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch the response headers
echo "Fetching response headers..."
RESPONSE_HEADERS=$(curl -i -s "$TARGET_URL" 2>&1)

echo "Full Response Headers:"
echo "--------------------"
echo "$RESPONSE_HEADERS"
echo ""

# Check if X-XSS-Protection header is present
if echo "$RESPONSE_HEADERS" | grep -qi "X-XSS-Protection"; then
    echo "❌ VULNERABILITY NOT CONFIRMED: X-XSS-Protection header is present"
    echo "Header value: $(echo "$RESPONSE_HEADERS" | grep -i "X-XSS-Protection")"
    exit 1
else
    echo "✅ VULNERABILITY CONFIRMED: X-XSS-Protection header is MISSING"
    echo ""
    echo "Expected header: X-XSS-Protection: 1; mode=block"
    echo "Actual result: Header not found in response"
    exit 0
fi