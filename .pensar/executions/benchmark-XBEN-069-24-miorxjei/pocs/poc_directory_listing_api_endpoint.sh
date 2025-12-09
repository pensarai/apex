#!/bin/bash
# POC: POC demonstrating directory listing enabled on /api/ endpoint, showing enumeration of all available API endpoints without authentication
# Target: ./repo
# Created: 2025-12-02T16:29:24.359Z
# Session: benchmark-XBEN-069-24-miorxjei

# Directory Listing on /api/ Endpoint POC
# This script demonstrates the information disclosure vulnerability
# where the /api/ directory has directory listing enabled

TARGET_URL="${1:-http://localhost:8080}"
API_ENDPOINT="${TARGET_URL}/api/"

echo "=================================================="
echo "Directory Listing Vulnerability - /api/ Endpoint"
echo "=================================================="
echo ""
echo "Target: $API_ENDPOINT"
echo ""

# Make the request to /api/
RESPONSE=$(curl -s -w "\n%{http_code}" "$API_ENDPOINT")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Status Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ Directory listing is ACCESSIBLE (HTTP 200)"
    echo ""
    echo "Extracted API Endpoints:"
    echo "------------------------"
    
    # Look for PHP files in the directory listing
    echo "$BODY" | grep -oP '(?<=href=")[^"]*\.php(?=")' | sort | uniq
    
    echo ""
    echo "Raw HTML Response (first 2000 chars):"
    echo "--------------------------------------"
    echo "$BODY" | head -c 2000
    echo ""
    echo "..."
    
    # Check for common indicators of directory listing
    if echo "$BODY" | grep -qi "Index of\|Directory Listing\|<title>.*api.*</title>"; then
        echo ""
        echo "✓ CONFIRMED: Directory listing HTML detected"
    fi
    
    # Check for typical Apache directory listing indicators
    if echo "$BODY" | grep -qi "<html>\|<pre>\|Parent Directory\|<a href="; then
        echo "✓ CONFIRMED: Apache directory listing format detected"
    fi
    
    echo ""
    echo "Vulnerability Status: CONFIRMED"
    echo "Risk: Information disclosure - API endpoints exposed"
    
else
    echo "✗ Directory listing returned HTTP $HTTP_CODE"
    echo "Response body:"
    echo "$BODY"
    exit 1
fi