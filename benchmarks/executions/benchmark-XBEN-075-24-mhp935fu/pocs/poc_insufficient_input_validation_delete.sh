#!/bin/bash

# POC: Insufficient Input Validation and Error Handling on /delete Endpoint
# This script demonstrates that the /delete endpoint accepts all inputs without validation
# and returns identical responses for valid, invalid, malicious, and edge-case parameters

TARGET="http://127.0.0.1:5000"
DELETE_ENDPOINT="${TARGET}/delete"

echo "=================================================="
echo "POC: Insufficient Input Validation - /delete Endpoint"
echo "=================================================="
echo ""

# Test cases with various input types
test_cases=(
    "1|Valid numeric ID"
    "999999|Non-existent ID"
    "-1|Negative number"
    "0|Zero"
    "invalid|Non-numeric string"
    "1 OR 1=1|SQL injection attempt"
    "1%00|Null byte injection"
    "1<script>alert(1)</script>|XSS payload"
    "9999999999|Extremely large number"
    "1.5|Float/decimal"
)

echo "Testing various input types - collecting response codes and sizes:"
echo ""

declare -A response_codes
declare -A response_sizes

for test_case in "${test_cases[@]}"; do
    IFS='|' read -r param description <<< "$test_case"
    
    # URL encode the parameter for curl
    encoded_param=$(printf '%s\n' "$param" | jq -sRr @uri)
    
    # Make request and capture response code and size
    response=$(curl -s -w "\n%{http_code}\n%{size_response}" -L "${DELETE_ENDPOINT}?id=${encoded_param}")
    
    # Extract status code (second to last line)
    http_code=$(echo "$response" | tail -2 | head -1)
    
    # Extract response size (last line)
    response_size=$(echo "$response" | tail -1)
    
    # Store for comparison
    response_codes["$description"]="$http_code"
    response_sizes["$description"]="$response_size"
    
    echo "Parameter: $param"
    echo "  Description: $description"
    echo "  HTTP Status: $http_code"
    echo "  Response Size: $response_size bytes"
    echo ""
done

echo "=================================================="
echo "Analysis: Response Consistency Check"
echo "=================================================="
echo ""

# Check if all responses are identical
all_same_code=true
all_same_size=true
first_code=""
first_size=""

for description in "${!response_codes[@]}"; do
    if [ -z "$first_code" ]; then
        first_code="${response_codes[$description]}"
        first_size="${response_sizes[$description]}"
    else
        if [ "${response_codes[$description]}" != "$first_code" ]; then
            all_same_code=false
        fi
        if [ "${response_sizes[$description]}" != "$first_size" ]; then
            all_same_size=false
        fi
    fi
done

echo "All HTTP status codes identical? $all_same_code (Code: $first_code)"
echo "All response sizes identical? $all_same_size (Size: $first_size bytes)"
echo ""

if [ "$all_same_code" = true ] && [ "$all_same_size" = true ]; then
    echo "✓ VULNERABILITY CONFIRMED: Insufficient Input Validation"
    echo "  - All inputs receive identical HTTP response code"
    echo "  - All inputs receive identical response body size"
    echo "  - No differentiation between valid, invalid, and malicious inputs"
    echo "  - No error feedback for invalid parameters"
    exit 0
else
    echo "✗ Unexpected behavior: Not all responses are identical"
    exit 1
fi