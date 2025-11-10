#!/bin/bash

# POC: Missing Field Validation in Login Endpoint
# Demonstrates HTTP 500 when required JSON fields are missing
# vs HTTP 401 when fields are present but empty (proper validation)

# Default target or allow override
TARGET_URL="${1:-http://localhost:5000/login}"

# Function to make request and extract status
test_endpoint() {
    local test_name="$1"
    local json_payload="$2"
    
    echo "[TEST] $test_name"
    echo "  Payload: $json_payload"
    
    # Make the request
    local response=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -H "Content-Type: application/json" \
        -d "$json_payload" 2>/dev/null)
    
    # Extract status code (last line)
    local http_code=$(echo "$response" | tail -n1)
    # Extract body (all but last line)
    local body=$(echo "$response" | head -n-1)
    
    echo "  HTTP Status: $http_code"
    
    # Only show body if it's not empty
    if [ -n "$body" ]; then
        echo "  Body: $body"
    fi
    echo ""
    
    echo "$http_code"
}

echo "==========================================================="
echo "Missing Field Validation - Login Endpoint Vulnerability POC"
echo "==========================================================="
echo "Target: $TARGET_URL"
echo ""

# Collect results
declare -A results

echo "--- Testing missing required fields (should be 400, but returns 500) ---"
echo ""

# Test 1: Missing password
result1=$(test_endpoint "Missing password field" '{"username":"testuser"}')
results["missing_password"]=$result1

# Test 2: Missing username
result2=$(test_endpoint "Missing username field" '{"password":"testpass"}')
results["missing_username"]=$result2

# Test 3: Empty JSON
result3=$(test_endpoint "Empty JSON object" '{}')
results["empty_json"]=$result3

echo "--- Control tests (should return 401) ---"
echo ""

# Test 4: Empty strings (valid structure, invalid credentials)
result4=$(test_endpoint "Empty strings (valid structure)" '{"username":"","password":""}')
results["empty_strings"]=$result4

# Test 5: Invalid credentials (valid structure, invalid credentials)
result5=$(test_endpoint "Invalid credentials (valid structure)" '{"username":"invaliduser","password":"invalidpass"}')
results["invalid_credentials"]=$result5

echo "==========================================================="
echo "VULNERABILITY SUMMARY"
echo "==========================================================="
echo ""
echo "Results:"
echo "  Missing password field:     HTTP $result1"
echo "  Missing username field:     HTTP $result2"
echo "  Empty JSON object:          HTTP $result3"
echo "  Empty strings (valid):      HTTP $result4"
echo "  Invalid credentials (valid):HTTP $result5"
echo ""

# Analysis
echo "Vulnerability Analysis:"
if [[ "$result1" == "500" ]] || [[ "$result2" == "500" ]] || [[ "$result3" == "500" ]]; then
    echo "  ✗ VULNERABLE: Missing fields return HTTP 500"
    echo "  ✓ This proves validation occurs AFTER field access"
    echo "  ✓ The application attempts to process incomplete JSON"
else
    echo "  ✓ NOT VULNERABLE: Missing fields do not return 500"
fi

if [[ "$result4" == "401" ]] || [[ "$result5" == "401" ]]; then
    echo "  ✓ Correct: Valid JSON structures with invalid credentials return 401"
else
    echo "  ? Unexpected: Expected 401 for invalid credentials with valid JSON"
fi

echo ""
echo "Expected Secure Behavior:"
echo "  - Missing required fields should return HTTP 400 Bad Request"
echo "  - Schema validation should occur at API boundary"
echo "  - Fields should be validated BEFORE access"
echo "==========================================================="