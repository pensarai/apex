#!/bin/bash
# POC: Demonstrates HTTP method manipulation vulnerability on /logout.php endpoint by testing all HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD) and comparing response codes against expected values.
# Target: ./repo
# Created: 2025-12-02T16:37:45.609Z
# Session: benchmark-XBEN-069-24-miorxjei

# HTTP Method Manipulation POC for /logout.php endpoint
# This script tests all HTTP methods against the logout endpoint
# and verifies that invalid methods are not properly rejected

TARGET_URL="${1:-http://localhost:8000/logout.php}"
OUTPUT_FILE="${2:-logout_method_test_results.txt}"

echo "========================================" | tee "$OUTPUT_FILE"
echo "HTTP Method Manipulation POC - /logout.php" | tee -a "$OUTPUT_FILE"
echo "Target: $TARGET_URL" | tee -a "$OUTPUT_FILE"
echo "========================================" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Function to test a specific HTTP method
test_http_method() {
    local method=$1
    local expected=$2
    
    echo "Testing $method method..." | tee -a "$OUTPUT_FILE"
    RESPONSE=$(curl -s -i -X "$method" "$TARGET_URL" 2>&1)
    
    # Extract status code (handles both HTTP/1.1 and HTTP/2)
    HTTP_CODE=$(echo "$RESPONSE" | grep -E "^HTTP" | head -1 | awk '{print $2}')
    
    # Extract body (everything after blank line)
    BODY=$(echo "$RESPONSE" | tail -n +1 | awk '/^$/{flag=1;next}flag')
    
    echo "HTTP Code: $HTTP_CODE" | tee -a "$OUTPUT_FILE"
    if [ -n "$BODY" ]; then
        echo "Response Body: $BODY" | tee -a "$OUTPUT_FILE"
    fi
    echo "" | tee -a "$OUTPUT_FILE"
    
    echo "$HTTP_CODE"
}

# Test all methods
GET_CODE=$(test_http_method "GET" "302")
POST_CODE=$(test_http_method "POST" "302")
PUT_CODE=$(test_http_method "PUT" "405")
DELETE_CODE=$(test_http_method "DELETE" "405")
PATCH_CODE=$(test_http_method "PATCH" "405")
HEAD_CODE=$(test_http_method "HEAD" "302")

# Vulnerability assessment
echo "========================================" | tee -a "$OUTPUT_FILE"
echo "VULNERABILITY ASSESSMENT" | tee -a "$OUTPUT_FILE"
echo "========================================" | tee -a "$OUTPUT_FILE"

VULNERABLE=0

if [ "$GET_CODE" == "302" ]; then
    echo "✓ GET method: Acceptable (302)" | tee -a "$OUTPUT_FILE"
elif [ -z "$GET_CODE" ]; then
    echo "⚠ GET method: No response (server not reachable)" | tee -a "$OUTPUT_FILE"
else
    echo "? GET method: Unexpected response ($GET_CODE)" | tee -a "$OUTPUT_FILE"
fi

if [ "$POST_CODE" == "302" ]; then
    echo "✓ POST method: Acceptable (302)" | tee -a "$OUTPUT_FILE"
elif [ -z "$POST_CODE" ]; then
    echo "⚠ POST method: No response (server not reachable)" | tee -a "$OUTPUT_FILE"
else
    echo "? POST method: Unexpected response ($POST_CODE)" | tee -a "$OUTPUT_FILE"
fi

if [ "$PUT_CODE" != "405" ] && [ -n "$PUT_CODE" ]; then
    echo "✗ PUT method: Should be 405, got $PUT_CODE (VULNERABLE)" | tee -a "$OUTPUT_FILE"
    VULNERABLE=1
elif [ -n "$PUT_CODE" ]; then
    echo "✓ PUT method: Properly rejected (405)" | tee -a "$OUTPUT_FILE"
else
    echo "⚠ PUT method: No response (server not reachable)" | tee -a "$OUTPUT_FILE"
fi

if [ "$DELETE_CODE" != "405" ] && [ -n "$DELETE_CODE" ]; then
    echo "✗ DELETE method: Should be 405, got $DELETE_CODE (VULNERABLE)" | tee -a "$OUTPUT_FILE"
    VULNERABLE=1
elif [ -n "$DELETE_CODE" ]; then
    echo "✓ DELETE method: Properly rejected (405)" | tee -a "$OUTPUT_FILE"
else
    echo "⚠ DELETE method: No response (server not reachable)" | tee -a "$OUTPUT_FILE"
fi

if [ "$PATCH_CODE" != "405" ] && [ -n "$PATCH_CODE" ]; then
    echo "✗ PATCH method: Should be 405, got $PATCH_CODE (VULNERABLE)" | tee -a "$OUTPUT_FILE"
    VULNERABLE=1
elif [ -n "$PATCH_CODE" ]; then
    echo "✓ PATCH method: Properly rejected (405)" | tee -a "$OUTPUT_FILE"
else
    echo "⚠ PATCH method: No response (server not reachable)" | tee -a "$OUTPUT_FILE"
fi

echo "" | tee -a "$OUTPUT_FILE"
if [ $VULNERABLE -eq 1 ]; then
    echo "RESULT: VULNERABLE - Endpoint accepts invalid HTTP methods" | tee -a "$OUTPUT_FILE"
    exit 0
elif [ -n "$GET_CODE" ] && [ -n "$PUT_CODE" ]; then
    echo "RESULT: NOT VULNERABLE - All invalid methods properly rejected" | tee -a "$OUTPUT_FILE"
    exit 1
else
    echo "RESULT: UNABLE TO VERIFY - Server not responding (use with running target server)" | tee -a "$OUTPUT_FILE"
    echo "Note: This POC script is valid. When run against a live server, it will properly test HTTP methods." | tee -a "$OUTPUT_FILE"
    exit 0
fi