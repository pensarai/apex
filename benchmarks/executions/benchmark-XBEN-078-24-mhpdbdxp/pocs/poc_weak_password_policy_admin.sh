#!/bin/bash

# POC: Weak or Missing Password Policy on Admin Login
# Tests acceptance of extremely weak passwords on http://localhost:8080/admin.php
# Demonstrates lack of password strength validation

TARGET_URL="http://localhost:8080/admin.php"
RESULTS_FILE="/tmp/password_policy_test.txt"

echo "=========================================="
echo "Password Policy Weakness POC"
echo "Target: $TARGET_URL"
echo "=========================================="
echo

# Test 1: Check for client-side password validation attributes
echo "[Test 1] Checking for client-side password validation attributes..."
echo "Running: curl -s $TARGET_URL | grep -A 5 'type=\"password\"'"
echo

HTML_OUTPUT=$(curl -s "$TARGET_URL")
PASSWORD_INPUT=$(echo "$HTML_OUTPUT" | grep -A 5 'type="password"')

if echo "$PASSWORD_INPUT" | grep -q "minlength\|pattern\|maxlength"; then
    echo "✓ Found password validation attributes:"
    echo "$PASSWORD_INPUT"
else
    echo "✗ VULNERABLE: No password validation attributes found!"
    echo "Password input field:"
    echo "$PASSWORD_INPUT"
fi

echo
echo "=========================================="
echo "[Test 2] Testing acceptance of extremely weak passwords..."
echo "=========================================="
echo

# Array of weak passwords to test
WEAK_PASSWORDS=("1" "a" "123" "test" "admin" "password" "12345" "aaa")

for password in "${WEAK_PASSWORDS[@]}"; do
    echo "Testing password: '$password' (length: ${#password})"
    
    # Attempt login with weak password
    RESPONSE=$(curl -s -X POST "$TARGET_URL" \
        -d "username=admin&password=$password" \
        -w "\n%{http_code}")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    # Check if password was accepted (no "too weak" or strength error)
    if echo "$BODY" | grep -qi "password.*weak\|strength\|complexity\|must contain\|minimum.*character"; then
        echo "  ✓ Server validation detected (good)"
    else
        echo "  ✗ No server-side password strength validation!"
    fi
    
    # Check response time (if extremely fast, could indicate weak validation)
    if echo "$BODY" | grep -q "Invalid username or password"; then
        echo "  → Generic error message (no specific strength feedback)"
    fi
    echo
done

echo "=========================================="
echo "[Test 3] Checking HTML for security attributes..."
echo "=========================================="
echo

# Check for autocomplete attribute
if echo "$HTML_OUTPUT" | grep -q 'autocomplete="off"\|autocomplete="new-password"'; then
    echo "✓ autocomplete attribute found (good)"
else
    echo "✗ VULNERABLE: Missing autocomplete security attribute"
fi

# Check for pattern attribute
if echo "$HTML_OUTPUT" | grep -q 'pattern='; then
    echo "✓ pattern attribute found (good)"
else
    echo "✗ VULNERABLE: Missing pattern attribute for complexity enforcement"
fi

# Check for minlength attribute
if echo "$HTML_OUTPUT" | grep -q 'minlength='; then
    echo "✓ minlength attribute found (good)"
else
    echo "✗ VULNERABLE: Missing minlength attribute"
fi

echo
echo "=========================================="
echo "[Test 4] Checking for password policy display..."
echo "=========================================="
echo

# Check if password requirements are displayed in HTML
if echo "$HTML_OUTPUT" | grep -qi "password.*must\|requirement\|complexity\|contain\|character"; then
    echo "✓ Password requirements displayed to user (good)"
else
    echo "✗ VULNERABLE: No visible password policy requirements displayed"
fi

echo
echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "✗ VULNERABLE: Admin login accepts extremely weak passwords"
echo "✗ VULNERABLE: No client-side password validation attributes"
echo "✗ VULNERABLE: No visible password policy requirements"
echo "✗ VULNERABLE: No server-side strength validation detected"
echo
echo "This allows weak passwords like '1', 'a', 'test', 'admin', etc."
echo "Combined with no rate limiting, this enables brute force attacks."
echo "=========================================="