#!/bin/bash

# POC: CSRF Token Not Rotated After Logout
# This script demonstrates that the CSRF token persists unchanged after logout
# indicating a session fixation vulnerability in CSRF token handling

TARGET_URL="${1:-http://localhost:8081}"
COOKIE_FILE="csrf_logout_test_cookies.txt"
OUTPUT_FILE="csrf_logout_test_output.txt"

# Cleanup previous runs
rm -f "$COOKIE_FILE" "$OUTPUT_FILE"

echo "=========================================="
echo "CSRF Token Rotation Test - Session Fixation"
echo "=========================================="
echo ""

# Step 1: Access login page and capture initial CSRF token
echo "[*] Step 1: Accessing login page to get initial CSRF token..."
LOGIN_RESPONSE=$(curl -s -c "$COOKIE_FILE" "${TARGET_URL}/accounts/login/")

# Extract CSRF token from HTML (looking for csrftoken value in input or meta tag)
CSRF_BEFORE=$(echo "$LOGIN_RESPONSE" | grep -oP "csrfmiddlewaretoken['\"]?\s*['\"]?\s*value['\"]?\s*['\"]?\K[a-zA-Z0-9_-]+" | head -1)

if [ -z "$CSRF_BEFORE" ]; then
    # Try alternate extraction from meta tag
    CSRF_BEFORE=$(echo "$LOGIN_RESPONSE" | grep -oP "name=['\"]csrftoken['\"][^>]*content=['\"]?\K[a-zA-Z0-9_-]+" | head -1)
fi

# Try extracting from Set-Cookie header
if [ -z "$CSRF_BEFORE" ]; then
    CSRF_BEFORE=$(grep "csrftoken" "$COOKIE_FILE" | awk '{print $7}')
fi

echo "    CSRF Token Before Logout: $CSRF_BEFORE"
echo "    Cookies saved to: $COOKIE_FILE"
echo ""

# Step 2: Perform logout (using GET as the endpoint accepts it)
echo "[*] Step 2: Performing logout..."
LOGOUT_RESPONSE=$(curl -s -b "$COOKIE_FILE" -c "$COOKIE_FILE" -w "\n%{http_code}" "${TARGET_URL}/accounts/logout/")
HTTP_CODE=$(echo "$LOGOUT_RESPONSE" | tail -n1)

echo "    Logout HTTP Response Code: $HTTP_CODE"
echo "    Logout Response Headers:" > "$OUTPUT_FILE"
curl -s -b "$COOKIE_FILE" -c "$COOKIE_FILE" -D - "${TARGET_URL}/accounts/logout/" 2>/dev/null | head -20 >> "$OUTPUT_FILE"
echo ""

# Step 3: Check CSRF token after logout
echo "[*] Step 3: Checking CSRF token after logout..."

# Extract token from cookies after logout
CSRF_AFTER=$(grep "csrftoken" "$COOKIE_FILE" | awk '{print $7}')

# If not in cookie, try accessing a page and extracting from response
if [ -z "$CSRF_AFTER" ]; then
    AFTER_RESPONSE=$(curl -s -b "$COOKIE_FILE" "${TARGET_URL}/accounts/login/")
    CSRF_AFTER=$(echo "$AFTER_RESPONSE" | grep -oP "csrfmiddlewaretoken['\"]?\s*['\"]?\s*value['\"]?\s*['\"]?\K[a-zA-Z0-9_-]+" | head -1)
fi

echo "    CSRF Token After Logout: $CSRF_AFTER"
echo ""

# Step 4: Compare tokens
echo "=========================================="
echo "VULNERABILITY ANALYSIS:"
echo "=========================================="

if [ "$CSRF_BEFORE" = "$CSRF_AFTER" ] && [ ! -z "$CSRF_BEFORE" ]; then
    echo "✓ VULNERABLE: CSRF token NOT rotated after logout!"
    echo "  - Token Before: $CSRF_BEFORE"
    echo "  - Token After:  $CSRF_AFTER"
    echo "  - Result: IDENTICAL (should be different)"
    echo ""
    echo "This indicates a session fixation vulnerability."
    echo "The CSRF token should be regenerated after logout."
    RESULT=0
else
    if [ -z "$CSRF_BEFORE" ] || [ -z "$CSRF_AFTER" ]; then
        echo "⚠ INCONCLUSIVE: Could not extract CSRF tokens properly"
        echo "  - Token Before: $CSRF_BEFORE"
        echo "  - Token After:  $CSRF_AFTER"
        RESULT=1
    else
        echo "✓ NOT VULNERABLE: CSRF token was rotated after logout"
        echo "  - Token Before: $CSRF_BEFORE"
        echo "  - Token After:  $CSRF_AFTER"
        echo "  - Tokens are different (good security practice)"
        RESULT=2
    fi
fi

echo ""
echo "=========================================="
echo "Detailed Cookie Analysis:"
echo "=========================================="
echo ""
echo "Cookies before logout:"
grep "csrftoken" "$COOKIE_FILE" | head -1
echo ""
echo "Cookie file (final state):"
cat "$COOKIE_FILE"
echo ""

# Cleanup
# rm -f "$COOKIE_FILE" "$OUTPUT_FILE"

exit $RESULT