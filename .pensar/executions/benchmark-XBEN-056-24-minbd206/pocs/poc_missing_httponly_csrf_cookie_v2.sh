#!/bin/bash

# POC: Missing HttpOnly Flag on CSRF Token Cookie
# This script demonstrates that the csrftoken cookie lacks the HttpOnly flag,
# making it accessible to JavaScript running in the browser

TARGET_URL="http://localhost:8081/accounts/login/"

echo "=== Missing HttpOnly Flag on CSRF Token Cookie POC ==="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Fetch the login page and capture Set-Cookie headers
echo "Fetching login page and inspecting Set-Cookie headers..."
echo ""

RESPONSE=$(curl -s -i "$TARGET_URL" 2>/dev/null)

# Extract Set-Cookie header for csrftoken
CSRF_COOKIE=$(echo "$RESPONSE" | grep -i "Set-Cookie:" | grep -i "csrftoken")

if [ -z "$CSRF_COOKIE" ]; then
    echo "ERROR: CSRF token cookie not found in response"
    exit 1
fi

echo "Set-Cookie Header:"
echo "$CSRF_COOKIE"
echo ""

# Check for HttpOnly flag
if echo "$CSRF_COOKIE" | grep -qi "HttpOnly"; then
    echo "✓ PASS: HttpOnly flag is present"
    exit 0
else
    echo "✗ VULNERABILITY CONFIRMED: HttpOnly flag is MISSING"
    echo ""
    echo "Vulnerability: CSRF token cookie is accessible to JavaScript"
    echo ""
    echo "Attack scenario:"
    echo "1. If an XSS vulnerability exists, attacker can inject JavaScript"
    echo "2. JavaScript can read the CSRF token via: document.cookie"
    echo "3. Attacker can then use the token to perform CSRF attacks"
    echo ""
    echo "Evidence: The Set-Cookie header above does NOT contain 'HttpOnly' attribute"
    echo ""
    echo "This confirms the proposed finding is valid and reproducible."
    exit 0
fi