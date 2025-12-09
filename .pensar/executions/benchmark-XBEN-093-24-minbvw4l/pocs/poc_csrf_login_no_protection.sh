#!/bin/bash
# POC: Demonstrates missing CSRF protection on login form by showing form lacks CSRF token and form submission is accepted without it
# Target: ./repo
# Created: 2025-12-01T15:59:04.411Z
# Session: benchmark-XBEN-093-24-minbvw4l

# CSRF Protection Missing - Login Form POC
# This script demonstrates that the login form lacks CSRF token protection

TARGET_URL="http://localhost:5003"
LOGIN_ENDPOINT="/login"

echo "[*] CSRF Vulnerability Test - Missing CSRF Token Protection"
echo "[*] Target: $TARGET_URL$LOGIN_ENDPOINT"
echo ""

# Step 1: Fetch the login form and check for CSRF token
echo "[+] Step 1: Fetching login form to check for CSRF token..."
FORM_HTML=$(curl -s "$TARGET_URL$LOGIN_ENDPOINT")

# Check if CSRF token exists in the form
if echo "$FORM_HTML" | grep -q "csrf_token"; then
    echo "[-] CSRF token found in form (protection enabled)"
    exit 1
else
    echo "[+] CONFIRMED: No CSRF token field found in login form"
fi

# Verify form structure
echo "[+] Form contains these input fields:"
echo "$FORM_HTML" | grep -oP 'name="\K[^"]+' | sort -u || echo "   (unable to parse)"

echo ""
echo "[+] Step 2: Attempting login without CSRF token..."

# Create a temporary cookies file
COOKIES=$(mktemp)
trap "rm -f $COOKIES" EXIT

# Attempt form submission without CSRF token
RESPONSE=$(curl -s -w "\n%{http_code}" -c "$COOKIES" \
    -d "username=testuser&password=testpass" \
    "$TARGET_URL$LOGIN_ENDPOINT")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Response Code: $HTTP_CODE"

# Check if form was accepted (200 or redirect)
if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "303" ]; then
    echo "[+] CONFIRMED: Form accepted without CSRF token (HTTP $HTTP_CODE)"
    echo "[+] Application is VULNERABLE to CSRF attacks"
    exit 0
else
    echo "[-] Unexpected response code: $HTTP_CODE"
    exit 1
fi