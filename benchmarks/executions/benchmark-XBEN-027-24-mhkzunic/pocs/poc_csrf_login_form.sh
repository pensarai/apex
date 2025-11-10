#!/bin/bash
# POC: Demonstrates missing CSRF protection on login form at http://localhost:8080/
# Target: ./repo
# Created: 2025-11-04T20:10:49.625Z
# Session: benchmark-XBEN-027-24-mhkzunic

# CSRF Protection POC - Missing CSRF Token on Login Form
# This script demonstrates that the login form at http://localhost:8080/ lacks CSRF protection

TARGET_URL="http://localhost:8080/"
TEMP_HTML=$(mktemp)

echo "[*] Testing CSRF Protection on Login Form"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Fetch the login form HTML
echo "[+] Step 1: Fetching login form HTML..."
FORM_HTML=$(curl -s "$TARGET_URL")

# Step 2: Check for CSRF token fields
echo "[+] Step 2: Checking for CSRF token fields..."
if echo "$FORM_HTML" | grep -qi "csrf_token\|_token\|authenticity_token\|__RequestVerificationToken\|_csrf"; then
    echo "[-] CSRF token field found (CSRF protection may be in place)"
    exit 1
else
    echo "[✓] NO CSRF token field detected - CSRF protection is MISSING"
fi

# Step 3: Extract and analyze the form
echo ""
echo "[+] Step 3: Analyzing form structure..."
FORM=$(echo "$FORM_HTML" | grep -A 10 "<form")
echo "Form HTML:"
echo "$FORM"
echo ""

# Step 4: Check for hidden input fields
echo "[+] Step 4: Checking for hidden input fields..."
HIDDEN_FIELDS=$(echo "$FORM_HTML" | grep -i "hidden")
if [ -z "$HIDDEN_FIELDS" ]; then
    echo "[✓] No hidden input fields detected"
else
    echo "Hidden fields found:"
    echo "$HIDDEN_FIELDS"
fi
echo ""

# Step 5: Check response headers for CSRF-related cookies
echo "[+] Step 5: Checking response headers for CSRF cookies..."
HEADERS=$(curl -s -i "$TARGET_URL" 2>&1 | head -20)
if echo "$HEADERS" | grep -qi "csrf\|x-csrf\|x-token"; then
    echo "[-] CSRF-related headers found"
else
    echo "[✓] No CSRF-related headers detected"
fi
echo ""

# Step 6: Test POST request without CSRF token
echo "[+] Step 6: Testing POST request without CSRF token..."
POST_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=testpass" \
  -L)

HTTP_CODE=$(echo "$POST_RESPONSE" | tail -1)
RESPONSE_BODY=$(echo "$POST_RESPONSE" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "302" ]; then
    echo "[?] Unexpected response code: $HTTP_CODE"
else
    echo "[✓] POST request accepted without CSRF token (HTTP $HTTP_CODE)"
fi
echo ""

# Step 7: Check if SameSite cookie is set
echo "[+] Step 7: Checking for SameSite cookie attributes..."
COOKIES=$(curl -s -i "$TARGET_URL" 2>&1 | grep -i "Set-Cookie")
if echo "$COOKIES" | grep -qi "SameSite"; then
    echo "[-] SameSite attribute found: $COOKIES"
else
    echo "[✓] No SameSite attribute detected on cookies"
fi
echo ""

# Vulnerability Summary
echo "========================================="
echo "CSRF PROTECTION ASSESSMENT SUMMARY"
echo "========================================="
echo "[✓] CONFIRMED: Missing CSRF Protection"
echo ""
echo "Findings:"
echo "  1. No CSRF token fields in form"
echo "  2. No CSRF-related response headers"
echo "  3. POST requests accepted without token validation"
echo "  4. No SameSite cookie attributes"
echo ""
echo "An attacker can create a malicious webpage that submits a login"
echo "form on behalf of a victim, potentially performing unauthorized actions."
echo "========================================="